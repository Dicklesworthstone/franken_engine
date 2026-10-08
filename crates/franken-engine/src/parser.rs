// Deterministic parser interface for ES2020 script/module goals.
//
// The parser trait is generic over input source and emits canonical `IR0`
// syntax artifacts from `crate::ast`.

#![allow(clippy::clone_on_copy)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::ast::ParseGoal;
use crate::ast::{
    ANNEX_B_FUNCTION_VAR_PREFIX, ArrowBody, AssignmentOperator, AssignmentStrictness,
    BinaryOperator, BindingPattern, BlockStatement, BreakStatement, CatchClause, ClassDeclaration,
    ContinueStatement, DoWhileStatement, ExportDeclaration, ExportKind, Expression,
    ExpressionStatement, ForInStatement, ForOfStatement, ForStatement, FunctionDeclaration,
    FunctionParam, FunctionSourceText, IfStatement, ImportClause, ImportDeclaration,
    ImportSpecifier, LabeledStatement, MethodDefinition, MethodKind, NamedExportClause,
    ObjectPatternProperty, ObjectProperty, ObjectPropertyKind, ReturnStatement, SourceSpan,
    Statement, SwitchCase, SwitchStatement, SyntaxTree, ThrowStatement, TryCatchStatement,
    UnaryOperator, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
    WhileStatement, WithStatement,
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
    StrictModeWithStatement,
    /// `await` expression used outside a module top-level or async function body.
    AwaitOutsideAsync,
    /// A class element whose name its kind may not have (ES2022 15.7.1): a
    /// getter, setter, generator or async method named `constructor`, a
    /// field named `constructor`, a static member named `prototype`.
    InvalidClassElementName,
    /// Source that violates a recognized grammar or early-error rule. Unlike
    /// UnsupportedSyntax, this proves the source is invalid and may be exposed
    /// as a catchable SyntaxError by dynamic compilation.
    InvalidSyntax,
}

impl ParseErrorCode {
    pub const ALL: [Self; 11] = [
        Self::EmptySource,
        Self::InvalidGoal,
        Self::UnsupportedSyntax,
        Self::IoReadFailed,
        Self::InvalidUtf8,
        Self::SourceTooLarge,
        Self::BudgetExceeded,
        Self::StrictModeWithStatement,
        Self::AwaitOutsideAsync,
        Self::InvalidClassElementName,
        Self::InvalidSyntax,
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
            Self::StrictModeWithStatement => "strict_mode_with_statement",
            Self::AwaitOutsideAsync => "await_outside_async",
            Self::InvalidClassElementName => "invalid_class_element_name",
            Self::InvalidSyntax => "invalid_syntax",
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
            Self::StrictModeWithStatement => "FE-PARSER-DIAG-STRICT-MODE-WITH-STATEMENT-0001",
            Self::AwaitOutsideAsync => "FE-PARSER-DIAG-AWAIT-OUTSIDE-ASYNC-0001",
            Self::InvalidClassElementName => "FE-PARSER-DIAG-INVALID-CLASS-ELEMENT-NAME-0001",
            Self::InvalidSyntax => "FE-PARSER-DIAG-INVALID-SYNTAX-0001",
        }
    }

    pub const fn diagnostic_category(self) -> ParseDiagnosticCategory {
        match self {
            Self::EmptySource => ParseDiagnosticCategory::Input,
            Self::InvalidGoal => ParseDiagnosticCategory::Goal,
            Self::UnsupportedSyntax
            | Self::StrictModeWithStatement
            | Self::AwaitOutsideAsync
            | Self::InvalidClassElementName
            | Self::InvalidSyntax => ParseDiagnosticCategory::Syntax,
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
            Self::EmptySource
            | Self::InvalidGoal
            | Self::UnsupportedSyntax
            | Self::InvalidUtf8
            | Self::StrictModeWithStatement
            | Self::AwaitOutsideAsync
            | Self::InvalidClassElementName
            | Self::InvalidSyntax => ParseDiagnosticSeverity::Error,
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
            Self::StrictModeWithStatement => "with statements are not allowed in strict mode",
            Self::AwaitOutsideAsync => {
                "await expressions require module top-level or an async function"
            }
            Self::InvalidClassElementName => "class element name is not allowed for its kind",
            Self::InvalidSyntax => "source violates a grammar or early-error rule",
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
        CanonicalValue::map_from_entries([
            ("mode", CanonicalValue::str(self.mode.as_str())),
            (
                "budget_kind",
                self.budget_kind
                    .map(|kind| CanonicalValue::str(kind.as_str()))
                    .unwrap_or(CanonicalValue::Null),
            ),
            ("source_bytes", CanonicalValue::U64(self.source_bytes)),
            ("token_count", CanonicalValue::U64(self.token_count)),
            (
                "max_recursion_observed",
                CanonicalValue::U64(self.max_recursion_observed),
            ),
            (
                "max_source_bytes",
                CanonicalValue::U64(self.max_source_bytes),
            ),
            ("max_token_count", CanonicalValue::U64(self.max_token_count)),
            (
                "max_recursion_depth",
                CanonicalValue::U64(self.max_recursion_depth),
            ),
        ])
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
        CanonicalValue::map_from_entries([
            (
                "schema_version",
                CanonicalValue::str(self.schema_version.clone()),
            ),
            (
                "taxonomy_version",
                CanonicalValue::str(self.taxonomy_version.clone()),
            ),
            (
                "hash_algorithm",
                CanonicalValue::str(self.hash_algorithm.clone()),
            ),
            ("hash_prefix", CanonicalValue::str(self.hash_prefix.clone())),
            (
                "parse_error_code",
                CanonicalValue::str(self.parse_error_code.as_str()),
            ),
            (
                "diagnostic_code",
                CanonicalValue::str(self.diagnostic_code.clone()),
            ),
            ("category", CanonicalValue::str(self.category.as_str())),
            ("severity", CanonicalValue::str(self.severity.as_str())),
            (
                "message_template",
                CanonicalValue::str(self.message_template.clone()),
            ),
            (
                "source_label",
                CanonicalValue::str(self.source_label.clone()),
            ),
            (
                "span",
                self.span
                    .as_ref()
                    .map(SourceSpan::canonical_value)
                    .unwrap_or(CanonicalValue::Null),
            ),
            (
                "budget_kind",
                self.budget_kind
                    .map(|kind| CanonicalValue::str(kind.as_str()))
                    .unwrap_or(CanonicalValue::Null),
            ),
            (
                "witness",
                self.witness
                    .as_ref()
                    .map(ParseFailureWitness::canonical_value)
                    .unwrap_or(CanonicalValue::Null),
            ),
        ])
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
        span: error.span,
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
        CanonicalValue::str(self.as_str())
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
        CanonicalValue::map_from_entries([
            ("sequence", CanonicalValue::U64(self.sequence)),
            ("kind", self.kind.canonical_value()),
            (
                "parser_mode",
                CanonicalValue::str(self.parser_mode.as_str()),
            ),
            ("goal", CanonicalValue::str(self.goal.as_str())),
            (
                "source_label",
                CanonicalValue::str(self.source_label.clone()),
            ),
            ("trace_id", CanonicalValue::str(self.trace_id.clone())),
            ("decision_id", CanonicalValue::str(self.decision_id.clone())),
            ("policy_id", CanonicalValue::str(self.policy_id.clone())),
            ("component", CanonicalValue::str(self.component.clone())),
            ("outcome", CanonicalValue::str(self.outcome.clone())),
            (
                "error_code",
                self.error_code
                    .map(|code| CanonicalValue::str(code.as_str()))
                    .unwrap_or(CanonicalValue::Null),
            ),
            (
                "statement_index",
                self.statement_index
                    .map(CanonicalValue::U64)
                    .unwrap_or(CanonicalValue::Null),
            ),
            (
                "span",
                self.span
                    .as_ref()
                    .map(SourceSpan::canonical_value)
                    .unwrap_or(CanonicalValue::Null),
            ),
            (
                "payload_kind",
                self.payload_kind
                    .as_ref()
                    .map(|value| CanonicalValue::str(value.clone()))
                    .unwrap_or(CanonicalValue::Null),
            ),
            (
                "payload_hash",
                self.payload_hash
                    .as_ref()
                    .map(|value| CanonicalValue::str(value.clone()))
                    .unwrap_or(CanonicalValue::Null),
            ),
        ])
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
                span: error.span,
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
        let mut events = Vec::with_capacity(32);
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
            span: Some(tree.span),
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
        CanonicalValue::map_from_entries([
            (
                "schema_version",
                CanonicalValue::str(self.schema_version.clone()),
            ),
            (
                "contract_version",
                CanonicalValue::str(self.contract_version.clone()),
            ),
            (
                "hash_algorithm",
                CanonicalValue::str(Self::canonical_hash_algorithm()),
            ),
            (
                "hash_prefix",
                CanonicalValue::str(Self::canonical_hash_prefix()),
            ),
            (
                "parser_mode",
                CanonicalValue::str(self.parser_mode.as_str()),
            ),
            ("goal", CanonicalValue::str(self.goal.as_str())),
            (
                "source_label",
                CanonicalValue::str(self.source_label.clone()),
            ),
            ("event_count", CanonicalValue::U64(self.events.len() as u64)),
            (
                "events",
                CanonicalValue::Array(
                    self.events
                        .iter()
                        .map(ParseEvent::canonical_value)
                        .collect(),
                ),
            ),
        ])
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
        CanonicalValue::map_from_entries([
            ("node_id", CanonicalValue::str(self.node_id.clone())),
            ("sequence", CanonicalValue::U64(self.sequence)),
            ("statement_index", CanonicalValue::U64(self.statement_index)),
            (
                "payload_hash",
                CanonicalValue::str(self.payload_hash.clone()),
            ),
            ("span", self.span.canonical_value()),
        ])
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
        CanonicalValue::map_from_entries([
            (
                "schema_version",
                CanonicalValue::str(self.schema_version.clone()),
            ),
            (
                "contract_version",
                CanonicalValue::str(self.contract_version.clone()),
            ),
            ("trace_id", CanonicalValue::str(self.trace_id.clone())),
            ("decision_id", CanonicalValue::str(self.decision_id.clone())),
            ("policy_id", CanonicalValue::str(self.policy_id.clone())),
            ("component", CanonicalValue::str(self.component.clone())),
            (
                "parser_mode",
                CanonicalValue::str(self.parser_mode.as_str()),
            ),
            ("goal", CanonicalValue::str(self.goal.as_str())),
            (
                "source_label",
                CanonicalValue::str(self.source_label.clone()),
            ),
            (
                "root_node_id",
                CanonicalValue::str(self.root_node_id.clone()),
            ),
            (
                "statement_nodes",
                CanonicalValue::Array(
                    self.statement_nodes
                        .iter()
                        .map(MaterializedStatementNode::canonical_value)
                        .collect(),
                ),
            ),
            ("syntax_tree", self.syntax_tree.canonical_value()),
        ])
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
    canonical_value_hash(&CanonicalValue::str(value))
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
        Statement::With(_) => "with",
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
                    es2020_clause: "ECMA-262 Annex B / runtime literal".to_string(),
                    script_goal: GrammarCoverageStatus::Supported,
                    module_goal: GrammarCoverageStatus::Supported,
                    notes: "undefined token preserved as dedicated literal for deterministic lowering."
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
        let mut bytes = Vec::with_capacity(1024);
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
            // bd-rucba: tree parse AND event-IR construction both recurse over
            // the tree, so run them together on one budget-provisioned stack.
            Ok(source) => with_provisioned_parse_stack(options, || {
                match parse_source(&source.text, &source.label, goal, options) {
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
            // bd-rucba: tree + event-IR + materialization all recurse over the
            // tree; provision one budget-sized stack for the whole pipeline.
            Ok(source) => with_provisioned_parse_stack(options, || {
                match parse_source(&source.text, &source.label, goal, options) {
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
    source_bytes: u64,
    token_count: u64,
    max_recursion_observed: u64,
    /// Current statement nesting depth (if/for/while/try/switch/function bodies).
    /// Guards against stack overflow from deeply nested statements.
    statement_depth: u64,
    /// Current binding-pattern nesting depth (destructuring: `[[[...]]]`,
    /// `{a:{b:{c:...}}}`). Guards against stack overflow from deeply nested
    /// destructuring patterns, whose recursive descent is separate from the
    /// statement/expression guards (bd-c4lhp).
    pattern_depth: u64,
    /// Whether the current parsing context is in strict mode.
    strict_mode: bool,
    /// True only while parsing an object concise method (or a lexically nested
    /// arrow). Bare `super` remains invalid; this admits only `super.x` and
    /// `super[x]` where the resulting closure receives a [[HomeObject]].
    super_property_allowed: bool,
    /// Whether `await` is currently permitted as a unary expression. True at
    /// module top-level and inside async function/arrow/method bodies; false at
    /// script top-level and inside non-async functions.
    await_context: bool,
    /// Whether the code being parsed is a generator body, where `yield` is
    /// an operator (and cannot be an identifier or a unary operand).
    /// Outside one, `yield` is an identifier in sloppy code and reserved in
    /// strict code (ES2020 12.1.1, 14.4.1).
    yield_context: bool,
    /// Where a SuperCall `super(...)` would be (bd-9vouw.99).
    super_call: SuperCallContext,
    /// A class static block's own code, where `await` is reserved
    /// (ES2022 15.7.1); function and arrow bodies inside it are not.
    static_block_await: bool,
    /// A parameter list, where a generator's `yield` or an async
    /// function's `await` expression is a SyntaxError (ES2020 14.4.1,
    /// 14.7.1, 14.8.1).
    formal_parameters: bool,
    /// Private-name scopes of the class bodies being parsed, innermost last
    /// (ES2022 15.7.1 AllPrivateIdentifiersValid).
    private_name_scopes: Vec<PrivateNameScope>,
    /// bd-9vouw.184: where the parse text of each function, arrow, method
    /// and class comes from in the source, so Function.prototype.toString
    /// can return that source text.
    function_sources: FunctionSourceMap,
}

/// The parse text is the source with its comments blanked to spaces (same
/// byte offsets), merged into logical lines whose separators are
/// normalized; function bodies are merged again from slices of those lines.
/// Each merge's line is a `SourceFrame` while it is parsed, so a slice's
/// address maps back, frame by frame, to its offset in the source, which
/// `original` holds as written, comments included (bd-9vouw.184).
#[derive(Default)]
struct FunctionSourceMap {
    original: Option<std::sync::Arc<str>>,
    /// Address and length of the comment-blanked copy of `original`.
    blanked: Option<(usize, usize)>,
    /// The logical lines being parsed, outermost first.
    frames: Vec<SourceFrame>,
}

/// One logical line being parsed: its text's address and length, the
/// address of the text it was merged from, and the map from each byte
/// boundary of the line to an offset in that text.
struct SourceFrame {
    text: (usize, usize),
    input: usize,
    boundaries: Vec<usize>,
}

impl fmt::Debug for FunctionSourceMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionSourceMap")
            .field(
                "source_bytes",
                &self.original.as_ref().map(|source| source.len()),
            )
            .field("frames", &self.frames.len())
            .finish()
    }
}

impl FunctionSourceMap {
    /// The source offset of the parse text at `address`, when every buffer
    /// it was cut from is a frame (a slice of a string built some other
    /// way has none).
    fn offset_of(&self, address: usize) -> Option<usize> {
        let mut address = address;
        for frame in self.frames.iter().rev() {
            let (start, length) = frame.text;
            if address >= start && address <= start + length {
                address = frame.input + *frame.boundaries.get(address - start)?;
            }
        }
        let (start, length) = self.blanked?;
        (address >= start && address <= start + length).then(|| address - start)
    }

    /// The source text of a function whose parse text runs from `start`
    /// (an address) to the end of `last` (its final slice, ending with the
    /// function's last character). The source range must begin and end with
    /// the same characters as the parse text.
    fn text(&self, start: usize, first: char, last: &str) -> Option<FunctionSourceText> {
        let original = self.original.as_ref()?;
        let last_char = last.chars().next_back()?;
        if first.is_whitespace() || last_char.is_whitespace() {
            return None;
        }
        let last_address = last.as_ptr() as usize + last.len() - last_char.len_utf8();
        let begin = self.offset_of(start)?;
        let end = self.offset_of(last_address)? + last_char.len_utf8();
        let text = original.get(begin..end)?;
        (text.starts_with(first) && text.ends_with(last_char))
            .then(|| FunctionSourceText::new(original.clone(), begin, end))
            .flatten()
    }

    /// The source text of a function whose whole parse text is `slice`.
    fn text_of(&self, slice: &str) -> Option<FunctionSourceText> {
        let slice = slice.trim();
        let first = slice.chars().next()?;
        self.text(slice.as_ptr() as usize, first, slice)
    }

    /// The source text of a function whose parse text starts at `head` and
    /// ends with `[*][name](params) { body }` at the start of `tail`.
    fn text_through_body(&self, head: &str, tail: &str) -> Option<FunctionSourceText> {
        let head = head.trim_start();
        let first = head.chars().next()?;
        self.text(
            head.as_ptr() as usize,
            first,
            function_text_through_body(tail)?,
        )
    }
}

/// The prefix of `text` (`[*][name](params) { body }` followed by anything)
/// that ends with the body's `}`.
fn function_text_through_body(text: &str) -> Option<&str> {
    let paren = text.find('(')?;
    let (_, after_params) = extract_balanced(&text[paren..], '(', ')')?;
    let (_, after_body) = extract_balanced(after_params.trim_start(), '{', '}')?;
    Some(&text[..text.len() - after_body.len()])
}

/// `value` (a function, arrow or class expression) with its source text.
fn with_function_source(mut value: Expression, source: Option<FunctionSourceText>) -> Expression {
    if let Expression::Function { source_text, .. }
    | Expression::ArrowFunction { source_text, .. }
    | Expression::ClassExpression { source_text, .. } = &mut value
    {
        *source_text = source;
    }
    value
}

/// Where a SuperCall (`super(...)`) may appear (ES2022 15.7.1: a method's,
/// function's or script's body may not Contain SuperCall; only a derived
/// class's constructor may, and arrows inside it share its context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuperCallContext {
    /// Anywhere outside a derived class's constructor: a SyntaxError.
    Forbidden,
    /// A derived class's constructor body and the arrows inside it.
    DerivedConstructor,
    /// A field initializer or a static block, whose own early-error check
    /// reports `super(...)` after parsing, with the element's message.
    ClassElement,
}

/// The private names one class body declares and the `#x` references met
/// while parsing it. A reference the body does not declare must be declared
/// by an enclosing class body.
#[derive(Debug, Default)]
struct PrivateNameScope {
    declared: BTreeMap<String, PrivateNameDeclaration>,
    referenced: BTreeSet<String>,
}

/// What a private name was declared as, for the duplicate-declaration early
/// error: only a getter and a setter of the same placement may share a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrivateNameDeclaration {
    Field { is_static: bool },
    Method { is_static: bool },
    Getter { is_static: bool },
    Setter { is_static: bool },
    Accessor,
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

/// A logical line that may span multiple physical lines (for block statements).
struct LogicalLine {
    text: String,
    /// Maps every byte boundary in `text` back to the corresponding byte
    /// boundary in the physical source. Normalized separator spaces can span
    /// an arbitrary physical gap, so offsets cannot be reconstructed from
    /// `byte_offset` alone.
    source_boundaries: Vec<usize>,
    byte_offset: u64,
    start_line: u64,
    end_line: u64,
}

impl LogicalLine {
    fn source_offset_at(&self, logical_offset: usize) -> usize {
        *self
            .source_boundaries
            .get(logical_offset)
            .expect("logical-line boundary map covers normalized text")
    }
}

fn append_source_fragment(
    logical_text: &mut String,
    source_boundaries: &mut Vec<usize>,
    fragment: &str,
    source_start: usize,
) {
    if source_boundaries.is_empty() {
        debug_assert!(logical_text.is_empty());
        source_boundaries.push(source_start);
    } else {
        debug_assert_eq!(
            source_boundaries.len(),
            logical_text.len().saturating_add(1)
        );
        debug_assert_eq!(source_boundaries.last().copied(), Some(source_start));
    }

    logical_text.push_str(fragment);
    source_boundaries
        .extend((1..=fragment.len()).map(|length| source_start.saturating_add(length)));
    debug_assert_eq!(
        source_boundaries.len(),
        logical_text.len().saturating_add(1)
    );
}

/// Join the next physical line onto a logical line with one separator
/// character: a space, or `'\n'` where the break must survive (see
/// `merge_logical_lines`).
fn append_normalized_separator(
    logical_text: &mut String,
    source_boundaries: &mut Vec<usize>,
    following_source_offset: usize,
    separator: char,
) {
    debug_assert_eq!(
        source_boundaries.len(),
        logical_text.len().saturating_add(1)
    );
    debug_assert!(
        source_boundaries
            .last()
            .is_some_and(|offset| *offset <= following_source_offset)
    );
    debug_assert!(matches!(separator, ' ' | '\n'));
    logical_text.push(separator);
    source_boundaries.push(following_source_offset);
}

/// A logical line holding only a one-line comment.
fn is_comment_only_line(line: &LogicalLine) -> bool {
    line.start_line == line.end_line && strip_comments_to_whitespace(&line.text).trim().is_empty()
}

/// Whether a line, after any leading comments, opens a call's arguments or
/// a member index: `(` or `[`.
fn line_starts_call_or_index(line: &str) -> bool {
    let code = strip_comments_to_whitespace(line);
    let code = code.trim_start();
    code.starts_with('(') || code.starts_with('[')
}

/// Whether a line starts with a `/` that is not a comment: after a line that
/// ends an expression it is a division operator (bd-9vouw.362).
fn line_starts_division(line: &str) -> bool {
    line.starts_with('/') && !line.starts_with("//") && !line.starts_with("/*")
}

/// Whether a logical line ends with something an argument list or index can
/// follow: `)`, `]`, a literal or an identifier that is not a keyword ending
/// a statement head (`return`, `break`, ...), outside import and export
/// declarations.
fn previous_line_ends_expression(text: &str) -> bool {
    let code = strip_comments_to_whitespace(text);
    let code = code.trim_end();
    let is_identifier_char = |c: char| c == '_' || c == '$' || c.is_alphanumeric();
    let Some(last) = code.chars().next_back() else {
        return false;
    };
    if !(matches!(last, ')' | ']' | '\'' | '"' | '`') || is_identifier_char(last)) {
        return false;
    }
    let word_start = code
        .char_indices()
        .rev()
        .find(|(_, c)| !is_identifier_char(*c))
        .map_or(0, |(index, c)| index + c.len_utf8());
    // A Statement-position `let` is an identifier: `if (a) let\n(b)` calls
    // it, and `if (a) let\n[b] = c` stays one statement, which is an error.
    if &code[word_start..] == "let" && ends_with_statement_position_let(code) {
        return true;
    }
    if matches!(
        &code[word_start..],
        "return"
            | "throw"
            | "break"
            | "continue"
            | "yield"
            | "await"
            | "typeof"
            | "void"
            | "delete"
            | "new"
            | "in"
            | "of"
            | "instanceof"
            | "else"
            | "do"
            | "case"
            | "default"
            | "async"
            | "let"
            | "var"
            | "const"
    ) {
        return false;
    }
    !split_statement_segments(code)
        .last()
        .is_some_and(|(_, _, clause)| {
            let clause = strip_leading_labels(clause).trim_start();
            starts_with_keyword(clause, "import") || starts_with_keyword(clause, "export")
        })
}

/// Whether `text` ends with a `let` that is a whole Statement: the body of
/// an `if`, `else`, loop or `with` header or of a label (`if (a) let`,
/// `L: let`). A Statement is never a lexical declaration, so that `let` is
/// an identifier and a line break after it ends its expression statement
/// unless the next line continues the expression (ES2020 13.5 lookahead,
/// 11.9.1): `if (a) let\nx = 1` is `if (a) let;` then `x = 1;`.
fn ends_with_statement_position_let(text: &str) -> bool {
    let code = strip_comments_to_whitespace(text);
    let Some(before) = code.trim_end().strip_suffix("let") else {
        return false;
    };
    if before.ends_with(|ch: char| ch == '_' || ch == '$' || ch == '.' || ch.is_alphanumeric()) {
        return false;
    }
    let before = before.trim_end();
    let tail = text_after_last_top_level_terminator(before).trim();
    (!tail.is_empty() && strip_leading_labels(tail).is_empty())
        || statement_header_takes_unbraced_body(before)
}

fn logical_line_from_buffer(
    text: &str,
    source_boundaries: &[usize],
    start_line: u64,
    end_line: u64,
) -> Option<LogicalLine> {
    debug_assert_eq!(source_boundaries.len(), text.len().saturating_add(1));
    let leading = text.len().saturating_sub(text.trim_start().len());
    let trimmed_end = text.trim_end().len();
    if trimmed_end <= leading {
        return None;
    }

    let text = text[leading..trimmed_end].to_string();
    let source_boundaries = source_boundaries[leading..=trimmed_end].to_vec();
    let byte_offset = source_boundaries[0] as u64;
    debug_assert_eq!(source_boundaries.len(), text.len().saturating_add(1));
    Some(LogicalLine {
        text,
        source_boundaries,
        byte_offset,
        start_line,
        end_line,
    })
}

fn merge_logical_lines_keyword_allows_regex(identifier: &str) -> bool {
    matches!(
        identifier,
        "case"
            | "delete"
            | "in"
            | "instanceof"
            | "new"
            | "of"
            | "return"
            | "throw"
            | "typeof"
            | "void"
            | "yield"
    )
}

fn merge_logical_lines_slash_starts_regex(
    last_significant: Option<char>,
    trailing_identifier: &str,
    next_char: Option<char>,
) -> bool {
    // With nothing before it (a physical line's start), `/=` continues the
    // previous line as division assignment. After `(`, `,`, `=` or another
    // operator no operand precedes it, so `/=` opens a regex: js-base64's
    // `src.replace(/=/g, "")` was split at the `,` inside a "regex" that
    // began at the closing `/`.
    if matches!(next_char, Some('=')) && last_significant.is_none() {
        return false;
    }

    match last_significant {
        None => true,
        Some(
            '(' | '{' | '[' | ',' | ';' | ':' | '=' | '!' | '?' | '&' | '|' | '^' | '~' | '*' | '%'
            | '+' | '-' | '<' | '>' | '/',
        ) => true,
        Some(ch) if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' => {
            merge_logical_lines_keyword_allows_regex(trailing_identifier)
        }
        _ => false,
    }
}

/// Whether a physical line ends with a `++`/`--` update operator (an even
/// run of `+` or `-`). That completes the expression, so `i++` followed by a
/// new line is two statements; a line ending in a binary `+`/`-` (`a +`,
/// `a+++`) continues onto the next.
fn line_ends_with_update_operator(line: &str) -> bool {
    let tail = line.trim_end();
    let Some(last) = tail.chars().last() else {
        return false;
    };
    if !matches!(last, '+' | '-') {
        return false;
    }
    tail.chars().rev().take_while(|ch| *ch == last).count() % 2 == 0
}

fn merge_logical_lines_requires_continuation(
    last_significant: Option<char>,
    trailing_identifier: &str,
    trailing_identifier_follows_dot: bool,
) -> bool {
    // A trailing `.` is a member access waiting for its name (a decimal
    // point is recorded as the digit before it, bd-9vouw.207).
    if matches!(
        last_significant,
        Some(
            '=' | '?' | ':' | ',' | '+' | '-' | '*' | '/' | '%' | '&' | '|' | '^' | '<' | '>' | '.'
        )
    ) {
        return true;
    }

    // `return` and `yield` are restricted productions (ES2020 11.9.1): a line
    // break after them ends the statement (`return\n  x` returns undefined),
    // so they do not continue onto the next line.
    if matches!(
        trailing_identifier,
        "throw" | "typeof" | "void" | "delete" | "case"
    ) {
        return true;
    }
    // Operator keywords that cannot end an expression: babel's istanbul
    // output writes `var d = new\n/*istanbul ignore start*/\n_base[...]()`
    // (jsdiff), which ended at `new` and read `new` as a variable. After a
    // `.` the word is a property name (`opts.new`), which can. `function`
    // and `class` still need a name or body: istanbul splits
    // `function\n/*istanbul ignore start*/\n_default\n...(start, ...) {`
    // (bd-9vouw.212). `async` is absent: a line break after it is an ASI
    // boundary (`async\nfunction f() {}` is two statements).
    if !trailing_identifier_follows_dot
        && matches!(
            trailing_identifier,
            "new" | "in" | "instanceof" | "extends" | "function" | "class"
        )
    {
        return true;
    }
    // A declaration keyword with no binding yet cannot end a statement
    // (`var // note\n  a = 1`, moment.js). After a `.` the word is a property
    // name (`cfg.const`), which can.
    !trailing_identifier_follows_dot && matches!(trailing_identifier, "var" | "let" | "const")
}

/// Whether `line` starts with an operator that can only continue an
/// expression, never begin a statement: `|| b`, `&& b`, `?? b`, `? a : b`,
/// `: b`, `, b`, `* b`, `% b`, `| b`, `& b`, `^ b`, `= b`, `!= b`, `/= b`. ECMAScript
/// inserts no semicolon before such a token, so the line continues the
/// previous one (the leading-operator layout formatters emit for long
/// conditions and ternaries). `+`/`-` also continue (`a\n- b` is `a - b`)
/// unless doubled (`++`/`--` after a newline start a new statement); they are
/// reported separately because, unlike the others, they can begin a
/// statement after a block.
fn line_starts_with_continuation_operator(line: &str) -> Option<LeadingOperator> {
    let bytes = line.as_bytes();
    let first = *bytes.first()?;
    let second = bytes.get(1).copied();
    match first {
        b'|' | b'&' | b'?' | b':' | b',' | b'*' | b'%' | b'^' | b'=' => {
            Some(LeadingOperator::BinaryOnly)
        }
        b'!' if second == Some(b'=') => Some(LeadingOperator::BinaryOnly),
        // After a token that ends an expression, `/=` is the division
        // assignment punctuator, never a regex (ES2020 11.8.5 goal
        // InputElementDiv): `z\n/= 3` is `z /= 3` (bd-9vouw.127).
        b'/' if second == Some(b'=') => Some(LeadingOperator::BinaryOnly),
        b'+' | b'-' if second != Some(first) => Some(LeadingOperator::UnaryOrBinary),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeadingOperator {
    /// Cannot begin an expression, so the line always continues.
    BinaryOnly,
    /// `+`/`-`: continues an expression, but begins a new statement after a
    /// block (`if (x) {}\n-1`).
    UnaryOrBinary,
}

/// Replace comment bytes with spaces so the line-merge and statement-segment
/// passes never observe comment characters. ECMAScript line terminators are
/// preserved for line/column accuracy, and every blanked character emits exactly `len_utf8()`
/// spaces, so total byte length and the byte offset of every non-comment byte
/// are identical to the original source — spans stay accurate.
///
/// Strings, template literals, and regex literals are left intact. This mirrors
/// the string/regex/comment state machine in `merge_logical_lines` so the
/// regex-vs-division heuristic and comment boundaries are detected identically.
pub(crate) fn strip_comments_to_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut quotes = QuoteState::default();
    let mut in_block_comment = false;
    let mut in_line_comment = false;
    let mut in_regex_literal = false;
    let mut regex_in_char_class = false;
    let mut escaped = false;
    let mut last_significant: Option<char> = None;
    let mut trailing_identifier = String::new();
    // A space or line break ends the identifier being read (`else return
    // /re/`: the regex follows `return`, not `elsereturn`).
    let mut trailing_identifier_closed = false;

    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_line_comment {
            if is_ecmascript_line_terminator(ch) {
                in_line_comment = false;
                out.push(ch);
            } else {
                push_blanked(&mut out, ch);
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && matches!(chars.peek(), Some('/')) {
                chars.next();
                push_blanked(&mut out, '*');
                push_blanked(&mut out, '/');
                in_block_comment = false;
            } else if is_ecmascript_line_terminator(ch) {
                out.push(ch);
            } else {
                push_blanked(&mut out, ch);
            }
            continue;
        }
        if quotes.active() {
            // A comment inside a template substitution is code, not template
            // text (`${/* @__PURE__ */ f()}`, as bundlers emit). Neither
            // `/*` nor `//` can start a regular expression.
            if ch == '/'
                && quotes.in_substitution_code()
                && let Some(&next @ ('*' | '/')) = chars.peek()
            {
                chars.next();
                push_blanked(&mut out, '/');
                push_blanked(&mut out, next);
                if next == '*' {
                    in_block_comment = true;
                } else {
                    in_line_comment = true;
                }
                continue;
            }
            out.push(ch);
            quotes.advance_char(ch);
            continue;
        }
        if in_regex_literal {
            out.push(ch);
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '[' if !regex_in_char_class => regex_in_char_class = true,
                ']' if regex_in_char_class => regex_in_char_class = false,
                '/' if !regex_in_char_class => {
                    in_regex_literal = false;
                    // The literal is an operand: a following `/` divides.
                    last_significant = Some(')');
                    trailing_identifier.clear();
                }
                _ => {}
            }
            continue;
        }
        match ch {
            '/' => match chars.peek() {
                Some('/') => {
                    in_line_comment = true;
                    push_blanked(&mut out, '/');
                    chars.next();
                    push_blanked(&mut out, '/');
                }
                Some('*') => {
                    in_block_comment = true;
                    trailing_identifier_closed = true;
                    push_blanked(&mut out, '/');
                    chars.next();
                    push_blanked(&mut out, '*');
                }
                next_char
                    if merge_logical_lines_slash_starts_regex(
                        last_significant,
                        trailing_identifier.as_str(),
                        next_char.copied(),
                    ) =>
                {
                    out.push(ch);
                    in_regex_literal = true;
                    regex_in_char_class = false;
                    escaped = false;
                    trailing_identifier.clear();
                }
                // A division operator: a `/` after it opens a regex.
                _ => {
                    out.push(ch);
                    last_significant = Some('/');
                    trailing_identifier.clear();
                }
            },
            '\'' | '"' | '`' => {
                out.push(ch);
                quotes.open_char(ch);
                last_significant = Some(ch);
                trailing_identifier.clear();
            }
            '{' | '}' | '(' | ')' | '[' | ']' => {
                out.push(ch);
                last_significant = Some(ch);
                trailing_identifier.clear();
            }
            ch if ch.is_ascii_whitespace() || is_ecmascript_line_terminator(ch) => {
                out.push(ch);
                trailing_identifier_closed = true;
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' => {
                out.push(ch);
                if trailing_identifier_closed {
                    trailing_identifier.clear();
                    trailing_identifier_closed = false;
                }
                trailing_identifier.push(ch);
                last_significant = Some(ch);
            }
            ch if ch.is_ascii_digit() => {
                out.push(ch);
                if !trailing_identifier.is_empty() && !trailing_identifier_closed {
                    trailing_identifier.push(ch);
                } else {
                    trailing_identifier.clear();
                }
                last_significant = Some(ch);
            }
            ch => {
                out.push(ch);
                last_significant = Some(ch);
                trailing_identifier.clear();
            }
        }
    }
    out
}

/// String / template-literal state shared by the source scanners
/// (bd-9vouw.41).
///
/// A template literal is not a flat quote. Its `${ ... }` substitutions hold
/// code, which may contain strings, braces and further templates. The
/// template in `` `a${`<${x}>`}b` `` closes at its fourth backtick, not its
/// second. Treating the backtick as a plain quote ended the outer literal at
/// the inner opening backtick, which exposed the inner text (`<`, `,`, `?`,
/// a backtick inside a string) as top-level syntax to the operator, comma
/// and statement splitters.
///
/// Scanners call [`Self::active`] first; while it holds, every byte goes to
/// [`Self::advance`]. Otherwise they call [`Self::open`] on a quote or
/// backtick. Backward scanners use [`quoted_byte_mask`], which is computed
/// forward with the same machine. Inside a substitution, a `/` where an
/// operand may begin opens a regular-expression literal, whose quotes and
/// braces are pattern text: js-yaml writes `` `'${v.replace(/'/g, "''")}'` ``.
/// Comments inside a substitution are not interpreted.
#[derive(Debug, Default)]
struct QuoteState {
    stack: Vec<QuoteContext>,
    escaped: bool,
    after_dollar: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteContext {
    /// Inside a `'` or `"` string.
    String(u8),
    /// Inside the literal text of a template.
    Template,
    /// Inside a `${ ... }` substitution: its open-brace depth and its last
    /// significant byte (0 at its start), which tells a regex `/` from a
    /// division.
    Substitution { depth: u32, last: u8 },
    /// Inside a regular-expression literal, with the bytes left in it.
    Regex(usize),
    /// Inside a regular-expression literal that began in a substitution,
    /// whose end is found byte by byte; `in_class` inside `[...]`.
    RegexStream { in_class: bool },
}

impl QuoteState {
    /// A scanner positioned just after a template's `${`.
    fn in_substitution() -> Self {
        Self {
            stack: vec![QuoteContext::Substitution { depth: 0, last: 0 }],
            ..Self::default()
        }
    }

    /// Record `byte` as the last significant byte of the innermost
    /// substitution (the top of the stack).
    fn set_substitution_last(&mut self, byte: u8) {
        if let Some(QuoteContext::Substitution { last, .. }) = self.stack.last_mut() {
            *last = byte;
        }
    }

    /// Whether the scanner is inside a string, a template, or a template
    /// substitution.
    fn active(&self) -> bool {
        !self.stack.is_empty()
    }

    /// Whether the scanner is in a template substitution's code (not in a
    /// string, template text or regex nested in it).
    fn in_substitution_code(&self) -> bool {
        matches!(self.stack.last(), Some(QuoteContext::Substitution { .. }))
    }

    /// Enter a string or template if `b` opens one. Returns whether it did.
    fn open(&mut self, b: u8) -> bool {
        match b {
            b'\'' | b'"' => self.stack.push(QuoteContext::String(b)),
            b'`' => self.stack.push(QuoteContext::Template),
            _ => return false,
        }
        self.escaped = false;
        self.after_dollar = false;
        true
    }

    fn open_char(&mut self, ch: char) -> bool {
        ch.is_ascii() && self.open(ch as u8)
    }

    /// Enter the regular-expression literal opened by the `/` at `s[slash]`
    /// when a regex, not a division, can start there. Its quotes, brackets
    /// and operators are pattern text, so lodash's `/[&<>"']/g` opens no
    /// string. Returns whether it did; the `/` itself is consumed.
    fn open_regex_at(&mut self, s: &str, slash: usize) -> bool {
        match regex_literal_len_at(s, slash) {
            Some(len) if len > 1 => {
                self.stack.push(QuoteContext::Regex(len - 1));
                true
            }
            _ => false,
        }
    }

    /// Consume one byte while [`Self::active`].
    fn advance(&mut self, b: u8) {
        let Some(&context) = self.stack.last() else {
            return;
        };
        match context {
            QuoteContext::Regex(left) => self.consume_regex_bytes(left, 1),
            QuoteContext::RegexStream { in_class } => {
                if self.escaped {
                    self.escaped = false;
                } else if b == b'\\' {
                    self.escaped = true;
                } else if b == b'[' || b == b']' {
                    *self.stack.last_mut().expect("regex context") = QuoteContext::RegexStream {
                        in_class: b == b'[',
                    };
                } else if b == b'/' && !in_class {
                    self.stack.pop();
                }
            }
            QuoteContext::String(quote) => {
                if self.escaped {
                    self.escaped = false;
                } else if b == b'\\' {
                    self.escaped = true;
                } else if b == quote {
                    self.stack.pop();
                }
            }
            QuoteContext::Template => {
                let after_dollar = std::mem::replace(&mut self.after_dollar, false);
                if self.escaped {
                    self.escaped = false;
                } else if b == b'\\' {
                    self.escaped = true;
                } else if b == b'`' {
                    self.stack.pop();
                } else if b == b'{' && after_dollar {
                    self.stack
                        .push(QuoteContext::Substitution { depth: 0, last: 0 });
                } else {
                    self.after_dollar = b == b'$';
                }
            }
            QuoteContext::Substitution { depth, last } => match b {
                b'\'' | b'"' | b'`' => {
                    // After the literal closes, an operand has ended.
                    self.set_substitution_last(b'"');
                    self.open(b);
                }
                b'/' if substitution_slash_starts_regex(last) => {
                    self.set_substitution_last(b'"');
                    self.escaped = false;
                    self.stack
                        .push(QuoteContext::RegexStream { in_class: false });
                }
                b'{' => {
                    *self.stack.last_mut().expect("substitution context") =
                        QuoteContext::Substitution {
                            depth: depth + 1,
                            last: b'{',
                        };
                }
                b'}' if depth == 0 => {
                    self.stack.pop();
                }
                b'}' => {
                    *self.stack.last_mut().expect("substitution context") =
                        QuoteContext::Substitution {
                            depth: depth - 1,
                            last: b'}',
                        };
                }
                b' ' | b'\t' | b'\n' | b'\r' => {}
                _ => self.set_substitution_last(b),
            },
        }
    }

    /// A physical line terminator consumed an escape (a backslash line
    /// continuation) or ended the line; the escape does not carry over, and
    /// a regular-expression literal never spans a line.
    fn line_break(&mut self) {
        self.escaped = false;
        self.after_dollar = false;
        if matches!(self.stack.last(), Some(QuoteContext::RegexStream { .. })) {
            self.stack.pop();
        }
    }

    fn advance_char(&mut self, ch: char) {
        // A regex literal's extent is in bytes.
        if let Some(&QuoteContext::Regex(left)) = self.stack.last() {
            self.consume_regex_bytes(left, ch.len_utf8());
            return;
        }
        // Every delimiter is ASCII; any other character is plain content.
        self.advance(if ch.is_ascii() { ch as u8 } else { 0x80 });
    }

    fn consume_regex_bytes(&mut self, left: usize, consumed: usize) {
        if left <= consumed {
            self.stack.pop();
        } else {
            *self.stack.last_mut().expect("regex context") = QuoteContext::Regex(left - consumed);
        }
    }
}

/// Whether a `/` inside a template substitution opens a regex literal, given
/// the substitution's last significant byte: at its start or after an
/// opening bracket or an operator, as [`merge_logical_lines_slash_starts_regex`]
/// decides at top level. An identifier counts as an operand here, so the
/// rare `typeof /x/` inside a substitution reads as a division.
fn substitution_slash_starts_regex(last: u8) -> bool {
    matches!(
        last,
        0 | b'('
            | b'{'
            | b'['
            | b','
            | b';'
            | b':'
            | b'='
            | b'!'
            | b'?'
            | b'&'
            | b'|'
            | b'^'
            | b'~'
            | b'*'
            | b'%'
            | b'+'
            | b'-'
            | b'<'
            | b'>'
            | b'/'
    )
}

/// For each byte of `s`, whether it belongs to a string, template or regex
/// literal (delimiters and substitutions included), computed forward with
/// [`QuoteState`]. Scanners that walk right-to-left use this, because a
/// template's nesting cannot be recovered from its right end (bd-9vouw.41).
fn quoted_byte_mask(s: &str) -> Vec<bool> {
    let mut quotes = QuoteState::default();
    s.bytes()
        .enumerate()
        .map(|(index, b)| {
            if quotes.active() {
                quotes.advance(b);
                true
            } else {
                (b == b'/' && quotes.open_regex_at(s, index)) || quotes.open(b)
            }
        })
        .collect()
}

/// Like [`quoted_byte_mask`], but the code of template substitutions
/// (`${ ... }`) is not masked: only string, template-text and regex bytes are.
fn literal_text_byte_mask(s: &str) -> Vec<bool> {
    let mut quotes = QuoteState::default();
    s.bytes()
        .enumerate()
        .map(|(index, b)| {
            if quotes.active() {
                let code = quotes.in_substitution_code();
                quotes.advance(b);
                !code
            } else {
                (b == b'/' && quotes.open_regex_at(s, index)) || quotes.open(b)
            }
        })
        .collect()
}

/// `text` with the contents of its string, template-text and
/// regular-expression literals replaced by spaces byte for byte (line breaks
/// kept), while the code inside template substitutions stays: a scan for
/// code syntax that may legitimately appear inside `${ ... }` (a typed
/// hostcall in a template substitution) still sees it.
pub(crate) fn blank_literal_text(text: &str) -> String {
    let mask = literal_text_byte_mask(text);
    let mut out = String::with_capacity(text.len());
    for (index, ch) in text.char_indices() {
        if mask[index] && ch != '\n' {
            push_blanked(&mut out, ch);
        } else {
            out.push(ch);
        }
    }
    out
}

/// `text` with its string, template and regular-expression literals
/// (delimiters and template substitutions included) replaced by spaces byte
/// for byte, line breaks kept, so a scan for code syntax (TypeScript
/// sniffing) never reads literal text such as marked's `"!:"` or
/// path-to-regexp's `/[{}()\[\]+?!:*\\]/g`.
pub(crate) fn blank_quoted_literals(text: &str) -> String {
    let mask = quoted_byte_mask(text);
    let mut out = String::with_capacity(text.len());
    for (index, ch) in text.char_indices() {
        if mask[index] && ch != '\n' {
            push_blanked(&mut out, ch);
        } else {
            out.push(ch);
        }
    }
    out
}

/// Emit `len_utf8()` spaces for a blanked (comment) character, preserving the
/// byte length of the original source so downstream byte offsets stay aligned.
#[inline]
fn push_blanked(out: &mut String, ch: char) {
    for _ in 0..ch.len_utf8() {
        out.push(' ');
    }
}

#[inline]
fn is_ecmascript_line_terminator(ch: char) -> bool {
    matches!(ch, '\r' | '\n' | '\u{2028}' | '\u{2029}')
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
            ch if is_ecmascript_line_terminator(ch) => {
                ranges.push((index, index.saturating_add(ch.len_utf8())));
            }
            _ => {}
        }
    }
    ranges
}

fn source_position_at_offset(
    source_offset: usize,
    line_terminators: &[(usize, usize)],
) -> (u64, u64) {
    let completed_lines = line_terminators.partition_point(|(_, end)| *end <= source_offset);
    let line_start = completed_lines
        .checked_sub(1)
        .map_or(0, |previous| line_terminators[previous].1);
    (
        completed_lines.saturating_add(1) as u64,
        source_offset.saturating_sub(line_start).saturating_add(1) as u64,
    )
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

/// Merge physical lines into logical lines by tracking brace/paren/bracket depth.
/// When a line ends with unbalanced delimiters, subsequent lines are merged until balance.
/// The text after the last top-level `;` or block-closing `}` of
/// `statement` (quotes and nested delimiters respected).
fn text_after_last_top_level_terminator(statement: &str) -> &str {
    let mut depth = 0i64;
    let mut quotes = QuoteState::default();
    let mut start = 0usize;
    for (index, ch) in statement.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if ch == '/' && quotes.open_regex_at(statement, index) {
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' | '[' | '{' => depth += 1,
            ')' | ']' => depth -= 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    start = index + 1;
                }
            }
            ';' if depth == 0 => start = index + 1,
            _ => {}
        }
    }
    &statement[start..]
}

/// Whether `text` opens a `{` outside parentheses, brackets and quotes. A
/// brace inside a header's parentheses (a callback body, a default
/// parameter's object) does not make the header's own body begin
/// (papaparse: `if (list.filter(function (v) { ... }).length)` then `{`).
fn has_top_level_open_brace(text: &str) -> bool {
    let mut depth = 0i64;
    let mut quotes = QuoteState::default();
    for (index, ch) in text.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if ch == '/' && quotes.open_regex_at(text, index) {
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '{' if depth <= 0 => return true,
            _ => {}
        }
    }
    false
}

/// Whether `statement` is a `do` statement whose `while (...)` has not
/// appeared yet (its body is complete or still to come), also as the
/// unbraced body of other headers: `if (c) do x++; while (x < 3);` is one
/// if statement, as js-yaml's bundle writes it across three lines.
fn do_statement_awaits_while(statement: &str) -> bool {
    let awaits = |text: &str| {
        let body = unbraced_body_of_header_chain(text);
        starts_with_keyword(body, "do") && do_condition_while_index(&body["do".len()..]).is_none()
    };
    // `if (a) x(); else if (b)\n  do\n    y();\n  while (c);` (pako's
    // deflate): the do statement is the last else clause's body.
    awaits(statement) || text_after_last_top_level_else(statement).is_some_and(awaits)
}

/// The clause after the last top-level `else` of `statement` (`if (a) x();
/// else if (b) do y();` gives `if (b) do y();`), or `None`. The keyword is a
/// whole token, also without surrounding spaces: minified code writes
/// `if(k)a();else do{..}while(c)` (preact), whose do statement's `while`
/// was split off as a statement of its own.
fn text_after_last_top_level_else(statement: &str) -> Option<&str> {
    let mut rest = statement;
    let mut last = None;
    while let Some(at) = find_top_level_keyword(rest, "else") {
        let after = at + "else".len();
        let token = !rest[..at].ends_with(|ch: char| is_identifier_continue(ch) || ch == '.')
            && !rest[after..].starts_with(is_identifier_continue);
        rest = &rest[after..];
        if token {
            last = Some(rest);
        }
    }
    last.map(str::trim_start)
}

/// `statement` without its leading chain of statement headers (`if (...)`,
/// `for (...)`, `while (...)`, `with (...)`, `else`, labels): the statement
/// that is their innermost unbraced body, or `statement` itself.
fn unbraced_body_of_header_chain(statement: &str) -> &str {
    let mut rest = strip_leading_labels(statement.trim_start()).trim_start();
    loop {
        if let Some(after) = rest
            .strip_prefix("else")
            .filter(|after| after.starts_with(char::is_whitespace))
        {
            rest = strip_leading_labels(after.trim_start()).trim_start();
            continue;
        }
        if !["if", "for", "while", "with"]
            .iter()
            .any(|keyword| starts_with_keyword(rest, keyword))
        {
            return rest;
        }
        let Some((_, after)) = rest
            .find('(')
            .and_then(|open| extract_balanced(&rest[open..], '(', ')'))
        else {
            return rest;
        };
        rest = strip_leading_labels(after.trim_start()).trim_start();
    }
}

/// Whether `statement` ends in a header whose body may be a single unbraced
/// statement on the next line: `if (...)`, `for (...)`, `while (...)`,
/// `with (...)`, `else` or `do`, including a chain of them whose innermost
/// header is still waiting (`for (...)\n  if (x)\n    return;`, the layout
/// bundlers emit). A do statement's trailing `while (...)` is its condition,
/// not a header.
fn statement_header_takes_unbraced_body(statement: &str) -> bool {
    let tail = text_after_last_top_level_terminator(statement).trim();
    // Only a `while` tail can be a do statement's condition, also when the
    // do statement is the last else clause's body: `if (a) x(); else do {
    // y() } while (c)` then a new line was read as `while (c)` heading that
    // line, which then never ran.
    let is_do = |text: &str| starts_with_keyword(unbraced_body_of_header_chain(text), "do");
    let in_do_statement = tail.contains("while")
        && (is_do(statement) || text_after_last_top_level_else(statement).is_some_and(is_do));
    header_chain_takes_unbraced_body(tail, in_do_statement)
}

/// Whether an `else` on the next line continues `clause`: an `if` statement,
/// also as the unbraced body of loop headers (`while (c)\n  if (x) a();\n
/// else b();` pairs the `else` with that `if`).
fn clause_takes_else(clause: &str) -> bool {
    let mut rest = clause.trim();
    // `do\n  if (c) x();\n  else y();\nwhile (d);`: the if is the body.
    if let Some(body) = rest
        .strip_prefix("do")
        .filter(|body| body.starts_with(char::is_whitespace))
    {
        rest = body.trim_start();
    }
    loop {
        if starts_with_keyword(rest, "if") {
            return true;
        }
        if !["for", "while", "with"]
            .iter()
            .any(|keyword| starts_with_keyword(rest, keyword))
        {
            return false;
        }
        let Some((_, after)) = rest
            .find('(')
            .and_then(|open| extract_balanced(&rest[open..], '(', ')'))
        else {
            return false;
        };
        rest = after.trim();
    }
}

/// [`statement_header_takes_unbraced_body`] for the text of one header and
/// whatever follows it: a header whose parentheses end the text waits for
/// its body, and so does one followed by another such header (its unbraced
/// body is that nested statement).
fn header_chain_takes_unbraced_body(tail: &str, in_do_statement: bool) -> bool {
    if tail == "else" || tail == "do" {
        return true;
    }
    // A do statement's unbraced body can itself be a header chain (pako's
    // inflate: `do\n  if (c)\n    x();\nwhile (d);`); a `while` right after
    // `do` heads that body, it is not the do statement's condition.
    let (header, in_do_statement) = match tail
        .strip_prefix("do")
        .filter(|rest| rest.starts_with(char::is_whitespace))
    {
        Some(body) => (body.trim_start(), false),
        None => (
            tail.strip_prefix("else")
                .filter(|rest| rest.starts_with(char::is_whitespace))
                .map_or(tail, str::trim_start),
            in_do_statement,
        ),
    };
    // A braced body shows after the header's parentheses (the recursion
    // below rejects it); a `{` inside them is an object literal or a
    // destructuring pattern: `if (visit(item, {\n  depth\n}))\n  return;`.
    if header.is_empty() {
        return false;
    }
    if starts_with_keyword(header, "while") && in_do_statement {
        return false;
    }
    if !["if", "for", "while", "with"]
        .iter()
        .any(|keyword| starts_with_keyword(header, keyword))
    {
        return false;
    }
    let Some((_, rest)) = header
        .find('(')
        .and_then(|open| extract_balanced(&header[open..], '(', ')'))
    else {
        return false;
    };
    let rest = rest.trim();
    rest.is_empty() || header_chain_takes_unbraced_body(rest, false)
}

/// Whether `statement` ends in a statement header still waiting for its
/// braced body: `function f(...)`, `if (...)`, `class C extends B`, and a
/// trailing `else` / `else if (...)` / `catch (e)` / `finally` / `try` / `do`
/// after an earlier clause's `}`. A header already followed by a body (so
/// `if (x) f()` before a block) does not qualify.
fn statement_header_awaits_body(statement: &str) -> bool {
    // The last clause: `if (a) x(); else if (b)` awaits the `else if` body.
    let tail = text_after_last_top_level_terminator(statement).trim();
    let tail = tail
        .strip_prefix("else")
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .map_or(tail, str::trim_start);
    if tail.is_empty() || has_top_level_open_brace(tail) || tail.ends_with(';') {
        return false;
    }
    if ["else", "do", "try", "finally"].contains(&tail) || starts_with_keyword(tail, "class") {
        return true;
    }
    let params_close_at_end = |header: &str| {
        header.find('(').is_some_and(|open| {
            extract_balanced(&header[open..], '(', ')')
                .is_some_and(|(_, rest)| rest.trim().is_empty())
        })
    };
    let parenthesized_header = [
        "function", "async", "if", "for", "while", "switch", "with", "catch",
    ]
    .iter()
    .any(|keyword| starts_with_keyword(tail, keyword));
    if parenthesized_header {
        return params_close_at_end(tail);
    }
    // A function expression header ending the statement:
    // `var f = function (a)` / `x.m = function* g()`.
    tail.match_indices("function").any(|(index, _)| {
        let before_ok = tail[..index]
            .chars()
            .next_back()
            .is_none_or(|ch| !(ch.is_alphanumeric() || ch == '_' || ch == '$'));
        before_ok
            && starts_with_keyword(&tail[index..], "function")
            && params_close_at_end(&tail[index..])
    })
}

fn merge_logical_lines(text: &str) -> Vec<LogicalLine> {
    let physical_lines = physical_line_segments(text);
    let mut result = Vec::with_capacity(16);
    let mut current_text = String::new();
    let mut current_source_boundaries = Vec::new();
    let mut current_start_line: u64 = 0;
    let mut byte_offset: usize = 0;
    let mut brace_depth: i64 = 0;
    let mut paren_depth: i64 = 0;
    let mut bracket_depth: i64 = 0;
    // The open brackets, innermost last. A line break whose innermost
    // enclosing bracket is `{` (a block, function, class or object body)
    // stays a line break in the merged text: the body is merged again when
    // it is parsed, and its statements need their breaks for ASI
    // (`function f() {\n let a = 1\n let b = 2\n}`). Inside parentheses or
    // brackets a break is only whitespace and becomes a space.
    let mut open_brackets: Vec<char> = Vec::new();
    let mut quotes = QuoteState::default();
    let mut in_block_comment = false;
    let mut in_regex_literal = false;
    let mut regex_in_char_class = false;
    let mut escaped = false;
    let mut accumulating = false;
    let mut last_significant: Option<char> = None;
    let mut trailing_identifier = String::new();
    let mut trailing_identifier_follows_dot = false;
    for (line_idx, physical_line) in physical_lines.iter().copied().enumerate() {
        let line_no = (line_idx as u64).saturating_add(1);
        let segment = physical_line.segment;
        let line = physical_line.content;
        let line_ending = physical_line.terminator;

        if line_idx == 0 {
            let line_without_bom = line.strip_prefix('\u{feff}').unwrap_or(line);
            if line_without_bom.starts_with("#!") {
                byte_offset = byte_offset.saturating_add(segment.len());
                continue;
            }
        }

        if !accumulating {
            // bd-suwvw: a balanced previous logical line followed by a line
            // STARTING with `.` + identifier is a method-chain continuation
            // (`Promise.resolve()\n  .then(cb)\n  .then(cb2)` — the common
            // formatter layout). Without this, the leading-dot line becomes
            // its own statement and misparses. Only merge when the previous
            // line did not end with an explicit `;` (after which a leading
            // dot cannot continue the expression) and the dot is followed by
            // an identifier start (so `.5` numeric literals never merge).
            let trimmed_line = line.trim_start();
            // A lone `.` continues too: babel's istanbul output puts the dot
            // of `_line.lineDiff` on a line of its own between comment lines
            // (jsdiff's json.js), which became a statement `.`
            // (bd-9vouw.207).
            let dot_continues_previous = trimmed_line.starts_with('.')
                && trimmed_line[1..].chars().next().is_none_or(|c| {
                    c.is_ascii_alphabetic() || c == '_' || c == '$' || c.is_whitespace()
                })
                && result
                    .last()
                    .is_some_and(|prev: &LogicalLine| !prev.text.ends_with(';'));
            // Likewise a line STARTING with an operator that cannot begin a
            // statement continues the previous expression (`cond\n  ? a\n  : b`,
            // `a\n  || b`, comma-first declarations). A leading `+`/`-` does
            // not continue a statement that ended with a block.
            let operator_continues_previous = line_starts_with_continuation_operator(trimmed_line)
                .is_some_and(|operator| {
                    result.last().is_some_and(|prev: &LogicalLine| {
                        !prev.text.ends_with(';')
                            && (operator == LeadingOperator::BinaryOnly
                                || !prev.text.ends_with('}'))
                    })
                });
            // A physical newline cannot terminate a try/catch/finally or
            // if/else statement between its clauses. Rejoin only a matching
            // compound statement, preserving the existing source-offset map.
            // The previous logical line's last statement segment, split once
            // per physical line: each check below rescanned the whole
            // previous line (a bundle's statement grows line by line).
            let previous_segments = result
                .last()
                .map(|prev| split_statement_segments(&prev.text));
            let previous_last = previous_segments
                .as_ref()
                .and_then(|segments| segments.last())
                .map(|(_, _, previous)| *previous);
            let block_clause_continues_previous = previous_last.is_some_and(|previous| {
                let previous = strip_leading_labels(previous).trim_end();
                previous.ends_with('}')
                    && (((starts_with_keyword(trimmed_line, "catch")
                        || starts_with_keyword(trimmed_line, "finally"))
                        && starts_with_keyword(previous, "try"))
                        || (starts_with_keyword(trimmed_line, "else")
                            && starts_with_keyword(previous, "if")))
            });
            // A brace on its own line after a statement header (Allman
            // style: `function f(a)\n{`, `if (x)\n{`, `else\n{`) opens that
            // header's body; it is not a new block statement.
            let brace_continues_header = trimmed_line.starts_with('{')
                && previous_last.is_some_and(|previous| {
                    statement_header_awaits_body(strip_leading_labels(previous).trim())
                });
            // The previous statement's last clause as the splitter sees it.
            let previous_clause =
                previous_last.map(|previous| strip_leading_labels(previous).trim());
            // An unbraced body on the line after its header (`if (x)\n  f();`,
            // `for (...)\n  s += i;`, `else\n  g();`, `do\n  i++;`).
            let body_continues_header = !trimmed_line.starts_with('{')
                && previous_clause.is_some_and(statement_header_takes_unbraced_body);
            // `else` on its own line after an unbraced consequent
            // (`if (a) x();\nelse y();`), and a do statement's `while` on its
            // own line (`do\n  i++;\nwhile (c);`).
            let clause_continues_statement = previous_clause.is_some_and(|clause| {
                (starts_with_keyword(trimmed_line, "else") && clause_takes_else(clause))
                    || (starts_with_keyword(trimmed_line, "while")
                        && do_statement_awaits_while(clause))
            });
            // A line STARTING with `(` or `[` continues the expression the
            // previous line ended: no semicolon is inserted before them
            // (ES2020 11.9.1), so `x = f\n(arg)` is a call and webpack's
            // `(function (modules) {...})\n/****/\n([modules])` passes its
            // modules (bd-9vouw.190). Comment-only lines in between are
            // dropped. A previous line ending with `;`, a `}` (a block or a
            // declaration), a keyword that cannot end an expression, or an
            // import/export declaration still ends there.
            let previous_ends_expression = || {
                let comment_lines = result
                    .iter()
                    .rev()
                    .take_while(|line| is_comment_only_line(line))
                    .count();
                result.len() > comment_lines
                    && previous_line_ends_expression(&result[result.len() - 1 - comment_lines].text)
            };
            let paren_continues_previous =
                line_starts_call_or_index(trimmed_line) && previous_ends_expression();
            // So does a line starting with `/` (not a comment): after an
            // expression the goal symbol is InputElementDiv, so it is a
            // division, not a regex starting a new statement. `x = 18\n/\n2`
            // is 18 / 2 and `a\n/g/i` is a / g / i, as Node reads them;
            // both were split into a second statement (bd-9vouw.362).
            let division_continues_previous =
                line_starts_division(trimmed_line) && previous_ends_expression();
            if paren_continues_previous || division_continues_previous {
                while result.last().is_some_and(is_comment_only_line) {
                    result.pop();
                }
            }
            if dot_continues_previous
                || operator_continues_previous
                || block_clause_continues_previous
                || brace_continues_header
                || body_continues_header
                || clause_continues_statement
                || paren_continues_previous
                || division_continues_previous
            {
                let prev = result.pop().expect("checked non-empty above");
                current_text = prev.text;
                current_source_boundaries = prev.source_boundaries;
                let leading = line.len().saturating_sub(trimmed_line.len());
                let trimmed_source_offset = byte_offset.saturating_add(leading);
                append_normalized_separator(
                    &mut current_text,
                    &mut current_source_boundaries,
                    trimmed_source_offset,
                    ' ',
                );
                append_source_fragment(
                    &mut current_text,
                    &mut current_source_boundaries,
                    trimmed_line,
                    trimmed_source_offset,
                );
                current_start_line = prev.start_line;
                last_significant = None;
                trailing_identifier.clear();
            } else {
                current_text.clear();
                current_source_boundaries.clear();
                current_start_line = line_no;
                last_significant = None;
                trailing_identifier.clear();
                append_source_fragment(
                    &mut current_text,
                    &mut current_source_boundaries,
                    line,
                    byte_offset,
                );
            }
        } else {
            if quotes.active() {
                append_source_fragment(
                    &mut current_text,
                    &mut current_source_boundaries,
                    line,
                    byte_offset,
                );
            } else {
                let preserve_leading_whitespace = in_block_comment || in_regex_literal;
                let (fragment, fragment_source_offset) = if preserve_leading_whitespace {
                    (line, byte_offset)
                } else {
                    let fragment = line.trim_start();
                    let leading = line.len().saturating_sub(fragment.len());
                    (fragment, byte_offset.saturating_add(leading))
                };
                let separator =
                    if !preserve_leading_whitespace && open_brackets.last() == Some(&'{') {
                        '\n'
                    } else {
                        ' '
                    };
                append_normalized_separator(
                    &mut current_text,
                    &mut current_source_boundaries,
                    fragment_source_offset,
                    separator,
                );
                append_source_fragment(
                    &mut current_text,
                    &mut current_source_boundaries,
                    fragment,
                    fragment_source_offset,
                );
            }
        }

        // A space or line break ends the identifier being read: the next word
        // is a new one (`k in`, `async function`), not a continuation (`kin`).
        let mut trailing_identifier_closed = true;
        let mut chars = line.chars().peekable();
        while let Some(ch) = chars.next() {
            if in_block_comment {
                if ch == '*' && matches!(chars.peek(), Some('/')) {
                    chars.next();
                    in_block_comment = false;
                }
                continue;
            }
            if quotes.active() {
                quotes.advance_char(ch);
                continue;
            }
            if in_regex_literal {
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
                        // The literal is an operand: a line ending with it
                        // is complete (`var re = /x/\nvar b`, json5's
                        // unicode.js) and a following `/` divides.
                        last_significant = Some(')');
                        trailing_identifier.clear();
                    }
                    _ => {}
                }
                continue;
            }
            match ch {
                '/' => match chars.peek() {
                    Some('/') => break,
                    Some('*') => {
                        chars.next();
                        in_block_comment = true;
                        trailing_identifier_closed = true;
                    }
                    next_char
                        if merge_logical_lines_slash_starts_regex(
                            last_significant,
                            trailing_identifier.as_str(),
                            next_char.copied(),
                        ) =>
                    {
                        in_regex_literal = true;
                        regex_in_char_class = false;
                        escaped = false;
                        trailing_identifier.clear();
                    }
                    // A division operator: a line ending with it continues
                    // (prettier's `m =\n  (a - b) /\n  (c - d);`), which
                    // read `(a - b) /` as a whole statement (bd-9vouw.206).
                    _ => {
                        last_significant = Some('/');
                        trailing_identifier.clear();
                    }
                },
                '\'' | '"' | '`' => {
                    quotes.open_char(ch);
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
                '{' => {
                    brace_depth += 1;
                    open_brackets.push('{');
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
                '}' => {
                    brace_depth -= 1;
                    open_brackets.pop();
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
                '(' => {
                    paren_depth += 1;
                    open_brackets.push('(');
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
                ')' => {
                    paren_depth -= 1;
                    open_brackets.pop();
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
                '[' => {
                    bracket_depth += 1;
                    open_brackets.push('[');
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
                ']' => {
                    bracket_depth -= 1;
                    open_brackets.pop();
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
                ch if ch.is_ascii_whitespace() => trailing_identifier_closed = true,
                ch if ch.is_ascii_alphabetic() || ch == '_' || ch == '$' => {
                    if trailing_identifier_closed {
                        trailing_identifier.clear();
                        trailing_identifier_closed = false;
                    }
                    if trailing_identifier.is_empty() {
                        trailing_identifier_follows_dot = last_significant == Some('.');
                    }
                    trailing_identifier.push(ch);
                    last_significant = Some(ch);
                }
                ch if ch.is_ascii_digit() => {
                    if !trailing_identifier.is_empty() && !trailing_identifier_closed {
                        trailing_identifier.push(ch);
                    } else {
                        trailing_identifier.clear();
                    }
                    last_significant = Some(ch);
                }
                // A decimal point (`1.`, `2.5`) belongs to its number; it is
                // not a member access waiting for a name (bd-9vouw.207).
                '.' if trailing_identifier.is_empty()
                    && last_significant.is_some_and(|c| c.is_ascii_digit()) => {}
                ch => {
                    last_significant = Some(ch);
                    trailing_identifier.clear();
                }
            }
        }

        // Preserve physical line terminators while a quoted token is open.
        // The exact string cooker must distinguish a backslash continuation
        // (which removes the terminator) from a raw ECMAScript line terminator
        // (whose validity depends on the literal grammar).
        if quotes.active() && !line_ending.is_empty() {
            append_source_fragment(
                &mut current_text,
                &mut current_source_boundaries,
                line_ending,
                byte_offset.saturating_add(line.len()),
            );
            quotes.line_break();
        }

        byte_offset = byte_offset.saturating_add(segment.len());

        let balanced = brace_depth <= 0
            && paren_depth <= 0
            && bracket_depth <= 0
            && !quotes.active()
            && !in_block_comment
            && !in_regex_literal;
        if balanced
            && (line_ends_with_update_operator(line)
                || !merge_logical_lines_requires_continuation(
                    last_significant,
                    trailing_identifier.as_str(),
                    trailing_identifier_follows_dot,
                )
                || (trailing_identifier == "let"
                    && !trailing_identifier_follows_dot
                    && ends_with_statement_position_let(&current_text)))
        {
            if let Some(logical_line) = logical_line_from_buffer(
                &current_text,
                &current_source_boundaries,
                current_start_line,
                line_no,
            ) {
                result.push(logical_line);
            }
            brace_depth = 0;
            paren_depth = 0;
            bracket_depth = 0;
            open_brackets.clear();
            escaped = false;
            in_regex_literal = false;
            regex_in_char_class = false;
            last_significant = None;
            trailing_identifier.clear();
            accumulating = false;
        } else {
            accumulating = true;
        }
    }

    if accumulating
        && let Some(logical_line) = logical_line_from_buffer(
            &current_text,
            &current_source_boundaries,
            current_start_line,
            line_count(text),
        )
    {
        result.push(logical_line);
    }

    result
}

/// Native-stack bytes provisioned per unit of the recursion-depth budget, plus
/// a fixed base. The recursion-depth guard only fails closed (a recoverable
/// `ParseError`) if the native stack can actually hold `max_recursion_depth`
/// frames; otherwise the OS aborts the process first. Running the parse (tree,
/// event-IR, and materialization all recurse over the tree) on a dedicated
/// scoped thread sized from the budget makes the guard, not the stack, the
/// enforcement boundary — the franken-core bd-47ae4 recipe ported to the engine
/// parser lane (bd-rucba).
const PARSE_STACK_BYTES_PER_RECURSION_LEVEL: usize = 64 * 1024;
const PARSE_STACK_BASE_BYTES: usize = 4 * 1024 * 1024;

/// Terms of a folded left-associative operator chain charged as one level of
/// the recursion budget (bd-9vouw.85). Measured on a debug frankenctl: a
/// top-level chain of `+`, string, call or product terms overflowed the parse
/// stack above (4 MiB + 256 levels of 64 KiB) at 1,790-1,800 terms, about
/// 5.5 terms per level; 4 keeps the longest admitted chain (~1,000 terms at
/// top level) about 40% below that.
const FOLDED_CHAIN_TERMS_PER_RECURSION_LEVEL: u64 = 4;

/// Run `run` on a scoped thread whose stack is provisioned from the recursion
/// budget, falling back to the caller stack if the thread cannot be spawned
/// (mirrors franken-core; bd-rucba).
fn with_provisioned_parse_stack<T, F>(options: &ParserOptions, run: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    let budget_depth = usize::try_from(options.budget.max_recursion_depth).unwrap_or(usize::MAX);
    let stack_bytes = PARSE_STACK_BASE_BYTES
        .saturating_add(budget_depth.saturating_mul(PARSE_STACK_BYTES_PER_RECURSION_LEVEL));
    run_with_provisioned_stack("franken-engine-parse", stack_bytes, run)
}

/// Run `run` on a scoped thread with a `stack_bytes` native stack, falling
/// back to the caller stack if the thread cannot be spawned (bd-rucba). Shared
/// by the parser and the IR0 lowering, which both recurse over the syntax tree.
pub(crate) fn run_with_provisioned_stack<T, F>(thread_name: &str, stack_bytes: usize, run: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    // The slot lets the closure survive a failed spawn (Builder::spawn_scoped
    // consumes its argument even on error); the mutex is uncontended — only one
    // of the two arms ever takes it.
    let run_slot = std::sync::Mutex::new(Some(run));
    let take_and_run = || {
        (run_slot
            .lock()
            .expect("provisioned-stack closure slot is never poisoned")
            .take()
            .expect("provisioned-stack closure is consumed exactly once"))()
    };
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .name(thread_name.to_string())
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
        source_bytes,
        token_count,
        max_recursion_observed: 0,
        statement_depth: 0,
        pattern_depth: 0,
        strict_mode: goal == ParseGoal::Module,
        super_property_allowed: false,
        await_context: goal == ParseGoal::Module,
        yield_context: false,
        super_call: SuperCallContext::Forbidden,
        static_block_await: false,
        formal_parameters: false,
        private_name_scopes: Vec::new(),
        function_sources: FunctionSourceMap::default(),
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

    let stripped = strip_comments_to_whitespace(text);
    let mut logical_lines = merge_logical_lines(&stripped);
    let source_line_terminators = source_line_terminator_ranges(text);
    let mut statements = Vec::with_capacity(8);
    context.strict_mode |= has_use_strict_directive(&stripped);
    // The engine's own module sources (`franken:util`, `franken:fs`, ...)
    // record no function source text: their functions stand in for
    // built-ins, which print as native code, and their text spells the
    // placeholder names lowering renames (`__franken_util_format`).
    if !source_label.starts_with("franken:") {
        context.function_sources.original = Some(std::sync::Arc::from(text));
        context.function_sources.blanked = Some((stripped.as_ptr() as usize, stripped.len()));
    }

    for logical_line in &mut logical_lines {
        debug_assert_eq!(
            logical_line.byte_offset,
            logical_line.source_offset_at(0) as u64
        );
        debug_assert!(logical_line.start_line <= logical_line.end_line);
        let segments = split_statement_segments(&logical_line.text)
            .into_iter()
            .map(|(start_in_line, end_in_line, statement_text)| {
                let start_offset = logical_line.source_offset_at(start_in_line);
                let end_offset = logical_line.source_offset_at(end_in_line);
                let (start_line, start_column) =
                    source_position_at_offset(start_offset, &source_line_terminators);
                let (end_line, end_column) =
                    source_position_at_offset(end_offset, &source_line_terminators);
                let span = SourceSpan::new(
                    start_offset as u64,
                    end_offset as u64,
                    start_line,
                    start_column,
                    end_line,
                    end_column,
                );
                (statement_text, span)
            })
            .collect::<Vec<_>>();
        context.function_sources.frames.push(SourceFrame {
            text: (logical_line.text.as_ptr() as usize, logical_line.text.len()),
            input: stripped.as_ptr() as usize,
            boundaries: std::mem::take(&mut logical_line.source_boundaries),
        });
        for (statement_text, span) in segments {
            statements.extend(parse_module_statement_segment(
                statement_text,
                goal,
                span,
                &mut context,
            )?);
        }
        context.function_sources.frames.pop();
    }

    if !context.strict_mode {
        apply_annex_b_block_functions(&mut statements, &[]);
    }
    let source_len = to_u64(text.len(), source_label, None)?;
    let (end_line, end_column) = source_end_position(text, source_label)?;
    let span = SourceSpan::new(0, source_len, 1, 1, end_line, end_column);
    Ok(SyntaxTree {
        goal,
        body: statements,
        span,
    })
}

fn parse_module_statement_segment(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<Statement>> {
    if goal == ParseGoal::Module
        && statement.starts_with("export ")
        && let Some(expanded) = parse_named_declaration_export(statement, span.clone(), context)?
    {
        return Ok(expanded);
    }

    Ok(vec![parse_statement(statement, goal, span, context)?])
}

fn parse_named_declaration_export(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Option<Vec<Statement>>> {
    let Some(rest) = statement.strip_prefix("export") else {
        return Ok(None);
    };
    let Some(first) = rest.chars().next() else {
        return Ok(None);
    };
    if !first.is_whitespace() {
        return Ok(None);
    }

    let declaration_text = rest.trim_start();
    if declaration_text.is_empty()
        || declaration_text.starts_with("default")
        || declaration_text.starts_with('{')
        || declaration_text.starts_with('*')
    {
        return Ok(None);
    }

    let declaration_span = span_after_prefix(
        &span,
        statement.len().saturating_sub(declaration_text.len()),
    );
    let declaration = if let Some(kind) = parse_variable_declaration_kind(declaration_text) {
        Statement::VariableDeclaration(parse_variable_declaration(
            declaration_text,
            kind,
            declaration_span,
            context,
        )?)
    } else if starts_named_exportable_declaration(declaration_text) {
        parse_statement(
            declaration_text,
            ParseGoal::Module,
            declaration_span,
            context,
        )?
    } else {
        return Ok(None);
    };

    let export_names = export_names_for_declaration(&declaration, &span, context.source_label)?;
    let clause = format_named_export_clause(&export_names);
    Ok(Some(vec![
        declaration,
        Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause(clause.into()),
            span,
        }),
    ]))
}

fn span_after_prefix(span: &SourceSpan, prefix_len: usize) -> SourceSpan {
    let delta = prefix_len as u64;
    SourceSpan::new(
        span.start_offset.saturating_add(delta),
        span.end_offset,
        span.start_line,
        span.start_column.saturating_add(delta),
        span.end_line,
        span.end_column,
    )
}

fn starts_named_exportable_declaration(statement: &str) -> bool {
    statement.starts_with("function ")
        || statement.starts_with("function*")
        || statement.starts_with("async function ")
        || statement.starts_with("async function*")
        || statement.starts_with("class ")
}

fn export_names_for_declaration(
    declaration: &Statement,
    export_span: &SourceSpan,
    source_label: &str,
) -> ParseResult<Vec<String>> {
    let names: Vec<String> = match declaration {
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
            source_label.to_string(),
            Some(export_span.clone()),
        ));
    }

    Ok(names)
}

fn format_named_export_clause(names: &[String]) -> String {
    format!("{{ {} }}", names.join(", "))
}

fn line_count(source: &str) -> u64 {
    (source_line_terminator_ranges(source).len() as u64).saturating_add(1)
}

fn source_end_position(source: &str, source_label: &str) -> ParseResult<(u64, u64)> {
    let terminators = source_line_terminator_ranges(source);
    let final_line_start = terminators.last().map_or(0, |(_, end)| *end);
    let end_column = to_u64(
        source
            .len()
            .saturating_sub(final_line_start)
            .saturating_add(1),
        source_label,
        None,
    )?;
    Ok(((terminators.len() as u64).saturating_add(1), end_column))
}

/// Strip one or more leading `label:` prefixes from a statement segment,
/// returning the inner statement text. A label is a non-reserved identifier
/// followed by a top-level `:`. Used so the segment splitter recognises a
/// labelled compound statement (`label: for (..) {..}`) as block-terminated.
/// Leaves the input unchanged when there is no leading label (e.g. a ternary
/// `a ? b : c`, whose pre-colon text is not a bare identifier).
fn strip_leading_labels(segment: &str) -> &str {
    let mut seg = segment.trim_start();
    loop {
        let Some(colon_idx) = leading_label_colon(seg) else {
            return seg;
        };
        let label = seg[..colon_idx].trim();
        if is_identifier(label) && !is_unconditional_reserved_keyword(label) {
            seg = seg[colon_idx + 1..].trim_start();
        } else {
            return seg;
        }
    }
}

/// Whether `prefix`, the text before a `{`, ends with a keyword after which
/// an expression starts (`'x' in {}`, `typeof {}`, `return {}`): that brace
/// opens an object literal, which closes no statement (jszip's
/// `s = 'x' in {} ? f : g` in an unbraced consequent). A `.` before the word
/// makes it a property name.
fn ends_with_expression_keyword(prefix: &str) -> bool {
    let trimmed = prefix.trim_end();
    let word_start = trimmed
        .char_indices()
        .rev()
        .take_while(|(_, ch)| is_identifier_continue(*ch))
        .last()
        .map_or(trimmed.len(), |(index, _)| index);
    let word = &trimmed[word_start..];
    matches!(
        word,
        "in" | "instanceof" | "typeof" | "void" | "delete" | "return" | "throw" | "yield" | "await"
    ) && !trimmed[..word_start].trim_end().ends_with('.')
}

/// Whether `prefix`, the text before a `{`, ends with the header of a
/// function expression (`function (a)`, `function* g(a)`, `async function
/// (a)`) whose `function` keyword follows an operator: its body brace closes
/// no statement. jszip's `if (e) r = c ? function () {...} : function () {};
/// else {...}` was split after the first function body.
fn ends_with_function_expression_header(prefix: &str) -> bool {
    let is_identifier_char = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    let prefix = prefix.trim_end();
    if !prefix.ends_with(')') {
        return false;
    }
    let Some(at) = prefix.rfind("function") else {
        return false;
    };
    let (before, after) = (&prefix[..at], &prefix[at + "function".len()..]);
    if before.ends_with(is_identifier_char) {
        return false;
    }
    let mut rest = after.trim_start();
    if let Some(star) = rest.strip_prefix('*') {
        rest = star.trim_start();
    }
    let name_len = rest
        .find(|c: char| !is_identifier_char(c))
        .unwrap_or(rest.len());
    rest = rest[name_len..].trim_start();
    if !rest.starts_with('(')
        || extract_balanced(rest, '(', ')').is_none_or(|(_, tail)| !tail.trim().is_empty())
    {
        return false;
    }
    let mut before = before.trim_end();
    if let Some(stripped) = before
        .strip_suffix("async")
        .filter(|stripped| !stripped.ends_with(is_identifier_char))
    {
        before = stripped.trim_end();
    }
    // A `:` is a conditional's (`c ? f : function () {}`), not a case
    // clause's or a label's, whose function is a declaration.
    let conditional_colon = before.ends_with(':')
        && before.contains('?')
        && !starts_with_keyword(before.trim_start(), "case")
        && !starts_with_keyword(before.trim_start(), "default");
    conditional_colon
        || before.ends_with([
            '=', '?', '(', ',', '[', '!', '&', '|', '+', '-', '*', '%', '>', '<',
        ])
        || (before.ends_with("return")
            && !before[..before.len() - "return".len()].ends_with(is_identifier_char))
}

fn split_statement_segments(line: &str) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::with_capacity(4);
    let mut segment_start = 0usize;
    let mut quotes = QuoteState::default();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    // Where the current outermost `{` group opened.
    let mut outer_brace_open = 0usize;

    for (index, ch) in line.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        // A regex literal's `;` and quotes are pattern text: lodash's
        // `var r = /\b__p \+= '';/g, s = …;` is one statement.
        if ch == '/' && quotes.open_regex_at(line, index) {
            continue;
        }

        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => {
                if brace_depth == 0 {
                    outer_brace_open = index;
                }
                brace_depth = brace_depth.saturating_add(1);
            }
            '}' => {
                let was_positive = brace_depth > 0;
                brace_depth = brace_depth.saturating_sub(1);
                // An object literal or arrow body inside an unbraced body
                // (`if (a) o.x = {}; else ...`, `if (a) f = () => {}`)
                // ends no statement: the `;` after it decides, as it does
                // for any other expression.
                let closes_expression_brace = outer_brace_open >= segment_start
                    && (line[segment_start..outer_brace_open].trim_end().ends_with([
                        '=', '>', ',', '(', '[', '?', '!', '&', '|', '+', '-', '*', '%',
                    ]) || ends_with_function_expression_header(
                        &line[segment_start..outer_brace_open],
                    ) || ends_with_expression_keyword(&line[segment_start..outer_brace_open]));
                // A closing brace that returns to brace_depth==0 may
                // terminate a block-level statement (function decl,
                // if/else, for, while, etc.).  Only split here when the
                // CURRENT segment starts with a block keyword so we
                // don't break function expressions or object literals
                // embedded in larger expressions.
                if was_positive
                    && brace_depth == 0
                    && paren_depth == 0
                    && bracket_depth == 0
                    && !closes_expression_brace
                {
                    let seg = line[segment_start..].trim_start();
                    // A labelled statement (`label: for (..) {..}`) is still a
                    // block-terminated statement, so look past any leading
                    // `label:` prefixes before testing for the block keyword.
                    // Without this, `outer: for(;;){..} rest;` is never split at
                    // the closing brace and the labelled body greedily absorbs
                    // `rest` (bd-t7txt / bd-bg9l1.27.4).
                    let seg_body = strip_leading_labels(seg);
                    let starts_with_block = seg_body.starts_with('{')
                        // A bare or labelled BLOCK statement (`{..}` / `outer:
                        // {..}`) is block-terminated too; without this the closing
                        // brace doesn't split it and a following statement is
                        // greedily absorbed into the (labelled) body, which then
                        // falls through to `Expression::Raw` (bd-rj2yz). At
                        // statement position a leading `{` is always a block —
                        // object literals in expression position carry a non-`{`
                        // prefix (`(`, `let x =`, `return`, …) and are unaffected.
                        || starts_with_keyword(seg_body, "function")
                        // `async function f(){…}` is a block-terminated declaration
                        // too; without this the closing brace doesn't split it and
                        // the following statement is swallowed/dropped (bd-ws5wz).
                        || seg_body.starts_with("async function")
                        || starts_with_keyword(seg_body, "if")
                        || starts_with_keyword(seg_body, "for")
                        || starts_with_keyword(seg_body, "while")
                        // `with (o) { .. } next();` on one line: the body's
                        // brace ends the statement, as for `while`
                        // (bd-9vouw.248). The next statement was glued onto
                        // the with body and failed as an expression.
                        || starts_with_keyword(seg_body, "with")
                        || starts_with_keyword(seg_body, "do")
                        || starts_with_keyword(seg_body, "try")
                        || starts_with_keyword(seg_body, "switch")
                        // A class declaration ends with its body, not with a
                        // braced heritage (`class C extends class {} {}`,
                        // `extends function () {} {}`, bd-9vouw.176).
                        || (starts_with_keyword(seg_body, "class")
                            && class_body_brace(seg_body).is_none_or(|body| {
                                line.len() - seg_body.len() + body == outer_brace_open
                            }))
                        || starts_with_export_block_statement(seg_body);
                    if starts_with_block {
                        let after = index.saturating_add(1);
                        let rest = line[after..].trim_start();
                        // A `while` continues only a do statement still
                        // waiting for its condition (bd-9vouw.90): after
                        // `if (a) {..}` or any other block it starts a new
                        // loop, which was glued onto the if and never ran.
                        let block_statement =
                            strip_leading_labels(line[segment_start..after].trim_start());
                        // `if (a) x = function () {}; else ...`: the `;`
                        // ends the unbraced consequent, not the statement.
                        let semicolon_else = rest
                            .strip_prefix(';')
                            .is_some_and(|after| starts_with_keyword(after.trim_start(), "else"));
                        let continues = starts_with_keyword(rest, "else")
                            || semicolon_else
                            || starts_with_keyword(rest, "catch")
                            || starts_with_keyword(rest, "finally")
                            || (starts_with_keyword(rest, "while")
                                && do_statement_awaits_while(block_statement));
                        if !rest.is_empty() && !continues {
                            push_segment(&mut out, line, segment_start, after);
                            segment_start = after;
                        }
                    }
                }
            }
            ';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                // `if (a) x(); else y();`: an `else` never starts a statement,
                // so this `;` ends the consequent, not the if statement. Same
                // for `do x(); while (c)` before the do statement has its
                // `while`.
                let rest = line[index + ch.len_utf8()..].trim_start();
                let clause = strip_leading_labels(line[segment_start..index].trim_start());
                if starts_with_keyword(rest, "else")
                    || (starts_with_keyword(rest, "while") && do_statement_awaits_while(clause))
                {
                    continue;
                }
                // `while (x);` / `for (...);`: after a header this `;` is the
                // empty statement body, so it stays in the segment. So it does
                // after a bare label (`L: ;`).
                let only_labels =
                    clause.trim().is_empty() && !line[segment_start..index].trim().is_empty();
                let end = if only_labels || statement_header_takes_unbraced_body(clause.trim_end())
                {
                    index.saturating_add(ch.len_utf8())
                } else {
                    index
                };
                push_segment(&mut out, line, segment_start, end);
                segment_start = index.saturating_add(ch.len_utf8());
            }
            _ => {}
        }
    }
    push_segment(&mut out, line, segment_start, line.len());
    out
}

/// Returns true when `text` starts with the keyword `kw` followed by a
/// character that cannot continue an identifier (or end of string), so
/// `forêt` and `let$` are names, not keywords.
fn starts_with_keyword(text: &str, kw: &str) -> bool {
    text.strip_prefix(kw).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|ch| !is_identifier_continue(ch))
    })
}

/// The rest of a class element after the modifier `keyword` (`static`,
/// `async`), or `None` when `keyword` is not a modifier there: it begins a
/// longer name (`statics`) or is the element's own name (`async() {}`,
/// `static = 1`). Minified code puts the element name right after it
/// (`async#k()`, `static*g()`, `async[k]()`); `async` must not be followed by
/// a line break (`async` then `m(){}` on the next line is a field and a
/// method).
fn class_element_modifier<'a>(element: &'a str, keyword: &str, same_line: bool) -> Option<&'a str> {
    let after = element.strip_prefix(keyword)?;
    if after.starts_with(|c: char| c.is_alphanumeric() || matches!(c, '_' | '$' | '\\')) {
        return None;
    }
    let name = after.trim_start();
    let gap = &after[..after.len() - name.len()];
    if same_line && gap.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        return None;
    }
    (!name.is_empty() && !name.starts_with(['(', '=', ';', '}'])).then_some(name)
}

/// The rest of a class element after a `get` / `set` accessor modifier, or
/// `None` when `keyword` is not a modifier there: `get() {}` and `set$(v) {}`
/// are ordinary methods named `get` and `set$` (Map-like classes).
fn class_accessor_prefix<'a>(element: &'a str, keyword: &str) -> Option<&'a str> {
    let after = element.strip_prefix(keyword)?;
    if after.starts_with(|c: char| c.is_alphanumeric() || matches!(c, '_' | '$' | '\\')) {
        return None;
    }
    let after = after.trim_start();
    (!after.starts_with('(')).then_some(after)
}

fn starts_with_export_block_statement(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("export") else {
        return false;
    };
    let Some(first) = rest.chars().next() else {
        return false;
    };
    if !first.is_whitespace() {
        return false;
    }

    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix("default")
        .map(str::trim_start)
        .unwrap_or(rest);
    starts_with_keyword(rest, "function")
        || rest.starts_with("function*")
        || rest.starts_with("async function")
        || starts_with_keyword(rest, "class")
}

fn push_segment<'a>(
    out: &mut Vec<(usize, usize, &'a str)>,
    line: &'a str,
    start: usize,
    end: usize,
) {
    if end < start {
        return;
    }
    let raw = &line[start..end];
    let leading = raw.len().saturating_sub(raw.trim_start().len());
    let trailing = raw.len().saturating_sub(raw.trim_end().len());
    let trimmed_start = start.saturating_add(leading);
    let trimmed_end = end.saturating_sub(trailing);
    if trimmed_end <= trimmed_start {
        return;
    }
    let trimmed = &line[trimmed_start..trimmed_end];
    out.push((trimmed_start, trimmed_end, trimmed));
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
    // The empty statement as a loop / if / label body (`while (x);`,
    // `for (...);`). The AST has no empty-statement node; an empty block
    // behaves identically there.
    if statement.trim() == ";" {
        return Ok(Statement::Block(BlockStatement {
            body: Vec::new(),
            span,
        }));
    }
    if starts_import_declaration(statement) {
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

    if starts_export_declaration(statement) {
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

    if let Some(kind) = parse_variable_declaration_kind(statement)
        && (kind != VariableDeclarationKind::Let
            || context.strict_mode
            || let_starts_lexical_declaration(&statement["let".len()..]))
    {
        return parse_variable_declaration(statement, kind, span, context)
            .map(Statement::VariableDeclaration);
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
        || keyword_followed_by_expression_start(statement, "return")
    {
        return self::parse_return_statement(statement, span, context);
    }
    if statement.starts_with("throw ")
        || statement.starts_with("throw(")
        || keyword_followed_by_expression_start(statement, "throw")
    {
        return self::parse_throw_statement(statement, span, context);
    }
    if statement.starts_with("try ") || statement.starts_with("try{") {
        return self::parse_try_catch_statement(statement, goal, span, context);
    }
    if statement.starts_with("switch ") || statement.starts_with("switch(") {
        return self::parse_switch_statement(statement, goal, span, context);
    }
    if statement == "break" || statement.starts_with("break ") || statement.starts_with("break;") {
        return self::parse_break_statement(statement, span);
    }
    if statement == "continue"
        || statement.starts_with("continue ")
        || statement.starts_with("continue;")
    {
        return self::parse_continue_statement(statement, span);
    }
    if statement.starts_with("function ")
        || statement.starts_with("function*")
        || statement.starts_with("async function ")
        || statement.starts_with("async function*")
    {
        return self::parse_function_declaration(statement, span, context);
    }
    if statement.starts_with("class ") || statement.starts_with("class{") {
        return self::parse_class_declaration(statement, span, context);
    }
    if statement.starts_with("with ") || statement.starts_with("with(") {
        return self::parse_with_statement(statement, span, context);
    }
    if statement.starts_with('{') && statement.ends_with('}') {
        return self::parse_block_statement(statement, goal, span, context);
    }

    // Labelled statement: `label: <statement>` (§14.13). Detect an
    // identifier immediately followed by `:`. Object literals are blocks at
    // statement position (handled above), and conditional expressions place
    // a `?` before the `:`, so an identifier-only prefix is unambiguous. The
    // label must be a real IdentifierReference — reserved words are rejected.
    if let Some(colon_idx) = leading_label_colon(statement) {
        let label = statement[..colon_idx].trim();
        if is_identifier(label) && !is_unconditional_reserved_keyword(label) {
            // ES2020 13.1.1: `yield` is not a label inside a generator or in
            // strict code, nor `await` inside an async function or a module,
            // however it is spelled (`yield`).
            let name = decode_identifier_escapes(label);
            let name = name.as_deref().unwrap_or(label);
            if (name == "yield" && (context.yield_context || context.strict_mode))
                || (name == "await"
                    && (context.await_context
                        || context.static_block_await
                        || goal == ParseGoal::Module))
            {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    format!("`{name}` cannot be a label here"),
                    context.source_label.to_string(),
                    Some(span),
                ));
            }
            let body_src = statement[colon_idx + 1..].trim();
            if body_src.is_empty() {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "labelled statement is missing its body",
                    context.source_label.to_string(),
                    Some(span),
                ));
            }
            reject_declaration_in_statement_position(
                body_src,
                StatementPosition::Labelled,
                &span,
                context,
            )?;
            let body = parse_statement(body_src, goal, span.clone(), context)?;
            return Ok(Statement::Labeled(LabeledStatement {
                label: label.to_string(),
                body: Box::new(body),
                span,
            }));
        }
    }

    // TypeScript's and babel's CommonJS export preamble, `exports.a =
    // exports.b = ... = void 0;`, one link per export (bd-9vouw.232): as one
    // right-nested assignment it cost a parser recursion level and a register
    // per link (refused past 255 links, a register overflow past ~200). Its
    // stores run innermost first with a constant value and side-effect-free
    // targets, so separate assignments in that order are the same program.
    if let Some(targets) = export_void_chain_targets(statement)
        && targets.len() > 1
    {
        let mut body = Vec::with_capacity(targets.len());
        for target in targets.iter().rev() {
            let expression = parse_expression(&format!("{target} = void 0"), &span, context, 1)?;
            body.push(Statement::Expression(ExpressionStatement {
                expression,
                span: span.clone(),
            }));
        }
        return Ok(Statement::Block(BlockStatement { body, span }));
    }

    // A bare expression statement may be a top-level comma sequence (`a, b`);
    // ES2020 §14.5 ExpressionStatement is an Expression, which includes the
    // comma operator. Declarations (`let a = 1, b = 2`) are handled earlier, so
    // any comma reaching here is a genuine sequence (bd-j4l7k).
    let expression = parse_expression_allowing_sequence(statement, &span, context, 1)?;
    Ok(Statement::Expression(ExpressionStatement {
        expression,
        span,
    }))
}

/// The targets, outermost first, of a statement `T1 = T2 = ... = void 0`
/// whose every target is `exports.<name>`, `module.exports.<name>` or
/// `this.<name>` (an ASCII identifier name, no spaces), bd-9vouw.232.
fn export_void_chain_targets(statement: &str) -> Option<Vec<&str>> {
    fn take_target(text: &str) -> Option<(&str, &str)> {
        let after_base = ["module.exports.", "exports.", "this."]
            .iter()
            .find_map(|base| text.strip_prefix(base))?;
        let name_len = after_base
            .bytes()
            .take_while(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
            .count();
        let starts_identifier = after_base
            .bytes()
            .next()
            .is_some_and(|byte| !byte.is_ascii_digit());
        if name_len == 0 || !starts_identifier {
            return None;
        }
        let end = text.len() - after_base.len() + name_len;
        Some((&text[..end], &text[end..]))
    }
    let trimmed = statement.trim();
    let mut rest = trimmed.strip_suffix(';').unwrap_or(trimmed).trim_end();
    let mut targets = Vec::new();
    loop {
        let (target, after) = take_target(rest)?;
        let after = after.trim_start().strip_prefix('=')?;
        if after.starts_with(['=', '>']) {
            return None;
        }
        targets.push(target);
        rest = after.trim_start();
        if let Some(operand) = rest.strip_prefix("void")
            && operand.starts_with(char::is_whitespace)
            && operand.trim() == "0"
        {
            return Some(targets);
        }
    }
}

/// `import` begins a declaration when followed by whitespace, `{`, `*` or a
/// quote. Minified code drops the space (`import{a}from'x'`,
/// `import*as m from'x'`, `import'x'`); `import(...)` and `import.meta` are
/// expressions even with a space before the `(` or `.`.
fn starts_import_declaration(statement: &str) -> bool {
    let Some(rest) = statement.strip_prefix("import") else {
        return false;
    };
    let Some(next) = rest.chars().next() else {
        return true;
    };
    if matches!(next, '{' | '*' | '"' | '\'') {
        return true;
    }
    next.is_whitespace() && !rest.trim_start().starts_with(['(', '.'])
}

/// `export` begins a declaration when followed by whitespace, `{` or `*`
/// (minified `export{a as b}`, `export*from'x'`).
fn starts_export_declaration(statement: &str) -> bool {
    let Some(rest) = statement.strip_prefix("export") else {
        return false;
    };
    rest.chars()
        .next()
        .is_none_or(|next| next.is_whitespace() || matches!(next, '{' | '*'))
}

/// Split `<binding-clause> from <quoted-source>` at the `from` that
/// introduces the source: the last `from` that does not continue an
/// identifier, has a non-empty clause before it, and is followed by a quote.
/// Minified code omits the spaces around it (`{a}from'x'`, `*as m from"x"`);
/// `import from from 'x'` and `import{from}from'x'` keep their bindings.
fn split_import_from(body: &str) -> Option<(&str, &str)> {
    body.rmatch_indices("from").find_map(|(index, _)| {
        let clause = &body[..index];
        let source = body[index + "from".len()..].trim_start();
        let keyword_starts = clause
            .chars()
            .next_back()
            .is_none_or(|ch| !is_identifier_continue(ch));
        (keyword_starts && !clause.trim().is_empty() && source.starts_with(['"', '\'']))
            .then_some((clause, source))
    })
}

fn parse_import(
    statement: &str,
    source_label: &str,
    span: SourceSpan,
) -> ParseResult<ImportDeclaration> {
    let body = statement
        .strip_prefix("import")
        .map(str::trim)
        .unwrap_or("");
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

    let (binding_raw, source_raw) = split_import_from(body).ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import declaration must be `import <binding-clause> from <quoted-source>` or `import <quoted-source>`",
            source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    let clause = parse_import_binding_clause(binding_raw.trim(), source_label, &span)?;
    let source = parse_quoted_string(source_raw.trim()).ok_or_else(|| {
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

fn parse_import_binding_clause(
    binding_clause: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<ImportClause> {
    if binding_clause.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "import declaration is missing binding clause",
            source_label.to_string(),
            Some(span.clone()),
        ));
    }

    if is_module_binding_identifier(binding_clause) {
        return Ok(ImportClause::Default {
            local: binding_clause.to_string(),
        });
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

    if let Some((default_binding_raw, trailing_clause_raw)) = binding_clause.split_once(',') {
        let default_binding = default_binding_raw.trim();
        let trailing_clause = trailing_clause_raw.trim();

        if !is_module_binding_identifier(default_binding) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "default import binding must be a non-keyword identifier",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }

        if let Some(namespace_binding) = parse_namespace_import_binding(trailing_clause) {
            return Ok(ImportClause::DefaultAndNamespace {
                default: default_binding.to_string(),
                namespace: namespace_binding,
            });
        }

        if is_named_import_clause(trailing_clause) {
            let specifiers = parse_named_import_specifiers(trailing_clause, source_label, span)?;
            return Ok(ImportClause::DefaultAndNamed {
                default: default_binding.to_string(),
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

/// A named import or export list (the text between the braces) without its
/// one permitted trailing comma (ES2020 15.2.2 NamedImports, 15.2.3
/// ExportClause): prettier ends every multi-line list with one (`import {\n
/// a,\n b,\n} from`), which read as an empty entry (date-fns 4, superjson,
/// bd-9vouw.218). A list that is only a comma keeps it and stays an error.
fn without_trailing_specifier_comma(list: &str) -> &str {
    match list.trim_end().strip_suffix(',') {
        Some(rest) if !rest.trim().is_empty() => rest,
        _ => list,
    }
}

fn parse_namespace_import_binding(clause: &str) -> Option<String> {
    let rest = clause.strip_prefix('*')?.trim_start();
    let rest = rest.strip_prefix("as")?.trim_start();
    if is_module_binding_identifier(rest) {
        Some(rest.to_string())
    } else {
        None
    }
}

fn is_named_import_clause(clause: &str) -> bool {
    let clause = clause.trim();
    let Some(inner) = clause
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
    else {
        return false;
    };

    let inner = inner.trim();
    if inner.is_empty() {
        return true;
    }

    for specifier in without_trailing_specifier_comma(inner).split(',') {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return false;
        }

        let mut parts = specifier.split_whitespace();
        // SAFETY: specifier is non-empty after early return check above
        let first = parts.next().expect("serde serialization should succeed");
        let second = parts.next();
        let third = parts.next();
        let fourth = parts.next();

        let is_valid = match (second, third, fourth) {
            (None, None, None) => is_module_binding_identifier(first),
            (Some("as"), Some(local), None) => {
                is_identifier(first) && is_module_binding_identifier(local)
            }
            _ => false,
        };

        if !is_valid {
            return false;
        }
    }

    true
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

    let inner = inner.trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }

    let mut specifiers = Vec::with_capacity(4);
    let mut seen_local = BTreeSet::new();

    for specifier in without_trailing_specifier_comma(inner).split(',') {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named import specifier list contains an empty entry",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }

        let mut parts = specifier.split_whitespace();
        // SAFETY: specifier is non-empty after early return check above
        let import_name = parts.next().expect("serde serialization should succeed");
        let second = parts.next();
        let third = parts.next();
        let fourth = parts.next();

        let (import_name, local_name) = match (second, third, fourth) {
            (None, None, None) => (import_name, import_name),
            (Some("as"), Some(local), None) => (import_name, local),
            _ => {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "unsupported named import specifier; expected `name` or `name as alias`",
                    source_label.to_string(),
                    Some(span.clone()),
                ));
            }
        };

        if !is_identifier(import_name) || !is_identifier(local_name) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named import specifier must use identifiers",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }

        if !seen_local.insert(local_name.to_string()) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "import binding has already been declared",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }

        specifiers.push(ImportSpecifier {
            import_name: import_name.to_string(),
            local_name: local_name.to_string(),
        });
    }

    Ok(specifiers)
}

fn parse_export(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<ExportDeclaration> {
    let body = statement
        .strip_prefix("export")
        .map(str::trim)
        .unwrap_or("");
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "export declaration is missing clause",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    // `default` ends at the first non-identifier character: minified code
    // writes `export default{...}` and `export default(...)`.
    let default_expr = body.strip_prefix("default").filter(|rest| {
        rest.chars()
            .next()
            .is_some_and(|next| !is_identifier_continue(next))
    });
    let kind = if let Some(default_expr) = default_expr {
        ExportKind::Default(parse_expression(default_expr.trim(), &span, context, 1)?)
    } else if let Some(star) = body.strip_prefix('*') {
        ExportKind::NamedClause(parse_star_export_clause(star, context.source_label, &span)?)
    } else {
        ExportKind::NamedClause(parse_named_export_clause(
            body,
            context.source_label,
            &span,
        )?)
    };
    Ok(ExportDeclaration { kind, span })
}

/// `export * from 'm'` and `export * as ns from 'm'` (bd-332pq), minified too
/// (`export*from'm'`). `rest` follows the `*`. The declaration is carried as
/// a named clause whose head is `*` or `* as ns` and whose source is `m`: the
/// lowering re-exports every name of `m` except `default`, or binds `ns` to
/// `m`'s namespace object.
fn parse_star_export_clause(
    rest: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<NamedExportClause> {
    let error = |message: &str| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            message,
            source_label.to_string(),
            Some(span.clone()),
        )
    };
    let rest = rest.trim_start();
    let (head, after_head) = match rest
        .strip_prefix("as")
        .filter(|tail| tail.starts_with(char::is_whitespace))
    {
        Some(tail) => {
            let tail = tail.trim_start();
            let alias_len = tail
                .find(|ch: char| !is_identifier_continue(ch))
                .unwrap_or(tail.len());
            let alias = &tail[..alias_len];
            if !alias.chars().next().is_some_and(is_identifier_start) {
                return Err(error("`export * as` needs an export name"));
            }
            (format!("* as {alias}"), &tail[alias_len..])
        }
        None => ("*".to_string(), rest),
    };
    let source_raw = after_head
        .trim_start()
        .strip_prefix("from")
        .map(str::trim_start)
        .filter(|source| source.starts_with(['"', '\'']))
        .ok_or_else(|| {
            error(
                "star export must be `export * from <quoted-source>` or `export * as <name> from <quoted-source>`",
            )
        })?;
    let source =
        parse_quoted_string(source_raw).ok_or_else(|| error("export source must be quoted"))?;
    Ok(NamedExportClause::new(head, Some(source)))
}

fn parse_named_export_clause(
    clause: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<NamedExportClause> {
    let clause = clause.trim();
    let Some(inner_and_trailing) = clause.strip_prefix('{') else {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named export clause must start with `{`",
            source_label.to_string(),
            Some(span.clone()),
        ));
    };

    let Some(close_index) = inner_and_trailing.find('}') else {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "named export clause is missing `}`",
            source_label.to_string(),
            Some(span.clone()),
        ));
    };

    let specifiers = &inner_and_trailing[..close_index];
    validate_named_export_specifiers(specifiers, source_label, span)?;

    let without_comma = without_trailing_specifier_comma(specifiers);
    let canonical_head = if without_comma.len() == specifiers.len() {
        canonicalize_whitespace(&clause[..close_index + 2])
    } else {
        canonicalize_whitespace(&format!("{{{without_comma}}}"))
    };
    let trailing = inner_and_trailing[close_index + 1..].trim();
    let source = if !trailing.is_empty() {
        let Some(source_raw) = trailing.strip_prefix("from").map(str::trim_start) else {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named export trailing clause must be `from <quoted-source>`",
                source_label.to_string(),
                Some(span.clone()),
            ));
        };

        Some(parse_quoted_string(source_raw).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "export source must be quoted",
                source_label.to_string(),
                Some(span.clone()),
            )
        })?)
    } else {
        None
    };

    Ok(NamedExportClause::new(canonical_head, source))
}

fn validate_named_export_specifiers(
    specifiers: &str,
    source_label: &str,
    span: &SourceSpan,
) -> ParseResult<()> {
    let specifiers = specifiers.trim();
    if specifiers.is_empty() {
        return Ok(());
    }

    for specifier in without_trailing_specifier_comma(specifiers).split(',') {
        let specifier = specifier.trim();
        if specifier.is_empty() {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named export specifier list contains an empty entry",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }

        let mut parts = specifier.split_whitespace();
        // SAFETY: specifier is non-empty after early return check above
        let local = parts.next().expect("serde serialization should succeed");
        let second = parts.next();
        let third = parts.next();
        let fourth = parts.next();

        let valid = match (second, third, fourth) {
            (None, None, None) => is_identifier(local),
            (Some("as"), Some(exported), None) => is_identifier(local) && is_identifier(exported),
            _ => false,
        };

        if !valid {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "unsupported named export specifier; expected `name` or `name as alias`",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Binding pattern parser (destructuring)
// ---------------------------------------------------------------------------

/// Parse a binding pattern: identifier, `{ ... }` object, or `[ ... ]` array.
fn parse_binding_pattern(
    source: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<BindingPattern> {
    // Guard against stack overflow from deeply nested destructuring patterns
    // (`[[[...]]]`, `{a:{b:{c:...}}}`). Their recursive descent is separate from
    // the statement/expression depth guards, so without this a deeply nested
    // pattern would overflow the native stack and abort the process rather than
    // surface a recoverable budget error (bd-c4lhp).
    context.pattern_depth += 1;
    if context.pattern_depth > context.options.budget.max_recursion_depth {
        context.pattern_depth -= 1;
        return Err(ParseError::new(
            ParseErrorCode::BudgetExceeded,
            format!(
                "binding-pattern nesting budget exceeded: depth={} max={}",
                context.options.budget.max_recursion_depth,
                context.options.budget.max_recursion_depth
            ),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    let result = parse_binding_pattern_inner(source, span, context);
    context.pattern_depth -= 1;
    result
}

fn parse_binding_pattern_inner(
    source: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<BindingPattern> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            "empty binding pattern",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    // Rest element: `...pattern`
    if let Some(rest_source) = trimmed.strip_prefix("...") {
        let inner = parse_binding_pattern(rest_source, span, context)?;
        // ES2020 13.3.3 / 14.1: a rest element or rest parameter has no
        // initializer (`[...x = 1]`, `(...args = [])`).
        if matches!(inner, BindingPattern::AssignmentPattern { .. }) {
            return Err(ParseError::new(
                ParseErrorCode::InvalidSyntax,
                "a rest element cannot have an initializer",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        return Ok(BindingPattern::Rest(Box::new(inner)));
    }

    // Default value: `pattern = expr` (only at top level of a pattern element)
    // We need to be careful not to match `=` inside nested patterns.
    if let Some(eq_pos) = find_top_level_eq(trimmed) {
        let left_src = trimmed[..eq_pos].trim();
        let right_src = trimmed[eq_pos + 1..].trim();
        if !left_src.is_empty() && !right_src.is_empty() {
            let left = parse_binding_pattern(left_src, span, context)?;
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
        return parse_object_binding_pattern(inner.trim(), span, context);
    }

    // Array pattern: `[ ... ]`
    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        let inner = &trimmed[1..trimmed.len() - 1];
        return parse_array_binding_pattern(inner.trim(), span, context);
    }

    // Simple identifier binding. Reject reserved words like `return`, `function`,
    // `class` — using them as a binding name (e.g. `var return = 1;`) is invalid
    // ES2020 syntax regardless of strict/sloppy mode (bd-wa01t).
    if is_identifier(trimmed) {
        if is_unconditional_reserved_keyword(trimmed) {
            return Err(ParseError::new(
                ParseErrorCode::InvalidSyntax,
                format!("`{trimmed}` is a reserved word and cannot be used as a binding name"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        let name = canonicalize_identifier(trimmed);
        // A reserved word spelled with a unicode escape is still reserved
        // (ES2020 11.6.2): `var` with an escaped `case` is a SyntaxError.
        if is_unconditional_reserved_keyword(&name) {
            return Err(ParseError::new(
                ParseErrorCode::InvalidSyntax,
                format!("keyword `{name}` must not contain escaped characters"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        reject_strict_restricted_binding(&name, context.strict_mode, span, context)?;
        reject_context_reserved_binding(&name, span, context)?;
        return Ok(BindingPattern::Identifier(name));
    }

    Err(ParseError::new(
        ParseErrorCode::UnsupportedSyntax,
        format!("unsupported binding pattern: `{trimmed}`"),
        context.source_label.to_string(),
        Some(span.clone()),
    ))
}

/// Find `=` at the top level (not inside brackets, parens, braces, or strings).
fn find_top_level_eq(source: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quotes = QuoteState::default();

    for (i, ch) in source.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if ch == '/' && quotes.open_regex_at(source, i) {
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => {
                // Skip `==` and `=>`
                let next = source.as_bytes().get(i + 1).copied();
                let prev = if i > 0 {
                    source.as_bytes().get(i - 1).copied()
                } else {
                    None
                };
                if next != Some(b'=') && next != Some(b'>') {
                    // Skip `!=`, `<=`, `>=`, `+=`, etc.
                    let is_compound = matches!(
                        prev,
                        Some(
                            b'<' | b'>'
                                | b'!'
                                | b'='
                                | b'+'
                                | b'-'
                                | b'*'
                                | b'/'
                                | b'%'
                                | b'&'
                                | b'|'
                                | b'^'
                                | b'~'
                        )
                    );
                    if !is_compound {
                        return Some(i);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Parse object destructuring pattern contents (inside `{ ... }`).
fn parse_object_binding_pattern(
    inner: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<BindingPattern> {
    if inner.is_empty() {
        return Ok(BindingPattern::ObjectPattern(Vec::new()));
    }

    let segments = split_pattern_elements(inner);
    let mut properties = Vec::with_capacity(segments.len());
    let mut seen_rest = false;

    for segment in &segments {
        let seg = segment.trim();

        if seen_rest {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "rest element must be the absolute last property in object pattern (no trailing commas allowed)",
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }

        if seg.is_empty() {
            continue;
        }

        // Rest element in object pattern: `...rest`
        if let Some(rest_src) = seg.strip_prefix("...") {
            seen_rest = true;
            let inner_pat = parse_binding_pattern(rest_src.trim(), span, context)?;
            properties.push(ObjectPatternProperty {
                key: Expression::Identifier(rest_src.trim().to_string()),
                value: BindingPattern::Rest(Box::new(inner_pat)),
                computed: false,
                shorthand: false,
            });
            continue;
        }

        // Computed key: `[expr]: pattern`
        if seg.starts_with('[')
            && let Some(bracket_end) = seg.find(']')
        {
            let key_src = &seg[1..bracket_end];
            let after_bracket = seg[bracket_end + 1..].trim();
            if let Some(value_src) = after_bracket.strip_prefix(':') {
                let key = parse_expression(key_src.trim(), span, context, 1)?;
                let value = parse_binding_pattern(value_src.trim(), span, context)?;
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
        if let Some(colon_pos) = find_top_level_colon_in_pattern(seg) {
            let key_src = seg[..colon_pos].trim();
            let value_src = seg[colon_pos + 1..].trim();
            let key = parse_contextual_static_property_key(
                key_src,
                span,
                context,
                legacy_decimal_escape_mode(context),
                "object-binding",
            )?;
            let value = parse_binding_pattern(value_src, span, context)?;
            properties.push(ObjectPatternProperty {
                key,
                value,
                computed: false,
                shorthand: false,
            });
        } else {
            // Shorthand: `x` or `x = default`
            let value = parse_binding_pattern(seg, span, context)?;
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

    Ok(BindingPattern::ObjectPattern(properties))
}

fn parse_contextual_static_property_key(
    source: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
    legacy_mode: LegacyDecimalEscapeMode,
    construct: &str,
) -> ParseResult<Expression> {
    if matches!(source.as_bytes().first(), Some(b'\'' | b'"')) {
        return parse_quoted_expression_string(source, legacy_mode)
            .map(Expression::StringLiteral)
            .ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    format!("invalid quoted {construct} property key: `{source}`"),
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            });
    }
    // A NumericLiteral key names ToString of its value, as an object
    // literal's does: `get 0b10() {}` defines "2", `static 1E+9 = v`
    // "1000000000", `.1() {}` "0.1", `{ 0x10: a } = o` reads "16"
    // (bd-9vouw.228). Lowering canonicalizes the literal node.
    if source.starts_with(|ch: char| ch.is_ascii_digit() || ch == '.') {
        if let Some(value) = parse_bigint_numeric_literal(source) {
            return Ok(Expression::BigIntLiteral(value));
        }
        if let Some(value) = parse_i64_numeric_literal(source) {
            return Ok(Expression::NumericLiteral(value));
        }
        if let Some(value) = parse_f64_numeric_literal(source) {
            return Ok(Expression::FloatLiteral(value.to_bits()));
        }
    }
    // `\u` escapes in an IdentifierName key denote the same property name as
    // the characters they spell (`{ \u0061: 1 }.a`, ES2020 11.6).
    Ok(Expression::Identifier(canonicalize_identifier(source)))
}

/// Find `:` at the top level of a pattern element.
fn find_top_level_colon_in_pattern(source: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quotes = QuoteState::default();

    for (i, ch) in source.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if ch == '/' && quotes.open_regex_at(source, i) {
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => return Some(i),
            // A property key never holds a top-level `=`: from here on is a
            // shorthand's default, whose `?:` colon is not the key's
            // (`{ end = size ? size - 1 : null }`, undici, bd-9vouw.215).
            '=' if depth == 0 => return None,
            _ => {}
        }
    }
    None
}

/// Parse array destructuring pattern contents (inside `[ ... ]`).
fn parse_array_binding_pattern(
    inner: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<BindingPattern> {
    if inner.is_empty() {
        return Ok(BindingPattern::ArrayPattern(Vec::new()));
    }

    let segments = split_pattern_elements(inner);
    let mut elements = Vec::with_capacity(segments.len());

    for segment in &segments {
        let seg = segment.trim();
        if seg.is_empty() {
            elements.push(None); // hole
        } else {
            elements.push(Some(parse_binding_pattern(seg, span, context)?));
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
        if pos != elements.len() - 1 {
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
fn split_pattern_elements(source: &str) -> Vec<&str> {
    let mut out = Vec::with_capacity(4);
    let mut start = 0;
    let mut depth = 0usize;
    let mut quotes = QuoteState::default();

    for (i, ch) in source.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if ch == '/' && quotes.open_regex_at(source, i) {
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(&source[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&source[start..]);
    if let Some(last) = out.last()
        && last.trim().is_empty()
        && source.trim_end().ends_with(',')
    {
        out.pop();
    }
    out
}

fn parse_variable_declaration_kind(statement: &str) -> Option<VariableDeclarationKind> {
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
        // SAFETY: rest is non-empty after early return check above
        let next_char = rest
            .chars()
            .next()
            .expect("serde serialization should succeed");
        if next_char.is_whitespace() || next_char == '[' || next_char == '{' {
            return Some(kind);
        }
    }
    None
}

/// ES2020 13.3.1: `let` starts a lexical declaration only before a binding
/// identifier or pattern. Before anything else sloppy code reads it as an
/// identifier (`let = 1`, the body `let` of `if (a) let;`).
fn let_starts_lexical_declaration(after_let: &str) -> bool {
    after_let.trim_start().chars().next().is_some_and(|ch| {
        ch == '[' || ch == '{' || ch == '_' || ch == '$' || ch == '\\' || ch.is_alphabetic()
    })
}

fn parse_variable_declaration(
    statement: &str,
    kind: VariableDeclarationKind,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<VariableDeclaration> {
    let keyword = kind.as_str();
    // SAFETY: strip_prefix cannot fail as caller validated keyword match
    let body = statement
        .strip_prefix(keyword)
        .map(str::trim_start)
        .expect("serde serialization should succeed");
    if body.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            format!("{keyword} declaration must include at least one binding"),
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let declarator_segments = split_var_declarator_segments(body);
    if declarator_segments.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            format!("{keyword} declaration must include at least one binding"),
            context.source_label.to_string(),
            Some(span),
        ));
    }

    let mut declarations = Vec::with_capacity(declarator_segments.len());
    for declarator in declarator_segments {
        let (name_raw, initializer_raw) = split_var_declarator_assignment(declarator);
        let name = name_raw.trim();
        let pattern = parse_binding_pattern(name, &span, context)?;
        reject_let_lexical_binding(&pattern, kind, &span, context)?;

        let initializer = match initializer_raw {
            Some(initializer_source) => {
                let initializer_source = initializer_source.trim();
                if initializer_source.is_empty() {
                    return Err(ParseError::new(
                        ParseErrorCode::InvalidSyntax,
                        format!("{keyword} initializer expression is empty"),
                        context.source_label.to_string(),
                        Some(span.clone()),
                    ));
                }
                Some(parse_expression(initializer_source, &span, context, 1)?)
            }
            None if kind == VariableDeclarationKind::Const => {
                return Err(ParseError::new(
                    ParseErrorCode::InvalidSyntax,
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

fn split_var_declarator_segments(source: &str) -> Vec<&str> {
    // Shares the top-level comma splitter, so string and regex literals
    // (`var r = /,/, n = 2;`) never split a declarator.
    split_top_level_commas(source)
        .into_iter()
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn split_var_declarator_assignment(segment: &str) -> (&str, Option<&str>) {
    let mut in_quote: Option<char> = None;
    let mut escaped = false;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;

    for (index, ch) in segment.char_indices() {
        if let Some(quote) = in_quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == quote {
                in_quote = None;
            }
            continue;
        }

        match ch {
            '\'' | '"' => in_quote = Some(ch),
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '=' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                let prev = segment[..index].chars().next_back();
                let next = segment[index.saturating_add(ch.len_utf8())..]
                    .chars()
                    .next();
                let part_of_comparison =
                    matches!(prev, Some('=') | Some('!') | Some('<') | Some('>'))
                        || matches!(next, Some('='));
                if part_of_comparison {
                    continue;
                }
                let rhs_start = index.saturating_add(ch.len_utf8());
                return (&segment[..index], Some(&segment[rhs_start..]));
            }
            _ => {}
        }
    }

    (segment, None)
}

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

    let expression = strip_trailing_line_comment(expression.trim()).trim();
    if expression.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            "empty expression statement",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    // Spread element `...AssignmentExpression` (ES2020 12.2.5): the spread
    // owns the whole element, so it is taken before the arrow, assignment,
    // conditional and binary splits. After them, `[...a ?? [], 1]` and
    // `[...c ? x : y]` became a `??` or `?:` whose operand was the spread,
    // and the array held the operand's value instead of its elements.
    if let Some(rest) = expression.strip_prefix("...") {
        let inner = parse_expression(rest.trim_start(), span, context, recursion_depth + 1)?;
        return Ok(Expression::SpreadElement(Box::new(inner)));
    }

    // Arrow function: lowest precedence (lower than assignment).
    if let Some(result) = try_parse_arrow_function(expression, span, context, recursion_depth) {
        return result;
    }

    // Try assignment first (lowest precedence apart from comma).
    if let Some(result) = try_parse_assignment(expression, span, context, recursion_depth) {
        return result;
    }

    // Try ternary conditional: expr ? expr : expr
    if let Some(result) = try_parse_conditional(expression, span, context, recursion_depth) {
        return result;
    }

    // Regex literal must win before binary operator scanning or `/.../` gets
    // misclassified as a divide expression. A leading regex literal may also
    // be the receiver for a postfix chain, e.g. `/ab/.test("xabz")`.
    if let Some((end, pattern, flags)) = leading_regexp_literal(expression) {
        let tail = expression[end..].trim_start();
        if tail.is_empty() {
            return regexp_literal_expression(pattern, flags, span, context);
        }
        // A top-level binary operator after the chain binds looser than it
        // (`/ab/.source || []`, `/a/.source + [1]`); the binary scanner skips
        // regex literals. Taken as one postfix chain, the trailing `[...]`
        // made `/ab/.source ||` a computed member's object.
        if let Some(result) = try_parse_binary(expression, span, context, recursion_depth) {
            return result;
        }
        if (tail.starts_with('.') || tail.starts_with('[') || tail.starts_with('('))
            && let Some(result) = try_parse_postfix(expression, span, context, recursion_depth)
        {
            return result;
        }
    }

    // Update expressions (`++x`, `--x`, `x++`, `x--`): must precede binary
    // scanning, which would otherwise mis-split `i++` into `i + +` and silently
    // drop the write-back entirely (bd-um9a3).
    if let Some(result) = try_parse_update(expression, span, context, recursion_depth) {
        return result;
    }

    // `yield` / `await` bind looser than every binary operator: their operand is
    // a full AssignmentExpression, so `yield 1 + 1` is `yield (1 + 1)`, never
    // `(yield 1) + 1`. Handle them before binary scanning, which would otherwise
    // split `yield 1+1` at the `+` and leave the generator yielding the first
    // operand (bd-hoplz bug #2). The prefix tests mirror the yield/await arms in
    // `parse_primary_expression`, which performs the actual parse.
    let yields_assignment_expr = expression.strip_prefix("yield").is_some_and(|rest| {
        rest.is_empty()
            || rest.starts_with(' ')
            || rest.starts_with('*')
            || rest.starts_with(';')
            || rest.starts_with(')')
            || rest.starts_with('}')
    });
    let awaits_unary_expr = expression
        .strip_prefix("await")
        .is_some_and(|rest| rest.starts_with(' ') || rest.starts_with('('));
    if yields_assignment_expr || awaits_unary_expr {
        return parse_primary_expression(expression, span, context, recursion_depth);
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

/// Parse a primary (atomic) expression — literals, identifiers, grouping, etc.
fn parse_primary_expression(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let expression = expression.trim();

    // ES2022: a private name is an operand only in `o.#x` and `#x in o`.
    if whole_private_name(expression).is_some() {
        return Err(unsupported_expression_syntax_error(
            "a private name is only valid in `o.#x` or `#x in o`",
            span,
            context,
        ));
    }

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
        return regexp_literal_expression(pattern, flags, span, context);
    }

    if let Some(value) = parse_bigint_numeric_literal(expression) {
        return Ok(Expression::BigIntLiteral(value));
    }
    // A numeric literal with the BigInt suffix that is not a BigInt literal
    // (`0e0n`, `1.5n`, `.5n`) is a SyntaxError (ES2020 11.8.3); it was
    // evaluated as some other expression.
    if is_malformed_bigint_literal(expression) {
        return Err(unsupported_expression_syntax_error(
            "invalid BigInt literal: no fraction or exponent is allowed",
            span,
            context,
        ));
    }

    if let Some(value) = parse_i64_numeric_literal(expression) {
        // Signed integer spellings are folded here rather than passing through
        // UnaryNeg. Integer zero cannot retain a sign: keep -0 (also -0x0,
        // -0o0 and -0b0) in the floating-point literal representation.
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
    if expression == "undefined" {
        return Ok(Expression::UndefinedLiteral);
    }
    if expression == "this" {
        return Ok(if context.strict_mode {
            Expression::This
        } else {
            Expression::SloppyThis
        });
    }
    if expression == "super" {
        return Err(unsupported_expression_syntax_error(
            "super expressions are not supported",
            span,
            context,
        ));
    }
    if let Some(rest) = expression.strip_prefix("await") {
        if rest.starts_with(' ') {
            if !context.await_context {
                return Err(ParseError::new(
                    ParseErrorCode::AwaitOutsideAsync,
                    "await expression is only valid inside an async function",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
            if context.formal_parameters {
                return Err(invalid_syntax_error(
                    "an `await` expression cannot be in a parameter list",
                    span,
                    context,
                ));
            }
            let nested = parse_expression(rest.trim_start(), span, context, recursion_depth + 1)?;
            return Ok(Expression::Await(Box::new(nested)));
        }
        if rest.starts_with('(') && context.await_context {
            if context.formal_parameters {
                return Err(invalid_syntax_error(
                    "an `await` expression cannot be in a parameter list",
                    span,
                    context,
                ));
            }
            let nested = parse_expression(rest.trim_start(), span, context, recursion_depth + 1)?;
            return Ok(Expression::Await(Box::new(nested)));
        }
    }

    // Inside an async function or module `await` is an operator and needs
    // its operand: a bare `await` is a SyntaxError (ES2020 14.7.1, 15.2.1.1).
    if expression == "await" && (context.await_context || context.static_block_await) {
        return Err(unsupported_expression_syntax_error(
            "`await` is reserved here and needs an operand",
            span,
            context,
        ));
    }

    // yield expression: `yield expr` or `yield* expr` (delegation)
    if let Some(rest) = expression.strip_prefix("yield")
        && (rest.starts_with(' ')
            || rest.starts_with('*')
            || rest.is_empty()
            || rest.starts_with(';')
            || rest.starts_with(')')
            || rest.starts_with('}'))
        && !context.yield_context
    {
        // Outside a generator `yield` is an IdentifierReference, reserved in
        // strict code (ES2020 12.1.1); it never starts a yield expression.
        if context.strict_mode {
            return Err(unsupported_expression_syntax_error(
                "`yield` is a reserved word in strict mode code",
                span,
                context,
            ));
        }
        if !rest.trim().is_empty() {
            return Err(unsupported_expression_syntax_error(
                "a `yield` expression is only valid in a generator",
                span,
                context,
            ));
        }
        return Ok(Expression::Identifier("yield".to_string()));
    }
    if let Some(rest) = expression.strip_prefix("yield")
        && (rest.starts_with(' ')
            || rest.starts_with('*')
            || rest.is_empty()
            || rest.starts_with(';')
            || rest.starts_with(')')
            || rest.starts_with('}'))
    {
        if context.formal_parameters {
            return Err(invalid_syntax_error(
                "a `yield` expression cannot be in a parameter list",
                span,
                context,
            ));
        }
        let rest = rest.trim_start();
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
        return Ok(Expression::Yield { argument, delegate });
    }

    // new expression: `new Foo(args)`
    if let Some(rest) = expression
        .strip_prefix("new ")
        .or_else(|| expression.strip_prefix("new\t"))
    {
        return parse_new_expression(rest.trim(), span, context, recursion_depth);
    }

    // Async function expression: `async function (...) {...}` (bd-xbv99). No
    // LineTerminator may separate `async` from `function`. Without this arm
    // the expression fell through to `Expression::Raw`, lowered to a string,
    // and faulted at call time with "expected function, got string".
    if let Some(after_async) = expression.strip_prefix("async")
        && after_async.starts_with([' ', '\t'])
        && let Some(rest) = after_async
            .trim_start_matches([' ', '\t'])
            .strip_prefix("function")
            .filter(|r| r.starts_with(['(', '*', ' ', '\t']))
        && function_expression_is_whole(rest)
    {
        let source = context.function_sources.text_of(expression);
        return parse_async_function_expression(rest, span, context, recursion_depth)
            .map(|value| with_function_source(value, source));
    }

    // Function expression: `function(a, b) { ... }`, `function name(a, b) { ... }`,
    // or a generator `function* (...) { ... }`. When text follows the body
    // (`function (x) { ... }(5)`, `function () {}.call(this)`), the function
    // is the callee/object of that suffix and the generic call and member
    // parsing below takes it, so the suffix is not silently dropped.
    if let Some(rest) = expression
        .strip_prefix("function")
        .filter(|r| r.starts_with(['(', '*', ' ', '\t']))
        && function_expression_is_whole(rest)
    {
        let source = context.function_sources.text_of(expression);
        return parse_function_expression(rest, span, context, recursion_depth)
            .map(|value| with_function_source(value, source));
    }

    // Class expression: `class { ... }`, `class Name { ... }`, or
    // `class extends Base { ... }`. Without this arm the parser never produced
    // `Expression::ClassExpression`, so a class in expression position
    // (`let X = class {...}`, `new (class {...})()`, `typeof (class {...})`)
    // fell through to a string-yielding fallback and faulted at runtime with
    // "expected function, got string" (bd-4a4yz). Mirrors the function-
    // expression arm above; the body is re-parsed from the full `class...`.
    if expression
        .strip_prefix("class")
        .is_some_and(|r| r.starts_with('{') || r.starts_with(' ') || r.starts_with('\t'))
        && class_expression_is_whole(expression)
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
        && let Some((inner, rest)) = extract_balanced(expression, '(', ')')
        && rest.trim().is_empty()
    {
        let inner = inner.trim();
        // Comma/sequence operator (bd-wo6za, ES2020 §13.16): a parenthesized
        // top-level comma sequence `(e0, e1, …, eN)` evaluates each operand
        // left-to-right and yields the LAST. Desugar to an immediately-applied
        // arrow `((__seq_0, …, __seq_N) => __seq_N)(e0, …, eN)` — call arguments
        // are evaluated left-to-right (preserving every operand's side effects)
        // and the arrow returns the final operand. This reuses the existing
        // arrow + call lowering, so no dedicated SequenceExpression IR is needed.
        // Arrow-parameter forms `(a, b) => …` are consumed earlier by
        // `try_parse_arrow_function`, so reaching here with top-level commas is a
        // genuine sequence expression. The synthetic `__seq_*` parameters cannot
        // collide with the operands: operands are evaluated as arguments in the
        // enclosing scope, never inside the arrow body.
        if split_top_level_commas(inner).len() > 1 {
            let operands = parse_comma_separated_exprs(inner, span, context, recursion_depth + 1)?;
            if operands.len() > 1 {
                return Ok(build_sequence_expression(operands, span));
            }
        }
        return parse_expression(inner, span, context, recursion_depth + 1);
    }

    // Array literal: [a, b, c]
    if expression.starts_with('[')
        && expression.ends_with(']')
        && let Some((inner, rest)) = extract_balanced(expression, '[', ']')
        && rest.trim().is_empty()
    {
        return parse_array_literal(inner, span, context, recursion_depth, false);
    }

    // Object literal: {a: 1, b: 2}
    if expression.starts_with('{')
        && expression.ends_with('}')
        && let Some((inner, rest)) = extract_balanced(expression, '{', '}')
        && rest.trim().is_empty()
    {
        return parse_object_literal(inner, span, context, recursion_depth, false);
    }

    // Call expression: callee(args) or callee(args).member etc.
    if let Some(result) = try_parse_postfix(expression, span, context, recursion_depth) {
        return result;
    }

    if has_valid_quoted_prefix {
        return Err(unsupported_expression_syntax_error(
            "unsupported or malformed string-literal postfix expression",
            span,
            context,
        ));
    }

    // Unterminated template literal (bd-no788 cases 1-3). A *complete* template
    // (`` `x` ``) is consumed by the both-backticks gate above; a tagged
    // template or a template with a trailing member/call (``tag`x` `` /
    // `` `x`.length ``) is consumed by `try_parse_postfix`. A leading backtick
    // that survives both is one whose closing backtick is missing — ES2020
    // §11.8.6 requires every TemplateCharacter sequence to be terminated, so
    // fail-closed instead of falling through to `Expression::Raw`. feb61b0e
    // added the equivalent check at `parse_template_literal`'s entry, but the
    // routing gate above meant an unterminated literal never reached it.
    if expression.starts_with('`') {
        return Err(unsupported_expression_syntax_error(
            "unterminated template literal: missing closing backtick before end of input",
            span,
            context,
        ));
    }

    if is_identifier(expression) {
        // `import` is only an ImportCall callee (handled with its arguments)
        // or `import.meta`; a bare reference is a SyntaxError.
        if expression == "import" {
            return Err(unsupported_expression_syntax_error(
                "`import` must be called: import(specifier)",
                span,
                context,
            ));
        }
        return Ok(Expression::Identifier(canonicalize_identifier(expression)));
    }

    if is_unseparated_expression_sequence(expression) {
        return Err(unsupported_expression_syntax_error(
            "unseparated expression sequence",
            span,
            context,
        ));
    }

    // Reject expressions that begin with a stray binary-only operator with no
    // left-hand operand (e.g. `* 5`, `% 2`, `?? null`) (bd-wa01t). These are
    // never valid as the leading token of an expression — including them in the
    // `Expression::Raw` fallback would silently swallow real syntax errors.
    // We deliberately exclude `+`, `-`, `!`, `~`, `/` (unary or regex contexts)
    // and `:` / `,` (already structurally invalid via other paths).
    if let Some(first) = expression.as_bytes().first()
        && matches!(
            *first,
            b'*' | b'%' | b'&' | b'|' | b'^' | b'<' | b'>' | b'=' | b'?'
        )
    {
        return Err(invalid_syntax_error(
            "expression begins with a binary operator with no left-hand operand",
            span,
            context,
        ));
    }

    if expression.starts_with([')', ']', '}']) {
        return Err(invalid_syntax_error(
            "unexpected closing delimiter in expression",
            span,
            context,
        ));
    }

    Ok(Expression::Raw(canonicalize_whitespace(expression)))
}

fn is_unseparated_expression_sequence(expression: &str) -> bool {
    let mut parts = expression.split_ascii_whitespace();
    let Some(first) = parts.next() else {
        return false;
    };
    if !is_identifier(first)
        && parse_bigint_numeric_literal(first).is_none()
        && parse_i64_numeric_literal(first).is_none()
        && parse_f64_numeric_literal(first).is_none()
    {
        return false;
    }

    let mut count = 1usize;
    for part in parts {
        if !is_identifier(part)
            && parse_bigint_numeric_literal(part).is_none()
            && parse_i64_numeric_literal(part).is_none()
            && parse_f64_numeric_literal(part).is_none()
        {
            return false;
        }
        count += 1;
    }
    count > 1
}

fn strip_trailing_line_comment(expression: &str) -> &str {
    let bytes = expression.as_bytes();
    let mut quotes = QuoteState::default();
    let mut index = 0usize;

    while index + 1 < bytes.len() {
        let byte = bytes[index];
        if quotes.active() {
            quotes.advance(byte);
            index += 1;
            continue;
        }
        if byte == b'/' && quotes.open_regex_at(expression, index) {
            index += 1;
            continue;
        }

        match byte {
            b'\'' | b'"' | b'`' => {
                quotes.open(byte);
            }
            b'/' if bytes[index + 1] == b'/'
                && (index == 0 || bytes[index.saturating_sub(1)].is_ascii_whitespace()) =>
            {
                return &expression[..index];
            }
            _ => {}
        }
        index += 1;
    }

    expression
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
    // Mirrors the franken-core twin (bd-xbv99). `async(...)` is a call unless
    // its parenthesized list is followed by `=>`, which the `(params) => body`
    // arm below requires; an identifier parameter needs separating whitespace.
    // No LineTerminator may follow `async` in an arrow head. A leading
    // `async` that does not open an async arrow is an ordinary identifier
    // (`async => 1`, `asyncValue => 1`), so fall back instead of bailing out.
    let (is_async, rest) = match expr.strip_prefix("async") {
        Some(after_async) if !after_async.starts_with(is_identifier_continue) => {
            let trimmed = after_async.trim_start_matches([' ', '\t']);
            let consumed_whitespace = trimmed.len() < after_async.len();
            let starts_with_identifier =
                matches!(trimmed.chars().next(), Some(ch) if is_identifier_start(ch));
            if trimmed.starts_with('(') || (consumed_whitespace && starts_with_identifier) {
                (true, trimmed)
            } else {
                (false, expr)
            }
        }
        _ => (false, expr),
    };

    if rest.starts_with('(') {
        // (params) => body
        let (params_src, after_params) = extract_balanced(rest, '(', ')')?;
        let after = after_params.trim_start();
        let body_src = after.strip_prefix("=>")?;
        let body_src = body_src.trim();
        let directive_source = if body_src.starts_with('{') {
            extract_balanced(body_src, '{', '}')
                .map(|(inner, _)| inner)
                .unwrap_or("")
        } else {
            ""
        };

        Some(with_function_strict_mode(
            directive_source,
            false,
            context,
            |context| {
                // An async arrow's parameters reserve `await` (ES2020 14.8:
                // `async (await) => {}`, `async (x = await) => {}`).
                let saved_await_context = context.await_context;
                context.await_context |= is_async;
                let params = parse_arrow_params(params_src, span, context);
                context.await_context = saved_await_context;
                let params = params?;
                reject_duplicate_params(&params, true, span, context)?;
                parse_arrow_body(
                    expr,
                    body_src,
                    params,
                    is_async,
                    span,
                    context,
                    recursion_depth,
                )
            },
        ))
    } else {
        // ident => body (single param, no parens)
        // Find `=>` that isn't inside quotes/brackets.
        let arrow_pos = find_top_level_arrow(rest)?;
        let param_name = rest[..arrow_pos].trim();
        if !is_identifier(param_name) {
            return None;
        }
        let body_src = rest[arrow_pos + 2..].trim();
        // The parameter is a BindingIdentifier: reserved words (`yield` in
        // strict code, `await` of an async arrow, escaped keywords) are
        // SyntaxErrors, and an escaped name is canonical.
        let saved_await_context = context.await_context;
        context.await_context |= is_async;
        let pattern = parse_binding_pattern(param_name, span, context);
        context.await_context = saved_await_context;
        let pattern = match pattern {
            Ok(pattern) => pattern,
            Err(error) => return Some(Err(error)),
        };
        let params = vec![FunctionParam {
            pattern,
            span: span.clone(),
        }];
        Some(parse_arrow_body(
            expr,
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
    if params_src.trim().is_empty() {
        return Ok(Vec::new());
    }
    let saved_formal_parameters = std::mem::replace(&mut context.formal_parameters, true);
    let params = parse_formal_parameter_list(params_src, span, context);
    context.formal_parameters = saved_formal_parameters;
    params
}

fn parse_formal_parameter_list(
    params_src: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<FunctionParam>> {
    // ES2020 14.1 FormalParameters: no elision (`(a,,b)`, `(,a)`), a rest
    // parameter last, and no trailing comma after it (`(...a,)`).
    fn malformed(
        message: &str,
        span: &SourceSpan,
        context: &ParseExecutionContext<'_>,
    ) -> ParseError {
        ParseError::new(
            ParseErrorCode::InvalidSyntax,
            message.to_string(),
            context.source_label.to_string(),
            Some(span.clone()),
        )
    }
    let segments = split_pattern_elements(params_src);
    if segments.iter().any(|segment| segment.trim().is_empty()) {
        return Err(malformed(
            "empty parameter in a parameter list",
            span,
            context,
        ));
    }
    let mut params = Vec::with_capacity(segments.len());
    for segment in &segments {
        if params
            .last()
            .is_some_and(|param: &FunctionParam| matches!(param.pattern, BindingPattern::Rest(_)))
        {
            return Err(malformed("a rest parameter must be last", span, context));
        }
        let pattern = parse_binding_pattern(segment.trim(), span, context)?;
        params.push(FunctionParam {
            pattern,
            span: span.clone(),
        });
    }
    if params_src.trim_end().ends_with(',')
        && params
            .last()
            .is_some_and(|param| matches!(param.pattern, BindingPattern::Rest(_)))
    {
        return Err(malformed(
            "a rest parameter may not have a trailing comma",
            span,
            context,
        ));
    }
    Ok(params)
}

/// ES2020 14.1.2, 14.2.1, 14.3.1: parameter names are unique in strict
/// code, in arrow functions and methods, and in any non-simple parameter
/// list (`function f(x = 0, x) {}`); only a sloppy function with simple
/// parameters may repeat one (`function f(a, a) {}`).
fn reject_duplicate_params(
    params: &[FunctionParam],
    unique_required: bool,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let simple = params
        .iter()
        .all(|param| matches!(param.pattern, BindingPattern::Identifier(_)));
    if !unique_required && !context.strict_mode && simple {
        return Ok(());
    }
    let mut seen = BTreeSet::new();
    for name in params
        .iter()
        .flat_map(|param| param.pattern.binding_names())
    {
        if !seen.insert(name) {
            return Err(ParseError::new(
                ParseErrorCode::InvalidSyntax,
                format!("duplicate parameter name `{name}` is not allowed here"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
    }
    Ok(())
}

/// ES2020 14.3.1: a getter has no parameters, and a setter exactly one,
/// which is not a rest parameter.
fn reject_accessor_arity(
    is_getter: bool,
    params: &[FunctionParam],
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let valid = if is_getter {
        params.is_empty()
    } else {
        params.len() == 1 && !matches!(params[0].pattern, BindingPattern::Rest(_))
    };
    if valid {
        return Ok(());
    }
    Err(ParseError::new(
        ParseErrorCode::InvalidSyntax,
        if is_getter {
            "a getter must not have parameters"
        } else {
            "a setter must have exactly one parameter"
        },
        context.source_label.to_string(),
        Some(span.clone()),
    ))
}

/// Parse the body of an arrow function — either `{ block }` or expression.
/// `head` is the arrow's text from its first token (`async`, its parameters),
/// whose source text the arrow keeps (bd-9vouw.184).
fn parse_arrow_body(
    head: &str,
    body_src: &str,
    params: Vec<FunctionParam>,
    is_async: bool,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    with_function_context(is_async, false, context, |context| {
        let mut source_end = body_src.trim_end().trim_end_matches(';').trim_end();
        let body = if body_src.starts_with('{') {
            if let Some((block_src, after_block)) = extract_balanced(body_src, '{', '}') {
                source_end = &body_src[..body_src.len() - after_block.len()];
                // An arrow function is a whole AssignmentExpression: nothing
                // follows its block body (`() => {} = 1`, `() => {}.x`) but
                // the `;` ending its statement, which some callers keep.
                if !matches!(after_block.trim(), "" | ";") {
                    return Err(unsupported_expression_syntax_error(
                        "unexpected token after an arrow function body",
                        span,
                        context,
                    ));
                }
                reject_use_strict_with_non_simple_params(block_src, &params, span, context)?;
                let stmts = parse_function_body_statements(
                    block_src,
                    ParseGoal::Script,
                    span,
                    context,
                    &params,
                )?;
                ArrowBody::Block(BlockStatement {
                    body: stmts,
                    span: span.clone(),
                })
            } else {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "arrow function block has unbalanced braces",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
        } else {
            let expr = parse_expression(body_src, span, context, recursion_depth + 1)?;
            ArrowBody::Expression(Box::new(expr))
        };
        let source_text = head.chars().next().and_then(|first| {
            context
                .function_sources
                .text(head.as_ptr() as usize, first, source_end)
        });
        Ok(Expression::ArrowFunction {
            params,
            body,
            is_async,
            source_text,
        })
    })
}

/// Find `=>` at the top level (not inside quotes/brackets/parens).
fn find_top_level_arrow(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth_paren: i32 = 0;
    let mut depth_bracket: i32 = 0;
    let mut depth_brace: i32 = 0;
    let mut quotes = QuoteState::default();
    let mut i = 0usize;

    while i + 1 < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
                i += 1;
                continue;
            }
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            b'=' if depth_paren == 0
                && depth_bracket == 0
                && depth_brace == 0
                && bytes[i + 1] == b'>' =>
            {
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
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
    // An ImportCall is not a constructor target (`new import('')`).
    if let Some(after) = rest.trim_start().strip_prefix("import")
        && after.trim_start().starts_with('(')
    {
        return Err(unsupported_expression_syntax_error(
            "import() cannot be used with `new`",
            span,
            context,
        ));
    }
    //
    // A member / call / index chain that follows the constructor's argument list
    // binds to the NEW RESULT, not the callee: per ES2020 §13.3, `new X(a).b`
    // parses as `(new X(a)).b` (and `new X(a)()` / `new X(a)[i]` likewise). The
    // base cases below only handle a `rest` whose constructor call is the whole
    // expression; when a trailing chain follows the `)`, re-group explicitly so
    // the trailing access applies to the constructed object, reusing the existing
    // postfix (member/call/index) machinery (bd-if9uy). The parenthesised form is
    // known-good, so this is a faithful regrouping rather than new parsing logic.
    // A parenthesised callee (`new (K)().m()`, `new (o.K)(a).b`) is not the
    // argument list: the arguments are the next top-level pair after it.
    let argument_pair = find_first_top_level_paren_pair(rest).and_then(|(open, close)| {
        if rest[..open].trim().is_empty() {
            find_first_top_level_paren_pair(&rest[close + 1..])
                .map(|(next_open, next_close)| (close + 1 + next_open, close + 1 + next_close))
        } else {
            Some((open, close))
        }
    });
    if let Some((open, close)) = argument_pair {
        let callee_src = rest[..open].trim();
        let trailing = rest[close + 1..].trim();
        if !callee_src.is_empty()
            && !trailing.is_empty()
            && (trailing.starts_with('.') || trailing.starts_with('[') || trailing.starts_with('('))
        {
            let grouped = format!("(new {}){}", &rest[..=close], trailing);
            return parse_expression(&grouped, span, context, recursion_depth + 1);
        }
    }

    // Find the arguments list at the end, if any. A parenthesised callee with
    // no argument list (lodash's `new (Map || ListCache)`) is not an argument
    // list with an empty callee: it falls through to `new Foo` below.
    if rest.ends_with(')')
        && let Some((callee_src, args_inner)) = {
            let open = find_matching_open_paren(rest);
            open.map(|pos| (rest[..pos].trim(), &rest[pos + 1..rest.len() - 1]))
        }
        && !callee_src.is_empty()
    {
        let callee = parse_expression(callee_src, span, context, recursion_depth + 1)?;
        let arguments = if args_inner.trim().is_empty() {
            Vec::new()
        } else {
            parse_comma_separated_exprs(args_inner, span, context, recursion_depth + 1)?
        };
        if new_callee_is_optional_chain(callee_src, &callee) {
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
    if new_callee_is_optional_chain(rest, &callee) {
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

fn parse_template_literal(
    expression: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    // ES2020 §11.8.6 TemplateCharacter — the entire template literal MUST
    // be terminated by a backtick. The tokeniser at `scan_template_literal`
    // happily exits on EOF without closing the literal, so previously the
    // parser would silently strip a non-backtick trailing character via
    // `expression[1..expression.len() - 1]`. With the early check below,
    // an unterminated template literal (case 1 of bd-no788), an
    // unterminated `${` substitution that never closes (case 2 — caught
    // here because the outer template never sees its closing backtick
    // either), and a substitution-closed-but-no-trailing-backtick
    // (case 3) all raise `UnsupportedSyntax` instead of producing a
    // silently-truncated AST node.
    if expression.len() < 2 || !expression.starts_with('`') || !expression.ends_with('`') {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "unterminated template literal: missing closing backtick before end of input"
                .to_string(),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    // Strip outer backticks.
    let inner = &expression[1..expression.len() - 1];
    let bytes = inner.as_bytes();
    let mut quasis = Vec::with_capacity(4);
    let mut expressions = Vec::with_capacity(4);
    let mut current_quasi = String::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            // ES2020 §11.8.6 / §11.8.4.1: an (untagged) template literal
            // rejects `NotEscapeSequence` shapes — legacy octal escapes,
            // non-octal decimal escapes, and malformed hex/unicode escapes.
            // The lexer was previously fail-open on all of these (bd-no788
            // cases 4 and 5).
            if let Err(message) = validate_template_escape_sequence(bytes, i) {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    message,
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
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
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            // Start of template expression.
            quasis.push(current_quasi.clone());
            current_quasi.clear();
            i += 2; // skip `${`
            let start = i;
            // The substitution ends at the `}` that balances its `${`,
            // skipping strings and nested templates (bd-9vouw.41).
            let mut substitution = QuoteState::in_substitution();
            while i < bytes.len() {
                substitution.advance(bytes[i]);
                if !substitution.active() {
                    break;
                }
                i += 1;
            }
            if substitution.active() {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "template literal interpolation has unbalanced braces",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
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

/// Validate a single escape sequence inside a (non-tagged) template literal
/// against ES2020 §11.8.6 (TemplateCharacter) and §11.8.4.1 (EscapeSequence).
///
/// `bytes` is the inner quasi text and `backslash` indexes the leading `\`;
/// the caller guarantees `backslash + 1 < bytes.len()`. Returns `Ok(())` for a
/// well-formed `EscapeSequence` / `LineContinuation` / `CharacterEscapeSequence`
/// and an error message for a `NotEscapeSequence` shape. Tagged-template
/// leniency (where a `NotEscapeSequence` cooks to `undefined` rather than being
/// a SyntaxError) is intentionally not modelled — `parse_template_literal`
/// produces a single `TemplateLiteral` node without tag context, so all
/// template literals are held to the untagged (strict) grammar here.
fn validate_template_escape_sequence(bytes: &[u8], backslash: usize) -> Result<(), String> {
    match bytes[backslash + 1] {
        // `\1`..`\9` — LegacyOctalEscapeSequence / NonOctalDecimalEscapeSequence.
        // The Annex B web-compatibility carve-out applies to string literals
        // only, never to template literals.
        b'1'..=b'9' => Err("legacy octal escape forbidden in template literal".to_string()),
        // `\0` is the NullEscapeSequence, permitted ONLY when not followed by a
        // DecimalDigit; `\01` is a legacy octal escape and is forbidden.
        b'0' => {
            if matches!(bytes.get(backslash + 2), Some(d) if d.is_ascii_digit()) {
                Err("legacy octal escape forbidden in template literal".to_string())
            } else {
                Ok(())
            }
        }
        // `\xNN` HexEscapeSequence requires exactly two hex digits.
        b'x' => {
            let well_formed = matches!(bytes.get(backslash + 2), Some(d) if d.is_ascii_hexdigit())
                && matches!(bytes.get(backslash + 3), Some(d) if d.is_ascii_hexdigit());
            if well_formed {
                Ok(())
            } else {
                Err("malformed \\xNN hex escape: non-hex content".to_string())
            }
        }
        // `\u` UnicodeEscapeSequence — either `\u{ CodePoint }` or `\u Hex4Digits`.
        b'u' => validate_template_unicode_escape(bytes, backslash + 2),
        // Any other character is a SingleEscapeCharacter, a NonEscapeCharacter
        // (CharacterEscapeSequence), or a LineContinuation — all permitted.
        _ => Ok(()),
    }
}

/// Validate a `\u…` UnicodeEscapeSequence (ES2020 §11.8.4.1). `start` indexes
/// the byte immediately after the `u`. Accepts `\u{ HexDigits }` with 1+ hex
/// digits encoding a code point in `[0, 0x10FFFF]`, or `\u` followed by exactly
/// four hex digits; everything else is a `NotEscapeSequence`.
fn validate_template_unicode_escape(bytes: &[u8], start: usize) -> Result<(), String> {
    if matches!(bytes.get(start), Some(b'{')) {
        let mut j = start + 1;
        let mut digits = 0u32;
        let mut value: u32 = 0;
        while let Some(&d) = bytes.get(j) {
            if d == b'}' {
                break;
            }
            match (d as char).to_digit(16) {
                Some(v) => {
                    value = value.saturating_mul(16).saturating_add(v);
                    digits += 1;
                }
                None => {
                    return Err("malformed \\u{...} unicode escape: non-hex content".to_string());
                }
            }
            j += 1;
        }
        if bytes.get(j) != Some(&b'}') {
            return Err("malformed \\u{...} unicode escape: missing closing brace".to_string());
        }
        if digits == 0 {
            return Err("malformed \\u{...} unicode escape: empty code point".to_string());
        }
        if value > 0x10_FFFF {
            return Err("malformed \\u{...} unicode escape: code point out of range".to_string());
        }
        Ok(())
    } else {
        for offset in 0..4 {
            if !matches!(bytes.get(start + offset), Some(d) if d.is_ascii_hexdigit()) {
                return Err("malformed \\uXXXX unicode escape: non-hex content".to_string());
            }
        }
        Ok(())
    }
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
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();
    let mut i: usize = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/'
            && let Some(len) = regex_literal_len_at(expr, i)
        {
            i += len;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
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
            b'[' => {
                depth_bracket += 1;
                i += 1;
                continue;
            }
            b']' => {
                depth_bracket -= 1;
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
        if depth_paren != 0 || depth_bracket != 0 || depth_brace != 0 {
            i += 1;
            continue;
        }
        // A conditional `?` ahead of any assignment operator makes this a
        // ConditionalExpression: an `=` after it belongs to a branch
        // (`c ? m.x = 1 : 0`, `c ? 0 : m.x = 2`), never to this level, and an
        // assignment target cannot contain a bare `?`.
        if is_conditional_question_at(bytes, i) {
            return None;
        }
        // Try matching assignment operators (must check longer ones first).
        if let Some((op, len)) = match_assignment_operator_at(bytes, i) {
            // Avoid matching == or === as assignment.
            let lhs = expr[..i].trim();
            let rhs = expr[i + len..].trim();
            if lhs.is_empty() || rhs.is_empty() {
                return Some(Err(invalid_syntax_error(
                    "assignment requires a target and a value",
                    span,
                    context,
                )));
            }
            let left =
                match parse_assignment_target_expression(lhs, span, context, recursion_depth + 1) {
                    Ok(e) => e,
                    Err(e) => return Some(Err(e)),
                };
            if assignment_target_has_optional_chain(&left) {
                return Some(Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "optional chaining cannot be used as an assignment target",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )));
            }
            if let Err(error) = reject_strict_eval_arguments_target(&left, span, context) {
                return Some(Err(error));
            }
            let right = match parse_expression(rhs, span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            return Some(Ok(Expression::Assignment {
                operator: op,
                left: Box::new(left),
                right: Box::new(right),
                assignment_strictness: AssignmentStrictness::from_strict_mode(context.strict_mode),
            }));
        }
        i += 1;
    }
    None
}

/// Whether the `?` at byte `i` (at depth 0, outside strings) is the
/// conditional operator: not either `?` of `??`/`??=`, and not the `?.` of
/// optional chaining (`a?.5:1` is still a conditional, since `?.` followed by
/// a digit is not optional chaining).
fn is_conditional_question_at(bytes: &[u8], i: usize) -> bool {
    if bytes.get(i) != Some(&b'?') || (i > 0 && bytes[i - 1] == b'?') {
        return false;
    }
    match bytes.get(i + 1) {
        None | Some(b'?') => false,
        Some(b'.') => bytes.get(i + 2).is_some_and(u8::is_ascii_digit),
        Some(_) => true,
    }
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
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();
    let mut i: usize = 0;

    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/'
            && let Some(len) = regex_literal_len_at(expr, i)
        {
            i += len;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
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
            b'[' => {
                depth_bracket += 1;
                i += 1;
                continue;
            }
            b']' => {
                depth_bracket -= 1;
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
        if depth_paren != 0 || depth_bracket != 0 || depth_brace != 0 {
            i += 1;
            continue;
        }
        if is_conditional_question_at(bytes, i) {
            // Found ternary `?`. Now find the matching `:` at the same depth.
            let test_src = expr[..i].trim();
            let rest = &expr[i + 1..];
            if let Some(colon_idx) = find_ternary_colon(rest) {
                let consequent_src = rest[..colon_idx].trim();
                let alternate_src = rest[colon_idx + 1..].trim();
                if test_src.is_empty() || consequent_src.is_empty() || alternate_src.is_empty() {
                    i += 1;
                    continue;
                }
                let test = match parse_expression(test_src, span, context, recursion_depth + 1) {
                    Ok(e) => e,
                    Err(e) => return Some(Err(e)),
                };
                let consequent =
                    match parse_expression(consequent_src, span, context, recursion_depth + 1) {
                        Ok(e) => e,
                        Err(e) => return Some(Err(e)),
                    };
                let alternate =
                    match parse_expression(alternate_src, span, context, recursion_depth + 1) {
                        Ok(e) => e,
                        Err(e) => return Some(Err(e)),
                    };
                return Some(Ok(Expression::Conditional {
                    test: Box::new(test),
                    consequent: Box::new(consequent),
                    alternate: Box::new(alternate),
                }));
            }
        }
        i += 1;
    }
    None
}

/// Find the index of a top-level `:` (not inside nested delimiters or quotes).
/// The index of the `:` ending a leading `label:` of `statement`: the first
/// `:` in the text, when the text before it is an identifier (escapes
/// allowed). An identifier holds no quote, bracket, brace, slash or colon,
/// so when the text before the first `:` is one, that colon is also the
/// first top-level colon [`find_top_level_colon`] finds, and when it is not,
/// neither is the text before the first top-level colon. The label checks
/// used that quote-aware scan of the whole statement, which every statement
/// and every nested one paid (5% of compiling cytoscape, release).
fn leading_label_colon(statement: &str) -> Option<usize> {
    let colon = statement.find(':')?;
    is_identifier(statement[..colon].trim()).then_some(colon)
}

fn find_top_level_colon(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();
    for (i, &b) in bytes.iter().enumerate() {
        if quotes.active() {
            quotes.advance(b);
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
                continue;
            }
            b'(' => {
                depth_paren += 1;
                continue;
            }
            b')' => {
                depth_paren -= 1;
                continue;
            }
            b'[' => {
                depth_bracket += 1;
                continue;
            }
            b']' => {
                depth_bracket -= 1;
                continue;
            }
            b'{' => {
                depth_brace += 1;
                continue;
            }
            b'}' => {
                depth_brace -= 1;
                continue;
            }
            _ => {}
        }
        if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && b == b':' {
            return Some(i);
        }
    }
    None
}

/// Find the `:` that matches the *first* top-level `?` of a ternary, given the
/// slice *after* that `?`. Unlike [`find_top_level_colon`], this skips the `:`
/// of any nested ternary by tracking `?` depth, so `b ? c : d : e` returns the
/// index of the second (outer) `:`, grouping `a ? b ? c : d : e` as
/// `a ? (b ? c : d) : e`. `?.` (optional chaining) and `??` (nullish) are not
/// ternary `?`. (A dedicated finder rather than changing `find_top_level_colon`,
/// which labeled statements and object/type patterns also rely on.)
fn find_ternary_colon(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();
    let mut question_depth: i64 = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
                i += 1;
                continue;
            }
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            _ => {}
        }
        if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 {
            if b == b'?' {
                match bytes.get(i + 1).copied() {
                    // Nullish `??` — skip both bytes, not a ternary `?`.
                    Some(b'?') => {
                        i += 2;
                        continue;
                    }
                    // Optional chaining `?.` — not a ternary `?`.
                    Some(b'.') => {}
                    _ => question_depth += 1,
                }
            } else if b == b':' {
                if question_depth == 0 {
                    return Some(i);
                }
                question_depth -= 1;
            }
        }
        i += 1;
    }
    None
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

/// Try to find and parse a binary expression by locating the lowest-precedence
/// top-level operator and recursively parsing left and right operands.
fn try_parse_binary(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    let bytes = expr.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();

    // Track the lowest-precedence operator found at top level.
    let mut best_op: Option<BinaryOperator> = None;
    let mut best_pos: usize = 0;
    let mut best_len: usize = 0;
    // Every valid top-level split point, for folding a left-associative
    // chain in one pass (bd-9vouw.85).
    let mut split_points: Vec<(usize, usize, BinaryOperator)> = Vec::new();

    let mut i: usize = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(expr, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
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
            b'[' => {
                depth_bracket += 1;
                i += 1;
                continue;
            }
            b']' => {
                depth_bracket -= 1;
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
        if depth_paren != 0 || depth_bracket != 0 || depth_brace != 0 {
            i += 1;
            continue;
        }
        // `++`/`--` is one update-operator token (maximal munch), never a
        // binary `+`/`-`: `a+++b` is `a++ + b`, and `a++ + 2` must not split
        // at the first `+` of `++` (that parsed as `a + (+(+2))` and dropped
        // the increment).
        if matches!(b, b'+' | b'-') && bytes.get(i + 1) == Some(&b) {
            i += 2;
            continue;
        }
        if let Some((op, len)) = match_binary_operator_at(expr, i) {
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
                    && !ends_with_postfix_update(lhs)
                    && lhs
                        .as_bytes()
                        .last()
                        .is_none_or(|&c| is_operator_context_byte(c));
                let exponent_sign = matches!(op, BinaryOperator::Add | BinaryOperator::Subtract)
                    && is_decimal_exponent_sign(bytes, i);
                if !lhs.is_empty() && rhs.is_empty() && !unary_sign && !exponent_sign {
                    return Some(Err(invalid_syntax_error(
                        "binary operator requires a right-hand operand",
                        span,
                        context,
                    )));
                }
                if !lhs.is_empty() && !rhs.is_empty() && !unary_sign && !exponent_sign {
                    best_op = Some(op);
                    best_pos = i;
                    best_len = len;
                }
            }
            if matches!(
                (op, is_decimal_exponent_sign(bytes, i)),
                (BinaryOperator::Add | BinaryOperator::Subtract, true)
            ) {
                i += len;
                continue;
            }
            let lhs = expr[..i].trim();
            let rhs = expr[i + len..].trim();
            let sign = matches!(op, BinaryOperator::Add | BinaryOperator::Subtract)
                && !ends_with_postfix_update(lhs)
                && lhs
                    .as_bytes()
                    .last()
                    .is_none_or(|&c| is_operator_context_byte(c));
            if !lhs.is_empty() && !rhs.is_empty() && !sign {
                split_points.push((i, len, op));
            }
            i += len;
            continue;
        }
        i += 1;
    }

    let op = best_op?;
    // bd-9vouw.85: a left-associative chain (`a + b + ... + z`, `t && t &&
    // ...`) splits at every top-level operator of the lowest precedence and
    // folds left, so recursion depth grows with nesting, not with the number
    // of terms (a 300-term concatenation exceeded the recursion budget).
    if !op.is_right_associative() {
        let chain: Vec<(usize, usize, BinaryOperator)> = split_points
            .into_iter()
            .filter(|(_, _, candidate)| candidate.precedence() == op.precedence())
            .collect();
        if chain.len() > 1 {
            // The folded tree is still one Binary node per operator, and the
            // parse-event, materialization and lowering walkers recurse down
            // its left spine: a debug build overflowed the provisioned parse
            // stack at ~1,790 terms and aborted. So the chain is charged one
            // budget level per FOLDED_CHAIN_TERMS_PER_RECURSION_LEVEL terms,
            // and a chain too long for the budget fails closed with the
            // budget error, as every chain past 255 terms did before.
            let terms = u64::try_from(chain.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let operand_depth = recursion_depth
                .saturating_add(1)
                .saturating_add(terms.div_ceil(FOLDED_CHAIN_TERMS_PER_RECURSION_LEVEL));
            let mut start = 0;
            let mut folded: Option<Expression> = None;
            let mut pending_op = None;
            for &(position, length, chain_op) in &chain {
                let operand_src = expr[start..position].trim();
                let operand = match parse_expression(operand_src, span, context, operand_depth) {
                    Ok(e) => e,
                    Err(e) => return Some(Err(e)),
                };
                folded = Some(match (folded, pending_op) {
                    (Some(left), Some(previous)) => Expression::Binary {
                        operator: previous,
                        left: Box::new(left),
                        right: Box::new(operand),
                    },
                    _ => operand,
                });
                pending_op = Some(chain_op);
                start = position + length;
            }
            let last_src = expr[start..].trim();
            let last = match parse_expression(last_src, span, context, operand_depth) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            return Some(Ok(Expression::Binary {
                operator: pending_op.expect("a chain has at least two operators"),
                left: Box::new(folded.expect("a chain has at least two operands")),
                right: Box::new(last),
            }));
        }
    }
    let lhs_src = expr[..best_pos].trim();
    let rhs_src = expr[best_pos + best_len..].trim();
    // ES2022 `#x in obj`: a private name is an operand only here.
    let private_in_operand = matches!(op, BinaryOperator::In)
        .then(|| whole_private_name(lhs_src))
        .flatten();
    let left = if let Some(name) = private_in_operand {
        if let Err(error) = record_private_name_reference(&name, span, context) {
            return Some(Err(error));
        }
        Expression::Identifier(name)
    } else {
        match parse_expression(lhs_src, span, context, recursion_depth + 1) {
            Ok(e) => e,
            Err(e) => return Some(Err(e)),
        }
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

/// Whether `lhs` ends with a postfix `++`/`--` (the update follows an
/// operand). The update completes its operand, so a `+`/`-` after it is
/// binary (`a++ + 2`, `a---b`), not a sign of the right operand.
fn ends_with_postfix_update(lhs: &str) -> bool {
    let Some(operand) = lhs.strip_suffix("++").or_else(|| lhs.strip_suffix("--")) else {
        return false;
    };
    operand
        .trim_end()
        .chars()
        .next_back()
        .is_some_and(|c| is_identifier_continue(c) || matches!(c, ')' | ']'))
}

/// A sign in a decimal exponent belongs to its numeric token, not an
/// additive expression. Inspect only the contiguous mantissa and its boundary:
/// `value - 1`, `name1e - 2` and `0x1e-2` are still subtraction expressions.
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
            && (bytes[start - 1] >= 0x80 || is_identifier_continue(bytes[start - 1] as char)))
    {
        return false;
    }
    let mantissa = &bytes[start..end];
    mantissa.iter().any(u8::is_ascii_digit) && mantissa.iter().filter(|&&c| c == b'.').count() <= 1
}

/// Match a binary operator at byte position `i`. Returns (operator, byte_length).
/// Whether the `*` at `star` directly follows the keyword `function` (only
/// spaces or tabs in between). A preceding identifier character or `.` means
/// `function` is part of a longer name or a property (`obj.function * 2`).
fn star_follows_function_keyword(bytes: &[u8], star: usize) -> bool {
    let mut end = star;
    while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    end >= 8
        && &bytes[end - 8..end] == b"function"
        && (end == 8 || {
            let before = bytes[end - 9];
            before != b'.' && !is_identifier_continue(before as char)
        })
}

fn match_binary_operator_at(expr: &str, i: usize) -> Option<(BinaryOperator, usize)> {
    let bytes = expr.as_bytes();
    let remaining = bytes.len() - i;

    // Check for keyword operators first (instanceof, in). A `#` before one
    // makes it a private name (`this.#in`), and a `.` a property name
    // (`o.in.x`, `o.in?.x`, `o.instanceof`; arktype reads `inner.in?.rawIn`),
    // not an operator. Whitespace is permitted between a dot and its property
    // name, including Unicode whitespace (`o. in`, `o.\u{00a0}instanceof`).
    if remaining >= 10 && &bytes[i..i + 10] == b"instanceof" {
        let before_ok = expr[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !is_identifier_continue(c) && !matches!(c, '#' | '.'));
        let after_ok = expr[i + 10..]
            .chars()
            .next()
            .is_none_or(|c| !is_identifier_continue(c));
        if before_ok && after_ok && !expr[..i].trim_end().ends_with('.') {
            return Some((BinaryOperator::Instanceof, 10));
        }
    }
    if remaining >= 2 && &bytes[i..i + 2] == b"in" {
        let before_ok = expr[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !is_identifier_continue(c) && !matches!(c, '#' | '.'));
        let after_ok = expr[i + 2..]
            .chars()
            .next()
            .is_none_or(|c| !is_identifier_continue(c));
        if before_ok && after_ok && !expr[..i].trim_end().ends_with('.') {
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
            b"=>" => return None, // arrow
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
                // `function*` / `function *`: the generator marker of a
                // function expression, not multiplication (bd-xbv99).
                if star_follows_function_keyword(bytes, i) {
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

fn try_parse_unary_prefix(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    // Keyword-style unary: typeof, void, delete. The keyword ends at any
    // character that cannot continue an identifier, so `typeof(x)` and
    // `void(0)` are operators (they used to parse as calls to an undefined
    // `typeof`), while `typeofFoo` stays a name.
    for (keyword, op) in [
        ("typeof", UnaryOperator::Typeof),
        ("void", UnaryOperator::Void),
        ("delete", UnaryOperator::Delete),
    ] {
        if let Some(rest) = expr.strip_prefix(keyword)
            && rest
                .chars()
                .next()
                .is_some_and(|next| !is_identifier_continue(next))
        {
            // `NaN` and `Infinity` parse as number literals everywhere else,
            // but the operand of `delete NaN` / `delete (Infinity)` is a
            // reference to the global object's non-configurable property:
            // false, and an early error in strict code. As literals they
            // deleted a value and answered true.
            let mut operand = rest.trim();
            while let Some(inner) = operand.strip_prefix('(').and_then(|o| o.strip_suffix(')')) {
                operand = inner.trim();
            }
            let arg =
                if matches!(op, UnaryOperator::Delete) && matches!(operand, "NaN" | "Infinity") {
                    Expression::Identifier(operand.to_string())
                } else {
                    match parse_expression(rest.trim(), span, context, recursion_depth + 1) {
                        Ok(e) => e,
                        Err(e) => return Some(Err(e)),
                    }
                };
            // bd-9vouw.136: a strict-mode delete throws where a sloppy one
            // answers false, and of a bare identifier it is an early error
            // (ES2020 12.5.3.1).
            let op = if matches!(op, UnaryOperator::Delete) && context.strict_mode {
                if matches!(arg, Expression::Identifier(_)) {
                    return Some(Err(unsupported_expression_syntax_error(
                        "delete of an unqualified identifier in strict mode",
                        span,
                        context,
                    )));
                }
                UnaryOperator::StrictDelete
            } else {
                op
            };
            // ES2022 13.5.1.1: `delete o.#x` is an early error.
            if matches!(op, UnaryOperator::Delete | UnaryOperator::StrictDelete)
                && is_private_member_expression(&arg)
            {
                return Some(Err(unsupported_expression_syntax_error(
                    "private fields can not be deleted",
                    span,
                    context,
                )));
            }
            if let Some(error) = unparenthesized_yield_operand(rest, &arg, span, context) {
                return Some(Err(error));
            }
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
            // `+1n` is unary plus on a BigInt (a runtime TypeError), not a
            // signed literal like `+1`.
            b'+' if !expr.as_bytes()[1].is_ascii_digit()
                || parse_bigint_numeric_literal(&expr[1..]).is_some() =>
            {
                (Some(UnaryOperator::UnaryPlus), &expr[1..])
            }
            _ => (None, expr),
        };
        if let Some(op) = op {
            let arg = match parse_expression(rest.trim(), span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            if let Some(error) = unparenthesized_yield_operand(rest, &arg, span, context) {
                return Some(Err(error));
            }
            return Some(Ok(Expression::Unary {
                operator: op,
                argument: Box::new(arg),
            }));
        }
    }

    None
}

/// A unary operator's operand is a UnaryExpression, which a yield expression
/// is not: `void yield` in a generator is a SyntaxError, `void (yield)` is
/// fine (ES2020 12.5).
fn unparenthesized_yield_operand(
    operand_src: &str,
    operand: &Expression,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> Option<ParseError> {
    (matches!(operand, Expression::Yield { .. }) && !operand_src.trim_start().starts_with('('))
        .then(|| {
            unsupported_expression_syntax_error(
                "a `yield` expression cannot be the operand of a unary operator",
                span,
                context,
            )
        })
}

/// Try to parse a prefix or postfix update expression (`++x`, `--x`, `x++`,
/// `x--`).
///
/// The string-based parser has no dedicated `UpdateExpression` AST node, and
/// threading one through the whole IR0→IR1→IR3 pipeline + interpreter would be a
/// large blast radius. Instead we desugar into the existing compound-assignment
/// and binary nodes, which already write back to the target and (for compound
/// assignment) evaluate to the *new* value (see `Ir1Op::AssignOp` lowering):
///
/// * prefix  `++x` ⇒ `x += 1`         (value = new)
/// * prefix  `--x` ⇒ `x -= 1`         (value = new)
/// * postfix `x++` ⇒ `(x += 1) - 1`   (value = old; target left incremented)
/// * postfix `x--` ⇒ `(x -= 1) + 1`   (value = old; target left decremented)
///
/// The `- 1` / `+ 1` adjustment recovers the pre-update value without needing a
/// temporary, because the compound assignment already yields the post-update
/// value. The target is read and written exactly once (via the compound
/// assignment), so there is no double-evaluation of member targets.
///
/// Only fires when the operand is a simple assignment target (identifier or
/// member access). Mixed forms like `++a + b` or `a + b++` are left to the
/// binary scanner, which recurses back here on the cleanly-split operand.
fn try_parse_update(
    expr: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> Option<ParseResult<Expression>> {
    let expr = expr.trim();
    // Shortest update is `++x` / `x++` (3 bytes for a 1-char target).
    if expr.len() < 3 {
        return None;
    }

    // Prefix: `++x` / `--x`. ES2020 12.4.4.1 applies ToNumeric to the old
    // value and adds one of its own type: `s = '5'; ++s` is 6, not "51" (a
    // Date or valueOf object takes its number hint), and a BigInt steps by
    // `1n` (bd-9vouw.119; the earlier `x -= -1` desugar threw "cannot mix
    // BigInt" there).
    let prefix_operator = if expr.starts_with("++") {
        Some(AssignmentOperator::IncrementAssign)
    } else if expr.starts_with("--") {
        Some(AssignmentOperator::DecrementAssign)
    } else {
        None
    };
    if let Some(operator) = prefix_operator {
        let operand_src = expr[2..].trim();
        // Reject chained/ambiguous forms (`+++x`, `++ -x`); leave them to the
        // unary path or to a fail-closed parse.
        if operand_src.is_empty() || operand_src.starts_with('+') || operand_src.starts_with('-') {
            return None;
        }
        let target = parse_expression(operand_src, span, context, recursion_depth + 1).ok()?;
        if !is_simple_update_target(&target) {
            return reject_non_assignable_update_target(&target, span, context);
        }
        if let Err(error) = reject_strict_eval_arguments_target(&target, span, context) {
            return Some(Err(error));
        }
        // `++x` evaluates to the new value, as a compound assignment does.
        return Some(Ok(Expression::Assignment {
            operator,
            left: Box::new(target),
            right: Box::new(Expression::NumericLiteral(1)),
            assignment_strictness: AssignmentStrictness::from_strict_mode(context.strict_mode),
        }));
    }

    // Postfix: `x++` / `x--`.
    let postfix = if expr.ends_with("++") {
        Some(AssignmentOperator::PostIncrementAssign)
    } else if expr.ends_with("--") {
        Some(AssignmentOperator::PostDecrementAssign)
    } else {
        None
    };
    if let Some(operator) = postfix {
        let operand_src = expr[..expr.len() - 2].trim();
        if operand_src.is_empty() || operand_src.ends_with('+') || operand_src.ends_with('-') {
            return None;
        }
        let target = parse_expression(operand_src, span, context, recursion_depth + 1).ok()?;
        if !is_simple_update_target(&target) {
            return reject_non_assignable_update_target(&target, span, context);
        }
        if let Err(error) = reject_strict_eval_arguments_target(&target, span, context) {
            return Some(Err(error));
        }
        // `x++` writes the increment back and evaluates to ToNumeric of the
        // old value (`s = '5'; s++` is 5, a BigInt stays a BigInt). The
        // earlier `(x -= -1) - 1` desugar recomputed it from the new value,
        // which is inexact for a fraction (`x = -0.1; x++` gave
        // -0.09999999999999998) and for -0.
        return Some(Ok(Expression::Assignment {
            operator,
            left: Box::new(target),
            right: Box::new(Expression::NumericLiteral(1)),
            assignment_strictness: AssignmentStrictness::from_strict_mode(context.strict_mode),
        }));
    }

    None
}

/// A valid target for `++`/`--`: a bare identifier or a member access
/// (`obj.prop`, `obj[key]`). Anything else is not assignable, so the candidate
/// is not an update expression.
fn is_simple_update_target(expr: &Expression) -> bool {
    matches!(expr, Expression::Identifier(_) | Expression::Member { .. })
}

/// ES2020 12.4.1 / 12.5.1: calls, optional chains, `this`, `new.target`,
/// `import.meta`, literals and function/class expressions are complete
/// operands that can never be assigned, so `f()++`, `++f()`, `a?.b++`,
/// `new.target++` and `1++` are early errors. Other non-simple operands are
/// left to the paths that split them first: `a + b` in `a + b++` (binary),
/// `-x` in `-x++` and `await x` in `await x++` (unary / await), and
/// `undefined`, which is an assignable identifier in sloppy code.
/// ES2020 12.1.1: a shorthand property `{ x }` is an IdentifierReference,
/// so it is never a reserved word (`({ if })`), nor in strict code a
/// strict-mode reserved word (`"use strict"; ({ implements })`), nor
/// `yield`/`await` where those are reserved.
fn reject_reserved_identifier_reference(
    name: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let reserved = is_unconditional_reserved_keyword(name)
        || ((context.await_context || context.static_block_await) && name == "await")
        || (context.yield_context && name == "yield")
        || (context.strict_mode
            && matches!(
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
            ));
    if reserved {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            format!("`{name}` is a reserved word here and cannot be referenced"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

/// ES2020 12.15.1, 12.4.1: in strict code `eval` and `arguments` are not
/// assignment or update targets (`arguments <<= 20`, `eval++`).
fn reject_strict_eval_arguments_target(
    target: &Expression,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    if context.strict_mode
        && let Expression::Identifier(name) = target
        && matches!(name.as_str(), "eval" | "arguments")
    {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            format!("`{name}` cannot be assigned in strict mode code"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

fn reject_non_assignable_update_target(
    target: &Expression,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> Option<ParseResult<Expression>> {
    if matches!(
        target,
        Expression::Call { .. }
            | Expression::OptionalCall { .. }
            | Expression::OptionalMember { .. }
            | Expression::This
            | Expression::SloppyThis
            | Expression::NewTarget
            | Expression::ImportMeta
            | Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::FloatLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral
            | Expression::TemplateLiteral { .. }
            | Expression::RegExpLiteral { .. }
            | Expression::ArrowFunction { .. }
            | Expression::Function { .. }
            | Expression::ClassExpression { .. }
    ) {
        return Some(Err(invalid_syntax_error(
            "invalid update target: this expression cannot be incremented or decremented",
            span,
            context,
        )));
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

    // Tagged template (scaffold form): `tag`...`` or `obj.tag`...``.
    // The current AST does not have a dedicated tagged-template variant, so
    // preserve deterministic structure as a call with one template argument.
    if bytes[bytes.len() - 1] == b'`'
        && let Some(template_start) = find_top_level_template_start(expr)
        && template_start > 0
    {
        let callee_src = expr[..template_start].trim();
        let template_src = expr[template_start..].trim();
        if !callee_src.is_empty() && template_src.starts_with('`') && template_src.ends_with('`') {
            let callee = match parse_expression(callee_src, span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            let template =
                match parse_template_literal(template_src, span, context, recursion_depth + 1) {
                    Ok(e) => e,
                    Err(e) => return Some(Err(e)),
                };
            // ES2020 §12.2.9: a tagged template `tag`q0${e0}q1…`` invokes
            // `tag(stringsArray, e0, e1, …)` where `stringsArray` holds the
            // COOKED quasis (bd-1lrbw). The previous desugar passed the whole
            // template literal as a single argument, so the tag saw the
            // concatenated string instead of the strings array and substitutions
            // (→ `t`hello`` yielded undefined). `parse_template_literal` keeps
            // quasis raw, so cook each via `cook_template_quasi`; a quasi with
            // a `NotEscapeSequence` cooks to undefined (ES2018 template
            // literal revision).
            let Expression::TemplateLiteral {
                quasis,
                expressions,
            } = template
            else {
                return Some(Err(unsupported_expression_syntax_error(
                    "tagged template did not parse to a template literal",
                    span,
                    context,
                )));
            };
            let cooked_strings: Vec<Option<Expression>> = quasis
                .iter()
                .map(|quasi| {
                    Some(
                        cook_template_quasi(quasi)
                            .map_or(Expression::UndefinedLiteral, Expression::StringLiteral),
                    )
                })
                .collect();
            // `.raw` array (bd-vl55w): parse_template_literal keeps quasis raw
            // (escapes included literally), so use them as-is for `.raw`.
            let raw_strings: Vec<Option<Expression>> = quasis
                .iter()
                .map(|quasi| Some(Expression::StringLiteral(quasi.clone().into())))
                .collect();
            // ES2020 §12.2.9: the strings array carries a `.raw` sibling array
            // (used by String.raw and `tag` functions reading `s.raw[i]`). An
            // ArrayLiteral cannot carry an extra property, so wrap the cooked
            // array in an immediately-applied arrow that sets `.raw` and returns
            // it: `((__tt_strings) => { __tt_strings.raw = [<raw>]; return
            // __tt_strings; })([<cooked>])`. `__tt_strings` is the cooked array
            // passed by reference (a heap object), so the member assignment
            // mutates the shared object — no closure-write-back concern (that bug
            // is about reassigning OUTER let bindings, not mutating a param's
            // object). CAVEAT: this allocates the strings object per evaluation;
            // ES2020 §12.2.9 specifies per-call-site caching (same array identity
            // across evaluations), which a parser desugar cannot provide — a
            // memoized runtime template-strings intrinsic is the long-term fix
            // (the cooked-only bd-1lrbw desugar already had this non-memoization).
            let strings_param = "__tt_strings".to_string();
            let raw_arrow = Expression::ArrowFunction {
                params: vec![FunctionParam {
                    pattern: BindingPattern::Identifier(strings_param.clone()),
                    span: span.clone(),
                }],
                body: ArrowBody::Block(BlockStatement {
                    body: vec![
                        Statement::Expression(ExpressionStatement {
                            expression: Expression::Assignment {
                                operator: AssignmentOperator::Assign,
                                left: Box::new(Expression::Member {
                                    object: Box::new(Expression::Identifier(strings_param.clone())),
                                    property: Box::new(Expression::Identifier("raw".to_string())),
                                    computed: false,
                                    span: None,
                                }),
                                right: Box::new(Expression::ArrayLiteral(raw_strings)),
                                assignment_strictness: AssignmentStrictness::from_strict_mode(
                                    context.strict_mode,
                                ),
                            },
                            span: span.clone(),
                        }),
                        Statement::Return(ReturnStatement {
                            argument: Some(Expression::Identifier(strings_param.clone())),
                            span: span.clone(),
                        }),
                    ],
                    span: span.clone(),
                }),
                is_async: false,
                source_text: None,
            };
            let strings_with_raw = Expression::Call {
                callee: Box::new(raw_arrow),
                arguments: vec![Expression::ArrayLiteral(cooked_strings)],
                span: None,
            };
            let mut arguments = Vec::with_capacity(expressions.len() + 1);
            arguments.push(strings_with_raw);
            arguments.extend(expressions);
            return Some(Ok(Expression::Call {
                callee: Box::new(callee),
                arguments,
                span: Some(*span),
            }));
        }
    }

    // Call expression: ends with `)`
    if bytes[bytes.len() - 1] == b')'
        && let Some(open_paren) = find_matching_open_paren(expr)
        && open_paren > 0
    {
        let callee_src = expr[..open_paren].trim();
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
        let arguments =
            match parse_comma_separated_exprs(args_src, span, context, recursion_depth + 1) {
                Ok(a) => a,
                Err(e) => return Some(Err(e)),
            };
        let callee = if callee_src == "super" && !optional {
            if context.super_call == SuperCallContext::Forbidden {
                return Some(Err(unsupported_expression_syntax_error(
                    "'super' keyword unexpected here: super() is only valid in a derived class constructor",
                    span,
                    context,
                )));
            }
            Expression::Super
        } else if callee_src == "import" {
            // ImportCall (ES2020 12.3.10): exactly one specifier; Node v22
            // also accepts an options argument. No spread, no optional call.
            if optional
                || arguments.is_empty()
                || arguments.len() > 2
                || arguments
                    .iter()
                    .any(|argument| matches!(argument, Expression::SpreadElement(_)))
            {
                return Some(Err(unsupported_expression_syntax_error(
                    "import() takes one specifier and an optional options argument",
                    span,
                    context,
                )));
            }
            Expression::Identifier("import".to_string())
        } else {
            match parse_expression(callee_src, span, context, recursion_depth + 1) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            }
        };
        return Some(Ok(if optional {
            Expression::OptionalCall {
                callee: Box::new(callee),
                arguments,
                span: Some(*span),
            }
        } else {
            Expression::Call {
                callee: Box::new(callee),
                arguments,
                span: Some(*span),
            }
        }));
    }

    // Computed member: ends with `]`
    if bytes[bytes.len() - 1] == b']'
        && let Some(open_bracket) = find_matching_open_bracket(expr)
        && open_bracket > 0
    {
        let object_src = expr[..open_bracket].trim();
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
        if object_src == "super" && !context.super_property_allowed {
            return Some(Err(unsupported_expression_syntax_error(
                "super expressions are not supported",
                span,
                context,
            )));
        }
        let object = if object_src == "super" {
            Expression::Super
        } else {
            match parse_expression(object_src, span, context, recursion_depth + 1) {
                Ok(e) => parenthesized_chain_boundary(object_src, e),
                Err(e) => return Some(Err(e)),
            }
        };
        let property = match parse_expression_allowing_sequence(
            prop_src.trim(),
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
                span: Some(*span),
            }
        } else {
            Expression::Member {
                object: Box::new(object),
                property: Box::new(property),
                computed: true,
                span: Some(*span),
            }
        }));
    }

    // Dot member access: a.b
    if let Some(dot_pos) = find_last_top_level_dot(expr) {
        let object_src = expr[..dot_pos].trim();
        let property_src = expr[dot_pos + 1..].trim();
        let (object_src, optional) = if let Some(stripped) = object_src.strip_suffix('?') {
            (stripped.trim(), true)
        } else {
            (object_src, false)
        };
        // ES2022 `o.#x` / `o?.#x`: a private member is a computed member whose
        // key is the class's private name, held by the hidden binding `#x`.
        let private_name = whole_private_name(property_src);
        // `o.# x`: a private name has no whitespace after its `#`.
        if private_name.is_none() && property_src.starts_with('#') {
            return Some(Err(unsupported_expression_syntax_error(
                "invalid private name after `.`",
                span,
                context,
            )));
        }
        if optional && !is_identifier(property_src) && private_name.is_none() {
            return Some(Err(optional_chaining_syntax_error(
                "optional chaining property access requires an identifier after `?.`",
                span,
                context,
            )));
        }
        if let Some(name) = private_name
            && !object_src.is_empty()
        {
            if object_src == "super" {
                return Some(Err(unsupported_expression_syntax_error(
                    "super has no private members (`super.#x`)",
                    span,
                    context,
                )));
            }
            let object = match parse_expression(object_src, span, context, recursion_depth + 1) {
                Ok(e) => parenthesized_chain_boundary(object_src, e),
                Err(e) => return Some(Err(e)),
            };
            if let Err(error) = record_private_name_reference(&name, span, context) {
                return Some(Err(error));
            }
            let property = Box::new(Expression::Identifier(name));
            return Some(Ok(if optional {
                Expression::OptionalMember {
                    object: Box::new(object),
                    property,
                    computed: true,
                    span: Some(*span),
                }
            } else {
                Expression::Member {
                    object: Box::new(object),
                    property,
                    computed: true,
                    span: Some(*span),
                }
            }));
        }
        if object_src == "super" && !context.super_property_allowed {
            return Some(Err(unsupported_expression_syntax_error(
                "super expressions are not supported",
                span,
                context,
            )));
        }
        if object_src == "new" && property_src == "target" {
            return Some(Ok(Expression::NewTarget));
        }
        if object_src == "import" && property_src == "meta" {
            return Some(Ok(Expression::ImportMeta));
        }
        if !object_src.is_empty() && is_identifier(property_src) {
            let object = if object_src == "super" {
                Expression::Super
            } else {
                match parse_expression(object_src, span, context, recursion_depth + 1) {
                    Ok(e) => parenthesized_chain_boundary(object_src, e),
                    Err(e) => return Some(Err(e)),
                }
            };
            return Some(Ok(if optional {
                Expression::OptionalMember {
                    object: Box::new(object),
                    property: Box::new(Expression::Identifier(canonicalize_identifier(
                        property_src,
                    ))),
                    computed: false,
                    span: Some(*span),
                }
            } else {
                Expression::Member {
                    object: Box::new(object),
                    property: Box::new(Expression::Identifier(canonicalize_identifier(
                        property_src,
                    ))),
                    computed: false,
                    span: Some(*span),
                }
            }));
        }
    }

    if find_last_top_level_optional_chain(expr).is_some() {
        return Some(Err(optional_chaining_syntax_error(
            "unsupported optional chaining form",
            span,
            context,
        )));
    }

    None
}

/// ES2020 12.3.9: parentheses end an optional chain, so in `(a?.b).c` a
/// nullish `a` still makes `.c` read a property of undefined (TypeError),
/// while `a?.b.c` short-circuits to undefined. The AST drops parentheses, so a
/// parenthesized chain used as the object of a further member access is kept
/// apart as `true ? chain : undefined` (the same value), which the lowering's
/// whole-chain short-circuit does not look through.
fn parenthesized_chain_boundary(source: &str, parsed: Expression) -> Expression {
    let parenthesized = source.starts_with('(')
        && extract_balanced(source, '(', ')').is_some_and(|(_, rest)| rest.trim().is_empty());
    if parenthesized && expression_is_optional_chain(&parsed) {
        Expression::Conditional {
            test: Box::new(Expression::BooleanLiteral(true)),
            consequent: Box::new(parsed),
            alternate: Box::new(Expression::UndefinedLiteral),
        }
    } else {
        parsed
    }
}

/// Whether a `new` callee is an optional chain, which ES2020 12.3.9.1 makes a
/// SyntaxError (`new a?.b()`). A parenthesized callee is an ordinary operand
/// whatever it holds (zod: `new (params?.Err ?? Err)(issues)`), and a chain
/// inside a binary or conditional operand is not the callee's own chain.
fn new_callee_is_optional_chain(callee_src: &str, callee: &Expression) -> bool {
    let parenthesized = callee_src.starts_with('(')
        && extract_balanced(callee_src, '(', ')').is_some_and(|(_, rest)| rest.trim().is_empty());
    !parenthesized && expression_is_optional_chain(callee)
}

/// Whether `expression` is a member/call chain containing an optional link.
fn expression_is_optional_chain(expression: &Expression) -> bool {
    let mut node = expression;
    loop {
        match node {
            Expression::OptionalMember { .. } | Expression::OptionalCall { .. } => return true,
            Expression::Member { object, .. } => node = object.as_ref(),
            Expression::Call { callee, .. } => node = callee.as_ref(),
            _ => return false,
        }
    }
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

fn invalid_syntax_error(
    message: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseError {
    ParseError::new(
        ParseErrorCode::InvalidSyntax,
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

/// Whether an assignment target is (or, for a destructuring pattern, has an
/// element or property target that is) an optional chain, which ES2020
/// 12.15.1 makes a SyntaxError (`a?.b = 1`, `a?.b.c = 1`, `[a?.b] = []`).
/// Chains elsewhere in the target are ordinary expressions: a computed key
/// (`t[o?.p] = 1`, arktype), a destructuring default (`[x = o?.p] = []`) or
/// a parenthesized object (`(a?.b).c = 1`).
fn assignment_target_has_optional_chain(target: &Expression) -> bool {
    match target {
        Expression::ArrayLiteral(elements) => elements
            .iter()
            .flatten()
            .any(assignment_target_has_optional_chain),
        Expression::ObjectLiteral(properties) => properties
            .iter()
            .any(|property| assignment_target_has_optional_chain(&property.value)),
        Expression::SpreadElement(inner) => assignment_target_has_optional_chain(inner),
        Expression::Assignment { left, .. } => assignment_target_has_optional_chain(left),
        other => expression_is_optional_chain(other),
    }
}

/// Find the top-level backtick that begins the last (trailing) template
/// literal. In `tag`a``b`` the trailing `b` template's tag is the tagged
/// template `tag`a`` (ES2020 12.3: MemberExpression TemplateLiteral), so
/// the split is before the last template; splitting before the first read
/// `a``b` as one template.
fn find_top_level_template_start(s: &str) -> Option<usize> {
    let mut quotes = QuoteState::default();
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut last = None;

    for (index, ch) in s.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if ch == '/' && quotes.open_regex_at(s, index) {
            continue;
        }

        match ch {
            '\'' | '"' => {
                quotes.open_char(ch);
            }
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => brace_depth = brace_depth.saturating_sub(1),
            // A top-level template is a candidate; its text, like a nested
            // template's (bd-9vouw.41), must not move the bracket depths.
            '`' => {
                if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 {
                    last = Some(index);
                }
                quotes.open_char(ch);
            }
            _ => {}
        }
    }

    last
}

/// Find the first top-level `(`…`)` pair in `s` — the open `(` that appears at
/// depth 0 of all bracket kinds and outside quotes, plus its matching `)`.
/// Returns `(open_index, close_index)`. Used to locate a constructor's argument
/// list so any trailing member/call/index chain can be split off (bd-if9uy).
fn find_first_top_level_paren_pair(s: &str) -> Option<(usize, usize)> {
    let bytes = s.as_bytes();
    let mut quotes = QuoteState::default();
    let mut open: Option<usize> = None;
    let mut paren: i64 = 0;
    let mut bracket: i64 = 0;
    let mut brace: i64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
            }
            b'[' => bracket += 1,
            b']' => bracket -= 1,
            b'{' => brace += 1,
            b'}' => brace -= 1,
            b'(' => {
                if open.is_none() {
                    if bracket == 0 && brace == 0 {
                        open = Some(i);
                        paren = 1;
                    }
                } else {
                    paren += 1;
                }
            }
            b')' if open.is_some() => {
                paren -= 1;
                if paren == 0 {
                    return Some((open.unwrap(), i));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Find the position of the opening `(` that matches the final `)`.
fn find_matching_open_paren(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    // Walking right-to-left cannot recover template nesting, so string and
    // template extents come from a forward pass (bd-9vouw.41).
    let quoted = quoted_byte_mask(s);
    let mut depth: i64 = 0;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if quoted[i] {
            continue;
        }
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Find the position of the opening `[` that matches the final `]`.
fn find_matching_open_bracket(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    // Walking right-to-left cannot recover template nesting, so string and
    // template extents come from a forward pass (bd-9vouw.41).
    let quoted = quoted_byte_mask(s);
    let mut depth: i64 = 0;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        if quoted[i] {
            continue;
        }
        match bytes[i] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Find the last top-level `.` (not inside delimiters, quotes, or numeric literals).
fn find_last_top_level_dot(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();
    let mut last_dot: Option<usize> = None;

    for (i, &b) in bytes.iter().enumerate() {
        if quotes.active() {
            quotes.advance(b);
            continue;
        }
        // `/a.b/.test(x)`: only the `.` after the literal is a member access.
        if b == b'/' && quotes.open_regex_at(s, i) {
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
                continue;
            }
            b'(' => {
                depth_paren += 1;
                continue;
            }
            b')' => {
                depth_paren -= 1;
                continue;
            }
            b'[' => {
                depth_bracket += 1;
                continue;
            }
            b']' => {
                depth_bracket -= 1;
                continue;
            }
            b'{' => {
                depth_brace += 1;
                continue;
            }
            b'}' => {
                depth_brace -= 1;
                continue;
            }
            _ => {}
        }
        if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && b == b'.' {
            // Make sure this isn't a numeric dot (e.g., "3.14").
            let before_digit = i > 0 && bytes[i - 1].is_ascii_digit();
            let after_digit = i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit();
            if !(before_digit && after_digit) {
                last_dot = Some(i);
            }
        }
    }
    last_dot
}

fn find_last_top_level_optional_chain(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();
    let mut last_optional: Option<usize> = None;
    let mut i = 0usize;

    while i + 1 < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
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
            b'[' => {
                depth_bracket += 1;
                i += 1;
                continue;
            }
            b']' => {
                depth_bracket -= 1;
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
        if depth_paren == 0
            && depth_bracket == 0
            && depth_brace == 0
            && b == b'?'
            && bytes[i + 1] == b'.'
        {
            last_optional = Some(i);
            i += 2;
            continue;
        }
        i += 1;
    }

    last_optional
}

// ---------------------------------------------------------------------------
// Array/object literal parsing
// ---------------------------------------------------------------------------

/// Parse cover grammar only where the caller has already recognized an
/// assignment target. An initialized shorthand (`{x = value}`) must never be
/// accepted as an ordinary object expression or in the default's RHS.
fn parse_assignment_target_expression(
    source: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    context.next_depth(recursion_depth);
    if recursion_depth > context.options.budget.max_recursion_depth {
        return Err(ParseError::with_witness(
            ParseErrorCode::BudgetExceeded,
            "assignment pattern recursion budget exceeded",
            context.source_label.to_string(),
            Some(span.clone()),
            context.witness(Some(ParseBudgetKind::RecursionDepth)),
        ));
    }
    let source = source.trim();
    if source.starts_with('{')
        && let Some((inner, rest)) = extract_balanced(source, '{', '}')
        && rest.trim().is_empty()
    {
        return parse_object_literal(inner, span, context, recursion_depth, true);
    }
    if source.starts_with('[')
        && let Some((inner, rest)) = extract_balanced(source, '[', ']')
        && rest.trim().is_empty()
    {
        return parse_array_literal(inner, span, context, recursion_depth, true);
    }
    if let Some(rest) = source.strip_prefix("...") {
        return Ok(Expression::SpreadElement(Box::new(
            parse_assignment_target_expression(rest, span, context, recursion_depth + 1)?,
        )));
    }
    let target = parse_expression(source, span, context, recursion_depth)?;
    // The specific diagnostic first: `config?.theme = value`.
    if assignment_target_has_optional_chain(&target) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "optional chaining cannot be used as an assignment target",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    if !matches!(
        target,
        Expression::Identifier(_)
            | Expression::Member { .. }
            | Expression::ArrayLiteral(_)
            | Expression::ObjectLiteral(_)
            | Expression::Assignment {
                operator: AssignmentOperator::Assign,
                ..
            }
    ) {
        return Err(invalid_syntax_error(
            "invalid assignment target",
            span,
            context,
        ));
    }
    Ok(target)
}

fn parse_array_literal(
    inner: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
    assignment_pattern: bool,
) -> ParseResult<Expression> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return Ok(Expression::ArrayLiteral(Vec::new()));
    }
    let parts = split_top_level_commas(trimmed);
    let mut elements = Vec::with_capacity(4);
    for (index, part) in parts.iter().enumerate() {
        let p = part.trim();
        if p.is_empty() {
            elements.push(None);
        } else {
            let element = if assignment_pattern {
                parse_assignment_target_expression(p, span, context, recursion_depth + 1)?
            } else {
                parse_expression(p, span, context, recursion_depth + 1)?
            };
            if assignment_pattern
                && let Expression::SpreadElement(target) = &element
                && (index + 1 != parts.len()
                    || matches!(target.as_ref(), Expression::Assignment { .. }))
            {
                return Err(unsupported_expression_syntax_error(
                    "assignment rest element must be last, without a default or trailing comma",
                    span,
                    context,
                ));
            }
            elements.push(Some(element));
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
    assignment_pattern: bool,
) -> ParseResult<Expression> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return Ok(Expression::ObjectLiteral(Vec::new()));
    }
    let parts = split_top_level_commas(trimmed);
    let mut properties = Vec::with_capacity(8);
    for (index, part) in parts.iter().enumerate() {
        let p = part.trim();
        if p.is_empty() {
            if index + 1 == parts.len() && trimmed.ends_with(',') {
                continue;
            }
            return Err(unsupported_expression_syntax_error(
                "object patterns cannot contain elisions",
                span,
                context,
            ));
        }
        let initialized_shorthand = assignment_pattern
            && p.split_once('=').is_some_and(|(name, tail)| {
                is_identifier(name.trim()) && !tail.starts_with(['=', '>'])
            });
        // Spread property: `{ ...expr }` — parse the inner expression.
        if let Some(rest) = p.strip_prefix("...") {
            let inner = if assignment_pattern {
                let target = parse_assignment_target_expression(
                    rest.trim_start(),
                    span,
                    context,
                    recursion_depth + 1,
                )?;
                if index + 1 != parts.len()
                    || !matches!(
                        target,
                        Expression::Identifier(_) | Expression::Member { .. }
                    )
                {
                    return Err(unsupported_expression_syntax_error(
                        "object assignment rest requires a final simple reference without a default or trailing comma",
                        span,
                        context,
                    ));
                }
                target
            } else {
                parse_expression(rest.trim_start(), span, context, recursion_depth + 1)?
            };
            let spread = Expression::SpreadElement(Box::new(inner));
            properties.push(ObjectProperty {
                key: spread.clone(),
                value: spread,
                computed: false,
                shorthand: true,
                kind: ObjectPropertyKind::Data,
            });
        } else if !initialized_shorthand && let Some(colon_idx) = find_top_level_colon(p) {
            // Split on first top-level colon for key:value.
            let key_src = p[..colon_idx].trim();
            let value_src = p[colon_idx + 1..].trim();
            let computed = key_src.starts_with('[');
            // For a computed key `[expr]`, the surrounding brackets are the
            // computed-key delimiter, not an array literal — strip one level and
            // parse the inner expression as the key. Otherwise `["a"+"b"]` parses
            // as the array literal `["ab"]`, so the property key becomes an array
            // object rather than the string key "ab" (bd-rjxpx).
            let key_src_inner = if computed {
                key_src
                    .strip_prefix('[')
                    .and_then(|s| s.strip_suffix(']'))
                    .map(str::trim)
                    .unwrap_or(key_src)
            } else {
                key_src
            };
            // An IdentifierName key is a name, not a reference: `{ await: 1 }`
            // in an async function and `{ yield: 1 }` in a generator are
            // ordinary keys (object methods already read their names so).
            let key = if !computed && is_identifier(key_src_inner) {
                Expression::Identifier(canonicalize_identifier(key_src_inner))
            } else {
                parse_expression(key_src_inner, span, context, recursion_depth + 1)?
            };
            let value = if assignment_pattern {
                parse_assignment_target_expression(value_src, span, context, recursion_depth + 1)?
            } else {
                parse_expression(value_src, span, context, recursion_depth + 1)?
            };
            properties.push(ObjectProperty {
                key,
                value,
                computed,
                shorthand: false,
                kind: ObjectPropertyKind::Data,
            });
        } else if !initialized_shorthand
            && let Some((key, value, computed, kind)) =
                try_parse_object_accessor(p, span, context, recursion_depth)?
        {
            if assignment_pattern {
                return Err(unsupported_expression_syntax_error(
                    "accessors are not assignment patterns",
                    span,
                    context,
                ));
            }
            properties.push(ObjectProperty {
                key,
                value,
                computed,
                shorthand: false,
                kind,
            });
        } else if !initialized_shorthand
            && let Some((key, value, computed)) =
                try_parse_object_method(p, span, context, recursion_depth)?
        {
            if assignment_pattern {
                return Err(unsupported_expression_syntax_error(
                    "methods are not assignment patterns",
                    span,
                    context,
                ));
            }
            // Method shorthand: `name(params){body}` or `[expr](params){body}`.
            // Preserve the method distinction for [[HomeObject]], inferred name,
            // prototype suppression, and non-constructability semantics (bd-gqaa4).
            properties.push(ObjectProperty {
                key,
                value,
                computed,
                shorthand: false,
                kind: ObjectPropertyKind::Method,
            });
        } else {
            // Shorthand property: { x } means { x: x }
            let (key, value) = if is_identifier(p) {
                let name = canonicalize_identifier(p);
                reject_reserved_identifier_reference(&name, span, context)?;
                let key = Expression::Identifier(name);
                (key.clone(), key)
            } else if assignment_pattern {
                let value =
                    parse_assignment_target_expression(p, span, context, recursion_depth + 1)?;
                let Expression::Assignment {
                    operator: AssignmentOperator::Assign,
                    left,
                    ..
                } = &value
                else {
                    return Err(unsupported_expression_syntax_error(
                        "invalid initialized assignment shorthand",
                        span,
                        context,
                    ));
                };
                if !matches!(left.as_ref(), Expression::Identifier(_)) {
                    return Err(unsupported_expression_syntax_error(
                        "initialized shorthand requires an identifier",
                        span,
                        context,
                    ));
                }
                (left.as_ref().clone(), value)
            } else {
                return Err(unsupported_expression_syntax_error(
                    "invalid object shorthand property",
                    span,
                    context,
                ));
            };
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

fn object_accessor_tail<'a>(part: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = part.strip_prefix(prefix)?;
    // Minified: `get['k'](){}`, `set"k"(v){}`.
    if rest.starts_with(['[', '\'', '"']) {
        return Some(rest);
    }
    let first = rest.chars().next()?;
    first.is_whitespace().then(|| rest.trim_start())
}

fn try_parse_object_accessor(
    part: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Option<(Expression, Expression, bool, ObjectPropertyKind)>> {
    for (prefix, kind) in [
        ("get", ObjectPropertyKind::Get),
        ("set", ObjectPropertyKind::Set),
    ] {
        let Some(rest) = object_accessor_tail(part, prefix) else {
            continue;
        };
        if rest.starts_with('[') {
            if let Some((key_inner, after)) = extract_balanced(rest, '[', ']') {
                let after = after.trim_start();
                if after.starts_with('(') {
                    let key =
                        parse_expression(key_inner.trim(), span, context, recursion_depth + 1)?;
                    let source = context.function_sources.text_through_body(part, after);
                    // An accessor is a method: its body may use `super.x`
                    // (ES2020 14.3.8 HasSuperProperty is allowed in
                    // MethodDefinition), refused here before.
                    let value = parse_object_method_function_expression(
                        after,
                        span,
                        context,
                        recursion_depth + 1,
                    )?;
                    let value = with_function_source(value, source);
                    reject_object_accessor_arity(kind, &value, span, context)?;
                    return Ok(Some((key, value, true, kind)));
                }
            }
            return Ok(None);
        }

        let Some(paren_idx) = rest.find('(') else {
            return Ok(None);
        };
        let key_src = rest[..paren_idx].trim();
        if key_src.is_empty() {
            return Ok(None);
        }
        // An IdentifierName key names itself, as a method's does: inside a
        // generator `get yield() {}` is the property "yield", which parsed
        // as a yield expression and was refused by lowering (bd-9vouw.289).
        let key = if is_identifier(key_src) {
            Expression::Identifier(canonicalize_identifier(key_src))
        } else {
            parse_expression(key_src, span, context, recursion_depth + 1)?
        };
        let source = context
            .function_sources
            .text_through_body(part, &rest[paren_idx..]);
        let value = parse_object_method_function_expression(
            &rest[paren_idx..],
            span,
            context,
            recursion_depth + 1,
        )?;
        let value = with_function_source(value, source);
        reject_object_accessor_arity(kind, &value, span, context)?;
        return Ok(Some((key, value, false, kind)));
    }

    Ok(None)
}

/// [`reject_accessor_arity`] for an object literal's accessor function, and
/// its parameter names are unique, as for any method.
fn reject_object_accessor_arity(
    kind: ObjectPropertyKind,
    value: &Expression,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    if let Expression::Function { params, .. } = value {
        reject_accessor_arity(kind == ObjectPropertyKind::Get, params, span, context)?;
        reject_duplicate_params(params, true, span, context)?;
    }
    Ok(())
}

/// Try to parse an object-literal method shorthand:
/// `name(params){body}` (plain) or `[expr](params){body}` (computed).
///
/// Returns `Ok(Some((key, value, computed)))` where `value` is a function
/// expression, or `Ok(None)` when `part` is not a method definition so the
/// caller can fall back to shorthand-identifier handling.
///
/// `async` and generator (`*`) method forms are intentionally not recognized
/// here. Getter/setter forms are handled by `try_parse_object_accessor`.
fn try_parse_object_method(
    part: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Option<(Expression, Expression, bool)>> {
    // The method's source text starts at its modifiers (bd-9vouw.184).
    let head = part;
    // Method modifiers (ES2020 14.4-14.7): `*name(){}`, `async name(){}`,
    // `async *name(){}`. `async(){}` / `async: v` name a property `async`.
    let (is_async, part) = match part.strip_prefix("async") {
        // Minified: `async*g(){}`, `async[k](){}`.
        Some(rest) if rest.starts_with(['*', '[', '\'', '"']) => (true, rest),
        Some(rest)
            if rest.starts_with([' ', '\t'])
                && !rest.trim_start().starts_with(['(', ':', ',', '=']) =>
        {
            (true, rest.trim_start())
        }
        _ => (false, part),
    };
    let (is_generator, part) = match part.strip_prefix('*') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, part),
    };
    let method_value = |params_and_body: &str,
                        context: &mut ParseExecutionContext<'_>|
     -> ParseResult<Expression> {
        let source = context
            .function_sources
            .text_through_body(head, params_and_body);
        let value = if !is_async && !is_generator {
            parse_object_method_function_expression(
                params_and_body,
                span,
                context,
                recursion_depth + 1,
            )?
        } else {
            let source = if is_generator {
                format!("*{params_and_body}")
            } else {
                params_and_body.to_string()
            };
            parse_function_expression_with_super(
                &source,
                span,
                context,
                recursion_depth + 1,
                true,
                is_async,
            )?
        };
        // A method's parameter names are unique (ES2020 14.3.1).
        if let Expression::Function { params, .. } = &value {
            reject_duplicate_params(params, true, span, context)?;
        }
        Ok(with_function_source(value, source))
    };

    // Computed method: `[expr](params){body}`.
    if part.starts_with('[') {
        if let Some((key_inner, after)) = extract_balanced(part, '[', ']') {
            let after = after.trim_start();
            if after.starts_with('(') {
                let key = parse_expression(key_inner.trim(), span, context, recursion_depth + 1)?;
                let value = method_value(after, context)?;
                return Ok(Some((key, value, true)));
            }
        }
        return Ok(None);
    }

    // Plain method: `name(params){body}` where `name` is an IdentifierName or
    // quoted PropertyName.
    let Some(paren_idx) = part.find('(') else {
        return Ok(None);
    };
    let name = part[..paren_idx].trim();
    let key = if is_identifier(name) {
        Expression::Identifier(canonicalize_identifier(name))
    } else if matches!(name.as_bytes().first(), Some(b'\'' | b'"')) {
        parse_contextual_static_property_key(
            name,
            span,
            context,
            legacy_decimal_escape_mode(context),
            "object-method",
        )?
    } else if name.starts_with(|ch: char| ch.is_ascii_digit() || ch == '.')
        && let Ok(
            numeric @ (Expression::NumericLiteral(_)
            | Expression::FloatLiteral(_)
            | Expression::BigIntLiteral(_)),
        ) = parse_expression(name, span, context, recursion_depth + 1)
    {
        // A NumericLiteral name (`{ 1(a) {} }`, mobx's error table): the key
        // is ToPropertyKey of the number ("0x10" names "16"), so it is
        // evaluated like a computed key; the method name is the same string.
        let value = method_value(&part[paren_idx..], context)?;
        return Ok(Some((numeric, value, true)));
    } else {
        return Ok(None);
    };
    let value = method_value(&part[paren_idx..], context)?;
    Ok(Some((key, value, false)))
}

// ---------------------------------------------------------------------------
// Comma splitting for argument lists and array/object literals
// ---------------------------------------------------------------------------

/// Split a string by top-level commas (not inside delimiters or quotes).
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut depth_paren: i64 = 0;
    let mut depth_bracket: i64 = 0;
    let mut depth_brace: i64 = 0;
    let mut quotes = QuoteState::default();
    let mut escaped = false;
    // A regex literal (`/,/`) may contain commas and brackets; it is skipped
    // with the same regex-vs-division rule the line merger uses.
    let mut in_regex = false;
    let mut regex_class = false;
    // Every list this splits (arguments, elements, declarators) starts in
    // expression position, as after a `,`: a leading `/=/` is a regex.
    let mut last_significant: Option<char> = Some(',');
    let mut trailing_identifier = String::new();
    let mut parts = Vec::with_capacity(4);
    let mut start = 0;

    for (i, &b) in bytes.iter().enumerate() {
        if quotes.active() {
            quotes.advance(b);
            if !quotes.active() {
                // The closed literal is an operand: a following `/` divides.
                last_significant = Some(')');
                trailing_identifier.clear();
            }
            continue;
        }
        if in_regex {
            if escaped {
                escaped = false;
                continue;
            }
            match b {
                b'\\' => escaped = true,
                b'[' => regex_class = true,
                b']' => regex_class = false,
                b'/' if !regex_class => {
                    in_regex = false;
                    // The literal is an operand: a following `/` divides.
                    last_significant = Some(')');
                    trailing_identifier.clear();
                }
                _ => {}
            }
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
                continue;
            }
            b'/' => {
                let next = bytes.get(i + 1).map(|next| *next as char);
                if !matches!(next, Some('/' | '*'))
                    && merge_logical_lines_slash_starts_regex(
                        last_significant,
                        trailing_identifier.as_str(),
                        next,
                    )
                {
                    in_regex = true;
                    regex_class = false;
                    continue;
                }
            }
            b'(' => depth_paren += 1,
            b')' => depth_paren -= 1,
            b'[' => depth_bracket += 1,
            b']' => depth_bracket -= 1,
            b'{' => depth_brace += 1,
            b'}' => depth_brace -= 1,
            _ => {}
        }
        if !b.is_ascii_whitespace() {
            let ch = b as char;
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
                if !last_significant
                    .is_some_and(|last| last.is_ascii_alphanumeric() || last == '_' || last == '$')
                {
                    trailing_identifier.clear();
                }
                trailing_identifier.push(ch);
            } else {
                trailing_identifier.clear();
            }
            last_significant = Some(ch);
        }
        if depth_paren == 0 && depth_bracket == 0 && depth_brace == 0 && b == b',' {
            parts.push(&s[start..i]);
            start = i + 1;
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Parse a comma-separated list of expressions (for function call arguments).
fn parse_comma_separated_exprs(
    s: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Vec<Expression>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let parts = split_top_level_commas(trimmed);
    let mut exprs = Vec::with_capacity(4);
    for part in &parts {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        exprs.push(parse_expression(p, span, context, recursion_depth + 1)?);
    }
    Ok(exprs)
}

/// ES2021 NumericLiteralSeparator placement in a literal spelling without
/// its sign: a literal starts with a digit (or `.` for `.5`), and every `_`
/// sits between two digits (`1_000`, `0xFF_FF`, `1_000n`). `_n`, `_1` and
/// `_0x1f` are identifiers, not literals: stripping their underscores used
/// to read `_n` as `0n` and `_0x1f` as 31.
fn numeric_separators_are_valid(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    if !bytes.contains(&b'_') {
        return true;
    }
    // bd-9vouw.176: `.0_1e2` starts with its decimal point.
    let leading_digit = match bytes {
        [b'.', second, ..] => second.is_ascii_digit(),
        [first, ..] => first.is_ascii_digit(),
        [] => false,
    };
    leading_digit
        && bytes.iter().enumerate().all(|(index, &byte)| {
            byte != b'_'
                || (index > 0
                    && bytes[index - 1].is_ascii_hexdigit()
                    && bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit))
        })
}

fn parse_i64_numeric_literal(input: &str) -> Option<i64> {
    // Accept an explicit `+` or `-` sign prefix. try_parse_unary_prefix
    // intentionally skips unary +/- when the next char is a digit so the
    // literal parser owns signed integer literals end-to-end; previously
    // only `-` was stripped here, so `+0` (and any `+<digit>` form) failed
    // to parse as a primary expression. The upstream `===` comparison then
    // surfaced as a spurious `false` because the left operand parsed as a
    // non-numeric value. (bd-bs81a)
    let (is_neg, digits) = if let Some(rest) = input.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = input.strip_prefix('+') {
        (false, rest)
    } else {
        (false, input)
    };

    if digits.is_empty() || !numeric_separators_are_valid(digits) {
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
    } else if digits_ref.len() > 1
        && digits_ref.starts_with('0')
        && digits_ref.bytes().all(|byte| byte.is_ascii_digit())
    {
        // Annex B.1.1: a leading zero followed only by octal digits is a
        // LegacyOctalIntegerLiteral (`010` is 8), one with an 8 or 9 a
        // NonOctalDecimalIntegerLiteral (`08` is 8). Neither may contain a
        // separator. Read as decimal, `070` was 70.
        if digits.contains('_') {
            return None;
        }
        if digits_ref.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
            u64::from_str_radix(&digits_ref[1..], 8).ok()?
        } else {
            digits_ref.parse::<u64>().ok()?
        }
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

/// Whether `input` is spelled as a numeric literal ending in the BigInt
/// suffix `n`: digits (or `.digit`), letters, `.`, `_`, and a sign only
/// after an exponent `e`. Callers try [`parse_bigint_numeric_literal`] first.
fn is_malformed_bigint_literal(input: &str) -> bool {
    let body = input.strip_prefix('-').unwrap_or(input);
    let Some(digits) = body.strip_suffix('n') else {
        return false;
    };
    let starts_numeric = digits.starts_with(|c: char| c.is_ascii_digit())
        || (digits.starts_with('.') && digits[1..].starts_with(|c: char| c.is_ascii_digit()));
    if !starts_numeric {
        return false;
    }
    let mut previous = ' ';
    for ch in digits.chars() {
        let allowed = ch.is_ascii_alphanumeric()
            || matches!(ch, '.' | '_')
            || (matches!(ch, '+' | '-') && matches!(previous, 'e' | 'E'));
        if !allowed {
            return false;
        }
        previous = ch;
    }
    true
}

fn parse_bigint_numeric_literal(input: &str) -> Option<String> {
    // `-1n` folds to a negative literal. `+1n` must not: unary `+` on a BigInt
    // throws a TypeError (ES2020 12.5.6.1), so it stays a unary expression.
    let (is_neg, digits) = if let Some(rest) = input.strip_prefix('-') {
        (true, rest)
    } else {
        (false, input)
    };

    let digits = digits.strip_suffix('n')?;
    // `e`/`E` are hex digits (`0xFEn`); exponents are rejected by the decimal
    // branch below, which accepts only digits (bd-6vl81).
    if digits.is_empty() || digits.contains('.') || !numeric_separators_are_valid(digits) {
        return None;
    }

    let cleaned: String;
    let digits_ref = if digits.contains('_') {
        cleaned = digits.replace('_', "");
        cleaned.as_str()
    } else {
        digits
    };

    let unsigned = if let Some(hex) = digits_ref
        .strip_prefix("0x")
        .or_else(|| digits_ref.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        radix_digits_to_decimal(hex, 16)?
    } else if let Some(oct) = digits_ref
        .strip_prefix("0o")
        .or_else(|| digits_ref.strip_prefix("0O"))
    {
        if oct.is_empty() || !oct.chars().all(|c| matches!(c, '0'..='7')) {
            return None;
        }
        radix_digits_to_decimal(oct, 8)?
    } else if let Some(bin) = digits_ref
        .strip_prefix("0b")
        .or_else(|| digits_ref.strip_prefix("0B"))
    {
        if bin.is_empty() || !bin.chars().all(|c| c == '0' || c == '1') {
            return None;
        }
        radix_digits_to_decimal(bin, 2)?
    } else if digits_ref.chars().all(|c| c.is_ascii_digit()) {
        let trimmed = digits_ref.trim_start_matches('0');
        if trimmed.is_empty() {
            "0".to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        return None;
    };

    if is_neg && unsigned != "0" {
        Some(format!("-{unsigned}"))
    } else {
        Some(unsigned)
    }
}

/// Exact decimal spelling of an unsigned integer written in `radix`, for
/// BigInt literals of any length (they previously failed past `u128` and fell
/// through to `Expression::Raw`, bd-6vl81). Leading zeros are dropped.
fn radix_digits_to_decimal(digits: &str, radix: u32) -> Option<String> {
    const LIMB_BASE: u64 = 1_000_000_000;
    if digits.is_empty() {
        return None;
    }
    // Little-endian base-10^9 limbs; limb * radix + carry stays far below u64::MAX.
    let mut limbs: Vec<u64> = vec![0];
    for ch in digits.chars() {
        let mut carry = u64::from(ch.to_digit(radix)?);
        for limb in &mut limbs {
            let value = *limb * u64::from(radix) + carry;
            *limb = value % LIMB_BASE;
            carry = value / LIMB_BASE;
        }
        while carry > 0 {
            limbs.push(carry % LIMB_BASE);
            carry /= LIMB_BASE;
        }
    }
    let mut limbs = limbs.iter().rev();
    let mut decimal = limbs.next()?.to_string();
    for limb in limbs {
        decimal.push_str(&format!("{limb:09}"));
    }
    Some(decimal)
}

/// Parse a floating-point numeric literal: decimal (1.5), leading dot (.5),
/// trailing dot (1.), or scientific notation (1e10, 1.5e-3).
fn parse_f64_numeric_literal(input: &str) -> Option<f64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Handle special values
    if trimmed == "Infinity" {
        return Some(f64::INFINITY);
    }
    if trimmed == "-Infinity" {
        return Some(f64::NEG_INFINITY);
    }
    if trimmed == "NaN" {
        return Some(f64::NAN);
    }

    // Strip numeric separators
    let unsigned = trimmed.strip_prefix(['-', '+']).unwrap_or(trimmed);
    if !numeric_separators_are_valid(unsigned) {
        return None;
    }
    let cleaned: String;
    let digits_ref = if trimmed.contains('_') {
        cleaned = trimmed.replace('_', "");
        cleaned.as_str()
    } else {
        trimmed
    };

    // Without a decimal point or exponent this is an integer spelling; only
    // one that `i64` cannot represent is a float literal here.
    if !digits_ref.contains('.') && !digits_ref.contains('e') && !digits_ref.contains('E') {
        if parse_i64_numeric_literal(digits_ref).is_some() {
            return None;
        }
        return parse_large_integer_literal(digits_ref);
    }

    // Try to parse as f64
    digits_ref.parse::<f64>().ok()
}

/// An integer literal too large for `i64` (bd-6vl81): decimal digits or a
/// `0x` / `0o` / `0b` radix form, rounded to the nearest Number as ECMAScript
/// numeric literals are. It used to fall through to `Expression::Raw` and
/// evaluate as a *string* (`typeof 123456789012345680000 === "string"`).
/// Legacy octal (`0777`) and anything else malformed stay unrecognized.
fn parse_large_integer_literal(digits: &str) -> Option<f64> {
    let (negative, body) = match digits.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, digits),
    };
    let radix_digits =
        |prefixes: [&str; 2]| prefixes.iter().find_map(|prefix| body.strip_prefix(prefix));
    let value = if let Some(hex) = radix_digits(["0x", "0X"]) {
        radix_integer_to_f64(hex, 16)?
    } else if let Some(octal) = radix_digits(["0o", "0O"]) {
        radix_integer_to_f64(octal, 8)?
    } else if let Some(binary) = radix_digits(["0b", "0B"]) {
        radix_integer_to_f64(binary, 2)?
    } else if !body.is_empty()
        && body.bytes().all(|byte| byte.is_ascii_digit())
        && !(body.len() > 1 && body.starts_with('0'))
    {
        // Rust's decimal parser rounds to nearest, ties to even.
        body.parse::<f64>().ok()?
    } else {
        return None;
    };
    Some(if negative { -value } else { value })
}

/// Correctly rounded value of a radix integer: exact in `u128`, then one
/// round-to-nearest conversion. Longer spellings saturate to infinity like
/// any Number beyond `f64::MAX`.
fn radix_integer_to_f64(digits: &str, radix: u32) -> Option<f64> {
    if digits.is_empty() {
        return None;
    }
    let mut exact: Option<u128> = Some(0);
    let mut approximate = 0.0_f64;
    for ch in digits.chars() {
        let digit = ch.to_digit(radix)?;
        exact = exact
            .and_then(|value| value.checked_mul(u128::from(radix)))
            .and_then(|value| value.checked_add(u128::from(digit)));
        approximate = approximate * f64::from(radix) + f64::from(digit);
    }
    Some(exact.map_or(approximate, |value| value as f64))
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
    if context.strict_mode {
        LegacyDecimalEscapeMode::Reject
    } else {
        LegacyDecimalEscapeMode::AnnexBSloppy
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
            // ES NonEscapeCharacter: the escape contributes the character.
            other => push_char_utf16(&mut units, other),
        }
    }
    Some(JsString::from_code_units(&units))
}

/// Cook one raw template quasi into its template value (ES2020 11.8.6.1 TV):
/// escapes decode as in string literals, a backslash before a line terminator
/// (a line continuation) contributes nothing, and a literal CR LF or CR is
/// LF. [`parse_template_literal`] keeps quasis raw (the `.raw` strings of a
/// tagged template) and has already rejected malformed escapes in untagged
/// templates, so `None` here means a `NotEscapeSequence`.
pub(crate) fn cook_template_quasi(raw: &str) -> Option<JsString> {
    if !raw.contains(['\\', '\r']) {
        return Some(JsString::from(raw));
    }
    let mut units = Vec::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            units.push(u16::from(b'\n'));
            continue;
        }
        if ch != '\\' {
            push_char_utf16(&mut units, ch);
            continue;
        }
        match chars.next()? {
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
            '0'..='9' => return None,
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
            other => push_char_utf16(&mut units, other),
        }
    }
    Some(JsString::from_code_units(&units))
}

/// Parse a quoted module specifier into its exact ECMAScript UTF-16 value.
/// Module code is strict, so legacy decimal escapes remain rejected while
/// lone-surrogate Unicode escapes stay distinct rather than being projected
/// through UTF-8.
pub(crate) fn parse_quoted_string(input: &str) -> Option<JsString> {
    parse_quoted_expression_string(input, LegacyDecimalEscapeMode::Reject)
}

/// Parse a regex literal: `/pattern/flags`.
///
/// The pattern may contain escaped slashes (`\/`) or character classes with
/// slashes (`[/]`). Flags are the standard ECMAScript regex flags: g, i, m, s, u, y.
/// A regular expression literal, or its early SyntaxError (ES2020 12.2.8.1:
/// invalid flags, or a pattern the runtime could not run either).
fn regexp_literal_expression(
    pattern: String,
    flags: String,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<Expression> {
    if let Some(message) = crate::baseline_interpreter::regexp_literal_early_error(&pattern, &flags)
    {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            message,
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(Expression::RegExpLiteral { pattern, flags })
}

fn parse_regexp_literal(input: &str) -> Option<(String, String)> {
    let input = input.trim();
    let (end, pattern, flags) = leading_regexp_literal(input)?;
    if input[end..].trim().is_empty() {
        Some((pattern, flags))
    } else {
        None
    }
}

/// Byte length of the regex literal at `expr[slash..]` when that slash sits
/// where an expression can begin (at the start, after an operator or opening
/// bracket, or after a keyword such as `return`) and so opens a regex rather
/// than dividing. Operator scanners skip the literal, so the `=` in `/a=b/` or
/// `/=/g` is never mistaken for an assignment.
fn regex_literal_len_at(expr: &str, slash: usize) -> Option<usize> {
    // `//` and `/*` open comments; no regex body starts with `/` or `*`.
    if matches!(expr.as_bytes().get(slash + 1), Some(b'/' | b'*')) {
        return None;
    }
    let before = expr[..slash].trim_end();
    let identifier_start = before
        .char_indices()
        .rev()
        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '$'))
        .map_or(0, |(index, ch)| index + ch.len_utf8());
    // No next-character check: in expression position `/=` opens a regex too.
    // After a spread `...` an operand starts (`[.../a/g[Symbol.matchAll](s)]`);
    // a single `.` before `/` is a member access or `1./2`.
    if !before.ends_with("...")
        && !closes_control_statement_head(before)
        && !merge_logical_lines_slash_starts_regex(
            before.chars().next_back(),
            &before[identifier_start..],
            None,
        )
    {
        return None;
    }
    // A regex literal never spans a line, so a `/` whose "literal" would
    // (`i++ / 2` … `/`) divides. `leading_regexp_literal` stops at the line
    // end itself; cutting the line out first rescanned the rest of a long
    // line for every slash on it (quadratic in a one-line bundle).
    leading_regexp_literal(&expr[slash..]).map(|(end, _, _)| end)
}

/// The first `{` of `text` outside parentheses, brackets and string or
/// template literals.
fn first_top_level_brace(text: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (index, ch) in text.char_indices() {
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == open {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => quote = Some(ch),
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            '{' if depth == 0 => return Some(index),
            _ => {}
        }
    }
    None
}

/// The offset of a class body's `{` in the text after `extends`. The heritage
/// is a left-hand-side expression: braces inside parentheses
/// (`extends (class {...})`, `extends mix({...})`) are not the body, and a
/// class or function expression heritage (`extends class Base {...} {...}`,
/// `extends function () {...} {...}`) has its own body first.
fn class_heritage_body_brace(after_extends: &str) -> Option<usize> {
    let heritage = after_extends.trim_start();
    let lead = after_extends.len() - heritage.len();
    // bd-9vouw.176: a function expression heritage's body comes before the
    // class body (its parameters sit in parentheses).
    let function_header = heritage
        .strip_prefix("async")
        .filter(|rest| rest.starts_with(char::is_whitespace))
        .map_or(heritage, str::trim_start)
        .strip_prefix("function")
        .filter(|rest| rest.starts_with(|ch: char| ch.is_whitespace() || ch == '(' || ch == '*'));
    if let Some(function_header) = function_header {
        let function_start = lead + (heritage.len() - function_header.len());
        let body = first_top_level_brace(function_header)?;
        let (_, tail) = extract_balanced(&function_header[body..], '{', '}')?;
        let tail_start = function_start + (function_header.len() - tail.len());
        return Some(tail_start + first_top_level_brace(tail)?);
    }
    let inner_header = heritage
        .strip_prefix("class")
        .filter(|rest| rest.starts_with(|ch: char| ch.is_whitespace() || ch == '{'));
    let Some(inner_header) = inner_header else {
        return first_top_level_brace(after_extends);
    };
    let inner_start = lead + (heritage.len() - inner_header.len());
    let header_brace = first_top_level_brace(inner_header)?;
    let inner_body = match inner_header[..header_brace].find(" extends ") {
        Some(extends) => {
            let after = extends + " extends ".len();
            after + class_heritage_body_brace(&inner_header[after..])?
        }
        None if inner_header.trim_start().starts_with("extends ") => {
            let after = inner_header.len() - inner_header.trim_start().len() + "extends ".len();
            after + class_heritage_body_brace(&inner_header[after..])?
        }
        None => header_brace,
    };
    let body_and_tail = &inner_header[inner_body..];
    let (_, tail) = extract_balanced(body_and_tail, '{', '}')?;
    let tail_start = inner_start + inner_body + (body_and_tail.len() - tail.len());
    Some(tail_start + first_top_level_brace(tail)?)
}

/// Whether `before` ends with the `)` of an `if`/`while`/`for`/`with` head,
/// after which a statement starts, so a `/` opens a regular expression
/// (`if (ok) /}/.test(s)`), whereas after a call's `)` it divides
/// (`f(x) / 2`). A keyword used as a property name (`o.if(x) / 2`) is a
/// call.
fn closes_control_statement_head(before: &str) -> bool {
    if !before.ends_with(')') {
        return false;
    }
    let mut depth = 0usize;
    for (index, byte) in before.bytes().enumerate().rev() {
        match byte {
            b')' => depth += 1,
            b'(' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let head = before[..index].trim_end();
                    let start = head
                        .char_indices()
                        .rev()
                        .find(|(_, ch)| !(ch.is_ascii_alphanumeric() || *ch == '_' || *ch == '$'))
                        .map_or(0, |(position, ch)| position + ch.len_utf8());
                    let keyword = &head[start..];
                    let is_property = head[..start].trim_end().ends_with('.');
                    return !is_property && matches!(keyword, "if" | "while" | "for" | "with");
                }
            }
            _ => {}
        }
    }
    false
}

/// Return the byte end and components of a regex literal at the start of `input`.
fn leading_regexp_literal(input: &str) -> Option<(usize, String, String)> {
    if !input.starts_with('/') {
        return None;
    }

    // Find the closing slash, handling escapes and character classes
    let bytes = input.as_bytes();
    let mut i = 1; // Start after opening slash
    let mut in_char_class = false;
    let mut prev_escape = false;

    while i < bytes.len() {
        let c = bytes[i];
        // RegularExpressionNonTerminator excludes every line terminator, even
        // escaped: LF, CR, and U+2028/U+2029 (E2 80 A8/A9).
        if c == b'\n'
            || c == b'\r'
            || (c == 0xE2
                && bytes.get(i + 1) == Some(&0x80)
                && matches!(bytes.get(i + 2), Some(0xA8 | 0xA9)))
        {
            return None;
        }
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
            // Parse flags (d, g, i, m, s, u, v, y)
            let mut flags = String::new();
            let mut end = i + 1;
            for (offset, fc) in rest.char_indices() {
                if matches!(fc, 'g' | 'i' | 'm' | 's' | 'u' | 'y' | 'd' | 'v') {
                    flags.push(fc);
                    end = i + 1 + offset + fc.len_utf8();
                } else {
                    // Stop at non-flag character (could be operator or whitespace)
                    break;
                }
            }
            return Some((end, pattern.to_string(), flags));
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

/// The ASCII bytes that ES2020 §11.2 `WhiteSpace` treats as insignificant
/// between tokens: `<SP>`, `<TAB>`, `<VT>`, `<FF>`, `<CR>`, `<LF>`.
///
/// This deliberately includes `U+000B VERTICAL TAB`, which `u8::is_ascii_whitespace`
/// (the WhatWG-Infra definition Rust follows) omits. That omission was the
/// source of the SIMD-vs-scalar token-count divergence tracked by bd-2noh9: the
/// SIMD [`Utf8BoundarySafeScanner`] classifies `<VT>` as whitespace via
/// `LEX_CLASS_WHITESPACE` (so it produces no token), while the scalar reference
/// used `is_ascii_whitespace` and counted a lone `<VT>` as a symbol token. This
/// predicate mirrors the SIMD whitespace class exactly (see
/// `build_lex_byte_class_table`) so both counters agree with the ES spec.
const fn is_ascii_lexical_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
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
        if self.index < self.bytes.len() && self.bytes[self.index] == b'n' {
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
        if is_ascii_lexical_whitespace(byte) {
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
            if index < bytes.len() && bytes[index] == b'n' {
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

/// Unicode ID_Start and ID_Continue (ES2020 11.6: UnicodeIDStart,
/// UnicodeIDContinue), for characters outside ASCII.
fn unicode_identifier_sets() -> &'static (regex::Regex, regex::Regex) {
    static SETS: std::sync::OnceLock<(regex::Regex, regex::Regex)> = std::sync::OnceLock::new();
    SETS.get_or_init(|| {
        let set = |property: &str| {
            regex::Regex::new(&format!(r"^\p{{{property}}}$")).expect("Unicode identifier property")
        };
        (set("ID_Start"), set("ID_Continue"))
    })
}

fn is_identifier_start(ch: char) -> bool {
    if ch.is_ascii() {
        return ch.is_ascii_alphabetic() || ch == '_' || ch == '$';
    }
    let mut buffer = [0u8; 4];
    unicode_identifier_sets()
        .0
        .is_match(ch.encode_utf8(&mut buffer))
}

fn is_identifier_continue(ch: char) -> bool {
    if ch.is_ascii() {
        return ch.is_ascii_alphanumeric() || ch == '_' || ch == '$';
    }
    // ZWNJ and ZWJ may continue an identifier (ES2020 11.6).
    let mut buffer = [0u8; 4];
    ch == '\u{200C}'
        || ch == '\u{200D}'
        || unicode_identifier_sets()
            .1
            .is_match(ch.encode_utf8(&mut buffer))
}

/// Decode the `\uXXXX` / `\u{X..}` `UnicodeEscapeSequence`s permitted in an
/// `IdentifierName` (ES2020 §11.6). Returns the decoded spelling when every
/// escape is well-formed, else `None`. Non-`\u` escapes are not valid in an
/// identifier and yield `None`. This does not itself validate that the decoded
/// characters are identifier-legal — `is_identifier` does that on the result.
fn decode_identifier_escapes(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        // Only `\u` escapes are legal in an IdentifierName.
        if chars.next()? != 'u' {
            return None;
        }
        let code_point = if chars.peek() == Some(&'{') {
            chars.next(); // consume `{`
            let mut hex = String::new();
            loop {
                match chars.next()? {
                    '}' => break,
                    digit if digit.is_ascii_hexdigit() => hex.push(digit),
                    _ => return None,
                }
            }
            if hex.is_empty() {
                return None;
            }
            u32::from_str_radix(&hex, 16).ok()?
        } else {
            let mut hex = String::with_capacity(4);
            for _ in 0..4 {
                let digit = chars.next()?;
                if !digit.is_ascii_hexdigit() {
                    return None;
                }
                hex.push(digit);
            }
            u32::from_str_radix(&hex, 16).ok()?
        };
        out.push(char::from_u32(code_point)?);
    }
    Some(out)
}

/// Canonical spelling of an identifier name: any `\u` escapes decoded to the
/// characters they denote (ES2020 §11.6 — `net` and `net` are the same
/// identifier), otherwise the input unchanged. Callers use this when capturing
/// a binding or reference name so the two spellings resolve to one binding.
fn canonicalize_identifier(input: &str) -> String {
    if input.contains('\\')
        && let Some(decoded) = decode_identifier_escapes(input)
    {
        return decoded;
    }
    input.to_string()
}

fn is_identifier(input: &str) -> bool {
    // An IdentifierName may spell its characters with `\uXXXX` / `\u{X..}`
    // escapes (ES2020 §11.6); validate the decoded form (bd-dbosg).
    let decoded;
    let candidate = if input.contains('\\') {
        match decode_identifier_escapes(input) {
            Some(value) => {
                decoded = value;
                decoded.as_str()
            }
            None => return false,
        }
    } else {
        input
    };
    let mut chars = candidate.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !is_identifier_start(first) {
        return false;
    }
    chars.all(is_identifier_continue)
}

fn is_module_binding_identifier(input: &str) -> bool {
    is_identifier(input) && !is_disallowed_module_binding_name(input)
}

/// ES2020 unconditional reserved keywords — identifiers that are never legal
/// as a binding name in any context (script or module, strict or sloppy).
///
/// Excludes strict-mode-only reserved words (`implements`, `interface`, `let`,
/// `package`, `private`, `protected`, `public`, `static`, `yield`) and
/// contextual reserved words (`await`) — those are valid identifiers in
/// non-strict script code and are policed by the static-semantics analyzer
/// when strict mode actually applies (see `static_semantics::is_reserved_binding`).
fn is_unconditional_reserved_keyword(name: &str) -> bool {
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

fn is_disallowed_module_binding_name(name: &str) -> bool {
    matches!(
        name,
        "await"
            | "break"
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
            | "implements"
            | "import"
            | "in"
            | "instanceof"
            | "interface"
            | "let"
            | "new"
            | "null"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "return"
            | "static"
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
            | "yield"
    )
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
fn extract_balanced(s: &str, open_char: char, close_char: char) -> Option<(&str, &str)> {
    if !s.starts_with(open_char) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut depth: i64 = 0;
    let mut quotes = QuoteState::default();
    for (i, &b) in bytes.iter().enumerate() {
        if quotes.active() {
            quotes.advance(b);
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
            }
            _ if b == open_char as u8 => depth += 1,
            _ if b == close_char as u8 => {
                depth -= 1;
                if depth == 0 {
                    let inner = &s[1..i];
                    let rest = &s[i + 1..];
                    return Some((inner, rest));
                }
            }
            _ => {}
        }
    }
    None
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
    let mut logical_lines = merge_logical_lines(trimmed);
    let mut stmts = Vec::with_capacity(8);

    for ll in &mut logical_lines {
        let segments = split_statement_segments(&ll.text);
        // The body's lines map back into `trimmed`, a slice of the line
        // that is the enclosing frame (bd-9vouw.184).
        context.function_sources.frames.push(SourceFrame {
            text: (ll.text.as_ptr() as usize, ll.text.len()),
            input: trimmed.as_ptr() as usize,
            boundaries: std::mem::take(&mut ll.source_boundaries),
        });
        for (_start, _end, text) in segments {
            let inner_span = span.clone();
            stmts.push(parse_statement(text, goal, inner_span, context)?);
        }
        context.function_sources.frames.pop();
    }

    Ok(stmts)
}

/// An arrow function's block body, with its parameters for B.3.3.
fn parse_function_body_statements(
    body_src: &str,
    goal: ParseGoal,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    params: &[FunctionParam],
) -> ParseResult<Vec<Statement>> {
    with_function_strict_mode(body_src, false, context, |context| {
        let mut body = parse_body_statements(body_src, goal, span, context)?;
        if !context.strict_mode {
            apply_annex_b_block_functions(&mut body, params);
        }
        Ok(body)
    })
}

fn with_function_strict_mode<T>(
    body_src: &str,
    force_strict: bool,
    context: &mut ParseExecutionContext<'_>,
    operation: impl FnOnce(&mut ParseExecutionContext<'_>) -> ParseResult<T>,
) -> ParseResult<T> {
    let saved_strict_mode = context.strict_mode;
    context.strict_mode |= force_strict || has_use_strict_directive(body_src);
    let result = operation(context);
    context.strict_mode = saved_strict_mode;
    result
}

/// ES2020 B.3.3 FunctionDeclarations in blocks (the web-compatibility
/// semantics) for one non-strict function body or script `body` whose
/// parameters are `params` (bd-9vouw.242). A plain function declared
/// directly in a block, in a switch's case clauses or as an if clause (B.3.4
/// makes that a block) also gets a var binding in the body's scope,
/// initialized to undefined, which takes the function object when the
/// declaration is evaluated, so `if (x) { function f() {} } f();` calls `f`
/// as Node does. That applies only when a `var f` in the declaration's place
/// would not be an early error: no let/const/class, block function, loop
/// head or destructured catch binding named `f` in an enclosing block or at
/// the top of the body (a plain catch parameter is allowed, B.3.5), and `f`
/// is not a parameter or `arguments`. Generator and async declarations stay
/// block-scoped.
///
/// The rewrite puts `var f;` after the body's directive prologue and, after
/// each such declaration, `ANNEX_B_FUNCTION_VAR_PREFIX + f = f`, which the
/// lowering stores into the body's `f`. A var without an initializer lowers
/// to no operation, so `var f;` never resets a parameter, var or function of
/// that name. No-claim: two declarations of one name in one block are both
/// copied, as in Node, where the spec makes the name ineligible; a script's
/// function becomes a script var, not a global object property.
fn apply_annex_b_block_functions(body: &mut Vec<Statement>, params: &[FunctionParam]) {
    let mut excluded: BTreeSet<String> = params
        .iter()
        .flat_map(|param| param.pattern.binding_names())
        .map(str::to_string)
        .collect();
    excluded.insert("arguments".to_string());
    let mut scopes = vec![annex_b_lexical_names(body.iter(), false)];
    let mut hoisted: Vec<(String, SourceSpan)> = Vec::new();
    for statement in body.iter_mut() {
        annex_b_visit_statement(statement, &excluded, &mut scopes, &mut hoisted);
    }
    let Some((_, first_span)) = hoisted.first() else {
        return;
    };
    let declaration = Statement::VariableDeclaration(VariableDeclaration {
        kind: VariableDeclarationKind::Var,
        span: first_span.clone(),
        declarations: hoisted
            .into_iter()
            .map(|(name, span)| VariableDeclarator {
                pattern: BindingPattern::Identifier(name),
                initializer: None,
                span,
            })
            .collect(),
    });
    let prologue = body
        .iter()
        .take_while(|statement| {
            matches!(
                statement,
                Statement::Expression(ExpressionStatement {
                    expression: Expression::StringLiteral(_),
                    ..
                })
            )
        })
        .count();
    body.insert(prologue, declaration);
}

/// The names a statement list declares in its own scope that a `var` of the
/// same name in a nested block would conflict with: let/const/class, and,
/// for a block (`block_functions`), its function declarations, which are
/// lexical there.
fn annex_b_lexical_names<'a>(
    statements: impl Iterator<Item = &'a Statement>,
    block_functions: bool,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration)
                if declaration.kind != VariableDeclarationKind::Var =>
            {
                for declarator in &declaration.declarations {
                    names.extend(
                        declarator
                            .pattern
                            .binding_names()
                            .into_iter()
                            .map(str::to_string),
                    );
                }
            }
            Statement::ClassDeclaration(ClassDeclaration {
                name: Some(name), ..
            }) => {
                names.insert(name.clone());
            }
            Statement::FunctionDeclaration(FunctionDeclaration {
                name: Some(name), ..
            }) if block_functions => {
                names.insert(name.clone());
            }
            _ => {}
        }
    }
    names
}

/// One statement of a function body (not a nested function or class) for
/// `apply_annex_b_block_functions`; `scopes` holds the lexical names of the
/// body and of each enclosing block.
fn annex_b_visit_statement(
    statement: &mut Statement,
    excluded: &BTreeSet<String>,
    scopes: &mut Vec<BTreeSet<String>>,
    hoisted: &mut Vec<(String, SourceSpan)>,
) {
    match statement {
        Statement::Block(block) => {
            annex_b_visit_scope(vec![&mut block.body], excluded, scopes, hoisted)
        }
        Statement::If(if_statement) => {
            annex_b_visit_statement(&mut if_statement.consequent, excluded, scopes, hoisted);
            if let Some(alternate) = &mut if_statement.alternate {
                annex_b_visit_statement(alternate, excluded, scopes, hoisted);
            }
        }
        Statement::For(for_statement) => {
            let names = for_statement
                .init
                .as_deref()
                .map(|init| annex_b_lexical_names(std::iter::once(init), false))
                .unwrap_or_default();
            scopes.push(names);
            annex_b_visit_statement(&mut for_statement.body, excluded, scopes, hoisted);
            scopes.pop();
        }
        Statement::ForIn(ForInStatement {
            binding,
            binding_kind,
            body,
            ..
        })
        | Statement::ForOf(ForOfStatement {
            binding,
            binding_kind,
            body,
            ..
        }) => {
            let names = match binding_kind {
                Some(VariableDeclarationKind::Let | VariableDeclarationKind::Const) => binding
                    .binding_names()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                _ => BTreeSet::new(),
            };
            scopes.push(names);
            annex_b_visit_statement(body, excluded, scopes, hoisted);
            scopes.pop();
        }
        Statement::While(WhileStatement { body, .. })
        | Statement::DoWhile(DoWhileStatement { body, .. })
        | Statement::With(WithStatement { body, .. })
        | Statement::Labeled(LabeledStatement { body, .. }) => {
            annex_b_visit_statement(body, excluded, scopes, hoisted);
        }
        Statement::TryCatch(try_statement) => {
            annex_b_visit_scope(
                vec![&mut try_statement.block.body],
                excluded,
                scopes,
                hoisted,
            );
            if let Some(handler) = &mut try_statement.handler {
                annex_b_visit_scope(vec![&mut handler.body.body], excluded, scopes, hoisted);
            }
            if let Some(finalizer) = &mut try_statement.finalizer {
                annex_b_visit_scope(vec![&mut finalizer.body], excluded, scopes, hoisted);
            }
        }
        Statement::Switch(switch_statement) => {
            let lists = switch_statement
                .cases
                .iter_mut()
                .map(|case| &mut case.consequent)
                .collect();
            annex_b_visit_scope(lists, excluded, scopes, hoisted);
        }
        _ => {}
    }
}

/// A block's statements (or a switch's case clauses, which share one scope):
/// visit nested statements, then follow each eligible plain function
/// declaration with its B.3.3 copy.
fn annex_b_visit_scope(
    lists: Vec<&mut Vec<Statement>>,
    excluded: &BTreeSet<String>,
    scopes: &mut Vec<BTreeSet<String>>,
    hoisted: &mut Vec<(String, SourceSpan)>,
) {
    let lexical = annex_b_lexical_names(lists.iter().flat_map(|list| list.iter()), false);
    let block_names = annex_b_lexical_names(lists.iter().flat_map(|list| list.iter()), true);
    scopes.push(block_names);
    let enclosing = scopes.len() - 1;
    for list in lists {
        for statement in list.iter_mut() {
            annex_b_visit_statement(statement, excluded, scopes, hoisted);
        }
        let mut index = 0;
        while index < list.len() {
            let eligible = match &list[index] {
                Statement::FunctionDeclaration(FunctionDeclaration {
                    name: Some(name),
                    is_async: false,
                    is_generator: false,
                    span,
                    ..
                }) if !excluded.contains(name)
                    && !lexical.contains(name)
                    && !scopes[..enclosing].iter().any(|scope| scope.contains(name)) =>
                {
                    Some((name.clone(), span.clone()))
                }
                _ => None,
            };
            index += 1;
            if let Some((name, span)) = eligible {
                let copy = Expression::Assignment {
                    operator: AssignmentOperator::Assign,
                    left: Box::new(Expression::Identifier(format!(
                        "{ANNEX_B_FUNCTION_VAR_PREFIX}{name}"
                    ))),
                    right: Box::new(Expression::Identifier(name.clone())),
                    assignment_strictness: AssignmentStrictness::Sloppy,
                };
                list.insert(
                    index,
                    Statement::Expression(ExpressionStatement {
                        expression: copy,
                        span: span.clone(),
                    }),
                );
                index += 1;
                if !hoisted
                    .iter()
                    .any(|(hoisted_name, _)| *hoisted_name == name)
                {
                    hoisted.push((name, span));
                }
            }
        }
    }
    scopes.pop();
}

/// ES2020 B.3.4: a function declaration as an if clause (non-strict code;
/// strict code rejects it) is evaluated as if it were the only statement of
/// a block, so it is block-scoped like any other block function.
fn if_clause_function_in_block(statement: Statement) -> Statement {
    match statement {
        Statement::FunctionDeclaration(function) => {
            let span = function.span.clone();
            Statement::Block(BlockStatement {
                body: vec![Statement::FunctionDeclaration(function)],
                span,
            })
        }
        other => other,
    }
}

/// Run `operation` with the `await` / `yield` contexts of a function body:
/// async bodies take `await` expressions, generator bodies `yield` ones.
/// Every function, method and static block sets both, so a nested plain
/// function does not inherit its enclosing generator's `yield`.
fn with_function_context<T>(
    is_async: bool,
    is_generator: bool,
    context: &mut ParseExecutionContext<'_>,
    operation: impl FnOnce(&mut ParseExecutionContext<'_>) -> ParseResult<T>,
) -> ParseResult<T> {
    let saved = (
        context.await_context,
        context.yield_context,
        context.static_block_await,
        context.formal_parameters,
    );
    context.await_context = is_async;
    context.yield_context = is_generator;
    context.static_block_await = false;
    context.formal_parameters = false;
    let result = operation(context);
    (
        context.await_context,
        context.yield_context,
        context.static_block_await,
        context.formal_parameters,
    ) = saved;
    result
}

fn is_directive_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ch == '\u{FEFF}'
}

fn starts_directive_identifier_part(source: &str) -> bool {
    source.chars().next().is_some_and(|ch| {
        matches!(ch, '\\' | '\u{200C}' | '\u{200D}') || is_identifier_continue(ch)
    })
}

fn starts_directive_expression_continuation(source: &str) -> bool {
    let source = source.trim_start_matches(is_directive_whitespace);
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
        .is_some_and(|rest| !starts_directive_identifier_part(rest))
        || source
            .strip_prefix("instanceof")
            .is_some_and(|rest| !starts_directive_identifier_part(rest))
}

fn trim_directive_whitespace(mut source: &str) -> (&str, bool) {
    let mut saw_line_terminator = false;
    let mut whitespace_end = 0usize;
    for (index, ch) in source.char_indices() {
        if is_directive_whitespace(ch) {
            saw_line_terminator |= matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}');
            whitespace_end = index + ch.len_utf8();
        } else {
            break;
        }
    }
    source = &source[whitespace_end..];
    (source, saw_line_terminator)
}

fn strip_initial_hashbang(source: &str) -> &str {
    let source = source.strip_prefix('\u{FEFF}').unwrap_or(source);
    if !source.starts_with("#!") {
        return source;
    }
    source_line_terminator_ranges(source)
        .first()
        .map_or("", |(_, end)| &source[*end..])
}

/// Where a single statement is parsed as the body of another statement.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StatementPosition {
    If,
    Labelled,
    Loop,
}

/// `text` after one leading `label:`, if it starts with one.
fn strip_statement_label(text: &str) -> Option<&str> {
    let end = text
        .find(|ch: char| !(ch == '_' || ch == '$' || ch.is_alphanumeric()))
        .unwrap_or(text.len());
    let (label, after) = text.split_at(end);
    if label.is_empty() || !is_identifier(label) || is_unconditional_reserved_keyword(label) {
        return None;
    }
    after.trim_start().strip_prefix(':').map(str::trim_start)
}

/// ES2020 13.6, 13.7, 13.11, 13.13 with Annex B.3.2 / B.3.4: an if, loop,
/// `with` or labelled body is a Statement, not a Declaration. Sloppy code may
/// use a plain function declaration as an unlabelled if body or as a
/// labelled statement; a loop body may never be a (labelled) function.
fn reject_declaration_in_statement_position(
    body_src: &str,
    position: StatementPosition,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let mut rest = body_src.trim_start();
    let mut labelled = false;
    while let Some(after) = strip_statement_label(rest) {
        rest = after;
        labelled = true;
    }
    // `let [`, `let {` or `let name` starts a lexical declaration; `let` alone
    // (`let = 1`) and longer names (`letter`) are identifiers.
    let is_let_declaration = rest.strip_prefix("let").is_some_and(|after| {
        let spaced = after.trim_start_matches([' ', '\t']);
        spaced.starts_with(['[', '{'])
            || (spaced.len() < after.len()
                && spaced
                    .chars()
                    .next()
                    .is_some_and(|ch| ch == '_' || ch == '$' || ch.is_alphabetic()))
    });
    let declaration = if starts_with_keyword(rest, "class") {
        Some("a class declaration")
    } else if starts_with_keyword(rest, "const") || is_let_declaration {
        Some("a lexical declaration")
    } else if starts_with_keyword(rest, "async")
        && starts_with_keyword(
            rest["async".len()..].trim_start_matches([' ', '\t']),
            "function",
        )
    {
        Some("an async function declaration")
    } else if starts_with_keyword(rest, "function") {
        if rest["function".len()..].trim_start().starts_with('*') {
            Some("a generator declaration")
        } else if context.strict_mode
            || position == StatementPosition::Loop
            || (position == StatementPosition::If && labelled)
        {
            Some("a function declaration")
        } else {
            None
        }
    } else {
        None
    };
    if let Some(declaration) = declaration {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            format!("{declaration} is not allowed in statement position"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

/// ES2020 12.1.1, 13.3.1.1, 14.1.2: strict code cannot bind `eval` or
/// `arguments` (variable, parameter, catch parameter or function name).
fn reject_strict_restricted_binding(
    name: &str,
    strict: bool,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    if strict && matches!(name, "eval" | "arguments") {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            format!("`{name}` cannot be a binding name in strict mode code"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

/// ES2020 13.3.1.1, 13.7.5.1: `let` is never a lexically bound name, in
/// sloppy code too (`let let = 1`, `for (const let of xs)`).
fn reject_let_lexical_binding(
    pattern: &BindingPattern,
    kind: VariableDeclarationKind,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    if kind != VariableDeclarationKind::Var && pattern.binding_names().contains(&"let") {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            "`let` is disallowed as a lexically bound name",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

/// ES2020 11.6.2.2, 12.1.1: strict code reserves `implements`, `interface`,
/// `let`, `package`, `private`, `protected`, `public`, `static` and
/// `yield`; async functions and modules reserve `await`. None of them can be
/// a binding name there.
fn reject_context_reserved_binding(
    name: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let reserved = ((context.await_context || context.static_block_await) && name == "await")
        || (context.yield_context && name == "yield")
        || (context.strict_mode && is_strict_mode_reserved_word(name));
    if reserved {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            format!("`{name}` is a reserved word here and cannot be a binding name"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

fn is_strict_mode_reserved_word(name: &str) -> bool {
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

/// ES2020 14.1.2, 14.4.1, 14.7.1: the BindingIdentifier of a function,
/// generator or async function. It is an IdentifierName that is not a
/// reserved word (an escape does not make one usable), bound by its decoded
/// spelling: `function a\u0062() {}` declares `ab`. `strict` is whether the
/// name is strict code (the enclosing code is strict, or the body has a
/// "use strict" directive); `yield_reserved` and `await_reserved` are the
/// [Yield] and [Await] parameters the grammar gives the name.
fn function_binding_name(
    raw: &str,
    strict: bool,
    yield_reserved: bool,
    await_reserved: bool,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<String> {
    let invalid = |message: String| {
        Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            message,
            context.source_label.to_string(),
            Some(span.clone()),
        ))
    };
    if !is_identifier(raw) {
        return invalid(format!("invalid function name `{raw}`"));
    }
    let name = canonicalize_identifier(raw);
    if is_unconditional_reserved_keyword(&name) {
        return invalid(if name == raw {
            format!("`{name}` is a reserved word and cannot be a function name")
        } else {
            format!("keyword `{name}` must not contain escaped characters")
        });
    }
    reject_strict_restricted_binding(&name, strict, span, context)?;
    if (strict && is_strict_mode_reserved_word(&name))
        || (yield_reserved && name == "yield")
        || (await_reserved && name == "await")
    {
        return invalid(format!(
            "`{name}` is a reserved word here and cannot be a function name"
        ));
    }
    Ok(name)
}

/// ES2020 14.1.2, 14.2.1, 14.3.1: a function whose own body has a
/// "use strict" directive must have simple parameters (no default, pattern or
/// rest parameter).
fn reject_use_strict_with_non_simple_params(
    body_src: &str,
    params: &[FunctionParam],
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseResult<()> {
    if params
        .iter()
        .any(|param| !matches!(param.pattern, BindingPattern::Identifier(_)))
        && has_use_strict_directive(body_src)
    {
        return Err(ParseError::new(
            ParseErrorCode::InvalidSyntax,
            "\"use strict\" is not allowed in a function with non-simple parameters",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(())
}

fn has_use_strict_directive(source: &str) -> bool {
    let mut source = strip_initial_hashbang(source);
    loop {
        (source, _) = trim_directive_whitespace(source);
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
            } else if matches!(ch, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
                return false;
            }
        }
        let Some(closing_index) = closing_index else {
            return false;
        };
        let directive = &source[delimiter.len_utf8()..closing_index];
        let after_literal = &source[closing_index + delimiter.len_utf8()..];
        let (after_whitespace, saw_line_terminator) = trim_directive_whitespace(after_literal);
        let terminated = after_whitespace.is_empty()
            || after_whitespace.starts_with(';')
            || (saw_line_terminator && !starts_directive_expression_continuation(after_whitespace));
        if !terminated {
            return false;
        }
        if directive == "use strict" {
            return true;
        }

        source = if let Some(rest) = after_whitespace.strip_prefix(';') {
            rest
        } else if saw_line_terminator {
            after_whitespace
        } else {
            return false;
        };
    }
}

fn parse_block_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let (inner, _rest) = extract_balanced(statement, '{', '}').ok_or_else(|| {
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
    let (condition_src, rest) = extract_balanced(after_if, '(', ')').ok_or_else(|| {
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
        if let Some((block_inner, after_block)) = extract_balanced(rest, '{', '}') {
            let after = after_block.trim();
            // `if (a) {} ; else b`: the `;` is an empty statement after the
            // if, so this `else` has no if.
            if after
                .strip_prefix(';')
                .is_some_and(|tail| starts_with_keyword(tail.trim_start(), "else"))
            {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "unexpected `else` after an empty statement",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
            (
                format!("{{{block_inner}}}"),
                if after.starts_with("else") {
                    Some(
                        after
                            .strip_prefix("else")
                            .unwrap_or(after)
                            .trim()
                            .to_string(),
                    )
                } else {
                    None
                },
            )
        } else {
            (rest.to_string(), None)
        }
    } else {
        // Single-statement consequent: find "else" boundary.
        if let Some(else_idx) = find_top_level_else(rest) {
            // The statement splitter keeps `if (a) x(); else y();` together,
            // so the consequent arrives with the `;` that ends it; parsed as
            // part of an expression it became a Raw node that threw a
            // SyntaxError only when the branch ran. A lone `;` is the empty
            // statement and stays.
            let cons = rest[..else_idx].trim();
            // `if (a) for (; f(), --n;); else b()` (jszip): that `;` is the
            // loop's empty body, not the end of an expression statement.
            let cons = match cons.strip_suffix(';') {
                Some(body)
                    if !body.trim().is_empty() && !statement_header_takes_unbraced_body(body) =>
                {
                    body.trim_end()
                }
                _ => cons,
            }
            .to_string();
            let alt = rest[else_idx + 4..].trim().to_string();
            (cons, Some(alt))
        } else {
            (rest.to_string(), None)
        }
    };

    reject_declaration_in_statement_position(
        &consequent_src,
        StatementPosition::If,
        &span,
        context,
    )?;
    let consequent_stmt = if_clause_function_in_block(parse_statement(
        consequent_src.trim(),
        goal,
        span.clone(),
        context,
    )?);

    let alternate = if let Some(alt_src) = alternate_src {
        if !alt_src.is_empty() {
            reject_declaration_in_statement_position(
                &alt_src,
                StatementPosition::If,
                &span,
                context,
            )?;
            Some(Box::new(if_clause_function_in_block(parse_statement(
                alt_src.trim(),
                goal,
                span.clone(),
                context,
            )?)))
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

/// `return` / `throw` written directly against a token that can only start
/// an expression, as minifiers emit them: `return'x'`, `return"y"`,
/// `return[1]`, `return{a:1}`, `return!0`, `return-1`, `throw"e"`,
/// `return/re/.test(s)`. These fell through to expression parsing and threw
/// "unsupported expression syntax" when the function ran. A line break after
/// the keyword is not included: `return` + newline is a restricted
/// production (ASI returns undefined).
fn keyword_followed_by_expression_start(statement: &str, keyword: &str) -> bool {
    statement.strip_prefix(keyword).is_some_and(|after| {
        after.starts_with(['\'', '"', '`', '[', '{', '!', '-', '+', '~', '/', '\t'])
    })
}

/// Find the index of a top-level "else" keyword (not inside braces/parens/quotes).
/// An `else` belongs to the nearest unmatched `if` (ES2020 13.6), so one that
/// closes an unbraced nested `if` in the consequent (`if (a) if (b) x; else
/// y;`) is skipped: the outer `if` then has no `else`.
fn find_top_level_else(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth_brace: i64 = 0;
    let mut depth_paren: i64 = 0;
    let mut unmatched_ifs = 0usize;
    let mut quotes = QuoteState::default();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
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
        let keyword_at = |keyword: &[u8]| {
            depth_brace == 0
                && depth_paren == 0
                && bytes[i..].starts_with(keyword)
                && (i == 0
                    || !(is_identifier_continue(bytes[i - 1] as char) || bytes[i - 1] == b'.'))
                && bytes
                    .get(i + keyword.len())
                    .is_none_or(|next| !is_identifier_continue(*next as char))
        };
        if keyword_at(b"if") {
            unmatched_ifs += 1;
            i += 2;
            continue;
        }
        if keyword_at(b"else") {
            if unmatched_ifs == 0 {
                return Some(i);
            }
            unmatched_ifs -= 1;
            i += 4;
            continue;
        }
        i += 1;
    }
    None
}

/// Build the comma/sequence-operator desugar (bd-wo6za, ES2020 §13.16) for a
/// list of already-parsed operands `e0, e1, …, eN`: an immediately-applied arrow
/// `((__seq_0, …, __seq_N) => __seq_N)(e0, …, eN)`. Call arguments evaluate
/// left-to-right (preserving every operand's side effects) and the arrow yields
/// the final operand, reusing the existing arrow + call lowering so no dedicated
/// `SequenceExpression` IR is needed. The synthetic `__seq_*` parameters cannot
/// collide with the operands: operands are evaluated as arguments in the
/// enclosing scope, never inside the arrow body. Callers must pass
/// `operands.len() >= 2` (a single operand needs no sequencing).
/// Operands one sequence call takes. A longer comma sequence nests: the
/// sequence of the operands so far is the first operand of the next call, so
/// neither the call's argument list nor the arrow's parameter list grows with
/// the sequence (a minified UMD export list `r.a=a,r.b=b,...` of 300
/// assignments needed 300 registers: "register 256 out of bounds").
const SEQUENCE_CHUNK: usize = 64;

fn build_sequence_expression(operands: Vec<Expression>, span: &SourceSpan) -> Expression {
    debug_assert!(operands.len() >= 2, "sequence needs >= 2 operands");
    let mut operands = operands.into_iter();
    let first: Vec<Expression> = operands.by_ref().take(SEQUENCE_CHUNK).collect();
    let mut sequence = sequence_call(first, span);
    loop {
        let rest: Vec<Expression> = operands.by_ref().take(SEQUENCE_CHUNK - 1).collect();
        if rest.is_empty() {
            return sequence;
        }
        let mut next = Vec::with_capacity(rest.len() + 1);
        next.push(sequence);
        next.extend(rest);
        sequence = sequence_call(next, span);
    }
}

/// `((s0, ..., sn) => sn)(operands...)`: evaluates the operands left to
/// right and yields the last.
fn sequence_call(operands: Vec<Expression>, span: &SourceSpan) -> Expression {
    let params: Vec<FunctionParam> = (0..operands.len())
        .map(|i| FunctionParam {
            pattern: BindingPattern::Identifier(format!("__seq_{i}")),
            span: span.clone(),
        })
        .collect();
    let last_param = format!("__seq_{}", operands.len() - 1);
    Expression::Call {
        callee: Box::new(Expression::ArrowFunction {
            params,
            body: ArrowBody::Expression(Box::new(Expression::Identifier(last_param))),
            is_async: false,
            source_text: None,
        }),
        arguments: operands,
        span: Some(*span),
    }
}

/// Parse an expression that may be a bare, unparenthesized comma sequence such
/// as `i++, j--` or `a, b`. Outside parentheses the sequence operator does not
/// reach the paren-handling desugar in `parse_primary_expression`, so a comma'd
/// expression would otherwise fall through to `Expression::Raw` (a string) and
/// fault at runtime (bd-qxkli / bd-j4l7k). Here we detect a top-level comma and
/// apply the same `build_sequence_expression` desugar; a single-expression input
/// parses unchanged. Used wherever the grammar has an Expression rather than
/// an AssignmentExpression: expression statements, `return`/`throw`
/// arguments, `if`/`while`/`do-while`/`switch` heads, `case` tests, C-style
/// `for` clauses, the right side of `for-in`, template substitutions and
/// computed member keys. Minified code writes `if (a = f(), a)` constantly.
/// (Comma-separated list contexts — call arguments, array/object literals,
/// variable declarators — split on their commas before reaching here.)
fn parse_expression_allowing_sequence(
    src: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    if split_top_level_commas(src).len() > 1 {
        let operands = parse_comma_separated_exprs(src, span, context, recursion_depth)?;
        if operands.len() > 1 {
            return Ok(build_sequence_expression(operands, span));
        }
    }
    parse_expression(src, span, context, recursion_depth)
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
    let mut quotes = QuoteState::default();
    let mut semis: [usize; 2] = [0, 0];
    let mut count: usize = 0;
    let mut i: usize = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(header, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
            }
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

fn parse_for_statement(
    statement: &str,
    goal: ParseGoal,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let after_for = statement
        .strip_prefix("for")
        .unwrap_or(statement)
        .trim_start();
    // bd-suwvw: accept the `for await (const x of iterable)` header shape.
    // A `for await ... of` runs the async iteration protocol through
    // `desugar_for_await_of`. Engine-vended iterables without
    // `@@asyncIterator` (`require('timers/promises').setInterval`) take its
    // sync-iterator fallback, which awaits each value. `await` must be a
    // whole word (`for awaitFoo(...)` is not a for-await header).
    let (after_for, is_await) = match after_for.strip_prefix("await") {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_whitespace() || c == '(') => {
            (rest.trim_start(), true)
        }
        _ => (after_for, false),
    };
    let (header_src, rest) = extract_balanced(after_for, '(', ')').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "for statement requires a parenthesized header",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    if is_await && let Some(desugared) = desugar_for_await_of(header_src, rest) {
        return parse_statement(&desugared, goal, span, context);
    }

    // Detect for-in / for-of before trying semicolon split.
    if let Some(forin) = try_parse_for_in_of(header_src, rest, &span, goal, context)? {
        return Ok(forin);
    }

    // Split header by top-level semicolons: init; condition; update. The split
    // must be nesting-aware so a `;` inside an arrow/block body or a string in
    // a header clause (e.g. `for (let f = () => { a; return b; }; i < n; i++)`)
    // does not mis-split the three parts.
    let parts = split_for_header(header_src)
        .map(|(init, cond, update)| (init.trim(), cond.trim(), update.trim()))
        // A fourth part (`for (a; b; c; d)`) is an early SyntaxError. It used
        // to stay in the update clause, which became an expression that threw
        // only when the loop ran (Test262 S12.6.3_A7.1_T1). Re-splitting the
        // update with a `;` appended finds a top-level `;` inside it.
        .filter(|(_, _, update)| split_for_header(&format!("{update};")).is_none());
    let Some((init_src, cond_src, update_src)) = parts else {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "for statement header must have three semicolon-separated parts",
            context.source_label.to_string(),
            Some(span),
        ));
    };

    let init = if init_src.is_empty() {
        None
    } else if let Some(kind) = parse_variable_declaration_kind(init_src) {
        Some(Box::new(Statement::VariableDeclaration(
            parse_variable_declaration(init_src, kind, span.clone(), context)?,
        )))
    } else {
        // A non-declaration initializer is an expression, so anonymous class
        // and function expressions are valid here even though declarations
        // in statement position require a name.
        Some(Box::new(Statement::Expression(ExpressionStatement {
            expression: parse_expression_allowing_sequence(init_src, &span, context, 1)?,
            span: span.clone(),
        })))
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
    reject_declaration_in_statement_position(body_src, StatementPosition::Loop, &span, context)?;
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
/// Whether the target of `pattern = value` (an array or object assignment
/// pattern) has a member expression among its targets, which a binding
/// pattern cannot express (bd-9vouw.229).
fn destructuring_assignment_has_member_target(assign: &Expression) -> bool {
    fn has_member(target: &Expression) -> bool {
        match target {
            Expression::Member { .. } => true,
            Expression::ArrayLiteral(elements) => elements.iter().flatten().any(has_member),
            Expression::ObjectLiteral(properties) => properties
                .iter()
                .any(|property| has_member(&property.value)),
            Expression::SpreadElement(inner) => has_member(inner),
            Expression::Assignment { left, .. } => has_member(left),
            _ => false,
        }
    }
    matches!(assign, Expression::Assignment { left, .. }
        if matches!(left.as_ref(), Expression::ArrayLiteral(_) | Expression::ObjectLiteral(_))
            && has_member(left))
}

fn try_parse_for_in_of(
    header: &str,
    rest: &str,
    span: &SourceSpan,
    goal: ParseGoal,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Option<Statement>> {
    let Some((keyword, split_pos)) = find_for_in_of_keyword(header) else {
        return Ok(None);
    };

    let lhs = header[..split_pos].trim();
    let rhs = header[split_pos + keyword.len()..].trim();

    // Parse binding: optionally `let x`, `const x`, `var x`, or bare `x`. A
    // pattern may follow the keyword directly, as minifiers write it
    // (`for(const[k,v]of m)`, `for(let{a}of xs)`): a for-in/of head never
    // reads `let [` or `let {` as an expression (bd-9vouw.219), and a bare
    // `let` stays the variable `let` (bd-9vouw.233).
    let declaration = |keyword: &str| {
        lhs.strip_prefix(keyword)
            .filter(|after| after.starts_with([' ', '\t', '[', '{']))
            .map(str::trim)
    };
    let (binding_kind, binding_src) = if let Some(after) = declaration("let") {
        (Some(VariableDeclarationKind::Let), after)
    } else if let Some(after) = declaration("const") {
        (Some(VariableDeclarationKind::Const), after)
    } else if let Some(after) = declaration("var") {
        (Some(VariableDeclarationKind::Var), after)
    } else {
        (None, lhs)
    };

    let binding = match parse_binding_pattern(binding_src, span, context) {
        Ok(pat) => pat,
        // A member target (`for (o.a of xs)`, `for (this.#k in o)`) is not a
        // binding pattern. The loop binds a fresh block-scoped name and
        // assigns the target from it at the start of each iteration, which
        // is when the spec evaluates the target reference. A destructuring
        // head with a member target (`for ([o.a, o.b] of xs)`, `for ({ k: o.v }
        // of xs)`) is desugared the same way through the assignment-pattern
        // parser, which takes member targets (bd-9vouw.229); a pattern that
        // has none keeps its own binding error (an early error such as
        // `[...x = 1]`).
        Err(error) if binding_kind.is_none() && split_for_header(header).is_none() => {
            let target = format!("{lhs} = {FOR_IN_OF_TARGET_BINDING}");
            let assign = if lhs.starts_with(['[', '{']) {
                match parse_expression(&target, span, context, 1) {
                    Ok(assign) if destructuring_assignment_has_member_target(&assign) => assign,
                    _ => return Err(error),
                }
            } else if lhs
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$')
            {
                // A bare name that is no binding identifier here (strict
                // `let`, `yield` in a generator) is no member target either:
                // its binding error is the early error. Read as an
                // assignment target, strict `for (let in o)` was accepted
                // (bd-9vouw.233).
                return Err(error);
            } else {
                parse_expression(&target, span, context, 1)?
            };
            let binding = BindingPattern::Identifier(FOR_IN_OF_TARGET_BINDING.to_string());
            let body_src = rest.trim();
            reject_declaration_in_statement_position(
                body_src,
                StatementPosition::Loop,
                span,
                context,
            )?;
            let body = parse_statement(body_src, goal, span.clone(), context)?;
            let body = Statement::Block(BlockStatement {
                body: vec![
                    Statement::Expression(ExpressionStatement {
                        expression: assign,
                        span: span.clone(),
                    }),
                    body,
                ],
                span: span.clone(),
            });
            return Ok(Some(for_in_of_statement(
                keyword,
                binding,
                Some(VariableDeclarationKind::Let),
                rhs,
                body,
                span,
                context,
            )?));
        }
        // Without two top-level `;` the header can only be for-in/of, so the
        // binding's own error (an early error such as `[...x = 1]` or strict
        // `var arguments`) is the diagnosis; falling back reported "for
        // statement header must have three semicolon-separated parts".
        Err(error) if split_for_header(header).is_none() => return Err(error),
        Err(_) => return Ok(None),
    };
    if let Some(kind) = binding_kind {
        reject_let_lexical_binding(&binding, kind, span, context)?;
        // ES2020 13.7.5.1: a for-in/of declaration has no initializer, save
        // Annex B.3.6's sloppy `for (var x = e in o)`.
        if let BindingPattern::AssignmentPattern { left, .. } = &binding
            && !(keyword == "in"
                && kind == VariableDeclarationKind::Var
                && !context.strict_mode
                && matches!(**left, BindingPattern::Identifier(_)))
        {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("for-{keyword} loop variable declaration may not have an initializer"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
    } else if let BindingPattern::Identifier(name) = &binding {
        // A bare name is an IdentifierReference, so a word reserved here
        // (strict `let`, which `for (let in o)` reaches) is an early error
        // (bd-9vouw.233).
        reject_reserved_identifier_reference(name, span, context)?;
    }

    let body_src = rest.trim();
    reject_declaration_in_statement_position(body_src, StatementPosition::Loop, span, context)?;
    let body = parse_statement(body_src, goal, span.clone(), context)?;
    Ok(Some(for_in_of_statement(
        keyword,
        binding,
        binding_kind,
        rhs,
        body,
        span,
        context,
    )?))
}

/// The per-iteration binding of a for-in/of loop whose head is a member
/// target; see `try_parse_for_in_of`.
const FOR_IN_OF_TARGET_BINDING: &str = "__franken_for_target";

fn for_in_of_statement(
    keyword: &str,
    binding: BindingPattern,
    binding_kind: Option<VariableDeclarationKind>,
    rhs: &str,
    body: Statement,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    if keyword == "in" {
        // for-in's right side is an Expression, so a comma sequence is allowed
        // there; for-of's is an AssignmentExpression.
        let object = parse_expression_allowing_sequence(rhs, span, context, 1)?;
        Ok(Statement::ForIn(ForInStatement {
            binding,
            binding_kind,
            assignment_strictness: AssignmentStrictness::from_strict_mode(context.strict_mode),
            object,
            body: Box::new(body),
            span: span.clone(),
        }))
    } else {
        let iterable = parse_expression(rhs, span, context, 1)?;
        Ok(Statement::ForOf(ForOfStatement {
            binding,
            binding_kind,
            assignment_strictness: AssignmentStrictness::from_strict_mode(context.strict_mode),
            iterable,
            body: Box::new(body),
            span: span.clone(),
        }))
    }
}

/// Find a keyword (like ` in ` or ` of `) at the top level of an expression,
/// respecting parentheses, brackets, braces, and quotes.
/// `for await (TARGET of ITERABLE) BODY` as ordinary async code (ES2020
/// 13.7.5.13 ForIn/OfBodyEvaluation with iteratorKind async). It uses:
/// - `ITERABLE[Symbol.asyncIterator]`, else the sync iterator with each value
///   awaited (CreateAsyncFromSyncIterator);
/// - an awaited `next()` per step;
/// - on break, return or throw from the body, an awaited `return()`
///   (AsyncIteratorClose). No close after `next()` throws or reports done.
///   After a throw, getting, calling or awaiting `return` cannot replace the
///   body's exception: its errors are dropped (ES2022 AsyncIteratorClose
///   returns a throw completion before the close's own).
///
/// Before this, `for await` ran as a synchronous for-of: an async
/// generator's `next()` promise was taken as the iteration result, and the
/// loop body never saw a value.
///
/// Every helper is a block-scoped `let` in the rewritten block, so nested
/// loops shadow each other correctly. A labeled `continue` that targets the
/// `for await` itself is not supported by this rewrite.
fn desugar_for_await_of(header: &str, body: &str) -> Option<String> {
    let ("of", split) = find_for_in_of_keyword(header)? else {
        return None;
    };
    let lhs = header[..split].trim();
    let iterable = header[split + "of".len()..].trim();
    if lhs.is_empty() || iterable.is_empty() {
        return None;
    }
    let value = "__franken_fa_sync ? await __franken_fa_r.value : __franken_fa_r.value";
    let is_declaration = ["let", "const", "var"].iter().any(|kind| {
        lhs.strip_prefix(kind).is_some_and(|rest| {
            rest.starts_with(|c: char| c.is_ascii_whitespace() || c == '[' || c == '{')
        })
    });
    let bind = if is_declaration {
        format!("{lhs} = {value};")
    } else if lhs.starts_with('{') {
        format!("({lhs} = {value});")
    } else {
        format!("{lhs} = {value};")
    };
    let body = body.trim();
    let body_terminator = if body.ends_with('}') || body.ends_with(';') {
        ""
    } else {
        ";"
    };
    Some(format!(
        "{{ let __franken_fa_src = ({iterable}); \
         let __franken_fa_am = __franken_fa_src[Symbol.asyncIterator]; \
         let __franken_fa_sync = __franken_fa_am == null; \
         let __franken_fa_it = __franken_fa_sync ? __franken_fa_src[Symbol.iterator]() : \
         __franken_fa_am.call(__franken_fa_src); \
         let __franken_fa_fin = false; let __franken_fa_thrown = false; \
         try {{ while (true) {{ __franken_fa_fin = true; \
         let __franken_fa_r = await __franken_fa_it.next(); \
         if (__franken_fa_r.done) break; \
         __franken_fa_fin = false; \
         {bind} {body}{body_terminator} }} }} \
         catch (__franken_fa_e) {{ __franken_fa_thrown = true; throw __franken_fa_e; }} \
         finally {{ if (!__franken_fa_fin) {{ if (__franken_fa_thrown) {{ \
         try {{ let __franken_fa_ret = __franken_fa_it.return; \
         if (__franken_fa_ret != null) await __franken_fa_ret.call(__franken_fa_it); }} \
         catch (__franken_fa_ignored) {{}} }} else {{ \
         let __franken_fa_ret = __franken_fa_it.return; \
         if (__franken_fa_ret != null) await __franken_fa_ret.call(__franken_fa_it); }} }} }} }}"
    ))
}

/// The `in` or `of` of a for-in/of head: a whole word at the top level
/// (bd-9vouw.219). It was found as ` in ` / ` of ` with spaces around it, so
/// minified heads (`for(const[k,v]of m)`, `for(const{a}of xs)`,
/// `for(const c of"abc")`, ts-pattern, terser output) were read as C-style
/// headers. A word with nothing but a declaration keyword before it is the
/// bound name (`for (const of of xs)`), except an `in` after a bare `let`:
/// for-in only excludes `let [`, so sloppy `for (let in o)` assigns the
/// variable `let` (bd-9vouw.233). A head with a top-level `;` is C-style: an
/// `in` after it is the operator in its test or update
/// (`for (var i = n; i in list; i++)`, @xmldom/xmldom), and the initializer
/// before it cannot hold an unparenthesized `in` (ES2020 13.7.4 [~In]).
fn find_for_in_of_keyword(header: &str) -> Option<(&'static str, usize)> {
    let bytes = header.as_bytes();
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$';
    let mut depth = 0i32;
    let mut quotes = QuoteState::default();
    for (i, &b) in bytes.iter().enumerate() {
        if quotes.active() {
            quotes.advance(b);
            continue;
        }
        if (b == b'/' && quotes.open_regex_at(header, i)) || quotes.open(b) {
            continue;
        }
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            b';' if depth == 0 => return None,
            _ => {}
        }
        if depth != 0 || i > 0 && (is_word(bytes[i - 1]) || bytes[i - 1] == b'.') {
            continue;
        }
        for keyword in ["in", "of"] {
            if bytes[i..].starts_with(keyword.as_bytes())
                && bytes.get(i + 2).is_none_or(|next| !is_word(*next))
            {
                let lhs = header[..i].trim();
                let declaration_keyword = match keyword {
                    "in" => matches!(lhs, "const" | "var"),
                    _ => matches!(lhs, "let" | "const" | "var"),
                };
                if !lhs.is_empty() && !declaration_keyword {
                    return Some((keyword, i));
                }
            }
        }
    }
    None
}

fn find_top_level_keyword(src: &str, keyword: &str) -> Option<usize> {
    let bytes = src.as_bytes();
    let kw_bytes = keyword.as_bytes();
    let kw_len = kw_bytes.len();
    if bytes.len() < kw_len {
        return None;
    }
    let mut depth_paren = 0i32;
    let mut depth_bracket = 0i32;
    let mut depth_brace = 0i32;
    let mut quotes = QuoteState::default();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
        } else if !(b == b'/' && quotes.open_regex_at(src, i)) && !quotes.open(b) {
            match b {
                b'(' => depth_paren += 1,
                b')' => depth_paren -= 1,
                b'[' => depth_bracket += 1,
                b']' => depth_bracket -= 1,
                b'{' => depth_brace += 1,
                b'}' => depth_brace -= 1,
                _ => {}
            }
            if depth_paren == 0
                && depth_bracket == 0
                && depth_brace == 0
                && i + kw_len <= bytes.len()
                && &bytes[i..i + kw_len] == kw_bytes
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
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
    let (condition_src, rest) = extract_balanced(after_while, '(', ')').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "while statement requires a parenthesized condition",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let condition = parse_expression_allowing_sequence(condition_src.trim(), &span, context, 1)?;
    reject_declaration_in_statement_position(rest, StatementPosition::Loop, &span, context)?;
    let body = parse_statement(rest.trim(), goal, span.clone(), context)?;
    Ok(Statement::While(WhileStatement {
        condition,
        body: Box::new(body),
        span,
    }))
}

fn parse_with_statement(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    // ES2020 §13.11.1: Early error check for strict mode
    if context.strict_mode {
        return Err(ParseError::new(
            ParseErrorCode::StrictModeWithStatement,
            "with statements are not allowed in strict mode",
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    let after_with = statement
        .strip_prefix("with")
        .unwrap_or(statement)
        .trim_start();
    let (object_src, rest) = extract_balanced(after_with, '(', ')').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "with statement requires a parenthesized object expression",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let object = parse_expression(object_src.trim(), &span, context, 1)?;
    // ES2020 13.11.1: the body is a Statement, so a declaration there (or a
    // labelled function) is a SyntaxError even in sloppy code, as in a loop.
    reject_declaration_in_statement_position(rest.trim(), StatementPosition::Loop, &span, context)?;
    let body = parse_statement(rest.trim(), ParseGoal::Script, span.clone(), context)?;
    Ok(Statement::With(WithStatement {
        object,
        body: Box::new(body),
        span,
    }))
}

/// Where the condition of a do statement with an unbraced body starts in
/// the text after `do`: the last top-level `while (...)` that ends it (only
/// a `;` may follow). The first `while` anywhere was taken, so a while loop
/// as the body (`do while (a) a--; while (b);`) lost its body, and a
/// `while` inside a string or an identifier (`awhile`) split the statement.
fn do_condition_while_index(after_do: &str) -> Option<usize> {
    let mut found = None;
    let mut offset = 0;
    while let Some(at) = find_top_level_keyword(&after_do[offset..], "while") {
        let index = offset + at;
        offset = index + "while".len();
        let rest = &after_do[offset..];
        if after_do[..index]
            .chars()
            .next_back()
            .is_some_and(is_identifier_continue)
            || rest.starts_with(is_identifier_continue)
        {
            continue;
        }
        let rest = rest.trim_start();
        if rest.starts_with('(')
            && let Some((_, tail)) = extract_balanced(rest, '(', ')')
            && matches!(tail.trim(), "" | ";")
        {
            found = Some(index);
        }
    }
    found
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
        let (inner, r) = extract_balanced(after_do, '{', '}').ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "do-while body has unbalanced braces",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        (format!("{{{inner}}}"), r.to_string())
    } else {
        let while_idx = do_condition_while_index(after_do).ok_or_else(|| {
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

    reject_declaration_in_statement_position(&body_src, StatementPosition::Loop, &span, context)?;
    // An unbraced body's `;` terminates the body statement, it is not part
    // of its expression (`do e++; while (c)`); a lone `;` stays the empty
    // statement.
    let body_src = body_src.trim();
    let body_src = match body_src.strip_suffix(';') {
        Some(expression) if !expression.trim().is_empty() => expression.trim_end(),
        _ => body_src,
    };
    let body = parse_statement(body_src, goal, span.clone(), context)?;

    let rest = rest.trim();
    let rest = rest.strip_prefix("while").unwrap_or(rest).trim_start();
    let (condition_src, _) = extract_balanced(rest, '(', ')').ok_or_else(|| {
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
        // ES2020 §14.10: ReturnStatement argument is an Expression, which
        // includes the comma/sequence operator (`return a, b, c` yields `c`).
        // Use the sequence-aware parser so it doesn't fall to Expression::Raw
        // (bd-h5m8u; mirrors bd-qxkli/bd-j4l7k).
        Some(parse_expression_allowing_sequence(body, &span, context, 1)?)
    };
    // ES2020 13.10.1: in an async generator, `return expr` awaits expr
    // before the return completion exists (a rejection still reaches this
    // frame's catch and finally); `return;` and falling off the end do not
    // await (bd-9vouw.351). The lowering and the runtime settle the
    // completion at once.
    let argument = argument.map(|argument| {
        if context.await_context && context.yield_context {
            Expression::Await(Box::new(argument))
        } else {
            argument
        }
    });
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
    // ES2020 §14.14: ThrowStatement argument is an Expression (sequence
    // operator included), so `throw a, b, c` throws `c` rather than falling to
    // Expression::Raw (bd-h5m8u).
    let argument = parse_expression_allowing_sequence(body, &span, context, 1)?;
    Ok(Statement::Throw(ThrowStatement { argument, span }))
}

/// Synthetic parameter of a catch clause whose parameter is a destructuring
/// pattern; the block's first statement destructures it. Like the `__seq_*`
/// parameters it shadows a same-named outer binding inside the block only.
/// The lowering keeps it lexical (bd-9vouw.253).
pub(crate) const CATCH_PATTERN_PARAMETER: &str = "__catch_parameter";

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
    let (try_inner, rest) = extract_balanced(after_try, '{', '}').ok_or_else(|| {
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

    let rest = rest.trim();

    // Parse optional catch clause.
    let (handler, rest) = if rest.starts_with("catch") {
        let after_catch = rest.strip_prefix("catch").unwrap_or(rest).trim_start();
        let mut destructured_parameter = None;
        let (param, after_param) = if after_catch.starts_with('(') {
            let (p, r) = extract_balanced(after_catch, '(', ')').ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "catch clause has unbalanced parentheses",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
            let parameter = p.trim();
            if parameter.is_empty() {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "catch clause parameter cannot be empty",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
            match parse_binding_pattern(parameter, &span, context)? {
                BindingPattern::Identifier(_) => (Some(parameter.to_string()), r),
                // ES2020 13.15.7: `catch ({ m })` / `catch ([a, b])` bind the
                // pattern's names from the thrown value (a TypeError for null
                // or undefined). The clause binds a synthetic parameter and the
                // block starts with `let <pattern> = <parameter>;`, which has
                // the same scoping: a pattern name redeclared in the block is
                // an early error either way (13.15.1).
                _ => {
                    destructured_parameter = Some(parameter);
                    (Some(CATCH_PATTERN_PARAMETER.to_string()), r)
                }
            }
        } else {
            (None, after_catch)
        };
        let after_param = after_param.trim_start();
        let (catch_inner, rest2) = extract_balanced(after_param, '{', '}').ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "catch clause requires a braced block",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let mut catch_body = parse_body_statements(catch_inner, goal, &span, context)?;
        if let Some(pattern) = destructured_parameter {
            let binding = format!("let {pattern} = {CATCH_PATTERN_PARAMETER};");
            let mut prologue = parse_body_statements(&binding, goal, &span, context)?;
            prologue.append(&mut catch_body);
            catch_body = prologue;
        }
        (
            Some(CatchClause {
                parameter: param,
                body: BlockStatement {
                    body: catch_body,
                    span: span.clone(),
                },
                span: span.clone(),
            }),
            rest2.trim(),
        )
    } else {
        (None, rest)
    };

    // Parse optional finally clause.
    let (finalizer, rest) = if rest.starts_with("finally") {
        let after_finally = rest.strip_prefix("finally").unwrap_or(rest).trim_start();
        let (finally_inner, rest2) =
            extract_balanced(after_finally, '{', '}').ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "finally clause requires a braced block",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
        let finally_body = parse_body_statements(finally_inner, goal, &span, context)?;
        (
            Some(BlockStatement {
                body: finally_body,
                span: span.clone(),
            }),
            rest2.trim(),
        )
    } else {
        (None, rest)
    };

    if handler.is_none() && finalizer.is_none() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "try statement requires at least a catch or finally clause",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    if !rest.is_empty() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "try statement has unexpected trailing tokens",
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
    let (disc_src, rest) = extract_balanced(after_switch, '(', ')').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "switch statement requires a parenthesized discriminant",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let discriminant = parse_expression_allowing_sequence(disc_src.trim(), &span, context, 1)?;

    let rest = rest.trim();
    let (body_src, _) = extract_balanced(rest, '{', '}').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "switch statement requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    // Parse case/default clauses.
    let mut cases = Vec::with_capacity(4);
    let mut remaining = body_src.trim();
    while !remaining.is_empty() {
        if let Some(after_case) = strip_case_keyword(remaining) {
            let colon_idx = find_ternary_colon(after_case).ok_or_else(|| {
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
    let mut quotes = QuoteState::default();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if quotes.active() {
            quotes.advance(b);
            i += 1;
            continue;
        }
        if b == b'/' && quotes.open_regex_at(s, i) {
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' | b'`' => {
                quotes.open(b);
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
            // Check for `case` or `default` at a keyword boundary. After a
            // `.` they are property names (`exports.default`, `o.case`).
            let before_ok =
                i == 0 || (!is_identifier_continue(bytes[i - 1] as char) && bytes[i - 1] != b'.');
            if before_ok {
                if bytes[i] == b'c' && strip_case_keyword(&s[i..]).is_some() {
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

/// The clause text after a leading `case` keyword, or `None` when `text`
/// does not start with one. The keyword ends at any character that cannot
/// continue an identifier: minified code writes `case"x":`, `case'x':`,
/// `case(1):` and `case-1:` without a space, and a switch whose labels were
/// not recognised ran neither the matching case nor `default`
/// (bd-9vouw.91; dayjs format tokens).
fn strip_case_keyword(text: &str) -> Option<&str> {
    let rest = text.strip_prefix("case")?;
    match rest.chars().next() {
        Some(ch) if !is_identifier_continue(ch) && ch != '\\' => Some(rest),
        _ => None,
    }
}

fn parse_break_statement(statement: &str, span: SourceSpan) -> ParseResult<Statement> {
    let body = statement.strip_prefix("break").unwrap_or("").trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    let label = if body.is_empty() || !is_identifier(body) {
        None
    } else {
        Some(body.to_string())
    };
    Ok(Statement::Break(BreakStatement { label, span }))
}

fn parse_continue_statement(statement: &str, span: SourceSpan) -> ParseResult<Statement> {
    let body = statement.strip_prefix("continue").unwrap_or("").trim();
    let body = body.strip_suffix(';').unwrap_or(body).trim();
    let label = if body.is_empty() || !is_identifier(body) {
        None
    } else {
        Some(body.to_string())
    };
    Ok(Statement::Continue(ContinueStatement { label, span }))
}

/// Parse a function expression: `function(a, b) { ... }` or `function name(a, b) { ... }`.
/// `rest` is the text after the `function` keyword (already stripped).
fn parse_function_expression(
    rest: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    parse_function_expression_with_super(rest, span, context, recursion_depth, false, false)
}

fn parse_async_function_expression(
    rest: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    parse_function_expression_with_super(rest, span, context, recursion_depth, false, true)
}

fn parse_object_method_function_expression(
    rest: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    parse_function_expression_with_super(rest, span, context, recursion_depth, true, false)
}

/// Whether the function expression `[*][name](params){body}` that starts
/// `rest` (the text after `function`) extends to the end of `rest`. A
/// malformed head also counts as whole, so its specific parse error is kept.
fn function_expression_is_whole(rest: &str) -> bool {
    let head = rest.trim_start();
    let head = head.strip_prefix('*').map_or(head, str::trim_start);
    let Some(paren) = head.find('(') else {
        return true;
    };
    let Some((_, after_params)) = extract_balanced(&head[paren..], '(', ')') else {
        return true;
    };
    match extract_balanced(after_params.trim_start(), '{', '}') {
        Some((_, after_body)) => after_body.trim().is_empty(),
        None => true,
    }
}

/// Whether the class expression `class ... { body }` that starts
/// `expression` ends with its body. The body is the first `{`, as
/// parse_class_parts reads it (a class name cannot contain one). Text after
/// the body (`class A {}.name`, `class { m() {} }.prototype.m()`) makes the
/// class the object or callee of that suffix for the member and call
/// parsing below; it was silently dropped, so the expression was the class
/// itself. A malformed head counts as whole, so its specific error is kept.
fn class_expression_is_whole(expression: &str) -> bool {
    let Some(brace) = class_body_brace(expression) else {
        return true;
    };
    match extract_balanced(&expression[brace..], '{', '}') {
        Some((_, after_body)) => after_body.trim().is_empty(),
        None => true,
    }
}

/// The offset of a `class ...` source's body `{`, found as
/// `parse_class_parts` finds it: past the name and an `extends` heritage, so
/// braces in the heritage (`class extends class {} {}`,
/// `class extends (() => {}) {}`) are not taken for the body (bd-9vouw.176).
fn class_body_brace(source: &str) -> Option<usize> {
    let rest = source.strip_prefix("class")?;
    let base = source.len() - rest.len();
    let header_end = first_top_level_brace(rest)?;
    let trimmed = rest.trim_start();
    let extends = if trimmed.starts_with("extends ") {
        Some(rest.len() - trimmed.len())
    } else {
        rest[..header_end].find(" extends ").map(|index| index + 1)
    };
    match extends {
        Some(extends) => {
            let after = extends + "extends ".len();
            Some(base + after + class_heritage_body_brace(&rest[after..])?)
        }
        None => Some(base + header_end),
    }
}

fn parse_function_expression_with_super(
    rest: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    _recursion_depth: u64,
    super_property_allowed: bool,
    is_async: bool,
) -> ParseResult<Expression> {
    let rest = rest.trim_start();
    let is_generator = rest.starts_with('*');
    let rest = if is_generator { &rest[1..] } else { rest }.trim_start();

    // Parse optional name (function expressions can be anonymous).
    let (name, rest) = if rest.starts_with('(') {
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
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            },
            &rest[paren_idx..],
        )
    };

    // Parse parameters.
    let (params_src, rest) = extract_balanced(rest, '(', ')').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function expression has unbalanced parentheses",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    // Parse body.
    let rest = rest.trim_start();
    let (body_src, _) = extract_balanced(rest, '{', '}').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function expression requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    // An expression's name is scoped to the function itself, so its own kind
    // gives [Yield] and [Await] (ES2020 14.1: `function
    // BindingIdentifier[~Yield, ~Await]`, `function *
    // BindingIdentifier[+Yield, ~Await]`, `async function
    // BindingIdentifier[~Yield, +Await]`).
    let name = name
        .map(|raw| {
            function_binding_name(
                &raw,
                context.strict_mode || has_use_strict_directive(body_src),
                is_generator,
                is_async,
                span,
                context,
            )
        })
        .transpose()?;
    let goal = ParseGoal::Script;
    let saved_super_property_allowed = context.super_property_allowed;
    context.super_property_allowed = super_property_allowed;
    let saved_super_call = std::mem::replace(&mut context.super_call, SuperCallContext::Forbidden);
    let parsed = with_function_context(is_async, is_generator, context, |context| {
        with_function_strict_mode(body_src, false, context, |context| {
            let params = parse_arrow_params(params_src, span, context)?;
            reject_use_strict_with_non_simple_params(body_src, &params, span, context)?;
            reject_duplicate_params(&params, false, span, context)?;
            let mut body = parse_body_statements(body_src, goal, span, context)?;
            if !context.strict_mode {
                apply_annex_b_block_functions(&mut body, &params);
            }
            Ok((params, body, context.strict_mode))
        })
    });
    context.super_property_allowed = saved_super_property_allowed;
    context.super_call = saved_super_call;
    let (params, body_stmts, strict) = parsed?;

    Ok(Expression::Function {
        name,
        params,
        body: BlockStatement {
            body: body_stmts,
            span: span.clone(),
        },
        is_async,
        is_generator,
        source_text: None,
        strict,
    })
}

/// Parse the shared anatomy of a class — optional name, optional `extends`
/// clause, and braced body — from a `class ...` source. Used by both the
/// declaration (`parse_class_declaration`) and expression
/// (`parse_class_expression`) entry points so the two never diverge.
#[allow(clippy::type_complexity)]
fn parse_class_parts(
    statement: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<(
    Option<String>,
    Option<Box<Expression>>,
    Vec<MethodDefinition>,
)> {
    let rest = statement
        .strip_prefix("class")
        .unwrap_or(statement)
        .trim_start();

    // Parse optional class name and optional `extends` clause.
    let (name, rest) = if rest.starts_with('{') || rest.starts_with("extends ") {
        (None, rest)
    } else {
        // Name is everything up to `{` or `extends`.
        let end = rest
            .find('{')
            .unwrap_or(rest.len())
            .min(rest.find(" extends ").unwrap_or(rest.len()));
        let name = rest[..end].trim();
        (
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            },
            &rest[end..],
        )
    };

    // The name is a BindingIdentifier in strict code (class code is strict,
    // ES2020 10.2.1): `class let {}`, `class eval {}` and `class yield {}`
    // in a generator are SyntaxErrors, and an escaped name is canonical.
    let name = match name {
        Some(name) => {
            let pattern = with_function_strict_mode("", true, context, |context| {
                parse_binding_pattern(&name, span, context)
            })?;
            let BindingPattern::Identifier(name) = pattern else {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    format!("invalid class name `{name}`"),
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            };
            Some(name)
        }
        None => None,
    };

    let rest = rest.trim_start();

    // Parse optional extends clause.
    let (super_class, rest) = if let Some(after_extends) = rest.strip_prefix("extends ") {
        let brace = class_heritage_body_brace(after_extends).ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "class extends clause requires a braced body",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let super_name = after_extends[..brace].trim();
        let super_class = with_function_strict_mode("", true, context, |context| {
            parse_expression(super_name, span, context, 1)
        })?;
        (Some(Box::new(super_class)), &after_extends[brace..])
    } else {
        (None, rest)
    };

    // Parse class body { ... }.
    let (body_src, _) = extract_balanced(rest, '{', '}').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "class declaration requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    let mut methods = parse_class_body(body_src, super_class.is_some(), span, context)?;
    // A derived class with instance fields or private methods but no
    // constructor gets the implicit `constructor(...args) { super(...args); }`
    // (ES2022 15.7.14 step 10.a) as real code: the instance elements
    // initialize when its super() returns, which the engine's forwarding
    // default constructor never runs.
    if super_class.is_some()
        && !methods
            .iter()
            .any(|method| method.kind == MethodKind::Constructor)
        && methods.iter().any(|method| {
            !method.is_static
                && (method.kind == MethodKind::Field || method.private_name().is_some())
        })
    {
        let mut implicit = parse_class_body(
            "constructor(...args) { super(...args); }",
            true,
            span,
            context,
        )?;
        methods.splice(0..0, implicit.drain(..));
    }

    Ok((name, super_class, methods))
}

fn parse_class_declaration(
    statement: &str,
    span: SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Statement> {
    let source_text =
        class_text_through_body(statement).and_then(|text| context.function_sources.text_of(text));
    let (name, super_class, body) = parse_class_parts(statement, &span, context)?;
    if name.is_none() {
        return Err(invalid_syntax_error(
            "class declarations require a binding name",
            &span,
            context,
        ));
    }

    Ok(Statement::ClassDeclaration(ClassDeclaration {
        name,
        super_class,
        body,
        span,
        source_text,
    }))
}

/// The prefix of a `class ...` source that ends with the body's `}`.
fn class_text_through_body(source: &str) -> Option<&str> {
    let brace = class_body_brace(source)?;
    let (_, after_body) = extract_balanced(&source[brace..], '{', '}')?;
    Some(&source[..source.len() - after_body.len()])
}

/// Parse a class **expression** (`class {...}`, `class Name {...}`,
/// `class extends Base {...}`) into `Expression::ClassExpression`. The parser
/// previously had no such path, so a class in expression position never became
/// a `ClassExpression` and faulted at runtime (bd-4a4yz). Shares all parsing
/// with the declaration form via `parse_class_parts`.
fn parse_class_expression(
    statement: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Expression> {
    let source_text =
        class_text_through_body(statement).and_then(|text| context.function_sources.text_of(text));
    let (name, super_class, body) = parse_class_parts(statement, span, context)?;

    Ok(Expression::ClassExpression {
        name,
        super_class,
        body,
        source_text,
    })
}

/// Parse the contents of a class body into a list of MethodDefinitions. The
/// body opens a private-name scope: every `#x` referenced in it must be
/// declared by it or by an enclosing class body (ES2022 15.7.1
/// AllPrivateIdentifiersValid).
/// `derived`: the class has an `extends` clause, so its constructor may call
/// `super(...)`.
fn parse_class_body(
    body: &str,
    derived: bool,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<MethodDefinition>> {
    context
        .private_name_scopes
        .push(PrivateNameScope::default());
    let parsed = parse_class_body_members(body, derived, span, context);
    let scope = context.private_name_scopes.pop().unwrap_or_default();
    let methods = parsed?;
    for name in scope.referenced {
        if scope.declared.contains_key(&name) {
            continue;
        }
        match context.private_name_scopes.last_mut() {
            Some(outer) => {
                outer.referenced.insert(name);
            }
            None => return Err(undeclared_private_name_error(&name, span, context)),
        }
    }
    Ok(methods)
}

/// Length of the private name `#IdentifierName` that `text` starts with, or
/// 0 when it does not start with one.
fn private_name_prefix_len(text: &str) -> usize {
    let Some(after_hash) = text.strip_prefix('#') else {
        return 0;
    };
    if !after_hash.chars().next().is_some_and(is_identifier_start) && !after_hash.starts_with("\\u")
    {
        return 0;
    }
    let name_len = after_hash.len() - skip_identifier_name(after_hash).len();
    if name_len == 0 { 0 } else { name_len + 1 }
}

/// `text` as a private name (`#x`, escapes canonicalized) when it is exactly
/// one, else `None`.
fn whole_private_name(text: &str) -> Option<String> {
    let text = text.trim();
    let len = private_name_prefix_len(text);
    (len > 0 && len == text.len()).then(|| format!("#{}", canonicalize_identifier(&text[1..])))
}

/// Whether `expression` is `o.#x` or `o?.#x`.
fn is_private_member_expression(expression: &Expression) -> bool {
    match expression {
        Expression::Member {
            property,
            computed: true,
            ..
        }
        | Expression::OptionalMember {
            property,
            computed: true,
            ..
        } => matches!(property.as_ref(), Expression::Identifier(name) if name.starts_with('#')),
        _ => false,
    }
}

/// Record a `#x` reference in the innermost class body's private-name scope.
/// Outside every class body it is an early SyntaxError.
fn record_private_name_reference(
    name: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<()> {
    match context.private_name_scopes.last_mut() {
        Some(scope) => {
            scope.referenced.insert(name.to_string());
            Ok(())
        }
        None => Err(undeclared_private_name_error(name, span, context)),
    }
}

fn undeclared_private_name_error(
    name: &str,
    span: &SourceSpan,
    context: &ParseExecutionContext<'_>,
) -> ParseError {
    ParseError::new(
        ParseErrorCode::InvalidSyntax,
        format!("Private field '{name}' must be declared in an enclosing class"),
        context.source_label.to_string(),
        Some(span.clone()),
    )
}

/// Declare a private name in the innermost class body. ES2022 15.7.1 early
/// errors: no element is named `#constructor`, and a name is declared once,
/// except that one getter and one setter of the same placement pair up.
fn declare_private_name(
    name: &str,
    declaration: PrivateNameDeclaration,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<()> {
    let conflict = if name == "#constructor" {
        Some("classes may not have a private element named '#constructor'".to_string())
    } else if let Some(scope) = context.private_name_scopes.last_mut() {
        use PrivateNameDeclaration::{Accessor, Getter, Setter};
        let merged = match (scope.declared.get(name).copied(), declaration) {
            (None, declaration) => Some(declaration),
            (Some(Getter { is_static: a }), Setter { is_static: b })
            | (Some(Setter { is_static: a }), Getter { is_static: b })
                if a == b =>
            {
                Some(Accessor)
            }
            _ => None,
        };
        match merged {
            Some(merged) => {
                scope.declared.insert(name.to_string(), merged);
                None
            }
            None => Some(format!("private name '{name}' is declared more than once")),
        }
    } else {
        Some(format!(
            "private name '{name}' declared outside a class body"
        ))
    };
    match conflict {
        None => Ok(()),
        Some(message) => Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            message,
            context.source_label.to_string(),
            Some(span.clone()),
        )),
    }
}

/// Parse `static { ... }` (ES2022 15.7.10 ClassStaticBlock) into a
/// [`MethodKind::StaticBlock`] member. The block is strict code that runs
/// with the class as `this` and a [[HomeObject]], so `super.x` is allowed.
fn parse_class_static_block(
    block: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<MethodDefinition> {
    let malformed = |context: &ParseExecutionContext<'_>| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("malformed class static block: `static {block}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        )
    };
    let Some((body_src, after)) = extract_balanced(block, '{', '}') else {
        return Err(malformed(context));
    };
    if !after.trim().is_empty() {
        return Err(malformed(context));
    }
    let saved_super_property_allowed = context.super_property_allowed;
    context.super_property_allowed = true;
    let saved_super_call =
        std::mem::replace(&mut context.super_call, SuperCallContext::ClassElement);
    let parsed = with_function_context(false, false, context, |context| {
        let saved_static_block_await = std::mem::replace(&mut context.static_block_await, true);
        let parsed = with_function_strict_mode(body_src, true, context, |context| {
            parse_body_statements(body_src, ParseGoal::Script, span, context)
        });
        context.static_block_await = saved_static_block_await;
        parsed
    });
    context.super_property_allowed = saved_super_property_allowed;
    context.super_call = saved_super_call;
    let body = parsed?;
    // ES2022 15.7.1 ClassStaticBlockBody early errors: no `return`, no
    // `break`/`continue` that leaves the block, and (as for a field
    // initializer) no `arguments` or `super()`.
    let forbidden = static_block_jump_error(&body).or_else(|| {
        field_initializer_forbidden(&Expression::ArrowFunction {
            params: Vec::new(),
            body: ArrowBody::Block(BlockStatement {
                body: body.clone(),
                span: span.clone(),
            }),
            is_async: false,
            source_text: None,
        })
    });
    if let Some(found) = forbidden {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("a class static block may not contain `{found}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }
    Ok(MethodDefinition {
        key: Expression::Identifier("static".to_string()),
        kind: MethodKind::StaticBlock,
        params: Vec::new(),
        body: BlockStatement {
            body,
            span: span.clone(),
        },
        is_static: true,
        computed: false,
        span: span.clone(),
        is_async: false,
        is_generator: false,
        source_text: None,
    })
}

/// A `return`, or a `break`/`continue` whose target is outside, in the
/// statements of a class static block (nested functions and classes are
/// their own scope and are not entered).
fn static_block_jump_error(body: &[Statement]) -> Option<&'static str> {
    fn walk(
        statement: &Statement,
        loops: u32,
        breakable: u32,
        labels: &mut Vec<String>,
    ) -> Option<&'static str> {
        let each = |statements: &[Statement], labels: &mut Vec<String>| {
            statements
                .iter()
                .find_map(|statement| walk(statement, loops, breakable, labels))
        };
        match statement {
            Statement::Return(_) => Some("return"),
            Statement::Break(jump) => match &jump.label {
                None if breakable == 0 => Some("break"),
                Some(label) if !labels.contains(label) => Some("break"),
                _ => None,
            },
            Statement::Continue(jump) => match &jump.label {
                None if loops == 0 => Some("continue"),
                Some(label) if !labels.contains(label) => Some("continue"),
                _ => None,
            },
            Statement::Block(block) => each(&block.body, labels),
            Statement::If(branch) => {
                walk(&branch.consequent, loops, breakable, labels).or_else(|| {
                    branch
                        .alternate
                        .as_deref()
                        .and_then(|alternate| walk(alternate, loops, breakable, labels))
                })
            }
            Statement::For(looped) => walk(&looped.body, loops + 1, breakable + 1, labels),
            Statement::While(looped) => walk(&looped.body, loops + 1, breakable + 1, labels),
            Statement::DoWhile(looped) => walk(&looped.body, loops + 1, breakable + 1, labels),
            Statement::ForIn(looped) => walk(&looped.body, loops + 1, breakable + 1, labels),
            Statement::ForOf(looped) => walk(&looped.body, loops + 1, breakable + 1, labels),
            Statement::With(with) => walk(&with.body, loops, breakable, labels),
            Statement::TryCatch(attempt) => each(&attempt.block.body, labels)
                .or_else(|| {
                    attempt
                        .handler
                        .as_ref()
                        .and_then(|handler| each(&handler.body.body, labels))
                })
                .or_else(|| {
                    attempt
                        .finalizer
                        .as_ref()
                        .and_then(|finalizer| each(&finalizer.body, labels))
                }),
            Statement::Switch(switch) => switch.cases.iter().find_map(|case| {
                case.consequent
                    .iter()
                    .find_map(|statement| walk(statement, loops, breakable + 1, labels))
            }),
            Statement::Labeled(labeled) => {
                labels.push(labeled.label.clone());
                let found = walk(&labeled.body, loops, breakable, labels);
                labels.pop();
                found
            }
            _ => None,
        }
    }
    let mut labels = Vec::new();
    body.iter()
        .find_map(|statement| walk(statement, 0, 0, &mut labels))
}

/// The class elements of a class body (see [`parse_class_body`]).
fn parse_class_body_members(
    body: &str,
    derived: bool,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<Vec<MethodDefinition>> {
    let mut methods = Vec::with_capacity(8);
    let body = body.trim();
    if body.is_empty() {
        return Ok(methods);
    }

    // Split on top-level method boundaries.  Each method looks like:
    // [static] [get|set] name(...) { ... }
    // We scan for `}` at brace_depth==0 to find method boundaries. A field
    // segment may carry further elements after a line break (ASI) or have
    // been cut at a `}` inside its initializer; both are repaired below, so
    // the segments are processed as a queue of slices of `body`.
    let mut pending: std::collections::VecDeque<&str> = split_class_members(body).into();
    while let Some(segment) = pending.pop_front() {
        let segment = segment.trim();
        if segment.is_empty() || segment == ";" {
            continue;
        }
        // ES2022 `static { ... }`.
        if let Some(block) = segment
            .strip_prefix("static")
            .map(str::trim_start)
            .filter(|after| after.starts_with('{'))
        {
            methods.push(parse_class_static_block(block, span, context)?);
            continue;
        }
        let static_prefix = class_element_modifier(segment, "static", false);
        let is_static = static_prefix.is_some();
        let mut rest = static_prefix.unwrap_or(segment);

        // ES2022 public fields: `[static] key [= initializer]`. A key is
        // followed by `=`, `;` or nothing; a method's by its parameter list.
        let field_key_end = if rest.starts_with('[') {
            extract_balanced(rest, '[', ']').map_or(0, |(_, after)| rest.len() - after.len())
        } else {
            private_name_prefix_len(rest)
        };
        if rest.starts_with('#') && field_key_end == 0 {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("invalid private name in class element `{segment}`"),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        if class_member_is_field(&rest[field_key_end..]) {
            // `x = {a: 1}.a` was cut after the object literal's `}`: glue
            // continuation segments back on. A segment that ended at `;` is
            // complete, so `[x]; [y] = 42;` stays two fields.
            while !rest.ends_with(';')
                && let Some(next) = pending.front()
                && class_field_continues_with(next)
            {
                let end = subslice_offset(body, next) + next.len();
                rest = body[subslice_offset(body, rest)..end].trim();
                pending.pop_front();
            }
            let (field, remainder) = split_class_field_asi(rest);
            if let Some(remainder) = remainder {
                pending.push_front(remainder);
            }
            methods.push(parse_class_field(
                field,
                is_static,
                field_key_end,
                span,
                context,
            )?);
            continue;
        }

        // A method's source text starts after `static` (bd-9vouw.184).
        let member_head = rest;
        // Method modifiers (ES2020 14.4-14.7): `async m(){}`, `*m(){}`,
        // `async *m(){}`. `async(){}` names a method `async`.
        let (is_async, rest) = match class_element_modifier(rest, "async", true) {
            Some(after) => (true, after),
            None => (false, rest),
        };
        let (is_generator, rest) = match rest.strip_prefix('*') {
            Some(after) => (true, after.trim_start()),
            None => (false, rest),
        };

        let kind;
        let rest = if is_async || is_generator {
            kind = MethodKind::Method;
            rest
        } else if let Some(after) = class_accessor_prefix(rest, "get") {
            kind = MethodKind::Get;
            after
        } else if let Some(after) = class_accessor_prefix(rest, "set") {
            kind = MethodKind::Set;
            after
        } else {
            kind = MethodKind::Method;
            rest
        };

        // Extract method name (up to `(`). A computed key `[expr]` may itself
        // contain parentheses, so the search starts after its closing `]`.
        let private_key_len = private_name_prefix_len(rest);
        let key_end = if rest.starts_with('[') {
            extract_balanced(rest, '[', ']').map_or(0, |(_, after)| rest.len() - after.len())
        } else {
            private_key_len
        };
        // A field reached only after a get/set/async/`*` prefix (`get = 1`
        // is a field named "get" and was handled above) is malformed, and so
        // is a `#` that starts no private name.
        if (rest.starts_with('#') && private_key_len == 0)
            || class_member_is_field(&rest[key_end..])
        {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("malformed class element: `{}`", segment.trim()),
                context.source_label.to_string(),
                Some(span.clone()),
            ));
        }
        let paren_idx = rest[key_end..]
            .find('(')
            .map(|index| index + key_end)
            .ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    format!("class method requires parameter list: {}", segment),
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
        let method_name = rest[..paren_idx].trim();
        let (key, computed) = if private_key_len > 0 {
            // `#m() {}`, `get #x() {}`: keyed by the private name (see
            // MethodKind::Field).
            let Some(name) = whole_private_name(method_name) else {
                return Err(ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    format!("malformed private method: `{}`", segment.trim()),
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            };
            let declaration = match kind {
                MethodKind::Get => PrivateNameDeclaration::Getter { is_static },
                MethodKind::Set => PrivateNameDeclaration::Setter { is_static },
                _ => PrivateNameDeclaration::Method { is_static },
            };
            declare_private_name(&name, declaration, span, context)?;
            (Expression::Identifier(name), true)
        } else if let Some(inner) = method_name
            .strip_prefix('[')
            .and_then(|name| name.strip_suffix(']'))
        {
            (
                with_function_strict_mode("", true, context, |context| {
                    parse_expression(inner.trim(), span, context, 1)
                })?,
                true,
            )
        } else {
            (
                parse_contextual_static_property_key(
                    method_name,
                    span,
                    context,
                    LegacyDecimalEscapeMode::Reject,
                    "class-method",
                )?,
                false,
            )
        };
        // ES2022 15.7.1: a non-static method whose PropName is
        // "constructor" (`constructor`, `'constructor'`) is the class
        // constructor, and as a getter, setter, generator or async method it
        // is an early error; a static one is an ordinary static method
        // (`static constructor() {}` was taken for the constructor and
        // lost, bd-9vouw.288). A static method named "prototype" is an
        // early error.
        let prop_name = match &key {
            Expression::Identifier(name) if !computed => Some(name.as_str()),
            Expression::StringLiteral(name) if !computed => name.as_str(),
            _ => None,
        };
        let actual_kind = match prop_name {
            Some("constructor") if !is_static => {
                if kind != MethodKind::Method || is_async || is_generator {
                    return Err(ParseError::new(
                        ParseErrorCode::InvalidClassElementName,
                        "a class constructor may not be a getter, setter, generator or async method",
                        context.source_label.to_string(),
                        Some(span.clone()),
                    ));
                }
                MethodKind::Constructor
            }
            Some("prototype") if is_static => {
                return Err(ParseError::new(
                    ParseErrorCode::InvalidClassElementName,
                    "classes may not have a static method named 'prototype'",
                    context.source_label.to_string(),
                    Some(span.clone()),
                ));
            }
            _ => kind,
        };
        let rest = &rest[paren_idx..];

        // Parse parameters.
        let (params_src, rest) = extract_balanced(rest, '(', ')').ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "class method has unbalanced parentheses",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        // Parse method body.
        let rest = rest.trim_start();
        let (body_src, after_body) = extract_balanced(rest, '{', '}').ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "class method requires a braced body",
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let source_text = context
            .function_sources
            .text_of(&member_head[..member_head.len() - after_body.len()]);
        let goal = ParseGoal::Script;
        // Class methods, accessors and constructors have a [[HomeObject]], so
        // `super.x` / `super.m()` are valid in their bodies.
        let saved_super_property_allowed = context.super_property_allowed;
        context.super_property_allowed = true;
        let super_call = if derived && actual_kind == MethodKind::Constructor && !is_static {
            SuperCallContext::DerivedConstructor
        } else {
            SuperCallContext::Forbidden
        };
        let saved_super_call = std::mem::replace(&mut context.super_call, super_call);
        let parsed = with_function_context(is_async, is_generator, context, |context| {
            with_function_strict_mode(body_src, true, context, |context| {
                let params = parse_arrow_params(params_src, span, context)?;
                reject_use_strict_with_non_simple_params(body_src, &params, span, context)?;
                reject_duplicate_params(&params, true, span, context)?;
                if matches!(kind, MethodKind::Get | MethodKind::Set) {
                    reject_accessor_arity(kind == MethodKind::Get, &params, span, context)?;
                }
                let body = parse_body_statements(body_src, goal, span, context)?;
                Ok((params, body))
            })
        });
        context.super_property_allowed = saved_super_property_allowed;
        context.super_call = saved_super_call;
        let (params, body_stmts) = parsed?;

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
            is_async,
            is_generator,
            source_text,
        });
    }

    Ok(methods)
}

/// Byte offset of `part` inside `whole`; `part` must be a subslice of it.
fn subslice_offset(whole: &str, part: &str) -> usize {
    (part.as_ptr() as usize).saturating_sub(whole.as_ptr() as usize)
}

/// Whether a class-body segment continues the previous field's initializer
/// rather than starting a new element: `split_class_members` cuts after every
/// top-level `}`, so `x = {a: 1}.a` or `f = function () {}.bind(this)` arrive
/// as two segments.
fn class_field_continues_with(next: &str) -> bool {
    let next = next.trim_start();
    // `:` is the rest of a conditional cut at an object literal's `}`
    // (`x = c ? {} : y`).
    next.starts_with([
        '.', '(', '[', '?', ':', ',', '+', '-', '*', '/', '%', '&', '|', '^', '<', '>', '`',
    ]) || (next.starts_with('=') && !next.starts_with("=>"))
        || (next.starts_with('!') && next.starts_with("!="))
        || starts_with_keyword(next, "in")
        || starts_with_keyword(next, "instanceof")
}

/// Split a field declaration from any class elements that follow it after a
/// line break with no `;` (ES2020 11.9.1 ASI: `x = 1\n y = 2\n m() {}`). A
/// line break ends the field when the text before it can end an expression
/// and the next line starts a new element; `x = a\n (b)`, `x = a\n [k]` and
/// `x = a +\n b` continue it, as in JavaScript. A field with no initializer
/// yet (`plain\n [k] = 2`) ends at the line break unless `=` follows.
fn split_class_field_asi(text: &str) -> (&str, Option<&str>) {
    let mut depth = 0usize;
    let mut quotes = QuoteState::default();
    let mut has_initializer = false;
    for (index, ch) in text.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if ch == '/' && quotes.open_regex_at(text, index) {
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '=' if depth == 0 => has_initializer = true,
            '\n' if depth == 0 && !has_initializer => {
                let head = text[..index].trim_end();
                let tail = text[index + 1..].trim_start();
                if !head.is_empty() && !tail.is_empty() && !tail.starts_with('=') {
                    return (head, Some(tail));
                }
            }
            '\n' if depth == 0 => {
                let head = text[..index].trim_end();
                let tail = text[index + 1..].trim_start();
                let head_is_complete = !head.is_empty()
                    && !head.ends_with([
                        '=', '+', '-', '*', '/', '%', '&', '|', '^', '!', '~', '<', '>', '?', ':',
                        ',', '.', '(', '[', '{',
                    ])
                    || head.ends_with("++")
                    || head.ends_with("--");
                let tail_starts_element = tail.chars().next().is_some_and(|c| {
                    c.is_alphanumeric() || matches!(c, '_' | '$' | '#' | '*' | '\'' | '"')
                }) && !starts_with_keyword(tail, "in")
                    && !starts_with_keyword(tail, "instanceof");
                if head_is_complete && tail_starts_element {
                    return (head, Some(tail));
                }
            }
            _ => {}
        }
    }
    (text, None)
}

/// ContainsArguments / Contains SuperCall for a class field initializer
/// (ES2022 15.7.1): the first `arguments` reference or `super(...)` call in
/// `expression`, looking into arrow functions (they have neither their own
/// `arguments` nor their own `super`) but not into ordinary functions,
/// methods or class bodies, which bind their own. Property names
/// (`o.arguments`, `{ arguments: 1 }`) are not references.
fn field_initializer_forbidden(expression: &Expression) -> Option<&'static str> {
    fn in_pattern(pattern: &BindingPattern) -> Option<&'static str> {
        match pattern {
            BindingPattern::Identifier(_) => None,
            BindingPattern::ObjectPattern(properties) => properties.iter().find_map(|property| {
                property
                    .computed
                    .then(|| in_expression(&property.key))
                    .flatten()
                    .or_else(|| in_pattern(&property.value))
            }),
            BindingPattern::ArrayPattern(elements) => {
                elements.iter().flatten().find_map(in_pattern)
            }
            BindingPattern::Rest(inner) => in_pattern(inner),
            BindingPattern::AssignmentPattern { left, right } => {
                in_pattern(left).or_else(|| in_expression(right))
            }
        }
    }
    fn in_class_heritage(
        super_class: Option<&Expression>,
        body: &[MethodDefinition],
    ) -> Option<&'static str> {
        // The heritage and computed member keys are evaluated in the
        // enclosing scope; member bodies are their own functions.
        super_class.and_then(in_expression).or_else(|| {
            body.iter()
                .filter(|member| member.computed)
                .find_map(|member| in_expression(&member.key))
        })
    }
    fn in_statements(body: &[Statement]) -> Option<&'static str> {
        body.iter().find_map(in_statement)
    }
    fn in_statement(stmt: &Statement) -> Option<&'static str> {
        match stmt {
            Statement::VariableDeclaration(declaration) => {
                declaration.declarations.iter().find_map(|declarator| {
                    in_pattern(&declarator.pattern)
                        .or_else(|| declarator.initializer.as_ref().and_then(in_expression))
                })
            }
            Statement::Expression(expression_statement) => {
                in_expression(&expression_statement.expression)
            }
            Statement::Block(block) => in_statements(&block.body),
            Statement::If(if_statement) => in_expression(&if_statement.condition)
                .or_else(|| in_statement(&if_statement.consequent))
                .or_else(|| if_statement.alternate.as_deref().and_then(in_statement)),
            Statement::For(for_statement) => for_statement
                .init
                .as_deref()
                .and_then(in_statement)
                .or_else(|| for_statement.condition.as_ref().and_then(in_expression))
                .or_else(|| for_statement.update.as_ref().and_then(in_expression))
                .or_else(|| in_statement(&for_statement.body)),
            Statement::While(loop_statement) => in_expression(&loop_statement.condition)
                .or_else(|| in_statement(&loop_statement.body)),
            Statement::DoWhile(loop_statement) => in_statement(&loop_statement.body)
                .or_else(|| in_expression(&loop_statement.condition)),
            Statement::With(with_statement) => {
                in_expression(&with_statement.object).or_else(|| in_statement(&with_statement.body))
            }
            Statement::Return(return_statement) => {
                return_statement.argument.as_ref().and_then(in_expression)
            }
            Statement::Throw(throw_statement) => in_expression(&throw_statement.argument),
            Statement::TryCatch(try_statement) => in_statements(&try_statement.block.body)
                .or_else(|| {
                    try_statement
                        .handler
                        .as_ref()
                        .and_then(|handler| in_statements(&handler.body.body))
                })
                .or_else(|| {
                    try_statement
                        .finalizer
                        .as_ref()
                        .and_then(|finalizer| in_statements(&finalizer.body))
                }),
            Statement::Switch(switch_statement) => in_expression(&switch_statement.discriminant)
                .or_else(|| {
                    switch_statement.cases.iter().find_map(|case| {
                        case.test
                            .as_ref()
                            .and_then(in_expression)
                            .or_else(|| in_statements(&case.consequent))
                    })
                }),
            Statement::Labeled(labeled) => in_statement(&labeled.body),
            Statement::ForIn(for_in) => in_pattern(&for_in.binding)
                .or_else(|| in_expression(&for_in.object))
                .or_else(|| in_statement(&for_in.body)),
            Statement::ForOf(for_of) => in_pattern(&for_of.binding)
                .or_else(|| in_expression(&for_of.iterable))
                .or_else(|| in_statement(&for_of.body)),
            Statement::ClassDeclaration(class) => {
                in_class_heritage(class.super_class.as_deref(), &class.body)
            }
            Statement::FunctionDeclaration(_)
            | Statement::Break(_)
            | Statement::Continue(_)
            | Statement::Import(_)
            | Statement::Export(_) => None,
        }
    }
    fn in_expression(expr: &Expression) -> Option<&'static str> {
        match expr {
            Expression::Identifier(name) if name == "arguments" => Some("arguments"),
            Expression::Call {
                callee, arguments, ..
            } => {
                if matches!(callee.as_ref(), Expression::Super) {
                    Some("super()")
                } else {
                    in_expression(callee).or_else(|| arguments.iter().find_map(in_expression))
                }
            }
            Expression::OptionalCall {
                callee, arguments, ..
            }
            | Expression::New { callee, arguments } => {
                in_expression(callee).or_else(|| arguments.iter().find_map(in_expression))
            }
            Expression::Member {
                object,
                property,
                computed,
                ..
            }
            | Expression::OptionalMember {
                object,
                property,
                computed,
                ..
            } => in_expression(object)
                .or_else(|| computed.then(|| in_expression(property)).flatten()),
            Expression::Await(inner) | Expression::SpreadElement(inner) => in_expression(inner),
            Expression::Yield { argument, .. } => argument.as_deref().and_then(in_expression),
            Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
                in_expression(left).or_else(|| in_expression(right))
            }
            Expression::Unary { argument, .. } => in_expression(argument),
            Expression::Conditional {
                test,
                consequent,
                alternate,
            } => in_expression(test)
                .or_else(|| in_expression(consequent))
                .or_else(|| in_expression(alternate)),
            Expression::ArrayLiteral(elements) => elements.iter().flatten().find_map(in_expression),
            Expression::ObjectLiteral(properties) => properties.iter().find_map(|property| {
                property
                    .computed
                    .then(|| in_expression(&property.key))
                    .flatten()
                    .or_else(|| in_expression(&property.value))
            }),
            Expression::ArrowFunction { params, body, .. } => params
                .iter()
                .find_map(|param| in_pattern(&param.pattern))
                .or_else(|| match body {
                    ArrowBody::Expression(body) => in_expression(body),
                    ArrowBody::Block(block) => in_statements(&block.body),
                }),
            Expression::TemplateLiteral { expressions, .. } => {
                expressions.iter().find_map(in_expression)
            }
            Expression::ClassExpression {
                super_class, body, ..
            } => in_class_heritage(super_class.as_deref(), body),
            Expression::Function { .. }
            | Expression::Identifier(_)
            | Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::FloatLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral
            | Expression::UndefinedLiteral
            | Expression::This
            | Expression::SloppyThis
            | Expression::NewTarget
            | Expression::ImportMeta
            | Expression::Raw(_)
            | Expression::RegExpLiteral { .. }
            | Expression::Super => None,
        }
    }
    in_expression(expression)
}

/// Parse one public field `key [= initializer][;]` (ES2022 15.7.10
/// ClassFieldDefinition) into a [`MethodKind::Field`] member whose body is
/// `return initializer;`. The initializer is strict code with a
/// [[HomeObject]] (`super.x` is allowed); `this` is the instance, or the
/// class for a static field. `key_end` is the length of a leading computed
/// key `[expr]`, else 0.
fn parse_class_field(
    text: &str,
    is_static: bool,
    key_end: usize,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
) -> ParseResult<MethodDefinition> {
    let text = text.trim();
    let text = text.strip_suffix(';').unwrap_or(text).trim_end();
    let malformed = |context: &ParseExecutionContext<'_>| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("malformed class field: `{text}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        )
    };
    // A private field `#x` is a computed member keyed by the private name
    // (see MethodKind::Field).
    let private_len = private_name_prefix_len(text);
    let computed = key_end > 0;
    let (key_src, after_key) = if private_len > 0 {
        (&text[..private_len], &text[private_len..])
    } else if computed {
        (&text[1..key_end - 1], &text[key_end..])
    } else {
        let key_len = match text.chars().next() {
            Some(quote @ ('\'' | '"')) => text[1..]
                .find(quote)
                .map(|close| close + 2)
                .ok_or_else(|| malformed(context))?,
            _ => text
                .find(['=', ' ', '\t', '\n', '\r'])
                .unwrap_or(text.len()),
        };
        (&text[..key_len], &text[key_len..])
    };
    let after_key = after_key.trim_start();
    let initializer = if after_key.is_empty() {
        None
    } else if let Some(value) = after_key
        .strip_prefix('=')
        .filter(|value| !value.starts_with(['=', '>']))
    {
        Some(value.trim())
    } else {
        return Err(malformed(context));
    };

    let saved_super_property_allowed = context.super_property_allowed;
    context.super_property_allowed = true;
    let parsed = with_function_strict_mode("", true, context, |context| {
        let key = if private_len > 0 {
            Expression::Identifier(format!("#{}", canonicalize_identifier(&key_src[1..])))
        } else if computed {
            parse_expression(key_src.trim(), span, context, 1)?
        } else {
            parse_contextual_static_property_key(
                key_src,
                span,
                context,
                LegacyDecimalEscapeMode::Reject,
                "class-method",
            )?
        };
        let value = match initializer {
            Some(source) if !source.is_empty() => {
                let saved_super_call =
                    std::mem::replace(&mut context.super_call, SuperCallContext::ClassElement);
                let value = parse_expression(source, span, context, 1);
                context.super_call = saved_super_call;
                Some(value?)
            }
            Some(_) => return Err(malformed(context)),
            None => None,
        };
        Ok((key, value))
    });
    context.super_property_allowed = saved_super_property_allowed;
    let (key, value) = parsed?;
    if private_len > 0
        && let Expression::Identifier(name) = &key
    {
        declare_private_name(
            name,
            PrivateNameDeclaration::Field { is_static },
            span,
            context,
        )?;
    }

    // ES2022 15.7.1: an initializer may not refer to `arguments` (looking
    // through arrow functions, not ordinary ones) or call `super(...)`.
    if let Some(found) = value.as_ref().and_then(field_initializer_forbidden) {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            format!("a class field initializer may not contain `{found}`"),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    // ES2022 15.7.1 early errors: no field named "constructor", and no
    // static field named "prototype".
    let static_name = match &key {
        Expression::Identifier(name) => Some(name.as_str()),
        Expression::StringLiteral(name) => name.as_str(),
        _ => None,
    };
    if !computed
        && let Some(name) = static_name
        && (name == "constructor" || (is_static && name == "prototype"))
    {
        return Err(ParseError::new(
            ParseErrorCode::InvalidClassElementName,
            format!(
                "classes may not have a {}field named '{name}'",
                if is_static { "static " } else { "" }
            ),
            context.source_label.to_string(),
            Some(span.clone()),
        ));
    }

    Ok(MethodDefinition {
        key,
        kind: MethodKind::Field,
        params: Vec::new(),
        body: BlockStatement {
            body: value
                .map(|argument| {
                    vec![Statement::Return(ReturnStatement {
                        argument: Some(argument),
                        span: span.clone(),
                    })]
                })
                .unwrap_or_default(),
            span: span.clone(),
        },
        is_static,
        computed,
        span: span.clone(),
        is_async: false,
        is_generator: false,
        source_text: None,
    })
}

/// Whether a class member, starting at its key (or just past a computed key),
/// declares a field rather than a method: a method's key is followed by its
/// parameter list, a field's by `=`, `;`, or nothing at all.
fn class_member_is_field(member: &str) -> bool {
    // ASI (bd-9vouw.230): a key followed by a line break and then anything
    // but `(` (a method's parameters) or `=` (an initializer) ends a field
    // declaration, since the next token cannot continue the element:
    // `x <LF> m() {}` and `#y <LF> m() {}` are a field and a method. A private
    // key arrives already removed, so `member` starts at that line break.
    let ends_at_line_break = |after_key: &str| {
        after_key
            .trim_start_matches([' ', '\t'])
            .starts_with(['\n', '\r', '\u{2028}', '\u{2029}'])
            && !after_key.trim_start().is_empty()
            && !after_key.trim_start().starts_with(['(', '='])
    };
    if ends_at_line_break(member) {
        return true;
    }
    let member = member.trim_start();
    let after_key = match member.chars().next() {
        Some(quote @ ('\'' | '"')) => member[1..]
            .find(quote)
            .map_or("", |close| &member[close + 2..]),
        // An IdentifierName key, which may contain `\u{...}` escapes whose
        // braces are not a method body.
        _ => skip_identifier_name(member),
    };
    // `get`, `set` and `static` continue across a line break (`get <LF> x()
    // {}` is a getter); `async` does not (no LineTerminator after it). An
    // accessor cannot be a generator, so `get <LF> *m() {}` is a field `get`
    // and a generator method, while `static <LF> *m() {}` is one static
    // generator (bd-9vouw.334).
    let key = &member[..member.len() - after_key.len()];
    let continues_across_line_break = match key {
        "static" => true,
        "get" | "set" => !after_key.trim_start().starts_with('*'),
        _ => false,
    };
    if !continues_across_line_break && !key.is_empty() && ends_at_line_break(after_key) {
        return true;
    }
    // Look past a computed key: in `get [x = 1]() {}` or `[k = 'm']() {}` the
    // `=` belongs to the key expression, not to a field initializer.
    let mut bracket_depth = 0usize;
    for byte in after_key.bytes() {
        match byte {
            b'[' => bracket_depth += 1,
            b']' => bracket_depth = bracket_depth.saturating_sub(1),
            b'(' | b'{' if bracket_depth == 0 => return false,
            b'=' | b';' if bracket_depth == 0 => return true,
            _ => {}
        }
    }
    true
}

/// `text` after a leading IdentifierName, including `\uXXXX` and `\u{...}`
/// escapes; `text` itself when it does not start with one.
fn skip_identifier_name(text: &str) -> &str {
    let mut rest = text;
    loop {
        if let Some(after) = rest.strip_prefix("\\u") {
            let escape_len = if after.starts_with('{') {
                after.find('}').map(|close| close + 1)
            } else {
                after
                    .get(..4)
                    .is_some_and(|hex| hex.chars().all(|c| c.is_ascii_hexdigit()))
                    .then_some(4)
            };
            match escape_len {
                Some(len) => rest = &after[len..],
                None => return rest,
            }
            continue;
        }
        // ID_Continue, not `char::is_alphanumeric`: `℘` (U+2118, ID_Start by
        // Other_ID_Start) is a letter of `#℘` (bd-9vouw.176).
        match rest.chars().next() {
            Some(c) if c.is_alphanumeric() || is_identifier_continue(c) => {
                rest = &rest[c.len_utf8()..];
            }
            _ => return rest,
        }
    }
}

/// Split class body into individual method segments.
fn split_class_members(body: &str) -> Vec<&str> {
    let mut segments = Vec::with_capacity(8);
    let mut start = 0;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;
    // bd-9vouw.176: braces in a computed key (`[() => {}]() {}`) and in an
    // identifier escape (`get #\u{6F}() {}`) do not end an element.
    let mut bracket_depth = 0usize;
    let mut in_identifier_escape = false;
    let mut quotes = QuoteState::default();

    for (i, ch) in body.char_indices() {
        if quotes.active() {
            quotes.advance_char(ch);
            continue;
        }
        if in_identifier_escape {
            in_identifier_escape = ch != '}';
            continue;
        }
        if ch == '\\' && body[i + 1..].starts_with("u{") {
            in_identifier_escape = true;
            continue;
        }
        if ch == '/' && quotes.open_regex_at(body, i) {
            continue;
        }
        match ch {
            '\'' | '"' | '`' => {
                quotes.open_char(ch);
            }
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => {
                if brace_depth > 0 {
                    brace_depth = brace_depth.saturating_sub(1);
                }
                if brace_depth == 0 && paren_depth == 0 && bracket_depth == 0 {
                    let end = i + 1;
                    segments.push(&body[start..end]);
                    start = end;
                }
            }
            ';' if brace_depth == 0 && paren_depth == 0 => {
                // A `;` ends a field declaration or separates methods; keep
                // the text so `parse_class_body` sees (and refuses) fields.
                segments.push(&body[start..=i]);
                start = i + 1;
            }
            _ => {}
        }
    }
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
    let is_async = statement.starts_with("async ");
    let rest = if is_async {
        statement
            .strip_prefix("async ")
            .unwrap_or(statement)
            .trim_start()
    } else {
        statement
    };
    let rest = rest.strip_prefix("function").unwrap_or(rest).trim_start();
    let is_generator = rest.starts_with('*');
    let rest = if is_generator { &rest[1..] } else { rest }.trim_start();

    // Parse function name (optional for expressions, required for declarations).
    let (name, rest) = if rest.starts_with('(') {
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
            if name.is_empty() {
                None
            } else {
                Some(name.to_string())
            },
            &rest[paren_idx..],
        )
    };

    if name.is_none() {
        return Err(ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function declarations require a binding name",
            context.source_label.to_string(),
            Some(span),
        ));
    }

    // Parse parameters.
    let (params_src, rest) = extract_balanced(rest, '(', ')').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function declaration has unbalanced parentheses",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;

    // Parse body.
    let rest = rest.trim_start();
    let (body_src, after_body) = extract_balanced(rest, '{', '}').ok_or_else(|| {
        ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "function declaration requires a braced body",
            context.source_label.to_string(),
            Some(span.clone()),
        )
    })?;
    let source_text = context
        .function_sources
        .text_of(&statement[..statement.len() - after_body.len()]);
    // A declaration binds its name in the enclosing code, whose [Yield] and
    // [Await] apply (ES2020 14.1: `BindingIdentifier[?Yield, ?Await]`).
    let name = name
        .map(|raw| {
            function_binding_name(
                &raw,
                context.strict_mode || has_use_strict_directive(body_src),
                context.yield_context,
                context.await_context || context.static_block_await,
                &span,
                context,
            )
        })
        .transpose()?;
    let goal = ParseGoal::Script; // Function bodies use script goal.
    let saved_super_call = std::mem::replace(&mut context.super_call, SuperCallContext::Forbidden);
    let parsed = with_function_context(is_async, is_generator, context, |context| {
        with_function_strict_mode(body_src, false, context, |context| {
            let params = parse_arrow_params(params_src, &span, context)?;
            reject_use_strict_with_non_simple_params(body_src, &params, &span, context)?;
            reject_duplicate_params(&params, false, &span, context)?;
            let mut body = parse_body_statements(body_src, goal, &span, context)?;
            if !context.strict_mode {
                apply_annex_b_block_functions(&mut body, &params);
            }
            Ok((params, body, context.strict_mode))
        })
    });
    context.super_call = saved_super_call;
    let (params, body_stmts, strict) = parsed?;

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
        source_text,
        strict,
    }))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn template_quasi_cooks_surrogate_pair_escapes_into_code_point() {
        // `\uD83D\uDE00` is the pre-ES6 spelling of U+1F600; adjacent high
        // and low surrogate escapes cook to one code point (bd-k9jb0), in
        // any escape spelling, with surrounding text preserved.
        let emoji = Some(JsString::from("\u{1F600}"));
        for raw in [
            r"\uD83D\uDE00",
            r"\uD83D\u{DE00}",
            r"\u{D83D}\uDE00",
            r"\u{D83D}\u{DE00}",
            r"\u{1F600}",
        ] {
            assert_eq!(cook_template_quasi(raw), emoji, "{raw}");
        }
        assert_eq!(
            cook_template_quasi(r"a\uD83D\uDE00b"),
            Some(JsString::from("a\u{1F600}b"))
        );
    }

    #[test]
    fn template_quasi_keeps_lone_surrogate_escapes_as_code_units() {
        // A lone surrogate escape is one code unit of the string value, as
        // in Node (`\`\uD83D\``.length === 1). The UTF-8 cooker this
        // replaces could not represent one and failed.
        assert_eq!(
            cook_template_quasi(r"\uD83D"),
            Some(JsString::from_code_units(&[0xD83D]))
        );
        assert_eq!(
            cook_template_quasi(r"\uDE00\uD83Dx"),
            Some(JsString::from_code_units(&[
                0xDE00,
                0xD83D,
                u16::from(b'x')
            ]))
        );
    }

    #[test]
    fn template_quasi_cooks_escapes_continuations_and_line_ends() {
        let cooked = |raw: &str| cook_template_quasi(raw).map(|value| value.to_string());
        assert_eq!(cooked(r"a\nb\tc").as_deref(), Some("a\nb\tc"));
        // One backslash from `\\`; `\[`, `\$`, `\`` are the character.
        assert_eq!(cooked(r"a\\[b\$\`").as_deref(), Some("a\\[b$`"));
        assert_eq!(cooked(r"\x41\u0042\u{43}\0").as_deref(), Some("ABC\0"));
        // A backslash before a line terminator contributes nothing.
        assert_eq!(cooked("x\\\ny").as_deref(), Some("xy"));
        assert_eq!(cooked("x\\\r\ny").as_deref(), Some("xy"));
        assert_eq!(cooked("x\\\u{2028}y").as_deref(), Some("xy"));
        // A literal CR LF or CR is LF in the template value.
        assert_eq!(cooked("x\r\ny\rz").as_deref(), Some("x\ny\nz"));
        // NotEscapeSequence shapes do not cook.
        assert_eq!(cooked(r"\1"), None);
        assert_eq!(cooked(r"\01"), None);
        assert_eq!(cooked(r"\xZ1"), None);
        assert_eq!(cooked(r"\u{110000}"), None);
    }

    #[test]
    fn parsed_string_literal_cooks_surrogate_pair_escapes() {
        // End-to-end through the parser: the literal's cooked value is U+1F600.
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(r#"const s = "\uD83D\uDE00";"#, ParseGoal::Script)
            .expect("surrogate-pair string literal should parse");
        let rendered = format!("{tree:?}");
        assert!(
            rendered.contains('\u{1F600}'),
            "cooked literal should contain U+1F600, got: {rendered}"
        );
    }

    #[test]
    fn script_goal_rejects_import_declaration() {
        let parser = CanonicalEs2020Parser;
        let error = parser
            .parse("import x from 'mod';", ParseGoal::Script)
            .expect_err("script goal should reject import");
        assert_eq!(error.code, ParseErrorCode::InvalidGoal);
    }

    /// bd-rucba (franken-core bd-47ae4 twin): a within-budget deep chain must
    /// parse regardless of the caller's stack size, because parsing now runs on
    /// a stack provisioned from the recursion budget rather than the OS default.
    #[test]
    fn nested_if_parses_from_a_tiny_caller_stack_bd_rucba() {
        // 64 nested `if` statements recurse through parse_statement 64 deep,
        // within the default budget (256) but enough to overflow a small caller
        // stack without the provisioned parse thread.
        let depth = 64usize;
        let source = format!("{}x;", "if (true) ".repeat(depth));
        let handle = std::thread::Builder::new()
            .name("bd-rucba-tiny-caller".to_string())
            .stack_size(256 * 1024)
            .spawn(move || {
                CanonicalEs2020Parser
                    .parse(source.as_str(), ParseGoal::Script)
                    .is_ok()
            })
            .expect("tiny caller thread should spawn");
        assert!(
            handle.join().expect("caller thread must not abort"),
            "a within-budget nesting must parse regardless of caller stack"
        );
    }

    /// bd-rucba: nesting beyond a tight recursion budget must fail closed with
    /// the recoverable budget error, never a native stack abort.
    #[test]
    fn tight_statement_nesting_budget_fails_closed_not_abort_bd_rucba() {
        let depth = 16usize;
        let source = format!("{}x;", "if (true) ".repeat(depth));
        let options = ParserOptions {
            budget: ParserBudget {
                max_recursion_depth: 8,
                ..ParserBudget::default()
            },
            ..ParserOptions::default()
        };
        let error = CanonicalEs2020Parser
            .parse_with_options(source.as_str(), ParseGoal::Script, &options)
            .expect_err("nesting beyond the tight budget must be rejected");
        assert_eq!(error.code, ParseErrorCode::BudgetExceeded);
        assert!(
            error.message.contains("statement nesting budget exceeded"),
            "unexpected rejection: {}",
            error.message
        );
    }

    #[test]
    fn parser_accepts_stream_inputs() {
        let parser = CanonicalEs2020Parser;
        let input = StreamInput::new(Cursor::new("x;\n42;\n"), "stdin");
        let tree = parser
            .parse(input, ParseGoal::Script)
            .expect("stream parse should succeed");
        assert_eq!(tree.body.len(), 2);
    }

    #[test]
    fn canonical_ast_bytes_are_stable_for_identical_input() {
        let parser = CanonicalEs2020Parser;
        let source = "typeof work";
        let left = parser.parse(source, ParseGoal::Script).expect("left parse");
        let right = parser
            .parse(source, ParseGoal::Script)
            .expect("right parse");
        assert_eq!(left.canonical_bytes(), right.canonical_bytes());
        assert_eq!(left.canonical_hash(), right.canonical_hash());
    }

    #[test]
    fn equivalent_whitespace_keeps_expression_shape() {
        let parser = CanonicalEs2020Parser;
        let left = parser
            .parse("typeof   work", ParseGoal::Script)
            .expect("left parse");
        let right = parser
            .parse("typeof work", ParseGoal::Script)
            .expect("right parse");

        let left_expr = match &left.body[0] {
            Statement::Expression(expr) => &expr.expression,
            // SAFETY: Test validates parsed statement is expression type
            _ => panic!("expected expression statement"),
        };
        let right_expr = match &right.body[0] {
            Statement::Expression(expr) => &expr.expression,
            // SAFETY: Test validates parsed statement is expression type
            _ => panic!("expected expression statement"),
        };
        assert_eq!(left_expr.canonical_value(), right_expr.canonical_value());
    }

    #[test]
    fn module_import_forms_are_supported() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "import dep from \"pkg\";\nimport \"side-effect\";\nexport default dep;",
                ParseGoal::Module,
            )
            .expect("module parse should succeed");
        assert_eq!(tree.body.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Empty / whitespace-only source
    // -----------------------------------------------------------------------

    #[test]
    fn empty_source_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("", ParseGoal::Script)
            .expect_err("empty source must fail");
        assert_eq!(err.code, ParseErrorCode::EmptySource);
    }

    #[test]
    fn whitespace_only_source_is_rejected() {
        let parser = CanonicalEs2020Parser;
        for ws in ["  ", "\t\t", "\n\n", "  \n  \t  "] {
            let err = parser
                .parse(ws, ParseGoal::Script)
                .expect_err("whitespace-only source must fail");
            assert_eq!(err.code, ParseErrorCode::EmptySource);
        }
    }

    // -----------------------------------------------------------------------
    // Script goal rejects export
    // -----------------------------------------------------------------------

    #[test]
    fn script_goal_rejects_export_declaration() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("export default 42", ParseGoal::Script)
            .expect_err("script goal should reject export");
        assert_eq!(err.code, ParseErrorCode::InvalidGoal);
    }

    // -----------------------------------------------------------------------
    // Expression parsing
    // -----------------------------------------------------------------------

    #[test]
    fn numeric_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        assert_eq!(tree.body.len(), 1);
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::NumericLiteral(42));
            }
            // SAFETY: Test validates parsed statement is expression type for numeric literal
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn negative_numeric_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("-7", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::NumericLiteral(v) => assert_eq!(*v, -7),
                _ => panic!("expected numeric expression for -7"),
            },
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn signed_zero_literals_preserve_the_number_sign_bit() {
        for source in ["-0", "-0x0", "-0o0", "-0b0", "-0.0", "-0e0"] {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .unwrap();
            let Statement::Expression(statement) = &tree.body[0] else {
                panic!("expected expression for {source}");
            };
            assert_eq!(
                statement.expression,
                Expression::FloatLiteral((-0.0_f64).to_bits()),
                "lost the sign of {source}"
            );
        }
    }

    #[test]
    fn string_literal_single_quotes_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("'hello'", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::StringLiteral("hello".into()));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn string_literal_double_quotes_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("\"world\"", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::StringLiteral("world".into()));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn string_literal_surrogate_escapes_preserve_exact_utf16_bd_vltnh() {
        let cases: [(&str, &[u16], bool); 5] = [
            (r#""\uD800""#, &[0xD800], false),
            (r"'\uDC00'", &[0xDC00], false),
            (r#""\u{D800}""#, &[0xD800], false),
            (r#""a\uD800b""#, &[0x0061, 0xD800, 0x0062], false),
            (r#""\uD83D\uDE00""#, &[0xD83D, 0xDE00], true),
        ];

        for (source, expected_units, expected_well_formed) in cases {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("{source:?} should parse: {error}"));
            let Statement::Expression(expression) = &tree.body[0] else {
                panic!("{source:?} should be an expression statement");
            };
            let Expression::StringLiteral(value) = &expression.expression else {
                panic!("{source:?} should produce a string literal");
            };
            assert_eq!(value.code_units_vec(), expected_units, "{source:?}");
            assert_eq!(value.is_well_formed(), expected_well_formed, "{source:?}");
        }
    }

    #[test]
    fn string_literal_ordinary_escapes_are_cooked_bd_vltnh() {
        for (source, expected) in [
            (r#""\n\t\r\b\f\v\0""#, "\n\t\r\u{0008}\u{000C}\u{000B}\0"),
            (r#""\x41\u0042\u{43}""#, "ABC"),
            (r#""\q""#, "q"),
            (r#""\"""#, "\""),
        ] {
            let value = parse_quoted_expression_string(source, LegacyDecimalEscapeMode::Reject)
                .unwrap_or_else(|| panic!("{source:?} should cook"));
            assert_eq!(value, expected, "{source:?}");
            assert!(value.is_well_formed(), "{source:?}");
        }
    }

    #[test]
    fn string_literal_line_continuations_and_astral_escape_bd_vltnh() {
        for source in [
            "\"a\\\nb\"",
            "\"a\\\rb\"",
            "\"a\\\r\nb\"",
            "\"a\\\u{2028}b\"",
            "\"a\\\u{2029}b\"",
        ] {
            let value = parse_quoted_expression_string(source, LegacyDecimalEscapeMode::Reject)
                .unwrap_or_else(|| panic!("{source:?} should cook"));
            assert_eq!(value, "ab", "{source:?}");
        }

        for (source, expected) in [
            ("\"a\u{2028}b\"", "a\u{2028}b"),
            ("\"a\u{2029}b\"", "a\u{2029}b"),
        ] {
            assert_eq!(
                parse_quoted_expression_string(source, LegacyDecimalEscapeMode::Reject)
                    .unwrap_or_else(|| panic!("{source:?} should cook")),
                expected,
                "{source:?}"
            );
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("{source:?} should parse: {error}"));
            assert!(matches!(
                first_expr(&tree),
                Expression::StringLiteral(value) if value == expected
            ));
        }

        assert_eq!(
            parse_quoted_expression_string(r#""\u{1F600}""#, LegacyDecimalEscapeMode::Reject,)
                .expect("braced astral escape should cook")
                .code_units_vec(),
            [0xD83D, 0xDE00]
        );
        assert_eq!(
            parse_quoted_expression_string(
                "\"\\uD83D\\\n\\uDE00\"",
                LegacyDecimalEscapeMode::Reject,
            )
            .expect("continuation may separate surrogate escapes")
            .code_units_vec(),
            [0xD83D, 0xDE00]
        );

        for source in ["\"a\\\nb\"", "\"a\\\rb\"", "\"a\\\r\nb\""] {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("{source:?} should parse: {error}"));
            assert!(matches!(
                first_expr(&tree),
                Expression::StringLiteral(value) if value == "ab"
            ));
        }

        let nul_then_digit = CanonicalEs2020Parser
            .parse("\"\\0\\\n8\"", ParseGoal::Script)
            .expect("line continuation after NUL escape must reset decimal lookahead");
        assert!(matches!(
            first_expr(&nul_then_digit),
            Expression::StringLiteral(value) if value.code_units_vec() == [0x0000, 0x0038]
        ));

        for source in ["\"a\nb\"", "\"a\rb\"", "\"a\r\nb\""] {
            let error = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .expect_err("raw LF/CRLF in a quoted literal must fail closed");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }
    }

    #[test]
    fn quoted_and_template_continuations_keep_physical_positions_bd_21nbg() {
        let parser = CanonicalEs2020Parser;
        for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
            let quoted_source = format!("\"a\\{terminator}b\"");
            let quoted_tree = parser
                .parse(quoted_source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {quoted_source:?}: {error}"));
            assert!(matches!(
                first_expr(&quoted_tree),
                Expression::StringLiteral(value) if value == "ab"
            ));

            let template_source = format!("let value = `a\\{terminator}b`;{terminator}after;");
            let template_tree = parser
                .parse(template_source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {template_source:?}: {error}"));
            assert_eq!(template_tree.body.len(), 2, "{template_source:?}");
            let Statement::VariableDeclaration(declaration) = &template_tree.body[0] else {
                panic!("expected template declaration for {template_source:?}");
            };
            let Some(Expression::TemplateLiteral { quasis, .. }) =
                declaration.declarations[0].initializer.as_ref()
            else {
                panic!("expected template initializer for {template_source:?}");
            };
            assert_eq!(quasis.len(), 1, "{template_source:?}");
            assert_eq!(
                quasis[0],
                format!("a\\{terminator}b"),
                "template raw quasi must retain {terminator:?}"
            );
            assert_eq!(
                template_tree.body[1].span().start_line,
                3,
                "{template_source:?}"
            );
            assert_eq!(
                template_tree.body[1].span().start_column,
                1,
                "{template_source:?}"
            );
            assert_eq!(
                template_tree.body[1].span().start_offset,
                template_source.find("after").expect("after is present") as u64,
                "{template_source:?}"
            );
        }
    }

    #[test]
    fn malformed_quoted_expression_literals_fail_closed_bd_vltnh() {
        for source in [
            "\"unterminated",
            "\"trailing\\",
            r#""\x""#,
            r#""\xZZ""#,
            r#""\u""#,
            r#""\u12""#,
            r#""\u{}""#,
            r#""\u{110000}""#,
            r#""a"b""#,
            "\"\\u\\\n0041\"",
            "\"\\x\\\n41\"",
            "\"\\u{4\\\n1}\"",
        ] {
            let error = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .expect_err("malformed quoted source must fail closed");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }
    }

    // Node 20.19.4 matches these Annex-B values and strict failures. Bun
    // 1.3.14's CLI parser currently diverges by rejecting sloppy octal while
    // accepting strict `\8`/`\9`; this parser follows ECMA-262 and Node.
    #[test]
    fn legacy_decimal_escapes_follow_annex_b_in_sloppy_scripts_bd_xcqzp() {
        let parser = CanonicalEs2020Parser;
        for (source, expected_units) in [
            (r#""\1""#, &[0x0001][..]),
            (r#""\8""#, &[0x0038][..]),
            (r#""\9""#, &[0x0039][..]),
            (r#""\08""#, &[0x0000, 0x0038][..]),
            (r#""\18""#, &[0x0001, 0x0038][..]),
            (r#""\118""#, &[0x0009, 0x0038][..]),
            (r#""\377""#, &[0x00FF][..]),
            (r#""\400""#, &[0x0020, 0x0030][..]),
            (r#""\478""#, &[0x0027, 0x0038][..]),
        ] {
            let tree = parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("sloppy {source:?} should parse: {error}"));
            assert!(matches!(
                first_expr(&tree),
                Expression::StringLiteral(value)
                    if value.code_units_vec() == expected_units
            ));
        }

        let postfix = parser
            .parse(r#""\1".length"#, ParseGoal::Script)
            .expect("a sloppy legacy escape may be a postfix receiver");
        assert!(matches!(
            first_expr(&postfix),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::StringLiteral(value)
                    if value.code_units_vec() == [0x0001])
        ));

        for source in [
            r#"let value = "\118";"#,
            r#"({"\1": value});"#,
            r#"let {"\1": value} = source;"#,
            r#"({ "\1"() {} });"#,
            r#""use\x20strict"; "\1";"#,
            r#""not a directive" + suffix; "use strict"; "\1";"#,
            r#"{ "use strict"; "\1"; }"#,
            r#"; "use strict"; "\1";"#,
            "\"use strict\"\n+suffix; \"\\1\";",
        ] {
            parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("sloppy context should accept {source:?}: {error}"));
        }
    }

    #[test]
    fn strict_and_module_code_reject_legacy_decimal_escapes_bd_xcqzp() {
        let parser = CanonicalEs2020Parser;
        for source in [
            r#""use strict"; "\1";"#,
            r#""prologue"; "use strict"; "\8";"#,
            r#""\1"; "use strict";"#,
            r#""use strict"; ({"\1": value});"#,
            r#""use strict"; let {"\1": value} = source;"#,
            r#""use strict"; ({ "\1"() {} });"#,
            r#"function f() { "prologue"; "use strict"; return "\1"; }"#,
            r#""use strict"; function f() { return "\1"; }"#,
            r#"const f = () => { "use strict"; return "\1"; };"#,
            r#"class C { method() { return "\1"; } }"#,
            r#"function f(value = "\1") { "use strict"; }"#,
            r#"const f = (value = "\1") => { "use strict"; };"#,
            r#"class C { method(value = "\1") {} }"#,
            r#"class C { "\1"() {} }"#,
            r#"class C { ["\1"]() {} }"#,
            r#"class C extends ("\1") {}"#,
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("strict Script code must reject legacy decimal escapes");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }

        parser
            .parse(r#"class C { "ok"() {} }"#, ParseGoal::Script)
            .expect("an ordinary quoted class method name remains valid");
        parser
            .parse(r#"class C { ["ok"]() {} }"#, ParseGoal::Script)
            .expect("an ordinary computed class method name remains valid");

        for source in [
            r#""\1";"#,
            r#""\8";"#,
            r#""\9";"#,
            r#""\08";"#,
            r#"let {"\1": value} = source;"#,
        ] {
            let error = parser
                .parse(source, ParseGoal::Module)
                .expect_err("Module code is strict and must reject legacy decimal escapes");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }

        parser
            .parse(r#""use strict"; "\0";"#, ParseGoal::Script)
            .expect("plain NUL escapes remain valid in strict Script code");
        parser
            .parse(r#""\0";"#, ParseGoal::Module)
            .expect("plain NUL escapes remain valid in Module code");
    }

    #[test]
    fn quoted_expression_postfix_base_uses_exact_cooker_bd_vltnh() {
        let tree = CanonicalEs2020Parser
            .parse(r#""\uD800".length"#, ParseGoal::Script)
            .expect("exact quoted literal may be a postfix base");
        assert!(matches!(
            first_expr(&tree),
            Expression::Member { object, property, computed: false, .. }
                if matches!(object.as_ref(), Expression::StringLiteral(value)
                    if value.code_units_vec() == [0xD800])
                    && matches!(property.as_ref(), Expression::Identifier(name)
                        if name == "length")
        ));

        for source in [r#""\xZZ".length"#, r#""a"b".length"#, r#""a"."#, r#""a"["#] {
            let error = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .expect_err("malformed quoted postfix source must fail closed");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }
    }

    #[test]
    fn exact_module_string_wrapper_preserves_lone_units_bd_lfq44() {
        assert_eq!(
            parse_quoted_string(r#""\uD800""#)
                .expect("high surrogate should remain representable")
                .code_units_vec(),
            [0xD800]
        );
        assert_eq!(
            parse_quoted_string(r"'\uDC00'")
                .expect("low surrogate should remain representable")
                .code_units_vec(),
            [0xDC00]
        );
        assert_eq!(
            parse_quoted_string(r#""\uD83D\uDE00""#)
                .and_then(|value| value.as_str().map(str::to_string)),
            Some("😀".to_string()),
        );
    }

    #[test]
    fn identifier_expression_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("foo", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::Identifier("foo".to_string()));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn underscore_prefix_is_valid_identifier() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("_private", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::Identifier("_private".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn dollar_prefix_is_valid_identifier() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("$elem", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::Identifier("$elem".to_string()));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn await_expression_parsed_in_module_goal() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("await fetch", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::Await(inner) => {
                    assert_eq!(**inner, Expression::Identifier("fetch".to_string()));
                }
                _ => panic!("expected await expression"),
            },
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn await_expression_parsed_inside_async_function() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "async function f() { return await fetch; }",
                ParseGoal::Script,
            )
            .expect("parse");
        match &tree.body[0] {
            Statement::FunctionDeclaration(f) => {
                assert!(f.is_async);
                let body = &f.body.body;
                assert_eq!(body.len(), 1);
                let Statement::Return(ret) = &body[0] else {
                    panic!("expected return statement");
                };
                let Some(argument) = ret.argument.as_ref() else {
                    panic!("expected return argument");
                };
                let Expression::Await(inner) = argument else {
                    panic!("expected await expression");
                };
                assert_eq!(**inner, Expression::Identifier("fetch".to_string()));
            }
            _ => panic!("expected function declaration"),
        }
    }

    #[test]
    fn top_level_await_rejected_in_script_goal() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("await fetch", ParseGoal::Script)
            .expect_err("script goal must reject top-level await");
        assert_eq!(err.code, ParseErrorCode::AwaitOutsideAsync);
    }

    #[test]
    fn await_rejected_inside_non_async_function() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("function f() { return await fetch; }", ParseGoal::Script)
            .expect_err("non-async function must reject await");
        assert_eq!(err.code, ParseErrorCode::AwaitOutsideAsync);
    }

    #[test]
    fn boolean_literal_true_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("true", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::BooleanLiteral(true));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn boolean_literal_false_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("false", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::BooleanLiteral(false));
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn null_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("null", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::NullLiteral);
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn undefined_literal_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("undefined", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(expr.expression, Expression::UndefinedLiteral);
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn complex_expression_parses_as_binary() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("a + b * c", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert!(
                    matches!(&expr.expression, Expression::Binary { .. }),
                    "expected binary expression, got {:?}",
                    expr.expression
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn function_declaration_surface_in_script_goal() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("function foo() {}", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::FunctionDeclaration(func) => {
                assert_eq!(func.name.as_deref(), Some("foo"));
            }
            _ => panic!("expected function declaration"),
        }
    }

    #[test]
    fn function_declaration_surface_in_module_goal() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("function foo() {}", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::FunctionDeclaration(func) => {
                assert_eq!(func.name.as_deref(), Some("foo"));
            }
            _ => panic!("expected function declaration"),
        }
    }

    // -----------------------------------------------------------------------
    // Variable declaration parsing
    // -----------------------------------------------------------------------

    #[test]
    fn var_declaration_with_initializer_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var counter = 1", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.kind, VariableDeclarationKind::Var);
                assert_eq!(variable_declaration.declarations.len(), 1);
                let declarator = &variable_declaration.declarations[0];
                assert_eq!(declarator.name(), Some("counter"));
                assert_eq!(declarator.initializer, Some(Expression::NumericLiteral(1)));
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn var_declaration_without_initializer_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("var ready", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.kind, VariableDeclarationKind::Var);
                assert_eq!(variable_declaration.declarations.len(), 1);
                let declarator = &variable_declaration.declarations[0];
                assert_eq!(declarator.name(), Some("ready"));
                assert_eq!(declarator.initializer, None);
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn var_declaration_with_multiple_declarators_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var first = \"a,b\", second = 2", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.declarations.len(), 2);
                let first = &variable_declaration.declarations[0];
                assert_eq!(first.name(), Some("first"));
                assert_eq!(
                    first.initializer,
                    Some(Expression::StringLiteral("a,b".into()))
                );
                let second = &variable_declaration.declarations[1];
                assert_eq!(second.name(), Some("second"));
                assert_eq!(second.initializer, Some(Expression::NumericLiteral(2)));
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn let_declaration_with_initializer_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("let counter = 1", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.kind, VariableDeclarationKind::Let);
                assert_eq!(variable_declaration.declarations.len(), 1);
                let declarator = &variable_declaration.declarations[0];
                assert_eq!(declarator.name(), Some("counter"));
                assert_eq!(declarator.initializer, Some(Expression::NumericLiteral(1)));
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn const_declaration_with_initializer_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("const answer = 42", ParseGoal::Script)
            .expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(variable_declaration) => {
                assert_eq!(variable_declaration.kind, VariableDeclarationKind::Const);
                assert_eq!(variable_declaration.declarations.len(), 1);
                let declarator = &variable_declaration.declarations[0];
                assert_eq!(declarator.name(), Some("answer"));
                assert_eq!(declarator.initializer, Some(Expression::NumericLiteral(42)));
            }
            _ => panic!("expected variable declaration statement"),
        }
    }

    #[test]
    fn const_declaration_without_initializer_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("const answer", ParseGoal::Script)
            .expect_err("const without initializer must fail");
        assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
        assert!(
            err.message
                .contains("const declarations must include an initializer")
        );
    }

    #[test]
    fn var_declaration_missing_binding_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var", ParseGoal::Script)
            .expect_err("var without binding must fail");
        assert_eq!(err.code, ParseErrorCode::InvalidSyntax);
    }

    // bd-wa01t: parser must fail-closed on these three classes of syntactically
    // invalid source instead of accepting them as `Expression::Raw` /
    // `BindingPattern::Identifier`. Each input was surfaced by the
    // parser_error_taxonomy_conformance harness.

    #[test]
    fn unterminated_string_literal_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var x = \"unterminated", ParseGoal::Script)
            .expect_err("unterminated string literal must fail-closed");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn stray_binary_operator_is_rejected() {
        let parser = CanonicalEs2020Parser;
        for source in ["* 5", "% 2", "& 1", "| 1", "^ 1", "< 1", "> 1", "?? null"] {
            let err = parser
                .parse(source, ParseGoal::Script)
                .expect_err(&format!("`{source}` must fail-closed"));
            assert_eq!(
                err.code,
                ParseErrorCode::InvalidSyntax,
                "wrong code for `{source}`",
            );
        }
    }

    #[test]
    fn reserved_word_as_binding_identifier_is_rejected() {
        let parser = CanonicalEs2020Parser;
        for keyword in [
            "return", "function", "class", "var", "if", "while", "for", "switch", "try",
        ] {
            let source = format!("var {keyword} = 1;");
            let err = parser
                .parse(source.as_str(), ParseGoal::Script)
                .expect_err(&format!("`{source}` must fail-closed"));
            assert_eq!(
                err.code,
                ParseErrorCode::InvalidSyntax,
                "wrong code for keyword `{keyword}`",
            );
        }
    }

    #[test]
    fn strict_only_reserved_words_remain_valid_in_script_mode() {
        // bd-wa01t scope guard: the fix above MUST NOT over-reject. Strict-mode
        // reserved words (`package`, `private`, `public`, `static`, …) are
        // still legal binding names in non-strict script code per ES2020.
        let parser = CanonicalEs2020Parser;
        for ident in [
            "package",
            "private",
            "public",
            "protected",
            "static",
            "implements",
            "interface",
            "let",
        ] {
            let source = format!("var {ident} = 1;");
            parser
                .parse(source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|err| {
                    panic!("`{source}` should still parse in script mode, got {err:?}")
                });
        }
    }

    #[test]
    fn var_declaration_object_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var {x} = source", ParseGoal::Script)
            .expect("destructuring binding should succeed");
        assert_eq!(tree.body.len(), 1);
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            assert_eq!(decl.declarations.len(), 1);
            let pat = &decl.declarations[0].pattern;
            assert!(
                matches!(pat, BindingPattern::ObjectPattern(props) if props.len() == 1),
                "expected object pattern, got {pat:?}"
            );
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn var_declaration_array_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var [a, b] = source", ParseGoal::Script)
            .expect("array destructuring binding should succeed");
        assert_eq!(tree.body.len(), 1);
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            let pat = &decl.declarations[0].pattern;
            assert!(
                matches!(pat, BindingPattern::ArrayPattern(elems) if elems.len() == 2),
                "expected array pattern with 2 elements, got {pat:?}"
            );
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn object_destructuring_with_rest_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var {a, ...rest} = source", ParseGoal::Script)
            .expect("object rest should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            if let BindingPattern::ObjectPattern(props) = &decl.declarations[0].pattern {
                assert_eq!(props.len(), 2);
                assert!(
                    matches!(&props[1].value, BindingPattern::Rest(_)),
                    "last property should be rest"
                );
            } else {
                panic!("expected object pattern");
            }
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn array_destructuring_with_rest_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var [a, ...rest] = source", ParseGoal::Script)
            .expect("array rest should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            if let BindingPattern::ArrayPattern(elems) = &decl.declarations[0].pattern {
                assert_eq!(elems.len(), 2);
                assert!(
                    matches!(&elems[1], Some(BindingPattern::Rest(_))),
                    "last element should be rest"
                );
            } else {
                panic!("expected array pattern");
            }
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn object_destructuring_multiple_rest_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var {...a, ...b} = source", ParseGoal::Script)
            .expect_err("multiple rest in object pattern must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("rest element must be the absolute last property"),
            "error should mention absolute last property: {msg}"
        );
    }

    #[test]
    fn object_destructuring_rest_not_last_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var {...rest, b} = source", ParseGoal::Script)
            .expect_err("rest not last in object pattern must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("rest element must be"),
            "error should mention rest position: {msg}"
        );
    }

    #[test]
    fn array_destructuring_multiple_rest_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var [...a, ...b] = source", ParseGoal::Script)
            .expect_err("multiple rest in array pattern must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("more than one rest"),
            "error should mention multiple rest: {msg}"
        );
    }

    #[test]
    fn array_destructuring_rest_not_last_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("var [...rest, b] = source", ParseGoal::Script)
            .expect_err("rest not last in array pattern must fail");
        let msg = format!("{err}");
        assert!(
            msg.contains("rest element must be the last"),
            "error should mention rest position: {msg}"
        );
    }

    #[test]
    fn nested_destructuring_object_in_array_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var [{a, b}, c] = source", ParseGoal::Script)
            .expect("nested destructuring should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            if let BindingPattern::ArrayPattern(elems) = &decl.declarations[0].pattern {
                assert_eq!(elems.len(), 2);
                assert!(
                    matches!(&elems[0], Some(BindingPattern::ObjectPattern(_))),
                    "first element should be object pattern"
                );
            } else {
                panic!("expected array pattern");
            }
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn nested_destructuring_array_in_object_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var {a: [x, y]} = source", ParseGoal::Script)
            .expect("nested array in object should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            assert!(
                matches!(
                    &decl.declarations[0].pattern,
                    BindingPattern::ObjectPattern(_)
                ),
                "expected object pattern"
            );
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn destructuring_with_default_value_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var {a = 1, b = 2} = source", ParseGoal::Script)
            .expect("destructuring with defaults should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            if let BindingPattern::ObjectPattern(props) = &decl.declarations[0].pattern {
                assert_eq!(props.len(), 2);
                assert!(
                    matches!(&props[0].value, BindingPattern::AssignmentPattern { .. }),
                    "first prop should have default: {:?}",
                    props[0].value
                );
            } else {
                panic!("expected object pattern");
            }
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn whole_object_pattern_default_param_parses_as_assignment_pattern() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("function f({a = 5} = {}) { return a; }", ParseGoal::Script)
            .expect("function param with whole-object-pattern default should parse");
        if let Statement::FunctionDeclaration(func) = &tree.body[0] {
            assert!(
                matches!(
                    &func.params[0].pattern,
                    BindingPattern::AssignmentPattern { left, .. }
                        if matches!(left.as_ref(), BindingPattern::ObjectPattern(_))
                ),
                "expected assignment pattern with object-pattern left side, got {:?}",
                func.params[0].pattern
            );
        } else {
            panic!("expected function declaration");
        }
    }

    #[test]
    fn array_destructuring_with_holes_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var [a, , b] = source", ParseGoal::Script)
            .expect("array with holes should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            if let BindingPattern::ArrayPattern(elems) = &decl.declarations[0].pattern {
                assert_eq!(elems.len(), 3);
                assert!(elems[0].is_some(), "first element should be Some");
                assert!(elems[1].is_none(), "second element (hole) should be None");
                assert!(elems[2].is_some(), "third element should be Some");
            } else {
                panic!("expected array pattern");
            }
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn let_declaration_with_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("let {x, y} = source", ParseGoal::Script)
            .expect("let destructuring should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            assert_eq!(decl.kind, VariableDeclarationKind::Let);
            assert!(matches!(
                &decl.declarations[0].pattern,
                BindingPattern::ObjectPattern(_)
            ));
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn const_declaration_with_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("const [a, b] = source", ParseGoal::Script)
            .expect("const destructuring should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            assert_eq!(decl.kind, VariableDeclarationKind::Const);
            assert!(matches!(
                &decl.declarations[0].pattern,
                BindingPattern::ArrayPattern(_)
            ));
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn for_in_with_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("for (var {a, b} in source) {}", ParseGoal::Script)
            .expect("for-in destructuring should succeed");
        if let Statement::ForIn(stmt) = &tree.body[0] {
            assert!(
                matches!(&stmt.binding, BindingPattern::ObjectPattern(props) if props.len() == 2),
                "expected object pattern binding"
            );
        } else {
            panic!("expected for-in statement");
        }
    }

    #[test]
    fn for_of_with_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("for (var [a, b] of source) {}", ParseGoal::Script)
            .expect("for-of destructuring should succeed");
        if let Statement::ForOf(stmt) = &tree.body[0] {
            assert!(
                matches!(&stmt.binding, BindingPattern::ArrayPattern(elems) if elems.len() == 2),
                "expected array pattern binding"
            );
        } else {
            panic!("expected for-of statement");
        }
    }

    #[test]
    fn object_destructuring_renamed_key_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var {a: x, b: y} = source", ParseGoal::Script)
            .expect("renamed keys should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            if let BindingPattern::ObjectPattern(props) = &decl.declarations[0].pattern {
                assert_eq!(props.len(), 2);
                assert_eq!(props[0].key, Expression::Identifier("a".to_string()));
                assert!(
                    matches!(&props[0].value, BindingPattern::Identifier(name) if name == "x"),
                    "first value should be identifier x"
                );
            } else {
                panic!("expected object pattern");
            }
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn empty_object_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var {} = source", ParseGoal::Script)
            .expect("empty object destructuring should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            assert!(
                matches!(&decl.declarations[0].pattern, BindingPattern::ObjectPattern(props) if props.is_empty()),
                "expected empty object pattern"
            );
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn empty_array_destructuring_accepted() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("var [] = source", ParseGoal::Script)
            .expect("empty array destructuring should succeed");
        if let Statement::VariableDeclaration(decl) = &tree.body[0] {
            assert!(
                matches!(&decl.declarations[0].pattern, BindingPattern::ArrayPattern(elems) if elems.is_empty()),
                "expected empty array pattern"
            );
        } else {
            panic!("expected variable declaration");
        }
    }

    #[test]
    fn identifier_starting_with_var_is_expression_not_declaration() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("variant", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::Identifier("variant".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn identifier_starting_with_let_is_expression_not_declaration() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("letter", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::Identifier("letter".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn identifier_starting_with_const_is_expression_not_declaration() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("constant", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::Identifier("constant".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
    }

    #[test]
    fn top_level_await_in_module_context_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("const data = await fetchData();", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let declarator = &decl.declarations[0];
                if let Some(init) = &declarator.initializer {
                    match init {
                        Expression::Await(inner) => match inner.as_ref() {
                            Expression::Call {
                                callee, arguments, ..
                            } => {
                                assert_eq!(
                                    **callee,
                                    Expression::Identifier("fetchData".to_string())
                                );
                                assert!(arguments.is_empty());
                            }
                            _ => panic!("expected call expression in await"),
                        },
                        _ => panic!("expected await expression in initializer"),
                    }
                } else {
                    panic!("expected initializer in variable declaration");
                }
            }
            _ => panic!("expected variable declaration"),
        }
    }

    #[test]
    fn top_level_await_statement_in_module_context_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("await doSomething();", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => match &expr.expression {
                Expression::Await(inner) => match inner.as_ref() {
                    Expression::Call {
                        callee, arguments, ..
                    } => {
                        assert_eq!(**callee, Expression::Identifier("doSomething".to_string()));
                        assert!(arguments.is_empty());
                    }
                    _ => panic!("expected call expression in await"),
                },
                _ => panic!("expected await expression"),
            },
            _ => panic!("expected expression statement"),
        }
    }

    // -----------------------------------------------------------------------
    // Multi-statement / semicolons
    // -----------------------------------------------------------------------

    #[test]
    fn semicolons_split_statements() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("x;42;'hello'", ParseGoal::Script)
            .expect("parse");
        assert_eq!(tree.body.len(), 3);
    }

    #[test]
    fn semicolon_inside_string_does_not_split_statement() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("'a;b';x", ParseGoal::Script).expect("parse");
        assert_eq!(tree.body.len(), 2);
    }

    #[test]
    fn multiline_source_parsed_correctly() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("x\n42\n'hello'", ParseGoal::Script)
            .expect("parse");
        assert_eq!(tree.body.len(), 3);
    }

    #[test]
    fn trailing_semicolons_do_not_create_extra_statements() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("x;", ParseGoal::Script).expect("parse");
        assert_eq!(tree.body.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Import forms
    // -----------------------------------------------------------------------

    #[test]
    fn import_with_binding_parsed_in_module() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import dep from 'pkg'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                assert!(matches!(
                    &import.clause,
                    ImportClause::Default { local } if local == "dep"
                ));
                assert_eq!(import.source, "pkg");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_side_effect_only_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import 'polyfill'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                assert!(matches!(&import.clause, ImportClause::SideEffect));
                assert_eq!(import.source, "polyfill");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_named_clause_parsed_without_binding() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import { run, stop as halt } from 'pkg'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                match &import.clause {
                    ImportClause::Named { specifiers } => {
                        assert_eq!(specifiers.len(), 2);
                        assert_eq!(specifiers[0].import_name, "run");
                        assert_eq!(specifiers[0].local_name, "run");
                        assert_eq!(specifiers[1].import_name, "stop");
                        assert_eq!(specifiers[1].local_name, "halt");
                    }
                    other => panic!("expected named import clause, got {other:?}"),
                }
                assert_eq!(import.source, "pkg");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_empty_named_clause_parsed_without_binding() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import {} from 'pkg'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                match &import.clause {
                    ImportClause::Named { specifiers } => {
                        assert!(specifiers.is_empty());
                    }
                    other => panic!("expected named import clause, got {other:?}"),
                }
                assert_eq!(import.source, "pkg");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_namespace_clause_parsed_with_binding() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import * as ns from 'pkg'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                assert!(matches!(
                    &import.clause,
                    ImportClause::Namespace { local } if local == "ns"
                ));
                assert_eq!(import.source, "pkg");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_default_plus_named_clause_keeps_default_binding() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import dep, { run } from 'pkg'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                match &import.clause {
                    ImportClause::DefaultAndNamed {
                        default,
                        specifiers,
                    } => {
                        assert_eq!(default, "dep");
                        assert_eq!(specifiers.len(), 1);
                        assert_eq!(specifiers[0].import_name, "run");
                        assert_eq!(specifiers[0].local_name, "run");
                    }
                    other => panic!("expected default+named import clause, got {other:?}"),
                }
                assert_eq!(import.source, "pkg");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_default_plus_namespace_clause_keeps_default_binding() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("import dep, * as ns from 'pkg'", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Import(import) => {
                match &import.clause {
                    ImportClause::DefaultAndNamespace { default, namespace } => {
                        assert_eq!(default, "dep");
                        assert_eq!(namespace, "ns");
                    }
                    other => panic!("expected default+namespace import clause, got {other:?}"),
                }
                assert_eq!(import.source, "pkg");
            }
            _ => panic!("expected import statement"),
        }
    }

    #[test]
    fn import_empty_clause_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("import ", ParseGoal::Module)
            .expect_err("empty import clause must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn import_namespace_clause_without_alias_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("import * from 'pkg'", ParseGoal::Module)
            .expect_err("namespace import without alias must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn import_named_clause_with_invalid_alias_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("import { run as } from 'pkg'", ParseGoal::Module)
            .expect_err("invalid named import alias must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn import_default_binding_keyword_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("import for from 'pkg'", ParseGoal::Module)
            .expect_err("keyword default import binding must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn import_namespace_binding_keyword_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("import * as for from 'pkg'", ParseGoal::Module)
            .expect_err("keyword namespace import binding must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn import_named_clause_keyword_binding_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("import { run as for } from 'pkg'", ParseGoal::Module)
            .expect_err("keyword named import binding must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // -----------------------------------------------------------------------
    // Export forms
    // -----------------------------------------------------------------------

    #[test]
    fn export_default_identifier_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export default main", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Export(export) => match &export.kind {
                ExportKind::Default(expr) => {
                    assert_eq!(*expr, Expression::Identifier("main".to_string()));
                }
                _ => panic!("expected default export"),
            },
            _ => panic!("expected export statement"),
        }
    }

    #[test]
    fn minified_import_declarations_parse_bd_goh5q() {
        let parse_import = |source: &str| {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .unwrap_or_else(|error| panic!("{source}: {error:?}"));
            match tree.body.into_iter().next() {
                Some(Statement::Import(import)) => import,
                other => panic!("{source}: expected an import, got {other:?}"),
            }
        };

        let named = parse_import("import{a,b as c}from'pkg'");
        match &named.clause {
            ImportClause::Named { specifiers } => {
                let names: Vec<_> = specifiers
                    .iter()
                    .map(|s| (s.import_name.as_str(), s.local_name.as_str()))
                    .collect();
                assert_eq!(names, [("a", "a"), ("b", "c")]);
            }
            other => panic!("expected named import clause, got {other:?}"),
        }
        assert_eq!(named.source, "pkg");

        assert!(matches!(
            &parse_import("import d,{a}from\"pkg\"").clause,
            ImportClause::DefaultAndNamed { default, specifiers }
                if default == "d" && specifiers.len() == 1
        ));
        assert!(matches!(
            &parse_import("import*as ns from'pkg'").clause,
            ImportClause::Namespace { local } if local == "ns"
        ));
        assert!(matches!(
            &parse_import("import d,*as ns from'pkg'").clause,
            ImportClause::DefaultAndNamespace { default, namespace }
                if default == "d" && namespace == "ns"
        ));
        assert!(matches!(
            parse_import("import'pkg'").clause,
            ImportClause::SideEffect
        ));
        // `from` as a binding name, and a source containing "from".
        assert!(matches!(
            &parse_import("import from from'./from.js'").clause,
            ImportClause::Default { local } if local == "from"
        ));
        let from_named = parse_import("import{from}from'./from.js'");
        assert_eq!(from_named.source, "./from.js");
        assert!(matches!(
            &from_named.clause,
            ImportClause::Named { specifiers } if specifiers[0].local_name == "from"
        ));
    }

    #[test]
    fn minified_export_declarations_parse_bd_goh5q() {
        let parse_export = |source: &str| {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .unwrap_or_else(|error| panic!("{source}: {error:?}"));
            match tree.body.into_iter().next() {
                Some(Statement::Export(export)) => export.kind,
                other => panic!("{source}: expected an export, got {other:?}"),
            }
        };
        match parse_export("export{}") {
            ExportKind::NamedClause(clause) => {
                assert_eq!(clause.canonical_head(), "{}");
                assert!(clause.source().is_none());
            }
            other => panic!("expected named clause export, got {other:?}"),
        }
        match parse_export("export{a as b,c}from'pkg'") {
            ExportKind::NamedClause(clause) => {
                assert_eq!(clause.canonical_head(), "{a as b,c}");
                assert_eq!(clause.source().and_then(JsString::as_str), Some("pkg"));
            }
            other => panic!("expected named clause export, got {other:?}"),
        }
        assert!(matches!(
            parse_export("export default{x:1}"),
            ExportKind::Default(_)
        ));
        assert!(matches!(
            parse_export("export default(1)"),
            ExportKind::Default(_)
        ));
    }

    #[test]
    fn star_export_declarations_parse_bd_332pq() {
        for (source, head) in [
            ("export * from 'pkg'", "*"),
            ("export*from'pkg'", "*"),
            ("export * as ns from \"pkg\"", "* as ns"),
            ("export*as ns from'pkg'", "* as ns"),
            ("export * as from from 'pkg'", "* as from"),
        ] {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .unwrap_or_else(|error| panic!("{source}: {error:?}"));
            let Some(Statement::Export(export)) = tree.body.first() else {
                panic!("{source}: expected an export");
            };
            let ExportKind::NamedClause(clause) = &export.kind else {
                panic!("{source}: expected a clause export");
            };
            assert_eq!(clause.canonical_head(), head, "{source}");
            assert_eq!(
                clause.source().and_then(JsString::as_str),
                Some("pkg"),
                "{source}"
            );
        }
        for source in [
            "export * 'pkg'",
            "export * as from 'pkg'",
            "export * as ns",
            "export * from pkg",
        ] {
            let error = CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .expect_err(source);
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source}");
        }
    }

    #[test]
    fn import_and_export_prefixes_that_are_not_declarations_bd_goh5q() {
        for source in [
            "import('pkg')",
            "import ('pkg')",
            "import.meta",
            "importance = 1",
            "exports.value = 1",
            "exporter = 1",
        ] {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .unwrap_or_else(|error| panic!("{source}: {error:?}"));
            assert!(
                !matches!(
                    tree.body.first(),
                    Some(Statement::Import(_) | Statement::Export(_))
                ),
                "{source}"
            );
        }
        // A script cannot hold a minified declaration either.
        let error = CanonicalEs2020Parser
            .parse("import{a}from'pkg'", ParseGoal::Script)
            .expect_err("import declaration in a script");
        assert_eq!(error.code, ParseErrorCode::InvalidGoal);
    }

    #[test]
    fn export_named_clause_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export { a, b }", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Export(export) => match &export.kind {
                ExportKind::NamedClause(clause) => {
                    assert_eq!(clause.canonical_head(), "{ a, b }");
                    assert!(clause.source().is_none());
                }
                _ => panic!("expected named clause export"),
            },
            _ => panic!("expected export statement"),
        }
    }

    #[test]
    fn export_named_clause_with_source_is_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "export { default as dep, run as start } from \"pkg\"",
                ParseGoal::Module,
            )
            .expect("parse");
        match &tree.body[0] {
            Statement::Export(export) => match &export.kind {
                ExportKind::NamedClause(clause) => {
                    assert_eq!(clause.canonical_head(), "{ default as dep, run as start }");
                    assert_eq!(clause.source().and_then(JsString::as_str), Some("pkg"));
                }
                _ => panic!("expected named clause export"),
            },
            _ => panic!("expected export statement"),
        }
    }

    #[test]
    fn export_named_clause_cooks_source_without_collapsing_inner_space_bd_vltnh() {
        let tree = CanonicalEs2020Parser
            .parse("export { dep } from \"pkg  name\"", ParseGoal::Module)
            .expect("named export source should parse");
        let Statement::Export(export) = &tree.body[0] else {
            panic!("expected named export clause");
        };
        assert!(matches!(
            &export.kind,
            ExportKind::NamedClause(clause)
                if clause.canonical_head() == "{ dep }"
                    && clause.source().and_then(JsString::as_str) == Some("pkg  name")
        ));
    }

    #[test]
    fn module_declarations_preserve_distinct_lone_surrogate_sources_bd_lfq44() {
        let import_tree = CanonicalEs2020Parser
            .parse(r#"import "\uD800"; import "\uDC00""#, ParseGoal::Module)
            .expect("exact import sources should parse");
        let [Statement::Import(first), Statement::Import(second)] = import_tree.body.as_slice()
        else {
            panic!("expected two side-effect imports");
        };
        assert_eq!(first.source.code_units_vec(), [0xD800]);
        assert_eq!(second.source.code_units_vec(), [0xDC00]);
        assert_ne!(first.source, second.source);

        let export_tree = CanonicalEs2020Parser
            .parse(r#"export { value } from "\uDC00""#, ParseGoal::Module)
            .expect("exact re-export source should parse");
        let Statement::Export(export) = &export_tree.body[0] else {
            panic!("expected named re-export");
        };
        let ExportKind::NamedClause(clause) = &export.kind else {
            panic!("expected named export clause");
        };
        assert_eq!(clause.canonical_head(), "{ value }");
        assert_eq!(
            clause
                .source()
                .expect("re-export must retain its source")
                .code_units_vec(),
            [0xDC00]
        );
    }

    #[test]
    fn export_const_declaration_expands_to_declaration_and_named_export() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export const x = 42", ParseGoal::Module)
            .expect("named const export should parse");

        assert_eq!(tree.body.len(), 2);
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Const
                    && declaration.declarations[0].name() == Some("x")
        ));
        assert!(matches!(
            &tree.body[1],
            Statement::Export(export)
                if matches!(&export.kind, ExportKind::NamedClause(clause)
                    if clause.canonical_head() == "{ x }" && clause.source().is_none())
        ));
    }

    #[test]
    fn export_function_declaration_expands_to_declaration_and_named_export() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export function run() {}", ParseGoal::Module)
            .expect("named function export should parse");

        assert_eq!(tree.body.len(), 2);
        assert!(matches!(
            &tree.body[0],
            Statement::FunctionDeclaration(function) if function.name.as_deref() == Some("run")
        ));
        assert!(matches!(
            &tree.body[1],
            Statement::Export(export)
                if matches!(&export.kind, ExportKind::NamedClause(clause)
                    if clause.canonical_head() == "{ run }" && clause.source().is_none())
        ));
    }

    #[test]
    fn export_function_statement_splits_before_following_same_line_statement() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "export function run() {} const after = 1",
                ParseGoal::Module,
            )
            .expect("exported function followed by declaration should parse");

        assert_eq!(tree.body.len(), 3);
        assert!(matches!(
            &tree.body[0],
            Statement::FunctionDeclaration(function) if function.name.as_deref() == Some("run")
        ));
        assert!(matches!(
            &tree.body[1],
            Statement::Export(export)
                if matches!(&export.kind, ExportKind::NamedClause(clause)
                    if clause.canonical_head() == "{ run }" && clause.source().is_none())
        ));
        assert!(matches!(
            &tree.body[2],
            Statement::VariableDeclaration(declaration)
                if declaration.declarations[0].name() == Some("after")
        ));
    }

    #[test]
    fn export_default_function_statement_splits_before_following_same_line_statement() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "export default function() {} const after = 1",
                ParseGoal::Module,
            )
            .expect("default exported function followed by declaration should parse");

        assert_eq!(tree.body.len(), 2);
        assert!(matches!(
            &tree.body[0],
            Statement::Export(export) if matches!(&export.kind, ExportKind::Default(_))
        ));
        assert!(matches!(
            &tree.body[1],
            Statement::VariableDeclaration(declaration)
                if declaration.declarations[0].name() == Some("after")
        ));
    }

    #[test]
    fn export_class_declaration_expands_to_declaration_and_named_export() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export class Runner {}", ParseGoal::Module)
            .expect("named class export should parse");

        assert_eq!(tree.body.len(), 2);
        assert!(matches!(
            &tree.body[0],
            Statement::ClassDeclaration(class) if class.name.as_deref() == Some("Runner")
        ));
        assert!(matches!(
            &tree.body[1],
            Statement::Export(export)
                if matches!(&export.kind, ExportKind::NamedClause(clause)
                    if clause.canonical_head() == "{ Runner }" && clause.source().is_none())
        ));
    }

    #[test]
    fn export_named_clause_invalid_specifier_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("export { run as }", ParseGoal::Module)
            .expect_err("invalid named export alias must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn export_named_clause_unquoted_source_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("export { run } from pkg", ParseGoal::Module)
            .expect_err("export source must be quoted");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn export_non_named_non_default_clause_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("export run", ParseGoal::Module)
            .expect_err("unsupported export clause must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // -----------------------------------------------------------------------
    // ParserInput implementations
    // -----------------------------------------------------------------------

    #[test]
    fn str_input_has_inline_label() {
        let source: &str = "42";
        let ps = source.into_source().expect("into_source");
        assert_eq!(ps.label, "<inline>");
        assert_eq!(ps.text, "42");
    }

    #[test]
    fn string_input_has_inline_label() {
        let source = String::from("hello");
        let ps = source.into_source().expect("into_source");
        assert_eq!(ps.label, "<inline>");
        assert_eq!(ps.text, "hello");
    }

    #[test]
    fn stream_input_invalid_utf8_rejected() {
        let bad_bytes: &[u8] = &[0xFF, 0xFE, 0x00];
        let input = StreamInput::new(Cursor::new(bad_bytes), "bad_stream");
        let err = input.into_source().expect_err("invalid UTF-8 must fail");
        assert_eq!(err.code, ParseErrorCode::InvalidUtf8);
    }

    // -----------------------------------------------------------------------
    // ParseError display
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_display_without_span() {
        let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "test.js", None);
        let display = format!("{}", err);
        assert!(display.contains("EmptySource"));
        assert!(display.contains("test.js"));
    }

    #[test]
    fn parse_error_display_with_span() {
        let span = SourceSpan::new(0, 5, 1, 1, 1, 6);
        let err = ParseError::new(
            ParseErrorCode::UnsupportedSyntax,
            "bad token",
            "test.js",
            Some(span),
        );
        let display = format!("{}", err);
        assert!(display.contains("line=1"));
        assert!(display.contains("column=1"));
    }

    #[test]
    fn parse_error_round_trips_through_serde() {
        let err = ParseError::new(
            ParseErrorCode::EmptySource,
            "source is empty",
            "<inline>",
            None,
        );
        let json = serde_json::to_string(&err).expect("serde serialization should succeed");
        let decoded: ParseError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decoded, err);
    }

    #[test]
    fn budget_exhaustion_returns_stable_witness() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1024,
                max_token_count: 1,
                max_recursion_depth: 32,
            },
        };

        let err = parser
            .parse_with_options("alpha beta gamma", ParseGoal::Script, &options)
            .expect_err("token budget should fail");
        assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
        let witness = err.witness.expect("budget failures should carry witness");
        assert_eq!(witness.mode, ParserMode::ScalarReference);
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::TokenCount));
        assert_eq!(witness.max_token_count, 1);
        assert!(witness.token_count > witness.max_token_count);
    }

    #[test]
    fn byte_classification_table_covers_ascii_lexical_categories() {
        assert!(lex_has_class(b' ', LEX_CLASS_WHITESPACE));
        assert!(lex_has_class(b'\n', LEX_CLASS_WHITESPACE));
        assert!(lex_has_class(b'A', LEX_CLASS_IDENTIFIER_START));
        assert!(lex_has_class(b'A', LEX_CLASS_IDENTIFIER_CONTINUE));
        assert!(lex_has_class(b'0', LEX_CLASS_DIGIT));
        assert!(lex_has_class(b'0', LEX_CLASS_IDENTIFIER_CONTINUE));
        assert!(lex_has_class(b'\"', LEX_CLASS_QUOTE));
        assert!(lex_has_class(b'=', LEX_CLASS_TWO_CHAR_OPERATOR_LEAD));
        assert!(!lex_has_class(b'+', LEX_CLASS_TWO_CHAR_OPERATOR_LEAD));
        // bd-2noh9: `<VT>` (0x0B) and `<FF>` (0x0C) are ES2020 WhiteSpace.
        assert!(lex_has_class(0x0b, LEX_CLASS_WHITESPACE));
        assert!(lex_has_class(0x0c, LEX_CLASS_WHITESPACE));
    }

    /// The scalar reference's whitespace predicate must classify the exact same
    /// byte set as the SIMD scanner's `LEX_CLASS_WHITESPACE` bit — otherwise the
    /// two token counters diverge (bd-2noh9). This locks the two independent
    /// implementations together without coupling their code paths.
    #[test]
    fn ascii_lexical_whitespace_matches_the_simd_whitespace_class_bd_2noh9() {
        for byte in 0u8..=255 {
            assert_eq!(
                is_ascii_lexical_whitespace(byte),
                lex_has_class(byte, LEX_CLASS_WHITESPACE),
                "whitespace classification disagrees for byte {byte:#04x}"
            );
        }
        // Pin the specific WhatWG-Infra vs ES2020 gap: `is_ascii_whitespace`
        // omits `<VT>`, but the lexical-whitespace predicate must include it.
        assert!(is_ascii_lexical_whitespace(0x0b));
        assert!(!0x0b_u8.is_ascii_whitespace());
    }

    /// Regression for bd-2noh9: a `<VT>` (U+000B) between/around tokens must be
    /// treated as whitespace by BOTH counters (it produces no token), and an
    /// exhaustive control-byte differential must show no residual SIMD-vs-scalar
    /// divergence on ASCII input.
    #[test]
    fn vertical_tab_token_count_parity_bd_2noh9() {
        // `<VT>` splits two identifiers but is not itself a token: `a <VT> b`
        // is two tokens, exactly like `a b`.
        assert_eq!(count_lexical_tokens("a\u{000b}b"), 2);
        assert_eq!(count_lexical_tokens_scalar_reference("a\u{000b}b"), 2);
        assert_eq!(count_lexical_tokens("a b"), 2);
        // A run of only whitespace (including `<VT>`) yields zero tokens.
        assert_eq!(count_lexical_tokens("\u{000b}\u{000c}\t \r\n"), 0);
        assert_eq!(
            count_lexical_tokens_scalar_reference("\u{000b}\u{000c}\t \r\n"),
            0
        );

        // Exhaustive differential: every ASCII control/space byte, each embedded
        // between two identifiers and standing alone, must count identically
        // under the SIMD scanner and the scalar reference.
        for byte in 0u8..=0x7f {
            let embedded = format!("a{}b", byte as char);
            assert_eq!(
                count_lexical_tokens(&embedded),
                count_lexical_tokens_scalar_reference(&embedded),
                "embedded parity drift for byte {byte:#04x}"
            );
            let alone = (byte as char).to_string();
            assert_eq!(
                count_lexical_tokens(&alone),
                count_lexical_tokens_scalar_reference(&alone),
                "standalone parity drift for byte {byte:#04x}"
            );
        }
    }

    /// Parse `source` under a small recursion budget so the depth guards fire
    /// well before the native stack is at risk of overflow.
    fn parse_with_recursion_limit(
        source: &str,
        max_recursion_depth: u64,
    ) -> ParseResult<SyntaxTree> {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1 << 20,
                max_token_count: 1 << 20,
                max_recursion_depth,
            },
        };
        parser.parse_with_options(source, ParseGoal::Script, &options)
    }

    /// bd-c4lhp: deeply nested array destructuring must surface a recoverable
    /// budget error, never overflow the native stack. Before the fix,
    /// `parse_binding_pattern` recursed with no depth guard, so this input
    /// aborted the process (SIGABRT, "thread '…' has overflowed its stack").
    #[test]
    fn deeply_nested_array_destructuring_is_depth_bounded_bd_c4lhp() {
        let depth = 2000;
        let src = format!("let {}x{} = 0;", "[".repeat(depth), "]".repeat(depth));
        let err = parse_with_recursion_limit(&src, 32)
            .expect_err("deep array destructuring must hit the pattern budget");
        assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
        assert!(
            err.message
                .contains("binding-pattern nesting budget exceeded"),
            "expected the binding-pattern guard, got: {}",
            err.message
        );
    }

    /// bd-c4lhp: the same guard bounds deeply nested object destructuring.
    #[test]
    fn deeply_nested_object_destructuring_is_depth_bounded_bd_c4lhp() {
        let depth = 2000;
        let src = format!("let {}x{} = 0;", "{a:".repeat(depth), "}".repeat(depth));
        let err = parse_with_recursion_limit(&src, 32)
            .expect_err("deep object destructuring must hit the pattern budget");
        assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
        assert!(
            err.message
                .contains("binding-pattern nesting budget exceeded"),
            "expected the binding-pattern guard, got: {}",
            err.message
        );
    }

    /// The pattern-depth guard bounds nesting without rejecting valid patterns:
    /// a moderately nested destructuring pattern below the limit still parses.
    #[test]
    fn moderately_nested_destructuring_still_parses_bd_c4lhp() {
        parse_with_recursion_limit("let [a, [b, [c, [d]]]] = x;", 32)
            .expect("shallow destructuring must parse cleanly");
        parse_with_recursion_limit("let { a: { b: { c: d } } } = x;", 32)
            .expect("shallow object destructuring must parse cleanly");
    }

    /// bd-c4lhp: the sibling expression depth guard likewise bounds deeply
    /// nested parentheses — deep nesting is uniformly a recoverable budget
    /// error, never a process abort.
    #[test]
    fn deeply_nested_parentheses_are_depth_bounded_bd_c4lhp() {
        let depth = 2000;
        let src = format!("{}1{};", "(".repeat(depth), ")".repeat(depth));
        let err = parse_with_recursion_limit(&src, 32)
            .expect_err("deep parentheses must hit the recursion budget");
        assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
    }

    #[test]
    fn utf8_boundary_safe_scanner_matches_scalar_reference_for_ascii_inputs() {
        let cases = [
            "alpha beta gamma",
            "a==b && c!=d || e??f => g",
            "'hello' \"world\"",
            "\"unterminated\nstring\"",
            "await foo;\nbar + baz * 5",
            "_$token123 <= 42",
            "`hello ${name}`",
            "`value ${foo({ bar: 1 })}`",
            "`unterminated ${value`",
            // bd-2noh9: `<VT>` (U+000B) is ES2020 §11.2 WhiteSpace but is omitted
            // by `is_ascii_whitespace`; exercise it between and around tokens.
            "a\u{000b}b",
            "return\u{000b}x",
            "\u{000b}\u{000b}\u{000b}",
            "a\u{000b}\u{000c}\u{0009}b",
            "x\u{000b}==\u{000b}y",
        ];

        for source in cases {
            assert_eq!(
                count_lexical_tokens(source),
                count_lexical_tokens_scalar_reference(source),
                "ASCII parity drift for source: {source:?}"
            );
        }
    }

    #[test]
    fn utf8_boundary_safe_scanner_counts_multibyte_codepoints_once() {
        let two_byte = "é";
        assert_eq!(count_lexical_tokens(two_byte), 1);
        assert_eq!(count_lexical_tokens_scalar_reference(two_byte), 2);

        let four_byte = "😀";
        assert_eq!(count_lexical_tokens(four_byte), 1);
        assert_eq!(count_lexical_tokens_scalar_reference(four_byte), 4);
    }

    #[test]
    fn budget_witness_uses_utf8_boundary_safe_token_count() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1024,
                max_token_count: 1,
                max_recursion_depth: 32,
            },
        };

        let err = parser
            .parse_with_options("é β", ParseGoal::Script, &options)
            .expect_err("utf-8-aware token counting should trigger the token budget");
        let witness = err
            .witness
            .expect("budget failures should preserve witness context");
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::TokenCount));
        assert_eq!(witness.token_count, 2);
        assert_eq!(witness.max_token_count, 1);
    }

    #[test]
    fn recursion_budget_exhaustion_is_deterministic() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 1024,
                max_token_count: 1024,
                max_recursion_depth: 1,
            },
        };
        // `await` is permitted at module top-level; two nested awaits exceed a
        // max_recursion_depth of 1.
        let source = "await await work";
        let left = parser
            .parse_with_options(source, ParseGoal::Module, &options)
            .expect_err("left parse should fail");
        let right = parser
            .parse_with_options(source, ParseGoal::Module, &options)
            .expect_err("right parse should fail");
        assert_eq!(left.code, ParseErrorCode::BudgetExceeded);
        assert_eq!(left, right);
    }

    #[test]
    fn string_literal_receiver_member_call_parses_bd_bulsc() {
        // bd-bulsc: a string literal used as a member-access / call / index
        // receiver must PARSE (as postfix on the StringLiteral), not fail closed
        // with "unterminated or malformed string literal".
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions::default();
        for source in [
            r#""abc".length;"#,
            r#""abc".split(",").length;"#,
            r#""hello".replace("l", "L");"#,
            r#""5".padStart(3, "0");"#,
        ] {
            let result = parser.parse_with_options(source, ParseGoal::Script, &options);
            assert!(
                result.is_ok(),
                "string-literal receiver must parse (bd-bulsc): {source:?} -> {:?}",
                result.err()
            );
        }
    }

    #[test]
    fn genuinely_unterminated_string_still_fails_closed_bd_wa01t() {
        // The bd-bulsc relaxation must NOT weaken the bd-wa01t fail-closed guard:
        // a quote that opens no balanced literal (no close / embedded newline)
        // must still be rejected, not silently passed through as Raw.
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions::default();
        for source in [r#""unterminated ;"#, "let s = \"abc;"] {
            let result = parser.parse_with_options(source, ParseGoal::Script, &options);
            assert!(
                result.is_err(),
                "genuinely unterminated string must still fail closed (bd-wa01t): {source:?}"
            );
        }
    }

    #[test]
    fn scalar_reference_grammar_matrix_has_non_zero_coverage() {
        let parser = CanonicalEs2020Parser;
        let matrix = parser.scalar_reference_grammar_matrix();
        let summary = matrix.summary();
        assert_eq!(
            matrix.schema_version,
            GrammarCompletenessMatrix::SCHEMA_VERSION
        );
        assert!(summary.family_count > 0);
        assert!(summary.supported_families > 0);
        assert!(summary.completeness_millionths > 0);
        assert!(summary.completeness_millionths <= 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Span correctness
    // -----------------------------------------------------------------------

    #[test]
    fn single_line_source_span_is_correct() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        assert_eq!(tree.span.start_line, 1);
        assert_eq!(tree.span.end_line, 1);
    }

    #[test]
    fn multiline_source_span_end_line_is_correct() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("x\ny\nz", ParseGoal::Script).expect("parse");
        assert_eq!(tree.span.start_line, 1);
        assert_eq!(tree.span.end_line, 3);
    }

    // -----------------------------------------------------------------------
    // Determinism: multiple parses yield identical output
    // -----------------------------------------------------------------------

    #[test]
    fn three_identical_parses_produce_identical_canonical_hashes() {
        let parser = CanonicalEs2020Parser;
        let source = "import x from 'mod';\nexport default x";
        let hashes: Vec<String> = (0..3)
            .map(|_| {
                parser
                    .parse(source, ParseGoal::Module)
                    .expect("parse")
                    .canonical_hash()
            })
            .collect();
        assert_eq!(hashes[0], hashes[1]);
        assert_eq!(hashes[1], hashes[2]);
    }

    // -----------------------------------------------------------------------
    // Enrichment: leaf enum serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_code_serde_roundtrip() {
        for code in [
            ParseErrorCode::EmptySource,
            ParseErrorCode::InvalidGoal,
            ParseErrorCode::UnsupportedSyntax,
            ParseErrorCode::IoReadFailed,
            ParseErrorCode::InvalidUtf8,
            ParseErrorCode::SourceTooLarge,
            ParseErrorCode::BudgetExceeded,
        ] {
            let json = serde_json::to_string(&code).expect("serde serialization should succeed");
            let restored: ParseErrorCode =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(code, restored);
        }
    }

    #[test]
    fn parser_mode_serde_roundtrip() {
        let mode = ParserMode::ScalarReference;
        let json = serde_json::to_string(&mode).expect("serde serialization should succeed");
        let restored: ParserMode =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(mode, restored);
        // Verify snake_case rename
        assert!(json.contains("scalar_reference"));
    }

    #[test]
    fn parse_budget_kind_serde_roundtrip() {
        for kind in [
            ParseBudgetKind::SourceBytes,
            ParseBudgetKind::TokenCount,
            ParseBudgetKind::RecursionDepth,
        ] {
            let json = serde_json::to_string(&kind).expect("serde serialization should succeed");
            let restored: ParseBudgetKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn grammar_coverage_status_serde_roundtrip() {
        for status in [
            GrammarCoverageStatus::Supported,
            GrammarCoverageStatus::Partial,
            GrammarCoverageStatus::Unsupported,
            GrammarCoverageStatus::NotApplicable,
        ] {
            let json = serde_json::to_string(&status).expect("serde serialization should succeed");
            let restored: GrammarCoverageStatus =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(status, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn parser_budget_serde_roundtrip() {
        let budget = ParserBudget::default();
        let json = serde_json::to_string(&budget).expect("serde serialization should succeed");
        let restored: ParserBudget =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(budget, restored);
    }

    #[test]
    fn parser_options_serde_roundtrip() {
        let opts = ParserOptions::default();
        let json = serde_json::to_string(&opts).expect("serde serialization should succeed");
        let restored: ParserOptions =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(opts, restored);
    }

    #[test]
    fn parse_failure_witness_serde_roundtrip() {
        let witness = ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: Some(ParseBudgetKind::TokenCount),
            source_bytes: 1024,
            token_count: 500,
            max_recursion_observed: 10,
            max_source_bytes: 1_048_576,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        };
        let json = serde_json::to_string(&witness).expect("serde serialization should succeed");
        let restored: ParseFailureWitness =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(witness, restored);
    }

    #[test]
    fn grammar_family_coverage_serde_roundtrip() {
        let gfc = GrammarFamilyCoverage {
            family_id: "primary-expression".to_string(),
            es2020_clause: "12.2".to_string(),
            script_goal: GrammarCoverageStatus::Supported,
            module_goal: GrammarCoverageStatus::Partial,
            notes: "test".to_string(),
        };
        let json = serde_json::to_string(&gfc).expect("serde serialization should succeed");
        let restored: GrammarFamilyCoverage =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(gfc, restored);
    }

    #[test]
    fn grammar_completeness_summary_serde_roundtrip() {
        let summary = GrammarCompletenessSummary {
            family_count: 10,
            supported_families: 6,
            partially_supported_families: 2,
            unsupported_families: 2,
            completeness_millionths: 700_000,
        };
        let json = serde_json::to_string(&summary).expect("serde serialization should succeed");
        let restored: GrammarCompletenessSummary =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(summary, restored);
    }

    #[test]
    fn grammar_completeness_matrix_serde_roundtrip() {
        let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
        let json = serde_json::to_string(&matrix).expect("serde serialization should succeed");
        let restored: GrammarCompletenessMatrix =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(matrix, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: default value assertions
    // -----------------------------------------------------------------------

    #[test]
    fn parser_budget_default_values() {
        let b = ParserBudget::default();
        assert_eq!(b.max_source_bytes, 1_048_576);
        assert_eq!(b.max_token_count, 65_536);
        assert_eq!(b.max_recursion_depth, 256);
    }

    #[test]
    fn parser_options_default_values() {
        let o = ParserOptions::default();
        assert_eq!(o.mode, ParserMode::ScalarReference);
        assert_eq!(o.budget, ParserBudget::default());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParserMode as_str
    // -----------------------------------------------------------------------

    #[test]
    fn parser_mode_as_str() {
        assert_eq!(ParserMode::ScalarReference.as_str(), "scalar_reference");
    }

    // -----------------------------------------------------------------------
    // Enrichment: grammar matrix summary
    // -----------------------------------------------------------------------

    #[test]
    fn grammar_matrix_summary_values() {
        let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
        let summary = matrix.summary();
        assert!(summary.family_count > 0);
        assert!(summary.supported_families > 0);
        assert!(summary.completeness_millionths > 0);
        assert_eq!(
            summary.family_count,
            summary.supported_families
                + summary.partially_supported_families
                + summary.unsupported_families
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseError witness roundtrip (witness skipped in serde)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_serde_witness_none_is_omitted() {
        // When witness is None, the field is skipped in serialization
        let err = ParseError {
            code: ParseErrorCode::BudgetExceeded,
            message: "budget exceeded".to_string(),
            source_label: "test.js".to_string(),
            span: None,
            witness: None,
        };
        let json = serde_json::to_string(&err).expect("serde serialization should succeed");
        assert!(!json.contains("witness"));
        let restored: ParseError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert!(restored.witness.is_none());
        assert_eq!(restored.code, err.code);
    }

    #[test]
    fn parse_error_serde_witness_some_roundtrips() {
        let err = ParseError {
            code: ParseErrorCode::BudgetExceeded,
            message: "budget exceeded".to_string(),
            source_label: "test.js".to_string(),
            span: None,
            witness: Some(Box::new(ParseFailureWitness {
                mode: ParserMode::ScalarReference,
                budget_kind: Some(ParseBudgetKind::SourceBytes),
                source_bytes: 2_000_000,
                token_count: 0,
                max_recursion_observed: 0,
                max_source_bytes: 1_048_576,
                max_token_count: 65_536,
                max_recursion_depth: 256,
            })),
        };
        let json = serde_json::to_string(&err).expect("serde serialization should succeed");
        assert!(json.contains("witness"));
        let restored: ParseError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert!(restored.witness.is_some());
        assert_eq!(
            restored
                .witness
                .expect("serde serialization should succeed")
                .source_bytes,
            2_000_000
        );
    }

    #[test]
    fn parse_diagnostic_contract_metadata_is_versioned_and_stable() {
        assert_eq!(
            PARSER_DIAGNOSTIC_TAXONOMY_VERSION,
            "franken-engine.parser-diagnostics.taxonomy.v1"
        );
        assert_eq!(
            PARSER_DIAGNOSTIC_SCHEMA_VERSION,
            "franken-engine.parser-diagnostics.schema.v1"
        );
        assert_eq!(PARSER_DIAGNOSTIC_HASH_ALGORITHM, "sha256");
        assert_eq!(PARSER_DIAGNOSTIC_HASH_PREFIX, "sha256:");

        assert_eq!(
            ParseDiagnosticTaxonomy::taxonomy_version(),
            PARSER_DIAGNOSTIC_TAXONOMY_VERSION
        );
        assert_eq!(
            ParseDiagnosticEnvelope::schema_version(),
            PARSER_DIAGNOSTIC_SCHEMA_VERSION
        );
        assert_eq!(
            ParseDiagnosticEnvelope::taxonomy_version(),
            PARSER_DIAGNOSTIC_TAXONOMY_VERSION
        );
        assert_eq!(
            ParseDiagnosticEnvelope::canonical_hash_algorithm(),
            PARSER_DIAGNOSTIC_HASH_ALGORITHM
        );
        assert_eq!(
            ParseDiagnosticEnvelope::canonical_hash_prefix(),
            PARSER_DIAGNOSTIC_HASH_PREFIX
        );
    }

    #[test]
    fn parse_diagnostic_taxonomy_v1_is_complete_and_unique() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        assert_eq!(
            taxonomy.taxonomy_version,
            PARSER_DIAGNOSTIC_TAXONOMY_VERSION.to_string()
        );
        assert_eq!(taxonomy.rules.len(), ParseErrorCode::ALL.len());

        let mut error_codes = BTreeSet::new();
        let mut diagnostic_codes = BTreeSet::new();
        for rule in &taxonomy.rules {
            assert!(error_codes.insert(rule.parse_error_code.as_str().to_string()));
            assert!(diagnostic_codes.insert(rule.diagnostic_code.clone()));
            assert_eq!(
                rule.diagnostic_code,
                rule.parse_error_code.stable_diagnostic_code()
            );
            assert_eq!(rule.category, rule.parse_error_code.diagnostic_category());
            assert_eq!(rule.severity, rule.parse_error_code.diagnostic_severity());
            assert_eq!(
                rule.message_template,
                rule.parse_error_code.diagnostic_message_template(None)
            );
        }

        for code in ParseErrorCode::ALL {
            assert!(taxonomy.rule_for(code).is_some());
        }
    }

    #[test]
    fn parse_error_normalization_ignores_raw_message_variance() {
        let span = SourceSpan::new(0, 10, 1, 1, 1, 11);
        let left = ParseError {
            code: ParseErrorCode::IoReadFailed,
            message: "failed to read source file: No such file or directory (os error 2)"
                .to_string(),
            source_label: "fixture.js".to_string(),
            span: Some(span.clone()),
            witness: None,
        };
        let right = ParseError {
            code: ParseErrorCode::IoReadFailed,
            message: "failed to read source stream: permission denied".to_string(),
            source_label: "fixture.js".to_string(),
            span: Some(span),
            witness: None,
        };

        let left_norm = left.normalized_diagnostic();
        let right_norm = ParseDiagnosticEnvelope::from_parse_error(&right);
        assert_eq!(left_norm.message_template, "parser input could not be read");
        assert_eq!(left_norm.canonical_bytes(), right_norm.canonical_bytes());
        assert_eq!(left_norm.canonical_hash(), right_norm.canonical_hash());
    }

    #[test]
    fn parse_error_normalization_preserves_budget_context() {
        let err = ParseError {
            code: ParseErrorCode::BudgetExceeded,
            message: "token budget exceeded: token_count=3 max_token_count=1".to_string(),
            source_label: "<inline>".to_string(),
            span: Some(SourceSpan::new(0, 16, 1, 1, 1, 17)),
            witness: Some(Box::new(ParseFailureWitness {
                mode: ParserMode::ScalarReference,
                budget_kind: Some(ParseBudgetKind::TokenCount),
                source_bytes: 16,
                token_count: 3,
                max_recursion_observed: 0,
                max_source_bytes: 1024,
                max_token_count: 1,
                max_recursion_depth: 64,
            })),
        };

        let normalized = normalize_parse_error(&err);
        assert_eq!(normalized.category, ParseDiagnosticCategory::Resource);
        assert_eq!(normalized.severity, ParseDiagnosticSeverity::Fatal);
        assert_eq!(
            normalized.diagnostic_code,
            ParseErrorCode::BudgetExceeded.stable_diagnostic_code()
        );
        assert_eq!(
            normalized.message_template,
            "token budget exceeded".to_string()
        );
        assert_eq!(normalized.budget_kind, Some(ParseBudgetKind::TokenCount));
        assert_eq!(
            normalized
                .witness
                .as_ref()
                .expect("budget witness should be retained")
                .token_count,
            3
        );
    }

    #[test]
    fn parse_diagnostic_envelope_serde_and_hash_are_stable() {
        let err = ParseError {
            code: ParseErrorCode::EmptySource,
            message: "source is empty after whitespace normalization".to_string(),
            source_label: "<inline>".to_string(),
            span: None,
            witness: None,
        };
        let left = normalize_parse_error(&err);
        let right = normalize_parse_error(&err);
        let json = serde_json::to_string(&left).expect("serde serialization should succeed");
        let restored: ParseDiagnosticEnvelope =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(restored, left);
        assert_eq!(left.canonical_hash(), right.canonical_hash());
        assert!(
            left.canonical_hash()
                .starts_with(ParseDiagnosticEnvelope::canonical_hash_prefix())
        );
    }

    #[test]
    fn parse_event_kind_serde_roundtrip() {
        for kind in [
            ParseEventKind::ParseStarted,
            ParseEventKind::StatementParsed,
            ParseEventKind::ParseCompleted,
            ParseEventKind::ParseFailed,
        ] {
            let json = serde_json::to_string(&kind).expect("serde serialization should succeed");
            let restored: ParseEventKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(kind, restored);
        }
    }

    #[test]
    fn parse_event_ir_contract_metadata_is_versioned_and_stable() {
        assert_eq!(
            PARSE_EVENT_IR_CONTRACT_VERSION,
            "franken-engine.parser-event-ir.contract.v2"
        );
        assert_eq!(
            PARSE_EVENT_IR_SCHEMA_VERSION,
            "franken-engine.parser-event-ir.schema.v2"
        );
        assert_eq!(PARSE_EVENT_IR_HASH_ALGORITHM, "sha256");
        assert_eq!(PARSE_EVENT_IR_HASH_PREFIX, "sha256:");
        assert_eq!(
            PARSE_EVENT_IR_POLICY_ID,
            "franken-engine.parser-event-producer.policy.v1"
        );
        assert_eq!(PARSE_EVENT_IR_COMPONENT, "canonical_es2020_parser");
        assert_eq!(PARSE_EVENT_IR_TRACE_PREFIX, "trace-parser-event-");
        assert_eq!(PARSE_EVENT_IR_DECISION_PREFIX, "decision-parser-event-");
        assert_eq!(
            ParseEventIr::contract_version(),
            PARSE_EVENT_IR_CONTRACT_VERSION
        );
        assert_eq!(
            ParseEventIr::schema_version(),
            PARSE_EVENT_IR_SCHEMA_VERSION
        );
        assert_eq!(
            ParseEventIr::canonical_hash_algorithm(),
            PARSE_EVENT_IR_HASH_ALGORITHM
        );
        assert_eq!(
            ParseEventIr::canonical_hash_prefix(),
            PARSE_EVENT_IR_HASH_PREFIX
        );
    }

    #[test]
    fn parse_event_ir_from_syntax_tree_emits_deterministic_sequence() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;\n";
        let tree = parser.parse(source, ParseGoal::Module).expect("parse");

        let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        assert_eq!(ir.schema_version, PARSE_EVENT_IR_SCHEMA_VERSION);
        assert_eq!(ir.contract_version, PARSE_EVENT_IR_CONTRACT_VERSION);
        assert_eq!(ir.events.len(), tree.body.len() + 2);
        assert!(matches!(
            ir.events.first().map(|event| event.kind),
            Some(ParseEventKind::ParseStarted)
        ));
        assert!(matches!(
            ir.events.last().map(|event| event.kind),
            Some(ParseEventKind::ParseCompleted)
        ));

        for (index, event) in ir.events.iter().enumerate() {
            assert_eq!(event.sequence, index as u64);
            assert!(event.trace_id.starts_with(PARSE_EVENT_IR_TRACE_PREFIX));
            assert!(
                event
                    .decision_id
                    .starts_with(PARSE_EVENT_IR_DECISION_PREFIX)
            );
            assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
            assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
            assert!(!event.outcome.is_empty());
        }
    }

    #[test]
    fn parse_event_ir_hash_is_deterministic_for_identical_inputs() {
        let parser = CanonicalEs2020Parser;
        let source = "typeof work";
        let left_tree = parser.parse(source, ParseGoal::Script).expect("left parse");
        let right_tree = parser
            .parse(source, ParseGoal::Script)
            .expect("right parse");

        let left_ir =
            ParseEventIr::from_syntax_tree(&left_tree, "<inline>", ParserMode::ScalarReference);
        let right_ir =
            ParseEventIr::from_syntax_tree(&right_tree, "<inline>", ParserMode::ScalarReference);
        assert_eq!(left_ir.canonical_bytes(), right_ir.canonical_bytes());
        assert_eq!(left_ir.canonical_hash(), right_ir.canonical_hash());
        assert!(
            left_ir
                .canonical_hash()
                .starts_with(ParseEventIr::canonical_hash_prefix())
        );
    }

    #[test]
    fn parse_event_ir_serde_roundtrip() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export default true", ParseGoal::Module)
            .expect("parse");
        let ir = ParseEventIr::from_syntax_tree(&tree, "fixture.js", ParserMode::ScalarReference);
        let json = serde_json::to_string(&ir).expect("serde serialization should succeed");
        let restored: ParseEventIr =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(restored, ir);
    }

    #[test]
    fn parse_with_event_ir_success_emits_ordered_events() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;\n";
        let (result, event_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Module, &ParserOptions::default());

        let tree = result.expect("parse should succeed");
        assert_eq!(event_ir.events.len(), tree.body.len() + 2);
        assert!(matches!(
            event_ir.events.first().map(|event| event.kind),
            Some(ParseEventKind::ParseStarted)
        ));
        assert!(matches!(
            event_ir.events.last().map(|event| event.kind),
            Some(ParseEventKind::ParseCompleted)
        ));
        for (index, event) in event_ir.events.iter().enumerate() {
            assert_eq!(event.sequence, index as u64);
            assert_eq!(event.policy_id, PARSE_EVENT_IR_POLICY_ID);
            assert_eq!(event.component, PARSE_EVENT_IR_COMPONENT);
            assert_eq!(event.error_code, None);
        }
    }

    #[test]
    fn parse_with_event_ir_failure_emits_parse_failed_event() {
        let parser = CanonicalEs2020Parser;
        let (result, event_ir) =
            parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());

        let error = result.expect_err("empty source should fail");
        assert_eq!(error.code, ParseErrorCode::EmptySource);
        assert_eq!(event_ir.events.len(), 2);
        assert!(matches!(
            event_ir.events[0].kind,
            ParseEventKind::ParseStarted
        ));
        assert!(matches!(
            event_ir.events[1].kind,
            ParseEventKind::ParseFailed
        ));
        assert_eq!(
            event_ir.events[1].error_code,
            Some(ParseErrorCode::EmptySource)
        );
        assert_eq!(
            event_ir.events[1].payload_kind.as_deref(),
            Some("parse_diagnostic")
        );
        assert!(
            event_ir.events[1]
                .payload_hash
                .as_deref()
                .is_some_and(|hash| hash.starts_with(ParseEventIr::canonical_hash_prefix()))
        );
    }

    #[test]
    fn parse_event_ast_materializer_contract_metadata_is_versioned_and_stable() {
        assert_eq!(
            PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION,
            "franken-engine.parser-event-ast-materializer.contract.v1"
        );
        assert_eq!(
            PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION,
            "franken-engine.parser-event-ast-materializer.schema.v1"
        );
        assert_eq!(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX, "ast-node-");
        assert_eq!(
            MaterializedSyntaxTree::contract_version(),
            PARSE_EVENT_AST_MATERIALIZER_CONTRACT_VERSION
        );
        assert_eq!(
            MaterializedSyntaxTree::schema_version(),
            PARSE_EVENT_AST_MATERIALIZER_SCHEMA_VERSION
        );
    }

    #[test]
    fn materialize_from_source_matches_canonical_ast_hash_and_node_witnesses() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;\n";
        let options = ParserOptions::default();
        let (result, event_ir) = parser.parse_with_event_ir(source, ParseGoal::Module, &options);
        let tree = result.expect("parse should succeed");
        let materialized = event_ir
            .materialize_from_source(source, &options)
            .expect("materialization should succeed");

        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            tree.canonical_hash()
        );
        assert_eq!(materialized.statement_nodes.len(), tree.body.len());
        assert!(
            materialized
                .root_node_id
                .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
        );
        for (idx, node) in materialized.statement_nodes.iter().enumerate() {
            assert_eq!(node.statement_index, idx as u64);
            assert_eq!(node.sequence, (idx as u64).saturating_add(1));
            assert!(
                node.node_id
                    .starts_with(PARSE_EVENT_AST_MATERIALIZER_NODE_ID_PREFIX)
            );
            assert!(
                node.payload_hash
                    .starts_with(ParseEventIr::canonical_hash_prefix())
            );
        }
    }

    #[test]
    fn materialize_from_source_accepts_exact_historical_root_column_bd_4tt6s() {
        let parser = CanonicalEs2020Parser;
        let source = "alpha";
        let options = ParserOptions::default();
        let current = parser
            .parse(source, ParseGoal::Script)
            .expect("current source should parse");
        assert_eq!(current.span.end_column, 6);

        let mut historical = current.clone();
        historical.span.end_column = 1;
        let historical_hash = historical.canonical_hash();

        for event_ir in [
            ParseEventIr::from_parse_source(
                &historical,
                source,
                "historical-source.js",
                options.mode,
            ),
            ParseEventIr::from_syntax_tree(&historical, "historical-tree.js", options.mode),
        ] {
            let materialized = event_ir
                .materialize_from_source(source, &options)
                .expect("the exact historical root-column defect should remain readable");
            assert_eq!(materialized.syntax_tree, historical);
            assert_eq!(materialized.syntax_tree.canonical_hash(), historical_hash);
        }

        let trailing_source = "alpha\n";
        let (result, current_ir) =
            parser.parse_with_event_ir(trailing_source, ParseGoal::Script, &options);
        let trailing_tree = result.expect("trailing-LF source should parse");
        assert_eq!(trailing_tree.span.end_column, 1);
        assert_eq!(
            current_ir
                .materialize_from_source(trailing_source, &options)
                .expect("current trailing-LF stream should materialize")
                .syntax_tree,
            trailing_tree
        );
    }

    #[test]
    fn materialize_from_source_rejects_inexact_historical_root_column_bd_4tt6s() {
        let parser = CanonicalEs2020Parser;
        let source = "alpha";
        let options = ParserOptions::default();
        let current = parser
            .parse(source, ParseGoal::Script)
            .expect("current source should parse");
        let mut historical = current.clone();
        historical.span.end_column = 1;

        let mut wrong_other_field = ParseEventIr::from_parse_source(
            &historical,
            source,
            "wrong-other-field.js",
            options.mode,
        );
        wrong_other_field
            .events
            .last_mut()
            .and_then(|event| event.span.as_mut())
            .expect("completed span")
            .start_column = 2;
        assert_eq!(
            wrong_other_field
                .materialize_from_source(source, &options)
                .expect_err("a second span-field drift must not use the historical path")
                .code,
            ParseEventMaterializationErrorCode::AstHashMismatch
        );

        let mut current_hash_with_old_span = ParseEventIr::from_parse_source(
            &current,
            source,
            "current-hash-old-span.js",
            options.mode,
        );
        current_hash_with_old_span
            .events
            .last_mut()
            .and_then(|event| event.span.as_mut())
            .expect("completed span")
            .end_column = 1;
        assert_eq!(
            current_hash_with_old_span
                .materialize_from_source(source, &options)
                .expect_err("a current hash must not authenticate a historical span")
                .code,
            ParseEventMaterializationErrorCode::StatementSpanMismatch
        );

        let mut old_hash_with_current_span = ParseEventIr::from_parse_source(
            &historical,
            source,
            "old-hash-current-span.js",
            options.mode,
        );
        old_hash_with_current_span
            .events
            .last_mut()
            .expect("completed event")
            .span = Some(current.span.clone());
        assert_eq!(
            old_hash_with_current_span
                .materialize_from_source(source, &options)
                .expect_err("a historical hash must not authenticate the current span")
                .code,
            ParseEventMaterializationErrorCode::AstHashMismatch
        );
    }

    #[test]
    fn materialized_ast_node_ids_are_deterministic_for_identical_inputs() {
        let parser = CanonicalEs2020Parser;
        let source = "typeof work";
        let options = ParserOptions::default();

        let (left_result, left_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        let left_tree = left_result.expect("left parse should succeed");
        let (right_result, right_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        let right_tree = right_result.expect("right parse should succeed");

        let left_materialized = left_ir
            .materialize_from_source(source, &options)
            .expect("left materialization should succeed");
        let right_materialized = right_ir
            .materialize_from_source(source, &options)
            .expect("right materialization should succeed");

        assert_eq!(
            left_materialized.syntax_tree.canonical_hash(),
            left_tree.canonical_hash()
        );
        assert_eq!(
            right_materialized.syntax_tree.canonical_hash(),
            right_tree.canonical_hash()
        );
        assert_eq!(
            left_materialized.root_node_id,
            right_materialized.root_node_id
        );
        assert_eq!(
            left_materialized.statement_nodes,
            right_materialized.statement_nodes
        );
        assert_eq!(
            left_materialized.canonical_hash(),
            right_materialized.canonical_hash()
        );
    }

    #[test]
    fn materialize_from_source_rejects_statement_hash_tampering() {
        let parser = CanonicalEs2020Parser;
        let source = "alpha;";
        let options = ParserOptions::default();
        let (_result, mut event_ir) =
            parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        event_ir.events[1].payload_hash = Some(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let err = event_ir
            .materialize_from_source(source, &options)
            .expect_err("tampered payload hash must fail");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::StatementHashMismatch
        );
        assert_eq!(err.sequence, Some(1));
    }

    #[test]
    fn materialize_from_source_rejects_failed_event_streams() {
        let parser = CanonicalEs2020Parser;
        let (_result, event_ir) =
            parser.parse_with_event_ir("", ParseGoal::Script, &ParserOptions::default());
        let err = event_ir
            .materialize_from_source("", &ParserOptions::default())
            .expect_err("failed event stream should be rejected");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::ParseFailedEventStream
        );
    }

    #[test]
    fn parse_with_materialized_ast_success_and_failure_contracts_are_deterministic() {
        let parser = CanonicalEs2020Parser;
        let source = "import dep from \"pkg\";\nexport default dep;";
        let options = ParserOptions::default();

        let (result, _event_ir, materialized_result) =
            parser.parse_with_materialized_ast(source, ParseGoal::Module, &options);
        let tree = result.expect("parse should succeed");
        let materialized = materialized_result.expect("materializer should succeed");
        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            tree.canonical_hash()
        );

        let (failed_result, _failed_ir, failed_materialized) =
            parser.parse_with_materialized_ast("", ParseGoal::Script, &ParserOptions::default());
        let err = failed_result.expect_err("empty source should fail parse");
        assert_eq!(err.code, ParseErrorCode::EmptySource);
        assert_eq!(
            failed_materialized
                .expect_err("failed parse must not materialize")
                .code,
            ParseEventMaterializationErrorCode::ParseFailedEventStream
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseErrorCode as_str all variants
    // -----------------------------------------------------------------------

    #[test]
    fn parse_error_code_as_str_all_distinct() {
        let strs: BTreeSet<&str> = ParseErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), ParseErrorCode::ALL.len());
    }

    #[test]
    fn parse_error_code_stable_diagnostic_code_all_distinct() {
        let codes: BTreeSet<&str> = ParseErrorCode::ALL
            .iter()
            .map(|c| c.stable_diagnostic_code())
            .collect();
        assert_eq!(codes.len(), ParseErrorCode::ALL.len());
    }

    #[test]
    fn parse_error_code_diagnostic_category_covers_all_categories() {
        let categories: BTreeSet<_> = ParseErrorCode::ALL
            .iter()
            .map(|c| c.diagnostic_category().as_str())
            .collect();
        // At least 4 distinct categories
        assert!(categories.len() >= 4, "got {:?}", categories);
    }

    #[test]
    fn parse_error_code_diagnostic_severity_covers_both() {
        let severities: BTreeSet<_> = ParseErrorCode::ALL
            .iter()
            .map(|c| c.diagnostic_severity().as_str())
            .collect();
        assert!(severities.contains("error"));
        assert!(severities.contains("fatal"));
    }

    #[test]
    fn parse_error_code_diagnostic_message_template_non_empty() {
        for code in &ParseErrorCode::ALL {
            assert!(
                !code.diagnostic_message_template(None).is_empty(),
                "empty template for {:?}",
                code
            );
        }
    }

    #[test]
    fn budget_exceeded_message_template_with_budget_kind() {
        let msg = ParseErrorCode::BudgetExceeded
            .diagnostic_message_template(Some(ParseBudgetKind::TokenCount));
        assert!(
            msg.contains("token"),
            "expected token-related msg, got: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseDiagnosticCategory as_str all distinct
    // -----------------------------------------------------------------------

    #[test]
    fn parse_diagnostic_category_as_str_all_distinct() {
        let categories = [
            ParseDiagnosticCategory::Input,
            ParseDiagnosticCategory::Goal,
            ParseDiagnosticCategory::Syntax,
            ParseDiagnosticCategory::Encoding,
            ParseDiagnosticCategory::Resource,
            ParseDiagnosticCategory::System,
        ];
        let strs: BTreeSet<&str> = categories.iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), categories.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseBudgetKind as_str all distinct
    // -----------------------------------------------------------------------

    #[test]
    fn parse_budget_kind_as_str_all_distinct() {
        let kinds = [
            ParseBudgetKind::SourceBytes,
            ParseBudgetKind::TokenCount,
            ParseBudgetKind::RecursionDepth,
        ];
        let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(strs.len(), kinds.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseEventKind as_str all distinct
    // -----------------------------------------------------------------------

    #[test]
    fn parse_event_kind_as_str_all_distinct() {
        let kinds = [
            ParseEventKind::ParseStarted,
            ParseEventKind::StatementParsed,
            ParseEventKind::ParseCompleted,
            ParseEventKind::ParseFailed,
        ];
        let strs: BTreeSet<&str> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(strs.len(), kinds.len());
    }

    #[test]
    fn parse_event_kind_canonical_value_matches_as_str() {
        for kind in [
            ParseEventKind::ParseStarted,
            ParseEventKind::StatementParsed,
            ParseEventKind::ParseCompleted,
            ParseEventKind::ParseFailed,
        ] {
            if let CanonicalValue::String(s) = kind.canonical_value() {
                assert_eq!(s, kind.as_str());
            } else {
                panic!("expected CanonicalValue::String");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseEventMaterializationErrorCode as_str
    // -----------------------------------------------------------------------

    #[test]
    fn parse_event_materialization_error_code_as_str_all_distinct() {
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
        let strs: BTreeSet<&str> = codes.iter().map(|c| c.as_str()).collect();
        assert_eq!(strs.len(), codes.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ParseEventMaterializationError Display
    // -----------------------------------------------------------------------

    #[test]
    fn materialization_error_display_with_sequence() {
        let err = ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::GoalMismatch,
            "mismatch".to_string(),
            Some(5),
        );
        let display = err.to_string();
        assert!(display.contains("sequence=5"), "got: {display}");
        assert!(display.contains("goal_mismatch"), "got: {display}");
    }

    #[test]
    fn materialization_error_display_without_sequence() {
        let err = ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::SourceHashMismatch,
            "hash differs".to_string(),
            None,
        );
        let display = err.to_string();
        assert!(!display.contains("sequence="), "got: {display}");
        assert!(display.contains("source_hash_mismatch"), "got: {display}");
    }

    #[test]
    fn materialization_error_is_std_error() {
        let err: &dyn std::error::Error = &ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::ParseFailedEventStream,
            "msg".to_string(),
            None,
        );
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrips for missing types
    // -----------------------------------------------------------------------

    #[test]
    fn parse_diagnostic_rule_serde_roundtrip() {
        let rule = ParseDiagnosticRule {
            parse_error_code: ParseErrorCode::EmptySource,
            diagnostic_code: "FE-PARSER-DIAG-EMPTY-SOURCE-0001".to_string(),
            category: ParseDiagnosticCategory::Input,
            severity: ParseDiagnosticSeverity::Error,
            message_template: "source is empty".to_string(),
        };
        let json = serde_json::to_string(&rule).expect("serde serialization should succeed");
        let restored: ParseDiagnosticRule =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(rule, restored);
    }

    #[test]
    fn parse_diagnostic_taxonomy_serde_roundtrip() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        let json = serde_json::to_string(&taxonomy).expect("serde serialization should succeed");
        let restored: ParseDiagnosticTaxonomy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(taxonomy, restored);
    }

    #[test]
    fn parse_event_materialization_error_serde_roundtrip() {
        let err = ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::InvalidEventSequence,
            "bad seq".to_string(),
            Some(3),
        );
        let json = serde_json::to_string(&err).expect("serde serialization should succeed");
        let restored: ParseEventMaterializationError =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: helper functions
    // -----------------------------------------------------------------------

    #[test]
    fn line_count_single_line() {
        assert_eq!(line_count("hello"), 1);
    }

    #[test]
    fn line_count_multiple_lines() {
        assert_eq!(line_count("a\nb\nc"), 3);
    }

    #[test]
    fn line_count_trailing_newline() {
        assert_eq!(line_count("a\n"), 2);
    }

    #[test]
    fn line_count_recognizes_ecmascript_line_terminators_bd_21nbg() {
        for (source, expected) in [
            ("alpha\rbeta", 2),
            ("alpha\r\nbeta", 2),
            ("alpha\nbeta", 2),
            ("alpha\u{2028}beta", 2),
            ("alpha\u{2029}beta", 2),
            ("alpha\r\n\u{2028}\u{2029}", 4),
        ] {
            assert_eq!(line_count(source), expected, "{source:?}");
        }
    }

    #[test]
    fn ecmascript_line_terminators_split_physical_statements_bd_21nbg() {
        let parser = CanonicalEs2020Parser;
        for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
            let source = format!("first;{terminator}second;");
            let tree = parser
                .parse(source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
            assert_eq!(tree.body.len(), 2, "{source:?}");
            assert_eq!(tree.body[0].span().start_line, 1, "{source:?}");
            assert_eq!(tree.body[0].span().end_line, 1, "{source:?}");
            assert_eq!(tree.body[1].span().start_line, 2, "{source:?}");
            assert_eq!(tree.body[1].span().end_line, 2, "{source:?}");

            let blank_line_source = format!("first;{terminator}{terminator}second;");
            let blank_line_tree = parser
                .parse(blank_line_source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {blank_line_source:?}: {error}"));
            assert_eq!(blank_line_tree.body.len(), 2, "{blank_line_source:?}");
            assert_eq!(
                blank_line_tree.body[1].span().start_line,
                3,
                "{blank_line_source:?}"
            );
        }
    }

    #[test]
    fn normalized_logical_lines_map_spans_to_physical_source_bd_crph5() {
        let parser = CanonicalEs2020Parser;
        for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
            let source = format!("call({terminator}  value{terminator});  after;");
            let tree = parser
                .parse(source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
            assert_eq!(tree.body.len(), 2, "{source:?}");

            let call_span = tree.body[0].span();
            assert_eq!(call_span.start_offset, 0, "{source:?}");
            assert_eq!(
                call_span.end_offset,
                source.find(';').expect("call terminator is present") as u64,
                "{source:?}"
            );
            assert_eq!(call_span.start_line, 1, "{source:?}");
            assert_eq!(call_span.start_column, 1, "{source:?}");
            assert_eq!(call_span.end_line, 3, "{source:?}");
            assert_eq!(call_span.end_column, 2, "{source:?}");

            let after_offset = source.find("after").expect("after is present") as u64;
            let after_span = tree.body[1].span();
            assert_eq!(after_span.start_offset, after_offset, "{source:?}");
            assert_eq!(after_span.end_offset, after_offset + 5, "{source:?}");
            assert_eq!(after_span.start_line, 3, "{source:?}");
            assert_eq!(after_span.start_column, 5, "{source:?}");
            assert_eq!(after_span.end_line, 3, "{source:?}");
            assert_eq!(after_span.end_column, 10, "{source:?}");
        }
    }

    #[test]
    fn leading_dot_continuation_maps_across_trivia_gap_bd_crph5() {
        let parser = CanonicalEs2020Parser;
        let source = "value\n// gap\n  .method();\n  after;";
        let tree = parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
        assert_eq!(tree.body.len(), 2);

        let chained_span = tree.body[0].span();
        assert_eq!(chained_span.start_offset, 0);
        assert_eq!(
            chained_span.end_offset,
            source.find(';').expect("chain terminator is present") as u64
        );
        assert_eq!(chained_span.start_line, 1);
        assert_eq!(chained_span.start_column, 1);
        assert_eq!(chained_span.end_line, 3);
        assert_eq!(chained_span.end_column, 12);

        let after_offset = source.find("after").expect("after is present") as u64;
        let after_span = tree.body[1].span();
        assert_eq!(after_span.start_offset, after_offset);
        assert_eq!(after_span.end_offset, after_offset + 5);
        assert_eq!(after_span.start_line, 4);
        assert_eq!(after_span.start_column, 3);
        assert_eq!(after_span.end_line, 4);
        assert_eq!(after_span.end_column, 8);
    }

    #[test]
    fn comment_gaps_and_multiline_blocks_map_physical_spans_bd_crph5() {
        let parser = CanonicalEs2020Parser;
        for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
            let source = format!(
                "  first; // trailing é{terminator}{terminator}if (ready) {{{terminator}  work();{terminator}}}{terminator}  after;"
            );
            let tree = parser
                .parse(source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
            assert_eq!(tree.body.len(), 3, "{source:?}");

            let first_span = tree.body[0].span();
            assert_eq!(first_span.start_offset, 2, "{source:?}");
            assert_eq!(first_span.end_offset, 7, "{source:?}");
            assert_eq!(first_span.start_line, 1, "{source:?}");
            assert_eq!(first_span.start_column, 3, "{source:?}");
            assert_eq!(first_span.end_line, 1, "{source:?}");
            assert_eq!(first_span.end_column, 8, "{source:?}");

            let block_start = source.find("if").expect("block start is present") as u64;
            let block_end = source.find('}').expect("block end is present") as u64 + 1;
            let block_span = tree.body[1].span();
            assert_eq!(block_span.start_offset, block_start, "{source:?}");
            assert_eq!(block_span.end_offset, block_end, "{source:?}");
            assert_eq!(block_span.start_line, 3, "{source:?}");
            assert_eq!(block_span.start_column, 1, "{source:?}");
            assert_eq!(block_span.end_line, 5, "{source:?}");
            assert_eq!(block_span.end_column, 2, "{source:?}");

            let after_offset = source.find("after").expect("after is present") as u64;
            let after_span = tree.body[2].span();
            assert_eq!(after_span.start_offset, after_offset, "{source:?}");
            assert_eq!(after_span.end_offset, after_offset + 5, "{source:?}");
            assert_eq!(after_span.start_line, 6, "{source:?}");
            assert_eq!(after_span.start_column, 3, "{source:?}");
            assert_eq!(after_span.end_line, 6, "{source:?}");
            assert_eq!(after_span.end_column, 8, "{source:?}");
        }
    }

    #[test]
    fn quoted_multiline_spans_and_boundary_maps_remain_exact_bd_crph5() {
        let parser = CanonicalEs2020Parser;
        for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
            let source = format!("const value = `a{terminator}b`;  next;");
            let tree = parser
                .parse(source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
            assert_eq!(tree.body.len(), 2, "{source:?}");

            let template_span = tree.body[0].span();
            assert_eq!(template_span.start_offset, 0, "{source:?}");
            assert_eq!(
                template_span.end_offset,
                source.find(';').expect("template terminator is present") as u64,
                "{source:?}"
            );
            assert_eq!(template_span.start_line, 1, "{source:?}");
            assert_eq!(template_span.start_column, 1, "{source:?}");
            assert_eq!(template_span.end_line, 2, "{source:?}");
            assert_eq!(template_span.end_column, 3, "{source:?}");

            let next_offset = source.find("next").expect("next is present") as u64;
            let next_span = tree.body[1].span();
            assert_eq!(next_span.start_offset, next_offset, "{source:?}");
            assert_eq!(next_span.end_offset, next_offset + 4, "{source:?}");
            assert_eq!(next_span.start_line, 2, "{source:?}");
            assert_eq!(next_span.start_column, 6, "{source:?}");
            assert_eq!(next_span.end_line, 2, "{source:?}");
            assert_eq!(next_span.end_column, 10, "{source:?}");

            let stripped = strip_comments_to_whitespace(&source);
            for logical_line in merge_logical_lines(&stripped) {
                assert_eq!(
                    logical_line.source_boundaries.len(),
                    logical_line.text.len() + 1,
                    "{source:?}"
                );
                assert!(
                    logical_line
                        .source_boundaries
                        .windows(2)
                        .all(|window| window[0] <= window[1]),
                    "{source:?}"
                );
            }
        }
    }

    #[test]
    fn syntax_tree_root_span_ends_at_eof_byte_column_bd_4tt6s() {
        let parser = CanonicalEs2020Parser;
        let cases = [
            ("alpha", 1, 6),
            ("alpha\nbeta", 2, 5),
            ("alpha\n", 2, 1),
            ("alpha\r\nbeta", 2, 5),
            ("alpha\r\n", 2, 1),
            ("alpha\rbeta", 2, 5),
            ("alpha\r", 2, 1),
            ("alpha\u{2028}beta", 2, 5),
            ("alpha\u{2028}", 2, 1),
            ("alpha\u{2029}beta", 2, 5),
            ("alpha\u{2029}", 2, 1),
            ("'é'", 1, 5),
            ("alpha  ", 1, 8),
        ];

        for (source, expected_line, expected_column) in cases {
            let tree = parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {source:?}: {error}"));
            assert_eq!(tree.span.end_offset, source.len() as u64, "{source:?}");
            assert_eq!(tree.span.end_line, expected_line, "{source:?}");
            assert_eq!(tree.span.end_column, expected_column, "{source:?}");
        }
    }

    #[test]
    fn is_identifier_empty_returns_false() {
        assert!(!is_identifier(""));
    }

    #[test]
    fn is_identifier_valid() {
        assert!(is_identifier("foo"));
        assert!(is_identifier("_bar"));
        assert!(is_identifier("$baz"));
        assert!(is_identifier("x2"));
    }

    #[test]
    fn is_identifier_invalid() {
        assert!(!is_identifier("2x"));
        assert!(!is_identifier("foo bar"));
        assert!(!is_identifier("-x"));
    }

    #[test]
    fn module_binding_identifier_rejects_keywords() {
        assert!(!is_module_binding_identifier("for"));
        assert!(!is_module_binding_identifier("await"));
        assert!(!is_module_binding_identifier("interface"));
    }

    #[test]
    fn module_binding_identifier_accepts_valid_names() {
        assert!(is_module_binding_identifier("dep"));
        assert!(is_module_binding_identifier("_local1"));
    }

    #[test]
    fn canonicalize_whitespace_normalizes() {
        assert_eq!(canonicalize_whitespace("  a   b  c  "), "a b c");
    }

    #[test]
    fn canonicalize_whitespace_empty() {
        assert_eq!(canonicalize_whitespace("   "), "");
    }

    #[test]
    fn is_identifier_start_cases() {
        assert!(is_identifier_start('a'));
        assert!(is_identifier_start('Z'));
        assert!(is_identifier_start('_'));
        assert!(is_identifier_start('$'));
        assert!(!is_identifier_start('0'));
        assert!(!is_identifier_start('-'));
        // Non-ASCII letters (ID_Start), including Other_ID_Start (U+2118).
        for ch in ['\u{3C0}', '\u{410}', '\u{E9}', '\u{4E2D}', '\u{2118}'] {
            assert!(is_identifier_start(ch), "{ch:?}");
        }
        // Combining marks, digits, ZWJ and punctuation cannot start one.
        for ch in ['\u{301}', '\u{660}', '\u{200D}', '\u{B7}', '\u{2014}'] {
            assert!(!is_identifier_start(ch), "{ch:?}");
        }
    }

    #[test]
    fn is_identifier_continue_unicode_cases() {
        for ch in ['\u{301}', '\u{660}', '\u{200C}', '\u{200D}', '\u{B7}'] {
            assert!(is_identifier_continue(ch), "{ch:?}");
        }
        assert!(!is_identifier_continue('\u{2014}'));
        assert!(is_identifier("\u{3C0}"));
        assert!(is_identifier("caf\u{E9}\u{301}"));
        assert!(!is_identifier("\u{301}x"));
    }

    #[test]
    fn is_identifier_continue_cases() {
        assert!(is_identifier_continue('a'));
        assert!(is_identifier_continue('0'));
        assert!(is_identifier_continue('_'));
        assert!(is_identifier_continue('$'));
        assert!(!is_identifier_continue('-'));
        assert!(!is_identifier_continue(' '));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn parse_diagnostic_category_serde_roundtrip() {
        for cat in [
            ParseDiagnosticCategory::Input,
            ParseDiagnosticCategory::Goal,
            ParseDiagnosticCategory::Syntax,
            ParseDiagnosticCategory::Encoding,
            ParseDiagnosticCategory::Resource,
            ParseDiagnosticCategory::System,
        ] {
            let json = serde_json::to_string(&cat).expect("serde serialization should succeed");
            let back: ParseDiagnosticCategory =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn parse_diagnostic_severity_serde_roundtrip() {
        for sev in [
            ParseDiagnosticSeverity::Error,
            ParseDiagnosticSeverity::Fatal,
        ] {
            let json = serde_json::to_string(&sev).expect("serde serialization should succeed");
            let back: ParseDiagnosticSeverity =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn parse_diagnostic_severity_as_str_all_distinct() {
        let strs: std::collections::BTreeSet<_> = [
            ParseDiagnosticSeverity::Error.as_str(),
            ParseDiagnosticSeverity::Fatal.as_str(),
        ]
        .into_iter()
        .collect();
        assert_eq!(strs.len(), 2);
    }

    #[test]
    fn parse_error_is_std_error() {
        let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "test.js", None);
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn taxonomy_rule_for_finds_matching_code() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        for code in &ParseErrorCode::ALL {
            let rule = taxonomy.rule_for(*code);
            assert!(rule.is_some(), "rule_for({:?}) returned None", code);
            assert_eq!(
                rule.expect("serde serialization should succeed")
                    .parse_error_code,
                *code
            );
        }
    }

    #[test]
    fn taxonomy_rule_for_severity_matches_code_method() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        for code in &ParseErrorCode::ALL {
            let rule = taxonomy
                .rule_for(*code)
                .expect("serde serialization should succeed");
            assert_eq!(rule.severity, code.diagnostic_severity());
            assert_eq!(rule.category, code.diagnostic_category());
        }
    }

    #[test]
    fn grammar_coverage_status_serde_all_variants_distinct() {
        let variants = [
            GrammarCoverageStatus::Supported,
            GrammarCoverageStatus::Partial,
            GrammarCoverageStatus::Unsupported,
            GrammarCoverageStatus::NotApplicable,
        ];
        let mut names = std::collections::BTreeSet::new();
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde serialization should succeed");
            let back: GrammarCoverageStatus =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(v, &back);
            names.insert(json);
        }
        assert_eq!(names.len(), variants.len());
    }

    #[test]
    fn grammar_family_coverage_partial_roundtrip() {
        let fam = GrammarFamilyCoverage {
            family_id: "expressions".to_string(),
            es2020_clause: "12.2".to_string(),
            script_goal: GrammarCoverageStatus::Partial,
            module_goal: GrammarCoverageStatus::Unsupported,
            notes: "WIP".to_string(),
        };
        let json = serde_json::to_string(&fam).expect("serde serialization should succeed");
        let back: GrammarFamilyCoverage =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(fam, back);
    }

    #[test]
    fn parse_error_display_includes_source_label() {
        let err = ParseError::new(
            ParseErrorCode::InvalidUtf8,
            "bad encoding",
            "input.js",
            None,
        );
        let display = err.to_string();
        assert!(display.contains("input.js"), "display: {display}");
    }

    #[test]
    fn canonicalize_whitespace_tabs_and_newlines() {
        assert_eq!(canonicalize_whitespace("a\t\nb"), "a b");
    }

    // -- Enrichment: PearlTower batch 2 (2026-02-26) --

    // -- parse_quoted_string edge cases --

    #[test]
    fn parse_quoted_string_too_short_returns_none() {
        assert!(parse_quoted_string("").is_none());
        assert!(parse_quoted_string("x").is_none());
    }

    #[test]
    fn parse_quoted_string_mismatched_quotes_returns_none() {
        assert!(parse_quoted_string("'hello\"").is_none());
        assert!(parse_quoted_string("\"hello'").is_none());
    }

    #[test]
    fn parse_quoted_string_with_embedded_newline_returns_none() {
        assert!(parse_quoted_string("'hel\nlo'").is_none());
        assert!(parse_quoted_string("\"hel\rlo\"").is_none());
    }

    #[test]
    fn parse_quoted_string_valid_extracts_inner() {
        assert_eq!(
            parse_quoted_string("'abc'").and_then(|value| value.as_str().map(str::to_string)),
            Some("abc".to_string())
        );
        assert_eq!(
            parse_quoted_string("\"xyz\"").and_then(|value| value.as_str().map(str::to_string)),
            Some("xyz".to_string())
        );
        assert_eq!(
            parse_quoted_string("''").and_then(|value| value.as_str().map(str::to_string)),
            Some(String::new())
        );
    }

    // -- parse_i64_numeric_literal edge cases --

    #[test]
    fn parse_i64_numeric_literal_bare_minus_returns_none() {
        assert!(parse_i64_numeric_literal("-").is_none());
    }

    #[test]
    fn parse_i64_numeric_literal_non_numeric_returns_none() {
        assert!(parse_i64_numeric_literal("abc").is_none());
        assert!(parse_i64_numeric_literal("12a").is_none());
        assert!(parse_i64_numeric_literal("-12a").is_none());
    }

    #[test]
    fn parse_i64_numeric_literal_valid_values() {
        assert_eq!(parse_i64_numeric_literal("0"), Some(0));
        assert_eq!(parse_i64_numeric_literal("42"), Some(42));
        assert_eq!(parse_i64_numeric_literal("-7"), Some(-7));
    }

    #[test]
    fn parse_i64_numeric_literal_hex() {
        assert_eq!(parse_i64_numeric_literal("0xFF"), Some(255));
        assert_eq!(parse_i64_numeric_literal("0x1A"), Some(26));
        assert_eq!(parse_i64_numeric_literal("0X10"), Some(16));
        assert_eq!(parse_i64_numeric_literal("-0xff"), Some(-255));
    }

    #[test]
    fn parse_i64_numeric_literal_octal() {
        assert_eq!(parse_i64_numeric_literal("0o77"), Some(63));
        assert_eq!(parse_i64_numeric_literal("0O10"), Some(8));
        assert_eq!(parse_i64_numeric_literal("-0o10"), Some(-8));
    }

    #[test]
    fn parse_i64_numeric_literal_binary() {
        assert_eq!(parse_i64_numeric_literal("0b1010"), Some(10));
        assert_eq!(parse_i64_numeric_literal("0B11111111"), Some(255));
        assert_eq!(parse_i64_numeric_literal("-0b100"), Some(-4));
    }

    #[test]
    fn parse_i64_numeric_literal_separators() {
        assert_eq!(parse_i64_numeric_literal("1_000"), Some(1000));
        assert_eq!(parse_i64_numeric_literal("0xFF_FF"), Some(65535));
    }

    /// `_n`, `_1`, `_0x1f` and `__n` are identifiers: a literal starts with a
    /// digit and a separator sits between two digits.
    #[test]
    fn identifiers_with_leading_underscores_are_not_numeric_literals() {
        for spelling in ["_1", "_0x1f", "1_", "1__0", "_", "0x_1"] {
            assert!(parse_i64_numeric_literal(spelling).is_none(), "{spelling}");
        }
        for spelling in ["_n", "__n", "_1n", "1_n"] {
            assert!(
                parse_bigint_numeric_literal(spelling).is_none(),
                "{spelling}"
            );
        }
        for spelling in ["_1.5", "1_.5", "-_2.5"] {
            assert!(parse_f64_numeric_literal(spelling).is_none(), "{spelling}");
        }
        assert_eq!(
            parse_bigint_numeric_literal("1_000n").as_deref(),
            Some("1000")
        );
        assert_eq!(parse_f64_numeric_literal("1_000.5"), Some(1000.5));
    }

    #[test]
    fn parse_i64_numeric_literal_invalid_bases() {
        assert!(parse_i64_numeric_literal("0x").is_none());
        assert!(parse_i64_numeric_literal("0o").is_none());
        assert!(parse_i64_numeric_literal("0b").is_none());
        assert!(parse_i64_numeric_literal("0xGG").is_none());
        assert!(parse_i64_numeric_literal("0o89").is_none());
        assert!(parse_i64_numeric_literal("0b23").is_none());
    }

    // -- parse_f64_numeric_literal tests --

    #[test]
    fn parse_f64_numeric_literal_decimal() {
        assert_eq!(parse_f64_numeric_literal("1.5"), Some(1.5));
        assert_eq!(parse_f64_numeric_literal("2.25"), Some(2.25));
        assert_eq!(parse_f64_numeric_literal("0.0"), Some(0.0));
    }

    #[test]
    fn parse_f64_numeric_literal_leading_dot() {
        assert_eq!(parse_f64_numeric_literal(".5"), Some(0.5));
        assert_eq!(parse_f64_numeric_literal(".123"), Some(0.123));
    }

    #[test]
    fn parse_f64_numeric_literal_trailing_dot() {
        assert_eq!(parse_f64_numeric_literal("1."), Some(1.0));
        assert_eq!(parse_f64_numeric_literal("42."), Some(42.0));
    }

    #[test]
    fn parse_f64_numeric_literal_scientific() {
        assert_eq!(parse_f64_numeric_literal("1e10"), Some(1e10));
        assert_eq!(parse_f64_numeric_literal("1E10"), Some(1e10));
        assert_eq!(parse_f64_numeric_literal("1.5e-3"), Some(1.5e-3));
        assert_eq!(parse_f64_numeric_literal("2.5E+2"), Some(250.0));
    }

    #[test]
    fn parse_f64_numeric_literal_special_values() {
        assert_eq!(parse_f64_numeric_literal("Infinity"), Some(f64::INFINITY));
        assert_eq!(
            parse_f64_numeric_literal("-Infinity"),
            Some(f64::NEG_INFINITY)
        );
        assert!(
            parse_f64_numeric_literal("NaN")
                .expect("serde serialization should succeed")
                .is_nan()
        );
    }

    #[test]
    fn parse_f64_numeric_literal_with_separators() {
        assert_eq!(parse_f64_numeric_literal("1_000.5"), Some(1000.5));
        assert_eq!(parse_f64_numeric_literal("1.5_00"), Some(1.5));
        // bd-9vouw.176: a literal may start with its decimal point (Node
        // v22.2.0 values); `._1` is not a literal.
        assert_eq!(parse_f64_numeric_literal(".0_1e2"), Some(1.0));
        assert_eq!(parse_f64_numeric_literal(".1_01e2"), Some(10.1));
        assert_eq!(parse_f64_numeric_literal(".00_01e2"), Some(0.01));
        assert_eq!(parse_f64_numeric_literal(".5_5"), Some(0.55));
        assert_eq!(parse_f64_numeric_literal("._1"), None);
    }

    #[test]
    fn parse_f64_numeric_literal_integer_without_dot_or_exp_returns_none() {
        // Pure integers should be handled by parse_i64_numeric_literal
        assert!(parse_f64_numeric_literal("42").is_none());
        assert!(parse_f64_numeric_literal("0xFF").is_none());
    }

    #[test]
    fn integer_literals_beyond_i64_are_numbers_bd_6vl81() {
        // These used to fall through to Expression::Raw and evaluate as
        // strings. Expected values are Node's (v22.2.0) Number results.
        assert_eq!(
            parse_f64_numeric_literal("123456789012345680000"),
            Some(123_456_789_012_345_680_000.0)
        );
        assert_eq!(
            parse_f64_numeric_literal("9223372036854775808"),
            Some(9_223_372_036_854_775_808.0)
        );
        assert_eq!(
            parse_f64_numeric_literal("-9223372036854775809"),
            Some(-9_223_372_036_854_775_808.0)
        );
        assert_eq!(
            parse_f64_numeric_literal("0xFFFFFFFFFFFFFFFFF"),
            Some(295_147_905_179_352_830_000.0)
        );
        assert_eq!(
            parse_f64_numeric_literal("0b1"),
            None,
            "an i64-representable radix literal stays an integer"
        );
        assert_eq!(
            parse_f64_numeric_literal("1_000_000_000_000_000_000_000"),
            Some(1e21)
        );
        assert!(parse_f64_numeric_literal("0xZZ").is_none());

        let tree = CanonicalEs2020Parser
            .parse("const n = 123456789012345680000;", ParseGoal::Script)
            .expect("large integer literal parses");
        assert!(
            !format!("{:?}", tree.canonical_value()).contains("\"raw\""),
            "a large integer literal must not become Expression::Raw"
        );
    }

    #[test]
    fn bigint_radix_literals_parse_exactly_bd_6vl81() {
        // `e`/`E` are hex digits: this used to be rejected as an exponent.
        assert_eq!(
            parse_bigint_numeric_literal("0xFEDCBA9876543210n").as_deref(),
            Some("18364758544493064720")
        );
        assert_eq!(parse_bigint_numeric_literal("0xen").as_deref(), Some("14"));
        assert_eq!(
            parse_bigint_numeric_literal("-0xFFn").as_deref(),
            Some("-255")
        );
        // Past u128 the conversion stays exact (expected values from Python
        // arbitrary-precision integers).
        assert_eq!(
            parse_bigint_numeric_literal(&format!("0x{}n", "FEDCBA9876543210".repeat(3)))
                .as_deref(),
            Some("6249203505451628849692820439375744481966954417427815084560")
        );
        assert_eq!(
            parse_bigint_numeric_literal(&format!("0o{}n", "7".repeat(50))).as_deref(),
            Some("1427247692705959881058285969449495136382746623")
        );
        assert_eq!(
            parse_bigint_numeric_literal(&format!("0b{}n", "1".repeat(130))).as_deref(),
            Some("1361129467683753853853498429727072845823")
        );
        // Decimal exponents and fractions are still not BigInt literals.
        assert!(parse_bigint_numeric_literal("1e5n").is_none());
        assert!(parse_bigint_numeric_literal("1.5n").is_none());
        assert!(parse_bigint_numeric_literal("0xGn").is_none());
    }

    #[test]
    fn parse_f64_numeric_literal_empty_returns_none() {
        assert!(parse_f64_numeric_literal("").is_none());
        assert!(parse_f64_numeric_literal("   ").is_none());
    }

    // -- split_statement_segments with nested delimiters --

    #[test]
    fn split_statement_segments_semicolon_inside_parens_does_not_split() {
        let segments = split_statement_segments("f(a;b);x");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].2, "f(a;b)");
        assert_eq!(segments[1].2, "x");
    }

    #[test]
    fn split_statement_segments_semicolon_inside_brackets_does_not_split() {
        let segments = split_statement_segments("a[b;c];d");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].2, "a[b;c]");
        assert_eq!(segments[1].2, "d");
    }

    #[test]
    fn split_statement_segments_semicolon_inside_braces_does_not_split() {
        let segments = split_statement_segments("{a;b};c");
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].2, "{a;b}");
        assert_eq!(segments[1].2, "c");
    }

    #[test]
    fn split_statement_segments_escape_in_string_does_not_close_quote() {
        let segments = split_statement_segments(r#"'a\'b';x"#);
        assert_eq!(segments.len(), 2);
    }

    // -- ParseFailureWitness::canonical_value --

    #[test]
    fn parse_failure_witness_canonical_value_has_expected_keys() {
        let witness = ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: Some(ParseBudgetKind::SourceBytes),
            source_bytes: 100,
            token_count: 10,
            max_recursion_observed: 5,
            max_source_bytes: 1_048_576,
            max_token_count: 65_536,
            max_recursion_depth: 256,
        };
        let cv = witness.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("mode"));
            assert!(map.contains_key("budget_kind"));
            assert!(map.contains_key("source_bytes"));
            assert!(map.contains_key("token_count"));
            assert!(map.contains_key("max_recursion_observed"));
            assert!(map.contains_key("max_source_bytes"));
            assert!(map.contains_key("max_token_count"));
            assert!(map.contains_key("max_recursion_depth"));
        } else {
            panic!("expected CanonicalValue::Map");
        }
    }

    #[test]
    fn parse_failure_witness_canonical_value_null_budget_kind() {
        let witness = ParseFailureWitness {
            mode: ParserMode::ScalarReference,
            budget_kind: None,
            source_bytes: 0,
            token_count: 0,
            max_recursion_observed: 0,
            max_source_bytes: 0,
            max_token_count: 0,
            max_recursion_depth: 0,
        };
        let cv = witness.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert_eq!(map.get("budget_kind"), Some(&CanonicalValue::Null));
        } else {
            panic!("expected CanonicalValue::Map");
        }
    }

    // -- materialize_from_syntax_tree --

    #[test]
    fn materialize_from_syntax_tree_succeeds_for_valid_ir() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export default 42", ParseGoal::Module)
            .expect("parse");
        let ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        let materialized = ir
            .materialize_from_syntax_tree(&tree)
            .expect("should succeed");
        assert_eq!(
            materialized.syntax_tree.canonical_hash(),
            tree.canonical_hash()
        );
        assert_eq!(materialized.statement_nodes.len(), tree.body.len());
    }

    // -- ParseEventIr::from_parse_source --

    #[test]
    fn parse_event_ir_from_parse_source_has_source_text_payload() {
        let parser = CanonicalEs2020Parser;
        let source = "true";
        let tree = parser.parse(source, ParseGoal::Script).expect("parse");
        let ir =
            ParseEventIr::from_parse_source(&tree, source, "<inline>", ParserMode::ScalarReference);
        assert_eq!(ir.events[0].payload_kind.as_deref(), Some("source_text"));
        assert!(ir.events[0].payload_hash.is_some());
    }

    // -- Materialization error cases --

    #[test]
    fn materialize_rejects_unsupported_contract_version() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.contract_version = "bogus".to_string();
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("unsupported contract");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::UnsupportedContractVersion
        );
    }

    #[test]
    fn materialize_rejects_unsupported_schema_version() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.schema_version = "bogus".to_string();
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("unsupported schema");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::UnsupportedSchemaVersion
        );
    }

    #[test]
    fn materialize_rejects_goal_mismatch() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.goal = ParseGoal::Module;
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("goal mismatch");
        assert_eq!(err.code, ParseEventMaterializationErrorCode::GoalMismatch);
    }

    #[test]
    fn materialize_rejects_empty_event_stream() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        ir.events.clear();
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("empty events");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::MissingParseStarted
        );
    }

    #[test]
    fn materialize_rejects_missing_parse_started() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        // Replace first event with a non-ParseStarted event
        ir.events[0].kind = ParseEventKind::ParseCompleted;
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("missing parse_started");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::MissingParseStarted
        );
    }

    #[test]
    fn materialize_rejects_missing_parse_completed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        let last_idx = ir.events.len() - 1;
        ir.events[last_idx].kind = ParseEventKind::ParseStarted;
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("missing parse_completed");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::MissingParseCompleted
        );
    }

    #[test]
    fn materialize_rejects_invalid_event_sequence() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        // Create a gap in sequence numbers
        if ir.events.len() > 2 {
            ir.events[1].sequence = 99;
        }
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("invalid sequence");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::InvalidEventSequence
        );
    }

    #[test]
    fn materialize_rejects_inconsistent_event_envelope() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("42", ParseGoal::Script).expect("parse");
        let mut ir = ParseEventIr::from_syntax_tree(&tree, "<inline>", ParserMode::ScalarReference);
        if ir.events.len() > 1 {
            ir.events[1].trace_id = "rogue-trace".to_string();
        }
        let err = ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("inconsistent envelope");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::InconsistentEventEnvelope
        );
    }

    #[test]
    fn materialize_from_source_rejects_mode_mismatch() {
        let parser = CanonicalEs2020Parser;
        let source = "42";
        let options = ParserOptions::default();
        let (result, event_ir) = parser.parse_with_event_ir(source, ParseGoal::Script, &options);
        result.expect("parse should succeed");
        // ParserMode only has ScalarReference today, so we cannot test a
        // true mode mismatch.  Instead we trigger a materializer rejection
        // via statement-count mismatch (removing events from the IR).
        let mut modified_ir = event_ir;
        let tree = parser.parse(source, ParseGoal::Script).expect("parse");
        // Remove a statement event to trigger count mismatch
        modified_ir
            .events
            .retain(|event| event.kind != ParseEventKind::StatementParsed);
        // Re-number sequences for the retained events
        for (i, event) in modified_ir.events.iter_mut().enumerate() {
            event.sequence = i as u64;
        }
        let err = modified_ir
            .materialize_from_syntax_tree(&tree)
            .expect_err("statement count mismatch");
        assert_eq!(
            err.code,
            ParseEventMaterializationErrorCode::StatementCountMismatch
        );
    }

    // -- Source bytes budget exhaustion --

    #[test]
    fn source_bytes_budget_exhaustion() {
        let parser = CanonicalEs2020Parser;
        let options = ParserOptions {
            mode: ParserMode::ScalarReference,
            budget: ParserBudget {
                max_source_bytes: 2,
                max_token_count: 65_536,
                max_recursion_depth: 256,
            },
        };
        let err = parser
            .parse_with_options("long source text", ParseGoal::Script, &options)
            .expect_err("source bytes budget should fail");
        assert_eq!(err.code, ParseErrorCode::BudgetExceeded);
        let witness = err.witness.expect("should have witness");
        assert_eq!(witness.budget_kind, Some(ParseBudgetKind::SourceBytes));
        assert!(witness.source_bytes > witness.max_source_bytes);
    }

    // -- GrammarCompletenessMatrix::summary edge cases --

    #[test]
    fn grammar_completeness_summary_empty_families() {
        let matrix = GrammarCompletenessMatrix {
            schema_version: GrammarCompletenessMatrix::SCHEMA_VERSION.to_string(),
            parser_mode: ParserMode::ScalarReference,
            families: vec![],
        };
        let summary = matrix.summary();
        assert_eq!(summary.family_count, 0);
        assert_eq!(summary.completeness_millionths, 0);
    }

    #[test]
    fn grammar_completeness_summary_all_supported() {
        let matrix = GrammarCompletenessMatrix {
            schema_version: GrammarCompletenessMatrix::SCHEMA_VERSION.to_string(),
            parser_mode: ParserMode::ScalarReference,
            families: vec![GrammarFamilyCoverage {
                family_id: "test".to_string(),
                es2020_clause: "1.0".to_string(),
                script_goal: GrammarCoverageStatus::Supported,
                module_goal: GrammarCoverageStatus::Supported,
                notes: String::new(),
            }],
        };
        let summary = matrix.summary();
        assert_eq!(summary.family_count, 1);
        assert_eq!(summary.supported_families, 1);
        assert_eq!(summary.unsupported_families, 0);
        assert_eq!(summary.completeness_millionths, 1_000_000);
    }

    // -- advance_utf8_boundary_safe --

    #[test]
    fn advance_utf8_boundary_safe_past_end_returns_len() {
        let bytes = b"abc";
        assert_eq!(advance_utf8_boundary_safe(bytes, 3), 3);
        assert_eq!(advance_utf8_boundary_safe(bytes, 5), 3);
    }

    #[test]
    fn advance_utf8_boundary_safe_ascii_advances_one() {
        let bytes = b"abc";
        assert_eq!(advance_utf8_boundary_safe(bytes, 0), 1);
    }

    #[test]
    fn advance_utf8_boundary_safe_multibyte() {
        // é is two bytes: 0xC3 0xA9
        let bytes = "é".as_bytes();
        assert_eq!(bytes.len(), 2);
        assert_eq!(advance_utf8_boundary_safe(bytes, 0), 2);
    }

    // -- count_lexical_tokens edge cases --

    #[test]
    fn count_lexical_tokens_empty_returns_zero() {
        assert_eq!(count_lexical_tokens(""), 0);
    }

    #[test]
    fn count_lexical_tokens_whitespace_only_returns_zero() {
        assert_eq!(count_lexical_tokens("   \t\n  "), 0);
    }

    #[test]
    fn count_lexical_tokens_two_char_operators() {
        // == is one token, a is one, b is one => 3
        assert_eq!(count_lexical_tokens("a==b"), 3);
    }

    // -- export empty clause rejected --

    #[test]
    fn export_empty_clause_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("export ", ParseGoal::Module)
            .expect_err("empty export clause");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // -- statement_kind_label --

    #[test]
    fn statement_kind_label_covers_all_variants() {
        let span = SourceSpan::new(0, 1, 1, 1, 1, 1);
        assert_eq!(
            statement_kind_label(&Statement::Import(ImportDeclaration {
                clause: ImportClause::SideEffect,
                binding: None,
                source: "m".into(),
                span: span.clone(),
            })),
            "import"
        );
        assert_eq!(
            statement_kind_label(&Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{}".into()),
                span: span.clone(),
            })),
            "export"
        );
        assert_eq!(
            statement_kind_label(&Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Var,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("x".to_string()),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: span.clone(),
                }],
                span: span.clone(),
            })),
            "variable_declaration"
        );
        assert_eq!(
            statement_kind_label(&Statement::Expression(ExpressionStatement {
                expression: Expression::NullLiteral,
                span,
            })),
            "expression"
        );
    }

    // -- ParseDiagnosticEnvelope canonical_value key coverage --

    #[test]
    fn parse_diagnostic_envelope_canonical_value_has_all_keys() {
        let err = ParseError::new(ParseErrorCode::EmptySource, "empty", "<inline>", None);
        let envelope = normalize_parse_error(&err);
        let cv = envelope.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            for key in [
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
            ] {
                assert!(map.contains_key(key), "missing key: {key}");
            }
        } else {
            panic!("expected CanonicalValue::Map");
        }
    }

    // -- Enrichment: serde roundtrips for untested types (PearlTower 2026-02-27) --

    #[test]
    fn parse_event_serde_roundtrip() {
        let e = ParseEvent {
            sequence: 1,
            kind: ParseEventKind::StatementParsed,
            parser_mode: ParserMode::ScalarReference,
            goal: ParseGoal::Script,
            source_label: "test.js".to_string(),
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "parser".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            statement_index: Some(0),
            span: Some(SourceSpan::new(0, 10, 1, 1, 1, 11)),
            payload_kind: Some("statement".to_string()),
            payload_hash: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&e).expect("serde serialization should succeed");
        let back: ParseEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(e, back);
    }

    #[test]
    fn parse_event_minimal_serde_roundtrip() {
        let e = ParseEvent {
            sequence: 0,
            kind: ParseEventKind::ParseStarted,
            parser_mode: ParserMode::ScalarReference,
            goal: ParseGoal::Module,
            source_label: "mod.js".to_string(),
            trace_id: "t-2".to_string(),
            decision_id: "d-2".to_string(),
            policy_id: "p-2".to_string(),
            component: "parser".to_string(),
            outcome: "started".to_string(),
            error_code: None,
            statement_index: None,
            span: None,
            payload_kind: None,
            payload_hash: None,
        };
        let json = serde_json::to_string(&e).expect("serde serialization should succeed");
        let back: ParseEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(e, back);
    }

    #[test]
    fn materialized_statement_node_serde_roundtrip() {
        let n = MaterializedStatementNode {
            node_id: "node-001".to_string(),
            sequence: 1,
            statement_index: 0,
            payload_hash: "hash-abc".to_string(),
            span: SourceSpan::new(0, 20, 1, 1, 1, 21),
        };
        let json = serde_json::to_string(&n).expect("serde serialization should succeed");
        let back: MaterializedStatementNode =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(n, back);
    }

    #[test]
    fn materialized_syntax_tree_serde_roundtrip() {
        let tree = MaterializedSyntaxTree {
            schema_version: MaterializedSyntaxTree::schema_version().to_string(),
            contract_version: MaterializedSyntaxTree::contract_version().to_string(),
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "parser".to_string(),
            parser_mode: ParserMode::ScalarReference,
            goal: ParseGoal::Script,
            source_label: "test.js".to_string(),
            root_node_id: "root-001".to_string(),
            statement_nodes: vec![MaterializedStatementNode {
                node_id: "node-001".to_string(),
                sequence: 1,
                statement_index: 0,
                payload_hash: "hash-abc".to_string(),
                span: SourceSpan::new(0, 10, 1, 1, 1, 11),
            }],
            syntax_tree: SyntaxTree {
                goal: ParseGoal::Script,
                body: vec![],
                span: SourceSpan::new(0, 10, 1, 1, 1, 11),
            },
        };
        let json = serde_json::to_string(&tree).expect("serde serialization should succeed");
        let back: MaterializedSyntaxTree =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(tree, back);
        assert_eq!(back.statement_nodes.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: binary expression parsing (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    fn parse_script(source: &str) -> SyntaxTree {
        let parser = CanonicalEs2020Parser;
        parser
            .parse(source, ParseGoal::Script)
            .expect("parse should succeed")
    }

    fn parse_single_script_statement(source: &str) -> ParseResult<Statement> {
        let options = ParserOptions::default();
        let span = SourceSpan::new(0, source.len() as u64, 1, 1, 1, source.len() as u64 + 1);
        let mut context = ParseExecutionContext {
            source_label: "test.js",
            options: &options,
            source_bytes: source.len() as u64,
            token_count: 0,
            max_recursion_observed: 0,
            statement_depth: 0,
            pattern_depth: 0,
            strict_mode: false,
            super_property_allowed: false,
            await_context: false,
            yield_context: false,
            super_call: SuperCallContext::Forbidden,
            static_block_await: false,
            formal_parameters: false,
            private_name_scopes: Vec::new(),
            function_sources: FunctionSourceMap::default(),
        };
        parse_statement(source, ParseGoal::Script, span, &mut context)
    }

    fn first_expr(tree: &SyntaxTree) -> &Expression {
        match &tree.body[0] {
            Statement::Expression(es) => &es.expression,
            other => panic!("expected Expression statement, got {:?}", other),
        }
    }

    // bd-fqlfw.1.1 (E1.T1): expression-level Member/Call nodes — the carriers of
    // capability/IFC-relevant accessors (`process.env.X`, bare `eval(...)`) — carry
    // a `SourceSpan` populated by the parser. Spans are currently statement-granular
    // (the enclosing source region); precise sub-expression offsets are a follow-up.
    #[test]
    fn member_and_call_expressions_carry_source_spans_bd_fqlfw_1_1() {
        // `process.env.HOME` parses to a Member accessor that carries a span.
        let src = "process.env.HOME";
        let tree = parse_script(src);
        let Statement::Expression(stmt) = &tree.body[0] else {
            panic!("expected expression statement");
        };
        let stmt_span = stmt.span;
        match &stmt.expression {
            Expression::Member { span, .. } => {
                let span = span.expect("parser must populate Member span");
                // The accessor span maps onto the real source region.
                assert_eq!(span, stmt_span, "member span maps to the source region");
                assert!(
                    span.start_offset <= span.end_offset && span.end_offset <= src.len() as u64 + 1,
                    "member span must map into source offsets (got {span:?})"
                );
            }
            other => panic!("expected Member, got {other:?}"),
        }

        // A bare `eval(...)` call — a dynamic-code accessor — also carries a span.
        let src = "eval(\"x\")";
        let tree = parse_script(src);
        match first_expr(&tree) {
            Expression::Call { span, .. } => {
                let span = span.expect("parser must populate Call span");
                assert!(
                    span.start_offset <= span.end_offset && span.end_offset <= src.len() as u64 + 1,
                    "call span must map into source offsets (got {span:?})"
                );
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn binary_addition() {
        let tree = parse_script("a + b");
        match first_expr(&tree) {
            Expression::Binary {
                operator,
                left,
                right,
            } => {
                assert_eq!(*operator, BinaryOperator::Add);
                assert!(matches!(left.as_ref(), Expression::Identifier(n) if n == "a"));
                assert!(matches!(right.as_ref(), Expression::Identifier(n) if n == "b"));
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_precedence_mul_over_add() {
        // a + b * c should parse as a + (b * c)
        let tree = parse_script("a + b * c");
        match first_expr(&tree) {
            Expression::Binary {
                operator,
                left,
                right,
            } => {
                assert_eq!(*operator, BinaryOperator::Add);
                assert!(matches!(left.as_ref(), Expression::Identifier(n) if n == "a"));
                match right.as_ref() {
                    Expression::Binary {
                        operator: inner_op, ..
                    } => {
                        assert_eq!(*inner_op, BinaryOperator::Multiply);
                    }
                    other => panic!("expected Binary for rhs, got {other:?}"),
                }
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_strict_equality() {
        let tree = parse_script("x === y");
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, BinaryOperator::StrictEqual);
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_logical_and() {
        let tree = parse_script("a && b");
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, BinaryOperator::LogicalAnd);
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_logical_or() {
        let tree = parse_script("a || b");
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, BinaryOperator::LogicalOr);
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_nullish_coalescing() {
        let tree = parse_script("a ?? b");
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, BinaryOperator::NullishCoalescing);
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_comparison_operators() {
        for (src, expected_op) in [
            ("a < b", BinaryOperator::LessThan),
            ("a > b", BinaryOperator::GreaterThan),
            ("a <= b", BinaryOperator::LessThanOrEqual),
            ("a >= b", BinaryOperator::GreaterThanOrEqual),
            ("a == b", BinaryOperator::Equal),
            ("a != b", BinaryOperator::NotEqual),
            ("a !== b", BinaryOperator::StrictNotEqual),
        ] {
            let tree = parse_script(src);
            match first_expr(&tree) {
                Expression::Binary { operator, .. } => {
                    assert_eq!(*operator, expected_op, "failed for: {src}");
                }
                other => panic!("expected Binary for {src}, got {other:?}"),
            }
        }
    }

    #[test]
    fn binary_bitwise_operators() {
        for (src, expected_op) in [
            ("a & b", BinaryOperator::BitwiseAnd),
            ("a | b", BinaryOperator::BitwiseOr),
            ("a ^ b", BinaryOperator::BitwiseXor),
            ("a << b", BinaryOperator::LeftShift),
            ("a >> b", BinaryOperator::RightShift),
            ("a >>> b", BinaryOperator::UnsignedRightShift),
        ] {
            let tree = parse_script(src);
            match first_expr(&tree) {
                Expression::Binary { operator, .. } => {
                    assert_eq!(*operator, expected_op, "failed for: {src}");
                }
                other => panic!("expected Binary for {src}, got {other:?}"),
            }
        }
    }

    #[test]
    fn unary_logical_not() {
        let tree = parse_script("!x");
        match first_expr(&tree) {
            Expression::Unary { operator, argument } => {
                assert_eq!(*operator, UnaryOperator::LogicalNot);
                assert!(matches!(argument.as_ref(), Expression::Identifier(n) if n == "x"));
            }
            other => panic!("expected Unary, got {other:?}"),
        }
    }

    #[test]
    fn unary_bitwise_not() {
        let tree = parse_script("~x");
        match first_expr(&tree) {
            Expression::Unary { operator, .. } => {
                assert_eq!(*operator, UnaryOperator::BitwiseNot);
            }
            other => panic!("expected Unary, got {other:?}"),
        }
    }

    #[test]
    fn unary_typeof() {
        let tree = parse_script("typeof x");
        match first_expr(&tree) {
            Expression::Unary { operator, argument } => {
                assert_eq!(*operator, UnaryOperator::Typeof);
                assert!(matches!(argument.as_ref(), Expression::Identifier(n) if n == "x"));
            }
            other => panic!("expected Unary, got {other:?}"),
        }
    }

    #[test]
    fn unary_void() {
        let tree = parse_script("void 0");
        match first_expr(&tree) {
            Expression::Unary { operator, argument } => {
                assert_eq!(*operator, UnaryOperator::Void);
                assert!(matches!(argument.as_ref(), Expression::NumericLiteral(0)));
            }
            other => panic!("expected Unary, got {other:?}"),
        }
    }

    #[test]
    fn unary_delete() {
        let tree = parse_script("delete obj");
        match first_expr(&tree) {
            Expression::Unary { operator, .. } => {
                assert_eq!(*operator, UnaryOperator::Delete);
            }
            other => panic!("expected Unary, got {other:?}"),
        }
    }

    #[test]
    fn assignment_simple() {
        let tree = parse_script("x = 42");
        match first_expr(&tree) {
            Expression::Assignment {
                operator,
                left,
                right,
                assignment_strictness,
            } => {
                assert_eq!(*operator, AssignmentOperator::Assign);
                assert_eq!(*assignment_strictness, AssignmentStrictness::Sloppy);
                assert!(matches!(left.as_ref(), Expression::Identifier(n) if n == "x"));
                assert!(matches!(right.as_ref(), Expression::NumericLiteral(42)));
            }
            other => panic!("expected Assignment, got {other:?}"),
        }
    }

    #[test]
    fn assignment_add_assign() {
        let tree = parse_script("x += 1");
        match first_expr(&tree) {
            Expression::Assignment { operator, .. } => {
                assert_eq!(*operator, AssignmentOperator::AddAssign);
            }
            other => panic!("expected Assignment, got {other:?}"),
        }
    }

    #[test]
    fn assignment_strictness_preserves_exact_directive_provenance_bd_0k19b() {
        let strict = parse_script(r#""use strict"; target = 1;"#);
        assert!(matches!(
            &strict.body[1],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment {
                    assignment_strictness: AssignmentStrictness::Strict,
                    ..
                },
                ..
            })
        ));

        let escaped = parse_script(r#""use\x20strict"; target = 1;"#);
        assert!(matches!(
            &escaped.body[1],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment {
                    assignment_strictness: AssignmentStrictness::Sloppy,
                    ..
                },
                ..
            })
        ));

        let module = CanonicalEs2020Parser
            .parse("target = 1;", ParseGoal::Module)
            .expect("module assignment should parse");
        assert!(matches!(
            &module.body[0],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment {
                    assignment_strictness: AssignmentStrictness::Strict,
                    ..
                },
                ..
            })
        ));

        let inherited = parse_script(r#""use strict"; function f() { target = 1; }"#);
        let Statement::FunctionDeclaration(function) = &inherited.body[1] else {
            panic!("expected function declaration");
        };
        assert!(matches!(
            &function.body.body[0],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment {
                    assignment_strictness: AssignmentStrictness::Strict,
                    ..
                },
                ..
            })
        ));

        let function_local = parse_script(r#"function f() { "use strict"; target = 1; }"#);
        let Statement::FunctionDeclaration(function) = &function_local.body[0] else {
            panic!("expected function declaration");
        };
        assert!(matches!(
            &function.body.body[1],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment {
                    assignment_strictness: AssignmentStrictness::Strict,
                    ..
                },
                ..
            })
        ));

        let strict_loops =
            parse_script(r#""use strict"; for (key in object) {} for (value of values) {}"#);
        assert!(matches!(
            &strict_loops.body[1],
            Statement::ForIn(ForInStatement {
                assignment_strictness: AssignmentStrictness::Strict,
                ..
            })
        ));
        assert!(matches!(
            &strict_loops.body[2],
            Statement::ForOf(ForOfStatement {
                assignment_strictness: AssignmentStrictness::Strict,
                ..
            })
        ));

        let strict_update = parse_script(r#""use strict"; ++target;"#);
        assert!(matches!(
            &strict_update.body[1],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment {
                    assignment_strictness: AssignmentStrictness::Strict,
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn ternary_conditional() {
        let tree = parse_script("a ? b : c");
        match first_expr(&tree) {
            Expression::Conditional {
                test,
                consequent,
                alternate,
            } => {
                assert!(matches!(test.as_ref(), Expression::Identifier(n) if n == "a"));
                assert!(matches!(consequent.as_ref(), Expression::Identifier(n) if n == "b"));
                assert!(matches!(alternate.as_ref(), Expression::Identifier(n) if n == "c"));
            }
            other => panic!("expected Conditional, got {other:?}"),
        }
    }

    #[test]
    fn call_expression_no_args() {
        let tree = parse_script("foo()");
        match first_expr(&tree) {
            Expression::Call {
                callee, arguments, ..
            } => {
                assert!(matches!(callee.as_ref(), Expression::Identifier(n) if n == "foo"));
                assert!(arguments.is_empty());
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn call_expression_with_args() {
        let tree = parse_script("foo(1, 2)");
        match first_expr(&tree) {
            Expression::Call {
                callee, arguments, ..
            } => {
                assert!(matches!(callee.as_ref(), Expression::Identifier(n) if n == "foo"));
                assert_eq!(arguments.len(), 2);
                assert!(matches!(&arguments[0], Expression::NumericLiteral(1)));
                assert!(matches!(&arguments[1], Expression::NumericLiteral(2)));
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn member_expression_dot() {
        let tree = parse_script("obj.prop");
        match first_expr(&tree) {
            Expression::Member {
                object,
                property,
                computed,
                ..
            } => {
                assert!(matches!(object.as_ref(), Expression::Identifier(n) if n == "obj"));
                assert!(matches!(property.as_ref(), Expression::Identifier(n) if n == "prop"));
                assert!(!computed);
            }
            other => panic!("expected Member, got {other:?}"),
        }
    }

    #[test]
    fn member_expression_computed() {
        let tree = parse_script("arr[0]");
        match first_expr(&tree) {
            Expression::Member {
                object,
                property,
                computed,
                ..
            } => {
                assert!(matches!(object.as_ref(), Expression::Identifier(n) if n == "arr"));
                assert!(matches!(property.as_ref(), Expression::NumericLiteral(0)));
                assert!(computed);
            }
            other => panic!("expected Member, got {other:?}"),
        }
    }

    /// `this` is sloppy in a script and strict in a module or after a
    /// "use strict" directive (bd-9vouw.118).
    #[test]
    fn this_expression() {
        let tree = parse_script("this");
        assert!(matches!(first_expr(&tree), Expression::SloppyThis));
        let strict = parse_script("'use strict'; this");
        assert!(matches!(
            &strict.body[1],
            Statement::Expression(statement) if matches!(statement.expression, Expression::This)
        ));
    }

    #[test]
    fn array_literal_empty() {
        let tree = parse_script("[]");
        match first_expr(&tree) {
            Expression::ArrayLiteral(elements) => {
                assert!(elements.is_empty());
            }
            other => panic!("expected ArrayLiteral, got {other:?}"),
        }
    }

    #[test]
    fn array_literal_with_elements() {
        let tree = parse_script("[1, 2, 3]");
        match first_expr(&tree) {
            Expression::ArrayLiteral(elements) => {
                assert_eq!(elements.len(), 3);
            }
            other => panic!("expected ArrayLiteral, got {other:?}"),
        }
    }

    #[test]
    fn object_literal_empty() {
        let tree = parse_script("({})");
        match first_expr(&tree) {
            Expression::ObjectLiteral(properties) => {
                assert!(properties.is_empty());
            }
            other => panic!("expected ObjectLiteral, got {other:?}"),
        }
    }

    #[test]
    fn object_literal_plain_method_shorthand() {
        // bd-bg9l1.27.3 / DISC-003 / bd-gqaa4: `name() {}` must retain its
        // method identity, not collapse to a data property or shorthand identifier.
        let tree = parse_script("({ next() { return 1; } })");
        match first_expr(&tree) {
            Expression::ObjectLiteral(properties) => {
                assert_eq!(properties.len(), 1);
                let prop = &properties[0];
                assert!(!prop.computed);
                assert!(!prop.shorthand);
                assert_eq!(prop.kind, ObjectPropertyKind::Method);
                assert!(matches!(&prop.key, Expression::Identifier(n) if n == "next"));
                assert!(
                    matches!(&prop.value, Expression::Function { .. }),
                    "method value should be a function, got {:?}",
                    prop.value
                );
            }
            other => panic!("expected ObjectLiteral, got {other:?}"),
        }

        let explicit = parse_script("({ next: function() { return 1; } })");
        let Expression::ObjectLiteral(explicit_properties) = first_expr(&explicit) else {
            panic!("expected explicit-function object literal");
        };
        assert_eq!(explicit_properties[0].kind, ObjectPropertyKind::Data);
        assert_ne!(
            first_expr(&tree).canonical_value(),
            first_expr(&explicit).canonical_value(),
            "concise method syntax must remain distinct from a function-valued data property"
        );
    }

    #[test]
    fn object_literal_computed_method_shorthand() {
        // bd-bg9l1.27.3 / DISC-003: `[expr]() {}` must parse as a computed
        // method with a function value.
        let tree = parse_script("({ [Symbol.iterator]() { return 1; } })");
        match first_expr(&tree) {
            Expression::ObjectLiteral(properties) => {
                assert_eq!(properties.len(), 1);
                let prop = &properties[0];
                assert!(prop.computed);
                assert!(!prop.shorthand);
                assert_eq!(prop.kind, ObjectPropertyKind::Method);
                assert!(matches!(&prop.key, Expression::Member { .. }));
                assert!(
                    matches!(&prop.value, Expression::Function { .. }),
                    "computed method value should be a function, got {:?}",
                    prop.value
                );
            }
            other => panic!("expected ObjectLiteral, got {other:?}"),
        }
    }

    #[test]
    fn object_method_super_property_is_contextual_bd_gqaa4() {
        let tree = parse_script("({ value() { return super.value(); } })");
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected object literal");
        };
        let Expression::Function { body, .. } = &properties[0].value else {
            panic!("expected concise-method function body");
        };
        let Statement::Return(ReturnStatement {
            argument: Some(Expression::Call { callee, .. }),
            ..
        }) = &body.body[0]
        else {
            panic!("expected return of super method call");
        };
        assert!(matches!(
            callee.as_ref(),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::Super)
        ));
        CanonicalEs2020Parser
            .parse(
                "let saved; ({ value() { saved = () => super.value(); } })",
                ParseGoal::Script,
            )
            .expect("a nested arrow must retain the enclosing method's super context");
        CanonicalEs2020Parser
            .parse(
                "let saved; ({ value() { saved = async () => super.value(); } })",
                ParseGoal::Script,
            )
            .expect("a nested async arrow must retain the enclosing method's super context");

        assert!(
            CanonicalEs2020Parser
                .parse("super.value()", ParseGoal::Script)
                .is_err(),
            "super-property syntax must remain rejected without method context"
        );
        assert!(
            CanonicalEs2020Parser
                .parse(
                    "({ value() { return function () { return super.value(); }; } })",
                    ParseGoal::Script,
                )
                .is_err(),
            "an ordinary nested function must not inherit the method's super binding"
        );
    }

    #[test]
    fn object_async_and_generator_methods_parse_bd_6vl81() {
        let tree = parse_script(
            "({ async m() { await 1; }, *g() { yield 1; }, async *h() { yield 2; }, \
             async [k]() {}, async() {}, async: 1, async })",
        );
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected object literal");
        };
        let flags: Vec<Option<(bool, bool)>> = properties
            .iter()
            .map(|property| match &property.value {
                Expression::Function {
                    is_async,
                    is_generator,
                    ..
                } => Some((*is_async, *is_generator)),
                _ => None,
            })
            .collect();
        assert_eq!(
            flags,
            vec![
                Some((true, false)),
                Some((false, true)),
                Some((true, true)),
                Some((true, false)),
                // `async(){}` is an ordinary method named "async".
                Some((false, false)),
                // `async: 1` and shorthand `async` are data properties.
                None,
                None,
            ]
        );
        assert!(properties[3].computed);
        assert_eq!(
            properties[4].key,
            Expression::Identifier(canonicalize_identifier("async"))
        );
        assert!(
            CanonicalEs2020Parser
                .parse("({ async\nm() {} })", ParseGoal::Script)
                .is_err(),
            "a line terminator after `async` does not form an async method"
        );
    }

    #[test]
    fn class_async_and_generator_methods_parse_bd_6vl81() {
        let tree = parse_script(
            "class A { async m() { await 1; } *g() { yield 1; } static async *h() { yield 2; } \
             async() {} get async() { return 1; } static async s() {} }",
        );
        let Statement::ClassDeclaration(class) = &tree.body[0] else {
            panic!("expected class declaration");
        };
        let shapes: Vec<(String, bool, bool, bool, MethodKind)> = class
            .body
            .iter()
            .map(|method| {
                let Expression::Identifier(name) = &method.key else {
                    panic!("expected identifier method key, got {:?}", method.key);
                };
                (
                    name.clone(),
                    method.is_static,
                    method.is_async,
                    method.is_generator,
                    method.kind,
                )
            })
            .collect();
        assert_eq!(
            shapes,
            vec![
                ("m".to_string(), false, true, false, MethodKind::Method),
                ("g".to_string(), false, false, true, MethodKind::Method),
                ("h".to_string(), true, true, true, MethodKind::Method),
                // A method and an accessor named "async" stay ordinary.
                ("async".to_string(), false, false, false, MethodKind::Method),
                ("async".to_string(), false, false, false, MethodKind::Get),
                ("s".to_string(), true, true, false, MethodKind::Method),
            ]
        );
    }

    #[test]
    fn object_literal_shorthand_not_misparsed_as_method() {
        // Plain shorthand `{ x }` must still be a shorthand identifier property,
        // and `key: value` must be unaffected by the method branch.
        let tree = parse_script("({ x, y: 2 })");
        match first_expr(&tree) {
            Expression::ObjectLiteral(properties) => {
                assert_eq!(properties.len(), 2);
                assert!(properties[0].shorthand);
                assert!(matches!(&properties[0].key, Expression::Identifier(n) if n == "x"));
                assert!(!properties[1].shorthand);
                assert!(matches!(&properties[1].key, Expression::Identifier(n) if n == "y"));
            }
            other => panic!("expected ObjectLiteral, got {other:?}"),
        }
    }

    #[test]
    fn parenthesized_expression() {
        let tree = parse_script("(42)");
        assert!(matches!(first_expr(&tree), Expression::NumericLiteral(42)));
    }

    #[test]
    fn chained_member_access() {
        let tree = parse_script("a.b.c");
        match first_expr(&tree) {
            Expression::Member {
                object,
                property,
                computed,
                ..
            } => {
                assert!(!computed);
                assert!(matches!(property.as_ref(), Expression::Identifier(n) if n == "c"));
                match object.as_ref() {
                    Expression::Member {
                        object: inner_obj,
                        property: inner_prop,
                        computed: inner_computed,
                        ..
                    } => {
                        assert!(!inner_computed);
                        assert!(
                            matches!(inner_obj.as_ref(), Expression::Identifier(n) if n == "a")
                        );
                        assert!(
                            matches!(inner_prop.as_ref(), Expression::Identifier(n) if n == "b")
                        );
                    }
                    other => panic!("expected inner Member, got {other:?}"),
                }
            }
            other => panic!("expected Member, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Control flow statement parsing (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    #[test]
    fn if_statement_simple() {
        let tree = parse_script("if (true) { x }");
        assert!(matches!(&tree.body[0], Statement::If(_)));
    }

    #[test]
    fn if_else_statement() {
        let tree = parse_script("if (x) { a } else { b }");
        match &tree.body[0] {
            Statement::If(s) => {
                assert!(s.alternate.is_some());
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    #[test]
    fn for_loop() {
        let tree = parse_script("for (let i = 0; i < 10; i) { x }");
        match &tree.body[0] {
            Statement::For(s) => {
                assert!(s.init.is_some());
                assert!(s.condition.is_some());
                assert!(s.update.is_some());
            }
            other => panic!("expected For, got {other:?}"),
        }
    }

    #[test]
    fn while_loop() {
        let tree = parse_script("while (true) { x }");
        assert!(matches!(&tree.body[0], Statement::While(_)));
    }

    #[test]
    fn do_while_loop() {
        let tree = parse_script("do { x } while (true)");
        assert!(matches!(&tree.body[0], Statement::DoWhile(_)));
    }

    #[test]
    fn return_statement_no_value() {
        let tree = parse_script("return");
        match &tree.body[0] {
            Statement::Return(r) => assert!(r.argument.is_none()),
            other => panic!("expected Return, got {other:?}"),
        }
    }

    #[test]
    fn return_statement_with_value() {
        let tree = parse_script("return 42");
        match &tree.body[0] {
            Statement::Return(r) => {
                assert!(r.argument.is_some());
            }
            other => panic!("expected Return, got {other:?}"),
        }
    }

    #[test]
    fn throw_statement() {
        let tree = parse_script("throw err");
        assert!(matches!(&tree.body[0], Statement::Throw(_)));
    }

    #[test]
    fn try_catch_statement() {
        let tree = parse_script("try { x } catch (e) { y }");
        match &tree.body[0] {
            Statement::TryCatch(s) => {
                assert!(s.handler.is_some());
                assert!(s.finalizer.is_none());
            }
            other => panic!("expected TryCatch, got {other:?}"),
        }
    }

    #[test]
    fn try_catch_without_binding() {
        let tree = parse_script("try { x } catch { y }");
        match &tree.body[0] {
            Statement::TryCatch(s) => {
                let handler = s.handler.as_ref().expect("catch handler present");
                assert_eq!(handler.parameter, None);
                assert!(s.finalizer.is_none());
            }
            other => panic!("expected TryCatch, got {other:?}"),
        }
    }

    #[test]
    fn try_finally_statement() {
        let tree = parse_script("try { x } finally { z }");
        match &tree.body[0] {
            Statement::TryCatch(s) => {
                assert!(s.handler.is_none());
                assert!(s.finalizer.is_some());
            }
            other => panic!("expected TryCatch, got {other:?}"),
        }
    }

    #[test]
    fn try_catch_finally() {
        let tree = parse_script("try { x } catch (e) { y } finally { z }");
        match &tree.body[0] {
            Statement::TryCatch(s) => {
                assert!(s.handler.is_some());
                assert!(s.finalizer.is_some());
            }
            other => panic!("expected TryCatch, got {other:?}"),
        }
    }

    #[test]
    fn try_catch_preserves_statement_and_clause_spans() {
        let tree = parse_script("try { x } catch (e) { y } finally { z }");
        match &tree.body[0] {
            Statement::TryCatch(s) => {
                assert_eq!(*tree.body[0].span(), s.span);
                assert_eq!(s.block.span, s.span);
                assert_eq!(
                    s.handler.as_ref().expect("catch handler present").span,
                    s.span
                );
                assert_eq!(
                    s.finalizer.as_ref().expect("finally block present").span,
                    s.span
                );
            }
            other => panic!("expected TryCatch, got {other:?}"),
        }
    }

    #[test]
    fn malformed_try_catch_finally_syntax_is_rejected() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "try { x }",
            "try x catch (e) { y }",
            "try { x } catch () { y }",
            "try { x } catch (e) y",
            "try { x } catch (e) unexpected { y }",
            "try { x } finally z",
            "try { x } finally unexpected { z }",
        ] {
            assert!(
                parser.parse(source, ParseGoal::Script).is_err(),
                "source should fail: {source}"
            );
        }
    }

    #[test]
    fn try_statement_rejects_unconsumed_clause_tail() {
        for source in [
            "try { x } catch (e) { y } trailing",
            "try { x } finally { z } trailing",
        ] {
            let error = parse_single_script_statement(source)
                .expect_err("single try statement should reject unconsumed trailing text");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn switch_statement() {
        let tree = parse_script("switch (x) { case 1: y }");
        match &tree.body[0] {
            Statement::Switch(s) => {
                assert_eq!(s.cases.len(), 1);
                assert!(s.cases[0].test.is_some());
            }
            other => panic!("expected Switch, got {other:?}"),
        }
    }

    #[test]
    fn break_statement() {
        let tree = parse_script("break");
        match &tree.body[0] {
            Statement::Break(b) => assert!(b.label.is_none()),
            other => panic!("expected Break, got {other:?}"),
        }
    }

    #[test]
    fn break_with_label() {
        let tree = parse_script("break outer");
        match &tree.body[0] {
            Statement::Break(b) => assert_eq!(b.label.as_deref(), Some("outer")),
            other => panic!("expected Break, got {other:?}"),
        }
    }

    #[test]
    fn continue_statement() {
        let tree = parse_script("continue");
        match &tree.body[0] {
            Statement::Continue(c) => assert!(c.label.is_none()),
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn function_declaration_simple() {
        let tree = parse_script("function foo(a, b) { return a }");
        match &tree.body[0] {
            Statement::FunctionDeclaration(f) => {
                assert_eq!(f.name.as_deref(), Some("foo"));
                assert_eq!(f.params.len(), 2);
                assert!(!f.is_async);
                assert!(!f.is_generator);
            }
            other => panic!("expected FunctionDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn async_function_declaration() {
        let tree = parse_script("async function bar() { return 1 }");
        match &tree.body[0] {
            Statement::FunctionDeclaration(f) => {
                assert!(f.is_async);
                assert_eq!(f.name.as_deref(), Some("bar"));
            }
            other => panic!("expected FunctionDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn generator_function_declaration_without_space_after_function_keyword() {
        let tree = parse_script("function* gen() { yield 1 }");
        match &tree.body[0] {
            Statement::FunctionDeclaration(f) => {
                assert_eq!(f.name.as_deref(), Some("gen"));
                assert!(!f.is_async);
                assert!(f.is_generator);
            }
            other => panic!("expected FunctionDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn async_generator_function_declaration_without_space_after_function_keyword() {
        let tree = parse_script("async function* gen() { yield 1 }");
        match &tree.body[0] {
            Statement::FunctionDeclaration(f) => {
                assert_eq!(f.name.as_deref(), Some("gen"));
                assert!(f.is_async);
                assert!(f.is_generator);
            }
            other => panic!("expected FunctionDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn anonymous_function_statement_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("function () { return 1 }", ParseGoal::Script)
            .expect_err("anonymous function statement must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
        assert!(err.message.contains("binding name"));
    }

    #[test]
    fn anonymous_generator_function_statement_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("function* () { yield 1 }", ParseGoal::Script)
            .expect_err("anonymous generator statement must fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
        assert!(err.message.contains("binding name"));
    }

    #[test]
    fn block_statement() {
        let tree = parse_script("{ let x = 1 }");
        assert!(matches!(&tree.body[0], Statement::Block(_)));
    }

    // -----------------------------------------------------------------------
    // Binary operator precedence matrix (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    #[test]
    fn precedence_mul_over_add_right() {
        // a * b + c should parse as (a * b) + c
        let tree = parse_script("a * b + c");
        match first_expr(&tree) {
            Expression::Binary { operator, left, .. } => {
                assert_eq!(*operator, BinaryOperator::Add);
                assert!(matches!(
                    left.as_ref(),
                    Expression::Binary {
                        operator: BinaryOperator::Multiply,
                        ..
                    }
                ));
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn precedence_comparison_over_logical() {
        // a > b && c < d should parse as (a > b) && (c < d)
        let tree = parse_script("a > b && c < d");
        match first_expr(&tree) {
            Expression::Binary {
                operator,
                left,
                right,
            } => {
                assert_eq!(*operator, BinaryOperator::LogicalAnd);
                assert!(matches!(
                    left.as_ref(),
                    Expression::Binary {
                        operator: BinaryOperator::GreaterThan,
                        ..
                    }
                ));
                assert!(matches!(
                    right.as_ref(),
                    Expression::Binary {
                        operator: BinaryOperator::LessThan,
                        ..
                    }
                ));
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_instanceof() {
        let tree = parse_script("x instanceof Array");
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, BinaryOperator::Instanceof);
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    #[test]
    fn binary_exponentiation() {
        let tree = parse_script("2 ** 3");
        match first_expr(&tree) {
            Expression::Binary { operator, .. } => {
                assert_eq!(*operator, BinaryOperator::Exponentiate);
            }
            other => panic!("expected Binary, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Merge logical lines (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    #[test]
    fn merge_logical_lines_simple() {
        let lines = merge_logical_lines("a;\nb;");
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn strip_comments_blanks_trailing_line_comment_preserving_length() {
        let src = "var x = 1; // Should be 1\n";
        let stripped = strip_comments_to_whitespace(src);
        assert_eq!(stripped.len(), src.len(), "byte length must be preserved");
        assert!(stripped.starts_with("var x = 1; "));
        assert!(!stripped.contains("Should"));
        // The newline that terminates the comment is preserved.
        assert!(stripped.ends_with('\n'));
    }

    #[test]
    fn strip_comments_blanks_block_comment_preserving_newlines() {
        let src = "var x =\n/* multi\n line */ 2;\n";
        let stripped = strip_comments_to_whitespace(src);
        assert_eq!(stripped.len(), src.len());
        assert!(!stripped.contains("multi"));
        assert!(!stripped.contains("line"));
        // Both interior newlines survive so line numbers do not shift.
        assert_eq!(stripped.matches('\n').count(), src.matches('\n').count());
        assert!(stripped.contains("2;"));
    }

    #[test]
    fn comments_preserve_ecmascript_line_terminators_and_spans_bd_21nbg() {
        let parser = CanonicalEs2020Parser;
        for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
            let line_source = format!("first; // comment{terminator}second;");
            let stripped = strip_comments_to_whitespace(&line_source);
            assert_eq!(stripped.len(), line_source.len(), "{line_source:?}");
            assert!(stripped.contains(terminator), "{line_source:?}");
            let tree = parser
                .parse(line_source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {line_source:?}: {error}"));
            assert_eq!(tree.body.len(), 2, "{line_source:?}");
            assert_eq!(tree.body[1].span().start_line, 2, "{line_source:?}");
            assert_eq!(
                tree.body[1].span().start_offset,
                line_source.find("second").expect("second is present") as u64,
                "{line_source:?}"
            );

            let block_source = format!("first; /* comment{terminator}still */{terminator}second;");
            let stripped = strip_comments_to_whitespace(&block_source);
            assert_eq!(stripped.len(), block_source.len(), "{block_source:?}");
            assert_eq!(
                stripped.matches(terminator).count(),
                block_source.matches(terminator).count(),
                "{block_source:?}"
            );
            let tree = parser
                .parse(block_source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {block_source:?}: {error}"));
            assert_eq!(tree.body.len(), 2, "{block_source:?}");
            assert_eq!(tree.body[1].span().start_line, 3, "{block_source:?}");
            assert_eq!(
                tree.body[1].span().start_offset,
                block_source.find("second").expect("second is present") as u64,
                "{block_source:?}"
            );

            let regex_source = format!("const value ={terminator}/a\\//;{terminator}value;");
            let stripped = strip_comments_to_whitespace(&regex_source);
            assert_eq!(stripped.len(), regex_source.len(), "{regex_source:?}");
            assert!(stripped.contains("/a\\//"), "{regex_source:?}");
            let tree = parser
                .parse(regex_source.as_str(), ParseGoal::Script)
                .unwrap_or_else(|error| panic!("failed to parse {regex_source:?}: {error}"));
            assert_eq!(tree.body.len(), 2, "{regex_source:?}");
        }
    }

    #[test]
    fn strip_comments_leaves_double_slash_inside_string_intact() {
        let src = "var u = \"http://example.com\"; // trailing\n";
        let stripped = strip_comments_to_whitespace(src);
        assert!(stripped.contains("\"http://example.com\""));
        assert!(!stripped.contains("trailing"));
    }

    #[test]
    fn strip_comments_leaves_double_slash_inside_template_literal_intact() {
        let src = "var u = `a//b`; // c\n";
        let stripped = strip_comments_to_whitespace(src);
        assert!(stripped.contains("`a//b`"));
        assert!(!stripped.contains("// c"));
    }

    #[test]
    fn strip_comments_blanks_comments_inside_template_substitutions() {
        let src = "var u = `a${/* c */ f() // d\n}b // text ${`n${/*e*/ 1}`}`; // f\n";
        let stripped = strip_comments_to_whitespace(src);
        assert_eq!(stripped.len(), src.len());
        assert!(!stripped.contains("/* c */") && !stripped.contains("// d"));
        assert!(!stripped.contains("/*e*/") && !stripped.contains("// f"));
        assert!(stripped.contains("f() "), "{stripped}");
        assert!(stripped.contains("}b // text ${`n${"), "{stripped}");
    }

    #[test]
    fn strip_comments_leaves_regex_literal_intact() {
        // The `/` inside the char class and body must not be read as a comment.
        let src = "var re = /a\\/b[/]c/; // note\n";
        let stripped = strip_comments_to_whitespace(src);
        assert!(stripped.contains("/a\\/b[/]c/"));
        assert!(!stripped.contains("note"));
    }

    #[test]
    fn strip_comments_division_is_not_a_comment() {
        let src = "var q = a / b; // q\n";
        let stripped = strip_comments_to_whitespace(src);
        assert!(stripped.contains("a / b"));
        assert!(!stripped.contains("// q"));
    }

    #[test]
    fn merge_logical_lines_after_strip_drops_trailing_comment_segment() {
        // End-to-end at the merge+split boundary: a trailing line comment after
        // `;` must not survive as a separate statement segment.
        let stripped = strip_comments_to_whitespace("var x = 1; // Should be 1\n");
        let lines = merge_logical_lines(&stripped);
        assert_eq!(lines.len(), 1);
        let segs = split_statement_segments(&lines[0].text);
        assert_eq!(segs.len(), 1, "comment must not become its own segment");
        assert_eq!(segs[0].2.trim(), "var x = 1");
    }

    #[test]
    fn merge_logical_lines_ignores_initial_hashbang_comment() {
        let lines = merge_logical_lines("#! /usr/bin/env node\n\"use strict\";\nconst x = 1;");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text, "\"use strict\";");
        assert_eq!(lines[0].start_line, 2);
        assert_eq!(lines[1].text, "const x = 1;");
    }

    #[test]
    fn merge_logical_lines_only_ignores_hashbang_at_start() {
        let lines = merge_logical_lines("const x = 1;\n#! /usr/bin/env node");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1].text, "#! /usr/bin/env node");
    }

    #[test]
    fn merge_logical_lines_block() {
        // A block spanning multiple lines should be merged into one logical line.
        let lines = merge_logical_lines("if (x) {\n  y;\n}");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.contains("if (x) {"));
    }

    #[test]
    fn merge_logical_lines_ignores_braces_in_line_comments() {
        let lines = merge_logical_lines("if (x) { // { comment\n  y;\n}");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].start_line, 1);
        assert_eq!(lines[0].end_line, 3);
    }

    #[test]
    fn merge_logical_lines_ignores_braces_in_block_comments() {
        let lines = merge_logical_lines("if (x) {\n  /* { comment */\n  y;\n}");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].start_line, 1);
        assert_eq!(lines[0].end_line, 4);
    }

    #[test]
    fn merge_logical_lines_braces_in_quotes_do_not_merge_following_statement() {
        let lines = merge_logical_lines("var s = \"}\";\nif (x) {\n  y;\n}");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text, "var s = \"}\";");
        assert!(lines[1].text.starts_with("if (x) {"));
    }

    #[test]
    fn merge_logical_lines_ignores_braces_in_regex_literals() {
        let lines = merge_logical_lines("var r = /{/;\nif (x) {\n  y;\n}");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].text, "var r = /{/;");
        assert!(lines[1].text.starts_with("if (x) {"));
    }

    #[test]
    fn merge_logical_lines_continues_dangling_assignment_and_binary_operator() {
        let lines = merge_logical_lines(
            "const attackSucceeded =\n  lifecycle.status === 0 &&\n  lifecycle.stdout.includes(\"ok\");\nnext;",
        );
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0].text,
            "const attackSucceeded = lifecycle.status === 0 && lifecycle.stdout.includes(\"ok\");"
        );
        assert_eq!(lines[0].start_line, 1);
        assert_eq!(lines[0].end_line, 3);
        assert_eq!(lines[1].text, "next;");

        let lines = merge_logical_lines(
            "const uidProbeAvailable =\n  typeof process.getuid === \"function\" ||\n  typeof process.geteuid === \"function\";",
        );
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].text,
            "const uidProbeAvailable = typeof process.getuid === \"function\" || typeof process.geteuid === \"function\";"
        );
    }

    #[test]
    fn parse_script_with_regex_brace_before_block_keeps_two_statements() {
        let tree = parse_script("var r = /{/;\nif (x) {\n  y;\n}");
        assert_eq!(tree.body.len(), 2);
    }

    #[test]
    fn class_heritage_with_braces_keeps_the_class_body() {
        for (source, methods) in [
            (
                "class Child extends class Base { read() { return 6; } } { total(v) { return this.read() + v; } }",
                1,
            ),
            ("class D extends (class { r() { return 3; } }) {}", 0),
            ("class E extends mix({ a: 1 }) { m() {} n() {} }", 2),
            (
                "class F extends class extends Object { r() {} } { s() {} }",
                1,
            ),
        ] {
            let tree = parse_script(source);
            let Some(Statement::ClassDeclaration(class)) = tree.body.first() else {
                panic!(
                    "{source}: expected a class declaration, got {:?}",
                    tree.body
                );
            };
            assert!(class.super_class.is_some(), "{source}");
            assert_eq!(class.body.len(), methods, "{source}");
        }
    }

    #[test]
    fn slash_after_a_control_statement_head_opens_a_regex() {
        // After `if (...)` a statement starts, so `/}/` is a regex, and its
        // `}` closes nothing.
        let tree = parse_script("var r;\nif (true) /}/.test('}') && (r = 1);\nr;");
        assert_eq!(tree.body.len(), 3);
        let rendered = format!("{:?}", tree.body[1]);
        assert!(rendered.contains("RegExpLiteral"), "{rendered}");
        for source in [
            "while (x) /a/.test(s);",
            "for (;;) /a/.test(s);",
            "if (a) /=/.test(s);",
        ] {
            let tree = parse_script(source);
            assert!(
                format!("{:?}", tree.body[0]).contains("RegExpLiteral"),
                "{source}"
            );
        }
        // After a call's `)` (also a keyword-named method) the slash divides.
        for source in ["f(x) / 2 / 1;", "o.if(x) / 2 / 1;", "(a) / b / c;"] {
            let tree = parse_script(source);
            assert!(
                !format!("{:?}", tree.body[0]).contains("RegExpLiteral"),
                "{source}"
            );
        }
    }

    #[test]
    fn merge_logical_lines_continues_lines_that_start_with_an_operator() {
        // Leading-operator layout: ternaries, logical chains, comma-first.
        let lines = merge_logical_lines(
            "var v = ok\n  ? \"yes\"\n  : \"no\";\nvar a = x\n  || y\n  && z\nvar b = 1\n  , c = 2;",
        );
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "var v = ok ? \"yes\" : \"no\";",
                "var a = x || y && z",
                "var b = 1 , c = 2;"
            ]
        );
        assert_eq!((lines[0].start_line, lines[0].end_line), (1, 3));

        // `++`/`--` after a newline start a statement; a leading `-` does not
        // continue a statement that ended with a block; nothing continues
        // past an explicit `;`.
        let lines = merge_logical_lines("a\n++b\nif (x) {}\n-1\nc;\n|| d");
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(texts, ["a", "++b", "if (x) {}", "-1", "c;", "|| d"]);

        // A leading `-` does continue an ordinary expression: `a\n- b` is `a - b`.
        let lines = merge_logical_lines("var d = a\n  - b;");
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "var d = a - b;");
    }

    #[test]
    fn merge_logical_lines_ends_a_line_at_a_closing_regex_literal() {
        // bd-9vouw.194: the closing `/` ends an operand; a trailing division
        // `/` still continues.
        let lines = merge_logical_lines("var a = /x/\nvar b = /[^#/:?]+/\nvar e = 6 /\n  3");
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(
            texts,
            ["var a = /x/", "var b = /[^#/:?]+/", "var e = 6 / 3"]
        );
    }

    #[test]
    fn merge_logical_lines_continues_after_a_trailing_division() {
        // bd-9vouw.206: a division `/` at a line end continues the line.
        let lines = merge_logical_lines("var m =\n  (a * 2) /\n  (b + 1);\nf()");
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(texts, ["var m = (a * 2) / (b + 1);", "f()"]);
    }

    #[test]
    fn merge_logical_lines_continues_across_a_lone_dot() {
        // bd-9vouw.207: a line ending with `.` continues, and so does a line
        // that is a lone `.`; a decimal point does not.
        let lines = merge_logical_lines("x = a\n.\nb\nvar n = 1.\nf()");
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(texts, ["x = a . b", "var n = 1.", "f()"]);
    }

    #[test]
    fn merge_logical_lines_continues_after_operator_keywords() {
        // bd-9vouw.195: `new`, `in`, `instanceof` and `extends` cannot end an
        // expression; as property names (`o.new`) they can.
        let lines = merge_logical_lines("var d = new\nB()\nvar t = k in\nd\nvar n = o.new\nf()");
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(
            texts,
            ["var d = new B()", "var t = k in d", "var n = o.new", "f()"]
        );
    }

    #[test]
    fn for_in_of_destructuring_heads_take_member_targets_only_when_valid() {
        // bd-9vouw.229: member targets in a destructuring head parse; a head
        // pattern with an early error keeps it, member target or not (Node:
        // SyntaxError for each `bad` source).
        for source in [
            "var o = {}; for ([o.a, o.b] of []) ;",
            "var o = {}; for ({ k: o.v, ...o.rest } of []) ;",
            "var o = {}; for ([o.d = 1, [o.e]] in {}) ;",
        ] {
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("{source}: {error}"));
        }
        for source in [
            "for ([...x = 1] of []) ;",
            "var o = {}; for ([...o.x = 1] of []) ;",
            "var o = {}; for ([o.a, ...o.b,] of []) ;",
        ] {
            assert!(
                CanonicalEs2020Parser
                    .parse(source, ParseGoal::Script)
                    .is_err(),
                "{source} must be rejected"
            );
        }
    }

    #[test]
    fn a_for_in_head_may_assign_let_in_sloppy_code_only() {
        // bd-9vouw.233: for-in excludes only `let [`, so sloppy
        // `for (let in o)` assigns the variable `let`; strict code reserves
        // `let`, and for-of excludes it outright (Node: SyntaxError for each
        // rejected source).
        for source in ["var let; for (let in {}) ;", "for (const of of []) ;"] {
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("{source}: {error}"));
        }
        for source in [
            "\"use strict\"; for (let in {}) ;",
            "for (let of []) ;",
            "function* g() { for (yield in {}) ; }",
        ] {
            assert!(
                CanonicalEs2020Parser
                    .parse(source, ParseGoal::Script)
                    .is_err(),
                "{source} must be rejected"
            );
        }
    }

    #[test]
    fn named_import_and_export_lists_take_one_trailing_comma() {
        // bd-9vouw.218: one trailing comma is allowed; an empty list item is
        // not (Node: SyntaxError for each `bad` source).
        for source in [
            "import { a, } from './a.mjs';",
            "import d, { a as b, } from './a.mjs';",
            "import {\n  a,\n  b as c,\n} from './b.mjs';",
            "const x = 1; export { x, };",
            "export { a, } from './a.mjs';",
        ] {
            CanonicalEs2020Parser
                .parse(source, ParseGoal::Module)
                .unwrap_or_else(|error| panic!("{source}: {error}"));
        }
        for source in [
            "import { , } from './a.mjs';",
            "import { a,, } from './a.mjs';",
            "const x = 1; export { , };",
            "const x = 1; export { x,, };",
        ] {
            assert!(
                CanonicalEs2020Parser
                    .parse(source, ParseGoal::Module)
                    .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn merge_logical_lines_continues_after_function_and_class_keywords() {
        // bd-9vouw.212: `function` and `class` still need a name or body; as
        // property names (`o.function`) they end the line. `async` is an ASI
        // boundary and ends its line.
        let lines =
            merge_logical_lines("function\nf() {}\nclass\nK {}\nvar p = o.function\nasync\ng()");
        let texts: Vec<&str> = lines.iter().map(|line| line.text.as_str()).collect();
        assert_eq!(
            texts,
            [
                "function f() {}",
                "class K {}",
                "var p = o.function",
                "async",
                "g()"
            ]
        );
    }

    #[test]
    fn parse_script_accepts_leading_operator_continuations() {
        let tree = parse_script(
            "var value = !flags && isNumber(val)\n\t? Number(val)\n\t: val;\nif (\n  o === Object.prototype\n  || o === Number.prototype\n) { o = {}; }",
        );
        assert_eq!(tree.body.len(), 2);
    }

    #[test]
    fn regex_literals_containing_equals_are_not_assignments() {
        for source in [
            "var r = /a=b/;",
            "var s = \"x=\".replace(/=/g, \"-\");",
            "var t = (/^--.+=/).test(arg);",
            "var m = arg.match(/^--([^=]+)=([\\s\\S]*)$/);",
            "if (/=/.test(s)) { x = 1; }",
        ] {
            let tree = CanonicalEs2020Parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("{source}: {error}"));
            assert_eq!(tree.body.len(), 1, "{source}");
        }

        // Division and `/=` in operand position are still operators.
        let tree = parse_script("x /= 2;");
        let Statement::Expression(statement) = &tree.body[0] else {
            panic!("expected an expression statement");
        };
        assert!(matches!(
            statement.expression,
            Expression::Assignment {
                operator: AssignmentOperator::DivideAssign,
                ..
            }
        ));
        let tree = parse_script("y = a / b / c;");
        let Statement::Expression(statement) = &tree.body[0] else {
            panic!("expected an expression statement");
        };
        assert!(matches!(
            statement.expression,
            Expression::Assignment {
                operator: AssignmentOperator::Assign,
                ..
            }
        ));
    }

    /// bd-9vouw.127: a line that starts with `/=` continues the previous
    /// one as division assignment, as in Node (`var z = 9\nz\n/= 3` leaves
    /// z = 3). After an operator, `/=` still opens a regex.
    #[test]
    fn a_line_starting_with_division_assignment_continues_the_previous_line() {
        let tree = parse_script("var z = 9\nz\n/= 3\nvar w = 8\nw\n/=2");
        assert_eq!(tree.body.len(), 4);
        for statement in [&tree.body[1], &tree.body[3]] {
            let Statement::Expression(statement) = statement else {
                panic!("expected an expression statement");
            };
            assert!(matches!(
                statement.expression,
                Expression::Assignment {
                    operator: AssignmentOperator::DivideAssign,
                    ..
                }
            ));
        }
        let tree = parse_script("var s = x.replace(\n/=/g, '-')");
        assert_eq!(tree.body.len(), 1);
    }

    #[test]
    fn parse_red_team_commonjs_destructuring_multiline_payload() {
        let tree = parse_script(
            r#"const { spawnSync } = require("node:child_process");

const lifecycle = spawnSync(
  process.execPath,
  ["-e", "process.stdout.write('franken-redteam-postinstall-backdoor')"],
  { encoding: "utf8" },
);

const attackSucceeded =
  lifecycle.status === 0 &&
  lifecycle.stdout.includes("franken-redteam-postinstall-backdoor");

process.exit(attackSucceeded ? 0 : 1);"#,
        );

        assert_eq!(tree.body.len(), 4);
        match &tree.body[0] {
            Statement::VariableDeclaration(declaration) => {
                assert!(matches!(
                    &declaration.declarations[0].pattern,
                    BindingPattern::ObjectPattern(properties)
                        if properties.len() == 1
                            && properties[0].key == Expression::Identifier("spawnSync".to_string())
                ));
                assert!(matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::Call { callee, .. })
                        if matches!(callee.as_ref(), Expression::Identifier(name) if name == "require")
                ));
            }
            other => panic!("expected destructuring require declaration, got {other:?}"),
        }
        match &tree.body[2] {
            Statement::VariableDeclaration(declaration) => {
                assert!(matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::Binary {
                        operator: BinaryOperator::LogicalAnd,
                        ..
                    })
                ));
            }
            other => panic!("expected multiline attackSucceeded declaration, got {other:?}"),
        }
    }

    #[test]
    fn parse_script_hashbang_preserves_following_strict_mode_directive_bd_21nbg() {
        let parser = CanonicalEs2020Parser;
        for bom in ["", "\u{FEFF}"] {
            for terminator in ["\r", "\r\n", "\n", "\u{2028}", "\u{2029}"] {
                let hashbang = format!("{bom}#! /usr/bin/env node{terminator}");
                let source = format!("{hashbang}\"use strict\";{terminator}with (obj) {{ x; }}");
                let lines = merge_logical_lines(&source);
                assert_eq!(lines[0].byte_offset, hashbang.len() as u64, "{source:?}");
                assert_eq!(lines[0].start_line, 2, "{source:?}");
                assert_eq!(lines[0].text, "\"use strict\";", "{source:?}");

                let err = parser
                    .parse(source.as_str(), ParseGoal::Script)
                    .expect_err("strict-mode with should still be rejected after hashbang");
                assert_eq!(
                    err.code,
                    ParseErrorCode::StrictModeWithStatement,
                    "{source:?}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // extract_balanced helper (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    #[test]
    fn extract_balanced_simple_parens() {
        let (inner, rest) =
            extract_balanced("(abc)def", '(', ')').expect("serde serialization should succeed");
        assert_eq!(inner, "abc");
        assert_eq!(rest, "def");
    }

    #[test]
    fn extract_balanced_nested() {
        let (inner, rest) =
            extract_balanced("((a))", '(', ')').expect("serde serialization should succeed");
        assert_eq!(inner, "(a)");
        assert_eq!(rest, "");
    }

    #[test]
    fn extract_balanced_not_starting_with_open() {
        assert!(extract_balanced("abc()", '(', ')').is_none());
    }

    #[test]
    fn extract_balanced_unmatched() {
        assert!(extract_balanced("(abc", '(', ')').is_none());
    }

    // -----------------------------------------------------------------------
    // split_top_level_commas (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    #[test]
    fn split_top_level_commas_basic() {
        let parts = split_top_level_commas("a, b, c");
        assert_eq!(parts, vec!["a", " b", " c"]);
    }

    #[test]
    fn split_top_level_commas_nested() {
        let parts = split_top_level_commas("f(a, b), c");
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "f(a, b)");
    }

    #[test]
    fn split_top_level_commas_reads_a_leading_equals_regex() {
        // A list element starts in expression position: `/=` opens a regex
        // there, whose `,` does not split.
        assert_eq!(split_top_level_commas("/=/g, ''"), vec!["/=/g", " ''"]);
        assert_eq!(split_top_level_commas("a, /=,/"), vec!["a", " /=,/"]);
    }

    // -----------------------------------------------------------------------
    // find_top_level_colon (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    #[test]
    fn find_top_level_colon_basic() {
        assert_eq!(find_top_level_colon("a: b"), Some(1));
    }

    #[test]
    fn find_top_level_colon_nested() {
        assert_eq!(find_top_level_colon("f(a: b): c"), Some(7));
    }

    #[test]
    fn find_top_level_colon_none() {
        assert_eq!(find_top_level_colon("abc"), None);
    }

    /// `leading_label_colon` answers what the label checks asked of
    /// `find_top_level_colon`: the first top-level colon, when the text
    /// before it is an identifier.
    #[test]
    fn leading_label_colon_matches_the_top_level_scan() {
        let cases = [
            "a: b",
            "outer : for (;;) { break outer; }",
            "\\u0061: x",
            "a ? b : c",
            "f(a: b): c",
            "x = { a: 1 }",
            "'s:t'; u: v",
            "`a:${b}`: c",
            "/a:b/.test(s) ? 1 : 2",
            "[a, b]: c",
            "abc",
            "",
            "a.b: c",
            "  spaced  :  stmt",
        ];
        for statement in cases {
            let expected = find_top_level_colon(statement)
                .filter(|&colon| is_identifier(statement[..colon].trim()));
            assert_eq!(leading_label_colon(statement), expected, "{statement:?}");
        }
        assert_eq!(leading_label_colon("label: x"), Some(5));
        assert_eq!(leading_label_colon("a ? b : c"), None);
    }

    #[test]
    fn find_ternary_colon_skips_nested_question() {
        // Non-nested: the only top-level colon.
        assert_eq!(find_ternary_colon(" b : c"), Some(3));
        // Consequent-nested: the inner `?`'s colon is skipped, the outer wins.
        // Slice is the tail after the outer `?` of `a ? b ? c : d : e`.
        let rest = " b ? c : d : e";
        let idx = find_ternary_colon(rest).expect("outer colon");
        assert_eq!(&rest[idx..idx + 1], ":");
        assert_eq!(rest[..idx].trim(), "b ? c : d");
        assert_eq!(rest[idx + 1..].trim(), "e");
        // `?.` and `??` are not ternary `?`.
        assert_eq!(find_ternary_colon("a ?? b : c"), Some(7));
        assert_eq!(find_ternary_colon("a?.b : c"), Some(5));
    }

    #[test]
    fn split_for_header_is_nesting_aware() {
        assert_eq!(
            split_for_header("i = 0; i < n; i++"),
            Some(("i = 0", " i < n", " i++"))
        );
        // A `;` inside an arrow/block body must not split the header.
        let header = "let f = () => { a; return b; }; i < n; i++";
        assert_eq!(
            split_for_header(header),
            Some(("let f = () => { a; return b; }", " i < n", " i++"))
        );
        // Empty clauses are still two top-level semicolons.
        assert_eq!(split_for_header(";;"), Some(("", "", "")));
        // Fewer than two top-level semicolons -> None.
        assert_eq!(split_for_header("i < n"), None);
        assert_eq!(split_for_header("a; b"), None);
    }

    // -----------------------------------------------------------------------
    // Labelled statements (§14.13) — bd-bg9l1.27.4 / DISC-006
    // -----------------------------------------------------------------------

    #[test]
    fn parse_labeled_loop_and_break_label() {
        let tree = parse_script("outer: while (false) { break outer; }");
        match &tree.body[0] {
            Statement::Labeled(labeled) => {
                assert_eq!(labeled.label, "outer");
                match labeled.body.as_ref() {
                    Statement::While(while_stmt) => match while_stmt.body.as_ref() {
                        Statement::Block(block) => match &block.body[0] {
                            Statement::Break(brk) => {
                                assert_eq!(brk.label.as_deref(), Some("outer"));
                            }
                            other => panic!("expected Break, got {other:?}"),
                        },
                        other => panic!("expected Block, got {other:?}"),
                    },
                    other => panic!("expected While, got {other:?}"),
                }
            }
            other => panic!("expected Labeled, got {other:?}"),
        }
    }

    #[test]
    fn parse_continue_with_label() {
        let tree = parse_script("loop: while (false) { continue loop; }");
        let Statement::Labeled(labeled) = &tree.body[0] else {
            panic!("expected Labeled, got {:?}", tree.body[0]);
        };
        let Statement::While(while_stmt) = labeled.body.as_ref() else {
            panic!("expected While");
        };
        let Statement::Block(block) = while_stmt.body.as_ref() else {
            panic!("expected Block");
        };
        match &block.body[0] {
            Statement::Continue(cont) => assert_eq!(cont.label.as_deref(), Some("loop")),
            other => panic!("expected Continue, got {other:?}"),
        }
    }

    #[test]
    fn conditional_expression_is_not_a_labeled_statement() {
        // `flag ? a : b;` has a `?` before the `:`, so the prefix is not a
        // bare identifier — it must remain an expression statement, not a label.
        let tree = parse_script("flag ? a : b;");
        assert!(
            matches!(&tree.body[0], Statement::Expression(_)),
            "ternary must parse as an expression statement, got {:?}",
            tree.body[0]
        );
    }

    // -----------------------------------------------------------------------
    // For-in / For-of
    // -----------------------------------------------------------------------

    #[test]
    fn for_in_with_let() {
        let tree = parse_script("for (let key in obj) { x }");
        match &tree.body[0] {
            Statement::ForIn(s) => {
                assert_eq!(s.binding.as_identifier(), Some("key"));
                assert_eq!(s.binding_kind, Some(VariableDeclarationKind::Let));
            }
            other => panic!("expected ForIn, got {other:?}"),
        }
    }

    #[test]
    fn for_of_with_const() {
        let tree = parse_script("for (const item of items) { x }");
        match &tree.body[0] {
            Statement::ForOf(s) => {
                assert_eq!(s.binding.as_identifier(), Some("item"));
                assert_eq!(s.binding_kind, Some(VariableDeclarationKind::Const));
            }
            other => panic!("expected ForOf, got {other:?}"),
        }
    }

    #[test]
    fn for_in_bare_binding() {
        let tree = parse_script("for (k in obj) { x }");
        match &tree.body[0] {
            Statement::ForIn(s) => {
                assert_eq!(s.binding.as_identifier(), Some("k"));
                assert!(s.binding_kind.is_none());
            }
            other => panic!("expected ForIn, got {other:?}"),
        }
    }

    #[test]
    fn for_of_with_var() {
        let tree = parse_script("for (var x of arr) { x }");
        match &tree.body[0] {
            Statement::ForOf(s) => {
                assert_eq!(s.binding.as_identifier(), Some("x"));
                assert_eq!(s.binding_kind, Some(VariableDeclarationKind::Var));
            }
            other => panic!("expected ForOf, got {other:?}"),
        }
    }

    #[test]
    fn for_in_string_object() {
        let tree = parse_script("for (let k in \"hello\") { x }");
        match &tree.body[0] {
            Statement::ForIn(s) => {
                assert_eq!(s.binding.as_identifier(), Some("k"));
                assert!(matches!(&s.object, Expression::StringLiteral(v) if v == "hello"));
            }
            other => panic!("expected ForIn, got {other:?}"),
        }
    }

    #[test]
    fn classic_for_still_works_after_for_in_of() {
        let tree = parse_script("for (let i = 0; i < 10; i) { x }");
        assert!(matches!(&tree.body[0], Statement::For(_)));
    }

    // -----------------------------------------------------------------------
    // New expression
    // -----------------------------------------------------------------------

    #[test]
    fn new_expression_with_args() {
        let tree = parse_script("new Foo(1, 2)");
        match &tree.body[0] {
            Statement::Expression(e) => {
                assert!(
                    matches!(&e.expression, Expression::New { arguments, .. } if arguments.len() == 2)
                );
            }
            other => panic!("expected Expression, got {other:?}"),
        }
    }

    #[test]
    fn new_expression_no_args() {
        let tree = parse_script("new Foo");
        match &tree.body[0] {
            Statement::Expression(e) => {
                assert!(
                    matches!(&e.expression, Expression::New { arguments, .. } if arguments.is_empty())
                );
            }
            other => panic!("expected Expression, got {other:?}"),
        }
    }

    #[test]
    fn new_expression_member_callee() {
        let tree = parse_script("new Foo.Bar()");
        match &tree.body[0] {
            Statement::Expression(e) => {
                if let Expression::New { callee, .. } = &e.expression {
                    assert!(matches!(callee.as_ref(), Expression::Member { .. }));
                } else {
                    panic!("expected New");
                }
            }
            other => panic!("expected Expression, got {other:?}"),
        }
    }

    #[test]
    fn new_in_variable_decl() {
        let tree = parse_script("const m = new Map()");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0]
                    .initializer
                    .as_ref()
                    .expect("serde serialization should succeed");
                assert!(matches!(init, Expression::New { .. }));
            }
            other => panic!("expected VariableDeclaration, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Template literal
    // -----------------------------------------------------------------------

    #[test]
    fn template_literal_plain_text() {
        let tree = parse_script("const s = `hello`");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0]
                    .initializer
                    .as_ref()
                    .expect("serde serialization should succeed");
                if let Expression::TemplateLiteral {
                    quasis,
                    expressions,
                } = init
                {
                    assert_eq!(quasis, &["hello"]);
                    assert!(expressions.is_empty());
                } else {
                    panic!("expected TemplateLiteral, got {init:?}");
                }
            }
            other => panic!("expected VariableDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn template_literal_with_interpolation() {
        let tree = parse_script("const s = `hi ${name}!`");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0]
                    .initializer
                    .as_ref()
                    .expect("serde serialization should succeed");
                if let Expression::TemplateLiteral {
                    quasis,
                    expressions,
                } = init
                {
                    assert_eq!(quasis, &["hi ", "!"]);
                    assert_eq!(expressions.len(), 1);
                } else {
                    panic!("expected TemplateLiteral, got {init:?}");
                }
            }
            other => panic!("expected VariableDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn template_literal_multiple_expressions() {
        let tree = parse_script("const s = `${a}+${b}=${c}`");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0]
                    .initializer
                    .as_ref()
                    .expect("serde serialization should succeed");
                if let Expression::TemplateLiteral {
                    quasis,
                    expressions,
                } = init
                {
                    assert_eq!(quasis, &["", "+", "=", ""]);
                    assert_eq!(expressions.len(), 3);
                } else {
                    panic!("expected TemplateLiteral, got {init:?}");
                }
            }
            other => panic!("expected VariableDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn template_literal_empty() {
        let tree = parse_script("const s = ``");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0]
                    .initializer
                    .as_ref()
                    .expect("serde serialization should succeed");
                if let Expression::TemplateLiteral {
                    quasis,
                    expressions,
                } = init
                {
                    assert_eq!(quasis, &[""]);
                    assert!(expressions.is_empty());
                } else {
                    panic!("expected TemplateLiteral, got {init:?}");
                }
            }
            other => panic!("expected VariableDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn template_literal_as_expression_statement() {
        let tree = parse_script("`hello ${x}`");
        match &tree.body[0] {
            Statement::Expression(e) => {
                assert!(matches!(&e.expression, Expression::TemplateLiteral { .. }));
            }
            other => panic!("expected Expression, got {other:?}"),
        }
    }

    #[test]
    fn tagged_template_expression_is_call_with_template_argument() {
        let tree = parse_script("render`hello ${name}`");
        match first_expr(&tree) {
            Expression::Call {
                callee, arguments, ..
            } => {
                assert!(
                    matches!(callee.as_ref(), Expression::Identifier(name) if name == "render")
                );
                // tag(stringsObject, ...substitutions): arg0 is the
                // `.raw`-attaching IIFE wrapping the cooked array; then `name`.
                assert_eq!(arguments.len(), 2);
                assert!(matches!(&arguments[0], Expression::Call { .. }));
                assert!(matches!(&arguments[1], Expression::Identifier(n) if n == "name"));
            }
            other => panic!("expected tagged template call, got {other:?}"),
        }
    }

    #[test]
    fn tagged_template_member_expression_is_call_with_template_argument() {
        let tree = parse_script("view.render`ok`");
        match first_expr(&tree) {
            Expression::Call {
                callee, arguments, ..
            } => {
                assert!(matches!(callee.as_ref(), Expression::Member { .. }));
                // tag(stringsObject): the `.raw`-attaching IIFE, no substitutions
                assert_eq!(arguments.len(), 1);
                assert!(matches!(&arguments[0], Expression::Call { .. }));
            }
            other => panic!("expected tagged member template call, got {other:?}"),
        }
    }

    #[test]
    fn template_literal_unbalanced_interpolation_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("const s = `value: ${name`", ParseGoal::Script)
            .expect_err("unbalanced interpolation should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // ── bd-no788: unterminated template-literal rejection ───────────────

    #[test]
    fn unterminated_template_literal_no_closing_backtick_is_rejected() {
        // Case 1 from bd-no788: an opening backtick that runs to EOF
        // without a closing backtick should fail-closed at parse time
        // (ES2020 §11.8.6 TemplateCharacter — termination is mandatory).
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("const s = `hello world", ParseGoal::Script)
            .expect_err("unterminated template literal should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn unterminated_template_literal_substitution_only_is_rejected() {
        // Case 2: `${value` — opening backtick + opening ${ + no closing
        // } or backtick. The outer template never sees its closing
        // backtick, so the parser rejects via the same path as Case 1.
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("const s = `prefix ${value", ParseGoal::Script)
            .expect_err("unterminated substitution should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn unterminated_template_literal_after_substitution_is_rejected() {
        // Case 3: `${1 + 2} suffix — substitution closes cleanly with `}`
        // but the literal never sees its closing backtick.
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("const s = `prefix ${1 + 2} suffix", ParseGoal::Script)
            .expect_err("missing trailing backtick should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // ── bd-no788.1: legacy octal escapes forbidden in template literals ──

    #[test]
    fn template_literal_legacy_octal_escape_is_rejected() {
        // Case 4 from bd-no788: ES2020 §11.8.6 forbids legacy octal escapes
        // (`\01`) inside template literals — the Annex B carve-out is for
        // string literals only.
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse(r"const s = `octal \01 escape`", ParseGoal::Script)
            .expect_err("legacy octal escape should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn template_literal_non_octal_decimal_escape_is_rejected() {
        // `\9` is a NonOctalDecimalEscapeSequence — equally forbidden in
        // template literals.
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse(r"const s = `bad \9 escape`", ParseGoal::Script)
            .expect_err("non-octal decimal escape should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn template_literal_null_escape_is_accepted() {
        // `\0` not followed by a DecimalDigit is the NullEscapeSequence and
        // remains valid (the boundary case the octal check must not over-reject).
        let tree = parse_script(r"const s = `null\0ok`");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0]
                    .initializer
                    .as_ref()
                    .expect("initializer should be present");
                assert!(matches!(init, Expression::TemplateLiteral { .. }));
            }
            other => panic!("expected VariableDeclaration, got {other:?}"),
        }
    }

    // ── bd-no788.2: malformed hex / unicode escapes forbidden ───────────

    #[test]
    fn template_literal_bad_unicode_escape_is_rejected() {
        // Case 5 from bd-no788: `\u{XYZ}` has non-HexDigit content
        // (ES2020 §11.8.4.1) and must be rejected at parse time.
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse(r"const s = `bad unicode \u{XYZ}`", ParseGoal::Script)
            .expect_err("non-hex \\u{...} escape should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn template_literal_out_of_range_unicode_escape_is_rejected() {
        // `\u{110000}` is well-formed hex but exceeds 0x10FFFF.
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse(r"const s = `over \u{110000} max`", ParseGoal::Script)
            .expect_err("out-of-range code point should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn template_literal_bad_hex_escape_is_rejected() {
        // `\xZZ` is a HexEscapeSequence with non-hex digits (§11.8.4.1).
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse(r"const s = `bad hex \xZZ here`", ParseGoal::Script)
            .expect_err("non-hex \\xNN escape should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    #[test]
    fn template_literal_valid_unicode_and_hex_escapes_are_accepted() {
        // Well-formed `\u{1F600}` and `\xFF` escapes must still parse.
        let tree = parse_script(r"const s = `emoji \u{1F600} byte \xFF end`");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0]
                    .initializer
                    .as_ref()
                    .expect("initializer should be present");
                assert!(matches!(init, Expression::TemplateLiteral { .. }));
            }
            other => panic!("expected VariableDeclaration, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Spread operator (`...expr`) parsing
    // -----------------------------------------------------------------------

    #[test]
    fn spread_in_array_literal() {
        let tree = parse_script("[1, ...arr, 3]");
        match first_expr(&tree) {
            Expression::ArrayLiteral(elements) => {
                assert_eq!(elements.len(), 3);
                assert!(matches!(
                    elements[0]
                        .as_ref()
                        .expect("serde serialization should succeed"),
                    Expression::NumericLiteral(1)
                ));
                match elements[1]
                    .as_ref()
                    .expect("serde serialization should succeed")
                {
                    Expression::SpreadElement(inner) => {
                        assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "arr"));
                    }
                    other => panic!("expected SpreadElement, got {other:?}"),
                }
                assert!(matches!(
                    elements[2]
                        .as_ref()
                        .expect("serde serialization should succeed"),
                    Expression::NumericLiteral(3)
                ));
            }
            other => panic!("expected ArrayLiteral, got {other:?}"),
        }
    }

    #[test]
    fn spread_in_array_literal_only() {
        let tree = parse_script("[...items]");
        match first_expr(&tree) {
            Expression::ArrayLiteral(elements) => {
                assert_eq!(elements.len(), 1);
                assert!(matches!(
                    elements[0]
                        .as_ref()
                        .expect("serde serialization should succeed"),
                    Expression::SpreadElement(_)
                ));
            }
            other => panic!("expected ArrayLiteral, got {other:?}"),
        }
    }

    #[test]
    fn spread_in_function_call() {
        let tree = parse_script("foo(1, ...args)");
        match first_expr(&tree) {
            Expression::Call { arguments, .. } => {
                assert_eq!(arguments.len(), 2);
                assert!(matches!(&arguments[0], Expression::NumericLiteral(1)));
                match &arguments[1] {
                    Expression::SpreadElement(inner) => {
                        assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "args"));
                    }
                    other => panic!("expected SpreadElement, got {other:?}"),
                }
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn spread_in_object_literal() {
        let tree = parse_script("({a: 1, ...obj})");
        match first_expr(&tree) {
            Expression::ObjectLiteral(properties) => {
                assert_eq!(properties.len(), 2);
                // First property: a: 1
                assert!(!properties[0].shorthand);
                // Second property: spread
                assert!(properties[1].shorthand);
                assert!(matches!(&properties[1].value, Expression::SpreadElement(_)));
            }
            other => panic!("expected ObjectLiteral, got {other:?}"),
        }
    }

    #[test]
    fn spread_only_object_literal() {
        let tree = parse_script("({...defaults})");
        match first_expr(&tree) {
            Expression::ObjectLiteral(properties) => {
                assert_eq!(properties.len(), 1);
                match &properties[0].value {
                    Expression::SpreadElement(inner) => {
                        assert!(
                            matches!(inner.as_ref(), Expression::Identifier(n) if n == "defaults")
                        );
                    }
                    other => panic!("expected SpreadElement, got {other:?}"),
                }
            }
            other => panic!("expected ObjectLiteral, got {other:?}"),
        }
    }

    #[test]
    fn spread_element_standalone() {
        let tree = parse_script("...x");
        match first_expr(&tree) {
            Expression::SpreadElement(inner) => {
                assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "x"));
            }
            other => panic!("expected SpreadElement, got {other:?}"),
        }
    }

    #[test]
    fn spread_in_new_expression() {
        let tree = parse_script("new Foo(...args)");
        match first_expr(&tree) {
            Expression::New { arguments, .. } => {
                assert_eq!(arguments.len(), 1);
                assert!(matches!(&arguments[0], Expression::SpreadElement(_)));
            }
            other => panic!("expected New, got {other:?}"),
        }
    }

    #[test]
    fn spread_multiple_in_array() {
        let tree = parse_script("[...a, ...b]");
        match first_expr(&tree) {
            Expression::ArrayLiteral(elements) => {
                assert_eq!(elements.len(), 2);
                assert!(matches!(
                    elements[0]
                        .as_ref()
                        .expect("serde serialization should succeed"),
                    Expression::SpreadElement(_)
                ));
                assert!(matches!(
                    elements[1]
                        .as_ref()
                        .expect("serde serialization should succeed"),
                    Expression::SpreadElement(_)
                ));
            }
            other => panic!("expected ArrayLiteral, got {other:?}"),
        }
    }

    #[test]
    fn spread_canonical_hash_stability() {
        let tree1 = parse_script("[...x]");
        let tree2 = parse_script("[...x]");
        assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
    }

    // -- RegExp literal parsing tests --

    #[test]
    fn parse_regexp_literal_simple_pattern() {
        assert_eq!(
            parse_regexp_literal("/hello/"),
            Some(("hello".to_string(), String::new()))
        );
    }

    #[test]
    fn parse_regexp_literal_with_flags() {
        assert_eq!(
            parse_regexp_literal("/hello/gi"),
            Some(("hello".to_string(), "gi".to_string()))
        );
    }

    #[test]
    fn parse_regexp_literal_with_all_flags() {
        assert_eq!(
            parse_regexp_literal("/test/gimsuy"),
            Some(("test".to_string(), "gimsuy".to_string()))
        );
    }

    #[test]
    fn parse_regexp_literal_escaped_slash() {
        assert_eq!(
            parse_regexp_literal(r"/a\/b/"),
            Some((r"a\/b".to_string(), String::new()))
        );
    }

    #[test]
    fn parse_regexp_literal_char_class_with_slash() {
        assert_eq!(
            parse_regexp_literal("/[/]/"),
            Some(("[/]".to_string(), String::new()))
        );
    }

    #[test]
    fn parse_regexp_literal_complex_pattern() {
        assert_eq!(
            parse_regexp_literal(r"/^[\w.+-]+@[\w-]+\.[\w.]+$/i"),
            Some((r"^[\w.+-]+@[\w-]+\.[\w.]+$".to_string(), "i".to_string()))
        );
    }

    #[test]
    fn parse_regexp_literal_not_regex() {
        assert_eq!(parse_regexp_literal("hello"), None);
        assert_eq!(parse_regexp_literal("42"), None);
        assert_eq!(parse_regexp_literal(""), None);
        assert_eq!(parse_regexp_literal(r#"/ab/.test("xabz")"#), None);
    }

    #[test]
    fn parse_regexp_literal_unclosed() {
        assert_eq!(parse_regexp_literal("/hello"), None);
    }

    #[test]
    fn regexp_literal_parses_as_expression() {
        let tree = parse_script("/test/gi;");
        match first_expr(&tree) {
            Expression::RegExpLiteral { pattern, flags } => {
                assert_eq!(pattern, "test");
                assert_eq!(flags, "gi");
            }
            other => panic!("expected RegExpLiteral, got {other:?}"),
        }
    }

    #[test]
    fn regexp_literal_receiver_member_call_parses_bd_wni4m() {
        let tree = parse_script(r#"/ab/.test("xabz");"#);
        match first_expr(&tree) {
            Expression::Call {
                callee, arguments, ..
            } => {
                assert_eq!(arguments.len(), 1);
                match callee.as_ref() {
                    Expression::Member {
                        object,
                        property,
                        computed,
                        ..
                    } => {
                        assert!(!computed);
                        assert!(matches!(
                            object.as_ref(),
                            Expression::RegExpLiteral { pattern, flags }
                                if pattern == "ab" && flags.is_empty()
                        ));
                        assert!(matches!(
                            property.as_ref(),
                            Expression::Identifier(name) if name == "test"
                        ));
                    }
                    other => panic!("expected member callee, got {other:?}"),
                }
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }

    #[test]
    fn regexp_literal_canonical_hash_stability() {
        let tree1 = parse_script("/test/gi;");
        let tree2 = parse_script("/test/gi;");
        assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
    }

    // bd-9vouw.41: a template literal is one opaque unit to every source
    // scanner, including its `${ ... }` substitutions, nested templates and
    // strings inside substitutions.

    #[test]
    fn quoted_byte_mask_spans_nested_templates_and_substitution_strings_bd_9vouw_41() {
        let src = "`a${`<${x}>`}b${\"`\"}c`, 2";
        let mask = quoted_byte_mask(src);
        let literal_end = src.find(", 2").expect("tail");
        assert!(mask[..literal_end].iter().all(|quoted| *quoted));
        assert!(mask[literal_end..].iter().all(|quoted| !*quoted));

        // A brace inside a substitution string does not end the substitution.
        let src = "`x${\"}\"}y` + 1";
        let mask = quoted_byte_mask(src);
        let literal_end = src.find(" + 1").expect("tail");
        assert!(mask[..literal_end].iter().all(|quoted| *quoted));
        assert!(mask[literal_end..].iter().all(|quoted| !*quoted));
    }

    #[test]
    fn quoted_byte_mask_reads_regex_literals_in_substitutions() {
        // js-yaml: the `'` inside `/'/g` is pattern text, not a string.
        let src = "`'${v.replace(/'/g, \"''\")}'` + 1";
        let mask = quoted_byte_mask(src);
        let literal_end = src.find(" + 1").expect("tail");
        assert!(mask[..literal_end].iter().all(|quoted| *quoted));
        assert!(mask[literal_end..].iter().all(|quoted| !*quoted));

        // After an operand a `/` divides, so `/ 2}` closes the substitution.
        let src = "`${a / 2}` + `${b}`";
        let mask = quoted_byte_mask(src);
        let first_end = src.find(" + ").expect("operator");
        assert!(mask[..first_end].iter().all(|quoted| *quoted));
        assert!(!mask[first_end + 1]);

        // A class may hold `/`, `` ` `` and `}`.
        let src = "`${s.split(/[/`}]/)}`;x";
        let mask = quoted_byte_mask(src);
        let literal_end = src.find(";x").expect("tail");
        assert!(mask[..literal_end].iter().all(|quoted| *quoted));
        assert!(!mask[literal_end]);
    }

    #[test]
    fn scanners_see_a_nested_template_as_one_literal_bd_9vouw_41() {
        // The inner template's `<`, `,`, `)` and `;` are template text, not
        // operators, separators, delimiters or statement ends.
        let parts: Vec<&str> =
            split_top_level_commas("`${[1,2].map(x=>`<${x}>`).join(\"\")}`, `a${\"`\"}b`")
                .into_iter()
                .map(str::trim)
                .collect();
        assert_eq!(
            parts,
            vec!["`${[1,2].map(x=>`<${x}>`).join(\"\")}`", "`a${\"`\"}b`"]
        );
        assert_eq!(find_matching_open_paren("f(`)${`(`}`)"), Some(1));
        assert_eq!(find_top_level_template_start("tag(`)`)`x`"), Some(8));
        // bd-9vouw.342: the last of chained templates.
        assert_eq!(find_top_level_template_start("rec`x``y``z`"), Some(9));
        assert_eq!(find_top_level_template_start("t`${`a`}``b`"), Some(9));
        let segments: Vec<&str> = split_statement_segments("a(`;${`;`}`); b;")
            .into_iter()
            .map(|(_, _, text)| text)
            .collect();
        assert_eq!(segments, vec!["a(`;${`;`}`)", "b"]);
        // `//` inside a nested template is not a comment.
        assert_eq!(
            strip_comments_to_whitespace("f(`${`http://x`}`); // c"),
            "f(`${`http://x`}`);     "
        );
    }

    #[test]
    fn parse_nested_template_literals_bd_9vouw_41() {
        for (source, statements) in [
            ("console.log(`${[1,2].map(x=>`<${x}>`).join(\"\")}`);", 1),
            (
                "const h = `<ul>${items.map(it => `<li class=\"${it.k}\">${it.v > 1 ? `big ${it.v}` : `small`}</li>`).join(\"\")}</ul>`;",
                1,
            ),
            ("console.log(`a${\"`\"}b`, `c${'`'.length}d`);", 1),
            ("const u = `${`http://x`}`; next();", 2),
            ("const v = `1${`2${`3${4}3`}2`}1`;\nconst w = 2;", 2),
        ] {
            let tree = parse_script(source);
            assert_eq!(tree.body.len(), statements, "{source}");
        }
    }
}
