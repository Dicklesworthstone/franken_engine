// Deterministic parser interface for ES2020 script/module goals.
//
// The parser trait is generic over input source and emits canonical `IR0`
// syntax artifacts from `crate::ast`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::ast::ParseGoal;
use crate::ast::{
    ArrowBody, AssignmentOperator, BinaryOperator, BindingPattern, BlockStatement, BreakStatement,
    CatchClause, ClassDeclaration, ContinueStatement, DoWhileStatement, ExportDeclaration,
    ExportKind, Expression, ExpressionStatement, ForInStatement, ForOfStatement, ForStatement,
    FunctionDeclaration, FunctionParam, IfStatement, ImportClause, ImportDeclaration,
    ImportSpecifier, MethodDefinition, MethodKind, ObjectPatternProperty, ObjectProperty,
    ReturnStatement, SourceSpan, Statement, SwitchCase, SwitchStatement, SyntaxTree,
    ThrowStatement, TryCatchStatement, UnaryOperator, UpdateOperator, VariableDeclaration,
    VariableDeclarationKind, VariableDeclarator, WhileStatement,
};
use crate::deterministic_serde::{self, CanonicalValue};

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
        self.materialize_with_tree(&parsed, Some(source_text))
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
            Ok(source) => match parse_source(&source.text, &source.label, goal, options) {
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
            },
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
            Ok(source) => match parse_source(&source.text, &source.label, goal, options) {
                Ok(tree) => {
                    let event_ir = ParseEventIr::from_parse_source(
                        &tree,
                        &source.text,
                        source.label.clone(),
                        options.mode,
                    );
                    let materialized = event_ir.materialize_with_tree(&tree, Some(&source.text));
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
            },
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
        || (starts_with_keyword(statement, "try")
            && (starts_with_keyword(following, "catch")
                || starts_with_keyword(following, "finally")))
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
    CatchAwaitBody,
    CatchAwaitFinally,
    FinallyAwaitBody,
    DoAwaitWhile,
    DoWhileAwaitCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingClauseContinuation {
    kind: PendingClauseKind,
    fragment_start: usize,
}

fn pending_clause_after_statement(
    statement: &str,
    following: &str,
    fragment_start: usize,
) -> Option<PendingClauseContinuation> {
    let kind = if starts_with_keyword(statement, "if") && starts_with_keyword(following, "else") {
        PendingClauseKind::IfAwaitElse
    } else if starts_with_keyword(statement, "try")
        && (starts_with_keyword(following, "catch") || starts_with_keyword(following, "finally"))
    {
        PendingClauseKind::TryAwaitHandler
    } else if starts_with_keyword(statement, "do") && starts_with_keyword(following, "while") {
        PendingClauseKind::DoAwaitWhile
    } else {
        return None;
    };
    Some(PendingClauseContinuation {
        kind,
        fragment_start,
    })
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

fn catch_clause_is_complete(fragment: &str, grammar_context: ScanGrammarContext) -> bool {
    let Some(after_catch) = clause_keyword_tail(fragment, "catch", grammar_context) else {
        return false;
    };
    if after_catch.is_empty() {
        return false;
    }
    let body_source = if after_catch.starts_with('(') {
        let Some((_, remaining)) =
            extract_balanced_with_context(after_catch, '(', ')', grammar_context)
        else {
            return false;
        };
        trim_binding_pattern_leading_trivia_with_context(remaining, grammar_context)
            .unwrap_or_default()
    } else {
        after_catch
    };
    body_source.starts_with('{')
        && extract_balanced_with_context(body_source, '{', '}', grammar_context).is_some()
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
    source.starts_with("?.") || matches!(source.chars().next(), Some('(' | '[' | '.' | '`'))
}

fn restricted_statement_ends_at_line_terminator(
    source: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    ["return", "throw", "break", "continue"]
        .into_iter()
        .any(|keyword| {
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
}

fn pending_clause_with_kind(
    kind: PendingClauseKind,
    fragment_start: usize,
) -> PendingClauseContinuation {
    PendingClauseContinuation {
        kind,
        fragment_start,
    }
}

fn completed_clause_statement(
    await_else_after_completion: bool,
    next_after_trivia: &str,
    current_len: usize,
) -> Option<PendingClauseContinuation> {
    (await_else_after_completion && starts_with_keyword(next_after_trivia, "else")).then_some(
        pending_clause_with_kind(PendingClauseKind::IfAwaitElse, current_len),
    )
}

fn advance_clause_statement(
    pending: PendingClauseContinuation,
    mut statement: &str,
    next_after_trivia: &str,
    current_len: usize,
    mut await_else_after_completion: bool,
    grammar_context: ScanGrammarContext,
) -> Option<PendingClauseContinuation> {
    loop {
        if starts_with_keyword(statement, "if") {
            match parenthesized_statement_status(statement, "if", grammar_context) {
                Some(ParenthesizedStatementStatus::MissingCondition)
                    if next_after_trivia.starts_with('(') =>
                {
                    return Some(pending);
                }
                Some(ParenthesizedStatementStatus::MissingBody) => {
                    return Some(pending_clause_with_kind(
                        PendingClauseKind::ElseIfAwaitBody,
                        current_len,
                    ));
                }
                Some(ParenthesizedStatementStatus::Complete) => {
                    let tail = clause_keyword_tail(statement, "if", grammar_context)?;
                    let (_, body) = extract_balanced_with_context(tail, '(', ')', grammar_context)?;
                    statement =
                        trim_binding_pattern_leading_trivia_with_context(body, grammar_context)?;
                    await_else_after_completion = true;
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
                    let kind = if await_else_after_completion {
                        PendingClauseKind::ElseIfAwaitBody
                    } else {
                        PendingClauseKind::ElseAwaitStatement
                    };
                    return Some(pending_clause_with_kind(kind, current_len));
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

        if starts_with_keyword(statement, "try")
            && (starts_with_keyword(next_after_trivia, "catch")
                || starts_with_keyword(next_after_trivia, "finally"))
        {
            return Some(pending_clause_with_kind(
                PendingClauseKind::TryAwaitHandler,
                current_len,
            ));
        }
        if starts_with_keyword(statement, "do") && starts_with_keyword(next_after_trivia, "while") {
            return Some(pending_clause_with_kind(
                PendingClauseKind::DoAwaitWhile,
                current_len,
            ));
        }

        if declaration_source_needs_continuation(statement, next_after_trivia, grammar_context) {
            let kind = if await_else_after_completion {
                PendingClauseKind::ElseIfDeclarationContinuation
            } else {
                PendingClauseKind::ElseDeclarationContinuation
            };
            return Some(pending_clause_with_kind(kind, current_len));
        }
        if expression_statement_continues(statement, next_after_trivia, grammar_context) {
            let kind = if await_else_after_completion {
                PendingClauseKind::ElseIfExpressionContinuation
            } else {
                PendingClauseKind::ElseExpressionContinuation
            };
            return Some(pending_clause_with_kind(kind, current_len));
        }
        return completed_clause_statement(
            await_else_after_completion,
            next_after_trivia,
            current_len,
        );
    }
}

fn advance_pending_clause(
    pending: PendingClauseContinuation,
    current_text: &str,
    next_after_trivia: &str,
    grammar_context: ScanGrammarContext,
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
                return Some(pending_clause_with_kind(
                    PendingClauseKind::ElseAwaitStatement,
                    current_text.len(),
                ));
            }
            advance_clause_statement(
                pending,
                alternate,
                next_after_trivia,
                current_text.len(),
                false,
                grammar_context,
            )
        }
        PendingClauseKind::ElseAwaitStatement => advance_clause_statement(
            pending,
            fragment,
            next_after_trivia,
            current_text.len(),
            false,
            grammar_context,
        ),
        PendingClauseKind::ElseExpressionContinuation => {
            if expression_statement_continues(fragment, next_after_trivia, grammar_context) {
                Some(pending_clause_with_kind(
                    PendingClauseKind::ElseExpressionContinuation,
                    current_text.len(),
                ))
            } else {
                None
            }
        }
        PendingClauseKind::ElseDeclarationContinuation => {
            let line_ends_continuation = fragment.ends_with(',') || fragment.ends_with('=');
            if pending_declaration_fragment_needs_continuation(
                fragment,
                line_ends_continuation,
                next_after_trivia,
                grammar_context,
            ) {
                Some(pending_clause_with_kind(
                    PendingClauseKind::ElseDeclarationContinuation,
                    current_text.len(),
                ))
            } else {
                None
            }
        }
        PendingClauseKind::ElseIfAwaitBody => advance_clause_statement(
            pending,
            fragment,
            next_after_trivia,
            current_text.len(),
            true,
            grammar_context,
        ),
        PendingClauseKind::ElseIfExpressionContinuation => {
            if expression_statement_continues(fragment, next_after_trivia, grammar_context) {
                Some(pending_clause_with_kind(
                    PendingClauseKind::ElseIfExpressionContinuation,
                    current_text.len(),
                ))
            } else if starts_with_keyword(next_after_trivia, "else") {
                Some(pending_clause_with_kind(
                    PendingClauseKind::IfAwaitElse,
                    current_text.len(),
                ))
            } else {
                None
            }
        }
        PendingClauseKind::ElseIfDeclarationContinuation => {
            let line_ends_continuation = fragment.ends_with(',') || fragment.ends_with('=');
            if pending_declaration_fragment_needs_continuation(
                fragment,
                line_ends_continuation,
                next_after_trivia,
                grammar_context,
            ) {
                Some(pending_clause_with_kind(
                    PendingClauseKind::ElseIfDeclarationContinuation,
                    current_text.len(),
                ))
            } else if starts_with_keyword(next_after_trivia, "else") {
                Some(pending_clause_with_kind(
                    PendingClauseKind::IfAwaitElse,
                    current_text.len(),
                ))
            } else {
                None
            }
        }
        PendingClauseKind::TryAwaitHandler => {
            if starts_with_keyword(fragment, "catch") {
                let after_catch = clause_keyword_tail(fragment, "catch", grammar_context)?;
                if after_catch.is_empty() {
                    return if next_after_trivia.starts_with('{') {
                        Some(pending_clause_with_kind(
                            PendingClauseKind::CatchAwaitBody,
                            current_text.len(),
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
                        return Some(pending_clause_with_kind(
                            PendingClauseKind::CatchAwaitBody,
                            current_text.len(),
                        ));
                    }
                }
                if !catch_clause_is_complete(fragment, grammar_context) {
                    return None;
                }
                starts_with_keyword(next_after_trivia, "finally").then_some(
                    pending_clause_with_kind(
                        PendingClauseKind::CatchAwaitFinally,
                        current_text.len(),
                    ),
                )
            } else if starts_with_keyword(fragment, "finally") {
                let body = clause_keyword_tail(fragment, "finally", grammar_context)?;
                if body.is_empty() && next_after_trivia.starts_with('{') {
                    Some(pending_clause_with_kind(
                        PendingClauseKind::FinallyAwaitBody,
                        current_text.len(),
                    ))
                } else {
                    None
                }
            } else {
                None
            }
        }
        PendingClauseKind::CatchAwaitBody => {
            if !fragment.starts_with('{')
                || extract_balanced_with_context(fragment, '{', '}', grammar_context).is_none()
            {
                return None;
            }
            starts_with_keyword(next_after_trivia, "finally").then_some(pending_clause_with_kind(
                PendingClauseKind::CatchAwaitFinally,
                current_text.len(),
            ))
        }
        PendingClauseKind::CatchAwaitFinally => {
            if !starts_with_keyword(fragment, "finally") {
                return None;
            }
            let body = clause_keyword_tail(fragment, "finally", grammar_context)?;
            if body.is_empty() && next_after_trivia.starts_with('{') {
                Some(pending_clause_with_kind(
                    PendingClauseKind::FinallyAwaitBody,
                    current_text.len(),
                ))
            } else {
                None
            }
        }
        PendingClauseKind::FinallyAwaitBody => None,
        PendingClauseKind::DoAwaitWhile => {
            if !starts_with_keyword(fragment, "while") {
                return None;
            }
            let condition = clause_keyword_tail(fragment, "while", grammar_context)?;
            if condition.is_empty() && next_after_trivia.starts_with('(') {
                Some(pending_clause_with_kind(
                    PendingClauseKind::DoWhileAwaitCondition,
                    current_text.len(),
                ))
            } else {
                None
            }
        }
        PendingClauseKind::DoWhileAwaitCondition => None,
    }
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

fn trailing_statement_source(source: &str, grammar_context: ScanGrammarContext) -> Option<&str> {
    trim_binding_pattern_trivia_with_context(source, grammar_context)
        .filter(|source| !source.ends_with(';'))
        .and_then(|_| {
            split_statement_segments_with_context(source, grammar_context)
                .last()
                .map(|(_, _, statement)| *statement)
        })
        .and_then(|source| trim_binding_pattern_trivia_with_context(source, grammar_context))
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
    !next_after_trivia.is_empty()
        && ((body.is_empty() && (next_selects_declaration || let_expression_continues))
            || source.ends_with(',')
            || source.ends_with('=')
            || matches!(next, Some(',' | '=')))
}

fn pending_declaration_fragment_needs_continuation(
    line: &str,
    line_ends_continuation: bool,
    next_after_trivia: &str,
    grammar_context: ScanGrammarContext,
) -> bool {
    let next = next_after_trivia.chars().next();
    let next_continues_declaration =
        !next_after_trivia.is_empty() && matches!(next, Some(',' | '='));
    let Some(source) = trim_binding_pattern_trivia_with_context(line, grammar_context) else {
        // The opening quote/comment can be on an earlier physical line, so a
        // closing fragment need not be self-contained lexical input.
        return line_ends_continuation || next_continues_declaration;
    };
    if source.is_empty() {
        return true;
    }
    let Some(trailing_source) = trailing_statement_source(source, grammar_context) else {
        return false;
    };
    if declaration_source_needs_continuation(trailing_source, next_after_trivia, grammar_context) {
        return true;
    }
    !next_after_trivia.is_empty()
        && (trailing_source.ends_with(',')
            || trailing_source.ends_with('=')
            || next_continues_declaration)
}

/// Merge physical lines into logical lines by tracking brace/paren/bracket depth.
/// When a line ends with unbalanced delimiters, subsequent lines are merged until balance.
fn merge_logical_lines_with_context(
    text: &str,
    grammar_context: ScanGrammarContext,
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
    let mut current_text = String::new();
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
        // is otherwise flushable. A pending declaration is updated from the
        // newly appended physical-line fragment, so neither comments nor one
        // declarator/comma per line rescan the growing logical statement.
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
                let line_ends_continuation =
                    line_has_significant_code && matches!(last_significant, Some(',' | '='));
                (
                    !line_has_significant_code
                        || pending_declaration_fragment_needs_continuation(
                            line,
                            line_ends_continuation,
                            next_after_trivia,
                            grammar_context,
                        ),
                    None,
                )
            } else if accumulating && pending_clause_continuation.is_some() {
                (
                    false,
                    if !line_has_significant_code {
                        pending_clause_continuation
                    } else {
                        pending_clause_continuation.and_then(|pending| {
                            advance_pending_clause(
                                pending,
                                &current_text,
                                next_after_trivia,
                                grammar_context,
                            )
                        })
                    },
                )
            } else {
                let trailing_source = trailing_statement_source(&current_text, grammar_context);
                let declaration_needs_binding = trailing_source.is_some_and(|source| {
                    declaration_source_needs_continuation(
                        source,
                        next_after_trivia,
                        grammar_context,
                    )
                });
                let clause_continues = trailing_source.and_then(|source| {
                    pending_clause_after_statement(source, next_after_trivia, current_text.len())
                });
                (declaration_needs_binding, clause_continues)
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
            accumulating = false;
            pending_declaration_continuation = false;
            pending_clause_continuation = None;
        } else {
            accumulating = true;
            pending_declaration_continuation = declaration_needs_binding;
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

    let logical_lines = merge_logical_lines_with_context(
        text,
        ScanGrammarContext::from_execution_context(&context),
    );
    let source_line_starts = source_line_start_offsets(text);
    let mut statements = Vec::new();

    for logical_line in &logical_lines {
        let logical_line_starts = logical_line_start_offsets(&logical_line.text);
        for (start_in_line, end_in_line, statement_text) in split_statement_segments_with_context(
            &logical_line.text,
            ScanGrammarContext::from_execution_context(&context),
        ) {
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
            statements.push(parse_statement(statement_text, goal, span, &mut context)?);
        }
    }

    let source_len = to_u64(text.len(), source_label, None)?;
    let span = SourceSpan::new(0, source_len, 1, 1, line_count(text), 1);
    Ok(SyntaxTree {
        goal,
        body: statements,
        span,
    })
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

fn line_count(source: &str) -> u64 {
    (source_line_terminator_ranges(source).len() as u64).saturating_add(1)
}

fn split_statement_segments_with_context(
    line: &str,
    grammar_context: ScanGrammarContext,
) -> Vec<(usize, usize, &str)> {
    let mut out = Vec::new();
    let mut segment_start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;

    scan_binding_pattern_source_with_context(line, grammar_context, |index, ch, depth, quoted| {
        if quoted {
            return;
        }
        if depth == 0 && async_function_asi_boundary(line, segment_start, index, grammar_context) {
            push_segment(&mut out, line, segment_start, index, grammar_context);
            segment_start = index;
        }
        match ch {
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
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
                    let starts_with_block = starts_with_keyword(seg, "function")
                        || strip_async_function_keyword(seg).is_some()
                        || starts_with_keyword(seg, "if")
                        || starts_with_keyword(seg, "for")
                        || starts_with_keyword(seg, "while")
                        || starts_with_keyword(seg, "do")
                        || starts_with_keyword(seg, "try")
                        || starts_with_keyword(seg, "switch")
                        || starts_with_keyword(seg, "class");
                    if starts_with_block {
                        let after = index.saturating_add(1);
                        let rest_with_trivia = &line[after..];
                        let rest = trim_directive_trivia(rest_with_trivia).0;
                        let continues = statement_clause_continues(seg, rest);
                        if !rest_with_trivia.trim_start().is_empty() && !continues {
                            push_segment(&mut out, line, segment_start, after, grammar_context);
                            segment_start = after;
                        }
                    }
                }
            }
            ';' if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 => {
                push_segment(&mut out, line, segment_start, index, grammar_context);
                segment_start = index.saturating_add(ch.len_utf8());
            }
            _ => {}
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
    if statement.starts_with("import ") || statement == "import" {
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

    if statement.starts_with("export ") || statement == "export" {
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
        return self::parse_break_statement(statement, span);
    }
    if statement == "continue"
        || statement.starts_with("continue ")
        || statement.starts_with("continue;")
    {
        return self::parse_continue_statement(statement, span);
    }
    if starts_with_keyword(statement, "function")
        || strip_async_function_keyword(statement).is_some()
    {
        return self::parse_function_declaration(statement, span, context);
    }
    if statement.starts_with("class ") || statement.starts_with("class{") {
        return self::parse_class_declaration(statement, span, context);
    }
    if statement.starts_with('{') && statement.ends_with('}') {
        return self::parse_block_statement(statement, goal, span, context);
    }

    let expression_source = statement.strip_suffix(';').unwrap_or(statement).trim();
    let expression = parse_expression(expression_source, &span, context, 1)?;
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
    let body = statement
        .get("import ".len()..)
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

    let (binding_raw, source_raw) = split_import_from_clause(body).ok_or_else(|| {
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
        let default_binding_source = default_binding_raw.trim();
        let trailing_clause = trailing_clause_raw.trim();

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

    for specifier in split_top_level_commas(inner) {
        if trim_binding_pattern_trivia(specifier).is_none_or(str::is_empty) {
            return false;
        }
        if parse_named_import_specifier_parts(specifier).is_none() {
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

    let mut specifiers = Vec::new();
    let mut seen_local = BTreeSet::new();

    for specifier in split_top_level_commas(inner) {
        if trim_binding_pattern_trivia(specifier).is_none_or(str::is_empty) {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named import specifier list contains an empty entry",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }

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
    let body = statement
        .get("export ".len()..)
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

    let kind = if let Some(default_expr) = body.strip_prefix("default ") {
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
) -> ParseResult<String> {
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

    let trailing = inner_and_trailing[close_index + 1..].trim();
    if !trailing.is_empty() {
        let Some(source_raw) = trailing.strip_prefix("from").map(str::trim_start) else {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "named export trailing clause must be `from <quoted-source>`",
                source_label.to_string(),
                Some(span.clone()),
            ));
        };

        if parse_quoted_string(source_raw).is_none() {
            return Err(ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                "export source must be quoted",
                source_label.to_string(),
                Some(span.clone()),
            ));
        }
    }

    Ok(canonicalize_whitespace(clause))
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

    for specifier in specifiers.split(',') {
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
        let local = parts.next().unwrap();
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
            && !chars
                .peek()
                .is_some_and(|(_, next)| matches!(*next, '?' | '.'))
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
                if let Some((_pattern, _flags, consumed)) =
                    parse_regexp_literal_prefix(&source[index..])
                {
                    let regexp_end = index.saturating_add(consumed);
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
        let cooked = parse_binding_property_string_literal(source).ok_or_else(&invalid_key)?;
        return Ok(Expression::StringLiteral(cooked));
    }

    if source.ends_with('n') && binding_numeric_key_starts_like_literal(source) {
        let key = parse_bigint_binding_property_key(source).ok_or_else(&invalid_key)?;
        return Ok(Expression::StringLiteral(key));
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
        Expression::StringLiteral(js_number_property_key(value))
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

fn parse_binding_property_string_literal(source: &str) -> Option<String> {
    if source.len() < 2 {
        return None;
    }
    let delimiter = source.chars().next()?;
    if !matches!(delimiter, '\'' | '"') || source.chars().next_back()? != delimiter {
        return None;
    }
    unescape_binding_property_string(&source[1..source.len() - 1], delimiter)
}

fn unescape_binding_property_string(inner: &str, delimiter: char) -> Option<String> {
    if !inner.contains('\\') {
        return (!inner.contains(delimiter) && !inner.contains('\n') && !inner.contains('\r'))
            .then(|| inner.to_string());
    }
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            if ch == delimiter || matches!(ch, '\n' | '\r') {
                return None;
            }
            out.push(ch);
            continue;
        }
        match chars.next()? {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000C}'),
            'v' => out.push('\u{000B}'),
            '0' => {
                if chars.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                    return None;
                }
                out.push('\0');
            }
            '1'..='9' => return None,
            '\\' => out.push('\\'),
            '\'' => out.push('\''),
            '"' => out.push('"'),
            '`' => out.push('`'),
            '\n' => {}
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            '\u{2028}' | '\u{2029}' => {}
            'x' => {
                let high = chars.next()?.to_digit(16)?;
                let low = chars.next()?.to_digit(16)?;
                out.push(char::from_u32(high * 16 + low)?);
            }
            'u' => {
                let first = decode_binding_unicode_escape_value(&mut chars)?;
                let decoded = if (0xD800..=0xDBFF).contains(&first) {
                    if chars.next()? != '\\' || chars.next()? != 'u' {
                        return None;
                    }
                    let low = decode_binding_unicode_escape_value(&mut chars)?;
                    if !(0xDC00..=0xDFFF).contains(&low) {
                        return None;
                    }
                    char::from_u32(0x10000 + ((first - 0xD800) << 10) + (low - 0xDC00))?
                } else {
                    char::from_u32(first)?
                };
                out.push(decoded);
            }
            other => out.push(other),
        }
    }
    Some(out)
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

    // Arrow function: lowest precedence (lower than assignment).
    if let Some(result) = try_parse_arrow_function(expression, span, context, recursion_depth) {
        return result;
    }

    // YieldExpression is an AssignmentExpression form, so it must claim the
    // whole trailing assignment before the higher-precedence binary scanner.
    if context.allow_yield_expression
        && let Some(rest) = strip_contextual_keyword(expression, "yield")
    {
        return parse_yield_expression(expression, rest, span, context, recursion_depth);
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
    expression: &str,
    rest: &str,
    span: &SourceSpan,
    context: &mut ParseExecutionContext<'_>,
    recursion_depth: u64,
) -> ParseResult<Expression> {
    let (rest, saw_line_terminator) = trim_directive_trivia(rest);
    if rest.starts_with(',') {
        // SequenceExpression does not yet have a dedicated AST carrier. Keep
        // the legacy deterministic fallback without misattaching the sequence
        // tail as YieldExpression's argument.
        return Ok(Expression::Raw(canonicalize_whitespace(expression)));
    }
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
    if let Some(value) = parse_quoted_string(expression) {
        return Ok(Expression::StringLiteral(value));
    }

    // Regex literal: /pattern/flags
    if let Some((pattern, flags)) = parse_regexp_literal(expression) {
        return Ok(Expression::RegExpLiteral { pattern, flags });
    }

    if let Some(value) = parse_i64_numeric_literal(expression) {
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
        return parse_expression(inner.trim(), span, context, recursion_depth + 1);
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

    if let Some(identifier) = parse_identifier_reference(expression, span, context)? {
        return Ok(Expression::Identifier(identifier));
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
    let (is_async, rest) = if let Some(after_async) = expr.strip_prefix("async") {
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
            return None;
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
        let arrow_pos = find_top_level_arrow(
            rest,
            ScanGrammarContext::from_execution_context(context).expression(),
        )?;
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
            let expr = parse_expression(expr_src.trim(), span, context, recursion_depth + 1)?;
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
    let complete = scan_binding_pattern_source_with_context(
        expr,
        ScanGrammarContext::from_execution_context(context).expression(),
        |index, _ch, depth, quoted| {
            if assignment.is_some() || quoted || depth != 0 {
                return;
            }
            let Some((operator, len)) = match_assignment_operator_at(bytes, index) else {
                return;
            };
            if !expr[..index].trim().is_empty() && !expr[index + len..].trim().is_empty() {
                assignment = Some((operator, index, len));
            }
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
                && bytes.get(index + 1) != Some(&b'.')
                && bytes.get(index + 1) != Some(&b'?')
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
    let colon_idx = find_ternary_colon(rest, grammar_context)?;
    let consequent_src = rest[..colon_idx].trim();
    let alternate_src = rest[colon_idx + 1..].trim();
    if test_src.is_empty() || consequent_src.is_empty() || alternate_src.is_empty() {
        return None;
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
            if ch == '?' {
                match bytes.get(index + 1).copied() {
                    // Nullish `??` — skip both bytes, not a ternary `?`.
                    Some(b'?') => {}
                    // Optional chaining `?.` — not a ternary `?`.
                    Some(b'.') => {}
                    _ => question_depth += 1,
                }
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
    let grammar_context = ScanGrammarContext::from_execution_context(context).expression();
    let complete =
        scan_binding_pattern_source_with_context(expr, grammar_context, |i, _ch, depth, quoted| {
            if quoted || depth != 0 || i < skip_until {
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
                    && lhs
                        .as_bytes()
                        .last()
                        .is_none_or(|&c| is_operator_context_byte(c));
                if !lhs.is_empty() && !rhs.is_empty() && !unary_sign {
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
        let property = match parse_expression(prop_src, span, context, recursion_depth + 1) {
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
        if !quoted
            && depth == 0
            && ch == '?'
            && bytes.get(index + 1).is_some_and(|next| *next == b'.')
        {
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
                if inner.trim().is_empty() || !rest.trim().is_empty() {
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
            });
        }
    }
    Ok(Expression::ObjectLiteral(properties))
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
    let cleaned: String;
    let digits_ref = if trimmed.contains('_') {
        cleaned = trimmed.replace('_', "");
        cleaned.as_str()
    } else {
        trimmed
    };

    // Must contain a decimal point or exponent to be a float
    if !digits_ref.contains('.') && !digits_ref.contains('e') && !digits_ref.contains('E') {
        return None;
    }

    // Try to parse as f64
    digits_ref.parse::<f64>().ok()
}

fn cook_quoted_string_line_continuations(inner: &str) -> Option<String> {
    let mut cooked = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if matches!(ch, '\n' | '\r') || (escaped && matches!(ch, '\u{2028}' | '\u{2029}')) {
            if !escaped {
                return None;
            }
            let continuation = cooked.pop();
            debug_assert_eq!(continuation, Some('\\'));
            if ch == '\r' && chars.peek() == Some(&'\n') {
                chars.next();
            }
            escaped = false;
            continue;
        }

        cooked.push(ch);
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        }
    }
    Some(cooked)
}

fn parse_quoted_string(input: &str) -> Option<String> {
    if input.len() < 2 {
        return None;
    }
    let delimiter = input.chars().next()?;
    if !matches!(delimiter, '\'' | '"') || input.chars().next_back()? != delimiter {
        return None;
    }
    cook_quoted_string_line_continuations(
        &input[delimiter.len_utf8()..input.len() - delimiter.len_utf8()],
    )
}

/// Parse a regex literal: `/pattern/flags`.
///
/// The pattern may contain escaped slashes (`\/`) or character classes with
/// slashes (`[/]`). Flags are the standard ECMAScript regex flags: g, i, m, s, u, y.
fn parse_regexp_literal(input: &str) -> Option<(String, String)> {
    let (pattern, flags, _consumed) = parse_regexp_literal_prefix(input)?;
    Some((pattern, flags))
}

fn parse_regexp_literal_prefix(input: &str) -> Option<(String, String, usize)> {
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
            // Parse flags (g, i, m, s, u, y, d)
            let mut flags = String::new();
            for fc in rest.chars() {
                if matches!(fc, 'g' | 'i' | 'm' | 's' | 'u' | 'y' | 'd') {
                    flags.push(fc);
                } else {
                    // Stop at non-flag character (could be operator or whitespace)
                    break;
                }
            }
            let consumed = i + 1 + flags.len();
            return Some((pattern.to_string(), flags, consumed));
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
    let logical_lines = merge_logical_lines_with_context(
        trimmed,
        ScanGrammarContext::from_execution_context(context),
    );
    let mut stmts = Vec::new();
    for ll in &logical_lines {
        for (_start, _end, text) in split_statement_segments_with_context(
            &ll.text,
            ScanGrammarContext::from_execution_context(context),
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
    let condition = parse_expression(condition_src.trim(), &span, context, 1)?;

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
                if let Some(after_else) = after.strip_prefix("else") {
                    Some(trim_directive_trivia(after_else).0.trim_end().to_string())
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
    let (header_src, rest) = extract_balanced_with_context(
        after_for,
        '(',
        ')',
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
        Some(parse_expression(cond_src, &span, context, 1)?)
    };
    let update = if update_src.is_empty() {
        None
    } else {
        Some(parse_expression(update_src, &span, context, 1)?)
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
        let Ok(parsed_binding) = parse_binding_pattern(binding_src, span, context, grammar_context)
        else {
            continue;
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
        let object = parse_expression(rhs, span, context, 1)?;
        Ok(Some(Statement::ForIn(ForInStatement {
            binding,
            binding_kind,
            pre_loop_initializer,
            object,
            body: Box::new(body),
            span: span.clone(),
        })))
    } else {
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
    let condition = parse_expression(condition_src.trim(), &span, context, 1)?;
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
        // Find "while" keyword at top level.
        let while_idx = after_do.find("while").ok_or_else(|| {
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
    let condition = parse_expression(condition_src.trim(), &span, context, 1)?;

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
        Some(parse_expression(body, &span, context, 1)?)
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
    let argument = parse_expression(body, &span, context, 1)?;
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
    let discriminant = parse_expression(disc_src.trim(), &span, context, 1)?;

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
            let colon_idx = after_case.find(':').ok_or_else(|| {
                ParseError::new(
                    ParseErrorCode::UnsupportedSyntax,
                    "switch case requires a colon after test expression",
                    context.source_label.to_string(),
                    Some(span.clone()),
                )
            })?;
            let test_src = after_case[..colon_idx].trim();
            let test = Some(parse_expression(test_src, &span, context, 1)?);
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
            let Ok(super_class) = parse_expression(super_name, span, context, 1) else {
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
    // [static] [get|set] name(...) { ... }
    // We scan for `}` at brace_depth==0 to find method boundaries.
    let segments = split_class_members(body);
    for segment in segments {
        let segment = segment.trim();
        if segment.is_empty() || segment == ";" {
            continue;
        }
        let is_static = segment.starts_with("static ");
        let rest = if is_static {
            segment
                .strip_prefix("static ")
                .unwrap_or(segment)
                .trim_start()
        } else {
            segment
        };

        let kind;
        let rest = if starts_with_keyword(rest, "get") {
            kind = MethodKind::Get;
            rest.strip_prefix("get").unwrap_or(rest).trim_start()
        } else if starts_with_keyword(rest, "set") {
            kind = MethodKind::Set;
            rest.strip_prefix("set").unwrap_or(rest).trim_start()
        } else {
            kind = MethodKind::Method;
            rest
        };

        // Extract method name (up to `(`).
        let paren_idx = rest.find('(').ok_or_else(|| {
            ParseError::new(
                ParseErrorCode::UnsupportedSyntax,
                format!("class method requires parameter list: {}", segment),
                context.source_label.to_string(),
                Some(span.clone()),
            )
        })?;
        let method_name = rest[..paren_idx].trim();
        let actual_kind = if method_name == "constructor" {
            MethodKind::Constructor
        } else {
            kind
        };
        let key = Expression::Identifier(method_name.to_string());
        let rest = &rest[paren_idx..];

        // Parse parameters.
        let (params_src, rest) =
            extract_balanced_with_context(rest, '(', ')', ScanGrammarContext::STRICT_SCRIPT)
                .ok_or_else(|| {
                    ParseError::new(
                        ParseErrorCode::UnsupportedSyntax,
                        "class method has unbalanced parentheses",
                        context.source_label.to_string(),
                        Some(span.clone()),
                    )
                })?;
        // Parse method body.
        let rest = rest.trim_start();
        let (body_src, _) =
            extract_balanced_with_context(rest, '{', '}', ScanGrammarContext::STRICT_SCRIPT)
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
        let params = with_grammar_context(context, true, false, false, false, false, |context| {
            parse_arrow_params(params_src, span, context)
        })?;
        validate_parameter_binding_names(&params, true, false, false, false, span, context)?;
        validate_use_strict_parameter_list(&params, has_own_use_strict_directive, span, context)?;
        let body_stmts =
            with_grammar_context(context, true, false, false, false, false, |context| {
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
            computed: false,
            span: span.clone(),
        });
    }

    Ok(methods)
}

/// Split class body into individual method segments.
fn split_class_members(body: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut brace_depth = 0usize;
    let mut paren_depth = 0usize;

    scan_binding_pattern_source_with_context_seeded(
        body,
        ScanGrammarContext::STRICT_SCRIPT,
        0,
        |index, ch, _, quoted| {
            if quoted {
                return;
            }
            match ch {
                '(' => paren_depth = paren_depth.saturating_add(1),
                ')' => paren_depth = paren_depth.saturating_sub(1),
                '{' => brace_depth = brace_depth.saturating_add(1),
                '}' => {
                    if brace_depth > 0 {
                        brace_depth = brace_depth.saturating_sub(1);
                    }
                    if brace_depth == 0 && paren_depth == 0 {
                        let end = index.saturating_add(ch.len_utf8());
                        segments.push(&body[start..end]);
                        start = end;
                    }
                }
                ';' if brace_depth == 0 && paren_depth == 0 => {
                    // Semicolons between methods — skip.
                    start = index.saturating_add(ch.len_utf8());
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
mod tests {
    use std::collections::BTreeSet;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn script_goal_rejects_import_declaration() {
        let parser = CanonicalEs2020Parser;
        let error = parser
            .parse("import x from 'mod';", ParseGoal::Script)
            .expect_err("script goal should reject import");
        assert_eq!(error.code, ParseErrorCode::InvalidGoal);
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
        let source = "await work";
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
            .parse("await   work", ParseGoal::Script)
            .expect("left parse");
        let right = parser
            .parse("await work", ParseGoal::Script)
            .expect("right parse");

        let left_expr = match &left.body[0] {
            Statement::Expression(expr) => &expr.expression,
            _ => panic!("expected expression statement"),
        };
        let right_expr = match &right.body[0] {
            Statement::Expression(expr) => &expr.expression,
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
    fn string_literal_single_quotes_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser.parse("'hello'", ParseGoal::Script).expect("parse");
        match &tree.body[0] {
            Statement::Expression(expr) => {
                assert_eq!(
                    expr.expression,
                    Expression::StringLiteral("hello".to_string())
                );
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
                assert_eq!(
                    expr.expression,
                    Expression::StringLiteral("world".to_string())
                );
            }
            _ => panic!("expected expression statement"),
        }
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
    fn await_expression_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("await fetch", ParseGoal::Script)
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
                    Some(Expression::StringLiteral("a,b".to_string()))
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
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
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
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
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
    fn whole_pattern_defaults_parse_before_containers_bd_laab3() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "function objectDefault({ a = 5 } = {}) { return a; }",
                ParseGoal::Script,
            )
            .expect("whole object-pattern default should parse");
        let Statement::FunctionDeclaration(function) = &tree.body[0] else {
            panic!("expected function declaration");
        };
        let BindingPattern::AssignmentPattern { left, .. } = &function.params[0].pattern else {
            panic!("expected outer assignment pattern");
        };
        let BindingPattern::ObjectPattern(properties) = left.as_ref() else {
            panic!("expected object-pattern left side");
        };
        assert!(matches!(
            &properties[0].value,
            BindingPattern::AssignmentPattern { .. }
        ));

        let tree = parser
            .parse("let arrayDefault = ([a = 7] = []) => a;", ParseGoal::Script)
            .expect("whole array-pattern default should parse");
        let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
            panic!("expected variable declaration");
        };
        let Some(Expression::ArrowFunction { params, .. }) =
            declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected arrow initializer");
        };
        let BindingPattern::AssignmentPattern { left, .. } = &params[0].pattern else {
            panic!("expected outer assignment pattern");
        };
        let BindingPattern::ArrayPattern(elements) = left.as_ref() else {
            panic!("expected array-pattern left side");
        };
        assert!(matches!(
            &elements[0],
            Some(BindingPattern::AssignmentPattern { .. })
        ));
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
    fn object_binding_property_keys_are_semantic_ast_values_bd_h4esx() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                r#"var {'v\x61lue': quoted, \u0076alue: escaped_identifier, 0x10: hex, 1e3: exponent, 9007199254740993: rounded_number, 0x10n: radix_bigint, 9007199254740993n: precise_bigint, π: unicode_name, \u03C0: escaped_unicode_name} = source"#,
                ParseGoal::Script,
            )
            .expect("static property names should parse to semantic key values");
        let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
            panic!("expected variable declaration");
        };
        let BindingPattern::ObjectPattern(properties) = &declaration.declarations[0].pattern else {
            panic!("expected object binding pattern");
        };
        assert_eq!(properties.len(), 9);
        assert_eq!(
            properties[0].key,
            Expression::StringLiteral("value".to_string())
        );
        assert_eq!(
            properties[1].key,
            Expression::Identifier("value".to_string())
        );
        assert_eq!(properties[2].key, Expression::NumericLiteral(16));
        assert_eq!(properties[3].key, Expression::NumericLiteral(1000));
        assert_eq!(
            properties[4].key,
            Expression::NumericLiteral(9_007_199_254_740_992)
        );
        assert_eq!(
            properties[5].key,
            Expression::StringLiteral("16".to_string())
        );
        assert_eq!(
            properties[6].key,
            Expression::StringLiteral("9007199254740993".to_string())
        );
        assert_eq!(properties[7].key, Expression::Identifier("π".to_string()));
        assert_eq!(properties[8].key, Expression::Identifier("π".to_string()));
    }

    #[test]
    fn binding_patterns_treat_comments_and_bom_as_trivia_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "let/* declaration */\u{FEFF}{/* lead */ value /* : , = } ] */: /* target */ x, \
                 'quoted' /* : , = */: y, 1 /* : , = */: z, \
                 [/* ] , : = */ 'computed' /* ] */] /* : */: computed, \
                 shorthand /* = , */ = 5, ... /* rest */ rest} = source; \
                 let [/* comment-only hole */, first /* , = ] } */ = 1, second] = values; \
                 let empty = (/* no parameters */) => 1;",
                ParseGoal::Script,
            )
            .expect("comments and BOM are lexical trivia around binding-pattern tokens");

        let Statement::VariableDeclaration(object_declaration) = &tree.body[0] else {
            panic!("expected object-binding declaration");
        };
        let BindingPattern::ObjectPattern(properties) = &object_declaration.declarations[0].pattern
        else {
            panic!("expected object-binding pattern");
        };
        assert_eq!(properties.len(), 6);
        assert_eq!(properties[0].key, Expression::Identifier("value".into()));
        assert!(matches!(
            &properties[0].value,
            BindingPattern::Identifier(name) if name == "x"
        ));
        assert_eq!(
            properties[1].key,
            Expression::StringLiteral("quoted".into())
        );
        assert_eq!(properties[2].key, Expression::NumericLiteral(1));
        assert!(properties[3].computed);
        assert!(matches!(
            &properties[4].value,
            BindingPattern::AssignmentPattern { left, .. }
                if matches!(left.as_ref(), BindingPattern::Identifier(name) if name == "shorthand")
        ));
        assert!(matches!(
            &properties[5].value,
            BindingPattern::Rest(inner)
                if matches!(inner.as_ref(), BindingPattern::Identifier(name) if name == "rest")
        ));

        let Statement::VariableDeclaration(array_declaration) = &tree.body[1] else {
            panic!("expected array-binding declaration");
        };
        assert!(matches!(
            &array_declaration.declarations[0].pattern,
            BindingPattern::ArrayPattern(elements)
                if elements.len() == 3
                    && elements[0].is_none()
                    && matches!(&elements[1], Some(BindingPattern::AssignmentPattern { .. }))
                    && matches!(&elements[2], Some(BindingPattern::Identifier(name)) if name == "second")
        ));

        let Statement::VariableDeclaration(arrow_declaration) = &tree.body[2] else {
            panic!("expected arrow declaration");
        };
        assert!(matches!(
            arrow_declaration.declarations[0].initializer.as_ref(),
            Some(Expression::ArrowFunction { params, .. }) if params.is_empty()
        ));

        parser
            .parse(
                "let {line // : , = ] }\n: renamed} = source",
                ParseGoal::Script,
            )
            .expect("a line comment may separate a property name from its colon");
        parser
            .parse(
                "let emptyObject = ({/* comment only */} = {}) => 1; \
                 let trailingParameter = (value, /* trailing */) => value;",
                ParseGoal::Script,
            )
            .expect("comment-only empty patterns and trivia after a trailing comma remain valid");
        let tight_default_tree = parser
            .parse(
                "let {x/* tight */=1} = source; \
                 let [y/* tight */=2] = values; \
                 function defaults(value/* tight */=3) {} \
                 let arrow = (value/* tight */=4) => value; \
                 let {whole}/* tight */={whole: 5};",
                ParseGoal::Script,
            )
            .expect("a comment immediately before a default equals remains lexical trivia");
        assert_eq!(tight_default_tree.body.len(), 5);
        let comment_segment_tree = parser
            .parse(
                "let/* ; ' \" ` { [ ( */first = 1; \
                 let second/* ; } ] ) */=2; \
                 let third = 3/* ; } ] ) */, fourth = 4;",
                ParseGoal::Script,
            )
            .expect("comment punctuation cannot split or rebalance binding declarations");
        assert_eq!(comment_segment_tree.body.len(), 3);
        assert!(matches!(
            &comment_segment_tree.body[2],
            Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 2
        ));
        parser
            .parse(
                "var let = value; var counter = 1; let\n++counter; let\n(4);",
                ParseGoal::Script,
            )
            .expect("sloppy let preserves update ASI and call continuation across a line ending");
        parser
            .parse(
                "let {escaped = /\\//, matcher = /[,:=]/, product = /a/*factor} = source; \
                 let re = /\\//, value = 1",
                ParseGoal::Script,
            )
            .expect("comment recognition must not consume RegExp literals or following multiply");
        let regexp_division_tree = parser
            .parse("let {x = /a/ / 2, y = /b/ / 3} = source", ParseGoal::Script)
            .expect("division after a RegExp literal must preserve the next binding property");
        let Statement::VariableDeclaration(regexp_declaration) = &regexp_division_tree.body[0]
        else {
            panic!("expected RegExp-default binding declaration");
        };
        assert!(matches!(
            &regexp_declaration.declarations[0].pattern,
            BindingPattern::ObjectPattern(properties) if properties.len() == 2
        ));
        parser
            .parse(
                "let {line = // trivia\n/\\//, bom = \u{FEFF}/\\//, \
                 block = /* trivia */ /\\//} = source",
                ParseGoal::Script,
            )
            .expect("RegExp context survives line, block, and BOM binding trivia");
        parser
            .parse(
                "for (let/* trivia */[x] of values) {} \
                 for (const\u{FEFF}{x} of values) {} \
                 for (var/* trivia */{x} in source) {}",
                ParseGoal::Script,
            )
            .expect("for-in/of declaration bindings accept comment and BOM trivia");
        let for_comment_tree = parser
            .parse(
                "for (const {x /* } in */: y} of [{x: 7}]) { y; } \
                 for (const matcher of / in /) {} \
                 for (let x/* comment */of [1]) {} \
                 for (let x\tin {a: 1}) {} \
                 for (let x\u{FEFF}of [1]) {} \
                 for (let x /* before */ in/* after */ {x: 1}) {} \
                 for (let of of [1]) {} \
                 for (let of in {x: 1}) {} \
                 for (const [nested = 1] of [[]]) {} \
                 for (let in {x: 1}) {}",
                ParseGoal::Script,
            )
            .expect("fake loop keywords inside comments and RegExp literals are ignored");
        assert!(matches!(
            &for_comment_tree.body[0],
            Statement::ForOf(statement)
                if matches!(&statement.binding, BindingPattern::ObjectPattern(properties) if properties.len() == 1)
        ));
        assert!(matches!(&for_comment_tree.body[1], Statement::ForOf(_)));
        for (index, expected_of) in [true, false, true, false, true, false, true, false]
            .into_iter()
            .enumerate()
        {
            let statement = &for_comment_tree.body[index + 2];
            assert_eq!(
                matches!(statement, Statement::ForOf(_)),
                expected_of,
                "unexpected loop kind at donor case {index}"
            );
        }
        let Statement::ForOf(contextual_of_loop) = &for_comment_tree.body[6] else {
            panic!("expected contextual `let of` declaration in for-of loop");
        };
        assert_eq!(
            contextual_of_loop.binding_kind,
            Some(VariableDeclarationKind::Let)
        );
        assert!(matches!(
            &contextual_of_loop.binding,
            BindingPattern::Identifier(name) if name == "of"
        ));
        let Statement::ForIn(bare_let_loop) = &for_comment_tree.body[9] else {
            panic!("expected sloppy bare-let for-in loop");
        };
        assert_eq!(bare_let_loop.binding_kind, None);
        assert!(matches!(
            &bare_let_loop.binding,
            BindingPattern::Identifier(name) if name == "let"
        ));
        let contextual_loop_tree = parser
            .parse(
                "for (async in {}) {} \
                 for (let async of []) {} \
                 for (var async of []) {} \
                 for (let [...rest] of [[]]) {}",
                ParseGoal::Script,
            )
            .expect("for-head contextual names and nested rest follow ES2020 early errors");
        assert!(matches!(&contextual_loop_tree.body[0], Statement::ForIn(_)));
        assert!(
            contextual_loop_tree.body[1..]
                .iter()
                .all(|statement| matches!(statement, Statement::ForOf(_)))
        );

        let unparenthesized_arrow_tree = parser
            .parse(
                "let commented = value /* fake => */ => value; \
                 let bom = item\u{FEFF}=> item; \
                 let asynchronous = async value /* trivia */ => value; \
                 let asyncComment = async/* trivia */value => value; \
                 let asyncBom = async\u{FEFF}(value) => value; \
                 let parenthesizedComment = (value)/* trivia */=> value; \
                 let parenthesizedBom = (value)\u{FEFF}=> value; \
                 let asyncBoth = async/**/(value)/* trivia */=> value;",
                ParseGoal::Script,
            )
            .expect("arrow bindings accept comment and BOM trivia around the arrow token");
        for (statement, expected_async) in unparenthesized_arrow_tree
            .body
            .iter()
            .zip([false, false, true, true, true, false, false, true])
        {
            let Statement::VariableDeclaration(declaration) = statement else {
                panic!("expected arrow variable declaration");
            };
            assert!(matches!(
                declaration.declarations[0].initializer.as_ref(),
                Some(Expression::ArrowFunction { params, is_async, .. })
                    if params.len() == 1 && *is_async == expected_async
            ));
        }

        let parameter_tree = parser
            .parse(
                "let arrow = (/* ) */ value) => value; \
                 function regular(/* ( */ value) { return value; } \
                 class C { first(/* ( */ value) {} second(other) {} }",
                ParseGoal::Script,
            )
            .expect("comment delimiters do not terminate or inflate parameter lists");
        let Statement::VariableDeclaration(arrow_declaration) = &parameter_tree.body[0] else {
            panic!("expected arrow declaration");
        };
        assert!(matches!(
            arrow_declaration.declarations[0].initializer.as_ref(),
            Some(Expression::ArrowFunction { params, .. }) if params.len() == 1
        ));
        let Statement::FunctionDeclaration(function) = &parameter_tree.body[1] else {
            panic!("expected function declaration");
        };
        assert_eq!(function.params.len(), 1);
        let Statement::ClassDeclaration(class) = &parameter_tree.body[2] else {
            panic!("expected class declaration");
        };
        assert_eq!(class.body.len(), 2);
        assert_eq!(class.body[0].params.len(), 1);
        assert_eq!(class.body[0].key, Expression::Identifier("first".into()));
        assert_eq!(class.body[1].key, Expression::Identifier("second".into()));

        let line_comment_declarations = parser
            .parse(
                "let// declaration trivia\nx = 1;\n\
                 const// declaration trivia\ny = 2;\n\
                 var// declaration trivia\nz = 3;\n\
                 let/* closed block trivia */\nblockValue = 4;\n\
                 const\u{FEFF}\nbomValue = 5;\n\
                 var\nplainValue = 6;",
                ParseGoal::Script,
            )
            .expect("a line terminator may separate a declaration keyword from its binding");
        assert_eq!(line_comment_declarations.body.len(), 6);

        let continued_declarations = parser
            .parse(
                "const first // before initializer\n= 2; \
                 let second // before initializer\n= 3; \
                 const [third] // before initializer\n= [4]; \
                 let fourth // before comma\n, fifth = 5;",
                ParseGoal::Script,
            )
            .expect(
                "a declaration continues across trailing comment trivia before equals or comma",
            );
        assert_eq!(continued_declarations.body.len(), 4);
        assert!(matches!(
            &continued_declarations.body[3],
            Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 2
        ));

        let array_edge_tree = parser
            .parse(
                "let [] = empty; let [/* comment only */] = alsoEmpty; \
                 let [/* comment */,] = oneHole; let [,/* comment */] = anotherHole;",
                ParseGoal::Script,
            )
            .expect("comment trivia preserves empty arrays and exact elision counts");
        for (index, expected_elements) in [0, 0, 1, 1].into_iter().enumerate() {
            let Statement::VariableDeclaration(declaration) = &array_edge_tree.body[index] else {
                panic!("expected array binding declaration");
            };
            let BindingPattern::ArrayPattern(elements) = &declaration.declarations[0].pattern
            else {
                panic!("expected array binding pattern");
            };
            assert_eq!(elements.len(), expected_elements);
            assert!(elements.iter().all(Option::is_none));
        }

        assert_eq!(
            split_pattern_elements("x = numerator /* trivia */ / denominator, y = left / right")
                .len(),
            2,
            "division after a comment must not consume the next pattern comma as RegExp text"
        );
        assert_eq!(
            split_var_declarator_segments("x = 12 /* trivia */ / 3, y = /z/").len(),
            2,
            "division after a comment must preserve the next variable declarator"
        );
        assert_eq!(
            split_var_declarator_segments("x = /a/ / 2, y = /b/").len(),
            2,
            "a completed RegExp is an operand, so a following slash is division"
        );
        for source in [
            "x = obj.in / divisor, y = left / right",
            "x = obj.return / divisor, y = left / right",
            "x = obj.await / divisor, y = left / right",
            "x = value++ / divisor, y = left / right",
            "x = value-- / divisor, y = left / right",
            "x = value/* trivia */++ / divisor, y = left / right",
            "x = key in /[,]/, y = left / right",
            "x = key instanceof /[,]/, y = left / right",
        ] {
            assert_eq!(
                split_pattern_elements(source).len(),
                2,
                "member keywords and postfix updates remain operands before division: {source}"
            );
        }
        for identifier in ["await", "yield", "of"] {
            let source = format!("x = {identifier} / 2, y = /b/");
            assert_eq!(
                split_var_declarator_segments(&source).len(),
                2,
                "contextual identifier remains an operand before division: {source}"
            );
        }
        assert_eq!(
            extract_balanced("(x++ / y) / z", '(', ')'),
            Some(("x++ / y", " / z"))
        );
    }

    #[test]
    fn merge_logical_lines_preserves_es_whitespace_before_regexp_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;
        let source = "let {x = \u{FEFF}/[}]/,\n y} = {};";
        let lines = merge_logical_lines(source);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.contains("\n y}"));

        let tree = parser
            .parse(source, ParseGoal::Script)
            .expect("BOM trivia must preserve the RegExp lexical goal across physical lines");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if matches!(
                    &declaration.declarations[0].pattern,
                    BindingPattern::ObjectPattern(properties) if properties.len() == 2
                )
        ));

        let tree = parser
            .parse(
                r"let holder = async function y\u0069eld() {};",
                ParseGoal::Script,
            )
            .expect("valid async function-expression name should canonicalize");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::Function {
                        name: Some(name),
                        is_async: true,
                        is_generator: false,
                        ..
                    }) if name == "yield"
                )
        ));

        let mut trivia_run = String::from("let\n");
        trivia_run.push_str(&"/* trivia-only physical line */\n".repeat(256));
        trivia_run.push_str("value = 1;");
        let trivia_lines = merge_logical_lines(&trivia_run);
        assert_eq!(trivia_lines.len(), 1);
        parser
            .parse(&trivia_run, ParseGoal::Script)
            .expect("long trivia-only runs preserve a pending declaration in linear scans");

        let declarators = (0..500)
            .map(|index| format!("x{index}"))
            .collect::<Vec<_>>()
            .join("\n,\n");
        let significant_run = format!("let\n{declarators};");
        let significant_lines = merge_logical_lines(&significant_run);
        assert_eq!(significant_lines.len(), 1);
        let significant_tree = parser
            .parse(&significant_run, ParseGoal::Script)
            .expect("significant multiline declarators use incremental continuation state");
        assert!(matches!(
            &significant_tree.body[0],
            Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 500
        ));

        for source in [
            "let\nx = `foo\nbar`\n,\ny = 1;",
            "let\nx =\n\"a\\\nb\"\n,\ny;",
            "let\nx = `foo\nbar`,\ny = 1;",
            "let\nx =\n\"a\\\nb\",\ny;",
        ] {
            assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
            let tree = parser
                .parse(source, ParseGoal::Script)
                .expect("inherited literal state must survive an incremental line fragment");
            assert!(matches!(
                &tree.body[0],
                Statement::VariableDeclaration(declaration)
                    if declaration.declarations.len() == 2
            ));
        }

        let mut else_if_run = String::from("if (false) {}");
        else_if_run.push_str(&"\nelse if (false) {}".repeat(500));
        else_if_run.push_str("\nelse {}");
        assert_eq!(merge_logical_lines(&else_if_run).len(), 1);
    }

    #[test]
    fn merge_logical_lines_tracks_multiline_clause_phases_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;

        let standalone_else = "let x = 0;\nif (false) {}\nelse\nx = 2;\nx;";
        assert_eq!(merge_logical_lines(standalone_else).len(), 3);
        let standalone_tree = parser
            .parse(standalone_else, ParseGoal::Script)
            .expect("a standalone else may precede an arbitrary Statement");
        assert_eq!(standalone_tree.body.len(), 3);
        assert!(matches!(
            &standalone_tree.body[1],
            Statement::If(statement) if statement.alternate.is_some()
        ));

        let split_assignment = "let x = 0;\nif (false) {}\nelse\nx\n= 2;\nx;";
        assert_eq!(merge_logical_lines(split_assignment).len(), 3);
        assert_eq!(
            parser
                .parse(split_assignment, ParseGoal::Script)
                .expect("an alternate expression may continue with an assignment operator")
                .body
                .len(),
            3
        );

        for source in [
            "if (false) {}\nelse\nhit = ({})\ninstanceof\nObject;",
            "if (false) {}\nelse\nhit = typeof\nmissing;",
            "if (false) {}\nelse\n++\nx;",
            "if (false) {}\nelse\nwhile (x < 1) x\n= 1;",
            "if (false) {}\nelse\nif (true) x\n= 1;",
        ] {
            assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
            parser
                .parse(source, ParseGoal::Script)
                .expect("an alternate retains every required expression and inline body tail");
        }

        for alternate in ["obj.new", "obj.in", "/a/", "1."] {
            let source = format!("if (false) {{}}\nelse\n{alternate}\nx = 2;");
            assert_eq!(
                merge_logical_lines(&source).len(),
                2,
                "a complete operand must permit ASI before the next statement: {source:?}"
            );
            parser.parse(&source, ParseGoal::Script).expect(
                "member, RegExp, and numeric operands remain complete alternate statements",
            );
        }

        for alternate in ["1.0.", ".5.", "1e2.", "1e+2.", "1e-2.", "0x1."] {
            let source = format!("if (false) {{}}\nelse\n{alternate}\ntoString();");
            assert_eq!(
                merge_logical_lines(&source).len(),
                1,
                "a member-access dot after a numeric literal must retain its property: {source:?}"
            );
            parser
                .parse(&source, ParseGoal::Script)
                .expect("a numeric member expression may continue after its member-access dot");
        }

        for next_statement in ["[1];", "(x = 10);", "`tag`;"] {
            let source = format!("let x = 0;\nif (false) {{}}\nelse\nx++\n{next_statement}\nx;");
            assert_eq!(
                merge_logical_lines(&source).len(),
                4,
                "a postfix update is ASI-separated from postfix-only syntax: {source:?}"
            );
            assert_eq!(
                parser
                    .parse(&source, ParseGoal::Script)
                    .expect("postfix update restricted productions permit ASI")
                    .body
                    .len(),
                4
            );
        }
        let postfix_division = "if (false) {}\nelse\nx++\n/ divisor;\ny = 2;";
        assert_eq!(
            merge_logical_lines(postfix_division).len(),
            2,
            "binary division may continue a completed postfix update without leaking lexical state"
        );
        assert_eq!(
            parser
                .parse(postfix_division, ParseGoal::Script)
                .expect("postfix update followed by cross-line division remains a clause body")
                .body
                .len(),
            2
        );

        for source in [
            "if (false) {}\nelse\n/[{]/;\nx = 2;",
            "if (false) {}\nelse\n/=/;\nx = 2;",
            "if (false) {}\nelse\n/=/\nlet x = 2;",
            "if (false) {} else /[{]/;\nx = 2;",
            "if (false) {}\nelse\nif (true)\n/[{]/;\nx = 2;",
            "if (false) {}\nelse\nwhile (false) /[{]/;\nx = 2;",
            "if (false) {}\nelse\ndo /[{]/; while (false);\nx = 2;",
            "if (false) {} else while (false) /[{]/;\nx = 2;",
            "if (false) {}\nelse {\nwhile (false) /[{]/;\n}\nx = 2;",
            "if (false) {}\nelse {} /[{]/;\nx = 2;",
        ] {
            assert_eq!(
                merge_logical_lines(source).len(),
                2,
                "a RegExp statement body must not leak character-class delimiters: {source:?}"
            );
            assert_eq!(
                parser
                    .parse(source, ParseGoal::Script)
                    .expect("a pending clause statement starts with the RegExp lexical goal")
                    .body
                    .len(),
                2
            );
        }
        for member in ["obj.do", "obj.else", "obj.in"] {
            let source = format!("if (false) {{}}\nelse\n{member} / divisor;\nx = 2;");
            assert_eq!(
                merge_logical_lines(&source).len(),
                2,
                "a keyword-named member remains an operand before division: {source:?}"
            );
        }
        for source in [
            "if (false) {}\nelse\n/a/ / 2;\ny = 2;",
            "if (false) {}\nelse\n/a/\n/ 2;\ny = 2;",
        ] {
            assert_eq!(
                merge_logical_lines(source).len(),
                2,
                "a completed RegExp is an operand before division: {source:?}"
            );
        }
        for operator in ["++", "--"] {
            let source = format!("if (false) {{}}\nelse\n{operator}\n/a/.lastIndex;\ny = 2;");
            assert_eq!(
                merge_logical_lines(&source).len(),
                2,
                "a LineTerminator forces an update at statement start to be prefix: {source:?}"
            );
            parser
                .parse(&source, ParseGoal::Script)
                .expect("a split prefix update retains the RegExp lexical goal");
        }
        for block_prefix_update in [
            "{ x\n++/[{]/.lastIndex; }\ny = 2;",
            "{ x// comment\n++/[{]/.lastIndex; }\ny = 2;",
            "{ x/* comment\n*/++/[{]/.lastIndex; }\ny = 2;",
        ] {
            assert_eq!(merge_logical_lines(block_prefix_update).len(), 2);
            parser
                .parse(block_prefix_update, ParseGoal::Script)
                .expect("LineTerminator-restricted updates remain prefix inside a block");
        }

        let regexp_equals = "let r = /=[{]/; let x = 2;";
        assert_eq!(merge_logical_lines(regexp_equals).len(), 1);
        assert_eq!(
            parser
                .parse(regexp_equals, ParseGoal::Script)
                .expect("slash-equals begins a RegExp in an expression lexical goal")
                .body
                .len(),
            2
        );

        let nested_else = "if (false) {}\nelse\nif (false) {}\nelse {}";
        assert_eq!(merge_logical_lines(nested_else).len(), 1);
        let nested_tree = parser
            .parse(nested_else, ParseGoal::Script)
            .expect("a dangling else binds to the nested if alternate");
        assert!(matches!(
            &nested_tree.body[0],
            Statement::If(statement)
                if matches!(
                    statement.alternate.as_deref(),
                    Some(Statement::If(nested)) if nested.alternate.is_some()
                )
        ));

        let multiline_else_if = "if (false) {}\nelse if (false) {\n  let value = 1;\n}\nelse {}";
        assert_eq!(merge_logical_lines(multiline_else_if).len(), 1);
        parser
            .parse(multiline_else_if, ParseGoal::Script)
            .expect("a multiline else-if body remains eligible for its else clause");

        for source in [
            "if (false) {}\nelse\nwhile (false)\nx++;",
            "if (false) {}\nelse\nwhile\n(false)\nx++;",
        ] {
            assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
            parser
                .parse(source, ParseGoal::Script)
                .expect("a control-statement alternate retains its required body");
        }

        let independent_while = "if (false) {}\nelse {}\nwhile (false) {}";
        assert_eq!(merge_logical_lines(independent_while).len(), 2);
        assert_eq!(
            parser
                .parse(independent_while, ParseGoal::Script)
                .expect("an independent while must not be absorbed by an else clause")
                .body
                .len(),
            2
        );

        for source in [
            "try {}\ncatch\n(error)\n{\n}\nfinally\n{\n}",
            "try {}\nfinally\n{\n}",
            "do {}\nwhile\n(false);",
        ] {
            assert_eq!(merge_logical_lines(source).len(), 1, "source: {source:?}");
            parser
                .parse(source, ParseGoal::Script)
                .expect("required clause tails may span balanced physical fragments");
        }

        let mut malformed_else_if = String::from("if (false) {}\nelse\nif");
        malformed_else_if.push_str(
            &(0..512)
                .map(|index| format!("\nidentifier{index}"))
                .collect::<String>(),
        );
        assert_eq!(
            merge_logical_lines(&malformed_else_if).len(),
            513,
            "an impossible balanced if head must fail its clause phase immediately"
        );

        let deeply_nested_inline =
            format!("if (false) {{}}\nelse\n{}x = 1;", "if (true) ".repeat(512));
        assert_eq!(
            merge_logical_lines(&deeply_nested_inline).len(),
            1,
            "inline control-body descent must advance through strict suffixes"
        );

        let nested_divisions = format!(
            "if (false) {{}}\nelse\n{}{};",
            "if (true) ".repeat(256),
            std::iter::repeat_n("x", 256)
                .collect::<Vec<_>>()
                .join(" / ")
        );
        assert_eq!(
            merge_logical_lines(&nested_divisions).len(),
            1,
            "incremental lexical goals must not rescan nested control prefixes per division"
        );
    }

    #[test]
    fn sloppy_let_trivia_selects_expression_or_declaration_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;
        for expression in [
            "let",
            "let/**/(4)",
            "let\u{FEFF}(4)",
            "let/**/.x",
            "let/**/+2",
            "let\n=1",
            "let\nin object",
            "let\n, 2",
        ] {
            assert_eq!(
                parse_variable_declaration_kind(expression),
                None,
                "sloppy IdentifierReference expression was misclassified: {expression:?}"
            );
        }
        assert_eq!(
            parse_variable_declaration_kind("let/**/x = 9"),
            Some(VariableDeclarationKind::Let)
        );

        let trivia_tree = parser
            .parse(
                "var let = value => value + 1; \
                 let/**/(4); let\u{FEFF}(4); let/**/.x; let/**/+2; let/**/x = 9;",
                ParseGoal::Script,
            )
            .expect(
                "comment and BOM trivia must not force sloppy let expressions into declarations",
            );
        assert_eq!(trivia_tree.body.len(), 6);
        assert!(matches!(
            &trivia_tree.body[5],
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Let
        ));

        let continuation_tree = parser
            .parse(
                "var let = 0; let\n= 1; \
                 var object = {x: 1}; let\nin object; let\n, 2;",
                ParseGoal::Script,
            )
            .expect(
                "sloppy let assignment, in, and comma expressions continue across a line ending",
            );
        assert_eq!(continuation_tree.body.len(), 5);
        assert!(matches!(
            &continuation_tree.body[1],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Assignment { .. },
                ..
            })
        ));
        assert!(matches!(
            &continuation_tree.body[3],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Binary {
                    operator: BinaryOperator::In,
                    ..
                },
                ..
            })
        ));

        let call_tree = parser
            .parse("var let = value => value + 1; let\n(4);", ParseGoal::Script)
            .expect("a line ending before call arguments does not trigger ASI");
        assert_eq!(call_tree.body.len(), 2);
        assert!(matches!(
            &call_tree.body[1],
            Statement::Expression(ExpressionStatement {
                expression: Expression::Call { .. },
                ..
            })
        ));

        let reserved_word_tree = parser
            .parse("var let = 1; let\ntrue; let\nnull; let;", ParseGoal::Script)
            .expect("reserved-word statements after bare sloppy let remain ASI-separated");
        assert_eq!(reserved_word_tree.body.len(), 6);

        let trailing_declaration_tree = parser
            .parse(
                "let a = 1; const // before binding\n b = 2; \
                 let d = 1; const e // before equals\n = 2; \
                 let f = 1; let g // before comma\n , h = 2; \
                 a + b + d + e + f + h;",
                ParseGoal::Script,
            )
            .expect("continuation analysis must inspect the final top-level statement segment");
        assert_eq!(trailing_declaration_tree.body.len(), 7);
        assert!(matches!(
            &trailing_declaration_tree.body[5],
            Statement::VariableDeclaration(declaration) if declaration.declarations.len() == 2
        ));
    }

    #[test]
    fn comment_only_statement_segments_are_lexical_trivia_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;
        let trailing = parser
            .parse("let x = 1; /* trailing */", ParseGoal::Script)
            .expect("a trailing block comment is not an expression statement");
        assert_eq!(trailing.body.len(), 1);

        let between = parser
            .parse(
                "let x = 1; /* block only */ ; // line only\n x;",
                ParseGoal::Script,
            )
            .expect("comment-only segments between statements are lexical trivia");
        assert_eq!(between.body.len(), 2);

        let comment_only = parser
            .parse("/* block only */\n// line only", ParseGoal::Script)
            .expect("a comment-only Script has an empty statement list");
        assert!(comment_only.body.is_empty());

        for (source, expected_start, expected_end) in [("/*\n*/x;", 5, 6), ("/*\r\n*/x;", 6, 7)] {
            let span_tree = parser
                .parse(source, ParseGoal::Script)
                .expect("leading multiline comment trivia preserves physical coordinates");
            let Statement::Expression(expression) = &span_tree.body[0] else {
                panic!("expected expression after leading comment trivia");
            };
            assert_eq!(expression.span.start_offset, expected_start);
            assert_eq!(expression.span.end_offset, expected_end);
            assert_eq!(expression.span.start_line, 2);
            assert_eq!(expression.span.start_column, 3);
            assert_eq!(expression.span.end_line, 2);
            assert_eq!(expression.span.end_column, 4);
        }

        let leading = parser
            .parse("/* leading */ let x = 1; x;", ParseGoal::Script)
            .expect("leading comment trivia must not hide declaration dispatch");
        assert!(matches!(
            &leading.body[0],
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Let
        ));

        let between_declarations = parser
            .parse(
                "let a = 1; /* before declaration */ const b = 2; a + b;",
                ParseGoal::Script,
            )
            .expect("comment trivia after a semicolon must not hide declaration dispatch");
        assert!(matches!(
            &between_declarations.body[1],
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Const
        ));

        let leading_function = parser
            .parse(
                "/* leading */ function f() {} let x = 1; x;",
                ParseGoal::Script,
            )
            .expect("leading trivia must not hide a block statement split boundary");
        assert_eq!(leading_function.body.len(), 3);
        assert!(matches!(
            &leading_function.body[0],
            Statement::FunctionDeclaration(_)
        ));

        let clause_tree = parser
            .parse(
                "let x = 0; if (false) { x = 1; }/* clause */else { x = 2; } x;",
                ParseGoal::Script,
            )
            .expect("comment trivia between if and else preserves the clause boundary");
        assert_eq!(clause_tree.body.len(), 3);
        assert!(matches!(
            &clause_tree.body[1],
            Statement::If(statement) if statement.alternate.is_some()
        ));

        let clause_prefix_tree = parser
            .parse(
                "var else$foo = 7; var x = 0; \
                 if (false) { x = 1; } else$foo; x + else$foo;",
                ParseGoal::Script,
            )
            .expect("an identifier beginning with else is not an else clause");
        assert_eq!(clause_prefix_tree.body.len(), 5);
        assert!(matches!(
            &clause_prefix_tree.body[2],
            Statement::If(statement) if statement.alternate.is_none()
        ));
        for identifier in ["else$foo", "elseπ", r"else\u0066oo"] {
            assert!(
                !starts_with_keyword(identifier, "else"),
                "IdentifierName continuation was mistaken for a clause keyword: {identifier}"
            );
        }

        parser
            .parse(
                "try {}/* clause */catch (error) {} \
                 try {}// clause\nfinally {} \
                 do {}/* clause */while (false);",
                ParseGoal::Script,
            )
            .expect("comment trivia preserves catch, finally, and do-while clauses");
    }

    #[test]
    fn binding_pattern_trivia_does_not_join_tokens_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;
        assert!(!is_binding_pattern_whitespace('\u{0085}'));
        assert_eq!(
            parse_variable_declaration_kind("let\u{0085}value = 1"),
            None
        );
        assert_eq!(
            trim_binding_pattern_trivia("\u{0085}value\u{0085}"),
            Some("\u{0085}value\u{0085}")
        );
        assert_eq!(
            trim_binding_pattern_trivia("\u{FEFF}/* lead */ value /* tail */"),
            Some("value")
        );
        assert_eq!(
            trim_binding_pattern_trivia("va/* internal */lue"),
            Some("va/* internal */lue")
        );
        assert_eq!(trim_binding_pattern_trivia("value /* unterminated"), None);
        parser
            .parse(
                "let string = '\u{0085}'; let regexp = /\u{0085}/; \
                 let commented = /* \u{0085} */ 1;",
                ParseGoal::Script,
            )
            .expect("non-ES whitespace remains valid inside lexical literals and comments");
        for source in [
            "var {va/* c */lue: picked} = source",
            "var {'value' /* c */ junk: picked} = source",
            "var {1 /* c */ 2: picked} = source",
            "let {\u{0085}value: picked} = source",
            "let {value\u{0085}: picked} = source",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("comments cannot splice separate tokens into one property name");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
            assert!(error.message.contains("object-binding property key"));
        }
        for source in [
            "var \u{0085}value = 1",
            "const \u{0085}value = 1",
            "let value = \u{0085}1",
            "let value = 1\u{0085} + 2",
            "let value = first\u{0085}second",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("non-ECMAScript whitespace cannot act as declaration trivia");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
        for source in [
            "let {[key] /* c */ junk: value} = source",
            "let {...re/* c */st} = source",
            "let {[key]/* c */: va/* c */lue} = source",
        ] {
            assert!(
                parser.parse(source, ParseGoal::Script).is_err(),
                "binding trivia cannot hide residual or token-spliced syntax: {source}"
            );
        }
        for source in [
            "let invalid = (/* c */, ) => 1",
            "let invalid = (/* c */, value) => value",
            "let invalid = (value, /* c */, ) => value",
            "let invalid = value/*\n*/=> value",
            "let invalid = async value/*\n*/=> value",
            "let invalid = (value)\n=> value",
            "let invalid = (value)/*\n*/=> value",
            "for (let value = 1 of [2]) {}",
            "for (const value = 1 in {x: 1}) {}",
            "for (var value = 1 of [2]) {}",
            "for (let [value] = [1] of [[2]]) {}",
            "for (var [value] = [1] in {x: 1}) {}",
            "'use strict'; for (var value = 1 in {x: 1}) {}",
            "for (let of values) {}",
            "'use strict'; for (let in {x: 1}) {}",
            "for (async of []) {}",
            "for (async/* comment */of []) {}",
            "for (let ...rest of []) {}",
            "for (const ...rest in {}) {}",
            "for (var ...rest of []) {}",
            "for (...rest of []) {}",
            "function invalid(/* c */, ) {}",
            "let {/* c */, value} = source",
            "let {value, /* c */, other} = source",
            "let [...rest, /* c */] = source",
            "let {...rest, /* c */} = source",
            "function invalid(...rest, /* c */) {}",
        ] {
            assert!(
                parser.parse(source, ParseGoal::Script).is_err(),
                "comment-only leading or interior slots stay syntax errors: {source}"
            );
        }
    }

    #[test]
    fn object_binding_numeric_keys_use_ecmascript_number_spelling_bd_h4esx() {
        for (value, expected) in [
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (f64::from_bits(1), "5e-324"),
            (667_082_108_456_853.2, "667082108456853.2"),
        ] {
            assert_eq!(js_number_property_key(value), expected);
        }
        assert_eq!(
            js_number_property_key(
                "9007199254740993"
                    .parse::<f64>()
                    .expect("numeric boundary should parse")
            ),
            "9007199254740992"
        );
        assert_eq!(
            js_number_property_key(
                "18446744073709551615"
                    .parse::<f64>()
                    .expect("wide numeric boundary should parse")
            ),
            "18446744073709552000"
        );
    }

    #[test]
    fn object_binding_identifier_names_use_unicode_identifier_classes_bd_h4esx() {
        let parser = CanonicalEs2020Parser;
        parser
            .parse(r"var {a\u203F: connector} = source", ParseGoal::Script)
            .expect("connector punctuation is valid after an identifier start");
        parser
            .parse(
                r"var {\u037A: id_start, a\u037A: id_continue} = source",
                ParseGoal::Script,
            )
            .expect("ECMAScript uses Unicode ID classes rather than XID classes");

        for source in [
            "var {a½: value} = source",
            "var {\u{0345}bad: value} = source",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("invalid Unicode identifier class must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
            assert!(error.message.contains("object-binding property key"));
        }
    }

    #[test]
    fn unicode_and_escaped_binding_names_canonicalize_bd_t4947() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                r"var {π, \u0076alue, a\u037A} = source; var [\u03C0] = values; var \u0064irect = 1",
                ParseGoal::Script,
            )
            .expect("literal and escaped binding names should parse");

        let Statement::VariableDeclaration(object_declaration) = &tree.body[0] else {
            panic!("expected object-binding declaration");
        };
        let BindingPattern::ObjectPattern(properties) = &object_declaration.declarations[0].pattern
        else {
            panic!("expected object-binding pattern");
        };
        assert_eq!(properties.len(), 3);
        for (property, expected) in properties.iter().zip(["π", "value", "aͺ"]) {
            assert!(property.shorthand);
            assert!(matches!(
                &property.key,
                Expression::Identifier(name) if name == expected
            ));
            assert!(matches!(
                &property.value,
                BindingPattern::Identifier(name) if name == expected
            ));
        }

        let Statement::VariableDeclaration(array_declaration) = &tree.body[1] else {
            panic!("expected array-binding declaration");
        };
        assert!(matches!(
            &array_declaration.declarations[0].pattern,
            BindingPattern::ArrayPattern(elements)
                if matches!(
                    &elements[0],
                    Some(BindingPattern::Identifier(name)) if name == "π"
                )
        ));

        let Statement::VariableDeclaration(direct_declaration) = &tree.body[2] else {
            panic!("expected direct binding declaration");
        };
        assert!(matches!(
            &direct_declaration.declarations[0].pattern,
            BindingPattern::Identifier(name) if name == "direct"
        ));
    }

    #[test]
    fn unicode_and_escaped_identifier_references_canonicalize_bd_t4947() {
        let tree = parse_script(r"π + \u0076alue");
        let Expression::Binary { left, right, .. } = first_expr(&tree) else {
            panic!("expected binary expression");
        };
        assert!(matches!(
            left.as_ref(),
            Expression::Identifier(name) if name == "π"
        ));
        assert!(matches!(
            right.as_ref(),
            Expression::Identifier(name) if name == "value"
        ));

        let tree = parse_script(r"\u0066n(π)");
        let Expression::Call { callee, arguments } = first_expr(&tree) else {
            panic!("expected call expression");
        };
        assert!(matches!(
            callee.as_ref(),
            Expression::Identifier(name) if name == "fn"
        ));
        assert!(matches!(
            &arguments[0],
            Expression::Identifier(name) if name == "π"
        ));
    }

    #[test]
    fn unicode_and_escaped_arrow_parameters_canonicalize_bd_t4947() {
        let parser = CanonicalEs2020Parser;
        for (source, expected, expected_async) in [
            (r"let arrow = \u03C0 => ({π})", "π", false),
            (r"let arrow = (\u0076alue) => ({value})", "value", false),
            ("let arrow = async π => ({π})", "π", true),
        ] {
            let tree = parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| panic!("`{source}` should parse: {error:?}"));
            let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
                panic!("expected arrow variable declaration");
            };
            let Some(Expression::ArrowFunction {
                params, is_async, ..
            }) = declaration.declarations[0].initializer.as_ref()
            else {
                panic!("expected arrow initializer for `{source}`");
            };
            assert_eq!(*is_async, expected_async);
            assert!(matches!(
                &params[0].pattern,
                BindingPattern::Identifier(name) if name == expected
            ));
        }
    }

    #[test]
    fn binding_names_apply_goal_reserved_word_rules_after_decoding_bd_t4947() {
        let parser = CanonicalEs2020Parser;
        parser
            .parse(
                "var {await, static, yield} = source; var let = 1; (let) => let",
                ParseGoal::Script,
            )
            .expect("sloppy Script bindings should allow contextual names");

        for source in [
            "var {if} = source",
            r"var {\u0069f} = source",
            "var if = 1",
            r"var \u0069f = 1",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("reserved binding name must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }

        for source in [
            "var {await} = source",
            r"var {\u0061wait} = source",
            "var {static} = source",
            "var eval = 1",
            "var arguments = 1",
            "import eval from 'pkg'",
            "import * as arguments from 'pkg'",
            "import {value as eval} from 'pkg'",
        ] {
            let error = parser
                .parse(source, ParseGoal::Module)
                .expect_err("Module bindings must apply strict identifier restrictions");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn declaration_catch_and_import_names_canonicalize_bd_7vm4l() {
        let parser = CanonicalEs2020Parser;

        let tree = parser
            .parse(r"function v\u0061lue() {}", ParseGoal::Script)
            .expect("escaped function declaration name should parse");
        assert!(matches!(
            &tree.body[0],
            Statement::FunctionDeclaration(function)
                if function.name.as_deref() == Some("value")
        ));

        let tree = parser
            .parse(r"let holder = function n\u0061med() {};", ParseGoal::Script)
            .expect("escaped function expression name should parse");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::Function { name: Some(name), .. }) if name == "named"
                )
        ));

        let tree = parser
            .parse(r"class V\u0061lue {}", ParseGoal::Script)
            .expect("escaped class declaration name should parse");
        assert!(matches!(
            &tree.body[0],
            Statement::ClassDeclaration(class) if class.name.as_deref() == Some("Value")
        ));

        let tree = parser
            .parse(r"let holder = class N\u0061med {};", ParseGoal::Script)
            .expect("escaped class expression name should parse");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::ClassExpression { name: Some(name), .. }) if name == "Named"
                )
        ));

        let tree = parser
            .parse(
                r"try { throw 1 } catch (e\u0072r) { err }",
                ParseGoal::Script,
            )
            .expect("escaped catch binding should parse");
        assert!(matches!(
            &tree.body[0],
            Statement::TryCatch(statement)
                if statement.handler.as_ref().and_then(|handler| handler.parameter.as_deref())
                    == Some("err")
        ));

        let tree = parser
            .parse(
                r"import v\u0061lue, {d\u0065fault as f\u0061llback, st\u0061tic as alias} from 'pkg';
                   import * as n\u0061mes from 'other';",
                ParseGoal::Module,
            )
            .expect("escaped import IdentifierNames and bindings should parse");
        assert!(matches!(
            &tree.body[0],
            Statement::Import(import)
                if matches!(
                    &import.clause,
                    ImportClause::DefaultAndNamed { default, specifiers }
                        if default == "value"
                            && specifiers[0].import_name == "default"
                            && specifiers[0].local_name == "fallback"
                            && specifiers[1].import_name == "static"
                            && specifiers[1].local_name == "alias"
                )
        ));
        assert!(matches!(
            &tree.body[1],
            Statement::Import(import)
                if matches!(&import.clause, ImportClause::Namespace { local } if local == "names")
        ));
    }

    #[test]
    fn binding_names_allow_only_boundary_lexical_trivia_bd_7vm4l() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "function value/* trailing */() {}",
            "function value\u{FEFF}() {}",
            "class Value/* trailing */ {}",
            "class Value\u{FEFF} {}",
        ] {
            parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| {
                    panic!("boundary lexical trivia should remain valid in `{source}`: {error:?}")
                });
        }

        for source in [
            "import value/* trailing */ from 'pkg';",
            "import * as names/* trailing */ from 'pkg';",
            "import {source/* trailing */ as local, other as alias/* trailing */} from 'pkg';",
            "import value/**/from 'pkg';",
            "import * as names/**/from 'pkg';",
            "import {source as local}/**/from 'pkg';",
            "import value\u{FEFF}from 'pkg';",
            "import from from 'pkg';",
        ] {
            parser
                .parse(source, ParseGoal::Module)
                .unwrap_or_else(|error| {
                    panic!("import boundary trivia should remain valid in `{source}`: {error:?}")
                });
        }

        for source in [
            "function va/* internal */lue() {}",
            "class Va/* internal */lue {}",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("internal trivia cannot splice one binding identifier");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }

        for source in [
            "import va/* internal */lue from 'pkg';",
            "import {sou/* internal */rce as local} from 'pkg';",
        ] {
            let error = parser
                .parse(source, ParseGoal::Module)
                .expect_err("internal trivia cannot splice one import identifier");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn async_function_expression_line_terminator_boundary_bd_7vm4l() {
        let parser = CanonicalEs2020Parser;

        for (source, expected_name, expected_generator) in [
            (
                "async/**/function declared() {} let observed = declared;",
                "declared",
                false,
            ),
            (
                "async\u{FEFF}function bomDeclared() {}",
                "bomDeclared",
                false,
            ),
            ("async/**/function/**/ * generated() {}", "generated", true),
        ] {
            let tree = parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| {
                    panic!("trivia-separated async declaration should parse: {error:?}")
                });
            assert!(matches!(
                &tree.body[0],
                Statement::FunctionDeclaration(function)
                    if function.name.as_deref() == Some(expected_name)
                        && function.is_async
                        && function.is_generator == expected_generator
            ));
        }

        let tree = parser
            .parse(
                "let holder = async/**/function named() {};",
                ParseGoal::Script,
            )
            .expect("a block comment without a line terminator remains async-function trivia");
        assert!(matches!(
            &tree.body[0],
            Statement::VariableDeclaration(declaration)
                if matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::Function {
                        name: Some(name),
                        is_async: true,
                        is_generator: false,
                        ..
                    }) if name == "named"
                )
        ));

        for (asi_source, expected_name) in [
            ("let holder = async/*\n*/function named() {};", "named"),
            (
                "let holder = a\\u0073ync/*\n*/function escapedNamed() {};",
                "escapedNamed",
            ),
            (
                "let holder = a\\u{73}ync/*\n*/function bracedNamed() {};",
                "bracedNamed",
            ),
        ] {
            assert_eq!(split_statement_segments(asi_source).len(), 2);
            let tree = parser
                .parse(asi_source, ParseGoal::Script)
                .expect("a line terminator before a named function declaration triggers ASI");
            assert!(matches!(
                &tree.body[..],
                [
                    Statement::VariableDeclaration(declaration),
                    Statement::FunctionDeclaration(function)
                ] if matches!(
                    declaration.declarations[0].initializer.as_ref(),
                    Some(Expression::Identifier(name)) if name == "async"
                ) && function.name.as_deref() == Some(expected_name)
            ));
        }

        for source in [
            "let holder = async/*\n*/function() {};",
            "let holder = (async/*\n*/function named() {});",
            "let holder = a\\u0073ync/*\n*/function() {};",
            "let holder = a\\u0073ync/**/function named() {};",
            "let holder = (a\\u0073ync/*\n*/function named() {});",
            "let holder = a\\u{73}ync/*\n*/function() {};",
            "let holder = a\\u{73}ync/**/function named() {};",
            "let holder = (a\\u{73}ync/*\n*/function named() {});",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("a function expression cannot cross an async line terminator");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn canonical_reserved_bindings_fail_across_carriers_bd_7vm4l() {
        let parser = CanonicalEs2020Parser;
        for source in [
            r"var r\u0065turn = 1",
            r"function invalid(r\u0065turn) {}",
            r"var {return: r\u0065turn} = source",
            r"try {} catch (r\u0065turn) {}",
            r"for (var r\u0065turn = 0; ; ) {}",
            r"for (var r\u0065turn in source) {}",
            r"for (var r\u0065turn of source) {}",
            r"function r\u0065turn() {}",
            r"let holder = function r\u0065turn() {};",
            r"class r\u0065turn {}",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("canonical reserved binding must be rejected");
            assert_eq!(
                error.code,
                ParseErrorCode::UnsupportedSyntax,
                "wrong rejection for `{source}`"
            );
        }

        for source in [
            r"import r\u0065turn from 'pkg'",
            r"import {value as r\u0065turn} from 'pkg'",
            r"import {value as local, other as l\u006fcal} from 'pkg'",
            r"import {st\u0061tic} from 'pkg'",
            r"function aw\u0061it() {}",
            r"class aw\u0061it {}",
            r"try {} catch (aw\u0061it) {}",
        ] {
            let error = parser
                .parse(source, ParseGoal::Module)
                .expect_err("invalid canonical module binding must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn binding_name_contexts_do_not_conflate_properties_bd_7vm4l() {
        let parser = CanonicalEs2020Parser;
        for source in [
            r"async function aw\u0061it() {}",
            r"function* y\u0069eld() {}",
            r"let ordinaryAwait = function aw\u0061it() {};",
            r"let ordinaryYield = function y\u0069eld() {};",
            r"let asyncYield = async function y\u0069eld() {};",
            r"class aw\u0061it {}",
            r"try {} catch (l\u0065t) {}",
            r"'use strict'; try {} catch (aw\u0061it) {}",
            r"try {} catch ({r\u0065turn: value}) {}",
            r"function duplicate(value, v\u0061lue) { return value; }",
        ] {
            parser
                .parse(source, ParseGoal::Script)
                .unwrap_or_else(|error| {
                    panic!("`{source}` should retain its grammar-specific acceptance: {error:?}")
                });
        }

        for source in [
            r"function st\u0061tic() {'use strict';}",
            r"let named = function* y\u0069eld() {};",
            r"class st\u0061tic {}",
            r"async function outer() { function aw\u0061it() {} }",
            r"function* outer() { function y\u0069eld() {} }",
            r"try {} catch ({value: r\u0065turn}) {}",
            r"function duplicate(value, v\u0061lue) {'use strict';}",
            r"let duplicate = (value, v\u0061lue) => value;",
            r"function duplicate([value, v\u0061lue]) {}",
            r"try {} catch ([value, v\u0061lue]) {}",
            r"function ev\u0061l() {'use strict';}",
            r"class ev\u0061l {}",
            r"'use strict'; try {} catch (ev\u0061l) {}",
            r"let invalid = async function aw\u0061it() {};",
            r"let invalid = async function* aw\u0061it() {};",
            r"let invalid = async function* y\u0069eld() {};",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("binding grammar restriction must be enforced");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn binding_names_apply_lexical_and_function_context_rules_bd_t4947() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "let let = 1",
            "let {let} = source",
            "const {let} = source",
            "for (let let of values) {}",
            "for (const {let} of values) {}",
            "let arrow = async await => 1",
            r"let arrow = async (\u0061wait) => 1",
            "async function invalid(value = await 1) {}",
            r"async function invalid(value = \u0061wait(1)) {}",
            "let arrow = async (value = await(1)) => value",
            "async function outer() { let invalid = (value = await 1) => value; }",
            "function* generator(yield) {}",
            "function* invalid(value = yield 1) {}",
            r"function* invalid(value = \u0079ield(1)) {}",
            "let generator = function*(value = yield(1)) {}",
            "function* outer() { let invalid = (value = yield 1) => value; }",
            "function* invalid() { let value = (yield\n1); }",
            "function* invalid() { let value = (yield\n*items); }",
            "function* invalid() { let value = (yield/* line\nterm */1); }",
            r"let generator = function*(\u0079ield) {}",
            "function strict(eval) {'use strict';}",
            "function strictDefault(value = 1) {'use strict';}",
            "let strictArrow = (value = 1) => {'use strict';}",
            "class StrictMethod { method(value = 1) {'use strict';} }",
            "'use strict'; var static = 1",
            "'use strict'; var arguments = 1",
            "function strictAsi() {\n'use strict'\nvar static = 1;\n}",
            "function strictLeading() { /* lead */ 'use strict'; var static = 1; }",
            "function strictTrailing() { 'use strict' /* tail */; var static = 1; }",
            "/* lead */ 'use strict' /* tail */; var static = 1",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("binding name must honor its lexical and function context");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn identifier_references_track_strict_async_and_generator_context_bd_4d60a() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "'use strict'; ({static})",
            r"'use strict'; ({\u0073tatic})",
            "'not strict'; 'use strict'; ({static})",
            "'use strict'\n++value; ({static})",
            "let arrow = async () => ({await})",
            r"let arrow = async () => ({\u0061wait})",
            "function* generator() { return {yield}; }",
            r"function* generator() { return {\u0079ield}; }",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("identifier reference must honor its grammar context");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }

        parser
            .parse(r#""\x75se strict"; ({static})"#, ParseGoal::Script)
            .expect("escaped directive text must not enable strict mode");
        parser
            .parse("\"use strict\"\n({static})", ParseGoal::Script)
            .expect("a continued string-literal expression is not a directive");
        parser
            .parse(
                r#"function notStrict() { "use \
strict"; var static = 1; }"#,
                ParseGoal::Script,
            )
            .expect("a string containing a LineContinuation is not a use strict directive");
        for continued in [
            "\"use strict\"\nin({})",
            "\"use strict\"\ninstanceof/* comment */ value",
            "\"use strict\"\n!= value",
        ] {
            assert!(
                !has_use_strict_directive(continued),
                "continued expression must not become a directive: {continued}"
            );
        }

        parser
            .parse(
                "var await = value => value; var yield = 3; await(yield)",
                ParseGoal::Script,
            )
            .expect("sloppy Script should treat await and yield as identifier references");
        parser
            .parse(
                "async function wait(value) { return await value; } function* items() { yield 1; }",
                ParseGoal::Script,
            )
            .expect("async and generator bodies should parse their contextual expressions");
        parser
            .parse(
                "async function waits() { return await[1]; } \
                 async function waitsOnObject() { return await{value: 1}; } \
                 function* yields() { yield(1); yield[1]; yield{value: 1}; }",
                ParseGoal::Script,
            )
            .expect("contextual expressions should accept adjacent primary-expression forms");
        parser
            .parse(
                "async function outerAsync() { function inner(await) { return await; } } \
                 function* outerGenerator() { function inner(yield) { return yield; } } \
                 function* splitYield() { yield\n1; yield/* line\nterm */2; \
                     yield/* line\u{2028}separator */3; } \
                 function* commaYield() { let first = (yield, 1); \
                     let second = (yield\n, 2); }",
                ParseGoal::Script,
            )
            .expect(
                "nested functions reset grammar parameters and bare yield honors restricted ASI",
            );
        for member_expression in [
            "return obj.yield /* line\nterm */ + 1",
            "return obj . yield /* line\nterm */ * 2",
            "return obj?.yield /* line\nterm */ + 1",
            "return obj.yield /* line\nterm */ (1)",
            "return obj. /* member */ yield /* line\nterm */ (1)",
            "return obj?. /* member */ yield /* line\nterm */ (1)",
            "return obj.\u{00A0}yield /* line\nterm */ (1)",
            "return obj.\u{FEFF}yield /* line\nterm */ (1)",
        ] {
            assert!(
                top_level_yield_asi_split(member_expression).is_none(),
                "member property `yield` is not a YieldExpression: {member_expression}"
            );
        }
        parser
            .parse(
                "function* memberYield() { return obj.yield /* line\nterm */ + 1; \
                    return obj . yield /* line\nterm */ * 2; \
                    return obj.yield /* line\nterm */ (1); \
                    return obj. /* member */ yield /* line\nterm */ (1); }",
                ParseGoal::Script,
            )
            .expect("member properties named yield must not trigger restricted-production ASI");
    }

    #[test]
    fn malformed_unicode_binding_names_fail_closed_bd_t4947() {
        let parser = CanonicalEs2020Parser;
        for source in [
            r"var {\u0030bad} = source",
            r"var {\x61} = source",
            r"var \u{110000} = 1",
            r"\u0030bad => 1",
            r"\x61 => 1",
            r"let value = \u0030bad",
            r"let value = \x61",
            r"let value = \u{110000}",
            r"let value = \u{+61}",
            r"let value = a\u{61-}",
            "let value = \u{0300}bad",
            "let value = \u{200C}bad",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("malformed binding name must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
        }
    }

    #[test]
    fn unsupported_raw_expressions_remain_compatible_bd_t4947() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse(
                "let bigint = 1n; let dynamic = import('pkg'); \
                 let generator = function*(){ yield 1; }; \
                 let commented = function /* function marker */ * /* params */ () { yield 2; }; \
                 let product = obj . function * 2",
                ParseGoal::Script,
            )
            .expect("legacy valid-expression carriers should remain parse-compatible");
        let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
            panic!("expected variable declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::Raw(source)) if source == "1n"
        ));

        let Statement::VariableDeclaration(declaration) = &tree.body[1] else {
            panic!("expected dynamic-import declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::Call { callee, .. })
                if matches!(callee.as_ref(), Expression::Identifier(name) if name == "import")
        ));

        let Statement::VariableDeclaration(declaration) = &tree.body[2] else {
            panic!("expected generator declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::Function {
                is_generator: true,
                ..
            })
        ));

        let Statement::VariableDeclaration(declaration) = &tree.body[3] else {
            panic!("expected trivia-separated generator declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::Function {
                is_generator: true,
                ..
            })
        ));

        let Statement::VariableDeclaration(declaration) = &tree.body[4] else {
            panic!("expected member-product declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::Binary {
                operator: BinaryOperator::Multiply,
                ..
            })
        ));

        assert!(generator_function_marker_prefix(
            "function /* function marker */ "
        ));
        for property_prefix in ["obj. /* member */ function ", "obj.function // function\n "] {
            assert!(
                !generator_function_marker_prefix(property_prefix),
                "property named function is not a generator marker: {property_prefix:?}"
            );
        }
    }

    #[test]
    fn postfix_operands_preserve_comment_trivia_bd_56geo() {
        let tree = parse_script(
            "let blockProduct = obj. /* member */ function * 2; \
             let lineProduct = obj.function // trailing member trivia\n * 2; \
             let memberCall = obj. /* member . */ function /* callee */ \
                 (/* argument ) , */ 2 /* trailing argument */); \
             let directCall = callback /* callee */ \
                 (/* argument */ 3 /* trailing argument */); \
             let optionalMember = obj?. /* member . */ function; \
             let computedMember = obj[/* property ] */ 'function']; \
             let commentOnlyCall = callback(/**/); \
             let punctuatedArguments = callback(/* delimiters ) , */ 1, 2); \
             let trailingComment = callback(1, /* trailing */);",
        );
        let initializer = |index: usize| {
            let Statement::VariableDeclaration(declaration) = &tree.body[index] else {
                panic!("expected variable declaration at index {index}");
            };
            declaration.declarations[0]
                .initializer
                .as_ref()
                .unwrap_or_else(|| panic!("missing initializer at index {index}"))
        };

        for index in [0, 1] {
            assert!(matches!(
                initializer(index),
                Expression::Binary {
                    operator: BinaryOperator::Multiply,
                    left,
                    right,
                } if matches!(left.as_ref(), Expression::Member {
                    object,
                    property,
                    computed: false,
                } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
                    && matches!(property.as_ref(), Expression::Identifier(name) if name == "function"))
                    && matches!(right.as_ref(), Expression::NumericLiteral(2))
            ));
        }

        assert!(matches!(
            initializer(2),
            Expression::Call { callee, arguments }
                if matches!(arguments.as_slice(), [Expression::NumericLiteral(2)])
                    && matches!(callee.as_ref(), Expression::Member {
                        object,
                        property,
                        computed: false,
                    } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
                        && matches!(property.as_ref(), Expression::Identifier(name) if name == "function"))
        ));
        assert!(matches!(
            initializer(3),
            Expression::Call { callee, arguments }
                if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                    && matches!(arguments.as_slice(), [Expression::NumericLiteral(3)])
        ));
        assert!(matches!(
            initializer(4),
            Expression::OptionalMember {
                object,
                property,
                computed: false,
            } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
                && matches!(property.as_ref(), Expression::Identifier(name) if name == "function")
        ));
        assert!(matches!(
            initializer(5),
            Expression::Member {
                object,
                property,
                computed: true,
            } if matches!(object.as_ref(), Expression::Identifier(name) if name == "obj")
                && matches!(property.as_ref(), Expression::StringLiteral(name) if name == "function")
        ));
        assert!(matches!(
            initializer(6),
            Expression::Call { callee, arguments }
                if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                    && arguments.is_empty()
        ));
        assert!(matches!(
            initializer(7),
            Expression::Call { callee, arguments }
                if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                    && matches!(arguments.as_slice(), [
                        Expression::NumericLiteral(1),
                        Expression::NumericLiteral(2),
                    ])
        ));
        assert!(matches!(
            initializer(8),
            Expression::Call { callee, arguments }
                if matches!(callee.as_ref(), Expression::Identifier(name) if name == "callback")
                    && matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
        ));
    }

    #[test]
    fn unterminated_postfix_comment_trivia_fails_closed_bd_56geo() {
        let parser = CanonicalEs2020Parser;
        for source in ["obj./*", "obj[/*]", "callback(/*)"] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("unterminated postfix comment must fail closed");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }

        for source in ["obj? .value", "obj?\n.value", "obj?/* trivia */.value"] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("lexical trivia must not be joined into the `?.` punctuator");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }
    }

    #[test]
    fn postfix_comment_trivia_does_not_hide_invalid_delimiters_bd_56geo() {
        let parser = CanonicalEs2020Parser;
        for source in ["callback(/* trivia */, 1)", "callback(1, /* trivia */, 2)"] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("comment trivia must not hide invalid postfix delimiters");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
        }

        for source in ["callback(1))", "obj['value']]"] {
            assert!(
                matches!(first_expr(&parse_script(source)), Expression::Raw(_)),
                "an unmatched final delimiter must not create a Call or Member: {source:?}"
            );
        }
    }

    #[test]
    fn malformed_static_object_binding_keys_fail_closed_bd_h4esx() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "var {0_1: value} = source",
            "var {a-b: value} = source",
            r"var {\u0030bad: value} = source",
            r"var {'\01': value} = source",
            r"var {'\1': value} = source",
            r#"var {"a""b": value} = source"#,
            r"var {'a''b': value} = source",
            "var {'a\nb': value} = source",
            "var {'a\rb': value} = source",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("malformed static property key must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
            assert!(error.message.contains("object-binding property key"));
        }
    }

    #[test]
    fn static_object_literal_keys_use_canonical_ast_forms_bd_y74cd() {
        let tree = parse_script(r#"({"v\x61lue": 1, 1e3: 2, 0x10n: 3, \u03C0: 4})"#);
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected object literal");
        };
        assert_eq!(properties.len(), 4);
        assert!(matches!(
            &properties[0].key,
            Expression::StringLiteral(key) if key == "value"
        ));
        assert!(matches!(
            &properties[1].key,
            Expression::NumericLiteral(1000)
        ));
        assert!(matches!(
            &properties[2].key,
            Expression::StringLiteral(key) if key == "16"
        ));
        assert!(matches!(
            &properties[3].key,
            Expression::Identifier(key) if key == "π"
        ));
    }

    #[test]
    fn computed_object_literal_key_parses_the_inner_expression_bd_y74cd() {
        let tree = parse_script("({[null]: 7})");
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected object literal");
        };
        assert!(properties[0].computed);
        assert!(matches!(&properties[0].key, Expression::NullLiteral));
    }

    #[test]
    fn object_literal_shorthand_uses_canonical_identifier_bd_y74cd() {
        let tree = parse_script(r"({\u0076alue, await, static})");
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected object literal");
        };
        assert_eq!(properties.len(), 3);
        for (property, expected) in properties.iter().zip(["value", "await", "static"]) {
            assert!(property.shorthand);
            assert!(matches!(
                &property.key,
                Expression::Identifier(name) if name == expected
            ));
            assert!(matches!(
                &property.value,
                Expression::Identifier(name) if name == expected
            ));
        }
    }

    #[test]
    fn reserved_words_remain_valid_static_object_literal_keys_bd_y74cd() {
        let tree = parse_script("({if: 1, true: 2, null: 3})");
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected object literal");
        };
        for (property, expected) in properties.iter().zip(["if", "true", "null"]) {
            assert!(!property.shorthand);
            assert!(matches!(
                &property.key,
                Expression::Identifier(name) if name == expected
            ));
        }
    }

    #[test]
    fn malformed_static_object_literal_keys_fail_closed_bd_y74cd() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "let value = {0_1: 7}",
            "let value = {a-b: 7}",
            r#"let value = {"a""b": 7}"#,
            r"let value = {'a''b': 7}",
            r"let value = {'\01': 7}",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("malformed static object key must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
            assert!(error.message.contains("object-literal property key"));
        }
    }

    #[test]
    fn malformed_computed_object_literal_keys_fail_closed_bd_y74cd() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "let value = {[]: 7}",
            "let value = {[key] trailing: 7}",
            "let value = {[1, 2]: 7}",
            "let value = {[...items]: 7}",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("malformed computed object key must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
            assert!(
                error
                    .message
                    .contains("computed object-literal property key")
            );
        }
    }

    #[test]
    fn computed_object_literal_key_scans_are_regexp_aware_bd_egjks() {
        let tree = parse_script(r"({[/]/]: 7, [/[/]/]: 8, [/\]/]: 9, [/[:,\]]/g]: 10})");
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected object literal");
        };
        assert_eq!(properties.len(), 4);
        for (property, (pattern, flags, value)) in properties.iter().zip([
            ("]", "", 7),
            ("[/]", "", 8),
            (r"\]", "", 9),
            (r"[:,\]]", "g", 10),
        ]) {
            assert!(property.computed);
            assert!(matches!(
                &property.key,
                Expression::RegExpLiteral {
                    pattern: actual_pattern,
                    flags: actual_flags,
                } if actual_pattern == pattern && actual_flags == flags
            ));
            assert!(matches!(
                &property.value,
                Expression::NumericLiteral(actual) if *actual == value
            ));
        }

        let tree = parse_script("({[left / right]: 1, [nested[key]]: 2, [']']: 3, [`]`]: 4})");
        let Expression::ObjectLiteral(properties) = first_expr(&tree) else {
            panic!("expected mixed computed-key object literal");
        };
        assert!(matches!(
            &properties[0].key,
            Expression::Binary {
                operator: BinaryOperator::Divide,
                ..
            }
        ));
        assert!(matches!(
            &properties[1].key,
            Expression::Member { computed: true, .. }
        ));
        assert!(matches!(
            &properties[2].key,
            Expression::StringLiteral(value) if value == "]"
        ));
        assert!(matches!(
            &properties[3].key,
            Expression::TemplateLiteral { quasis, expressions }
                if matches!(quasis.as_slice(), [value] if value == "]")
                    && expressions.is_empty()
        ));
    }

    #[test]
    fn malformed_object_literal_shorthand_fails_closed_bd_y74cd() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "let value = {[key: 7}",
            r#"let value = {"key"}"#,
            "let value = {1}",
            "let value = {if}",
            "let value = {class}",
            "let value = {null}",
            "let value = {true}",
            "let value = {this}",
            "let value = {return}",
            "let value = {super}",
            r"let value = {\u0069f}",
            r"let value = {\u0063lass}",
        ] {
            let error = parser
                .parse(source, ParseGoal::Script)
                .expect_err("non-identifier shorthand must be rejected");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
            assert!(error.message.contains("object-literal shorthand property"));
        }

        for source in ["({await})", "({static})"] {
            let error = parser
                .parse(source, ParseGoal::Module)
                .expect_err("module shorthand must apply strict identifier restrictions");
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax);
            assert!(error.message.contains("object-literal shorthand property"));
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
    fn export_named_clause_parsed() {
        let parser = CanonicalEs2020Parser;
        let tree = parser
            .parse("export { a, b }", ParseGoal::Module)
            .expect("parse");
        match &tree.body[0] {
            Statement::Export(export) => match &export.kind {
                ExportKind::NamedClause(clause) => {
                    assert_eq!(clause, "{ a, b }");
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
                    assert_eq!(clause, "{ default as dep, run as start } from \"pkg\"");
                }
                _ => panic!("expected named clause export"),
            },
            _ => panic!("expected export statement"),
        }
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
        let json = serde_json::to_string(&err).unwrap();
        let decoded: ParseError = serde_json::from_str(&json).unwrap();
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
        let source = "await await work";
        let left = parser
            .parse_with_options(source, ParseGoal::Script, &options)
            .expect_err("left parse should fail");
        let right = parser
            .parse_with_options(source, ParseGoal::Script, &options)
            .expect_err("right parse should fail");
        assert_eq!(left.code, ParseErrorCode::BudgetExceeded);
        assert_eq!(left, right);
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
            let json = serde_json::to_string(&code).unwrap();
            let restored: ParseErrorCode = serde_json::from_str(&json).unwrap();
            assert_eq!(code, restored);
        }
    }

    #[test]
    fn parser_mode_serde_roundtrip() {
        let mode = ParserMode::ScalarReference;
        let json = serde_json::to_string(&mode).unwrap();
        let restored: ParserMode = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&kind).unwrap();
            let restored: ParseBudgetKind = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&status).unwrap();
            let restored: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, restored);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn parser_budget_serde_roundtrip() {
        let budget = ParserBudget::default();
        let json = serde_json::to_string(&budget).unwrap();
        let restored: ParserBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, restored);
    }

    #[test]
    fn parser_options_serde_roundtrip() {
        let opts = ParserOptions::default();
        let json = serde_json::to_string(&opts).unwrap();
        let restored: ParserOptions = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&witness).unwrap();
        let restored: ParseFailureWitness = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&gfc).unwrap();
        let restored: GrammarFamilyCoverage = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&summary).unwrap();
        let restored: GrammarCompletenessSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, restored);
    }

    #[test]
    fn grammar_completeness_matrix_serde_roundtrip() {
        let matrix = CanonicalEs2020Parser.scalar_reference_grammar_matrix();
        let json = serde_json::to_string(&matrix).unwrap();
        let restored: GrammarCompletenessMatrix = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("witness"));
        let restored: ParseError = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("witness"));
        let restored: ParseError = serde_json::from_str(&json).unwrap();
        assert!(restored.witness.is_some());
        assert_eq!(restored.witness.unwrap().source_bytes, 2_000_000);
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
        let json = serde_json::to_string(&left).unwrap();
        let restored: ParseDiagnosticEnvelope = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&kind).unwrap();
            let restored: ParseEventKind = serde_json::from_str(&json).unwrap();
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
        let source = "await work";
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
        let json = serde_json::to_string(&ir).unwrap();
        let restored: ParseEventIr = serde_json::from_str(&json).unwrap();
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
    fn materialized_ast_node_ids_are_deterministic_for_identical_inputs() {
        let parser = CanonicalEs2020Parser;
        let source = "await work";
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
        let json = serde_json::to_string(&rule).unwrap();
        let restored: ParseDiagnosticRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, restored);
    }

    #[test]
    fn parse_diagnostic_taxonomy_serde_roundtrip() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        let json = serde_json::to_string(&taxonomy).unwrap();
        let restored: ParseDiagnosticTaxonomy = serde_json::from_str(&json).unwrap();
        assert_eq!(taxonomy, restored);
    }

    #[test]
    fn parse_event_materialization_error_serde_roundtrip() {
        let err = ParseEventMaterializationError::new(
            ParseEventMaterializationErrorCode::InvalidEventSequence,
            "bad seq".to_string(),
            Some(3),
        );
        let json = serde_json::to_string(&err).unwrap();
        let restored: ParseEventMaterializationError = serde_json::from_str(&json).unwrap();
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
        assert_eq!(line_count("a\rb\r\nc\u{2028}d\u{2029}e"), 5);
    }

    #[test]
    fn line_count_trailing_newline() {
        assert_eq!(line_count("a\n"), 2);
        assert_eq!(line_count("a\r"), 2);
        assert_eq!(line_count("a\u{2028}"), 2);
        assert_eq!(line_count("a\u{2029}"), 2);
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
        assert!(canonical_module_binding_identifier("for").is_none());
        assert!(canonical_module_binding_identifier("await").is_none());
        assert!(canonical_module_binding_identifier("interface").is_none());
    }

    #[test]
    fn module_binding_identifier_accepts_valid_names() {
        assert!(canonical_module_binding_identifier("dep").is_some());
        assert!(canonical_module_binding_identifier("_local1").is_some());
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
            let json = serde_json::to_string(&cat).unwrap();
            let back: ParseDiagnosticCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn parse_diagnostic_severity_serde_roundtrip() {
        for sev in [
            ParseDiagnosticSeverity::Error,
            ParseDiagnosticSeverity::Fatal,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: ParseDiagnosticSeverity = serde_json::from_str(&json).unwrap();
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
            assert_eq!(rule.unwrap().parse_error_code, *code);
        }
    }

    #[test]
    fn taxonomy_rule_for_severity_matches_code_method() {
        let taxonomy = ParseDiagnosticTaxonomy::v1();
        for code in &ParseErrorCode::ALL {
            let rule = taxonomy.rule_for(*code).unwrap();
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
            let json = serde_json::to_string(v).unwrap();
            let back: GrammarCoverageStatus = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&fam).unwrap();
        let back: GrammarFamilyCoverage = serde_json::from_str(&json).unwrap();
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
        assert_eq!(parse_quoted_string("'abc'"), Some("abc".to_string()));
        assert_eq!(parse_quoted_string("\"xyz\""), Some("xyz".to_string()));
        assert_eq!(parse_quoted_string("''"), Some(String::new()));
        assert_eq!(parse_quoted_string("'a\\\nb'"), Some("ab".to_string()));
        assert_eq!(
            parse_quoted_string("'a\u{2028}b'"),
            Some("a\u{2028}b".to_string()),
            "ES2020 permits unescaped line and paragraph separators in string literals"
        );
        assert_eq!(
            parse_quoted_string(r"'a\nb'"),
            Some(r"a\nb".to_string()),
            "ordinary escape spelling remains raw for the legacy AST contract"
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
        assert!(parse_f64_numeric_literal("NaN").unwrap().is_nan());
    }

    #[test]
    fn parse_f64_numeric_literal_with_separators() {
        assert_eq!(parse_f64_numeric_literal("1_000.5"), Some(1000.5));
        assert_eq!(parse_f64_numeric_literal("1.5_00"), Some(1.5));
    }

    #[test]
    fn parse_f64_numeric_literal_integer_without_dot_or_exp_returns_none() {
        // Pure integers should be handled by parse_i64_numeric_literal
        assert!(parse_f64_numeric_literal("42").is_none());
        assert!(parse_f64_numeric_literal("0xFF").is_none());
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
                source: "m".to_string(),
                span: span.clone(),
            })),
            "import"
        );
        assert_eq!(
            statement_kind_label(&Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{}".to_string()),
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
        let json = serde_json::to_string(&e).unwrap();
        let back: ParseEvent = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&e).unwrap();
        let back: ParseEvent = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&n).unwrap();
        let back: MaterializedStatementNode = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&tree).unwrap();
        let back: MaterializedSyntaxTree = serde_json::from_str(&json).unwrap();
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

    fn first_expr(tree: &SyntaxTree) -> &Expression {
        match &tree.body[0] {
            Statement::Expression(es) => &es.expression,
            other => panic!("expected Expression statement, got {:?}", other),
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
            } => {
                assert_eq!(*operator, AssignmentOperator::Assign);
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
            Expression::Call { callee, arguments } => {
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
            Expression::Call { callee, arguments } => {
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
            } => {
                assert!(matches!(object.as_ref(), Expression::Identifier(n) if n == "arr"));
                assert!(matches!(property.as_ref(), Expression::NumericLiteral(0)));
                assert!(computed);
            }
            other => panic!("expected Member, got {other:?}"),
        }
    }

    #[test]
    fn this_expression() {
        let tree = parse_script("this");
        assert!(matches!(first_expr(&tree), Expression::This));
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
            } => {
                assert!(!computed);
                assert!(matches!(property.as_ref(), Expression::Identifier(n) if n == "c"));
                match object.as_ref() {
                    Expression::Member {
                        object: inner_obj,
                        property: inner_prop,
                        computed: inner_computed,
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
    fn merge_logical_lines_preserves_string_line_continuations_bd_4d60a() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "var {'a\\\nb': value} = source;",
            "var {'a\\\r\nb': value} = source;",
        ] {
            let lines = merge_logical_lines(source);
            assert_eq!(lines.len(), 1);
            assert!(lines[0].text.contains('\\'));
            parser
                .parse(source, ParseGoal::Script)
                .expect("string token cooking should consume the preserved continuation");
        }

        let lines = merge_logical_lines("var {'a\nb': value} = source;");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.contains("'a\nb'"));
    }

    #[test]
    fn merge_logical_lines_preserves_template_line_continuation_bd_h4esx() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "let value = `a\\\nb`;",
            "let value = `a\\\r\nb`;",
            "let value = `a\\\rb`;",
            "let value = `a\\\u{2028}b`;",
            "let value = `a\\\u{2029}b`;",
        ] {
            let lines = merge_logical_lines(source);
            assert_eq!(lines.len(), 1);
            assert!(
                lines[0].text.contains('\\'),
                "merge must preserve the escape for literal cooking: {source:?}"
            );
            let tree = parser
                .parse(source, ParseGoal::Script)
                .expect("template LineContinuations are cooked by the literal parser");
            assert!(matches!(
                &tree.body[0],
                Statement::VariableDeclaration(declaration)
                    if matches!(
                        declaration.declarations[0].initializer.as_ref(),
                        Some(Expression::TemplateLiteral { quasis, .. }) if quasis == &["ab"]
                    )
            ));
        }
    }

    #[test]
    fn template_line_continuation_preserves_following_statement_span_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "let t = `a\\\nb`; x;",
            "let t = `a\\\r\nb`; x;",
            "let t = `a\\\rb`; x;",
            "let t = `a\\\u{2028}b`; x;",
            "let t = `a\\\u{2029}b`; x;",
        ] {
            let tree = parser
                .parse(source, ParseGoal::Script)
                .expect("a statement after a template continuation must retain its source span");
            let Statement::Expression(expression) = &tree.body[1] else {
                panic!("expected the trailing identifier expression");
            };
            let x_offset = source.rfind('x').expect("the source contains x") as u64;
            assert_eq!(expression.span.start_offset, x_offset);
            assert_eq!(expression.span.end_offset, x_offset + 1);
            assert_eq!(expression.span.start_line, 2);
            assert_eq!(expression.span.start_column, 5);
            assert_eq!(expression.span.end_line, 2);
            assert_eq!(expression.span.end_column, 6);
        }
    }

    #[test]
    fn template_text_normalizes_cr_and_crlf_to_lf_bd_rcnxf() {
        let parser = CanonicalEs2020Parser;
        for source in ["let value = `a\rb`;", "let value = `a\r\nb`;"] {
            let tree = parser
                .parse(source, ParseGoal::Script)
                .expect("template source text accepts every ECMAScript LineTerminator");
            assert!(matches!(
                &tree.body[0],
                Statement::VariableDeclaration(declaration)
                    if matches!(
                        declaration.declarations[0].initializer.as_ref(),
                        Some(Expression::TemplateLiteral { quasis, .. }) if quasis == &["a\nb"]
                    )
            ));
        }
    }

    #[test]
    fn merge_logical_lines_block() {
        // A block spanning multiple lines should be merged into one logical line.
        let lines = merge_logical_lines("if (x) {\n  y;\n}");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].text.contains("if (x) {"));
        assert!(
            lines[0].text.contains('\n'),
            "balanced logical lines must retain LineTerminator provenance"
        );
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
    fn parse_script_with_regex_brace_before_block_keeps_two_statements() {
        let tree = parse_script("var r = /{/;\nif (x) {\n  y;\n}");
        assert_eq!(tree.body.len(), 2);
    }

    // -----------------------------------------------------------------------
    // extract_balanced helper (PearlTower 2026-03-02)
    // -----------------------------------------------------------------------

    #[test]
    fn extract_balanced_simple_parens() {
        let (inner, rest) = extract_balanced("(abc)def", '(', ')').unwrap();
        assert_eq!(inner, "abc");
        assert_eq!(rest, "def");
    }

    #[test]
    fn extract_balanced_nested() {
        let (inner, rest) = extract_balanced("((a))", '(', ')').unwrap();
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
                assert!(s.pre_loop_initializer.is_none());
            }
            other => panic!("expected ForIn, got {other:?}"),
        }
    }

    #[test]
    fn legacy_var_for_in_initializer_has_distinct_ast_bd_1tafi() {
        let tree = parse_script("for (var value = init() in object) {}");
        let Statement::ForIn(stmt) = &tree.body[0] else {
            panic!("expected legacy var ForIn, got {:?}", tree.body[0]);
        };
        assert_eq!(stmt.binding, BindingPattern::Identifier("value".into()));
        assert_eq!(stmt.binding_kind, Some(VariableDeclarationKind::Var));
        let Some(Expression::Call { callee, arguments }) = &stmt.pre_loop_initializer else {
            panic!(
                "expected distinct call initializer, got {:?}",
                stmt.pre_loop_initializer
            );
        };
        assert_eq!(callee.as_ref(), &Expression::Identifier("init".into()));
        assert!(arguments.is_empty());
        assert_eq!(stmt.object, Expression::Identifier("object".into()));

        let trivia_tree = parse_script(
            "for (var/* head */\u{FEFF}value/* name */=/* eq */init()/* init */in object) {}",
        );
        let Statement::ForIn(trivia_stmt) = &trivia_tree.body[0] else {
            panic!("expected trivia-separated legacy var ForIn");
        };
        assert_eq!(trivia_stmt.binding, stmt.binding);
        assert_eq!(trivia_stmt.pre_loop_initializer, stmt.pre_loop_initializer);
        assert_eq!(trivia_stmt.object, stmt.object);

        let candidate_tree = parse_script("for (var value = seed() in lhs() in rhs()) {}");
        let Statement::ForIn(candidate_stmt) = &candidate_tree.body[0] else {
            panic!("expected first viable top-level `in` to form a ForIn head");
        };
        assert!(matches!(
            &candidate_stmt.pre_loop_initializer,
            Some(Expression::Call { callee, arguments })
                if arguments.is_empty()
                    && callee.as_ref() == &Expression::Identifier("seed".into())
        ));
        assert!(matches!(
            &candidate_stmt.object,
            Expression::Binary {
                operator: BinaryOperator::In,
                left,
                right,
            } if matches!(left.as_ref(), Expression::Call { callee, arguments }
                if arguments.is_empty()
                    && callee.as_ref() == &Expression::Identifier("lhs".into()))
                && matches!(right.as_ref(), Expression::Call { callee, arguments }
                    if arguments.is_empty()
                        && callee.as_ref() == &Expression::Identifier("rhs".into()))
        ));
    }

    #[test]
    fn legacy_var_for_in_initializer_rejects_non_annex_b_heads_bd_1tafi() {
        let parser = CanonicalEs2020Parser;
        for source in [
            "'use strict'; for (var value = 1 in object) {}",
            "for (var value = 1 of values) {}",
            "for (let value = 1 in object) {}",
            "for (const value = 1 in object) {}",
            "for (value = 1 in object) {}",
            "for (var [value] = [1] in object) {}",
            "for (var {value} = source in object) {}",
            "for (var value = 1, other in object) {}",
            "for (var value = 1, in object) {}",
            "for (var value = ; in object) {}",
            "for (var value = @ in object) {}",
        ] {
            assert!(
                parser.parse(source, ParseGoal::Script).is_err(),
                "non-Annex-B loop head must be rejected: {source}"
            );
        }
        assert!(
            parser
                .parse("for (var value = 1 in object) {}", ParseGoal::Module,)
                .is_err(),
            "module code is strict and must reject the Annex-B extension"
        );
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
    fn postfix_chain_binds_to_new_result_bd_7rj0t() {
        let member = parse_script("new Foo(1).bar");
        assert!(matches!(
            first_expr(&member),
            Expression::Member {
                object,
                property,
                computed: false,
            } if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1)
                && matches!(property.as_ref(), Expression::Identifier(name) if name == "bar")
        ));

        let method = parse_script("new Foo(1).bar()");
        assert!(matches!(
            first_expr(&method),
            Expression::Call { callee, arguments }
                if arguments.is_empty()
                    && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                        if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1))
        ));

        let computed = parse_script("new Foo(1)[0]");
        assert!(matches!(
            first_expr(&computed),
            Expression::Member {
                object,
                property,
                computed: true,
            } if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1)
                && matches!(property.as_ref(), Expression::NumericLiteral(0))
        ));

        let called_result = parse_script("new Foo(1)()");
        assert!(matches!(
            first_expr(&called_result),
            Expression::Call { callee, arguments }
                if arguments.is_empty()
                    && matches!(callee.as_ref(), Expression::New { arguments, .. } if arguments.len() == 1)
        ));
    }

    #[test]
    fn new_result_regrouping_preserves_existing_forms_bd_7rj0t() {
        assert!(matches!(
            first_expr(&parse_script("(new Foo()).bar")),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
        ));
        assert!(matches!(
            first_expr(&parse_script("new (factory())(1)")),
            Expression::New { callee, arguments }
                if arguments.len() == 1 && matches!(callee.as_ref(), Expression::Call { .. })
        ));
        assert!(matches!(
            first_expr(&parse_script("new (factory())(1).value")),
            Expression::Member { object, computed: false, .. }
                if matches!(object.as_ref(), Expression::New { callee, arguments }
                    if arguments.len() == 1 && matches!(callee.as_ref(), Expression::Call { .. }))
        ));
        assert!(matches!(
            first_expr(&parse_script("new (factory()).value")),
            Expression::New { callee, arguments }
                if arguments.is_empty()
                    && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                        if matches!(object.as_ref(), Expression::Call { .. }))
        ));
        assert!(matches!(
            first_expr(&parse_script("new Foo()?.value")),
            Expression::OptionalMember { object, computed: false, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
        ));
        assert!(matches!(
            first_expr(&parse_script("new Foo()?.[0]")),
            Expression::OptionalMember { object, computed: true, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
        ));
        assert!(matches!(
            first_expr(&parse_script("new Foo()?.()")),
            Expression::OptionalCall { callee, arguments }
                if arguments.is_empty()
                    && matches!(callee.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
        ));
        assert!(matches!(
            first_expr(&parse_script("new new Foo().value")),
            Expression::New { callee, arguments }
                if arguments.is_empty()
                    && matches!(callee.as_ref(), Expression::Member { object, .. }
                        if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty()))
        ));
        assert!(matches!(
            first_expr(&parse_script("new new Foo()(1).value")),
            Expression::Member { object, computed: false, .. }
                if matches!(object.as_ref(), Expression::New { callee, arguments }
                    if matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
                        && matches!(callee.as_ref(), Expression::New { arguments, .. }
                            if arguments.is_empty()))
        ));
        assert!(matches!(
            first_expr(&parse_script("new new (Foo)(1).value")),
            Expression::New { callee, arguments }
                if arguments.is_empty()
                    && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                        if matches!(object.as_ref(), Expression::New { callee, arguments }
                            if matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
                                && matches!(callee.as_ref(), Expression::Identifier(name) if name == "Foo")))
        ));
        assert!(matches!(
            first_expr(&parse_script("new new (factory())(1).value")),
            Expression::New { callee, arguments }
                if arguments.is_empty()
                    && matches!(callee.as_ref(), Expression::Member { object, computed: false, .. }
                        if matches!(object.as_ref(), Expression::New { callee, arguments }
                            if matches!(arguments.as_slice(), [Expression::NumericLiteral(1)])
                                && matches!(callee.as_ref(), Expression::Call { .. })))
        ));

        let invalid_optional_constructor = CanonicalEs2020Parser
            .parse("new Foo?.()", ParseGoal::Script)
            .expect_err("optional chaining in constructor position must fail");
        assert_eq!(
            invalid_optional_constructor.code,
            ParseErrorCode::UnsupportedSyntax
        );
        assert_eq!(
            invalid_optional_constructor.message,
            "optional chaining cannot be used in constructor position"
        );
    }

    #[test]
    fn new_result_regrouping_ignores_argument_delimiters_bd_7rj0t() {
        assert!(matches!(
            first_expr(&parse_script("new Foo(\")\").value")),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. }
                    if matches!(arguments.as_slice(), [Expression::StringLiteral(value)] if value == ")"))
        ));
        assert!(matches!(
            first_expr(&parse_script(r"new Foo(/\)/).value")),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. }
                    if matches!(arguments.as_slice(), [Expression::RegExpLiteral { pattern, .. }] if pattern == r"\)"))
        ));
        assert!(matches!(
            first_expr(&parse_script(r"new Foo(`${`)`}`).value")),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. }
                    if matches!(arguments.as_slice(), [Expression::TemplateLiteral { expressions, .. }]
                        if expressions.len() == 1))
        ));
        assert!(matches!(
            first_expr(&parse_script(
                r"new Foo(function(){ return /\)/; }).value"
            )),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. }
                    if matches!(arguments.as_slice(), [Expression::Function { .. }]))
        ));
        assert!(matches!(
            first_expr(&parse_script(
                r"new Foo(function(){ let x=1; /\)/.test(x); }).value"
            )),
            Expression::Member { object, .. }
                if matches!(object.as_ref(), Expression::New { arguments, .. }
                    if matches!(arguments.as_slice(), [Expression::Function { .. }]))
        ));
        assert!(matches!(
            first_expr(&parse_script("new Foo() /* gap */ .value")),
            Expression::Member { object, property, computed: false }
                if matches!(object.as_ref(), Expression::New { arguments, .. } if arguments.is_empty())
                    && matches!(property.as_ref(), Expression::Identifier(name) if name == "value")
        ));
    }

    #[test]
    fn new_in_variable_decl() {
        let tree = parse_script("const m = new Map()");
        match &tree.body[0] {
            Statement::VariableDeclaration(decl) => {
                let init = decl.declarations[0].initializer.as_ref().unwrap();
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
                let init = decl.declarations[0].initializer.as_ref().unwrap();
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
                let init = decl.declarations[0].initializer.as_ref().unwrap();
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
                let init = decl.declarations[0].initializer.as_ref().unwrap();
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
                let init = decl.declarations[0].initializer.as_ref().unwrap();
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
    fn tagged_template_expression_is_rejected_as_unsupported() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("render`hello ${name}`", ParseGoal::Script)
            .expect_err("tagged template expressions should be rejected");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
        assert!(
            err.message.contains("tagged template"),
            "error message should mention tagged templates: {}",
            err.message
        );
    }

    #[test]
    fn tagged_template_member_expression_is_rejected_as_unsupported() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("view.render`ok`", ParseGoal::Script)
            .expect_err("tagged template member expressions should be rejected");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
        assert!(
            err.message.contains("tagged template"),
            "error message should mention tagged templates: {}",
            err.message
        );
    }

    #[test]
    fn template_literal_unbalanced_interpolation_is_rejected() {
        let parser = CanonicalEs2020Parser;
        let err = parser
            .parse("const s = `value: ${name`", ParseGoal::Script)
            .expect_err("unbalanced interpolation should fail");
        assert_eq!(err.code, ParseErrorCode::UnsupportedSyntax);
    }

    // Donor parity for bd-8fzl3 was checked against Node 20.19.4 and Bun
    // 1.3.14: both accept the valid sloppy/async/generator/for/control/
    // nested-template cases below and reject the malformed delimiter and
    // formal-parameter cases. Keep the matrix local to the regressions so a
    // future lexical-goal change cannot silently shed its donor evidence.
    #[test]
    fn template_interpolation_uses_grammar_aware_slash_goals_bd_8fzl3() {
        let tree = parse_script(r#"const value = `${await / 2}:${yield / 3}:${of / 5}:${/[}]/}`;"#);
        let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
            panic!("expected template variable declaration");
        };
        let Some(Expression::TemplateLiteral {
            quasis,
            expressions,
        }) = declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected template initializer");
        };
        assert_eq!(quasis, &["", ":", ":", ":", ""]);
        assert_eq!(expressions.len(), 4);
        for (expression, identifier, divisor) in [
            (&expressions[0], "await", 2),
            (&expressions[1], "yield", 3),
            (&expressions[2], "of", 5),
        ] {
            assert!(matches!(
                expression,
                Expression::Binary {
                    operator: BinaryOperator::Divide,
                    left,
                    right,
                } if matches!(left.as_ref(), Expression::Identifier(name) if name == identifier)
                    && matches!(right.as_ref(), Expression::NumericLiteral(value) if *value == divisor)
            ));
        }
        assert!(matches!(
            &expressions[3],
            Expression::RegExpLiteral { pattern, flags }
                if pattern == "[}]" && flags.is_empty()
        ));

        let chained = parse_script(
            r#"const value = `${await / 2 / /}/}:${yield / 3 / /}/}:${of / 5 / /}/}`;"#,
        );
        let Statement::VariableDeclaration(declaration) = &chained.body[0] else {
            panic!("expected chained template variable declaration");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) =
            declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected chained template initializer");
        };
        assert_eq!(expressions.len(), 3);
        for expression in expressions {
            assert!(matches!(
                expression,
                Expression::Binary {
                    operator: BinaryOperator::Divide,
                    left,
                    right,
                } if matches!(left.as_ref(), Expression::Binary {
                    operator: BinaryOperator::Divide,
                    ..
                }) && matches!(right.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
            ));
        }

        let token_boundaries = parse_script(
            r#"const value = `${π / 2 / /}/}:${\u0061wait / 3 / /}/}:${\u{61}wait / 4 / /}/}:${1. / 2 / /}/}`;"#,
        );
        let Statement::VariableDeclaration(declaration) = &token_boundaries.body[0] else {
            panic!("expected token-boundary template declaration");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) =
            declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected token-boundary template initializer");
        };
        assert_eq!(expressions.len(), 4);
        for expression in expressions {
            assert!(matches!(
                expression,
                Expression::Binary {
                    operator: BinaryOperator::Divide,
                    left,
                    right,
                } if matches!(left.as_ref(), Expression::Binary {
                    operator: BinaryOperator::Divide,
                    ..
                }) && matches!(right.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
            ));
        }

        let strict_property_names =
            parse_script(r#""use strict"; const value = ({yield: 1, await: 2});"#);
        let Statement::VariableDeclaration(declaration) = &strict_property_names.body[1] else {
            panic!("expected strict object declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::ObjectLiteral(properties)) if properties.len() == 2
        ));

        assert_eq!(
            find_top_level_template_start(
                r#"/`/`tail`"#,
                ScanGrammarContext::SLOPPY_SCRIPT.expression(),
            ),
            Some(3),
            "a backtick inside a RegExp literal is not a template opener",
        );
        let regexp_backtick = parse_script(r#"const value = `${/`/.test("`")}`;"#);
        let Statement::VariableDeclaration(declaration) = &regexp_backtick.body[0] else {
            panic!("expected RegExp-backtick template declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::TemplateLiteral { expressions, .. })
                if matches!(&expressions[..], [Expression::Call { .. }])
        ));
    }

    #[test]
    fn binding_patterns_preserve_async_and_generator_slash_context_bd_8fzl3() {
        let async_tree = parse_script(
            r#"async function f(source) {
                const { [await /=/]: eq, [await /]/]: close, value = await /:/ } = source;
                const [item = await /}/,] = source;
            }"#,
        );
        assert!(matches!(
            &async_tree.body[..],
            [Statement::FunctionDeclaration(function)] if function.body.body.len() == 2
        ));

        let generator_tree = parse_script(
            r#"function* g(source) {
                const { [yield /=/]: eq, [yield /]/]: close, value = yield /:/ } = source;
                const [item = yield /}/,] = source;
            }"#,
        );
        assert!(matches!(
            &generator_tree.body[..],
            [Statement::FunctionDeclaration(function)] if function.body.body.len() == 2
        ));
    }

    #[test]
    fn postfix_arguments_and_constructors_preserve_slash_context_bd_8fzl3() {
        let async_tree = parse_script(
            r#"async function f(C, g) {
                const call = g(await /}/);
                const construct = new C(await /}/);
                const member = (await /}/).test("}");
                const computed = (await /}/)[0];
            }"#,
        );
        let [Statement::FunctionDeclaration(function)] = &async_tree.body[..] else {
            panic!("expected async function declaration");
        };
        let [
            Statement::VariableDeclaration(call),
            Statement::VariableDeclaration(construct),
            Statement::VariableDeclaration(member),
            Statement::VariableDeclaration(computed),
        ] = &function.body.body[..]
        else {
            panic!("expected four async-context declarations");
        };
        assert!(matches!(
            call.declarations[0].initializer.as_ref(),
            Some(Expression::Call { arguments, .. })
                if matches!(&arguments[..], [Expression::Await(argument)]
                    if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}"))
        ));
        assert!(matches!(
            construct.declarations[0].initializer.as_ref(),
            Some(Expression::New { arguments, .. })
                if matches!(&arguments[..], [Expression::Await(argument)]
                    if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}"))
        ));
        assert!(matches!(
            member.declarations[0].initializer.as_ref(),
            Some(Expression::Call { callee, .. })
                if matches!(callee.as_ref(), Expression::Member { object, .. }
                    if matches!(object.as_ref(), Expression::Await(_)))
        ));
        assert!(matches!(
            computed.declarations[0].initializer.as_ref(),
            Some(Expression::Member { object, computed: true, .. })
                if matches!(object.as_ref(), Expression::Await(_))
        ));

        let generator_tree = parse_script(
            r#"function* g(C, f) {
                const call = f(yield /}/);
                const construct = new C(yield /}/);
            }"#,
        );
        let [Statement::FunctionDeclaration(function)] = &generator_tree.body[..] else {
            panic!("expected generator function declaration");
        };
        for statement in &function.body.body {
            let Statement::VariableDeclaration(declaration) = statement else {
                panic!("expected generator-context declaration");
            };
            let expression = declaration.declarations[0]
                .initializer
                .as_ref()
                .expect("expected initializer");
            let arguments = match expression {
                Expression::Call { arguments, .. } | Expression::New { arguments, .. } => arguments,
                other => panic!("expected call or constructor, got {other:?}"),
            };
            assert!(matches!(
                &arguments[..],
                [Expression::Yield {
                    argument: Some(argument),
                    delegate: false,
                }] if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
            ));
        }
    }

    #[test]
    fn logical_line_continuations_preserve_slash_context_bd_8fzl3() {
        for source in [
            "async function f() { const value =\nawait /}/;\nif (\nawait /[)}]/\n) /}/; }",
            "function* g() { const value =\nyield /}/;\nif (\nyield /[)}]/\n) /}/; }",
        ] {
            let tree = parse_script(source);
            assert!(matches!(
                &tree.body[..],
                [Statement::FunctionDeclaration(function)] if function.body.body.len() == 2
            ));
        }
    }

    #[test]
    fn template_interpolation_scopes_async_generator_and_nested_functions_bd_8fzl3() {
        let async_tree = parse_script(
            r#"async function outer() {
                function normal(await) { return `${await / 2}:${/[}]/}`; }
                return `${await /[}]/}`;
            }"#,
        );
        let Statement::FunctionDeclaration(async_outer) = &async_tree.body[0] else {
            panic!("expected async function declaration");
        };
        let Statement::FunctionDeclaration(normal) = &async_outer.body.body[0] else {
            panic!("expected nested ordinary function");
        };
        let Statement::Return(normal_return) = &normal.body.body[0] else {
            panic!("expected nested return statement");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) = &normal_return.argument else {
            panic!("expected nested template return");
        };
        assert!(matches!(
            &expressions[0],
            Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                ..
            } if matches!(left.as_ref(), Expression::Identifier(name) if name == "await")
        ));
        assert!(matches!(&expressions[1], Expression::RegExpLiteral { .. }));

        let Statement::Return(async_return) = &async_outer.body.body[1] else {
            panic!("expected async return statement");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) = &async_return.argument else {
            panic!("expected async template return");
        };
        assert!(matches!(
            &expressions[0],
            Expression::Await(inner)
                if matches!(inner.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "[}]")
        ));

        let generator_tree = parse_script(
            r#"function* outer() {
                function normal(yield) { return `${yield / 3}:${/[}]/}`; }
                return `${yield /[}]/}`;
            }"#,
        );
        let Statement::FunctionDeclaration(generator_outer) = &generator_tree.body[0] else {
            panic!("expected generator function declaration");
        };
        let Statement::FunctionDeclaration(normal) = &generator_outer.body.body[0] else {
            panic!("expected nested ordinary function");
        };
        let Statement::Return(normal_return) = &normal.body.body[0] else {
            panic!("expected nested generator-context reset return");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) = &normal_return.argument else {
            panic!("expected nested generator-context reset template");
        };
        assert!(matches!(
            &expressions[0],
            Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                ..
            } if matches!(left.as_ref(), Expression::Identifier(name) if name == "yield")
        ));

        let Statement::Return(generator_return) = &generator_outer.body.body[1] else {
            panic!("expected generator return statement");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) = &generator_return.argument
        else {
            panic!("expected generator template return");
        };
        assert!(matches!(
            &expressions[0],
            Expression::Yield {
                argument: Some(argument),
                delegate: false,
            } if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "[}]")
        ));
    }

    #[test]
    fn template_interpolation_scopes_arrow_and_class_method_bodies_bd_8fzl3() {
        let async_arrow = parse_script(r#"const value = `${async(x) => await /}/}`;"#);
        let Statement::VariableDeclaration(declaration) = &async_arrow.body[0] else {
            panic!("expected async-arrow declaration");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) =
            declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected async-arrow template");
        };
        assert!(matches!(
            &expressions[0],
            Expression::ArrowFunction {
                is_async: true,
                body: ArrowBody::Expression(body),
                ..
            } if matches!(body.as_ref(), Expression::Await(argument)
                if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}"))
        ));

        let nested_arrow = parse_script(
            r#"async function outer() {
                return `${true ? () => await / 2 : await /}/}`;
            }"#,
        );
        let Statement::FunctionDeclaration(outer) = &nested_arrow.body[0] else {
            panic!("expected async outer function");
        };
        let Statement::Return(return_statement) = &outer.body.body[0] else {
            panic!("expected async outer return");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) = &return_statement.argument
        else {
            panic!("expected nested-arrow template");
        };
        let Expression::Conditional {
            consequent,
            alternate,
            ..
        } = &expressions[0]
        else {
            panic!("expected conditional containing an ordinary arrow");
        };
        assert!(matches!(
            consequent.as_ref(),
            Expression::ArrowFunction {
                is_async: false,
                body: ArrowBody::Expression(body),
                ..
            } if matches!(body.as_ref(), Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                ..
            } if matches!(left.as_ref(), Expression::Identifier(name) if name == "await"))
        ));
        assert!(matches!(
            alternate.as_ref(),
            Expression::Await(argument)
                if matches!(argument.as_ref(), Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));

        let class_method = parse_script(
            r#"async function outer() {
                class C { method() { return `${await / 2}`; } }
            }"#,
        );
        let Statement::FunctionDeclaration(outer) = &class_method.body[0] else {
            panic!("expected async outer function around class");
        };
        let Statement::ClassDeclaration(class) = &outer.body.body[0] else {
            panic!("expected nested class declaration");
        };
        let Statement::Return(return_statement) = &class.body[0].body.body[0] else {
            panic!("expected class-method return");
        };
        let Some(Expression::TemplateLiteral { expressions, .. }) = &return_statement.argument
        else {
            panic!("expected class-method template");
        };
        assert!(matches!(
            &expressions[0],
            Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                ..
            } if matches!(left.as_ref(), Expression::Identifier(name) if name == "await")
        ));
    }

    #[test]
    fn delimiter_cursor_distinguishes_for_heads_blocks_and_expression_bodies_bd_8fzl3() {
        let for_tree = parse_script("if (false) for (let of of /r/) {}");
        let Statement::If(if_statement) = &for_tree.body[0] else {
            panic!("expected guarding if statement");
        };
        let Statement::ForOf(for_of) = if_statement.consequent.as_ref() else {
            panic!("expected contextual for-of statement");
        };
        assert!(matches!(
            &for_of.binding,
            BindingPattern::Identifier(name) if name == "of"
        ));
        assert!(matches!(
            &for_of.iterable,
            Expression::RegExpLiteral { pattern, .. } if pattern == "r"
        ));

        let destructuring_for = parse_script("if (false) for (let [x] of /}/) {}");
        let Statement::If(if_statement) = &destructuring_for.body[0] else {
            panic!("expected guarding if for destructuring for-of");
        };
        let Statement::ForOf(for_of) = if_statement.consequent.as_ref() else {
            panic!("expected destructuring for-of statement");
        };
        assert!(matches!(
            &for_of.iterable,
            Expression::RegExpLiteral { pattern, .. } if pattern == "}"
        ));

        let if_tree = parse_script("if (true) /}/;");
        let Statement::If(if_statement) = &if_tree.body[0] else {
            panic!("expected if statement");
        };
        assert!(matches!(
            if_statement.consequent.as_ref(),
            Statement::Expression(statement)
                if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));

        let else_tree = parse_script("if (false) 0; else /}/;");
        let Statement::If(if_statement) = &else_tree.body[0] else {
            panic!("expected if/else statement");
        };
        assert!(matches!(
            if_statement.alternate.as_deref(),
            Some(Statement::Expression(statement))
                if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));

        let do_tree = parse_script("do /}/; while (false);");
        let Statement::DoWhile(do_while) = &do_tree.body[0] else {
            panic!("expected do/while statement");
        };
        assert!(matches!(
            do_while.body.as_ref(),
            Statement::Expression(statement)
                if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));

        let block_tree = parse_script("{} /}/;");
        assert_eq!(block_tree.body.len(), 2);
        assert!(matches!(&block_tree.body[0], Statement::Block(_)));
        assert!(matches!(
            &block_tree.body[1],
            Statement::Expression(statement)
                if matches!(&statement.expression, Expression::RegExpLiteral { pattern, .. } if pattern == "}")
        ));

        for (source, expected_left) in [
            ("({value: 12}) / 3", "object"),
            ("(function(){}) / 2", "function"),
            ("(class{}) / 2", "class"),
        ] {
            let tree = parse_script(source);
            let Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                ..
            } = first_expr(&tree)
            else {
                panic!("expected division after {expected_left} expression");
            };
            let correct_left = match expected_left {
                "object" => matches!(left.as_ref(), Expression::ObjectLiteral(_)),
                "function" => matches!(left.as_ref(), Expression::Function { .. }),
                "class" => matches!(left.as_ref(), Expression::ClassExpression { .. }),
                _ => false,
            };
            assert!(correct_left, "wrong left operand for {source:?}: {left:?}");
        }
    }

    #[test]
    fn nested_templates_share_the_grammar_aware_delimiter_cursor_bd_8fzl3() {
        let tree = parse_script(r#"const value = `A${`B${of / 3}:${/[}]/}C`}D`;"#);
        let Statement::VariableDeclaration(declaration) = &tree.body[0] else {
            panic!("expected nested-template declaration");
        };
        let Some(Expression::TemplateLiteral {
            quasis,
            expressions,
        }) = declaration.declarations[0].initializer.as_ref()
        else {
            panic!("expected outer template");
        };
        assert_eq!(quasis, &["A", "D"]);
        let [
            Expression::TemplateLiteral {
                quasis: nested_quasis,
                expressions: nested_expressions,
            },
        ] = expressions.as_slice()
        else {
            panic!("expected one nested template expression");
        };
        assert_eq!(nested_quasis, &["B", ":", "C"]);
        assert!(matches!(
            &nested_expressions[0],
            Expression::Binary {
                operator: BinaryOperator::Divide,
                left,
                ..
            } if matches!(left.as_ref(), Expression::Identifier(name) if name == "of")
        ));
        assert!(matches!(
            &nested_expressions[1],
            Expression::RegExpLiteral { pattern, .. } if pattern == "[}]"
        ));

        let multiline = parse_script(
            r#"const value = `A${`B
${/[}]/}C`}D`;"#,
        );
        assert_eq!(multiline.body.len(), 1);
        let Statement::VariableDeclaration(declaration) = &multiline.body[0] else {
            panic!("expected multiline nested-template declaration");
        };
        assert!(matches!(
            declaration.declarations[0].initializer.as_ref(),
            Some(Expression::TemplateLiteral { expressions, .. })
                if matches!(&expressions[0], Expression::TemplateLiteral { expressions, .. }
                    if matches!(&expressions[0], Expression::RegExpLiteral { pattern, .. } if pattern == "[}]"))
        ));
    }

    #[test]
    fn malformed_grammar_aware_delimiters_fail_closed_bd_8fzl3() {
        let parser = CanonicalEs2020Parser;
        for source in [
            r#"const value = `${/unterminated}`;"#,
            r#"const value = `${/[}]/.test("}")`;"#,
            r#"const value = `${]}`;"#,
            "const value = `${/unterminated\n/}`;",
            "for (let of /r/) {}",
            "async function bad(await) {}",
            "function* bad(yield) {}",
            "const bad = async (await) => 0;",
            "async function bad({[await /]/]: value}) {}",
            "function* bad({[yield /]/]: value}) {}",
        ] {
            let error = match parser.parse(source, ParseGoal::Script) {
                Ok(tree) => panic!("malformed source parsed as {tree:?}: {source:?}"),
                Err(error) => error,
            };
            assert_eq!(error.code, ParseErrorCode::UnsupportedSyntax, "{source:?}");
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
                    elements[0].as_ref().unwrap(),
                    Expression::NumericLiteral(1)
                ));
                match elements[1].as_ref().unwrap() {
                    Expression::SpreadElement(inner) => {
                        assert!(matches!(inner.as_ref(), Expression::Identifier(n) if n == "arr"));
                    }
                    other => panic!("expected SpreadElement, got {other:?}"),
                }
                assert!(matches!(
                    elements[2].as_ref().unwrap(),
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
                    elements[0].as_ref().unwrap(),
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
                    elements[0].as_ref().unwrap(),
                    Expression::SpreadElement(_)
                ));
                assert!(matches!(
                    elements[1].as_ref().unwrap(),
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
    fn regexp_literal_canonical_hash_stability() {
        let tree1 = parse_script("/test/gi;");
        let tree2 = parse_script("/test/gi;");
        assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
    }
}
