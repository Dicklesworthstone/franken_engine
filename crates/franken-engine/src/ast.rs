//! Canonical AST surface for the parser slot (`IR0 SyntaxIR`).
//!
//! This module defines a deterministic AST hierarchy for ES2020 script/module
//! goal symbols. The parser in `parser.rs` emits this representation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::deterministic_serde::{self, CanonicalValue};

/// Versioned canonical AST contract binding schema + hash semantics.
pub const CANONICAL_AST_CONTRACT_VERSION: &str = "franken-engine.parser-ast.contract.v1";
/// Versioned schema identifier for canonical AST structure and key ordering.
pub const CANONICAL_AST_SCHEMA_VERSION: &str = "franken-engine.parser-ast.schema.v1";
/// Hash algorithm used by `SyntaxTree::canonical_hash`.
pub const CANONICAL_AST_HASH_ALGORITHM: &str = "sha256";
/// Prefix used in canonical AST hash strings.
pub const CANONICAL_AST_HASH_PREFIX: &str = "sha256:";

/// Parse-goal marker for ES2020 sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParseGoal {
    Script,
    Module,
}

impl ParseGoal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Module => "module",
        }
    }
}

/// Source-span with byte offsets and one-based line/column markers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start_offset: u64,
    pub end_offset: u64,
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
}

impl SourceSpan {
    pub fn new(
        start_offset: u64,
        end_offset: u64,
        start_line: u64,
        start_column: u64,
        end_line: u64,
        end_column: u64,
    ) -> Self {
        Self {
            start_offset,
            end_offset,
            start_line,
            start_column,
            end_line,
            end_column,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "start_offset".to_string(),
            CanonicalValue::U64(self.start_offset),
        );
        map.insert(
            "end_offset".to_string(),
            CanonicalValue::U64(self.end_offset),
        );
        map.insert(
            "start_line".to_string(),
            CanonicalValue::U64(self.start_line),
        );
        map.insert(
            "start_column".to_string(),
            CanonicalValue::U64(self.start_column),
        );
        map.insert("end_line".to_string(), CanonicalValue::U64(self.end_line));
        map.insert(
            "end_column".to_string(),
            CanonicalValue::U64(self.end_column),
        );
        CanonicalValue::Map(map)
    }
}

/// Canonical parser output for `IR0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntaxTree {
    pub goal: ParseGoal,
    pub body: Vec<Statement>,
    pub span: SourceSpan,
}

impl SyntaxTree {
    pub const fn canonical_contract_version() -> &'static str {
        CANONICAL_AST_CONTRACT_VERSION
    }

    pub const fn canonical_schema_version() -> &'static str {
        CANONICAL_AST_SCHEMA_VERSION
    }

    pub const fn canonical_hash_algorithm() -> &'static str {
        CANONICAL_AST_HASH_ALGORITHM
    }

    pub const fn canonical_hash_prefix() -> &'static str {
        CANONICAL_AST_HASH_PREFIX
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "goal".to_string(),
            CanonicalValue::String(self.goal.as_str().to_string()),
        );
        map.insert(
            "body".to_string(),
            CanonicalValue::Array(self.body.iter().map(Statement::canonical_value).collect()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        deterministic_serde::encode_value(&self.canonical_value())
    }

    pub fn canonical_hash(&self) -> String {
        let digest = Sha256::digest(self.canonical_bytes());
        format!("{}{}", Self::canonical_hash_prefix(), hex::encode(digest))
    }
}

/// Statement hierarchy for the canonical AST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Statement {
    Import(ImportDeclaration),
    Export(ExportDeclaration),
    VariableDeclaration(VariableDeclaration),
    Expression(ExpressionStatement),
    Block(BlockStatement),
    If(IfStatement),
    For(ForStatement),
    While(WhileStatement),
    DoWhile(DoWhileStatement),
    Return(ReturnStatement),
    Throw(ThrowStatement),
    TryCatch(TryCatchStatement),
    Switch(SwitchStatement),
    Break(BreakStatement),
    Continue(ContinueStatement),
    FunctionDeclaration(FunctionDeclaration),
    ForIn(ForInStatement),
    ForOf(ForOfStatement),
}

impl Statement {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Import(v) => &v.span,
            Self::Export(v) => &v.span,
            Self::VariableDeclaration(v) => &v.span,
            Self::Expression(v) => &v.span,
            Self::Block(v) => &v.span,
            Self::If(v) => &v.span,
            Self::For(v) => &v.span,
            Self::While(v) => &v.span,
            Self::DoWhile(v) => &v.span,
            Self::Return(v) => &v.span,
            Self::Throw(v) => &v.span,
            Self::TryCatch(v) => &v.span,
            Self::Switch(v) => &v.span,
            Self::Break(v) => &v.span,
            Self::Continue(v) => &v.span,
            Self::FunctionDeclaration(v) => &v.span,
            Self::ForIn(v) => &v.span,
            Self::ForOf(v) => &v.span,
        }
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Import(import) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("import".to_string()),
                );
                map.insert("payload".to_string(), import.canonical_value());
            }
            Self::Export(export) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("export".to_string()),
                );
                map.insert("payload".to_string(), export.canonical_value());
            }
            Self::VariableDeclaration(variable_declaration) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("variable_declaration".to_string()),
                );
                map.insert(
                    "payload".to_string(),
                    variable_declaration.canonical_value(),
                );
            }
            Self::Expression(expr) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("expression".to_string()),
                );
                map.insert("payload".to_string(), expr.canonical_value());
            }
            Self::Block(block) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("block".to_string()),
                );
                map.insert("payload".to_string(), block.canonical_value());
            }
            Self::If(if_stmt) => {
                map.insert("kind".to_string(), CanonicalValue::String("if".to_string()));
                map.insert("payload".to_string(), if_stmt.canonical_value());
            }
            Self::For(for_stmt) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("for".to_string()),
                );
                map.insert("payload".to_string(), for_stmt.canonical_value());
            }
            Self::While(while_stmt) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("while".to_string()),
                );
                map.insert("payload".to_string(), while_stmt.canonical_value());
            }
            Self::DoWhile(do_while) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("do_while".to_string()),
                );
                map.insert("payload".to_string(), do_while.canonical_value());
            }
            Self::Return(ret) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("return".to_string()),
                );
                map.insert("payload".to_string(), ret.canonical_value());
            }
            Self::Throw(throw) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("throw".to_string()),
                );
                map.insert("payload".to_string(), throw.canonical_value());
            }
            Self::TryCatch(tc) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("try_catch".to_string()),
                );
                map.insert("payload".to_string(), tc.canonical_value());
            }
            Self::Switch(sw) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("switch".to_string()),
                );
                map.insert("payload".to_string(), sw.canonical_value());
            }
            Self::Break(brk) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("break".to_string()),
                );
                map.insert("payload".to_string(), brk.canonical_value());
            }
            Self::Continue(cont) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("continue".to_string()),
                );
                map.insert("payload".to_string(), cont.canonical_value());
            }
            Self::FunctionDeclaration(func) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("function_declaration".to_string()),
                );
                map.insert("payload".to_string(), func.canonical_value());
            }
            Self::ForIn(stmt) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("for_in".to_string()),
                );
                map.insert("payload".to_string(), stmt.canonical_value());
            }
            Self::ForOf(stmt) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("for_of".to_string()),
                );
                map.insert("payload".to_string(), stmt.canonical_value());
            }
        }
        map.insert("span".to_string(), self.span().canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDeclaration {
    pub binding: Option<String>,
    pub source: String,
    pub span: SourceSpan,
}

impl ImportDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "binding".to_string(),
            match &self.binding {
                Some(value) => CanonicalValue::String(value.clone()),
                None => CanonicalValue::Null,
            },
        );
        map.insert(
            "source".to_string(),
            CanonicalValue::String(self.source.clone()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportKind {
    Default(Expression),
    NamedClause(String),
}

impl ExportKind {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Default(expr) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("default".to_string()),
                );
                map.insert("value".to_string(), expr.canonical_value());
            }
            Self::NamedClause(clause) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("named".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(clause.clone()));
            }
        }
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportDeclaration {
    pub kind: ExportKind,
    pub span: SourceSpan,
}

impl ExportDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), self.kind.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Destructuring / binding pattern AST types
// ---------------------------------------------------------------------------

/// A property in an object destructuring pattern: `{ key: pattern = default }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectPatternProperty {
    /// The property key (Identifier or computed expression).
    pub key: Expression,
    /// The target pattern (may differ from key for `{ a: b }`).
    pub value: BindingPattern,
    /// Whether the key is a computed expression (`{ [expr]: pat }`).
    pub computed: bool,
    /// Whether this is shorthand (`{ x }` ≡ `{ x: x }`).
    pub shorthand: bool,
}

impl ObjectPatternProperty {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), self.key.canonical_value());
        map.insert("value".to_string(), self.value.canonical_value());
        map.insert("computed".to_string(), CanonicalValue::Bool(self.computed));
        map.insert(
            "shorthand".to_string(),
            CanonicalValue::Bool(self.shorthand),
        );
        CanonicalValue::Map(map)
    }
}

/// ES2020 destructuring binding pattern.
///
/// Represents the left-hand side of variable declarations, function parameters,
/// for-in/for-of bindings, and assignment targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindingPattern {
    /// Simple identifier binding: `x`
    Identifier(String),
    /// Object destructuring: `{ a, b: c, ...rest }`
    ObjectPattern(Vec<ObjectPatternProperty>),
    /// Array destructuring: `[a, , b, ...rest]`
    ArrayPattern(Vec<Option<BindingPattern>>),
    /// Rest element: `...x` or `...{ a, b }`
    Rest(Box<BindingPattern>),
    /// Default value: `x = defaultExpr`
    AssignmentPattern {
        left: Box<BindingPattern>,
        right: Expression,
    },
}

impl BindingPattern {
    /// Returns the identifier name if this is a simple identifier binding.
    pub fn as_identifier(&self) -> Option<&str> {
        match self {
            Self::Identifier(name) => Some(name),
            _ => None,
        }
    }

    /// Collects all bound names from this pattern (recursively).
    pub fn binding_names(&self) -> Vec<&str> {
        match self {
            Self::Identifier(name) => vec![name.as_str()],
            Self::ObjectPattern(props) => {
                props.iter().flat_map(|p| p.value.binding_names()).collect()
            }
            Self::ArrayPattern(elements) => elements
                .iter()
                .flatten()
                .flat_map(|e| e.binding_names())
                .collect(),
            Self::Rest(inner) => inner.binding_names(),
            Self::AssignmentPattern { left, .. } => left.binding_names(),
        }
    }

    /// Canonical value for deterministic hashing.
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Identifier(name) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("identifier".to_string()),
                );
                map.insert("name".to_string(), CanonicalValue::String(name.clone()));
            }
            Self::ObjectPattern(props) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("object_pattern".to_string()),
                );
                map.insert(
                    "properties".to_string(),
                    CanonicalValue::Array(props.iter().map(|p| p.canonical_value()).collect()),
                );
            }
            Self::ArrayPattern(elements) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("array_pattern".to_string()),
                );
                map.insert(
                    "elements".to_string(),
                    CanonicalValue::Array(
                        elements
                            .iter()
                            .map(|e| {
                                e.as_ref()
                                    .map(|p| p.canonical_value())
                                    .unwrap_or(CanonicalValue::Null)
                            })
                            .collect(),
                    ),
                );
            }
            Self::Rest(inner) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("rest_element".to_string()),
                );
                map.insert("argument".to_string(), inner.canonical_value());
            }
            Self::AssignmentPattern { left, right } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("assignment_pattern".to_string()),
                );
                map.insert("left".to_string(), left.canonical_value());
                map.insert("right".to_string(), right.canonical_value());
            }
        }
        CanonicalValue::Map(map)
    }
}

impl std::fmt::Display for BindingPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identifier(name) => write!(f, "{name}"),
            Self::ObjectPattern(props) => {
                write!(f, "{{ ")?;
                for (i, prop) in props.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    if prop.shorthand {
                        write!(f, "{}", prop.value)?;
                    } else {
                        write!(f, "{:?}: {}", prop.key, prop.value)?;
                    }
                }
                write!(f, " }}")
            }
            Self::ArrayPattern(elements) => {
                write!(f, "[")?;
                for (i, elem) in elements.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    if let Some(pat) = elem {
                        write!(f, "{pat}")?;
                    }
                }
                write!(f, "]")
            }
            Self::Rest(inner) => write!(f, "...{inner}"),
            Self::AssignmentPattern { left, right } => write!(f, "{left} = {right}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VariableDeclarationKind {
    Var,
    Let,
    Const,
}

impl VariableDeclarationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Var => "var",
            Self::Let => "let",
            Self::Const => "const",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableDeclarator {
    pub pattern: BindingPattern,
    pub initializer: Option<Expression>,
    pub span: SourceSpan,
}

impl VariableDeclarator {
    /// Convenience accessor for simple identifier bindings (backward compat).
    pub fn name(&self) -> Option<&str> {
        self.pattern.as_identifier()
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("pattern".to_string(), self.pattern.canonical_value());
        map.insert(
            "initializer".to_string(),
            self.initializer
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VariableDeclaration {
    pub kind: VariableDeclarationKind,
    pub declarations: Vec<VariableDeclarator>,
    pub span: SourceSpan,
}

impl VariableDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "kind".to_string(),
            CanonicalValue::String(self.kind.as_str().to_string()),
        );
        map.insert(
            "declarations".to_string(),
            CanonicalValue::Array(
                self.declarations
                    .iter()
                    .map(VariableDeclarator::canonical_value)
                    .collect(),
            ),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpressionStatement {
    pub expression: Expression,
    pub span: SourceSpan,
}

impl ExpressionStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("expression".to_string(), self.expression.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Control flow statement AST nodes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockStatement {
    pub body: Vec<Statement>,
    pub span: SourceSpan,
}

impl BlockStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "body".to_string(),
            CanonicalValue::Array(self.body.iter().map(Statement::canonical_value).collect()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfStatement {
    pub condition: Expression,
    pub consequent: Box<Statement>,
    pub alternate: Option<Box<Statement>>,
    pub span: SourceSpan,
}

impl IfStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("condition".to_string(), self.condition.canonical_value());
        map.insert("consequent".to_string(), self.consequent.canonical_value());
        map.insert(
            "alternate".to_string(),
            self.alternate
                .as_ref()
                .map(|s| s.canonical_value())
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForStatement {
    pub init: Option<Box<Statement>>,
    pub condition: Option<Expression>,
    pub update: Option<Expression>,
    pub body: Box<Statement>,
    pub span: SourceSpan,
}

impl ForStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "init".to_string(),
            self.init
                .as_ref()
                .map(|s| s.canonical_value())
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "condition".to_string(),
            self.condition
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "update".to_string(),
            self.update
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForInStatement {
    pub binding: BindingPattern,
    pub binding_kind: Option<VariableDeclarationKind>,
    pub object: Expression,
    pub body: Box<Statement>,
    pub span: SourceSpan,
}

impl ForInStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("binding".to_string(), self.binding.canonical_value());
        map.insert(
            "binding_kind".to_string(),
            self.binding_kind
                .as_ref()
                .map(|k| CanonicalValue::String(format!("{k:?}")))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("object".to_string(), self.object.canonical_value());
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForOfStatement {
    pub binding: BindingPattern,
    pub binding_kind: Option<VariableDeclarationKind>,
    pub iterable: Expression,
    pub body: Box<Statement>,
    pub span: SourceSpan,
}

impl ForOfStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("binding".to_string(), self.binding.canonical_value());
        map.insert(
            "binding_kind".to_string(),
            self.binding_kind
                .as_ref()
                .map(|k| CanonicalValue::String(format!("{k:?}")))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("iterable".to_string(), self.iterable.canonical_value());
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhileStatement {
    pub condition: Expression,
    pub body: Box<Statement>,
    pub span: SourceSpan,
}

impl WhileStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("condition".to_string(), self.condition.canonical_value());
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoWhileStatement {
    pub body: Box<Statement>,
    pub condition: Expression,
    pub span: SourceSpan,
}

impl DoWhileStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("condition".to_string(), self.condition.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReturnStatement {
    pub argument: Option<Expression>,
    pub span: SourceSpan,
}

impl ReturnStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "argument".to_string(),
            self.argument
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThrowStatement {
    pub argument: Expression,
    pub span: SourceSpan,
}

impl ThrowStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("argument".to_string(), self.argument.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatchClause {
    pub parameter: Option<String>,
    pub body: BlockStatement,
    pub span: SourceSpan,
}

impl CatchClause {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "parameter".to_string(),
            self.parameter
                .as_ref()
                .map(|p| CanonicalValue::String(p.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TryCatchStatement {
    pub block: BlockStatement,
    pub handler: Option<CatchClause>,
    pub finalizer: Option<BlockStatement>,
    pub span: SourceSpan,
}

impl TryCatchStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("block".to_string(), self.block.canonical_value());
        map.insert(
            "handler".to_string(),
            self.handler
                .as_ref()
                .map(CatchClause::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "finalizer".to_string(),
            self.finalizer
                .as_ref()
                .map(BlockStatement::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchCase {
    pub test: Option<Expression>,
    pub consequent: Vec<Statement>,
    pub span: SourceSpan,
}

impl SwitchCase {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "test".to_string(),
            self.test
                .as_ref()
                .map(Expression::canonical_value)
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "consequent".to_string(),
            CanonicalValue::Array(
                self.consequent
                    .iter()
                    .map(Statement::canonical_value)
                    .collect(),
            ),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchStatement {
    pub discriminant: Expression,
    pub cases: Vec<SwitchCase>,
    pub span: SourceSpan,
}

impl SwitchStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "discriminant".to_string(),
            self.discriminant.canonical_value(),
        );
        map.insert(
            "cases".to_string(),
            CanonicalValue::Array(self.cases.iter().map(SwitchCase::canonical_value).collect()),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakStatement {
    pub label: Option<String>,
    pub span: SourceSpan,
}

impl BreakStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "label".to_string(),
            self.label
                .as_ref()
                .map(|l| CanonicalValue::String(l.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContinueStatement {
    pub label: Option<String>,
    pub span: SourceSpan,
}

impl ContinueStatement {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "label".to_string(),
            self.label
                .as_ref()
                .map(|l| CanonicalValue::String(l.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionParam {
    pub pattern: BindingPattern,
    pub span: SourceSpan,
}

impl FunctionParam {
    /// Convenience accessor for simple identifier params (backward compat).
    pub fn name(&self) -> Option<&str> {
        self.pattern.as_identifier()
    }

    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("pattern".to_string(), self.pattern.canonical_value());
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionDeclaration {
    pub name: Option<String>,
    pub params: Vec<FunctionParam>,
    pub body: BlockStatement,
    pub is_async: bool,
    pub is_generator: bool,
    pub span: SourceSpan,
}

impl FunctionDeclaration {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "name".to_string(),
            self.name
                .as_ref()
                .map(|n| CanonicalValue::String(n.clone()))
                .unwrap_or(CanonicalValue::Null),
        );
        map.insert(
            "params".to_string(),
            CanonicalValue::Array(
                self.params
                    .iter()
                    .map(FunctionParam::canonical_value)
                    .collect(),
            ),
        );
        map.insert("body".to_string(), self.body.canonical_value());
        map.insert("is_async".to_string(), CanonicalValue::Bool(self.is_async));
        map.insert(
            "is_generator".to_string(),
            CanonicalValue::Bool(self.is_generator),
        );
        map.insert("span".to_string(), self.span.canonical_value());
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Binary operator enumeration
// ---------------------------------------------------------------------------

/// Binary operator kinds for ES2020 expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Remainder,
    Exponentiate,
    Equal,
    NotEqual,
    StrictEqual,
    StrictNotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LogicalAnd,
    LogicalOr,
    NullishCoalescing,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
    UnsignedRightShift,
    Instanceof,
    In,
}

impl BinaryOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Subtract => "-",
            Self::Multiply => "*",
            Self::Divide => "/",
            Self::Remainder => "%",
            Self::Exponentiate => "**",
            Self::Equal => "==",
            Self::NotEqual => "!=",
            Self::StrictEqual => "===",
            Self::StrictNotEqual => "!==",
            Self::LessThan => "<",
            Self::LessThanOrEqual => "<=",
            Self::GreaterThan => ">",
            Self::GreaterThanOrEqual => ">=",
            Self::LogicalAnd => "&&",
            Self::LogicalOr => "||",
            Self::NullishCoalescing => "??",
            Self::BitwiseAnd => "&",
            Self::BitwiseOr => "|",
            Self::BitwiseXor => "^",
            Self::LeftShift => "<<",
            Self::RightShift => ">>",
            Self::UnsignedRightShift => ">>>",
            Self::Instanceof => "instanceof",
            Self::In => "in",
        }
    }

    /// Precedence level for Pratt parsing (higher binds tighter).
    pub fn precedence(self) -> u8 {
        match self {
            Self::NullishCoalescing => 3,
            Self::LogicalOr => 4,
            Self::LogicalAnd => 5,
            Self::BitwiseOr => 6,
            Self::BitwiseXor => 7,
            Self::BitwiseAnd => 8,
            Self::Equal | Self::NotEqual | Self::StrictEqual | Self::StrictNotEqual => 9,
            Self::LessThan
            | Self::LessThanOrEqual
            | Self::GreaterThan
            | Self::GreaterThanOrEqual
            | Self::Instanceof
            | Self::In => 10,
            Self::LeftShift | Self::RightShift | Self::UnsignedRightShift => 11,
            Self::Add | Self::Subtract => 12,
            Self::Multiply | Self::Divide | Self::Remainder => 13,
            Self::Exponentiate => 14,
        }
    }

    /// Whether the operator is right-associative.
    pub fn is_right_associative(self) -> bool {
        matches!(self, Self::Exponentiate)
    }
}

/// Unary operator kinds for ES2020 expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOperator {
    Negate,
    BitwiseNot,
    LogicalNot,
    Typeof,
    Void,
    Delete,
    UnaryPlus,
}

impl UnaryOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Negate => "-",
            Self::BitwiseNot => "~",
            Self::LogicalNot => "!",
            Self::Typeof => "typeof",
            Self::Void => "void",
            Self::Delete => "delete",
            Self::UnaryPlus => "+",
        }
    }
}

/// Assignment operator kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignmentOperator {
    Assign,
    AddAssign,
    SubtractAssign,
    MultiplyAssign,
    DivideAssign,
    RemainderAssign,
    ExponentiateAssign,
    LeftShiftAssign,
    RightShiftAssign,
    UnsignedRightShiftAssign,
    BitwiseAndAssign,
    BitwiseOrAssign,
    BitwiseXorAssign,
    LogicalAndAssign,
    LogicalOrAssign,
    NullishCoalescingAssign,
}

impl AssignmentOperator {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Assign => "=",
            Self::AddAssign => "+=",
            Self::SubtractAssign => "-=",
            Self::MultiplyAssign => "*=",
            Self::DivideAssign => "/=",
            Self::RemainderAssign => "%=",
            Self::ExponentiateAssign => "**=",
            Self::LeftShiftAssign => "<<=",
            Self::RightShiftAssign => ">>=",
            Self::UnsignedRightShiftAssign => ">>>=",
            Self::BitwiseAndAssign => "&=",
            Self::BitwiseOrAssign => "|=",
            Self::BitwiseXorAssign => "^=",
            Self::LogicalAndAssign => "&&=",
            Self::LogicalOrAssign => "||=",
            Self::NullishCoalescingAssign => "??=",
        }
    }
}

/// Property in an object literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectProperty {
    pub key: Expression,
    pub value: Expression,
    pub computed: bool,
    pub shorthand: bool,
}

impl ObjectProperty {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("key".to_string(), self.key.canonical_value());
        map.insert("value".to_string(), self.value.canonical_value());
        map.insert("computed".to_string(), CanonicalValue::Bool(self.computed));
        map.insert(
            "shorthand".to_string(),
            CanonicalValue::Bool(self.shorthand),
        );
        CanonicalValue::Map(map)
    }
}

/// Arrow function body — either an expression or a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArrowBody {
    Expression(Box<Expression>),
    Block(BlockStatement),
}

impl ArrowBody {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Expression(expr) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("expression".to_string()),
                );
                map.insert("value".to_string(), expr.canonical_value());
            }
            Self::Block(block) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("block".to_string()),
                );
                map.insert("value".to_string(), block.canonical_value());
            }
        }
        CanonicalValue::Map(map)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expression {
    Identifier(String),
    StringLiteral(String),
    NumericLiteral(i64),
    BooleanLiteral(bool),
    NullLiteral,
    UndefinedLiteral,
    Await(Box<Expression>),
    Binary {
        operator: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Unary {
        operator: UnaryOperator,
        argument: Box<Expression>,
    },
    Assignment {
        operator: AssignmentOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Conditional {
        test: Box<Expression>,
        consequent: Box<Expression>,
        alternate: Box<Expression>,
    },
    Call {
        callee: Box<Expression>,
        arguments: Vec<Expression>,
    },
    Member {
        object: Box<Expression>,
        property: Box<Expression>,
        computed: bool,
    },
    OptionalCall {
        callee: Box<Expression>,
        arguments: Vec<Expression>,
    },
    OptionalMember {
        object: Box<Expression>,
        property: Box<Expression>,
        computed: bool,
    },
    This,
    ArrayLiteral(Vec<Option<Expression>>),
    ObjectLiteral(Vec<ObjectProperty>),
    ArrowFunction {
        params: Vec<FunctionParam>,
        body: ArrowBody,
        is_async: bool,
    },
    New {
        callee: Box<Expression>,
        arguments: Vec<Expression>,
    },
    TemplateLiteral {
        quasis: Vec<String>,
        expressions: Vec<Expression>,
    },
    Raw(String),
}

impl Expression {
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        match self {
            Self::Identifier(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("identifier".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(value.clone()));
            }
            Self::StringLiteral(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("string".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(value.clone()));
            }
            Self::NumericLiteral(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("numeric".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::I64(*value));
            }
            Self::BooleanLiteral(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("boolean".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Bool(*value));
            }
            Self::NullLiteral => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("null".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Null);
            }
            Self::UndefinedLiteral => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("undefined".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Null);
            }
            Self::Await(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("await".to_string()),
                );
                map.insert("value".to_string(), value.canonical_value());
            }
            Self::Binary {
                operator,
                left,
                right,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("binary".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
                map.insert("left".to_string(), left.canonical_value());
                map.insert("right".to_string(), right.canonical_value());
            }
            Self::Unary { operator, argument } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("unary".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
                map.insert("argument".to_string(), argument.canonical_value());
            }
            Self::Assignment {
                operator,
                left,
                right,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("assignment".to_string()),
                );
                map.insert(
                    "operator".to_string(),
                    CanonicalValue::String(operator.as_str().to_string()),
                );
                map.insert("left".to_string(), left.canonical_value());
                map.insert("right".to_string(), right.canonical_value());
            }
            Self::Conditional {
                test,
                consequent,
                alternate,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("conditional".to_string()),
                );
                map.insert("test".to_string(), test.canonical_value());
                map.insert("consequent".to_string(), consequent.canonical_value());
                map.insert("alternate".to_string(), alternate.canonical_value());
            }
            Self::Call { callee, arguments } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("call".to_string()),
                );
                map.insert("callee".to_string(), callee.canonical_value());
                map.insert(
                    "arguments".to_string(),
                    CanonicalValue::Array(
                        arguments.iter().map(Expression::canonical_value).collect(),
                    ),
                );
            }
            Self::Member {
                object,
                property,
                computed,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("member".to_string()),
                );
                map.insert("object".to_string(), object.canonical_value());
                map.insert("property".to_string(), property.canonical_value());
                map.insert("computed".to_string(), CanonicalValue::Bool(*computed));
            }
            Self::OptionalCall { callee, arguments } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("optional_call".to_string()),
                );
                map.insert("callee".to_string(), callee.canonical_value());
                map.insert(
                    "arguments".to_string(),
                    CanonicalValue::Array(
                        arguments.iter().map(Expression::canonical_value).collect(),
                    ),
                );
            }
            Self::OptionalMember {
                object,
                property,
                computed,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("optional_member".to_string()),
                );
                map.insert("object".to_string(), object.canonical_value());
                map.insert("property".to_string(), property.canonical_value());
                map.insert("computed".to_string(), CanonicalValue::Bool(*computed));
            }
            Self::This => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("this".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::Null);
            }
            Self::ArrayLiteral(elements) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("array".to_string()),
                );
                map.insert(
                    "elements".to_string(),
                    CanonicalValue::Array(
                        elements
                            .iter()
                            .map(|e| {
                                e.as_ref()
                                    .map(Expression::canonical_value)
                                    .unwrap_or(CanonicalValue::Null)
                            })
                            .collect(),
                    ),
                );
            }
            Self::ObjectLiteral(properties) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("object".to_string()),
                );
                map.insert(
                    "properties".to_string(),
                    CanonicalValue::Array(
                        properties
                            .iter()
                            .map(ObjectProperty::canonical_value)
                            .collect(),
                    ),
                );
            }
            Self::ArrowFunction {
                params,
                body,
                is_async,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("arrow_function".to_string()),
                );
                map.insert(
                    "params".to_string(),
                    CanonicalValue::Array(
                        params.iter().map(FunctionParam::canonical_value).collect(),
                    ),
                );
                map.insert("body".to_string(), body.canonical_value());
                map.insert("is_async".to_string(), CanonicalValue::Bool(*is_async));
            }
            Self::New { callee, arguments } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("new".to_string()),
                );
                map.insert("callee".to_string(), callee.canonical_value());
                map.insert(
                    "arguments".to_string(),
                    CanonicalValue::Array(
                        arguments.iter().map(Expression::canonical_value).collect(),
                    ),
                );
            }
            Self::TemplateLiteral {
                quasis,
                expressions,
            } => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("template_literal".to_string()),
                );
                map.insert(
                    "quasis".to_string(),
                    CanonicalValue::Array(
                        quasis
                            .iter()
                            .map(|q| CanonicalValue::String(q.clone()))
                            .collect(),
                    ),
                );
                map.insert(
                    "expressions".to_string(),
                    CanonicalValue::Array(
                        expressions
                            .iter()
                            .map(Expression::canonical_value)
                            .collect(),
                    ),
                );
            }
            Self::Raw(value) => {
                map.insert(
                    "kind".to_string(),
                    CanonicalValue::String("raw".to_string()),
                );
                map.insert("value".to_string(), CanonicalValue::String(value.clone()));
            }
        }
        CanonicalValue::Map(map)
    }
}

impl std::fmt::Display for Expression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Identifier(value) => write!(f, "{value}"),
            Self::StringLiteral(value) => write!(f, "\"{value}\""),
            Self::NumericLiteral(value) => write!(f, "{value}"),
            Self::BooleanLiteral(value) => write!(f, "{value}"),
            Self::NullLiteral => write!(f, "null"),
            Self::UndefinedLiteral => write!(f, "undefined"),
            Self::This => write!(f, "this"),
            Self::Raw(value) => write!(f, "{value}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // ParseGoal
    // -----------------------------------------------------------------------

    #[test]
    fn parse_goal_as_str_returns_stable_labels() {
        assert_eq!(ParseGoal::Script.as_str(), "script");
        assert_eq!(ParseGoal::Module.as_str(), "module");
    }

    #[test]
    fn parse_goal_equality_is_reflexive() {
        assert_eq!(ParseGoal::Script, ParseGoal::Script);
        assert_eq!(ParseGoal::Module, ParseGoal::Module);
        assert_ne!(ParseGoal::Script, ParseGoal::Module);
    }

    #[test]
    fn parse_goal_round_trips_through_serde() {
        for goal in [ParseGoal::Script, ParseGoal::Module] {
            let json = serde_json::to_string(&goal).expect("serialize");
            let decoded: ParseGoal = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, goal);
        }
    }

    #[test]
    fn expression_display_renders_primitive_literals_and_identifiers() {
        assert_eq!(
            Expression::Identifier("answer".to_string()).to_string(),
            "answer"
        );
        assert_eq!(
            Expression::StringLiteral("hello".to_string()).to_string(),
            "\"hello\""
        );
        assert_eq!(Expression::NumericLiteral(42).to_string(), "42");
        assert_eq!(Expression::BooleanLiteral(true).to_string(), "true");
        assert_eq!(Expression::NullLiteral.to_string(), "null");
        assert_eq!(Expression::UndefinedLiteral.to_string(), "undefined");
        assert_eq!(Expression::This.to_string(), "this");
        assert_eq!(Expression::Raw("x + y".to_string()).to_string(), "x + y");
    }

    #[test]
    fn binding_pattern_display_supports_expression_defaults() {
        let pattern = BindingPattern::AssignmentPattern {
            left: Box::new(BindingPattern::Identifier("value".to_string())),
            right: Expression::Identifier("fallback".to_string()),
        };
        assert_eq!(pattern.to_string(), "value = fallback");
    }

    // -----------------------------------------------------------------------
    // SourceSpan
    // -----------------------------------------------------------------------

    #[test]
    fn source_span_new_stores_all_fields() {
        let span = SourceSpan::new(10, 50, 2, 3, 5, 20);
        assert_eq!(span.start_offset, 10);
        assert_eq!(span.end_offset, 50);
        assert_eq!(span.start_line, 2);
        assert_eq!(span.start_column, 3);
        assert_eq!(span.end_line, 5);
        assert_eq!(span.end_column, 20);
    }

    #[test]
    fn source_span_canonical_value_contains_all_keys() {
        let span = SourceSpan::new(0, 100, 1, 1, 10, 5);
        let cv = span.canonical_value();
        match &cv {
            CanonicalValue::Map(map) => {
                assert!(map.contains_key("start_offset"));
                assert!(map.contains_key("end_offset"));
                assert!(map.contains_key("start_line"));
                assert!(map.contains_key("start_column"));
                assert!(map.contains_key("end_line"));
                assert!(map.contains_key("end_column"));
                assert_eq!(map.len(), 6);
            }
            _ => panic!("canonical_value must be a Map"),
        }
    }

    #[test]
    fn source_span_canonical_value_is_deterministic() {
        let span = SourceSpan::new(5, 42, 1, 6, 1, 43);
        let cv1 = span.canonical_value();
        let cv2 = span.canonical_value();
        assert_eq!(cv1, cv2);
    }

    #[test]
    fn source_span_equality_compares_all_fields() {
        let a = SourceSpan::new(0, 10, 1, 1, 1, 11);
        let b = SourceSpan::new(0, 10, 1, 1, 1, 11);
        let c = SourceSpan::new(0, 10, 1, 1, 1, 12);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn source_span_round_trips_through_serde() {
        let span = SourceSpan::new(7, 99, 3, 8, 10, 1);
        let json = serde_json::to_string(&span).expect("serialize");
        let decoded: SourceSpan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, span);
    }

    // -----------------------------------------------------------------------
    // SyntaxTree
    // -----------------------------------------------------------------------

    fn make_span() -> SourceSpan {
        SourceSpan::new(0, 10, 1, 1, 1, 11)
    }

    fn make_expr_stmt(expr: Expression) -> Statement {
        Statement::Expression(ExpressionStatement {
            expression: expr,
            span: make_span(),
        })
    }

    fn make_var_stmt(name: &str, initializer: Option<Expression>) -> Statement {
        Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier(name.to_string()),
                initializer,
                span: make_span(),
            }],
            span: make_span(),
        })
    }

    #[test]
    fn syntax_tree_empty_body_is_valid() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: make_span(),
        };
        assert_eq!(tree.body.len(), 0);
        assert_eq!(tree.goal, ParseGoal::Script);
    }

    #[test]
    fn syntax_tree_canonical_bytes_are_deterministic() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![make_expr_stmt(Expression::NumericLiteral(42))],
            span: make_span(),
        };
        let bytes1 = tree.canonical_bytes();
        let bytes2 = tree.canonical_bytes();
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn syntax_tree_canonical_hash_has_sha256_prefix() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: make_span(),
        };
        let hash = tree.canonical_hash();
        assert!(
            hash.starts_with(SyntaxTree::canonical_hash_prefix()),
            "hash must start with sha256: prefix"
        );
        assert_eq!(hash.len(), 7 + 64, "sha256 hex digest is 64 chars");
    }

    #[test]
    fn canonical_ast_contract_constants_are_stable() {
        assert_eq!(
            CANONICAL_AST_CONTRACT_VERSION,
            "franken-engine.parser-ast.contract.v1"
        );
        assert_eq!(
            CANONICAL_AST_SCHEMA_VERSION,
            "franken-engine.parser-ast.schema.v1"
        );
        assert_eq!(CANONICAL_AST_HASH_ALGORITHM, "sha256");
        assert_eq!(CANONICAL_AST_HASH_PREFIX, "sha256:");
    }

    #[test]
    fn syntax_tree_contract_metadata_accessors_match_constants() {
        assert_eq!(
            SyntaxTree::canonical_contract_version(),
            CANONICAL_AST_CONTRACT_VERSION
        );
        assert_eq!(
            SyntaxTree::canonical_schema_version(),
            CANONICAL_AST_SCHEMA_VERSION
        );
        assert_eq!(
            SyntaxTree::canonical_hash_algorithm(),
            CANONICAL_AST_HASH_ALGORITHM
        );
        assert_eq!(
            SyntaxTree::canonical_hash_prefix(),
            CANONICAL_AST_HASH_PREFIX
        );
    }

    #[test]
    fn syntax_tree_different_goals_produce_different_hashes() {
        let span = make_span();
        let script = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: span.clone(),
        };
        let module = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![],
            span,
        };
        assert_ne!(script.canonical_hash(), module.canonical_hash());
    }

    #[test]
    fn syntax_tree_canonical_value_contains_goal_body_span() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::Identifier("x".to_string()))],
            span: make_span(),
        };
        let cv = tree.canonical_value();
        match &cv {
            CanonicalValue::Map(map) => {
                assert!(map.contains_key("goal"));
                assert!(map.contains_key("body"));
                assert!(map.contains_key("span"));
            }
            _ => panic!("canonical_value must be a Map"),
        }
    }

    #[test]
    fn syntax_tree_round_trips_through_serde() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    binding: Some("x".to_string()),
                    source: "mod".to_string(),
                    span: make_span(),
                }),
                make_expr_stmt(Expression::NumericLiteral(1)),
            ],
            span: make_span(),
        };
        let json = serde_json::to_string(&tree).expect("serialize");
        let decoded: SyntaxTree = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, tree);
    }

    // -----------------------------------------------------------------------
    // Statement
    // -----------------------------------------------------------------------

    #[test]
    fn statement_span_returns_correct_span_for_each_variant() {
        let span = SourceSpan::new(5, 15, 2, 6, 2, 16);

        let import = Statement::Import(ImportDeclaration {
            binding: None,
            source: "x".to_string(),
            span: span.clone(),
        });
        assert_eq!(import.span(), &span);

        let export = Statement::Export(ExportDeclaration {
            kind: ExportKind::NamedClause("foo".to_string()),
            span: span.clone(),
        });
        assert_eq!(export.span(), &span);

        let expr = Statement::Expression(ExpressionStatement {
            expression: Expression::NumericLiteral(0),
            span: span.clone(),
        });
        assert_eq!(expr.span(), &span);

        let var_decl = Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Var,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("value".to_string()),
                initializer: Some(Expression::NumericLiteral(1)),
                span: span.clone(),
            }],
            span: span.clone(),
        });
        assert_eq!(var_decl.span(), &span);
    }

    #[test]
    fn statement_canonical_value_import_has_kind_import() {
        let stmt = Statement::Import(ImportDeclaration {
            binding: Some("dep".to_string()),
            source: "pkg".to_string(),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("import".to_string()))
                );
                assert!(map.contains_key("payload"));
                assert!(map.contains_key("span"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn variable_declaration_kind_as_str_is_stable() {
        assert_eq!(VariableDeclarationKind::Var.as_str(), "var");
        assert_eq!(VariableDeclarationKind::Let.as_str(), "let");
        assert_eq!(VariableDeclarationKind::Const.as_str(), "const");
    }

    #[test]
    fn statement_canonical_value_export_has_kind_export() {
        let stmt = Statement::Export(ExportDeclaration {
            kind: ExportKind::Default(Expression::Identifier("x".to_string())),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("export".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_canonical_value_expression_has_kind_expression() {
        let stmt = make_expr_stmt(Expression::Raw("a + b".to_string()));
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("expression".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_canonical_value_variable_has_kind_variable_declaration() {
        let stmt = make_var_stmt("counter", Some(Expression::NumericLiteral(0)));
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("variable_declaration".to_string()))
                );
                assert!(map.contains_key("payload"));
                assert!(map.contains_key("span"));
            }
            _ => panic!("expected map"),
        }
    }

    // -----------------------------------------------------------------------
    // ImportDeclaration
    // -----------------------------------------------------------------------

    #[test]
    fn import_declaration_with_binding_canonical_value() {
        let import = ImportDeclaration {
            binding: Some("foo".to_string()),
            source: "bar".to_string(),
            span: make_span(),
        };
        match import.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("binding"),
                    Some(&CanonicalValue::String("foo".to_string()))
                );
                assert_eq!(
                    map.get("source"),
                    Some(&CanonicalValue::String("bar".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn import_declaration_without_binding_canonical_value_has_null() {
        let import = ImportDeclaration {
            binding: None,
            source: "side-effect".to_string(),
            span: make_span(),
        };
        match import.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("binding"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    // -----------------------------------------------------------------------
    // ExportKind / ExportDeclaration
    // -----------------------------------------------------------------------

    #[test]
    fn export_kind_default_canonical_value() {
        let kind = ExportKind::Default(Expression::Identifier("main".to_string()));
        match kind.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("default".to_string()))
                );
                assert!(map.contains_key("value"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn export_kind_named_clause_canonical_value() {
        let kind = ExportKind::NamedClause("{ a, b }".to_string());
        match kind.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("named".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("{ a, b }".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    // -----------------------------------------------------------------------
    // Expression
    // -----------------------------------------------------------------------

    #[test]
    fn expression_identifier_canonical_value() {
        let expr = Expression::Identifier("myVar".to_string());
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("identifier".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("myVar".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_string_literal_canonical_value() {
        let expr = Expression::StringLiteral("hello".to_string());
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("string".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("hello".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_literal_canonical_value() {
        let expr = Expression::NumericLiteral(42);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("numeric".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(42)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_literal_handles_negative() {
        let expr = Expression::NumericLiteral(-100);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(-100)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_literal_handles_zero() {
        let expr = Expression::NumericLiteral(0);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(0)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_boolean_literal_canonical_value() {
        let expr = Expression::BooleanLiteral(true);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("boolean".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::Bool(true)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_null_literal_canonical_value() {
        let expr = Expression::NullLiteral;
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("null".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_undefined_literal_canonical_value() {
        let expr = Expression::UndefinedLiteral;
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("undefined".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_await_wraps_nested_expression() {
        let inner = Expression::Identifier("work".to_string());
        let expr = Expression::Await(Box::new(inner.clone()));
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("await".to_string()))
                );
                assert_eq!(map.get("value"), Some(&inner.canonical_value()));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_await_can_nest_deeply() {
        let inner = Expression::NumericLiteral(1);
        let mid = Expression::Await(Box::new(inner));
        let outer = Expression::Await(Box::new(mid));
        match outer.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("await".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_raw_canonical_value() {
        let expr = Expression::Raw("x + y * z".to_string());
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("raw".to_string()))
                );
                assert_eq!(
                    map.get("value"),
                    Some(&CanonicalValue::String("x + y * z".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_variants_round_trip_through_serde() {
        let expressions = vec![
            Expression::Identifier("x".to_string()),
            Expression::StringLiteral("hello".to_string()),
            Expression::NumericLiteral(42),
            Expression::BooleanLiteral(true),
            Expression::NullLiteral,
            Expression::UndefinedLiteral,
            Expression::Await(Box::new(Expression::Identifier("work".to_string()))),
            Expression::Raw("a + b".to_string()),
        ];
        for expr in expressions {
            let json = serde_json::to_string(&expr).expect("serialize");
            let decoded: Expression = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, expr);
        }
    }

    #[test]
    fn expression_equality_distinguishes_variants() {
        let id = Expression::Identifier("x".to_string());
        let string = Expression::StringLiteral("x".to_string());
        let raw = Expression::Raw("x".to_string());
        assert_ne!(id, string);
        assert_ne!(id, raw);
        assert_ne!(string, raw);
    }

    // -----------------------------------------------------------------------
    // Full AST determinism
    // -----------------------------------------------------------------------

    #[test]
    fn full_ast_canonical_bytes_are_stable_across_constructions() {
        let build_tree = || SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    binding: Some("dep".to_string()),
                    source: "pkg".to_string(),
                    span: SourceSpan::new(0, 18, 1, 1, 1, 19),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(Expression::Identifier("dep".to_string())),
                    span: SourceSpan::new(19, 37, 2, 1, 2, 19),
                }),
            ],
            span: SourceSpan::new(0, 37, 1, 1, 2, 19),
        };

        let tree1 = build_tree();
        let tree2 = build_tree();
        assert_eq!(tree1.canonical_bytes(), tree2.canonical_bytes());
        assert_eq!(tree1.canonical_hash(), tree2.canonical_hash());
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2: Display, edge cases, hash uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn parse_goal_clone_eq() {
        let a = ParseGoal::Script;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn expression_boolean_false_canonical_value() {
        let expr = Expression::BooleanLiteral(false);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::Bool(false)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn syntax_tree_different_bodies_produce_different_hashes() {
        let span = make_span();
        let t1 = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::NumericLiteral(1))],
            span: span.clone(),
        };
        let t2 = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::NumericLiteral(2))],
            span,
        };
        assert_ne!(t1.canonical_hash(), t2.canonical_hash());
    }

    #[test]
    fn syntax_tree_empty_vs_nonempty_body_different_hashes() {
        let span = make_span();
        let empty = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![],
            span: span.clone(),
        };
        let nonempty = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![make_expr_stmt(Expression::NullLiteral)],
            span,
        };
        assert_ne!(empty.canonical_hash(), nonempty.canonical_hash());
    }

    #[test]
    fn import_without_binding_serde_roundtrip() {
        let stmt = Statement::Import(ImportDeclaration {
            binding: None,
            source: "side-effect-module".to_string(),
            span: make_span(),
        });
        let json = serde_json::to_string(&stmt).expect("serialize");
        let restored: Statement = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stmt, restored);
    }

    #[test]
    fn export_kind_named_vs_default_different_canonical_value() {
        let default = ExportKind::Default(Expression::Identifier("x".to_string()));
        let named = ExportKind::NamedClause("x".to_string());
        assert_ne!(default.canonical_value(), named.canonical_value());
    }

    #[test]
    fn expression_numeric_i64_max() {
        let expr = Expression::NumericLiteral(i64::MAX);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(i64::MAX)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_numeric_i64_min() {
        let expr = Expression::NumericLiteral(i64::MIN);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("value"), Some(&CanonicalValue::I64(i64::MIN)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn source_span_zero_length_is_valid() {
        let span = SourceSpan::new(5, 5, 1, 6, 1, 6);
        assert_eq!(span.start_offset, span.end_offset);
        let cv = span.canonical_value();
        match &cv {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("start_offset"), map.get("end_offset"),);
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_await_serde_roundtrip_deep() {
        let expr = Expression::Await(Box::new(Expression::Await(Box::new(
            Expression::StringLiteral("deep".to_string()),
        ))));
        let json = serde_json::to_string(&expr).expect("serialize");
        let restored: Expression = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(expr, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 3: clone equality, JSON fields, roundtrip, boundary
    // -----------------------------------------------------------------------

    #[test]
    fn source_span_clone_equality() {
        let original = SourceSpan::new(10, 200, 3, 5, 12, 80);
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn import_declaration_clone_equality() {
        let original = ImportDeclaration {
            binding: Some("myDep".to_string()),
            source: "some-package".to_string(),
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn export_declaration_clone_equality() {
        let original = ExportDeclaration {
            kind: ExportKind::Default(Expression::NumericLiteral(99)),
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn expression_statement_clone_equality() {
        let original = ExpressionStatement {
            expression: Expression::Await(Box::new(Expression::Identifier("f".to_string()))),
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn syntax_tree_clone_equality() {
        let original = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    binding: None,
                    source: "effects".to_string(),
                    span: make_span(),
                }),
                make_expr_stmt(Expression::BooleanLiteral(true)),
            ],
            span: make_span(),
        };
        let cloned = original.clone();
        assert_eq!(original, cloned);
        assert_eq!(original.canonical_hash(), cloned.canonical_hash());
    }

    #[test]
    fn source_span_json_field_presence() {
        let span = SourceSpan::new(1, 2, 3, 4, 5, 6);
        let json = serde_json::to_string(&span).expect("serialize");
        assert!(json.contains("\"start_offset\""));
        assert!(json.contains("\"end_offset\""));
        assert!(json.contains("\"start_line\""));
        assert!(json.contains("\"start_column\""));
        assert!(json.contains("\"end_line\""));
        assert!(json.contains("\"end_column\""));
    }

    #[test]
    fn import_declaration_json_field_presence() {
        let import = ImportDeclaration {
            binding: Some("x".to_string()),
            source: "mod".to_string(),
            span: make_span(),
        };
        let json = serde_json::to_string(&import).expect("serialize");
        assert!(json.contains("\"binding\""));
        assert!(json.contains("\"source\""));
        assert!(json.contains("\"span\""));
    }

    #[test]
    fn export_declaration_json_field_presence() {
        let export = ExportDeclaration {
            kind: ExportKind::NamedClause("foo".to_string()),
            span: make_span(),
        };
        let json = serde_json::to_string(&export).expect("serialize");
        assert!(json.contains("\"kind\""));
        assert!(json.contains("\"span\""));
    }

    #[test]
    fn export_declaration_serde_roundtrip() {
        let export = ExportDeclaration {
            kind: ExportKind::Default(Expression::StringLiteral("value".to_string())),
            span: SourceSpan::new(0, 25, 1, 1, 1, 26),
        };
        let json = serde_json::to_string(&export).expect("serialize");
        let restored: ExportDeclaration = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(export, restored);
    }

    #[test]
    fn all_expression_canonical_kinds_are_unique() {
        let expressions = vec![
            Expression::Identifier("a".to_string()),
            Expression::StringLiteral("a".to_string()),
            Expression::NumericLiteral(0),
            Expression::BooleanLiteral(true),
            Expression::NullLiteral,
            Expression::UndefinedLiteral,
            Expression::Await(Box::new(Expression::NullLiteral)),
            Expression::Raw("a".to_string()),
        ];
        let mut kinds = std::collections::BTreeSet::new();
        for expr in &expressions {
            match expr.canonical_value() {
                CanonicalValue::Map(map) => {
                    if let Some(CanonicalValue::String(k)) = map.get("kind") {
                        assert!(kinds.insert(k.clone()), "duplicate canonical kind: {k}");
                    } else {
                        panic!("missing kind key");
                    }
                }
                _ => panic!("expected map"),
            }
        }
        assert_eq!(kinds.len(), 8);
    }

    #[test]
    fn source_span_max_offsets_boundary() {
        let span = SourceSpan::new(u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX);
        let json = serde_json::to_string(&span).expect("serialize");
        let restored: SourceSpan = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(span, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: operators, complex expressions, control-flow stmts
    // -----------------------------------------------------------------------

    #[test]
    fn unary_operator_as_str_all_variants() {
        let cases = [
            (UnaryOperator::Negate, "-"),
            (UnaryOperator::BitwiseNot, "~"),
            (UnaryOperator::LogicalNot, "!"),
            (UnaryOperator::Typeof, "typeof"),
            (UnaryOperator::Void, "void"),
            (UnaryOperator::Delete, "delete"),
            (UnaryOperator::UnaryPlus, "+"),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (op, expected) in &cases {
            assert_eq!(op.as_str(), *expected);
            assert!(seen.insert(op.as_str()), "duplicate: {expected}");
        }
        assert_eq!(seen.len(), 7);
    }

    #[test]
    fn unary_operator_serde_roundtrip_all() {
        let ops = [
            UnaryOperator::Negate,
            UnaryOperator::BitwiseNot,
            UnaryOperator::LogicalNot,
            UnaryOperator::Typeof,
            UnaryOperator::Void,
            UnaryOperator::Delete,
            UnaryOperator::UnaryPlus,
        ];
        for op in ops {
            let json = serde_json::to_string(&op).expect("serialize");
            let restored: UnaryOperator = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, op);
        }
    }

    #[test]
    fn assignment_operator_as_str_all_variants() {
        let cases = [
            (AssignmentOperator::Assign, "="),
            (AssignmentOperator::AddAssign, "+="),
            (AssignmentOperator::SubtractAssign, "-="),
            (AssignmentOperator::MultiplyAssign, "*="),
            (AssignmentOperator::DivideAssign, "/="),
            (AssignmentOperator::RemainderAssign, "%="),
            (AssignmentOperator::ExponentiateAssign, "**="),
            (AssignmentOperator::LeftShiftAssign, "<<="),
            (AssignmentOperator::RightShiftAssign, ">>="),
            (AssignmentOperator::UnsignedRightShiftAssign, ">>>="),
            (AssignmentOperator::BitwiseAndAssign, "&="),
            (AssignmentOperator::BitwiseOrAssign, "|="),
            (AssignmentOperator::BitwiseXorAssign, "^="),
            (AssignmentOperator::LogicalAndAssign, "&&="),
            (AssignmentOperator::LogicalOrAssign, "||="),
            (AssignmentOperator::NullishCoalescingAssign, "??="),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (op, expected) in &cases {
            assert_eq!(op.as_str(), *expected);
            assert!(seen.insert(op.as_str()), "duplicate: {expected}");
        }
        assert_eq!(seen.len(), 16);
    }

    #[test]
    fn assignment_operator_serde_roundtrip_all() {
        let ops = [
            AssignmentOperator::Assign,
            AssignmentOperator::AddAssign,
            AssignmentOperator::SubtractAssign,
            AssignmentOperator::MultiplyAssign,
            AssignmentOperator::DivideAssign,
            AssignmentOperator::RemainderAssign,
            AssignmentOperator::ExponentiateAssign,
            AssignmentOperator::LeftShiftAssign,
            AssignmentOperator::RightShiftAssign,
            AssignmentOperator::UnsignedRightShiftAssign,
            AssignmentOperator::BitwiseAndAssign,
            AssignmentOperator::BitwiseOrAssign,
            AssignmentOperator::BitwiseXorAssign,
            AssignmentOperator::LogicalAndAssign,
            AssignmentOperator::LogicalOrAssign,
            AssignmentOperator::NullishCoalescingAssign,
        ];
        for op in ops {
            let json = serde_json::to_string(&op).expect("serialize");
            let restored: AssignmentOperator = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, op);
        }
    }

    #[test]
    fn binary_operator_as_str_all_unique() {
        let ops = [
            BinaryOperator::Add,
            BinaryOperator::Subtract,
            BinaryOperator::Multiply,
            BinaryOperator::Divide,
            BinaryOperator::Remainder,
            BinaryOperator::Exponentiate,
            BinaryOperator::Equal,
            BinaryOperator::NotEqual,
            BinaryOperator::StrictEqual,
            BinaryOperator::StrictNotEqual,
            BinaryOperator::LessThan,
            BinaryOperator::LessThanOrEqual,
            BinaryOperator::GreaterThan,
            BinaryOperator::GreaterThanOrEqual,
            BinaryOperator::LogicalAnd,
            BinaryOperator::LogicalOr,
            BinaryOperator::NullishCoalescing,
            BinaryOperator::BitwiseAnd,
            BinaryOperator::BitwiseOr,
            BinaryOperator::BitwiseXor,
            BinaryOperator::LeftShift,
            BinaryOperator::RightShift,
            BinaryOperator::UnsignedRightShift,
            BinaryOperator::Instanceof,
            BinaryOperator::In,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for op in &ops {
            assert!(seen.insert(op.as_str()), "duplicate: {}", op.as_str());
        }
        assert_eq!(seen.len(), 25);
    }

    #[test]
    fn binary_operator_precedence_ordering() {
        assert!(BinaryOperator::Exponentiate.precedence() > BinaryOperator::Multiply.precedence());
        assert!(BinaryOperator::Multiply.precedence() > BinaryOperator::Add.precedence());
        assert!(BinaryOperator::Add.precedence() > BinaryOperator::LeftShift.precedence());
        assert!(BinaryOperator::LeftShift.precedence() > BinaryOperator::LessThan.precedence());
        assert!(BinaryOperator::LessThan.precedence() > BinaryOperator::Equal.precedence());
        assert!(BinaryOperator::Equal.precedence() > BinaryOperator::BitwiseAnd.precedence());
        assert!(BinaryOperator::BitwiseAnd.precedence() > BinaryOperator::BitwiseXor.precedence());
        assert!(BinaryOperator::BitwiseXor.precedence() > BinaryOperator::BitwiseOr.precedence());
        assert!(BinaryOperator::BitwiseOr.precedence() > BinaryOperator::LogicalAnd.precedence());
        assert!(BinaryOperator::LogicalAnd.precedence() > BinaryOperator::LogicalOr.precedence());
        assert!(
            BinaryOperator::LogicalOr.precedence() > BinaryOperator::NullishCoalescing.precedence()
        );
    }

    #[test]
    fn binary_operator_only_exponentiate_is_right_associative() {
        let ops = [
            BinaryOperator::Add,
            BinaryOperator::Subtract,
            BinaryOperator::Multiply,
            BinaryOperator::Divide,
            BinaryOperator::Equal,
            BinaryOperator::LogicalAnd,
            BinaryOperator::BitwiseOr,
        ];
        for op in ops {
            assert!(!op.is_right_associative(), "{:?} should be left-assoc", op);
        }
        assert!(BinaryOperator::Exponentiate.is_right_associative());
    }

    #[test]
    fn expression_binary_canonical_value() {
        let expr = Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(Expression::NumericLiteral(1)),
            right: Box::new(Expression::NumericLiteral(2)),
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("binary".to_string()))
                );
                assert_eq!(
                    map.get("operator"),
                    Some(&CanonicalValue::String("+".to_string()))
                );
                assert!(map.contains_key("left"));
                assert!(map.contains_key("right"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_unary_canonical_value() {
        let expr = Expression::Unary {
            operator: UnaryOperator::Typeof,
            argument: Box::new(Expression::Identifier("x".to_string())),
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("unary".to_string()))
                );
                assert_eq!(
                    map.get("operator"),
                    Some(&CanonicalValue::String("typeof".to_string()))
                );
                assert!(map.contains_key("argument"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_assignment_canonical_value() {
        let expr = Expression::Assignment {
            operator: AssignmentOperator::AddAssign,
            left: Box::new(Expression::Identifier("x".to_string())),
            right: Box::new(Expression::NumericLiteral(5)),
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("assignment".to_string()))
                );
                assert_eq!(
                    map.get("operator"),
                    Some(&CanonicalValue::String("+=".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_conditional_canonical_value() {
        let expr = Expression::Conditional {
            test: Box::new(Expression::BooleanLiteral(true)),
            consequent: Box::new(Expression::NumericLiteral(1)),
            alternate: Box::new(Expression::NumericLiteral(0)),
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("conditional".to_string()))
                );
                assert!(map.contains_key("test"));
                assert!(map.contains_key("consequent"));
                assert!(map.contains_key("alternate"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_call_canonical_value() {
        let expr = Expression::Call {
            callee: Box::new(Expression::Identifier("fn".to_string())),
            arguments: vec![
                Expression::NumericLiteral(1),
                Expression::StringLiteral("a".to_string()),
            ],
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("call".to_string()))
                );
                if let Some(CanonicalValue::Array(args)) = map.get("arguments") {
                    assert_eq!(args.len(), 2);
                } else {
                    panic!("arguments should be array");
                }
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_member_canonical_value() {
        let expr = Expression::Member {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("member".to_string()))
                );
                assert_eq!(map.get("computed"), Some(&CanonicalValue::Bool(false)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_member_computed_canonical_value() {
        let expr = Expression::Member {
            object: Box::new(Expression::Identifier("arr".to_string())),
            property: Box::new(Expression::NumericLiteral(0)),
            computed: true,
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("computed"), Some(&CanonicalValue::Bool(true)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_optional_call_canonical_value() {
        let expr = Expression::OptionalCall {
            callee: Box::new(Expression::Identifier("maybe_fn".to_string())),
            arguments: vec![Expression::NumericLiteral(1)],
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("optional_call".to_string()))
                );
                if let Some(CanonicalValue::Array(args)) = map.get("arguments") {
                    assert_eq!(args.len(), 1);
                } else {
                    panic!("arguments should be array");
                }
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_optional_member_canonical_value() {
        let expr = Expression::OptionalMember {
            object: Box::new(Expression::Identifier("config".to_string())),
            property: Box::new(Expression::Identifier("theme".to_string())),
            computed: false,
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("optional_member".to_string()))
                );
                assert_eq!(map.get("computed"), Some(&CanonicalValue::Bool(false)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_this_canonical_value() {
        let expr = Expression::This;
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("this".to_string()))
                );
                assert_eq!(map.get("value"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_array_literal_canonical_value() {
        let expr = Expression::ArrayLiteral(vec![
            Some(Expression::NumericLiteral(1)),
            None, // sparse hole
            Some(Expression::NumericLiteral(3)),
        ]);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("array".to_string()))
                );
                if let Some(CanonicalValue::Array(elems)) = map.get("elements") {
                    assert_eq!(elems.len(), 3);
                    assert_eq!(elems[1], CanonicalValue::Null);
                } else {
                    panic!("elements should be array");
                }
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_object_literal_canonical_value() {
        let expr = Expression::ObjectLiteral(vec![ObjectProperty {
            key: Expression::Identifier("a".to_string()),
            value: Expression::NumericLiteral(1),
            computed: false,
            shorthand: true,
        }]);
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("object".to_string()))
                );
                if let Some(CanonicalValue::Array(props)) = map.get("properties") {
                    assert_eq!(props.len(), 1);
                } else {
                    panic!("properties should be array");
                }
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn object_property_canonical_value_includes_all_fields() {
        let prop = ObjectProperty {
            key: Expression::StringLiteral("k".to_string()),
            value: Expression::NumericLiteral(42),
            computed: true,
            shorthand: false,
        };
        match prop.canonical_value() {
            CanonicalValue::Map(map) => {
                assert!(map.contains_key("key"));
                assert!(map.contains_key("value"));
                assert_eq!(map.get("computed"), Some(&CanonicalValue::Bool(true)));
                assert_eq!(map.get("shorthand"), Some(&CanonicalValue::Bool(false)));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_arrow_function_canonical_value() {
        let expr = Expression::ArrowFunction {
            params: vec![FunctionParam {
                pattern: BindingPattern::Identifier("x".to_string()),
                span: make_span(),
            }],
            body: ArrowBody::Expression(Box::new(Expression::Identifier("x".to_string()))),
            is_async: true,
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("arrow_function".to_string()))
                );
                assert_eq!(map.get("is_async"), Some(&CanonicalValue::Bool(true)));
                assert!(map.contains_key("params"));
                assert!(map.contains_key("body"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn arrow_body_expression_canonical_value() {
        let body = ArrowBody::Expression(Box::new(Expression::NumericLiteral(42)));
        match body.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("expression".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn arrow_body_block_canonical_value() {
        let body = ArrowBody::Block(BlockStatement {
            body: vec![],
            span: make_span(),
        });
        match body.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("block".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_new_canonical_value() {
        let expr = Expression::New {
            callee: Box::new(Expression::Identifier("Foo".to_string())),
            arguments: vec![Expression::NumericLiteral(1)],
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("new".to_string()))
                );
                assert!(map.contains_key("callee"));
                if let Some(CanonicalValue::Array(args)) = map.get("arguments") {
                    assert_eq!(args.len(), 1);
                } else {
                    panic!("arguments should be array");
                }
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn expression_template_literal_canonical_value() {
        let expr = Expression::TemplateLiteral {
            quasis: vec!["Hello ".to_string(), "!".to_string()],
            expressions: vec![Expression::Identifier("name".to_string())],
        };
        match expr.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("template_literal".to_string()))
                );
                if let Some(CanonicalValue::Array(q)) = map.get("quasis") {
                    assert_eq!(q.len(), 2);
                } else {
                    panic!("quasis should be array");
                }
                if let Some(CanonicalValue::Array(e)) = map.get("expressions") {
                    assert_eq!(e.len(), 1);
                } else {
                    panic!("expressions should be array");
                }
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn complex_expression_serde_roundtrip() {
        let expressions = vec![
            Expression::Binary {
                operator: BinaryOperator::StrictEqual,
                left: Box::new(Expression::Identifier("x".to_string())),
                right: Box::new(Expression::NumericLiteral(0)),
            },
            Expression::Unary {
                operator: UnaryOperator::LogicalNot,
                argument: Box::new(Expression::BooleanLiteral(false)),
            },
            Expression::Assignment {
                operator: AssignmentOperator::Assign,
                left: Box::new(Expression::Identifier("y".to_string())),
                right: Box::new(Expression::NumericLiteral(10)),
            },
            Expression::Conditional {
                test: Box::new(Expression::BooleanLiteral(true)),
                consequent: Box::new(Expression::StringLiteral("a".to_string())),
                alternate: Box::new(Expression::StringLiteral("b".to_string())),
            },
            Expression::Call {
                callee: Box::new(Expression::Identifier("f".to_string())),
                arguments: vec![],
            },
            Expression::Member {
                object: Box::new(Expression::Identifier("o".to_string())),
                property: Box::new(Expression::Identifier("p".to_string())),
                computed: false,
            },
            Expression::OptionalCall {
                callee: Box::new(Expression::Identifier("maybe".to_string())),
                arguments: vec![Expression::NullLiteral],
            },
            Expression::OptionalMember {
                object: Box::new(Expression::Identifier("cfg".to_string())),
                property: Box::new(Expression::Identifier("theme".to_string())),
                computed: false,
            },
            Expression::This,
            Expression::ArrayLiteral(vec![None, Some(Expression::NullLiteral)]),
            Expression::ObjectLiteral(vec![]),
            Expression::New {
                callee: Box::new(Expression::Identifier("C".to_string())),
                arguments: vec![],
            },
            Expression::TemplateLiteral {
                quasis: vec!["a".to_string(), "b".to_string()],
                expressions: vec![Expression::NumericLiteral(1)],
            },
        ];
        for expr in expressions {
            let json = serde_json::to_string(&expr).expect("serialize");
            let restored: Expression = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, expr);
        }
    }

    // -----------------------------------------------------------------------
    // Control-flow statement canonical values
    // -----------------------------------------------------------------------

    fn make_block_stmt(stmts: Vec<Statement>) -> BlockStatement {
        BlockStatement {
            body: stmts,
            span: make_span(),
        }
    }

    #[test]
    fn statement_block_canonical_value() {
        let stmt = Statement::Block(make_block_stmt(vec![make_expr_stmt(
            Expression::NumericLiteral(1),
        )]));
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("block".to_string()))
                );
                assert!(map.contains_key("payload"));
                assert!(map.contains_key("span"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_if_canonical_value() {
        let stmt = Statement::If(IfStatement {
            condition: Expression::BooleanLiteral(true),
            consequent: Box::new(make_expr_stmt(Expression::NumericLiteral(1))),
            alternate: Some(Box::new(make_expr_stmt(Expression::NumericLiteral(2)))),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("if".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_if_without_alternate_canonical_value() {
        let if_stmt = IfStatement {
            condition: Expression::BooleanLiteral(true),
            consequent: Box::new(make_expr_stmt(Expression::NullLiteral)),
            alternate: None,
            span: make_span(),
        };
        match if_stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("alternate"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_for_canonical_value() {
        let stmt = Statement::For(ForStatement {
            init: Some(Box::new(make_var_stmt(
                "i",
                Some(Expression::NumericLiteral(0)),
            ))),
            condition: Some(Expression::Binary {
                operator: BinaryOperator::LessThan,
                left: Box::new(Expression::Identifier("i".to_string())),
                right: Box::new(Expression::NumericLiteral(10)),
            }),
            update: Some(Expression::Assignment {
                operator: AssignmentOperator::AddAssign,
                left: Box::new(Expression::Identifier("i".to_string())),
                right: Box::new(Expression::NumericLiteral(1)),
            }),
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("for".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_for_infinite_loop_all_none() {
        let for_stmt = ForStatement {
            init: None,
            condition: None,
            update: None,
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            span: make_span(),
        };
        match for_stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("init"), Some(&CanonicalValue::Null));
                assert_eq!(map.get("condition"), Some(&CanonicalValue::Null));
                assert_eq!(map.get("update"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_for_in_canonical_value() {
        let stmt = Statement::ForIn(ForInStatement {
            binding: BindingPattern::Identifier("key".to_string()),
            binding_kind: Some(VariableDeclarationKind::Const),
            object: Expression::Identifier("obj".to_string()),
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("for_in".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_for_of_canonical_value() {
        let stmt = Statement::ForOf(ForOfStatement {
            binding: BindingPattern::Identifier("item".to_string()),
            binding_kind: Some(VariableDeclarationKind::Let),
            iterable: Expression::Identifier("arr".to_string()),
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("for_of".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_while_canonical_value() {
        let stmt = Statement::While(WhileStatement {
            condition: Expression::BooleanLiteral(true),
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("while".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_do_while_canonical_value() {
        let stmt = Statement::DoWhile(DoWhileStatement {
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            condition: Expression::BooleanLiteral(false),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("do_while".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_return_with_argument_canonical_value() {
        let ret = ReturnStatement {
            argument: Some(Expression::NumericLiteral(42)),
            span: make_span(),
        };
        match ret.canonical_value() {
            CanonicalValue::Map(map) => {
                assert!(map.contains_key("argument"));
                assert_ne!(map.get("argument"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_return_without_argument_canonical_value() {
        let ret = ReturnStatement {
            argument: None,
            span: make_span(),
        };
        match ret.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("argument"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_throw_canonical_value() {
        let stmt = Statement::Throw(ThrowStatement {
            argument: Expression::New {
                callee: Box::new(Expression::Identifier("Error".to_string())),
                arguments: vec![Expression::StringLiteral("oops".to_string())],
            },
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("throw".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_try_catch_canonical_value() {
        let stmt = Statement::TryCatch(TryCatchStatement {
            block: make_block_stmt(vec![]),
            handler: Some(CatchClause {
                parameter: Some("e".to_string()),
                body: make_block_stmt(vec![]),
                span: make_span(),
            }),
            finalizer: Some(make_block_stmt(vec![])),
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("try_catch".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn catch_clause_without_parameter() {
        let clause = CatchClause {
            parameter: None,
            body: make_block_stmt(vec![]),
            span: make_span(),
        };
        match clause.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("parameter"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_switch_canonical_value() {
        let stmt = Statement::Switch(SwitchStatement {
            discriminant: Expression::Identifier("x".to_string()),
            cases: vec![
                SwitchCase {
                    test: Some(Expression::NumericLiteral(1)),
                    consequent: vec![Statement::Break(BreakStatement {
                        label: None,
                        span: make_span(),
                    })],
                    span: make_span(),
                },
                SwitchCase {
                    test: None, // default case
                    consequent: vec![],
                    span: make_span(),
                },
            ],
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("switch".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn switch_case_default_has_null_test() {
        let case = SwitchCase {
            test: None,
            consequent: vec![],
            span: make_span(),
        };
        match case.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("test"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_break_with_label_canonical_value() {
        let brk = BreakStatement {
            label: Some("outer".to_string()),
            span: make_span(),
        };
        match brk.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("label"),
                    Some(&CanonicalValue::String("outer".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_continue_without_label_canonical_value() {
        let cont = ContinueStatement {
            label: None,
            span: make_span(),
        };
        match cont.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("label"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn statement_function_declaration_canonical_value() {
        let stmt = Statement::FunctionDeclaration(FunctionDeclaration {
            name: Some("myFunc".to_string()),
            params: vec![
                FunctionParam {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    span: make_span(),
                },
                FunctionParam {
                    pattern: BindingPattern::Identifier("b".to_string()),
                    span: make_span(),
                },
            ],
            body: make_block_stmt(vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::Binary {
                    operator: BinaryOperator::Add,
                    left: Box::new(Expression::Identifier("a".to_string())),
                    right: Box::new(Expression::Identifier("b".to_string())),
                }),
                span: make_span(),
            })]),
            is_async: false,
            is_generator: true,
            span: make_span(),
        });
        match stmt.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(
                    map.get("kind"),
                    Some(&CanonicalValue::String("function_declaration".to_string()))
                );
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn function_declaration_async_generator_flags() {
        let func = FunctionDeclaration {
            name: None,
            params: vec![],
            body: make_block_stmt(vec![]),
            is_async: true,
            is_generator: true,
            span: make_span(),
        };
        match func.canonical_value() {
            CanonicalValue::Map(map) => {
                assert_eq!(map.get("is_async"), Some(&CanonicalValue::Bool(true)));
                assert_eq!(map.get("is_generator"), Some(&CanonicalValue::Bool(true)));
                assert_eq!(map.get("name"), Some(&CanonicalValue::Null));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn function_param_canonical_value() {
        let param = FunctionParam {
            pattern: BindingPattern::Identifier("arg".to_string()),
            span: make_span(),
        };
        match param.canonical_value() {
            CanonicalValue::Map(map) => {
                assert!(map.contains_key("pattern"));
                assert!(map.contains_key("span"));
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn all_statement_kinds_produce_unique_canonical_kinds() {
        let span = make_span();
        let stmts: Vec<Statement> = vec![
            Statement::Import(ImportDeclaration {
                binding: None,
                source: "m".to_string(),
                span: span.clone(),
            }),
            Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("x".to_string()),
                span: span.clone(),
            }),
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Var,
                declarations: vec![],
                span: span.clone(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::NullLiteral,
                span: span.clone(),
            }),
            Statement::Block(BlockStatement {
                body: vec![],
                span: span.clone(),
            }),
            Statement::If(IfStatement {
                condition: Expression::BooleanLiteral(true),
                consequent: Box::new(make_expr_stmt(Expression::NullLiteral)),
                alternate: None,
                span: span.clone(),
            }),
            Statement::For(ForStatement {
                init: None,
                condition: None,
                update: None,
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: span.clone(),
            }),
            Statement::While(WhileStatement {
                condition: Expression::BooleanLiteral(true),
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: span.clone(),
            }),
            Statement::DoWhile(DoWhileStatement {
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                condition: Expression::BooleanLiteral(true),
                span: span.clone(),
            }),
            Statement::Return(ReturnStatement {
                argument: None,
                span: span.clone(),
            }),
            Statement::Throw(ThrowStatement {
                argument: Expression::NullLiteral,
                span: span.clone(),
            }),
            Statement::TryCatch(TryCatchStatement {
                block: BlockStatement {
                    body: vec![],
                    span: span.clone(),
                },
                handler: None,
                finalizer: None,
                span: span.clone(),
            }),
            Statement::Switch(SwitchStatement {
                discriminant: Expression::NullLiteral,
                cases: vec![],
                span: span.clone(),
            }),
            Statement::Break(BreakStatement {
                label: None,
                span: span.clone(),
            }),
            Statement::Continue(ContinueStatement {
                label: None,
                span: span.clone(),
            }),
            Statement::FunctionDeclaration(FunctionDeclaration {
                name: None,
                params: vec![],
                body: BlockStatement {
                    body: vec![],
                    span: span.clone(),
                },
                is_async: false,
                is_generator: false,
                span: span.clone(),
            }),
            Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".to_string()),
                binding_kind: None,
                object: Expression::NullLiteral,
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: span.clone(),
            }),
            Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("v".to_string()),
                binding_kind: None,
                iterable: Expression::NullLiteral,
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span,
            }),
        ];
        let mut kinds = std::collections::BTreeSet::new();
        for stmt in &stmts {
            match stmt.canonical_value() {
                CanonicalValue::Map(map) => {
                    if let Some(CanonicalValue::String(k)) = map.get("kind") {
                        assert!(kinds.insert(k.clone()), "duplicate statement kind: {k}");
                    } else {
                        panic!("missing kind");
                    }
                }
                _ => panic!("expected map"),
            }
        }
        assert_eq!(kinds.len(), 18);
    }

    #[test]
    fn statement_span_returns_correct_span_for_all_variants() {
        let span = SourceSpan::new(7, 77, 3, 8, 9, 10);
        let stmts: Vec<Statement> = vec![
            Statement::Block(BlockStatement {
                body: vec![],
                span: span.clone(),
            }),
            Statement::If(IfStatement {
                condition: Expression::BooleanLiteral(true),
                consequent: Box::new(make_expr_stmt(Expression::NullLiteral)),
                alternate: None,
                span: span.clone(),
            }),
            Statement::For(ForStatement {
                init: None,
                condition: None,
                update: None,
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: span.clone(),
            }),
            Statement::While(WhileStatement {
                condition: Expression::BooleanLiteral(true),
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: span.clone(),
            }),
            Statement::DoWhile(DoWhileStatement {
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                condition: Expression::BooleanLiteral(true),
                span: span.clone(),
            }),
            Statement::Return(ReturnStatement {
                argument: None,
                span: span.clone(),
            }),
            Statement::Throw(ThrowStatement {
                argument: Expression::NullLiteral,
                span: span.clone(),
            }),
            Statement::TryCatch(TryCatchStatement {
                block: BlockStatement {
                    body: vec![],
                    span: make_span(),
                },
                handler: None,
                finalizer: None,
                span: span.clone(),
            }),
            Statement::Switch(SwitchStatement {
                discriminant: Expression::NullLiteral,
                cases: vec![],
                span: span.clone(),
            }),
            Statement::Break(BreakStatement {
                label: None,
                span: span.clone(),
            }),
            Statement::Continue(ContinueStatement {
                label: None,
                span: span.clone(),
            }),
            Statement::FunctionDeclaration(FunctionDeclaration {
                name: None,
                params: vec![],
                body: BlockStatement {
                    body: vec![],
                    span: make_span(),
                },
                is_async: false,
                is_generator: false,
                span: span.clone(),
            }),
            Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".to_string()),
                binding_kind: None,
                object: Expression::NullLiteral,
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: span.clone(),
            }),
            Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("v".to_string()),
                binding_kind: None,
                iterable: Expression::NullLiteral,
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: span.clone(),
            }),
        ];
        for stmt in &stmts {
            assert_eq!(stmt.span(), &span, "span mismatch for {:?}", stmt);
        }
    }

    #[test]
    fn variable_declaration_kind_serde_roundtrip() {
        for kind in [
            VariableDeclarationKind::Var,
            VariableDeclarationKind::Let,
            VariableDeclarationKind::Const,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            let restored: VariableDeclarationKind =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, kind);
        }
    }

    #[test]
    fn syntax_tree_body_order_affects_hash() {
        let span = make_span();
        let stmt_a = make_expr_stmt(Expression::Identifier("a".to_string()));
        let stmt_b = make_expr_stmt(Expression::Identifier("b".to_string()));
        let tree_ab = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![stmt_a.clone(), stmt_b.clone()],
            span: span.clone(),
        };
        let tree_ba = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![stmt_b, stmt_a],
            span,
        };
        assert_ne!(tree_ab.canonical_hash(), tree_ba.canonical_hash());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    // -----------------------------------------------------------------------
    // BinaryOperator serde roundtrip (gap: only UnaryOp/AssignmentOp had it)
    // -----------------------------------------------------------------------

    #[test]
    fn binary_operator_serde_roundtrip_all() {
        let ops = [
            BinaryOperator::Add,
            BinaryOperator::Subtract,
            BinaryOperator::Multiply,
            BinaryOperator::Divide,
            BinaryOperator::Remainder,
            BinaryOperator::Exponentiate,
            BinaryOperator::Equal,
            BinaryOperator::NotEqual,
            BinaryOperator::StrictEqual,
            BinaryOperator::StrictNotEqual,
            BinaryOperator::LessThan,
            BinaryOperator::LessThanOrEqual,
            BinaryOperator::GreaterThan,
            BinaryOperator::GreaterThanOrEqual,
            BinaryOperator::LogicalAnd,
            BinaryOperator::LogicalOr,
            BinaryOperator::NullishCoalescing,
            BinaryOperator::BitwiseAnd,
            BinaryOperator::BitwiseOr,
            BinaryOperator::BitwiseXor,
            BinaryOperator::LeftShift,
            BinaryOperator::RightShift,
            BinaryOperator::UnsignedRightShift,
            BinaryOperator::Instanceof,
            BinaryOperator::In,
        ];
        for op in ops {
            let json = serde_json::to_string(&op).expect("serialize");
            let restored: BinaryOperator = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, op);
        }
    }

    // -----------------------------------------------------------------------
    // SourceSpan canonical_value content verification
    // -----------------------------------------------------------------------

    #[test]
    fn source_span_canonical_value_content() {
        let span = SourceSpan::new(10, 50, 3, 5, 7, 20);
        if let CanonicalValue::Map(map) = span.canonical_value() {
            assert_eq!(map["start_offset"], CanonicalValue::U64(10));
            assert_eq!(map["end_offset"], CanonicalValue::U64(50));
            assert_eq!(map["start_line"], CanonicalValue::U64(3));
            assert_eq!(map["start_column"], CanonicalValue::U64(5));
            assert_eq!(map["end_line"], CanonicalValue::U64(7));
            assert_eq!(map["end_column"], CanonicalValue::U64(20));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // SyntaxTree canonical_value goal content
    // -----------------------------------------------------------------------

    #[test]
    fn syntax_tree_canonical_value_goal_string() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![],
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = tree.canonical_value() {
            assert_eq!(map["goal"], CanonicalValue::String("module".to_string()));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // VariableDeclarator canonical_value (direct test, was only indirect)
    // -----------------------------------------------------------------------

    #[test]
    fn variable_declarator_canonical_value_with_init() {
        let decl = VariableDeclarator {
            pattern: BindingPattern::Identifier("x".to_string()),
            initializer: Some(Expression::NumericLiteral(42)),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = decl.canonical_value() {
            assert!(map.contains_key("pattern"));
            assert_ne!(map["initializer"], CanonicalValue::Null);
            assert!(map.contains_key("span"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn variable_declarator_canonical_value_without_init() {
        let decl = VariableDeclarator {
            pattern: BindingPattern::Identifier("y".to_string()),
            initializer: None,
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = decl.canonical_value() {
            assert_eq!(map["initializer"], CanonicalValue::Null);
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // ForIn/ForOf binding_kind None canonical_value
    // -----------------------------------------------------------------------

    #[test]
    fn for_in_binding_kind_none_canonical_value() {
        let stmt = ForInStatement {
            binding: BindingPattern::Identifier("k".to_string()),
            binding_kind: None,
            object: Expression::Identifier("obj".to_string()),
            body: Box::new(make_expr_stmt(Expression::NullLiteral)),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = stmt.canonical_value() {
            assert_eq!(map["binding_kind"], CanonicalValue::Null);
            assert!(map.contains_key("binding"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn for_of_binding_kind_none_canonical_value() {
        let stmt = ForOfStatement {
            binding: BindingPattern::Identifier("v".to_string()),
            binding_kind: None,
            iterable: Expression::Identifier("arr".to_string()),
            body: Box::new(make_expr_stmt(Expression::NullLiteral)),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = stmt.canonical_value() {
            assert_eq!(map["binding_kind"], CanonicalValue::Null);
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // TryCatch: no handler, no finalizer
    // -----------------------------------------------------------------------

    #[test]
    fn try_catch_no_handler_no_finalizer_canonical_value() {
        let tc = TryCatchStatement {
            block: BlockStatement {
                body: vec![],
                span: make_span(),
            },
            handler: None,
            finalizer: None,
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = tc.canonical_value() {
            assert_eq!(map["handler"], CanonicalValue::Null);
            assert_eq!(map["finalizer"], CanonicalValue::Null);
            assert!(map.contains_key("block"));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // Break without label, Continue with label
    // -----------------------------------------------------------------------

    #[test]
    fn break_without_label_canonical_value() {
        let brk = BreakStatement {
            label: None,
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = brk.canonical_value() {
            assert_eq!(map["label"], CanonicalValue::Null);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn continue_with_label_canonical_value() {
        let cont = ContinueStatement {
            label: Some("loop1".to_string()),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = cont.canonical_value() {
            assert_eq!(map["label"], CanonicalValue::String("loop1".to_string()));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // ArrowFunction serde roundtrip (gap: not in complex_expression_serde_roundtrip)
    // -----------------------------------------------------------------------

    #[test]
    fn expression_arrow_function_serde_roundtrip() {
        let expr = Expression::ArrowFunction {
            params: vec![FunctionParam {
                pattern: BindingPattern::Identifier("x".to_string()),
                span: make_span(),
            }],
            body: ArrowBody::Expression(Box::new(Expression::Binary {
                operator: BinaryOperator::Multiply,
                left: Box::new(Expression::Identifier("x".to_string())),
                right: Box::new(Expression::NumericLiteral(2)),
            })),
            is_async: true,
        };
        let json = serde_json::to_string(&expr).expect("serialize");
        let restored: Expression = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(expr, restored);
    }

    #[test]
    fn expression_arrow_function_block_body_serde_roundtrip() {
        let expr = Expression::ArrowFunction {
            params: vec![],
            body: ArrowBody::Block(BlockStatement {
                body: vec![Statement::Return(ReturnStatement {
                    argument: Some(Expression::NumericLiteral(1)),
                    span: make_span(),
                })],
                span: make_span(),
            }),
            is_async: false,
        };
        let json = serde_json::to_string(&expr).expect("serialize");
        let restored: Expression = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(expr, restored);
    }

    // -----------------------------------------------------------------------
    // SwitchCase with test present: verify test value is non-null
    // -----------------------------------------------------------------------

    #[test]
    fn switch_case_with_test_canonical_value() {
        let case = SwitchCase {
            test: Some(Expression::NumericLiteral(42)),
            consequent: vec![Statement::Break(BreakStatement {
                label: None,
                span: make_span(),
            })],
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = case.canonical_value() {
            assert_ne!(map["test"], CanonicalValue::Null);
            if let CanonicalValue::Array(stmts) = &map["consequent"] {
                assert_eq!(stmts.len(), 1);
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // All 17 expression canonical kinds
    // -----------------------------------------------------------------------

    #[test]
    fn all_expression_canonical_kinds_complete() {
        let expressions: Vec<Expression> = vec![
            Expression::Identifier("a".to_string()),
            Expression::StringLiteral("s".to_string()),
            Expression::NumericLiteral(0),
            Expression::BooleanLiteral(true),
            Expression::NullLiteral,
            Expression::UndefinedLiteral,
            Expression::Await(Box::new(Expression::NullLiteral)),
            Expression::Binary {
                operator: BinaryOperator::Add,
                left: Box::new(Expression::NumericLiteral(1)),
                right: Box::new(Expression::NumericLiteral(2)),
            },
            Expression::Unary {
                operator: UnaryOperator::Negate,
                argument: Box::new(Expression::NumericLiteral(1)),
            },
            Expression::Assignment {
                operator: AssignmentOperator::Assign,
                left: Box::new(Expression::Identifier("x".to_string())),
                right: Box::new(Expression::NumericLiteral(1)),
            },
            Expression::Conditional {
                test: Box::new(Expression::BooleanLiteral(true)),
                consequent: Box::new(Expression::NumericLiteral(1)),
                alternate: Box::new(Expression::NumericLiteral(0)),
            },
            Expression::Call {
                callee: Box::new(Expression::Identifier("f".to_string())),
                arguments: vec![],
            },
            Expression::Member {
                object: Box::new(Expression::Identifier("o".to_string())),
                property: Box::new(Expression::Identifier("p".to_string())),
                computed: false,
            },
            Expression::This,
            Expression::ArrayLiteral(vec![]),
            Expression::ObjectLiteral(vec![]),
            Expression::ArrowFunction {
                params: vec![],
                body: ArrowBody::Expression(Box::new(Expression::NullLiteral)),
                is_async: false,
            },
            Expression::New {
                callee: Box::new(Expression::Identifier("C".to_string())),
                arguments: vec![],
            },
            Expression::TemplateLiteral {
                quasis: vec!["a".to_string()],
                expressions: vec![],
            },
            Expression::Raw("r".to_string()),
        ];
        let mut kinds = std::collections::BTreeSet::new();
        for expr in &expressions {
            if let CanonicalValue::Map(map) = expr.canonical_value() {
                if let Some(CanonicalValue::String(k)) = map.get("kind") {
                    assert!(kinds.insert(k.clone()), "duplicate kind: {k}");
                } else {
                    panic!("missing kind");
                }
            } else {
                panic!("expected map");
            }
        }
        assert_eq!(
            kinds.len(),
            20,
            "all 20 expression canonical kinds must be unique"
        );
    }

    // -----------------------------------------------------------------------
    // Statement serde roundtrips for types not individually tested
    // -----------------------------------------------------------------------

    #[test]
    fn control_flow_statements_serde_roundtrip() {
        let stmts: Vec<Statement> = vec![
            Statement::Block(BlockStatement {
                body: vec![make_expr_stmt(Expression::NullLiteral)],
                span: make_span(),
            }),
            Statement::If(IfStatement {
                condition: Expression::BooleanLiteral(true),
                consequent: Box::new(make_expr_stmt(Expression::NumericLiteral(1))),
                alternate: Some(Box::new(make_expr_stmt(Expression::NumericLiteral(2)))),
                span: make_span(),
            }),
            Statement::For(ForStatement {
                init: None,
                condition: Some(Expression::BooleanLiteral(true)),
                update: None,
                body: Box::new(Statement::Break(BreakStatement {
                    label: None,
                    span: make_span(),
                })),
                span: make_span(),
            }),
            Statement::While(WhileStatement {
                condition: Expression::BooleanLiteral(false),
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: make_span(),
            }),
            Statement::DoWhile(DoWhileStatement {
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                condition: Expression::BooleanLiteral(true),
                span: make_span(),
            }),
            Statement::Return(ReturnStatement {
                argument: Some(Expression::NumericLiteral(0)),
                span: make_span(),
            }),
            Statement::Throw(ThrowStatement {
                argument: Expression::StringLiteral("err".to_string()),
                span: make_span(),
            }),
            Statement::TryCatch(TryCatchStatement {
                block: BlockStatement {
                    body: vec![],
                    span: make_span(),
                },
                handler: Some(CatchClause {
                    parameter: Some("e".to_string()),
                    body: BlockStatement {
                        body: vec![],
                        span: make_span(),
                    },
                    span: make_span(),
                }),
                finalizer: None,
                span: make_span(),
            }),
            Statement::Switch(SwitchStatement {
                discriminant: Expression::Identifier("x".to_string()),
                cases: vec![SwitchCase {
                    test: Some(Expression::NumericLiteral(1)),
                    consequent: vec![],
                    span: make_span(),
                }],
                span: make_span(),
            }),
            Statement::Break(BreakStatement {
                label: Some("lbl".to_string()),
                span: make_span(),
            }),
            Statement::Continue(ContinueStatement {
                label: None,
                span: make_span(),
            }),
            Statement::FunctionDeclaration(FunctionDeclaration {
                name: Some("f".to_string()),
                params: vec![FunctionParam {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    span: make_span(),
                }],
                body: BlockStatement {
                    body: vec![],
                    span: make_span(),
                },
                is_async: true,
                is_generator: false,
                span: make_span(),
            }),
            Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".to_string()),
                binding_kind: Some(VariableDeclarationKind::Let),
                object: Expression::Identifier("obj".to_string()),
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: make_span(),
            }),
            Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("v".to_string()),
                binding_kind: Some(VariableDeclarationKind::Const),
                iterable: Expression::Identifier("arr".to_string()),
                body: Box::new(make_expr_stmt(Expression::NullLiteral)),
                span: make_span(),
            }),
        ];
        for stmt in stmts {
            let json = serde_json::to_string(&stmt).expect("serialize");
            let restored: Statement = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(restored, stmt);
        }
    }

    // -----------------------------------------------------------------------
    // VariableDeclaration canonical_value content verification
    // -----------------------------------------------------------------------

    #[test]
    fn variable_declaration_canonical_value_content() {
        let decl = VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![
                VariableDeclarator {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    initializer: Some(Expression::NumericLiteral(1)),
                    span: make_span(),
                },
                VariableDeclarator {
                    pattern: BindingPattern::Identifier("b".to_string()),
                    initializer: Some(Expression::NumericLiteral(2)),
                    span: make_span(),
                },
            ],
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = decl.canonical_value() {
            assert_eq!(map["kind"], CanonicalValue::String("const".to_string()));
            if let CanonicalValue::Array(decls) = &map["declarations"] {
                assert_eq!(decls.len(), 2);
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // BinaryOperator precedence all levels
    // -----------------------------------------------------------------------

    #[test]
    fn binary_operator_precedence_all_levels_covered() {
        // Verify every operator has a non-zero precedence
        let ops = [
            BinaryOperator::Add,
            BinaryOperator::Subtract,
            BinaryOperator::Multiply,
            BinaryOperator::Divide,
            BinaryOperator::Remainder,
            BinaryOperator::Exponentiate,
            BinaryOperator::Equal,
            BinaryOperator::NotEqual,
            BinaryOperator::StrictEqual,
            BinaryOperator::StrictNotEqual,
            BinaryOperator::LessThan,
            BinaryOperator::LessThanOrEqual,
            BinaryOperator::GreaterThan,
            BinaryOperator::GreaterThanOrEqual,
            BinaryOperator::LogicalAnd,
            BinaryOperator::LogicalOr,
            BinaryOperator::NullishCoalescing,
            BinaryOperator::BitwiseAnd,
            BinaryOperator::BitwiseOr,
            BinaryOperator::BitwiseXor,
            BinaryOperator::LeftShift,
            BinaryOperator::RightShift,
            BinaryOperator::UnsignedRightShift,
            BinaryOperator::Instanceof,
            BinaryOperator::In,
        ];
        for op in ops {
            assert!(op.precedence() > 0, "{:?} has zero precedence", op);
        }
        // Same-group operators have equal precedence
        assert_eq!(
            BinaryOperator::Add.precedence(),
            BinaryOperator::Subtract.precedence()
        );
        assert_eq!(
            BinaryOperator::Multiply.precedence(),
            BinaryOperator::Divide.precedence()
        );
        assert_eq!(
            BinaryOperator::Multiply.precedence(),
            BinaryOperator::Remainder.precedence()
        );
        assert_eq!(
            BinaryOperator::Equal.precedence(),
            BinaryOperator::StrictNotEqual.precedence()
        );
        assert_eq!(
            BinaryOperator::Instanceof.precedence(),
            BinaryOperator::In.precedence()
        );
    }

    // -----------------------------------------------------------------------
    // Expression empty containers canonical_value
    // -----------------------------------------------------------------------

    #[test]
    fn expression_empty_array_canonical_value() {
        let expr = Expression::ArrayLiteral(vec![]);
        if let CanonicalValue::Map(map) = expr.canonical_value() {
            if let CanonicalValue::Array(elems) = &map["elements"] {
                assert!(elems.is_empty());
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn expression_empty_object_canonical_value() {
        let expr = Expression::ObjectLiteral(vec![]);
        if let CanonicalValue::Map(map) = expr.canonical_value() {
            if let CanonicalValue::Array(props) = &map["properties"] {
                assert!(props.is_empty());
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn expression_template_literal_no_expressions() {
        let expr = Expression::TemplateLiteral {
            quasis: vec!["plain text".to_string()],
            expressions: vec![],
        };
        if let CanonicalValue::Map(map) = expr.canonical_value() {
            if let CanonicalValue::Array(q) = &map["quasis"] {
                assert_eq!(q.len(), 1);
            } else {
                panic!("expected array");
            }
            if let CanonicalValue::Array(e) = &map["expressions"] {
                assert!(e.is_empty());
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn expression_call_no_args_canonical_value() {
        let expr = Expression::Call {
            callee: Box::new(Expression::Identifier("f".to_string())),
            arguments: vec![],
        };
        if let CanonicalValue::Map(map) = expr.canonical_value() {
            if let CanonicalValue::Array(args) = &map["arguments"] {
                assert!(args.is_empty());
            } else {
                panic!("expected array");
            }
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // CatchClause serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn catch_clause_serde_roundtrip() {
        let clause = CatchClause {
            parameter: Some("err".to_string()),
            body: BlockStatement {
                body: vec![make_expr_stmt(Expression::Identifier("err".to_string()))],
                span: make_span(),
            },
            span: make_span(),
        };
        let json = serde_json::to_string(&clause).expect("serialize");
        let restored: CatchClause = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(clause, restored);
    }

    // -- Enrichment: PearlTower 2026-03-02 batch 2 --

    // -----------------------------------------------------------------------
    // Standalone serde roundtrips for sub-types
    // -----------------------------------------------------------------------

    #[test]
    fn object_property_serde_roundtrip() {
        let prop = ObjectProperty {
            key: Expression::StringLiteral("name".to_string()),
            value: Expression::NumericLiteral(42),
            computed: true,
            shorthand: false,
        };
        let json = serde_json::to_string(&prop).expect("serialize");
        let restored: ObjectProperty = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(prop, restored);
    }

    #[test]
    fn function_param_serde_roundtrip() {
        let param = FunctionParam {
            pattern: BindingPattern::Identifier("arg".to_string()),
            span: SourceSpan::new(5, 8, 1, 6, 1, 9),
        };
        let json = serde_json::to_string(&param).expect("serialize");
        let restored: FunctionParam = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(param, restored);
    }

    #[test]
    fn arrow_body_expression_serde_roundtrip() {
        let body = ArrowBody::Expression(Box::new(Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(Expression::NumericLiteral(1)),
            right: Box::new(Expression::NumericLiteral(2)),
        }));
        let json = serde_json::to_string(&body).expect("serialize");
        let restored: ArrowBody = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(body, restored);
    }

    #[test]
    fn arrow_body_block_serde_roundtrip() {
        let body = ArrowBody::Block(BlockStatement {
            body: vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::StringLiteral("ok".to_string())),
                span: make_span(),
            })],
            span: make_span(),
        });
        let json = serde_json::to_string(&body).expect("serialize");
        let restored: ArrowBody = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(body, restored);
    }

    #[test]
    fn switch_case_serde_roundtrip() {
        let case = SwitchCase {
            test: Some(Expression::StringLiteral("a".to_string())),
            consequent: vec![
                make_expr_stmt(Expression::Identifier("doA".to_string())),
                Statement::Break(BreakStatement {
                    label: None,
                    span: make_span(),
                }),
            ],
            span: make_span(),
        };
        let json = serde_json::to_string(&case).expect("serialize");
        let restored: SwitchCase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(case, restored);
    }

    #[test]
    fn export_kind_serde_roundtrip_both_variants() {
        let default = ExportKind::Default(Expression::Identifier("main".to_string()));
        let json_d = serde_json::to_string(&default).expect("serialize");
        let restored_d: ExportKind = serde_json::from_str(&json_d).expect("deserialize");
        assert_eq!(default, restored_d);

        let named = ExportKind::NamedClause("{ foo, bar }".to_string());
        let json_n = serde_json::to_string(&named).expect("serialize");
        let restored_n: ExportKind = serde_json::from_str(&json_n).expect("deserialize");
        assert_eq!(named, restored_n);
    }

    #[test]
    fn import_declaration_serde_roundtrip_with_binding() {
        let import = ImportDeclaration {
            binding: Some("React".to_string()),
            source: "react".to_string(),
            span: SourceSpan::new(0, 25, 1, 1, 1, 26),
        };
        let json = serde_json::to_string(&import).expect("serialize");
        let restored: ImportDeclaration = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(import, restored);
    }

    // -----------------------------------------------------------------------
    // Canonical value content verification for control-flow types
    // -----------------------------------------------------------------------

    #[test]
    fn for_statement_canonical_value_all_fields_present() {
        let for_stmt = ForStatement {
            init: Some(Box::new(make_var_stmt(
                "i",
                Some(Expression::NumericLiteral(0)),
            ))),
            condition: Some(Expression::Binary {
                operator: BinaryOperator::LessThan,
                left: Box::new(Expression::Identifier("i".to_string())),
                right: Box::new(Expression::NumericLiteral(10)),
            }),
            update: Some(Expression::Assignment {
                operator: AssignmentOperator::AddAssign,
                left: Box::new(Expression::Identifier("i".to_string())),
                right: Box::new(Expression::NumericLiteral(1)),
            }),
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = for_stmt.canonical_value() {
            assert_ne!(map["init"], CanonicalValue::Null);
            assert_ne!(map["condition"], CanonicalValue::Null);
            assert_ne!(map["update"], CanonicalValue::Null);
            assert!(map.contains_key("body"));
            assert!(map.contains_key("span"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn while_statement_canonical_value_content() {
        let stmt = WhileStatement {
            condition: Expression::BooleanLiteral(true),
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = stmt.canonical_value() {
            assert!(map.contains_key("condition"));
            assert!(map.contains_key("body"));
            assert!(map.contains_key("span"));
            assert_ne!(map["condition"], CanonicalValue::Null);
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn do_while_statement_canonical_value_content() {
        let stmt = DoWhileStatement {
            body: Box::new(Statement::Block(make_block_stmt(vec![]))),
            condition: Expression::BooleanLiteral(false),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = stmt.canonical_value() {
            assert!(map.contains_key("body"));
            assert!(map.contains_key("condition"));
            assert!(map.contains_key("span"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn catch_clause_with_parameter_canonical_value_content() {
        let clause = CatchClause {
            parameter: Some("err".to_string()),
            body: make_block_stmt(vec![]),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = clause.canonical_value() {
            assert_eq!(map["parameter"], CanonicalValue::String("err".to_string()));
            assert!(map.contains_key("body"));
            assert!(map.contains_key("span"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn function_declaration_canonical_value_content() {
        let func = FunctionDeclaration {
            name: Some("add".to_string()),
            params: vec![
                FunctionParam {
                    pattern: BindingPattern::Identifier("a".to_string()),
                    span: make_span(),
                },
                FunctionParam {
                    pattern: BindingPattern::Identifier("b".to_string()),
                    span: make_span(),
                },
            ],
            body: make_block_stmt(vec![Statement::Return(ReturnStatement {
                argument: Some(Expression::Binary {
                    operator: BinaryOperator::Add,
                    left: Box::new(Expression::Identifier("a".to_string())),
                    right: Box::new(Expression::Identifier("b".to_string())),
                }),
                span: make_span(),
            })]),
            is_async: false,
            is_generator: false,
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = func.canonical_value() {
            assert_eq!(map["name"], CanonicalValue::String("add".to_string()));
            assert_eq!(map["is_async"], CanonicalValue::Bool(false));
            assert_eq!(map["is_generator"], CanonicalValue::Bool(false));
            if let CanonicalValue::Array(params) = &map["params"] {
                assert_eq!(params.len(), 2);
            } else {
                panic!("expected params array");
            }
            assert!(map.contains_key("body"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn block_statement_canonical_value_body_content() {
        let block = BlockStatement {
            body: vec![
                make_expr_stmt(Expression::NumericLiteral(1)),
                make_expr_stmt(Expression::NumericLiteral(2)),
            ],
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = block.canonical_value() {
            if let CanonicalValue::Array(stmts) = &map["body"] {
                assert_eq!(stmts.len(), 2);
            } else {
                panic!("expected body array");
            }
            assert!(map.contains_key("span"));
        } else {
            panic!("expected map");
        }
    }

    // -----------------------------------------------------------------------
    // Hash sensitivity to span changes
    // -----------------------------------------------------------------------

    #[test]
    fn syntax_tree_different_spans_produce_different_hashes() {
        let body = vec![make_expr_stmt(Expression::NumericLiteral(1))];
        let tree1 = SyntaxTree {
            goal: ParseGoal::Script,
            body: body.clone(),
            span: SourceSpan::new(0, 10, 1, 1, 1, 11),
        };
        let tree2 = SyntaxTree {
            goal: ParseGoal::Script,
            body,
            span: SourceSpan::new(0, 20, 1, 1, 2, 1),
        };
        assert_ne!(tree1.canonical_hash(), tree2.canonical_hash());
    }

    // -----------------------------------------------------------------------
    // ForIn/ForOf binding_kind Some content verification
    // -----------------------------------------------------------------------

    #[test]
    fn for_in_binding_kind_some_canonical_value_content() {
        let stmt = ForInStatement {
            binding: BindingPattern::Identifier("key".to_string()),
            binding_kind: Some(VariableDeclarationKind::Const),
            object: Expression::Identifier("obj".to_string()),
            body: Box::new(make_expr_stmt(Expression::NullLiteral)),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = stmt.canonical_value() {
            assert!(map.contains_key("binding"));
            assert_ne!(map["binding_kind"], CanonicalValue::Null);
            assert!(map.contains_key("object"));
            assert!(map.contains_key("body"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn for_of_binding_kind_some_canonical_value_content() {
        let stmt = ForOfStatement {
            binding: BindingPattern::Identifier("val".to_string()),
            binding_kind: Some(VariableDeclarationKind::Let),
            iterable: Expression::Identifier("items".to_string()),
            body: Box::new(make_expr_stmt(Expression::NullLiteral)),
            span: make_span(),
        };
        if let CanonicalValue::Map(map) = stmt.canonical_value() {
            assert!(map.contains_key("binding"));
            assert_ne!(map["binding_kind"], CanonicalValue::Null);
            assert!(map.contains_key("iterable"));
            assert!(map.contains_key("body"));
        } else {
            panic!("expected map");
        }
    }
}
