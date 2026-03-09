//! JSX/TSX parsing with typed nodes, stable spans, and fail-closed diagnostics.
//!
//! This module defines the AST node types, parsing logic, and evidence harness
//! for JSX/TSX syntax used in React and other JSX-consuming frameworks.
//!
//! Every JSX construct carries a stable `SourceSpan`. Unsupported or malformed
//! JSX emits a structured `JsxDiagnostic` with a deterministic code — no JSX
//! input may silently pass through without either producing a valid typed AST
//! or a fail-closed diagnostic.
//!
//! The evidence harness runs a canonical corpus through the parser and records
//! per-family verdicts suitable for CI gating and release-evidence publication.
//!
//! Reference: [RGC-206A]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::SourceSpan;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for JSX/TSX parser node contract.
pub const JSX_PARSER_SCHEMA_VERSION: &str = "franken-engine.jsx-tsx-parser.inventory.v1";
/// Schema version for JSX/TSX run manifests.
pub const JSX_PARSER_MANIFEST_SCHEMA_VERSION: &str = "franken-engine.jsx-tsx-parser.run-manifest.v1";
/// Schema version for JSX/TSX evidence events.
pub const JSX_PARSER_EVENT_SCHEMA_VERSION: &str = "franken-engine.jsx-tsx-parser.event.v1";
/// Component name for evidence linkage.
pub const JSX_PARSER_COMPONENT: &str = "jsx_tsx_parser";
/// Policy ID binding for the JSX/TSX parser module.
pub const JSX_PARSER_POLICY_ID: &str = "RGC-206A";

// ---------------------------------------------------------------------------
// JSX Runtime Mode
// ---------------------------------------------------------------------------

/// The JSX runtime transform mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsxRuntimeMode {
    /// Classic: `React.createElement` calls.
    Classic,
    /// Automatic: `jsx`/`jsxs` from `react/jsx-runtime`.
    Automatic,
    /// Preserve: emit JSX as-is (for downstream transforms).
    Preserve,
}

impl JsxRuntimeMode {
    pub const ALL: &[Self] = &[Self::Classic, Self::Automatic, Self::Preserve];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Automatic => "automatic",
            Self::Preserve => "preserve",
        }
    }
}

impl fmt::Display for JsxRuntimeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// JSX Feature Families
// ---------------------------------------------------------------------------

/// A JSX syntax family that the parser must handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsxFeatureFamily {
    /// `<div>...</div>` — standard element with open+close tags.
    Element,
    /// `<div />` — self-closing element.
    SelfClosing,
    /// `<>...</>` — fragment shorthand.
    Fragment,
    /// `<div className="x">` — string attribute.
    StringAttribute,
    /// `<div count={expr}>` — expression attribute.
    ExpressionAttribute,
    /// `<Comp {...props}>` — spread attribute.
    SpreadAttribute,
    /// `{expression}` inside element children.
    ExpressionChild,
    /// Plain text content inside elements.
    TextChild,
    /// `<ns:tag>` — namespaced element name (rare, XML-like).
    NamespacedName,
    /// `<Obj.Comp>` — member expression element name.
    MemberExpressionName,
    /// Nested elements: `<div><span>...</span></div>`.
    NestedElement,
    /// `<Component key={k}>` — key prop (React-specific semantics).
    KeyProp,
}

impl JsxFeatureFamily {
    pub const ALL: &[Self] = &[
        Self::Element,
        Self::SelfClosing,
        Self::Fragment,
        Self::StringAttribute,
        Self::ExpressionAttribute,
        Self::SpreadAttribute,
        Self::ExpressionChild,
        Self::TextChild,
        Self::NamespacedName,
        Self::MemberExpressionName,
        Self::NestedElement,
        Self::KeyProp,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Element => "element",
            Self::SelfClosing => "self_closing",
            Self::Fragment => "fragment",
            Self::StringAttribute => "string_attribute",
            Self::ExpressionAttribute => "expression_attribute",
            Self::SpreadAttribute => "spread_attribute",
            Self::ExpressionChild => "expression_child",
            Self::TextChild => "text_child",
            Self::NamespacedName => "namespaced_name",
            Self::MemberExpressionName => "member_expression_name",
            Self::NestedElement => "nested_element",
            Self::KeyProp => "key_prop",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Element => "Standard JSX element with open and close tags (`<div>...</div>`)",
            Self::SelfClosing => "Self-closing JSX element (`<br />`)",
            Self::Fragment => "JSX fragment shorthand (`<>...</>`)",
            Self::StringAttribute => "JSX string attribute (`className=\"app\"`)",
            Self::ExpressionAttribute => "JSX expression attribute (`count={n + 1}`)",
            Self::SpreadAttribute => "JSX spread attribute (`{...props}`)",
            Self::ExpressionChild => "Expression child inside JSX (`{items.map(...)}`)",
            Self::TextChild => "Plain text content inside JSX elements",
            Self::NamespacedName => "Namespaced element name (`<svg:rect />`)",
            Self::MemberExpressionName => "Member expression element name (`<Ctx.Provider />`)",
            Self::NestedElement => "Nested JSX elements (`<div><span>x</span></div>`)",
            Self::KeyProp => "React key prop (`<Item key={id} />`)",
        }
    }
}

impl fmt::Display for JsxFeatureFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// JSX AST Node Types
// ---------------------------------------------------------------------------

/// A JSX element name — identifier, member expression, or namespaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum JsxElementName {
    /// Simple identifier: `div`, `Component`.
    Identifier { name: String, span: SourceSpan },
    /// Member expression: `Ctx.Provider`, `a.b.c`.
    MemberExpression {
        segments: Vec<String>,
        span: SourceSpan,
    },
    /// Namespaced: `svg:rect`.
    NamespacedName {
        namespace: String,
        name: String,
        span: SourceSpan,
    },
}

impl JsxElementName {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Identifier { span, .. } => span,
            Self::MemberExpression { span, .. } => span,
            Self::NamespacedName { span, .. } => span,
        }
    }

    /// Whether this name starts with an uppercase letter (component vs intrinsic).
    pub fn is_component(&self) -> bool {
        match self {
            Self::Identifier { name, .. } => {
                name.starts_with(|c: char| c.is_ascii_uppercase())
            }
            Self::MemberExpression { segments, .. } => {
                segments.first().is_some_and(|s| s.starts_with(|c: char| c.is_ascii_uppercase()))
            }
            Self::NamespacedName { .. } => false,
        }
    }

    pub fn to_string_repr(&self) -> String {
        match self {
            Self::Identifier { name, .. } => name.clone(),
            Self::MemberExpression { segments, .. } => segments.join("."),
            Self::NamespacedName {
                namespace, name, ..
            } => format!("{namespace}:{name}"),
        }
    }
}

/// A JSX attribute on an opening element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum JsxAttribute {
    /// `name="value"` or `name={expr}`.
    Named {
        name: String,
        value: JsxAttributeValue,
        span: SourceSpan,
    },
    /// `{...expr}` spread.
    Spread {
        expression: String,
        span: SourceSpan,
    },
}

impl JsxAttribute {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Named { span, .. } => span,
            Self::Spread { span, .. } => span,
        }
    }
}

/// The value of a named JSX attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum JsxAttributeValue {
    /// String literal: `"hello"`.
    StringLiteral { value: String },
    /// Expression container: `{expr}`.
    Expression { expression: String },
    /// Boolean shorthand: `<input disabled />` (no value = true).
    ImplicitTrue,
}

/// A child inside a JSX element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum JsxChild {
    /// Plain text content.
    Text { value: String, span: SourceSpan },
    /// Expression container: `{expr}`.
    ExpressionContainer {
        expression: String,
        span: SourceSpan,
    },
    /// Nested JSX element.
    Element(Box<JsxElement>),
    /// Nested JSX fragment.
    Fragment(Box<JsxFragment>),
}

impl JsxChild {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Text { span, .. } => span,
            Self::ExpressionContainer { span, .. } => span,
            Self::Element(el) => &el.span,
            Self::Fragment(frag) => &frag.span,
        }
    }
}

/// A JSX element: `<Name attrs>children</Name>` or `<Name attrs />`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxElement {
    pub name: JsxElementName,
    pub attributes: Vec<JsxAttribute>,
    pub children: Vec<JsxChild>,
    pub self_closing: bool,
    pub span: SourceSpan,
}

/// A JSX fragment: `<>children</>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxFragment {
    pub children: Vec<JsxChild>,
    pub span: SourceSpan,
}

/// Top-level JSX parse result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum JsxNode {
    Element(JsxElement),
    Fragment(JsxFragment),
}

impl JsxNode {
    pub fn span(&self) -> &SourceSpan {
        match self {
            Self::Element(el) => &el.span,
            Self::Fragment(frag) => &frag.span,
        }
    }
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Severity level for JSX diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsxDiagnosticSeverity {
    Error,
    Warning,
}

impl JsxDiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
        }
    }
}

impl fmt::Display for JsxDiagnosticSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Diagnostic code for JSX parse failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsxDiagnosticCode {
    UnmatchedOpeningTag,
    UnmatchedClosingTag,
    MissingClosingTag,
    InvalidAttributeName,
    InvalidAttributeValue,
    UnclosedExpressionContainer,
    EmptyExpression,
    InvalidElementName,
    NestedFragmentDepthExceeded,
    UnsupportedJsxSyntax,
}

impl JsxDiagnosticCode {
    pub const ALL: &[Self] = &[
        Self::UnmatchedOpeningTag,
        Self::UnmatchedClosingTag,
        Self::MissingClosingTag,
        Self::InvalidAttributeName,
        Self::InvalidAttributeValue,
        Self::UnclosedExpressionContainer,
        Self::EmptyExpression,
        Self::InvalidElementName,
        Self::NestedFragmentDepthExceeded,
        Self::UnsupportedJsxSyntax,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnmatchedOpeningTag => "FE-JSX-0001",
            Self::UnmatchedClosingTag => "FE-JSX-0002",
            Self::MissingClosingTag => "FE-JSX-0003",
            Self::InvalidAttributeName => "FE-JSX-0004",
            Self::InvalidAttributeValue => "FE-JSX-0005",
            Self::UnclosedExpressionContainer => "FE-JSX-0006",
            Self::EmptyExpression => "FE-JSX-0007",
            Self::InvalidElementName => "FE-JSX-0008",
            Self::NestedFragmentDepthExceeded => "FE-JSX-0009",
            Self::UnsupportedJsxSyntax => "FE-JSX-0010",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::UnmatchedOpeningTag => "Opening tag has no matching closing tag",
            Self::UnmatchedClosingTag => "Closing tag has no matching opening tag",
            Self::MissingClosingTag => {
                "Element is not self-closing and has no closing tag"
            }
            Self::InvalidAttributeName => "Invalid JSX attribute name",
            Self::InvalidAttributeValue => "Invalid JSX attribute value",
            Self::UnclosedExpressionContainer => {
                "Expression container `{` is not closed with `}`"
            }
            Self::EmptyExpression => "Empty expression container `{}` is not allowed",
            Self::InvalidElementName => "Invalid JSX element name",
            Self::NestedFragmentDepthExceeded => {
                "Fragment nesting depth exceeds safety limit"
            }
            Self::UnsupportedJsxSyntax => "Unsupported JSX syntax",
        }
    }
}

impl fmt::Display for JsxDiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A structured JSX diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxDiagnostic {
    pub code: JsxDiagnosticCode,
    pub severity: JsxDiagnosticSeverity,
    pub message: String,
    pub span: Option<SourceSpan>,
}

impl fmt::Display for JsxDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}: {}",
            self.severity,
            self.code.as_str(),
            self.message
        )
    }
}

// ---------------------------------------------------------------------------
// Parse Error
// ---------------------------------------------------------------------------

/// Errors returned by the JSX parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JsxParseError {
    /// One or more diagnostics caused a fail-closed rejection.
    FailClosed { diagnostics: Vec<JsxDiagnostic> },
    /// Input is empty.
    EmptyInput,
    /// Nesting depth exceeds safety limit.
    DepthExceeded { depth: usize, limit: usize },
}

impl fmt::Display for JsxParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailClosed { diagnostics } => {
                write!(f, "JSX parse failed with {} diagnostic(s)", diagnostics.len())
            }
            Self::EmptyInput => write!(f, "JSX input is empty"),
            Self::DepthExceeded { depth, limit } => {
                write!(f, "JSX nesting depth {depth} exceeds limit {limit}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parser Configuration
// ---------------------------------------------------------------------------

/// Maximum nesting depth for JSX elements (safety limit).
const MAX_JSX_DEPTH: usize = 64;

/// Configuration for the JSX/TSX parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxParserConfig {
    /// JSX runtime transform mode.
    pub runtime_mode: JsxRuntimeMode,
    /// Maximum nesting depth.
    pub max_depth: usize,
    /// Whether to allow namespaced names (`<svg:rect>`).
    pub allow_namespaced_names: bool,
    /// Whether TypeScript generic syntax in JSX is expected (TSX mode).
    pub tsx_mode: bool,
}

impl Default for JsxParserConfig {
    fn default() -> Self {
        Self {
            runtime_mode: JsxRuntimeMode::Automatic,
            max_depth: MAX_JSX_DEPTH,
            allow_namespaced_names: false,
            tsx_mode: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Parse Result
// ---------------------------------------------------------------------------

/// Result of parsing a JSX source fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxParseResult {
    pub node: JsxNode,
    pub diagnostics: Vec<JsxDiagnostic>,
    pub feature_families_used: Vec<JsxFeatureFamily>,
}

// ---------------------------------------------------------------------------
// Core Parsing
// ---------------------------------------------------------------------------

/// Parse a JSX source fragment into typed AST nodes.
///
/// Returns a fail-closed error if the input contains malformed or unsupported
/// JSX syntax. Every valid construct produces a typed node with a stable span.
pub fn parse_jsx(source: &str, config: &JsxParserConfig) -> Result<JsxParseResult, JsxParseError> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Err(JsxParseError::EmptyInput);
    }

    let mut diagnostics = Vec::new();
    let mut families_used = Vec::new();
    let mut cursor = Cursor::new(trimmed);

    let node = parse_jsx_node(&mut cursor, config, 0, &mut diagnostics, &mut families_used)?;

    if !diagnostics.iter().all(|d| d.severity != JsxDiagnosticSeverity::Error) {
        return Err(JsxParseError::FailClosed { diagnostics });
    }

    Ok(JsxParseResult {
        node,
        diagnostics,
        feature_families_used: {
            let mut fam: Vec<_> = families_used.into_iter().collect();
            fam.sort();
            fam.dedup();
            fam
        },
    })
}

/// Internal cursor for character-by-character parsing.
struct Cursor<'a> {
    source: &'a str,
    pos: usize,
    line: u64,
    col: u64,
}

impl<'a> Cursor<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<char> {
        self.source[self.pos..].chars().next()
    }

    fn peek_str(&self, n: usize) -> &str {
        let end = (self.pos + n).min(self.source.len());
        &self.source[self.pos..end]
    }

    fn advance(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(ch)
    }

    fn span_start(&self) -> (u64, u64, u64) {
        (self.pos as u64, self.line, self.col)
    }

    fn make_span(&self, start: (u64, u64, u64)) -> SourceSpan {
        SourceSpan::new(start.0, self.pos as u64, start.1, start.2, self.line, self.col)
    }

    fn at_end(&self) -> bool {
        self.pos >= self.source.len()
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek() {
            if ch.is_ascii_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn remaining(&self) -> &str {
        &self.source[self.pos..]
    }
}

fn parse_jsx_node(
    cursor: &mut Cursor<'_>,
    config: &JsxParserConfig,
    depth: usize,
    diagnostics: &mut Vec<JsxDiagnostic>,
    families: &mut Vec<JsxFeatureFamily>,
) -> Result<JsxNode, JsxParseError> {
    if depth > config.max_depth {
        return Err(JsxParseError::DepthExceeded {
            depth,
            limit: config.max_depth,
        });
    }

    cursor.skip_whitespace();

    if cursor.peek_str(2) == "<>" {
        families.push(JsxFeatureFamily::Fragment);
        let frag = parse_fragment(cursor, config, depth, diagnostics, families)?;
        Ok(JsxNode::Fragment(frag))
    } else if cursor.peek() == Some('<') {
        let element = parse_element(cursor, config, depth, diagnostics, families)?;
        Ok(JsxNode::Element(element))
    } else {
        Err(JsxParseError::FailClosed {
            diagnostics: vec![JsxDiagnostic {
                code: JsxDiagnosticCode::UnsupportedJsxSyntax,
                severity: JsxDiagnosticSeverity::Error,
                message: "Expected JSX element starting with '<'".to_string(),
                span: None,
            }],
        })
    }
}

fn parse_fragment(
    cursor: &mut Cursor<'_>,
    config: &JsxParserConfig,
    depth: usize,
    diagnostics: &mut Vec<JsxDiagnostic>,
    families: &mut Vec<JsxFeatureFamily>,
) -> Result<JsxFragment, JsxParseError> {
    let start = cursor.span_start();

    // Consume `<>`
    cursor.advance(); // <
    cursor.advance(); // >

    let children = parse_children(cursor, config, depth, diagnostics, families, None)?;

    // Expect `</>`
    if cursor.peek_str(3) == "</>" {
        cursor.advance(); // <
        cursor.advance(); // /
        cursor.advance(); // >
    } else {
        diagnostics.push(JsxDiagnostic {
            code: JsxDiagnosticCode::MissingClosingTag,
            severity: JsxDiagnosticSeverity::Error,
            message: "Fragment missing closing `</>`".to_string(),
            span: Some(cursor.make_span(start)),
        });
    }

    Ok(JsxFragment {
        children,
        span: cursor.make_span(start),
    })
}

fn parse_element(
    cursor: &mut Cursor<'_>,
    config: &JsxParserConfig,
    depth: usize,
    diagnostics: &mut Vec<JsxDiagnostic>,
    families: &mut Vec<JsxFeatureFamily>,
) -> Result<JsxElement, JsxParseError> {
    let start = cursor.span_start();

    // Consume `<`
    cursor.advance();

    let name = parse_element_name(cursor, config, diagnostics, families)?;
    let attributes = parse_attributes(cursor, config, diagnostics, families)?;

    cursor.skip_whitespace();

    // Self-closing?
    if cursor.peek_str(2) == "/>" {
        families.push(JsxFeatureFamily::SelfClosing);
        cursor.advance(); // /
        cursor.advance(); // >
        return Ok(JsxElement {
            name,
            attributes,
            children: Vec::new(),
            self_closing: true,
            span: cursor.make_span(start),
        });
    }

    // Expect `>`
    if cursor.peek() == Some('>') {
        cursor.advance();
    } else {
        diagnostics.push(JsxDiagnostic {
            code: JsxDiagnosticCode::UnmatchedOpeningTag,
            severity: JsxDiagnosticSeverity::Error,
            message: format!(
                "Expected '>' to close opening tag <{}>",
                name.to_string_repr()
            ),
            span: Some(cursor.make_span(start)),
        });
        return Err(JsxParseError::FailClosed {
            diagnostics: diagnostics.clone(),
        });
    }

    families.push(JsxFeatureFamily::Element);

    let tag_name = name.to_string_repr();
    let children = parse_children(cursor, config, depth, diagnostics, families, Some(&tag_name))?;

    // Expect `</name>`
    if cursor.peek_str(2) == "</" {
        cursor.advance(); // <
        cursor.advance(); // /
        let closing_name = read_identifier(cursor);
        if closing_name != tag_name {
            diagnostics.push(JsxDiagnostic {
                code: JsxDiagnosticCode::UnmatchedClosingTag,
                severity: JsxDiagnosticSeverity::Error,
                message: format!(
                    "Closing tag </{closing_name}> does not match opening <{tag_name}>"
                ),
                span: Some(cursor.make_span(start)),
            });
        }
        cursor.skip_whitespace();
        if cursor.peek() == Some('>') {
            cursor.advance();
        }
    } else {
        diagnostics.push(JsxDiagnostic {
            code: JsxDiagnosticCode::MissingClosingTag,
            severity: JsxDiagnosticSeverity::Error,
            message: format!("Element <{tag_name}> has no closing tag"),
            span: Some(cursor.make_span(start)),
        });
    }

    Ok(JsxElement {
        name,
        attributes,
        children,
        self_closing: false,
        span: cursor.make_span(start),
    })
}

fn parse_element_name(
    cursor: &mut Cursor<'_>,
    config: &JsxParserConfig,
    diagnostics: &mut Vec<JsxDiagnostic>,
    families: &mut Vec<JsxFeatureFamily>,
) -> Result<JsxElementName, JsxParseError> {
    let start = cursor.span_start();
    let first_segment = read_identifier(cursor);

    if first_segment.is_empty() {
        diagnostics.push(JsxDiagnostic {
            code: JsxDiagnosticCode::InvalidElementName,
            severity: JsxDiagnosticSeverity::Error,
            message: "Expected element name after '<'".to_string(),
            span: Some(cursor.make_span(start)),
        });
        return Err(JsxParseError::FailClosed {
            diagnostics: diagnostics.clone(),
        });
    }

    // Check for namespaced name: `ns:name`
    if cursor.peek() == Some(':') && config.allow_namespaced_names {
        cursor.advance(); // :
        let local_name = read_identifier(cursor);
        families.push(JsxFeatureFamily::NamespacedName);
        return Ok(JsxElementName::NamespacedName {
            namespace: first_segment,
            name: local_name,
            span: cursor.make_span(start),
        });
    }

    // Check for member expression: `a.b.c`
    if cursor.peek() == Some('.') {
        let mut segments = vec![first_segment];
        while cursor.peek() == Some('.') {
            cursor.advance(); // .
            segments.push(read_identifier(cursor));
        }
        families.push(JsxFeatureFamily::MemberExpressionName);
        return Ok(JsxElementName::MemberExpression {
            segments,
            span: cursor.make_span(start),
        });
    }

    Ok(JsxElementName::Identifier {
        name: first_segment,
        span: cursor.make_span(start),
    })
}

fn parse_attributes(
    cursor: &mut Cursor<'_>,
    _config: &JsxParserConfig,
    diagnostics: &mut Vec<JsxDiagnostic>,
    families: &mut Vec<JsxFeatureFamily>,
) -> Result<Vec<JsxAttribute>, JsxParseError> {
    let mut attrs = Vec::new();

    loop {
        cursor.skip_whitespace();

        // End of attributes: '>', '/>'
        if cursor.at_end() || cursor.peek() == Some('>') || cursor.peek_str(2) == "/>" {
            break;
        }

        // Spread attribute: `{...expr}`
        if cursor.peek_str(4) == "{..." {
            let start = cursor.span_start();
            cursor.advance(); // {
            cursor.advance(); // .
            cursor.advance(); // .
            cursor.advance(); // .
            let expr = read_until_balanced_brace(cursor);
            families.push(JsxFeatureFamily::SpreadAttribute);
            attrs.push(JsxAttribute::Spread {
                expression: expr,
                span: cursor.make_span(start),
            });
            continue;
        }

        // Named attribute
        let start = cursor.span_start();
        let attr_name = read_identifier(cursor);
        if attr_name.is_empty() {
            // Not an attribute, bail
            break;
        }

        if attr_name == "key" {
            families.push(JsxFeatureFamily::KeyProp);
        }

        cursor.skip_whitespace();

        // Check for `=`
        if cursor.peek() == Some('=') {
            cursor.advance(); // =
            cursor.skip_whitespace();

            if cursor.peek() == Some('"') || cursor.peek() == Some('\'') {
                let quote = cursor.advance().unwrap();
                let value = read_until_char(cursor, quote);
                families.push(JsxFeatureFamily::StringAttribute);
                attrs.push(JsxAttribute::Named {
                    name: attr_name,
                    value: JsxAttributeValue::StringLiteral { value },
                    span: cursor.make_span(start),
                });
            } else if cursor.peek() == Some('{') {
                cursor.advance(); // {
                let expr = read_until_balanced_brace(cursor);
                families.push(JsxFeatureFamily::ExpressionAttribute);
                attrs.push(JsxAttribute::Named {
                    name: attr_name,
                    value: JsxAttributeValue::Expression { expression: expr },
                    span: cursor.make_span(start),
                });
            } else {
                diagnostics.push(JsxDiagnostic {
                    code: JsxDiagnosticCode::InvalidAttributeValue,
                    severity: JsxDiagnosticSeverity::Error,
                    message: format!("Invalid value for attribute '{attr_name}'"),
                    span: Some(cursor.make_span(start)),
                });
                break;
            }
        } else {
            // Boolean shorthand: `<input disabled />`
            attrs.push(JsxAttribute::Named {
                name: attr_name,
                value: JsxAttributeValue::ImplicitTrue,
                span: cursor.make_span(start),
            });
        }
    }

    Ok(attrs)
}

fn parse_children(
    cursor: &mut Cursor<'_>,
    config: &JsxParserConfig,
    depth: usize,
    diagnostics: &mut Vec<JsxDiagnostic>,
    families: &mut Vec<JsxFeatureFamily>,
    closing_tag: Option<&str>,
) -> Result<Vec<JsxChild>, JsxParseError> {
    let mut children = Vec::new();

    loop {
        if cursor.at_end() {
            break;
        }

        // Check for closing tag or fragment close
        if let Some(tag) = closing_tag {
            let close_pattern = format!("</{tag}");
            if cursor.remaining().starts_with(&close_pattern) {
                break;
            }
        } else if cursor.peek_str(3) == "</>" {
            break;
        }

        // Also break on any `</` for mismatched tags
        if cursor.peek_str(2) == "</" {
            break;
        }

        // Child element or fragment
        if cursor.peek_str(2) == "<>" {
            families.push(JsxFeatureFamily::Fragment);
            let frag = parse_fragment(cursor, config, depth + 1, diagnostics, families)?;
            children.push(JsxChild::Fragment(Box::new(frag)));
            continue;
        }

        if cursor.peek() == Some('<') {
            families.push(JsxFeatureFamily::NestedElement);
            let element = parse_element(cursor, config, depth + 1, diagnostics, families)?;
            children.push(JsxChild::Element(Box::new(element)));
            continue;
        }

        // Expression child: `{expr}`
        if cursor.peek() == Some('{') {
            let start = cursor.span_start();
            cursor.advance(); // {
            let expr = read_until_balanced_brace(cursor);
            families.push(JsxFeatureFamily::ExpressionChild);
            children.push(JsxChild::ExpressionContainer {
                expression: expr,
                span: cursor.make_span(start),
            });
            continue;
        }

        // Text content
        let start = cursor.span_start();
        let mut text = String::new();
        while let Some(ch) = cursor.peek() {
            if ch == '<' || ch == '{' {
                break;
            }
            text.push(ch);
            cursor.advance();
        }
        if !text.is_empty() {
            families.push(JsxFeatureFamily::TextChild);
            children.push(JsxChild::Text {
                value: text,
                span: cursor.make_span(start),
            });
        }
    }

    Ok(children)
}

fn read_identifier(cursor: &mut Cursor<'_>) -> String {
    let mut name = String::new();
    while let Some(ch) = cursor.peek() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '$' {
            name.push(ch);
            cursor.advance();
        } else {
            break;
        }
    }
    name
}

fn read_until_char(cursor: &mut Cursor<'_>, terminator: char) -> String {
    let mut value = String::new();
    while let Some(ch) = cursor.peek() {
        if ch == terminator {
            cursor.advance(); // consume terminator
            break;
        }
        value.push(ch);
        cursor.advance();
    }
    value
}

fn read_until_balanced_brace(cursor: &mut Cursor<'_>) -> String {
    let mut depth = 1usize;
    let mut value = String::new();
    while let Some(ch) = cursor.peek() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth -= 1;
            if depth == 0 {
                cursor.advance(); // consume closing }
                break;
            }
        }
        value.push(ch);
        cursor.advance();
    }
    value
}

// ---------------------------------------------------------------------------
// Evidence Harness: Corpus
// ---------------------------------------------------------------------------

/// Expected outcome for a corpus specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsxExpectedOutcome {
    /// Parsing succeeds with a valid JSX node.
    ParsesOk,
    /// Parsing produces a fail-closed diagnostic.
    FailClosed,
}

impl JsxExpectedOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParsesOk => "parses_ok",
            Self::FailClosed => "fail_closed",
        }
    }
}

/// A single JSX corpus specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxSpecimen {
    pub specimen_id: String,
    pub feature_family: JsxFeatureFamily,
    pub source: String,
    pub expected_outcome: JsxExpectedOutcome,
    pub description: String,
}

/// Build the canonical JSX corpus.
pub fn jsx_corpus() -> Vec<JsxSpecimen> {
    vec![
        JsxSpecimen {
            specimen_id: "simple_div".into(),
            feature_family: JsxFeatureFamily::Element,
            source: "<div>hello</div>".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Simple div element with text child".into(),
        },
        JsxSpecimen {
            specimen_id: "self_closing_br".into(),
            feature_family: JsxFeatureFamily::SelfClosing,
            source: "<br />".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Self-closing intrinsic element".into(),
        },
        JsxSpecimen {
            specimen_id: "self_closing_component".into(),
            feature_family: JsxFeatureFamily::SelfClosing,
            source: "<Component />".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Self-closing component element".into(),
        },
        JsxSpecimen {
            specimen_id: "fragment".into(),
            feature_family: JsxFeatureFamily::Fragment,
            source: "<>text</>".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Fragment with text child".into(),
        },
        JsxSpecimen {
            specimen_id: "string_attribute".into(),
            feature_family: JsxFeatureFamily::StringAttribute,
            source: r#"<div className="app">x</div>"#.into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "String attribute on element".into(),
        },
        JsxSpecimen {
            specimen_id: "expression_attribute".into(),
            feature_family: JsxFeatureFamily::ExpressionAttribute,
            source: "<div count={42}>x</div>".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Expression attribute on element".into(),
        },
        JsxSpecimen {
            specimen_id: "spread_attribute".into(),
            feature_family: JsxFeatureFamily::SpreadAttribute,
            source: "<Comp {...props} />".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Spread attribute on component".into(),
        },
        JsxSpecimen {
            specimen_id: "expression_child".into(),
            feature_family: JsxFeatureFamily::ExpressionChild,
            source: "<div>{x + 1}</div>".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Expression child in element".into(),
        },
        JsxSpecimen {
            specimen_id: "text_child".into(),
            feature_family: JsxFeatureFamily::TextChild,
            source: "<p>Hello, world!</p>".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Text child in paragraph element".into(),
        },
        JsxSpecimen {
            specimen_id: "nested_elements".into(),
            feature_family: JsxFeatureFamily::NestedElement,
            source: "<div><span>inner</span></div>".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Nested elements".into(),
        },
        JsxSpecimen {
            specimen_id: "member_expr_name".into(),
            feature_family: JsxFeatureFamily::MemberExpressionName,
            source: "<Ctx.Provider>x</Ctx.Provider>".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Member expression element name".into(),
        },
        JsxSpecimen {
            specimen_id: "key_prop".into(),
            feature_family: JsxFeatureFamily::KeyProp,
            source: r#"<Item key="a" />"#.into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Key prop on component".into(),
        },
        JsxSpecimen {
            specimen_id: "boolean_attribute".into(),
            feature_family: JsxFeatureFamily::StringAttribute,
            source: "<input disabled />".into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Boolean shorthand attribute".into(),
        },
        JsxSpecimen {
            specimen_id: "multiple_attributes".into(),
            feature_family: JsxFeatureFamily::ExpressionAttribute,
            source: r#"<Btn onClick={handler} disabled className="primary" />"#.into(),
            expected_outcome: JsxExpectedOutcome::ParsesOk,
            description: "Element with multiple mixed attributes".into(),
        },
        JsxSpecimen {
            specimen_id: "empty_input".into(),
            feature_family: JsxFeatureFamily::Element,
            source: "".into(),
            expected_outcome: JsxExpectedOutcome::FailClosed,
            description: "Empty input rejects fail-closed".into(),
        },
        JsxSpecimen {
            specimen_id: "mismatched_tags".into(),
            feature_family: JsxFeatureFamily::Element,
            source: "<div>text</span>".into(),
            expected_outcome: JsxExpectedOutcome::FailClosed,
            description: "Mismatched opening and closing tags".into(),
        },
        JsxSpecimen {
            specimen_id: "missing_close".into(),
            feature_family: JsxFeatureFamily::Element,
            source: "<div>text".into(),
            expected_outcome: JsxExpectedOutcome::FailClosed,
            description: "Missing closing tag".into(),
        },
        JsxSpecimen {
            specimen_id: "no_jsx_prefix".into(),
            feature_family: JsxFeatureFamily::Element,
            source: "just text".into(),
            expected_outcome: JsxExpectedOutcome::FailClosed,
            description: "Input without JSX start marker".into(),
        },
    ]
}

// ---------------------------------------------------------------------------
// Evidence Harness: Runner
// ---------------------------------------------------------------------------

/// Verdict for a single specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsxVerdict {
    Pass,
    Fail,
    ExpectedFailure,
}

impl JsxVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::ExpectedFailure => "expected_failure",
        }
    }
}

/// Evidence from running a single specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxSpecimenEvidence {
    pub specimen_id: String,
    pub feature_family: JsxFeatureFamily,
    pub verdict: JsxVerdict,
    pub parse_succeeded: bool,
    pub diagnostic_count: usize,
}

/// Evidence event for the harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub specimen_id: String,
    pub verdict: JsxVerdict,
}

/// Run manifest for the evidence harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxRunManifest {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub specimen_count: usize,
    pub pass_count: usize,
    pub fail_count: usize,
    pub expected_failure_count: usize,
}

/// Inventory of evidence across all specimens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub specimens: Vec<JsxSpecimenEvidence>,
    pub family_coverage: BTreeMap<String, usize>,
    pub evidence_hash: String,
}

/// Run the corpus and produce evidence.
pub fn run_jsx_corpus(config: &JsxParserConfig) -> (JsxRunManifest, JsxEvidenceInventory, Vec<JsxEvidenceEvent>) {
    let corpus = jsx_corpus();
    let mut specimens = Vec::new();
    let mut events = Vec::new();
    let mut family_coverage: BTreeMap<String, usize> = BTreeMap::new();
    let mut pass_count = 0usize;
    let mut fail_count = 0usize;
    let mut expected_failure_count = 0usize;

    for spec in &corpus {
        let result = parse_jsx(&spec.source, config);
        let parse_ok = result.is_ok();
        let diag_count = match &result {
            Ok(r) => r.diagnostics.len(),
            Err(JsxParseError::FailClosed { diagnostics }) => diagnostics.len(),
            Err(_) => 0,
        };

        let verdict = match (&spec.expected_outcome, parse_ok) {
            (JsxExpectedOutcome::ParsesOk, true) => {
                pass_count += 1;
                JsxVerdict::Pass
            }
            (JsxExpectedOutcome::FailClosed, false) => {
                expected_failure_count += 1;
                JsxVerdict::ExpectedFailure
            }
            _ => {
                fail_count += 1;
                JsxVerdict::Fail
            }
        };

        *family_coverage
            .entry(spec.feature_family.as_str().to_string())
            .or_insert(0) += 1;

        specimens.push(JsxSpecimenEvidence {
            specimen_id: spec.specimen_id.clone(),
            feature_family: spec.feature_family,
            verdict,
            parse_succeeded: parse_ok,
            diagnostic_count: diag_count,
        });

        events.push(JsxEvidenceEvent {
            schema_version: JSX_PARSER_EVENT_SCHEMA_VERSION.to_string(),
            component: JSX_PARSER_COMPONENT.to_string(),
            specimen_id: spec.specimen_id.clone(),
            verdict,
        });
    }

    let mut hasher = Sha256::new();
    for ev in &specimens {
        hasher.update(ev.specimen_id.as_bytes());
        hasher.update(ev.verdict.as_str().as_bytes());
    }
    let evidence_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    let manifest = JsxRunManifest {
        schema_version: JSX_PARSER_MANIFEST_SCHEMA_VERSION.to_string(),
        component: JSX_PARSER_COMPONENT.to_string(),
        policy_id: JSX_PARSER_POLICY_ID.to_string(),
        specimen_count: corpus.len(),
        pass_count,
        fail_count,
        expected_failure_count,
    };

    let inventory = JsxEvidenceInventory {
        schema_version: JSX_PARSER_SCHEMA_VERSION.to_string(),
        component: JSX_PARSER_COMPONENT.to_string(),
        policy_id: JSX_PARSER_POLICY_ID.to_string(),
        specimens,
        family_coverage,
        evidence_hash,
    };

    (manifest, inventory, events)
}

/// Artifact paths for evidence bundle output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsxArtifactPaths {
    pub run_manifest: PathBuf,
    pub evidence_inventory: PathBuf,
    pub events_jsonl: PathBuf,
}

/// Write the evidence bundle to disk.
pub fn write_jsx_evidence_bundle(
    output_dir: &Path,
    manifest: &JsxRunManifest,
    inventory: &JsxEvidenceInventory,
    events: &[JsxEvidenceEvent],
) -> std::io::Result<JsxArtifactPaths> {
    std::fs::create_dir_all(output_dir)?;

    let manifest_path = output_dir.join("jsx_run_manifest.json");
    let inventory_path = output_dir.join("jsx_evidence_inventory.json");
    let events_path = output_dir.join("jsx_events.jsonl");

    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(manifest)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
    )?;
    std::fs::write(
        &inventory_path,
        serde_json::to_string_pretty(inventory)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
    )?;

    let mut events_content = String::new();
    for event in events {
        let line = serde_json::to_string(event)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        events_content.push_str(&line);
        events_content.push('\n');
    }
    std::fs::write(&events_path, events_content)?;

    Ok(JsxArtifactPaths {
        run_manifest: manifest_path,
        evidence_inventory: inventory_path,
        events_jsonl: events_path,
    })
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> JsxParserConfig {
        JsxParserConfig::default()
    }

    fn ns_config() -> JsxParserConfig {
        JsxParserConfig {
            allow_namespaced_names: true,
            ..default_config()
        }
    }

    // --- Runtime mode ---

    #[test]
    fn test_runtime_mode_all() {
        assert_eq!(JsxRuntimeMode::ALL.len(), 3);
        for mode in JsxRuntimeMode::ALL {
            assert!(!mode.as_str().is_empty());
            assert_eq!(mode.to_string(), mode.as_str());
        }
    }

    // --- Feature families ---

    #[test]
    fn test_feature_family_all() {
        assert_eq!(JsxFeatureFamily::ALL.len(), 12);
        let mut names: Vec<_> = JsxFeatureFamily::ALL.iter().map(|f| f.as_str()).collect();
        let unique: std::collections::BTreeSet<_> = names.iter().collect();
        assert_eq!(names.len(), unique.len(), "family names must be unique");
        names.sort();
    }

    #[test]
    fn test_feature_family_descriptions_non_empty() {
        for family in JsxFeatureFamily::ALL {
            assert!(!family.description().is_empty(), "{}", family.as_str());
        }
    }

    #[test]
    fn test_feature_family_display() {
        assert_eq!(JsxFeatureFamily::Element.to_string(), "element");
        assert_eq!(JsxFeatureFamily::Fragment.to_string(), "fragment");
    }

    // --- Diagnostic codes ---

    #[test]
    fn test_diagnostic_code_all_have_str() {
        for code in JsxDiagnosticCode::ALL {
            assert!(!code.as_str().is_empty());
            assert!(!code.message().is_empty());
            assert!(code.as_str().starts_with("FE-JSX-"));
        }
    }

    #[test]
    fn test_diagnostic_code_unique() {
        let codes: std::collections::BTreeSet<_> =
            JsxDiagnosticCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(codes.len(), JsxDiagnosticCode::ALL.len());
    }

    #[test]
    fn test_diagnostic_display() {
        let d = JsxDiagnostic {
            code: JsxDiagnosticCode::MissingClosingTag,
            severity: JsxDiagnosticSeverity::Error,
            message: "test".to_string(),
            span: None,
        };
        let s = d.to_string();
        assert!(s.contains("FE-JSX-0003"));
        assert!(s.contains("error"));
        assert!(s.contains("test"));
    }

    // --- Parsing: simple element ---

    #[test]
    fn test_parse_simple_div() {
        let result = parse_jsx("<div>hello</div>", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.name.to_string_repr(), "div");
                assert!(!el.self_closing);
                assert_eq!(el.children.len(), 1);
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_self_closing() {
        let result = parse_jsx("<br />", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert!(el.self_closing);
                assert!(el.children.is_empty());
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_component() {
        let result = parse_jsx("<App />", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert!(el.name.is_component());
                assert!(el.self_closing);
            }
            _ => panic!("expected element"),
        }
    }

    // --- Parsing: fragment ---

    #[test]
    fn test_parse_fragment() {
        let result = parse_jsx("<>hello</>", &default_config()).unwrap();
        match &result.node {
            JsxNode::Fragment(frag) => {
                assert_eq!(frag.children.len(), 1);
            }
            _ => panic!("expected fragment"),
        }
    }

    #[test]
    fn test_parse_fragment_with_element_child() {
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

    // --- Parsing: attributes ---

    #[test]
    fn test_parse_string_attribute() {
        let result = parse_jsx(r#"<div className="app">x</div>"#, &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.attributes.len(), 1);
                match &el.attributes[0] {
                    JsxAttribute::Named { name, value, .. } => {
                        assert_eq!(name, "className");
                        match value {
                            JsxAttributeValue::StringLiteral { value } => {
                                assert_eq!(value, "app");
                            }
                            _ => panic!("expected string literal"),
                        }
                    }
                    _ => panic!("expected named attribute"),
                }
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_expression_attribute() {
        let result = parse_jsx("<div count={42}>x</div>", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.attributes.len(), 1);
                match &el.attributes[0] {
                    JsxAttribute::Named { name, value, .. } => {
                        assert_eq!(name, "count");
                        match value {
                            JsxAttributeValue::Expression { expression } => {
                                assert_eq!(expression, "42");
                            }
                            _ => panic!("expected expression"),
                        }
                    }
                    _ => panic!("expected named attribute"),
                }
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_spread_attribute() {
        let result = parse_jsx("<Comp {...props} />", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.attributes.len(), 1);
                match &el.attributes[0] {
                    JsxAttribute::Spread { expression, .. } => {
                        assert_eq!(expression, "props");
                    }
                    _ => panic!("expected spread"),
                }
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_boolean_attribute() {
        let result = parse_jsx("<input disabled />", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.attributes.len(), 1);
                match &el.attributes[0] {
                    JsxAttribute::Named { name, value, .. } => {
                        assert_eq!(name, "disabled");
                        assert_eq!(*value, JsxAttributeValue::ImplicitTrue);
                    }
                    _ => panic!("expected named attribute"),
                }
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_multiple_attributes() {
        let result = parse_jsx(
            r#"<Btn onClick={handler} disabled className="primary" />"#,
            &default_config(),
        )
        .unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.attributes.len(), 3);
            }
            _ => panic!("expected element"),
        }
    }

    // --- Parsing: children ---

    #[test]
    fn test_parse_expression_child() {
        let result = parse_jsx("<div>{x + 1}</div>", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.children.len(), 1);
                match &el.children[0] {
                    JsxChild::ExpressionContainer { expression, .. } => {
                        assert_eq!(expression, "x + 1");
                    }
                    _ => panic!("expected expression child"),
                }
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_nested_elements() {
        let result = parse_jsx("<div><span>inner</span></div>", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.children.len(), 1);
                match &el.children[0] {
                    JsxChild::Element(inner) => {
                        assert_eq!(inner.name.to_string_repr(), "span");
                    }
                    _ => panic!("expected nested element"),
                }
            }
            _ => panic!("expected element"),
        }
    }

    // --- Parsing: element names ---

    #[test]
    fn test_parse_member_expression_name() {
        let result =
            parse_jsx("<Ctx.Provider>x</Ctx.Provider>", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.name.to_string_repr(), "Ctx.Provider");
                assert!(el.name.is_component());
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_parse_namespaced_name() {
        let result = parse_jsx("<svg:rect />", &ns_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.name.to_string_repr(), "svg:rect");
                assert!(!el.name.is_component());
            }
            _ => panic!("expected element"),
        }
    }

    #[test]
    fn test_is_component_lowercase() {
        let name = JsxElementName::Identifier {
            name: "div".into(),
            span: SourceSpan::new(0, 3, 1, 1, 1, 4),
        };
        assert!(!name.is_component());
    }

    #[test]
    fn test_is_component_uppercase() {
        let name = JsxElementName::Identifier {
            name: "App".into(),
            span: SourceSpan::new(0, 3, 1, 1, 1, 4),
        };
        assert!(name.is_component());
    }

    // --- Parsing: error cases ---

    #[test]
    fn test_empty_input_error() {
        let err = parse_jsx("", &default_config()).unwrap_err();
        assert!(matches!(err, JsxParseError::EmptyInput));
    }

    #[test]
    fn test_whitespace_only_error() {
        let err = parse_jsx("   \n  ", &default_config()).unwrap_err();
        assert!(matches!(err, JsxParseError::EmptyInput));
    }

    #[test]
    fn test_no_jsx_start() {
        let err = parse_jsx("just text", &default_config()).unwrap_err();
        match err {
            JsxParseError::FailClosed { diagnostics } => {
                assert!(!diagnostics.is_empty());
            }
            _ => panic!("expected FailClosed"),
        }
    }

    #[test]
    fn test_depth_exceeded() {
        let config = JsxParserConfig {
            max_depth: 2,
            ..default_config()
        };
        // Build deeply nested JSX
        let source = "<a><b><c>x</c></b></a>";
        let err = parse_jsx(source, &config).unwrap_err();
        assert!(matches!(err, JsxParseError::DepthExceeded { .. }));
    }

    #[test]
    fn test_mismatched_tags() {
        let result = parse_jsx("<div>text</span>", &default_config());
        // Should produce diagnostics about mismatched tags
        match result {
            Ok(r) => {
                assert!(r.diagnostics.iter().any(|d| d.code == JsxDiagnosticCode::UnmatchedClosingTag));
            }
            Err(JsxParseError::FailClosed { diagnostics }) => {
                assert!(!diagnostics.is_empty());
            }
            _ => panic!("expected diagnostic"),
        }
    }

    // --- Parsing: spans ---

    #[test]
    fn test_span_starts_at_zero() {
        let result = parse_jsx("<div />", &default_config()).unwrap();
        let span = result.node.span();
        assert_eq!(span.start_offset, 0);
        assert_eq!(span.start_line, 1);
        assert_eq!(span.start_column, 1);
    }

    #[test]
    fn test_span_covers_full_element() {
        let source = "<div>hello</div>";
        let result = parse_jsx(source, &default_config()).unwrap();
        let span = result.node.span();
        assert_eq!(span.start_offset, 0);
        assert_eq!(span.end_offset, source.len() as u64);
    }

    // --- Serde roundtrips ---

    #[test]
    fn test_serde_jsx_element() {
        let el = JsxElement {
            name: JsxElementName::Identifier {
                name: "div".into(),
                span: SourceSpan::new(0, 3, 1, 1, 1, 4),
            },
            attributes: vec![],
            children: vec![],
            self_closing: true,
            span: SourceSpan::new(0, 7, 1, 1, 1, 8),
        };
        let json = serde_json::to_string(&el).unwrap();
        let roundtrip: JsxElement = serde_json::from_str(&json).unwrap();
        assert_eq!(el, roundtrip);
    }

    #[test]
    fn test_serde_jsx_node() {
        let node = JsxNode::Fragment(JsxFragment {
            children: vec![JsxChild::Text {
                value: "hello".into(),
                span: SourceSpan::new(2, 7, 1, 3, 1, 8),
            }],
            span: SourceSpan::new(0, 10, 1, 1, 1, 11),
        });
        let json = serde_json::to_string(&node).unwrap();
        let roundtrip: JsxNode = serde_json::from_str(&json).unwrap();
        assert_eq!(node, roundtrip);
    }

    #[test]
    fn test_serde_config() {
        let config = JsxParserConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let roundtrip: JsxParserConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn test_serde_diagnostic() {
        let d = JsxDiagnostic {
            code: JsxDiagnosticCode::MissingClosingTag,
            severity: JsxDiagnosticSeverity::Error,
            message: "test".into(),
            span: Some(SourceSpan::new(0, 5, 1, 1, 1, 6)),
        };
        let json = serde_json::to_string(&d).unwrap();
        let roundtrip: JsxDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(d, roundtrip);
    }

    #[test]
    fn test_serde_parse_error() {
        let err = JsxParseError::DepthExceeded {
            depth: 100,
            limit: 64,
        };
        let json = serde_json::to_string(&err).unwrap();
        let roundtrip: JsxParseError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, roundtrip);
    }

    #[test]
    fn test_serde_run_manifest() {
        let m = JsxRunManifest {
            schema_version: JSX_PARSER_MANIFEST_SCHEMA_VERSION.into(),
            component: JSX_PARSER_COMPONENT.into(),
            policy_id: JSX_PARSER_POLICY_ID.into(),
            specimen_count: 10,
            pass_count: 8,
            fail_count: 0,
            expected_failure_count: 2,
        };
        let json = serde_json::to_string(&m).unwrap();
        let roundtrip: JsxRunManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, roundtrip);
    }

    #[test]
    fn test_serde_evidence_inventory() {
        let inv = JsxEvidenceInventory {
            schema_version: JSX_PARSER_SCHEMA_VERSION.into(),
            component: JSX_PARSER_COMPONENT.into(),
            policy_id: JSX_PARSER_POLICY_ID.into(),
            specimens: vec![],
            family_coverage: BTreeMap::new(),
            evidence_hash: "sha256:abc".into(),
        };
        let json = serde_json::to_string(&inv).unwrap();
        let roundtrip: JsxEvidenceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, roundtrip);
    }

    // --- Evidence harness ---

    #[test]
    fn test_corpus_non_empty() {
        let corpus = jsx_corpus();
        assert!(corpus.len() >= 15, "corpus should have >= 15 specimens");
    }

    #[test]
    fn test_corpus_ids_unique() {
        let corpus = jsx_corpus();
        let ids: std::collections::BTreeSet<_> = corpus.iter().map(|s| &s.specimen_id).collect();
        assert_eq!(ids.len(), corpus.len());
    }

    #[test]
    fn test_corpus_covers_all_families() {
        let corpus = jsx_corpus();
        let families: std::collections::BTreeSet<_> =
            corpus.iter().map(|s| s.feature_family).collect();
        for family in JsxFeatureFamily::ALL {
            if *family == JsxFeatureFamily::NamespacedName {
                continue; // Not in default corpus (needs allow_namespaced_names)
            }
            assert!(
                families.contains(family),
                "corpus missing family: {}",
                family.as_str()
            );
        }
    }

    #[test]
    fn test_run_corpus_no_failures() {
        let config = default_config();
        let (manifest, inventory, events) = run_jsx_corpus(&config);
        assert_eq!(manifest.fail_count, 0, "corpus should have no unexpected failures");
        assert!(manifest.pass_count > 0);
        assert!(manifest.expected_failure_count > 0);
        assert_eq!(manifest.specimen_count, inventory.specimens.len());
        assert_eq!(events.len(), manifest.specimen_count);
    }

    #[test]
    fn test_run_corpus_deterministic() {
        let config = default_config();
        let (m1, inv1, _) = run_jsx_corpus(&config);
        let (m2, inv2, _) = run_jsx_corpus(&config);
        assert_eq!(m1, m2);
        assert_eq!(inv1.evidence_hash, inv2.evidence_hash);
    }

    #[test]
    fn test_evidence_hash_non_empty() {
        let config = default_config();
        let (_, inventory, _) = run_jsx_corpus(&config);
        assert!(inventory.evidence_hash.starts_with("sha256:"));
        assert!(inventory.evidence_hash.len() > 10);
    }

    // --- Config defaults ---

    #[test]
    fn test_config_defaults() {
        let config = JsxParserConfig::default();
        assert_eq!(config.runtime_mode, JsxRuntimeMode::Automatic);
        assert_eq!(config.max_depth, 64);
        assert!(!config.allow_namespaced_names);
        assert!(!config.tsx_mode);
    }

    // --- Parse error display ---

    #[test]
    fn test_parse_error_display() {
        let err = JsxParseError::EmptyInput;
        assert_eq!(err.to_string(), "JSX input is empty");

        let err2 = JsxParseError::DepthExceeded {
            depth: 100,
            limit: 64,
        };
        assert!(err2.to_string().contains("100"));
        assert!(err2.to_string().contains("64"));
    }

    // --- Schema version consistency ---

    #[test]
    fn test_schema_versions_non_empty() {
        assert!(!JSX_PARSER_SCHEMA_VERSION.is_empty());
        assert!(!JSX_PARSER_MANIFEST_SCHEMA_VERSION.is_empty());
        assert!(!JSX_PARSER_EVENT_SCHEMA_VERSION.is_empty());
        assert!(!JSX_PARSER_COMPONENT.is_empty());
        assert!(!JSX_PARSER_POLICY_ID.is_empty());
    }

    #[test]
    fn test_schema_versions_unique() {
        let versions = [
            JSX_PARSER_SCHEMA_VERSION,
            JSX_PARSER_MANIFEST_SCHEMA_VERSION,
            JSX_PARSER_EVENT_SCHEMA_VERSION,
        ];
        let unique: std::collections::BTreeSet<_> = versions.iter().collect();
        assert_eq!(versions.len(), unique.len());
    }

    // --- Key prop detection ---

    #[test]
    fn test_key_prop_detected() {
        let result = parse_jsx(r#"<Item key="a" />"#, &default_config()).unwrap();
        assert!(result
            .feature_families_used
            .contains(&JsxFeatureFamily::KeyProp));
    }

    // --- Mixed children ---

    #[test]
    fn test_mixed_children() {
        let result =
            parse_jsx("<div>text{expr}<span /></div>", &default_config()).unwrap();
        match &result.node {
            JsxNode::Element(el) => {
                assert_eq!(el.children.len(), 3);
                assert!(matches!(el.children[0], JsxChild::Text { .. }));
                assert!(matches!(el.children[1], JsxChild::ExpressionContainer { .. }));
                assert!(matches!(el.children[2], JsxChild::Element(_)));
            }
            _ => panic!("expected element"),
        }
    }

    // --- Attribute value enum ---

    #[test]
    fn test_attribute_value_implicit_true_serde() {
        let val = JsxAttributeValue::ImplicitTrue;
        let json = serde_json::to_string(&val).unwrap();
        let roundtrip: JsxAttributeValue = serde_json::from_str(&json).unwrap();
        assert_eq!(val, roundtrip);
    }

    // --- Inventory counts ---

    #[test]
    fn test_inventory_counts_consistent() {
        let config = default_config();
        let (manifest, inventory, events) = run_jsx_corpus(&config);
        let total = manifest.pass_count + manifest.fail_count + manifest.expected_failure_count;
        assert_eq!(total, manifest.specimen_count);
        assert_eq!(inventory.specimens.len(), manifest.specimen_count);
        assert_eq!(events.len(), manifest.specimen_count);
    }

    // --- Family coverage ---

    #[test]
    fn test_family_coverage_complete() {
        let config = default_config();
        let (_, inventory, _) = run_jsx_corpus(&config);
        assert!(!inventory.family_coverage.is_empty());
        // Every specimen family should appear in coverage
        for specimen in &inventory.specimens {
            assert!(inventory
                .family_coverage
                .contains_key(specimen.feature_family.as_str()));
        }
    }
}
