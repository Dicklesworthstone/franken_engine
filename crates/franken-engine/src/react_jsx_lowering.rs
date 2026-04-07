//! Native React lowering for classic and automatic JSX runtime modes.
//!
//! This module transforms parsed JSX/TSX AST nodes into deterministic IR1
//! operations that implement React's element-creation semantics. Two runtime
//! modes are supported:
//!
//! - **Classic**: `React.createElement(type, props, ...children)`
//! - **Automatic**: `jsx(type, { ...props, children })` / `jsxs(type, { ...props, children })`
//!
//! Fragment lowering, key/ref extraction, dev-vs-prod metadata contracts,
//! spread attribute merging, and deterministic compile receipts are all handled.
//! Every lowering decision carries an explicit reason and fail-closed diagnostic
//! when the input is rejected.
//!
//! Reference: [RGC-206B]

use std::collections::BTreeMap;
use std::fmt;

use crate::ast::SourceSpan;
use crate::hash_tiers::ContentHash;
use crate::jsx_tsx_parser::{
    JsxAttribute, JsxAttributeValue, JsxChild, JsxElement, JsxElementName, JsxFeatureFamily,
    JsxFragment, JsxNode, JsxParseResult, JsxRuntimeMode,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the React lowering contract.
pub const REACT_LOWERING_SCHEMA_VERSION: &str = "franken-engine.react-jsx-lowering.v1";
/// Component name for evidence linkage.
pub const REACT_LOWERING_COMPONENT: &str = "react_jsx_lowering";
/// Policy ID binding.
pub const REACT_LOWERING_POLICY_ID: &str = "RGC-206B";

/// Classic mode: the global object whose `.createElement` method is called.
const CLASSIC_REACT_OBJECT: &str = "React";
/// Classic mode: the method name on the React object.
const CLASSIC_CREATE_ELEMENT: &str = "createElement";
/// Automatic mode: the module specifier for JSX runtime.
const AUTOMATIC_RUNTIME_MODULE: &str = "react/jsx-runtime";
/// Automatic mode: the dev module specifier.
const AUTOMATIC_RUNTIME_DEV_MODULE: &str = "react/jsx-dev-runtime";
/// Automatic mode: single-child factory name.
const AUTOMATIC_JSX: &str = "jsx";
/// Automatic mode: multiple-children factory name.
const AUTOMATIC_JSXS: &str = "jsxs";
/// Automatic mode: dev factory name.
const AUTOMATIC_JSX_DEV: &str = "jsxDEV";
/// Fragment symbol name.
const FRAGMENT_SYMBOL: &str = "Fragment";
/// Default classic fragment pragma.
const CLASSIC_FRAGMENT_DEFAULT: &str = "React.Fragment";

/// Maximum lowering depth to prevent stack overflow on pathological input.
const MAX_LOWERING_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// Lowering Configuration
// ---------------------------------------------------------------------------

/// Whether the build is a development or production build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildMode {
    /// Development: include `__source`, `__self`, line/column metadata.
    Development,
    /// Production: strip dev-only metadata for smaller output.
    Production,
}

impl BuildMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Production => "production",
        }
    }
}

impl fmt::Display for BuildMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration for the React lowering pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactLoweringConfig {
    /// Runtime mode: Classic or Automatic.
    pub runtime_mode: JsxRuntimeMode,
    /// Build mode: dev or prod.
    pub build_mode: BuildMode,
    /// Source file path for dev metadata.
    pub source_file: Option<String>,
    /// Whether to emit `__self` in dev mode.
    pub emit_self: bool,
    /// Whether to emit `__source` location metadata in dev mode.
    pub emit_source: bool,
    /// Custom pragma for classic mode (e.g., "h" for Preact).
    pub classic_pragma: Option<String>,
    /// Custom pragma for fragments in classic mode.
    pub classic_fragment_pragma: Option<String>,
    /// Automatic runtime import source override.
    pub automatic_import_source: Option<String>,
    /// Maximum lowering depth.
    pub max_depth: usize,
}

impl Default for ReactLoweringConfig {
    fn default() -> Self {
        Self {
            runtime_mode: JsxRuntimeMode::Automatic,
            build_mode: BuildMode::Production,
            source_file: None,
            emit_self: true,
            emit_source: true,
            classic_pragma: None,
            classic_fragment_pragma: None,
            automatic_import_source: None,
            max_depth: MAX_LOWERING_DEPTH,
        }
    }
}

impl ReactLoweringConfig {
    /// Returns the factory object/function for classic mode.
    pub fn classic_object(&self) -> &str {
        self.classic_pragma
            .as_deref()
            .unwrap_or(CLASSIC_REACT_OBJECT)
    }

    /// Returns the fragment pragma for classic mode.
    pub fn classic_fragment(&self) -> &str {
        self.classic_fragment_pragma
            .as_deref()
            .unwrap_or(CLASSIC_FRAGMENT_DEFAULT)
    }

    /// Returns the automatic runtime import source.
    pub fn automatic_import(&self) -> &str {
        self.automatic_import_source
            .as_deref()
            .unwrap_or(match self.build_mode {
                BuildMode::Development => AUTOMATIC_RUNTIME_DEV_MODULE,
                BuildMode::Production => AUTOMATIC_RUNTIME_MODULE,
            })
    }

    /// Returns the JSX factory name for automatic mode.
    pub fn automatic_factory(&self, child_count: usize) -> &'static str {
        match self.build_mode {
            BuildMode::Development => AUTOMATIC_JSX_DEV,
            BuildMode::Production => {
                if child_count <= 1 {
                    AUTOMATIC_JSX
                } else {
                    AUTOMATIC_JSXS
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lowered IR Nodes
// ---------------------------------------------------------------------------

/// The type argument in a React.createElement / jsx call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ElementType {
    /// Intrinsic element: `"div"`, `"span"`, etc. — emitted as a string literal.
    Intrinsic { tag: String },
    /// Component reference: `Component`, `Ctx.Provider` — emitted as an identifier.
    Component { name: String },
    /// Fragment: `React.Fragment` or `Fragment` symbol.
    Fragment,
}

impl ElementType {
    /// Derive from a JSX element name.
    pub fn from_jsx_name(name: &JsxElementName) -> Self {
        if name.is_component() {
            Self::Component {
                name: name.to_string_repr(),
            }
        } else {
            Self::Intrinsic {
                tag: name.to_string_repr(),
            }
        }
    }

    /// Canonical string for hashing.
    pub fn canonical_value(&self) -> String {
        match self {
            Self::Intrinsic { tag } => format!("intrinsic:{tag}"),
            Self::Component { name } => format!("component:{name}"),
            Self::Fragment => "fragment".to_string(),
        }
    }
}

/// A single prop (key-value pair) in the lowered props object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum LoweredPropValue {
    /// String literal value.
    StringLiteral { value: String },
    /// Boolean `true` (implicit attribute like `<input disabled />`).
    BooleanTrue,
    /// Expression reference (opaque expression text).
    Expression { expression: String },
    /// Null literal.
    Null,
    /// A nested lowered element (child).
    Element(Box<LoweredElement>),
    /// An array of lowered children.
    ChildrenArray { children: Vec<LoweredChild> },
}

/// A named prop in the lowered output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredProp {
    /// Property name.
    pub name: String,
    /// Property value.
    pub value: LoweredPropValue,
    /// Source span of the attribute.
    pub span: Option<SourceSpan>,
}

/// A spread entry in the props construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum PropsEntry {
    /// A single named prop.
    Named(LoweredProp),
    /// A spread expression: `{...expr}`.
    Spread {
        expression: String,
        span: SourceSpan,
    },
}

/// The props object for a lowered element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredProps {
    /// Ordered entries (named props and spreads interleaved).
    pub entries: Vec<PropsEntry>,
    /// Whether spreads are present (requires runtime merging).
    pub has_spreads: bool,
    /// The extracted `key` prop, if any.
    pub extracted_key: Option<LoweredPropValue>,
    /// The extracted `ref` prop, if any.
    pub extracted_ref: Option<LoweredPropValue>,
}

impl LoweredProps {
    /// Returns the number of named props (excluding spreads).
    pub fn named_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| matches!(e, PropsEntry::Named(_)))
            .count()
    }

    /// Whether this is an empty props (null in classic mode).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.extracted_key.is_none() && self.extracted_ref.is_none()
    }
}

/// A lowered child node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum LoweredChild {
    /// String literal (from JSX text content).
    Text { value: String, span: SourceSpan },
    /// Expression child.
    Expression {
        expression: String,
        span: SourceSpan,
    },
    /// A nested lowered element.
    Element(Box<LoweredElement>),
}

/// Dev-mode source location metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Source file path.
    pub file_name: Option<String>,
    /// 1-based line number.
    pub line_number: u32,
    /// 0-based column number.
    pub column_number: u32,
}

/// The call convention describing how the lowered element is emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CallConvention {
    /// Classic: `React.createElement(type, props, ...children)`
    Classic { object: String, method: String },
    /// Automatic: `jsx(type, props)` or `jsxs(type, props)` or `jsxDEV(type, props, key, isStaticChildren, source, self)`
    Automatic {
        factory: String,
        import_source: String,
    },
}

/// A fully lowered React element — the output of the lowering pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweredElement {
    /// The element type (intrinsic, component, or fragment).
    pub element_type: ElementType,
    /// The lowered props object.
    pub props: LoweredProps,
    /// Children (only used in classic mode; automatic mode puts children in props).
    pub children: Vec<LoweredChild>,
    /// The call convention used.
    pub call_convention: CallConvention,
    /// Dev-mode source location.
    pub source_location: Option<SourceLocation>,
    /// Whether this element has static children (for jsxs).
    pub is_static_children: bool,
    /// The depth at which this element was lowered.
    pub depth: usize,
    /// Source span of the original JSX element.
    pub span: SourceSpan,
}

// ---------------------------------------------------------------------------
// Lowering Diagnostics
// ---------------------------------------------------------------------------

/// Diagnostic severity for lowering issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweringDiagnosticSeverity {
    /// Informational: lowering succeeded but with a note.
    Info,
    /// Warning: lowering succeeded but with a caveat.
    Warning,
    /// Error: lowering failed for this node.
    Error,
}

/// Diagnostic codes for lowering issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LoweringDiagnosticCode {
    /// FE-RJL-0001: Preserve mode — no lowering performed.
    PreserveModeNoOp,
    /// FE-RJL-0002: Maximum lowering depth exceeded.
    DepthExceeded,
    /// FE-RJL-0003: Spread attribute requires runtime merging.
    SpreadRequiresRuntime,
    /// FE-RJL-0004: Namespaced element name in React (non-standard).
    NamespacedElement,
    /// FE-RJL-0005: Key prop on fragment (must be propagated).
    KeyOnFragment,
    /// FE-RJL-0006: Ref prop on fragment (invalid).
    RefOnFragment,
    /// FE-RJL-0007: Empty JSX text trimmed.
    EmptyTextTrimmed,
    /// FE-RJL-0008: Dev metadata emitted.
    DevMetadataEmitted,
    /// FE-RJL-0009: Children flattened into props (automatic mode).
    ChildrenInProps,
    /// FE-RJL-0010: Duplicate key prop detected.
    DuplicateKey,
}

impl LoweringDiagnosticCode {
    pub const fn code_str(self) -> &'static str {
        match self {
            Self::PreserveModeNoOp => "FE-RJL-0001",
            Self::DepthExceeded => "FE-RJL-0002",
            Self::SpreadRequiresRuntime => "FE-RJL-0003",
            Self::NamespacedElement => "FE-RJL-0004",
            Self::KeyOnFragment => "FE-RJL-0005",
            Self::RefOnFragment => "FE-RJL-0006",
            Self::EmptyTextTrimmed => "FE-RJL-0007",
            Self::DevMetadataEmitted => "FE-RJL-0008",
            Self::ChildrenInProps => "FE-RJL-0009",
            Self::DuplicateKey => "FE-RJL-0010",
        }
    }
}

impl fmt::Display for LoweringDiagnosticCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code_str())
    }
}

/// A diagnostic emitted during lowering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringDiagnostic {
    /// Diagnostic code.
    pub code: LoweringDiagnosticCode,
    /// Severity level.
    pub severity: LoweringDiagnosticSeverity,
    /// Human-readable message.
    pub message: String,
    /// Source span where the issue occurred.
    pub span: Option<SourceSpan>,
}

// ---------------------------------------------------------------------------
// Lowering Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during React lowering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ReactLoweringError {
    /// The runtime mode is Preserve — no lowering should be performed.
    PreserveMode,
    /// Lowering depth exceeded the configured maximum.
    DepthExceeded { max_depth: usize, span: SourceSpan },
    /// An internal lowering invariant was violated.
    InternalError { message: String },
}

impl fmt::Display for ReactLoweringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreserveMode => write!(f, "JSX preserve mode: no lowering performed"),
            Self::DepthExceeded { max_depth, .. } => {
                write!(f, "JSX lowering depth exceeded maximum of {max_depth}")
            }
            Self::InternalError { message } => {
                write!(f, "internal lowering error: {message}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Lowering Result
// ---------------------------------------------------------------------------

/// The result of lowering a JSX parse result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactLoweringResult {
    /// The lowered element tree.
    pub element: LoweredElement,
    /// Diagnostics emitted during lowering.
    pub diagnostics: Vec<LoweringDiagnostic>,
    /// Runtime imports required by the lowered output.
    pub required_imports: Vec<RequiredImport>,
    /// Feature families encountered during lowering.
    pub feature_families_used: Vec<JsxFeatureFamily>,
    /// Lowering statistics.
    pub stats: LoweringStats,
}

/// A runtime import required by the lowered output.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequiredImport {
    /// The module specifier to import from.
    pub source: String,
    /// The named import binding.
    pub name: String,
    /// Whether this is a default import.
    pub is_default: bool,
}

/// Statistics about the lowering pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringStats {
    /// Total elements lowered.
    pub elements_lowered: u32,
    /// Total fragments lowered.
    pub fragments_lowered: u32,
    /// Total text children processed.
    pub text_children: u32,
    /// Total expression children processed.
    pub expression_children: u32,
    /// Total spreads encountered.
    pub spread_attributes: u32,
    /// Maximum depth reached.
    pub max_depth_reached: u32,
    /// Total props processed.
    pub total_props: u32,
    /// Keys extracted.
    pub keys_extracted: u32,
    /// Refs extracted.
    pub refs_extracted: u32,
}

// ---------------------------------------------------------------------------
// Compile Receipts
// ---------------------------------------------------------------------------

/// A deterministic compile receipt for a lowering pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringCompileReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Content hash of the input parse result.
    pub input_hash: ContentHash,
    /// Content hash of the lowered output.
    pub output_hash: ContentHash,
    /// The configuration used.
    pub config_summary: ConfigSummary,
    /// Lowering stats.
    pub stats: LoweringStats,
    /// Number of diagnostics.
    pub diagnostic_count: u32,
    /// Number of required imports.
    pub import_count: u32,
}

/// Summary of the lowering config for receipt purposes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub runtime_mode: String,
    pub build_mode: String,
    pub has_custom_pragma: bool,
    pub has_custom_fragment: bool,
    pub has_custom_import_source: bool,
}

impl ConfigSummary {
    pub fn from_config(config: &ReactLoweringConfig) -> Self {
        Self {
            runtime_mode: config.runtime_mode.as_str().to_string(),
            build_mode: config.build_mode.as_str().to_string(),
            has_custom_pragma: config.classic_pragma.is_some(),
            has_custom_fragment: config.classic_fragment_pragma.is_some(),
            has_custom_import_source: config.automatic_import_source.is_some(),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence Harness Types
// ---------------------------------------------------------------------------

/// A lowering specimen for the evidence corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringSpecimen {
    /// Specimen label.
    pub label: String,
    /// The JSX node to lower.
    pub node: JsxNode,
    /// Feature families exercised.
    pub features: Vec<JsxFeatureFamily>,
    /// Expected element type in the output.
    pub expected_element_type: String,
    /// Expected child count.
    pub expected_child_count: usize,
}

/// Verdict for a single specimen lowering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweringVerdict {
    /// Lowering succeeded and matches expectations.
    Pass,
    /// Lowering succeeded but with unexpected diagnostics.
    PassWithDiagnostics,
    /// Lowering failed.
    Fail,
    /// Specimen was skipped (e.g., preserve mode).
    Skipped,
}

/// Evidence for a single specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringSpecimenEvidence {
    pub label: String,
    pub verdict: LoweringVerdict,
    pub element_type_match: bool,
    pub child_count_match: bool,
    pub diagnostic_count: u32,
    pub error: Option<String>,
}

/// Run manifest for the lowering corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringRunManifest {
    pub schema_version: String,
    pub total_specimens: u32,
    pub pass_count: u32,
    pub fail_count: u32,
    pub skip_count: u32,
    pub evidence: Vec<LoweringSpecimenEvidence>,
    pub manifest_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Core Lowering Functions
// ---------------------------------------------------------------------------

/// Lower a parsed JSX node into a React element call tree.
///
/// This is the main entry point for React JSX lowering.
pub fn lower_jsx_to_react(
    node: &JsxNode,
    config: &ReactLoweringConfig,
) -> Result<ReactLoweringResult, ReactLoweringError> {
    if config.runtime_mode == JsxRuntimeMode::Preserve {
        return Err(ReactLoweringError::PreserveMode);
    }

    let mut ctx = LoweringCtx {
        config,
        diagnostics: Vec::new(),
        imports: BTreeMap::new(),
        stats: LoweringStats::default(),
        feature_families: BTreeMap::new(),
    };

    let element = ctx.lower_node(node, 0)?;

    // Collect required imports
    let required_imports: Vec<RequiredImport> = ctx.imports.into_values().collect();

    let feature_families: Vec<JsxFeatureFamily> = ctx.feature_families.keys().copied().collect();

    Ok(ReactLoweringResult {
        element,
        diagnostics: ctx.diagnostics,
        required_imports,
        feature_families_used: feature_families,
        stats: ctx.stats,
    })
}

/// Lower a `JsxParseResult` directly.
pub fn lower_parse_result(
    parse_result: &JsxParseResult,
    config: &ReactLoweringConfig,
) -> Result<ReactLoweringResult, ReactLoweringError> {
    lower_jsx_to_react(&parse_result.node, config)
}

/// Compute a deterministic compile receipt for a lowering pass.
pub fn compute_lowering_receipt(
    input: &JsxParseResult,
    result: &ReactLoweringResult,
    config: &ReactLoweringConfig,
) -> LoweringCompileReceipt {
    let input_bytes = serde_json::to_vec(input).unwrap_or_default();
    let output_bytes = serde_json::to_vec(&result.element).unwrap_or_default();

    LoweringCompileReceipt {
        schema_version: REACT_LOWERING_SCHEMA_VERSION.to_string(),
        input_hash: ContentHash::compute(&input_bytes),
        output_hash: ContentHash::compute(&output_bytes),
        config_summary: ConfigSummary::from_config(config),
        stats: result.stats.clone(),
        diagnostic_count: result.diagnostics.len() as u32,
        import_count: result.required_imports.len() as u32,
    }
}

// ---------------------------------------------------------------------------
// Internal Lowering Context
// ---------------------------------------------------------------------------

/// Input to `build_lowered_element` (avoids too-many-arguments).
struct BuildElementInput {
    element_type: ElementType,
    props: LoweredProps,
    children: Vec<LoweredChild>,
    source_location: Option<SourceLocation>,
    is_static_children: bool,
    depth: usize,
    span: SourceSpan,
}

struct LoweringCtx<'a> {
    config: &'a ReactLoweringConfig,
    diagnostics: Vec<LoweringDiagnostic>,
    imports: BTreeMap<String, RequiredImport>,
    stats: LoweringStats,
    feature_families: BTreeMap<JsxFeatureFamily, u32>,
}

impl<'a> LoweringCtx<'a> {
    fn record_feature(&mut self, family: JsxFeatureFamily) {
        *self.feature_families.entry(family).or_insert(0) += 1;
    }

    fn emit_diagnostic(
        &mut self,
        code: LoweringDiagnosticCode,
        severity: LoweringDiagnosticSeverity,
        message: String,
        span: Option<SourceSpan>,
    ) {
        self.diagnostics.push(LoweringDiagnostic {
            code,
            severity,
            message,
            span,
        });
    }

    fn require_import(&mut self, source: &str, name: &str) {
        let key = format!("{source}::{name}");
        self.imports.entry(key).or_insert_with(|| RequiredImport {
            source: source.to_string(),
            name: name.to_string(),
            is_default: false,
        });
    }

    fn lower_node(
        &mut self,
        node: &JsxNode,
        depth: usize,
    ) -> Result<LoweredElement, ReactLoweringError> {
        match node {
            JsxNode::Element(el) => self.lower_element(el, depth),
            JsxNode::Fragment(frag) => self.lower_fragment(frag, depth),
        }
    }

    fn lower_element(
        &mut self,
        element: &JsxElement,
        depth: usize,
    ) -> Result<LoweredElement, ReactLoweringError> {
        if depth >= self.config.max_depth {
            return Err(ReactLoweringError::DepthExceeded {
                max_depth: self.config.max_depth,
                span: element.span.clone(),
            });
        }

        self.stats.elements_lowered += 1;
        if depth as u32 > self.stats.max_depth_reached {
            self.stats.max_depth_reached = depth as u32;
        }

        // Record feature families
        if element.self_closing {
            self.record_feature(JsxFeatureFamily::SelfClosing);
        } else {
            self.record_feature(JsxFeatureFamily::Element);
        }

        // Determine element type
        let element_type = ElementType::from_jsx_name(&element.name);

        // Check for namespaced elements
        if matches!(&element.name, JsxElementName::NamespacedName { .. }) {
            self.record_feature(JsxFeatureFamily::NamespacedName);
            self.emit_diagnostic(
                LoweringDiagnosticCode::NamespacedElement,
                LoweringDiagnosticSeverity::Warning,
                format!(
                    "Namespaced element '{}' is non-standard in React",
                    element.name.to_string_repr()
                ),
                Some(element.span.clone()),
            );
        }

        if matches!(&element.name, JsxElementName::MemberExpression { .. }) {
            self.record_feature(JsxFeatureFamily::MemberExpressionName);
        }

        // Lower props
        let props = self.lower_attributes(&element.attributes, &element.span)?;

        // Lower children
        let children = self.lower_children(&element.children, depth)?;

        // Build source location for dev mode
        let source_location = self.build_source_location(&element.span);

        // Determine static children flag: true only when there are multiple
        // children AND all of them are statically-known (text or element, not
        // expression). An empty list is not "static children".
        let is_static_children = children.len() > 1
            && children
                .iter()
                .all(|c| matches!(c, LoweredChild::Text { .. } | LoweredChild::Element(_)));

        // Build the call convention and lowered element
        self.build_lowered_element(BuildElementInput {
            element_type,
            props,
            children,
            source_location,
            is_static_children,
            depth,
            span: element.span.clone(),
        })
    }

    fn lower_fragment(
        &mut self,
        fragment: &JsxFragment,
        depth: usize,
    ) -> Result<LoweredElement, ReactLoweringError> {
        if depth >= self.config.max_depth {
            return Err(ReactLoweringError::DepthExceeded {
                max_depth: self.config.max_depth,
                span: fragment.span.clone(),
            });
        }

        self.stats.fragments_lowered += 1;
        self.record_feature(JsxFeatureFamily::Fragment);

        if depth as u32 > self.stats.max_depth_reached {
            self.stats.max_depth_reached = depth as u32;
        }

        let children = self.lower_children(&fragment.children, depth)?;
        let source_location = self.build_source_location(&fragment.span);

        let is_static_children = children.len() > 1;

        let props = LoweredProps {
            entries: Vec::new(),
            has_spreads: false,
            extracted_key: None,
            extracted_ref: None,
        };

        // Add fragment import
        self.add_fragment_import();

        self.build_lowered_element(BuildElementInput {
            element_type: ElementType::Fragment,
            props,
            children,
            source_location,
            is_static_children,
            depth,
            span: fragment.span.clone(),
        })
    }

    fn lower_attributes(
        &mut self,
        attributes: &[JsxAttribute],
        _element_span: &SourceSpan,
    ) -> Result<LoweredProps, ReactLoweringError> {
        let mut entries = Vec::new();
        let mut extracted_key: Option<LoweredPropValue> = None;
        let mut extracted_ref: Option<LoweredPropValue> = None;
        let mut has_spreads = false;
        let mut seen_key = false;

        for attr in attributes {
            match attr {
                JsxAttribute::Named { name, value, span } => {
                    self.stats.total_props += 1;

                    let lowered_value = match value {
                        JsxAttributeValue::StringLiteral { value } => {
                            self.record_feature(JsxFeatureFamily::StringAttribute);
                            LoweredPropValue::StringLiteral {
                                value: value.clone(),
                            }
                        }
                        JsxAttributeValue::Expression { expression } => {
                            self.record_feature(JsxFeatureFamily::ExpressionAttribute);
                            LoweredPropValue::Expression {
                                expression: expression.clone(),
                            }
                        }
                        JsxAttributeValue::ImplicitTrue => {
                            self.record_feature(JsxFeatureFamily::StringAttribute);
                            LoweredPropValue::BooleanTrue
                        }
                    };

                    // Extract key and ref — they are not passed as regular props in React
                    if name == "key" {
                        self.record_feature(JsxFeatureFamily::KeyProp);
                        if seen_key {
                            self.emit_diagnostic(
                                LoweringDiagnosticCode::DuplicateKey,
                                LoweringDiagnosticSeverity::Warning,
                                "Duplicate key prop detected; last value wins".to_string(),
                                Some(span.clone()),
                            );
                        }
                        seen_key = true;
                        self.stats.keys_extracted += 1;
                        extracted_key = Some(lowered_value);
                        continue;
                    }

                    if name == "ref" {
                        self.stats.refs_extracted += 1;
                        extracted_ref = Some(lowered_value);
                        continue;
                    }

                    entries.push(PropsEntry::Named(LoweredProp {
                        name: name.clone(),
                        value: lowered_value,
                        span: Some(span.clone()),
                    }));
                }
                JsxAttribute::Spread { expression, span } => {
                    self.record_feature(JsxFeatureFamily::SpreadAttribute);
                    self.stats.spread_attributes += 1;
                    has_spreads = true;
                    self.emit_diagnostic(
                        LoweringDiagnosticCode::SpreadRequiresRuntime,
                        LoweringDiagnosticSeverity::Info,
                        "Spread attribute requires runtime Object.assign or equivalent".to_string(),
                        Some(span.clone()),
                    );
                    entries.push(PropsEntry::Spread {
                        expression: expression.clone(),
                        span: span.clone(),
                    });
                }
            }
        }

        Ok(LoweredProps {
            entries,
            has_spreads,
            extracted_key,
            extracted_ref,
        })
    }

    fn lower_children(
        &mut self,
        children: &[JsxChild],
        depth: usize,
    ) -> Result<Vec<LoweredChild>, ReactLoweringError> {
        let mut lowered = Vec::new();

        for child in children {
            match child {
                JsxChild::Text { value, span } => {
                    // Trim whitespace-only text nodes (React convention)
                    let trimmed = trim_jsx_text(value);
                    if trimmed.is_empty() {
                        self.emit_diagnostic(
                            LoweringDiagnosticCode::EmptyTextTrimmed,
                            LoweringDiagnosticSeverity::Info,
                            "Whitespace-only JSX text node trimmed".to_string(),
                            Some(span.clone()),
                        );
                        continue;
                    }
                    self.record_feature(JsxFeatureFamily::TextChild);
                    self.stats.text_children += 1;
                    lowered.push(LoweredChild::Text {
                        value: trimmed,
                        span: span.clone(),
                    });
                }
                JsxChild::ExpressionContainer { expression, span } => {
                    self.record_feature(JsxFeatureFamily::ExpressionChild);
                    self.stats.expression_children += 1;
                    lowered.push(LoweredChild::Expression {
                        expression: expression.clone(),
                        span: span.clone(),
                    });
                }
                JsxChild::Element(el) => {
                    self.record_feature(JsxFeatureFamily::NestedElement);
                    let nested = self.lower_element(el, depth + 1)?;
                    lowered.push(LoweredChild::Element(Box::new(nested)));
                }
                JsxChild::Fragment(frag) => {
                    self.record_feature(JsxFeatureFamily::Fragment);
                    let nested = self.lower_fragment(frag, depth + 1)?;
                    lowered.push(LoweredChild::Element(Box::new(nested)));
                }
            }
        }

        Ok(lowered)
    }

    fn build_source_location(&mut self, span: &SourceSpan) -> Option<SourceLocation> {
        if self.config.build_mode != BuildMode::Development {
            return None;
        }
        if !self.config.emit_source {
            return None;
        }

        self.emit_diagnostic(
            LoweringDiagnosticCode::DevMetadataEmitted,
            LoweringDiagnosticSeverity::Info,
            "Dev-mode source location metadata emitted".to_string(),
            Some(span.clone()),
        );

        Some(SourceLocation {
            file_name: self.config.source_file.clone(),
            line_number: span.start_line as u32,
            column_number: span.start_column as u32,
        })
    }

    fn add_fragment_import(&mut self) {
        match self.config.runtime_mode {
            JsxRuntimeMode::Classic => {
                // Classic mode uses React.Fragment — no additional import needed
                // (React is already imported)
            }
            JsxRuntimeMode::Automatic => {
                let source = self.config.automatic_import().to_string();
                self.require_import(&source, FRAGMENT_SYMBOL);
            }
            JsxRuntimeMode::Preserve => {}
        }
    }

    fn build_lowered_element(
        &mut self,
        input: BuildElementInput,
    ) -> Result<LoweredElement, ReactLoweringError> {
        let BuildElementInput {
            element_type,
            mut props,
            children,
            source_location,
            is_static_children,
            depth,
            span,
        } = input;
        let call_convention = match self.config.runtime_mode {
            JsxRuntimeMode::Classic => CallConvention::Classic {
                object: self.config.classic_object().to_string(),
                method: CLASSIC_CREATE_ELEMENT.to_string(),
            },
            JsxRuntimeMode::Automatic => {
                let factory = self.config.automatic_factory(children.len()).to_string();
                let import_source = self.config.automatic_import().to_string();

                // Register the import
                self.require_import(&import_source, &factory);

                // In automatic mode, children go into the props object
                if !children.is_empty() {
                    self.emit_diagnostic(
                        LoweringDiagnosticCode::ChildrenInProps,
                        LoweringDiagnosticSeverity::Info,
                        format!(
                            "Children ({} total) folded into props for automatic runtime",
                            children.len()
                        ),
                        Some(span.clone()),
                    );

                    let children_value = if children.len() == 1 {
                        // Single child: pass directly (not as array)
                        match &children[0] {
                            LoweredChild::Text { value, .. } => LoweredPropValue::StringLiteral {
                                value: value.clone(),
                            },
                            LoweredChild::Expression { expression, .. } => {
                                LoweredPropValue::Expression {
                                    expression: expression.clone(),
                                }
                            }
                            LoweredChild::Element(el) => LoweredPropValue::Element(el.clone()),
                        }
                    } else {
                        LoweredPropValue::ChildrenArray {
                            children: children.clone(),
                        }
                    };

                    props.entries.push(PropsEntry::Named(LoweredProp {
                        name: "children".to_string(),
                        value: children_value,
                        span: None,
                    }));
                }

                CallConvention::Automatic {
                    factory,
                    import_source,
                }
            }
            JsxRuntimeMode::Preserve => {
                return Err(ReactLoweringError::PreserveMode);
            }
        };

        // In automatic mode, children are in props; classic mode keeps them separate
        let final_children = match &call_convention {
            CallConvention::Classic { .. } => children,
            CallConvention::Automatic { .. } => Vec::new(),
        };

        Ok(LoweredElement {
            element_type,
            props,
            children: final_children,
            call_convention,
            source_location,
            is_static_children,
            depth,
            span,
        })
    }
}

// ---------------------------------------------------------------------------
// JSX Text Trimming (React whitespace rules)
// ---------------------------------------------------------------------------

/// Trim JSX text content following React's whitespace rules:
/// - Remove leading/trailing whitespace lines entirely
/// - Collapse internal whitespace sequences to single spaces
/// - Preserve intentional text content
fn trim_jsx_text(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return String::new();
    }

    // Single-line: trim both ends; if only whitespace, empty
    if lines.len() == 1 {
        let trimmed = lines[0].trim();
        return trimmed.to_string();
    }

    let mut result_parts: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let mut trimmed = line.to_string();

        // Trim leading whitespace on all lines except the first
        if i > 0 {
            trimmed = trimmed.trim_start().to_string();
        }

        // Trim trailing whitespace on all lines except the last
        if i < lines.len() - 1 {
            trimmed = trimmed.trim_end().to_string();
        }

        if !trimmed.is_empty() {
            result_parts.push(trimmed);
        }
    }

    if result_parts.is_empty() {
        return String::new();
    }

    result_parts.join(" ")
}

// ---------------------------------------------------------------------------
// Evidence Corpus
// ---------------------------------------------------------------------------

/// Build the standard lowering corpus specimens.
pub fn lowering_corpus() -> Vec<LoweringSpecimen> {
    let span = SourceSpan::new(0, 10, 1, 0, 1, 10);

    vec![
        // 1. Simple intrinsic element
        LoweringSpecimen {
            label: "intrinsic_div".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "div".to_string(),
                    span: span.clone(),
                },
                attributes: vec![JsxAttribute::Named {
                    name: "className".to_string(),
                    value: JsxAttributeValue::StringLiteral {
                        value: "container".to_string(),
                    },
                    span: span.clone(),
                }],
                children: vec![JsxChild::Text {
                    value: "Hello".to_string(),
                    span: span.clone(),
                }],
                self_closing: false,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::Element,
                JsxFeatureFamily::StringAttribute,
                JsxFeatureFamily::TextChild,
            ],
            expected_element_type: "intrinsic:div".to_string(),
            expected_child_count: 1,
        },
        // 2. Component element
        LoweringSpecimen {
            label: "component_element".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "Button".to_string(),
                    span: span.clone(),
                },
                attributes: vec![
                    JsxAttribute::Named {
                        name: "onClick".to_string(),
                        value: JsxAttributeValue::Expression {
                            expression: "handleClick".to_string(),
                        },
                        span: span.clone(),
                    },
                    JsxAttribute::Named {
                        name: "disabled".to_string(),
                        value: JsxAttributeValue::ImplicitTrue,
                        span: span.clone(),
                    },
                ],
                children: vec![JsxChild::Text {
                    value: "Click me".to_string(),
                    span: span.clone(),
                }],
                self_closing: false,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::Element,
                JsxFeatureFamily::ExpressionAttribute,
                JsxFeatureFamily::StringAttribute,
                JsxFeatureFamily::TextChild,
            ],
            expected_element_type: "component:Button".to_string(),
            expected_child_count: 1,
        },
        // 3. Self-closing element
        LoweringSpecimen {
            label: "self_closing_input".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "input".to_string(),
                    span: span.clone(),
                },
                attributes: vec![JsxAttribute::Named {
                    name: "type".to_string(),
                    value: JsxAttributeValue::StringLiteral {
                        value: "text".to_string(),
                    },
                    span: span.clone(),
                }],
                children: vec![],
                self_closing: true,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::SelfClosing,
                JsxFeatureFamily::StringAttribute,
            ],
            expected_element_type: "intrinsic:input".to_string(),
            expected_child_count: 0,
        },
        // 4. Fragment
        LoweringSpecimen {
            label: "fragment_with_children".to_string(),
            node: JsxNode::Fragment(JsxFragment {
                children: vec![
                    JsxChild::Text {
                        value: "First".to_string(),
                        span: span.clone(),
                    },
                    JsxChild::Text {
                        value: "Second".to_string(),
                        span: span.clone(),
                    },
                ],
                span: span.clone(),
            }),
            features: vec![JsxFeatureFamily::Fragment, JsxFeatureFamily::TextChild],
            expected_element_type: "fragment".to_string(),
            expected_child_count: 2,
        },
        // 5. Element with spread
        LoweringSpecimen {
            label: "element_with_spread".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "Component".to_string(),
                    span: span.clone(),
                },
                attributes: vec![
                    JsxAttribute::Named {
                        name: "id".to_string(),
                        value: JsxAttributeValue::StringLiteral {
                            value: "main".to_string(),
                        },
                        span: span.clone(),
                    },
                    JsxAttribute::Spread {
                        expression: "props".to_string(),
                        span: span.clone(),
                    },
                ],
                children: vec![],
                self_closing: true,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::SelfClosing,
                JsxFeatureFamily::StringAttribute,
                JsxFeatureFamily::SpreadAttribute,
            ],
            expected_element_type: "component:Component".to_string(),
            expected_child_count: 0,
        },
        // 6. Element with key and ref
        LoweringSpecimen {
            label: "element_with_key_ref".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "Item".to_string(),
                    span: span.clone(),
                },
                attributes: vec![
                    JsxAttribute::Named {
                        name: "key".to_string(),
                        value: JsxAttributeValue::Expression {
                            expression: "item.id".to_string(),
                        },
                        span: span.clone(),
                    },
                    JsxAttribute::Named {
                        name: "ref".to_string(),
                        value: JsxAttributeValue::Expression {
                            expression: "itemRef".to_string(),
                        },
                        span: span.clone(),
                    },
                    JsxAttribute::Named {
                        name: "data".to_string(),
                        value: JsxAttributeValue::Expression {
                            expression: "item.data".to_string(),
                        },
                        span: span.clone(),
                    },
                ],
                children: vec![],
                self_closing: true,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::SelfClosing,
                JsxFeatureFamily::ExpressionAttribute,
                JsxFeatureFamily::KeyProp,
            ],
            expected_element_type: "component:Item".to_string(),
            expected_child_count: 0,
        },
        // 7. Nested elements
        LoweringSpecimen {
            label: "nested_elements".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "div".to_string(),
                    span: span.clone(),
                },
                attributes: vec![],
                children: vec![
                    JsxChild::Element(Box::new(JsxElement {
                        name: JsxElementName::Identifier {
                            name: "span".to_string(),
                            span: span.clone(),
                        },
                        attributes: vec![],
                        children: vec![JsxChild::Text {
                            value: "inner".to_string(),
                            span: span.clone(),
                        }],
                        self_closing: false,
                        span: span.clone(),
                    })),
                    JsxChild::ExpressionContainer {
                        expression: "count".to_string(),
                        span: span.clone(),
                    },
                ],
                self_closing: false,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::Element,
                JsxFeatureFamily::NestedElement,
                JsxFeatureFamily::TextChild,
                JsxFeatureFamily::ExpressionChild,
            ],
            expected_element_type: "intrinsic:div".to_string(),
            expected_child_count: 2,
        },
        // 8. Member expression element
        LoweringSpecimen {
            label: "member_expression_element".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::MemberExpression {
                    segments: vec!["Ctx".to_string(), "Provider".to_string()],
                    span: span.clone(),
                },
                attributes: vec![JsxAttribute::Named {
                    name: "value".to_string(),
                    value: JsxAttributeValue::Expression {
                        expression: "ctxValue".to_string(),
                    },
                    span: span.clone(),
                }],
                children: vec![JsxChild::ExpressionContainer {
                    expression: "children".to_string(),
                    span: span.clone(),
                }],
                self_closing: false,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::Element,
                JsxFeatureFamily::MemberExpressionName,
                JsxFeatureFamily::ExpressionAttribute,
                JsxFeatureFamily::ExpressionChild,
            ],
            expected_element_type: "component:Ctx.Provider".to_string(),
            expected_child_count: 1,
        },
        // 9. Multiple expression children
        LoweringSpecimen {
            label: "multiple_children".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "ul".to_string(),
                    span: span.clone(),
                },
                attributes: vec![],
                children: vec![
                    JsxChild::Element(Box::new(JsxElement {
                        name: JsxElementName::Identifier {
                            name: "li".to_string(),
                            span: span.clone(),
                        },
                        attributes: vec![],
                        children: vec![JsxChild::Text {
                            value: "A".to_string(),
                            span: span.clone(),
                        }],
                        self_closing: false,
                        span: span.clone(),
                    })),
                    JsxChild::Element(Box::new(JsxElement {
                        name: JsxElementName::Identifier {
                            name: "li".to_string(),
                            span: span.clone(),
                        },
                        attributes: vec![],
                        children: vec![JsxChild::Text {
                            value: "B".to_string(),
                            span: span.clone(),
                        }],
                        self_closing: false,
                        span: span.clone(),
                    })),
                ],
                self_closing: false,
                span: span.clone(),
            }),
            features: vec![
                JsxFeatureFamily::Element,
                JsxFeatureFamily::NestedElement,
                JsxFeatureFamily::TextChild,
            ],
            expected_element_type: "intrinsic:ul".to_string(),
            expected_child_count: 2,
        },
        // 10. Empty element
        LoweringSpecimen {
            label: "empty_element".to_string(),
            node: JsxNode::Element(JsxElement {
                name: JsxElementName::Identifier {
                    name: "br".to_string(),
                    span: span.clone(),
                },
                attributes: vec![],
                children: vec![],
                self_closing: true,
                span: span.clone(),
            }),
            features: vec![JsxFeatureFamily::SelfClosing],
            expected_element_type: "intrinsic:br".to_string(),
            expected_child_count: 0,
        },
    ]
}

/// Run the lowering corpus and produce an evidence manifest.
pub fn run_lowering_corpus(config: &ReactLoweringConfig) -> LoweringRunManifest {
    let specimens = lowering_corpus();
    let mut evidence = Vec::new();
    let mut pass_count = 0u32;
    let mut fail_count = 0u32;
    let mut skip_count = 0u32;

    for specimen in &specimens {
        let result = lower_jsx_to_react(&specimen.node, config);

        let (verdict, element_type_match, child_count_match, diagnostic_count, error) =
            match result {
                Ok(res) => {
                    let et_match = res.element.element_type.canonical_value()
                        == specimen.expected_element_type;

                    // Count effective children based on mode
                    let actual_children =
                        match config.runtime_mode {
                            JsxRuntimeMode::Classic => res.element.children.len(),
                            JsxRuntimeMode::Automatic => {
                                // In automatic mode, children are in props
                                res.element
                            .props
                            .entries
                            .iter()
                            .filter(|e| matches!(e, PropsEntry::Named(p) if p.name == "children"))
                            .count()
                            .min(1)
                            * specimen.expected_child_count.min(1)
                            }
                            JsxRuntimeMode::Preserve => 0,
                        };

                    let cc_match =
                        if config.runtime_mode == JsxRuntimeMode::Automatic {
                            // For automatic mode, check that children presence matches
                            (specimen.expected_child_count > 0)
                                == res.element.props.entries.iter().any(
                                    |e| matches!(e, PropsEntry::Named(p) if p.name == "children"),
                                )
                        } else {
                            actual_children == specimen.expected_child_count
                        };

                    let v = if et_match && cc_match {
                        if res.diagnostics.is_empty() {
                            LoweringVerdict::Pass
                        } else {
                            LoweringVerdict::PassWithDiagnostics
                        }
                    } else {
                        LoweringVerdict::Fail
                    };

                    (v, et_match, cc_match, res.diagnostics.len() as u32, None)
                }
                Err(ReactLoweringError::PreserveMode) => {
                    (LoweringVerdict::Skipped, false, false, 0, None)
                }
                Err(e) => (LoweringVerdict::Fail, false, false, 0, Some(e.to_string())),
            };

        match verdict {
            LoweringVerdict::Pass | LoweringVerdict::PassWithDiagnostics => pass_count += 1,
            LoweringVerdict::Fail => fail_count += 1,
            LoweringVerdict::Skipped => skip_count += 1,
        }

        evidence.push(LoweringSpecimenEvidence {
            label: specimen.label.clone(),
            verdict,
            element_type_match,
            child_count_match,
            diagnostic_count,
            error,
        });
    }

    let evidence_bytes = serde_json::to_vec(&evidence).unwrap_or_default();
    let manifest_hash = ContentHash::compute(&evidence_bytes);

    LoweringRunManifest {
        schema_version: REACT_LOWERING_SCHEMA_VERSION.to_string(),
        total_specimens: specimens.len() as u32,
        pass_count,
        fail_count,
        skip_count,
        evidence,
        manifest_hash,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_span() -> SourceSpan {
        SourceSpan::new(0, 10, 1, 0, 1, 10)
    }

    fn classic_config() -> ReactLoweringConfig {
        ReactLoweringConfig {
            runtime_mode: JsxRuntimeMode::Classic,
            build_mode: BuildMode::Production,
            ..Default::default()
        }
    }

    fn automatic_config() -> ReactLoweringConfig {
        ReactLoweringConfig {
            runtime_mode: JsxRuntimeMode::Automatic,
            build_mode: BuildMode::Production,
            ..Default::default()
        }
    }

    fn dev_automatic_config() -> ReactLoweringConfig {
        ReactLoweringConfig {
            runtime_mode: JsxRuntimeMode::Automatic,
            build_mode: BuildMode::Development,
            source_file: Some("test.tsx".to_string()),
            ..Default::default()
        }
    }

    fn simple_div() -> JsxNode {
        JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![],
            self_closing: true,
            span: test_span(),
        })
    }

    // --- Schema & Constants ---

    #[test]
    fn test_schema_version_nonempty() {
        assert!(!REACT_LOWERING_SCHEMA_VERSION.is_empty());
        assert!(!REACT_LOWERING_COMPONENT.is_empty());
        assert!(!REACT_LOWERING_POLICY_ID.is_empty());
    }

    // --- BuildMode ---

    #[test]
    fn test_build_mode_as_str() {
        assert_eq!(BuildMode::Development.as_str(), "development");
        assert_eq!(BuildMode::Production.as_str(), "production");
    }

    #[test]
    fn test_build_mode_display() {
        assert_eq!(format!("{}", BuildMode::Development), "development");
        assert_eq!(format!("{}", BuildMode::Production), "production");
    }

    #[test]
    fn test_build_mode_serde_roundtrip() {
        for mode in [BuildMode::Development, BuildMode::Production] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: BuildMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    // --- ReactLoweringConfig ---

    #[test]
    fn test_default_config() {
        let cfg = ReactLoweringConfig::default();
        assert_eq!(cfg.runtime_mode, JsxRuntimeMode::Automatic);
        assert_eq!(cfg.build_mode, BuildMode::Production);
        assert!(cfg.classic_pragma.is_none());
        assert!(cfg.classic_fragment_pragma.is_none());
        assert!(cfg.automatic_import_source.is_none());
        assert_eq!(cfg.max_depth, MAX_LOWERING_DEPTH);
    }

    #[test]
    fn test_config_classic_object_default() {
        let cfg = classic_config();
        assert_eq!(cfg.classic_object(), "React");
    }

    #[test]
    fn test_config_classic_object_custom() {
        let cfg = ReactLoweringConfig {
            classic_pragma: Some("h".to_string()),
            ..classic_config()
        };
        assert_eq!(cfg.classic_object(), "h");
    }

    #[test]
    fn test_config_automatic_import_prod() {
        let cfg = automatic_config();
        assert_eq!(cfg.automatic_import(), "react/jsx-runtime");
    }

    #[test]
    fn test_config_automatic_import_dev() {
        let cfg = dev_automatic_config();
        assert_eq!(cfg.automatic_import(), "react/jsx-dev-runtime");
    }

    #[test]
    fn test_config_automatic_factory_single_child() {
        let cfg = automatic_config();
        assert_eq!(cfg.automatic_factory(0), "jsx");
        assert_eq!(cfg.automatic_factory(1), "jsx");
    }

    #[test]
    fn test_config_automatic_factory_multiple_children() {
        let cfg = automatic_config();
        assert_eq!(cfg.automatic_factory(2), "jsxs");
        assert_eq!(cfg.automatic_factory(5), "jsxs");
    }

    #[test]
    fn test_config_automatic_factory_dev() {
        let cfg = dev_automatic_config();
        assert_eq!(cfg.automatic_factory(0), "jsxDEV");
        assert_eq!(cfg.automatic_factory(3), "jsxDEV");
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let cfg = ReactLoweringConfig {
            runtime_mode: JsxRuntimeMode::Classic,
            build_mode: BuildMode::Development,
            source_file: Some("app.tsx".to_string()),
            classic_pragma: Some("createElement".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: ReactLoweringConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    // --- ElementType ---

    #[test]
    fn test_element_type_from_intrinsic() {
        let name = JsxElementName::Identifier {
            name: "div".to_string(),
            span: test_span(),
        };
        let et = ElementType::from_jsx_name(&name);
        assert_eq!(
            et,
            ElementType::Intrinsic {
                tag: "div".to_string()
            }
        );
    }

    #[test]
    fn test_element_type_from_component() {
        let name = JsxElementName::Identifier {
            name: "MyComponent".to_string(),
            span: test_span(),
        };
        let et = ElementType::from_jsx_name(&name);
        assert_eq!(
            et,
            ElementType::Component {
                name: "MyComponent".to_string()
            }
        );
    }

    #[test]
    fn test_element_type_from_member() {
        let name = JsxElementName::MemberExpression {
            segments: vec!["Ctx".to_string(), "Provider".to_string()],
            span: test_span(),
        };
        let et = ElementType::from_jsx_name(&name);
        assert_eq!(
            et,
            ElementType::Component {
                name: "Ctx.Provider".to_string()
            }
        );
    }

    #[test]
    fn test_element_type_canonical_value() {
        assert_eq!(
            ElementType::Intrinsic {
                tag: "div".to_string()
            }
            .canonical_value(),
            "intrinsic:div"
        );
        assert_eq!(
            ElementType::Component {
                name: "App".to_string()
            }
            .canonical_value(),
            "component:App"
        );
        assert_eq!(ElementType::Fragment.canonical_value(), "fragment");
    }

    #[test]
    fn test_element_type_serde_roundtrip() {
        for et in [
            ElementType::Intrinsic {
                tag: "span".to_string(),
            },
            ElementType::Component {
                name: "Comp".to_string(),
            },
            ElementType::Fragment,
        ] {
            let json = serde_json::to_string(&et).unwrap();
            let back: ElementType = serde_json::from_str(&json).unwrap();
            assert_eq!(et, back);
        }
    }

    // --- Core Lowering: Classic Mode ---

    #[test]
    fn test_classic_simple_div() {
        let node = simple_div();
        let cfg = classic_config();
        let result = lower_jsx_to_react(&node, &cfg).unwrap();
        assert_eq!(
            result.element.element_type,
            ElementType::Intrinsic {
                tag: "div".to_string()
            }
        );
        assert!(matches!(
            result.element.call_convention,
            CallConvention::Classic { .. }
        ));
        assert!(result.element.children.is_empty());
    }

    #[test]
    fn test_classic_with_props() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "input".to_string(),
                span: test_span(),
            },
            attributes: vec![
                JsxAttribute::Named {
                    name: "type".to_string(),
                    value: JsxAttributeValue::StringLiteral {
                        value: "text".to_string(),
                    },
                    span: test_span(),
                },
                JsxAttribute::Named {
                    name: "disabled".to_string(),
                    value: JsxAttributeValue::ImplicitTrue,
                    span: test_span(),
                },
            ],
            children: vec![],
            self_closing: true,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert_eq!(result.element.props.named_count(), 2);
        assert!(!result.element.props.has_spreads);
    }

    #[test]
    fn test_classic_with_children() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "p".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![
                JsxChild::Text {
                    value: "Hello ".to_string(),
                    span: test_span(),
                },
                JsxChild::ExpressionContainer {
                    expression: "name".to_string(),
                    span: test_span(),
                },
            ],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert_eq!(result.element.children.len(), 2);
        assert_eq!(result.stats.text_children, 1);
        assert_eq!(result.stats.expression_children, 1);
    }

    #[test]
    fn test_classic_key_extraction() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "Item".to_string(),
                span: test_span(),
            },
            attributes: vec![
                JsxAttribute::Named {
                    name: "key".to_string(),
                    value: JsxAttributeValue::Expression {
                        expression: "id".to_string(),
                    },
                    span: test_span(),
                },
                JsxAttribute::Named {
                    name: "data".to_string(),
                    value: JsxAttributeValue::Expression {
                        expression: "val".to_string(),
                    },
                    span: test_span(),
                },
            ],
            children: vec![],
            self_closing: true,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert!(result.element.props.extracted_key.is_some());
        assert_eq!(result.element.props.named_count(), 1); // only 'data', 'key' extracted
        assert_eq!(result.stats.keys_extracted, 1);
    }

    #[test]
    fn test_classic_ref_extraction() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![JsxAttribute::Named {
                name: "ref".to_string(),
                value: JsxAttributeValue::Expression {
                    expression: "myRef".to_string(),
                },
                span: test_span(),
            }],
            children: vec![],
            self_closing: true,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert!(result.element.props.extracted_ref.is_some());
        assert_eq!(result.stats.refs_extracted, 1);
    }

    #[test]
    fn test_classic_call_convention() {
        let result = lower_jsx_to_react(&simple_div(), &classic_config()).unwrap();
        match &result.element.call_convention {
            CallConvention::Classic { object, method } => {
                assert_eq!(object, "React");
                assert_eq!(method, "createElement");
            }
            _ => panic!("Expected classic call convention"),
        }
    }

    #[test]
    fn test_classic_fragment() {
        let node = JsxNode::Fragment(JsxFragment {
            children: vec![JsxChild::Text {
                value: "content".to_string(),
                span: test_span(),
            }],
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert_eq!(result.element.element_type, ElementType::Fragment);
        assert_eq!(result.element.children.len(), 1);
        assert_eq!(result.stats.fragments_lowered, 1);
    }

    // --- Core Lowering: Automatic Mode ---

    #[test]
    fn test_automatic_simple_div() {
        let result = lower_jsx_to_react(&simple_div(), &automatic_config()).unwrap();
        assert!(matches!(
            result.element.call_convention,
            CallConvention::Automatic { .. }
        ));
        // No children -> jsx
        match &result.element.call_convention {
            CallConvention::Automatic { factory, .. } => {
                assert_eq!(factory, "jsx");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_automatic_single_child_uses_jsx() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![JsxChild::Text {
                value: "Hello".to_string(),
                span: test_span(),
            }],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &automatic_config()).unwrap();
        match &result.element.call_convention {
            CallConvention::Automatic { factory, .. } => {
                assert_eq!(factory, "jsx");
            }
            _ => panic!("Expected automatic"),
        }
        // Children should be in props, not as separate children
        assert!(result.element.children.is_empty());
        assert!(
            result
                .element
                .props
                .entries
                .iter()
                .any(|e| matches!(e, PropsEntry::Named(p) if p.name == "children"))
        );
    }

    #[test]
    fn test_automatic_multiple_children_uses_jsxs() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![
                JsxChild::Text {
                    value: "A".to_string(),
                    span: test_span(),
                },
                JsxChild::Text {
                    value: "B".to_string(),
                    span: test_span(),
                },
            ],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &automatic_config()).unwrap();
        match &result.element.call_convention {
            CallConvention::Automatic { factory, .. } => {
                assert_eq!(factory, "jsxs");
            }
            _ => panic!("Expected automatic"),
        }
    }

    #[test]
    fn test_automatic_children_in_props() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![JsxAttribute::Named {
                name: "id".to_string(),
                value: JsxAttributeValue::StringLiteral {
                    value: "main".to_string(),
                },
                span: test_span(),
            }],
            children: vec![JsxChild::Text {
                value: "Hello".to_string(),
                span: test_span(),
            }],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &automatic_config()).unwrap();
        // Should have 'id' prop and 'children' prop
        assert_eq!(result.element.props.entries.len(), 2);
    }

    #[test]
    fn test_automatic_import_source() {
        let result = lower_jsx_to_react(&simple_div(), &automatic_config()).unwrap();
        assert!(
            result
                .required_imports
                .iter()
                .any(|i| i.source == "react/jsx-runtime")
        );
    }

    #[test]
    fn test_automatic_fragment_import() {
        let node = JsxNode::Fragment(JsxFragment {
            children: vec![JsxChild::Text {
                value: "x".to_string(),
                span: test_span(),
            }],
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &automatic_config()).unwrap();
        assert!(result.required_imports.iter().any(|i| i.name == "Fragment"));
    }

    // --- Dev Mode ---

    #[test]
    fn test_dev_mode_source_location() {
        let result = lower_jsx_to_react(&simple_div(), &dev_automatic_config()).unwrap();
        assert!(result.element.source_location.is_some());
        let loc = result.element.source_location.as_ref().unwrap();
        assert_eq!(loc.file_name.as_deref(), Some("test.tsx"));
        assert_eq!(loc.line_number, 1);
        assert_eq!(loc.column_number, 0);
    }

    #[test]
    fn test_dev_mode_uses_jsxdev() {
        let result = lower_jsx_to_react(&simple_div(), &dev_automatic_config()).unwrap();
        match &result.element.call_convention {
            CallConvention::Automatic { factory, .. } => {
                assert_eq!(factory, "jsxDEV");
            }
            _ => panic!("Expected automatic"),
        }
    }

    #[test]
    fn test_dev_mode_import_source() {
        let result = lower_jsx_to_react(&simple_div(), &dev_automatic_config()).unwrap();
        assert!(
            result
                .required_imports
                .iter()
                .any(|i| i.source == "react/jsx-dev-runtime")
        );
    }

    #[test]
    fn test_prod_mode_no_source_location() {
        let result = lower_jsx_to_react(&simple_div(), &automatic_config()).unwrap();
        assert!(result.element.source_location.is_none());
    }

    // --- Preserve Mode ---

    #[test]
    fn test_preserve_mode_error() {
        let cfg = ReactLoweringConfig {
            runtime_mode: JsxRuntimeMode::Preserve,
            ..Default::default()
        };
        let result = lower_jsx_to_react(&simple_div(), &cfg);
        assert!(matches!(result, Err(ReactLoweringError::PreserveMode)));
    }

    // --- Depth Limit ---

    #[test]
    fn test_depth_exceeded() {
        let cfg = ReactLoweringConfig {
            max_depth: 1,
            ..automatic_config()
        };
        let nested = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "span".to_string(),
                    span: test_span(),
                },
                attributes: vec![],
                children: vec![],
                self_closing: true,
                span: test_span(),
            }))],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&nested, &cfg);
        assert!(matches!(
            result,
            Err(ReactLoweringError::DepthExceeded { .. })
        ));
    }

    // --- Spread Attributes ---

    #[test]
    fn test_spread_attribute_diagnostic() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![JsxAttribute::Spread {
                expression: "props".to_string(),
                span: test_span(),
            }],
            children: vec![],
            self_closing: true,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert!(result.element.props.has_spreads);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.code == LoweringDiagnosticCode::SpreadRequiresRuntime)
        );
    }

    // --- Whitespace Trimming ---

    #[test]
    fn test_trim_jsx_text_empty() {
        assert_eq!(trim_jsx_text(""), "");
    }

    #[test]
    fn test_trim_jsx_text_whitespace_only() {
        assert_eq!(trim_jsx_text("   "), "");
        assert_eq!(trim_jsx_text("\n  \n"), "");
    }

    #[test]
    fn test_trim_jsx_text_preserves_content() {
        assert_eq!(trim_jsx_text("Hello"), "Hello");
    }

    #[test]
    fn test_trim_jsx_text_multiline() {
        assert_eq!(trim_jsx_text("Hello\n  World"), "Hello World");
    }

    #[test]
    fn test_whitespace_child_trimmed() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![JsxChild::Text {
                value: "   \n  \n  ".to_string(),
                span: test_span(),
            }],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert!(result.element.children.is_empty());
    }

    // --- Namespaced Elements ---

    #[test]
    fn test_namespaced_element_warning() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::NamespacedName {
                namespace: "svg".to_string(),
                name: "rect".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![],
            self_closing: true,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.code == LoweringDiagnosticCode::NamespacedElement)
        );
    }

    // --- LoweredProps ---

    #[test]
    fn test_lowered_props_empty() {
        let props = LoweredProps {
            entries: vec![],
            has_spreads: false,
            extracted_key: None,
            extracted_ref: None,
        };
        assert!(props.is_empty());
        assert_eq!(props.named_count(), 0);
    }

    #[test]
    fn test_lowered_props_with_entries() {
        let props = LoweredProps {
            entries: vec![PropsEntry::Named(LoweredProp {
                name: "id".to_string(),
                value: LoweredPropValue::StringLiteral {
                    value: "x".to_string(),
                },
                span: None,
            })],
            has_spreads: false,
            extracted_key: None,
            extracted_ref: None,
        };
        assert!(!props.is_empty());
        assert_eq!(props.named_count(), 1);
    }

    #[test]
    fn test_lowered_props_key_makes_nonempty() {
        let props = LoweredProps {
            entries: vec![],
            has_spreads: false,
            extracted_key: Some(LoweredPropValue::StringLiteral {
                value: "k".to_string(),
            }),
            extracted_ref: None,
        };
        assert!(!props.is_empty());
    }

    // --- Nested Lowering ---

    #[test]
    fn test_nested_element_lowering() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![JsxChild::Element(Box::new(JsxElement {
                name: JsxElementName::Identifier {
                    name: "span".to_string(),
                    span: test_span(),
                },
                attributes: vec![],
                children: vec![JsxChild::Text {
                    value: "hello".to_string(),
                    span: test_span(),
                }],
                self_closing: false,
                span: test_span(),
            }))],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert_eq!(result.element.children.len(), 1);
        assert_eq!(result.stats.elements_lowered, 2); // div + span
        assert_eq!(result.stats.max_depth_reached, 1);
    }

    #[test]
    fn test_nested_fragment_inside_element() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![],
            children: vec![JsxChild::Fragment(Box::new(JsxFragment {
                children: vec![JsxChild::Text {
                    value: "nested".to_string(),
                    span: test_span(),
                }],
                span: test_span(),
            }))],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert_eq!(result.stats.elements_lowered, 1);
        assert_eq!(result.stats.fragments_lowered, 1);
    }

    // --- Duplicate Key ---

    #[test]
    fn test_duplicate_key_warning() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![
                JsxAttribute::Named {
                    name: "key".to_string(),
                    value: JsxAttributeValue::StringLiteral {
                        value: "a".to_string(),
                    },
                    span: test_span(),
                },
                JsxAttribute::Named {
                    name: "key".to_string(),
                    value: JsxAttributeValue::StringLiteral {
                        value: "b".to_string(),
                    },
                    span: test_span(),
                },
            ],
            children: vec![],
            self_closing: true,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert!(
            result
                .diagnostics
                .iter()
                .any(|d| d.code == LoweringDiagnosticCode::DuplicateKey)
        );
        // Last key wins
        assert!(matches!(
            &result.element.props.extracted_key,
            Some(LoweredPropValue::StringLiteral { value }) if value == "b"
        ));
    }

    // --- Stats ---

    #[test]
    fn test_stats_tracking() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![
                JsxAttribute::Named {
                    name: "id".to_string(),
                    value: JsxAttributeValue::StringLiteral {
                        value: "x".to_string(),
                    },
                    span: test_span(),
                },
                JsxAttribute::Spread {
                    expression: "p".to_string(),
                    span: test_span(),
                },
            ],
            children: vec![
                JsxChild::Text {
                    value: "text".to_string(),
                    span: test_span(),
                },
                JsxChild::ExpressionContainer {
                    expression: "e".to_string(),
                    span: test_span(),
                },
            ],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert_eq!(result.stats.elements_lowered, 1);
        assert_eq!(result.stats.total_props, 1);
        assert_eq!(result.stats.spread_attributes, 1);
        assert_eq!(result.stats.text_children, 1);
        assert_eq!(result.stats.expression_children, 1);
    }

    // --- Evidence Corpus ---

    #[test]
    fn test_corpus_nonempty() {
        let corpus = lowering_corpus();
        assert!(corpus.len() >= 10);
    }

    #[test]
    fn test_corpus_labels_unique() {
        let corpus = lowering_corpus();
        let labels: Vec<&str> = corpus.iter().map(|s| s.label.as_str()).collect();
        let mut sorted = labels.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(labels.len(), sorted.len());
    }

    #[test]
    fn test_run_corpus_classic_all_pass() {
        let manifest = run_lowering_corpus(&classic_config());
        assert!(
            manifest.fail_count == 0,
            "Classic corpus failures: {}",
            manifest.fail_count
        );
        assert!(manifest.pass_count > 0);
    }

    #[test]
    fn test_run_corpus_automatic_all_pass() {
        let manifest = run_lowering_corpus(&automatic_config());
        assert!(
            manifest.fail_count == 0,
            "Automatic corpus failures: {}",
            manifest.fail_count
        );
        assert!(manifest.pass_count > 0);
    }

    #[test]
    fn test_run_corpus_preserve_all_skip() {
        let cfg = ReactLoweringConfig {
            runtime_mode: JsxRuntimeMode::Preserve,
            ..Default::default()
        };
        let manifest = run_lowering_corpus(&cfg);
        assert_eq!(manifest.pass_count, 0);
        assert_eq!(manifest.skip_count, manifest.total_specimens);
    }

    #[test]
    fn test_manifest_hash_deterministic() {
        let m1 = run_lowering_corpus(&classic_config());
        let m2 = run_lowering_corpus(&classic_config());
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    // --- Compile Receipt ---

    #[test]
    fn test_compile_receipt() {
        let node = simple_div();
        let cfg = classic_config();
        let parse_result = JsxParseResult {
            node: node.clone(),
            diagnostics: vec![],
            feature_families_used: vec![JsxFeatureFamily::SelfClosing],
        };
        let lowered = lower_jsx_to_react(&node, &cfg).unwrap();
        let receipt = compute_lowering_receipt(&parse_result, &lowered, &cfg);
        assert_eq!(receipt.schema_version, REACT_LOWERING_SCHEMA_VERSION);
        assert_eq!(receipt.config_summary.runtime_mode, "classic");
        assert_eq!(receipt.config_summary.build_mode, "production");
    }

    #[test]
    fn test_compile_receipt_deterministic() {
        let node = simple_div();
        let cfg = classic_config();
        let parse_result = JsxParseResult {
            node: node.clone(),
            diagnostics: vec![],
            feature_families_used: vec![],
        };
        let lowered = lower_jsx_to_react(&node, &cfg).unwrap();
        let r1 = compute_lowering_receipt(&parse_result, &lowered, &cfg);
        let r2 = compute_lowering_receipt(&parse_result, &lowered, &cfg);
        assert_eq!(r1.input_hash, r2.input_hash);
        assert_eq!(r1.output_hash, r2.output_hash);
    }

    // --- Serde Round-trips ---

    #[test]
    fn test_lowered_element_serde_roundtrip() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![JsxAttribute::Named {
                name: "id".to_string(),
                value: JsxAttributeValue::StringLiteral {
                    value: "main".to_string(),
                },
                span: test_span(),
            }],
            children: vec![JsxChild::Text {
                value: "Hello".to_string(),
                span: test_span(),
            }],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        let json = serde_json::to_string(&result.element).unwrap();
        let back: LoweredElement = serde_json::from_str(&json).unwrap();
        assert_eq!(result.element, back);
    }

    #[test]
    fn test_lowering_diagnostic_serde_roundtrip() {
        let diag = LoweringDiagnostic {
            code: LoweringDiagnosticCode::SpreadRequiresRuntime,
            severity: LoweringDiagnosticSeverity::Info,
            message: "test".to_string(),
            span: Some(test_span()),
        };
        let json = serde_json::to_string(&diag).unwrap();
        let back: LoweringDiagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, back);
    }

    #[test]
    fn test_lowering_error_serde_roundtrip() {
        for err in [
            ReactLoweringError::PreserveMode,
            ReactLoweringError::DepthExceeded {
                max_depth: 64,
                span: test_span(),
            },
            ReactLoweringError::InternalError {
                message: "bad".to_string(),
            },
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: ReactLoweringError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    #[test]
    fn test_lowering_error_display() {
        assert!(format!("{}", ReactLoweringError::PreserveMode).contains("preserve"));
        assert!(
            format!(
                "{}",
                ReactLoweringError::DepthExceeded {
                    max_depth: 10,
                    span: test_span()
                }
            )
            .contains("10")
        );
    }

    // --- Diagnostic Codes ---

    #[test]
    fn test_diagnostic_code_strs_unique() {
        let codes = [
            LoweringDiagnosticCode::PreserveModeNoOp,
            LoweringDiagnosticCode::DepthExceeded,
            LoweringDiagnosticCode::SpreadRequiresRuntime,
            LoweringDiagnosticCode::NamespacedElement,
            LoweringDiagnosticCode::KeyOnFragment,
            LoweringDiagnosticCode::RefOnFragment,
            LoweringDiagnosticCode::EmptyTextTrimmed,
            LoweringDiagnosticCode::DevMetadataEmitted,
            LoweringDiagnosticCode::ChildrenInProps,
            LoweringDiagnosticCode::DuplicateKey,
        ];
        let strs: Vec<&str> = codes.iter().map(|c| c.code_str()).collect();
        let mut deduped = strs.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(strs.len(), deduped.len());
    }

    #[test]
    fn test_diagnostic_code_display() {
        let code = LoweringDiagnosticCode::SpreadRequiresRuntime;
        assert_eq!(format!("{code}"), "FE-RJL-0003");
    }

    // --- Feature Tracking ---

    #[test]
    fn test_feature_families_tracked() {
        let node = JsxNode::Element(JsxElement {
            name: JsxElementName::Identifier {
                name: "div".to_string(),
                span: test_span(),
            },
            attributes: vec![JsxAttribute::Named {
                name: "key".to_string(),
                value: JsxAttributeValue::StringLiteral {
                    value: "k".to_string(),
                },
                span: test_span(),
            }],
            children: vec![JsxChild::Text {
                value: "hello".to_string(),
                span: test_span(),
            }],
            self_closing: false,
            span: test_span(),
        });
        let result = lower_jsx_to_react(&node, &classic_config()).unwrap();
        assert!(
            result
                .feature_families_used
                .contains(&JsxFeatureFamily::Element)
        );
        assert!(
            result
                .feature_families_used
                .contains(&JsxFeatureFamily::TextChild)
        );
        assert!(
            result
                .feature_families_used
                .contains(&JsxFeatureFamily::KeyProp)
        );
    }

    // --- Custom Pragma ---

    #[test]
    fn test_custom_classic_pragma() {
        let cfg = ReactLoweringConfig {
            classic_pragma: Some("h".to_string()),
            ..classic_config()
        };
        let result = lower_jsx_to_react(&simple_div(), &cfg).unwrap();
        match &result.element.call_convention {
            CallConvention::Classic { object, .. } => {
                assert_eq!(object, "h");
            }
            _ => panic!("Expected classic"),
        }
    }

    #[test]
    fn test_custom_automatic_import_source() {
        let cfg = ReactLoweringConfig {
            automatic_import_source: Some("preact/jsx-runtime".to_string()),
            ..automatic_config()
        };
        let result = lower_jsx_to_react(&simple_div(), &cfg).unwrap();
        assert!(
            result
                .required_imports
                .iter()
                .any(|i| i.source == "preact/jsx-runtime")
        );
    }

    // --- ConfigSummary ---

    #[test]
    fn test_config_summary() {
        let cfg = ReactLoweringConfig {
            classic_pragma: Some("h".to_string()),
            ..classic_config()
        };
        let summary = ConfigSummary::from_config(&cfg);
        assert_eq!(summary.runtime_mode, "classic");
        assert!(summary.has_custom_pragma);
        assert!(!summary.has_custom_fragment);
    }

    // --- LoweringStats Default ---

    #[test]
    fn test_lowering_stats_default() {
        let stats = LoweringStats::default();
        assert_eq!(stats.elements_lowered, 0);
        assert_eq!(stats.fragments_lowered, 0);
        assert_eq!(stats.text_children, 0);
        assert_eq!(stats.expression_children, 0);
        assert_eq!(stats.spread_attributes, 0);
        assert_eq!(stats.max_depth_reached, 0);
        assert_eq!(stats.total_props, 0);
        assert_eq!(stats.keys_extracted, 0);
        assert_eq!(stats.refs_extracted, 0);
    }

    // --- lower_parse_result ---

    #[test]
    fn test_lower_parse_result() {
        let pr = JsxParseResult {
            node: simple_div(),
            diagnostics: vec![],
            feature_families_used: vec![],
        };
        let result = lower_parse_result(&pr, &classic_config()).unwrap();
        assert_eq!(
            result.element.element_type,
            ElementType::Intrinsic {
                tag: "div".to_string()
            }
        );
    }
}
