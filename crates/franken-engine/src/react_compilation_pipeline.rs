//! React/JSX compilation pipeline integration.
//!
//! This module provides the main compilation pipeline that integrates JSX/TSX
//! parsing, React lowering, and IR generation to create a unified path from
//! React source code to executable engine instructions.
//!
//! The compilation pipeline follows these steps:
//! 1. Parse JSX/TSX source with typed nodes and stable spans
//! 2. Lower JSX to React function calls (createElement or jsx runtime)
//! 3. Emit JavaScript and validate it with the native ECMAScript parser
//! 4. Generate deterministic compile receipts for evidence
//!
//! This implements the missing bridge described in RGC-206: routing React
//! source through the same deterministic engine pipeline as other inputs.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ast::ParseGoal;
use crate::hash_tiers::ContentHash;
use crate::jsx_tsx_parser::{
    JsxParseError, JsxParseResult, JsxParserConfig, parse_jsx, transform_jsx_expressions,
};
use crate::parser::{CanonicalEs2020Parser, Es2020Parser};
use crate::react_jsx_lowering::{
    BuildMode, CallConvention, ElementType, LoweredChild, LoweredElement, LoweredPropValue,
    PropsEntry, ReactLoweringConfig, ReactLoweringResult, SourceLocation, lower_parse_result,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the React compilation pipeline.
pub const REACT_COMPILATION_SCHEMA_VERSION: &str = "franken-engine.react-compilation.v1";
/// Component name for evidence linkage.
pub const REACT_COMPILATION_COMPONENT: &str = "react_compilation_pipeline";
/// Policy ID binding for this module.
pub const REACT_COMPILATION_POLICY_ID: &str = "RGC-206";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the React compilation pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCompileConfig {
    /// JSX parser configuration.
    pub parser_config: JsxParserConfig,
    /// React lowering configuration.
    pub lowering_config: ReactLoweringConfig,
    /// Whether to generate source maps.
    pub generate_source_maps: bool,
    /// Whether to include debug information.
    pub include_debug_info: bool,
    /// Deterministic epoch stamped into compile metadata and evidence.
    #[serde(default = "default_compile_epoch")]
    pub compile_epoch: SecurityEpoch,
}

impl Default for ReactCompileConfig {
    fn default() -> Self {
        Self {
            parser_config: JsxParserConfig::default(),
            lowering_config: ReactLoweringConfig::default(),
            generate_source_maps: false,
            include_debug_info: false,
            compile_epoch: default_compile_epoch(),
        }
    }
}

fn default_compile_epoch() -> SecurityEpoch {
    SecurityEpoch::GENESIS
}

// ---------------------------------------------------------------------------
// Results and Evidence
// ---------------------------------------------------------------------------

/// Result of React compilation pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCompileResult {
    /// Original source input.
    pub source: String,
    /// JSX parse result.
    pub parse_result: JsxParseResult,
    /// React lowering result.
    pub lowering_result: ReactLoweringResult,
    /// Generated JavaScript code (post-lowering).
    pub generated_code: String,
    /// Source map (if requested).
    pub source_map: Option<String>,
    /// Compilation metadata.
    pub metadata: ReactCompileMetadata,
}

/// Metadata about the compilation process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCompileMetadata {
    /// Input source hash.
    pub input_hash: ContentHash,
    /// Configuration hash.
    pub config_hash: ContentHash,
    /// Deterministic compilation epoch stamp for evidence.
    pub timestamp: u64,
    /// Feature families encountered during parsing.
    pub feature_families: Vec<String>,
    /// Transform count by type.
    pub transform_counts: BTreeMap<String, u32>,
}

/// Evidence of successful compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCompileEvidence {
    /// Input specification.
    pub input_spec: ReactInputSpec,
    /// Output specification.
    pub output_spec: ReactOutputSpec,
    /// Compilation receipt.
    pub compile_receipt: ReactCompileReceipt,
    /// Evidence timestamp.
    pub timestamp: u64,
}

/// Specification of compilation input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactInputSpec {
    /// Source content hash.
    pub source_hash: ContentHash,
    /// Input language (jsx or tsx).
    pub language: ReactInputLanguage,
    /// Configuration used.
    pub config: ReactCompileConfig,
}

/// Specification of compilation output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactOutputSpec {
    /// Generated code hash.
    pub code_hash: ContentHash,
    /// Output format.
    pub format: ReactOutputFormat,
    /// Success indicator.
    pub success: bool,
}

/// Receipt proving compilation was deterministic and correct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCompileReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component that generated this receipt.
    pub component: String,
    /// Input hash.
    pub input_hash: ContentHash,
    /// Output hash.
    pub output_hash: ContentHash,
    /// Configuration hash.
    pub config_hash: ContentHash,
    /// Process hash (deterministic execution proof).
    pub process_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Supporting Types
// ---------------------------------------------------------------------------

/// React input language type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReactInputLanguage {
    /// JavaScript with JSX.
    Jsx,
    /// TypeScript with JSX.
    Tsx,
}

impl ReactInputLanguage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jsx => "jsx",
            Self::Tsx => "tsx",
        }
    }

    pub const fn file_extension(self) -> &'static str {
        match self {
            Self::Jsx => ".jsx",
            Self::Tsx => ".tsx",
        }
    }
}

impl fmt::Display for ReactInputLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// React compilation output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactOutputFormat {
    /// JavaScript (post-JSX transformation).
    JavaScript,
    /// IR3 (engine-ready instructions).
    Ir3,
}

impl ReactOutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::Ir3 => "ir3",
        }
    }
}

impl fmt::Display for ReactOutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Compilation Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during React compilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReactCompileError {
    /// JSX parsing failed.
    ParseError(String),
    /// React lowering failed.
    LoweringError(String),
    /// IR generation failed.
    IrGenerationError(String),
    /// Source map generation failed.
    SourceMapError(String),
    /// Configuration is invalid.
    InvalidConfig(String),
    /// Empty input provided.
    EmptyInput,
    /// Serialization failed.
    SerializationError(String),
}

impl fmt::Display for ReactCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ParseError(msg) => write!(f, "Parse error: {}", msg),
            Self::LoweringError(msg) => write!(f, "Lowering error: {}", msg),
            Self::IrGenerationError(msg) => write!(f, "IR generation error: {}", msg),
            Self::SourceMapError(msg) => write!(f, "Source map error: {}", msg),
            Self::InvalidConfig(msg) => write!(f, "Invalid config: {}", msg),
            Self::EmptyInput => f.write_str("Empty input provided"),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for ReactCompileError {}

impl From<JsxParseError> for ReactCompileError {
    fn from(error: JsxParseError) -> Self {
        Self::ParseError(format!("{error:?}"))
    }
}

// ---------------------------------------------------------------------------
// Main Compilation Functions
// ---------------------------------------------------------------------------

/// Compile one JSX/TSX expression into an executable JavaScript module.
///
/// The input is an expression fragment, not a complete JavaScript/TypeScript
/// source file. Automatic mode emits the imports required by the runtime;
/// classic mode uses the configured factory already present in the caller.
pub fn compile_react_source(
    source: &str,
    language: ReactInputLanguage,
    config: &ReactCompileConfig,
) -> Result<ReactCompileResult, ReactCompileError> {
    // Validate input
    if source.trim().is_empty() {
        return Err(ReactCompileError::EmptyInput);
    }

    // Step 1: Parse JSX/TSX
    let mut parser_config = config.parser_config.clone();
    parser_config.tsx_mode = language == ReactInputLanguage::Tsx;
    let parse_result = parse_jsx(source, &parser_config)
        .map_err(|e| ReactCompileError::ParseError(format!("{:?}", e)))?;

    // Step 2: Lower to React calls
    let lowering_result = lower_parse_result(&parse_result, &config.lowering_config)
        .map_err(|e| ReactCompileError::LoweringError(format!("{:?}", e)))?;

    // Step 3: Generate output code
    let generated_code = generate_javascript_output(
        source,
        &lowering_result,
        &config.lowering_config,
        &parser_config,
    )?;

    // Step 4: Generate source map (if requested)
    let source_map = if config.generate_source_maps {
        Some(generate_source_map(source, &generated_code)?)
    } else {
        None
    };

    // Step 5: Compute metadata
    let metadata = ReactCompileMetadata {
        input_hash: ContentHash::compute(source.as_bytes()),
        config_hash: ContentHash::compute(
            &serde_json::to_vec(config)
                .map_err(|e| ReactCompileError::SerializationError(e.to_string()))?,
        ),
        timestamp: config.compile_epoch.as_u64(),
        feature_families: extract_feature_families(&parse_result),
        transform_counts: count_transforms(&lowering_result),
    };

    Ok(ReactCompileResult {
        source: source.to_string(),
        parse_result,
        lowering_result,
        generated_code,
        source_map,
        metadata,
    })
}

/// Generate evidence for a successful compilation.
pub fn generate_compilation_evidence(
    result: &ReactCompileResult,
    config: &ReactCompileConfig,
    language: ReactInputLanguage,
) -> Result<ReactCompileEvidence, ReactCompileError> {
    let input_spec = ReactInputSpec {
        source_hash: result.metadata.input_hash,
        language,
        config: config.clone(),
    };

    let output_spec = ReactOutputSpec {
        code_hash: ContentHash::compute(result.generated_code.as_bytes()),
        format: ReactOutputFormat::JavaScript,
        success: true,
    };

    let compile_receipt = ReactCompileReceipt {
        schema_version: REACT_COMPILATION_SCHEMA_VERSION.to_string(),
        component: REACT_COMPILATION_COMPONENT.to_string(),
        input_hash: result.metadata.input_hash,
        output_hash: output_spec.code_hash,
        config_hash: result.metadata.config_hash,
        process_hash: compute_process_hash(result, config)?,
    };

    Ok(ReactCompileEvidence {
        input_spec,
        output_spec,
        compile_receipt,
        timestamp: result.metadata.timestamp,
    })
}

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

/// Emit an executable JavaScript module for one JSX expression.
///
/// Runtime imports use source-disjoint names. Element config entries remain in
/// source order, including every key/ref occurrence and spread; extracting their
/// values during compilation would drop or reorder observable JavaScript work.
/// This preserves classic React/createElement evaluation semantics in both
/// modes. Babel's automatic key-argument lifting can reorder or discard key
/// expressions; matching that optimization is deliberately not this contract.
fn generate_javascript_output(
    source: &str,
    lowering_result: &ReactLoweringResult,
    config: &ReactLoweringConfig,
    parser_config: &JsxParserConfig,
) -> Result<String, ReactCompileError> {
    let identifier_source = decode_unicode_escapes(source);
    let mut binding_prefix = "__franken_react_".to_string();
    while identifier_source.contains(&binding_prefix) {
        binding_prefix.push('_');
    }
    let mut emitter = JavaScriptEmitter {
        config,
        parser_config,
        import_aliases: BTreeMap::new(),
        binding_prefix,
        expression_depth: 0,
    };
    // Expression containers can introduce factories and fragments absent from
    // the outer lowering result. Emit the body first to discover all imports.
    let body = emitter.element(&lowering_result.element)?;
    let mut output = String::new();
    for ((source, name), alias) in &emitter.import_aliases {
        output.push_str(&format!(
            "import {{ {name} as {alias} }} from {};\n",
            javascript_string(source)?
        ));
    }
    output.push_str(&body);
    output.push_str(";\n");
    // JSX expression containers carry source text. Validate the emitted module
    // with the engine parser before returning a successful compile receipt.
    let parsed = CanonicalEs2020Parser
        .parse(output.as_str(), ParseGoal::Module)
        .map_err(|error| ReactCompileError::IrGenerationError(error.to_string()))?;
    // Raw is a recovery node, not proof that an expression is valid JS. It
    // would become a SyntaxError during native lowering, so fail compilation
    // here instead of issuing a successful receipt for unusable output.
    let parsed = serde_json::to_value(parsed)
        .map_err(|error| ReactCompileError::SerializationError(error.to_string()))?;
    if contains_raw_expression(&parsed) {
        return Err(ReactCompileError::IrGenerationError(
            "generated module contains an unsupported JavaScript expression".to_string(),
        ));
    }
    Ok(output)
}

struct JavaScriptEmitter<'a> {
    config: &'a ReactLoweringConfig,
    parser_config: &'a JsxParserConfig,
    import_aliases: BTreeMap<(String, String), String>,
    binding_prefix: String,
    expression_depth: usize,
}

impl JavaScriptEmitter<'_> {
    fn imported(&mut self, source: &str, name: &str) -> String {
        let alias = format!("{}{}", self.binding_prefix, self.import_aliases.len());
        self.import_aliases
            .entry((source.to_string(), name.to_string()))
            .or_insert(alias)
            .clone()
    }

    fn element(&mut self, element: &LoweredElement) -> Result<String, ReactCompileError> {
        let element_type = match &element.element_type {
            ElementType::Intrinsic { tag } => javascript_string(tag)?,
            ElementType::Component { name } => name.clone(),
            ElementType::Fragment => match &element.call_convention {
                CallConvention::Classic { .. } => self.config.classic_fragment().to_string(),
                CallConvention::Automatic { import_source, .. } => {
                    self.imported(import_source, "Fragment")
                }
            },
        };
        let mut entries = element
            .props
            .entries
            .iter()
            .map(|entry| match entry {
                PropsEntry::Named(prop) => Ok(format!(
                    "[{}]: {}",
                    javascript_string(&prop.name)?,
                    self.prop_value(&prop.value)?
                )),
                PropsEntry::Spread { expression, .. } => {
                    Ok(format!("...{}", self.expression(expression)?))
                }
            })
            .collect::<Result<Vec<_>, ReactCompileError>>()?;

        match &element.call_convention {
            CallConvention::Classic { object, method } => {
                if let Some(location) = &element.source_location {
                    entries.push(format!(
                        "[\"__source\"]: {}",
                        self.source_location(location)?
                    ));
                }
                if self.config.build_mode == BuildMode::Development && self.config.emit_self {
                    entries.push("[\"__self\"]: this".to_string());
                }
                let props = if entries.is_empty() {
                    "null".to_string()
                } else {
                    format!("{{{}}}", entries.join(", "))
                };
                let factory = self
                    .config
                    .classic_pragma
                    .clone()
                    .unwrap_or_else(|| format!("{object}.{method}"));
                let mut arguments = vec![element_type, props];
                for child in &element.children {
                    arguments.push(self.child(child)?);
                }
                Ok(format!("{factory}({})", arguments.join(", ")))
            }
            CallConvention::Automatic {
                factory,
                import_source,
            } => {
                let factory_alias = self.imported(import_source, factory);
                let props = format!("{{{}}}", entries.join(", "));
                let has_named_key =
                    element.props.entries.iter().any(
                        |entry| matches!(entry, PropsEntry::Named(prop) if prop.name == "key"),
                    );
                let type_binding = format!("{}type", self.binding_prefix);
                let key_binding = format!("{}key", self.binding_prefix);
                let props_binding = format!("{}props", self.binding_prefix);
                let mut arguments = if has_named_key {
                    vec![
                        type_binding.clone(),
                        props_binding.clone(),
                        key_binding.clone(),
                    ]
                } else {
                    vec![element_type.clone(), props.clone()]
                };
                if factory == "jsxDEV" {
                    if !has_named_key {
                        arguments.push("void 0".to_string());
                    }
                    arguments.push(element.is_static_children.to_string());
                    arguments.push(
                        element
                            .source_location
                            .as_ref()
                            .map(|location| self.source_location(location))
                            .transpose()?
                            .unwrap_or_else(|| "void 0".to_string()),
                    );
                    arguments.push(if self.config.emit_self {
                        "this".to_string()
                    } else {
                        "void 0".to_string()
                    });
                }
                let call = format!("{factory_alias}({})", arguments.join(", "));
                if has_named_key {
                    // Evaluate the complete config once, in source order, before
                    // moving its final key into the automatic runtime argument.
                    // Object rest preserves ref, symbol props and an own
                    // "__proto__" property without invoking Object.assign.
                    Ok(format!(
                        "(({type_binding}, {{key: {key_binding}, ...{props_binding}}}) => {call})({element_type}, {props})"
                    ))
                } else {
                    Ok(call)
                }
            }
        }
    }

    fn prop_value(&mut self, value: &LoweredPropValue) -> Result<String, ReactCompileError> {
        match value {
            LoweredPropValue::StringLiteral { value } => javascript_string(value),
            LoweredPropValue::BooleanTrue => Ok("true".to_string()),
            LoweredPropValue::Expression { expression } => self.expression(expression),
            LoweredPropValue::Null => Ok("null".to_string()),
            LoweredPropValue::Element(element) => self.element(element),
            LoweredPropValue::ChildrenArray { children } => {
                let values = children
                    .iter()
                    .map(|child| self.child(child))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(format!("[{}]", values.join(", ")))
            }
        }
    }

    fn child(&mut self, child: &LoweredChild) -> Result<String, ReactCompileError> {
        match child {
            LoweredChild::Text { value, .. } => javascript_string(value),
            LoweredChild::Expression { expression, .. } => self.expression(expression),
            LoweredChild::Element(element) => self.element(element),
        }
    }

    fn expression(&mut self, expression: &str) -> Result<String, ReactCompileError> {
        let parser_config = self.parser_config.clone();
        let transformed = transform_jsx_expressions(expression, &parser_config, |parsed| {
            if self.expression_depth >= self.parser_config.max_depth {
                return Err(ReactCompileError::IrGenerationError(
                    "nested JSX expression depth limit exceeded".to_string(),
                ));
            }
            let lowered = lower_parse_result(&parsed, self.config)
                .map_err(|error| ReactCompileError::LoweringError(format!("{error:?}")))?;
            self.expression_depth += 1;
            let emitted = self.element(&lowered.element);
            self.expression_depth -= 1;
            emitted
        });
        javascript_expression(&transformed?)
    }

    fn source_location(&self, location: &SourceLocation) -> Result<String, ReactCompileError> {
        serde_json::to_string(&serde_json::json!({
            "fileName": location.file_name,
            "lineNumber": location.line_number,
            "columnNumber": location.column_number,
        }))
        .map_err(|error| ReactCompileError::SerializationError(error.to_string()))
    }
}

fn contains_raw_expression(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => {
            (fields.len() == 1 && fields.get("Raw").is_some_and(serde_json::Value::is_string))
                || fields.values().any(contains_raw_expression)
        }
        serde_json::Value::Array(values) => values.iter().any(contains_raw_expression),
        _ => false,
    }
}

/// Conservatively decode identifier escape spellings even inside strings or
/// comments: false collisions are harmless, captured source identifiers aren't.
fn decode_unicode_escapes(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut remaining = source;
    while !remaining.is_empty() {
        if let Some(after_escape) = remaining.strip_prefix("\\u") {
            let parsed = if let Some(braced) = after_escape.strip_prefix('{') {
                braced.find('}').and_then(|end| {
                    u32::from_str_radix(&braced[..end], 16)
                        .ok()
                        .and_then(char::from_u32)
                        .map(|value| (value, end + 4))
                })
            } else {
                after_escape.get(..4).and_then(|digits| {
                    u32::from_str_radix(digits, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .map(|value| (value, 6))
                })
            };
            if let Some((value, consumed)) = parsed {
                output.push(value);
                remaining = &remaining[consumed..];
                continue;
            }
        }
        let character = remaining.chars().next().expect("remaining is not empty");
        output.push(character);
        remaining = &remaining[character.len_utf8()..];
    }
    output
}

fn javascript_string(value: &str) -> Result<String, ReactCompileError> {
    serde_json::to_string(value)
        .map(|literal| {
            literal
                .replace('\u{2028}', "\\u2028")
                .replace('\u{2029}', "\\u2029")
        })
        .map_err(|error| ReactCompileError::SerializationError(error.to_string()))
}

fn javascript_expression(expression: &str) -> Result<String, ReactCompileError> {
    if expression.trim().is_empty() {
        return Err(ReactCompileError::IrGenerationError(
            "empty JSX expression".to_string(),
        ));
    }
    // Newlines keep a trailing line comment from consuming the closing
    // delimiter. Parentheses retain comma expressions as a single argument.
    Ok(format!("(\n{expression}\n)"))
}

/// Generate a source map for the transformation.
fn generate_source_map(original: &str, _generated: &str) -> Result<String, ReactCompileError> {
    // Basic source map generation - in a full implementation this would be more sophisticated
    let source_map = serde_json::json!({
        "version": 3,
        "sources": ["input.jsx"],
        "names": [],
        "mappings": "",
        "sourcesContent": [original]
    });

    serde_json::to_string(&source_map).map_err(|e| ReactCompileError::SourceMapError(e.to_string()))
}

/// Extract feature families used in the parse result.
fn extract_feature_families(parse_result: &JsxParseResult) -> Vec<String> {
    // Extract the feature families that were encountered during parsing
    parse_result
        .feature_families_used
        .iter()
        .map(|f| format!("{:?}", f))
        .collect()
}

/// Count transforms by type in the lowering result.
fn count_transforms(lowering_result: &ReactLoweringResult) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::new();

    // Count transforms based on the feature families exercised during lowering.
    for family in &lowering_result.feature_families_used {
        *counts.entry(format!("{:?}", family)).or_insert(0) += 1;
    }

    counts
}

/// Compute deterministic process hash for compilation.
fn compute_process_hash(
    result: &ReactCompileResult,
    _config: &ReactCompileConfig,
) -> Result<ContentHash, ReactCompileError> {
    let process_data = serde_json::json!({
        "pipeline": "react_compilation",
        "steps": ["parse", "lower", "generate"],
        "input_hash": result.metadata.input_hash,
        "config_hash": result.metadata.config_hash,
        "output_hash": ContentHash::compute(result.generated_code.as_bytes()),
        "feature_families": result.metadata.feature_families,
        "transform_counts": result.metadata.transform_counts
    });

    Ok(ContentHash::compute(
        &serde_json::to_vec(&process_data)
            .map_err(|e| ReactCompileError::SerializationError(e.to_string()))?,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_react_compile_simple_element() {
        let source = r#"<div className="test">Hello World</div>"#;
        let config = ReactCompileConfig::default();

        let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
        assert!(
            result.is_ok(),
            "Compilation should succeed for simple element"
        );

        let result = result.expect("operation should succeed for valid inputs");
        assert_eq!(result.source, source);
        assert!(
            !result.generated_code.is_empty(),
            "Should generate output code"
        );
    }

    #[test]
    fn test_empty_input_error() {
        let config = ReactCompileConfig::default();
        let result = compile_react_source("", ReactInputLanguage::Jsx, &config);
        assert!(matches!(result, Err(ReactCompileError::EmptyInput)));
    }

    #[test]
    fn test_react_compile_with_expressions() {
        let source = r#"<div>{name}</div>"#;
        let config = ReactCompileConfig::default();

        let result = compile_react_source(source, ReactInputLanguage::Jsx, &config);
        assert!(
            result.is_ok(),
            "Compilation should succeed for expression children"
        );
    }

    #[test]
    fn test_compilation_evidence_generation() {
        let source = r#"<span>Test</span>"#;
        let config = ReactCompileConfig::default();

        let result = compile_react_source(source, ReactInputLanguage::Jsx, &config)
            .expect("operation should succeed for valid inputs");
        let evidence = generate_compilation_evidence(&result, &config, ReactInputLanguage::Jsx)
            .expect("Evidence generation should succeed");

        assert!(evidence.output_spec.success);
        assert_eq!(
            evidence.compile_receipt.component,
            REACT_COMPILATION_COMPONENT
        );
    }

    #[test]
    fn test_typescript_jsx_language() {
        assert_eq!(ReactInputLanguage::Tsx.as_str(), "tsx");
        assert_eq!(ReactInputLanguage::Tsx.file_extension(), ".tsx");
        assert_eq!(ReactInputLanguage::Jsx.as_str(), "jsx");
        assert_eq!(ReactInputLanguage::Jsx.file_extension(), ".jsx");
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(ReactOutputFormat::JavaScript.as_str(), "javascript");
        assert_eq!(ReactOutputFormat::Ir3.as_str(), "ir3");
    }
}
