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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::ast::{Expression, ParseGoal, SourceSpan, Statement, SyntaxTree};
use crate::hash_tiers::ContentHash;
use crate::jsx_tsx_parser::{
    JsxChild, JsxNode, JsxParseError, JsxParseResult, JsxParserConfig, JsxTransformedSource,
    parse_jsx, transform_jsx_with_spans,
};
use crate::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};
use crate::react_jsx_lowering::{
    BuildMode, CallConvention, ElementType, LoweredChild, LoweredElement, LoweredPropValue,
    PropsEntry, ReactLoweringConfig, ReactLoweringResult, SourceLocation, lower_parse_result,
};
use crate::security_epoch::SecurityEpoch;
use crate::ts_normalization::{
    TsNormalizationConfig, TsNormalizationError, normalize_typescript_to_es2020,
};

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

/// An entire JavaScript/TypeScript module after JSX lowering and type erasure.
/// Unlike the expression API, this retains imports, exports, declarations,
/// directive prologues and executable statements around every JSX expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactModuleCompileResult {
    pub source: String,
    pub generated_code: String,
    pub source_map: Option<String>,
    pub metadata: ReactCompileMetadata,
    /// Number of emitted JSX elements and fragments, including nested ones.
    pub jsx_elements: usize,
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
        Some(generate_fragment_source_map(
            source,
            &generated_code,
            parse_result.node.span().start_offset as usize,
            language,
            config,
        )?)
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

/// Compile a complete JS/JSX or TS/TSX module through the shared JSX emitter.
///
/// `Jsx` accepts ordinary JavaScript, and `Tsx` accepts ordinary TypeScript;
/// a module need not contain JSX or any runtime statements. Generated runtime
/// imports are hygienic across the whole source and follow its directives.
/// Source maps retain verified unchanged-line anchors and locate generated JSX
/// calls at their source element. Type-erased lines without an exact
/// correspondence are left unmapped, rather than assigned invented positions.
pub fn compile_react_module(
    source: &str,
    language: ReactInputLanguage,
    config: &ReactCompileConfig,
) -> Result<ReactModuleCompileResult, ReactCompileError> {
    let normalized = if language == ReactInputLanguage::Tsx && !source.trim().is_empty() {
        let mut ts_config = TsNormalizationConfig::default();
        ts_config.compiler_options.jsx = "preserve".to_string();
        match normalize_typescript_to_es2020(
            source,
            &ts_config,
            "react-module-compile",
            "react-module-normalize",
            REACT_COMPILATION_POLICY_ID,
        ) {
            Ok(normalized) => normalized.normalized_source,
            // A file containing only interfaces/type imports is a valid,
            // empty runtime module. Unsupported syntax uses other variants.
            Err(TsNormalizationError::EmptySource) => String::new(),
            Err(error) => return Err(ReactCompileError::ParseError(error.to_string())),
        }
    } else {
        source.to_string()
    };
    let locations = OriginalLocations::new(source, &normalized);
    let mut parser_config = config.parser_config.clone();
    parser_config.tsx_mode = language == ReactInputLanguage::Tsx;
    let mut emitter = JavaScriptEmitter::new(
        source,
        &config.lowering_config,
        &parser_config,
        Some(&locations),
    );
    let mut transformed =
        transform_jsx_with_spans(&normalized, &parser_config, true, |parsed, range| {
            emitter.source_offset = range.start;
            emitter.original_offset = locations.range_origin(range);
            emitter.lower_and_emit(&parsed)
        })?;
    // Validate the whole module, not just each transformed expression. The
    // parsed directive spans also tell us where imports may safely be added.
    let parsed = match validate_generated_module(&transformed.code) {
        Err(ReactCompileError::EmptyInput) => {
            // The runtime's canonical parser rejects an empty source unit.
            // An empty export keeps type-only and comment-only files valid
            // modules without adding any executable behavior or bindings.
            transformed.code.push_str("\nexport {};\n");
            validate_generated_module(&transformed.code)?
        }
        result => result?,
    };
    let insertion = runtime_import_insertion(&transformed.code, &parsed);
    let imports = emitter.runtime_imports()?;
    let injected = if imports.is_empty() {
        String::new()
    } else {
        format!("\n{imports}")
    };
    let mut generated_code = String::with_capacity(transformed.code.len() + injected.len());
    generated_code.push_str(&transformed.code[..insertion]);
    generated_code.push_str(&injected);
    generated_code.push_str(&transformed.code[insertion..]);
    if !injected.is_empty() {
        validate_generated_module(&generated_code)?;
    }
    let source_map = config
        .generate_source_maps
        .then(|| {
            generate_module_source_map(
                &locations,
                &transformed,
                &generated_code,
                insertion,
                injected.len(),
                language,
                config,
            )
        })
        .transpose()?;
    if normalized != source && language == ReactInputLanguage::Tsx {
        emitter.feature_families.insert("TypeScript".to_string());
        emitter
            .transform_counts
            .insert("TypeScriptNormalization".to_string(), 1);
    }
    let metadata = ReactCompileMetadata {
        input_hash: ContentHash::compute(source.as_bytes()),
        config_hash: ContentHash::compute(
            &serde_json::to_vec(&serde_json::json!({
                "config": config,
                "language": language,
                "input_kind": "module",
            }))
            .map_err(|error| ReactCompileError::SerializationError(error.to_string()))?,
        ),
        timestamp: config.compile_epoch.as_u64(),
        feature_families: emitter.feature_families.into_iter().collect(),
        transform_counts: emitter.transform_counts,
    };
    Ok(ReactModuleCompileResult {
        source: source.to_string(),
        generated_code,
        source_map,
        metadata,
        jsx_elements: emitter.jsx_elements,
    })
}

/// Bind a complete-module compilation to the same receipt format as fragments.
pub fn generate_module_compilation_evidence(
    result: &ReactModuleCompileResult,
    config: &ReactCompileConfig,
    language: ReactInputLanguage,
) -> Result<ReactCompileEvidence, ReactCompileError> {
    let output_hash = ContentHash::compute(result.generated_code.as_bytes());
    let process = serde_json::json!({
        "pipeline": "react_module_compilation",
        "steps": ["normalize_types", "transform_jsx", "validate_module"],
        "input_hash": result.metadata.input_hash,
        "config_hash": result.metadata.config_hash,
        "output_hash": output_hash,
        "source_map_hash": result.source_map.as_ref().map(|map| ContentHash::compute(map.as_bytes())),
        "jsx_elements": result.jsx_elements,
        "feature_families": result.metadata.feature_families,
        "transform_counts": result.metadata.transform_counts,
    });
    let process_hash = ContentHash::compute(
        &serde_json::to_vec(&process)
            .map_err(|error| ReactCompileError::SerializationError(error.to_string()))?,
    );
    Ok(ReactCompileEvidence {
        input_spec: ReactInputSpec {
            source_hash: result.metadata.input_hash,
            language,
            config: config.clone(),
        },
        output_spec: ReactOutputSpec {
            code_hash: output_hash,
            format: ReactOutputFormat::JavaScript,
            success: true,
        },
        compile_receipt: ReactCompileReceipt {
            schema_version: REACT_COMPILATION_SCHEMA_VERSION.to_string(),
            component: REACT_COMPILATION_COMPONENT.to_string(),
            input_hash: result.metadata.input_hash,
            output_hash,
            config_hash: result.metadata.config_hash,
            process_hash,
        },
        timestamp: result.metadata.timestamp,
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
    let mut emitter = JavaScriptEmitter::new(source, config, parser_config, None);
    // Expression containers can introduce factories and fragments absent from
    // the outer lowering result. Emit the body first to discover all imports.
    let body = emitter.element(&lowering_result.element)?;
    let mut output = emitter.runtime_imports()?;
    output.push_str(&body);
    output.push_str(";\n");
    validate_generated_module(&output)?;
    Ok(output)
}

fn validate_generated_module(output: &str) -> Result<SyntaxTree, ReactCompileError> {
    // JSX expression containers carry source text. Validate the emitted module
    // with the engine parser before returning a successful compile receipt.
    let parsed = CanonicalEs2020Parser
        .parse(output, ParseGoal::Module)
        .map_err(|error| {
            if error.code == ParseErrorCode::EmptySource {
                ReactCompileError::EmptyInput
            } else {
                ReactCompileError::IrGenerationError(error.to_string())
            }
        })?;
    // Raw is a recovery node, not proof that an expression is valid JS. It
    // would become a SyntaxError during native lowering, so fail compilation
    // here instead of issuing a successful receipt for unusable output.
    let serialized = serde_json::to_value(&parsed)
        .map_err(|error| ReactCompileError::SerializationError(error.to_string()))?;
    if contains_raw_expression(&serialized) {
        return Err(ReactCompileError::IrGenerationError(
            "generated module contains an unsupported JavaScript expression".to_string(),
        ));
    }
    Ok(parsed)
}

fn runtime_import_insertion(source: &str, parsed: &SyntaxTree) -> usize {
    parsed
        .body
        .iter()
        .skip_while(|statement| {
            matches!(statement,
                Statement::Expression(statement)
                    if matches!(statement.expression, Expression::StringLiteral(_)))
        })
        // Named declaration exports expand to a declaration followed by its
        // export record. The declaration span starts after `export`, while
        // the following record retains the full source statement's span.
        // Choose the earliest surface span, never the interior declaration.
        .map(|statement| statement.span().start_offset as usize)
        .min()
        .unwrap_or(source.len())
}

struct JavaScriptEmitter<'a> {
    config: &'a ReactLoweringConfig,
    parser_config: &'a JsxParserConfig,
    import_aliases: BTreeMap<(String, String), String>,
    binding_prefix: String,
    expression_depth: usize,
    locations: Option<&'a OriginalLocations<'a>>,
    source_offset: usize,
    original_offset: Option<usize>,
    feature_families: BTreeSet<String>,
    transform_counts: BTreeMap<String, u32>,
    jsx_elements: usize,
}

impl<'a> JavaScriptEmitter<'a> {
    fn new(
        source: &str,
        config: &'a ReactLoweringConfig,
        parser_config: &'a JsxParserConfig,
        locations: Option<&'a OriginalLocations<'a>>,
    ) -> Self {
        let identifier_source = decode_unicode_escapes(source);
        let mut binding_prefix = "__franken_react_".to_string();
        while identifier_source.contains(&binding_prefix) {
            binding_prefix.push('_');
        }
        Self {
            config,
            parser_config,
            import_aliases: BTreeMap::new(),
            binding_prefix,
            expression_depth: 0,
            locations,
            source_offset: 0,
            original_offset: None,
            feature_families: BTreeSet::new(),
            transform_counts: BTreeMap::new(),
            jsx_elements: 0,
        }
    }

    fn runtime_imports(&self) -> Result<String, ReactCompileError> {
        let mut imports = String::new();
        for ((source, name), alias) in &self.import_aliases {
            imports.push_str(&format!(
                "import {{ {name} as {alias} }} from {};\n",
                javascript_string(source)?
            ));
        }
        Ok(imports)
    }

    fn lower_and_emit(&mut self, parsed: &JsxParseResult) -> Result<String, ReactCompileError> {
        let mut lowered = lower_parse_result(parsed, self.config)
            .map_err(|error| ReactCompileError::LoweringError(format!("{error:?}")))?;
        if self.locations.is_some() {
            retain_module_child_expression_spans(&parsed.node, &mut lowered.element);
        }
        self.feature_families
            .extend(extract_feature_families(parsed));
        for (family, count) in count_transforms(&lowered) {
            *self.transform_counts.entry(family).or_default() += count;
        }
        self.element(&lowered.element)
    }

    fn imported(&mut self, source: &str, name: &str) -> String {
        let alias = format!("{}{}", self.binding_prefix, self.import_aliases.len());
        self.import_aliases
            .entry((source.to_string(), name.to_string()))
            .or_insert(alias)
            .clone()
    }

    fn element(&mut self, element: &LoweredElement) -> Result<String, ReactCompileError> {
        self.jsx_elements += 1;
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
                    self.prop_value(&prop.value, prop.span.as_ref())?
                )),
                PropsEntry::Spread { expression, span } => {
                    Ok(format!("...{}", self.expression(expression, Some(span))?))
                }
            })
            .collect::<Result<Vec<_>, ReactCompileError>>()?;

        let source_location = self.element_source_location(element);
        match &element.call_convention {
            CallConvention::Classic { object, method } => {
                if let Some(location) = &source_location {
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
                        source_location
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

    fn prop_value(
        &mut self,
        value: &LoweredPropValue,
        span: Option<&SourceSpan>,
    ) -> Result<String, ReactCompileError> {
        match value {
            LoweredPropValue::StringLiteral { value } => javascript_string(value),
            LoweredPropValue::BooleanTrue => Ok("true".to_string()),
            LoweredPropValue::Expression { expression } => self.expression(expression, span),
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
            LoweredChild::Expression { expression, span } => {
                self.expression(expression, Some(span))
            }
            LoweredChild::Element(element) => self.element(element),
        }
    }

    fn expression(
        &mut self,
        expression: &str,
        span: Option<&SourceSpan>,
    ) -> Result<String, ReactCompileError> {
        let parser_config = self.parser_config.clone();
        let previous_offset = self.source_offset;
        let previous_original = self.original_offset;
        let expression_offset = self.locations.and_then(|locations| {
            let span = span?;
            let start = previous_offset + span.start_offset as usize;
            let end = previous_offset + span.end_offset as usize;
            locations
                .normalized
                .get(start..end)?
                .find(expression)
                .map(|offset| start + offset)
        });
        let transformed =
            transform_jsx_with_spans(expression, &parser_config, false, |parsed, range| {
                if self.expression_depth >= self.parser_config.max_depth {
                    return Err(ReactCompileError::IrGenerationError(
                        "nested JSX expression depth limit exceeded".to_string(),
                    ));
                }
                if let Some(expression_offset) = expression_offset {
                    self.source_offset = expression_offset + range.start;
                    self.original_offset = previous_original
                        .map(|origin| origin + self.source_offset - previous_offset)
                        .or_else(|| {
                            self.locations.and_then(|locations| {
                                locations.range_origin(
                                    expression_offset + range.start..expression_offset + range.end,
                                )
                            })
                        });
                }
                self.expression_depth += 1;
                let emitted = self.lower_and_emit(&parsed);
                self.expression_depth -= 1;
                self.source_offset = previous_offset;
                self.original_offset = previous_original;
                emitted
            });
        javascript_expression(&transformed?.code)
    }

    fn element_source_location(&self, element: &LoweredElement) -> Option<SourceLocation> {
        let location = element.source_location.as_ref()?;
        let Some(locations) = self.locations else {
            return Some(location.clone());
        };
        let relative = element.span.start_offset as usize;
        let original = self
            .original_offset
            .map(|offset| offset + relative)
            .or_else(|| locations.original_offset(self.source_offset + relative))?;
        let (line, column) =
            source_position(locations.original, &locations.original_lines, original);
        Some(SourceLocation {
            file_name: location.file_name.clone(),
            line_number: line as u32 + 1,
            column_number: column as u32 + 1,
        })
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

/// Automatic lowering folds a single expression child into a synthetic prop.
/// Recover that child's span from the parsed tree before emitting a module so
/// nested JSX in `items.map(...)` retains its true development source location.
fn retain_module_child_expression_spans(node: &JsxNode, lowered: &mut LoweredElement) {
    fn collect<'a>(
        start: u64,
        children: &'a [JsxChild],
        spans: &mut BTreeMap<u64, Vec<(&'a str, &'a SourceSpan)>>,
    ) {
        for child in children {
            match child {
                JsxChild::ExpressionContainer { expression, span } => {
                    spans.entry(start).or_default().push((expression, span));
                }
                JsxChild::Element(element) => {
                    collect(element.span.start_offset, &element.children, spans)
                }
                JsxChild::Fragment(fragment) => {
                    collect(fragment.span.start_offset, &fragment.children, spans)
                }
                JsxChild::Text { .. } => {}
            }
        }
    }
    fn visit_value(value: &mut LoweredPropValue, spans: &BTreeMap<u64, Vec<(&str, &SourceSpan)>>) {
        match value {
            LoweredPropValue::Element(element) => visit_element(element, spans),
            LoweredPropValue::ChildrenArray { children } => visit_children(children, spans),
            _ => {}
        }
    }
    fn visit_children(
        children: &mut [LoweredChild],
        spans: &BTreeMap<u64, Vec<(&str, &SourceSpan)>>,
    ) {
        for child in children {
            if let LoweredChild::Element(element) = child {
                visit_element(element, spans);
            }
        }
    }
    fn visit_element(
        element: &mut LoweredElement,
        spans: &BTreeMap<u64, Vec<(&str, &SourceSpan)>>,
    ) {
        for entry in &mut element.props.entries {
            if let PropsEntry::Named(prop) = entry {
                if prop.name == "children"
                    && prop.span.is_none()
                    && let LoweredPropValue::Expression { expression } = &prop.value
                    && let Some(children) = spans.get(&element.span.start_offset)
                    && let Some((_, span)) = children.iter().find(|(text, _)| *text == expression)
                {
                    prop.span = Some(**span);
                }
                visit_value(&mut prop.value, spans);
            }
        }
        visit_children(&mut element.children, spans);
    }
    let mut spans = BTreeMap::new();
    match node {
        JsxNode::Element(element) => {
            collect(element.span.start_offset, &element.children, &mut spans)
        }
        JsxNode::Fragment(fragment) => {
            collect(fragment.span.start_offset, &fragment.children, &mut spans)
        }
    }
    visit_element(lowered, &spans);
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

/// Exact surviving-line correspondence through type erasure. The TS normalizer
/// also lowers enums/namespaces; its historical identity-line map cannot be
/// composed safely. Ambiguous or rewritten lines therefore remain unmapped.
struct OriginalLocations<'a> {
    original: &'a str,
    normalized: &'a str,
    original_lines: Vec<usize>,
    normalized_lines: Vec<usize>,
    line_origins: Vec<Option<usize>>,
}

impl<'a> OriginalLocations<'a> {
    fn new(original: &'a str, normalized: &'a str) -> Self {
        let original_lines = source_line_starts(original);
        let normalized_lines = source_line_starts(normalized);
        let mut line_origins = vec![None; normalized_lines.len()];
        if original != normalized {
            let mut original_occurrences = BTreeMap::<&str, Vec<usize>>::new();
            let mut normalized_occurrences = BTreeMap::<&str, Vec<usize>>::new();
            for (source, starts, occurrences) in [
                (original, &original_lines, &mut original_occurrences),
                (normalized, &normalized_lines, &mut normalized_occurrences),
            ] {
                for (line, &start) in starts.iter().enumerate() {
                    let end = starts.get(line + 1).copied().unwrap_or(source.len());
                    let text =
                        source[start..end].trim_end_matches(['\r', '\n', '\u{2028}', '\u{2029}']);
                    if !text.trim().is_empty() {
                        occurrences.entry(text).or_default().push(line);
                    }
                }
            }
            for (text, normalized_matches) in normalized_occurrences {
                let Some(original_matches) = original_occurrences.get(text) else {
                    continue;
                };
                // Never guess which repeated line survived an erased type.
                if normalized_matches.len() == original_matches.len() {
                    for (normalized, original) in
                        normalized_matches.into_iter().zip(original_matches)
                    {
                        line_origins[normalized] = Some(original_lines[*original]);
                    }
                }
            }
        }
        Self {
            original,
            normalized,
            original_lines,
            normalized_lines,
            line_origins,
        }
    }

    fn original_offset(&self, offset: usize) -> Option<usize> {
        if self.original == self.normalized {
            return Some(offset);
        }
        let line = self
            .normalized_lines
            .partition_point(|start| *start <= offset)
            - 1;
        let original = self.line_origins[line]? + offset - self.normalized_lines[line];
        self.original.is_char_boundary(original).then_some(original)
    }

    fn range_origin(&self, range: Range<usize>) -> Option<usize> {
        let fragment = self.normalized.get(range.clone())?;
        if let Some(offset) = self.original_offset(range.start)
            && self.original.get(offset..offset + fragment.len()) == Some(fragment)
        {
            return Some(offset);
        }
        // JSX on a type-erased declaration line often survives verbatim even
        // when the entire line does not. Only a unique match is trustworthy.
        let mut matches = self.original.match_indices(fragment);
        let (offset, _) = matches.next()?;
        matches.next().is_none().then_some(offset)
    }
}

fn source_line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0];
    let mut characters = source.char_indices().peekable();
    while let Some((offset, character)) = characters.next() {
        if character == '\r' && characters.peek().is_some_and(|(_, next)| *next == '\n') {
            let (offset, _) = characters.next().expect("peeked line feed");
            starts.push(offset + 1);
        } else if matches!(character, '\r' | '\n' | '\u{2028}' | '\u{2029}') {
            starts.push(offset + character.len_utf8());
        }
    }
    starts
}

fn source_position(source: &str, lines: &[usize], offset: usize) -> (usize, usize) {
    let line = lines.partition_point(|start| *start <= offset) - 1;
    // Source Map v3 columns count UTF-16 code units, not UTF-8 bytes.
    (line, source[lines[line]..offset].encode_utf16().count())
}

#[derive(Clone, Copy)]
struct SourceMapping {
    generated: usize,
    original: Option<usize>,
}

fn copied_source_mappings(
    locations: &OriginalLocations<'_>,
    source: Range<usize>,
    generated: usize,
    mappings: &mut Vec<SourceMapping>,
) {
    if source.is_empty() {
        return;
    }
    mappings.push(SourceMapping {
        generated,
        original: locations.original_offset(source.start),
    });
    for start in locations
        .normalized_lines
        .iter()
        .copied()
        .skip_while(|start| *start <= source.start)
        .take_while(|start| *start < source.end)
    {
        mappings.push(SourceMapping {
            generated: generated + start - source.start,
            original: locations.original_offset(start),
        });
    }
}

fn generate_module_source_map(
    locations: &OriginalLocations<'_>,
    transformed: &JsxTransformedSource,
    generated: &str,
    insertion: usize,
    inserted_bytes: usize,
    language: ReactInputLanguage,
    config: &ReactCompileConfig,
) -> Result<String, ReactCompileError> {
    let mut mappings = Vec::new();
    let mut source_cursor = 0;
    let mut generated_cursor = 0;
    for region in &transformed.regions {
        copied_source_mappings(
            locations,
            source_cursor..region.source.start,
            generated_cursor,
            &mut mappings,
        );
        let origin = locations.range_origin(region.source.clone());
        for line in source_line_starts(&transformed.code[region.generated.clone()]) {
            mappings.push(SourceMapping {
                generated: region.generated.start + line,
                original: origin,
            });
        }
        source_cursor = region.source.end;
        generated_cursor = region.generated.end;
    }
    copied_source_mappings(
        locations,
        source_cursor..locations.normalized.len(),
        generated_cursor,
        &mut mappings,
    );
    if inserted_bytes != 0 {
        // Save the original position at the insertion point even when it lies
        // between existing segments (e.g. after a same-line directive).
        let resume = if let Some(region) = transformed
            .regions
            .iter()
            .find(|region| region.generated.contains(&insertion))
        {
            locations.range_origin(region.source.clone())
        } else {
            let preceding = transformed
                .regions
                .iter()
                .take_while(|region| region.generated.end <= insertion)
                .last();
            let normalized_offset = preceding.map_or(insertion, |region| {
                region.source.end + insertion - region.generated.end
            });
            locations.original_offset(normalized_offset)
        };
        for mapping in &mut mappings {
            if mapping.generated >= insertion {
                mapping.generated += inserted_bytes;
            }
        }
        mappings.push(SourceMapping {
            generated: insertion,
            original: None,
        });
        if !mappings
            .iter()
            .any(|mapping| mapping.generated == insertion + inserted_bytes)
        {
            mappings.push(SourceMapping {
                generated: insertion + inserted_bytes,
                original: resume,
            });
        }
    }
    encode_source_map(
        locations.original,
        generated,
        mappings,
        language,
        config,
        "unchanged-lines-and-jsx-origins",
    )
}

fn generate_fragment_source_map(
    original: &str,
    generated: &str,
    origin: usize,
    language: ReactInputLanguage,
    config: &ReactCompileConfig,
) -> Result<String, ReactCompileError> {
    let mappings = source_line_starts(generated)
        .into_iter()
        .map(|generated_offset| {
            SourceMapping {
                generated: generated_offset,
                // Runtime imports have no source counterpart. Generated factory
                // calls carry the fragment's actual origin, explicitly coarse.
                original: (!generated[generated_offset..].starts_with("import ")).then_some(origin),
            }
        })
        .collect();
    encode_source_map(
        original,
        generated,
        mappings,
        language,
        config,
        "jsx-fragment-origin",
    )
}

fn encode_source_map(
    original: &str,
    generated: &str,
    mut mappings: Vec<SourceMapping>,
    language: ReactInputLanguage,
    config: &ReactCompileConfig,
    precision: &str,
) -> Result<String, ReactCompileError> {
    let original_lines = source_line_starts(original);
    let generated_lines = source_line_starts(generated);
    mappings.sort_by_key(|mapping| mapping.generated);
    mappings.dedup_by_key(|mapping| mapping.generated);
    let mut encoded = String::new();
    let mut line = 0;
    let mut generated_column = 0_i64;
    let mut original_line = 0_i64;
    let mut original_column = 0_i64;
    let mut has_segment = false;
    for mapping in mappings {
        let (next_line, next_column) =
            source_position(generated, &generated_lines, mapping.generated);
        while line < next_line {
            encoded.push(';');
            line += 1;
            generated_column = 0;
            has_segment = false;
        }
        if has_segment {
            encoded.push(',');
        }
        encode_vlq(next_column as i64 - generated_column, &mut encoded);
        generated_column = next_column as i64;
        if let Some(offset) = mapping.original {
            let (next_original_line, next_original_column) =
                source_position(original, &original_lines, offset);
            encode_vlq(0, &mut encoded); // All segments refer to sources[0].
            encode_vlq(next_original_line as i64 - original_line, &mut encoded);
            encode_vlq(next_original_column as i64 - original_column, &mut encoded);
            original_line = next_original_line as i64;
            original_column = next_original_column as i64;
        }
        has_segment = true;
    }
    let fallback = format!("input{}", language.file_extension());
    let source_name = config
        .lowering_config
        .source_file
        .as_deref()
        .unwrap_or(&fallback);
    let source_map = serde_json::json!({
        "version": 3,
        "sources": [source_name],
        "names": [],
        "mappings": encoded,
        "sourcesContent": [original],
        "x_franken_mapping_precision": precision,
    });
    serde_json::to_string(&source_map)
        .map_err(|error| ReactCompileError::SourceMapError(error.to_string()))
}

fn encode_vlq(value: i64, encoded: &mut String) {
    const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut digits = (value.unsigned_abs() << 1) | u64::from(value < 0);
    loop {
        let mut digit = (digits & 31) as usize;
        digits >>= 5;
        if digits != 0 {
            digit |= 32;
        }
        encoded.push(char::from(BASE64[digit]));
        if digits == 0 {
            break;
        }
    }
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

    #[test]
    fn module_preserves_directives_imports_exports_and_hygienic_aliases() {
        let source = "#!/usr/bin/env node\n\"use client\";\nimport { Card } from './Card.jsx';\nconst __franken_react_0 = 'caller';\nexport function App() { return <main><Card />{__franken_react_0}</main>; }\nexport default App;\n";
        let result = compile_react_module(
            source,
            ReactInputLanguage::Jsx,
            &ReactCompileConfig::default(),
        )
        .expect("complete module");
        assert!(
            result
                .generated_code
                .starts_with("#!/usr/bin/env node\n\"use client\";")
        );
        assert!(
            result
                .generated_code
                .contains("import { Card } from './Card.jsx';")
        );
        assert!(result.generated_code.contains("export function App()"));
        assert!(result.generated_code.contains("export default App;"));
        assert!(result.generated_code.contains("as __franken_react__0"));
        assert_eq!(result.jsx_elements, 2);
        assert!(
            result.generated_code.find("\"use client\"").unwrap()
                < result
                    .generated_code
                    .find("from \"react/jsx-runtime\"")
                    .unwrap()
        );
    }

    #[test]
    fn module_runtime_imports_precede_complete_export_declarations() {
        for declaration in [
            "export const app = <div/>;",
            "export function App() { return <div/>; }",
            "export default function App() { return <div/>; }",
            "export class App { render() { return <div/>; } }",
            "export default class App { render() { return <div/>; } }",
        ] {
            let source = format!("\"use client\";\n{declaration}");
            let compiled = compile_react_module(
                &source,
                ReactInputLanguage::Jsx,
                &ReactCompileConfig::default(),
            )
            .unwrap_or_else(|error| panic!("{declaration}: {error}"));
            let imports = compiled.generated_code.find("import {").unwrap();
            let export = compiled.generated_code.find("export ").unwrap();
            assert!(imports < export, "{}", compiled.generated_code);
            assert!(compiled.generated_code.starts_with("\"use client\";"));
            assert_eq!(compiled.jsx_elements, 1);
        }
    }

    #[test]
    fn module_scanner_preserves_quoted_template_and_regex_text() {
        let source = r#"
const text = "<Literal/>";
const template = `<Template/>`;
function f() {} /<Pattern>/.test(text);
export default <div title={text}>{template}</div>;
"#;
        let result = compile_react_module(
            source,
            ReactInputLanguage::Jsx,
            &ReactCompileConfig::default(),
        )
        .expect("module containing non-JSX angle brackets");
        assert!(result.generated_code.contains(r#""<Literal/>""#));
        assert!(result.generated_code.contains("`<Template/>`"));
        assert!(result.generated_code.contains("/<Pattern>/.test(text)"));
        assert!(!result.generated_code.contains("<div"));
        assert_eq!(result.jsx_elements, 1);
    }

    #[test]
    fn module_compiles_default_export_and_all_nested_jsx_roots() {
        let source = "const xs = [1, 2]; export default <>{xs.map(x => <b>{x}</b>)}<i>end</i></>;";
        let result = compile_react_module(
            source,
            ReactInputLanguage::Jsx,
            &ReactCompileConfig::default(),
        )
        .expect("nested JSX module");
        assert_eq!(result.jsx_elements, 3);
        assert_eq!(
            result
                .generated_code
                .matches("from \"react/jsx-runtime\"")
                .count(),
            3
        );
        assert!(result.generated_code.contains("Fragment as"));
        assert!(result.generated_code.contains("jsx as"));
        assert!(result.generated_code.contains("jsxs as"));
    }

    #[test]
    fn module_scanner_distinguishes_class_declarations_from_expression_division() {
        let source = r#"
class View { render() { return <main/>; } }
/<Declaration>/.test("<Declaration>");
const Value = class { render() { return <span/>; } } / 2;
export default class extends class {} { render() { return <footer/>; } }
/<Exported>/.test("<Exported>");
"#;
        let result = compile_react_module(
            source,
            ReactInputLanguage::Jsx,
            &ReactCompileConfig::default(),
        )
        .expect("classes preserve the following regular expression or division");
        assert_eq!(result.jsx_elements, 3);
        assert!(result.generated_code.contains("/<Declaration>/.test"));
        assert!(result.generated_code.contains("} / 2"));
        assert!(result.generated_code.contains("/<Exported>/.test"));
    }

    #[test]
    fn module_tsx_normalization_preserves_runtime_imports_and_erases_types() {
        let source = "import type { Props } from './types';\nimport { name } from './name.js';\ninterface Options { active: boolean; }\nexport function App(props: Props) { return <p title={name}>{props.label}</p>; }\n";
        let result = compile_react_module(
            source,
            ReactInputLanguage::Tsx,
            &ReactCompileConfig::default(),
        )
        .expect("typed module");
        assert!(!result.generated_code.contains("import type"));
        assert!(!result.generated_code.contains("interface Options"));
        assert!(!result.generated_code.contains("props: Props"));
        assert!(
            result
                .generated_code
                .contains("import { name } from './name.js';")
        );
        assert_eq!(result.jsx_elements, 1);
        assert_eq!(
            result
                .metadata
                .transform_counts
                .get("TypeScriptNormalization"),
            Some(&1)
        );
    }

    #[test]
    fn module_accepts_plain_js_and_empty_or_type_only_files() {
        let source = "export const answer = 42;\n";
        let config = ReactCompileConfig::default();
        let result = compile_react_module(source, ReactInputLanguage::Jsx, &config).unwrap();
        assert_eq!(result.generated_code, source);
        assert_eq!(result.jsx_elements, 0);
        for (source, language) in [
            ("", ReactInputLanguage::Jsx),
            ("// no runtime statements\n", ReactInputLanguage::Jsx),
            (
                "interface Props { label: string; }",
                ReactInputLanguage::Tsx,
            ),
            (
                "import type { Props } from './types';",
                ReactInputLanguage::Tsx,
            ),
        ] {
            let result = compile_react_module(source, language, &config).unwrap();
            validate_generated_module(&result.generated_code).expect("executable empty module");
            assert_eq!(result.jsx_elements, 0);
        }
    }

    #[test]
    fn module_rejects_invalid_surrounding_javascript_and_malformed_jsx() {
        for source in [
            "export const = <div/>;",
            "export default <div></span>;",
            "export default <div>{value +}</div>;",
        ] {
            assert!(
                compile_react_module(
                    source,
                    ReactInputLanguage::Jsx,
                    &ReactCompileConfig::default()
                )
                .is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn module_development_metadata_tracks_nested_expression_origins() {
        let source = "\nexport function App() {\n  return <div>{[1].map(value => <span>{value}</span>)}</div>;\n}\n";
        let mut config = ReactCompileConfig::default();
        config.lowering_config.build_mode = BuildMode::Development;
        config.lowering_config.source_file = Some("App.jsx".into());
        let result = compile_react_module(source, ReactInputLanguage::Jsx, &config).unwrap();
        assert!(
            result
                .generated_code
                .contains(r#""columnNumber":10,"fileName":"App.jsx","lineNumber":3"#),
            "{}",
            result.generated_code
        );
        assert!(
            result
                .generated_code
                .contains(r#""columnNumber":33,"fileName":"App.jsx","lineNumber":3"#),
            "{}",
            result.generated_code
        );
    }

    type DecodedMapping = (usize, usize, Option<(usize, usize)>);

    /// Decode the external v3 format independently of emission, then compare
    /// positions with concrete source tokens rather than encoded snapshots.
    fn decoded_mappings(map: &str) -> Vec<DecodedMapping> {
        let map: serde_json::Value = serde_json::from_str(map).unwrap();
        let mut original_line = 0_i64;
        let mut original_column = 0_i64;
        let mut result = Vec::new();
        for (line, encoded) in map["mappings"].as_str().unwrap().split(';').enumerate() {
            let mut generated_column = 0_i64;
            for segment in encoded.split(',').filter(|segment| !segment.is_empty()) {
                let mut values = Vec::new();
                let mut current = 0_u64;
                let mut shift = 0;
                for byte in segment.bytes() {
                    let digit = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                        .iter()
                        .position(|candidate| *candidate == byte)
                        .expect("base64 digit") as u64;
                    current |= (digit & 31) << shift;
                    if digit & 32 == 0 {
                        let magnitude = (current >> 1) as i64;
                        values.push(if current & 1 == 1 {
                            -magnitude
                        } else {
                            magnitude
                        });
                        current = 0;
                        shift = 0;
                    } else {
                        shift += 5;
                    }
                }
                assert!(values.len() == 1 || values.len() == 4);
                generated_column += values[0];
                let original = if values.len() == 4 {
                    assert_eq!(values[1], 0);
                    original_line += values[2];
                    original_column += values[3];
                    Some((original_line as usize, original_column as usize))
                } else {
                    None
                };
                result.push((line, generated_column as usize, original));
            }
        }
        result
    }

    #[test]
    fn module_source_maps_track_jsx_and_following_code_with_utf16_columns() {
        let source = "const emoji = '😀'; export const View = <div/>; const tail = 42;\nconsole.log(tail);\n";
        let config = ReactCompileConfig {
            generate_source_maps: true,
            ..Default::default()
        };
        let result = compile_react_module(source, ReactInputLanguage::Jsx, &config).unwrap();
        let map = result.source_map.as_deref().unwrap();
        let mappings = decoded_mappings(map);
        for (generated_token, original_token) in [
            ("(__franken_react_", "<div/>"),
            ("; const tail", "; const tail"),
            ("console.log", "console.log"),
        ] {
            let generated = result.generated_code.find(generated_token).unwrap();
            let expected_generated = source_position(
                &result.generated_code,
                &source_line_starts(&result.generated_code),
                generated,
            );
            let original = source.find(original_token).unwrap();
            let expected_original = source_position(source, &source_line_starts(source), original);
            assert!(
                mappings.contains(&(
                    expected_generated.0,
                    expected_generated.1,
                    Some(expected_original)
                )),
                "missing {generated_token}: {map}"
            );
        }
        let parsed: serde_json::Value = serde_json::from_str(map).unwrap();
        assert_eq!(parsed["sourcesContent"][0], source);
        assert_eq!(parsed["sources"][0], "input.jsx");
        assert!(
            mappings.iter().any(|(_, _, original)| original.is_none()),
            "imports must be unmapped"
        );
    }

    #[test]
    fn module_tsx_maps_point_to_original_lines_after_type_elision() {
        let source = "interface Props {\n  label: string;\n}\n\nexport function App(props: Props) {\n  return <p>{props.label}</p>;\n}\n";
        let mut config = ReactCompileConfig {
            generate_source_maps: true,
            ..Default::default()
        };
        config.lowering_config.source_file = Some("src/App.tsx".into());
        let result = compile_react_module(source, ReactInputLanguage::Tsx, &config).unwrap();
        let map = result.source_map.as_deref().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(map).unwrap();
        assert_eq!(parsed["sources"][0], "src/App.tsx");
        let generated = result.generated_code.find("(__franken_react_").unwrap();
        let position = source_position(
            &result.generated_code,
            &source_line_starts(&result.generated_code),
            generated,
        );
        assert!(
            decoded_mappings(map).contains(&(position.0, position.1, Some((5, 9)))),
            "{map}"
        );
    }

    #[test]
    fn module_receipts_are_deterministic_and_bind_map_and_language() {
        let source = "export default <p>ready</p>;";
        let config = ReactCompileConfig {
            generate_source_maps: true,
            ..Default::default()
        };
        let first = compile_react_module(source, ReactInputLanguage::Jsx, &config).unwrap();
        let second = compile_react_module(source, ReactInputLanguage::Jsx, &config).unwrap();
        assert_eq!(first, second);
        let evidence =
            generate_module_compilation_evidence(&first, &config, ReactInputLanguage::Jsx).unwrap();
        assert_eq!(
            evidence.compile_receipt.output_hash,
            ContentHash::compute(first.generated_code.as_bytes())
        );
        let mut changed = first.clone();
        changed.source_map = None;
        assert_ne!(
            evidence.compile_receipt.process_hash,
            generate_module_compilation_evidence(&changed, &config, ReactInputLanguage::Jsx)
                .unwrap()
                .compile_receipt
                .process_hash
        );
        assert_ne!(
            first.metadata.config_hash,
            compile_react_module(source, ReactInputLanguage::Tsx, &config)
                .unwrap()
                .metadata
                .config_hash
        );
    }
}
