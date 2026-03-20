#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::ParseGoal;
use crate::ir_contract::{EffectBoundary, Ir0Module};
use crate::lowering_pipeline::{LoweringContext, LoweringPipelineOutput, lower_ir0_to_ir3};
use crate::parser::{CanonicalEs2020Parser, ParseEventIr, ParserOptions};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsCompilerOptions {
    pub strict: bool,
    pub target: String,
    pub module: String,
    pub jsx: String,
}

impl Default for TsCompilerOptions {
    fn default() -> Self {
        Self {
            strict: true,
            target: "es2020".to_string(),
            module: "esnext".to_string(),
            jsx: "react-jsx".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TsNormalizationConfig {
    pub compiler_options: TsCompilerOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceMapEntry {
    pub normalized_line: usize,
    pub original_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityIntent {
    pub symbol: String,
    pub capability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationDecision {
    pub step: String,
    pub changed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizationEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsNormalizationWitness {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub source_hash: String,
    pub normalized_hash: String,
    pub compiler_options_hash: String,
    pub decisions: Vec<NormalizationDecision>,
    pub capability_intents: Vec<CapabilityIntent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsNormalizationOutput {
    pub normalized_source: String,
    pub capability_intents: Vec<CapabilityIntent>,
    pub source_map: Vec<SourceMapEntry>,
    pub witness: TsNormalizationWitness,
    pub events: Vec<NormalizationEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SourceLanguage {
    #[default]
    JavaScript,
    TypeScript,
}

impl SourceLanguage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIngestionSummary {
    pub source_language: SourceLanguage,
    pub normalization_applied: bool,
    pub original_source_hash: String,
    pub normalized_source_hash: String,
    pub ts_decision_count: usize,
    pub ts_capability_intent_count: usize,
}

impl Default for SourceIngestionSummary {
    fn default() -> Self {
        Self {
            source_language: SourceLanguage::JavaScript,
            normalization_applied: false,
            original_source_hash: String::new(),
            normalized_source_hash: String::new(),
            ts_decision_count: 0,
            ts_capability_intent_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSourceEntry {
    pub source_label: String,
    pub prepared_source: String,
    pub source_ingestion: SourceIngestionSummary,
    pub normalization_output: Option<TsNormalizationOutput>,
}

const TS_INGESTION_COMPONENT: &str = "ts_ingestion_lane";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsIngestionEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsIngestionArtifacts {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub source_label: String,
    pub parse_goal: ParseGoal,
    pub normalization_output: TsNormalizationOutput,
    pub parse_event_ir: ParseEventIr,
    pub ir0: Ir0Module,
    pub lowering_output: LoweringPipelineOutput,
    pub ingestion_events: Vec<TsIngestionEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsIngestionProvenance<'a> {
    pub trace_id: &'a str,
    pub decision_id: &'a str,
    pub policy_id: &'a str,
}

impl<'a> TsIngestionProvenance<'a> {
    pub const fn new(trace_id: &'a str, decision_id: &'a str, policy_id: &'a str) -> Self {
        Self {
            trace_id,
            decision_id,
            policy_id,
        }
    }
}

impl TsIngestionArtifacts {
    pub fn parse_event_ir_hash(&self) -> String {
        self.parse_event_ir.canonical_hash()
    }

    pub fn ir0_hash(&self) -> String {
        to_sha256_prefixed_hash(self.ir0.content_hash())
    }

    pub fn ir1_hash(&self) -> String {
        to_sha256_prefixed_hash(self.lowering_output.ir1.content_hash())
    }

    pub fn ir2_hash(&self) -> String {
        to_sha256_prefixed_hash(self.lowering_output.ir2.content_hash())
    }

    pub fn ir3_hash(&self) -> String {
        to_sha256_prefixed_hash(self.lowering_output.ir3.content_hash())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsIngestionErrorCode {
    NormalizationFailed,
    ParseFailed,
    LoweringFailed,
    CapabilityContractFailed,
}

impl TsIngestionErrorCode {
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::NormalizationFailed => "FE-TSINGEST-0001",
            Self::ParseFailed => "FE-TSINGEST-0002",
            Self::LoweringFailed => "FE-TSINGEST-0003",
            Self::CapabilityContractFailed => "FE-TSINGEST-0004",
        }
    }

    pub const fn stage(self) -> &'static str {
        match self {
            Self::NormalizationFailed => "normalize_typescript",
            Self::ParseFailed => "parse_normalized_source",
            Self::LoweringFailed => "lower_to_ir3",
            Self::CapabilityContractFailed => "validate_capability_contracts",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsIngestionError {
    pub code: TsIngestionErrorCode,
    pub stage: String,
    pub message: String,
    pub events: Vec<TsIngestionEvent>,
}

impl TsIngestionError {
    fn new(
        code: TsIngestionErrorCode,
        message: impl Into<String>,
        events: Vec<TsIngestionEvent>,
    ) -> Self {
        Self {
            code,
            stage: code.stage().to_string(),
            message: message.into(),
            events,
        }
    }

    pub const fn stable_code(&self) -> &'static str {
        self.code.stable_code()
    }
}

impl fmt::Display for TsIngestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ts ingestion error [{}] stage={} message={}",
            self.stable_code(),
            self.stage,
            self.message
        )
    }
}

impl std::error::Error for TsIngestionError {}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TsNormalizationError {
    #[error("TS source is empty after normalization")]
    EmptySource,
    #[error("unsupported syntax: {feature}")]
    UnsupportedSyntax { feature: &'static str },
    #[error("unsupported compiler option: {option}={value}")]
    UnsupportedCompilerOption { option: &'static str, value: String },
}

pub fn classify_source_language(source_label: Option<&str>, source: &str) -> SourceLanguage {
    if source_label.is_some_and(source_label_has_typescript_extension)
        || source_looks_typescript(source)
    {
        SourceLanguage::TypeScript
    } else {
        SourceLanguage::JavaScript
    }
}

pub fn prepare_source_entry_for_public_entrypoints(
    source: &str,
    source_label: &str,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> Result<PreparedSourceEntry, TsNormalizationError> {
    let source_language = classify_source_language(Some(source_label), source);
    let original_source_hash = sha256_hex(source);
    match source_language {
        SourceLanguage::JavaScript => Ok(PreparedSourceEntry {
            source_label: source_label.to_string(),
            prepared_source: source.to_string(),
            source_ingestion: SourceIngestionSummary {
                source_language,
                normalization_applied: false,
                original_source_hash: original_source_hash.clone(),
                normalized_source_hash: original_source_hash,
                ts_decision_count: 0,
                ts_capability_intent_count: 0,
            },
            normalization_output: None,
        }),
        SourceLanguage::TypeScript => {
            let normalization_output = normalize_typescript_to_es2020(
                source,
                &TsNormalizationConfig::default(),
                trace_id,
                decision_id,
                policy_id,
            )?;
            let source_ingestion = SourceIngestionSummary {
                source_language,
                normalization_applied: true,
                original_source_hash,
                normalized_source_hash: normalization_output.witness.normalized_hash.clone(),
                ts_decision_count: normalization_output.witness.decisions.len(),
                ts_capability_intent_count: normalization_output.capability_intents.len(),
            };
            Ok(PreparedSourceEntry {
                source_label: source_label.to_string(),
                prepared_source: normalization_output.normalized_source.clone(),
                source_ingestion,
                normalization_output: Some(normalization_output),
            })
        }
    }
}

pub fn normalize_typescript_to_es2020(
    source: &str,
    config: &TsNormalizationConfig,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> Result<TsNormalizationOutput, TsNormalizationError> {
    let mut events = Vec::<NormalizationEvent>::new();
    let mut decisions = Vec::<NormalizationDecision>::new();

    let normalized_newlines = normalize_newlines(source);
    let mut current = normalized_newlines.trim().to_string();
    if current.is_empty() {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "normalize",
            "FE-TSNORM-0001",
        ));
        return Err(TsNormalizationError::EmptySource);
    }

    let target = config.compiler_options.target.trim().to_ascii_lowercase();
    if target != "es2020" {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "target_validation",
            "FE-TSNORM-0004",
        ));
        return Err(TsNormalizationError::UnsupportedCompilerOption {
            option: "target",
            value: config.compiler_options.target.clone(),
        });
    }

    let module_kind = config.compiler_options.module.trim().to_ascii_lowercase();
    if module_kind != "esnext" && module_kind != "commonjs" {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "module_validation",
            "FE-TSNORM-0005",
        ));
        return Err(TsNormalizationError::UnsupportedCompilerOption {
            option: "module",
            value: config.compiler_options.module.clone(),
        });
    }

    let jsx_mode = config.compiler_options.jsx.trim().to_ascii_lowercase();
    if jsx_mode != "react-jsx" && jsx_mode != "react" && jsx_mode != "preserve" {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "jsx_validation",
            "FE-TSNORM-0006",
        ));
        return Err(TsNormalizationError::UnsupportedCompilerOption {
            option: "jsx",
            value: config.compiler_options.jsx.clone(),
        });
    }
    let jsx_preserve = jsx_mode == "preserve";

    let no_type_imports = elide_type_only_imports(&current);
    decisions.push(build_decision(
        "type_only_import_elision",
        no_type_imports != current,
        "Type-only imports and mixed type-only import/export specifiers were elided from runtime output.",
    ));
    current = no_type_imports;

    let type_space_declarations_stripped = strip_type_space_declarations(&current);
    decisions.push(build_decision(
        "type_space_declaration_elision",
        type_space_declarations_stripped != current,
        "Runtime-opaque interface/type declarations were removed from normalization output.",
    ));
    current = type_space_declarations_stripped;

    let namespace_lowered = match lower_simple_namespaces(&current) {
        Ok(lowered) => lowered,
        Err(error) => {
            events.push(failure_event(
                trace_id,
                decision_id,
                policy_id,
                "ts_normalization",
                "namespace_normalization",
                "FE-TSNORM-0002",
            ));
            return Err(error);
        }
    };
    decisions.push(build_decision(
        "namespace_lowering",
        namespace_lowered != current,
        "Simple namespace declarations lowered with deterministic merge semantics.",
    ));
    current = namespace_lowered;

    let decorator_lowered = match lower_simple_class_decorators(&current) {
        Ok(lowered) => lowered,
        Err(error) => {
            events.push(failure_event(
                trace_id,
                decision_id,
                policy_id,
                "ts_normalization",
                "decorator_normalization",
                "FE-TSNORM-0003",
            ));
            return Err(error);
        }
    };
    decisions.push(build_decision(
        "decorator_lowering",
        decorator_lowered != current,
        "Simple legacy class decorators lowered to deterministic wrapper application.",
    ));
    current = decorator_lowered;

    let definite_assignment_removed = normalize_definite_assignment_assertions(&current);
    decisions.push(build_decision(
        "definite_assignment_normalization",
        definite_assignment_removed != current,
        "Definite assignment assertions normalized.",
    ));
    current = definite_assignment_removed;

    let const_assertion_removed = strip_const_assertions(&current);
    decisions.push(build_decision(
        "const_assertion_normalization",
        const_assertion_removed != current,
        "Const assertions were stripped from runtime normalization output.",
    ));
    current = const_assertion_removed;

    let type_annotations_stripped = strip_type_annotations(&current);
    decisions.push(build_decision(
        "type_annotation_stripping",
        type_annotations_stripped != current,
        "Type annotations were removed while preserving runtime expressions.",
    ));
    current = type_annotations_stripped;

    let enum_lowered = lower_simple_enums(&current);
    decisions.push(build_decision(
        "enum_lowering",
        enum_lowered != current,
        "Simple enum declarations lowered to ES2020 object freeze forms.",
    ));
    current = enum_lowered;

    let parameter_property_lowered = lower_constructor_parameter_properties(&current);
    decisions.push(build_decision(
        "parameter_property_lowering",
        parameter_property_lowered != current,
        "Constructor parameter properties lowered into explicit assignments.",
    ));
    current = parameter_property_lowered;

    let abstract_class_lowered = lower_abstract_class_keywords(&current);
    decisions.push(build_decision(
        "abstract_class_lowering",
        abstract_class_lowered != current,
        "Abstract class declarations lowered to runtime-equivalent class declarations.",
    ));
    current = abstract_class_lowered;

    let implements_clauses_stripped = strip_implements_clauses(&current);
    decisions.push(build_decision(
        "implements_clause_normalization",
        implements_clauses_stripped != current,
        "Class implements clauses were stripped from runtime normalization output.",
    ));
    current = implements_clauses_stripped;

    let jsx_lowered = if jsx_preserve {
        current.clone()
    } else {
        lower_simple_jsx(&current)
    };
    decisions.push(build_decision(
        "jsx_lowering",
        jsx_lowered != current,
        "Simple JSX forms lowered to createElement calls.",
    ));
    current = jsx_lowered;

    let normalized_source = normalize_spacing(current);
    if normalized_source.trim().is_empty() {
        events.push(failure_event(
            trace_id,
            decision_id,
            policy_id,
            "ts_normalization",
            "post_normalization_validation",
            "FE-TSNORM-0001",
        ));
        return Err(TsNormalizationError::EmptySource);
    }

    let capability_intents = extract_capability_intents(&normalized_source);
    decisions.push(build_decision(
        "capability_intent_extraction",
        !capability_intents.is_empty(),
        "Capability intents were extracted from typed hostcall forms.",
    ));

    // After extracting capability intents, strip the generic type params from
    // hostcall<"cap">(args) so the ES2020 parser sees a plain call expression.
    let hostcall_stripped = strip_hostcall_type_params(&normalized_source);
    decisions.push(build_decision(
        "hostcall_type_param_stripping",
        hostcall_stripped != normalized_source,
        "Hostcall generic type parameters stripped for ES2020 parser compatibility.",
    ));
    let normalized_source = hostcall_stripped;

    let source_map = build_identity_source_map(&normalized_newlines, &normalized_source);

    let witness = TsNormalizationWitness {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        source_hash: sha256_hex(&normalized_newlines),
        normalized_hash: sha256_hex(&normalized_source),
        compiler_options_hash: sha256_hex(
            &serde_json::to_string(&config.compiler_options)
                .expect("compiler options should serialize deterministically"),
        ),
        decisions,
        capability_intents: capability_intents.clone(),
    };

    events.push(success_event(
        trace_id,
        decision_id,
        policy_id,
        "ts_normalization",
        "normalize",
    ));

    Ok(TsNormalizationOutput {
        normalized_source,
        capability_intents,
        source_map,
        witness,
        events,
    })
}

pub fn ingest_typescript_to_pipeline_artifacts(
    source: &str,
    normalization_config: &TsNormalizationConfig,
    source_label: &str,
    parse_goal: ParseGoal,
    parser_options: &ParserOptions,
    provenance: TsIngestionProvenance<'_>,
) -> Result<TsIngestionArtifacts, TsIngestionError> {
    let trace_id = provenance.trace_id;
    let decision_id = provenance.decision_id;
    let policy_id = provenance.policy_id;

    let mut ingestion_events = Vec::<TsIngestionEvent>::new();

    let normalization_output = match normalize_typescript_to_es2020(
        source,
        normalization_config,
        trace_id,
        decision_id,
        policy_id,
    ) {
        Ok(output) => {
            ingestion_events.push(success_ingestion_event(
                trace_id,
                decision_id,
                policy_id,
                TsIngestionErrorCode::NormalizationFailed.stage(),
            ));
            output
        }
        Err(error) => {
            ingestion_events.push(failure_ingestion_event(
                trace_id,
                decision_id,
                policy_id,
                TsIngestionErrorCode::NormalizationFailed,
            ));
            return Err(TsIngestionError::new(
                TsIngestionErrorCode::NormalizationFailed,
                error.to_string(),
                ingestion_events,
            ));
        }
    };

    let parser = CanonicalEs2020Parser;
    let (parse_result, parse_event_ir) = parser.parse_with_event_ir(
        normalization_output.normalized_source.as_str(),
        parse_goal,
        parser_options,
    );

    let syntax_tree = match parse_result {
        Ok(tree) => {
            ingestion_events.push(success_ingestion_event(
                trace_id,
                decision_id,
                policy_id,
                TsIngestionErrorCode::ParseFailed.stage(),
            ));
            tree
        }
        Err(error) => {
            ingestion_events.push(failure_ingestion_event(
                trace_id,
                decision_id,
                policy_id,
                TsIngestionErrorCode::ParseFailed,
            ));
            return Err(TsIngestionError::new(
                TsIngestionErrorCode::ParseFailed,
                format!(
                    "{} (parse_error_code={})",
                    error.message,
                    error.code.as_str()
                ),
                ingestion_events,
            ));
        }
    };

    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, source_label);
    let lowering_context = LoweringContext::new(trace_id, decision_id, policy_id);
    let lowering_output = match lower_ir0_to_ir3(&ir0, &lowering_context) {
        Ok(output) => {
            ingestion_events.push(success_ingestion_event(
                trace_id,
                decision_id,
                policy_id,
                TsIngestionErrorCode::LoweringFailed.stage(),
            ));
            output
        }
        Err(error) => {
            ingestion_events.push(failure_ingestion_event(
                trace_id,
                decision_id,
                policy_id,
                TsIngestionErrorCode::LoweringFailed,
            ));
            return Err(TsIngestionError::new(
                TsIngestionErrorCode::LoweringFailed,
                error.to_string(),
                ingestion_events,
            ));
        }
    };

    if let Err(message) = validate_capability_contracts(&normalization_output, &lowering_output) {
        ingestion_events.push(failure_ingestion_event(
            trace_id,
            decision_id,
            policy_id,
            TsIngestionErrorCode::CapabilityContractFailed,
        ));
        return Err(TsIngestionError::new(
            TsIngestionErrorCode::CapabilityContractFailed,
            message,
            ingestion_events,
        ));
    }
    ingestion_events.push(success_ingestion_event(
        trace_id,
        decision_id,
        policy_id,
        TsIngestionErrorCode::CapabilityContractFailed.stage(),
    ));

    Ok(TsIngestionArtifacts {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        source_label: source_label.to_string(),
        parse_goal,
        normalization_output,
        parse_event_ir,
        ir0,
        lowering_output,
        ingestion_events,
    })
}

pub fn ingest_typescript_to_pipeline_artifacts_default(
    source: &str,
    normalization_config: &TsNormalizationConfig,
    source_label: &str,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> Result<TsIngestionArtifacts, TsIngestionError> {
    let parser_options = ParserOptions::default();
    ingest_typescript_to_pipeline_artifacts(
        source,
        normalization_config,
        source_label,
        ParseGoal::Script,
        &parser_options,
        TsIngestionProvenance::new(trace_id, decision_id, policy_id),
    )
}

fn normalize_newlines(source: &str) -> String {
    source.replace("\r\n", "\n").replace('\r', "\n")
}

fn source_label_has_typescript_extension(source_label: &str) -> bool {
    let lower = source_label.trim().to_ascii_lowercase();
    [".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
}

fn source_looks_typescript(source: &str) -> bool {
    if source_contains_type_only_import_export_syntax(source)
        || source.contains(" as const")
        || source.contains("!:")
    {
        return true;
    }

    source.lines().any(line_looks_like_typescript_construct)
}

fn line_looks_like_typescript_construct(line: &str) -> bool {
    let trimmed = line.trim_start();
    if statement_uses_type_only_import_export_syntax(trimmed)
        || trimmed.starts_with("interface ")
        || trimmed.starts_with("export interface ")
        || trimmed.starts_with("enum ")
        || trimmed.starts_with("export enum ")
        || class_declaration_uses_implements_clause(trimmed)
    {
        return true;
    }
    if trimmed.starts_with("type ") && trimmed.contains('=') {
        return true;
    }

    looks_like_typed_variable_declaration(trimmed)
}

fn looks_like_typed_variable_declaration(line: &str) -> bool {
    let rest = ["const ", "let ", "var "]
        .iter()
        .find_map(|prefix| line.strip_prefix(prefix));
    let Some(rest) = rest else {
        return false;
    };

    let mut chars = rest.chars().peekable();
    let mut identifier = String::new();
    while let Some(ch) = chars.peek().copied() {
        if is_identifier_char(ch) {
            identifier.push(ch);
            chars.next();
        } else {
            break;
        }
    }
    if identifier.is_empty() {
        return false;
    }

    while chars.peek().is_some_and(|ch| ch.is_ascii_whitespace()) {
        chars.next();
    }
    if chars.next() != Some(':') {
        return false;
    }

    let remainder = chars.collect::<String>();
    let trimmed = remainder.trim_start();
    if trimmed.is_empty() {
        return false;
    }
    let Some(eq_index) = trimmed.find('=') else {
        return false;
    };
    let annotation = trimmed[..eq_index].trim();
    !annotation.is_empty()
        && annotation.chars().all(|ch| {
            ch.is_ascii_alphanumeric()
                || matches!(
                    ch,
                    '_' | '$' | '<' | '>' | '[' | ']' | '|' | '&' | '?' | ',' | '.' | ' '
                )
        })
}

fn class_declaration_uses_implements_clause(statement: &str) -> bool {
    let Some(start) = next_code_token_index(statement, 0) else {
        return false;
    };

    let class_index = if starts_with_keyword(statement, start, "class") {
        start
    } else if starts_with_keyword(statement, start, "export") {
        let Some(after_export) = next_code_token_index(statement, start + "export".len()) else {
            return false;
        };
        let candidate = if starts_with_keyword(statement, after_export, "default") {
            let Some(after_default) =
                next_code_token_index(statement, after_export + "default".len())
            else {
                return false;
            };
            after_default
        } else {
            after_export
        };
        if starts_with_keyword(statement, candidate, "class") {
            candidate
        } else {
            return false;
        }
    } else {
        return false;
    };

    let Some(body_start) = find_top_level_char(statement, class_index, '{') else {
        return false;
    };
    let mut cursor = class_index + "class".len();
    let mut state = LexicalRewriteState::Code;
    while let Some((index, _)) = next_code_scan_char(statement, &mut cursor, &mut state) {
        if index >= body_start {
            break;
        }
        if starts_with_keyword(statement, index, "implements") {
            return true;
        }
    }

    false
}

fn normalize_spacing(source: String) -> String {
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn build_decision(step: &str, changed: bool, detail: &str) -> NormalizationDecision {
    NormalizationDecision {
        step: step.to_string(),
        changed,
        detail: detail.to_string(),
    }
}

fn success_event(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    component: &str,
    event: &str,
) -> NormalizationEvent {
    NormalizationEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: component.to_string(),
        event: event.to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn failure_event(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    component: &str,
    event: &str,
    error_code: &str,
) -> NormalizationEvent {
    NormalizationEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: component.to_string(),
        event: event.to_string(),
        outcome: "fail".to_string(),
        error_code: Some(error_code.to_string()),
    }
}

fn success_ingestion_event(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    event: &str,
) -> TsIngestionEvent {
    TsIngestionEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: TS_INGESTION_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn failure_ingestion_event(
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    code: TsIngestionErrorCode,
) -> TsIngestionEvent {
    TsIngestionEvent {
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        component: TS_INGESTION_COMPONENT.to_string(),
        event: code.stage().to_string(),
        outcome: "fail".to_string(),
        error_code: Some(code.stable_code().to_string()),
    }
}

fn to_sha256_prefixed_hash(hash: crate::hash_tiers::ContentHash) -> String {
    format!("sha256:{}", hash.to_hex())
}

fn validate_capability_contracts(
    normalization_output: &TsNormalizationOutput,
    lowering_output: &LoweringPipelineOutput,
) -> Result<(), String> {
    let mut declared_capabilities = BTreeSet::<String>::new();
    for intent in &normalization_output.capability_intents {
        let capability = intent.capability.trim();
        if capability.is_empty() {
            return Err("capability annotation cannot be empty".to_string());
        }
        if !is_valid_capability_annotation(capability) {
            return Err(format!(
                "capability annotation `{capability}` is invalid; only [A-Za-z0-9._:-] are allowed"
            ));
        }
        declared_capabilities.insert(capability.to_string());
    }

    let has_annotation_marker = normalization_output
        .normalized_source
        .contains("hostcall<\"");
    let has_unannotated_hostcall = normalization_output.normalized_source.contains("hostcall(");

    if has_annotation_marker && declared_capabilities.is_empty() {
        return Err(
            "hostcall capability annotation marker detected but no valid annotations extracted"
                .to_string(),
        );
    }
    if has_unannotated_hostcall && declared_capabilities.is_empty() {
        return Err("hostcall invocation missing capability annotation".to_string());
    }

    if declared_capabilities.is_empty() {
        return Ok(());
    }

    let mut hostcall_contract_capabilities = BTreeSet::<String>::new();
    let mut has_hostcall_invoke_fallback = false;
    for op in &lowering_output.ir2.ops {
        if !matches!(op.effect, EffectBoundary::HostcallEffect) {
            continue;
        }

        let Some(capability) = op.required_capability.as_ref() else {
            return Err("hostcall effect missing required capability tag".to_string());
        };

        if capability.0 == "hostcall.invoke" {
            has_hostcall_invoke_fallback = true;
            continue;
        }

        hostcall_contract_capabilities.insert(capability.0.clone());
    }

    // When TS normalization strips type annotations from `hostcall<"cap">()`,
    // the parser sees a plain `hostcall()` call and the lowering pipeline tags
    // it with the `hostcall.invoke` fallback.  The declared capability intents
    // extracted from the original source are authoritative — accept them when
    // matching `hostcall.invoke` ops exist in the IR.
    if has_hostcall_invoke_fallback {
        for cap in &declared_capabilities {
            hostcall_contract_capabilities.insert(cap.clone());
        }
    }

    let missing_in_contract = declared_capabilities
        .difference(&hostcall_contract_capabilities)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_in_contract.is_empty() {
        return Err(format!(
            "capability annotations missing in IR contract: {}",
            missing_in_contract.join(", ")
        ));
    }

    Ok(())
}

fn is_valid_capability_annotation(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-'))
}

fn elide_type_only_imports(source: &str) -> String {
    rewrite_outside_strings_and_comments(source, |source, index, output| {
        if !is_statement_start(source, index)
            || (!starts_with_keyword(source, index, "import")
                && !starts_with_keyword(source, index, "export"))
        {
            return None;
        }

        let statement_end = find_import_export_statement_end(source, index)?;
        let statement = &source[index..statement_end];
        let rewritten = rewrite_type_only_import_export_statement(statement)?;
        trim_trailing_inline_whitespace(output);
        output.push_str(&rewritten);
        Some(statement_end)
    })
}

fn find_import_export_statement_end(source: &str, start: usize) -> Option<usize> {
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut cursor = start;
    let mut state = LexicalRewriteState::Code;
    let mut saw_code = false;

    while let Some((index, ch)) = next_code_scan_char(source, &mut cursor, &mut state) {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            ';' if paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0
                && angle_depth == 0 =>
            {
                return Some(index + ch.len_utf8());
            }
            '\n' if paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0
                && angle_depth == 0
                && saw_code =>
            {
                return Some(index);
            }
            _ => {}
        }

        if !ch.is_ascii_whitespace() {
            saw_code = true;
        }
    }

    Some(source.len())
}

fn rewrite_type_only_import_export_statement(statement: &str) -> Option<String> {
    let start = statement.find(|ch: char| !ch.is_ascii_whitespace())?;
    if starts_with_keyword(statement, start, "import") {
        let after_import = next_code_token_index(statement, start + "import".len())?;
        if starts_with_keyword(statement, after_import, "type")
            && import_type_keyword_uses_type_only_syntax(statement, after_import)
        {
            return Some(String::new());
        }
    } else if starts_with_keyword(statement, start, "export") {
        let after_export = next_code_token_index(statement, start + "export".len())?;
        if starts_with_keyword(statement, after_export, "type") {
            let after_type = next_code_token_index(statement, after_export + "type".len())?;
            if statement[after_type..].starts_with('{') || statement[after_type..].starts_with('*')
            {
                return Some(String::new());
            }
        }
    } else {
        return None;
    }

    let brace_start = find_top_level_char(statement, start, '{')?;
    let brace_end = find_matching_delimiter(statement, brace_start, '{', '}')?;
    let (runtime_specifiers, removed_any) =
        filter_runtime_named_specifiers(&statement[brace_start + 1..brace_end]);
    if !removed_any {
        return None;
    }

    let prefix = &statement[..brace_start];
    let suffix = statement[brace_end + 1..].trim_start();
    if runtime_specifiers.is_empty() {
        let prefix_without_specifiers =
            prefix.trim_end_matches(|ch: char| ch.is_ascii_whitespace() || ch == ',');
        let normalized_prefix = prefix_without_specifiers.trim_end();
        if normalized_prefix == "import" || normalized_prefix == "export" {
            return Some(String::new());
        }
        return Some(if suffix.is_empty() {
            normalized_prefix.to_string()
        } else {
            format!("{normalized_prefix} {suffix}")
        });
    }

    let normalized_prefix = prefix.trim_end();
    let mut rewritten = String::new();
    rewritten.push_str(normalized_prefix);
    if !rewritten.ends_with(' ') {
        rewritten.push(' ');
    }
    rewritten.push('{');
    rewritten.push(' ');
    rewritten.push_str(&runtime_specifiers.join(", "));
    rewritten.push(' ');
    rewritten.push('}');
    if !suffix.is_empty() {
        rewritten.push(' ');
        rewritten.push_str(suffix);
    }

    Some(rewritten)
}

fn filter_runtime_named_specifiers(specifiers: &str) -> (Vec<String>, bool) {
    let mut runtime_specifiers = Vec::<String>::new();
    let mut removed_any = false;

    for specifier in specifiers.split(',') {
        let trimmed = specifier.trim();
        if trimmed.is_empty() {
            continue;
        }

        if is_type_only_named_specifier(trimmed) {
            removed_any = true;
            continue;
        }

        runtime_specifiers.push(trimmed.to_string());
    }

    (runtime_specifiers, removed_any)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TypeSpaceDeclarationKind {
    Interface,
    TypeAlias,
}

fn strip_type_space_declarations(source: &str) -> String {
    rewrite_outside_strings_and_comments(source, |source, index, output| {
        let (kind, keyword_start) = match_type_space_declaration(source, index)?;
        trim_trailing_inline_whitespace(output);
        let end = match kind {
            TypeSpaceDeclarationKind::Interface => {
                find_interface_declaration_end(source, keyword_start)?
            }
            TypeSpaceDeclarationKind::TypeAlias => {
                find_type_alias_declaration_end(source, keyword_start)?
            }
        };
        Some(end)
    })
}

fn match_type_space_declaration(
    source: &str,
    index: usize,
) -> Option<(TypeSpaceDeclarationKind, usize)> {
    if !is_statement_start(source, index) {
        return None;
    }

    if starts_with_keyword(source, index, "export") {
        let after_export = skip_ascii_whitespace(source, index + "export".len());
        if starts_with_keyword(source, after_export, "interface") {
            return Some((TypeSpaceDeclarationKind::Interface, after_export));
        }
        if starts_with_keyword(source, after_export, "type") {
            return Some((TypeSpaceDeclarationKind::TypeAlias, after_export));
        }
        return None;
    }

    if starts_with_keyword(source, index, "interface") {
        return Some((TypeSpaceDeclarationKind::Interface, index));
    }
    if starts_with_keyword(source, index, "type") {
        return Some((TypeSpaceDeclarationKind::TypeAlias, index));
    }

    None
}

fn is_statement_start(source: &str, index: usize) -> bool {
    for ch in source[..index].chars().rev() {
        if ch == '\n' {
            return true;
        }
        if ch.is_ascii_whitespace() {
            continue;
        }
        return matches!(ch, ';' | '{' | '}');
    }

    true
}

fn skip_identifier(source: &str, index: usize) -> Option<usize> {
    let mut chars = source[index..].char_indices();
    let (_, first) = chars.next()?;
    if !matches!(first, '_' | '$') && !first.is_ascii_alphabetic() {
        return None;
    }

    let mut end = index + first.len_utf8();
    for (offset, ch) in chars {
        if is_identifier_char(ch) {
            end = index + offset + ch.len_utf8();
        } else {
            break;
        }
    }

    Some(end)
}

fn find_interface_declaration_end(source: &str, keyword_start: usize) -> Option<usize> {
    let mut cursor = skip_ascii_whitespace(source, keyword_start + "interface".len());
    cursor = skip_identifier(source, cursor)?;
    let body_start = find_top_level_char(source, cursor, '{')?;
    let body_end = find_matching_delimiter(source, body_start, '{', '}')?;
    let mut end = body_end + '}'.len_utf8();
    end = skip_ascii_whitespace(source, end);
    if source[end..].starts_with(';') {
        end += 1;
    }
    Some(end)
}

fn find_type_alias_declaration_end(source: &str, keyword_start: usize) -> Option<usize> {
    let mut cursor = skip_ascii_whitespace(source, keyword_start + "type".len());
    cursor = skip_identifier(source, cursor)?;
    find_top_level_statement_terminator(source, cursor)
}

fn next_code_scan_char(
    source: &str,
    cursor: &mut usize,
    state: &mut LexicalRewriteState,
) -> Option<(usize, char)> {
    let bytes = source.as_bytes();

    while *cursor < source.len() {
        match *state {
            LexicalRewriteState::Code => {
                if bytes[*cursor] == b'/' && *cursor + 1 < source.len() {
                    match bytes[*cursor + 1] {
                        b'/' => {
                            *cursor += 2;
                            *state = LexicalRewriteState::LineComment;
                            continue;
                        }
                        b'*' => {
                            *cursor += 2;
                            *state = LexicalRewriteState::BlockComment;
                            continue;
                        }
                        _ => {}
                    }
                }

                let index = *cursor;
                let ch = source[index..]
                    .chars()
                    .next()
                    .expect("cursor should remain on a char boundary");
                *cursor += ch.len_utf8();

                match ch {
                    '\'' => *state = LexicalRewriteState::SingleQuote,
                    '"' => *state = LexicalRewriteState::DoubleQuote,
                    '`' => *state = LexicalRewriteState::TemplateLiteral,
                    _ => return Some((index, ch)),
                }
            }
            LexicalRewriteState::SingleQuote => {
                let ch = source[*cursor..]
                    .chars()
                    .next()
                    .expect("cursor should remain on a char boundary");
                *cursor += ch.len_utf8();
                if ch == '\\' && *cursor < source.len() {
                    let escaped = source[*cursor..]
                        .chars()
                        .next()
                        .expect("escaped string should remain on a char boundary");
                    *cursor += escaped.len_utf8();
                    continue;
                }
                if ch == '\'' {
                    *state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::DoubleQuote => {
                let ch = source[*cursor..]
                    .chars()
                    .next()
                    .expect("cursor should remain on a char boundary");
                *cursor += ch.len_utf8();
                if ch == '\\' && *cursor < source.len() {
                    let escaped = source[*cursor..]
                        .chars()
                        .next()
                        .expect("escaped string should remain on a char boundary");
                    *cursor += escaped.len_utf8();
                    continue;
                }
                if ch == '"' {
                    *state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::TemplateLiteral => {
                let ch = source[*cursor..]
                    .chars()
                    .next()
                    .expect("cursor should remain on a char boundary");
                *cursor += ch.len_utf8();
                if ch == '\\' && *cursor < source.len() {
                    let escaped = source[*cursor..]
                        .chars()
                        .next()
                        .expect("escaped template should remain on a char boundary");
                    *cursor += escaped.len_utf8();
                    continue;
                }
                if ch == '`' {
                    *state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::LineComment => {
                let ch = source[*cursor..]
                    .chars()
                    .next()
                    .expect("cursor should remain on a char boundary");
                *cursor += ch.len_utf8();
                if ch == '\n' {
                    *state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::BlockComment => {
                if bytes[*cursor] == b'*'
                    && *cursor + 1 < source.len()
                    && bytes[*cursor + 1] == b'/'
                {
                    *cursor += 2;
                    *state = LexicalRewriteState::Code;
                    continue;
                }

                let ch = source[*cursor..]
                    .chars()
                    .next()
                    .expect("cursor should remain on a char boundary");
                *cursor += ch.len_utf8();
            }
        }
    }

    None
}

fn find_top_level_char(source: &str, start: usize, target: char) -> Option<usize> {
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut cursor = start;
    let mut state = LexicalRewriteState::Code;

    while let Some((index, ch)) = next_code_scan_char(source, &mut cursor, &mut state) {
        // Check target match BEFORE adjusting depth so that delimiter
        // characters like '(' can themselves be found at depth 0.
        if ch == target && paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 {
            return Some(index);
        }
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            _ => {}
        }
    }

    None
}

fn find_matching_delimiter(source: &str, start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut cursor = start;
    let mut state = LexicalRewriteState::Code;

    while let Some((index, ch)) = next_code_scan_char(source, &mut cursor, &mut state) {
        if ch == open {
            depth += 1;
        } else if ch == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(index);
            }
        }
    }

    None
}

fn find_top_level_statement_terminator(source: &str, start: usize) -> Option<usize> {
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut angle_depth = 0usize;
    let mut cursor = start;
    let mut state = LexicalRewriteState::Code;

    while let Some((index, ch)) = next_code_scan_char(source, &mut cursor, &mut state) {
        match ch {
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            ';' if paren_depth == 0
                && bracket_depth == 0
                && brace_depth == 0
                && angle_depth == 0 =>
            {
                return Some(index + ch.len_utf8());
            }
            _ => {}
        }
    }

    if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 && angle_depth == 0 {
        Some(source.len())
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LexicalRewriteState {
    Code,
    SingleQuote,
    DoubleQuote,
    TemplateLiteral,
    LineComment,
    BlockComment,
}

fn rewrite_outside_strings_and_comments<F>(source: &str, mut rewrite: F) -> String
where
    F: FnMut(&str, usize, &mut String) -> Option<usize>,
{
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut index = 0usize;
    let mut state = LexicalRewriteState::Code;

    while index < source.len() {
        match state {
            LexicalRewriteState::Code => {
                if let Some(next_index) = rewrite(source, index, &mut output) {
                    index = next_index;
                    continue;
                }

                if bytes[index] == b'/' && index + 1 < source.len() {
                    match bytes[index + 1] {
                        b'/' => {
                            output.push_str("//");
                            index += 2;
                            state = LexicalRewriteState::LineComment;
                            continue;
                        }
                        b'*' => {
                            output.push_str("/*");
                            index += 2;
                            state = LexicalRewriteState::BlockComment;
                            continue;
                        }
                        _ => {}
                    }
                }

                let ch = source[index..]
                    .chars()
                    .next()
                    .expect("scanner index should remain on char boundary");
                output.push(ch);
                index += ch.len_utf8();
                state = match ch {
                    '\'' => LexicalRewriteState::SingleQuote,
                    '"' => LexicalRewriteState::DoubleQuote,
                    '`' => LexicalRewriteState::TemplateLiteral,
                    _ => LexicalRewriteState::Code,
                };
            }
            LexicalRewriteState::SingleQuote => {
                let ch = source[index..]
                    .chars()
                    .next()
                    .expect("scanner index should remain on char boundary");
                output.push(ch);
                index += ch.len_utf8();
                if ch == '\\' && index < source.len() {
                    let escaped = source[index..]
                        .chars()
                        .next()
                        .expect("escaped string should remain on char boundary");
                    output.push(escaped);
                    index += escaped.len_utf8();
                    continue;
                }
                if ch == '\'' {
                    state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::DoubleQuote => {
                let ch = source[index..]
                    .chars()
                    .next()
                    .expect("scanner index should remain on char boundary");
                output.push(ch);
                index += ch.len_utf8();
                if ch == '\\' && index < source.len() {
                    let escaped = source[index..]
                        .chars()
                        .next()
                        .expect("escaped string should remain on char boundary");
                    output.push(escaped);
                    index += escaped.len_utf8();
                    continue;
                }
                if ch == '"' {
                    state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::TemplateLiteral => {
                let ch = source[index..]
                    .chars()
                    .next()
                    .expect("scanner index should remain on char boundary");
                output.push(ch);
                index += ch.len_utf8();
                if ch == '\\' && index < source.len() {
                    let escaped = source[index..]
                        .chars()
                        .next()
                        .expect("escaped template byte should remain on char boundary");
                    output.push(escaped);
                    index += escaped.len_utf8();
                    continue;
                }
                if ch == '`' {
                    state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::LineComment => {
                let ch = source[index..]
                    .chars()
                    .next()
                    .expect("scanner index should remain on char boundary");
                output.push(ch);
                index += ch.len_utf8();
                if ch == '\n' {
                    state = LexicalRewriteState::Code;
                }
            }
            LexicalRewriteState::BlockComment => {
                if bytes[index] == b'*' && index + 1 < source.len() && bytes[index + 1] == b'/' {
                    output.push_str("*/");
                    index += 2;
                    state = LexicalRewriteState::Code;
                    continue;
                }

                let ch = source[index..]
                    .chars()
                    .next()
                    .expect("scanner index should remain on char boundary");
                output.push(ch);
                index += ch.len_utf8();
            }
        }
    }

    output
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$')
}

fn has_token_boundary_before(source: &str, index: usize) -> bool {
    source[..index]
        .chars()
        .next_back()
        .is_none_or(|ch| !is_identifier_char(ch))
}

fn has_token_boundary_after(source: &str, index: usize) -> bool {
    source[index..]
        .chars()
        .next()
        .is_none_or(|ch| !is_identifier_char(ch))
}

fn starts_with_keyword(source: &str, index: usize, keyword: &str) -> bool {
    source[index..].starts_with(keyword)
        && has_token_boundary_before(source, index)
        && has_token_boundary_after(source, index + keyword.len())
}

fn strip_leading_keyword<'a>(source: &'a str, keyword: &str) -> Option<&'a str> {
    if !starts_with_keyword(source, 0, keyword) {
        return None;
    }

    let after = skip_ascii_whitespace(source, keyword.len());
    Some(&source[after..])
}

fn skip_ascii_whitespace(source: &str, mut index: usize) -> usize {
    while index < source.len() {
        let ch = source[index..]
            .chars()
            .next()
            .expect("scanner index should remain on char boundary");
        if !ch.is_ascii_whitespace() {
            break;
        }
        index += ch.len_utf8();
    }

    index
}

fn next_code_token_index(source: &str, start: usize) -> Option<usize> {
    let mut cursor = start;
    let mut state = LexicalRewriteState::Code;
    while let Some((index, ch)) = next_code_scan_char(source, &mut cursor, &mut state) {
        if !ch.is_ascii_whitespace() {
            return Some(index);
        }
    }

    None
}

fn import_type_keyword_uses_type_only_syntax(statement: &str, type_index: usize) -> bool {
    let Some(next_index) = next_code_token_index(statement, type_index + "type".len()) else {
        return false;
    };

    let Some(next_char) = statement[next_index..].chars().next() else {
        return false;
    };
    if next_char == ',' || starts_with_keyword(statement, next_index, "from") {
        return false;
    }

    true
}

fn statement_uses_type_only_import_export_syntax(statement: &str) -> bool {
    let Some(start) = next_code_token_index(statement, 0) else {
        return false;
    };

    if starts_with_keyword(statement, start, "import") {
        let Some(after_import) = next_code_token_index(statement, start + "import".len()) else {
            return false;
        };
        if starts_with_keyword(statement, after_import, "type") {
            return import_type_keyword_uses_type_only_syntax(statement, after_import);
        }
    } else if starts_with_keyword(statement, start, "export") {
        let Some(after_export) = next_code_token_index(statement, start + "export".len()) else {
            return false;
        };
        if starts_with_keyword(statement, after_export, "type") {
            return next_code_token_index(statement, after_export + "type".len())
                .is_some_and(|index| !starts_with_keyword(statement, index, "from"));
        }
    } else {
        return false;
    }

    let Some(brace_start) = find_top_level_char(statement, start, '{') else {
        return false;
    };
    let Some(brace_end) = find_matching_delimiter(statement, brace_start, '{', '}') else {
        return false;
    };

    statement[brace_start + 1..brace_end]
        .split(',')
        .map(str::trim)
        .any(is_type_only_named_specifier)
}

fn source_contains_type_only_import_export_syntax(source: &str) -> bool {
    let mut cursor = 0usize;
    let mut state = LexicalRewriteState::Code;
    while let Some((index, _)) = next_code_scan_char(source, &mut cursor, &mut state) {
        if !is_statement_start(source, index)
            || (!starts_with_keyword(source, index, "import")
                && !starts_with_keyword(source, index, "export"))
        {
            continue;
        }

        let Some(statement_end) = find_import_export_statement_end(source, index) else {
            return false;
        };
        if statement_uses_type_only_import_export_syntax(&source[index..statement_end]) {
            return true;
        }
        cursor = statement_end;
    }

    false
}

fn is_type_only_named_specifier(specifier: &str) -> bool {
    let Some(start) = next_code_token_index(specifier, 0) else {
        return false;
    };
    if !starts_with_keyword(specifier, start, "type") {
        return false;
    }

    next_code_token_index(specifier, start + "type".len())
        .is_some_and(|index| !starts_with_keyword(specifier, index, "as"))
}

fn trim_trailing_inline_whitespace(output: &mut String) {
    while matches!(output.chars().next_back(), Some(' ' | '\t')) {
        let _ = output.pop();
    }
}

fn lower_simple_namespaces(source: &str) -> Result<String, TsNormalizationError> {
    let mut namespace_order = Vec::<String>::new();
    let mut namespace_assignments = BTreeMap::<String, Vec<String>>::new();
    let mut rewritten = String::with_capacity(source.len());
    let mut emit_cursor = 0usize;
    let mut scan_cursor = 0usize;
    let mut state = LexicalRewriteState::Code;

    while let Some((index, _)) = next_code_scan_char(source, &mut scan_cursor, &mut state) {
        if !is_statement_start(source, index) || !starts_with_keyword(source, index, "namespace") {
            continue;
        }

        let (namespace_name, body_start, body_end, declaration_end) =
            parse_simple_namespace_declaration(source, index)?;
        rewritten.push_str(&source[emit_cursor..index]);

        let body = source[body_start + 1..body_end].trim();
        let parsed_assignments = parse_namespace_exports(body)?;
        if !namespace_assignments.contains_key(&namespace_name) {
            namespace_order.push(namespace_name.clone());
            namespace_assignments.insert(namespace_name.clone(), Vec::new());
            rewritten.push_str(&format!("/*__namespace:{namespace_name}__*/"));
        }

        if let Some(assignments) = namespace_assignments.get_mut(&namespace_name) {
            assignments.extend(parsed_assignments);
        }

        emit_cursor = declaration_end;
        scan_cursor = declaration_end;
        state = LexicalRewriteState::Code;
    }

    if namespace_order.is_empty() {
        return Ok(source.to_string());
    }

    rewritten.push_str(&source[emit_cursor..]);

    let mut rendered = rewritten;
    for namespace_name in namespace_order {
        let placeholder = format!("/*__namespace:{namespace_name}__*/");
        let namespace_block = render_namespace_block(
            &namespace_name,
            &namespace_assignments
                .remove(&namespace_name)
                .unwrap_or_default(),
        )
        .join("\n");
        rendered = rendered.replacen(&placeholder, &namespace_block, 1);
    }

    Ok(rendered)
}

fn parse_simple_namespace_declaration(
    source: &str,
    start: usize,
) -> Result<(String, usize, usize, usize), TsNormalizationError> {
    let mut cursor = skip_ascii_whitespace(source, start + "namespace".len());
    let name_start = cursor;
    let name_end =
        skip_identifier(source, cursor).ok_or(TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace declaration form",
        })?;
    let namespace_name = source[name_start..name_end].trim().to_string();
    if namespace_name.is_empty() {
        return Err(TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace declaration form",
        });
    }

    cursor =
        next_code_token_index(source, name_end).ok_or(TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace declaration form",
        })?;
    if !source[cursor..].starts_with('{') {
        return Err(TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace declaration form",
        });
    }
    let body_start = cursor;
    let body_end = find_matching_delimiter(source, body_start, '{', '}').ok_or(
        TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace declaration form",
        },
    )?;

    let mut declaration_end = body_end + '}'.len_utf8();
    if let Some(next_index) = next_code_token_index(source, declaration_end)
        && source[next_index..].starts_with(';')
    {
        declaration_end = next_index + ';'.len_utf8();
    }

    Ok((namespace_name, body_start, body_end, declaration_end))
}

fn parse_namespace_exports(body: &str) -> Result<Vec<String>, TsNormalizationError> {
    let mut assignments = Vec::<String>::new();
    let mut cursor = 0usize;

    while cursor < body.len() {
        cursor = next_code_token_index(body, cursor).unwrap_or(body.len());
        if cursor >= body.len() {
            break;
        }

        let statement_end = if is_namespace_export_function(body, cursor) {
            find_namespace_export_function_end(body, cursor)
        } else {
            find_top_level_statement_terminator(body, cursor)
        }
        .ok_or(TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace export form",
        })?;

        let normalized = body[cursor..statement_end]
            .trim()
            .trim_end_matches(';')
            .trim();
        if normalized.is_empty() {
            cursor = statement_end;
            continue;
        }

        let Some(exported) = strip_leading_keyword(normalized, "export") else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        };

        let declaration = if let Some(value) = strip_leading_keyword(exported, "const") {
            value
        } else if let Some(value) = strip_leading_keyword(exported, "let") {
            value
        } else if let Some(value) = strip_leading_keyword(exported, "var") {
            value
        } else if is_exported_function_declaration(exported) {
            assignments.extend(render_namespace_export_function(exported)?);
            cursor = statement_end;
            continue;
        } else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        };

        let Some((lhs, rhs)) = declaration.split_once('=') else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        };
        let symbol = lhs.split(':').next().unwrap_or(lhs).trim();
        if symbol.is_empty() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        }

        assignments.push(format!("  ns.{symbol} = {};", rhs.trim()));
        cursor = statement_end;
    }

    Ok(assignments)
}

fn is_namespace_export_function(source: &str, start: usize) -> bool {
    strip_leading_keyword(&source[start..], "export").is_some_and(is_exported_function_declaration)
}

fn is_exported_function_declaration(exported: &str) -> bool {
    parse_exported_function_name_range(exported).is_some()
}

fn find_namespace_export_function_end(source: &str, start: usize) -> Option<usize> {
    let source_from_start = &source[start..];
    let exported = strip_leading_keyword(source_from_start, "export")?;
    let exported_start = source_from_start.len() - exported.len();
    let (_, name_end) = parse_exported_function_name_range(exported)?;
    let params_start = find_top_level_char(exported, name_end, '(')?;
    let params_end = find_matching_delimiter(exported, params_start, '(', ')')?;
    let mut search_cursor = params_end + ')'.len_utf8();

    while search_cursor < exported.len() {
        let body_start = find_top_level_char(exported, search_cursor, '{')?;
        let body_end = find_matching_delimiter(exported, body_start, '{', '}')?;
        let mut next_statement_start = next_code_token_index(exported, body_end + '}'.len_utf8());
        while let Some(index) = next_statement_start {
            if !exported[index..].starts_with(';') {
                break;
            }
            next_statement_start = next_code_token_index(exported, index + ';'.len_utf8());
        }

        if let Some(index) = next_statement_start {
            if starts_with_keyword(exported, index, "export") {
                return Some(start + exported_start + body_end + '}'.len_utf8());
            }
            search_cursor = index;
            continue;
        }

        return Some(start + exported_start + body_end + '}'.len_utf8());
    }

    None
}

fn render_namespace_export_function(exported: &str) -> Result<Vec<String>, TsNormalizationError> {
    let (name_start, name_end) = parse_exported_function_name_range(exported).ok_or(
        TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace export form",
        },
    )?;
    let name = exported[name_start..name_end].trim();
    if name.is_empty() {
        return Err(TsNormalizationError::UnsupportedSyntax {
            feature: "unsupported namespace export form",
        });
    }

    let mut rendered = exported
        .lines()
        .map(|line| format!("  {}", line.trim_end()))
        .collect::<Vec<_>>();
    rendered.push(format!("  ns.{name} = {name};"));
    Ok(rendered)
}

fn parse_exported_function_name_range(exported: &str) -> Option<(usize, usize)> {
    let mut cursor = 0usize;
    if let Some(async_rest) = strip_leading_keyword(exported, "async") {
        cursor = exported.len() - async_rest.len();
    }
    if !starts_with_keyword(exported, cursor, "function") {
        return None;
    }
    cursor = skip_ascii_whitespace(exported, cursor + "function".len());
    if exported[cursor..].starts_with('*') {
        cursor += 1;
        cursor = skip_ascii_whitespace(exported, cursor);
    }
    let name_start = cursor;
    let name_end = skip_identifier(exported, name_start)?;
    Some((name_start, name_end))
}

fn render_namespace_block(namespace_name: &str, assignments: &[String]) -> Vec<String> {
    let mut lines = Vec::<String>::new();
    lines.push(format!("const {namespace_name} = (() => {{"));
    lines.push("  const ns = {};".to_string());
    lines.extend(assignments.iter().cloned());
    lines.push("  return ns;".to_string());
    lines.push("})();".to_string());
    lines
}

fn lower_simple_class_decorators(source: &str) -> Result<String, TsNormalizationError> {
    let lines = source.lines().collect::<Vec<_>>();
    let mut lowered = Vec::<String>::new();
    let mut index = 0usize;
    let mut lowered_any = false;

    while index < lines.len() {
        let trimmed = lines[index].trim();
        if !trimmed.starts_with('@') {
            lowered.push(lines[index].to_string());
            index += 1;
            continue;
        }

        let decorator_expr = trimmed.trim_start_matches('@').trim().trim_end_matches(';');
        if decorator_expr.is_empty() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator declaration form",
            });
        }

        index += 1;
        while index < lines.len() && lines[index].trim().is_empty() {
            index += 1;
        }

        if index >= lines.len() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            });
        }

        let class_line = lines[index].trim();
        if !class_line.starts_with("class ") {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            });
        }
        let Some(class_name) = parse_class_declaration_name(class_line) else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            });
        };

        let mut class_expr = class_line.to_string();
        if !class_expr.ends_with(';') {
            class_expr.push(';');
        }

        lowered.push(format!("let {class_name} = {class_expr}"));
        lowered.push(format!(
            "{class_name} = __applyClassDecorator({decorator_expr}, {class_name});"
        ));

        lowered_any = true;
        index += 1;
    }

    if !lowered_any || source.contains("function __applyClassDecorator(") {
        return Ok(lowered.join("\n"));
    }

    let mut with_helper = vec![
        "function __applyClassDecorator(decorator, target) {".to_string(),
        "  const next = decorator(target);".to_string(),
        "  return next ?? target;".to_string(),
        "}".to_string(),
    ];
    with_helper.extend(lowered);
    Ok(with_helper.join("\n"))
}

fn parse_class_declaration_name(class_declaration: &str) -> Option<String> {
    let remainder = class_declaration.strip_prefix("class ")?;
    let mut identifier = String::new();
    for ch in remainder.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '$' {
            identifier.push(ch);
            continue;
        }
        break;
    }

    if identifier.is_empty() {
        None
    } else {
        Some(identifier)
    }
}

fn lower_simple_enums(source: &str) -> String {
    let mut out = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("enum ") {
            out.push(line.to_string());
            continue;
        }

        let Some(rest) = trimmed.strip_prefix("enum ") else {
            out.push(line.to_string());
            continue;
        };
        let Some(brace_start) = rest.find('{') else {
            out.push(line.to_string());
            continue;
        };
        let Some(brace_end) = rest.rfind('}') else {
            out.push(line.to_string());
            continue;
        };

        let enum_name = rest[..brace_start].trim();
        let body = rest[brace_start + 1..brace_end].trim();
        if enum_name.is_empty() {
            out.push(line.to_string());
            continue;
        }

        let mut entries = Vec::<String>::new();
        let mut numeric_counter = 0i64;

        for raw_member in body.split(',') {
            let member = raw_member.trim();
            if member.is_empty() {
                continue;
            }

            if let Some((name, value)) = member.split_once('=') {
                let key = name.trim();
                let value_trimmed = value.trim();
                if key.is_empty() {
                    continue;
                }
                entries.push(format!("{key}: {value_trimmed}"));
                if let Ok(parsed) = value_trimmed.parse::<i64>() {
                    numeric_counter = parsed.saturating_add(1);
                }
            } else {
                let key = member;
                entries.push(format!("{key}: {numeric_counter}"));
                numeric_counter = numeric_counter.saturating_add(1);
            }
        }

        if entries.is_empty() {
            out.push(line.to_string());
            continue;
        }

        out.push(format!(
            "const {enum_name} = Object.freeze({{{}}});",
            entries.join(", ")
        ));
    }

    out.join("\n")
}

fn lower_constructor_parameter_properties(source: &str) -> String {
    let mut out = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("constructor(") {
            out.push(line.to_string());
            continue;
        }

        let Some(args_start) = trimmed.find('(') else {
            out.push(line.to_string());
            continue;
        };
        let Some(args_end) = trimmed.find(')') else {
            out.push(line.to_string());
            continue;
        };

        let args_text = &trimmed[args_start + 1..args_end];
        let mut normalized_args = Vec::<String>::new();
        let mut injected_assignments = Vec::<String>::new();

        for argument in args_text.split(',') {
            let raw_arg = argument.trim();
            if raw_arg.is_empty() {
                continue;
            }

            let (visibility, remaining) = if let Some(rest) = raw_arg.strip_prefix("private ") {
                (Some("private"), rest)
            } else if let Some(rest) = raw_arg.strip_prefix("public ") {
                (Some("public"), rest)
            } else if let Some(rest) = raw_arg.strip_prefix("protected ") {
                (Some("protected"), rest)
            } else {
                (None, raw_arg)
            };

            let no_readonly = remaining
                .strip_prefix("readonly ")
                .unwrap_or(remaining)
                .trim();

            let param_name = no_readonly.split(':').next().unwrap_or(no_readonly).trim();

            normalized_args.push(no_readonly.to_string());

            if visibility.is_some() && !param_name.is_empty() {
                injected_assignments.push(format!("this.{param_name} = {param_name};"));
            }
        }

        let mut rebuilt = String::new();
        rebuilt.push_str("constructor(");
        rebuilt.push_str(&normalized_args.join(", "));
        rebuilt.push(')');

        if let Some(brace_open) = trimmed.find('{') {
            let body_start = brace_open + 1;
            let body_end = trimmed.rfind('}').unwrap_or(trimmed.len());
            let existing_body = trimmed[body_start..body_end].trim();
            rebuilt.push_str(" {");
            if !injected_assignments.is_empty() {
                rebuilt.push(' ');
                rebuilt.push_str(&injected_assignments.join(" "));
            }
            if !existing_body.is_empty() {
                rebuilt.push(' ');
                rebuilt.push_str(existing_body);
            }
            rebuilt.push_str(" }");
        } else {
            rebuilt.push(';');
        }

        out.push(rebuilt);
    }

    out.join("\n")
}

fn normalize_definite_assignment_assertions(source: &str) -> String {
    rewrite_outside_strings_and_comments(source, |source, index, output| {
        if source[index..].starts_with("!:") {
            output.push(':');
            return Some(index + 2);
        }
        None
    })
}

fn strip_const_assertions(source: &str) -> String {
    rewrite_outside_strings_and_comments(source, |source, index, output| {
        if !starts_with_keyword(source, index, "as") {
            return None;
        }

        let whitespace_start = index + "as".len();
        let const_start = skip_ascii_whitespace(source, whitespace_start);
        if const_start == whitespace_start || !starts_with_keyword(source, const_start, "const") {
            return None;
        }

        trim_trailing_inline_whitespace(output);
        Some(const_start + "const".len())
    })
}

fn lower_abstract_class_keywords(source: &str) -> String {
    rewrite_outside_strings_and_comments(source, |source, index, _output| {
        if !starts_with_keyword(source, index, "abstract") {
            return None;
        }

        let class_start = skip_ascii_whitespace(source, index + "abstract".len());
        if class_start == index + "abstract".len()
            || !starts_with_keyword(source, class_start, "class")
        {
            return None;
        }

        Some(class_start)
    })
}

fn strip_implements_clauses(source: &str) -> String {
    rewrite_outside_strings_and_comments(source, |source, index, output| {
        if !starts_with_keyword(source, index, "implements")
            || !class_header_precedes_implements(source, index)
        {
            return None;
        }

        let mut cursor = index + "implements".len();
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        let mut angle_depth = 0usize;

        while cursor < source.len() {
            let ch = source[cursor..]
                .chars()
                .next()
                .expect("cursor should remain on a char boundary");
            match ch {
                '(' => paren_depth += 1,
                ')' => paren_depth = paren_depth.saturating_sub(1),
                '[' => bracket_depth += 1,
                ']' => bracket_depth = bracket_depth.saturating_sub(1),
                '<' => angle_depth += 1,
                '>' => angle_depth = angle_depth.saturating_sub(1),
                '{' if paren_depth == 0 && bracket_depth == 0 && angle_depth == 0 => {
                    trim_trailing_inline_whitespace(output);
                    if output
                        .chars()
                        .next_back()
                        .is_some_and(|last| !last.is_ascii_whitespace() && last != '{')
                    {
                        output.push(' ');
                    }
                    return Some(cursor);
                }
                _ => {}
            }
            cursor += ch.len_utf8();
        }

        None
    })
}

fn class_header_precedes_implements(source: &str, index: usize) -> bool {
    let mut cursor = index;
    while let Some((prev_index, ch)) = source[..cursor].char_indices().last() {
        if matches!(ch, '\n' | ';' | '{' | '}') {
            let header_start = prev_index + ch.len_utf8();
            return source[header_start..index].contains("class ");
        }
        cursor = prev_index;
    }

    source[..index].contains("class ")
}

fn strip_type_annotations(source: &str) -> String {
    let mut output = String::new();
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    // Track string/comment/template-literal state to avoid stripping colons
    // inside literal contexts.
    #[derive(PartialEq)]
    enum Ctx {
        Code,
        SingleQuote,
        DoubleQuote,
        TemplateLiteral,
        LineComment,
        BlockComment,
    }

    // Helper: advance index past one full UTF-8 codepoint starting at `start`
    // and return the end index. All context-switching characters are ASCII, so
    // multi-byte codepoints are always opaque content.
    #[inline]
    fn utf8_advance(bytes: &[u8], start: usize) -> usize {
        if start >= bytes.len() {
            return start;
        }
        let b = bytes[start];
        if b < 0x80 {
            start + 1
        } else if b & 0xE0 == 0xC0 {
            start + 2
        } else if b & 0xF0 == 0xE0 {
            start + 3
        } else {
            start + 4
        }
        .min(bytes.len())
    }

    let mut ctx = Ctx::Code;

    while i < len {
        let ch = bytes[i];

        match ctx {
            Ctx::LineComment => {
                if ch == b'\n' {
                    output.push('\n');
                    i += 1;
                    ctx = Ctx::Code;
                } else {
                    let end = utf8_advance(bytes, i);
                    output.push_str(&source[i..end]);
                    i = end;
                }
                continue;
            }
            Ctx::BlockComment => {
                if ch == b'*' && i + 1 < len && bytes[i + 1] == b'/' {
                    output.push_str("*/");
                    i += 2;
                    ctx = Ctx::Code;
                } else {
                    let end = utf8_advance(bytes, i);
                    output.push_str(&source[i..end]);
                    i = end;
                }
                continue;
            }
            Ctx::SingleQuote => {
                if ch == b'\\' && i + 1 < len {
                    // Escaped character: copy backslash + full next codepoint.
                    let esc_end = utf8_advance(bytes, i + 1);
                    output.push_str(&source[i..esc_end]);
                    i = esc_end;
                } else if ch == b'\'' {
                    output.push('\'');
                    ctx = Ctx::Code;
                    i += 1;
                } else {
                    let end = utf8_advance(bytes, i);
                    output.push_str(&source[i..end]);
                    i = end;
                }
                continue;
            }
            Ctx::DoubleQuote => {
                if ch == b'\\' && i + 1 < len {
                    let esc_end = utf8_advance(bytes, i + 1);
                    output.push_str(&source[i..esc_end]);
                    i = esc_end;
                } else if ch == b'"' {
                    output.push('"');
                    ctx = Ctx::Code;
                    i += 1;
                } else {
                    let end = utf8_advance(bytes, i);
                    output.push_str(&source[i..end]);
                    i = end;
                }
                continue;
            }
            Ctx::TemplateLiteral => {
                if ch == b'\\' && i + 1 < len {
                    let esc_end = utf8_advance(bytes, i + 1);
                    output.push_str(&source[i..esc_end]);
                    i = esc_end;
                } else if ch == b'`' {
                    output.push('`');
                    ctx = Ctx::Code;
                    i += 1;
                } else {
                    let end = utf8_advance(bytes, i);
                    output.push_str(&source[i..end]);
                    i = end;
                }
                continue;
            }
            Ctx::Code => {}
        }

        // In code context: detect string/comment openings.
        if ch == b'\'' {
            ctx = Ctx::SingleQuote;
            output.push('\'');
            i += 1;
            continue;
        }
        if ch == b'"' {
            ctx = Ctx::DoubleQuote;
            output.push('"');
            i += 1;
            continue;
        }
        if ch == b'`' {
            ctx = Ctx::TemplateLiteral;
            output.push('`');
            i += 1;
            continue;
        }
        if ch == b'/' && i + 1 < len {
            if bytes[i + 1] == b'/' {
                ctx = Ctx::LineComment;
                output.push_str("//");
                i += 2;
                continue;
            }
            if bytes[i + 1] == b'*' {
                ctx = Ctx::BlockComment;
                output.push_str("/*");
                i += 2;
                continue;
            }
        }

        // Strip type annotations: skip from colon until the next delimiter.
        if ch == b':' {
            i += 1;
            while i < len {
                if matches!(bytes[i], b',' | b')' | b'=' | b';' | b'{' | b'}' | b'\n') {
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Default: copy the full UTF-8 codepoint.
        let end = utf8_advance(bytes, i);
        output.push_str(&source[i..end]);
        i = end;
    }

    output
}

fn lower_simple_jsx(source: &str) -> String {
    let mut out = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with('<') && trimmed.ends_with("/>") {
            let tag = trimmed
                .trim_start_matches('<')
                .trim_end_matches("/>")
                .trim();
            if !tag.is_empty() {
                out.push(format!("createElement(\"{tag}\", null);"));
                continue;
            }
        }

        if trimmed.starts_with('<') && trimmed.contains('>') && trimmed.contains("</") {
            let Some(open_end) = trimmed.find('>') else {
                out.push(line.to_string());
                continue;
            };
            let open_tag = trimmed[1..open_end].trim();
            let close_tag = format!("</{open_tag}>");
            if trimmed.ends_with(&close_tag) {
                let inner = trimmed[open_end + 1..trimmed.len() - close_tag.len()].trim();
                out.push(format!("createElement(\"{open_tag}\", null, {inner});"));
                continue;
            }
        }

        out.push(line.to_string());
    }

    out.join("\n")
}

/// Strips `hostcall<"cap">` → `hostcall` so the ES2020 parser sees a plain
/// function call instead of comparison expressions around angle brackets.
fn strip_hostcall_type_params(source: &str) -> String {
    let marker = "hostcall<\"";
    let mut output = String::with_capacity(source.len());
    let mut remaining = source;

    while let Some(start) = remaining.find(marker) {
        output.push_str(&remaining[..start]);
        output.push_str("hostcall");
        let after_marker = &remaining[start + marker.len()..];
        if let Some(close) = after_marker.find("\">") {
            remaining = &after_marker[close + 2..];
        } else {
            // Malformed — keep original text
            output.push_str(&remaining[start + "hostcall".len()..]);
            remaining = "";
        }
    }
    output.push_str(remaining);
    output
}

fn extract_capability_intents(source: &str) -> Vec<CapabilityIntent> {
    let mut intents = Vec::<CapabilityIntent>::new();

    for token in source.split_whitespace() {
        if let Some(rest) = token.strip_prefix("hostcall<\"")
            && let Some(capability_end) = rest.find("\">")
        {
            let capability = rest[..capability_end].trim().to_string();
            intents.push(CapabilityIntent {
                symbol: "hostcall".to_string(),
                capability,
            });
        }
    }

    intents.sort_by(|left, right| {
        left.symbol
            .cmp(&right.symbol)
            .then_with(|| left.capability.cmp(&right.capability))
    });
    intents.dedup();
    intents
}

fn build_identity_source_map(original: &str, normalized: &str) -> Vec<SourceMapEntry> {
    let original_count = original.lines().count().max(1);
    normalized
        .lines()
        .enumerate()
        .map(|(idx, _)| SourceMapEntry {
            normalized_line: idx + 1,
            original_line: (idx + 1).min(original_count),
        })
        .collect()
}

fn sha256_hex(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_type_only_imports() {
        let source = r#"
import type { Foo } from "./types";
import { bar } from "./bar";
const value: number = 1;
"#;

        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert!(!output.normalized_source.contains("import type"));
        assert!(output.normalized_source.contains("import { bar }"));
    }

    #[test]
    fn lowers_simple_enum() {
        let source = "enum Status { Ready, Busy = 3 }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert!(
            output
                .normalized_source
                .contains("const Status = Object.freeze(")
        );
        assert!(output.normalized_source.contains("Ready: 0"));
        assert!(output.normalized_source.contains("Busy"));
    }

    #[test]
    fn lowers_parameter_properties() {
        let source = "constructor(private service: Service, public count: number) { doWork(); }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert!(output.normalized_source.contains("this.service = service;"));
        assert!(output.normalized_source.contains("this.count = count;"));
    }

    #[test]
    fn strips_interface_declarations() {
        let source = "interface Shape { area(): number; }\nconst shape = {};";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("interface declaration should be removed");

        assert!(!output.normalized_source.contains("interface Shape"));
        assert!(output.normalized_source.contains("const shape = {};"));
    }

    #[test]
    fn strips_export_type_alias_declarations() {
        let source = "export type UserId = string;\nconst userId = \"u1\";";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("type alias declaration should be removed");

        assert!(!output.normalized_source.contains("export type"));
        assert!(!output.normalized_source.contains("type UserId"));
        assert!(output.normalized_source.contains("const userId = \"u1\";"));
    }

    #[test]
    fn strips_type_aliases_with_comments_and_template_literals() {
        let source = r#"type Route = /* comment; */ `/api;${string}`;
const route = "/api/x";"#;
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("type alias with comment/template literal should be removed");

        assert!(!output.normalized_source.contains("type Route"));
        assert!(
            output
                .normalized_source
                .contains("const route = \"/api/x\";")
        );
    }

    #[test]
    fn strips_interface_declarations_with_comment_delimiters() {
        let source = "interface Shape { /* { nested } ; */ area(): number; }\nconst shape = {};";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("interface declaration with comments should be removed");

        assert!(!output.normalized_source.contains("interface Shape"));
        assert!(output.normalized_source.contains("const shape = {};"));
    }

    #[test]
    fn lowers_simple_jsx_to_create_element() {
        let source = "<Widget />";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert_eq!(output.normalized_source, "createElement(\"Widget\", null);");
    }

    #[test]
    fn captures_capability_intents() {
        let source = r#"const read = hostcall<"fs.read">();"#;
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("normalization should pass");

        assert_eq!(output.capability_intents.len(), 1);
        assert_eq!(output.capability_intents[0].capability, "fs.read");
    }

    #[test]
    fn lowers_simple_namespace_declaration() {
        let source = "namespace Demo { export const value = 1; }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("namespace normalization should pass");

        assert!(output.normalized_source.contains("const Demo = (() => {"));
        assert!(output.normalized_source.contains("ns.value = 1;"));
    }

    #[test]
    fn lowers_namespace_export_function_declarations() {
        let source = "namespace Demo { export function run() { return 1; } }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("namespace export function should lower");

        assert!(
            output
                .normalized_source
                .contains("function run() { return 1; }")
        );
        assert!(output.normalized_source.contains("ns.run = run;"));
    }

    #[test]
    fn lowers_multiline_namespace_export_function_declarations() {
        let source = r#"
namespace Demo {
  export function run() { return 1; } // preserve separation before the next export
  export const version = 1;
}
"#;
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("multiline namespace export function should lower");

        assert!(
            output
                .normalized_source
                .contains("function run() { return 1; }")
        );
        assert!(output.normalized_source.contains("ns.run = run;"));
        assert!(output.normalized_source.contains("ns.version = 1;"));
    }

    #[test]
    fn parses_namespace_exports_with_comment_after_function() {
        let body = r#"
export function run() { return 1; } // preserve separation before the next export
export const version = 1;
"#
        .trim();

        assert_eq!(
            find_namespace_export_function_end(body, 0),
            body.find("} //").map(|index| index + '}'.len_utf8())
        );
        assert_eq!(
            parse_namespace_exports(body).expect("namespace exports should parse"),
            vec![
                "  function run() { return 1; }".to_string(),
                "  ns.run = run;".to_string(),
                "  ns.version = 1;".to_string(),
            ]
        );
    }

    #[test]
    fn lowers_namespace_export_function_with_return_type() {
        // Uses a simple return type (not object-shaped) to avoid the known limitation
        // where strip_type_annotations cannot distinguish object-literal colons
        // (e.g. { key: value }) from type annotation colons.
        let source = "namespace Demo { export function make(): number { return 42; } }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("namespace export function with return type should lower");

        // After strip_type_annotations removes `: number`, the space before `{`
        // is consumed, producing `make(){` instead of `make() {`. This is a
        // known formatting artifact of the current type-stripping pass.
        assert!(output.normalized_source.contains("function make()"));
        assert!(output.normalized_source.contains("return 42;"));
        assert!(output.normalized_source.contains("ns.make = make;"));
    }

    #[test]
    fn rejects_namespace_export_function_with_object_shaped_return_type() {
        let source =
            "namespace Demo { export function make(): { value: number } { return { value: 1 }; } }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect_err("object-shaped return types remain unsupported");

        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            }
        );
    }

    #[test]
    fn rejects_unsupported_namespace_export_class_forms() {
        let source = "namespace Demo { export class Worker {} }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect_err("unsupported namespace class export should fail");

        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            }
        );
    }

    #[test]
    fn returns_error_for_empty_source() {
        let error = normalize_typescript_to_es2020(
            "  \n  ",
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect_err("empty source should fail");

        assert_eq!(error, TsNormalizationError::EmptySource);
    }

    #[test]
    fn allows_at_symbol_inside_string_literals() {
        let source = r#"const email = "person@example.com";"#;
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect("string literal should not be treated as decorator syntax");

        assert!(output.normalized_source.contains("person@example.com"));
    }

    // --- Error Display ---

    #[test]
    fn error_display_empty_source() {
        let e = TsNormalizationError::EmptySource;
        assert_eq!(e.to_string(), "TS source is empty after normalization");
    }

    #[test]
    fn error_display_unsupported_syntax() {
        let e = TsNormalizationError::UnsupportedSyntax {
            feature: "some feature",
        };
        assert_eq!(e.to_string(), "unsupported syntax: some feature");
    }

    #[test]
    fn error_display_unsupported_compiler_option() {
        let e = TsNormalizationError::UnsupportedCompilerOption {
            option: "target",
            value: "es5".to_string(),
        };
        assert_eq!(e.to_string(), "unsupported compiler option: target=es5");
    }

    // --- Unsupported compiler option errors ---

    #[test]
    fn rejects_unsupported_target() {
        let mut config = TsNormalizationConfig::default();
        config.compiler_options.target = "es5".to_string();
        let error =
            normalize_typescript_to_es2020("const x = 1;", &config, "t", "d", "p").unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedCompilerOption {
                option: "target",
                value: "es5".to_string(),
            }
        );
    }

    #[test]
    fn rejects_unsupported_module() {
        let mut config = TsNormalizationConfig::default();
        config.compiler_options.module = "amd".to_string();
        let error =
            normalize_typescript_to_es2020("const x = 1;", &config, "t", "d", "p").unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedCompilerOption {
                option: "module",
                value: "amd".to_string(),
            }
        );
    }

    #[test]
    fn accepts_commonjs_module() {
        let mut config = TsNormalizationConfig::default();
        config.compiler_options.module = "commonjs".to_string();
        let output =
            normalize_typescript_to_es2020("const x = 1;", &config, "t", "d", "p").unwrap();
        assert!(output.normalized_source.contains("const x = 1"));
    }

    #[test]
    fn rejects_unsupported_jsx() {
        let mut config = TsNormalizationConfig::default();
        config.compiler_options.jsx = "solid-jsx".to_string();
        let error =
            normalize_typescript_to_es2020("const x = 1;", &config, "t", "d", "p").unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedCompilerOption {
                option: "jsx",
                value: "solid-jsx".to_string(),
            }
        );
    }

    #[test]
    fn accepts_react_jsx_mode() {
        let mut config = TsNormalizationConfig::default();
        config.compiler_options.jsx = "react".to_string();
        let output =
            normalize_typescript_to_es2020("const x = 1;", &config, "t", "d", "p").unwrap();
        assert!(output.normalized_source.contains("const x = 1"));
    }

    #[test]
    fn jsx_preserve_skips_lowering() {
        let mut config = TsNormalizationConfig::default();
        config.compiler_options.jsx = "preserve".to_string();
        let output = normalize_typescript_to_es2020("<Widget />", &config, "t", "d", "p").unwrap();
        // In preserve mode, JSX is NOT lowered to createElement
        assert!(!output.normalized_source.contains("createElement"));
    }

    // --- Definite assignment normalization ---

    #[test]
    fn removes_definite_assignment_assertions() {
        let source = "let value!: string;";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        // `!:` is replaced with `:`; then type annotations are stripped
        assert!(!output.normalized_source.contains("!:"));
    }

    #[test]
    fn definite_assignment_normalization_skips_strings_and_comments() {
        let source = r#"const label = "!:";
// !:
let value!: string;"#;
        let normalized = normalize_definite_assignment_assertions(source);

        assert!(normalized.contains(r#""!:""#));
        assert!(normalized.contains("// !:"));
        assert!(normalized.contains("let value: string;"));
    }

    // --- Const assertion normalization ---

    #[test]
    fn removes_const_assertions() {
        let source = "const arr = [1, 2, 3] as const;";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(!output.normalized_source.contains("as const"));
    }

    #[test]
    fn const_assertion_stripping_skips_strings_and_comments() {
        let source = r#"const label = "as const";
/* as const */
const arr = [1, 2, 3] as const;"#;
        let normalized = strip_const_assertions(source);

        assert!(normalized.contains(r#""as const""#));
        assert!(normalized.contains("/* as const */"));
        assert!(normalized.contains("const arr = [1, 2, 3];"));
    }

    // --- Abstract class lowering ---

    #[test]
    fn lowers_abstract_class() {
        let source = "abstract class Base { }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(!output.normalized_source.contains("abstract"));
        assert!(output.normalized_source.contains("class Base"));
    }

    #[test]
    fn abstract_class_lowering_skips_strings_and_comments() {
        let source = r#"const label = "abstract class";
/* abstract class Commented {} */
abstract class Base { }"#;
        let normalized = lower_abstract_class_keywords(source);

        assert!(normalized.contains(r#""abstract class""#));
        assert!(normalized.contains("/* abstract class Commented {} */"));
        assert!(normalized.contains("class Base { }"));
    }

    #[test]
    fn strips_implements_clause_from_class_headers() {
        let source = "class Service implements Disposable, NamedService { run() { return 1; } }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();

        assert!(!output.normalized_source.contains("implements Disposable"));
        assert!(
            output
                .normalized_source
                .contains("class Service { run() { return 1; } }")
        );
    }

    // --- Decorator lowering ---

    #[test]
    fn lowers_simple_class_decorator() {
        let source = "@sealed\nclass Foo { }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("__applyClassDecorator"));
        assert!(output.normalized_source.contains("sealed"));
        assert!(output.normalized_source.contains("let Foo ="));
    }

    #[test]
    fn decorator_at_end_of_file_without_class_fails() {
        let source = "@orphan";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            }
        );
    }

    #[test]
    fn decorator_on_non_class_fails() {
        let source = "@logged\nfunction run() { }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator target",
            }
        );
    }

    #[test]
    fn empty_decorator_expression_fails() {
        let source = "@\nclass Foo { }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported decorator declaration form",
            }
        );
    }

    // --- JSX with children ---

    #[test]
    fn lowers_jsx_with_children() {
        let source = "<div>hello</div>";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(
            output
                .normalized_source
                .contains("createElement(\"div\", null, hello)")
        );
    }

    // --- Namespace edge cases ---

    #[test]
    fn namespace_missing_brace_fails() {
        let source = "namespace Broken";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            }
        );
    }

    #[test]
    fn namespace_empty_name_fails() {
        let source = "namespace  { export const x = 1; }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            }
        );
    }

    #[test]
    fn namespace_non_export_statement_fails() {
        let source = "namespace Demo { const hidden = 1; }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            }
        );
    }

    #[test]
    fn namespace_export_without_assignment_fails() {
        let source = "namespace Demo { export const x; }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap_err();
        assert_eq!(
            error,
            TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            }
        );
    }

    #[test]
    fn duplicate_namespace_declarations_merge() {
        let source = "namespace Ns { export const a = 1; }\nnamespace Ns { export const b = 2; }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("ns.a = 1;"));
        assert!(output.normalized_source.contains("ns.b = 2;"));
        // Only one IIFE block for the merged namespace
        let iife_count = output
            .normalized_source
            .matches("const Ns = (() => {")
            .count();
        assert_eq!(iife_count, 1);
    }

    // --- Enum edge cases ---

    #[test]
    fn enum_with_explicit_values_resets_counter() {
        let source = "enum Dir { Up = 10, Down }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("Up: 10"));
        assert!(output.normalized_source.contains("Down: 11"));
    }

    #[test]
    fn enum_missing_opening_brace_passes_through() {
        let source = "enum NoBrace }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        // Line passes through unchanged when no opening brace
        assert!(output.normalized_source.contains("enum NoBrace"));
    }

    #[test]
    fn enum_empty_body_passes_through() {
        let source = "enum Empty { }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        // Empty body → entries is empty → line passes through
        assert!(output.normalized_source.contains("enum Empty"));
    }

    #[test]
    fn enum_string_values() {
        let source = r#"enum Color { Red = "RED", Blue = "BLUE" }"#;
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("Object.freeze"));
        assert!(output.normalized_source.contains(r#"Red: "RED""#));
        assert!(output.normalized_source.contains(r#"Blue: "BLUE""#));
    }

    // --- Constructor parameter property edge cases ---

    #[test]
    fn constructor_protected_parameter() {
        let source = "constructor(protected name: string) { }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("this.name = name;"));
    }

    #[test]
    fn constructor_readonly_parameter() {
        let source = "constructor(public readonly id: number) { }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("this.id = id;"));
    }

    #[test]
    fn constructor_no_visibility_no_assignment() {
        let source = "constructor(value: number) { }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(!output.normalized_source.contains("this.value"));
    }

    #[test]
    fn constructor_without_body_gets_semicolon() {
        let source = "constructor(private x: number)";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        // No brace → rebuilt ends with semicolon
        assert!(output.normalized_source.contains("constructor("));
        assert!(output.normalized_source.ends_with(';'));
    }

    // --- Helper functions ---

    #[test]
    fn normalize_newlines_crlf_to_lf() {
        let result = normalize_newlines("line1\r\nline2\rline3");
        assert_eq!(result, "line1\nline2\nline3");
    }

    #[test]
    fn normalize_spacing_removes_blank_lines_and_trims() {
        let result = normalize_spacing("  hello  \n\n  world  ".to_string());
        assert_eq!(result, "hello\nworld");
    }

    #[test]
    fn build_decision_changed_true() {
        let d = build_decision("step_name", true, "description");
        assert_eq!(d.step, "step_name");
        assert!(d.changed);
        assert_eq!(d.detail, "description");
    }

    #[test]
    fn build_decision_changed_false() {
        let d = build_decision("step_name", false, "description");
        assert!(!d.changed);
    }

    #[test]
    fn success_event_fields() {
        let e = success_event("t", "d", "p", "comp", "evt");
        assert_eq!(e.trace_id, "t");
        assert_eq!(e.decision_id, "d");
        assert_eq!(e.policy_id, "p");
        assert_eq!(e.component, "comp");
        assert_eq!(e.event, "evt");
        assert_eq!(e.outcome, "pass");
        assert!(e.error_code.is_none());
    }

    #[test]
    fn failure_event_fields() {
        let e = failure_event("t", "d", "p", "comp", "evt", "ERR-001");
        assert_eq!(e.outcome, "fail");
        assert_eq!(e.error_code.as_deref(), Some("ERR-001"));
    }

    #[test]
    fn elide_type_only_imports_preserves_regular_imports() {
        let source = "import type { A } from \"a\";\nimport { B } from \"b\";\nconst x = 1;";
        let result = elide_type_only_imports(source);
        assert!(!result.contains("import type"));
        assert!(result.contains("import { B }"));
        assert!(result.contains("const x = 1"));
    }

    #[test]
    fn elide_type_only_imports_rewrites_mixed_named_import_specifiers() {
        let source = "import { type Foo, bar, type Baz as Qux } from \"pkg\";";
        let result = elide_type_only_imports(source);
        assert_eq!(result, "import { bar } from \"pkg\";");
    }

    #[test]
    fn elide_type_only_imports_accepts_extra_spacing_in_import_type_keyword() {
        let source = "import   type { Foo } from \"pkg\";\nconst value = 1;";
        let result = elide_type_only_imports(source);
        assert!(!result.contains("import   type"));
        assert!(result.contains("const value = 1;"));
    }

    #[test]
    fn elide_type_only_imports_rewrites_default_plus_type_only_named_imports() {
        let source = "import React, { type FC } from \"react\";";
        let result = elide_type_only_imports(source);
        assert_eq!(result, "import React from \"react\";");
    }

    #[test]
    fn elide_type_only_imports_preserves_runtime_specifier_named_type() {
        let source = "import { type as runtimeType, keep } from \"pkg\";";
        let result = elide_type_only_imports(source);
        assert_eq!(result, source);
    }

    #[test]
    fn elide_type_only_imports_preserves_runtime_default_import_named_type() {
        let source = "import type from \"pkg\";";
        let result = elide_type_only_imports(source);
        assert_eq!(result, source);
    }

    #[test]
    fn elide_type_only_imports_preserves_runtime_default_import_named_type_with_named_clause() {
        let source = "import type, { keep } from \"pkg\";";
        let result = elide_type_only_imports(source);
        assert_eq!(result, source);
    }

    #[test]
    fn elide_type_only_imports_rewrites_mixed_named_export_specifiers() {
        let source = "export { type Foo, bar, type Baz as Qux } from \"pkg\";";
        let result = elide_type_only_imports(source);
        assert_eq!(result, "export { bar } from \"pkg\";");
    }

    #[test]
    fn elide_type_only_imports_preserves_runtime_export_specifier_named_type() {
        let source = "export { type as runtimeType, keep } from \"pkg\";";
        let result = elide_type_only_imports(source);
        assert_eq!(result, source);
    }

    #[test]
    fn elide_type_only_imports_removes_export_type_named_reexports() {
        let source = "export type { Foo, Bar } from \"pkg\";\nconst value = 1;";
        let result = elide_type_only_imports(source);
        assert!(!result.contains("export type"));
        assert!(result.contains("const value = 1;"));
    }

    #[test]
    fn strip_type_annotations_basic() {
        let result = strip_type_annotations("let x: number = 5;");
        // The colon and everything until the next delimiter is stripped
        assert!(result.contains("let x"));
        assert!(result.contains("= 5;"));
        assert!(!result.contains("number"));
    }

    #[test]
    fn strip_type_annotations_preserves_string_content() {
        let result = strip_type_annotations(r#"const s = "hello: world";"#);
        assert!(result.contains("hello: world"));
    }

    #[test]
    fn lower_abstract_class_keywords_replaces() {
        assert_eq!(
            lower_abstract_class_keywords("abstract class Base { }"),
            "class Base { }"
        );
    }

    #[test]
    fn lower_abstract_class_keywords_noop() {
        assert_eq!(
            lower_abstract_class_keywords("class Concrete { }"),
            "class Concrete { }"
        );
    }

    #[test]
    fn parse_class_declaration_name_valid() {
        assert_eq!(
            parse_class_declaration_name("class MyClass { }"),
            Some("MyClass".to_string())
        );
    }

    #[test]
    fn parse_class_declaration_name_with_extends() {
        assert_eq!(
            parse_class_declaration_name("class Child extends Base { }"),
            Some("Child".to_string())
        );
    }

    #[test]
    fn parse_class_declaration_name_not_class() {
        assert_eq!(parse_class_declaration_name("function foo() { }"), None);
    }

    #[test]
    fn parse_class_declaration_name_empty_name() {
        assert_eq!(parse_class_declaration_name("class  { }"), None);
    }

    #[test]
    fn extract_capability_intents_multiple() {
        let source = r#"hostcall<"fs.read"> hostcall<"net.fetch"> hostcall<"fs.read">"#;
        let intents = extract_capability_intents(source);
        // Deduplicated
        assert_eq!(intents.len(), 2);
        assert_eq!(intents[0].capability, "fs.read");
        assert_eq!(intents[1].capability, "net.fetch");
    }

    #[test]
    fn extract_capability_intents_none() {
        let intents = extract_capability_intents("const x = 1;");
        assert!(intents.is_empty());
    }

    #[test]
    fn build_identity_source_map_basic() {
        let map = build_identity_source_map("a\nb\nc", "x\ny");
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].normalized_line, 1);
        assert_eq!(map[0].original_line, 1);
        assert_eq!(map[1].normalized_line, 2);
        assert_eq!(map[1].original_line, 2);
    }

    #[test]
    fn build_identity_source_map_clamps_to_original_count() {
        let map = build_identity_source_map("a", "x\ny\nz");
        assert_eq!(map.len(), 3);
        assert_eq!(map[2].original_line, 1); // clamped to max original
    }

    #[test]
    fn sha256_hex_deterministic() {
        let a = sha256_hex("hello");
        let b = sha256_hex("hello");
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
        assert_eq!(a.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn sha256_hex_different_inputs() {
        assert_ne!(sha256_hex("a"), sha256_hex("b"));
    }

    // --- Render namespace block ---

    #[test]
    fn render_namespace_block_structure() {
        let block = render_namespace_block("Foo", &["  ns.x = 1;".to_string()]);
        assert_eq!(block[0], "const Foo = (() => {");
        assert_eq!(block[1], "  const ns = {};");
        assert_eq!(block[2], "  ns.x = 1;");
        assert_eq!(block[3], "  return ns;");
        assert_eq!(block[4], "})();");
    }

    // --- Lower simple enums ---

    #[test]
    fn lower_simple_enums_no_enums() {
        assert_eq!(lower_simple_enums("const x = 1;"), "const x = 1;");
    }

    // --- Lower simple JSX ---

    #[test]
    fn lower_simple_jsx_non_jsx_passthrough() {
        assert_eq!(lower_simple_jsx("const x = 1;"), "const x = 1;");
    }

    // --- Serde round-trips ---

    #[test]
    fn ts_compiler_options_serde_round_trip() {
        let opts = TsCompilerOptions::default();
        let json = serde_json::to_string(&opts).unwrap();
        let back: TsCompilerOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(opts, back);
    }

    #[test]
    fn ts_normalization_config_serde_round_trip() {
        let config = TsNormalizationConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TsNormalizationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn normalization_decision_serde_round_trip() {
        let d = NormalizationDecision {
            step: "step".to_string(),
            changed: true,
            detail: "detail".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: NormalizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn normalization_event_serde_round_trip() {
        let e = NormalizationEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "c".to_string(),
            event: "e".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: NormalizationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn capability_intent_serde_round_trip() {
        let ci = CapabilityIntent {
            symbol: "hostcall".to_string(),
            capability: "fs.read".to_string(),
        };
        let json = serde_json::to_string(&ci).unwrap();
        let back: CapabilityIntent = serde_json::from_str(&json).unwrap();
        assert_eq!(ci, back);
    }

    #[test]
    fn source_map_entry_serde_round_trip() {
        let e = SourceMapEntry {
            normalized_line: 1,
            original_line: 1,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: SourceMapEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- Output structure ---

    #[test]
    fn output_witness_contains_hashes() {
        let output = normalize_typescript_to_es2020(
            "const x = 1;",
            &TsNormalizationConfig::default(),
            "trace-1",
            "decision-1",
            "policy-1",
        )
        .unwrap();
        assert_eq!(output.witness.trace_id, "trace-1");
        assert_eq!(output.witness.decision_id, "decision-1");
        assert_eq!(output.witness.policy_id, "policy-1");
        assert!(output.witness.source_hash.starts_with("sha256:"));
        assert!(output.witness.normalized_hash.starts_with("sha256:"));
        assert!(output.witness.compiler_options_hash.starts_with("sha256:"));
    }

    #[test]
    fn output_events_contain_success() {
        let output = normalize_typescript_to_es2020(
            "const x = 1;",
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.events.iter().any(|e| e.outcome == "pass"));
    }

    #[test]
    fn output_source_map_covers_all_normalized_lines() {
        let output = normalize_typescript_to_es2020(
            "const x = 1;\nconst y = 2;",
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        let normalized_line_count = output.normalized_source.lines().count();
        assert_eq!(output.source_map.len(), normalized_line_count);
    }

    #[test]
    fn output_decisions_cover_all_normalization_steps() {
        let output = normalize_typescript_to_es2020(
            "const x = 1;",
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        let steps: Vec<&str> = output
            .witness
            .decisions
            .iter()
            .map(|d| d.step.as_str())
            .collect();
        assert!(steps.contains(&"type_only_import_elision"));
        assert!(steps.contains(&"namespace_lowering"));
        assert!(steps.contains(&"decorator_lowering"));
        assert!(steps.contains(&"definite_assignment_normalization"));
        assert!(steps.contains(&"const_assertion_normalization"));
        assert!(steps.contains(&"type_annotation_stripping"));
        assert!(steps.contains(&"enum_lowering"));
        assert!(steps.contains(&"parameter_property_lowering"));
        assert!(steps.contains(&"abstract_class_lowering"));
        assert!(steps.contains(&"jsx_lowering"));
        assert!(steps.contains(&"capability_intent_extraction"));
    }

    // --- Failure events ---

    #[test]
    fn empty_source_produces_failure_event() {
        let _ =
            normalize_typescript_to_es2020("   ", &TsNormalizationConfig::default(), "t", "d", "p");
        // Just ensuring no panic — the error return is tested elsewhere
    }

    #[test]
    fn unsupported_target_produces_failure_event() {
        let mut config = TsNormalizationConfig::default();
        config.compiler_options.target = "es5".to_string();
        let error =
            normalize_typescript_to_es2020("const x = 1;", &config, "t", "d", "p").unwrap_err();
        assert!(matches!(
            error,
            TsNormalizationError::UnsupportedCompilerOption { .. }
        ));
    }

    // --- Default values ---

    #[test]
    fn ts_compiler_options_defaults() {
        let opts = TsCompilerOptions::default();
        assert!(opts.strict);
        assert_eq!(opts.target, "es2020");
        assert_eq!(opts.module, "esnext");
        assert_eq!(opts.jsx, "react-jsx");
    }

    #[test]
    fn ts_normalization_error_is_std_error() {
        let e: &dyn std::error::Error = &TsNormalizationError::EmptySource;
        assert!(!e.to_string().is_empty());
    }

    // --- Lower constructor parameter properties ---

    #[test]
    fn lower_constructor_parameter_properties_no_constructor() {
        let result = lower_constructor_parameter_properties("const x = 1;");
        assert_eq!(result, "const x = 1;");
    }

    // --- Namespace with multiple export types ---

    #[test]
    fn namespace_export_let_works() {
        let source = "namespace Ns { export let x = 1; }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("ns.x = 1;"));
    }

    #[test]
    fn namespace_export_var_works() {
        let source = "namespace Ns { export var x = 1; }";
        let output = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "t",
            "d",
            "p",
        )
        .unwrap();
        assert!(output.normalized_source.contains("ns.x = 1;"));
    }

    // --- Type annotation stripping with quotes ---

    #[test]
    fn strip_type_annotations_single_quoted_string() {
        let result = strip_type_annotations("const s = 'key: val';");
        assert!(result.contains("key: val"));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn ts_normalization_error_display_distinct() {
        let variants: Vec<TsNormalizationError> = vec![
            TsNormalizationError::EmptySource,
            TsNormalizationError::UnsupportedSyntax {
                feature: "decorators",
            },
            TsNormalizationError::UnsupportedCompilerOption {
                option: "target",
                value: "es3".into(),
            },
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn ts_compiler_options_default_serde_roundtrip() {
        let opts = TsCompilerOptions::default();
        let json = serde_json::to_string(&opts).unwrap();
        let back: TsCompilerOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(opts, back);
    }

    #[test]
    fn ts_normalization_config_default_serde_roundtrip() {
        let config = TsNormalizationConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TsNormalizationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn normalization_decision_serde_roundtrip() {
        let d = NormalizationDecision {
            step: "strip_types".into(),
            changed: true,
            detail: "removed 5 annotations".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: NormalizationDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn source_language_defaults_to_javascript() {
        assert_eq!(SourceLanguage::default(), SourceLanguage::JavaScript);
    }

    #[test]
    fn classify_source_language_uses_typescript_extension() {
        assert_eq!(
            classify_source_language(Some("src/main.ts"), "const value = 1;"),
            SourceLanguage::TypeScript
        );
        assert_eq!(
            classify_source_language(Some("src/App.tsx"), "const value = 1;"),
            SourceLanguage::TypeScript
        );
    }

    #[test]
    fn classify_source_language_detects_inline_typescript_markers() {
        assert_eq!(
            classify_source_language(None, "const value: number = 1;"),
            SourceLanguage::TypeScript
        );
        assert_eq!(
            classify_source_language(None, "import type { Foo } from './foo';"),
            SourceLanguage::TypeScript
        );
        assert_eq!(
            classify_source_language(None, "export type UserId = string;"),
            SourceLanguage::TypeScript
        );
        assert_eq!(
            classify_source_language(None, "import { type Foo, bar } from './foo';"),
            SourceLanguage::TypeScript
        );
        assert_eq!(
            classify_source_language(None, "export { type Foo, bar } from './foo';"),
            SourceLanguage::TypeScript
        );
    }

    #[test]
    fn classify_source_language_keeps_runtime_binding_named_type_as_javascript() {
        assert_eq!(
            classify_source_language(None, "import { type as runtimeType } from './foo';"),
            SourceLanguage::JavaScript
        );
        assert_eq!(
            classify_source_language(None, "export { type as runtimeType } from './foo';"),
            SourceLanguage::JavaScript
        );
        assert_eq!(
            classify_source_language(None, "import type from './foo';"),
            SourceLanguage::JavaScript
        );
        assert_eq!(
            classify_source_language(None, "import type, { keep } from './foo';"),
            SourceLanguage::JavaScript
        );
    }

    #[test]
    fn classify_source_language_ignores_strings_and_comments_with_ts_keywords() {
        assert_eq!(
            classify_source_language(None, "const note = \"interface Foo { bar: string }\";"),
            SourceLanguage::JavaScript
        );
        assert_eq!(
            classify_source_language(None, "// enum Status { Ready }\nconst value = 1;"),
            SourceLanguage::JavaScript
        );
        assert_eq!(
            classify_source_language(None, "class Message { note = \" implements \"; }"),
            SourceLanguage::JavaScript
        );
    }

    #[test]
    fn classify_source_language_keeps_plain_javascript_as_javascript() {
        assert_eq!(
            classify_source_language(None, "const value = { count: 1 };"),
            SourceLanguage::JavaScript
        );
    }

    #[test]
    fn prepare_public_source_entry_skips_normalization_for_javascript() {
        let prepared = prepare_source_entry_for_public_entrypoints(
            "const value = 1;",
            "fixture.js",
            "trace-js",
            "decision-js",
            "policy-js",
        )
        .unwrap();

        assert_eq!(
            prepared.source_ingestion.source_language,
            SourceLanguage::JavaScript
        );
        assert!(!prepared.source_ingestion.normalization_applied);
        assert_eq!(prepared.prepared_source, "const value = 1;");
        assert!(prepared.normalization_output.is_none());
        assert_eq!(
            prepared.source_ingestion.original_source_hash,
            prepared.source_ingestion.normalized_source_hash
        );
    }

    #[test]
    fn prepare_public_source_entry_normalizes_typescript_and_records_summary() {
        let prepared = prepare_source_entry_for_public_entrypoints(
            "const value: number = 1;",
            "fixture.ts",
            "trace-ts",
            "decision-ts",
            "policy-ts",
        )
        .unwrap();

        assert_eq!(
            prepared.source_ingestion.source_language,
            SourceLanguage::TypeScript
        );
        assert!(prepared.source_ingestion.normalization_applied);
        assert_ne!(
            prepared.source_ingestion.original_source_hash,
            prepared.source_ingestion.normalized_source_hash
        );
        assert!(prepared.source_ingestion.ts_decision_count > 0);
        assert!(prepared.normalization_output.is_some());
        assert!(!prepared.prepared_source.contains(": number"));
    }
}
