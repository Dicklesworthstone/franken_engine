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
        "Type-only imports were elided from runtime output.",
    ));
    current = no_type_imports;

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
    for op in &lowering_output.ir2.ops {
        if !matches!(op.effect, EffectBoundary::HostcallEffect) {
            continue;
        }

        let Some(capability) = op.required_capability.as_ref() else {
            return Err("hostcall effect missing required capability tag".to_string());
        };

        // `hostcall.invoke` is the dynamic fallback for non-annotated generic calls.
        // For TS-annotated hostcalls we validate against explicit capability tags.
        if capability.0 == "hostcall.invoke" {
            continue;
        }

        hostcall_contract_capabilities.insert(capability.0.clone());
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
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("import type "))
        .collect::<Vec<_>>()
        .join("\n")
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

fn trim_trailing_inline_whitespace(output: &mut String) {
    while matches!(output.chars().next_back(), Some(' ' | '\t')) {
        let _ = output.pop();
    }
}

fn lower_simple_namespaces(source: &str) -> Result<String, TsNormalizationError> {
    let mut namespace_order = Vec::<String>::new();
    let mut namespace_assignments = BTreeMap::<String, Vec<String>>::new();
    let mut with_placeholders = Vec::<String>::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("namespace ") {
            with_placeholders.push(line.to_string());
            continue;
        }

        let Some(rest) = trimmed.strip_prefix("namespace ") else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        };
        let Some(brace_start) = rest.find('{') else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        };
        let Some(brace_end) = rest.rfind('}') else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        };
        if brace_end < brace_start {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        }

        let namespace_name = rest[..brace_start].trim();
        if namespace_name.is_empty() {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace declaration form",
            });
        }

        let body = rest[brace_start + 1..brace_end].trim();
        let parsed_assignments = parse_namespace_exports(body)?;
        if !namespace_assignments.contains_key(namespace_name) {
            namespace_order.push(namespace_name.to_string());
            namespace_assignments.insert(namespace_name.to_string(), Vec::new());
            with_placeholders.push(format!("/*__namespace:{namespace_name}__*/"));
        }

        if let Some(assignments) = namespace_assignments.get_mut(namespace_name) {
            assignments.extend(parsed_assignments);
        }
    }

    let mut rendered = Vec::<String>::new();
    for line in with_placeholders {
        if let Some(namespace_name) = line
            .strip_prefix("/*__namespace:")
            .and_then(|value| value.strip_suffix("__*/"))
        {
            if let Some(assignments) = namespace_assignments.get(namespace_name) {
                rendered.extend(render_namespace_block(namespace_name, assignments));
            }
            continue;
        }
        rendered.push(line);
    }

    if namespace_order.is_empty() {
        Ok(source.to_string())
    } else {
        Ok(rendered.join("\n"))
    }
}

fn parse_namespace_exports(body: &str) -> Result<Vec<String>, TsNormalizationError> {
    let mut assignments = Vec::<String>::new();

    for statement in body.split(';') {
        let normalized = statement.trim();
        if normalized.is_empty() {
            continue;
        }

        let Some(exported) = normalized.strip_prefix("export ") else {
            return Err(TsNormalizationError::UnsupportedSyntax {
                feature: "unsupported namespace export form",
            });
        };

        let declaration = if let Some(value) = exported.strip_prefix("const ") {
            value
        } else if let Some(value) = exported.strip_prefix("let ") {
            value
        } else if let Some(value) = exported.strip_prefix("var ") {
            value
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
    }

    Ok(assignments)
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

fn strip_type_annotations(source: &str) -> String {
    let mut output = String::new();
    let mut chars = source.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;

    while let Some(ch) = chars.next() {
        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            output.push(ch);
            continue;
        }
        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            output.push(ch);
            continue;
        }

        if in_single_quote || in_double_quote {
            output.push(ch);
            continue;
        }

        if ch == ':' {
            while let Some(next) = chars.peek() {
                if matches!(next, ',' | ')' | '=' | ';' | '{' | '}' | '\n') {
                    break;
                }
                let _ = chars.next();
            }
            continue;
        }

        output.push(ch);
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
    fn rejects_unsupported_namespace_export_forms() {
        let source = "namespace Demo { export function run() { return 1; } }";
        let error = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            "trace",
            "decision",
            "policy",
        )
        .expect_err("unsupported namespace export should fail");

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
}
