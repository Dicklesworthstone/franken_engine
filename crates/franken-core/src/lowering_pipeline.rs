#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ast::{
    ArrowBody, AssignmentOperator, BinaryOperator, BindingPattern, ExportKind, Expression,
    FunctionParam, ImportClause, MethodDefinition, MethodKind, ParseGoal, SourceSpan, Statement,
    UnaryOperator, UpdateOperator, VariableDeclarationKind,
};
use crate::flow_lattice::{
    Clearance, DeclassificationObligation, FlowCheckResult as LatticeFlowCheckResult,
    Ir2FlowLattice, LabelClass,
};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::{Label, ProofMethod};
use crate::ir_contract::{
    BindingId, BindingKind, CapabilityTag, EffectBoundary, FlowAnnotation, IR_ACCESSOR_GET_PREFIX,
    IR_ACCESSOR_SET_PREFIX, IR_SUPER_CONSTRUCTOR_PROPERTY, IR_SUPER_PROTOTYPE_PROPERTY, Ir0Module,
    Ir1Literal, Ir1Module, Ir1Op, Ir1PropertyKey, Ir2Module, Ir2Op, Ir3FunctionDesc,
    Ir3Instruction, Ir3Module, IrError, IrLevel, IteratorCloseReason, Reg, RegRange,
    ResolvedBinding, ScopeId, ScopeKind, ScopeNode, verify_ir1_source, verify_ir3_specialization,
};
use crate::parser::{
    PARSER_DIAGNOSTIC_HASH_ALGORITHM, PARSER_DIAGNOSTIC_HASH_PREFIX,
    PARSER_DIAGNOSTIC_TAXONOMY_VERSION, ParseDiagnosticCategory, ParseDiagnosticSeverity,
    ParseErrorCode, SemanticError, SemanticErrorCode, SemanticValidationResult,
};
use crate::parser_gap_inventory::{
    ParserGapSiteId, ParserGapStage, UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION,
    UnsupportedSyntaxDiagnostic,
};

const COMPONENT: &str = "lowering_pipeline";
const IFC_RUNTIME_GUARD_CAPABILITY: &str = "ifc.check_flow";
const IFC_FLOW_PROOF_ERROR_CODE: &str = "FE-LOWER-IFC-0001";
const IFC_FLOW_PROOF_SCHEMA_VERSION: &str = "frankenengine.ir2_flow_proof_witness.v1";
pub(crate) const CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX: &str =
    "\0class-expression-constructor-self\0";
const CLASS_EXPRESSION_METHOD_SELF_CAPTURE_PREFIX: &str = "\0class-expression-method-self\0";

fn class_expression_constructor_self_capture_name(name: &str, origin_id: BindingId) -> String {
    format!("{CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX}{origin_id}\0{name}")
}

fn class_expression_method_self_capture_name(name: &str, origin_id: BindingId) -> String {
    format!("{CLASS_EXPRESSION_METHOD_SELF_CAPTURE_PREFIX}{origin_id}\0{name}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl LoweringContext {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassWitness {
    pub pass_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub rollback_token: String,
    pub invariant_checks: Vec<InvariantCheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsomorphismLedgerEntry {
    pub pass_id: String,
    pub input_hash: String,
    pub output_hash: String,
    pub input_op_count: u64,
    pub output_op_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringPassResult<T> {
    pub module: T,
    pub witness: PassWitness,
    pub ledger_entry: IsomorphismLedgerEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoweringPipelineOutput {
    pub ir1: Ir1Module,
    pub ir2: Ir2Module,
    pub ir3: Ir3Module,
    pub ir2_flow_proof_artifact: Ir2FlowProofArtifact,
    pub witnesses: Vec<PassWitness>,
    pub isomorphism_ledger: Vec<IsomorphismLedgerEntry>,
    pub events: Vec<LoweringEvent>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct FlowInferenceMetrics {
    total_flow_ops: u64,
    static_proven_ops: u64,
    runtime_check_ops: u64,
}

impl FlowInferenceMetrics {
    fn include(&mut self, other: Self) {
        self.total_flow_ops = self.total_flow_ops.saturating_add(other.total_flow_ops);
        self.static_proven_ops = self
            .static_proven_ops
            .saturating_add(other.static_proven_ops);
        self.runtime_check_ops = self
            .runtime_check_ops
            .saturating_add(other.runtime_check_ops);
    }

    fn static_coverage_millionths(self) -> u64 {
        if self.total_flow_ops == 0 {
            return 0;
        }
        (self.static_proven_ops.saturating_mul(1_000_000)) / self.total_flow_ops
    }
}

/// One effect-classified operation nested inside a function body. `op_index`
/// remains the enclosing top-level IR2 operation index so existing authority
/// consumers can resolve it to the function declaration/expression site;
/// `body_path` supplies a deterministic internal identity for repeated nested
/// flows without changing the v1 artifact schema.
#[derive(Debug, Clone)]
struct NestedIr2AnalysisSite {
    op_index: usize,
    body_path: Vec<usize>,
    op: Ir2Op,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ir2FlowProofArtifact {
    pub schema_version: String,
    pub artifact_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub module_id: String,
    pub proved_flows: Vec<FlowProofArtifactEntry>,
    pub denied_flows: Vec<DeniedFlowArtifactEntry>,
    pub required_declassifications: Vec<RequiredDeclassificationArtifactEntry>,
    pub runtime_checkpoints: Vec<RuntimeCheckpointArtifactEntry>,
}

impl Ir2FlowProofArtifact {
    fn finalize(mut self) -> Self {
        self.proved_flows.sort();
        self.denied_flows.sort();
        self.required_declassifications.sort();
        self.runtime_checkpoints.sort();
        self.artifact_id = compute_ir2_flow_artifact_id(&self);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowProofArtifactEntry {
    pub op_index: u64,
    /// Deterministic path within the enclosing function operation. Empty for
    /// top-level operations and legacy v1 artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_path: Vec<u64>,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub capability: Option<String>,
    pub proof_method: ProofMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeniedFlowArtifactEntry {
    pub op_index: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_path: Vec<u64>,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub capability: Option<String>,
    pub reason: String,
    pub error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequiredDeclassificationArtifactEntry {
    pub op_index: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_path: Vec<u64>,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub capability: Option<String>,
    pub obligation_id: String,
    #[serde(default)]
    pub decision_contract_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declassification_route_ref: Option<String>,
    #[serde(default)]
    pub requires_operator_approval: bool,
    #[serde(default)]
    pub receipt_linkage_required: bool,
    #[serde(default)]
    pub replay_command_hint: String,
}

// Lowering can point operators at the shipped replay surface, but it does not
// know a concrete trace artifact path and there is no shipped `--obligation`
// selector on `frankenctl replay run`.
const REQUIRED_DECLASSIFICATION_REPLAY_COMMAND_HINT: &str =
    "frankenctl replay run --trace <trace.json> --mode strict";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeCheckpointArtifactEntry {
    pub op_index: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub body_path: Vec<u64>,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub capability: Option<String>,
    pub reason: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LoweringPipelineError {
    #[error("IR0 module has no statements")]
    EmptyIr0Body,
    #[error("IR contract validation failed ({code}) at {level}: {message}")]
    IrContractValidation {
        code: String,
        level: IrLevel,
        message: String,
    },
    #[error("deterministic invariant failed: {detail}")]
    InvariantViolation { detail: &'static str },
    #[error("flow lattice evaluation failed: {detail}")]
    FlowLatticeFailure { detail: String },
    #[error(
        "unauthorized flow detected at op {op_index}: {source_label:?} -> {sink_clearance:?} ({detail})"
    )]
    UnauthorizedFlow {
        op_index: usize,
        source_label: Label,
        sink_clearance: Label,
        detail: String,
    },
    #[error("static semantics violation: {0}")]
    SemanticViolation(SemanticError),
    #[error("unsupported syntax rejected by fail-closed contract: {0}")]
    UnsupportedSyntax(Box<UnsupportedSyntaxDiagnostic>),
    #[error("Value stack underflow during lowering")]
    #[allow(dead_code)]
    ValueStackUnderflow,
}

#[allow(dead_code)]
fn unsupported_syntax_error(
    site: ParserGapSiteId,
    span: Option<SourceSpan>,
) -> LoweringPipelineError {
    LoweringPipelineError::UnsupportedSyntax(Box::new(UnsupportedSyntaxDiagnostic::from_site(
        site, "ir0", span,
    )))
}

fn unsupported_frontier_expression_error(
    feature_family: &str,
    diagnostic_code: &str,
    site_id: &str,
    message_template: &str,
    span: Option<SourceSpan>,
) -> LoweringPipelineError {
    LoweringPipelineError::UnsupportedSyntax(Box::new(UnsupportedSyntaxDiagnostic {
        schema_version: UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.to_string(),
        taxonomy_version: PARSER_DIAGNOSTIC_TAXONOMY_VERSION.to_string(),
        hash_algorithm: PARSER_DIAGNOSTIC_HASH_ALGORITHM.to_string(),
        hash_prefix: PARSER_DIAGNOSTIC_HASH_PREFIX.to_string(),
        parse_error_code: ParseErrorCode::UnsupportedSyntax,
        diagnostic_code: diagnostic_code.to_string(),
        category: ParseDiagnosticCategory::Syntax,
        severity: ParseDiagnosticSeverity::Error,
        message_template: message_template.to_string(),
        source_label: "ir0".to_string(),
        span,
        site_id: site_id.to_string(),
        stage: ParserGapStage::Ir0ToIr1,
        owner: COMPONENT.to_string(),
        feature_family: feature_family.to_string(),
        api_surface: "lower_ir0_to_ir1".to_string(),
    }))
}

pub fn lower_ir0_to_ir3(
    ir0: &Ir0Module,
    context: &LoweringContext,
) -> Result<LoweringPipelineOutput, LoweringPipelineError> {
    let mut events = Vec::<LoweringEvent>::new();

    let ir1_result = match lower_ir0_to_ir1(ir0) {
        Ok(result) => {
            events.push(success_event(context, "ir0_to_ir1_lowered"));
            result
        }
        Err(error) => {
            events.push(failure_event(
                context,
                "ir0_to_ir1_lowered",
                "FE-LOWER-0001",
            ));
            return Err(error);
        }
    };

    let ir2_result = match lower_ir1_to_ir2(&ir1_result.module) {
        Ok(result) => {
            events.push(success_event(context, "ir1_to_ir2_lowered"));
            result
        }
        Err(error) => {
            events.push(failure_event(
                context,
                "ir1_to_ir2_lowered",
                "FE-LOWER-0002",
            ));
            return Err(error);
        }
    };

    let ir2_flow_proof_artifact = match build_ir2_flow_proof_artifact(&ir2_result.module, context) {
        Ok(artifact) => {
            events.push(success_event(context, "ir2_flow_check_completed"));
            artifact
        }
        Err(error) => {
            events.push(failure_event(
                context,
                "ir2_flow_check_completed",
                IFC_FLOW_PROOF_ERROR_CODE,
            ));
            return Err(error);
        }
    };

    let ir3_result = match lower_ir2_to_ir3(&ir2_result.module) {
        Ok(result) => {
            events.push(success_event(context, "ir2_to_ir3_lowered"));
            result
        }
        Err(error) => {
            events.push(failure_event(
                context,
                "ir2_to_ir3_lowered",
                "FE-LOWER-0003",
            ));
            return Err(error);
        }
    };

    Ok(LoweringPipelineOutput {
        ir1: ir1_result.module,
        ir2: ir2_result.module,
        ir3: ir3_result.module,
        ir2_flow_proof_artifact,
        witnesses: vec![ir1_result.witness, ir2_result.witness, ir3_result.witness],
        isomorphism_ledger: vec![
            ir1_result.ledger_entry,
            ir2_result.ledger_entry,
            ir3_result.ledger_entry,
        ],
        events,
    })
}

/// Validate static semantics of an IR0 module without performing full lowering.
///
/// This catches early errors specified by ES2020:
/// - Duplicate `let`/`const` declarations in the same scope
/// - `var`/lexical binding conflicts
/// - `const` declarations without initializers
/// - Duplicate `import` bindings in module scope
///
/// Returns a `SemanticValidationResult` containing all detected errors.
pub fn validate_ir0_static_semantics(ir0: &Ir0Module) -> SemanticValidationResult {
    let mut result = SemanticValidationResult::new();

    let mut seen_bindings = BTreeMap::<String, BindingKind>::new();
    let mut default_export_count = 0u32;

    for statement in &ir0.tree.body {
        match statement {
            Statement::Import(import) => {
                for binding_name in import.clause.binding_names() {
                    if let Some(existing_kind) = seen_bindings.get(binding_name) {
                        let conflict = check_binding_conflict(*existing_kind, BindingKind::Import);
                        if let BindingConflict::Error(code) = conflict {
                            result.add_error(SemanticError::new(
                                code,
                                Some(binding_name.to_string()),
                                Some(import.span.clone()),
                            ));
                        }
                    }
                    seen_bindings.insert(binding_name.to_string(), BindingKind::Import);
                }
            }
            Statement::Export(export) => {
                if matches!(export.kind, ExportKind::Default(_)) {
                    default_export_count += 1;
                    if default_export_count > 1 {
                        result.add_error(SemanticError::new(
                            SemanticErrorCode::DuplicateDefaultExport,
                            None,
                            Some(export.span.clone()),
                        ));
                    }
                }
            }
            Statement::VariableDeclaration(variable_declaration) => {
                let binding_kind = binding_kind_for_variable_declaration(variable_declaration.kind);

                for declarator in &variable_declaration.declarations {
                    // Check const without initializer.
                    if variable_declaration.kind == VariableDeclarationKind::Const
                        && declarator.initializer.is_none()
                    {
                        let primary_name = declarator
                            .pattern
                            .binding_names()
                            .first()
                            .map(|s| (*s).to_string());
                        result.add_error(SemanticError::new(
                            SemanticErrorCode::ConstWithoutInitializer,
                            primary_name,
                            Some(declarator.span.clone()),
                        ));
                    }

                    // Check binding conflicts for all bound names.
                    for bound_name in declarator.pattern.binding_names() {
                        if let Some(existing_kind) = seen_bindings.get(bound_name) {
                            let conflict = check_binding_conflict(*existing_kind, binding_kind);
                            if let BindingConflict::Error(code) = conflict {
                                result.add_error(SemanticError::new(
                                    code,
                                    Some(bound_name.to_string()),
                                    Some(declarator.span.clone()),
                                ));
                            }
                        }
                        seen_bindings.insert(bound_name.to_string(), binding_kind);
                    }
                }
            }
            Statement::Expression(_) => {
                // Expression statements have no early errors at this level.
            }
            Statement::Block(_)
            | Statement::If(_)
            | Statement::For(_)
            | Statement::ForIn(_)
            | Statement::ForOf(_)
            | Statement::While(_)
            | Statement::DoWhile(_)
            | Statement::Return(_)
            | Statement::Throw(_)
            | Statement::TryCatch(_)
            | Statement::Switch(_)
            | Statement::Break(_)
            | Statement::Continue(_)
            | Statement::FunctionDeclaration(_)
            | Statement::ClassDeclaration(_) => {
                // Control flow, function and class declarations: static
                // semantic analysis for these is handled recursively as needed.
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Node `path` builtin recognition (bd-tu0c3) — core mirror of the
// franken-engine lowering interception. `require('path')` bindings that are
// actually USED as a recognized pure-compute `path` builtin (a member call
// like `path.join(...)` / `path.posix.join(...)` / `path.win32.join(...)` or a
// property read like `path.sep`) are recorded as NUL-sentinel aliases; the
// recognized declaration is elided, member calls lower to `builtin:Path*`
// hostcalls and constant property reads lower to string literals. A
// bare/unused `const path = require('path')` keeps core's existing behavior
// (a `module:require` hostcall). Keep in lockstep with
// `franken-engine/src/lowering_pipeline.rs`.
// ---------------------------------------------------------------------------

/// bd-tu0c3: true when `specifier` names the Node path module — `path` or
/// `node:path`.
fn is_path_module_specifier(specifier: &str) -> bool {
    specifier == "path" || specifier == "node:path"
}

/// bd-tu0c3: sentinel key recording that `name` is bound to the path module
/// via `const <name> = require('path')` AND used as a recognized `path`
/// builtin. Stored in the lowering `binding_lookup`; the leading NUL cannot
/// occur in a JS identifier so the sentinel never collides with or shadows a
/// real binding.
fn path_module_alias_sentinel(name: &str) -> String {
    format!("\0pathmod\0{name}")
}

/// bd-tu0c3: true when `expr` is exactly `require('path')` /
/// `require('node:path')` with an unshadowed `require` — the initializer shape
/// that aliases the path module in `const path = require('path')`.
fn is_require_path_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call { callee, arguments } = expr else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if name == "require" && !binding_lookup.contains_key(name.as_str()))
    {
        return false;
    }
    matches!(
        arguments.as_slice(),
        [Expression::StringLiteral(spec)] if is_path_module_specifier(spec)
    )
}

/// Which Node `path` namespace a recognized receiver selects (bd-tu0c3). The
/// default `path` object on linux IS the posix implementation, so both the
/// bare module receiver and `.posix` map to [`PathModuleNamespace::Posix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathModuleNamespace {
    Posix,
    Win32,
}

/// bd-tu0c3: capability tag for a recognized `path` method in `namespace`.
/// Single source of truth shared by the usage-lookahead scan and the call-site
/// recognizer. The win32 surface is deliberately the small separator-sensitive
/// subset (join/basename/isAbsolute).
fn path_method_capability(namespace: PathModuleNamespace, method: &str) -> Option<&'static str> {
    match namespace {
        PathModuleNamespace::Posix => match method {
            "join" => Some("builtin:PathJoin"),
            "basename" => Some("builtin:PathBasename"),
            "dirname" => Some("builtin:PathDirname"),
            "extname" => Some("builtin:PathExtname"),
            "normalize" => Some("builtin:PathNormalize"),
            "resolve" => Some("builtin:PathResolve"),
            "relative" => Some("builtin:PathRelative"),
            "isAbsolute" => Some("builtin:PathIsAbsolute"),
            "parse" => Some("builtin:PathParse"),
            "format" => Some("builtin:PathFormat"),
            _ => None,
        },
        PathModuleNamespace::Win32 => match method {
            "join" => Some("builtin:PathWin32Join"),
            "basename" => Some("builtin:PathWin32Basename"),
            "isAbsolute" => Some("builtin:PathWin32IsAbsolute"),
            _ => None,
        },
    }
}

/// bd-tu0c3: the constant value of a recognized `path` namespace property read
/// (`sep` / `delimiter`), per Node.
fn path_namespace_property_constant(
    namespace: PathModuleNamespace,
    property: &str,
) -> Option<&'static str> {
    match (namespace, property) {
        (PathModuleNamespace::Posix, "sep") => Some("/"),
        (PathModuleNamespace::Posix, "delimiter") => Some(":"),
        (PathModuleNamespace::Win32, "sep") => Some("\\"),
        (PathModuleNamespace::Win32, "delimiter") => Some(";"),
        _ => None,
    }
}

/// bd-tu0c3: resolve a member-expression receiver to a path-module namespace,
/// parameterized over the module-object predicate so the pre-scan (candidate
/// alias names) and the lowering (recorded sentinels) share one shape:
///   * `<module>`         -> Posix (linux default `path` IS posix)
///   * `<module>.posix`   -> Posix
///   * `<module>.win32`   -> Win32
fn path_receiver_namespace_with<F: Fn(&Expression) -> bool>(
    object: &Expression,
    is_module_object: &F,
) -> Option<PathModuleNamespace> {
    if is_module_object(object) {
        return Some(PathModuleNamespace::Posix);
    }
    if let Expression::Member {
        object: inner,
        property,
        computed: false,
    } = object
        && is_module_object(inner)
        && let Expression::Identifier(ns) | Expression::StringLiteral(ns) = property.as_ref()
    {
        return match ns.as_str() {
            "posix" => Some(PathModuleNamespace::Posix),
            "win32" => Some(PathModuleNamespace::Win32),
            _ => None,
        };
    }
    None
}

/// bd-tu0c3: true when `expr` IS the path module object at lowering time — a
/// sentinel-recorded require-binding alias or the inline `require('path')`
/// call.
fn is_path_module_object(expr: &Expression, binding_lookup: &BTreeMap<String, BindingId>) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&path_module_alias_sentinel(alias))
        }
        Expression::Call { callee, arguments } => {
            matches!(callee.as_ref(), Expression::Identifier(name)
                if name == "require" && !binding_lookup.contains_key(name.as_str()))
                && matches!(
                    arguments.as_slice(),
                    [Expression::StringLiteral(spec)] if is_path_module_specifier(spec)
                )
        }
        _ => false,
    }
}

/// bd-tu0c3: recognize a `path` builtin member call and return its
/// `builtin:Path*` capability. Purely syntactic — there is no real path module
/// heap object.
fn path_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = callee
    else {
        return None;
    };
    let namespace =
        path_receiver_namespace_with(object, &|expr| is_path_module_object(expr, binding_lookup))?;
    let method = match property.as_ref() {
        Expression::Identifier(name) | Expression::StringLiteral(name) => name.as_str(),
        _ => return None,
    };
    path_method_capability(namespace, method)
}

/// bd-tu0c3: recognize a `path` constant property READ (`path.sep`,
/// `path.posix.delimiter`, `path.win32.sep`, …) and return the string constant
/// it lowers to.
fn path_member_constant(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let namespace =
        path_receiver_namespace_with(object, &|expr| is_path_module_object(expr, binding_lookup))?;
    let prop = match (computed, property) {
        (false, Expression::Identifier(name) | Expression::StringLiteral(name)) => name.as_str(),
        (true, Expression::StringLiteral(name)) => name.as_str(),
        _ => return None,
    };
    path_namespace_property_constant(namespace, prop)
}

/// bd-tu0c3: scan-time twin of [`path_builtin_call_capability`]'s receiver
/// check — during the pre-scan the sentinels are not recorded yet, so the
/// module-object predicate is membership in the candidate alias-name set.
fn is_path_alias_method_callee(callee: &Expression, alias_names: &BTreeSet<String>) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = callee
    else {
        return false;
    };
    let Some(namespace) = path_receiver_namespace_with(
        object,
        &|expr| matches!(expr, Expression::Identifier(name) if alias_names.contains(name)),
    ) else {
        return false;
    };
    matches!(property.as_ref(),
        Expression::Identifier(m) | Expression::StringLiteral(m)
            if path_method_capability(namespace, m).is_some())
}

/// bd-tu0c3: scan-time twin of [`path_member_constant`]: true when `expr` is a
/// recognized constant property read on one of the candidate alias names.
fn is_path_alias_property_read(expr: &Expression, alias_names: &BTreeSet<String>) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = expr
    else {
        return false;
    };
    let Some(namespace) = path_receiver_namespace_with(
        object,
        &|inner| matches!(inner, Expression::Identifier(name) if alias_names.contains(name)),
    ) else {
        return false;
    };
    matches!(property.as_ref(),
        Expression::Identifier(p) | Expression::StringLiteral(p)
            if path_namespace_property_constant(namespace, p).is_some())
}

/// bd-tu0c3: recursively scan `expr` for a call whose callee satisfies
/// `is_target`. Function/arrow/class bodies and object literals are opaque
/// (fail-closed): a usage buried inside one is conservatively NOT detected, so
/// the corresponding alias keeps its existing behavior.
fn expr_contains_matching_call<F: Fn(&Expression) -> bool>(
    expr: &Expression,
    is_target: &F,
) -> bool {
    match expr {
        Expression::Call { callee, arguments } | Expression::OptionalCall { callee, arguments } => {
            is_target(callee)
                || expr_contains_matching_call(callee, is_target)
                || arguments
                    .iter()
                    .any(|a| expr_contains_matching_call(a, is_target))
        }
        Expression::New { callee, arguments } => {
            expr_contains_matching_call(callee, is_target)
                || arguments
                    .iter()
                    .any(|a| expr_contains_matching_call(a, is_target))
        }
        Expression::Member {
            object, property, ..
        }
        | Expression::OptionalMember {
            object, property, ..
        } => {
            expr_contains_matching_call(object, is_target)
                || expr_contains_matching_call(property, is_target)
        }
        Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
            expr_contains_matching_call(left, is_target)
                || expr_contains_matching_call(right, is_target)
        }
        Expression::Unary { argument, .. }
        | Expression::Update { argument, .. }
        | Expression::Await(argument)
        | Expression::SpreadElement(argument) => expr_contains_matching_call(argument, is_target),
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            expr_contains_matching_call(test, is_target)
                || expr_contains_matching_call(consequent, is_target)
                || expr_contains_matching_call(alternate, is_target)
        }
        Expression::Yield {
            argument: Some(argument),
            ..
        } => expr_contains_matching_call(argument, is_target),
        Expression::ArrayLiteral(elements) => elements
            .iter()
            .flatten()
            .any(|e| expr_contains_matching_call(e, is_target)),
        Expression::TemplateLiteral { expressions, .. } => expressions
            .iter()
            .any(|e| expr_contains_matching_call(e, is_target)),
        _ => false,
    }
}

/// bd-tu0c3: recursively scan `expr` for a member READ satisfying `is_target`
/// — the property-read sibling of [`expr_contains_matching_call`], same
/// traversal, same fail-closed opacity.
fn expr_contains_matching_member<F: Fn(&Expression) -> bool>(
    expr: &Expression,
    is_target: &F,
) -> bool {
    match expr {
        Expression::Member {
            object, property, ..
        }
        | Expression::OptionalMember {
            object, property, ..
        } => {
            is_target(expr)
                || expr_contains_matching_member(object, is_target)
                || expr_contains_matching_member(property, is_target)
        }
        Expression::Call { callee, arguments } | Expression::OptionalCall { callee, arguments } => {
            expr_contains_matching_member(callee, is_target)
                || arguments
                    .iter()
                    .any(|a| expr_contains_matching_member(a, is_target))
        }
        Expression::New { callee, arguments } => {
            expr_contains_matching_member(callee, is_target)
                || arguments
                    .iter()
                    .any(|a| expr_contains_matching_member(a, is_target))
        }
        Expression::Binary { left, right, .. } | Expression::Assignment { left, right, .. } => {
            expr_contains_matching_member(left, is_target)
                || expr_contains_matching_member(right, is_target)
        }
        Expression::Unary { argument, .. }
        | Expression::Update { argument, .. }
        | Expression::Await(argument)
        | Expression::SpreadElement(argument) => expr_contains_matching_member(argument, is_target),
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            expr_contains_matching_member(test, is_target)
                || expr_contains_matching_member(consequent, is_target)
                || expr_contains_matching_member(alternate, is_target)
        }
        Expression::Yield {
            argument: Some(argument),
            ..
        } => expr_contains_matching_member(argument, is_target),
        Expression::ArrayLiteral(elements) => elements
            .iter()
            .flatten()
            .any(|e| expr_contains_matching_member(e, is_target)),
        Expression::TemplateLiteral { expressions, .. } => expressions
            .iter()
            .any(|e| expr_contains_matching_member(e, is_target)),
        _ => false,
    }
}

/// bd-tu0c3: true when `expr` contains a recognized path usage on one of
/// `alias_names` — either a recognized method CALL (`<alias>.join(...)`) or a
/// recognized constant property READ (`<alias>.sep`).
fn expr_contains_path_alias_usage(expr: &Expression, alias_names: &BTreeSet<String>) -> bool {
    expr_contains_matching_call(expr, &|callee| {
        is_path_alias_method_callee(callee, alias_names)
    }) || expr_contains_matching_member(expr, &|member| {
        is_path_alias_property_read(member, alias_names)
    })
}

/// bd-tu0c3: statement-level usage scan for the path alias gate. Recurses
/// through control-flow statements (blocks, if/else, loops, switch,
/// try/catch/finally, return/throw); function and class bodies remain opaque —
/// a usage only inside one is conservatively not detected (fail-closed).
fn path_statement_contains_usage<F: Fn(&Expression) -> bool>(stmt: &Statement, uses: &F) -> bool {
    match stmt {
        Statement::Expression(es) => uses(&es.expression),
        Statement::VariableDeclaration(vd) => vd
            .declarations
            .iter()
            .any(|d| d.initializer.as_ref().is_some_and(uses)),
        Statement::Block(block) => block
            .body
            .iter()
            .any(|inner| path_statement_contains_usage(inner, uses)),
        Statement::If(if_stmt) => {
            uses(&if_stmt.condition)
                || path_statement_contains_usage(&if_stmt.consequent, uses)
                || if_stmt
                    .alternate
                    .as_deref()
                    .is_some_and(|alt| path_statement_contains_usage(alt, uses))
        }
        Statement::For(for_stmt) => {
            for_stmt
                .init
                .as_deref()
                .is_some_and(|init| path_statement_contains_usage(init, uses))
                || for_stmt.condition.as_ref().is_some_and(uses)
                || for_stmt.update.as_ref().is_some_and(uses)
                || path_statement_contains_usage(&for_stmt.body, uses)
        }
        Statement::ForIn(for_in) => {
            uses(&for_in.object) || path_statement_contains_usage(&for_in.body, uses)
        }
        Statement::ForOf(for_of) => {
            uses(&for_of.iterable) || path_statement_contains_usage(&for_of.body, uses)
        }
        Statement::While(while_stmt) => {
            uses(&while_stmt.condition) || path_statement_contains_usage(&while_stmt.body, uses)
        }
        Statement::DoWhile(do_while) => {
            uses(&do_while.condition) || path_statement_contains_usage(&do_while.body, uses)
        }
        Statement::Return(ret) => ret.argument.as_ref().is_some_and(uses),
        Statement::Throw(throw_stmt) => uses(&throw_stmt.argument),
        Statement::TryCatch(try_stmt) => {
            try_stmt
                .block
                .body
                .iter()
                .any(|inner| path_statement_contains_usage(inner, uses))
                || try_stmt.handler.as_ref().is_some_and(|handler| {
                    handler
                        .body
                        .body
                        .iter()
                        .any(|inner| path_statement_contains_usage(inner, uses))
                })
                || try_stmt.finalizer.as_ref().is_some_and(|finalizer| {
                    finalizer
                        .body
                        .iter()
                        .any(|inner| path_statement_contains_usage(inner, uses))
                })
        }
        Statement::Switch(switch_stmt) => {
            uses(&switch_stmt.discriminant)
                || switch_stmt.cases.iter().any(|case| {
                    case.test.as_ref().is_some_and(uses)
                        || case
                            .consequent
                            .iter()
                            .any(|inner| path_statement_contains_usage(inner, uses))
                })
        }
        // Function/class declarations stay opaque (fail-closed); imports,
        // exports, break and continue carry no scannable expression.
        _ => false,
    }
}

/// bd-tu0c3: compute the set of identifier names that are BOTH bound via
/// `const/let/var <name> = require('path')` / `require('node:path')` at the
/// unit root AND used as a recognized `path` builtin (method call or constant
/// property read) somewhere reachable by the fail-closed statement scan.
fn confirmed_path_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_path_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            path_statement_contains_usage(stmt, &|e| expr_contains_path_alias_usage(e, &single))
        }) {
            used.insert(name.clone());
        }
    }
    used
}

// ---------------------------------------------------------------------------
// Node `querystring` + `os` builtin recognition (bd-qmy52) — core mirror of
// the franken-engine lowering interception. Two further pure-compute module
// families following the `path` template (bd-tu0c3): usage-confirmed
// `require('querystring')` / `require('os')` aliases are recorded as
// NUL-sentinels and elided; member calls lower to `builtin:Querystring*` /
// `builtin:Os*` hostcalls, `os.EOL`/`os.devNull` property reads lower to
// string literals, and `os.constants` lowers to a 0-arg `builtin:OsConstants`
// HostCall. Bare/unused aliases keep core's existing `module:require`
// behavior. Keep in lockstep with `franken-engine/src/lowering_pipeline.rs`.
// ---------------------------------------------------------------------------

/// bd-qmy52: true when `specifier` names the Node querystring module —
/// `querystring` or `node:querystring`.
fn is_querystring_module_specifier(specifier: &str) -> bool {
    specifier == "querystring" || specifier == "node:querystring"
}

/// bd-qmy52: sentinel key recording that `name` is bound to the querystring
/// module via `const <name> = require('querystring')` AND used as a
/// recognized querystring builtin. Mirror of [`path_module_alias_sentinel`].
fn querystring_module_alias_sentinel(name: &str) -> String {
    format!("\0qsmod\0{name}")
}

/// bd-qmy52: true when `expr` is exactly `require('querystring')` /
/// `require('node:querystring')` with an unshadowed `require`.
fn is_require_querystring_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call { callee, arguments } = expr else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if name == "require" && !binding_lookup.contains_key(name.as_str()))
    {
        return false;
    }
    matches!(
        arguments.as_slice(),
        [Expression::StringLiteral(spec)] if is_querystring_module_specifier(spec)
    )
}

/// bd-qmy52: capability tag for a recognized `querystring` method. Single
/// source of truth shared by the usage-lookahead scan and the call-site
/// recognizer. `decode`/`encode` are Node's documented aliases of
/// `parse`/`stringify`.
fn querystring_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "parse" | "decode" => Some("builtin:QuerystringParse"),
        "stringify" | "encode" => Some("builtin:QuerystringStringify"),
        "escape" => Some("builtin:QuerystringEscape"),
        "unescape" => Some("builtin:QuerystringUnescape"),
        _ => None,
    }
}

/// bd-qmy52: true when `expr` IS the querystring module object at lowering
/// time — a sentinel-recorded require-binding alias or the inline
/// `require('querystring')` call.
fn is_querystring_module_object(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&querystring_module_alias_sentinel(alias))
        }
        Expression::Call { callee, arguments } => {
            matches!(callee.as_ref(), Expression::Identifier(name)
                if name == "require" && !binding_lookup.contains_key(name.as_str()))
                && matches!(
                    arguments.as_slice(),
                    [Expression::StringLiteral(spec)] if is_querystring_module_specifier(spec)
                )
        }
        _ => false,
    }
}

/// bd-qmy52: recognize a `querystring` builtin member call and return its
/// `builtin:Querystring*` capability. Purely syntactic; no sub-namespaces.
fn querystring_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = callee
    else {
        return None;
    };
    if !is_querystring_module_object(object, binding_lookup) {
        return None;
    }
    let method = match property.as_ref() {
        Expression::Identifier(name) | Expression::StringLiteral(name) => name.as_str(),
        _ => return None,
    };
    querystring_method_capability(method)
}

/// bd-qmy52: scan-time twin of [`querystring_builtin_call_capability`]'s
/// receiver check — during the pre-scan the sentinels are not recorded yet, so
/// the module-object predicate is membership in the candidate alias-name set.
fn is_querystring_alias_method_callee(callee: &Expression, alias_names: &BTreeSet<String>) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = callee
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    matches!(property.as_ref(),
        Expression::Identifier(m) | Expression::StringLiteral(m)
            if querystring_method_capability(m).is_some())
}

/// bd-qmy52: compute the set of identifier names that are BOTH bound via
/// `const/let/var <name> = require('querystring')` at the unit root AND used
/// as a recognized querystring builtin somewhere reachable by the fail-closed
/// statement scan. Mirror of [`confirmed_path_module_aliases`].
fn confirmed_querystring_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_querystring_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            path_statement_contains_usage(stmt, &|e| {
                expr_contains_matching_call(e, &|callee| {
                    is_querystring_alias_method_callee(callee, &single)
                })
            })
        }) {
            used.insert(name.clone());
        }
    }
    used
}

/// bd-qmy52: true when `specifier` names the Node os module — `os` or
/// `node:os`.
fn is_os_module_specifier(specifier: &str) -> bool {
    specifier == "os" || specifier == "node:os"
}

/// bd-qmy52: sentinel key recording that `name` is bound to the os module via
/// `const <name> = require('os')` AND used as a recognized os builtin. Mirror
/// of [`path_module_alias_sentinel`].
fn os_module_alias_sentinel(name: &str) -> String {
    format!("\0osmod\0{name}")
}

/// bd-qmy52: true when `expr` is exactly `require('os')` /
/// `require('node:os')` with an unshadowed `require`.
fn is_require_os_module_initializer(
    expr: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> bool {
    let Expression::Call { callee, arguments } = expr else {
        return false;
    };
    if !matches!(callee.as_ref(), Expression::Identifier(name)
        if name == "require" && !binding_lookup.contains_key(name.as_str()))
    {
        return false;
    }
    matches!(
        arguments.as_slice(),
        [Expression::StringLiteral(spec)] if is_os_module_specifier(spec)
    )
}

/// bd-qmy52: capability tag for a recognized `os` method. Single source of
/// truth shared by the usage-lookahead scan and the call-site recognizer. All
/// pure-compute: the interpreter dispatch returns FIXED engine-contained
/// values (documented at the dispatch arms).
fn os_method_capability(method: &str) -> Option<&'static str> {
    match method {
        "platform" => Some("builtin:OsPlatform"),
        "arch" => Some("builtin:OsArch"),
        "type" => Some("builtin:OsType"),
        "release" => Some("builtin:OsRelease"),
        "version" => Some("builtin:OsVersion"),
        "homedir" => Some("builtin:OsHomedir"),
        "tmpdir" => Some("builtin:OsTmpdir"),
        "hostname" => Some("builtin:OsHostname"),
        "uptime" => Some("builtin:OsUptime"),
        "totalmem" => Some("builtin:OsTotalmem"),
        "freemem" => Some("builtin:OsFreemem"),
        "loadavg" => Some("builtin:OsLoadavg"),
        "cpus" => Some("builtin:OsCpus"),
        "networkInterfaces" => Some("builtin:OsNetworkInterfaces"),
        "userInfo" => Some("builtin:OsUserInfo"),
        "endianness" => Some("builtin:OsEndianness"),
        "availableParallelism" => Some("builtin:OsAvailableParallelism"),
        "machine" => Some("builtin:OsMachine"),
        "getPriority" => Some("builtin:OsGetPriority"),
        "setPriority" => Some("builtin:OsSetPriority"),
        _ => None,
    }
}

/// bd-qmy52: what a recognized `os` property READ lowers to.
enum OsMemberReadLowering {
    /// Deterministic constant (`os.EOL`, `os.devNull`) — a string literal.
    StringConstant(&'static str),
    /// `os.constants` — a 0-arg `builtin:OsConstants` HostCall allocating the
    /// nested `{ signals, errno, priority }` object.
    ConstantsHostcall,
}

/// bd-qmy52: the lowering of a recognized `os` property name, per Node
/// (linux). Shared by the scan and the member arm so the confirmed-alias gate
/// can never diverge from what the lowering rewrites.
fn os_property_read_lowering(property: &str) -> Option<OsMemberReadLowering> {
    match property {
        "EOL" => Some(OsMemberReadLowering::StringConstant("\n")),
        "devNull" => Some(OsMemberReadLowering::StringConstant("/dev/null")),
        "constants" => Some(OsMemberReadLowering::ConstantsHostcall),
        _ => None,
    }
}

/// bd-qmy52: true when `expr` IS the os module object at lowering time — a
/// sentinel-recorded require-binding alias or the inline `require('os')` call.
fn is_os_module_object(expr: &Expression, binding_lookup: &BTreeMap<String, BindingId>) -> bool {
    match expr {
        Expression::Identifier(alias) => {
            binding_lookup.contains_key(&os_module_alias_sentinel(alias))
        }
        Expression::Call { callee, arguments } => {
            matches!(callee.as_ref(), Expression::Identifier(name)
                if name == "require" && !binding_lookup.contains_key(name.as_str()))
                && matches!(
                    arguments.as_slice(),
                    [Expression::StringLiteral(spec)] if is_os_module_specifier(spec)
                )
        }
        _ => false,
    }
}

/// bd-qmy52: recognize an `os` builtin member call and return its
/// `builtin:Os*` capability. Purely syntactic; no sub-namespaces.
fn os_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = callee
    else {
        return None;
    };
    if !is_os_module_object(object, binding_lookup) {
        return None;
    }
    let method = match property.as_ref() {
        Expression::Identifier(name) | Expression::StringLiteral(name) => name.as_str(),
        _ => return None,
    };
    os_method_capability(method)
}

/// Recognize the standard static methods that have real core interpreter
/// dispatch arms. Core deliberately has no heap-backed global-object registry,
/// so an unshadowed `Object.keys(...)`-style call must become its canonical
/// `builtin:*` hostcall during lowering. Keep this list limited to executable
/// arms in `baseline_interpreter.rs`; the numeric stdlib bridge advertises a
/// wider aspirational surface that is not callable yet (bd-zql4d).
const STATIC_BUILTIN_GLOBALS: [&str; 5] = ["Object", "Array", "String", "Math", "JSON"];

/// Intrinsics that exist only through a direct-call lowering seam. Bare
/// unshadowed reads are undefined, but a real outer lexical binding with the
/// same name must still propagate into a nested function and shadow the seam.
const DIRECT_CALL_INTRINSIC_GLOBALS: [&str; 1] = ["require"];

fn is_static_builtin_global(name: &str) -> bool {
    STATIC_BUILTIN_GLOBALS.contains(&name)
}

fn is_non_materialized_intrinsic_global(name: &str) -> bool {
    is_static_builtin_global(name) || DIRECT_CALL_INTRINSIC_GLOBALS.contains(&name)
}

fn static_builtin_call_capability(
    callee: &Expression,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Member {
        object,
        property,
        computed,
    } = callee
    else {
        return None;
    };
    let Expression::Identifier(global) = object.as_ref() else {
        return None;
    };
    if binding_lookup.contains_key(global.as_str()) {
        return None;
    }
    let property_name = match (*computed, property.as_ref()) {
        (false, Expression::Identifier(name) | Expression::StringLiteral(name)) => name.as_str(),
        (true, Expression::StringLiteral(name)) => name.as_str(),
        _ => return None,
    };
    match (global.as_str(), property_name) {
        ("Object", "keys") => Some("builtin:ObjectKeys"),
        ("Object", "values") => Some("builtin:ObjectValues"),
        ("Array", "isArray") => Some("builtin:ArrayIsArray"),
        ("String", "fromCharCode") => Some("builtin:StringFromCharCode"),
        ("String", "fromCodePoint") => Some("builtin:StringFromCodePoint"),
        ("Math", "abs") => Some("builtin:MathAbs"),
        ("JSON", "parse") => Some("builtin:JsonParse"),
        ("JSON", "stringify") => Some("builtin:JsonStringify"),
        _ => None,
    }
}

/// Recognize the one supported first-class static builtin member read.
///
/// Core has no materialized `Array` global object, so an unshadowed
/// `Array.isArray` value read needs a dedicated pure factory hostcall. Keep
/// this allowlist separate from direct-call interception: widening it to an
/// arbitrary capability-backed callable would bypass the normal hostcall
/// authority boundary when the returned value is invoked.
fn static_builtin_member_factory_capability(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<&'static str> {
    let Expression::Identifier(global) = object else {
        return None;
    };
    if binding_lookup.contains_key(global.as_str()) {
        return None;
    }
    let property_name = match (computed, property) {
        (false, Expression::Identifier(name) | Expression::StringLiteral(name)) => name.as_str(),
        (true, Expression::StringLiteral(name)) => name.as_str(),
        _ => return None,
    };
    match (global.as_str(), property_name) {
        ("Array", "isArray") => Some("builtin:ArrayIsArrayFunction"),
        _ => None,
    }
}

/// bd-qmy52: recognize an `os` property READ (`os.EOL`, `os.devNull`,
/// `os.constants`) on a recognized os-module object and return its lowering.
/// Accepts the same static/quoted property shapes as [`path_member_constant`].
fn os_member_read_lowering(
    object: &Expression,
    property: &Expression,
    computed: bool,
    binding_lookup: &BTreeMap<String, BindingId>,
) -> Option<OsMemberReadLowering> {
    if !is_os_module_object(object, binding_lookup) {
        return None;
    }
    let prop = match (computed, property) {
        (false, Expression::Identifier(name) | Expression::StringLiteral(name)) => name.as_str(),
        (true, Expression::StringLiteral(name)) => name.as_str(),
        _ => return None,
    };
    os_property_read_lowering(prop)
}

/// bd-qmy52: scan-time twin of [`os_builtin_call_capability`]'s receiver check.
fn is_os_alias_method_callee(callee: &Expression, alias_names: &BTreeSet<String>) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = callee
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    matches!(property.as_ref(),
        Expression::Identifier(m) | Expression::StringLiteral(m)
            if os_method_capability(m).is_some())
}

/// bd-qmy52: scan-time twin of [`os_member_read_lowering`]: true when `expr`
/// is a recognized os property read (`<alias>.EOL`, `<alias>.constants`, …) on
/// one of the candidate alias names.
fn is_os_alias_property_read(expr: &Expression, alias_names: &BTreeSet<String>) -> bool {
    let Expression::Member {
        object,
        property,
        computed: false,
    } = expr
    else {
        return false;
    };
    if !matches!(object.as_ref(), Expression::Identifier(name) if alias_names.contains(name)) {
        return false;
    }
    matches!(property.as_ref(),
        Expression::Identifier(p) | Expression::StringLiteral(p)
            if os_property_read_lowering(p).is_some())
}

/// bd-qmy52: true when `expr` contains a recognized os usage on one of
/// `alias_names` — either a recognized method CALL (`<alias>.platform()`) or a
/// recognized property READ (`<alias>.EOL`, `<alias>.constants`).
fn expr_contains_os_alias_usage(expr: &Expression, alias_names: &BTreeSet<String>) -> bool {
    expr_contains_matching_call(expr, &|callee| {
        is_os_alias_method_callee(callee, alias_names)
    }) || expr_contains_matching_member(expr, &|member| {
        is_os_alias_property_read(member, alias_names)
    })
}

/// bd-qmy52: compute the set of identifier names that are BOTH bound via
/// `const/let/var <name> = require('os')` at the unit root AND used as a
/// recognized os builtin (method call or property read) somewhere reachable by
/// the fail-closed statement scan. Mirror of
/// [`confirmed_path_module_aliases`].
fn confirmed_os_module_aliases(
    body: &[Statement],
    binding_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let mut candidates = BTreeSet::new();
    for stmt in body {
        if let Statement::VariableDeclaration(vd) = stmt {
            for d in &vd.declarations {
                if let (BindingPattern::Identifier(name), Some(init)) = (&d.pattern, &d.initializer)
                    && is_require_os_module_initializer(init, binding_lookup)
                {
                    candidates.insert(name.clone());
                }
            }
        }
    }
    if candidates.is_empty() {
        return candidates;
    }

    let mut used = BTreeSet::new();
    for name in &candidates {
        let single: BTreeSet<String> = std::iter::once(name.clone()).collect();
        if body.iter().any(|stmt| {
            path_statement_contains_usage(stmt, &|e| expr_contains_os_alias_usage(e, &single))
        }) {
            used.insert(name.clone());
        }
    }
    used
}

pub fn lower_ir0_to_ir1(
    ir0: &Ir0Module,
) -> Result<LoweringPassResult<Ir1Module>, LoweringPipelineError> {
    if ir0.tree.body.is_empty() {
        return Err(LoweringPipelineError::EmptyIr0Body);
    }

    let ir0_hash = ir0.content_hash();
    let mut ir1 = Ir1Module::new(ir0_hash, ir0.header.source_label.clone());
    let mut binding_index = 0u32;
    let root_scope_id = ScopeId { depth: 0, index: 0 };
    let root_scope_kind = match ir0.tree.goal {
        ParseGoal::Script => ScopeKind::Global,
        ParseGoal::Module => ScopeKind::Module,
    };
    let mut bindings = Vec::<ResolvedBinding>::new();
    let mut binding_lookup = BTreeMap::<String, BindingId>::new();
    let mut declared_root_bindings =
        reserve_root_scope_bindings(&ir0.tree.body, &mut binding_lookup, &mut binding_index);
    declared_root_bindings.extend(reserve_hoisted_var_bindings(
        &ir0.tree.body,
        &mut binding_lookup,
        &mut binding_index,
    ));
    // bd-tu0c3: record path-module binding aliases (`const path =
    // require('path')` that are actually used as a recognized pure-compute
    // `path` builtin) as NUL-sentinels in binding_lookup, so the binding form
    // lowers to `builtin:Path*` HostCalls and lowering-time string constants.
    // Usage-gated: a bare/unused `const path = require('path')` keeps core's
    // existing `module:require` behavior. The sentinel value is unused — its
    // presence is the signal; the NUL-prefixed key can never collide with a
    // real binding name and is never pushed into `bindings`.
    for alias in confirmed_path_module_aliases(&ir0.tree.body, &binding_lookup) {
        binding_lookup.insert(path_module_alias_sentinel(&alias), 0);
    }
    // bd-qmy52: same usage-gated sentinel recording for the two other
    // pure-compute module families — `require('querystring')` (member calls
    // lower to `builtin:Querystring*` HostCalls) and `require('os')` (member
    // calls lower to `builtin:Os*` HostCalls; `os.EOL`/`os.devNull` property
    // reads lower to string constants and `os.constants` to a 0-arg
    // `builtin:OsConstants` HostCall). A bare/unused alias keeps core's
    // existing `module:require` behavior.
    for alias in confirmed_querystring_module_aliases(&ir0.tree.body, &binding_lookup) {
        binding_lookup.insert(querystring_module_alias_sentinel(&alias), 0);
    }
    for alias in confirmed_os_module_aliases(&ir0.tree.body, &binding_lookup) {
        binding_lookup.insert(os_module_alias_sentinel(&alias), 0);
    }
    let mut synthetic_export_index = 0u32;
    let mut synthetic_import_index = 0u32;
    let mut label_counter = 0u32;

    for statement in &ir0.tree.body {
        match statement {
            Statement::Import(import) => {
                let specifier = import.source.clone();
                let alloc_import_binding =
                    |name: &str,
                     bindings: &mut Vec<ResolvedBinding>,
                     binding_lookup: &mut BTreeMap<String, BindingId>,
                     binding_index: &mut u32|
                     -> Result<BindingId, LoweringPipelineError> {
                        alloc_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            name,
                            BindingKind::Import,
                        )
                        .map_err(LoweringPipelineError::SemanticViolation)
                    };

                let make_temp_binding =
                    |synthetic_import_index: &mut u32,
                     bindings: &mut Vec<ResolvedBinding>,
                     binding_lookup: &mut BTreeMap<String, BindingId>,
                     binding_index: &mut u32|
                     -> Result<BindingId, LoweringPipelineError> {
                        let temp_name =
                            make_internal_binding_name("import_namespace", *synthetic_import_index);
                        *synthetic_import_index = synthetic_import_index.saturating_add(1);
                        alloc_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            &temp_name,
                            BindingKind::Const,
                        )
                        .map_err(LoweringPipelineError::SemanticViolation)
                    };

                match &import.clause {
                    ImportClause::SideEffect => {
                        ir1.ops.push(Ir1Op::ImportModule { specifier });
                        ir1.ops.push(Ir1Op::Pop);
                    }
                    ImportClause::Namespace { local } => {
                        ir1.ops.push(Ir1Op::ImportModule { specifier });
                        let binding_id = alloc_import_binding(
                            local,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::StoreBinding { binding_id });
                        ir1.ops.push(Ir1Op::Pop);
                    }
                    ImportClause::Default { local } => {
                        ir1.ops.push(Ir1Op::ImportModule { specifier });
                        ir1.ops.push(Ir1Op::GetProperty {
                            key: Ir1PropertyKey::Static("default".to_string()),
                        });
                        let binding_id = alloc_import_binding(
                            local,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::StoreBinding { binding_id });
                        ir1.ops.push(Ir1Op::Pop);
                    }
                    ImportClause::Named { specifiers } => {
                        let temp_binding_id = make_temp_binding(
                            &mut synthetic_import_index,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::ImportModule { specifier });
                        ir1.ops.push(Ir1Op::StoreBinding {
                            binding_id: temp_binding_id,
                        });
                        ir1.ops.push(Ir1Op::Pop);
                        for spec in specifiers {
                            ir1.ops.push(Ir1Op::LoadBinding {
                                binding_id: temp_binding_id,
                            });
                            ir1.ops.push(Ir1Op::GetProperty {
                                key: Ir1PropertyKey::Static(spec.import_name.clone()),
                            });
                            let binding_id = alloc_import_binding(
                                &spec.local_name,
                                &mut bindings,
                                &mut binding_lookup,
                                &mut binding_index,
                            )?;
                            ir1.ops.push(Ir1Op::StoreBinding { binding_id });
                            ir1.ops.push(Ir1Op::Pop);
                        }
                    }
                    ImportClause::DefaultAndNamed {
                        default,
                        specifiers,
                    } => {
                        let temp_binding_id = make_temp_binding(
                            &mut synthetic_import_index,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::ImportModule { specifier });
                        ir1.ops.push(Ir1Op::StoreBinding {
                            binding_id: temp_binding_id,
                        });
                        ir1.ops.push(Ir1Op::Pop);

                        ir1.ops.push(Ir1Op::LoadBinding {
                            binding_id: temp_binding_id,
                        });
                        ir1.ops.push(Ir1Op::GetProperty {
                            key: Ir1PropertyKey::Static("default".to_string()),
                        });
                        let default_binding_id = alloc_import_binding(
                            default,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::StoreBinding {
                            binding_id: default_binding_id,
                        });
                        ir1.ops.push(Ir1Op::Pop);

                        for spec in specifiers {
                            ir1.ops.push(Ir1Op::LoadBinding {
                                binding_id: temp_binding_id,
                            });
                            ir1.ops.push(Ir1Op::GetProperty {
                                key: Ir1PropertyKey::Static(spec.import_name.clone()),
                            });
                            let binding_id = alloc_import_binding(
                                &spec.local_name,
                                &mut bindings,
                                &mut binding_lookup,
                                &mut binding_index,
                            )?;
                            ir1.ops.push(Ir1Op::StoreBinding { binding_id });
                            ir1.ops.push(Ir1Op::Pop);
                        }
                    }
                    ImportClause::DefaultAndNamespace { default, namespace } => {
                        let temp_binding_id = make_temp_binding(
                            &mut synthetic_import_index,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::ImportModule { specifier });
                        ir1.ops.push(Ir1Op::StoreBinding {
                            binding_id: temp_binding_id,
                        });
                        ir1.ops.push(Ir1Op::Pop);

                        ir1.ops.push(Ir1Op::LoadBinding {
                            binding_id: temp_binding_id,
                        });
                        ir1.ops.push(Ir1Op::GetProperty {
                            key: Ir1PropertyKey::Static("default".to_string()),
                        });
                        let default_binding_id = alloc_import_binding(
                            default,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::StoreBinding {
                            binding_id: default_binding_id,
                        });
                        ir1.ops.push(Ir1Op::Pop);

                        ir1.ops.push(Ir1Op::LoadBinding {
                            binding_id: temp_binding_id,
                        });
                        let namespace_binding_id = alloc_import_binding(
                            namespace,
                            &mut bindings,
                            &mut binding_lookup,
                            &mut binding_index,
                        )?;
                        ir1.ops.push(Ir1Op::StoreBinding {
                            binding_id: namespace_binding_id,
                        });
                        ir1.ops.push(Ir1Op::Pop);
                    }
                }
            }
            Statement::Export(export) => match &export.kind {
                ExportKind::Default(expression) => {
                    lower_expression_to_ir1(
                        expression,
                        &mut ir1.ops,
                        &mut bindings,
                        &mut binding_lookup,
                        &mut binding_index,
                        root_scope_id,
                        &mut label_counter,
                    )?;
                    let binding_name =
                        make_internal_binding_name("default_export", synthetic_export_index);
                    synthetic_export_index = synthetic_export_index.saturating_add(1);
                    let binding_id = alloc_binding(
                        &mut bindings,
                        &mut binding_lookup,
                        &mut binding_index,
                        root_scope_id,
                        &binding_name,
                        BindingKind::Const,
                    )
                    .map_err(LoweringPipelineError::SemanticViolation)?;
                    ir1.ops.push(Ir1Op::StoreBinding { binding_id });
                    ir1.ops.push(Ir1Op::ExportBinding {
                        name: "default".to_string(),
                        binding_id,
                    });
                    ir1.ops.push(Ir1Op::Pop);
                }
                ExportKind::NamedClause(clause) => {
                    let specifiers = parse_named_export_clause_bindings(clause);
                    if let Some(source_specifier) = parse_named_export_clause_source(clause) {
                        if specifiers.is_empty() {
                            ir1.ops.push(Ir1Op::ImportModule {
                                specifier: source_specifier,
                            });
                            ir1.ops.push(Ir1Op::Pop);
                        } else {
                            let temp_binding_id = {
                                let temp_name = make_internal_binding_name(
                                    "reexport_namespace",
                                    synthetic_export_index,
                                );
                                synthetic_export_index = synthetic_export_index.saturating_add(1);
                                alloc_binding(
                                    &mut bindings,
                                    &mut binding_lookup,
                                    &mut binding_index,
                                    root_scope_id,
                                    &temp_name,
                                    BindingKind::Const,
                                )
                                .map_err(LoweringPipelineError::SemanticViolation)?
                            };
                            ir1.ops.push(Ir1Op::ImportModule {
                                specifier: source_specifier,
                            });
                            ir1.ops.push(Ir1Op::StoreBinding {
                                binding_id: temp_binding_id,
                            });
                            ir1.ops.push(Ir1Op::Pop);

                            for (import_name, exported_name) in specifiers {
                                ir1.ops.push(Ir1Op::LoadBinding {
                                    binding_id: temp_binding_id,
                                });
                                ir1.ops.push(Ir1Op::GetProperty {
                                    key: Ir1PropertyKey::Static(import_name),
                                });
                                let export_binding_name = make_internal_binding_name(
                                    "reexport_binding",
                                    synthetic_export_index,
                                );
                                synthetic_export_index = synthetic_export_index.saturating_add(1);
                                let export_binding_id = alloc_binding(
                                    &mut bindings,
                                    &mut binding_lookup,
                                    &mut binding_index,
                                    root_scope_id,
                                    &export_binding_name,
                                    BindingKind::Const,
                                )
                                .map_err(LoweringPipelineError::SemanticViolation)?;
                                ir1.ops.push(Ir1Op::StoreBinding {
                                    binding_id: export_binding_id,
                                });
                                ir1.ops.push(Ir1Op::ExportBinding {
                                    name: exported_name,
                                    binding_id: export_binding_id,
                                });
                                ir1.ops.push(Ir1Op::Pop);
                            }
                        }
                    } else {
                        for (local_name, exported_name) in specifiers {
                            if !declared_root_bindings.contains(local_name.as_str()) {
                                return Err(LoweringPipelineError::SemanticViolation(
                                    SemanticError::new(
                                        SemanticErrorCode::UndeclaredExportBinding,
                                        Some(local_name.clone()),
                                        Some(export.span.clone()),
                                    ),
                                ));
                            }
                            let binding_id = binding_lookup
                                .get(local_name.as_str())
                                .copied()
                                .ok_or(LoweringPipelineError::InvariantViolation {
                                    detail: "reserved root binding missing from binding lookup",
                                })?;
                            ir1.ops.push(Ir1Op::LoadBinding { binding_id });
                            ir1.ops.push(Ir1Op::ExportBinding {
                                name: exported_name,
                                binding_id,
                            });
                            ir1.ops.push(Ir1Op::Pop);
                        }
                    }
                }
            },
            _ => {
                lower_statement_to_ir1(
                    statement,
                    &mut ir1.ops,
                    &mut bindings,
                    &mut binding_lookup,
                    &mut binding_index,
                    root_scope_id,
                    &mut label_counter,
                )?;
            }
        }
    }

    ir1.ops.push(Ir1Op::Return);
    ir1.scopes.push(ScopeNode {
        scope_id: root_scope_id,
        parent: None,
        kind: root_scope_kind,
        bindings,
    });

    verify_ir1_source(&ir1, &ir0_hash).map_err(lowering_error_from_ir_error)?;

    let binding_ids_are_unique = scope_binding_ids_are_unique(&ir1.scopes);
    let checks = vec![
        InvariantCheck {
            name: "source_hash_linkage".to_string(),
            passed: true,
            detail: "IR1 source_hash references IR0 hash".to_string(),
        },
        InvariantCheck {
            name: "scope_binding_ids_unique".to_string(),
            passed: binding_ids_are_unique,
            detail: "All scope binding IDs are unique".to_string(),
        },
    ];
    ensure_checks_pass(&checks, "duplicate binding IDs in IR1 scope graph")?;

    let ir1_hash = ir1.content_hash();
    Ok(LoweringPassResult {
        ledger_entry: IsomorphismLedgerEntry {
            pass_id: "ir0_to_ir1".to_string(),
            input_hash: hash_string(&ir0_hash),
            output_hash: hash_string(&ir1_hash),
            input_op_count: ir0.tree.body.len() as u64,
            output_op_count: ir1.ops.len() as u64,
        },
        witness: PassWitness {
            pass_id: "ir0_to_ir1".to_string(),
            input_hash: hash_string(&ir0_hash),
            output_hash: hash_string(&ir1_hash),
            rollback_token: hash_string(&ir0_hash),
            invariant_checks: checks,
        },
        module: ir1,
    })
}

fn alloc_label(counter: &mut u32) -> u32 {
    let id = *counter;
    *counter = counter.checked_add(1).unwrap_or(u32::MAX);
    id
}

#[derive(Debug, Clone, Copy, Default)]
struct ControlFlowTargets {
    break_label: Option<u32>,
    continue_label: Option<u32>,
}

fn make_internal_binding_name(purpose: &str, index: u32) -> String {
    format!("@@franken_internal_{purpose}_{index}")
}

fn reserve_binding_id(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    name: &str,
) -> BindingId {
    if let Some(existing_id) = binding_lookup.get(name) {
        return *existing_id;
    }

    let binding_id = *binding_index;
    *binding_index = binding_index.saturating_add(1);
    binding_lookup.insert(name.to_string(), binding_id);
    binding_id
}

fn reserve_root_scope_bindings(
    statements: &[Statement],
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
) -> BTreeSet<String> {
    let mut declared = BTreeSet::new();

    for statement in statements {
        match statement {
            Statement::Import(import) => {
                for binding_name in import.clause.binding_names() {
                    reserve_binding_id(binding_lookup, binding_index, binding_name);
                    declared.insert(binding_name.to_string());
                }
            }
            Statement::VariableDeclaration(variable_declaration) => {
                for declarator in &variable_declaration.declarations {
                    for binding_name in declarator.pattern.binding_names() {
                        reserve_binding_id(binding_lookup, binding_index, binding_name);
                        declared.insert(binding_name.to_string());
                    }
                }
            }
            Statement::FunctionDeclaration(function) => {
                if let Some(name) = &function.name {
                    reserve_binding_id(binding_lookup, binding_index, name);
                    declared.insert(name.clone());
                }
            }
            Statement::ClassDeclaration(cls) => {
                if let Some(name) = &cls.name {
                    reserve_binding_id(binding_lookup, binding_index, name);
                    declared.insert(name.clone());
                }
            }
            _ => {}
        }
    }

    declared
}

/// Reserve `var` bindings from nested control-flow statements in their
/// enclosing function/module scope. Unlike `let`/`const`, a nested `var Math`
/// shadows the entire function, including calls textually before the block;
/// missing this pre-scan could incorrectly redirect such a call to a builtin.
/// Function and class bodies are separate scopes and are intentionally not
/// traversed here.
fn reserve_hoisted_var_bindings(
    statements: &[Statement],
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
) -> BTreeSet<String> {
    fn visit(
        statement: &Statement,
        binding_lookup: &mut BTreeMap<String, BindingId>,
        binding_index: &mut BindingId,
        declared: &mut BTreeSet<String>,
    ) {
        match statement {
            Statement::VariableDeclaration(declaration)
                if declaration.kind == VariableDeclarationKind::Var =>
            {
                for declarator in &declaration.declarations {
                    for name in declarator.pattern.binding_names() {
                        reserve_binding_id(binding_lookup, binding_index, name);
                        declared.insert(name.to_string());
                    }
                }
            }
            Statement::Block(block) => {
                for nested in &block.body {
                    visit(nested, binding_lookup, binding_index, declared);
                }
            }
            Statement::If(if_statement) => {
                visit(
                    &if_statement.consequent,
                    binding_lookup,
                    binding_index,
                    declared,
                );
                if let Some(alternate) = &if_statement.alternate {
                    visit(alternate, binding_lookup, binding_index, declared);
                }
            }
            Statement::For(for_statement) => {
                if let Some(initializer) = &for_statement.init {
                    visit(initializer, binding_lookup, binding_index, declared);
                }
                visit(&for_statement.body, binding_lookup, binding_index, declared);
            }
            Statement::ForIn(for_in) => {
                if for_in.binding_kind == Some(VariableDeclarationKind::Var) {
                    for name in for_in.binding.binding_names() {
                        reserve_binding_id(binding_lookup, binding_index, name);
                        declared.insert(name.to_string());
                    }
                }
                visit(&for_in.body, binding_lookup, binding_index, declared);
            }
            Statement::ForOf(for_of) => {
                if for_of.binding_kind == Some(VariableDeclarationKind::Var) {
                    for name in for_of.binding.binding_names() {
                        reserve_binding_id(binding_lookup, binding_index, name);
                        declared.insert(name.to_string());
                    }
                }
                visit(&for_of.body, binding_lookup, binding_index, declared);
            }
            Statement::While(while_statement) => visit(
                &while_statement.body,
                binding_lookup,
                binding_index,
                declared,
            ),
            Statement::DoWhile(do_while) => {
                visit(&do_while.body, binding_lookup, binding_index, declared)
            }
            Statement::TryCatch(try_catch) => {
                for nested in &try_catch.block.body {
                    visit(nested, binding_lookup, binding_index, declared);
                }
                if let Some(handler) = &try_catch.handler {
                    for nested in &handler.body.body {
                        visit(nested, binding_lookup, binding_index, declared);
                    }
                }
                if let Some(finalizer) = &try_catch.finalizer {
                    for nested in &finalizer.body {
                        visit(nested, binding_lookup, binding_index, declared);
                    }
                }
            }
            Statement::Switch(switch_statement) => {
                for case in &switch_statement.cases {
                    for nested in &case.consequent {
                        visit(nested, binding_lookup, binding_index, declared);
                    }
                }
            }
            Statement::FunctionDeclaration(_) | Statement::ClassDeclaration(_) => {}
            _ => {}
        }
    }

    let mut declared = BTreeSet::new();
    for statement in statements {
        visit(statement, binding_lookup, binding_index, &mut declared);
    }
    declared
}

/// Install the lexical declarations owned by a block before lowering any of
/// its statements.  A fresh binding ID is required even when an outer scope
/// already has the same name: otherwise a call before `let`/`const`/`class`
/// initialization can be mistaken for an unshadowed static builtin.
///
/// The returned map records the enclosing lookup entries so the caller can
/// restore them after the block while retaining any unrelated free-variable
/// discoveries made while lowering the block.
fn reserve_fresh_lexical_bindings(
    lexical_names: BTreeSet<String>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
) -> BTreeMap<String, Option<BindingId>> {
    let mut enclosing_bindings = BTreeMap::new();
    for name in lexical_names {
        enclosing_bindings.insert(name.clone(), binding_lookup.get(&name).copied());
        let binding_id = *binding_index;
        *binding_index = binding_index.saturating_add(1);
        binding_lookup.insert(name, binding_id);
    }
    enclosing_bindings
}

fn reserve_block_lexical_bindings(
    statements: &[Statement],
    additional_lexical_name: Option<&str>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
) -> BTreeMap<String, Option<BindingId>> {
    let mut lexical_names = BTreeSet::new();
    if let Some(name) = additional_lexical_name {
        lexical_names.insert(name.to_string());
    }
    for statement in statements {
        match statement {
            Statement::VariableDeclaration(declaration)
                if declaration.kind != VariableDeclarationKind::Var =>
            {
                for declarator in &declaration.declarations {
                    lexical_names.extend(
                        declarator
                            .pattern
                            .binding_names()
                            .into_iter()
                            .map(str::to_string),
                    );
                }
            }
            Statement::FunctionDeclaration(function) => {
                if let Some(name) = &function.name {
                    lexical_names.insert(name.clone());
                }
            }
            Statement::ClassDeclaration(cls) => {
                if let Some(name) = &cls.name {
                    lexical_names.insert(name.clone());
                }
            }
            _ => {}
        }
    }

    reserve_fresh_lexical_bindings(lexical_names, binding_lookup, binding_index)
}

fn restore_block_lexical_bindings(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    enclosing_bindings: BTreeMap<String, Option<BindingId>>,
) {
    for (name, enclosing_binding) in enclosing_bindings {
        if let Some(binding_id) = enclosing_binding {
            binding_lookup.insert(name, binding_id);
        } else {
            binding_lookup.remove(&name);
        }
    }
}

fn restore_class_expression_self_binding(
    binding_lookup: &mut BTreeMap<String, BindingId>,
    self_name: Option<&str>,
    enclosing_binding: Option<BindingId>,
) {
    let Some(self_name) = self_name else {
        return;
    };
    if let Some(binding_id) = enclosing_binding {
        binding_lookup.insert(self_name.to_string(), binding_id);
    } else {
        binding_lookup.remove(self_name);
    }
}

fn emit_reference_error_throw(ops: &mut Vec<Ir1Op>, name: &str) {
    ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::String(format!("{name} is not defined")),
    });
    ops.push(Ir1Op::HostCall {
        capability: "builtin:ReferenceError".to_string(),
        arg_count: 1,
    });
    ops.push(Ir1Op::Throw);
    ops.push(Ir1Op::LoadLiteral {
        value: Ir1Literal::Undefined,
    });
}

/// Class bodies use ordinary function lowering, but an unresolved bare name
/// must still throw instead of becoming a captured `undefined` placeholder.
/// Preserve the special `typeof missingName` behavior and any real enclosing
/// binding; named class expressions install their private self alias in the
/// outer lookup before this pass runs.
fn rewrite_unresolved_class_body_loads(
    body_ops: &mut Vec<Ir1Op>,
    body_lookup: &BTreeMap<String, BindingId>,
    pre_lower_names: &BTreeSet<String>,
    outer_lookup: &BTreeMap<String, BindingId>,
) -> BTreeSet<String> {
    let locally_defined_ids: BTreeSet<BindingId> = body_ops
        .iter()
        .filter_map(|op| match op {
            Ir1Op::StoreBinding { binding_id } | Ir1Op::DeclareFunction { binding_id, .. } => {
                Some(*binding_id)
            }
            _ => None,
        })
        .collect();
    let unresolved_by_id: BTreeMap<BindingId, String> = body_lookup
        .iter()
        .filter(|(name, binding_id)| {
            !is_internal_lowering_binding(name)
                && !pre_lower_names.contains(name.as_str())
                && !outer_lookup.contains_key(name.as_str())
                && !locally_defined_ids.contains(binding_id)
        })
        .map(|(name, binding_id)| (*binding_id, name.clone()))
        .collect();
    if unresolved_by_id.is_empty() {
        return BTreeSet::new();
    }
    let unresolved_names = unresolved_by_id.values().cloned().collect();

    let mut rewritten = Vec::with_capacity(body_ops.len());
    for (index, op) in body_ops.iter().enumerate() {
        if let Ir1Op::LoadBinding { binding_id } = op
            && let Some(name) = unresolved_by_id.get(binding_id)
            && !matches!(
                body_ops.get(index.saturating_add(1)),
                Some(Ir1Op::UnaryOp {
                    operator: UnaryOperator::Typeof
                })
            )
        {
            emit_reference_error_throw(&mut rewritten, name);
            continue;
        }
        rewritten.push(op.clone());
    }
    *body_ops = rewritten;
    unresolved_names
}

/// Give a class-expression self capture a runtime-private name while retaining
/// its exact body and outer binding IDs. Constructor and method markers are
/// deliberately distinct: only a constructor marker is initialized to the new
/// closure at runtime, while methods capture the already-created class value.
fn rewrite_class_expression_self_capture(
    body_lookup: &BTreeMap<String, BindingId>,
    self_name: &str,
    runtime_name: String,
    free_vars: &mut [String],
    free_var_ids: &[BindingId],
) {
    let Some(self_binding) = body_lookup.get(self_name) else {
        return;
    };
    let Some(index) = free_var_ids.iter().position(|id| id == self_binding) else {
        return;
    };
    if let Some(free_var) = free_vars.get_mut(index) {
        *free_var = runtime_name;
    }
}

#[allow(clippy::too_many_arguments)]
fn lower_lexical_statement_sequence(
    statements: &[Statement],
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    label_counter: &mut u32,
    control_flow: ControlFlowTargets,
) -> Result<(), LoweringPipelineError> {
    let enclosing_bindings =
        reserve_block_lexical_bindings(statements, None, binding_lookup, binding_index);
    let result = statements.iter().try_for_each(|statement| {
        lower_statement_to_ir1_with_flow(
            statement,
            ops,
            bindings,
            binding_lookup,
            binding_index,
            scope_id,
            label_counter,
            control_flow,
        )
    });
    restore_block_lexical_bindings(binding_lookup, enclosing_bindings);
    result
}

fn seed_function_outer_static_bindings(
    outer_lookup: &BTreeMap<String, BindingId>,
    body_lookup: &mut BTreeMap<String, BindingId>,
    body_binding_index: &mut BindingId,
) {
    for global in STATIC_BUILTIN_GLOBALS
        .iter()
        .chain(DIRECT_CALL_INTRINSIC_GLOBALS.iter())
        .copied()
    {
        if !body_lookup.contains_key(global) && outer_lookup.contains_key(global) {
            reserve_binding_id(body_lookup, body_binding_index, global);
        }
    }
}

/// Pre-reserve declarations in a function-like body. `declared_names` is
/// captured immediately after formal bindings are allocated, so a declaration
/// in the body can shadow a same-named capture used by a default expression
/// without changing the parameter environment's binding identity.
fn prepare_function_body_bindings(
    statements: Option<&[Statement]>,
    mut declared_names: BTreeSet<String>,
    body_lookup: &mut BTreeMap<String, BindingId>,
    body_binding_index: &mut BindingId,
) -> BTreeSet<String> {
    if let Some(statements) = statements {
        declared_names.extend(reserve_root_scope_bindings(
            statements,
            body_lookup,
            body_binding_index,
        ));
        declared_names.extend(reserve_hoisted_var_bindings(
            statements,
            body_lookup,
            body_binding_index,
        ));
    }
    declared_names
}

fn merge_unshadowed_parameter_prologue_captures(
    captures: &[(String, BindingId)],
    body_lookup: &mut BTreeMap<String, BindingId>,
) {
    for (name, binding_id) in captures {
        body_lookup.entry(name.clone()).or_insert(*binding_id);
    }
}

/// Validate the rest-parameter syntax represented by the positional ABI.
/// Every preceding formal occupies one slot, including default and
/// destructuring patterns, so `rest_param_index` remains the source position.
fn validate_rest_parameter_abi(
    params: &[FunctionParam],
) -> Result<Option<u32>, LoweringPipelineError> {
    let rest_params = params
        .iter()
        .enumerate()
        .filter(|(_, param)| matches!(&param.pattern, BindingPattern::Rest(_)))
        .collect::<Vec<_>>();
    let Some((rest_index, rest_param)) = rest_params.first().copied() else {
        return Ok(None);
    };

    let rest_binds_identifier = matches!(
        &rest_param.pattern,
        BindingPattern::Rest(inner) if inner.as_identifier().is_some()
    );
    if rest_params.len() != 1 || rest_index + 1 != params.len() || !rest_binds_identifier {
        return Err(unsupported_frontier_expression_error(
            "function_parameter_patterns_with_rest",
            "FE-LOWER-UNSUPPORTED-REST-PARAM-ABI-0001",
            "core.function_rest_parameter_abi",
            "rest parameters require one final identifier rest binding",
            Some(rest_param.span.clone()),
        ));
    }

    Ok(Some(rest_index as u32))
}

/// Object-rest lowering needs an own-property clone/exclusion operation that
/// FrankenCore does not yet expose. Reject it in parameter prologues instead
/// of silently reading a property literally named after the rest binding.
fn contains_unsupported_parameter_object_rest(pattern: &BindingPattern) -> bool {
    match pattern {
        BindingPattern::Identifier(_) => false,
        BindingPattern::ObjectPattern(properties) => properties.iter().any(|property| {
            matches!(&property.value, BindingPattern::Rest(_))
                || contains_unsupported_parameter_object_rest(&property.value)
        }),
        BindingPattern::ArrayPattern(elements) => elements
            .iter()
            .flatten()
            .any(contains_unsupported_parameter_object_rest),
        BindingPattern::Rest(inner) => contains_unsupported_parameter_object_rest(inner),
        BindingPattern::AssignmentPattern { left, .. } => {
            contains_unsupported_parameter_object_rest(left)
        }
    }
}

fn contains_unsupported_parameter_nested_rest(pattern: &BindingPattern) -> bool {
    match pattern {
        BindingPattern::Identifier(_) => false,
        BindingPattern::ObjectPattern(properties) => properties
            .iter()
            .any(|property| contains_unsupported_parameter_nested_rest(&property.value)),
        BindingPattern::ArrayPattern(elements) => elements
            .iter()
            .flatten()
            .any(contains_unsupported_parameter_nested_rest),
        BindingPattern::Rest(inner) => {
            inner.as_identifier().is_none() || contains_unsupported_parameter_nested_rest(inner)
        }
        BindingPattern::AssignmentPattern { left, .. } => {
            contains_unsupported_parameter_nested_rest(left)
        }
    }
}

fn contains_unsupported_parameter_computed_key(pattern: &BindingPattern) -> bool {
    match pattern {
        BindingPattern::Identifier(_) => false,
        BindingPattern::ObjectPattern(properties) => properties.iter().any(|property| {
            property.computed || contains_unsupported_parameter_computed_key(&property.value)
        }),
        BindingPattern::ArrayPattern(elements) => elements
            .iter()
            .flatten()
            .any(contains_unsupported_parameter_computed_key),
        BindingPattern::Rest(inner) => contains_unsupported_parameter_computed_key(inner),
        BindingPattern::AssignmentPattern { left, .. } => {
            contains_unsupported_parameter_computed_key(left)
        }
    }
}

/// Allocate one runtime slot per formal and every identifier introduced by a
/// pattern. Non-identifier formals use an unforgeable synthetic source slot;
/// their entry prologue copies/defaults/destructures that slot into user
/// bindings before the body executes (bd-ur3tk.10).
#[derive(Default)]
struct FunctionParameterPlan<'a> {
    param_names: Vec<String>,
    destructure_params: Vec<(String, &'a BindingPattern, &'a SourceSpan)>,
    rest_param_index: Option<u32>,
}

fn parameter_prologue_referenced_binding_ids(ops: &[Ir1Op]) -> BTreeSet<BindingId> {
    let mut referenced = BTreeSet::new();
    for op in ops {
        match op {
            Ir1Op::LoadBinding { binding_id }
            | Ir1Op::StoreBinding { binding_id }
            | Ir1Op::AssignOp { binding_id, .. }
            | Ir1Op::ExportBinding { binding_id, .. } => {
                referenced.insert(*binding_id);
            }
            Ir1Op::DeclareFunction {
                body_ops,
                free_var_ids,
                free_var_outer_ids,
                ..
            }
            | Ir1Op::CreateFunction {
                body_ops,
                free_var_ids,
                free_var_outer_ids,
                ..
            } => {
                let child_references = parameter_prologue_referenced_binding_ids(body_ops);
                referenced.extend(free_var_ids.iter().zip(free_var_outer_ids).filter_map(
                    |(body_id, outer_id)| child_references.contains(body_id).then_some(*outer_id),
                ));
            }
            _ => {}
        }
    }
    referenced
}

fn arrow_body_uses_lexical_call_context(ops: &[Ir1Op]) -> bool {
    ops.iter().any(|op| match op {
        Ir1Op::LoadThis | Ir1Op::LoadNewTarget | Ir1Op::LoadSuper => true,
        Ir1Op::CreateFunction {
            body_ops,
            is_arrow: true,
            ..
        } => arrow_body_uses_lexical_call_context(body_ops),
        _ => false,
    })
}

fn allocate_function_parameter_bindings<'a>(
    params: &'a [FunctionParam],
    body_bindings: &mut Vec<ResolvedBinding>,
    body_lookup: &mut BTreeMap<String, BindingId>,
    body_binding_index: &mut BindingId,
    body_scope: ScopeId,
) -> Result<FunctionParameterPlan<'a>, LoweringPipelineError> {
    let rest_param_index = validate_rest_parameter_abi(params)?;
    if let Some(param) = params
        .iter()
        .find(|param| contains_unsupported_parameter_object_rest(&param.pattern))
    {
        return Err(unsupported_frontier_expression_error(
            "function_parameter_object_rest",
            "FE-LOWER-UNSUPPORTED-OBJECT-REST-PARAM-0001",
            "core.function_parameter_object_rest",
            "object-rest parameter patterns require own-property exclusion lowering",
            Some(param.span.clone()),
        ));
    }
    if let Some(param) = params
        .iter()
        .find(|param| contains_unsupported_parameter_nested_rest(&param.pattern))
    {
        return Err(unsupported_frontier_expression_error(
            "function_parameter_nested_rest",
            "FE-LOWER-UNSUPPORTED-NESTED-REST-PARAM-0001",
            "core.function_parameter_nested_rest",
            "nested rest parameter targets require recursive slice destructuring",
            Some(param.span.clone()),
        ));
    }
    if let Some(param) = params
        .iter()
        .find(|param| contains_unsupported_parameter_computed_key(&param.pattern))
    {
        return Err(unsupported_frontier_expression_error(
            "function_parameter_computed_destructuring_key",
            "FE-LOWER-UNSUPPORTED-COMPUTED-PARAM-KEY-0001",
            "core.function_parameter_computed_key",
            "computed parameter-pattern keys require dynamic property-key lowering",
            Some(param.span.clone()),
        ));
    }
    let mut param_names = Vec::with_capacity(params.len());
    let mut destructure_params = Vec::with_capacity(params.len());
    for (index, param) in params.iter().enumerate() {
        if let BindingPattern::Rest(inner) = &param.pattern
            && let Some(name) = inner.as_identifier()
        {
            param_names.push(name.to_string());
            continue;
        }
        if let Some(name) = param.name() {
            param_names.push(name.to_string());
        } else {
            let synthetic_name = format!("@@franken_internal_param_{index}");
            param_names.push(synthetic_name.clone());
            destructure_params.push((synthetic_name, &param.pattern, &param.span));
        }
    }

    for param_name in &param_names {
        let _ = alloc_binding(
            body_bindings,
            body_lookup,
            body_binding_index,
            body_scope,
            param_name,
            BindingKind::Parameter,
        )
        .map_err(LoweringPipelineError::SemanticViolation)?;
    }
    for (_, pattern, _) in &destructure_params {
        for bound_name in pattern.binding_names() {
            let _ = alloc_binding(
                body_bindings,
                body_lookup,
                body_binding_index,
                body_scope,
                bound_name,
                BindingKind::Parameter,
            )
            .map_err(LoweringPipelineError::SemanticViolation)?;
        }
    }
    Ok(FunctionParameterPlan {
        param_names,
        destructure_params,
        rest_param_index,
    })
}

#[allow(clippy::too_many_arguments)]
fn lower_function_parameter_prologue(
    destructure_params: &[(String, &BindingPattern, &SourceSpan)],
    outer_lookup: &BTreeMap<String, BindingId>,
    body_ops: &mut Vec<Ir1Op>,
    body_bindings: &mut Vec<ResolvedBinding>,
    parameter_lookup: &BTreeMap<String, BindingId>,
    body_binding_index: &mut BindingId,
    body_scope: ScopeId,
    body_label_counter: &mut u32,
) -> Result<Vec<(String, BindingId)>, LoweringPipelineError> {
    if destructure_params.is_empty() {
        return Ok(Vec::new());
    }
    let parameter_binding_names = parameter_lookup.keys().cloned().collect::<BTreeSet<_>>();
    let mut prologue_lookup = parameter_lookup.clone();
    seed_function_outer_static_bindings(outer_lookup, &mut prologue_lookup, body_binding_index);
    let prologue_start = body_ops.len();
    for (synthetic_name, pattern, span) in destructure_params {
        let source_binding_id = *prologue_lookup.get(synthetic_name).ok_or(
            LoweringPipelineError::InvariantViolation {
                detail: "synthetic parameter source binding must be allocated before its prologue",
            },
        )?;
        let prologue_op_start = body_ops.len();
        lower_destructuring_to_ir1(
            pattern,
            source_binding_id,
            body_ops,
            body_bindings,
            &mut prologue_lookup,
            body_binding_index,
            body_scope,
            body_label_counter,
        )?;
        if body_ops[prologue_op_start..].iter().any(|op| match op {
            Ir1Op::CreateFunction {
                name,
                body_ops,
                free_var_ids,
                is_arrow,
                ..
            } => {
                let referenced = parameter_prologue_referenced_binding_ids(body_ops);
                name.is_some()
                    || (*is_arrow && arrow_body_uses_lexical_call_context(body_ops))
                    || free_var_ids
                        .iter()
                        .any(|binding_id| referenced.contains(binding_id))
            }
            Ir1Op::DeclareFunction { .. } => true,
            _ => false,
        }) {
            return Err(unsupported_frontier_expression_error(
                "function_parameter_default_closure",
                "FE-LOWER-UNSUPPORTED-PARAM-DEFAULT-CLOSURE-0001",
                "core.function_parameter_default_closure",
                "capturing, self-named, or lexical-context parameter-default closures require persistent environment cells",
                Some((*span).clone()),
            ));
        }
    }
    let referenced_binding_ids =
        parameter_prologue_referenced_binding_ids(&body_ops[prologue_start..]);
    Ok(prologue_lookup
        .into_iter()
        .filter(|(name, _)| {
            !parameter_binding_names.contains(name) && !is_internal_lowering_binding(name)
        })
        .filter(|(_, binding_id)| referenced_binding_ids.contains(binding_id))
        .collect())
}

fn reject_self_referential_parameter_capture(
    captures: &[(String, BindingId)],
    self_name: &str,
    span: SourceSpan,
) -> Result<(), LoweringPipelineError> {
    if captures.iter().any(|(name, _)| name == self_name) {
        return Err(unsupported_frontier_expression_error(
            "self_referential_parameter_default",
            "FE-LOWER-UNSUPPORTED-SELF-PARAM-DEFAULT-0001",
            "core.self_referential_parameter_default",
            "self-referential parameter defaults require a live function-name environment",
            Some(span),
        ));
    }
    Ok(())
}

fn parse_named_export_clause_bindings(clause: &str) -> Vec<(String, String)> {
    let trimmed = clause.trim();
    let local_clause = split_named_export_clause(trimmed)
        .map(|(head, _)| head.trim())
        .unwrap_or(trimmed);

    if let Some(inner) = local_clause
        .strip_prefix('{')
        .and_then(|body| body.strip_suffix('}'))
    {
        let inner = inner.trim();
        if inner.is_empty() {
            return Vec::new();
        }

        return inner
            .split(',')
            .filter_map(|specifier| {
                let specifier = specifier.trim();
                if specifier.is_empty() {
                    return None;
                }
                let parts: Vec<&str> = specifier.split_whitespace().collect();
                let (local_name, exported_name) = match parts.as_slice() {
                    [name] => (*name, *name),
                    [local, "as", exported] => (*local, *exported),
                    _ => (specifier, specifier),
                };
                Some((local_name.to_string(), exported_name.to_string()))
            })
            .collect();
    }

    if trimmed.is_empty() {
        Vec::new()
    } else {
        vec![(trimmed.to_string(), trimmed.to_string())]
    }
}

fn parse_named_export_clause_source(clause: &str) -> Option<String> {
    let trimmed = clause.trim();
    let (_head, source_raw) = split_named_export_clause(trimmed)?;
    parse_quoted_export_source(source_raw.trim())
}

fn split_named_export_clause(clause: &str) -> Option<(&str, &str)> {
    clause.split_once(" from ")
}

fn parse_quoted_export_source(input: &str) -> Option<String> {
    if input.len() < 2 {
        return None;
    }
    let bytes = input.as_bytes();
    let first = bytes[0];
    let last = bytes[bytes.len() - 1];
    if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
        let inner = &input[1..input.len() - 1];
        if inner.contains('\n') || inner.contains('\r') {
            return None;
        }
        return Some(inner.to_string());
    }
    None
}

fn alloc_pattern_primary_binding(
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    pattern: &BindingPattern,
    binding_kind: BindingKind,
) -> Result<BindingId, SemanticError> {
    let names = pattern.binding_names();
    let mut first_user_binding = None;

    for name in names {
        let binding_id = alloc_binding(
            bindings,
            binding_lookup,
            binding_index,
            scope_id,
            name,
            binding_kind,
        )?;
        if first_user_binding.is_none() {
            first_user_binding = Some(binding_id);
        }
    }

    if matches!(pattern, BindingPattern::Identifier(_)) {
        return Ok(first_user_binding.unwrap_or(0));
    }

    let source_name = make_internal_binding_name("destructure_source", *binding_index);
    alloc_binding(
        bindings,
        binding_lookup,
        binding_index,
        scope_id,
        &source_name,
        BindingKind::Let,
    )
}

/// Resolve the identifiers in a `for-in`/`for-of` assignment target.
///
/// A loop head without `let`/`const`/`var` is an assignment, not a lexical
/// declaration.  Existing bindings must therefore be reused instead of
/// passing through declaration-conflict checks or installing a temporary
/// loop scope.  For consistency with ordinary assignment lowering, an
/// unresolved target gets a root-scope placeholder binding.
fn resolve_assignment_pattern_primary_binding(
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    pattern: &BindingPattern,
) -> Result<BindingId, SemanticError> {
    let mut first_target = None;

    for name in pattern.binding_names() {
        let binding_id = if let Some(existing) = binding_lookup.get(name) {
            *existing
        } else {
            alloc_binding(
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                name,
                BindingKind::Let,
            )?
        };
        first_target.get_or_insert(binding_id);
    }

    Ok(first_target.unwrap_or(0))
}

/// Emit IR1 ops to destructure a value (already stored in `source_bid`) into
/// the individual bindings declared by `pattern`. For object patterns this
/// emits `LoadBinding(source) + GetProperty(key) + StoreBinding(target) + Pop`
/// for each property. Array patterns use numeric index strings.
#[allow(clippy::only_used_in_recursion)]
#[allow(clippy::too_many_arguments)]
fn lower_destructuring_to_ir1(
    pattern: &BindingPattern,
    source_bid: BindingId,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    label_counter: &mut u32,
) -> Result<(), LoweringPipelineError> {
    match pattern {
        BindingPattern::Identifier(_) => {
            // Simple binding — already handled by StoreBinding above.
        }
        BindingPattern::ObjectPattern(props) => {
            for prop in props {
                let target_names = prop.value.binding_names();
                let target_name = match target_names.first() {
                    Some(n) => *n,
                    None => continue,
                };
                let target_bid = match binding_lookup.get(target_name) {
                    Some(bid) => *bid,
                    None => continue,
                };

                // Determine the property key string.
                let key_str = if prop.shorthand {
                    target_name.to_string()
                } else {
                    match &prop.key {
                        Expression::Identifier(name) => name.clone(),
                        Expression::StringLiteral(s) => s.clone(),
                        Expression::NumericLiteral(n) => n.to_string(),
                        _ => target_name.to_string(),
                    }
                };

                // Load the source object, get the property, store to target binding.
                ops.push(Ir1Op::LoadBinding {
                    binding_id: source_bid,
                });
                ops.push(Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(key_str),
                });

                match &prop.value {
                    BindingPattern::Identifier(_) => {
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: target_bid,
                        });
                        ops.push(Ir1Op::Pop);
                    }
                    _ => {
                        let temp_binding = alloc_internal_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            scope_id,
                            "destructure_prop",
                        )?;
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: temp_binding,
                        });
                        ops.push(Ir1Op::Pop);
                        lower_destructuring_to_ir1(
                            &prop.value,
                            temp_binding,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            scope_id,
                            label_counter,
                        )?;
                    }
                }

                // Nested destructuring uses temp bindings to avoid
                // source-overwrite bugs.
            }
        }
        BindingPattern::ArrayPattern(elements) => {
            for (index, element) in elements.iter().enumerate() {
                let element = match element {
                    Some(el) => el,
                    None => continue, // hole: `[, b]`
                };

                // Handle rest element: `[a, ...rest]`
                if let BindingPattern::Rest(inner) = element {
                    let target_names = inner.binding_names();
                    let target_name = match target_names.first() {
                        Some(n) => *n,
                        None => continue,
                    };
                    if let Some(&target_bid) = binding_lookup.get(target_name) {
                        // Rest collects remaining elements by slicing the source array
                        // from the current index to the end.
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: source_bid,
                        });
                        ops.push(Ir1Op::LoadLiteral {
                            value: Ir1Literal::Integer(index as i64),
                        });
                        ops.push(Ir1Op::ArraySlice);
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: target_bid,
                        });
                        ops.push(Ir1Op::Pop);
                    }
                    continue;
                }

                let target_names = element.binding_names();
                let target_name = match target_names.first() {
                    Some(n) => *n,
                    None => continue,
                };
                let target_bid = match binding_lookup.get(target_name) {
                    Some(bid) => *bid,
                    None => continue,
                };

                // Load source array, get element by index string.
                ops.push(Ir1Op::LoadBinding {
                    binding_id: source_bid,
                });
                ops.push(Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(index.to_string()),
                });
                match element {
                    BindingPattern::Identifier(_) => {
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: target_bid,
                        });
                        ops.push(Ir1Op::Pop);
                    }
                    _ => {
                        let temp_binding = alloc_internal_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            scope_id,
                            "destructure_elem",
                        )?;
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: temp_binding,
                        });
                        ops.push(Ir1Op::Pop);
                        lower_destructuring_to_ir1(
                            element,
                            temp_binding,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            scope_id,
                            label_counter,
                        )?;
                    }
                }

                // Nested array destructuring uses temp bindings to avoid
                // source-overwrite bugs.
            }
        }
        BindingPattern::AssignmentPattern { left, right } => {
            // The outer assignment pattern with default value. The value has
            // already been stored to source_bid. Only `undefined` triggers
            // the default (not null).
            let default_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);

            ops.push(Ir1Op::LoadBinding {
                binding_id: source_bid,
            });
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            });
            ops.push(Ir1Op::BinaryOp {
                operator: BinaryOperator::StrictEqual,
            });
            ops.push(Ir1Op::JumpIfTruthy {
                label_id: default_label,
            });

            match left.as_ref() {
                BindingPattern::Identifier(name) => {
                    if let Some(&target_bid) = binding_lookup.get(name.as_str()) {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: source_bid,
                        });
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: target_bid,
                        });
                        ops.push(Ir1Op::Pop);
                    }
                }
                _ => {
                    lower_destructuring_to_ir1(
                        left,
                        source_bid,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        scope_id,
                        label_counter,
                    )?;
                }
            }
            ops.push(Ir1Op::Jump {
                label_id: end_label,
            });

            ops.push(Ir1Op::Label { id: default_label });
            lower_expression_to_ir1(
                right,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::StoreBinding {
                binding_id: source_bid,
            });
            ops.push(Ir1Op::Pop);
            match left.as_ref() {
                BindingPattern::Identifier(name) => {
                    if let Some(&target_bid) = binding_lookup.get(name.as_str()) {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: source_bid,
                        });
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: target_bid,
                        });
                        ops.push(Ir1Op::Pop);
                    }
                }
                _ => {
                    lower_destructuring_to_ir1(
                        left,
                        source_bid,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        scope_id,
                        label_counter,
                    )?;
                }
            }

            ops.push(Ir1Op::Label { id: end_label });
        }
        BindingPattern::Rest(inner) => {
            // Rest at top level (unusual but valid). Recurse into inner.
            lower_destructuring_to_ir1(
                inner,
                source_bid,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lower_statement_to_ir1(
    statement: &Statement,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    label_counter: &mut u32,
) -> Result<(), LoweringPipelineError> {
    lower_statement_to_ir1_with_flow(
        statement,
        ops,
        bindings,
        binding_lookup,
        binding_index,
        scope_id,
        label_counter,
        ControlFlowTargets::default(),
    )
}

#[allow(clippy::too_many_arguments)]
fn lower_statement_to_ir1_with_flow(
    statement: &Statement,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    label_counter: &mut u32,
    control_flow: ControlFlowTargets,
) -> Result<(), LoweringPipelineError> {
    match statement {
        Statement::Expression(stmt) => {
            lower_expression_to_ir1(
                &stmt.expression,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::Pop);
        }
        Statement::VariableDeclaration(vd) => {
            let binding_kind = binding_kind_for_variable_declaration(vd.kind);
            if vd.kind == VariableDeclarationKind::Const {
                for d in &vd.declarations {
                    if d.initializer.is_none() {
                        let primary_name =
                            d.pattern.binding_names().first().map(|s| (*s).to_string());
                        return Err(LoweringPipelineError::SemanticViolation(
                            SemanticError::new(
                                SemanticErrorCode::ConstWithoutInitializer,
                                primary_name,
                                Some(d.span.clone()),
                            ),
                        ));
                    }
                }
            }
            for d in &vd.declarations {
                // Allocate all bindings referenced by the pattern first.
                let primary_bid = alloc_pattern_primary_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &d.pattern,
                    binding_kind,
                )
                .map_err(LoweringPipelineError::SemanticViolation)?;

                // Lower the initializer expression (pushes value onto stack).
                if let Some(init) = &d.initializer {
                    // bd-tu0c3: when `<id> = require('path')` aliases the path
                    // module AND the alias was confirmed at pre-scan (used as a
                    // recognized `path.*` builtin; the NUL-sentinel is
                    // present), bind `id` to `undefined` and SKIP lowering the
                    // inner `require('path')` — which would otherwise emit a
                    // `module:require` hostcall that faults at runtime. The
                    // pure-compute operations are recognized at the member
                    // call/read sites. A bare/unused `const path =
                    // require('path')` is not recorded, so it keeps the
                    // existing behavior. Mirror of the franken-engine elision.
                    // bd-qmy52 joins the querystring and os require-bindings
                    // to the same elision (confirmed aliases only; unused
                    // aliases keep the `module:require` behavior).
                    if let BindingPattern::Identifier(alias) = &d.pattern
                        && ((is_require_path_module_initializer(init, binding_lookup)
                            && binding_lookup.contains_key(&path_module_alias_sentinel(alias)))
                            || (is_require_querystring_module_initializer(init, binding_lookup)
                                && binding_lookup
                                    .contains_key(&querystring_module_alias_sentinel(alias)))
                            || (is_require_os_module_initializer(init, binding_lookup)
                                && binding_lookup.contains_key(&os_module_alias_sentinel(alias))))
                    {
                        ops.push(Ir1Op::LoadLiteral {
                            value: Ir1Literal::Undefined,
                        });
                    } else {
                        lower_expression_to_ir1(
                            init,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            scope_id,
                            label_counter,
                        )?;
                    }
                } else {
                    ops.push(Ir1Op::LoadLiteral {
                        value: Ir1Literal::Undefined,
                    });
                }

                // `alloc_pattern_primary_binding` returns the user binding for simple
                // identifiers and a dedicated source binding for destructuring.
                let source_binding_id = primary_bid;

                // Store the initializer value to the source binding.
                ops.push(Ir1Op::StoreBinding {
                    binding_id: source_binding_id,
                });
                ops.push(Ir1Op::Pop);

                // If the pattern is a simple Identifier, we're done.
                // For destructuring patterns, emit property-extraction ops.
                if !matches!(d.pattern, BindingPattern::Identifier(_)) {
                    lower_destructuring_to_ir1(
                        &d.pattern,
                        source_binding_id,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        scope_id,
                        label_counter,
                    )?;
                }
            }
        }
        Statement::Block(block) => {
            let enclosing_bindings =
                reserve_block_lexical_bindings(&block.body, None, binding_lookup, binding_index);
            let result = block.body.iter().try_for_each(|inner| {
                lower_statement_to_ir1_with_flow(
                    inner,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    control_flow,
                )
            });
            restore_block_lexical_bindings(binding_lookup, enclosing_bindings);
            result?;
        }
        Statement::If(if_stmt) => {
            lower_expression_to_ir1(
                &if_stmt.condition,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            let else_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);
            ops.push(Ir1Op::JumpIfFalsy {
                label_id: else_label,
            });
            ops.push(Ir1Op::Pop);
            lower_statement_to_ir1_with_flow(
                &if_stmt.consequent,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
                control_flow,
            )?;
            ops.push(Ir1Op::Jump {
                label_id: end_label,
            });
            ops.push(Ir1Op::Label { id: else_label });
            if let Some(alt) = &if_stmt.alternate {
                lower_statement_to_ir1_with_flow(
                    alt,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    control_flow,
                )?;
            }
            ops.push(Ir1Op::Label { id: end_label });
        }
        Statement::For(for_stmt) => {
            let for_enclosing_bindings =
                for_stmt.init.as_deref().map_or_else(BTreeMap::new, |init| {
                    reserve_block_lexical_bindings(
                        std::slice::from_ref(init),
                        None,
                        binding_lookup,
                        binding_index,
                    )
                });
            if let Some(init) = &for_stmt.init {
                lower_statement_to_ir1_with_flow(
                    init,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    control_flow,
                )?;
            }
            let loop_label = alloc_label(label_counter);
            let continue_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);
            ops.push(Ir1Op::Label { id: loop_label });
            if let Some(test) = &for_stmt.condition {
                lower_expression_to_ir1(
                    test,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::JumpIfFalsy {
                    label_id: end_label,
                });
                ops.push(Ir1Op::Pop);
            }
            lower_statement_to_ir1_with_flow(
                &for_stmt.body,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
                ControlFlowTargets {
                    break_label: Some(end_label),
                    continue_label: Some(continue_label),
                },
            )?;
            ops.push(Ir1Op::Label { id: continue_label });
            if let Some(update) = &for_stmt.update {
                lower_expression_to_ir1(
                    update,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::Pop);
            }
            ops.push(Ir1Op::Jump {
                label_id: loop_label,
            });
            ops.push(Ir1Op::Label { id: end_label });
            restore_block_lexical_bindings(binding_lookup, for_enclosing_bindings);
        }
        Statement::ForIn(for_in_stmt) => {
            // Lowering: for (let k in obj) { body }
            //   1. Evaluate object expression → push on stack
            //   2. ForInInit → pop object, push enumerator
            //   3. loop_label:
            //   4. ForInNext { done_label: end } → push next key (or jump)
            //   5. StoreBinding(k) → bind key to loop variable
            //   6. Pop
            //   7. body
            //   8. Jump → loop_label
            //   9. end_label:
            //  10. IteratorClose (break path wired through control_flow)
            let for_in_enclosing_bindings = if matches!(
                for_in_stmt.binding_kind,
                Some(VariableDeclarationKind::Let | VariableDeclarationKind::Const)
            ) {
                reserve_fresh_lexical_bindings(
                    for_in_stmt
                        .binding
                        .binding_names()
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    binding_lookup,
                    binding_index,
                )
            } else {
                BTreeMap::new()
            };

            // A lexical loop-head binding is already in its TDZ while the
            // right-hand side is evaluated. Reserving it first also prevents
            // a same-name static builtin (for example `Math`) from being
            // intercepted through an outer/global spelling. `var` and bare
            // assignment targets intentionally keep their enclosing binding.
            lower_expression_to_ir1(
                &for_in_stmt.object,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::ForInInit);

            let loop_label = alloc_label(label_counter);
            let continue_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);

            ops.push(Ir1Op::Label { id: loop_label });
            ops.push(Ir1Op::ForInNext {
                done_label: end_label,
            });

            // Bind the yielded key to the loop variable.
            let bid = match for_in_stmt.binding_kind {
                None => resolve_assignment_pattern_primary_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &for_in_stmt.binding,
                ),
                Some(kind) => alloc_pattern_primary_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &for_in_stmt.binding,
                    binding_kind_for_variable_declaration(kind),
                ),
            };
            let bid = bid.map_err(LoweringPipelineError::SemanticViolation)?;
            // For simple identifier patterns, store to the primary binding.
            // For destructuring patterns, use a dedicated internal source binding.
            let source_binding_id = if matches!(for_in_stmt.binding, BindingPattern::Identifier(_))
            {
                bid
            } else {
                // Allocate a dedicated internal binding to avoid source-overwrite bugs
                let source_name = make_internal_binding_name("for_in_source", *binding_index);
                alloc_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &source_name,
                    BindingKind::Let,
                )
                .map_err(LoweringPipelineError::SemanticViolation)?
            };

            ops.push(Ir1Op::StoreBinding {
                binding_id: source_binding_id,
            });
            ops.push(Ir1Op::Pop);
            if !matches!(for_in_stmt.binding, BindingPattern::Identifier(_)) {
                lower_destructuring_to_ir1(
                    &for_in_stmt.binding,
                    source_binding_id,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
            }

            lower_statement_to_ir1_with_flow(
                &for_in_stmt.body,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
                ControlFlowTargets {
                    break_label: Some(end_label),
                    continue_label: Some(continue_label),
                },
            )?;
            ops.push(Ir1Op::Label { id: continue_label });
            ops.push(Ir1Op::Jump {
                label_id: loop_label,
            });
            ops.push(Ir1Op::Label { id: end_label });
            restore_block_lexical_bindings(binding_lookup, for_in_enclosing_bindings);
        }
        Statement::ForOf(for_of_stmt) => {
            // Lowering: for (let v of iterable) { body }
            //   1. Evaluate iterable → push on stack
            //   2. ForOfInit → pop iterable, call @@iterator, push iterator
            //   3. loop_label:
            //   4. ForOfNext { done_label: end } → push next value (or jump)
            //   5. StoreBinding(v) → bind value to loop variable
            //   6. Pop
            //   7. body (break path calls IteratorClose)
            //   8. Jump → loop_label
            //   9. end_label:
            let for_of_enclosing_bindings = if matches!(
                for_of_stmt.binding_kind,
                Some(VariableDeclarationKind::Let | VariableDeclarationKind::Const)
            ) {
                reserve_fresh_lexical_bindings(
                    for_of_stmt
                        .binding
                        .binding_names()
                        .into_iter()
                        .map(str::to_string)
                        .collect(),
                    binding_lookup,
                    binding_index,
                )
            } else {
                BTreeMap::new()
            };

            // See the for-in twin above: lexical loop heads shadow during
            // RHS evaluation, while `var` and assignment targets do not.
            lower_expression_to_ir1(
                &for_of_stmt.iterable,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::ForOfInit);

            let loop_label = alloc_label(label_counter);
            let continue_label = alloc_label(label_counter);
            let close_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);

            ops.push(Ir1Op::Label { id: loop_label });
            ops.push(Ir1Op::ForOfNext {
                done_label: end_label,
            });

            // Bind the yielded value to the loop variable.
            let bid = match for_of_stmt.binding_kind {
                None => resolve_assignment_pattern_primary_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &for_of_stmt.binding,
                ),
                Some(kind) => alloc_pattern_primary_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &for_of_stmt.binding,
                    binding_kind_for_variable_declaration(kind),
                ),
            };
            let bid = bid.map_err(LoweringPipelineError::SemanticViolation)?;
            // For simple identifier patterns, store to the primary binding.
            // For destructuring patterns, use a dedicated internal source binding.
            let source_binding_id = if matches!(for_of_stmt.binding, BindingPattern::Identifier(_))
            {
                bid
            } else {
                // Allocate a dedicated internal binding to avoid source-overwrite bugs
                let source_name = make_internal_binding_name("for_of_source", *binding_index);
                alloc_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &source_name,
                    BindingKind::Let,
                )
                .map_err(LoweringPipelineError::SemanticViolation)?
            };

            ops.push(Ir1Op::StoreBinding {
                binding_id: source_binding_id,
            });
            ops.push(Ir1Op::Pop);
            if !matches!(for_of_stmt.binding, BindingPattern::Identifier(_)) {
                lower_destructuring_to_ir1(
                    &for_of_stmt.binding,
                    source_binding_id,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
            }

            lower_statement_to_ir1_with_flow(
                &for_of_stmt.body,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
                ControlFlowTargets {
                    break_label: Some(close_label),
                    continue_label: Some(continue_label),
                },
            )?;
            ops.push(Ir1Op::Label { id: continue_label });
            ops.push(Ir1Op::Jump {
                label_id: loop_label,
            });
            // Break path: close the iterator before exiting.
            ops.push(Ir1Op::Label { id: close_label });
            ops.push(Ir1Op::IteratorClose {
                reason: IteratorCloseReason::Break,
            });
            ops.push(Ir1Op::Label { id: end_label });
            restore_block_lexical_bindings(binding_lookup, for_of_enclosing_bindings);
        }
        Statement::While(while_stmt) => {
            let loop_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);
            ops.push(Ir1Op::Label { id: loop_label });
            lower_expression_to_ir1(
                &while_stmt.condition,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::JumpIfFalsy {
                label_id: end_label,
            });
            ops.push(Ir1Op::Pop);
            lower_statement_to_ir1_with_flow(
                &while_stmt.body,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
                ControlFlowTargets {
                    break_label: Some(end_label),
                    continue_label: Some(loop_label),
                },
            )?;
            ops.push(Ir1Op::Jump {
                label_id: loop_label,
            });
            ops.push(Ir1Op::Label { id: end_label });
        }
        Statement::DoWhile(do_while) => {
            let loop_label = alloc_label(label_counter);
            let continue_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);
            ops.push(Ir1Op::Label { id: loop_label });
            lower_statement_to_ir1_with_flow(
                &do_while.body,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
                ControlFlowTargets {
                    break_label: Some(end_label),
                    continue_label: Some(continue_label),
                },
            )?;
            ops.push(Ir1Op::Label { id: continue_label });
            lower_expression_to_ir1(
                &do_while.condition,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::JumpIfFalsy {
                label_id: end_label,
            });
            ops.push(Ir1Op::Pop);
            ops.push(Ir1Op::Jump {
                label_id: loop_label,
            });
            ops.push(Ir1Op::Label { id: end_label });
        }
        Statement::Return(ret) => {
            if let Some(arg) = &ret.argument {
                lower_expression_to_ir1(
                    arg,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
            } else {
                ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                });
            }
            // Keep explicit returns aligned with the module-level `Return`
            // lowering path, which reads register 0 after control flow.
            ops.push(Ir1Op::Pop);
            ops.push(Ir1Op::Return);
        }
        Statement::Throw(throw_stmt) => {
            lower_expression_to_ir1(
                &throw_stmt.argument,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::Throw);
        }
        Statement::TryCatch(tc) => {
            let has_handler = tc.handler.is_some();
            let has_finalizer = tc.finalizer.is_some();
            let end_label = alloc_label(label_counter);
            let finally_label = if has_finalizer {
                Some(alloc_label(label_counter))
            } else {
                None
            };
            // Abrupt exits from a try body must pop its handler frame even
            // when there is no finalizer. Otherwise a later throw/return can
            // re-enter the stale handler after control has left the try.
            let try_needs_abrupt_forwarders = has_handler || has_finalizer;
            let try_break_forwarder = if try_needs_abrupt_forwarders {
                control_flow.break_label.map(|_| alloc_label(label_counter))
            } else {
                None
            };
            let try_continue_forwarder = if try_needs_abrupt_forwarders {
                control_flow
                    .continue_label
                    .map(|_| alloc_label(label_counter))
            } else {
                None
            };
            let try_control_flow = ControlFlowTargets {
                break_label: try_break_forwarder.or(control_flow.break_label),
                continue_label: try_continue_forwarder.or(control_flow.continue_label),
            };
            // A catch body has no live frame unless it is guarded by the
            // nested try/finally used to route rethrows through `finally`.
            // Give that guard its own forwarders so each exit pops exactly
            // the frame that is active on its path.
            let catch_break_forwarder = if has_handler && has_finalizer {
                control_flow.break_label.map(|_| alloc_label(label_counter))
            } else {
                None
            };
            let catch_continue_forwarder = if has_handler && has_finalizer {
                control_flow
                    .continue_label
                    .map(|_| alloc_label(label_counter))
            } else {
                None
            };
            let catch_control_flow = ControlFlowTargets {
                break_label: catch_break_forwarder.or(control_flow.break_label),
                continue_label: catch_continue_forwarder.or(control_flow.continue_label),
            };
            // When there is a catch handler, allocate a distinct catch label.
            // When there is only a finally (no catch), route exceptions
            // directly to the finally label so `EnterCatch` is NOT emitted
            // and the pending exception is preserved for `EndFinally`.
            let catch_label = if tc.handler.is_some() {
                alloc_label(label_counter)
            } else {
                finally_label.unwrap_or_else(|| alloc_label(label_counter))
            };
            ops.push(Ir1Op::BeginTry {
                catch_label,
                finally_label,
            });
            let try_enclosing_bindings =
                reserve_block_lexical_bindings(&tc.block.body, None, binding_lookup, binding_index);
            let try_result = tc.block.body.iter().try_for_each(|inner| {
                lower_statement_to_ir1_with_flow(
                    inner,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    try_control_flow,
                )
            });
            restore_block_lexical_bindings(binding_lookup, try_enclosing_bindings);
            try_result?;
            let has_try_abrupt_forwarders =
                try_break_forwarder.is_some() || try_continue_forwarder.is_some();
            let normal_try_complete_label =
                has_try_abrupt_forwarders.then(|| alloc_label(label_counter));
            if let Some(normal_try_complete_label) = normal_try_complete_label {
                ops.push(Ir1Op::Jump {
                    label_id: normal_try_complete_label,
                });
                if let (Some(via_break_label), Some(actual_break_label)) =
                    (try_break_forwarder, control_flow.break_label)
                {
                    ops.push(Ir1Op::Label {
                        id: via_break_label,
                    });
                    ops.push(Ir1Op::EndTry);
                    if let Some(finalizer) = &tc.finalizer {
                        lower_lexical_statement_sequence(
                            &finalizer.body,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            scope_id,
                            label_counter,
                            control_flow,
                        )?;
                    }
                    ops.push(Ir1Op::Jump {
                        label_id: actual_break_label,
                    });
                }
                if let (Some(via_continue_label), Some(actual_continue_label)) =
                    (try_continue_forwarder, control_flow.continue_label)
                {
                    ops.push(Ir1Op::Label {
                        id: via_continue_label,
                    });
                    ops.push(Ir1Op::EndTry);
                    if let Some(finalizer) = &tc.finalizer {
                        lower_lexical_statement_sequence(
                            &finalizer.body,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            scope_id,
                            label_counter,
                            control_flow,
                        )?;
                    }
                    ops.push(Ir1Op::Jump {
                        label_id: actual_continue_label,
                    });
                }
                ops.push(Ir1Op::Label {
                    id: normal_try_complete_label,
                });
            }
            ops.push(Ir1Op::EndTry);
            // Normal completion: jump past catch to finally (or end).
            let after_try_target = finally_label.unwrap_or(end_label);
            ops.push(Ir1Op::Jump {
                label_id: after_try_target,
            });
            // Emit catch handler section only when there is a real handler.
            // When catch_label == finally_label (try/finally with no catch),
            // exceptions route directly to the finally block and we must NOT
            // emit EnterCatch which would consume the pending exception.
            if tc.handler.is_some() {
                ops.push(Ir1Op::Label { id: catch_label });
                let catch_requires_finally_guard = finally_label.is_some();
                if let Some(finally_guard_label) = finally_label {
                    // A throw inside `catch` must still execute the enclosing
                    // `finally` block before propagating outward. Guard the
                    // catch body with a nested try/finally-without-catch so
                    // rethrows route directly to the finalizer label.
                    ops.push(Ir1Op::BeginTry {
                        catch_label: finally_guard_label,
                        finally_label: Some(finally_guard_label),
                    });
                }
                if let Some(handler) = &tc.handler {
                    let catch_enclosing_bindings = reserve_block_lexical_bindings(
                        &handler.body.body,
                        handler.parameter.as_deref(),
                        binding_lookup,
                        binding_index,
                    );
                    let catch_result = (|| -> Result<(), LoweringPipelineError> {
                        if let Some(param) = &handler.parameter {
                            let bid = alloc_binding(
                                bindings,
                                binding_lookup,
                                binding_index,
                                scope_id,
                                param,
                                BindingKind::Let,
                            )
                            .map_err(LoweringPipelineError::SemanticViolation)?;
                            ops.push(Ir1Op::StoreBinding { binding_id: bid });
                            ops.push(Ir1Op::Pop);
                        } else {
                            // The exception is pushed onto the stack by EnterCatch.
                            // We must pop it so the stack remains balanced.
                            ops.push(Ir1Op::Pop);
                        }
                        for inner in &handler.body.body {
                            lower_statement_to_ir1_with_flow(
                                inner,
                                ops,
                                bindings,
                                binding_lookup,
                                binding_index,
                                scope_id,
                                label_counter,
                                catch_control_flow,
                            )?;
                        }
                        Ok(())
                    })();
                    restore_block_lexical_bindings(binding_lookup, catch_enclosing_bindings);
                    catch_result?;
                }
                if catch_requires_finally_guard {
                    let has_catch_abrupt_forwarders =
                        catch_break_forwarder.is_some() || catch_continue_forwarder.is_some();
                    let normal_catch_complete_label =
                        has_catch_abrupt_forwarders.then(|| alloc_label(label_counter));
                    if let Some(normal_catch_complete_label) = normal_catch_complete_label {
                        ops.push(Ir1Op::Jump {
                            label_id: normal_catch_complete_label,
                        });
                        if let (Some(via_break_label), Some(actual_break_label)) =
                            (catch_break_forwarder, control_flow.break_label)
                        {
                            ops.push(Ir1Op::Label {
                                id: via_break_label,
                            });
                            ops.push(Ir1Op::EndTry);
                            if let Some(finalizer) = &tc.finalizer {
                                lower_lexical_statement_sequence(
                                    &finalizer.body,
                                    ops,
                                    bindings,
                                    binding_lookup,
                                    binding_index,
                                    scope_id,
                                    label_counter,
                                    control_flow,
                                )?;
                            }
                            ops.push(Ir1Op::Jump {
                                label_id: actual_break_label,
                            });
                        }
                        if let (Some(via_continue_label), Some(actual_continue_label)) =
                            (catch_continue_forwarder, control_flow.continue_label)
                        {
                            ops.push(Ir1Op::Label {
                                id: via_continue_label,
                            });
                            ops.push(Ir1Op::EndTry);
                            if let Some(finalizer) = &tc.finalizer {
                                lower_lexical_statement_sequence(
                                    &finalizer.body,
                                    ops,
                                    bindings,
                                    binding_lookup,
                                    binding_index,
                                    scope_id,
                                    label_counter,
                                    control_flow,
                                )?;
                            }
                            ops.push(Ir1Op::Jump {
                                label_id: actual_continue_label,
                            });
                        }
                        ops.push(Ir1Op::Label {
                            id: normal_catch_complete_label,
                        });
                    }
                    ops.push(Ir1Op::EndTry);
                    // After catch: enter the same finally block used by the
                    // surrounding try. The nested guard ensures abrupt exits
                    // from the catch body also land there.
                    ops.push(Ir1Op::Jump {
                        label_id: after_try_target,
                    });
                }
            }
            // The forwarder copies above run after EndTry and therefore have
            // no in-flight completion. The canonical finalizer below is
            // different: break/continue issued after EnterFinally must discard
            // the completion that caused entry before leaving the block.
            if let Some(finalizer) = &tc.finalizer {
                let fl = finally_label.ok_or(LoweringPipelineError::InvariantViolation {
                    detail: "Finalizer missing lowering label",
                })?;
                let finalizer_break_forwarder =
                    control_flow.break_label.map(|_| alloc_label(label_counter));
                let finalizer_continue_forwarder = control_flow
                    .continue_label
                    .map(|_| alloc_label(label_counter));
                let finalizer_control_flow = ControlFlowTargets {
                    break_label: finalizer_break_forwarder.or(control_flow.break_label),
                    continue_label: finalizer_continue_forwarder.or(control_flow.continue_label),
                };
                ops.push(Ir1Op::Label { id: fl });
                ops.push(Ir1Op::EnterFinally);
                lower_lexical_statement_sequence(
                    &finalizer.body,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    finalizer_control_flow,
                )?;
                let has_finalizer_abrupt_forwarders =
                    finalizer_break_forwarder.is_some() || finalizer_continue_forwarder.is_some();
                let normal_finally_complete_label =
                    has_finalizer_abrupt_forwarders.then(|| alloc_label(label_counter));
                if let Some(normal_finally_complete_label) = normal_finally_complete_label {
                    ops.push(Ir1Op::Jump {
                        label_id: normal_finally_complete_label,
                    });
                    if let (Some(via_break_label), Some(actual_break_label)) =
                        (finalizer_break_forwarder, control_flow.break_label)
                    {
                        ops.push(Ir1Op::Label {
                            id: via_break_label,
                        });
                        ops.push(Ir1Op::DiscardAbruptCompletion);
                        ops.push(Ir1Op::Jump {
                            label_id: actual_break_label,
                        });
                    }
                    if let (Some(via_continue_label), Some(actual_continue_label)) =
                        (finalizer_continue_forwarder, control_flow.continue_label)
                    {
                        ops.push(Ir1Op::Label {
                            id: via_continue_label,
                        });
                        ops.push(Ir1Op::DiscardAbruptCompletion);
                        ops.push(Ir1Op::Jump {
                            label_id: actual_continue_label,
                        });
                    }
                    ops.push(Ir1Op::Label {
                        id: normal_finally_complete_label,
                    });
                }
                ops.push(Ir1Op::EndFinally);
                ops.push(Ir1Op::Jump {
                    label_id: end_label,
                });
            }
            ops.push(Ir1Op::Label { id: end_label });
        }
        Statement::Switch(switch_stmt) => {
            lower_switch_to_ir1(
                switch_stmt,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
                control_flow,
            )?;
        }
        Statement::Break(brk) => {
            if let Some(label) = &brk.label {
                return Err(LoweringPipelineError::SemanticViolation(
                    SemanticError::new(
                        SemanticErrorCode::UndefinedLabel,
                        Some(label.clone()),
                        Some(brk.span.clone()),
                    ),
                ));
            }
            let label_id = control_flow.break_label.ok_or_else(|| {
                LoweringPipelineError::SemanticViolation(SemanticError::new(
                    SemanticErrorCode::IllegalBreak,
                    None,
                    Some(brk.span.clone()),
                ))
            })?;
            ops.push(Ir1Op::Jump { label_id });
        }
        Statement::Continue(cont) => {
            if let Some(label) = &cont.label {
                return Err(LoweringPipelineError::SemanticViolation(
                    SemanticError::new(
                        SemanticErrorCode::UndefinedLabel,
                        Some(label.clone()),
                        Some(cont.span.clone()),
                    ),
                ));
            }
            let label_id = control_flow.continue_label.ok_or_else(|| {
                LoweringPipelineError::SemanticViolation(SemanticError::new(
                    SemanticErrorCode::IllegalContinue,
                    None,
                    Some(cont.span.clone()),
                ))
            })?;
            ops.push(Ir1Op::Jump { label_id });
        }
        Statement::FunctionDeclaration(func) => {
            let name = func.name.clone().unwrap_or_else(|| "anonymous".to_string());
            let bid = alloc_binding(
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                &name,
                BindingKind::Var,
            )
            .map_err(LoweringPipelineError::SemanticViolation)?;

            // Lower function body with its own fresh scope.
            let mut body_ops = Vec::new();
            let mut body_bindings = Vec::new();
            let mut body_lookup = BTreeMap::new();
            let mut body_binding_index: BindingId = 0;
            let body_scope = ScopeId { depth: 0, index: 0 };
            let mut body_label_counter: u32 = 0;
            let FunctionParameterPlan {
                param_names,
                destructure_params,
                rest_param_index,
            } = allocate_function_parameter_bindings(
                &func.params,
                &mut body_bindings,
                &mut body_lookup,
                &mut body_binding_index,
                body_scope,
            )?;
            if rest_param_index.is_some() && func.is_generator {
                return Err(unsupported_frontier_expression_error(
                    "generator_rest_parameters",
                    "FE-LOWER-UNSUPPORTED-GENERATOR-REST-0001",
                    "core.generator_rest_parameter_runtime",
                    "generator rest parameters require suspended-frame argument persistence",
                    Some(func.span.clone()),
                ));
            }
            let parameter_binding_names = body_lookup.keys().cloned().collect();
            let parameter_prologue_captures = lower_function_parameter_prologue(
                &destructure_params,
                binding_lookup,
                &mut body_ops,
                &mut body_bindings,
                &body_lookup,
                &mut body_binding_index,
                body_scope,
                &mut body_label_counter,
            )?;
            reject_self_referential_parameter_capture(
                &parameter_prologue_captures,
                &name,
                func.span.clone(),
            )?;
            let pre_lower_names = prepare_function_body_bindings(
                Some(&func.body.body),
                parameter_binding_names,
                &mut body_lookup,
                &mut body_binding_index,
            );
            merge_unshadowed_parameter_prologue_captures(
                &parameter_prologue_captures,
                &mut body_lookup,
            );
            seed_function_outer_static_bindings(
                binding_lookup,
                &mut body_lookup,
                &mut body_binding_index,
            );
            for stmt in &func.body.body {
                lower_statement_to_ir1(
                    stmt,
                    &mut body_ops,
                    &mut body_bindings,
                    &mut body_lookup,
                    &mut body_binding_index,
                    body_scope,
                    &mut body_label_counter,
                )?;
            }
            // Ensure body ends with a return.
            if !matches!(body_ops.last(), Some(Ir1Op::Return)) {
                body_ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                });
                body_ops.push(Ir1Op::Return);
            }

            // Identify free variables: bindings created as forward
            // references that exist in the OUTER scope's lookup. Capture the
            // body binding-id alongside the name so the deferred IR3 pass can
            // resolve them exactly (bd-snlhk; mirrors the engine fix).
            let (mut free_vars, mut free_var_ids, mut free_var_outer_ids) = collect_free_vars(
                &body_lookup,
                &pre_lower_names,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
            );
            append_shadowed_parameter_prologue_captures(
                &parameter_prologue_captures,
                &mut free_vars,
                &mut free_var_ids,
                &mut free_var_outer_ids,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
            );

            ops.push(Ir1Op::DeclareFunction {
                name,
                binding_id: bid,
                param_names,
                body_ops,
                free_vars,
                free_var_ids,
                free_var_outer_ids,
                is_generator: func.is_generator,
                rest_param_index,
            });
            ops.push(Ir1Op::Pop);
        }
        Statement::ClassDeclaration(cls) => {
            let class_name = cls.name.clone().unwrap_or_else(|| "anonymous".to_string());
            // Find the constructor method, if any.
            let constructor = cls.body.iter().find(|m| m.kind == MethodKind::Constructor);
            // Lower constructor as a function declaration.
            let mut body_ops = Vec::new();
            let mut body_bindings = Vec::new();
            let mut body_lookup = BTreeMap::new();
            let mut body_binding_index: BindingId = 0;
            let body_scope = ScopeId { depth: 0, index: 0 };
            let mut body_label_counter: u32 = 0;
            let FunctionParameterPlan {
                param_names,
                destructure_params,
                rest_param_index,
            } = if let Some(ctor) = constructor {
                allocate_function_parameter_bindings(
                    &ctor.params,
                    &mut body_bindings,
                    &mut body_lookup,
                    &mut body_binding_index,
                    body_scope,
                )?
            } else {
                FunctionParameterPlan::default()
            };
            let parameter_binding_names = body_lookup.keys().cloned().collect();
            let parameter_prologue_captures = lower_function_parameter_prologue(
                &destructure_params,
                binding_lookup,
                &mut body_ops,
                &mut body_bindings,
                &body_lookup,
                &mut body_binding_index,
                body_scope,
                &mut body_label_counter,
            )?;
            reject_self_referential_parameter_capture(
                &parameter_prologue_captures,
                &class_name,
                cls.span.clone(),
            )?;
            let ctor_pre_lower_names = if let Some(ctor) = constructor {
                let pre_lower_names = prepare_function_body_bindings(
                    Some(&ctor.body.body),
                    parameter_binding_names,
                    &mut body_lookup,
                    &mut body_binding_index,
                );
                merge_unshadowed_parameter_prologue_captures(
                    &parameter_prologue_captures,
                    &mut body_lookup,
                );
                seed_function_outer_static_bindings(
                    binding_lookup,
                    &mut body_lookup,
                    &mut body_binding_index,
                );
                for stmt in &ctor.body.body {
                    lower_statement_to_ir1(
                        stmt,
                        &mut body_ops,
                        &mut body_bindings,
                        &mut body_lookup,
                        &mut body_binding_index,
                        body_scope,
                        &mut body_label_counter,
                    )?;
                }
                pre_lower_names
            } else {
                body_lookup.keys().cloned().collect()
            };
            if !matches!(body_ops.last(), Some(Ir1Op::Return)) {
                body_ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                });
                body_ops.push(Ir1Op::Return);
            }
            let (mut ctor_free_vars, mut ctor_free_var_ids, mut ctor_free_var_outer_ids) =
                collect_free_vars(
                    &body_lookup,
                    &ctor_pre_lower_names,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                );
            append_shadowed_parameter_prologue_captures(
                &parameter_prologue_captures,
                &mut ctor_free_vars,
                &mut ctor_free_var_ids,
                &mut ctor_free_var_outer_ids,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
            );
            let bid = alloc_binding(
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                &class_name,
                BindingKind::Let,
            )
            .map_err(LoweringPipelineError::SemanticViolation)?;
            ops.push(Ir1Op::DeclareFunction {
                name: class_name,
                binding_id: bid,
                param_names,
                body_ops,
                free_vars: ctor_free_vars,
                free_var_ids: ctor_free_var_ids,
                free_var_outer_ids: ctor_free_var_outer_ids,
                is_generator: false,
                rest_param_index,
            });

            // Set up inheritance if this class extends another
            if let Some(super_class) = &cls.super_class {
                // Record parent constructor for constructor-frame `super()`.
                ops.push(Ir1Op::LoadBinding { binding_id: bid });
                lower_expression_to_ir1(
                    super_class,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::SetProperty {
                    key: Ir1PropertyKey::Static(IR_SUPER_CONSTRUCTOR_PROPERTY.to_string()),
                });

                // Load child constructor (our class)
                ops.push(Ir1Op::LoadBinding { binding_id: bid });
                ops.push(Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static("prototype".to_string()),
                });

                // Load parent constructor
                lower_expression_to_ir1(
                    super_class,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static("prototype".to_string()),
                });

                // Set Child.prototype.__proto__ = Parent.prototype
                ops.push(Ir1Op::SetProperty {
                    key: Ir1PropertyKey::Static("__proto__".to_string()),
                });
                ops.push(Ir1Op::Pop);
            }

            // Attach non-constructor methods to the constructor's prototype.
            // Static methods go on the constructor itself.
            for method in cls
                .body
                .iter()
                .filter(|m| m.kind != MethodKind::Constructor)
            {
                let method_name = match &method.key {
                    Expression::Identifier(name) => name.clone(),
                    Expression::StringLiteral(s) => s.clone(),
                    _ => "anonymous_method".to_string(),
                };

                // Lower method body with its own scope.
                let mut m_body_ops = Vec::new();
                let mut m_bindings = Vec::new();
                let mut m_lookup = BTreeMap::new();
                let mut m_binding_index: BindingId = 0;
                let m_scope = ScopeId { depth: 0, index: 0 };
                let mut m_label_counter: u32 = 0;
                let FunctionParameterPlan {
                    param_names: m_param_names,
                    destructure_params: m_destructure_params,
                    rest_param_index: m_rest_param_index,
                } = allocate_function_parameter_bindings(
                    &method.params,
                    &mut m_bindings,
                    &mut m_lookup,
                    &mut m_binding_index,
                    m_scope,
                )?;
                if m_rest_param_index.is_some()
                    && matches!(method.kind, MethodKind::Get | MethodKind::Set)
                {
                    return Err(unsupported_frontier_expression_error(
                        "accessor_rest_parameters",
                        "FE-LOWER-UNSUPPORTED-ACCESSOR-REST-0001",
                        "core.accessor_rest_parameter_runtime",
                        "getter and setter functions cannot declare rest parameters",
                        Some(method.span.clone()),
                    ));
                }
                let parameter_binding_names = m_lookup.keys().cloned().collect();
                let parameter_prologue_captures = lower_function_parameter_prologue(
                    &m_destructure_params,
                    binding_lookup,
                    &mut m_body_ops,
                    &mut m_bindings,
                    &m_lookup,
                    &mut m_binding_index,
                    m_scope,
                    &mut m_label_counter,
                )?;
                let method_pre_lower_names = prepare_function_body_bindings(
                    Some(&method.body.body),
                    parameter_binding_names,
                    &mut m_lookup,
                    &mut m_binding_index,
                );
                merge_unshadowed_parameter_prologue_captures(
                    &parameter_prologue_captures,
                    &mut m_lookup,
                );
                seed_function_outer_static_bindings(
                    binding_lookup,
                    &mut m_lookup,
                    &mut m_binding_index,
                );
                for stmt in &method.body.body {
                    lower_statement_to_ir1(
                        stmt,
                        &mut m_body_ops,
                        &mut m_bindings,
                        &mut m_lookup,
                        &mut m_binding_index,
                        m_scope,
                        &mut m_label_counter,
                    )?;
                }
                if !matches!(m_body_ops.last(), Some(Ir1Op::Return)) {
                    m_body_ops.push(Ir1Op::LoadLiteral {
                        value: Ir1Literal::Undefined,
                    });
                    m_body_ops.push(Ir1Op::Return);
                }
                let (mut method_free_vars, mut method_free_var_ids, mut method_free_var_outer_ids) =
                    collect_free_vars(
                        &m_lookup,
                        &method_pre_lower_names,
                        bindings,
                        binding_lookup,
                        binding_index,
                        scope_id,
                    );
                append_shadowed_parameter_prologue_captures(
                    &parameter_prologue_captures,
                    &mut method_free_vars,
                    &mut method_free_var_ids,
                    &mut method_free_var_outer_ids,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                );
                let method_super_binding = if cls.super_class.is_some() {
                    Some(alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        scope_id,
                        "class_method_super",
                    )?)
                } else {
                    None
                };

                // Push target object: prototype for instance methods,
                // constructor for static methods.
                ops.push(Ir1Op::LoadBinding { binding_id: bid });
                if !method.is_static {
                    ops.push(Ir1Op::GetProperty {
                        key: Ir1PropertyKey::Static("prototype".to_string()),
                    });
                }

                // Push the method function value.
                ops.push(Ir1Op::CreateFunction {
                    name: Some(method_name.clone()),
                    param_names: m_param_names,
                    body_ops: m_body_ops,
                    free_vars: method_free_vars,
                    free_var_ids: method_free_var_ids,
                    free_var_outer_ids: method_free_var_outer_ids,
                    is_generator: false,
                    is_arrow: false,
                    rest_param_index: m_rest_param_index,
                });
                if let Some(method_binding) = method_super_binding {
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: method_binding,
                    });
                }

                let property_key = match method.kind {
                    MethodKind::Get => format!("{IR_ACCESSOR_GET_PREFIX}{method_name}"),
                    MethodKind::Set => format!("{IR_ACCESSOR_SET_PREFIX}{method_name}"),
                    MethodKind::Method | MethodKind::Constructor => method_name,
                };

                // SetProperty pops value (top), then object (next).
                // Stack is now: [target_obj, method_fn]
                ops.push(Ir1Op::SetProperty {
                    key: Ir1PropertyKey::Static(property_key),
                });
                if let (Some(super_class), Some(method_binding)) =
                    (&cls.super_class, method_super_binding)
                {
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: method_binding,
                    });
                    lower_expression_to_ir1(
                        super_class,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        scope_id,
                        label_counter,
                    )?;
                    if !method.is_static {
                        ops.push(Ir1Op::GetProperty {
                            key: Ir1PropertyKey::Static("prototype".to_string()),
                        });
                    }
                    ops.push(Ir1Op::SetProperty {
                        key: Ir1PropertyKey::Static(IR_SUPER_PROTOTYPE_PROPERTY.to_string()),
                    });
                }
                // Do not emit Pop here: module-level Pop updates the script
                // completion register and can clobber the class binding when
                // the constructor lives in register 0.
            }
        }
        Statement::Import(_) | Statement::Export(_) => {
            // Handled at top level only.
            ops.push(Ir1Op::Nop);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lower_switch_to_ir1(
    switch_stmt: &crate::ast::SwitchStatement,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    label_counter: &mut u32,
    control_flow: ControlFlowTargets,
) -> Result<(), LoweringPipelineError> {
    lower_expression_to_ir1(
        &switch_stmt.discriminant,
        ops,
        bindings,
        binding_lookup,
        binding_index,
        scope_id,
        label_counter,
    )?;
    let discriminant_binding_name =
        make_internal_binding_name("switch_discriminant", *binding_index);
    let discriminant_binding = alloc_binding(
        bindings,
        binding_lookup,
        binding_index,
        scope_id,
        &discriminant_binding_name,
        BindingKind::Let,
    )
    .map_err(LoweringPipelineError::SemanticViolation)?;
    ops.push(Ir1Op::StoreBinding {
        binding_id: discriminant_binding,
    });

    let switch_body = switch_stmt
        .cases
        .iter()
        .flat_map(|case| case.consequent.iter().cloned())
        .collect::<Vec<_>>();
    let switch_enclosing_bindings =
        reserve_block_lexical_bindings(&switch_body, None, binding_lookup, binding_index);
    let switch_result = (|| -> Result<(), LoweringPipelineError> {
        let end_label = alloc_label(label_counter);
        let case_labels: Vec<u32> = (0..switch_stmt.cases.len())
            .map(|_| alloc_label(label_counter))
            .collect();
        let mut default_label = None;

        for (case, case_label) in switch_stmt.cases.iter().zip(case_labels.iter().copied()) {
            if let Some(test) = &case.test {
                ops.push(Ir1Op::LoadBinding {
                    binding_id: discriminant_binding,
                });
                lower_expression_to_ir1(
                    test,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::BinaryOp {
                    operator: BinaryOperator::StrictEqual,
                });
                let next_case_label = alloc_label(label_counter);
                ops.push(Ir1Op::JumpIfFalsy {
                    label_id: next_case_label,
                });
                ops.push(Ir1Op::Pop);
                ops.push(Ir1Op::Jump {
                    label_id: case_label,
                });
                ops.push(Ir1Op::Label {
                    id: next_case_label,
                });
            } else {
                default_label = Some(case_label);
            }
        }

        ops.push(Ir1Op::Jump {
            label_id: default_label.unwrap_or(end_label),
        });

        let switch_flow = ControlFlowTargets {
            break_label: Some(end_label),
            continue_label: control_flow.continue_label,
        };
        for (case, case_label) in switch_stmt.cases.iter().zip(case_labels.iter().copied()) {
            ops.push(Ir1Op::Label { id: case_label });
            for body_stmt in &case.consequent {
                lower_statement_to_ir1_with_flow(
                    body_stmt,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    switch_flow,
                )?;
            }
        }

        ops.push(Ir1Op::Label { id: end_label });
        Ok(())
    })();
    restore_block_lexical_bindings(binding_lookup, switch_enclosing_bindings);
    switch_result
}

/// Synthetic names never denote source-level bindings and therefore must not
/// be promoted through enclosing closure scopes.
fn is_internal_lowering_binding(name: &str) -> bool {
    name.starts_with("<internal:")
        || name.starts_with("@@franken_internal_")
        || name.starts_with('\0')
}

/// Collect free variables of a function body: names present in the body's
/// binding lookup that were NOT declared by the body itself (params /
/// pre-lowered names). If a name is not yet present in the immediate outer
/// lookup, reserve an exact forward binding there before recording the child
/// capture. As recursive lowering unwinds, the intermediate function's own
/// collection promotes that same binding one scope farther outward. This is
/// what lets `outer -> middle -> inner -> x` capture `x` even when `middle`
/// never references it directly (bd-x0ld5).
///
/// Returns names paired index-wise with both their body-scope and immediate
/// outer-scope binding ids, so downstream passes never reconstruct capture
/// identity heuristically (bd-snlhk; mirrors the engine's bd-g0aok fix).
fn collect_free_vars(
    body_lookup: &BTreeMap<String, BindingId>,
    pre_lower_names: &BTreeSet<String>,
    outer_bindings: &mut Vec<ResolvedBinding>,
    outer_lookup: &mut BTreeMap<String, BindingId>,
    outer_binding_index: &mut BindingId,
    outer_scope: ScopeId,
) -> (Vec<String>, Vec<BindingId>, Vec<BindingId>) {
    let mut names = Vec::new();
    let mut body_ids = Vec::new();
    let mut outer_ids = Vec::new();
    for (name, id) in body_lookup.iter() {
        if pre_lower_names.contains(name.as_str()) || is_internal_lowering_binding(name) {
            continue;
        }
        let outer_id = if let Some(outer_id) = outer_lookup.get(name.as_str()) {
            *outer_id
        } else {
            let outer_id = *outer_binding_index;
            *outer_binding_index = outer_binding_index.saturating_add(1);
            outer_bindings.push(ResolvedBinding {
                name: name.clone(),
                binding_id: outer_id,
                scope: outer_scope,
                kind: BindingKind::Let,
            });
            outer_lookup.insert(name.clone(), outer_id);
            outer_id
        };
        names.push(name.clone());
        body_ids.push(*id);
        outer_ids.push(outer_id);
    }
    (names, body_ids, outer_ids)
}

/// Parameter defaults execute in a distinct environment. Most of their
/// captures are also visible to the body and are collected normally; a body
/// declaration with the same name deliberately hides one from `body_lookup`.
/// Preserve those shadowed capture binding IDs explicitly so the prologue's
/// `LoadBinding` still resolves to the outer environment.
#[allow(clippy::too_many_arguments)]
fn append_shadowed_parameter_prologue_captures(
    captures: &[(String, BindingId)],
    names: &mut Vec<String>,
    body_ids: &mut Vec<BindingId>,
    outer_ids: &mut Vec<BindingId>,
    outer_bindings: &mut Vec<ResolvedBinding>,
    outer_lookup: &mut BTreeMap<String, BindingId>,
    outer_binding_index: &mut BindingId,
    outer_scope: ScopeId,
) {
    for (name, body_id) in captures {
        if body_ids.contains(body_id) {
            continue;
        }
        let outer_id = if let Some(outer_id) = outer_lookup.get(name) {
            *outer_id
        } else {
            let outer_id = *outer_binding_index;
            *outer_binding_index = outer_binding_index.saturating_add(1);
            outer_bindings.push(ResolvedBinding {
                name: name.clone(),
                binding_id: outer_id,
                scope: outer_scope,
                kind: BindingKind::Let,
            });
            outer_lookup.insert(name.clone(), outer_id);
            outer_id
        };
        names.push(name.clone());
        body_ids.push(*body_id);
        outer_ids.push(outer_id);
    }
}

fn binding_kind_for_variable_declaration(kind: VariableDeclarationKind) -> BindingKind {
    match kind {
        VariableDeclarationKind::Var => BindingKind::Var,
        VariableDeclarationKind::Let => BindingKind::Let,
        VariableDeclarationKind::Const => BindingKind::Const,
    }
}

fn nested_function_body(op: &Ir1Op) -> Option<&[Ir1Op]> {
    match op {
        Ir1Op::DeclareFunction { body_ops, .. } | Ir1Op::CreateFunction { body_ops, .. } => {
            Some(body_ops)
        }
        _ => None,
    }
}

/// Classify every operation nested in a function body while keeping its
/// enclosing top-level IR2 index. Flow inference is reset for each function
/// frame so labels cannot leak between unrelated bodies.
fn collect_nested_ir2_analysis(
    top_level_ops: &[Ir1Op],
) -> (Vec<NestedIr2AnalysisSite>, FlowInferenceMetrics) {
    fn visit_body(
        body_ops: &[Ir1Op],
        top_level_index: usize,
        path_prefix: &mut Vec<usize>,
        sites: &mut Vec<NestedIr2AnalysisSite>,
        metrics: &mut FlowInferenceMetrics,
    ) {
        let mut classified = body_ops
            .iter()
            .map(|op| {
                let (effect, required_capability, flow) = classify_ir1_op(op);
                Ir2Op {
                    inner: op.clone(),
                    effect,
                    required_capability,
                    flow,
                }
            })
            .collect::<Vec<_>>();
        metrics.include(infer_ir2_flow_annotations_for_ops(&mut classified));

        for (body_index, op) in classified.into_iter().enumerate() {
            path_prefix.push(body_index);
            sites.push(NestedIr2AnalysisSite {
                op_index: top_level_index,
                body_path: path_prefix.clone(),
                op: op.clone(),
            });
            if let Some(nested_body) = nested_function_body(&op.inner) {
                visit_body(nested_body, top_level_index, path_prefix, sites, metrics);
            }
            path_prefix.pop();
        }
    }

    let mut sites = Vec::new();
    let mut metrics = FlowInferenceMetrics::default();
    for (top_level_index, op) in top_level_ops.iter().enumerate() {
        if let Some(body_ops) = nested_function_body(op) {
            visit_body(
                body_ops,
                top_level_index,
                &mut Vec::new(),
                &mut sites,
                &mut metrics,
            );
        }
    }
    (sites, metrics)
}

pub fn lower_ir1_to_ir2(
    ir1: &Ir1Module,
) -> Result<LoweringPassResult<Ir2Module>, LoweringPipelineError> {
    let ir1_hash = ir1.content_hash();
    let mut ir2 = Ir2Module::new(ir1_hash, ir1.header.source_label.clone());
    ir2.scopes = ir1.scopes.clone();

    let mut required_capabilities = BTreeSet::<String>::new();
    for op in &ir1.ops {
        let (effect, required_capability, flow) = classify_ir1_op(op);
        if let Some(capability) = &required_capability {
            required_capabilities.insert(capability.0.clone());
        }
        ir2.ops.push(Ir2Op {
            inner: op.clone(),
            effect,
            required_capability,
            flow,
        });
    }
    let (nested_sites, nested_flow_metrics) = collect_nested_ir2_analysis(&ir1.ops);
    for site in &nested_sites {
        if let Some(capability) = &site.op.required_capability {
            required_capabilities.insert(capability.0.clone());
        }
    }
    ir2.required_capabilities = required_capabilities
        .into_iter()
        .map(CapabilityTag)
        .collect();
    let mut flow_metrics = infer_ir2_flow_annotations(&mut ir2);
    flow_metrics.include(nested_flow_metrics);

    let source_hash_matches = ir2.header.source_hash.as_ref() == Some(&ir1_hash);
    let hostcall_effects_have_capability = ir2
        .ops
        .iter()
        .filter(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
        .all(|op| op.required_capability.is_some())
        && nested_sites
            .iter()
            .filter(|site| matches!(site.op.effect, EffectBoundary::HostcallEffect))
            .all(|site| site.op.required_capability.is_some());
    let flow_metrics_consistent = flow_metrics.static_proven_ops + flow_metrics.runtime_check_ops
        == flow_metrics.total_flow_ops;
    let static_coverage_millionths = flow_metrics.static_coverage_millionths();
    let checks = vec![
        InvariantCheck {
            name: "source_hash_linkage".to_string(),
            passed: source_hash_matches,
            detail: "IR2 source_hash references IR1 hash".to_string(),
        },
        InvariantCheck {
            name: "hostcall_capability_required".to_string(),
            passed: hostcall_effects_have_capability,
            detail: "Hostcall effects always carry capability tags".to_string(),
        },
        InvariantCheck {
            name: "ir2_flow_metrics_consistent".to_string(),
            passed: flow_metrics_consistent,
            detail: format!(
                "flow_ops={} static_proven={} runtime_checks={}",
                flow_metrics.total_flow_ops,
                flow_metrics.static_proven_ops,
                flow_metrics.runtime_check_ops
            ),
        },
        InvariantCheck {
            name: "ir2_static_flow_coverage_ratio".to_string(),
            passed: true,
            detail: format!(
                "static_coverage_millionths={} static_proven={} total_flow_ops={}",
                static_coverage_millionths,
                flow_metrics.static_proven_ops,
                flow_metrics.total_flow_ops
            ),
        },
    ];
    ensure_checks_pass(&checks, "IR2 invariants failed")?;

    let ir2_hash = ir2.content_hash();
    Ok(LoweringPassResult {
        ledger_entry: IsomorphismLedgerEntry {
            pass_id: "ir1_to_ir2".to_string(),
            input_hash: hash_string(&ir1_hash),
            output_hash: hash_string(&ir2_hash),
            input_op_count: ir1.ops.len() as u64,
            output_op_count: ir2.ops.len() as u64,
        },
        witness: PassWitness {
            pass_id: "ir1_to_ir2".to_string(),
            input_hash: hash_string(&ir1_hash),
            output_hash: hash_string(&ir2_hash),
            rollback_token: hash_string(&ir1_hash),
            invariant_checks: checks,
        },
        module: ir2,
    })
}

// ── Operator → IR3 instruction helpers (shared by main + function-body lowering) ──

fn lower_binary_op_to_ir3(
    operator: BinaryOperator,
    dst: Reg,
    lhs: Reg,
    rhs: Reg,
) -> Ir3Instruction {
    match operator {
        BinaryOperator::Add => Ir3Instruction::Add { dst, lhs, rhs },
        BinaryOperator::Subtract => Ir3Instruction::Sub { dst, lhs, rhs },
        BinaryOperator::Multiply => Ir3Instruction::Mul { dst, lhs, rhs },
        BinaryOperator::Divide => Ir3Instruction::Div { dst, lhs, rhs },
        BinaryOperator::Remainder => Ir3Instruction::Mod { dst, lhs, rhs },
        BinaryOperator::Exponentiate => Ir3Instruction::Exp { dst, lhs, rhs },
        BinaryOperator::LessThan => Ir3Instruction::Lt { dst, lhs, rhs },
        BinaryOperator::LessThanOrEqual => Ir3Instruction::Lte { dst, lhs, rhs },
        BinaryOperator::GreaterThan => Ir3Instruction::Gt { dst, lhs, rhs },
        BinaryOperator::GreaterThanOrEqual => Ir3Instruction::Gte { dst, lhs, rhs },
        BinaryOperator::Equal => Ir3Instruction::Eq { dst, lhs, rhs },
        BinaryOperator::StrictEqual => Ir3Instruction::StrictEq { dst, lhs, rhs },
        BinaryOperator::NotEqual => Ir3Instruction::NotEq { dst, lhs, rhs },
        BinaryOperator::StrictNotEqual => Ir3Instruction::StrictNotEq { dst, lhs, rhs },
        BinaryOperator::BitwiseAnd => Ir3Instruction::BitAnd { dst, lhs, rhs },
        BinaryOperator::BitwiseOr => Ir3Instruction::BitOr { dst, lhs, rhs },
        BinaryOperator::BitwiseXor => Ir3Instruction::BitXor { dst, lhs, rhs },
        BinaryOperator::LeftShift => Ir3Instruction::Shl { dst, lhs, rhs },
        BinaryOperator::RightShift => Ir3Instruction::Shr { dst, lhs, rhs },
        BinaryOperator::UnsignedRightShift => Ir3Instruction::Ushr { dst, lhs, rhs },
        BinaryOperator::Instanceof => Ir3Instruction::InstanceOf { dst, lhs, rhs },
        BinaryOperator::In => Ir3Instruction::InOp { dst, lhs, rhs },
        // Logical operators should be lowered to short-circuit form before
        // reaching this helper.  Fall back to a no-op move for safety.
        BinaryOperator::LogicalAnd
        | BinaryOperator::LogicalOr
        | BinaryOperator::NullishCoalescing => Ir3Instruction::Move { dst, src: lhs },
    }
}

fn lower_unary_op_to_ir3(operator: UnaryOperator, dst: Reg, src: Reg) -> Ir3Instruction {
    match operator {
        UnaryOperator::Negate => Ir3Instruction::UnaryNeg { dst, src },
        UnaryOperator::BitwiseNot => Ir3Instruction::BitNot { dst, src },
        UnaryOperator::LogicalNot => Ir3Instruction::LogicalNot { dst, src },
        UnaryOperator::Typeof => Ir3Instruction::TypeOf { dst, src },
        UnaryOperator::Void => Ir3Instruction::Void { dst, src },
        UnaryOperator::UnaryPlus => Ir3Instruction::UnaryPlus { dst, src },
        // delete is lowered through DeleteProperty before reaching here.
        UnaryOperator::Delete => Ir3Instruction::LoadBool { dst, value: true },
    }
}

fn lower_assign_op_to_ir3(
    operator: AssignmentOperator,
    dst: Reg,
    lhs: Reg,
    rhs: Reg,
) -> Ir3Instruction {
    match operator {
        AssignmentOperator::Assign => Ir3Instruction::Move { dst, src: rhs },
        AssignmentOperator::AddAssign => Ir3Instruction::Add { dst, lhs, rhs },
        AssignmentOperator::SubtractAssign => Ir3Instruction::Sub { dst, lhs, rhs },
        AssignmentOperator::MultiplyAssign => Ir3Instruction::Mul { dst, lhs, rhs },
        AssignmentOperator::DivideAssign => Ir3Instruction::Div { dst, lhs, rhs },
        AssignmentOperator::RemainderAssign => Ir3Instruction::Mod { dst, lhs, rhs },
        AssignmentOperator::ExponentiateAssign => Ir3Instruction::Exp { dst, lhs, rhs },
        AssignmentOperator::BitwiseAndAssign => Ir3Instruction::BitAnd { dst, lhs, rhs },
        AssignmentOperator::BitwiseOrAssign => Ir3Instruction::BitOr { dst, lhs, rhs },
        AssignmentOperator::BitwiseXorAssign => Ir3Instruction::BitXor { dst, lhs, rhs },
        AssignmentOperator::LeftShiftAssign => Ir3Instruction::Shl { dst, lhs, rhs },
        AssignmentOperator::RightShiftAssign => Ir3Instruction::Shr { dst, lhs, rhs },
        AssignmentOperator::UnsignedRightShiftAssign => Ir3Instruction::Ushr { dst, lhs, rhs },
        AssignmentOperator::LogicalAndAssign => Ir3Instruction::Move { dst, src: rhs },
        AssignmentOperator::LogicalOrAssign => Ir3Instruction::Move { dst, src: rhs },
        AssignmentOperator::NullishCoalescingAssign => Ir3Instruction::Move { dst, src: rhs },
    }
}

/// The binary operation a *non-logical* compound assignment applies to the
/// current value and the right-hand side (`a += b` -> `a = a + b`). Returns
/// `None` for a plain `Assign` (no combine) and for the short-circuiting logical
/// compound operators (`&&=`, `||=`, `??=`), which must be lowered through their
/// dedicated jump form before reaching a load-op-store site. This is the member-
/// target analogue of `lower_assign_op_to_ir3`'s per-operator dispatch, used to
/// combine a property's loaded current value with the RHS (bd-rmxao).
fn compound_assignment_binary_operator(operator: AssignmentOperator) -> Option<BinaryOperator> {
    match operator {
        AssignmentOperator::AddAssign => Some(BinaryOperator::Add),
        AssignmentOperator::SubtractAssign => Some(BinaryOperator::Subtract),
        AssignmentOperator::MultiplyAssign => Some(BinaryOperator::Multiply),
        AssignmentOperator::DivideAssign => Some(BinaryOperator::Divide),
        AssignmentOperator::RemainderAssign => Some(BinaryOperator::Remainder),
        AssignmentOperator::ExponentiateAssign => Some(BinaryOperator::Exponentiate),
        AssignmentOperator::LeftShiftAssign => Some(BinaryOperator::LeftShift),
        AssignmentOperator::RightShiftAssign => Some(BinaryOperator::RightShift),
        AssignmentOperator::UnsignedRightShiftAssign => Some(BinaryOperator::UnsignedRightShift),
        AssignmentOperator::BitwiseAndAssign => Some(BinaryOperator::BitwiseAnd),
        AssignmentOperator::BitwiseOrAssign => Some(BinaryOperator::BitwiseOr),
        AssignmentOperator::BitwiseXorAssign => Some(BinaryOperator::BitwiseXor),
        AssignmentOperator::Assign
        | AssignmentOperator::LogicalAndAssign
        | AssignmentOperator::LogicalOrAssign
        | AssignmentOperator::NullishCoalescingAssign => None,
    }
}

fn emit_exact_nested_capture_scope(
    ir3: &mut Ir3Module,
    function_binding_registers: &mut BTreeMap<BindingId, Reg>,
    function_free_var_names: &BTreeMap<BindingId, String>,
    register_cursor: &mut Reg,
    names: &[String],
    body_ids: &[BindingId],
    outer_ids: &[BindingId],
) -> Result<bool, LoweringPipelineError> {
    if names.len() != body_ids.len() || names.len() != outer_ids.len() {
        return Err(LoweringPipelineError::InvariantViolation {
            detail: "Nested function capture metadata lengths differ",
        });
    }
    if names.is_empty() {
        return Ok(false);
    }

    // Materialize inherited free variables before installing a temporary
    // same-name scope, otherwise the new declaration would shadow the value
    // we are trying to capture. Local/parameter sources come from their exact
    // function-frame binding register.
    let mut sources = Vec::with_capacity(names.len());
    for (name, outer_id) in names.iter().zip(outer_ids.iter()) {
        let source = if let Some(parent_runtime_name) = function_free_var_names.get(outer_id) {
            let dst = alloc_register(register_cursor);
            let name_pool_index = push_constant(&mut ir3.constant_pool, parent_runtime_name);
            ir3.instructions.push(Ir3Instruction::LoadScoped {
                dst,
                name_pool_index,
            });
            dst
        } else {
            *function_binding_registers
                .entry(*outer_id)
                .or_insert_with(|| alloc_register(register_cursor))
        };
        sources.push((name, source));
    }

    ir3.instructions.push(Ir3Instruction::PushScope);
    for (name, source) in sources {
        let name_pool_index = push_constant(&mut ir3.constant_pool, name);
        ir3.instructions.push(Ir3Instruction::DeclareBinding {
            name_pool_index,
            kind: 0,
        });
        ir3.instructions.push(Ir3Instruction::StoreScoped {
            src: source,
            name_pool_index,
        });
    }
    Ok(true)
}

fn validate_deferred_rest_parameter_abi(
    param_count: usize,
    rest_param_index: Option<u32>,
) -> Result<(), LoweringPipelineError> {
    let Some(rest_index) = rest_param_index else {
        return Ok(());
    };
    let arity =
        u32::try_from(param_count).map_err(|_| LoweringPipelineError::InvariantViolation {
            detail: "Function parameter count exceeds the IR3 positional ABI",
        })?;
    if rest_index.checked_add(1) != Some(arity) {
        return Err(LoweringPipelineError::InvariantViolation {
            detail: "Function rest metadata must identify the final positional parameter",
        });
    }
    Ok(())
}

pub fn lower_ir2_to_ir3(
    ir2: &Ir2Module,
) -> Result<LoweringPassResult<Ir3Module>, LoweringPipelineError> {
    enum PendingJump {
        Unconditional {
            instruction_index: usize,
            label_id: u32,
        },
        Conditional {
            instruction_index: usize,
            label_id: u32,
        },
        JumpIfFalsy {
            truthy_skip_index: usize,
            falsy_jump_index: usize,
            label_id: u32,
        },
        IteratorDoneTarget {
            instruction_index: usize,
            label_id: u32,
        },
        TryCatch {
            instruction_index: usize,
            catch_label_id: u32,
            finally_label_id: Option<u32>,
        },
    }

    let ir2_hash = ir2.content_hash();
    let mut ir3 = Ir3Module::new(ir2_hash, ir2.header.source_label.clone());
    // Register 0 is the module's reserved completion-value slot: the baseline
    // interpreter returns `read_reg(0)` when execution falls off the end of the
    // instruction stream (Halt), and module-level `Return` lowers to
    // `Return { value: 0 }`. The expression-statement `Pop` handler keeps r0
    // fresh by emitting `Move { dst: 0, src: <value> }`. Binding/temporary
    // allocation must therefore start at register 1 — if it started at 0 the
    // first-declared binding (e.g. a top-level `function` closure) would be
    // pinned to r0 and then silently clobbered by every later expression-
    // statement Pop, breaking any call that reads that binding inside a loop
    // (bd-fqlfw.2.11.1: "expected function, got boolean").
    let mut register_cursor: Reg = 1;
    let mut binding_registers = BTreeMap::<BindingId, Reg>::new();
    let mut required_capabilities = BTreeSet::<String>::new();
    let mut value_stack: Vec<Reg> = Vec::new();
    let mut label_targets = BTreeMap::<u32, u32>::new();
    let mut iterator_cleanup_labels = BTreeMap::<u32, Reg>::new();
    let mut pending_jumps = Vec::<PendingJump>::new();
    let mut catch_entry_labels = BTreeSet::<u32>::new();
    // Deferred function bodies:
    // (body_ir1_ops, param_names, name, free_vars, free_var_ids,
    //  is_generator, rest_param_index).
    // After the main code + Halt, each body is lowered into the instruction
    // stream and registered in function_table.  Index 0 is reserved for main.
    #[allow(clippy::type_complexity)]
    let mut deferred_functions: Vec<(
        Vec<Ir1Op>,
        Vec<String>,
        Option<String>,
        Vec<String>,
        Vec<BindingId>,
        bool,
        Option<u32>,
    )> = Vec::new();

    // Build name→BindingId lookup from the module's scope tree so the
    // IR3 lowering can resolve free-variable names to register indices.
    let mut name_to_binding_id = BTreeMap::<String, BindingId>::new();
    let mut binding_id_to_name = BTreeMap::<BindingId, String>::new();
    for scope in &ir2.scopes {
        for binding in &scope.bindings {
            name_to_binding_id
                .entry(binding.name.clone())
                .or_insert(binding.binding_id);
            binding_id_to_name
                .entry(binding.binding_id)
                .or_insert(binding.name.clone());
        }
    }
    let is_commonjs = Path::new(&ir2.header.source_label)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("cjs"))
        .unwrap_or(false);
    let mut cjs_binding_ids = BTreeSet::<BindingId>::new();
    if is_commonjs {
        if let Some(binding_id) = name_to_binding_id.get("module") {
            cjs_binding_ids.insert(*binding_id);
        }
        if let Some(binding_id) = name_to_binding_id.get("exports") {
            cjs_binding_ids.insert(*binding_id);
        }
        if let Some(binding_id) = name_to_binding_id.get("__filename") {
            cjs_binding_ids.insert(*binding_id);
        }
        if let Some(binding_id) = name_to_binding_id.get("__dirname") {
            cjs_binding_ids.insert(*binding_id);
        }
    }

    for op in &ir2.ops {
        if matches!(op.effect, EffectBoundary::HostcallEffect) {
            let capability = op
                .required_capability
                .clone()
                .unwrap_or_else(|| CapabilityTag("hostcall.invoke".to_string()));

            // Reconstruct logic for HostCall intercept.
            // Calls pop the callee + args; hostcalls pop only the args.
            let (start_reg, arg_count) = match &op.inner {
                Ir1Op::Call { arg_count } => {
                    let count = *arg_count;
                    let mut args = Vec::new();
                    for _ in 0..count {
                        args.push(value_stack.pop().unwrap_or(0));
                    }
                    args.reverse();
                    let _callee = value_stack.pop().unwrap_or(0); // Pop callee, not used for HostCall cap
                    let start = register_cursor;
                    for arg_reg in args {
                        let dst = alloc_register(&mut register_cursor);
                        ir3.instructions
                            .push(Ir3Instruction::Move { dst, src: arg_reg });
                    }
                    (start, count)
                }
                Ir1Op::HostCall { arg_count, .. } => {
                    let count = *arg_count;
                    let mut args = Vec::new();
                    for _ in 0..count {
                        args.push(value_stack.pop().unwrap_or(0));
                    }
                    args.reverse();
                    let start = register_cursor;
                    for arg_reg in args {
                        let dst = alloc_register(&mut register_cursor);
                        ir3.instructions
                            .push(Ir3Instruction::Move { dst, src: arg_reg });
                    }
                    (start, count)
                }
                _ => {
                    let hostcall_arg = value_stack.pop().unwrap_or(0);
                    let start = alloc_register(&mut register_cursor);
                    ir3.instructions.push(Ir3Instruction::Move {
                        dst: start,
                        src: hostcall_arg,
                    });
                    (start, 1)
                }
            };

            if flow_requires_runtime_check(op.flow.as_ref(), &capability) {
                required_capabilities.insert(IFC_RUNTIME_GUARD_CAPABILITY.to_string());
                let guard_dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::HostCall {
                    capability: CapabilityTag(IFC_RUNTIME_GUARD_CAPABILITY.to_string()),
                    args: RegRange {
                        start: start_reg,
                        count: arg_count,
                    },
                    dst: guard_dst,
                });
            }
            required_capabilities.insert(capability.0.clone());
            let dst = alloc_register(&mut register_cursor);
            ir3.instructions.push(Ir3Instruction::HostCall {
                capability,
                args: RegRange {
                    start: start_reg,
                    count: arg_count,
                },
                dst,
            });
            value_stack.push(dst);
            continue;
        }

        match &op.inner {
            Ir1Op::LoadLiteral { value } => {
                let dst = alloc_register(&mut register_cursor);
                lower_literal_to_ir3(value, dst, &mut ir3.instructions, &mut ir3.constant_pool);
                value_stack.push(dst);
            }
            Ir1Op::LoadBinding { binding_id } => {
                if cjs_binding_ids.contains(binding_id) {
                    let name = binding_id_to_name
                        .get(binding_id)
                        .cloned()
                        .unwrap_or_else(|| format!("__binding_{binding_id}"));
                    let dst = alloc_register(&mut register_cursor);
                    let pool_index = push_constant(&mut ir3.constant_pool, &name);
                    ir3.instructions.push(Ir3Instruction::LoadScoped {
                        dst,
                        name_pool_index: pool_index,
                    });
                    value_stack.push(dst);
                } else {
                    let source_reg = *binding_registers
                        .entry(*binding_id)
                        .or_insert_with(|| alloc_register(&mut register_cursor));
                    let dst = alloc_register(&mut register_cursor);
                    ir3.instructions.push(Ir3Instruction::Move {
                        dst,
                        src: source_reg,
                    });
                    value_stack.push(dst);
                }
            }
            Ir1Op::StoreBinding { binding_id } => {
                let src = value_stack.pop().unwrap_or(0);
                if cjs_binding_ids.contains(binding_id) {
                    let name = binding_id_to_name
                        .get(binding_id)
                        .cloned()
                        .unwrap_or_else(|| format!("__binding_{binding_id}"));
                    let pool_index = push_constant(&mut ir3.constant_pool, &name);
                    ir3.instructions.push(Ir3Instruction::StoreScoped {
                        src,
                        name_pool_index: pool_index,
                    });
                    value_stack.push(src);
                } else {
                    let dst = *binding_registers
                        .entry(*binding_id)
                        .or_insert_with(|| alloc_register(&mut register_cursor));
                    ir3.instructions.push(Ir3Instruction::Move { dst, src });
                    value_stack.push(dst);
                }
            }
            Ir1Op::Call { arg_count } => {
                let count = *arg_count as usize;
                // Stack layout: [..., callee, arg0, arg1, ...]; we pop `count`
                // args plus the callee, so `count + 1` slots must be present.
                if count.saturating_add(1) > value_stack.len() {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Value stack underflow in Call",
                    });
                }
                let mut args = Vec::with_capacity(count);
                for _ in 0..count {
                    args.push(value_stack.pop().unwrap_or(0));
                }
                args.reverse();
                let callee = value_stack.pop().unwrap_or(0);

                let start_reg = register_cursor;
                for arg_reg in args {
                    let dst = alloc_register(&mut register_cursor);
                    ir3.instructions
                        .push(Ir3Instruction::Move { dst, src: arg_reg });
                }

                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::Call {
                    callee,
                    args: RegRange {
                        start: start_reg,
                        count: *arg_count,
                    },
                    dst,
                });
                value_stack.push(dst);
            }
            Ir1Op::CallMethod { arg_count } => {
                let count = *arg_count as usize;
                // Stack layout: [..., callee, receiver, arg0, arg1, ...]
                // Pop args first, then receiver, then callee, so `count + 2`
                // slots must be present.
                if count.saturating_add(2) > value_stack.len() {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Value stack underflow in CallMethod",
                    });
                }
                let mut args = Vec::with_capacity(count);
                for _ in 0..count {
                    args.push(value_stack.pop().unwrap_or(0));
                }
                args.reverse();
                let receiver = value_stack.pop().unwrap_or(0);
                let callee = value_stack.pop().unwrap_or(0);

                let start_reg = register_cursor;
                for arg_reg in args {
                    let dst = alloc_register(&mut register_cursor);
                    ir3.instructions
                        .push(Ir3Instruction::Move { dst, src: arg_reg });
                }

                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::CallMethod {
                    receiver,
                    callee,
                    args: RegRange {
                        start: start_reg,
                        count: *arg_count,
                    },
                    dst,
                });
                value_stack.push(dst);
            }
            Ir1Op::ImportModule { specifier } => {
                let string_reg = alloc_register(&mut register_cursor);
                let pool_index = push_constant(&mut ir3.constant_pool, specifier);
                ir3.instructions.push(Ir3Instruction::LoadStr {
                    dst: string_reg,
                    pool_index,
                });
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::ImportModule {
                    specifier: string_reg,
                    dst,
                });
                value_stack.push(dst);
            }
            Ir1Op::ExportBinding { name, .. } => {
                let src = value_stack.pop().unwrap_or(0);
                let pool_index = push_constant(&mut ir3.constant_pool, name);
                ir3.instructions.push(Ir3Instruction::ExportBinding {
                    name_pool_index: pool_index,
                    src,
                });
                value_stack.push(src);
            }
            Ir1Op::Await => {
                let current = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions
                    .push(Ir3Instruction::Move { dst, src: current });
                value_stack.push(dst);
            }
            Ir1Op::Yield { delegate } => {
                let value_reg = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::Yield {
                    value: value_reg,
                    delegate: *delegate,
                    resume_dst: dst,
                });
                value_stack.push(dst);
            }
            Ir1Op::Return => {
                // The main loop only processes module-level Returns
                // (function body Returns are handled in the deferred
                // function loop).  At module level the completion value
                // is always in register 0 (kept up-to-date by Pop),
                // so use register 0 regardless of value_stack state
                // which may be stale after control flow (switch, if).
                let _discard = value_stack.pop();
                ir3.instructions.push(Ir3Instruction::Return { value: 0 });
            }
            Ir1Op::Nop | Ir1Op::Pop => {
                let register = value_stack.pop().unwrap_or(0);
                if matches!(op.inner, Ir1Op::Pop) {
                    // Expression-statement completion: move the discarded
                    // value into register 0 so the interpreter returns it as
                    // the script completion value when execution falls off
                    // the end of the instruction stream.
                    ir3.instructions.push(Ir3Instruction::Move {
                        dst: 0,
                        src: register,
                    });
                } else {
                    ir3.instructions.push(Ir3Instruction::Move {
                        dst: register,
                        src: register,
                    });
                    value_stack.push(register);
                }
            }
            Ir1Op::BeginTry {
                catch_label,
                finally_label,
            } => {
                // Only mark as catch-entry when there is a real catch handler
                // (i.e., catch_label != finally_label).  For try/finally without
                // catch, exceptions go directly to the finally block and
                // EnterCatch must NOT be emitted — it would consume the pending
                // exception before EndFinally can re-throw it.
                if finally_label.as_ref() != Some(catch_label) {
                    catch_entry_labels.insert(*catch_label);
                }
                let instr_idx = ir3.instructions.len();
                ir3.instructions.push(Ir3Instruction::BeginTry {
                    catch_target: 0,
                    finally_target: None,
                });
                pending_jumps.push(PendingJump::TryCatch {
                    instruction_index: instr_idx,
                    catch_label_id: *catch_label,
                    finally_label_id: *finally_label,
                });
            }
            Ir1Op::EndTry => {
                ir3.instructions.push(Ir3Instruction::EndTry);
            }
            Ir1Op::EnterFinally => {
                ir3.instructions.push(Ir3Instruction::EnterFinally);
            }
            Ir1Op::EndFinally => {
                ir3.instructions.push(Ir3Instruction::EndFinally);
            }
            Ir1Op::DiscardAbruptCompletion => {
                ir3.instructions
                    .push(Ir3Instruction::DiscardAbruptCompletion);
            }
            Ir1Op::BinaryOp { operator } => {
                let rhs = value_stack.pop().unwrap_or(0);
                let lhs = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                let instr = match operator {
                    BinaryOperator::Add => Ir3Instruction::Add { dst, lhs, rhs },
                    BinaryOperator::Subtract => Ir3Instruction::Sub { dst, lhs, rhs },
                    BinaryOperator::Multiply => Ir3Instruction::Mul { dst, lhs, rhs },
                    BinaryOperator::Divide => Ir3Instruction::Div { dst, lhs, rhs },
                    BinaryOperator::Remainder => Ir3Instruction::Mod { dst, lhs, rhs },
                    BinaryOperator::Exponentiate => Ir3Instruction::Exp { dst, lhs, rhs },
                    BinaryOperator::LessThan => Ir3Instruction::Lt { dst, lhs, rhs },
                    BinaryOperator::LessThanOrEqual => Ir3Instruction::Lte { dst, lhs, rhs },
                    BinaryOperator::GreaterThan => Ir3Instruction::Gt { dst, lhs, rhs },
                    BinaryOperator::GreaterThanOrEqual => Ir3Instruction::Gte { dst, lhs, rhs },
                    BinaryOperator::Equal => Ir3Instruction::Eq { dst, lhs, rhs },
                    BinaryOperator::StrictEqual => Ir3Instruction::StrictEq { dst, lhs, rhs },
                    BinaryOperator::NotEqual => Ir3Instruction::NotEq { dst, lhs, rhs },
                    BinaryOperator::StrictNotEqual => Ir3Instruction::StrictNotEq { dst, lhs, rhs },
                    BinaryOperator::BitwiseAnd => Ir3Instruction::BitAnd { dst, lhs, rhs },
                    BinaryOperator::BitwiseOr => Ir3Instruction::BitOr { dst, lhs, rhs },
                    BinaryOperator::BitwiseXor => Ir3Instruction::BitXor { dst, lhs, rhs },
                    BinaryOperator::LeftShift => Ir3Instruction::Shl { dst, lhs, rhs },
                    BinaryOperator::RightShift => Ir3Instruction::Shr { dst, lhs, rhs },
                    BinaryOperator::UnsignedRightShift => Ir3Instruction::Ushr { dst, lhs, rhs },
                    BinaryOperator::Instanceof => Ir3Instruction::InstanceOf { dst, lhs, rhs },
                    BinaryOperator::In => Ir3Instruction::InOp { dst, lhs, rhs },
                    BinaryOperator::LogicalAnd
                    | BinaryOperator::LogicalOr
                    | BinaryOperator::NullishCoalescing => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "logical operators must be short-circuit lowered before IR3",
                        });
                    }
                };
                ir3.instructions.push(instr);
                value_stack.push(dst);
            }
            Ir1Op::UnaryOp { operator } => {
                let src = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                let instr = match operator {
                    UnaryOperator::Negate => Ir3Instruction::UnaryNeg { dst, src },
                    UnaryOperator::BitwiseNot => Ir3Instruction::BitNot { dst, src },
                    UnaryOperator::LogicalNot => Ir3Instruction::LogicalNot { dst, src },
                    UnaryOperator::Typeof => Ir3Instruction::TypeOf { dst, src },
                    UnaryOperator::Void => Ir3Instruction::Void { dst, src },
                    UnaryOperator::Delete => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "delete must lower through delete_property or literal-true path before IR3",
                        });
                    }
                    UnaryOperator::UnaryPlus => Ir3Instruction::UnaryPlus { dst, src },
                };
                ir3.instructions.push(instr);
                value_stack.push(dst);
            }
            Ir1Op::AssignOp {
                binding_id,
                operator,
            } => {
                let dst = *binding_registers
                    .entry(*binding_id)
                    .or_insert_with(|| alloc_register(&mut register_cursor));
                let src = value_stack.pop().unwrap_or(0);
                match operator {
                    AssignmentOperator::Assign => {
                        ir3.instructions.push(Ir3Instruction::Move { dst, src });
                    }
                    AssignmentOperator::AddAssign => {
                        ir3.instructions.push(Ir3Instruction::Add {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::SubtractAssign => {
                        ir3.instructions.push(Ir3Instruction::Sub {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::MultiplyAssign => {
                        ir3.instructions.push(Ir3Instruction::Mul {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::DivideAssign => {
                        ir3.instructions.push(Ir3Instruction::Div {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::RemainderAssign => {
                        ir3.instructions.push(Ir3Instruction::Mod {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::ExponentiateAssign => {
                        ir3.instructions.push(Ir3Instruction::Exp {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::LeftShiftAssign => {
                        ir3.instructions.push(Ir3Instruction::Shl {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::RightShiftAssign => {
                        ir3.instructions.push(Ir3Instruction::Shr {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::UnsignedRightShiftAssign => {
                        ir3.instructions.push(Ir3Instruction::Ushr {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::BitwiseAndAssign => {
                        ir3.instructions.push(Ir3Instruction::BitAnd {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::BitwiseOrAssign => {
                        ir3.instructions.push(Ir3Instruction::BitOr {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::BitwiseXorAssign => {
                        ir3.instructions.push(Ir3Instruction::BitXor {
                            dst,
                            lhs: dst,
                            rhs: src,
                        });
                    }
                    AssignmentOperator::LogicalAndAssign
                    | AssignmentOperator::LogicalOrAssign
                    | AssignmentOperator::NullishCoalescingAssign => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "logical compound assignments must be short-circuit lowered before IR3",
                        });
                    }
                }
                value_stack.push(dst);
            }
            Ir1Op::Label { id } => {
                // Record the label target FIRST so that catch_target in
                // BeginTry points TO the EnterCatch instruction, not past it.
                let target = u32::try_from(ir3.instructions.len()).map_err(|_| {
                    LoweringPipelineError::InvariantViolation {
                        detail: "IR3 instruction stream exceeds addressable size",
                    }
                })?;
                if label_targets.insert(*id, target).is_some() {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "IR2 contains duplicate label ids",
                    });
                }
                // If this label is a catch handler entry, emit EnterCatch
                // so the runtime can provide the exception value.
                if catch_entry_labels.contains(id) {
                    let dst = alloc_register(&mut register_cursor);
                    ir3.instructions.push(Ir3Instruction::EnterCatch { dst });
                    value_stack.push(dst);
                }
                if iterator_cleanup_labels
                    .get(id)
                    .is_some_and(|expected| value_stack.last() == Some(expected))
                {
                    value_stack.pop();
                }
            }
            Ir1Op::Jump { label_id } => {
                let instruction_index = ir3.instructions.len();
                ir3.instructions.push(Ir3Instruction::Jump { target: 0 });
                pending_jumps.push(PendingJump::Unconditional {
                    instruction_index,
                    label_id: *label_id,
                });
            }
            Ir1Op::JumpIfFalsy { label_id } => {
                let cond = value_stack.pop().unwrap_or(0);
                let truthy_skip_index = ir3.instructions.len();
                ir3.instructions
                    .push(Ir3Instruction::JumpIf { cond, target: 0 });
                let falsy_jump_index = ir3.instructions.len();
                ir3.instructions.push(Ir3Instruction::Jump { target: 0 });
                pending_jumps.push(PendingJump::JumpIfFalsy {
                    truthy_skip_index,
                    falsy_jump_index,
                    label_id: *label_id,
                });
                value_stack.push(cond);
            }
            Ir1Op::JumpIfFalsyConsume { label_id } => {
                let cond = value_stack.pop().unwrap_or(0);
                let truthy_skip_index = ir3.instructions.len();
                ir3.instructions
                    .push(Ir3Instruction::JumpIf { cond, target: 0 });
                let falsy_jump_index = ir3.instructions.len();
                ir3.instructions.push(Ir3Instruction::Jump { target: 0 });
                pending_jumps.push(PendingJump::JumpIfFalsy {
                    truthy_skip_index,
                    falsy_jump_index,
                    label_id: *label_id,
                });
            }
            Ir1Op::JumpIfTruthy { label_id } => {
                let cond = value_stack.pop().unwrap_or(0);
                let instruction_index = ir3.instructions.len();
                ir3.instructions
                    .push(Ir3Instruction::JumpIf { cond, target: 0 });
                pending_jumps.push(PendingJump::Conditional {
                    instruction_index,
                    label_id: *label_id,
                });
            }
            Ir1Op::JumpIfNullish { label_id } => {
                let cond = value_stack.pop().unwrap_or(0);
                let instruction_index = ir3.instructions.len();
                ir3.instructions
                    .push(Ir3Instruction::JumpIfNullish { cond, target: 0 });
                pending_jumps.push(PendingJump::Conditional {
                    instruction_index,
                    label_id: *label_id,
                });
            }
            Ir1Op::GetProperty { key } => {
                let (obj, key_reg) = match key {
                    Ir1PropertyKey::Static(key) => {
                        let obj = value_stack.pop().unwrap_or(0);
                        let key_reg = alloc_register(&mut register_cursor);
                        let pool_index = push_constant(&mut ir3.constant_pool, key);
                        ir3.instructions.push(Ir3Instruction::LoadStr {
                            dst: key_reg,
                            pool_index,
                        });
                        (obj, key_reg)
                    }
                    Ir1PropertyKey::Dynamic => {
                        let key_reg = value_stack.pop().unwrap_or(0);
                        let obj = value_stack.pop().unwrap_or(0);
                        (obj, key_reg)
                    }
                };
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::GetProperty {
                    obj,
                    key: key_reg,
                    dst,
                });
                value_stack.push(dst);
            }
            Ir1Op::SetProperty { key } => {
                let val = value_stack.pop().unwrap_or(0);
                let (obj, key_reg) = match key {
                    Ir1PropertyKey::Static(key) => {
                        let obj = value_stack.pop().unwrap_or(0);
                        let key_reg = alloc_register(&mut register_cursor);
                        let pool_index = push_constant(&mut ir3.constant_pool, key);
                        ir3.instructions.push(Ir3Instruction::LoadStr {
                            dst: key_reg,
                            pool_index,
                        });
                        (obj, key_reg)
                    }
                    Ir1PropertyKey::Dynamic => {
                        let key_reg = value_stack.pop().unwrap_or(0);
                        let obj = value_stack.pop().unwrap_or(0);
                        (obj, key_reg)
                    }
                };
                ir3.instructions.push(Ir3Instruction::SetProperty {
                    obj,
                    key: key_reg,
                    val,
                });
                value_stack.push(val);
            }
            Ir1Op::DeleteProperty { key } => {
                let (obj, key_reg) = match key {
                    Ir1PropertyKey::Static(key) => {
                        let obj = value_stack.pop().unwrap_or(0);
                        let key_reg = alloc_register(&mut register_cursor);
                        let pool_index = push_constant(&mut ir3.constant_pool, key);
                        ir3.instructions.push(Ir3Instruction::LoadStr {
                            dst: key_reg,
                            pool_index,
                        });
                        (obj, key_reg)
                    }
                    Ir1PropertyKey::Dynamic => {
                        let key_reg = value_stack.pop().unwrap_or(0);
                        let obj = value_stack.pop().unwrap_or(0);
                        (obj, key_reg)
                    }
                };
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::DeleteProperty {
                    obj,
                    key: key_reg,
                    dst,
                });
                value_stack.push(dst);
            }
            Ir1Op::NewArray { count } => {
                let cnt = *count as usize;
                if cnt > value_stack.len() {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Value stack underflow in NewArray",
                    });
                }
                let mut elements = Vec::with_capacity(cnt);
                for _ in 0..cnt {
                    elements.push(value_stack.pop().unwrap_or(0));
                }
                elements.reverse();

                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::NewArray { dst });

                for (i, val_reg) in elements.into_iter().enumerate() {
                    let key_str = i.to_string();
                    let key_reg = alloc_register(&mut register_cursor);
                    let pool_index = push_constant(&mut ir3.constant_pool, &key_str);
                    ir3.instructions.push(Ir3Instruction::LoadStr {
                        dst: key_reg,
                        pool_index,
                    });
                    ir3.instructions.push(Ir3Instruction::SetProperty {
                        obj: dst,
                        key: key_reg,
                        val: val_reg,
                    });
                }
                value_stack.push(dst);
            }
            Ir1Op::NewObject { count } => {
                let cnt = *count as usize;
                if cnt
                    .checked_mul(2)
                    .is_none_or(|needed| needed > value_stack.len())
                {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Value stack underflow in NewObject",
                    });
                }
                let mut properties = Vec::with_capacity(cnt);
                for _ in 0..cnt {
                    let val = value_stack.pop().unwrap_or(0);
                    let key = value_stack.pop().unwrap_or(0);
                    properties.push((key, val));
                }
                properties.reverse();

                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::NewObject { dst });

                for (key_reg, val_reg) in properties {
                    ir3.instructions.push(Ir3Instruction::SetProperty {
                        obj: dst,
                        key: key_reg,
                        val: val_reg,
                    });
                }
                value_stack.push(dst);
            }
            Ir1Op::ArrayPush => {
                // Stack: [..., array, element] -> [..., array]
                let element = value_stack.pop().unwrap_or(0);
                let array = value_stack.pop().unwrap_or(0);
                ir3.instructions
                    .push(Ir3Instruction::ArrayPush { array, element });
                value_stack.push(array);
            }
            Ir1Op::ArraySlice => {
                // Stack: [..., array, start_index] -> [..., sliced_array]
                let start = value_stack.pop().unwrap_or(0);
                let array = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions
                    .push(Ir3Instruction::ArraySlice { array, start, dst });
                value_stack.push(dst);
            }
            Ir1Op::SpreadIntoArray => {
                // Stack: [..., array, iterable] -> [..., array]
                let iterable = value_stack.pop().unwrap_or(0);
                let array = value_stack.pop().unwrap_or(0);
                ir3.instructions
                    .push(Ir3Instruction::SpreadIntoArray { array, iterable });
                value_stack.push(array);
            }
            Ir1Op::SpreadIntoObject => {
                // Stack: [..., target, source] -> [..., target]
                let source = value_stack.pop().unwrap_or(0);
                let target = value_stack.pop().unwrap_or(0);
                ir3.instructions
                    .push(Ir3Instruction::SpreadIntoObject { target, source });
                value_stack.push(target);
            }
            Ir1Op::Throw => {
                let value = value_stack.pop().unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Throw { value });
            }
            Ir1Op::LoadThis => {
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::LoadThis { dst });
                value_stack.push(dst);
            }
            Ir1Op::LoadNewTarget => {
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::LoadNewTarget { dst });
                value_stack.push(dst);
            }
            Ir1Op::LoadSuper => {
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::LoadSuper { dst });
                value_stack.push(dst);
            }
            Ir1Op::DeclareFunction {
                binding_id,
                name,
                param_names,
                body_ops,
                free_vars,
                free_var_ids,
                free_var_outer_ids,
                is_generator,
                rest_param_index,
                ..
            } => {
                if free_vars.len() != free_var_ids.len()
                    || free_vars.len() != free_var_outer_ids.len()
                {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Function capture metadata lengths differ",
                    });
                }
                let dst = *binding_registers
                    .entry(*binding_id)
                    .or_insert_with(|| alloc_register(&mut register_cursor));
                {
                    // If the function has free variables, put the current
                    // scope's bindings onto the scope chain so
                    // CreateClosure can capture them.
                    if !free_vars.is_empty() {
                        ir3.instructions.push(Ir3Instruction::PushScope);
                        for (fv, outer_binding_id) in
                            free_vars.iter().zip(free_var_outer_ids.iter())
                        {
                            let pool_idx = push_constant(&mut ir3.constant_pool, fv);
                            ir3.instructions.push(Ir3Instruction::DeclareBinding {
                                name_pool_index: pool_idx,
                                kind: 0, // var
                            });
                            // Copy register value to scope chain.
                            if let Some(&reg) = binding_registers.get(outer_binding_id) {
                                ir3.instructions.push(Ir3Instruction::StoreScoped {
                                    src: reg,
                                    name_pool_index: pool_idx,
                                });
                            }
                        }
                    }
                    let function_index = deferred_functions.len() as u32 + 1;
                    deferred_functions.push((
                        body_ops.clone(),
                        param_names.clone(),
                        Some(name.clone()),
                        free_vars.clone(),
                        free_var_ids.clone(),
                        *is_generator,
                        *rest_param_index,
                    ));
                    if *is_generator {
                        ir3.instructions.push(Ir3Instruction::CreateGenerator {
                            dst,
                            function_index,
                            capture_count: free_vars.len() as u32,
                        });
                    } else {
                        ir3.instructions.push(Ir3Instruction::CreateClosure {
                            dst,
                            function_index,
                            capture_count: free_vars.len() as u32,
                        });
                    }
                    if !free_vars.is_empty() {
                        ir3.instructions.push(Ir3Instruction::PopScope);
                    }
                }
                value_stack.push(dst);
            }
            Ir1Op::CreateFunction {
                name,
                param_names,
                body_ops,
                free_vars,
                free_var_ids,
                free_var_outer_ids,
                is_generator,
                rest_param_index,
                ..
            } => {
                if free_vars.len() != free_var_ids.len()
                    || free_vars.len() != free_var_outer_ids.len()
                {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Function capture metadata lengths differ",
                    });
                }
                let dst = alloc_register(&mut register_cursor);
                // If the function has free variables, put them on the
                // scope chain before capturing.
                if !free_vars.is_empty() {
                    ir3.instructions.push(Ir3Instruction::PushScope);
                    for (fv, outer_binding_id) in free_vars.iter().zip(free_var_outer_ids.iter()) {
                        let pool_idx = push_constant(&mut ir3.constant_pool, fv);
                        ir3.instructions.push(Ir3Instruction::DeclareBinding {
                            name_pool_index: pool_idx,
                            kind: 0,
                        });
                        if let Some(&reg) = binding_registers.get(outer_binding_id) {
                            ir3.instructions.push(Ir3Instruction::StoreScoped {
                                src: reg,
                                name_pool_index: pool_idx,
                            });
                        }
                    }
                }
                let function_index = deferred_functions.len() as u32 + 1;
                deferred_functions.push((
                    body_ops.clone(),
                    param_names.clone(),
                    name.clone(),
                    free_vars.clone(),
                    free_var_ids.clone(),
                    *is_generator,
                    *rest_param_index,
                ));
                if *is_generator {
                    ir3.instructions.push(Ir3Instruction::CreateGenerator {
                        dst,
                        function_index,
                        capture_count: free_vars.len() as u32,
                    });
                } else {
                    ir3.instructions.push(Ir3Instruction::CreateClosure {
                        dst,
                        function_index,
                        capture_count: free_vars.len() as u32,
                    });
                }
                if !free_vars.is_empty() {
                    ir3.instructions.push(Ir3Instruction::PopScope);
                }
                value_stack.push(dst);
            }
            Ir1Op::ForInInit => {
                let src = value_stack
                    .pop()
                    .ok_or(LoweringPipelineError::InvariantViolation {
                        detail: "ForInInit requires an object register on the value stack",
                    })?;
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions
                    .push(Ir3Instruction::ForInInit { src, dst });
                value_stack.push(dst);
            }
            Ir1Op::ForOfInit => {
                let src = value_stack
                    .pop()
                    .ok_or(LoweringPipelineError::InvariantViolation {
                        detail: "ForOfInit requires an iterable register on the value stack",
                    })?;
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions
                    .push(Ir3Instruction::ForOfInit { src, dst });
                value_stack.push(dst);
            }
            Ir1Op::ForInNext { done_label } => {
                let iterator = value_stack.last().copied().ok_or(
                    LoweringPipelineError::InvariantViolation {
                        detail: "ForInNext requires an active iterator register on the value stack",
                    },
                )?;
                let value_dst = alloc_register(&mut register_cursor);
                let instruction_index = ir3.instructions.len();
                ir3.instructions.push(Ir3Instruction::ForInNext {
                    iterator,
                    value_dst,
                    done_target: 0,
                });
                pending_jumps.push(PendingJump::IteratorDoneTarget {
                    instruction_index,
                    label_id: *done_label,
                });
                iterator_cleanup_labels
                    .entry(*done_label)
                    .or_insert(iterator);
                value_stack.push(value_dst);
            }
            Ir1Op::ForOfNext { done_label } => {
                let iterator = value_stack.last().copied().ok_or(
                    LoweringPipelineError::InvariantViolation {
                        detail: "ForOfNext requires an active iterator register on the value stack",
                    },
                )?;
                let value_dst = alloc_register(&mut register_cursor);
                let instruction_index = ir3.instructions.len();
                ir3.instructions.push(Ir3Instruction::ForOfNext {
                    iterator,
                    value_dst,
                    done_target: 0,
                });
                pending_jumps.push(PendingJump::IteratorDoneTarget {
                    instruction_index,
                    label_id: *done_label,
                });
                iterator_cleanup_labels
                    .entry(*done_label)
                    .or_insert(iterator);
                value_stack.push(value_dst);
            }
            Ir1Op::IteratorClose { reason } => {
                let iterator = value_stack.pop().ok_or(LoweringPipelineError::InvariantViolation {
                    detail: "IteratorClose requires an active iterator register on the value stack",
                })?;
                ir3.instructions.push(Ir3Instruction::IteratorClose {
                    iterator,
                    reason: *reason,
                });
            }
            Ir1Op::Construct { arg_count } => {
                // Pop callee + arg_count args from value stack; push result.
                let count = *arg_count as usize;
                // We need `count` args + 1 callee.
                if count
                    .checked_add(1)
                    .is_none_or(|needed| needed > value_stack.len())
                {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Value stack underflow in Construct",
                    });
                }
                let mut arg_regs = Vec::with_capacity(count.min(1024));
                for _ in 0..count {
                    arg_regs.push(value_stack.pop().unwrap_or(0));
                }
                arg_regs.reverse();
                let callee = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                // Copy args into contiguous registers so RegRange is valid.
                let args = if arg_regs.is_empty() {
                    RegRange { start: 0, count: 0 }
                } else {
                    let start_reg = register_cursor;
                    for &src in &arg_regs {
                        let contiguous_dst = alloc_register(&mut register_cursor);
                        ir3.instructions.push(Ir3Instruction::Move {
                            dst: contiguous_dst,
                            src,
                        });
                    }
                    RegRange {
                        start: start_reg,
                        count: arg_regs.len() as u32,
                    }
                };
                ir3.instructions
                    .push(Ir3Instruction::Construct { callee, args, dst });
                value_stack.push(dst);
            }
            Ir1Op::TemplateLiteral { quasi_count } => {
                // Pop interleaved quasis and expressions.
                // quasi_count quasis + (quasi_count - 1) expressions.
                let total = if *quasi_count == 0 {
                    0
                } else {
                    (*quasi_count as usize) + (*quasi_count as usize).saturating_sub(1)
                };
                if total > value_stack.len() {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Value stack underflow in TemplateLiteral",
                    });
                }
                // Pop part registers in reverse order and collect them.
                let mut part_regs: Vec<u32> = Vec::with_capacity(total.min(1024));
                for _ in 0..total {
                    part_regs.push(value_stack.pop().unwrap_or(0));
                }
                part_regs.reverse();
                let dst = alloc_register(&mut register_cursor);
                if part_regs.is_empty() {
                    // Empty template literal => empty string.
                    ir3.instructions
                        .push(Ir3Instruction::Move { dst, src: dst });
                } else {
                    // Copy parts into contiguous registers so RegRange is valid.
                    let start_reg = register_cursor;
                    for &src in &part_regs {
                        let contiguous_dst = alloc_register(&mut register_cursor);
                        ir3.instructions.push(Ir3Instruction::Move {
                            dst: contiguous_dst,
                            src,
                        });
                    }
                    let parts = RegRange {
                        start: start_reg,
                        count: part_regs.len() as u32,
                    };
                    ir3.instructions
                        .push(Ir3Instruction::TemplateLiteral { parts, dst });
                }
                value_stack.push(dst);
            }
            Ir1Op::HostCall {
                capability,
                arg_count,
            } => {
                let count = *arg_count as usize;
                if count > value_stack.len() {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Value stack underflow in HostCall",
                    });
                }
                let mut args = Vec::with_capacity(count);
                for _ in 0..count {
                    args.push(value_stack.pop().unwrap_or(0));
                }
                args.reverse();
                let start_reg = register_cursor;
                for arg_reg in args {
                    let contiguous_dst = alloc_register(&mut register_cursor);
                    ir3.instructions.push(Ir3Instruction::Move {
                        dst: contiguous_dst,
                        src: arg_reg,
                    });
                }
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::HostCall {
                    capability: CapabilityTag(capability.clone()),
                    args: RegRange {
                        start: start_reg,
                        count: *arg_count,
                    },
                    dst,
                });
                value_stack.push(dst);
            }
        }
    }

    for pending_jump in pending_jumps {
        match pending_jump {
            PendingJump::Unconditional {
                instruction_index,
                label_id,
            } => {
                let target = *label_targets.get(&label_id).ok_or(
                    LoweringPipelineError::InvariantViolation {
                        detail: "lowered control-flow references missing label",
                    },
                )?;
                ir3.instructions[instruction_index] = Ir3Instruction::Jump { target };
            }
            PendingJump::Conditional {
                instruction_index,
                label_id,
            } => {
                let target = *label_targets.get(&label_id).ok_or(
                    LoweringPipelineError::InvariantViolation {
                        detail: "lowered control-flow references missing label",
                    },
                )?;
                match &mut ir3.instructions[instruction_index] {
                    Ir3Instruction::JumpIf {
                        target: jump_target,
                        ..
                    }
                    | Ir3Instruction::JumpIfNullish {
                        target: jump_target,
                        ..
                    } => {
                        *jump_target = target;
                    }
                    _ => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "conditional lowering emitted unexpected instruction shape",
                        });
                    }
                }
            }
            PendingJump::JumpIfFalsy {
                truthy_skip_index,
                falsy_jump_index,
                label_id,
            } => {
                let falsy_target = *label_targets.get(&label_id).ok_or(
                    LoweringPipelineError::InvariantViolation {
                        detail: "lowered control-flow references missing label",
                    },
                )?;
                let truthy_target = u32::try_from(falsy_jump_index + 1).map_err(|_| {
                    LoweringPipelineError::InvariantViolation {
                        detail: "IR3 instruction stream exceeds addressable size",
                    }
                })?;
                let cond = match ir3.instructions[truthy_skip_index] {
                    Ir3Instruction::JumpIf { cond, .. } => cond,
                    _ => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "conditional lowering emitted unexpected instruction shape",
                        });
                    }
                };
                ir3.instructions[truthy_skip_index] = Ir3Instruction::JumpIf {
                    cond,
                    target: truthy_target,
                };
                ir3.instructions[falsy_jump_index] = Ir3Instruction::Jump {
                    target: falsy_target,
                };
            }
            PendingJump::IteratorDoneTarget {
                instruction_index,
                label_id,
            } => {
                let target = *label_targets.get(&label_id).ok_or(
                    LoweringPipelineError::InvariantViolation {
                        detail: "iterator lowering references missing label",
                    },
                )?;
                match &mut ir3.instructions[instruction_index] {
                    Ir3Instruction::ForInNext { done_target, .. }
                    | Ir3Instruction::ForOfNext { done_target, .. } => {
                        *done_target = target;
                    }
                    _ => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "iterator lowering emitted unexpected instruction shape",
                        });
                    }
                }
            }
            PendingJump::TryCatch {
                instruction_index,
                catch_label_id,
                finally_label_id,
            } => {
                let catch_target = *label_targets.get(&catch_label_id).ok_or(
                    LoweringPipelineError::InvariantViolation {
                        detail: "try/catch lowering references missing catch label",
                    },
                )?;
                let finally_target = if let Some(fl_id) = finally_label_id {
                    Some(*label_targets.get(&fl_id).ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "try/finally lowering references missing finally label",
                        },
                    )?)
                } else {
                    None
                };
                ir3.instructions[instruction_index] = Ir3Instruction::BeginTry {
                    catch_target,
                    finally_target,
                };
            }
        }
    }

    if !matches!(ir3.instructions.last(), Some(Ir3Instruction::Halt)) {
        ir3.instructions.push(Ir3Instruction::Halt);
    }
    ir3.function_table.push(Ir3FunctionDesc {
        entry: 0,
        arity: 0,
        frame_size: register_cursor.max(1),
        name: Some("main".to_string()),
        is_generator: false,
        rest_param_index: None,
    });

    // ── Deferred function bodies ──────────────────────────────────────
    // Each body is lowered with its own register frame (starting at 0)
    // and appended after the main Halt.  Use index-based iteration so
    // that nested DeclareFunction / CreateFunction discovered inside a
    // body can push new entries without conflicting with the borrow.
    let mut deferred_idx = 0;
    while deferred_idx < deferred_functions.len() {
        let (
            body_ops,
            param_names,
            fn_name,
            free_vars,
            free_var_ids,
            fn_is_generator,
            fn_rest_param_index,
        ) = deferred_functions[deferred_idx].clone();
        deferred_idx += 1;
        validate_deferred_rest_parameter_abi(param_names.len(), fn_rest_param_index)?;
        let (body_ops, param_names, fn_name, free_vars, free_var_ids) =
            (&body_ops, &param_names, &fn_name, &free_vars, &free_var_ids);
        let entry = u32::try_from(ir3.instructions.len()).map_err(|_| {
            LoweringPipelineError::InvariantViolation {
                detail: "IR3 instruction stream exceeds addressable size",
            }
        })?;
        let arity = u32::try_from(param_names.len()).map_err(|_| {
            LoweringPipelineError::InvariantViolation {
                detail: "Function parameter count exceeds the IR3 positional ABI",
            }
        })?;
        let mut fn_reg: Reg = 0;
        let mut fn_binding_regs = BTreeMap::<BindingId, Reg>::new();
        let mut fn_value_stack: Vec<Reg> = Vec::new();
        // bd-fqlfw.2.11.4: register discarded by the most recent function-body
        // `Pop`, so an immediately-following explicit `Return` (whose IR1 is
        // `[eval X, Pop, Return]`) can deliver that value instead of reading r0.
        let mut fn_last_popped: Option<Reg> = None;
        let mut fn_label_targets = BTreeMap::<u32, u32>::new();
        let mut fn_pending_jumps = Vec::<PendingJump>::new();
        let mut fn_catch_entry_labels = BTreeSet::<u32>::new();
        // Iterator registers to drop from the value stack when their loop's
        // done-label lands (bd-ddloz; mirrors the top-level pass).
        let mut fn_iterator_cleanup_labels = BTreeMap::<u32, Reg>::new();

        // Allocate parameter registers r0..rN-1.
        for (i, _pname) in param_names.iter().enumerate() {
            fn_binding_regs.insert(i as BindingId, i as Reg);
            fn_reg = fn_reg.max(i as Reg + 1);
        }

        // When this function has free variables, put parameters on the
        // scope chain so LoadScoped can find them alongside captured
        // outer bindings.
        if !free_vars.is_empty() {
            ir3.instructions.push(Ir3Instruction::PushScope);
            for (i, pname) in param_names.iter().enumerate() {
                let pool_idx = push_constant(&mut ir3.constant_pool, pname);
                ir3.instructions.push(Ir3Instruction::DeclareBinding {
                    name_pool_index: pool_idx,
                    kind: 0,
                });
                ir3.instructions.push(Ir3Instruction::InitBinding {
                    name_pool_index: pool_idx,
                    src: i as Reg,
                });
            }
        }

        // Exact free-variable binding_id -> name mapping, carried from IR1
        // via `free_var_ids` (paired index-wise with `free_vars` by
        // `collect_free_vars`). Replaces the old first-appearance zip
        // heuristic, which silently mis-bound names whenever the body's
        // first-use order diverged from the alphabetical `free_vars` order
        // (recursion, captured `let`s, multi-free-var closures) and swept
        // body locals into the free-var set (bd-snlhk; the engine shipped
        // the same fix as bd-g0aok).
        let fv_id_to_name: BTreeMap<BindingId, String> = free_var_ids
            .iter()
            .zip(free_vars.iter())
            .map(|(id, name)| (*id, name.clone()))
            .collect();

        // Collect the exact local binding IDs that child closures capture.
        // Name-only or ordinal reconstruction cannot distinguish nested
        // lexical shadows and can mirror an unrelated earlier local.
        let mut child_captured_bindings = BTreeMap::<BindingId, String>::new();
        for body_op in body_ops {
            let capture_metadata = match body_op {
                Ir1Op::CreateFunction {
                    free_vars,
                    free_var_ids,
                    free_var_outer_ids,
                    ..
                }
                | Ir1Op::DeclareFunction {
                    free_vars,
                    free_var_ids,
                    free_var_outer_ids,
                    ..
                } => Some((free_vars, free_var_ids, free_var_outer_ids)),
                _ => None,
            };
            let Some((names, body_ids, outer_ids)) = capture_metadata else {
                continue;
            };
            if names.len() != body_ids.len() || names.len() != outer_ids.len() {
                return Err(LoweringPipelineError::InvariantViolation {
                    detail: "Nested function capture metadata lengths differ",
                });
            }
            for (name, outer_id) in names.iter().zip(outer_ids.iter()) {
                child_captured_bindings.insert(*outer_id, name.clone());
            }
        }
        let has_capturing_children = !child_captured_bindings.is_empty();

        // If children capture our locals, push a scope frame at the
        // beginning of this function body.
        if has_capturing_children {
            ir3.instructions.push(Ir3Instruction::PushScope);
            // Put parameters on the scope chain too (children may capture them).
            for (i, pname) in param_names.iter().enumerate() {
                if child_captured_bindings.get(&(i as BindingId)) == Some(pname) {
                    let pool_idx = push_constant(&mut ir3.constant_pool, pname);
                    ir3.instructions.push(Ir3Instruction::DeclareBinding {
                        name_pool_index: pool_idx,
                        kind: 0,
                    });
                    ir3.instructions.push(Ir3Instruction::InitBinding {
                        name_pool_index: pool_idx,
                        src: i as Reg,
                    });
                }
            }
        }

        // Classify and infer the whole function body as one flow frame before
        // lowering it.  Per-op classification alone loses the accumulated
        // source label needed to guard a later declassification hostcall.
        let mut body_ir2_ops = body_ops
            .iter()
            .map(|body_ir1| {
                let (effect, required_capability, flow) = classify_ir1_op(body_ir1);
                Ir2Op {
                    inner: body_ir1.clone(),
                    effect,
                    required_capability,
                    flow,
                }
            })
            .collect::<Vec<_>>();
        infer_ir2_flow_annotations_for_ops(&mut body_ir2_ops);
        for ir2_op in &body_ir2_ops {
            let body_ir1 = &ir2_op.inner;
            if matches!(ir2_op.effect, EffectBoundary::HostcallEffect) {
                let capability = ir2_op
                    .required_capability
                    .clone()
                    .unwrap_or_else(|| CapabilityTag("hostcall.invoke".to_string()));
                let (start_reg, arg_count) = match body_ir1 {
                    Ir1Op::HostCall { arg_count, .. } => {
                        let count = *arg_count;
                        if count as usize > fn_value_stack.len() {
                            return Err(LoweringPipelineError::InvariantViolation {
                                detail: "Value stack underflow in function-body HostCall",
                            });
                        }
                        let mut args = Vec::with_capacity(count as usize);
                        for _ in 0..count {
                            args.push(fn_value_stack.pop().unwrap_or(0));
                        }
                        args.reverse();
                        let start = fn_reg;
                        for arg_reg in args {
                            let dst = alloc_register(&mut fn_reg);
                            ir3.instructions
                                .push(Ir3Instruction::Move { dst, src: arg_reg });
                        }
                        (start, count)
                    }
                    _ => {
                        let hostcall_arg = fn_value_stack.pop().unwrap_or(0);
                        let start = alloc_register(&mut fn_reg);
                        ir3.instructions.push(Ir3Instruction::Move {
                            dst: start,
                            src: hostcall_arg,
                        });
                        (start, 1)
                    }
                };

                if flow_requires_runtime_check(ir2_op.flow.as_ref(), &capability) {
                    required_capabilities.insert(IFC_RUNTIME_GUARD_CAPABILITY.to_string());
                    let guard_dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::HostCall {
                        capability: CapabilityTag(IFC_RUNTIME_GUARD_CAPABILITY.to_string()),
                        args: RegRange {
                            start: start_reg,
                            count: arg_count,
                        },
                        dst: guard_dst,
                    });
                }
                required_capabilities.insert(capability.0.clone());
                let dst = alloc_register(&mut fn_reg);
                ir3.instructions.push(Ir3Instruction::HostCall {
                    capability,
                    args: RegRange {
                        start: start_reg,
                        count: arg_count,
                    },
                    dst,
                });
                fn_value_stack.push(dst);
                continue;
            }
            // We handle a core subset of ops that appear in function bodies.
            match body_ir1 {
                Ir1Op::LoadLiteral { value } => {
                    let dst = alloc_register(&mut fn_reg);
                    match value {
                        Ir1Literal::Integer(n) => {
                            ir3.instructions
                                .push(Ir3Instruction::LoadInt { dst, value: *n });
                        }
                        Ir1Literal::Float(bits) => {
                            ir3.instructions
                                .push(Ir3Instruction::LoadFloat { dst, bits: *bits });
                        }
                        Ir1Literal::String(s) => {
                            let pool_index = push_constant(&mut ir3.constant_pool, s);
                            ir3.instructions
                                .push(Ir3Instruction::LoadStr { dst, pool_index });
                        }
                        Ir1Literal::Boolean(b) => {
                            ir3.instructions
                                .push(Ir3Instruction::LoadBool { dst, value: *b });
                        }
                        Ir1Literal::Null => {
                            ir3.instructions.push(Ir3Instruction::LoadNull { dst });
                        }
                        Ir1Literal::Undefined => {
                            ir3.instructions.push(Ir3Instruction::LoadUndefined { dst });
                        }
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::LoadBinding { binding_id } => {
                    if let Some(name) = fv_id_to_name.get(binding_id) {
                        // Free variable: load from scope chain by name.
                        let dst = alloc_register(&mut fn_reg);
                        let pool_idx = push_constant(&mut ir3.constant_pool, name);
                        ir3.instructions.push(Ir3Instruction::LoadScoped {
                            dst,
                            name_pool_index: pool_idx,
                        });
                        fn_value_stack.push(dst);
                    } else {
                        let src = *fn_binding_regs
                            .entry(*binding_id)
                            .or_insert_with(|| alloc_register(&mut fn_reg));
                        let dst = alloc_register(&mut fn_reg);
                        ir3.instructions.push(Ir3Instruction::Move { dst, src });
                        fn_value_stack.push(dst);
                    }
                }
                Ir1Op::StoreBinding { binding_id } => {
                    let is_first_store = !fn_binding_regs.contains_key(binding_id);
                    let dst = *fn_binding_regs
                        .entry(*binding_id)
                        .or_insert_with(|| alloc_register(&mut fn_reg));
                    let src = fn_value_stack.pop().unwrap_or(0);
                    ir3.instructions.push(Ir3Instruction::Move { dst, src });
                    // If this function has capturing children and this
                    // binding is being stored for the first time (i.e.,
                    // it's a local variable init, not a parameter
                    // already handled above), also put it on the scope
                    // chain so child closures can find it via LoadScoped.
                    if has_capturing_children
                        && *binding_id >= param_names.len() as BindingId
                        && let Some(name) = child_captured_bindings.get(binding_id)
                    {
                        let pool_idx = push_constant(&mut ir3.constant_pool, name);
                        if is_first_store {
                            ir3.instructions.push(Ir3Instruction::DeclareBinding {
                                name_pool_index: pool_idx,
                                kind: 0,
                            });
                        }
                        ir3.instructions.push(Ir3Instruction::StoreScoped {
                            src: dst,
                            name_pool_index: pool_idx,
                        });
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::BinaryOp { operator } => {
                    let rhs = fn_value_stack.pop().unwrap_or(0);
                    let lhs = fn_value_stack.pop().unwrap_or(0);
                    let dst = alloc_register(&mut fn_reg);
                    let instr = lower_binary_op_to_ir3(*operator, dst, lhs, rhs);
                    ir3.instructions.push(instr);
                    fn_value_stack.push(dst);
                }
                Ir1Op::UnaryOp { operator } => {
                    let operand = fn_value_stack.pop().unwrap_or(0);
                    let dst = alloc_register(&mut fn_reg);
                    let instr = lower_unary_op_to_ir3(*operator, dst, operand);
                    ir3.instructions.push(instr);
                    fn_value_stack.push(dst);
                }
                Ir1Op::Return => {
                    // bd-fqlfw.2.11.4: deliver the actual return value. The
                    // synthetic fall-off-end return (`[LoadLiteral Undefined,
                    // Return]`, no Pop — appended ~line 2164) leaves its value on
                    // the stack, so prefer the stack top; an explicit `return X`
                    // (`[eval X, Pop, Return]`) emptied the stack via its Pop, so
                    // fall back to the register that Pop discarded
                    // (`fn_last_popped`). `unwrap_or(0)` only as a last resort.
                    let value = fn_value_stack.pop().or(fn_last_popped).unwrap_or(0);
                    ir3.instructions.push(Ir3Instruction::Return { value });
                }
                Ir1Op::Call { arg_count } => {
                    let count = *arg_count as usize;
                    let mut args = Vec::with_capacity(count);
                    for _ in 0..count {
                        args.push(fn_value_stack.pop().unwrap_or(0));
                    }
                    args.reverse();
                    let callee = fn_value_stack.pop().unwrap_or(0);
                    let start_reg = fn_reg;
                    for arg_reg in &args {
                        let dst = alloc_register(&mut fn_reg);
                        ir3.instructions
                            .push(Ir3Instruction::Move { dst, src: *arg_reg });
                    }
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::Call {
                        callee,
                        args: RegRange {
                            start: start_reg,
                            count: count as u32,
                        },
                        dst,
                    });
                    fn_value_stack.push(dst);
                }
                Ir1Op::CallMethod { arg_count } => {
                    let count = *arg_count as usize;
                    let mut args = Vec::with_capacity(count);
                    for _ in 0..count {
                        args.push(fn_value_stack.pop().unwrap_or(0));
                    }
                    args.reverse();
                    let receiver = fn_value_stack.pop().unwrap_or(0);
                    let callee = fn_value_stack.pop().unwrap_or(0);
                    let start_reg = fn_reg;
                    for arg_reg in &args {
                        let dst = alloc_register(&mut fn_reg);
                        ir3.instructions
                            .push(Ir3Instruction::Move { dst, src: *arg_reg });
                    }
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::CallMethod {
                        receiver,
                        callee,
                        args: RegRange {
                            start: start_reg,
                            count: count as u32,
                        },
                        dst,
                    });
                    fn_value_stack.push(dst);
                }
                Ir1Op::Label { id } => {
                    let target = u32::try_from(ir3.instructions.len()).map_err(|_| {
                        LoweringPipelineError::InvariantViolation {
                            detail: "IR3 instruction stream exceeds addressable size",
                        }
                    })?;
                    if fn_label_targets.insert(*id, target).is_some() {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "Deferred function body contains duplicate label ids",
                        });
                    }
                    if fn_catch_entry_labels.contains(id) {
                        let dst = alloc_register(&mut fn_reg);
                        ir3.instructions.push(Ir3Instruction::EnterCatch { dst });
                        fn_value_stack.push(dst);
                    }
                    // A for..in/of done-label lands with the iterator
                    // register still on the value stack; drop it so the
                    // stack stays balanced (bd-ddloz; mirrors the
                    // top-level pass).
                    if fn_iterator_cleanup_labels
                        .get(id)
                        .is_some_and(|expected| fn_value_stack.last() == Some(expected))
                    {
                        fn_value_stack.pop();
                    }
                }
                Ir1Op::Jump { label_id } => {
                    let idx = ir3.instructions.len();
                    ir3.instructions.push(Ir3Instruction::Jump { target: 0 });
                    fn_pending_jumps.push(PendingJump::Unconditional {
                        instruction_index: idx,
                        label_id: *label_id,
                    });
                }
                Ir1Op::JumpIfFalsy { label_id } => {
                    // Jump to `label_id` when the condition is FALSY. The
                    // interpreter's `JumpIf` jumps on TRUTHY, so a bare
                    // `JumpIf { cond, target: label }` here INVERTED every
                    // function-body conditional and loop test — `if (c) {..}`
                    // skipped its body when `c` was true and a `for`/`while`
                    // test fell straight through to the loop end, so a
                    // loop-accumulate IIFE returned its pre-loop value
                    // (bd-my5ar). Emit the same two-instruction
                    // "skip-on-truthy, then unconditional jump-to-label"
                    // pattern the module-level loop uses (`PendingJump::JumpIfFalsy`).
                    // Non-consuming: the condition register stays on the value
                    // stack for the trailing `Pop` the lowering emits after the test.
                    let cond = fn_value_stack.pop().unwrap_or(0);
                    let truthy_skip_index = ir3.instructions.len();
                    ir3.instructions
                        .push(Ir3Instruction::JumpIf { cond, target: 0 });
                    let falsy_jump_index = ir3.instructions.len();
                    ir3.instructions.push(Ir3Instruction::Jump { target: 0 });
                    fn_pending_jumps.push(PendingJump::JumpIfFalsy {
                        truthy_skip_index,
                        falsy_jump_index,
                        label_id: *label_id,
                    });
                    fn_value_stack.push(cond);
                }
                Ir1Op::JumpIfFalsyConsume { label_id } => {
                    // Same falsy-jump shape as `JumpIfFalsy`, but consumes the
                    // condition register (does not leave it on the value stack).
                    let cond = fn_value_stack.pop().unwrap_or(0);
                    let truthy_skip_index = ir3.instructions.len();
                    ir3.instructions
                        .push(Ir3Instruction::JumpIf { cond, target: 0 });
                    let falsy_jump_index = ir3.instructions.len();
                    ir3.instructions.push(Ir3Instruction::Jump { target: 0 });
                    fn_pending_jumps.push(PendingJump::JumpIfFalsy {
                        truthy_skip_index,
                        falsy_jump_index,
                        label_id: *label_id,
                    });
                }
                Ir1Op::JumpIfTruthy { label_id } => {
                    let cond = fn_value_stack.pop().unwrap_or(0);
                    let idx = ir3.instructions.len();
                    ir3.instructions
                        .push(Ir3Instruction::JumpIf { cond, target: 0 });
                    fn_pending_jumps.push(PendingJump::Conditional {
                        instruction_index: idx,
                        label_id: *label_id,
                    });
                }
                Ir1Op::JumpIfNullish { label_id } => {
                    let cond = fn_value_stack.pop().ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail:
                                "JumpIfNullish requires a condition register in a function body",
                        },
                    )?;
                    let instruction_index = ir3.instructions.len();
                    ir3.instructions
                        .push(Ir3Instruction::JumpIfNullish { cond, target: 0 });
                    fn_pending_jumps.push(PendingJump::Conditional {
                        instruction_index,
                        label_id: *label_id,
                    });
                }
                Ir1Op::Pop | Ir1Op::Nop => {
                    let reg = fn_value_stack.pop().unwrap_or(0);
                    if matches!(body_ir1, Ir1Op::Pop) {
                        // bd-fqlfw.2.11.4: a function-body `Pop` must DISCARD the
                        // expression value, NOT route it through register 0. r0 is
                        // the function's first parameter (the calling convention
                        // writes args to the callee window at r0,r1,...), so the
                        // old `Move { dst: 0, src: reg }` clobbered param0 —
                        // corrupting any `return <param0>` (or re-read of param0)
                        // that followed an expression statement. Remember the
                        // discarded register so an immediately-following `Return`
                        // (the IR1 for `return X` is `[eval X, Pop, Return]`, whose
                        // `Pop` empties the value stack) delivers the actual value
                        // rather than underflowing to r0. The module-level Pop
                        // handler keeps its r0-completion convention (it reserves
                        // r0); only this deferred function-body loop changes. The
                        // engine lane already discards here (bd-62un6).
                        fn_last_popped = Some(reg);
                    }
                }
                Ir1Op::AssignOp {
                    binding_id,
                    operator,
                } => {
                    let src = fn_value_stack.pop().unwrap_or(0);
                    let dst = *fn_binding_regs
                        .entry(*binding_id)
                        .or_insert_with(|| alloc_register(&mut fn_reg));
                    if *operator == AssignmentOperator::Assign {
                        ir3.instructions.push(Ir3Instruction::Move { dst, src });
                    } else {
                        let result = alloc_register(&mut fn_reg);
                        let instr = lower_assign_op_to_ir3(*operator, result, dst, src);
                        ir3.instructions.push(instr);
                        ir3.instructions
                            .push(Ir3Instruction::Move { dst, src: result });
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::GetProperty { key } => {
                    let (obj, key_reg) = match key {
                        Ir1PropertyKey::Static(k) => {
                            let obj = fn_value_stack.pop().unwrap_or(0);
                            let kr = alloc_register(&mut fn_reg);
                            let pool_index = push_constant(&mut ir3.constant_pool, k);
                            ir3.instructions.push(Ir3Instruction::LoadStr {
                                dst: kr,
                                pool_index,
                            });
                            (obj, kr)
                        }
                        Ir1PropertyKey::Dynamic => {
                            let kr = fn_value_stack.pop().unwrap_or(0);
                            let obj = fn_value_stack.pop().unwrap_or(0);
                            (obj, kr)
                        }
                    };
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::GetProperty {
                        obj,
                        key: key_reg,
                        dst,
                    });
                    fn_value_stack.push(dst);
                }
                Ir1Op::SetProperty { key } => {
                    let value = fn_value_stack.pop().unwrap_or(0);
                    let (obj, key_reg) = match key {
                        Ir1PropertyKey::Static(k) => {
                            let obj = fn_value_stack.pop().unwrap_or(0);
                            let kr = alloc_register(&mut fn_reg);
                            let pool_index = push_constant(&mut ir3.constant_pool, k);
                            ir3.instructions.push(Ir3Instruction::LoadStr {
                                dst: kr,
                                pool_index,
                            });
                            (obj, kr)
                        }
                        Ir1PropertyKey::Dynamic => {
                            let kr = fn_value_stack.pop().unwrap_or(0);
                            let obj = fn_value_stack.pop().unwrap_or(0);
                            (obj, kr)
                        }
                    };
                    ir3.instructions.push(Ir3Instruction::SetProperty {
                        obj,
                        key: key_reg,
                        val: value,
                    });
                    fn_value_stack.push(value);
                }
                Ir1Op::DeleteProperty { key } => {
                    let (obj, key_reg) = match key {
                        Ir1PropertyKey::Static(key) => {
                            let obj = fn_value_stack.pop().ok_or(
                                LoweringPipelineError::InvariantViolation {
                                    detail:
                                        "DeleteProperty requires an object register in a function body",
                                },
                            )?;
                            let key_reg = alloc_register(&mut fn_reg);
                            let pool_index = push_constant(&mut ir3.constant_pool, key);
                            ir3.instructions.push(Ir3Instruction::LoadStr {
                                dst: key_reg,
                                pool_index,
                            });
                            (obj, key_reg)
                        }
                        Ir1PropertyKey::Dynamic => {
                            let key_reg = fn_value_stack.pop().ok_or(
                                LoweringPipelineError::InvariantViolation {
                                    detail:
                                        "DeleteProperty requires a key register in a function body",
                                },
                            )?;
                            let obj = fn_value_stack.pop().ok_or(
                                LoweringPipelineError::InvariantViolation {
                                    detail:
                                        "DeleteProperty requires an object register in a function body",
                                },
                            )?;
                            (obj, key_reg)
                        }
                    };
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::DeleteProperty {
                        obj,
                        key: key_reg,
                        dst,
                    });
                    fn_value_stack.push(dst);
                }
                Ir1Op::LoadThis => {
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::LoadThis { dst });
                    fn_value_stack.push(dst);
                }
                Ir1Op::LoadNewTarget => {
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::LoadNewTarget { dst });
                    fn_value_stack.push(dst);
                }
                Ir1Op::LoadSuper => {
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::LoadSuper { dst });
                    fn_value_stack.push(dst);
                }
                Ir1Op::NewArray { count } => {
                    let cnt = *count as usize;
                    let mut elems = Vec::with_capacity(cnt);
                    for _ in 0..cnt {
                        elems.push(fn_value_stack.pop().unwrap_or(0));
                    }
                    elems.reverse();
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::NewArray { dst });
                    for (i, val_reg) in elems.into_iter().enumerate() {
                        let key_reg = alloc_register(&mut fn_reg);
                        let pool_index = push_constant(&mut ir3.constant_pool, &i.to_string());
                        ir3.instructions.push(Ir3Instruction::LoadStr {
                            dst: key_reg,
                            pool_index,
                        });
                        ir3.instructions.push(Ir3Instruction::SetProperty {
                            obj: dst,
                            key: key_reg,
                            val: val_reg,
                        });
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::NewObject { count } => {
                    let cnt = *count as usize;
                    let mut properties = Vec::with_capacity(cnt);
                    for _ in 0..cnt {
                        let val = fn_value_stack.pop().unwrap_or(0);
                        let key = fn_value_stack.pop().unwrap_or(0);
                        properties.push((key, val));
                    }
                    properties.reverse();
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::NewObject { dst });
                    for (key_reg, val_reg) in properties {
                        ir3.instructions.push(Ir3Instruction::SetProperty {
                            obj: dst,
                            key: key_reg,
                            val: val_reg,
                        });
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::ArrayPush => {
                    // Stack: [..., array, element] -> [..., array]
                    let element = fn_value_stack.pop().unwrap_or(0);
                    let array = fn_value_stack.pop().unwrap_or(0);
                    ir3.instructions
                        .push(Ir3Instruction::ArrayPush { array, element });
                    fn_value_stack.push(array);
                }
                Ir1Op::ArraySlice => {
                    // Stack: [..., array, start_index] -> [..., sliced_array]
                    let start = fn_value_stack.pop().unwrap_or(0);
                    let array = fn_value_stack.pop().unwrap_or(0);
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions
                        .push(Ir3Instruction::ArraySlice { array, start, dst });
                    fn_value_stack.push(dst);
                }
                Ir1Op::SpreadIntoArray => {
                    // Stack: [..., array, iterable] -> [..., array]
                    let iterable = fn_value_stack.pop().unwrap_or(0);
                    let array = fn_value_stack.pop().unwrap_or(0);
                    ir3.instructions
                        .push(Ir3Instruction::SpreadIntoArray { array, iterable });
                    fn_value_stack.push(array);
                }
                Ir1Op::SpreadIntoObject => {
                    // Stack: [..., target, source] -> [..., target]
                    let source = fn_value_stack.pop().unwrap_or(0);
                    let target = fn_value_stack.pop().unwrap_or(0);
                    ir3.instructions
                        .push(Ir3Instruction::SpreadIntoObject { target, source });
                    fn_value_stack.push(target);
                }
                Ir1Op::Throw => {
                    let value = fn_value_stack.pop().unwrap_or(0);
                    ir3.instructions.push(Ir3Instruction::Throw { value });
                }
                Ir1Op::BeginTry {
                    catch_label,
                    finally_label,
                } => {
                    if finally_label.as_ref() != Some(catch_label) {
                        fn_catch_entry_labels.insert(*catch_label);
                    }
                    let instruction_index = ir3.instructions.len();
                    ir3.instructions.push(Ir3Instruction::BeginTry {
                        catch_target: 0,
                        finally_target: None,
                    });
                    fn_pending_jumps.push(PendingJump::TryCatch {
                        instruction_index,
                        catch_label_id: *catch_label,
                        finally_label_id: *finally_label,
                    });
                }
                Ir1Op::EndTry => {
                    ir3.instructions.push(Ir3Instruction::EndTry);
                }
                Ir1Op::EnterFinally => {
                    ir3.instructions.push(Ir3Instruction::EnterFinally);
                }
                Ir1Op::EndFinally => {
                    ir3.instructions.push(Ir3Instruction::EndFinally);
                }
                Ir1Op::DiscardAbruptCompletion => {
                    ir3.instructions
                        .push(Ir3Instruction::DiscardAbruptCompletion);
                }
                // Nested function definitions inside function bodies.
                Ir1Op::DeclareFunction {
                    binding_id: inner_bid,
                    body_ops: inner_body,
                    param_names: inner_params,
                    name: inner_name,
                    free_vars: inner_fv,
                    free_var_ids: inner_fv_ids,
                    free_var_outer_ids: inner_fv_outer_ids,
                    is_generator: inner_gen,
                    rest_param_index: inner_rest,
                } if !inner_body.is_empty() => {
                    let dst = *fn_binding_regs
                        .entry(*inner_bid)
                        .or_insert_with(|| alloc_register(&mut fn_reg));
                    let function_index = deferred_functions.len() as u32 + 1;
                    deferred_functions.push((
                        inner_body.clone(),
                        inner_params.clone(),
                        Some(inner_name.clone()),
                        inner_fv.clone(),
                        inner_fv_ids.clone(),
                        *inner_gen,
                        *inner_rest,
                    ));
                    let pushed_capture_scope = emit_exact_nested_capture_scope(
                        &mut ir3,
                        &mut fn_binding_regs,
                        &fv_id_to_name,
                        &mut fn_reg,
                        inner_fv,
                        inner_fv_ids,
                        inner_fv_outer_ids,
                    )?;
                    if *inner_gen {
                        ir3.instructions.push(Ir3Instruction::CreateGenerator {
                            dst,
                            function_index,
                            capture_count: inner_fv.len() as u32,
                        });
                    } else {
                        ir3.instructions.push(Ir3Instruction::CreateClosure {
                            dst,
                            function_index,
                            capture_count: inner_fv.len() as u32,
                        });
                    }
                    if pushed_capture_scope {
                        ir3.instructions.push(Ir3Instruction::PopScope);
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::CreateFunction {
                    body_ops: inner_body,
                    param_names: inner_params,
                    name: inner_name,
                    free_vars: inner_fv,
                    free_var_ids: inner_fv_ids,
                    free_var_outer_ids: inner_fv_outer_ids,
                    is_generator: inner_gen,
                    rest_param_index: inner_rest,
                    ..
                } => {
                    let dst = alloc_register(&mut fn_reg);
                    let function_index = deferred_functions.len() as u32 + 1;
                    deferred_functions.push((
                        inner_body.clone(),
                        inner_params.clone(),
                        inner_name.clone(),
                        inner_fv.clone(),
                        inner_fv_ids.clone(),
                        *inner_gen,
                        *inner_rest,
                    ));
                    let pushed_capture_scope = emit_exact_nested_capture_scope(
                        &mut ir3,
                        &mut fn_binding_regs,
                        &fv_id_to_name,
                        &mut fn_reg,
                        inner_fv,
                        inner_fv_ids,
                        inner_fv_outer_ids,
                    )?;
                    if *inner_gen {
                        ir3.instructions.push(Ir3Instruction::CreateGenerator {
                            dst,
                            function_index,
                            capture_count: inner_fv.len() as u32,
                        });
                    } else {
                        ir3.instructions.push(Ir3Instruction::CreateClosure {
                            dst,
                            function_index,
                            capture_count: inner_fv.len() as u32,
                        });
                    }
                    if pushed_capture_scope {
                        ir3.instructions.push(Ir3Instruction::PopScope);
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::Yield { delegate } => {
                    let value_reg = fn_value_stack.pop().unwrap_or(0);
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions.push(Ir3Instruction::Yield {
                        value: value_reg,
                        delegate: *delegate,
                        resume_dst: dst,
                    });
                    fn_value_stack.push(dst);
                }
                Ir1Op::Await => {
                    let current = fn_value_stack.pop().unwrap_or(0);
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions
                        .push(Ir3Instruction::Move { dst, src: current });
                    fn_value_stack.push(dst);
                }
                // Iterator-protocol ops (bd-ddloz): mirror the top-level
                // pass. Previously these fell through to the nop arm below,
                // so a for..of/for..in inside a function body kept its loop
                // jumps but lost its iterator init/advance and spun to
                // instruction-budget exhaustion.
                Ir1Op::ForInInit => {
                    let src = fn_value_stack.pop().ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "ForInInit requires an iterable register on the value stack",
                        },
                    )?;
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions
                        .push(Ir3Instruction::ForInInit { src, dst });
                    fn_value_stack.push(dst);
                }
                Ir1Op::ForOfInit => {
                    let src = fn_value_stack.pop().ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "ForOfInit requires an iterable register on the value stack",
                        },
                    )?;
                    let dst = alloc_register(&mut fn_reg);
                    ir3.instructions
                        .push(Ir3Instruction::ForOfInit { src, dst });
                    fn_value_stack.push(dst);
                }
                Ir1Op::ForInNext { done_label } => {
                    let iterator = fn_value_stack.last().copied().ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail:
                                "ForInNext requires an active iterator register on the value stack",
                        },
                    )?;
                    let value_dst = alloc_register(&mut fn_reg);
                    let instruction_index = ir3.instructions.len();
                    ir3.instructions.push(Ir3Instruction::ForInNext {
                        iterator,
                        value_dst,
                        done_target: 0,
                    });
                    fn_pending_jumps.push(PendingJump::IteratorDoneTarget {
                        instruction_index,
                        label_id: *done_label,
                    });
                    fn_iterator_cleanup_labels
                        .entry(*done_label)
                        .or_insert(iterator);
                    fn_value_stack.push(value_dst);
                }
                Ir1Op::ForOfNext { done_label } => {
                    let iterator = fn_value_stack.last().copied().ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail:
                                "ForOfNext requires an active iterator register on the value stack",
                        },
                    )?;
                    let value_dst = alloc_register(&mut fn_reg);
                    let instruction_index = ir3.instructions.len();
                    ir3.instructions.push(Ir3Instruction::ForOfNext {
                        iterator,
                        value_dst,
                        done_target: 0,
                    });
                    fn_pending_jumps.push(PendingJump::IteratorDoneTarget {
                        instruction_index,
                        label_id: *done_label,
                    });
                    fn_iterator_cleanup_labels
                        .entry(*done_label)
                        .or_insert(iterator);
                    fn_value_stack.push(value_dst);
                }
                Ir1Op::IteratorClose { reason } => {
                    let iterator = fn_value_stack.pop().ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail:
                                "IteratorClose requires an active iterator register on the value stack",
                        },
                    )?;
                    ir3.instructions.push(Ir3Instruction::IteratorClose {
                        iterator,
                        reason: *reason,
                    });
                }
                Ir1Op::Construct { arg_count } => {
                    let count = *arg_count as usize;
                    if count
                        .checked_add(1)
                        .is_none_or(|needed| needed > fn_value_stack.len())
                    {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "Value stack underflow in function-body Construct",
                        });
                    }
                    let mut args = Vec::with_capacity(count.min(1024));
                    for _ in 0..count {
                        args.push(fn_value_stack.pop().unwrap_or(0));
                    }
                    args.reverse();
                    let callee = fn_value_stack.pop().unwrap_or(0);
                    let dst = alloc_register(&mut fn_reg);
                    let args = if args.is_empty() {
                        RegRange { start: 0, count: 0 }
                    } else {
                        let start = fn_reg;
                        for src in args {
                            let contiguous_dst = alloc_register(&mut fn_reg);
                            ir3.instructions.push(Ir3Instruction::Move {
                                dst: contiguous_dst,
                                src,
                            });
                        }
                        RegRange {
                            start,
                            count: *arg_count,
                        }
                    };
                    ir3.instructions
                        .push(Ir3Instruction::Construct { callee, args, dst });
                    fn_value_stack.push(dst);
                }
                Ir1Op::TemplateLiteral { quasi_count } => {
                    let quasi_count = *quasi_count as usize;
                    let part_count = if quasi_count == 0 {
                        0
                    } else {
                        quasi_count
                            .checked_mul(2)
                            .and_then(|n| n.checked_sub(1))
                            .ok_or(LoweringPipelineError::InvariantViolation {
                                detail: "Function-body template literal part count overflow",
                            })?
                    };
                    if part_count > fn_value_stack.len() {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "Value stack underflow in function-body TemplateLiteral",
                        });
                    }
                    let mut parts = Vec::with_capacity(part_count.min(1024));
                    for _ in 0..part_count {
                        parts.push(fn_value_stack.pop().unwrap_or(0));
                    }
                    parts.reverse();

                    let dst = alloc_register(&mut fn_reg);
                    if parts.is_empty() {
                        let pool_index = push_constant(&mut ir3.constant_pool, "");
                        ir3.instructions
                            .push(Ir3Instruction::LoadStr { dst, pool_index });
                    } else {
                        let start = fn_reg;
                        for src in parts {
                            let contiguous_dst = alloc_register(&mut fn_reg);
                            ir3.instructions.push(Ir3Instruction::Move {
                                dst: contiguous_dst,
                                src,
                            });
                        }
                        ir3.instructions.push(Ir3Instruction::TemplateLiteral {
                            parts: RegRange {
                                start,
                                count: part_count as u32,
                            },
                            dst,
                        });
                    }
                    fn_value_stack.push(dst);
                }
                Ir1Op::ImportModule { .. } => {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "ImportModule is not valid in a deferred function body",
                    });
                }
                Ir1Op::ExportBinding { .. } => {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "ExportBinding is not valid in a deferred function body",
                    });
                }
                Ir1Op::DeclareFunction { .. } => {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "Deferred function declaration has an empty body",
                    });
                }
                Ir1Op::HostCall { .. } => {
                    return Err(LoweringPipelineError::InvariantViolation {
                        detail: "HostCall bypassed function-body capability lowering",
                    });
                }
            }
        }

        // Ensure function body ends with Return.
        if !matches!(ir3.instructions.last(), Some(Ir3Instruction::Return { .. })) {
            // bd-fqlfw.2.11.4: fall-off-end returns `undefined` per spec, NOT r0
            // (which now holds param0, since the function-body Pop no longer
            // routes the completion value through r0). This tail is normally
            // unreachable — the IR1 builder already appends a synthetic
            // `[LoadLiteral Undefined, Return]` (~line 2164) — but keep it
            // spec-correct should a future body-lowering path skip that.
            let undef = alloc_register(&mut fn_reg);
            ir3.instructions
                .push(Ir3Instruction::LoadUndefined { dst: undef });
            ir3.instructions
                .push(Ir3Instruction::Return { value: undef });
        }

        // Resolve pending jumps within this function body.
        for pj in fn_pending_jumps {
            match pj {
                PendingJump::Unconditional {
                    instruction_index,
                    label_id,
                } => {
                    let target = *fn_label_targets.get(&label_id).ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "function-body control-flow references missing label",
                        },
                    )?;
                    ir3.instructions[instruction_index] = Ir3Instruction::Jump { target };
                }
                PendingJump::Conditional {
                    instruction_index,
                    label_id,
                } => {
                    let target = *fn_label_targets.get(&label_id).ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "function-body control-flow references missing label",
                        },
                    )?;
                    match &mut ir3.instructions[instruction_index] {
                        Ir3Instruction::JumpIf {
                            target: jump_target,
                            ..
                        }
                        | Ir3Instruction::JumpIfNullish {
                            target: jump_target,
                            ..
                        } => {
                            *jump_target = target;
                        }
                        _ => {
                            return Err(LoweringPipelineError::InvariantViolation {
                                detail: "function-body conditional lowering emitted unexpected instruction shape",
                            });
                        }
                    }
                }
                PendingJump::JumpIfFalsy {
                    truthy_skip_index,
                    falsy_jump_index,
                    label_id,
                } => {
                    // Wire the two-instruction falsy-jump pattern emitted above:
                    // `JumpIf` skips the unconditional `Jump` when the condition
                    // is truthy (so control falls through past the loop/if
                    // target); the `Jump` carries the falsy branch to `label_id`.
                    let falsy_target = *fn_label_targets.get(&label_id).ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "function-body control-flow references missing label",
                        },
                    )?;
                    let truthy_target = u32::try_from(falsy_jump_index + 1).map_err(|_| {
                        LoweringPipelineError::InvariantViolation {
                            detail: "IR3 instruction stream exceeds addressable size",
                        }
                    })?;
                    let cond = match ir3.instructions[truthy_skip_index] {
                        Ir3Instruction::JumpIf { cond, .. } => cond,
                        _ => {
                            return Err(LoweringPipelineError::InvariantViolation {
                                detail: "function-body conditional lowering emitted unexpected instruction shape",
                            });
                        }
                    };
                    ir3.instructions[truthy_skip_index] = Ir3Instruction::JumpIf {
                        cond,
                        target: truthy_target,
                    };
                    ir3.instructions[falsy_jump_index] = Ir3Instruction::Jump {
                        target: falsy_target,
                    };
                }
                PendingJump::IteratorDoneTarget {
                    instruction_index,
                    label_id,
                } => {
                    // Fail closed on a missing done-label: a ForIn/ForOfNext
                    // whose done_target stays 0 would jump into unrelated
                    // code instead of exiting the loop (bd-ddloz).
                    let target = *fn_label_targets.get(&label_id).ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "iterator lowering references missing label",
                        },
                    )?;
                    match &mut ir3.instructions[instruction_index] {
                        Ir3Instruction::ForInNext { done_target, .. }
                        | Ir3Instruction::ForOfNext { done_target, .. } => {
                            *done_target = target;
                        }
                        _ => {
                            return Err(LoweringPipelineError::InvariantViolation {
                                detail: "iterator lowering emitted unexpected instruction shape",
                            });
                        }
                    }
                }
                PendingJump::TryCatch {
                    instruction_index,
                    catch_label_id,
                    finally_label_id,
                } => {
                    let catch_target = *fn_label_targets.get(&catch_label_id).ok_or(
                        LoweringPipelineError::InvariantViolation {
                            detail: "function try/catch lowering references missing catch label",
                        },
                    )?;
                    let finally_target = if let Some(finally_label_id) = finally_label_id {
                        Some(*fn_label_targets.get(&finally_label_id).ok_or(
                            LoweringPipelineError::InvariantViolation {
                                detail: "function try/finally lowering references missing finally label",
                            },
                        )?)
                    } else {
                        None
                    };
                    ir3.instructions[instruction_index] = Ir3Instruction::BeginTry {
                        catch_target,
                        finally_target,
                    };
                }
            }
        }

        ir3.function_table.push(Ir3FunctionDesc {
            entry,
            arity,
            frame_size: fn_reg.max(1),
            name: fn_name.clone(),
            is_generator: fn_is_generator,
            rest_param_index: fn_rest_param_index,
        });
    }

    ir3.required_capabilities = required_capabilities
        .into_iter()
        .map(CapabilityTag)
        .collect();

    verify_ir3_specialization(&ir3).map_err(lowering_error_from_ir_error)?;

    let source_hash_matches = ir3.header.source_hash.as_ref() == Some(&ir2_hash);
    let has_main_function = !ir3.function_table.is_empty();
    // Function bodies are appended after the main Halt, so the last
    // instruction may be a Return from the final deferred body.  Check
    // that a Halt exists anywhere in the stream (the main block always
    // emits one at the end of its own instruction window).
    let has_terminal_halt = ir3
        .instructions
        .iter()
        .any(|i| matches!(i, Ir3Instruction::Halt));
    let instruction_len = ir3.instructions.len();
    let control_flow_targets_resolved =
        ir3.instructions
            .iter()
            .all(|instruction| match instruction {
                Ir3Instruction::Jump { target }
                | Ir3Instruction::JumpIf { target, .. }
                | Ir3Instruction::JumpIfNullish { target, .. }
                | Ir3Instruction::ForInNext {
                    done_target: target,
                    ..
                }
                | Ir3Instruction::ForOfNext {
                    done_target: target,
                    ..
                } => (*target as usize) < instruction_len,
                _ => true,
            });
    let checks = vec![
        InvariantCheck {
            name: "source_hash_linkage".to_string(),
            passed: source_hash_matches,
            detail: "IR3 source_hash references IR2 hash".to_string(),
        },
        InvariantCheck {
            name: "function_table_present".to_string(),
            passed: has_main_function,
            detail: "IR3 function table contains a deterministic main entry".to_string(),
        },
        InvariantCheck {
            name: "terminal_halt_instruction".to_string(),
            passed: has_terminal_halt,
            detail: "IR3 instruction stream ends with HALT".to_string(),
        },
        InvariantCheck {
            name: "resolved_control_flow_targets".to_string(),
            passed: control_flow_targets_resolved,
            detail: "IR3 jump targets resolve to concrete instruction indices".to_string(),
        },
    ];
    ensure_checks_pass(&checks, "IR3 invariants failed")?;

    let ir3_hash = ir3.content_hash();
    Ok(LoweringPassResult {
        ledger_entry: IsomorphismLedgerEntry {
            pass_id: "ir2_to_ir3".to_string(),
            input_hash: hash_string(&ir2_hash),
            output_hash: hash_string(&ir3_hash),
            input_op_count: ir2.ops.len() as u64,
            output_op_count: ir3.instructions.len() as u64,
        },
        witness: PassWitness {
            pass_id: "ir2_to_ir3".to_string(),
            input_hash: hash_string(&ir2_hash),
            output_hash: hash_string(&ir3_hash),
            rollback_token: hash_string(&ir2_hash),
            invariant_checks: checks,
        },
        module: ir3,
    })
}

fn build_ir2_flow_proof_artifact(
    ir2: &Ir2Module,
    context: &LoweringContext,
) -> Result<Ir2FlowProofArtifact, LoweringPipelineError> {
    let mut lattice =
        Ir2FlowLattice::with_decision_id(context.policy_id.clone(), context.decision_id.clone());
    let mut artifact = Ir2FlowProofArtifact {
        schema_version: IFC_FLOW_PROOF_SCHEMA_VERSION.to_string(),
        artifact_id: String::new(),
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        module_id: ir2.header.source_label.clone(),
        proved_flows: Vec::new(),
        denied_flows: Vec::new(),
        required_declassifications: Vec::new(),
        runtime_checkpoints: Vec::new(),
    };

    let mut analysis_sites = ir2
        .ops
        .iter()
        .enumerate()
        .map(|(op_index, op)| NestedIr2AnalysisSite {
            op_index,
            body_path: Vec::new(),
            op: op.clone(),
        })
        .collect::<Vec<_>>();
    let top_level_ir1_ops = ir2
        .ops
        .iter()
        .map(|op| op.inner.clone())
        .collect::<Vec<_>>();
    let (nested_sites, _) = collect_nested_ir2_analysis(&top_level_ir1_ops);
    analysis_sites.extend(nested_sites);

    for site in &analysis_sites {
        let op = &site.op;
        let Some(flow) = op.flow.as_ref() else {
            continue;
        };
        // Keep the v1 `op_index` namespace compatible with authority consumers:
        // nested operations point at their enclosing top-level function op.
        let op_index_u64 = site.op_index as u64;
        let body_path = site
            .body_path
            .iter()
            .map(|index| *index as u64)
            .collect::<Vec<_>>();
        let source_label = flow.data_label.clone();
        let sink_clearance_label = flow.sink_clearance.clone();
        let source_class = LabelClass::from_label(&source_label);
        let sink_clearance = sink_label_to_clearance(&sink_clearance_label);
        let capability = op.required_capability.as_ref().map(|cap| cap.0.clone());
        let mut obligation_hint = None;

        if flow.declassification_required
            && let Some(required_capability) = op.required_capability.as_ref()
            && flow_capability_supports_declassification(required_capability)
        {
            let obligation_id = if site.body_path.is_empty() {
                format!("declass-op-{}", site.op_index)
            } else {
                let body_path = site
                    .body_path
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join("-");
                format!("declass-op-{}-body-{body_path}", site.op_index)
            };
            if !lattice.obligations().contains_key(&obligation_id) {
                lattice
                    .register_obligation(DeclassificationObligation {
                        obligation_id: obligation_id.clone(),
                        source_label: source_class.clone(),
                        target_clearance: sink_clearance.clone(),
                        decision_contract_id: context.decision_id.clone(),
                        declassification_route_ref: capability.clone(),
                        requires_operator_approval: true,
                        max_uses: 0,
                        use_count: 0,
                    })
                    .map_err(|err| LoweringPipelineError::FlowLatticeFailure {
                        detail: err.to_string(),
                    })?;
            }
            obligation_hint = Some(obligation_id);
        }

        if let Some(required_capability) = op.required_capability.as_ref()
            && flow_requires_runtime_checkpoint(Some(flow), required_capability)
        {
            artifact
                .runtime_checkpoints
                .push(RuntimeCheckpointArtifactEntry {
                    op_index: op_index_u64,
                    body_path: body_path.clone(),
                    source_label,
                    sink_clearance: sink_clearance_label,
                    capability,
                    reason: runtime_checkpoint_reason(flow, required_capability),
                });
            continue;
        }

        match lattice.check_flow_with_obligation_hint(
            &source_class,
            &sink_clearance,
            obligation_hint.as_deref(),
            &context.trace_id,
        ) {
            LatticeFlowCheckResult::LegalByLattice => {
                artifact.proved_flows.push(FlowProofArtifactEntry {
                    op_index: op_index_u64,
                    body_path: body_path.clone(),
                    source_label,
                    sink_clearance: sink_clearance_label,
                    capability,
                    proof_method: ProofMethod::StaticAnalysis,
                });
            }
            LatticeFlowCheckResult::RequiresDeclassification { obligation_id } => {
                let obligation = lattice.obligations().get(&obligation_id).ok_or_else(|| {
                    LoweringPipelineError::FlowLatticeFailure {
                        detail: format!(
                            "missing declassification obligation metadata for {obligation_id}"
                        ),
                    }
                })?;
                artifact
                    .required_declassifications
                    .push(RequiredDeclassificationArtifactEntry {
                        op_index: op_index_u64,
                        body_path: body_path.clone(),
                        source_label,
                        sink_clearance: sink_clearance_label,
                        capability,
                        obligation_id,
                        decision_contract_id: obligation.decision_contract_id.clone(),
                        declassification_route_ref: obligation.declassification_route_ref.clone(),
                        requires_operator_approval: obligation.requires_operator_approval,
                        receipt_linkage_required: true,
                        replay_command_hint: REQUIRED_DECLASSIFICATION_REPLAY_COMMAND_HINT
                            .to_string(),
                    });
            }
            LatticeFlowCheckResult::Blocked { .. } => {
                artifact.denied_flows.push(DeniedFlowArtifactEntry {
                    op_index: op_index_u64,
                    body_path,
                    source_label,
                    sink_clearance: sink_clearance_label,
                    capability,
                    reason: "no_lattice_or_declassification_path".to_string(),
                    error_code: IFC_FLOW_PROOF_ERROR_CODE.to_string(),
                });
            }
        }
    }

    let artifact = artifact.finalize();
    if let Some(first_denied) = artifact.denied_flows.first() {
        return Err(LoweringPipelineError::UnauthorizedFlow {
            op_index: first_denied.op_index as usize,
            source_label: first_denied.source_label.clone(),
            sink_clearance: first_denied.sink_clearance.clone(),
            detail: format!(
                "artifact_id={} denied_flow_count={} reason={}",
                artifact.artifact_id,
                artifact.denied_flows.len(),
                first_denied.reason
            ),
        });
    }

    Ok(artifact)
}

fn compute_ir2_flow_artifact_id(artifact: &Ir2FlowProofArtifact) -> String {
    let mut preimage = artifact.clone();
    preimage.artifact_id.clear();
    let encoded = serde_json::to_vec(&preimage).unwrap();
    let hash = ContentHash::compute(&encoded);
    format!("sha256:{}", hex::encode(hash.as_bytes()))
}

fn sink_label_to_clearance(label: &Label) -> Clearance {
    match label {
        Label::Public => Clearance::NeverSink,
        Label::Internal => Clearance::RestrictedSink,
        Label::Confidential => Clearance::AuditedSink,
        Label::Secret => Clearance::SealedSink,
        Label::TopSecret => Clearance::OpenSink,
        Label::Custom { level, .. } => match level {
            0 => Clearance::NeverSink,
            1 => Clearance::RestrictedSink,
            2 => Clearance::AuditedSink,
            3 => Clearance::SealedSink,
            _ => Clearance::OpenSink,
        },
    }
}

fn flow_capability_supports_declassification(capability: &CapabilityTag) -> bool {
    let normalized = capability.0.to_ascii_lowercase();
    normalized.contains("declassify") || normalized.contains("declassification")
}

fn flow_requires_runtime_checkpoint(
    flow: Option<&FlowAnnotation>,
    capability: &CapabilityTag,
) -> bool {
    let capability_is_dynamic = capability.0 == "hostcall.invoke";
    let flow_is_ambiguous = flow.is_some_and(|annotation| {
        matches!(annotation.data_label, Label::Custom { .. })
            || matches!(annotation.sink_clearance, Label::Custom { .. })
    });
    capability_is_dynamic || flow_is_ambiguous
}

fn runtime_checkpoint_reason(flow: &FlowAnnotation, capability: &CapabilityTag) -> String {
    if capability.0 == "hostcall.invoke" {
        return "dynamic_capability".to_string();
    }
    if matches!(flow.data_label, Label::Custom { .. }) {
        return "ambiguous_data_label".to_string();
    }
    if matches!(flow.sink_clearance, Label::Custom { .. }) {
        return "ambiguous_sink_clearance".to_string();
    }
    "runtime_checkpoint_required".to_string()
}

/// Binding conflict result from `check_binding_conflict`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BindingConflict {
    /// No conflict — proceed with allocation.
    None,
    /// Semantic error — the redeclaration is invalid.
    Error(SemanticErrorCode),
}

/// Check whether declaring `name` with `new_kind` conflicts with an existing
/// binding of `existing_kind` in the same scope.
///
/// ES2020 rules (simplified):
/// - `let`/`const` + `let`/`const` in same scope → error
/// - `let`/`const` + `var` in same scope → error (either direction)
/// - `let`/`const` + `import` in same scope → error
/// - `var` + `var` in same scope → legal (reuse)
/// - `import` + `import` in same scope → error
/// - Any duplicate in module-scope `import` → error
fn check_binding_conflict(existing_kind: BindingKind, new_kind: BindingKind) -> BindingConflict {
    match (existing_kind, new_kind) {
        // var + var is legal (redeclaration merges).
        (BindingKind::Var, BindingKind::Var) => BindingConflict::None,
        // FunctionDecl + FunctionDecl in same scope is legal in non-strict mode.
        (BindingKind::FunctionDecl, BindingKind::FunctionDecl) => BindingConflict::None,
        // var + FunctionDecl and reverse are legal (hoisting merges).
        (BindingKind::Var, BindingKind::FunctionDecl)
        | (BindingKind::FunctionDecl, BindingKind::Var) => BindingConflict::None,
        // let/const redeclared as let/const.
        (BindingKind::Let | BindingKind::Const, BindingKind::Let | BindingKind::Const) => {
            BindingConflict::Error(SemanticErrorCode::DuplicateLetConstDeclaration)
        }
        // var conflicts with let/const.
        (BindingKind::Let | BindingKind::Const, BindingKind::Var) => {
            BindingConflict::Error(SemanticErrorCode::LexicalConflictsWithVar)
        }
        (BindingKind::Var, BindingKind::Let | BindingKind::Const) => {
            BindingConflict::Error(SemanticErrorCode::VarConflictsWithLexical)
        }
        // import + anything else in same scope.
        (BindingKind::Import, _) | (_, BindingKind::Import) => {
            BindingConflict::Error(SemanticErrorCode::DuplicateImportBinding)
        }
        // let/const + FunctionDecl or reverse.
        (BindingKind::Let | BindingKind::Const, BindingKind::FunctionDecl)
        | (BindingKind::FunctionDecl, BindingKind::Let | BindingKind::Const) => {
            BindingConflict::Error(SemanticErrorCode::DuplicateLetConstDeclaration)
        }
        // Parameter + let/const in the same scope.
        (BindingKind::Parameter, BindingKind::Let | BindingKind::Const)
        | (BindingKind::Let | BindingKind::Const, BindingKind::Parameter) => {
            BindingConflict::Error(SemanticErrorCode::DuplicateLetConstDeclaration)
        }
        // Parameter + var is legal (function-scoped merge).
        (BindingKind::Parameter, BindingKind::Var) | (BindingKind::Var, BindingKind::Parameter) => {
            BindingConflict::None
        }
        // Parameter + Parameter (duplicate params — only error in strict mode,
        // currently always allowed since we don't track strict mode yet).
        (BindingKind::Parameter, BindingKind::Parameter) => BindingConflict::None,
        // Parameter + FunctionDecl is legal.
        (BindingKind::Parameter, BindingKind::FunctionDecl)
        | (BindingKind::FunctionDecl, BindingKind::Parameter) => BindingConflict::None,
        // FunctionDecl + let/const is already handled above.
        // Import + Import is already handled above.
        // FunctionDecl + Import / Import + FunctionDecl is already handled above.
    }
}

fn alloc_binding(
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope: ScopeId,
    name: &str,
    kind: BindingKind,
) -> Result<BindingId, SemanticError> {
    if let Some(existing_id) = binding_lookup.get(name) {
        // Find existing binding to check its kind.
        let existing_kind = bindings
            .iter()
            .find(|b| b.binding_id == *existing_id)
            .map(|b| b.kind);

        if let Some(existing_kind) = existing_kind {
            match check_binding_conflict(existing_kind, kind) {
                BindingConflict::None => {
                    // Legal re-declaration; reuse existing binding.
                    return Ok(*existing_id);
                }
                BindingConflict::Error(code) => {
                    return Err(SemanticError::new(code, Some(name.to_string()), None));
                }
            }
        }
        // Reserved bindings are inserted into the lookup before their
        // declarations are lowered so exports and forward references can
        // share a stable binding ID.
        bindings.push(ResolvedBinding {
            name: name.to_string(),
            binding_id: *existing_id,
            scope,
            kind,
        });
        return Ok(*existing_id);
    }

    let binding_id = *binding_index;
    *binding_index = binding_index.saturating_add(1);
    bindings.push(ResolvedBinding {
        name: name.to_string(),
        binding_id,
        scope,
        kind,
    });
    binding_lookup.insert(name.to_string(), binding_id);
    Ok(binding_id)
}

fn alloc_internal_binding(
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope: ScopeId,
    purpose: &str,
) -> Result<BindingId, LoweringPipelineError> {
    let name = format!("<internal:{purpose}:{}>", *binding_index);
    alloc_binding(
        bindings,
        binding_lookup,
        binding_index,
        scope,
        &name,
        BindingKind::Let,
    )
    .map_err(LoweringPipelineError::SemanticViolation)
}

#[allow(clippy::too_many_arguments)]
fn lower_class_expression_to_ir1(
    name: Option<&str>,
    super_class: Option<&Expression>,
    body: &[MethodDefinition],
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    label_counter: &mut u32,
) -> Result<(), LoweringPipelineError> {
    let constructor = body
        .iter()
        .find(|method| method.kind == MethodKind::Constructor);
    let class_binding = alloc_internal_binding(
        bindings,
        binding_lookup,
        binding_index,
        scope_id,
        "class_expression",
    )?;
    let mut body_ops = Vec::new();
    let mut body_bindings = Vec::new();
    let mut body_lookup = BTreeMap::new();
    let mut body_binding_index: BindingId = 0;
    let body_scope = ScopeId { depth: 0, index: 0 };
    let mut body_label_counter: u32 = 0;
    let FunctionParameterPlan {
        param_names,
        destructure_params,
        rest_param_index,
    } = if let Some(ctor) = constructor {
        allocate_function_parameter_bindings(
            &ctor.params,
            &mut body_bindings,
            &mut body_lookup,
            &mut body_binding_index,
            body_scope,
        )?
    } else {
        FunctionParameterPlan::default()
    };
    let parameter_binding_names = body_lookup.keys().cloned().collect();
    let parameter_prologue_captures = lower_function_parameter_prologue(
        &destructure_params,
        binding_lookup,
        &mut body_ops,
        &mut body_bindings,
        &body_lookup,
        &mut body_binding_index,
        body_scope,
        &mut body_label_counter,
    )?;
    if let (Some(self_name), Some(ctor)) = (name, constructor) {
        reject_self_referential_parameter_capture(
            &parameter_prologue_captures,
            self_name,
            ctor.span.clone(),
        )?;
    }
    let ctor_enclosing_self_binding =
        name.and_then(|self_name| binding_lookup.insert(self_name.to_string(), class_binding));
    let mut ctor_pre_lower_names = if let Some(ctor) = constructor {
        let pre_lower_names = prepare_function_body_bindings(
            Some(&ctor.body.body),
            parameter_binding_names,
            &mut body_lookup,
            &mut body_binding_index,
        );
        merge_unshadowed_parameter_prologue_captures(
            &parameter_prologue_captures,
            &mut body_lookup,
        );
        seed_function_outer_static_bindings(
            binding_lookup,
            &mut body_lookup,
            &mut body_binding_index,
        );
        for stmt in &ctor.body.body {
            lower_statement_to_ir1(
                stmt,
                &mut body_ops,
                &mut body_bindings,
                &mut body_lookup,
                &mut body_binding_index,
                body_scope,
                &mut body_label_counter,
            )?;
        }
        pre_lower_names
    } else {
        body_lookup.keys().cloned().collect()
    };
    if !matches!(body_ops.last(), Some(Ir1Op::Return)) {
        body_ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        });
        body_ops.push(Ir1Op::Return);
    }
    let unresolved_ctor_names = rewrite_unresolved_class_body_loads(
        &mut body_ops,
        &body_lookup,
        &ctor_pre_lower_names,
        binding_lookup,
    );
    ctor_pre_lower_names.extend(unresolved_ctor_names);
    let (mut ctor_free_vars, mut ctor_free_var_ids, mut ctor_free_var_outer_ids) =
        collect_free_vars(
            &body_lookup,
            &ctor_pre_lower_names,
            bindings,
            binding_lookup,
            binding_index,
            scope_id,
        );
    append_shadowed_parameter_prologue_captures(
        &parameter_prologue_captures,
        &mut ctor_free_vars,
        &mut ctor_free_var_ids,
        &mut ctor_free_var_outer_ids,
        bindings,
        binding_lookup,
        binding_index,
        scope_id,
    );
    if let Some(self_name) = name {
        rewrite_class_expression_self_capture(
            &body_lookup,
            self_name,
            class_expression_constructor_self_capture_name(self_name, class_binding),
            &mut ctor_free_vars,
            &ctor_free_var_ids,
        );
    }
    restore_class_expression_self_binding(binding_lookup, name, ctor_enclosing_self_binding);
    ops.push(Ir1Op::CreateFunction {
        name: name.map(str::to_string),
        param_names,
        body_ops,
        free_vars: ctor_free_vars,
        free_var_ids: ctor_free_var_ids,
        free_var_outer_ids: ctor_free_var_outer_ids,
        is_generator: false,
        is_arrow: false,
        rest_param_index,
    });
    ops.push(Ir1Op::StoreBinding {
        binding_id: class_binding,
    });
    ops.push(Ir1Op::Nop);

    if let Some(super_expr) = super_class {
        ops.push(Ir1Op::LoadBinding {
            binding_id: class_binding,
        });
        lower_expression_to_ir1(
            super_expr,
            ops,
            bindings,
            binding_lookup,
            binding_index,
            scope_id,
            label_counter,
        )?;
        ops.push(Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(IR_SUPER_CONSTRUCTOR_PROPERTY.to_string()),
        });
        ops.push(Ir1Op::Nop);

        ops.push(Ir1Op::LoadBinding {
            binding_id: class_binding,
        });
        ops.push(Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static("prototype".to_string()),
        });
        lower_expression_to_ir1(
            super_expr,
            ops,
            bindings,
            binding_lookup,
            binding_index,
            scope_id,
            label_counter,
        )?;
        ops.push(Ir1Op::GetProperty {
            key: Ir1PropertyKey::Static("prototype".to_string()),
        });
        ops.push(Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static("__proto__".to_string()),
        });
        ops.push(Ir1Op::Nop);
    }

    for method in body
        .iter()
        .filter(|method| method.kind != MethodKind::Constructor)
    {
        let method_name = match &method.key {
            Expression::Identifier(name) => name.clone(),
            Expression::StringLiteral(name) => name.clone(),
            _ => "anonymous_method".to_string(),
        };
        let mut method_body_ops = Vec::new();
        let mut method_bindings = Vec::new();
        let mut method_lookup = BTreeMap::new();
        let mut method_binding_index: BindingId = 0;
        let method_scope = ScopeId { depth: 0, index: 0 };
        let mut method_label_counter: u32 = 0;
        let FunctionParameterPlan {
            param_names: method_param_names,
            destructure_params: method_destructure_params,
            rest_param_index: method_rest_param_index,
        } = allocate_function_parameter_bindings(
            &method.params,
            &mut method_bindings,
            &mut method_lookup,
            &mut method_binding_index,
            method_scope,
        )?;
        if method_rest_param_index.is_some()
            && matches!(method.kind, MethodKind::Get | MethodKind::Set)
        {
            return Err(unsupported_frontier_expression_error(
                "accessor_rest_parameters",
                "FE-LOWER-UNSUPPORTED-ACCESSOR-REST-0001",
                "core.accessor_rest_parameter_runtime",
                "getter and setter functions cannot declare rest parameters",
                Some(method.span.clone()),
            ));
        }
        let parameter_binding_names = method_lookup.keys().cloned().collect();
        let parameter_prologue_captures = lower_function_parameter_prologue(
            &method_destructure_params,
            binding_lookup,
            &mut method_body_ops,
            &mut method_bindings,
            &method_lookup,
            &mut method_binding_index,
            method_scope,
            &mut method_label_counter,
        )?;
        if let Some(self_name) = name {
            reject_self_referential_parameter_capture(
                &parameter_prologue_captures,
                self_name,
                method.span.clone(),
            )?;
        }
        let method_enclosing_self_binding =
            name.and_then(|self_name| binding_lookup.insert(self_name.to_string(), class_binding));
        let mut method_pre_lower_names = prepare_function_body_bindings(
            Some(&method.body.body),
            parameter_binding_names,
            &mut method_lookup,
            &mut method_binding_index,
        );
        merge_unshadowed_parameter_prologue_captures(
            &parameter_prologue_captures,
            &mut method_lookup,
        );
        seed_function_outer_static_bindings(
            binding_lookup,
            &mut method_lookup,
            &mut method_binding_index,
        );
        for stmt in &method.body.body {
            lower_statement_to_ir1(
                stmt,
                &mut method_body_ops,
                &mut method_bindings,
                &mut method_lookup,
                &mut method_binding_index,
                method_scope,
                &mut method_label_counter,
            )?;
        }
        if !matches!(method_body_ops.last(), Some(Ir1Op::Return)) {
            method_body_ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            });
            method_body_ops.push(Ir1Op::Return);
        }
        let unresolved_method_names = rewrite_unresolved_class_body_loads(
            &mut method_body_ops,
            &method_lookup,
            &method_pre_lower_names,
            binding_lookup,
        );
        method_pre_lower_names.extend(unresolved_method_names);
        let (mut method_free_vars, mut method_free_var_ids, mut method_free_var_outer_ids) =
            collect_free_vars(
                &method_lookup,
                &method_pre_lower_names,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
            );
        append_shadowed_parameter_prologue_captures(
            &parameter_prologue_captures,
            &mut method_free_vars,
            &mut method_free_var_ids,
            &mut method_free_var_outer_ids,
            bindings,
            binding_lookup,
            binding_index,
            scope_id,
        );
        if let Some(self_name) = name {
            rewrite_class_expression_self_capture(
                &method_lookup,
                self_name,
                class_expression_method_self_capture_name(self_name, class_binding),
                &mut method_free_vars,
                &method_free_var_ids,
            );
        }
        restore_class_expression_self_binding(binding_lookup, name, method_enclosing_self_binding);

        let method_super_binding = if super_class.is_some() {
            Some(alloc_internal_binding(
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                "class_expression_method_super",
            )?)
        } else {
            None
        };

        ops.push(Ir1Op::LoadBinding {
            binding_id: class_binding,
        });
        if !method.is_static {
            ops.push(Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static("prototype".to_string()),
            });
        }
        ops.push(Ir1Op::CreateFunction {
            name: Some(method_name.clone()),
            param_names: method_param_names,
            body_ops: method_body_ops,
            free_vars: method_free_vars,
            free_var_ids: method_free_var_ids,
            free_var_outer_ids: method_free_var_outer_ids,
            is_generator: false,
            is_arrow: false,
            rest_param_index: method_rest_param_index,
        });
        if let Some(method_binding) = method_super_binding {
            ops.push(Ir1Op::StoreBinding {
                binding_id: method_binding,
            });
        }

        let property_key = match method.kind {
            MethodKind::Get => format!("{IR_ACCESSOR_GET_PREFIX}{method_name}"),
            MethodKind::Set => format!("{IR_ACCESSOR_SET_PREFIX}{method_name}"),
            MethodKind::Method | MethodKind::Constructor => method_name,
        };
        ops.push(Ir1Op::SetProperty {
            key: Ir1PropertyKey::Static(property_key),
        });
        ops.push(Ir1Op::Nop);

        if let (Some(super_expr), Some(method_binding)) = (super_class, method_super_binding) {
            ops.push(Ir1Op::LoadBinding {
                binding_id: method_binding,
            });
            lower_expression_to_ir1(
                super_expr,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                scope_id,
                label_counter,
            )?;
            if !method.is_static {
                ops.push(Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static("prototype".to_string()),
                });
            }
            ops.push(Ir1Op::SetProperty {
                key: Ir1PropertyKey::Static(IR_SUPER_PROTOTYPE_PROPERTY.to_string()),
            });
            ops.push(Ir1Op::Nop);
        }
    }

    ops.push(Ir1Op::LoadBinding {
        binding_id: class_binding,
    });
    Ok(())
}

fn lower_expression_to_ir1(
    expression: &Expression,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    root_scope_id: ScopeId,
    label_counter: &mut u32,
) -> Result<(), LoweringPipelineError> {
    match expression {
        Expression::Identifier(name) => {
            // Core has no heap-backed Object/Array/String/Math/JSON globals,
            // and `require` is supported only as a direct-call lowering seam.
            // An unbound bare read is therefore undefined and must not create
            // a forward-reference entry that poisons a later supported static
            // call such as `Math.nope; Math.abs(1)` (bd-zql4d) or a later
            // unshadowed `require('x')` after lowering a nested closure
            // (bd-x0ld5).
            if is_non_materialized_intrinsic_global(name)
                && !binding_lookup.contains_key(name.as_str())
            {
                ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                });
                return Ok(());
            }
            // Identifier references look up an existing binding or create
            // a forward-reference placeholder.  This must NOT trigger the
            // duplicate-declaration conflict check that applies only to
            // actual VariableDeclaration / Import sites.
            let binding_id = if let Some(existing) = binding_lookup.get(name.as_str()) {
                *existing
            } else {
                let id = *binding_index;
                *binding_index = binding_index.saturating_add(1);
                bindings.push(ResolvedBinding {
                    name: name.clone(),
                    binding_id: id,
                    scope: root_scope_id,
                    kind: BindingKind::Let,
                });
                binding_lookup.insert(name.clone(), id);
                id
            };
            ops.push(Ir1Op::LoadBinding { binding_id });
        }
        Expression::StringLiteral(value) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String(value.clone()),
            });
        }
        Expression::NumericLiteral(value) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(*value),
            });
        }
        Expression::FloatLiteral(bits) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Float(*bits),
            });
        }
        Expression::BooleanLiteral(value) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Boolean(*value),
            });
        }
        Expression::NullLiteral => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Null,
            });
        }
        Expression::UndefinedLiteral => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            });
        }
        Expression::Await(inner) => {
            lower_expression_to_ir1(
                inner,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::Await);
        }
        Expression::Yield { argument, delegate } => {
            if let Some(arg) = argument {
                lower_expression_to_ir1(
                    arg,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
            } else {
                ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                });
            }
            ops.push(Ir1Op::Yield {
                delegate: *delegate,
            });
        }
        Expression::Raw(raw) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String(raw.clone()),
            });
            if raw.contains('(') {
                ops.push(Ir1Op::Call { arg_count: 0 });
            }
        }
        Expression::SpreadElement(inner) => {
            // Spread in expression position: lower the inner expression.
            // The actual spreading (iteration into array/object/call) is
            // handled at the call site (array literal, object literal, call).
            // At expression level, spread just evaluates to the inner value.
            lower_expression_to_ir1(
                inner,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
        }
        Expression::RegExpLiteral { pattern, flags } => {
            // Load pattern and flags as string literals, then create RegExp.
            // For now, emit a hostcall to regexp:create.
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String(pattern.clone()),
            });
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String(flags.clone()),
            });
            ops.push(Ir1Op::HostCall {
                capability: "regexp:create".to_string(),
                arg_count: 2,
            });
        }
        Expression::Binary {
            operator,
            left,
            right,
        } => {
            if matches!(
                operator,
                BinaryOperator::LogicalAnd
                    | BinaryOperator::LogicalOr
                    | BinaryOperator::NullishCoalescing
            ) {
                let temp_binding = alloc_internal_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    "short_circuit",
                )?;
                let eval_rhs_label = alloc_label(label_counter);
                let end_label = alloc_label(label_counter);

                lower_expression_to_ir1(
                    left,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::StoreBinding {
                    binding_id: temp_binding,
                });
                ops.push(Ir1Op::Pop);
                ops.push(Ir1Op::LoadBinding {
                    binding_id: temp_binding,
                });

                match operator {
                    BinaryOperator::LogicalAnd => ops.push(Ir1Op::JumpIfTruthy {
                        label_id: eval_rhs_label,
                    }),
                    BinaryOperator::LogicalOr => ops.push(Ir1Op::JumpIfFalsyConsume {
                        label_id: eval_rhs_label,
                    }),
                    BinaryOperator::NullishCoalescing => ops.push(Ir1Op::JumpIfNullish {
                        label_id: eval_rhs_label,
                    }),
                    _ => {
                        return Err(LoweringPipelineError::InvariantViolation {
                            detail: "unexpected operator in logical assignment",
                        });
                    }
                }

                ops.push(Ir1Op::Jump {
                    label_id: end_label,
                });
                ops.push(Ir1Op::Label { id: eval_rhs_label });
                lower_expression_to_ir1(
                    right,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::StoreBinding {
                    binding_id: temp_binding,
                });
                ops.push(Ir1Op::Pop);
                ops.push(Ir1Op::Label { id: end_label });
                ops.push(Ir1Op::LoadBinding {
                    binding_id: temp_binding,
                });
                return Ok(());
            }

            lower_expression_to_ir1(
                left,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            lower_expression_to_ir1(
                right,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::BinaryOp {
                operator: *operator,
            });
        }
        Expression::Unary {
            operator, argument, ..
        } => {
            if *operator == UnaryOperator::Delete {
                match argument.as_ref() {
                    Expression::Member {
                        object,
                        property,
                        computed,
                    } => {
                        lower_expression_to_ir1(
                            object,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        let key = lower_member_property_key_to_ir1(
                            property,
                            *computed,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::DeleteProperty { key });
                    }
                    _ => {
                        lower_expression_to_ir1(
                            argument,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::Pop);
                        ops.push(Ir1Op::LoadLiteral {
                            value: Ir1Literal::Boolean(true),
                        });
                    }
                }
                return Ok(());
            }

            lower_expression_to_ir1(
                argument,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::UnaryOp {
                operator: *operator,
            });
        }
        Expression::Update {
            operator,
            argument,
            prefix,
        } => {
            // ES `++`/`--` operate numerically (ToNumber), writing the operand
            // back as operand ± 1 and yielding the PRIOR value for a postfix
            // update or the NEW value for a prefix update. The parser emits
            // `Update` for identifier and member targets (bd-xi3bk, bd-rmxao);
            // any other operand is not a valid reference.
            let step_operator = match operator {
                UpdateOperator::Increment => BinaryOperator::Add,
                UpdateOperator::Decrement => BinaryOperator::Subtract,
            };

            match argument.as_ref() {
                Expression::Identifier(name) => {
                    let binding_id = if let Some(existing) = binding_lookup.get(name.as_str()) {
                        *existing
                    } else {
                        let id = *binding_index;
                        *binding_index = binding_index.saturating_add(1);
                        bindings.push(ResolvedBinding {
                            name: name.clone(),
                            binding_id: id,
                            scope: root_scope_id,
                            kind: BindingKind::Let,
                        });
                        binding_lookup.insert(name.clone(), id);
                        id
                    };

                    // Read the operand and ToNumber-coerce it (unary `+`): ES
                    // `++`/`--` always operate numerically, unlike `x += 1` which
                    // would string-concatenate a string operand.
                    ops.push(Ir1Op::LoadBinding { binding_id });
                    ops.push(Ir1Op::UnaryOp {
                        operator: UnaryOperator::UnaryPlus,
                    });

                    // A postfix update yields the PRIOR numeric value, so stash it
                    // before the write (there is no stack-dup op; use a binding).
                    let prior_binding = if *prefix {
                        None
                    } else {
                        let tmp = alloc_internal_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            "update_prior_value",
                        )?;
                        ops.push(Ir1Op::StoreBinding { binding_id: tmp });
                        Some(tmp)
                    };

                    // new = prior ± 1, written back through `AssignOp` (scope/
                    // capture aware). The store leaves the new value on the stack.
                    ops.push(Ir1Op::LoadLiteral {
                        value: Ir1Literal::Integer(1),
                    });
                    ops.push(Ir1Op::BinaryOp {
                        operator: step_operator,
                    });
                    ops.push(Ir1Op::AssignOp {
                        binding_id,
                        operator: AssignmentOperator::Assign,
                    });

                    // Prefix: keep the new value. Postfix: drop it and reload the
                    // stashed prior value as the expression result.
                    if let Some(tmp) = prior_binding {
                        ops.push(Ir1Op::Pop);
                        ops.push(Ir1Op::LoadBinding { binding_id: tmp });
                    }
                }
                Expression::Member {
                    object,
                    property,
                    computed,
                } => {
                    // A consumed member-target update (`obj.x++`, `a[i]--`) needs
                    // the same ToNumber + prior/new result semantics as an
                    // identifier target, but the object and computed key must be
                    // evaluated ONCE and reused for both the load and the store
                    // (single-eval — bd-rmxao). Stash them in internal bindings.
                    let object_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "update_object",
                    )?;
                    lower_expression_to_ir1(
                        object,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: object_binding,
                    });
                    ops.push(Ir1Op::Pop);

                    let (key, dynamic_key_binding) = if *computed {
                        let key_binding = alloc_internal_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            "update_key",
                        )?;
                        lower_expression_to_ir1(
                            property,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: key_binding,
                        });
                        ops.push(Ir1Op::Pop);
                        (Ir1PropertyKey::Dynamic, Some(key_binding))
                    } else {
                        (
                            lower_member_property_key_to_ir1(
                                property,
                                false,
                                ops,
                                bindings,
                                binding_lookup,
                                binding_index,
                                root_scope_id,
                                label_counter,
                            )?,
                            None,
                        )
                    };

                    // prior = ToNumber(obj[key])
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: object_binding,
                    });
                    if let Some(key_binding) = dynamic_key_binding {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: key_binding,
                        });
                    }
                    ops.push(Ir1Op::GetProperty { key: key.clone() });
                    ops.push(Ir1Op::UnaryOp {
                        operator: UnaryOperator::UnaryPlus,
                    });

                    let prior_binding = if *prefix {
                        None
                    } else {
                        let tmp = alloc_internal_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            "update_prior_value",
                        )?;
                        ops.push(Ir1Op::StoreBinding { binding_id: tmp });
                        Some(tmp)
                    };

                    // new = prior ± 1
                    ops.push(Ir1Op::LoadLiteral {
                        value: Ir1Literal::Integer(1),
                    });
                    ops.push(Ir1Op::BinaryOp {
                        operator: step_operator,
                    });

                    // Write `new` back through the stashed reference. SetProperty
                    // needs the object (and key) beneath the value, so stash the
                    // new value and reload the reference before it.
                    let result_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "update_result",
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: result_binding,
                    });
                    ops.push(Ir1Op::Pop);
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: object_binding,
                    });
                    if let Some(key_binding) = dynamic_key_binding {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: key_binding,
                        });
                    }
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: result_binding,
                    });
                    // SetProperty leaves the new value on the stack (the prefix
                    // result). For a postfix update, drop it and reload the prior.
                    ops.push(Ir1Op::SetProperty { key });
                    if let Some(tmp) = prior_binding {
                        ops.push(Ir1Op::Pop);
                        ops.push(Ir1Op::LoadBinding { binding_id: tmp });
                    }
                }
                _ => {
                    return Err(unsupported_frontier_expression_error(
                        "update_target",
                        "FE-LOWER-UPDATE-0001",
                        "lower_ir0_to_ir1.update_target",
                        "update expression operand must be an identifier or member expression",
                        None,
                    ));
                }
            }
        }
        Expression::Assignment {
            operator,
            left,
            right,
        } => {
            if let Expression::Identifier(name) = left.as_ref() {
                let binding_id = if let Some(existing) = binding_lookup.get(name.as_str()) {
                    *existing
                } else {
                    let id = *binding_index;
                    *binding_index = binding_index.saturating_add(1);
                    bindings.push(ResolvedBinding {
                        name: name.clone(),
                        binding_id: id,
                        scope: root_scope_id,
                        kind: BindingKind::Let,
                    });
                    binding_lookup.insert(name.clone(), id);
                    id
                };

                match operator {
                    AssignmentOperator::LogicalAndAssign
                    | AssignmentOperator::LogicalOrAssign
                    | AssignmentOperator::NullishCoalescingAssign => {
                        let eval_rhs_label = alloc_label(label_counter);
                        let end_label = alloc_label(label_counter);

                        ops.push(Ir1Op::LoadBinding { binding_id });
                        match operator {
                            AssignmentOperator::LogicalAndAssign => {
                                ops.push(Ir1Op::JumpIfTruthy {
                                    label_id: eval_rhs_label,
                                });
                            }
                            AssignmentOperator::LogicalOrAssign => {
                                ops.push(Ir1Op::JumpIfFalsyConsume {
                                    label_id: eval_rhs_label,
                                });
                            }
                            AssignmentOperator::NullishCoalescingAssign => {
                                ops.push(Ir1Op::JumpIfNullish {
                                    label_id: eval_rhs_label,
                                });
                            }
                            _ => {
                                return Err(LoweringPipelineError::InvariantViolation {
                                    detail: "unexpected operator in logical assignment",
                                });
                            }
                        }
                        ops.push(Ir1Op::Jump {
                            label_id: end_label,
                        });
                        ops.push(Ir1Op::Label { id: eval_rhs_label });
                        lower_expression_to_ir1(
                            right,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::AssignOp {
                            binding_id,
                            operator: AssignmentOperator::Assign,
                        });
                        ops.push(Ir1Op::Pop);
                        ops.push(Ir1Op::Label { id: end_label });
                        ops.push(Ir1Op::LoadBinding { binding_id });
                        return Ok(());
                    }
                    _ => {}
                }

                lower_expression_to_ir1(
                    right,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::AssignOp {
                    binding_id,
                    operator: *operator,
                });
            } else if let Expression::Member {
                object,
                property,
                computed,
            } = left.as_ref()
            {
                if matches!(
                    operator,
                    AssignmentOperator::LogicalAndAssign
                        | AssignmentOperator::LogicalOrAssign
                        | AssignmentOperator::NullishCoalescingAssign
                ) {
                    let object_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "member_assignment_object",
                    )?;
                    lower_expression_to_ir1(
                        object,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: object_binding,
                    });
                    ops.push(Ir1Op::Pop);

                    let (key, dynamic_key_binding) = if *computed {
                        let key_binding = alloc_internal_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            "member_assignment_key",
                        )?;
                        lower_expression_to_ir1(
                            property,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: key_binding,
                        });
                        ops.push(Ir1Op::Pop);
                        (Ir1PropertyKey::Dynamic, Some(key_binding))
                    } else {
                        (
                            lower_member_property_key_to_ir1(
                                property,
                                false,
                                ops,
                                bindings,
                                binding_lookup,
                                binding_index,
                                root_scope_id,
                                label_counter,
                            )?,
                            None,
                        )
                    };

                    ops.push(Ir1Op::LoadBinding {
                        binding_id: object_binding,
                    });
                    if let Some(key_binding) = dynamic_key_binding {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: key_binding,
                        });
                    }
                    ops.push(Ir1Op::GetProperty { key: key.clone() });

                    let current_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "member_assignment_current",
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: current_binding,
                    });
                    ops.push(Ir1Op::Pop);

                    let eval_rhs_label = alloc_label(label_counter);
                    let end_label = alloc_label(label_counter);

                    ops.push(Ir1Op::LoadBinding {
                        binding_id: current_binding,
                    });
                    match operator {
                        AssignmentOperator::LogicalAndAssign => {
                            ops.push(Ir1Op::JumpIfTruthy {
                                label_id: eval_rhs_label,
                            });
                        }
                        AssignmentOperator::LogicalOrAssign => {
                            ops.push(Ir1Op::JumpIfFalsyConsume {
                                label_id: eval_rhs_label,
                            });
                        }
                        AssignmentOperator::NullishCoalescingAssign => {
                            ops.push(Ir1Op::JumpIfNullish {
                                label_id: eval_rhs_label,
                            });
                        }
                        _ => {
                            return Err(LoweringPipelineError::InvariantViolation {
                                detail: "unexpected operator in member logical assignment",
                            });
                        }
                    }
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: current_binding,
                    });
                    ops.push(Ir1Op::Jump {
                        label_id: end_label,
                    });
                    ops.push(Ir1Op::Label { id: eval_rhs_label });

                    let rhs_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "member_assignment_rhs",
                    )?;
                    lower_expression_to_ir1(
                        right,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: rhs_binding,
                    });
                    ops.push(Ir1Op::Pop);
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: object_binding,
                    });
                    if let Some(key_binding) = dynamic_key_binding {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: key_binding,
                        });
                    }
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: rhs_binding,
                    });
                    ops.push(Ir1Op::SetProperty { key });
                    ops.push(Ir1Op::Label { id: end_label });
                    return Ok(());
                }

                if let Some(binary_operator) = compound_assignment_binary_operator(*operator) {
                    // Non-logical compound member assignment (`obj.x += rhs`,
                    // `a[i] *= rhs`, …): the operand and key must be evaluated
                    // ONCE, the current property value loaded and combined with the
                    // RHS, then written back. The prior bare `SetProperty` path
                    // ignored `operator` and stored the RHS alone, so `obj.x += 1`
                    // set `obj.x = 1` rather than `obj.x + 1` (bd-rmxao). Stash the
                    // object (and computed key) in internal bindings so the same
                    // reference feeds both the load and the store without re-
                    // evaluating a side-effecting object/key expression.
                    let object_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "member_compound_object",
                    )?;
                    lower_expression_to_ir1(
                        object,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: object_binding,
                    });
                    ops.push(Ir1Op::Pop);

                    let (key, dynamic_key_binding) = if *computed {
                        let key_binding = alloc_internal_binding(
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            "member_compound_key",
                        )?;
                        lower_expression_to_ir1(
                            property,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::StoreBinding {
                            binding_id: key_binding,
                        });
                        ops.push(Ir1Op::Pop);
                        (Ir1PropertyKey::Dynamic, Some(key_binding))
                    } else {
                        (
                            lower_member_property_key_to_ir1(
                                property,
                                false,
                                ops,
                                bindings,
                                binding_lookup,
                                binding_index,
                                root_scope_id,
                                label_counter,
                            )?,
                            None,
                        )
                    };

                    // current = obj[key]
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: object_binding,
                    });
                    if let Some(key_binding) = dynamic_key_binding {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: key_binding,
                        });
                    }
                    ops.push(Ir1Op::GetProperty { key: key.clone() });

                    // combined = current <op> rhs (current is the deeper stack
                    // slot / lhs; BinaryOp pops rhs then lhs).
                    lower_expression_to_ir1(
                        right,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                    ops.push(Ir1Op::BinaryOp {
                        operator: binary_operator,
                    });

                    // SetProperty needs the object (and key) beneath the value, so
                    // stash the combined value and reload the reference before it.
                    let result_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "member_compound_result",
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: result_binding,
                    });
                    ops.push(Ir1Op::Pop);
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: object_binding,
                    });
                    if let Some(key_binding) = dynamic_key_binding {
                        ops.push(Ir1Op::LoadBinding {
                            binding_id: key_binding,
                        });
                    }
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: result_binding,
                    });
                    // SetProperty leaves the assigned value on the stack, so the
                    // compound assignment yields the combined value (as ES requires).
                    ops.push(Ir1Op::SetProperty { key });
                    return Ok(());
                }

                lower_expression_to_ir1(
                    object,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                let key = lower_member_property_key_to_ir1(
                    property,
                    *computed,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                lower_expression_to_ir1(
                    right,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::SetProperty { key });
            } else {
                return Err(unsupported_frontier_expression_error(
                    "assignment_target",
                    "FE-LOWER-ASSIGN-0001",
                    "lower_ir0_to_ir1.assignment_target",
                    "assignment to non-lvalue target is not supported; only identifiers and member expressions are valid assignment targets",
                    None,
                ));
            }
        }
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            // Both branches store into a shared temporary binding so the
            // result is in a single register regardless of which branch
            // executed at runtime (the value_stack is tracked linearly and
            // would otherwise reference a register from only one branch).
            let result_binding = alloc_internal_binding(
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                "cond_result",
            )?;

            lower_expression_to_ir1(
                test,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            let else_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);
            ops.push(Ir1Op::JumpIfFalsy {
                label_id: else_label,
            });
            ops.push(Ir1Op::Pop);
            lower_expression_to_ir1(
                consequent,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::StoreBinding {
                binding_id: result_binding,
            });
            ops.push(Ir1Op::Pop);
            ops.push(Ir1Op::Jump {
                label_id: end_label,
            });
            ops.push(Ir1Op::Label { id: else_label });
            lower_expression_to_ir1(
                alternate,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::StoreBinding {
                binding_id: result_binding,
            });
            ops.push(Ir1Op::Pop);
            ops.push(Ir1Op::Label { id: end_label });
            ops.push(Ir1Op::LoadBinding {
                binding_id: result_binding,
            });
        }
        Expression::Call { callee, arguments } => {
            if matches!(callee.as_ref(), Expression::Super) {
                ops.push(Ir1Op::LoadSuper);
                ops.push(Ir1Op::LoadThis);
                for arg in arguments {
                    lower_expression_to_ir1(
                        arg,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::CallMethod {
                    arg_count: arguments.len() as u32,
                });
                return Ok(());
            }
            if let Expression::Member {
                object,
                property,
                computed,
            } = callee.as_ref()
                && matches!(object.as_ref(), Expression::Super)
            {
                ops.push(Ir1Op::LoadSuper);
                let key = lower_member_property_key_to_ir1(
                    property,
                    *computed,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::GetProperty { key });
                ops.push(Ir1Op::LoadThis);
                for arg in arguments {
                    lower_expression_to_ir1(
                        arg,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::CallMethod {
                    arg_count: arguments.len() as u32,
                });
                return Ok(());
            }
            if let Expression::Identifier(name) = callee.as_ref()
                && name == "require"
                && !binding_lookup.contains_key(name.as_str())
            {
                for arg in arguments {
                    lower_expression_to_ir1(
                        arg,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::HostCall {
                    capability: "module:require".to_string(),
                    arg_count: arguments.len() as u32,
                });
                return Ok(());
            }
            // bd-tu0c3: pure-compute Node `path` builtins. Recognized member
            // calls on a confirmed path-module alias (`const path =
            // require('path')`), on its `.posix`/`.win32` namespaces, or on an
            // inline `require('path')` receiver lower to `builtin:Path*`
            // hostcalls. The receiver is deliberately NOT lowered — the
            // recognized require declaration is elided and recognition is
            // purely syntactic. Arity is validated at dispatch (variadic
            // join/resolve, optional basename ext). Mirror of the
            // franken-engine call-arm interception.
            if let Some(capability) = path_builtin_call_capability(callee, binding_lookup) {
                for arg in arguments {
                    lower_expression_to_ir1(
                        arg,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::HostCall {
                    capability: capability.to_string(),
                    arg_count: arguments.len() as u32,
                });
                return Ok(());
            }
            // bd-qmy52: pure-compute Node `querystring` and `os` builtins.
            // Recognized member calls on a confirmed module alias or an
            // inline `require('querystring')` / `require('os')` receiver
            // lower to `builtin:Querystring*` / `builtin:Os*` hostcalls,
            // exactly like the path interception above (receiver NOT lowered;
            // arity validated at dispatch). Mirror of the franken-engine
            // call-arm interception.
            if let Some(capability) = querystring_builtin_call_capability(callee, binding_lookup)
                .or_else(|| os_builtin_call_capability(callee, binding_lookup))
            {
                for arg in arguments {
                    lower_expression_to_ir1(
                        arg,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::HostCall {
                    capability: capability.to_string(),
                    arg_count: arguments.len() as u32,
                });
                return Ok(());
            }
            // Core has no global-object registry, so supported static methods
            // on bare unshadowed globals resolve directly to hostcalls.
            if let Some(capability) = static_builtin_call_capability(callee, binding_lookup) {
                for arg in arguments {
                    lower_expression_to_ir1(
                        arg,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::HostCall {
                    capability: capability.to_string(),
                    arg_count: arguments.len() as u32,
                });
                return Ok(());
            }
            // Detect method calls: obj.method(args) → CallMethod with receiver
            let is_method = matches!(
                callee.as_ref(),
                Expression::Member {
                    computed: false,
                    ..
                }
            );
            if is_method {
                if let Expression::Member {
                    object, property, ..
                } = callee.as_ref()
                {
                    // Push receiver (object) first
                    lower_expression_to_ir1(
                        object,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                    // Push the method (GetProperty on the object)
                    // We need to duplicate the object ref for GetProperty
                    // Store object in a temp binding
                    let receiver_binding = alloc_internal_binding(
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        "method_receiver",
                    )?;
                    ops.push(Ir1Op::StoreBinding {
                        binding_id: receiver_binding,
                    });
                    // Object is still on stack from StoreBinding (it pushes back)
                    // GetProperty pops object and pushes property value
                    let key = lower_member_property_key_to_ir1(
                        property,
                        false,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                    ops.push(Ir1Op::GetProperty { key });
                    // Now stack has: [... receiver_binding_val, method_val]
                    // Push receiver again for CallMethod
                    ops.push(Ir1Op::LoadBinding {
                        binding_id: receiver_binding,
                    });
                    // Push args
                    for arg in arguments {
                        lower_expression_to_ir1(
                            arg,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                    }
                    ops.push(Ir1Op::CallMethod {
                        arg_count: arguments.len() as u32,
                    });
                }
            } else {
                lower_expression_to_ir1(
                    callee,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                for arg in arguments {
                    lower_expression_to_ir1(
                        arg,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::Call {
                    arg_count: arguments.len() as u32,
                });
            }
        }
        Expression::Member {
            object,
            property,
            computed,
        } => {
            // bd-cue2u: unshadowed `Array.isArray` / `Array["isArray"]`
            // member reads materialize a deterministic first-class builtin
            // callable. Direct calls are still intercepted earlier as
            // `builtin:ArrayIsArray`, while lexical `Array` bindings fall
            // through to ordinary property access.
            if let Some(capability) = static_builtin_member_factory_capability(
                object,
                property,
                *computed,
                binding_lookup,
            ) {
                ops.push(Ir1Op::HostCall {
                    capability: capability.to_string(),
                    arg_count: 0,
                });
                return Ok(());
            }
            // bd-tu0c3: `path.sep` / `path.delimiter` (and the
            // `.posix`/`.win32` namespace forms) on a confirmed path-module
            // alias are deterministic platform constants; lower them directly
            // to string literals. The receiver is deliberately NOT lowered (no
            // real path module object). Mirror of the franken-engine
            // member-arm interception.
            if let Some(constant) =
                path_member_constant(object, property, *computed, binding_lookup)
            {
                ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::String(constant.to_string()),
                });
                return Ok(());
            }
            // bd-qmy52: recognized `os` property READS on a confirmed
            // os-module alias. `os.EOL` / `os.devNull` lower to string
            // literals; `os.constants` lowers to a 0-arg `builtin:OsConstants`
            // HostCall allocating the nested `{ signals, errno, priority }`
            // object so chained reads (`os.constants.signals.SIGINT`) and
            // bare reads (`typeof os.constants`) both work on a real heap
            // object. Mirror of the franken-engine member-arm interception.
            if let Some(lowering) =
                os_member_read_lowering(object, property, *computed, binding_lookup)
            {
                match lowering {
                    OsMemberReadLowering::StringConstant(constant) => {
                        ops.push(Ir1Op::LoadLiteral {
                            value: Ir1Literal::String(constant.to_string()),
                        });
                    }
                    OsMemberReadLowering::ConstantsHostcall => {
                        ops.push(Ir1Op::HostCall {
                            capability: "builtin:OsConstants".to_string(),
                            arg_count: 0,
                        });
                    }
                }
                return Ok(());
            }
            lower_expression_to_ir1(
                object,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            let key = lower_member_property_key_to_ir1(
                property,
                *computed,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::GetProperty { key });
        }
        Expression::OptionalMember {
            object,
            property,
            computed,
        } => {
            // Desugar `obj?.prop` / `obj?.[expr]` into:
            //   temp_obj = <object>
            //   if (temp_obj == null || temp_obj == undefined) goto skip
            //   result = temp_obj.<property>
            //   goto end
            //   skip: result = undefined
            //   end: push result
            let temp_obj = alloc_internal_binding(
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                "opt_member_obj",
            )?;
            let result_binding = alloc_internal_binding(
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                "opt_member_result",
            )?;
            let skip_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);

            // Evaluate the object expression and store into temp.
            lower_expression_to_ir1(
                object,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::StoreBinding {
                binding_id: temp_obj,
            });
            ops.push(Ir1Op::Pop);

            // Nullish check: if object is null/undefined, short-circuit.
            ops.push(Ir1Op::LoadBinding {
                binding_id: temp_obj,
            });
            ops.push(Ir1Op::JumpIfNullish {
                label_id: skip_label,
            });

            // Not-nullish path: perform property access.
            ops.push(Ir1Op::LoadBinding {
                binding_id: temp_obj,
            });
            let key = lower_member_property_key_to_ir1(
                property,
                *computed,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::GetProperty { key });
            ops.push(Ir1Op::StoreBinding {
                binding_id: result_binding,
            });
            ops.push(Ir1Op::Pop);
            ops.push(Ir1Op::Jump {
                label_id: end_label,
            });

            // Nullish path: produce undefined.
            ops.push(Ir1Op::Label { id: skip_label });
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            });
            ops.push(Ir1Op::StoreBinding {
                binding_id: result_binding,
            });
            ops.push(Ir1Op::Pop);

            // End: load the result.
            ops.push(Ir1Op::Label { id: end_label });
            ops.push(Ir1Op::LoadBinding {
                binding_id: result_binding,
            });
        }
        Expression::OptionalCall { callee, arguments } => {
            // Desugar `fn?.()` / `obj.m?.()` into:
            //   temp_callee = <callee>
            //   if (temp_callee == null || temp_callee == undefined) goto skip
            //   result = temp_callee(<args...>)
            //   goto end
            //   skip: result = undefined
            //   end: push result
            let temp_callee = alloc_internal_binding(
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                "opt_call_callee",
            )?;
            let result_binding = alloc_internal_binding(
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                "opt_call_result",
            )?;
            let skip_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);

            // Evaluate the callee and store into temp.
            lower_expression_to_ir1(
                callee,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            ops.push(Ir1Op::StoreBinding {
                binding_id: temp_callee,
            });
            ops.push(Ir1Op::Pop);

            // Nullish check: if callee is null/undefined, short-circuit.
            ops.push(Ir1Op::LoadBinding {
                binding_id: temp_callee,
            });
            ops.push(Ir1Op::JumpIfNullish {
                label_id: skip_label,
            });

            // Not-nullish path: perform the call.
            ops.push(Ir1Op::LoadBinding {
                binding_id: temp_callee,
            });
            for arg in arguments {
                lower_expression_to_ir1(
                    arg,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
            }
            ops.push(Ir1Op::Call {
                arg_count: arguments.len() as u32,
            });
            ops.push(Ir1Op::StoreBinding {
                binding_id: result_binding,
            });
            ops.push(Ir1Op::Pop);
            ops.push(Ir1Op::Jump {
                label_id: end_label,
            });

            // Nullish path: produce undefined.
            ops.push(Ir1Op::Label { id: skip_label });
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined,
            });
            ops.push(Ir1Op::StoreBinding {
                binding_id: result_binding,
            });
            ops.push(Ir1Op::Pop);

            // End: load the result.
            ops.push(Ir1Op::Label { id: end_label });
            ops.push(Ir1Op::LoadBinding {
                binding_id: result_binding,
            });
        }
        Expression::This => {
            ops.push(Ir1Op::LoadThis);
        }
        Expression::NewTarget => {
            ops.push(Ir1Op::LoadNewTarget);
        }
        Expression::Super => {
            ops.push(Ir1Op::LoadSuper);
        }
        Expression::ArrayLiteral(elements) => {
            // Check if any element is a spread
            let has_spread = elements
                .iter()
                .any(|elem| matches!(elem, Some(Expression::SpreadElement(_))));

            if has_spread {
                // With spreads, use incremental approach:
                // 1. Create empty array
                // 2. For each element: ArrayPush or SpreadIntoArray
                ops.push(Ir1Op::NewArray { count: 0 });
                for elem in elements {
                    match elem {
                        Some(Expression::SpreadElement(inner)) => {
                            // Lower the iterable
                            lower_expression_to_ir1(
                                inner,
                                ops,
                                bindings,
                                binding_lookup,
                                binding_index,
                                root_scope_id,
                                label_counter,
                            )?;
                            ops.push(Ir1Op::SpreadIntoArray);
                        }
                        Some(expr) => {
                            // Lower normal element
                            lower_expression_to_ir1(
                                expr,
                                ops,
                                bindings,
                                binding_lookup,
                                binding_index,
                                root_scope_id,
                                label_counter,
                            )?;
                            ops.push(Ir1Op::ArrayPush);
                        }
                        None => {
                            // Hole - push undefined
                            ops.push(Ir1Op::LoadLiteral {
                                value: Ir1Literal::Undefined,
                            });
                            ops.push(Ir1Op::ArrayPush);
                        }
                    }
                }
            } else {
                // No spreads - use original efficient batch approach
                for elem in elements {
                    if let Some(expr) = elem {
                        lower_expression_to_ir1(
                            expr,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                    } else {
                        ops.push(Ir1Op::LoadLiteral {
                            value: Ir1Literal::Undefined,
                        });
                    }
                }
                ops.push(Ir1Op::NewArray {
                    count: elements.len() as u32,
                });
            }
        }
        Expression::ObjectLiteral(properties) => {
            // Check if any property is a spread ({...obj})
            let has_spread = properties
                .iter()
                .any(|prop| matches!(&prop.value, Expression::SpreadElement(_)));

            if has_spread {
                // With spreads, use incremental approach:
                // 1. Create empty object
                // 2. For each property: SetProperty or SpreadIntoObject
                ops.push(Ir1Op::NewObject { count: 0 });
                for prop in properties {
                    if let Expression::SpreadElement(inner) = &prop.value {
                        // Spread property - lower the source object and spread
                        lower_expression_to_ir1(
                            inner,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::SpreadIntoObject);
                    } else {
                        // Normal property - emit key and value, then set
                        if prop.computed {
                            lower_expression_to_ir1(
                                &prop.key,
                                ops,
                                bindings,
                                binding_lookup,
                                binding_index,
                                root_scope_id,
                                label_counter,
                            )?;
                        } else {
                            let key_str = match &prop.key {
                                Expression::Identifier(name) => name.clone(),
                                Expression::StringLiteral(s) => s.clone(),
                                Expression::NumericLiteral(n) => n.to_string(),
                                other => format!("{other:?}"),
                            };
                            ops.push(Ir1Op::LoadLiteral {
                                value: Ir1Literal::String(key_str),
                            });
                        }
                        lower_expression_to_ir1(
                            &prop.value,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                        ops.push(Ir1Op::SetProperty {
                            key: Ir1PropertyKey::Dynamic,
                        });
                    }
                }
            } else {
                // No spreads - use original batch approach
                for prop in properties {
                    if prop.computed {
                        lower_expression_to_ir1(
                            &prop.key,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                    } else {
                        let key_str = match &prop.key {
                            Expression::Identifier(name) => name.clone(),
                            Expression::StringLiteral(s) => s.clone(),
                            Expression::NumericLiteral(n) => n.to_string(),
                            other => format!("{other:?}"),
                        };
                        ops.push(Ir1Op::LoadLiteral {
                            value: Ir1Literal::String(key_str),
                        });
                    }
                    lower_expression_to_ir1(
                        &prop.value,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ops.push(Ir1Op::NewObject {
                    count: properties.len() as u32,
                });
            }
        }
        Expression::ArrowFunction { params, body, .. } => {
            // Lower arrow function body with its own fresh scope.
            let mut body_ops = Vec::new();
            let mut body_bindings = Vec::new();
            let mut body_lookup = BTreeMap::new();
            let mut body_binding_index: BindingId = 0;
            let body_scope = ScopeId { depth: 0, index: 0 };
            let mut body_label_counter: u32 = 0;
            let FunctionParameterPlan {
                param_names,
                destructure_params,
                rest_param_index,
            } = allocate_function_parameter_bindings(
                params,
                &mut body_bindings,
                &mut body_lookup,
                &mut body_binding_index,
                body_scope,
            )?;
            let parameter_binding_names = body_lookup.keys().cloned().collect();
            let parameter_prologue_captures = lower_function_parameter_prologue(
                &destructure_params,
                binding_lookup,
                &mut body_ops,
                &mut body_bindings,
                &body_lookup,
                &mut body_binding_index,
                body_scope,
                &mut body_label_counter,
            )?;
            let pre_lower_names = prepare_function_body_bindings(
                match body {
                    ArrowBody::Block(block) => Some(block.body.as_slice()),
                    ArrowBody::Expression(_) => None,
                },
                parameter_binding_names,
                &mut body_lookup,
                &mut body_binding_index,
            );
            merge_unshadowed_parameter_prologue_captures(
                &parameter_prologue_captures,
                &mut body_lookup,
            );
            seed_function_outer_static_bindings(
                binding_lookup,
                &mut body_lookup,
                &mut body_binding_index,
            );
            match body {
                ArrowBody::Expression(expr) => {
                    lower_expression_to_ir1(
                        expr,
                        &mut body_ops,
                        &mut body_bindings,
                        &mut body_lookup,
                        &mut body_binding_index,
                        body_scope,
                        &mut body_label_counter,
                    )?;
                }
                ArrowBody::Block(block) => {
                    for stmt in &block.body {
                        lower_statement_to_ir1(
                            stmt,
                            &mut body_ops,
                            &mut body_bindings,
                            &mut body_lookup,
                            &mut body_binding_index,
                            body_scope,
                            &mut body_label_counter,
                        )?;
                    }
                }
            }
            // Ensure body ends with a return.
            if !matches!(body_ops.last(), Some(Ir1Op::Return)) {
                body_ops.push(Ir1Op::Return);
            }
            let (mut arrow_free_vars, mut arrow_free_var_ids, mut arrow_free_var_outer_ids) =
                collect_free_vars(
                    &body_lookup,
                    &pre_lower_names,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                );
            append_shadowed_parameter_prologue_captures(
                &parameter_prologue_captures,
                &mut arrow_free_vars,
                &mut arrow_free_var_ids,
                &mut arrow_free_var_outer_ids,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
            );
            ops.push(Ir1Op::CreateFunction {
                name: None,
                param_names,
                body_ops,
                free_vars: arrow_free_vars,
                free_var_ids: arrow_free_var_ids,
                free_var_outer_ids: arrow_free_var_outer_ids,
                is_generator: false,
                is_arrow: true,
                rest_param_index,
            });
        }
        Expression::Function {
            name,
            params,
            body,
            is_generator,
            ..
        } => {
            // Same as ArrowFunction but with a BlockStatement body and optional name.
            let mut body_ops = Vec::new();
            let mut body_bindings = Vec::new();
            let mut body_lookup = BTreeMap::new();
            let mut body_binding_index: BindingId = 0;
            let body_scope = ScopeId { depth: 0, index: 0 };
            let mut body_label_counter: u32 = 0;
            let FunctionParameterPlan {
                param_names,
                destructure_params,
                rest_param_index,
            } = allocate_function_parameter_bindings(
                params,
                &mut body_bindings,
                &mut body_lookup,
                &mut body_binding_index,
                body_scope,
            )?;
            if rest_param_index.is_some() && *is_generator {
                return Err(unsupported_frontier_expression_error(
                    "generator_rest_parameters",
                    "FE-LOWER-UNSUPPORTED-GENERATOR-REST-0001",
                    "core.generator_rest_parameter_runtime",
                    "generator rest parameters require suspended-frame argument persistence",
                    Some(body.span.clone()),
                ));
            }
            let parameter_binding_names = body_lookup.keys().cloned().collect();
            let parameter_prologue_captures = lower_function_parameter_prologue(
                &destructure_params,
                binding_lookup,
                &mut body_ops,
                &mut body_bindings,
                &body_lookup,
                &mut body_binding_index,
                body_scope,
                &mut body_label_counter,
            )?;
            if let Some(function_name) = name {
                reject_self_referential_parameter_capture(
                    &parameter_prologue_captures,
                    function_name,
                    body.span.clone(),
                )?;
            }
            let mut pre_lower_names = prepare_function_body_bindings(
                Some(&body.body),
                parameter_binding_names,
                &mut body_lookup,
                &mut body_binding_index,
            );
            // A named function expression has an internal lexical name that
            // shadows globals in its own body. Parameters and declarations
            // in the function body are inner and intentionally win if they
            // reuse that spelling, so install the self name only after their
            // pre-scan.
            if let Some(function_name) = name
                && !body_lookup.contains_key(function_name)
            {
                let _ = alloc_binding(
                    &mut body_bindings,
                    &mut body_lookup,
                    &mut body_binding_index,
                    body_scope,
                    function_name,
                    BindingKind::FunctionDecl,
                )
                .map_err(LoweringPipelineError::SemanticViolation)?;
                pre_lower_names.insert(function_name.clone());
            }
            merge_unshadowed_parameter_prologue_captures(
                &parameter_prologue_captures,
                &mut body_lookup,
            );
            seed_function_outer_static_bindings(
                binding_lookup,
                &mut body_lookup,
                &mut body_binding_index,
            );
            for stmt in &body.body {
                lower_statement_to_ir1(
                    stmt,
                    &mut body_ops,
                    &mut body_bindings,
                    &mut body_lookup,
                    &mut body_binding_index,
                    body_scope,
                    &mut body_label_counter,
                )?;
            }
            if !matches!(body_ops.last(), Some(Ir1Op::Return)) {
                body_ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                });
                body_ops.push(Ir1Op::Return);
            }
            let (mut fn_free_vars, mut fn_free_var_ids, mut fn_free_var_outer_ids) =
                collect_free_vars(
                    &body_lookup,
                    &pre_lower_names,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                );
            append_shadowed_parameter_prologue_captures(
                &parameter_prologue_captures,
                &mut fn_free_vars,
                &mut fn_free_var_ids,
                &mut fn_free_var_outer_ids,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
            );
            ops.push(Ir1Op::CreateFunction {
                name: name.clone(),
                param_names,
                body_ops,
                free_vars: fn_free_vars,
                free_var_ids: fn_free_var_ids,
                free_var_outer_ids: fn_free_var_outer_ids,
                is_generator: *is_generator,
                is_arrow: false,
                rest_param_index,
            });
        }
        Expression::New { callee, arguments } => {
            lower_expression_to_ir1(
                callee,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
            for arg in arguments {
                lower_expression_to_ir1(
                    arg,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
            }
            ops.push(Ir1Op::Construct {
                arg_count: arguments.len() as u32,
            });
        }
        Expression::TemplateLiteral {
            quasis,
            expressions,
        } => {
            // Interleave quasis and expressions: quasi[0], expr[0], quasi[1], ..., quasi[N-1]
            for (i, quasi) in quasis.iter().enumerate() {
                ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::String(quasi.clone()),
                });
                if i < expressions.len() {
                    lower_expression_to_ir1(
                        &expressions[i],
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
            }
            ops.push(Ir1Op::TemplateLiteral {
                quasi_count: quasis.len() as u32,
            });
        }
        Expression::ClassExpression {
            name,
            super_class,
            body,
        } => {
            lower_class_expression_to_ir1(
                name.as_deref(),
                super_class.as_deref(),
                body,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lower_member_property_key_to_ir1(
    property: &Expression,
    computed: bool,
    ops: &mut Vec<Ir1Op>,
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    root_scope_id: ScopeId,
    label_counter: &mut u32,
) -> Result<Ir1PropertyKey, LoweringPipelineError> {
    if computed {
        lower_expression_to_ir1(
            property,
            ops,
            bindings,
            binding_lookup,
            binding_index,
            root_scope_id,
            label_counter,
        )?;
        return Ok(Ir1PropertyKey::Dynamic);
    }

    let key = match property {
        Expression::Identifier(name) => name.clone(),
        Expression::StringLiteral(value) => value.clone(),
        Expression::NumericLiteral(value) => value.to_string(),
        _ => "unknown".to_string(),
    };
    Ok(Ir1PropertyKey::Static(key))
}

fn classify_ir1_op(
    op: &Ir1Op,
) -> (
    EffectBoundary,
    Option<CapabilityTag>,
    Option<FlowAnnotation>,
) {
    match op {
        Ir1Op::ImportModule { .. } => (
            EffectBoundary::ReadEffect,
            Some(CapabilityTag("module.import".to_string())),
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::HostCall { capability, .. } => (
            EffectBoundary::HostcallEffect,
            Some(CapabilityTag(capability.clone())),
            Some(FlowAnnotation {
                data_label: Label::Confidential,
                sink_clearance: Label::Confidential,
                declassification_required: false,
            }),
        ),
        Ir1Op::Call { .. } | Ir1Op::CallMethod { .. } => (
            // User-defined function calls are pure; they must reach the
            // regular Ir1Op::Call → Ir3Instruction::Call lowering path
            // so the interpreter can set up a call frame and execute the
            // function body.  Hostcall-grade IFC gating, when required,
            // should be emitted as a separate guard instruction rather
            // than hijacking the call itself.
            EffectBoundary::Pure,
            None,
            None,
        ),
        Ir1Op::Await | Ir1Op::Yield { .. } => (
            EffectBoundary::ReadEffect,
            None,
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(raw),
        } => {
            if let Some(capability) = extract_hostcall_capability(raw) {
                return (
                    EffectBoundary::HostcallEffect,
                    Some(CapabilityTag(capability)),
                    Some(FlowAnnotation {
                        data_label: Label::Confidential,
                        sink_clearance: Label::Confidential,
                        declassification_required: false,
                    }),
                );
            }
            (EffectBoundary::Pure, None, None)
        }
        Ir1Op::Throw
        | Ir1Op::BeginTry { .. }
        | Ir1Op::EndTry
        | Ir1Op::EnterFinally
        | Ir1Op::EndFinally
        | Ir1Op::DiscardAbruptCompletion => (
            EffectBoundary::ReadEffect,
            None,
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::GetProperty { .. } | Ir1Op::SetProperty { .. } | Ir1Op::DeleteProperty { .. } => {
            (EffectBoundary::ReadEffect, None, None)
        }
        Ir1Op::ForInInit
        | Ir1Op::ForInNext { .. }
        | Ir1Op::ForOfInit
        | Ir1Op::ForOfNext { .. }
        | Ir1Op::IteratorClose { .. }
        | Ir1Op::Construct { .. }
        | Ir1Op::TemplateLiteral { .. } => (EffectBoundary::ReadEffect, None, None),
        _ => (EffectBoundary::Pure, None, None),
    }
}

fn infer_ir2_flow_annotations(ir2: &mut Ir2Module) -> FlowInferenceMetrics {
    infer_ir2_flow_annotations_for_ops(&mut ir2.ops)
}

fn infer_ir2_flow_annotations_for_ops(ops: &mut [Ir2Op]) -> FlowInferenceMetrics {
    let mut binding_labels = BTreeMap::<BindingId, Label>::new();
    let mut last_label = Label::Public;
    let mut metrics = FlowInferenceMetrics {
        total_flow_ops: 0,
        static_proven_ops: 0,
        runtime_check_ops: 0,
    };

    for op in ops {
        let inferred_data_label =
            infer_data_label_for_op(&op.inner, &binding_labels, last_label.clone());
        let inferred_sink_clearance = infer_sink_clearance(
            &op.effect,
            op.required_capability.as_ref(),
            &inferred_data_label,
        );
        let requires_declassification = !inferred_data_label.can_flow_to(&inferred_sink_clearance);
        let runtime_guard_needed = op.required_capability.as_ref().is_some_and(|capability| {
            flow_requires_runtime_check(
                Some(&FlowAnnotation {
                    data_label: inferred_data_label.clone(),
                    sink_clearance: inferred_sink_clearance.clone(),
                    declassification_required: requires_declassification,
                }),
                capability,
            )
        });
        let should_annotate = op.flow.is_some() || !matches!(op.effect, EffectBoundary::Pure);
        if should_annotate {
            metrics.total_flow_ops = metrics.total_flow_ops.saturating_add(1);
            if requires_declassification || runtime_guard_needed {
                metrics.runtime_check_ops = metrics.runtime_check_ops.saturating_add(1);
            } else {
                metrics.static_proven_ops = metrics.static_proven_ops.saturating_add(1);
            }
            op.flow = Some(FlowAnnotation {
                data_label: inferred_data_label.clone(),
                sink_clearance: inferred_sink_clearance,
                declassification_required: requires_declassification,
            });
        } else {
            op.flow = None;
        }

        if let Ir1Op::StoreBinding { binding_id } = &op.inner {
            binding_labels.insert(*binding_id, inferred_data_label.clone());
        }
        if let Ir1Op::LoadBinding { binding_id } = &op.inner
            && let Some(existing) = binding_labels.get(binding_id)
        {
            last_label = existing.clone();
            continue;
        }
        last_label = inferred_data_label;
    }

    metrics
}

fn infer_data_label_for_op(
    op: &Ir1Op,
    binding_labels: &BTreeMap<BindingId, Label>,
    last_label: Label,
) -> Label {
    match op {
        Ir1Op::LoadLiteral {
            value: Ir1Literal::String(raw),
        } => {
            let lowered = raw.to_ascii_lowercase();
            if lowered.contains("secret")
                || lowered.contains("token")
                || lowered.contains("api_key")
                || lowered.contains("password")
                || lowered.contains("credential")
            {
                Label::Secret
            } else {
                Label::Public
            }
        }
        Ir1Op::LoadLiteral { .. } => Label::Public,
        Ir1Op::LoadBinding { binding_id } => binding_labels
            .get(binding_id)
            .cloned()
            .unwrap_or(Label::Internal),
        Ir1Op::StoreBinding { .. } => last_label,
        Ir1Op::ImportModule { .. } | Ir1Op::Await | Ir1Op::Yield { .. } => Label::Internal,
        Ir1Op::Call { .. } => last_label,
        Ir1Op::ExportBinding { .. } => last_label,
        Ir1Op::Return | Ir1Op::Nop => last_label,
        // New IR1 ops (binary/unary/assign/control-flow) — propagate last label
        _ => last_label,
    }
}

fn infer_sink_clearance(
    effect: &EffectBoundary,
    required_capability: Option<&CapabilityTag>,
    data_label: &Label,
) -> Label {
    if let Some(capability) = required_capability {
        return sink_clearance_from_capability(&capability.0);
    }

    match effect {
        EffectBoundary::NetworkEffect => Label::Public,
        EffectBoundary::FsEffect => Label::Internal,
        EffectBoundary::ReadEffect | EffectBoundary::WriteEffect => Label::Internal,
        EffectBoundary::HostcallEffect => Label::Internal,
        EffectBoundary::Pure => data_label.clone(),
    }
}

fn sink_clearance_from_capability(capability: &str) -> Label {
    let normalized = capability.to_ascii_lowercase();
    if normalized == "hostcall.invoke" {
        return Label::Internal;
    }
    if normalized.contains("net.")
        || normalized.contains("net_")
        || normalized.contains("network")
        || normalized.contains("process.")
        || normalized.contains("process_")
        || normalized.contains("spawn")
    {
        return Label::Public;
    }
    if normalized.contains("credential") || normalized.contains("key_material") {
        return Label::TopSecret;
    }
    if normalized.contains("secret") || normalized.contains("token") || normalized.contains("key") {
        return Label::Secret;
    }
    if normalized.contains("fs.read") {
        return Label::Internal;
    }
    if normalized.contains("fs.write")
        || normalized.contains("module.import")
        || normalized.contains("import")
    {
        return Label::Internal;
    }
    if normalized.contains("declassify") {
        return Label::Public;
    }
    Label::Internal
}

fn flow_requires_runtime_check(flow: Option<&FlowAnnotation>, capability: &CapabilityTag) -> bool {
    let capability_is_dynamic = capability.0 == "hostcall.invoke";
    let flow_is_ambiguous = flow.is_some_and(|annotation| {
        matches!(annotation.data_label, Label::Custom { .. })
            || matches!(annotation.sink_clearance, Label::Custom { .. })
    });
    let flow_requires_declassification =
        flow.is_some_and(|annotation| annotation.declassification_required);
    capability_is_dynamic || flow_is_ambiguous || flow_requires_declassification
}

fn extract_hostcall_capability(raw: &str) -> Option<String> {
    for (marker, terminator) in [("hostcall<\"", "\">"), ("hostcall<\\\"", "\\\">")] {
        let Some(start) = raw.find(marker) else {
            continue;
        };
        let remainder = &raw[start + marker.len()..];
        let Some(end) = remainder.find(terminator) else {
            continue;
        };
        let capability = remainder[..end].trim();
        if !capability.is_empty() {
            return Some(capability.to_string());
        }
    }

    None
}

fn lower_literal_to_ir3(
    value: &Ir1Literal,
    dst: Reg,
    instructions: &mut Vec<Ir3Instruction>,
    constant_pool: &mut Vec<String>,
) {
    match value {
        Ir1Literal::String(text) => {
            let pool_index = push_constant(constant_pool, text);
            instructions.push(Ir3Instruction::LoadStr { dst, pool_index });
        }
        Ir1Literal::Integer(value) => {
            instructions.push(Ir3Instruction::LoadInt { dst, value: *value })
        }
        Ir1Literal::Float(bits) => {
            instructions.push(Ir3Instruction::LoadFloat { dst, bits: *bits })
        }
        Ir1Literal::Boolean(value) => {
            instructions.push(Ir3Instruction::LoadBool { dst, value: *value })
        }
        Ir1Literal::Null => instructions.push(Ir3Instruction::LoadNull { dst }),
        Ir1Literal::Undefined => instructions.push(Ir3Instruction::LoadUndefined { dst }),
    }
}

fn push_constant(pool: &mut Vec<String>, value: &str) -> u32 {
    if let Some(index) = pool.iter().position(|entry| entry == value) {
        return u32::try_from(index).unwrap_or(u32::MAX);
    }

    pool.push(value.to_string());
    u32::try_from(pool.len() - 1).unwrap_or(u32::MAX)
}

fn alloc_register(cursor: &mut Reg) -> Reg {
    let register = *cursor;
    *cursor = cursor.checked_add(1).unwrap_or(u32::MAX);
    register
}

fn scope_binding_ids_are_unique(scopes: &[ScopeNode]) -> bool {
    let mut seen = BTreeSet::<BindingId>::new();
    for scope in scopes {
        for binding in &scope.bindings {
            if !seen.insert(binding.binding_id) {
                return false;
            }
        }
    }
    true
}

fn hash_string(hash: &ContentHash) -> String {
    format!("sha256:{}", hex::encode(hash.as_bytes()))
}

fn lowering_error_from_ir_error(error: IrError) -> LoweringPipelineError {
    LoweringPipelineError::IrContractValidation {
        code: error.code.as_str().to_string(),
        level: error.level,
        message: error.message,
    }
}

fn ensure_checks_pass(
    checks: &[InvariantCheck],
    failure_detail: &'static str,
) -> Result<(), LoweringPipelineError> {
    if checks.iter().any(|check| !check.passed) {
        return Err(LoweringPipelineError::InvariantViolation {
            detail: failure_detail,
        });
    }
    Ok(())
}

fn success_event(context: &LoweringContext, event: &str) -> LoweringEvent {
    LoweringEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "pass".to_string(),
        error_code: None,
    }
}

fn failure_event(context: &LoweringContext, event: &str, error_code: &str) -> LoweringEvent {
    LoweringEvent {
        trace_id: context.trace_id.clone(),
        decision_id: context.decision_id.clone(),
        policy_id: context.policy_id.clone(),
        component: COMPONENT.to_string(),
        event: event.to_string(),
        outcome: "fail".to_string(),
        error_code: Some(error_code.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{
        ArrowBody, AssignmentOperator, BinaryOperator, BindingPattern, BlockStatement,
        BreakStatement, CatchClause, ContinueStatement, DoWhileStatement, ExportDeclaration,
        ExportKind, Expression, ExpressionStatement, ForInStatement, ForOfStatement, ForStatement,
        FunctionDeclaration, FunctionParam, IfStatement, ImportDeclaration, MethodDefinition,
        MethodKind, ObjectPatternProperty, ObjectProperty, ParseGoal, ReturnStatement, SourceSpan,
        Statement, SwitchCase, SwitchStatement, SyntaxTree, ThrowStatement, TryCatchStatement,
        UnaryOperator, VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
        WhileStatement,
    };
    use crate::baseline_interpreter::{InterpreterConfig, QuickJsLane, Value};
    use crate::capability::RuntimeCapability;
    use crate::parser::{CanonicalEs2020Parser, Es2020Parser};
    use crate::parser_gap_inventory::{ParserGapSiteId, UnsupportedSyntaxDiagnostic};

    fn span() -> SourceSpan {
        SourceSpan::new(0, 1, 1, 1, 1, 2)
    }

    fn script_ir0() -> Ir0Module {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(42),
                span: span(),
            })],
            span: span(),
        };
        Ir0Module::from_syntax_tree(tree, "fixture.js")
    }

    fn lower_rest_source_to_ir3(source: &str) -> Result<Ir3Module, LoweringPipelineError> {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("rest-parameter regression source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "rest_params.js");
        lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new("trace-rest", "decision-rest", "policy-rest"),
        )
        .map(|output| output.ir3)
    }

    fn lower_exception_source_to_ir3_bd_47p8z(source: &str) -> Ir3Module {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("exception-lowering regression source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd_47p8z.js");
        lower_ir0_to_ir3(
            &ir0,
            &LoweringContext::new("trace-bd-47p8z", "decision-bd-47p8z", "policy-bd-47p8z"),
        )
        .expect("exception-lowering regression source should lower")
        .ir3
    }

    fn execute_exception_module_bd_47p8z(module: &Ir3Module) -> Value {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        QuickJsLane::with_config(config)
            .execute(module, "trace-bd-47p8z")
            .expect("exception-lowering regression should execute")
            .value
    }

    fn lower_and_execute_deferred_source_bd_6pvhn(source: &str) -> (Ir1Module, Ir3Module, Value) {
        let tree = CanonicalEs2020Parser
            .parse(source, ParseGoal::Script)
            .expect("deferred-operation regression source should parse");
        let ir0 = Ir0Module::from_syntax_tree(tree, "bd_6pvhn.js");
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("deferred-operation regression should lower to IR1")
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("deferred-operation regression should lower to IR2")
            .module;
        let module = lower_ir2_to_ir3(&ir2)
            .expect("deferred-operation regression should lower to IR3")
            .module;
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = BTreeSet::from([
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]);
        let value = QuickJsLane::with_config(config)
            .execute(&module, "trace-bd-6pvhn")
            .expect("deferred-operation regression should execute")
            .value;
        (ir1, module, value)
    }

    fn deferred_ir1_body_bd_6pvhn<'a>(ir1: &'a Ir1Module, name: &str) -> &'a [Ir1Op] {
        ir1.ops
            .iter()
            .find_map(|op| match op {
                Ir1Op::DeclareFunction {
                    name: function_name,
                    body_ops,
                    ..
                } if function_name == name => Some(body_ops.as_slice()),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing IR1 deferred body for {name}"))
    }

    fn deferred_ir3_body_bd_6pvhn<'a>(module: &'a Ir3Module, name: &str) -> &'a [Ir3Instruction] {
        let start = module
            .function_table
            .iter()
            .find(|desc| desc.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("missing IR3 deferred body for {name}"))
            .entry as usize;
        let end = module
            .function_table
            .iter()
            .map(|desc| desc.entry as usize)
            .filter(|entry| *entry > start)
            .min()
            .unwrap_or(module.instructions.len());
        &module.instructions[start..end]
    }

    fn malformed_deferred_ir2_bd_6pvhn(body_ops: Vec<Ir1Op>) -> Ir2Module {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(b"malformed-deferred-ir0"),
            "bd_6pvhn_malformed.js",
        );
        ir1.ops.push(Ir1Op::DeclareFunction {
            name: "outer".to_string(),
            binding_id: 0,
            param_names: Vec::new(),
            body_ops,
            free_vars: Vec::new(),
            free_var_ids: Vec::new(),
            free_var_outer_ids: Vec::new(),
            is_generator: false,
            rest_param_index: None,
        });
        lower_ir1_to_ir2(&ir1)
            .expect("hand-built deferred IR1 should reach IR2 validation")
            .module
    }

    #[test]
    fn lower_ir0_to_ir1_emits_witness_and_scope() {
        let ir0 = script_ir0();
        let result = lower_ir0_to_ir1(&ir0).expect("IR0->IR1 should succeed");

        assert_eq!(result.witness.pass_id, "ir0_to_ir1");
        assert_eq!(result.module.header.level, IrLevel::Ir1);
        assert_eq!(result.module.scopes.len(), 1);
        assert!(!result.module.ops.is_empty());
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .all(|check| check.passed)
        );
    }

    #[test]
    fn lower_ir1_to_ir2_collects_capabilities_deterministically() {
        let ir0 = script_ir0();
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("IR0->IR1 should succeed")
            .module;
        let result = lower_ir1_to_ir2(&ir1).expect("IR1->IR2 should succeed");

        assert_eq!(result.witness.pass_id, "ir1_to_ir2");
        assert_eq!(result.module.header.level, IrLevel::Ir2);
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .all(|check| check.passed)
        );
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .any(|check| check.name == "ir2_static_flow_coverage_ratio")
        );
    }

    #[test]
    fn lower_ir1_to_ir2_zero_flow_ops_reports_zero_static_coverage() {
        let ir1 = Ir1Module::new(ContentHash::compute(b"zero-flow-ir0"), "zero_flow.js");
        let result = lower_ir1_to_ir2(&ir1).expect("IR1->IR2 should succeed");
        let coverage = result
            .witness
            .invariant_checks
            .iter()
            .find(|check| check.name == "ir2_static_flow_coverage_ratio")
            .expect("coverage check should be present");

        assert!(coverage.passed);
        assert!(coverage.detail.contains("static_coverage_millionths=0"));
        assert!(coverage.detail.contains("total_flow_ops=0"));
    }

    #[test]
    fn lower_ir2_to_ir3_produces_exec_instructions() {
        let ir0 = script_ir0();
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("IR0->IR1 should succeed")
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let result = lower_ir2_to_ir3(&ir2).expect("IR2->IR3 should succeed");

        assert_eq!(result.witness.pass_id, "ir2_to_ir3");
        assert_eq!(result.module.header.level, IrLevel::Ir3);
        assert!(!result.module.instructions.is_empty());
        assert!(matches!(
            result.module.instructions.last(),
            Some(Ir3Instruction::Halt)
        ));
        assert!(
            result
                .witness
                .invariant_checks
                .iter()
                .all(|check| check.passed)
        );
    }

    #[test]
    fn lower_ir2_to_ir3_resolves_jump_if_falsy_targets() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"jump-if-falsy"), "jump_if_falsy.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::LoadLiteral {
                value: Ir1Literal::Boolean(false),
            },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::JumpIfFalsy { label_id: 7 },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(1),
            },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Return,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Label { id: 7 },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(2),
            },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Return,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("IR2->IR3 should resolve conditional control-flow")
            .module;

        // The condition value (`LoadBool false`) lands in register 1, not 0:
        // module-level binding/temporary allocation starts at register 1 because
        // r0 is reserved for the script completion value (bd-fqlfw.2.11.1). The
        // jump TARGETS (instruction indices 3 and 5) are unaffected by register
        // numbering. (bd-7duxc: this assertion's `cond: 0` was stale after the
        // register-0 reservation landed.)
        assert!(matches!(
            ir3.instructions.get(1),
            Some(Ir3Instruction::JumpIf { cond: 1, target: 3 })
        ));
        assert!(matches!(
            ir3.instructions.get(2),
            Some(Ir3Instruction::Jump { target: 5 })
        ));
        assert!(
            ir3.instructions
                .iter()
                .all(|instruction| match instruction {
                    Ir3Instruction::Jump { target }
                    | Ir3Instruction::JumpIf { target, .. }
                    | Ir3Instruction::JumpIfNullish { target, .. } => {
                        *target != 0
                    }
                    _ => true,
                })
        );
    }

    #[test]
    fn lower_ir2_to_ir3_rejects_missing_jump_labels() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"missing-label"), "missing_label.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Jump { label_id: 42 },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });

        let err = lower_ir2_to_ir3(&ir2).expect_err("missing label should fail closed");
        assert_eq!(
            err,
            LoweringPipelineError::InvariantViolation {
                detail: "lowered control-flow references missing label",
            }
        );
    }

    #[test]
    fn lower_ir2_to_ir3_call_fails_closed_when_callee_missing() {
        // A `Call` needs `arg_count + 1` stack slots (the args plus the callee).
        // With an empty value stack, even `arg_count == 0` must fail closed on
        // the absent callee rather than silently defaulting it to register 0.
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"call-underflow"), "call_underflow.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Call { arg_count: 0 },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });

        let err = lower_ir2_to_ir3(&ir2).expect_err("missing callee should fail closed");
        assert_eq!(
            err,
            LoweringPipelineError::InvariantViolation {
                detail: "Value stack underflow in Call",
            }
        );
    }

    #[test]
    fn lower_ir2_to_ir3_call_method_fails_closed_on_underflow() {
        // A `CallMethod` needs `arg_count + 2` stack slots (the args plus the
        // receiver and the callee). An empty stack must fail closed instead of
        // popping defaulted register-0 values for the receiver and callee.
        let mut ir2 = Ir2Module::new(
            ContentHash::compute(b"call-method-underflow"),
            "call_method_underflow.js",
        );
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::CallMethod { arg_count: 0 },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });

        let err = lower_ir2_to_ir3(&ir2).expect_err("missing receiver/callee should fail closed");
        assert_eq!(
            err,
            LoweringPipelineError::InvariantViolation {
                detail: "Value stack underflow in CallMethod",
            }
        );
    }

    #[test]
    fn lower_ir2_to_ir3_emits_begin_try_end_try_instructions() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"begin-try"), "begin_try.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::BeginTry {
                catch_label: 1,
                finally_label: None,
            },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(9),
            },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::EndTry,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Label { id: 1 },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Return,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("IR2->IR3 should emit BeginTry/EndTry instructions")
            .module;

        assert!(matches!(
            ir3.instructions.first(),
            Some(Ir3Instruction::BeginTry { .. })
        ));
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EndTry))
        );
        // Catch label should produce an EnterCatch instruction
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EnterCatch { .. }))
        );
    }

    #[test]
    fn dynamic_hostcall_paths_insert_runtime_ifc_guard() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "dynamic_flow.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("secret_token".to_string()),
        });
        ir1.ops.push(Ir1Op::HostCall {
            capability: "hostcall.invoke".to_string(),
            arg_count: 1,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let call_op = ir2
            .ops
            .iter()
            .find(|op| matches!(op.inner, Ir1Op::HostCall { .. }))
            .expect("hostcall op");
        assert!(
            call_op
                .flow
                .as_ref()
                .expect("flow annotation")
                .declassification_required
        );

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("IR2->IR3 should succeed")
            .module;
        let hostcall_caps: Vec<&str> = ir3
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
                _ => None,
            })
            .collect();
        assert!(hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY));
        assert!(hostcall_caps.contains(&"hostcall.invoke"));

        let guard_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                    if capability.0 == IFC_RUNTIME_GUARD_CAPABILITY
                )
            })
            .expect("guard hostcall");
        let invoke_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                    if capability.0 == "hostcall.invoke"
                )
            })
            .expect("dynamic hostcall");
        assert!(guard_index < invoke_index);
    }

    #[test]
    fn nested_dynamic_hostcall_is_guarded_and_accounted_for_in_ir2() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"nested-flow-ir0"), "nested_flow.js");
        ir1.ops.push(Ir1Op::DeclareFunction {
            name: "nestedFlow".to_string(),
            binding_id: 0,
            param_names: Vec::new(),
            body_ops: vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("secret_token".to_string()),
                },
                Ir1Op::HostCall {
                    capability: "hostcall.invoke".to_string(),
                    arg_count: 1,
                },
                Ir1Op::Pop,
                Ir1Op::Return,
            ],
            free_vars: Vec::new(),
            free_var_ids: Vec::new(),
            free_var_outer_ids: Vec::new(),
            is_generator: false,
            rest_param_index: None,
        });
        ir1.ops.push(Ir1Op::Pop);
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("nested dynamic hostcall should lower to IR2")
            .module;
        assert!(
            ir2.required_capabilities
                .iter()
                .any(|capability| capability.0 == "hostcall.invoke")
        );
        let context = LoweringContext::new("nested-trace", "nested-decision", "nested-policy");
        let proof = build_ir2_flow_proof_artifact(&ir2, &context)
            .expect("nested dynamic flow should produce a proof artifact");
        assert!(proof.runtime_checkpoints.iter().any(|entry| {
            entry.op_index == 0
                && entry.capability.as_deref() == Some("hostcall.invoke")
                && entry.reason == "dynamic_capability"
        }));

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("nested dynamic hostcall should lower to IR3")
            .module;
        let guard_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                        if capability.0 == IFC_RUNTIME_GUARD_CAPABILITY
                )
            })
            .expect("nested dynamic hostcall must have an IFC guard");
        let invoke_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                        if capability.0 == "hostcall.invoke"
                )
            })
            .expect("nested dynamic hostcall must be emitted");
        assert!(guard_index < invoke_index);
    }

    #[test]
    fn nested_declassification_hostcall_uses_inferred_function_flow_for_guard() {
        let mut ir1 = Ir1Module::new(
            ContentHash::compute(b"nested-declass-flow-ir0"),
            "nested_declass_flow.js",
        );
        ir1.ops.push(Ir1Op::DeclareFunction {
            name: "nestedDeclassFlow".to_string(),
            binding_id: 0,
            param_names: Vec::new(),
            body_ops: vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("secret_token".to_string()),
                },
                Ir1Op::HostCall {
                    capability: "declassify.audit".to_string(),
                    arg_count: 1,
                },
                Ir1Op::Pop,
                Ir1Op::Return,
            ],
            free_vars: Vec::new(),
            free_var_ids: Vec::new(),
            free_var_outer_ids: Vec::new(),
            is_generator: false,
            rest_param_index: None,
        });
        ir1.ops.push(Ir1Op::Pop);
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("nested declassification hostcall should lower to IR2")
            .module;
        let context = LoweringContext::new(
            "nested-declass-trace",
            "nested-declass-decision",
            "nested-declass-policy",
        );
        let proof = build_ir2_flow_proof_artifact(&ir2, &context)
            .expect("nested declassification should produce an obligation");
        assert!(proof.required_declassifications.iter().any(|entry| {
            entry.op_index == 0 && entry.capability.as_deref() == Some("declassify.audit")
        }));

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("nested declassification hostcall should lower to IR3")
            .module;
        let guard_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                        if capability.0 == IFC_RUNTIME_GUARD_CAPABILITY
                )
            })
            .expect("nested declassification hostcall must have an IFC guard");
        let declassify_index = ir3
            .instructions
            .iter()
            .position(|instruction| {
                matches!(
                    instruction,
                    Ir3Instruction::HostCall { capability, .. }
                        if capability.0 == "declassify.audit"
                )
            })
            .expect("nested declassification hostcall must be emitted");
        assert!(guard_index < declassify_index);
    }

    #[test]
    fn mismatched_function_capture_metadata_fails_closed() {
        let mut ir2 = Ir2Module::new(
            ContentHash::compute(b"mismatched-capture-metadata"),
            "mismatched_capture.js",
        );
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::CreateFunction {
                name: Some("badCapture".to_string()),
                param_names: Vec::new(),
                body_ops: vec![Ir1Op::Return],
                free_vars: vec!["captured".to_string()],
                free_var_ids: Vec::new(),
                free_var_outer_ids: vec![0],
                is_generator: false,
                is_arrow: false,
                rest_param_index: None,
            },
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });

        let error = lower_ir2_to_ir3(&ir2)
            .expect_err("parallel capture vectors with different lengths must fail closed");
        assert_eq!(
            error,
            LoweringPipelineError::InvariantViolation {
                detail: "Function capture metadata lengths differ",
            }
        );
    }

    #[test]
    fn statically_proven_hostcall_skips_runtime_ifc_guard() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "static_flow.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let hostcall_op = ir2
            .ops
            .iter()
            .find(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
            .expect("hostcall op");
        let flow = hostcall_op.flow.as_ref().expect("flow annotation");
        assert!(!flow.declassification_required);
        assert_eq!(flow.data_label, Label::Public);

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("IR2->IR3 should succeed")
            .module;
        let hostcall_caps: Vec<&str> = ir3
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Ir3Instruction::HostCall { capability, .. } => Some(capability.0.as_str()),
                _ => None,
            })
            .collect();
        assert!(hostcall_caps.contains(&"fs.read"));
        assert!(!hostcall_caps.contains(&IFC_RUNTIME_GUARD_CAPABILITY));
    }

    #[test]
    fn ir2_flow_proof_artifact_records_static_proof() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "static_flow.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let context = LoweringContext::new("trace-static", "decision-static", "policy-static");
        let artifact = build_ir2_flow_proof_artifact(&ir2, &context)
            .expect("static flow artifact should succeed");

        assert!(artifact.denied_flows.is_empty());
        assert!(artifact.required_declassifications.is_empty());
        assert!(artifact.runtime_checkpoints.is_empty());
        assert!(
            artifact
                .proved_flows
                .iter()
                .any(|entry| entry.proof_method == ProofMethod::StaticAnalysis
                    && entry.capability.as_deref() == Some("fs.read"))
        );
        assert!(artifact.artifact_id.starts_with("sha256:"));
    }

    #[test]
    fn ir2_flow_proof_artifact_records_dynamic_runtime_checkpoint() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "dynamic_flow.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("secret_token".to_string()),
        });
        ir1.ops.push(Ir1Op::HostCall {
            capability: "hostcall.invoke".to_string(),
            arg_count: 1,
        });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let context = LoweringContext::new("trace-dyn", "decision-dyn", "policy-dyn");
        let artifact = build_ir2_flow_proof_artifact(&ir2, &context)
            .expect("dynamic flow artifact should succeed");

        assert!(artifact.denied_flows.is_empty());
        assert!(artifact.proved_flows.is_empty());
        assert!(artifact.required_declassifications.is_empty());
        assert_eq!(artifact.runtime_checkpoints.len(), 1);
        assert_eq!(artifact.runtime_checkpoints[0].reason, "dynamic_capability");
        assert_eq!(
            artifact.runtime_checkpoints[0].capability.as_deref(),
            Some("hostcall.invoke")
        );
    }

    #[test]
    fn ir2_flow_proof_artifact_detects_required_declassification() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "declass_fixture.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::HostCall {
                capability: "declassify.audit".to_string(),
                arg_count: 1,
            },
            effect: EffectBoundary::HostcallEffect,
            required_capability: Some(CapabilityTag("declassify.audit".to_string())),
            flow: Some(FlowAnnotation {
                data_label: Label::Secret,
                sink_clearance: Label::Public,
                declassification_required: true,
            }),
        });

        let context = LoweringContext::new("trace-declass", "decision-declass", "policy-declass");
        let artifact = build_ir2_flow_proof_artifact(&ir2, &context)
            .expect("declassification route should be tracked");

        assert!(artifact.denied_flows.is_empty());
        assert!(artifact.proved_flows.is_empty());
        assert_eq!(artifact.required_declassifications.len(), 1);
        assert_eq!(
            artifact.required_declassifications[0].obligation_id,
            "declass-op-0"
        );
        assert_eq!(
            artifact.required_declassifications[0].decision_contract_id,
            "decision-declass"
        );
        assert_eq!(
            artifact.required_declassifications[0]
                .declassification_route_ref
                .as_deref(),
            Some("declassify.audit")
        );
        assert!(artifact.required_declassifications[0].requires_operator_approval);
        assert!(artifact.required_declassifications[0].receipt_linkage_required);
        assert_eq!(
            artifact.required_declassifications[0].replay_command_hint,
            REQUIRED_DECLASSIFICATION_REPLAY_COMMAND_HINT
        );
        assert!(
            !artifact.required_declassifications[0]
                .replay_command_hint
                .contains("--obligation")
        );
    }

    #[test]
    fn ir2_flow_proof_artifact_keeps_distinct_obligation_ids_for_repeated_matching_flows() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "declass_repeat_fixture.js");
        for _ in 0..2 {
            ir2.ops.push(Ir2Op {
                inner: Ir1Op::HostCall {
                    capability: "declassify.audit".to_string(),
                    arg_count: 1,
                },
                effect: EffectBoundary::HostcallEffect,
                required_capability: Some(CapabilityTag("declassify.audit".to_string())),
                flow: Some(FlowAnnotation {
                    data_label: Label::Secret,
                    sink_clearance: Label::Public,
                    declassification_required: true,
                }),
            });
        }

        let context = LoweringContext::new("trace-repeat", "decision-repeat", "policy-repeat");
        let artifact = build_ir2_flow_proof_artifact(&ir2, &context)
            .expect("repeated declassification routes should be tracked independently");

        assert!(artifact.denied_flows.is_empty());
        assert!(artifact.proved_flows.is_empty());
        assert_eq!(artifact.required_declassifications.len(), 2);
        assert_eq!(
            artifact.required_declassifications[0].obligation_id,
            "declass-op-0"
        );
        assert_eq!(
            artifact.required_declassifications[1].obligation_id,
            "declass-op-1"
        );
        assert_eq!(artifact.required_declassifications[0].op_index, 0);
        assert_eq!(artifact.required_declassifications[1].op_index, 1);
    }

    #[test]
    fn ir2_flow_proof_artifact_rejects_unauthorized_static_flow() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "denied_fixture.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::HostCall {
                capability: "fs.write".to_string(),
                arg_count: 1,
            },
            effect: EffectBoundary::HostcallEffect,
            required_capability: Some(CapabilityTag("fs.write".to_string())),
            flow: Some(FlowAnnotation {
                data_label: Label::Secret,
                sink_clearance: Label::Public,
                declassification_required: true,
            }),
        });

        let context = LoweringContext::new("trace-deny", "decision-deny", "policy-deny");
        let err = build_ir2_flow_proof_artifact(&ir2, &context).expect_err("must fail closed");

        match err {
            LoweringPipelineError::UnauthorizedFlow {
                op_index,
                source_label,
                sink_clearance,
                detail,
            } => {
                assert_eq!(op_index, 0);
                assert_eq!(source_label, Label::Secret);
                assert_eq!(sink_clearance, Label::Public);
                assert!(detail.contains("artifact_id=sha256:"));
                assert!(detail.contains("denied_flow_count=1"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn ir2_flow_proof_artifact_is_deterministic() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "deterministic_fixture.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::HostCall {
                capability: "declassify.audit".to_string(),
                arg_count: 1,
            },
            effect: EffectBoundary::HostcallEffect,
            required_capability: Some(CapabilityTag("declassify.audit".to_string())),
            flow: Some(FlowAnnotation {
                data_label: Label::Secret,
                sink_clearance: Label::Public,
                declassification_required: true,
            }),
        });

        let context = LoweringContext::new("trace-det", "decision-det", "policy-det");
        let first = build_ir2_flow_proof_artifact(&ir2, &context).expect("first");
        let second = build_ir2_flow_proof_artifact(&ir2, &context).expect("second");

        assert_eq!(first, second);
        let first_json = serde_json::to_string(&first).unwrap();
        let second_json = serde_json::to_string(&second).unwrap();
        assert_eq!(first_json, second_json);
    }

    #[test]
    fn pipeline_output_includes_flow_proof_artifact() {
        let ir0 = script_ir0();
        let context =
            LoweringContext::new("trace-artifact", "decision-artifact", "policy-artifact");
        let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

        assert_eq!(
            output.ir2_flow_proof_artifact.schema_version,
            IFC_FLOW_PROOF_SCHEMA_VERSION
        );
        assert!(
            output
                .ir2_flow_proof_artifact
                .artifact_id
                .starts_with("sha256:")
        );
    }

    #[test]
    fn pipeline_emits_structured_events_with_governance_fields() {
        let ir0 = script_ir0();
        let context = LoweringContext::new("trace-a", "decision-a", "policy-a");
        let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

        assert_eq!(output.events.len(), 4);
        assert!(output.events.iter().all(|event| {
            !event.trace_id.is_empty()
                && !event.decision_id.is_empty()
                && !event.policy_id.is_empty()
                && !event.component.is_empty()
                && !event.event.is_empty()
                && !event.outcome.is_empty()
        }));
        assert!(
            output
                .events
                .iter()
                .any(|event| event.event == "ir2_flow_check_completed")
        );
        assert_eq!(output.witnesses.len(), 3);
        assert_eq!(output.isomorphism_ledger.len(), 3);
    }

    #[test]
    fn pipeline_is_deterministic_for_identical_input() {
        let ir0 = script_ir0();
        let context = LoweringContext::new("trace-b", "decision-b", "policy-b");
        let first = lower_ir0_to_ir3(&ir0, &context).expect("first run should succeed");
        let second = lower_ir0_to_ir3(&ir0, &context).expect("second run should succeed");

        assert_eq!(first.ir1.content_hash(), second.ir1.content_hash());
        assert_eq!(first.ir2.content_hash(), second.ir2.content_hash());
        assert_eq!(first.ir3.content_hash(), second.ir3.content_hash());
        assert_eq!(first.witnesses, second.witnesses);
        assert_eq!(first.isomorphism_ledger, second.isomorphism_ledger);
    }

    #[test]
    fn empty_ir0_body_fails_deterministically() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: Vec::new(),
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "empty.js");
        let error = lower_ir0_to_ir1(&ir0).expect_err("empty IR0 should fail");
        assert_eq!(error, LoweringPipelineError::EmptyIr0Body);
    }

    // ================================================================
    // Additional coverage tests
    // ================================================================

    // -- LoweringContext --

    #[test]
    fn lowering_context_new() {
        let ctx = LoweringContext::new("trace-1", "decision-1", "policy-1");
        assert_eq!(ctx.trace_id, "trace-1");
        assert_eq!(ctx.decision_id, "decision-1");
        assert_eq!(ctx.policy_id, "policy-1");
    }

    #[test]
    fn lowering_context_serde_roundtrip() {
        let ctx = LoweringContext::new("t", "d", "p");
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: LoweringContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, parsed);
    }

    // -- LoweringEvent serde --

    #[test]
    fn lowering_event_serde_roundtrip() {
        let event = LoweringEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "lowering_pipeline".to_string(),
            event: "test".to_string(),
            outcome: "pass".to_string(),
            error_code: Some("FE-LOWER-0001".to_string()),
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: LoweringEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    // -- InvariantCheck serde --

    #[test]
    fn invariant_check_serde_roundtrip() {
        let check = InvariantCheck {
            name: "test_check".to_string(),
            passed: true,
            detail: "detail".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let parsed: InvariantCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, parsed);
    }

    // -- PassWitness serde --

    #[test]
    fn pass_witness_serde_roundtrip() {
        let witness = PassWitness {
            pass_id: "ir0_to_ir1".to_string(),
            input_hash: "sha256:abc".to_string(),
            output_hash: "sha256:def".to_string(),
            rollback_token: "sha256:abc".to_string(),
            invariant_checks: vec![InvariantCheck {
                name: "check1".to_string(),
                passed: true,
                detail: "ok".to_string(),
            }],
        };
        let json = serde_json::to_string(&witness).unwrap();
        let parsed: PassWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(witness, parsed);
    }

    // -- IsomorphismLedgerEntry serde --

    #[test]
    fn isomorphism_ledger_entry_serde_roundtrip() {
        let entry = IsomorphismLedgerEntry {
            pass_id: "ir1_to_ir2".to_string(),
            input_hash: "sha256:123".to_string(),
            output_hash: "sha256:456".to_string(),
            input_op_count: 10,
            output_op_count: 15,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: IsomorphismLedgerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    // -- FlowInferenceMetrics --

    #[test]
    fn flow_inference_metrics_zero_ops_returns_zero() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 0,
            static_proven_ops: 0,
            runtime_check_ops: 0,
        };
        assert_eq!(metrics.static_coverage_millionths(), 0);
    }

    #[test]
    fn flow_inference_metrics_all_static() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 10,
            static_proven_ops: 10,
            runtime_check_ops: 0,
        };
        assert_eq!(metrics.static_coverage_millionths(), 1_000_000);
    }

    #[test]
    fn flow_inference_metrics_half_static() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 10,
            static_proven_ops: 5,
            runtime_check_ops: 5,
        };
        assert_eq!(metrics.static_coverage_millionths(), 500_000);
    }

    #[test]
    fn flow_inference_metrics_one_of_many_static() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 8,
            static_proven_ops: 1,
            runtime_check_ops: 7,
        };
        assert_eq!(metrics.static_coverage_millionths(), 125_000);
    }

    #[test]
    fn flow_inference_metrics_none_static() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 4,
            static_proven_ops: 0,
            runtime_check_ops: 4,
        };
        assert_eq!(metrics.static_coverage_millionths(), 0);
    }

    // -- extract_hostcall_capability --

    #[test]
    fn extract_hostcall_capability_valid() {
        assert_eq!(
            extract_hostcall_capability("hostcall<\"fs.read\">"),
            Some("fs.read".to_string())
        );
    }

    #[test]
    fn extract_hostcall_capability_embedded() {
        assert_eq!(
            extract_hostcall_capability("something hostcall<\"net.write\"> more"),
            Some("net.write".to_string())
        );
    }

    #[test]
    fn extract_hostcall_capability_accepts_parser_preserved_escape_form() {
        assert_eq!(
            extract_hostcall_capability(r#"hostcall<\"net.write\">"#),
            Some("net.write".to_string())
        );
    }

    #[test]
    fn extract_hostcall_capability_no_marker() {
        assert_eq!(extract_hostcall_capability("plain string"), None);
    }

    #[test]
    fn extract_hostcall_capability_empty_capability() {
        assert_eq!(extract_hostcall_capability("hostcall<\"\">"), None);
    }

    #[test]
    fn extract_hostcall_capability_whitespace_only() {
        assert_eq!(extract_hostcall_capability("hostcall<\"   \">"), None);
    }

    #[test]
    fn extract_hostcall_capability_missing_close() {
        assert_eq!(extract_hostcall_capability("hostcall<\"fs.read"), None);
    }

    // -- sink_clearance_from_capability --

    #[test]
    fn sink_clearance_hostcall_invoke() {
        assert_eq!(
            sink_clearance_from_capability("hostcall.invoke"),
            Label::Internal
        );
    }

    #[test]
    fn sink_clearance_network_capabilities() {
        assert_eq!(sink_clearance_from_capability("net.write"), Label::Public);
        assert_eq!(sink_clearance_from_capability("net_connect"), Label::Public);
        assert_eq!(
            sink_clearance_from_capability("network.send"),
            Label::Public
        );
        assert_eq!(
            sink_clearance_from_capability("process.spawn"),
            Label::Public
        );
        assert_eq!(
            sink_clearance_from_capability("process_exec"),
            Label::Public
        );
        assert_eq!(
            sink_clearance_from_capability("spawn_worker"),
            Label::Public
        );
    }

    #[test]
    fn sink_clearance_credential_capabilities() {
        assert_eq!(
            sink_clearance_from_capability("credential.read"),
            Label::TopSecret
        );
        assert_eq!(
            sink_clearance_from_capability("key_material.derive"),
            Label::TopSecret
        );
    }

    #[test]
    fn sink_clearance_secret_capabilities() {
        assert_eq!(sink_clearance_from_capability("read_secret"), Label::Secret);
        assert_eq!(
            sink_clearance_from_capability("token.validate"),
            Label::Secret
        );
        assert_eq!(
            sink_clearance_from_capability("api_key.fetch"),
            Label::Secret
        );
    }

    #[test]
    fn sink_clearance_fs_capabilities() {
        assert_eq!(sink_clearance_from_capability("fs.read"), Label::Internal);
        assert_eq!(sink_clearance_from_capability("fs.write"), Label::Internal);
    }

    #[test]
    fn sink_clearance_import_capabilities() {
        assert_eq!(
            sink_clearance_from_capability("module.import"),
            Label::Internal
        );
        assert_eq!(
            sink_clearance_from_capability("import.resolve"),
            Label::Internal
        );
    }

    #[test]
    fn sink_clearance_declassify() {
        assert_eq!(
            sink_clearance_from_capability("declassify.check"),
            Label::Public
        );
    }

    #[test]
    fn sink_clearance_unknown_defaults_internal() {
        assert_eq!(sink_clearance_from_capability("custom.op"), Label::Internal);
    }

    // -- classify_ir1_op --

    #[test]
    fn classify_import_module() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::ImportModule {
            specifier: "mod".to_string(),
        });
        assert_eq!(effect, EffectBoundary::ReadEffect);
        assert!(cap.is_some());
        assert_eq!(cap.unwrap().0, "module.import");
        assert!(flow.is_some());
    }

    #[test]
    fn classify_call() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Call { arg_count: 1 });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_await() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Await);
        assert_eq!(effect, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
        assert!(flow.is_some());
    }

    #[test]
    fn classify_load_literal_string_hostcall() {
        let (effect, cap, _flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
        });
        assert_eq!(effect, EffectBoundary::HostcallEffect);
        assert!(cap.is_some());
        assert_eq!(cap.unwrap().0, "fs.read");
    }

    #[test]
    fn classify_load_literal_string_plain() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hello".to_string()),
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_integer() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_boolean() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Boolean(true),
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_null() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Null,
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_literal_undefined() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Undefined,
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_load_binding() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::LoadBinding { binding_id: 0 });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_store_binding() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::StoreBinding { binding_id: 0 });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_export_binding() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::ExportBinding {
            name: "foo".to_string(),
            binding_id: 0,
        });
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_return() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Return);
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_nop() {
        let (effect, cap, flow) = classify_ir1_op(&Ir1Op::Nop);
        assert_eq!(effect, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    // -- push_constant dedup --

    #[test]
    fn push_constant_deduplicates() {
        let mut pool = Vec::new();
        let idx1 = push_constant(&mut pool, "hello");
        let idx2 = push_constant(&mut pool, "world");
        let idx3 = push_constant(&mut pool, "hello");
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // dedup
        assert_eq!(pool.len(), 2);
    }

    // -- lower_literal_to_ir3 --

    #[test]
    fn lower_literal_string_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(
            &Ir1Literal::String("hello".to_string()),
            0,
            &mut instructions,
            &mut pool,
        );
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0
            }
        ));
        assert_eq!(pool, vec!["hello"]);
    }

    #[test]
    fn lower_literal_integer_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Integer(99), 1, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadInt { dst: 1, value: 99 }
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn lower_literal_boolean_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Boolean(true), 2, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadBool {
                dst: 2,
                value: true
            }
        ));
    }

    #[test]
    fn lower_literal_null_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Null, 3, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadNull { dst: 3 }
        ));
    }

    #[test]
    fn lower_literal_undefined_to_ir3() {
        let mut instructions = Vec::new();
        let mut pool = Vec::new();
        lower_literal_to_ir3(&Ir1Literal::Undefined, 4, &mut instructions, &mut pool);
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            Ir3Instruction::LoadUndefined { dst: 4 }
        ));
    }

    // -- flow_requires_runtime_check --

    #[test]
    fn flow_requires_runtime_check_dynamic_capability() {
        let cap = CapabilityTag("hostcall.invoke".to_string());
        assert!(flow_requires_runtime_check(None, &cap));
    }

    #[test]
    fn flow_requires_runtime_check_declassification() {
        let cap = CapabilityTag("fs.read".to_string());
        let annotation = FlowAnnotation {
            data_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_required: true,
        };
        assert!(flow_requires_runtime_check(Some(&annotation), &cap));
    }

    #[test]
    fn flow_requires_runtime_check_custom_label() {
        let cap = CapabilityTag("fs.read".to_string());
        let annotation = FlowAnnotation {
            data_label: Label::Custom {
                name: "my_label".to_string(),
                level: 50,
            },
            sink_clearance: Label::Internal,
            declassification_required: false,
        };
        assert!(flow_requires_runtime_check(Some(&annotation), &cap));
    }

    #[test]
    fn flow_requires_runtime_check_static_safe() {
        let cap = CapabilityTag("fs.read".to_string());
        let annotation = FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Internal,
            declassification_required: false,
        };
        assert!(!flow_requires_runtime_check(Some(&annotation), &cap));
    }

    #[test]
    fn flow_requires_runtime_check_none_flow_static_cap() {
        let cap = CapabilityTag("fs.read".to_string());
        assert!(!flow_requires_runtime_check(None, &cap));
    }

    // -- LoweringPipelineError Display --

    #[test]
    fn lowering_pipeline_error_display_empty_ir0() {
        let err = LoweringPipelineError::EmptyIr0Body;
        assert_eq!(err.to_string(), "IR0 module has no statements");
    }

    #[test]
    fn lowering_pipeline_error_display_ir_contract() {
        let err = LoweringPipelineError::IrContractValidation {
            code: "FE-IR-001".to_string(),
            level: IrLevel::Ir1,
            message: "bad scope".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("FE-IR-001"));
        assert!(display.contains("bad scope"));
    }

    #[test]
    fn lowering_pipeline_error_display_invariant() {
        let err = LoweringPipelineError::InvariantViolation {
            detail: "duplicate binding IDs in IR1 scope graph",
        };
        assert!(err.to_string().contains("duplicate binding IDs"));
    }

    #[test]
    fn lowering_pipeline_error_display_unsupported_syntax() {
        let err = LoweringPipelineError::UnsupportedSyntax(Box::new(
            UnsupportedSyntaxDiagnostic::from_site(
                ParserGapSiteId::ForInStatementPlaceholder,
                "ir0",
                Some(span()),
            ),
        ));
        let display = err.to_string();
        assert!(display.contains("FE-PARSER-GAP-FOR-IN-0001"));
        assert!(display.contains("lower_ir0_to_ir1.for_in_placeholder"));
    }

    // -- Module lowering with imports --

    #[test]
    fn lower_module_with_import() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Import(ImportDeclaration {
                clause: ImportClause::Default {
                    local: "_".to_string(),
                },
                source: "lodash".to_string(),
                binding: Some("_".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "module_import.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_import = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ImportModule { specifier } if specifier == "lodash"));
        assert!(has_import);
        assert_eq!(result.module.scopes[0].kind, ScopeKind::Module);
    }

    #[test]
    fn lower_module_with_default_export() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::VariableDeclaration(VariableDeclaration {
                    kind: VariableDeclarationKind::Const,
                    declarations: vec![VariableDeclarator {
                        pattern: BindingPattern::Identifier("__default_export_0".to_string()),
                        initializer: Some(Expression::NumericLiteral(7)),
                        span: span(),
                    }],
                    span: span(),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(Expression::NumericLiteral(42)),
                    span: span(),
                }),
            ],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "default_export.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_export = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "default"));
        assert!(has_export);
    }

    #[test]
    fn lower_module_with_named_export() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::VariableDeclaration(VariableDeclaration {
                    kind: VariableDeclarationKind::Const,
                    declarations: vec![VariableDeclarator {
                        pattern: BindingPattern::Identifier("foo".to_string()),
                        initializer: Some(Expression::NumericLiteral(1)),
                        span: span(),
                    }],
                    span: span(),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("{ foo as published }".to_string()),
                    span: span(),
                }),
            ],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "named_export.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_export = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "published"));
        assert!(has_export);
    }

    #[test]
    fn lower_module_with_reexport_named_clause() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ foo as bar } from \"./dep.js\"".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "named_reexport.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("re-export should lower");

        let has_import =
            result.module.ops.iter().any(
                |op| matches!(op, Ir1Op::ImportModule { specifier } if specifier == "./dep.js"),
            );
        assert!(has_import);
        let has_export = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "bar"));
        assert!(has_export);
    }

    #[test]
    fn lower_module_with_named_export_unknown_binding() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![Statement::Export(ExportDeclaration {
                kind: ExportKind::NamedClause("{ bar }".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "named_unknown.mjs");
        let err = lower_ir0_to_ir1(&ir0).expect_err("undeclared export should fail");
        assert!(matches!(
            err,
            LoweringPipelineError::SemanticViolation(SemanticError {
                code: SemanticErrorCode::UndeclaredExportBinding,
                ..
            })
        ));
    }

    #[test]
    fn lower_module_with_named_export_before_declaration() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::NamedClause("{ foo }".to_string()),
                    span: span(),
                }),
                Statement::VariableDeclaration(VariableDeclaration {
                    kind: VariableDeclarationKind::Const,
                    declarations: vec![VariableDeclarator {
                        pattern: BindingPattern::Identifier("foo".to_string()),
                        initializer: Some(Expression::NumericLiteral(3)),
                        span: span(),
                    }],
                    span: span(),
                }),
            ],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "named_export_before_decl.mjs");
        let result = lower_ir0_to_ir1(&ir0).expect("forward export should lower");

        let has_export = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::ExportBinding { name, .. } if name == "foo"));
        assert!(has_export);
    }

    #[test]
    fn lower_switch_discriminant_internal_binding_avoids_user_name_collision() {
        let ir0 = stmt_ir0(vec![
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier(
                        "__franken_switch_discriminant_1".to_string(),
                    ),
                    initializer: Some(Expression::NumericLiteral(0)),
                    span: span(),
                }],
                span: span(),
            }),
            Statement::Switch(SwitchStatement {
                discriminant: Expression::Identifier("x".into()),
                cases: vec![SwitchCase {
                    test: Some(Expression::NumericLiteral(1)),
                    consequent: vec![Statement::Break(BreakStatement {
                        label: None,
                        span: span(),
                    })],
                    span: span(),
                }],
                span: span(),
            }),
        ]);
        let result = lower_ir0_to_ir1(&ir0).expect("internal switch temp should stay hidden");
        assert!(
            result
                .module
                .scopes
                .first()
                .expect("root scope")
                .bindings
                .iter()
                .any(|binding| binding.name == "__franken_switch_discriminant_1")
        );
    }

    // -- Module lowering with await --

    #[test]
    fn lower_await_expression() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::Await(Box::new(Expression::Identifier(
                    "promise".to_string(),
                ))),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "await.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_await = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Await));
        assert!(has_await);
    }

    #[test]
    fn lower_var_declaration_without_initializer_loads_undefined() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Var,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("counter".to_string()),
                    initializer: None,
                    span: span(),
                }],
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "var_undefined.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let counter_binding = result.module.scopes[0]
            .bindings
            .iter()
            .find(|binding| binding.name == "counter")
            .expect("counter binding must exist");
        assert_eq!(counter_binding.kind, BindingKind::Var);
        assert!(matches!(
            result.module.ops.as_slice(),
            [
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined
                },
                Ir1Op::StoreBinding { binding_id },
                Ir1Op::Pop,
                Ir1Op::Return
            ] if *binding_id == counter_binding.binding_id
        ));
    }

    #[test]
    fn lower_var_declaration_hoists_bindings_before_initializers() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Var,
                declarations: vec![
                    VariableDeclarator {
                        pattern: BindingPattern::Identifier("y".to_string()),
                        initializer: Some(Expression::Identifier("x".to_string())),
                        span: span(),
                    },
                    VariableDeclarator {
                        pattern: BindingPattern::Identifier("x".to_string()),
                        initializer: Some(Expression::NumericLiteral(1)),
                        span: span(),
                    },
                ],
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "var_hoist.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let scope = &result.module.scopes[0];
        let y_binding = scope
            .bindings
            .iter()
            .find(|binding| binding.name == "y")
            .expect("y binding must exist");
        let x_binding = scope
            .bindings
            .iter()
            .find(|binding| binding.name == "x")
            .expect("x binding must exist");
        assert_eq!(y_binding.kind, BindingKind::Var);
        assert_eq!(x_binding.kind, BindingKind::Var);

        assert!(matches!(
            result.module.ops.as_slice(),
            [
                Ir1Op::LoadBinding {
                    binding_id: load_x_binding_id
                },
                Ir1Op::StoreBinding {
                    binding_id: store_y_binding_id
                },
                Ir1Op::Pop,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(1)
                },
                Ir1Op::StoreBinding {
                    binding_id: store_x_binding_id
                },
                Ir1Op::Pop,
                Ir1Op::Return
            ] if *load_x_binding_id == x_binding.binding_id
                && *store_y_binding_id == y_binding.binding_id
                && *store_x_binding_id == x_binding.binding_id
        ));
    }

    #[test]
    fn lower_let_declaration_uses_let_binding_kind() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("value".to_string()),
                    initializer: Some(Expression::NumericLiteral(7)),
                    span: span(),
                }],
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "let_binding.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let binding = result.module.scopes[0]
            .bindings
            .iter()
            .find(|binding| binding.name == "value")
            .expect("value binding must exist");
        assert_eq!(binding.kind, BindingKind::Let);
    }

    #[test]
    fn lower_const_declaration_uses_const_binding_kind() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Const,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("answer".to_string()),
                    initializer: Some(Expression::NumericLiteral(42)),
                    span: span(),
                }],
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "const_binding.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let binding = result.module.scopes[0]
            .bindings
            .iter()
            .find(|binding| binding.name == "answer")
            .expect("answer binding must exist");
        assert_eq!(binding.kind, BindingKind::Const);
    }

    // -- Raw expression with call --

    #[test]
    fn lower_raw_expression_with_call_pattern() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::Raw("console.log(42)".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "raw_call.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_call = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { .. }));
        assert!(has_call);
    }

    #[test]
    fn lower_raw_expression_without_call_pattern() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::Raw("console".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "raw_no_call.js");
        let result = lower_ir0_to_ir1(&ir0).expect("should succeed");

        let has_call = result
            .module
            .ops
            .iter()
            .any(|op| matches!(op, Ir1Op::Call { .. }));
        assert!(!has_call);
    }

    // -- Full pipeline with imports/exports --

    #[test]
    fn full_pipeline_module_with_import_and_export() {
        let tree = SyntaxTree {
            goal: ParseGoal::Module,
            body: vec![
                Statement::Import(ImportDeclaration {
                    clause: ImportClause::Default {
                        local: "_".to_string(),
                    },
                    source: "lodash".to_string(),
                    binding: Some("_".to_string()),
                    span: span(),
                }),
                Statement::Export(ExportDeclaration {
                    kind: ExportKind::Default(Expression::Identifier("_".to_string())),
                    span: span(),
                }),
            ],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "full_pipeline.mjs");
        let context = LoweringContext::new("trace-fp", "decision-fp", "policy-fp");
        let output = lower_ir0_to_ir3(&ir0, &context).expect("full pipeline should succeed");

        assert_eq!(output.witnesses.len(), 3);
        assert_eq!(output.isomorphism_ledger.len(), 3);
        assert_eq!(output.events.len(), 4);
        assert!(
            output
                .events
                .iter()
                .all(|e| e.outcome == "pass" && e.component == "lowering_pipeline")
        );
        assert!(matches!(
            output.ir3.instructions.last(),
            Some(Ir3Instruction::Halt)
        ));
    }

    // -- Pipeline with string literal --

    #[test]
    fn full_pipeline_string_literal() {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::StringLiteral("hello world".to_string()),
                span: span(),
            })],
            span: span(),
        };
        let ir0 = Ir0Module::from_syntax_tree(tree, "string_lit.js");
        let context = LoweringContext::new("trace-sl", "decision-sl", "policy-sl");
        let output = lower_ir0_to_ir3(&ir0, &context).expect("pipeline should succeed");

        assert!(
            output
                .ir3
                .constant_pool
                .contains(&"hello world".to_string())
        );
    }

    // -- scope_binding_ids_are_unique --

    #[test]
    fn scope_binding_ids_unique_empty() {
        assert!(scope_binding_ids_are_unique(&[]));
    }

    #[test]
    fn scope_binding_ids_unique_single_scope() {
        let scope = ScopeNode {
            scope_id: ScopeId { depth: 0, index: 0 },
            parent: None,
            kind: ScopeKind::Global,
            bindings: vec![
                ResolvedBinding {
                    name: "a".to_string(),
                    binding_id: 0,
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
                ResolvedBinding {
                    name: "b".to_string(),
                    binding_id: 1,
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
            ],
        };
        assert!(scope_binding_ids_are_unique(&[scope]));
    }

    #[test]
    fn scope_binding_ids_duplicate_detected() {
        let scope = ScopeNode {
            scope_id: ScopeId { depth: 0, index: 0 },
            parent: None,
            kind: ScopeKind::Global,
            bindings: vec![
                ResolvedBinding {
                    name: "a".to_string(),
                    binding_id: 0,
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
                ResolvedBinding {
                    name: "b".to_string(),
                    binding_id: 0, // duplicate
                    scope: ScopeId { depth: 0, index: 0 },
                    kind: BindingKind::Let,
                },
            ],
        };
        assert!(!scope_binding_ids_are_unique(&[scope]));
    }

    // -- infer_data_label_for_op --

    #[test]
    fn infer_data_label_secret_patterns() {
        let labels = BTreeMap::new();
        let secret = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("my_secret_key".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(secret, Label::Secret);

        let token = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("AUTH_TOKEN".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(token, Label::Secret);

        let api_key = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("my_api_key_here".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(api_key, Label::Secret);

        let password = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("user_password".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(password, Label::Secret);

        let credential = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("credential_store".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(credential, Label::Secret);
    }

    #[test]
    fn infer_data_label_public_string() {
        let labels = BTreeMap::new();
        let public = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::String("hello world".to_string()),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(public, Label::Public);
    }

    #[test]
    fn infer_data_label_numeric_literal() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(
            &Ir1Op::LoadLiteral {
                value: Ir1Literal::Integer(42),
            },
            &labels,
            Label::Secret,
        );
        assert_eq!(label, Label::Public);
    }

    #[test]
    fn infer_data_label_load_binding_known() {
        let mut labels = BTreeMap::new();
        labels.insert(5u32, Label::Confidential);
        let label = infer_data_label_for_op(
            &Ir1Op::LoadBinding { binding_id: 5 },
            &labels,
            Label::Public,
        );
        assert_eq!(label, Label::Confidential);
    }

    #[test]
    fn infer_data_label_load_binding_unknown() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(
            &Ir1Op::LoadBinding { binding_id: 99 },
            &labels,
            Label::Public,
        );
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_data_label_import_is_internal() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(
            &Ir1Op::ImportModule {
                specifier: "lodash".to_string(),
            },
            &labels,
            Label::Public,
        );
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_data_label_return_uses_last_label() {
        let labels = BTreeMap::new();
        let label = infer_data_label_for_op(&Ir1Op::Return, &labels, Label::Confidential);
        assert_eq!(label, Label::Confidential);
    }

    // -- success_event / failure_event --

    #[test]
    fn success_event_fields() {
        let ctx = LoweringContext::new("t", "d", "p");
        let event = success_event(&ctx, "test_pass");
        assert_eq!(event.trace_id, "t");
        assert_eq!(event.decision_id, "d");
        assert_eq!(event.policy_id, "p");
        assert_eq!(event.component, "lowering_pipeline");
        assert_eq!(event.event, "test_pass");
        assert_eq!(event.outcome, "pass");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn failure_event_fields() {
        let ctx = LoweringContext::new("t", "d", "p");
        let event = failure_event(&ctx, "test_fail", "FE-LOWER-9999");
        assert_eq!(event.outcome, "fail");
        assert_eq!(event.error_code, Some("FE-LOWER-9999".to_string()));
    }

    // -- infer_sink_clearance --

    #[test]
    fn infer_sink_clearance_network_effect() {
        let label = infer_sink_clearance(&EffectBoundary::NetworkEffect, None, &Label::Secret);
        assert_eq!(label, Label::Public);
    }

    #[test]
    fn infer_sink_clearance_fs_effect() {
        let label = infer_sink_clearance(&EffectBoundary::FsEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_read_effect() {
        let label = infer_sink_clearance(&EffectBoundary::ReadEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_write_effect() {
        let label = infer_sink_clearance(&EffectBoundary::WriteEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_hostcall_effect() {
        let label = infer_sink_clearance(&EffectBoundary::HostcallEffect, None, &Label::Secret);
        assert_eq!(label, Label::Internal);
    }

    #[test]
    fn infer_sink_clearance_pure_uses_data_label() {
        let label = infer_sink_clearance(&EffectBoundary::Pure, None, &Label::Secret);
        assert_eq!(label, Label::Secret);
    }

    #[test]
    fn infer_sink_clearance_with_capability_overrides() {
        let cap = CapabilityTag("net.write".to_string());
        let label = infer_sink_clearance(&EffectBoundary::Pure, Some(&cap), &Label::Secret);
        assert_eq!(label, Label::Public);
    }

    // -- alloc_register --

    #[test]
    fn alloc_register_increments() {
        let mut cursor: Reg = 0;
        let r0 = alloc_register(&mut cursor);
        let r1 = alloc_register(&mut cursor);
        let r2 = alloc_register(&mut cursor);
        assert_eq!(r0, 0);
        assert_eq!(r1, 1);
        assert_eq!(r2, 2);
        assert_eq!(cursor, 3);
    }

    // -- hash_string --

    #[test]
    fn hash_string_format() {
        let hash = ContentHash::compute(b"test");
        let s = hash_string(&hash);
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    // -- ensure_checks_pass --

    #[test]
    fn ensure_checks_pass_all_pass() {
        let checks = vec![
            InvariantCheck {
                name: "a".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            InvariantCheck {
                name: "b".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
        ];
        assert!(ensure_checks_pass(&checks, "should not fail").is_ok());
    }

    #[test]
    fn ensure_checks_pass_one_fails() {
        let checks = vec![
            InvariantCheck {
                name: "a".to_string(),
                passed: true,
                detail: "ok".to_string(),
            },
            InvariantCheck {
                name: "b".to_string(),
                passed: false,
                detail: "bad".to_string(),
            },
        ];
        let err = ensure_checks_pass(&checks, "test failure").unwrap_err();
        assert!(matches!(
            err,
            LoweringPipelineError::InvariantViolation {
                detail: "test failure"
            }
        ));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn lowering_pipeline_error_display_distinct() {
        use crate::ifc_artifacts::Label;
        use crate::ir_contract::IrLevel;
        let variants: Vec<LoweringPipelineError> = vec![
            LoweringPipelineError::EmptyIr0Body,
            LoweringPipelineError::IrContractValidation {
                code: "E001".into(),
                level: IrLevel::Ir1,
                message: "msg".into(),
            },
            LoweringPipelineError::InvariantViolation { detail: "bad" },
            LoweringPipelineError::FlowLatticeFailure {
                detail: "fail".into(),
            },
            LoweringPipelineError::UnauthorizedFlow {
                op_index: 0,
                source_label: Label::Public,
                sink_clearance: Label::Public,
                detail: "x".into(),
            },
            LoweringPipelineError::UnsupportedSyntax(Box::new(
                UnsupportedSyntaxDiagnostic::from_site(
                    ParserGapSiteId::TemplateLiteralRawPlaceholder,
                    "ir0",
                    None,
                ),
            )),
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn lowering_pipeline_error_is_std_error() {
        let e = LoweringPipelineError::EmptyIr0Body;
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn ir2_flow_proof_artifact_serde_roundtrip() {
        let artifact = Ir2FlowProofArtifact {
            schema_version: "1.0".into(),
            artifact_id: "art-1".into(),
            trace_id: "t-1".into(),
            decision_id: "d-1".into(),
            policy_id: "p-1".into(),
            module_id: "m-1".into(),
            proved_flows: vec![],
            denied_flows: vec![],
            required_declassifications: vec![],
            runtime_checkpoints: vec![],
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: Ir2FlowProofArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn lowering_pipeline_output_serde_roundtrip() {
        let ctx = LoweringContext::new("t", "d", "p");
        let ir0 = script_ir0();
        let output = lower_ir0_to_ir3(&ir0, &ctx).unwrap();
        let json = serde_json::to_string(&output).unwrap();
        let back: LoweringPipelineOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    #[test]
    fn lowering_pass_result_serde_roundtrip() {
        let result = LoweringPassResult {
            module: "test_module".to_string(),
            witness: PassWitness {
                pass_id: "p1".into(),
                input_hash: "ih".into(),
                output_hash: "oh".into(),
                rollback_token: "rt".into(),
                invariant_checks: vec![InvariantCheck {
                    name: "check1".into(),
                    passed: true,
                    detail: "ok".into(),
                }],
            },
            ledger_entry: IsomorphismLedgerEntry {
                pass_id: "p1".into(),
                input_hash: "ih".into(),
                output_hash: "oh".into(),
                input_op_count: 5,
                output_op_count: 4,
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: LoweringPassResult<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // ================================================================
    // Expression lowering enrichment
    // ================================================================

    fn expr_ir0(expression: Expression) -> Ir0Module {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: vec![Statement::Expression(ExpressionStatement {
                expression,
                span: span(),
            })],
            span: span(),
        };
        Ir0Module::from_syntax_tree(tree, "expr_fixture.js")
    }

    fn stmt_ir0(stmts: Vec<Statement>) -> Ir0Module {
        let tree = SyntaxTree {
            goal: ParseGoal::Script,
            body: stmts,
            span: span(),
        };
        Ir0Module::from_syntax_tree(tree, "stmt_fixture.js")
    }

    fn basic_class_expression(name: Option<&str>) -> Expression {
        Expression::ClassExpression {
            name: name.map(str::to_string),
            super_class: None,
            body: vec![],
        }
    }

    fn complex_class_expression() -> Expression {
        Expression::ClassExpression {
            name: Some("Derived".to_string()),
            super_class: Some(Box::new(Expression::Identifier("Base".to_string()))),
            body: vec![
                MethodDefinition {
                    key: Expression::Identifier("constructor".to_string()),
                    kind: MethodKind::Constructor,
                    params: vec![FunctionParam {
                        pattern: BindingPattern::Identifier("value".to_string()),
                        span: span(),
                    }],
                    body: BlockStatement {
                        body: vec![Statement::Return(ReturnStatement {
                            argument: Some(Expression::Identifier("value".to_string())),
                            span: span(),
                        })],
                        span: span(),
                    },
                    is_static: false,
                    computed: false,
                    span: span(),
                },
                MethodDefinition {
                    key: Expression::Identifier("method".to_string()),
                    kind: MethodKind::Method,
                    params: vec![],
                    body: BlockStatement {
                        body: vec![Statement::Return(ReturnStatement {
                            argument: Some(Expression::NumericLiteral(7)),
                            span: span(),
                        })],
                        span: span(),
                    },
                    is_static: false,
                    computed: false,
                    span: span(),
                },
            ],
        }
    }

    fn assert_class_expression_lowers(expression: Expression) -> Ir1Module {
        let result = lower_ir0_to_ir1(&expr_ir0(expression))
            .expect("class expression should lower to executable constructor IR");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::CreateFunction { .. })),
            "class expression lowering should create a constructor function"
        );
        result.module
    }

    #[test]
    fn lower_binary_expression() {
        let ir0 = expr_ir0(Expression::Binary {
            operator: BinaryOperator::Add,
            left: Box::new(Expression::NumericLiteral(1)),
            right: Box::new(Expression::NumericLiteral(2)),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("binary should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::BinaryOp {
                operator: BinaryOperator::Add
            }
        )));
    }

    #[test]
    fn anonymous_class_expression_lowers() {
        assert_class_expression_lowers(basic_class_expression(None));
    }

    #[test]
    fn named_class_expression_lowers() {
        assert_class_expression_lowers(basic_class_expression(Some("NamedClass")));
    }

    #[test]
    fn named_class_expression_uses_private_constructor_and_method_captures_bd_va13y() {
        let tree = CanonicalEs2020Parser
            .parse(
                "let C = class Inner { \
                     constructor(){ this.ctor = Inner; } \
                     method(){ return Inner; } \
                 };",
                ParseGoal::Script,
            )
            .expect("bd-va13y named class source should parse");
        let module = lower_ir0_to_ir1(&Ir0Module::from_syntax_tree(tree, "bd_va13y_named.js"))
            .expect("bd-va13y named class source should lower")
            .module;
        let capture_names: Vec<&str> = module
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::CreateFunction { free_vars, .. } => Some(free_vars.as_slice()),
                _ => None,
            })
            .flatten()
            .map(String::as_str)
            .collect();

        assert!(
            capture_names
                .iter()
                .any(|name| { name.starts_with(CLASS_EXPRESSION_CONSTRUCTOR_SELF_CAPTURE_PREFIX) })
        );
        assert!(
            capture_names
                .iter()
                .any(|name| name.starts_with(CLASS_EXPRESSION_METHOD_SELF_CAPTURE_PREFIX))
        );
        assert!(!capture_names.contains(&"Inner"));
        assert!(
            module
                .scopes
                .iter()
                .flat_map(|scope| &scope.bindings)
                .all(|binding| binding.name != "Inner"),
            "class self name must not become an enclosing lexical binding"
        );
    }

    #[test]
    fn anonymous_class_unresolved_name_is_not_promoted_to_outer_capture_bd_va13y() {
        let tree = CanonicalEs2020Parser
            .parse(
                "let C = class { method(){ try { anonymous; } catch (error) {} } };",
                ParseGoal::Script,
            )
            .expect("bd-va13y anonymous class source should parse");
        let module = lower_ir0_to_ir1(&Ir0Module::from_syntax_tree(tree, "bd_va13y_anonymous.js"))
            .expect("bd-va13y anonymous class source should lower")
            .module;

        assert!(
            module
                .scopes
                .iter()
                .flat_map(|scope| &scope.bindings)
                .all(|binding| binding.name != "anonymous")
        );
        let functions: Vec<(&[String], &[Ir1Op])> = module
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::CreateFunction {
                    free_vars,
                    body_ops,
                    ..
                } => Some((free_vars.as_slice(), body_ops.as_slice())),
                _ => None,
            })
            .collect();
        assert!(
            functions
                .iter()
                .all(|(free_vars, _)| { !free_vars.iter().any(|name| name == "anonymous") })
        );
        assert!(functions.iter().any(|(_, body_ops)| {
            body_ops.iter().any(|op| {
                matches!(
                    op,
                    Ir1Op::HostCall { capability, .. }
                        if capability == "builtin:ReferenceError"
                )
            })
        }));
    }

    #[test]
    fn class_expression_in_assignment_rhs_lowers() {
        assert_class_expression_lowers(Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(Expression::Identifier("target".to_string())),
            right: Box::new(basic_class_expression(Some("AssignedClass"))),
        });
    }

    #[test]
    fn class_expression_in_call_argument_lowers() {
        assert_class_expression_lowers(Expression::Call {
            callee: Box::new(Expression::Identifier("consume".to_string())),
            arguments: vec![basic_class_expression(None)],
        });
    }

    #[test]
    fn class_expression_with_extends_and_methods_lowers_super_metadata() {
        let module = assert_class_expression_lowers(complex_class_expression());
        assert!(
            module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::SetProperty {
                    key: Ir1PropertyKey::Static(key)
                } if key == IR_SUPER_CONSTRUCTOR_PROPERTY
            )),
            "derived class expression should record parent constructor metadata"
        );
        assert!(
            module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::SetProperty {
                    key: Ir1PropertyKey::Static(key)
                } if key == IR_SUPER_PROTOTYPE_PROPERTY
            )),
            "derived class expression should record parent prototype metadata"
        );
    }

    #[test]
    fn lower_unary_expression() {
        let ir0 = expr_ir0(Expression::Unary {
            operator: UnaryOperator::Typeof,
            argument: Box::new(Expression::Identifier("x".into())),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("unary should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::UnaryOp {
                operator: UnaryOperator::Typeof
            }
        )));
    }

    #[test]
    fn lower_assignment_to_identifier() {
        let ir0 = expr_ir0(Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(Expression::Identifier("x".into())),
            right: Box::new(Expression::NumericLiteral(42)),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("assignment should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::AssignOp { .. }))
        );
    }

    #[test]
    fn lower_assignment_to_member_emits_set_property() {
        let ir0 = expr_ir0(Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(Expression::Member {
                object: Box::new(Expression::Identifier("obj".into())),
                property: Box::new(Expression::Identifier("prop".into())),
                computed: false,
            }),
            right: Box::new(Expression::NumericLiteral(1)),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("member assignment should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::SetProperty {
                key: Ir1PropertyKey::Static(key)
            } if key == "prop"
        )));
    }

    #[test]
    fn lower_conditional_expression() {
        let ir0 = expr_ir0(Expression::Conditional {
            test: Box::new(Expression::BooleanLiteral(true)),
            consequent: Box::new(Expression::NumericLiteral(1)),
            alternate: Box::new(Expression::NumericLiteral(2)),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("conditional should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }))
        );
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Jump { .. }))
        );
        // Four Pops expected:
        // 1. After JumpIfFalsy - pops the test value from the stack
        // 2-3. After storing each branch into the shared result binding
        // 4. From the expression-statement wrapper - pops the result value
        let pop_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::Pop))
            .count();
        assert_eq!(
            pop_count, 4,
            "test-value Pop + branch-store Pops + expression-statement Pop expected"
        );
        let label_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::Label { .. }))
            .count();
        assert_eq!(label_count, 2);
        let lit_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::LoadLiteral { .. }))
            .count();
        assert!(lit_count >= 3); // true, 1, 2
    }

    #[test]
    fn lower_call_expression() {
        let ir0 = expr_ir0(Expression::Call {
            callee: Box::new(Expression::Identifier("fn".into())),
            arguments: vec![
                Expression::NumericLiteral(1),
                Expression::StringLiteral("a".into()),
            ],
        });
        let result = lower_ir0_to_ir1(&ir0).expect("call should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Call { arg_count: 2 }))
        );
    }

    #[test]
    fn lower_member_expression() {
        let ir0 = expr_ir0(Expression::Member {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::Identifier("key".into())),
            computed: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("member should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(key)
            } if key == "key"
        )));
    }

    #[test]
    fn lower_computed_member_expression_uses_dynamic_key() {
        let ir0 = expr_ir0(Expression::Member {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::Identifier("key".into())),
            computed: true,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("computed member should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Dynamic
            }
        )));
    }

    #[test]
    fn lower_optional_member_expression_uses_nullish_short_circuit() {
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::Identifier("key".into())),
            computed: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("optional member should lower");

        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
            "optional member should branch on nullish bases"
        );
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(key)
            } if key == "key"
        )));
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined
            }
        )));
    }

    #[test]
    fn lower_optional_member_base_expression_is_evaluated_once() {
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(Expression::Call {
                callee: Box::new(Expression::Identifier("make_obj".into())),
                arguments: vec![],
            }),
            property: Box::new(Expression::Identifier("value".into())),
            computed: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("optional member should lower");

        let call_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::Call { arg_count: 0 }))
            .count();
        assert_eq!(
            call_count, 1,
            "optional member lowering must evaluate the base expression exactly once"
        );
    }

    #[test]
    fn lower_optional_computed_member_checks_nullish_before_key_evaluation() {
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("obj".into())),
            property: Box::new(Expression::NumericLiteral(7)),
            computed: true,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("computed optional member should lower");

        let jump_index = result
            .module
            .ops
            .iter()
            .position(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
            .expect("optional member should emit JumpIfNullish");
        let key_eval_index = result
            .module
            .ops
            .iter()
            .position(|op| {
                matches!(
                    op,
                    Ir1Op::LoadLiteral {
                        value: Ir1Literal::Integer(7)
                    }
                )
            })
            .expect("computed key should still be lowered");
        let get_property_index = result
            .module
            .ops
            .iter()
            .position(|op| {
                matches!(
                    op,
                    Ir1Op::GetProperty {
                        key: Ir1PropertyKey::Dynamic
                    }
                )
            })
            .expect("computed optional member should use dynamic key access");

        assert!(
            jump_index < key_eval_index,
            "computed key evaluation must happen after the nullish short-circuit guard"
        );
        assert!(
            key_eval_index < get_property_index,
            "computed key must still feed the property read on the non-nullish path"
        );
    }

    #[test]
    fn lower_nested_optional_member_expression_emits_two_nullish_checks() {
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(Expression::OptionalMember {
                object: Box::new(Expression::Identifier("obj".into())),
                property: Box::new(Expression::Identifier("nested".into())),
                computed: false,
            }),
            property: Box::new(Expression::Identifier("value".into())),
            computed: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("nested optional member should lower");

        let jump_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
            .count();
        assert_eq!(
            jump_count, 2,
            "nested optional member should guard each optional segment"
        );
    }

    #[test]
    fn lower_grouped_optional_member_only_guards_the_grouped_segment() {
        let ir0 = expr_ir0(Expression::Member {
            object: Box::new(Expression::OptionalMember {
                object: Box::new(Expression::Identifier("obj".into())),
                property: Box::new(Expression::Identifier("nested".into())),
                computed: false,
            }),
            property: Box::new(Expression::Identifier("value".into())),
            computed: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("grouped optional member should lower");

        let jump_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
            .count();
        assert_eq!(
            jump_count, 1,
            "grouped follow-on member access should not widen the optional short-circuit scope"
        );
        assert_eq!(
            result
                .module
                .ops
                .iter()
                .filter(|op| matches!(op, Ir1Op::GetProperty { .. }))
                .count(),
            2,
            "grouped optional member lowering should preserve both the inner and follow-on property reads"
        );
    }

    #[test]
    fn lower_this_expression() {
        let ir0 = expr_ir0(Expression::This);
        let result = lower_ir0_to_ir1(&ir0).expect("this should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::LoadThis))
        );
    }

    #[test]
    fn lower_array_literal() {
        let ir0 = expr_ir0(Expression::ArrayLiteral(vec![
            Some(Expression::NumericLiteral(1)),
            None,
            Some(Expression::NumericLiteral(3)),
        ]));
        let result = lower_ir0_to_ir1(&ir0).expect("array should lower");
        // Holes are lowered as LoadLiteral { Undefined }, so count
        // reflects total slots including holes.
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::NewArray { count: 3 }))
        );
    }

    #[test]
    fn lower_object_literal() {
        let ir0 = expr_ir0(Expression::ObjectLiteral(vec![ObjectProperty {
            key: Expression::Identifier("a".into()),
            value: Expression::NumericLiteral(1),
            computed: false,
            shorthand: false,
        }]));
        let result = lower_ir0_to_ir1(&ir0).expect("object should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::NewObject { count: 1 }))
        );
    }

    #[test]
    fn lower_arrow_function_expression_body() {
        let ir0 = expr_ir0(Expression::ArrowFunction {
            params: vec![FunctionParam {
                pattern: BindingPattern::Identifier("x".into()),
                span: span(),
            }],
            body: ArrowBody::Expression(Box::new(Expression::Identifier("x".into()))),
            is_async: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("arrow should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Return))
        );
    }

    #[test]
    fn lower_arrow_function_block_body() {
        let ir0 = expr_ir0(Expression::ArrowFunction {
            params: vec![],
            body: ArrowBody::Block(BlockStatement {
                body: vec![Statement::Return(ReturnStatement {
                    argument: Some(Expression::NumericLiteral(99)),
                    span: span(),
                })],
                span: span(),
            }),
            is_async: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("arrow block should lower");
        let function_body = result
            .module
            .ops
            .iter()
            .find_map(|op| match op {
                Ir1Op::CreateFunction { body_ops, .. } => Some(body_ops),
                _ => None,
            })
            .expect("arrow function should lower into CreateFunction");
        assert!(
            function_body.iter().any(|op| matches!(op, Ir1Op::Return)),
            "block-bodied arrow function should retain its body return"
        );
    }

    #[test]
    fn lower_arrow_function_block_reuses_outer_label_counter() {
        let ir0 = stmt_ir0(vec![
            Statement::If(IfStatement {
                condition: Expression::BooleanLiteral(true),
                consequent: Box::new(Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })),
                alternate: None,
                span: span(),
            }),
            Statement::Expression(ExpressionStatement {
                expression: Expression::ArrowFunction {
                    params: vec![],
                    body: ArrowBody::Block(BlockStatement {
                        body: vec![Statement::If(IfStatement {
                            condition: Expression::BooleanLiteral(false),
                            consequent: Box::new(Statement::Return(ReturnStatement {
                                argument: Some(Expression::NumericLiteral(2)),
                                span: span(),
                            })),
                            alternate: None,
                            span: span(),
                        })],
                        span: span(),
                    }),
                    is_async: false,
                },
                span: span(),
            }),
        ]);
        let result = lower_ir0_to_ir1(&ir0).expect("arrow block labels should stay unique");
        let label_ids: Vec<u32> = result
            .module
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::Label { id } => Some(*id),
                _ => None,
            })
            .collect();
        let unique_label_count = label_ids.iter().copied().collect::<BTreeSet<_>>().len();
        assert_eq!(label_ids.len(), unique_label_count);
    }

    #[test]
    fn lower_new_expression_emits_construct() {
        let ir0 = expr_ir0(Expression::New {
            callee: Box::new(Expression::Identifier("Foo".into())),
            arguments: vec![Expression::NumericLiteral(1)],
        });
        let result = lower_ir0_to_ir1(&ir0).expect("new expression should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Construct { .. }))
        );
    }

    #[test]
    fn lower_template_literal_emits_template_op() {
        let ir0 = expr_ir0(Expression::TemplateLiteral {
            quasis: vec!["hello ".into(), " world".into()],
            expressions: vec![Expression::Identifier("name".into())],
        });
        let result = lower_ir0_to_ir1(&ir0).expect("template literal should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::TemplateLiteral { .. }))
        );
    }

    #[test]
    fn lower_computed_member_assignment_uses_dynamic_key_without_nop() {
        let ir0 = expr_ir0(Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(Expression::Member {
                object: Box::new(Expression::Identifier("obj".into())),
                property: Box::new(Expression::Identifier("field".into())),
                computed: true,
            }),
            right: Box::new(Expression::NumericLiteral(7)),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("computed member assignment should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::SetProperty {
                key: Ir1PropertyKey::Dynamic
            }
        )));
        assert!(!result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
    }

    #[test]
    fn lower_non_arithmetic_binary_emits_typed_instruction() {
        let ir0 = expr_ir0(Expression::Binary {
            operator: BinaryOperator::LessThan,
            left: Box::new(Expression::NumericLiteral(1)),
            right: Box::new(Expression::NumericLiteral(2)),
        });
        let ctx = LoweringContext::new("trace-gap", "decision-gap", "policy-gap");
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("comparison currently lowers");
        assert!(output.ir3.instructions.iter().any(|instruction| matches!(
            instruction,
            crate::ir_contract::Ir3Instruction::Lt { .. }
        )));
    }

    // ================================================================
    // Statement lowering enrichment
    // ================================================================

    #[test]
    fn lower_block_statement() {
        let ir0 = stmt_ir0(vec![Statement::Block(BlockStatement {
            body: vec![Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("block should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::LoadLiteral { .. }))
        );
    }

    #[test]
    fn lower_if_statement_with_else() {
        let ir0 = stmt_ir0(vec![Statement::If(IfStatement {
            condition: Expression::BooleanLiteral(true),
            consequent: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            alternate: Some(Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(2),
                span: span(),
            }))),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("if-else should lower");
        let label_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::Label { .. }))
            .count();
        assert_eq!(label_count, 2); // else label + end label
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }))
        );
    }

    #[test]
    fn lower_if_statement_without_else() {
        let ir0 = stmt_ir0(vec![Statement::If(IfStatement {
            condition: Expression::BooleanLiteral(false),
            consequent: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            alternate: None,
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("if-only should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfFalsy { .. }))
        );
    }

    #[test]
    fn lower_for_statement() {
        let ir0 = stmt_ir0(vec![Statement::For(ForStatement {
            init: Some(Box::new(Statement::VariableDeclaration(
                VariableDeclaration {
                    kind: VariableDeclarationKind::Let,
                    declarations: vec![VariableDeclarator {
                        pattern: BindingPattern::Identifier("i".into()),
                        initializer: Some(Expression::NumericLiteral(0)),
                        span: span(),
                    }],
                    span: span(),
                },
            ))),
            condition: Some(Expression::BooleanLiteral(true)),
            update: Some(Expression::NumericLiteral(1)),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(99),
                span: span(),
            })),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("for should lower");
        let jump_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::Jump { .. }))
            .count();
        assert!(jump_count >= 1); // back-edge
    }

    #[test]
    fn lower_for_in_statement_produces_ir1_ops() {
        let ir0 = stmt_ir0(vec![Statement::ForIn(ForInStatement {
            binding: BindingPattern::Identifier("k".into()),
            binding_kind: Some(VariableDeclarationKind::Let),
            object: Expression::Identifier("obj".into()),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::Identifier("k".into()),
                span: span(),
            })),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("for-in lowering should succeed");
        let ops = &result.module.ops;
        // Must contain ForInInit and ForInNext opcodes.
        assert!(
            ops.iter().any(|op| matches!(op, Ir1Op::ForInInit)),
            "missing ForInInit"
        );
        assert!(
            ops.iter().any(|op| matches!(op, Ir1Op::ForInNext { .. })),
            "missing ForInNext"
        );
    }

    #[test]
    fn lower_for_of_statement_produces_ir1_ops() {
        let ir0 = stmt_ir0(vec![Statement::ForOf(ForOfStatement {
            binding: BindingPattern::Identifier("v".into()),
            binding_kind: Some(VariableDeclarationKind::Const),
            iterable: Expression::Identifier("arr".into()),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::Identifier("v".into()),
                span: span(),
            })),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("for-of lowering should succeed");
        let ops = &result.module.ops;
        // Must contain ForOfInit, ForOfNext, and IteratorClose opcodes.
        assert!(
            ops.iter().any(|op| matches!(op, Ir1Op::ForOfInit)),
            "missing ForOfInit"
        );
        assert!(
            ops.iter().any(|op| matches!(op, Ir1Op::ForOfNext { .. })),
            "missing ForOfNext"
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, Ir1Op::IteratorClose { .. })),
            "missing IteratorClose"
        );
    }

    #[test]
    fn lower_while_statement() {
        let ir0 = stmt_ir0(vec![Statement::While(WhileStatement {
            condition: Expression::BooleanLiteral(true),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("while should lower");
        let labels = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::Label { .. }))
            .count();
        assert_eq!(labels, 2); // loop + end
    }

    #[test]
    fn lower_do_while_statement() {
        let ir0 = stmt_ir0(vec![Statement::DoWhile(DoWhileStatement {
            condition: Expression::BooleanLiteral(false),
            body: Box::new(Statement::Continue(ContinueStatement {
                label: None,
                span: span(),
            })),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("do-while should lower");
        let labels: Vec<u32> = result
            .module
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::Label { id } => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(labels.len(), 3); // loop + continue-to-condition + end

        let jumps: Vec<u32> = result
            .module
            .ops
            .iter()
            .filter_map(|op| match op {
                Ir1Op::Jump { label_id } => Some(*label_id),
                _ => None,
            })
            .collect();
        assert!(
            jumps.contains(&labels[1]),
            "continue in do-while must jump to the condition-check label"
        );
        assert!(
            jumps.contains(&labels[0]),
            "do-while must retain a back-edge jump to the loop label"
        );
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::JumpIfFalsy { label_id } if *label_id == labels[2]
        )));
    }

    #[test]
    fn lower_return_with_argument() {
        let ir0 = stmt_ir0(vec![Statement::Return(ReturnStatement {
            argument: Some(Expression::NumericLiteral(42)),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("return should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Return))
        );
    }

    #[test]
    fn lower_return_without_argument() {
        let ir0 = stmt_ir0(vec![Statement::Return(ReturnStatement {
            argument: None,
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("bare return should lower");
        // Should push undefined then return.
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined
            }
        )));
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Return))
        );
    }

    #[test]
    fn lower_throw_statement() {
        let ir0 = stmt_ir0(vec![Statement::Throw(ThrowStatement {
            argument: Expression::StringLiteral("err".into()),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("throw should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Throw))
        );
    }

    #[test]
    fn lower_try_catch_with_param() {
        let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })],
                span: span(),
            },
            handler: Some(CatchClause {
                parameter: Some("e".into()),
                body: BlockStatement {
                    body: vec![Statement::Expression(ExpressionStatement {
                        expression: Expression::Identifier("e".into()),
                        span: span(),
                    })],
                    span: span(),
                },
                span: span(),
            }),
            finalizer: None,
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("try-catch should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::BeginTry { .. }))
        );
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::EndTry))
        );
        let binding = result
            .module
            .scopes
            .first()
            .expect("scope")
            .bindings
            .iter()
            .find(|b| b.name == "e");
        assert!(binding.is_some());
    }

    #[test]
    fn lower_try_catch_with_finalizer() {
        let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })],
                span: span(),
            },
            handler: None,
            finalizer: Some(BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(99),
                    span: span(),
                })],
                span: span(),
            }),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("try-finally should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::BeginTry { .. }))
        );
        // Finally block must have EnterFinally/EndFinally markers
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::EnterFinally)),
            "try/finally must emit EnterFinally IR1 op"
        );
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::EndFinally)),
            "try/finally must emit EndFinally IR1 op"
        );
        // BeginTry must carry a finally_label
        let begin_try = result
            .module
            .ops
            .iter()
            .find(|op| matches!(op, Ir1Op::BeginTry { .. }));
        assert!(
            matches!(
                begin_try,
                Some(Ir1Op::BeginTry {
                    finally_label: Some(_),
                    ..
                })
            ),
            "BeginTry must include finally_label when finalizer is present"
        );
    }

    #[test]
    fn try_finally_emits_ir3_finally_instructions() {
        let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })],
                span: span(),
            },
            handler: None,
            finalizer: Some(BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(99),
                    span: span(),
                })],
                span: span(),
            }),
            span: span(),
        })]);
        let ir1 = lower_ir0_to_ir1(&ir0).expect("try-finally IR0->IR1").module;
        let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
        let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::BeginTry { .. })),
            "IR3 must contain BeginTry"
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EnterFinally)),
            "IR3 must contain EnterFinally"
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EndFinally)),
            "IR3 must contain EndFinally"
        );
        // BeginTry must have a non-None finally_target
        let begin_try = ir3
            .instructions
            .iter()
            .find(|i| matches!(i, Ir3Instruction::BeginTry { .. }));
        assert!(
            matches!(
                begin_try,
                Some(Ir3Instruction::BeginTry {
                    finally_target: Some(_),
                    ..
                })
            ),
            "IR3 BeginTry must have finally_target set when finalizer is present"
        );
    }

    #[test]
    fn try_catch_finally_emits_all_ir3_exception_instructions() {
        let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })],
                span: span(),
            },
            handler: Some(CatchClause {
                parameter: Some("e".into()),
                body: BlockStatement {
                    body: vec![Statement::Expression(ExpressionStatement {
                        expression: Expression::Identifier("e".into()),
                        span: span(),
                    })],
                    span: span(),
                },
                span: span(),
            }),
            finalizer: Some(BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(42),
                    span: span(),
                })],
                span: span(),
            }),
            span: span(),
        })]);
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("try-catch-finally IR0->IR1")
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
        let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
        // All exception IR3 instructions must be present
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::BeginTry { .. }))
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EndTry))
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EnterCatch { .. }))
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EnterFinally))
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EndFinally))
        );
        // BeginTry must have both catch_target and finally_target
        let begin_try = ir3
            .instructions
            .iter()
            .find(|i| matches!(i, Ir3Instruction::BeginTry { .. }));
        if let Some(Ir3Instruction::BeginTry {
            catch_target,
            finally_target,
        }) = begin_try
        {
            assert!(*catch_target > 0, "catch_target must be resolved");
            assert!(
                finally_target.is_some(),
                "finally_target must be set for try/catch/finally"
            );
        } else {
            panic!("BeginTry not found in IR3 output");
        }
    }

    #[test]
    fn nested_try_catch_lowers_to_ir3() {
        // try { try { throw 1; } catch (inner) { } } catch (outer) { }
        let inner_try = Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![Statement::Throw(ThrowStatement {
                    argument: Expression::NumericLiteral(1),
                    span: span(),
                })],
                span: span(),
            },
            handler: Some(CatchClause {
                parameter: Some("inner".into()),
                body: BlockStatement {
                    body: vec![],
                    span: span(),
                },
                span: span(),
            }),
            finalizer: None,
            span: span(),
        });
        let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![inner_try],
                span: span(),
            },
            handler: Some(CatchClause {
                parameter: Some("outer".into()),
                body: BlockStatement {
                    body: vec![],
                    span: span(),
                },
                span: span(),
            }),
            finalizer: None,
            span: span(),
        })]);
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("nested try-catch IR0->IR1")
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
        let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
        // Must have two BeginTry instructions for nested try blocks
        let begin_try_count = ir3
            .instructions
            .iter()
            .filter(|i| matches!(i, Ir3Instruction::BeginTry { .. }))
            .count();
        assert_eq!(begin_try_count, 2, "nested try must produce 2 BeginTry");
        // Must have a Throw instruction
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::Throw { .. }))
        );
    }

    #[test]
    fn throw_statement_emits_ir3_throw() {
        let ir0 = stmt_ir0(vec![Statement::Throw(ThrowStatement {
            argument: Expression::StringLiteral("err".into()),
            span: span(),
        })]);
        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("throw should lower to IR1")
            .module;
        let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
        let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::Throw { .. }))
        );
    }

    #[test]
    fn try_catch_emits_ir3_exception_instructions() {
        let ir0 = stmt_ir0(vec![Statement::TryCatch(TryCatchStatement {
            block: BlockStatement {
                body: vec![Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })],
                span: span(),
            },
            handler: Some(CatchClause {
                parameter: Some("e".into()),
                body: BlockStatement {
                    body: vec![Statement::Expression(ExpressionStatement {
                        expression: Expression::Identifier("e".into()),
                        span: span(),
                    })],
                    span: span(),
                },
                span: span(),
            }),
            finalizer: None,
            span: span(),
        })]);
        let ir1 = lower_ir0_to_ir1(&ir0).expect("try-catch IR0->IR1").module;
        let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
        let ir3 = lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module;
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::BeginTry { .. }))
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EndTry))
        );
        assert!(
            ir3.instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::EnterCatch { .. }))
        );
    }

    #[test]
    fn lower_switch_statement() {
        let ir0 = stmt_ir0(vec![Statement::Switch(SwitchStatement {
            discriminant: Expression::Identifier("x".into()),
            cases: vec![
                SwitchCase {
                    test: Some(Expression::NumericLiteral(1)),
                    consequent: vec![Statement::Expression(ExpressionStatement {
                        expression: Expression::StringLiteral("one".into()),
                        span: span(),
                    })],
                    span: span(),
                },
                SwitchCase {
                    test: None,
                    consequent: vec![Statement::Expression(ExpressionStatement {
                        expression: Expression::StringLiteral("default".into()),
                        span: span(),
                    })],
                    span: span(),
                },
            ],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("switch should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::BinaryOp {
                operator: BinaryOperator::StrictEqual
            }
        )));
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::LoadBinding { .. }))
        );
    }

    #[test]
    fn lower_break_outside_control_flow_is_error() {
        let ir0 = stmt_ir0(vec![Statement::Break(BreakStatement {
            label: None,
            span: span(),
        })]);
        let err = lower_ir0_to_ir1(&ir0).expect_err("top-level break should fail");
        assert!(matches!(
            err,
            LoweringPipelineError::SemanticViolation(SemanticError {
                code: SemanticErrorCode::IllegalBreak,
                ..
            })
        ));
    }

    #[test]
    fn lower_continue_outside_loop_is_error() {
        let ir0 = stmt_ir0(vec![Statement::Continue(ContinueStatement {
            label: None,
            span: span(),
        })]);
        let err = lower_ir0_to_ir1(&ir0).expect_err("top-level continue should fail");
        assert!(matches!(
            err,
            LoweringPipelineError::SemanticViolation(SemanticError {
                code: SemanticErrorCode::IllegalContinue,
                ..
            })
        ));
    }

    #[test]
    fn lower_break_inside_switch_emits_jump() {
        let ir0 = stmt_ir0(vec![Statement::Switch(SwitchStatement {
            discriminant: Expression::Identifier("x".into()),
            cases: vec![SwitchCase {
                test: Some(Expression::NumericLiteral(1)),
                consequent: vec![Statement::Break(BreakStatement {
                    label: None,
                    span: span(),
                })],
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("break in switch should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Jump { .. }))
        );
        assert!(!result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
    }

    #[test]
    fn lower_continue_inside_for_emits_jump() {
        let ir0 = stmt_ir0(vec![Statement::For(ForStatement {
            init: None,
            condition: Some(Expression::BooleanLiteral(true)),
            update: Some(Expression::NumericLiteral(1)),
            body: Box::new(Statement::Continue(ContinueStatement {
                label: None,
                span: span(),
            })),
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("continue in for should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Jump { .. }))
        );
        assert!(!result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
    }

    #[test]
    fn lower_block_destructuring_allocates_all_bindings() {
        let ir0 = stmt_ir0(vec![Statement::Block(BlockStatement {
            body: vec![Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::ObjectPattern(vec![
                        ObjectPatternProperty {
                            key: Expression::Identifier("a".into()),
                            value: BindingPattern::Identifier("a".into()),
                            computed: false,
                            shorthand: true,
                        },
                        ObjectPatternProperty {
                            key: Expression::Identifier("b".into()),
                            value: BindingPattern::Identifier("renamed".into()),
                            computed: false,
                            shorthand: false,
                        },
                    ]),
                    initializer: Some(Expression::Identifier("source".into())),
                    span: span(),
                }],
                span: span(),
            })],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("destructuring block should lower");
        let scope = result.module.scopes.first().expect("root scope");
        assert!(scope.bindings.iter().any(|binding| binding.name == "a"));
        assert!(
            scope
                .bindings
                .iter()
                .any(|binding| binding.name == "renamed")
        );
    }

    #[test]
    fn lower_function_declaration() {
        let ir0 = stmt_ir0(vec![Statement::FunctionDeclaration(FunctionDeclaration {
            name: Some("myFunc".into()),
            params: vec![FunctionParam {
                pattern: BindingPattern::Identifier("a".into()),
                span: span(),
            }],
            body: BlockStatement {
                body: vec![],
                span: span(),
            },
            is_async: false,
            is_generator: false,
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("function should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::DeclareFunction { name, .. } if name == "myFunc"
        )));
    }

    #[test]
    fn rest_parameter_metadata_reaches_ir3_for_function_shapes_bd_ur3tk_9() {
        let ir3 = lower_rest_source_to_ir3(
            "let arrow = (head, ...arrowTail) => arrowTail.length;\
             function outer(head, ...outerTail) {\
               function inner(head, ...innerTail) { return innerTail.length; }\
               return inner(head);\
             }\
             class Bucket {\
               constructor(head, ...ctorTail) {}\
               collect(head, ...methodTail) { return methodTail.length; }\
             }",
        )
        .expect("supported identifier rest parameters should lower");

        for name in ["outer", "inner", "Bucket", "collect"] {
            let desc = ir3
                .function_table
                .iter()
                .find(|desc| desc.name.as_deref() == Some(name))
                .unwrap_or_else(|| panic!("missing IR3 descriptor for {name}"));
            assert_eq!(desc.arity, 2, "{name} positional arity");
            assert_eq!(desc.rest_param_index, Some(1), "{name} rest slot");
        }

        let arrow = ir3
            .function_table
            .iter()
            .find(|desc| desc.name.is_none())
            .expect("anonymous arrow descriptor");
        assert_eq!(arrow.arity, 2);
        assert_eq!(arrow.rest_param_index, Some(1));
        let main = ir3
            .function_table
            .iter()
            .find(|desc| desc.name.as_deref() == Some("main"))
            .expect("main descriptor");
        assert_eq!(main.rest_param_index, None);
    }

    #[test]
    fn patterned_formals_keep_positional_slots_for_every_function_shape_bd_ur3tk_10() {
        let ir3 = lower_rest_source_to_ir3(
            "function mixed({ value }, ...tail) { return value; }\
             function outer([head], ...outerTail) {\
               function inner({ nested }, ...innerTail) { return nested; }\
               return inner({ nested: head });\
             }\
             let arrow = ({ left }, ...arrowTail) => left;\
             let expressed = function expressed({ right }, ...expressionTail) { return right; };\
             class Bucket {\
               constructor({ item }, ...ctorTail) {}\
               collect([entry], ...methodTail) { return entry; }\
             }\
             let Crate = class Crate {\
               constructor([item], ...exprCtorTail) {}\
               collectExpr({ entry }, ...exprMethodTail) { return entry; }\
             };",
        )
        .expect("patterned prefixes must retain their positional slots before rest");

        for name in [
            "mixed",
            "outer",
            "inner",
            "expressed",
            "Bucket",
            "collect",
            "Crate",
            "collectExpr",
        ] {
            let desc = ir3
                .function_table
                .iter()
                .find(|desc| desc.name.as_deref() == Some(name))
                .unwrap_or_else(|| panic!("missing IR3 descriptor for {name}"));
            assert_eq!(desc.arity, 2, "{name} must retain both formal slots");
            assert_eq!(desc.rest_param_index, Some(1), "{name} rest slot");
        }

        let arrow = ir3
            .function_table
            .iter()
            .find(|desc| desc.name.is_none())
            .expect("anonymous patterned arrow descriptor");
        assert_eq!(arrow.arity, 2);
        assert_eq!(arrow.rest_param_index, Some(1));
    }

    #[test]
    fn patterned_default_and_rest_formals_execute_bd_ur3tk_10() {
        let (ir1, module, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function mixed({ value }, scale = 4, ...tail) {\
                 return value * 10 + scale + tail.length;\
             }\
             mixed({ value: 3 }, undefined, 1, 2);",
        );
        let Ir1Op::DeclareFunction {
            param_names,
            rest_param_index,
            ..
        } = ir1
            .ops
            .iter()
            .find(|op| matches!(op, Ir1Op::DeclareFunction { name, .. } if name == "mixed"))
            .expect("mixed declaration")
        else {
            unreachable!("filtered declaration shape")
        };
        assert_eq!(param_names.len(), 3);
        assert!(param_names[0].starts_with("@@franken_internal_param_"));
        assert!(param_names[1].starts_with("@@franken_internal_param_"));
        assert_eq!(param_names[2], "tail");
        assert_eq!(*rest_param_index, Some(2));
        assert!(
            deferred_ir1_body_bd_6pvhn(&ir1, "mixed")
                .iter()
                .any(|op| matches!(op, Ir1Op::GetProperty { .. })),
            "the object and default parameters must run their entry prologue"
        );
        assert!(
            deferred_ir3_body_bd_6pvhn(&module, "mixed")
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::GetProperty { .. }))
        );
        assert_eq!(value, Value::Int(36));
    }

    #[test]
    fn whole_pattern_defaults_execute_bd_laab3() {
        let source_prefix = "function objectDefault({ a = 5 } = {}) { return a; }\
             let arrayDefault = ([a = 7] = []) => a;";

        let (_, _, supplied) = lower_and_execute_deferred_source_bd_6pvhn(&format!(
            "{source_prefix} objectDefault({{ a: 2 }}) + arrayDefault([3]);"
        ));
        assert_eq!(supplied, Value::Int(5));

        let (_, _, explicit_undefined) = lower_and_execute_deferred_source_bd_6pvhn(&format!(
            "{source_prefix} objectDefault(undefined) + arrayDefault(undefined);"
        ));
        assert_eq!(explicit_undefined, Value::Int(12));

        let (_, _, omitted) = lower_and_execute_deferred_source_bd_6pvhn(&format!(
            "{source_prefix} objectDefault() + arrayDefault();"
        ));
        assert_eq!(omitted, Value::Int(12));

        let (_, _, empty_containers) = lower_and_execute_deferred_source_bd_6pvhn(&format!(
            "{source_prefix} objectDefault({{}}) + arrayDefault([]);"
        ));
        assert_eq!(empty_containers, Value::Int(12));
    }

    #[test]
    fn patterned_prologues_execute_for_expression_and_class_shapes_bd_ur3tk_10() {
        let (_, _, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "let expressed = function expressed({ value }, add = 1, ...tail) {\
                 return value + add + tail.length;\
             };\
             class Declared {\
                 constructor({ value }, add = 1, ...tail) {\
                     this.total = value + add + tail.length;\
                 }\
                 collect([value], add = 1, ...tail) {\
                     return value + add + tail.length;\
                 }\
             }\
             let Expressed = class Expressed {\
                 constructor([value], add = 1, ...tail) {\
                     this.total = value + add + tail.length;\
                 }\
                 collect({ value }, add = 1, ...tail) {\
                     return value + add + tail.length;\
                 }\
             };\
             let declared = new Declared({ value: 2 }, undefined, 0);\
             let classExpression = new Expressed([4], undefined, 0);\
             expressed({ value: 1 }, undefined, 0)\
                 + declared.total\
                 + declared.collect([3], undefined, 0)\
                 + classExpression.total\
                 + classExpression.collect({ value: 5 }, undefined, 0);",
        );
        assert_eq!(value, Value::Int(25));
    }

    #[test]
    fn nested_and_empty_pattern_formals_execute_bd_ur3tk_10() {
        let (_, _, nested) = lower_and_execute_deferred_source_bd_6pvhn(
            "let combine = ([head, [nested]], scale = 2, ...tail) =>\
                 head + nested * scale + tail.length;\
             combine([1, [3]], undefined, 8, 9);",
        );
        assert_eq!(nested, Value::Int(9));

        let (_, _, empty_rest) = lower_and_execute_deferred_source_bd_6pvhn(
            "function count({}, ...tail) { return tail.length; } count({});",
        );
        assert_eq!(empty_rest, Value::Int(0));

        let (_, _, canonical_numeric_key) = lower_and_execute_deferred_source_bd_6pvhn(
            "function read({ 1: value }, ...tail) { return value + tail.length; }\
             read({ 1: 3 });",
        );
        assert_eq!(canonical_numeric_key, Value::Int(3));

        let (_, _, canonical_decimal_keys) = lower_and_execute_deferred_source_bd_6pvhn(
            "function decimal({ 1.5: value }, ...tail) { return value; }\
             function wide({ 9007199254740992: value }, ...tail) { return value; }\
             decimal({ '1.5': 3 }) + wide({ '9007199254740992': 4 });",
        );
        assert_eq!(canonical_decimal_keys, Value::Int(7));
    }

    #[test]
    fn captureless_default_closure_executes_bd_ur3tk_10() {
        let (_, _, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "let Math = 11;\
             function invoke(callback = () => 4, ...tail) {\
                 return callback() + tail.length;\
             }\
             invoke(undefined, 9);",
        );
        assert_eq!(value, Value::Int(5));

        let (_, _, ordinary_function_this) = lower_and_execute_deferred_source_bd_6pvhn(
            "function invoke(callback = function () { return this; }, ...tail) {\
                 return tail.length;\
             }\
             invoke(undefined, 9);",
        );
        assert_eq!(ordinary_function_this, Value::Int(1));

        let (_, _, arrow_with_ordinary_child) = lower_and_execute_deferred_source_bd_6pvhn(
            "function invoke(callback = () => function () { return this; }, ...tail) {\
                 return tail.length;\
             }\
             invoke(undefined, 9);",
        );
        assert_eq!(arrow_with_ordinary_child, Value::Int(1));
    }

    #[test]
    fn unused_static_spelled_self_name_is_not_a_capture_bd_ur3tk_10() {
        let (_, _, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function Math(callback = () => 4, { value }, ...tail) {\
                 return callback() + value + tail.length;\
             }\
             Math(undefined, { value: 3 });",
        );
        assert_eq!(value, Value::Int(7));
    }

    #[test]
    fn synthetic_parameter_slots_cannot_collide_with_source_names_bd_ur3tk_10() {
        let (_, _, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function add(__param_1, { value }) { return __param_1 + value; }\
             add(2, { value: 3 });",
        );
        assert_eq!(value, Value::Int(5));
    }

    #[test]
    fn default_parameter_environment_survives_body_shadowing_bd_ur3tk_10() {
        let (_, _, ordinary) = lower_and_execute_deferred_source_bd_6pvhn(
            "let fallback = 7;\
             function read(value = fallback) {\
                 let fallback = 99;\
                 return value;\
             }\
             read();",
        );
        assert_eq!(ordinary, Value::Int(7));

        let (_, _, static_name) = lower_and_execute_deferred_source_bd_6pvhn(
            "let Math = 11;\
             function readStatic(value = Math) {\
                 let Math = 88;\
                 return value;\
             }\
             readStatic();",
        );
        assert_eq!(static_name, Value::Int(11));

        let (_, _, nested_var) = lower_and_execute_deferred_source_bd_6pvhn(
            "let fallback = 5;\
             function readNested(value = fallback) {\
                 if (true) { var fallback = 77; }\
                 return value;\
             }\
             readNested();",
        );
        assert_eq!(nested_var, Value::Int(5));
    }

    #[test]
    fn object_rest_parameter_patterns_fail_closed_bd_ur3tk_10() {
        let error = lower_rest_source_to_ir3(
            "function unsupported({ kept, ...rest }, ...tail) { return rest; }",
        )
        .expect_err("object rest must not silently lower as an ordinary property");
        let LoweringPipelineError::UnsupportedSyntax(diagnostic) = error else {
            panic!("expected fail-closed object-rest parameter diagnostic");
        };
        assert_eq!(
            diagnostic.diagnostic_code,
            "FE-LOWER-UNSUPPORTED-OBJECT-REST-PARAM-0001"
        );
        assert_eq!(diagnostic.site_id, "core.function_parameter_object_rest");
    }

    #[test]
    fn nested_rest_parameter_targets_fail_closed_bd_ur3tk_10() {
        let error = lower_rest_source_to_ir3(
            "function unsupported([...[value]], ...tail) { return value; }",
        )
        .expect_err("nested rest targets must not receive the unsplit remainder array");
        let LoweringPipelineError::UnsupportedSyntax(diagnostic) = error else {
            panic!("expected fail-closed nested-rest parameter diagnostic");
        };
        assert_eq!(
            diagnostic.diagnostic_code,
            "FE-LOWER-UNSUPPORTED-NESTED-REST-PARAM-0001"
        );
        assert_eq!(diagnostic.site_id, "core.function_parameter_nested_rest");
    }

    #[test]
    fn computed_parameter_pattern_keys_fail_closed_bd_ur3tk_10() {
        let error = lower_rest_source_to_ir3(
            "function unsupported({ ['value']: picked }, ...tail) { return picked; }",
        )
        .expect_err("computed keys must not silently fall back to the target binding name");
        let LoweringPipelineError::UnsupportedSyntax(diagnostic) = error else {
            panic!("expected fail-closed computed-key parameter diagnostic");
        };
        assert_eq!(
            diagnostic.diagnostic_code,
            "FE-LOWER-UNSUPPORTED-COMPUTED-PARAM-KEY-0001"
        );
        assert_eq!(diagnostic.site_id, "core.function_parameter_computed_key");
    }

    #[test]
    fn static_object_binding_keys_execute_with_canonical_property_names_bd_h4esx() {
        for (binding_key, canonical_key) in [
            (r#""value""#, "value"),
            (r"'v\x61lue'", "value"),
            (r"'v\u0061lue'", "value"),
            (r"'\uD83D\uDE00'", "😀"),
            (r"'\u{1F600}'", "😀"),
            ("'a\\\nb'", "ab"),
            ("'a\\\r\nb'", "ab"),
            ("'a\\\rb'", "ab"),
            ("'a\\\u{2028}b'", "ab"),
            ("'a\\\u{2029}b'", "ab"),
            (r"\u0076alue", "value"),
            ("π", "π"),
            (r"\u03C0", "π"),
            (r"\u037A", "ͺ"),
            (r"a\u037A", "aͺ"),
            ("0x10", "16"),
            ("0b10", "2"),
            ("0o10", "8"),
            ("1_000", "1000"),
            ("1e3", "1000"),
            ("1.5", "1.5"),
            (".5", "0.5"),
            ("1e-6", "0.000001"),
            ("1e-7", "1e-7"),
            ("1e20", "100000000000000000000"),
            ("1e21", "1e+21"),
            ("667082108456853.2", "667082108456853.2"),
            ("9007199254740993", "9007199254740992"),
            ("18446744073709551615", "18446744073709552000"),
            ("0x10n", "16"),
            ("1_000n", "1000"),
            (
                "123456789012345678901234567890n",
                "123456789012345678901234567890",
            ),
        ] {
            let source = format!(
                "function pick({{{binding_key}: parameter}}) {{ return parameter; }}\
                 let {{{binding_key}: variable}} = {{'{canonical_key}': 7}};\
                 pick({{'{canonical_key}': 5}}) * 10 + variable;"
            );
            let (_, _, value) = lower_and_execute_deferred_source_bd_6pvhn(&source);
            assert_eq!(
                value,
                Value::Int(57),
                "binding key `{binding_key}` must resolve canonical property `{canonical_key}`"
            );
        }
    }

    #[test]
    fn parameter_default_closures_fail_closed_without_live_cells_bd_ur3tk_10() {
        for source in [
            "function captured(callback = () => later, later = 3) { return callback(); }",
            "function lexical(callback = () => this) { return callback(); }",
            "function nestedLexical(callback = () => () => this) { return callback(); }",
        ] {
            let error = lower_rest_source_to_ir3(source).expect_err(
                "capturing defaults must not snapshot parameters or lexical call context",
            );
            let LoweringPipelineError::UnsupportedSyntax(diagnostic) = error else {
                panic!("expected fail-closed parameter-default closure diagnostic");
            };
            assert_eq!(
                diagnostic.diagnostic_code,
                "FE-LOWER-UNSUPPORTED-PARAM-DEFAULT-CLOSURE-0001"
            );
            assert_eq!(
                diagnostic.site_id,
                "core.function_parameter_default_closure"
            );
        }
    }

    #[test]
    fn self_referential_parameter_defaults_fail_closed_bd_ur3tk_10() {
        for source in [
            "let wrapped = function self(value = self) { return value === self; };",
            "let Wrapped = class Self { method(value = Self) { return value === Self; } };",
        ] {
            let error = lower_rest_source_to_ir3(source)
                .expect_err("self capture must not snapshot an uninitialized closure");
            let LoweringPipelineError::UnsupportedSyntax(diagnostic) = error else {
                panic!("expected fail-closed self-parameter diagnostic");
            };
            assert_eq!(
                diagnostic.diagnostic_code,
                "FE-LOWER-UNSUPPORTED-SELF-PARAM-DEFAULT-0001"
            );
            assert_eq!(
                diagnostic.site_id,
                "core.self_referential_parameter_default"
            );
        }
    }

    #[test]
    fn generator_rest_fails_closed_until_arguments_are_persisted_bd_ur3tk_9() {
        let error = lower_rest_source_to_ir3("function* generated(...tail) { yield tail; }")
            .expect_err("generator creation currently discards invocation arguments");
        let LoweringPipelineError::UnsupportedSyntax(diagnostic) = error else {
            panic!("expected fail-closed generator-rest diagnostic");
        };
        assert_eq!(
            diagnostic.diagnostic_code,
            "FE-LOWER-UNSUPPORTED-GENERATOR-REST-0001"
        );
        assert_eq!(diagnostic.site_id, "core.generator_rest_parameter_runtime");
    }

    #[test]
    fn malformed_ir1_rest_metadata_fails_ir3_lowering_bd_ur3tk_9() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"malformed-rest-ir0"), "rest_ir1.js");
        ir1.ops.push(Ir1Op::DeclareFunction {
            name: "malformedRest".to_string(),
            binding_id: 0,
            param_names: vec!["head".to_string(), "tail".to_string()],
            body_ops: vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined,
                },
                Ir1Op::Return,
            ],
            free_vars: Vec::new(),
            free_var_ids: Vec::new(),
            free_var_outer_ids: Vec::new(),
            is_generator: false,
            rest_param_index: Some(0),
        });
        ir1.ops.push(Ir1Op::Pop);
        ir1.ops.push(Ir1Op::Return);
        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should preserve hand-built metadata for validation")
            .module;

        assert_eq!(
            lower_ir2_to_ir3(&ir2).expect_err("non-final rest metadata must fail closed"),
            LoweringPipelineError::InvariantViolation {
                detail: "Function rest metadata must identify the final positional parameter",
            }
        );
    }

    #[test]
    fn rest_only_function_and_class_expressions_reach_ir3_bd_ur3tk_9() {
        let ir3 = lower_rest_source_to_ir3(
            "let expressed = function expressed(...expressionTail) { return expressionTail; };\
             let BucketExpression = class BucketExpression {\
               constructor(...ctorTail) {}\
               collectExpression(...methodTail) { return methodTail; }\
             };",
        )
        .expect("rest-only expression forms should lower");

        for name in ["expressed", "BucketExpression", "collectExpression"] {
            let desc = ir3
                .function_table
                .iter()
                .find(|desc| desc.name.as_deref() == Some(name))
                .unwrap_or_else(|| panic!("missing IR3 descriptor for {name}"));
            assert_eq!(desc.arity, 1, "{name} positional arity");
            assert_eq!(desc.rest_param_index, Some(0), "{name} rest slot");
        }
    }

    #[test]
    fn lower_anonymous_function_declaration() {
        let ir0 = stmt_ir0(vec![Statement::FunctionDeclaration(FunctionDeclaration {
            name: None,
            params: vec![],
            body: BlockStatement {
                body: vec![],
                span: span(),
            },
            is_async: false,
            is_generator: false,
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("anon function should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::DeclareFunction { name, .. } if name == "anonymous"
        )));
    }

    #[test]
    fn function_declaration_with_body_emits_create_closure() {
        let ir0 = stmt_ir0(vec![Statement::FunctionDeclaration(FunctionDeclaration {
            name: Some("answer".into()),
            params: vec![FunctionParam {
                pattern: BindingPattern::Identifier("x".into()),
                span: span(),
            }],
            body: BlockStatement {
                body: vec![Statement::Return(ReturnStatement {
                    argument: Some(Expression::Identifier("x".into())),
                    span: span(),
                })],
                span: span(),
            },
            is_async: false,
            is_generator: false,
            span: span(),
        })]);

        let ir1 = lower_ir0_to_ir1(&ir0)
            .expect("function declaration should lower to IR1")
            .module;
        let (param_names, body_ops, free_vars, is_generator) = ir1
            .ops
            .iter()
            .find_map(|op| match op {
                Ir1Op::DeclareFunction {
                    name,
                    param_names,
                    body_ops,
                    free_vars,
                    is_generator,
                    ..
                } if name == "answer" => Some((param_names, body_ops, free_vars, is_generator)),
                _ => None,
            })
            .expect("IR1 should retain the lowered function body");
        assert_eq!(param_names, &vec!["x".to_string()]);
        assert!(
            body_ops
                .iter()
                .any(|op| matches!(op, Ir1Op::LoadBinding { .. })),
            "function body should load its parameter"
        );
        assert!(
            body_ops.iter().any(|op| matches!(op, Ir1Op::Return)),
            "function body should retain an explicit return"
        );
        assert!(free_vars.is_empty());
        assert!(!*is_generator);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("function declaration should lower to IR2")
            .module;
        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("function declaration should lower to IR3")
            .module;

        let (function_index, capture_count) = ir3
            .instructions
            .iter()
            .find_map(|instruction| match instruction {
                Ir3Instruction::CreateClosure {
                    function_index,
                    capture_count,
                    ..
                } => Some((*function_index, *capture_count)),
                _ => None,
            })
            .expect("IR3 should create a closure for the function declaration");
        assert_eq!(function_index, 1);
        assert_eq!(capture_count, 0);

        let main_halt_index = ir3
            .instructions
            .iter()
            .position(|instruction| matches!(instruction, Ir3Instruction::Halt))
            .expect("main instruction stream should terminate with Halt");
        let function_desc = ir3
            .function_table
            .get(function_index as usize)
            .expect("function table should include the deferred body");
        assert_eq!(function_desc.name.as_deref(), Some("answer"));
        assert_eq!(function_desc.arity, 1);
        assert!(
            function_desc.entry as usize > main_halt_index,
            "function body should be appended after the main instruction stream"
        );
        assert!(
            ir3.instructions[function_desc.entry as usize..]
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::Return { .. })),
            "deferred function body should lower to executable IR3"
        );
    }

    #[test]
    fn deferred_nullish_jump_lowers_and_executes_bd_6pvhn() {
        let (ir1, module, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function fallback(value) { return value ?? 7; } fallback(null) * 10 + fallback(3);",
        );
        assert!(
            deferred_ir1_body_bd_6pvhn(&ir1, "fallback")
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
            "the source must reach the affected deferred IR1 operation"
        );
        assert!(
            deferred_ir3_body_bd_6pvhn(&module, "fallback")
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::JumpIfNullish { .. })),
            "the deferred body must retain its nullish branch"
        );
        assert_eq!(value, Value::Int(73));
    }

    #[test]
    fn deferred_delete_property_lowers_and_executes_bd_6pvhn() {
        let (ir1, module, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function remove(key) {\
                 let object = { fixed: 1, dynamic: 2 };\
                 let fixed = delete object.fixed;\
                 let dynamic = delete object[key];\
                 return fixed && dynamic;\
             }\
             remove('dynamic');",
        );
        assert_eq!(
            deferred_ir1_body_bd_6pvhn(&ir1, "remove")
                .iter()
                .filter(|op| matches!(op, Ir1Op::DeleteProperty { .. }))
                .count(),
            2,
            "the source must reach static and dynamic deferred delete operations"
        );
        assert_eq!(
            deferred_ir3_body_bd_6pvhn(&module, "remove")
                .iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::DeleteProperty { .. }))
                .count(),
            2,
            "the deferred body must retain both delete operations"
        );
        assert_eq!(value, Value::Bool(true));
    }

    #[test]
    fn postfix_member_and_call_on_new_result_execute_bd_7rj0t() {
        let (_, _, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function Constructor(value) {\
                 this.value = value;\
                 this.method = function() { return 9; };\
             }\
             new Constructor(5).value + new Constructor().method() + new Constructor(4)['value'];",
        );
        assert_eq!(value, Value::Int(18));
    }

    #[test]
    fn parenthesized_callee_postfix_executes_bd_7rj0t() {
        let (_, _, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function Constructor(value) { this.value = value; }\
             new (Constructor)(6).value;",
        );
        assert_eq!(value, Value::Int(6));
    }

    #[test]
    fn deferred_construct_lowers_and_executes_bd_6pvhn() {
        let (ir1, module, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function Empty() { this.value = 1; }\
             function Pair(left, right) { this.value = left + right; }\
             function make(EmptyConstructor, PairConstructor) {\
                 return (new EmptyConstructor()).value * 10\
                     + (new PairConstructor(3, 4)).value;\
             }\
             make(Empty, Pair);",
        );
        assert_eq!(
            deferred_ir1_body_bd_6pvhn(&ir1, "make")
                .iter()
                .filter(|op| matches!(op, Ir1Op::Construct { .. }))
                .count(),
            2,
            "the source must reach zero- and multi-argument deferred construction"
        );
        let construct_arg_counts = deferred_ir3_body_bd_6pvhn(&module, "make")
            .iter()
            .filter_map(|instruction| match instruction {
                Ir3Instruction::Construct { args, .. } => Some(args.count),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(construct_arg_counts, vec![0, 2]);
        assert_eq!(value, Value::Int(17));
    }

    #[test]
    fn deferred_template_literal_lowers_and_executes_bd_6pvhn() {
        let (ir1, module, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function render(left, right) { return `${left}:${right}` + ``; } render('a', 7);",
        );
        assert_eq!(
            deferred_ir1_body_bd_6pvhn(&ir1, "render")
                .iter()
                .filter(|op| matches!(op, Ir1Op::TemplateLiteral { .. }))
                .count(),
            2,
            "the source must reach interpolated and empty deferred templates"
        );
        assert_eq!(
            deferred_ir3_body_bd_6pvhn(&module, "render")
                .iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::TemplateLiteral { .. }))
                .count(),
            2,
            "the deferred body must retain both template concatenations"
        );
        assert_eq!(value, Value::Str("a:7".into()));
    }

    #[test]
    fn malformed_module_ops_in_deferred_body_fail_closed_bd_6pvhn() {
        for (body_op, expected_detail) in [
            (
                Ir1Op::ImportModule {
                    specifier: "./dependency.js".to_string(),
                },
                "ImportModule is not valid in a deferred function body",
            ),
            (
                Ir1Op::ExportBinding {
                    name: "value".to_string(),
                    binding_id: 0,
                },
                "ExportBinding is not valid in a deferred function body",
            ),
        ] {
            let ir2 = malformed_deferred_ir2_bd_6pvhn(vec![body_op]);
            assert_eq!(
                lower_ir2_to_ir3(&ir2)
                    .expect_err("module-only operations in deferred bodies must fail closed"),
                LoweringPipelineError::InvariantViolation {
                    detail: expected_detail,
                }
            );
        }
    }

    #[test]
    fn malformed_empty_nested_declaration_fails_closed_bd_6pvhn() {
        let ir2 = malformed_deferred_ir2_bd_6pvhn(vec![Ir1Op::DeclareFunction {
            name: "empty".to_string(),
            binding_id: 1,
            param_names: Vec::new(),
            body_ops: Vec::new(),
            free_vars: Vec::new(),
            free_var_ids: Vec::new(),
            free_var_outer_ids: Vec::new(),
            is_generator: false,
            rest_param_index: None,
        }]);

        assert_eq!(
            lower_ir2_to_ir3(&ir2)
                .expect_err("empty nested deferred declarations must fail closed"),
            LoweringPipelineError::InvariantViolation {
                detail: "Deferred function declaration has an empty body",
            }
        );
    }

    #[test]
    fn valid_empty_nested_source_function_still_lowers_bd_6pvhn() {
        let (ir1, _, value) = lower_and_execute_deferred_source_bd_6pvhn(
            "function outer() { function inner() {} return inner(); } outer();",
        );
        let inner_body = deferred_ir1_body_bd_6pvhn(&ir1, "outer")
            .iter()
            .find_map(|op| match op {
                Ir1Op::DeclareFunction { name, body_ops, .. } if name == "inner" => Some(body_ops),
                _ => None,
            })
            .expect("source nested declaration should reach the deferred matcher");
        assert!(
            !inner_body.is_empty(),
            "source lowering must synthesize the empty function's return body"
        );
        assert_eq!(value, Value::Undefined);
    }

    #[test]
    fn malformed_deferred_hostcall_underflow_fails_closed_bd_6pvhn() {
        let ir2 = malformed_deferred_ir2_bd_6pvhn(vec![Ir1Op::HostCall {
            capability: "hostcall.invoke".to_string(),
            arg_count: 1,
        }]);

        assert_eq!(
            lower_ir2_to_ir3(&ir2)
                .expect_err("hostcalls must pass through checked capability lowering"),
            LoweringPipelineError::InvariantViolation {
                detail: "Value stack underflow in function-body HostCall",
            }
        );
    }

    #[test]
    fn malformed_deferred_operation_underflows_fail_closed_bd_6pvhn() {
        for (body_op, expected_detail) in [
            (
                Ir1Op::JumpIfNullish { label_id: 0 },
                "JumpIfNullish requires a condition register in a function body",
            ),
            (
                Ir1Op::DeleteProperty {
                    key: Ir1PropertyKey::Static("value".to_string()),
                },
                "DeleteProperty requires an object register in a function body",
            ),
            (
                Ir1Op::Construct { arg_count: 0 },
                "Value stack underflow in function-body Construct",
            ),
            (
                Ir1Op::TemplateLiteral { quasi_count: 1 },
                "Value stack underflow in function-body TemplateLiteral",
            ),
        ] {
            let ir2 = malformed_deferred_ir2_bd_6pvhn(vec![body_op]);
            assert_eq!(
                lower_ir2_to_ir3(&ir2)
                    .expect_err("malformed deferred stack consumers must fail closed"),
                LoweringPipelineError::InvariantViolation {
                    detail: expected_detail,
                }
            );
        }
    }

    #[test]
    fn malformed_deferred_jump_target_fails_closed_bd_6pvhn() {
        let ir2 = malformed_deferred_ir2_bd_6pvhn(vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Null,
            },
            Ir1Op::JumpIfNullish { label_id: 99 },
        ]);

        assert_eq!(
            lower_ir2_to_ir3(&ir2)
                .expect_err("an unresolved deferred jump must not retain target zero"),
            LoweringPipelineError::InvariantViolation {
                detail: "function-body control-flow references missing label",
            }
        );
    }

    #[test]
    fn malformed_duplicate_deferred_labels_fail_closed_bd_6pvhn() {
        let ir2 =
            malformed_deferred_ir2_bd_6pvhn(vec![Ir1Op::Label { id: 7 }, Ir1Op::Label { id: 7 }]);

        assert_eq!(
            lower_ir2_to_ir3(&ir2)
                .expect_err("duplicate labels must not overwrite deferred jump targets"),
            LoweringPipelineError::InvariantViolation {
                detail: "Deferred function body contains duplicate label ids",
            }
        );
    }

    #[test]
    fn zero_quasi_deferred_template_loads_real_empty_string_bd_6pvhn() {
        let ir2 = malformed_deferred_ir2_bd_6pvhn(vec![
            Ir1Op::TemplateLiteral { quasi_count: 0 },
            Ir1Op::Return,
        ]);
        let module = lower_ir2_to_ir3(&ir2)
            .expect("zero-quasi compatibility artifact should lower deterministically")
            .module;
        let entry = module
            .function_table
            .iter()
            .find(|desc| desc.name.as_deref() == Some("outer"))
            .expect("deferred function descriptor should exist")
            .entry as usize;

        let Ir3Instruction::LoadStr { pool_index, .. } = module.instructions[entry] else {
            panic!("zero-quasi template must materialize an empty string")
        };
        assert_eq!(module.constant_pool[pool_index as usize], "");
    }

    #[test]
    fn deferred_function_try_catch_relocates_and_executes_bd_47p8z() {
        let module = lower_exception_source_to_ir3_bd_47p8z(
            "function f(){ try { throw 7; } catch(e){ return e; } } f();",
        );
        let entry = module
            .function_table
            .iter()
            .find(|desc| desc.name.as_deref() == Some("f"))
            .expect("deferred function descriptor should exist")
            .entry as usize;

        assert!(matches!(
            module.instructions[entry],
            Ir3Instruction::BeginTry {
                catch_target,
                finally_target: None,
            } if catch_target == (entry + 5) as u32
        ));
        assert!(matches!(
            module.instructions[entry + 3],
            Ir3Instruction::EndTry
        ));
        assert!(matches!(
            module.instructions[entry + 5],
            Ir3Instruction::EnterCatch { .. }
        ));
        assert_eq!(execute_exception_module_bd_47p8z(&module), Value::Int(7));
    }

    #[test]
    fn deferred_function_finally_overrides_pending_return_bd_47p8z() {
        let module = lower_exception_source_to_ir3_bd_47p8z(
            "function f(){ try { return 1; } finally { return 2; } } f();",
        );
        let function = module
            .function_table
            .iter()
            .find(|desc| desc.name.as_deref() == Some("f"))
            .expect("deferred function descriptor should exist");
        let entry = function.entry as usize;
        let body = &module.instructions[entry..];

        assert!(matches!(
            module.instructions[entry],
            Ir3Instruction::BeginTry {
                catch_target,
                finally_target: Some(finally_target),
            } if catch_target == (entry + 5) as u32
                && finally_target == (entry + 5) as u32
        ));
        assert!(matches!(
            module.instructions[entry + 5],
            Ir3Instruction::EnterFinally
        ));
        assert!(
            !body
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::EnterCatch { .. })),
            "a finally-only handler must not consume the pending abrupt completion"
        );
        assert_eq!(execute_exception_module_bd_47p8z(&module), Value::Int(2));
    }

    #[test]
    fn deferred_nested_catch_finally_targets_stay_in_function_bd_47p8z() {
        let module = lower_exception_source_to_ir3_bd_47p8z(
            "function f(){ try { try { throw 1; } catch(inner){ throw 2; } finally {} } catch(outer){ return outer; } } f();",
        );
        let entry = module
            .function_table
            .iter()
            .find(|desc| desc.name.as_deref() == Some("f"))
            .expect("deferred function descriptor should exist")
            .entry as usize;
        let body = &module.instructions[entry..];

        assert!(matches!(
            module.instructions[entry],
            Ir3Instruction::BeginTry {
                catch_target,
                finally_target: None,
            } if catch_target == (entry + 18) as u32
        ));
        assert!(matches!(
            module.instructions[entry + 1],
            Ir3Instruction::BeginTry {
                catch_target,
                finally_target: Some(finally_target),
            } if catch_target == (entry + 6) as u32
                && finally_target == (entry + 13) as u32
        ));
        assert!(matches!(
            module.instructions[entry + 7],
            Ir3Instruction::BeginTry {
                catch_target,
                finally_target: Some(finally_target),
            } if catch_target == (entry + 13) as u32
                && finally_target == (entry + 13) as u32
        ));
        assert!(matches!(
            module.instructions[entry + 6],
            Ir3Instruction::EnterCatch { .. }
        ));
        assert!(matches!(
            module.instructions[entry + 13],
            Ir3Instruction::EnterFinally
        ));
        assert!(matches!(
            module.instructions[entry + 18],
            Ir3Instruction::EnterCatch { .. }
        ));
        assert_eq!(
            body.iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::BeginTry { .. }))
                .count(),
            3
        );
        assert_eq!(
            body.iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::EndTry))
                .count(),
            3
        );
        assert_eq!(
            body.iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::EnterCatch { .. }))
                .count(),
            2
        );
        assert_eq!(
            body.iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::EnterFinally))
                .count(),
            1
        );
        assert_eq!(
            body.iter()
                .filter(|instruction| matches!(instruction, Ir3Instruction::EndFinally))
                .count(),
            1
        );
        assert_eq!(execute_exception_module_bd_47p8z(&module), Value::Int(2));
    }

    fn execute_exception_source_bd_kfxwe(source: &str) -> Value {
        let module = lower_exception_source_to_ir3_bd_47p8z(source);
        execute_exception_module_bd_47p8z(&module)
    }

    #[test]
    fn break_through_finally_pops_handler_before_later_throw_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let hits=0; try { while(true) { try { break; } finally { hits=hits+1; } } throw 0; } catch(e) {} hits;",
            ),
            Value::Int(1)
        );
    }

    #[test]
    fn continue_through_finally_does_not_accumulate_handlers_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let hits=0; let i=0; try { while(i<2) { i=i+1; try { continue; } finally { hits=hits+1; } } throw 0; } catch(e) {} hits;",
            ),
            Value::Int(2)
        );
    }

    #[test]
    fn break_through_try_catch_without_finally_pops_handler_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let caught=0; try { while(true) { try { break; } catch(e) { caught=99; } } throw 1; } catch(e) { caught=caught+1; } caught;",
            ),
            Value::Int(1)
        );
    }

    #[test]
    fn break_from_catch_pops_finally_guard_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let hits=0; try { while(true) { try { throw 1; } catch(e) { break; } finally { hits=hits+1; } } throw 2; } catch(e) { hits=hits+10; } hits;",
            ),
            Value::Int(11)
        );
    }

    #[test]
    fn return_from_break_forwarder_does_not_replay_finalizer_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "function f(){ let hits=0; while(true) { try { break; } finally { hits=hits+1; return hits*10+7; } } return 0; } f();",
            ),
            Value::Int(17)
        );
    }

    #[test]
    fn throw_from_break_forwarder_does_not_replay_finalizer_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let hits=0; try { while(true) { try { break; } finally { hits=hits+1; throw \"new\"; } } } catch(e) { hits=hits+10; } hits;",
            ),
            Value::Int(11)
        );
    }

    #[test]
    fn continue_inside_finally_discards_overridden_exception_bd_kfxwe() {
        let module = lower_exception_source_to_ir3_bd_47p8z(
            "let log=\"\"; let i=0; while(i<1) { i=i+1; try { throw \"old\"; } finally { log=log+\"f\"; continue; } } try { log=log+\"n\"; } finally { log=log+\"g\"; } log;",
        );
        assert!(
            module
                .instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::DiscardAbruptCompletion))
        );
        assert_eq!(
            execute_exception_module_bd_47p8z(&module),
            Value::str("fng")
        );
    }

    #[test]
    fn local_finally_break_restores_suspended_outer_throw_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let log=\"\"; try { try { throw \"outer\"; } finally { while(true) { try { throw \"inner\"; } finally { break; } } log=log+\"after;\"; } } catch(e) { log=log+\"caught:\"+e; } log;",
            ),
            Value::str("after;caught:outer")
        );
    }

    #[test]
    fn local_finally_continue_restores_suspended_outer_return_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "function f(){ try { return \"outer\"; } finally { let i=0; while(i<1) { i=i+1; try { throw \"inner\"; } finally { continue; } } } } f();",
            ),
            Value::str("outer")
        );
    }

    #[test]
    fn normal_nested_finally_break_preserves_outer_throw_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let log=\"\"; try { try { throw \"outer\"; } finally { while(true) { try {} finally { break; } } log=log+\"after;\"; } } catch(e) { log=log+\"caught:\"+e; } log;",
            ),
            Value::str("after;caught:outer")
        );
    }

    #[test]
    fn normal_nested_finally_break_preserves_outer_return_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "function f(){ try { return \"outer\"; } finally { while(true) { try {} finally { break; } } } } f();",
            ),
            Value::str("outer")
        );
    }

    #[test]
    fn escaping_throw_discards_inner_return_but_preserves_outer_return_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "function f(){ try { return \"outer\"; } finally { try { try { return \"inner\"; } finally { throw \"new\"; } } catch(e) {} } } f();",
            ),
            Value::str("outer")
        );
    }

    #[test]
    fn throw_caught_inside_same_finally_resumes_owned_return_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "function f(){ try { return \"outer\"; } finally { try { throw \"new\"; } catch(e) {} } } f();",
            ),
            Value::str("outer")
        );
    }

    #[test]
    fn throw_caught_inside_same_finally_resumes_owned_exception_bd_kfxwe() {
        assert_eq!(
            execute_exception_source_bd_kfxwe(
                "let log=\"\"; try { try { throw \"outer\"; } finally { try { throw \"new\"; } catch(e) { log=e+\";\"; } log=log+\"after;\"; } } catch(e) { log=log+e; } log;",
            ),
            Value::str("new;after;outer")
        );
    }

    // ================================================================
    // Additional edge cases
    // ================================================================

    #[test]
    fn lower_nested_binary_expressions() {
        let ir0 = expr_ir0(Expression::Binary {
            operator: BinaryOperator::Multiply,
            left: Box::new(Expression::Binary {
                operator: BinaryOperator::Add,
                left: Box::new(Expression::NumericLiteral(1)),
                right: Box::new(Expression::NumericLiteral(2)),
            }),
            right: Box::new(Expression::NumericLiteral(3)),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("nested binary should lower");
        let op_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::BinaryOp { .. }))
            .count();
        assert_eq!(op_count, 2);
    }

    #[test]
    fn lower_call_with_no_args() {
        let ir0 = expr_ir0(Expression::Call {
            callee: Box::new(Expression::Identifier("f".into())),
            arguments: vec![],
        });
        let result = lower_ir0_to_ir1(&ir0).expect("0-arg call should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Call { arg_count: 0 }))
        );
    }

    #[test]
    fn lower_empty_array_literal() {
        let ir0 = expr_ir0(Expression::ArrayLiteral(vec![]));
        let result = lower_ir0_to_ir1(&ir0).expect("empty array should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::NewArray { count: 0 }))
        );
    }

    #[test]
    fn lower_empty_object_literal() {
        let ir0 = expr_ir0(Expression::ObjectLiteral(vec![]));
        let result = lower_ir0_to_ir1(&ir0).expect("empty object should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::NewObject { count: 0 }))
        );
    }

    #[test]
    fn lower_null_literal_expression() {
        let ir0 = expr_ir0(Expression::NullLiteral);
        let result = lower_ir0_to_ir1(&ir0).expect("null should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Null
            }
        )));
    }

    #[test]
    fn lower_undefined_literal_expression() {
        let ir0 = expr_ir0(Expression::UndefinedLiteral);
        let result = lower_ir0_to_ir1(&ir0).expect("undefined should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Undefined
            }
        )));
    }

    #[test]
    fn lower_boolean_true_expression() {
        let ir0 = expr_ir0(Expression::BooleanLiteral(true));
        let result = lower_ir0_to_ir1(&ir0).expect("true should lower");
        assert!(result.module.ops.iter().any(|op| matches!(
            op,
            Ir1Op::LoadLiteral {
                value: Ir1Literal::Boolean(true)
            }
        )));
    }

    #[test]
    fn lower_identifier_creates_binding() {
        let ir0 = expr_ir0(Expression::Identifier("myVar".into()));
        let result = lower_ir0_to_ir1(&ir0).expect("identifier should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::LoadBinding { .. }))
        );
        let binding = result
            .module
            .scopes
            .first()
            .expect("scope")
            .bindings
            .iter()
            .find(|b| b.name == "myVar");
        assert!(binding.is_some());
    }

    #[test]
    fn lower_const_without_init_errors() {
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::Identifier("x".into()),
                initializer: None,
                span: span(),
            }],
            span: span(),
        })]);
        let err = lower_ir0_to_ir1(&ir0).expect_err("const without init should fail");
        assert!(matches!(err, LoweringPipelineError::SemanticViolation(_)));
    }

    #[test]
    fn validate_static_semantics_for_in_for_of_noop() {
        let ir0 = stmt_ir0(vec![
            Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".into()),
                binding_kind: Some(VariableDeclarationKind::Let),
                object: Expression::Identifier("obj".into()),
                body: Box::new(Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })),
                span: span(),
            }),
            Statement::ForOf(ForOfStatement {
                binding: BindingPattern::Identifier("v".into()),
                binding_kind: Some(VariableDeclarationKind::Const),
                iterable: Expression::Identifier("arr".into()),
                body: Box::new(Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(2),
                    span: span(),
                })),
                span: span(),
            }),
        ]);
        let result = validate_ir0_static_semantics(&ir0);
        assert!(result.is_valid());
    }

    #[test]
    fn full_pipeline_binary_expression() {
        let ir0 = expr_ir0(Expression::Binary {
            operator: BinaryOperator::Subtract,
            left: Box::new(Expression::NumericLiteral(10)),
            right: Box::new(Expression::NumericLiteral(3)),
        });
        let ctx = LoweringContext::new("t", "d", "p");
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("full pipeline should succeed");
        assert!(!output.ir3.instructions.is_empty());
        assert_eq!(output.witnesses.len(), 3);
        assert_eq!(output.events.len(), 4);
    }

    #[test]
    fn full_pipeline_if_statement() {
        let ir0 = stmt_ir0(vec![Statement::If(IfStatement {
            condition: Expression::BooleanLiteral(true),
            consequent: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            alternate: None,
            span: span(),
        })]);
        let ctx = LoweringContext::new("t", "d", "p");
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("if pipeline should succeed");
        assert!(!output.ir1.ops.is_empty());
        assert!(!output.ir3.instructions.is_empty());
    }

    #[test]
    fn full_pipeline_while_statement() {
        let ir0 = stmt_ir0(vec![Statement::While(WhileStatement {
            condition: Expression::BooleanLiteral(false),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            span: span(),
        })]);
        let ctx = LoweringContext::new("t", "d", "p");
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("while pipeline should succeed");
        assert!(!output.ir3.instructions.is_empty());
    }

    #[test]
    fn for_in_without_binding_kind_reuses_existing_assignment_target() {
        let ir0 = stmt_ir0(vec![
            Statement::VariableDeclaration(VariableDeclaration {
                kind: VariableDeclarationKind::Let,
                declarations: vec![VariableDeclarator {
                    pattern: BindingPattern::Identifier("k".into()),
                    initializer: Some(Expression::StringLiteral(String::new())),
                    span: span(),
                }],
                span: span(),
            }),
            Statement::ForIn(ForInStatement {
                binding: BindingPattern::Identifier("k".into()),
                binding_kind: None,
                object: Expression::Identifier("obj".into()),
                body: Box::new(Statement::Expression(ExpressionStatement {
                    expression: Expression::NumericLiteral(1),
                    span: span(),
                })),
                span: span(),
            }),
        ]);
        let result =
            lower_ir0_to_ir1(&ir0).expect("a bare for-in target should assign an existing binding");
        let k_bindings = result.module.scopes[0]
            .bindings
            .iter()
            .filter(|binding| binding.name == "k")
            .collect::<Vec<_>>();
        assert_eq!(k_bindings.len(), 1);
        let k_id = k_bindings[0].binding_id;
        assert_eq!(
            result
                .module
                .ops
                .iter()
                .filter(
                    |op| matches!(op, Ir1Op::StoreBinding { binding_id } if *binding_id == k_id)
                )
                .count(),
            2,
            "the declaration initializer and loop assignment must store the same binding"
        );
    }

    #[test]
    fn classify_ir1_op_await_is_read_effect() {
        let (boundary, cap, _flow) = classify_ir1_op(&Ir1Op::Await);
        assert_eq!(boundary, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
    }

    #[test]
    fn classify_ir1_op_throw_is_read_effect() {
        let (boundary, cap, _flow) = classify_ir1_op(&Ir1Op::Throw);
        assert_eq!(boundary, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
    }

    #[test]
    fn classify_ir1_op_call_is_pure() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::Call { arg_count: 1 });
        assert_eq!(boundary, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_ir1_op_load_literal_is_pure() {
        let (boundary, cap, _flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::Integer(42),
        });
        assert_eq!(boundary, EffectBoundary::Pure);
        assert!(cap.is_none());
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn sink_label_to_clearance_public_is_never_sink() {
        assert_eq!(
            sink_label_to_clearance(&Label::Public),
            Clearance::NeverSink
        );
    }

    #[test]
    fn sink_label_to_clearance_internal_is_restricted() {
        assert_eq!(
            sink_label_to_clearance(&Label::Internal),
            Clearance::RestrictedSink
        );
    }

    #[test]
    fn sink_label_to_clearance_confidential_is_audited() {
        assert_eq!(
            sink_label_to_clearance(&Label::Confidential),
            Clearance::AuditedSink
        );
    }

    #[test]
    fn sink_label_to_clearance_secret_is_sealed() {
        assert_eq!(
            sink_label_to_clearance(&Label::Secret),
            Clearance::SealedSink
        );
    }

    #[test]
    fn sink_label_to_clearance_top_secret_is_open() {
        assert_eq!(
            sink_label_to_clearance(&Label::TopSecret),
            Clearance::OpenSink
        );
    }

    #[test]
    fn sink_label_to_clearance_custom_level_0_is_never() {
        let label = Label::Custom {
            name: "low".to_string(),
            level: 0,
        };
        assert_eq!(sink_label_to_clearance(&label), Clearance::NeverSink);
    }

    #[test]
    fn sink_label_to_clearance_custom_level_1_is_restricted() {
        let label = Label::Custom {
            name: "mid".to_string(),
            level: 1,
        };
        assert_eq!(sink_label_to_clearance(&label), Clearance::RestrictedSink);
    }

    #[test]
    fn sink_label_to_clearance_custom_level_2_is_audited() {
        let label = Label::Custom {
            name: "high".to_string(),
            level: 2,
        };
        assert_eq!(sink_label_to_clearance(&label), Clearance::AuditedSink);
    }

    #[test]
    fn sink_label_to_clearance_custom_level_3_is_sealed() {
        let label = Label::Custom {
            name: "critical".to_string(),
            level: 3,
        };
        assert_eq!(sink_label_to_clearance(&label), Clearance::SealedSink);
    }

    #[test]
    fn sink_label_to_clearance_custom_level_4_plus_is_open() {
        for level in [4, 5, 100, u32::MAX] {
            let label = Label::Custom {
                name: format!("lvl{level}"),
                level,
            };
            assert_eq!(sink_label_to_clearance(&label), Clearance::OpenSink);
        }
    }

    #[test]
    fn flow_capability_supports_declassification_true_cases() {
        let cases = [
            CapabilityTag("ifc.declassify".to_string()),
            CapabilityTag("ifc.declassification.route".to_string()),
            CapabilityTag("DECLASSIFY".to_string()),
            CapabilityTag("auto_declassification".to_string()),
        ];
        for cap in &cases {
            assert!(
                flow_capability_supports_declassification(cap),
                "expected true for {:?}",
                cap
            );
        }
    }

    #[test]
    fn flow_capability_supports_declassification_false_cases() {
        let cases = [
            CapabilityTag("hostcall.invoke".to_string()),
            CapabilityTag("module.import".to_string()),
            CapabilityTag("ifc.check_flow".to_string()),
            CapabilityTag("network.write".to_string()),
        ];
        for cap in &cases {
            assert!(
                !flow_capability_supports_declassification(cap),
                "expected false for {:?}",
                cap
            );
        }
    }

    #[test]
    fn runtime_checkpoint_reason_dynamic_capability() {
        let flow = FlowAnnotation {
            data_label: Label::Public,
            sink_clearance: Label::Public,
            declassification_required: false,
        };
        let cap = CapabilityTag("hostcall.invoke".to_string());
        assert_eq!(runtime_checkpoint_reason(&flow, &cap), "dynamic_capability");
    }

    #[test]
    fn runtime_checkpoint_reason_ambiguous_data_label() {
        let flow = FlowAnnotation {
            data_label: Label::Custom {
                name: "pii".to_string(),
                level: 2,
            },
            sink_clearance: Label::Public,
            declassification_required: false,
        };
        let cap = CapabilityTag("ifc.check_flow".to_string());
        assert_eq!(
            runtime_checkpoint_reason(&flow, &cap),
            "ambiguous_data_label"
        );
    }

    #[test]
    fn runtime_checkpoint_reason_ambiguous_sink_clearance() {
        let flow = FlowAnnotation {
            data_label: Label::Public,
            sink_clearance: Label::Custom {
                name: "audit_sink".to_string(),
                level: 1,
            },
            declassification_required: false,
        };
        let cap = CapabilityTag("ifc.check_flow".to_string());
        assert_eq!(
            runtime_checkpoint_reason(&flow, &cap),
            "ambiguous_sink_clearance"
        );
    }

    #[test]
    fn runtime_checkpoint_reason_fallback() {
        let flow = FlowAnnotation {
            data_label: Label::Internal,
            sink_clearance: Label::Internal,
            declassification_required: false,
        };
        let cap = CapabilityTag("ifc.check_flow".to_string());
        assert_eq!(
            runtime_checkpoint_reason(&flow, &cap),
            "runtime_checkpoint_required"
        );
    }

    #[test]
    fn flow_proof_artifact_entry_serde_roundtrip() {
        let entry = FlowProofArtifactEntry {
            op_index: 7,
            body_path: vec![2, 4],
            source_label: Label::Confidential,
            sink_clearance: Label::Internal,
            capability: Some("hostcall.invoke".to_string()),
            proof_method: ProofMethod::StaticAnalysis,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: FlowProofArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn denied_flow_artifact_entry_serde_roundtrip() {
        let entry = DeniedFlowArtifactEntry {
            op_index: 3,
            body_path: vec![1],
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            capability: None,
            reason: "lattice violation".to_string(),
            error_code: "FE-LOWER-IFC-0001".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DeniedFlowArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn required_declassification_artifact_entry_serde_roundtrip() {
        let entry = RequiredDeclassificationArtifactEntry {
            op_index: 5,
            body_path: vec![0, 3],
            source_label: Label::Confidential,
            sink_clearance: Label::Public,
            capability: Some("ifc.declassify".to_string()),
            obligation_id: "obl-42".to_string(),
            decision_contract_id: "decision-42".to_string(),
            declassification_route_ref: Some("route-42".to_string()),
            requires_operator_approval: true,
            receipt_linkage_required: true,
            replay_command_hint: REQUIRED_DECLASSIFICATION_REPLAY_COMMAND_HINT.to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RequiredDeclassificationArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn runtime_checkpoint_artifact_entry_serde_roundtrip() {
        let entry = RuntimeCheckpointArtifactEntry {
            op_index: 9,
            body_path: vec![6],
            source_label: Label::Internal,
            sink_clearance: Label::Custom {
                name: "audit".to_string(),
                level: 2,
            },
            capability: Some("hostcall.invoke".to_string()),
            reason: "dynamic_capability".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RuntimeCheckpointArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn lowering_pipeline_error_display_flow_lattice_failure() {
        let err = LoweringPipelineError::FlowLatticeFailure {
            detail: "lattice merge diverged".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("lattice merge diverged"),
            "FlowLatticeFailure display should contain detail: {display}"
        );
    }

    #[test]
    fn runtime_checkpoint_artifact_entry_confidential_roundtrip() {
        let entry = RuntimeCheckpointArtifactEntry {
            op_index: 7,
            body_path: Vec::new(),
            source_label: Label::Confidential,
            sink_clearance: Label::Public,
            capability: Some("ifc.check_flow".to_string()),
            reason: "checkpoint serde roundtrip test".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RuntimeCheckpointArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn flow_requires_runtime_checkpoint_confidential() {
        let flow = FlowAnnotation {
            data_label: Label::Confidential,
            sink_clearance: Label::Custom {
                name: "log".to_string(),
                level: 0,
            },
            declassification_required: false,
        };
        let cap = CapabilityTag("ifc.check_flow".to_string());
        assert!(flow_requires_runtime_checkpoint(Some(&flow), &cap));
    }

    #[test]
    fn flow_requires_runtime_checkpoint_static_safe() {
        let flow = FlowAnnotation {
            data_label: Label::Public,
            sink_clearance: Label::Public,
            declassification_required: false,
        };
        let cap = CapabilityTag("ifc.check_flow".to_string());
        assert!(!flow_requires_runtime_checkpoint(Some(&flow), &cap));
    }

    // -- Optional chaining lowering tests (bd-1lsy.2.10.1) ------------------

    #[test]
    fn optional_member_static_property_lowers_to_ir1() {
        // obj?.prop
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("optional member should lower");
        // Must contain JumpIfNullish for the short-circuit path.
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
            "optional member must emit JumpIfNullish"
        );
        // Must contain GetProperty for the non-nullish path.
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::GetProperty { .. })),
            "optional member must emit GetProperty"
        );
        // Must contain LoadLiteral Undefined for the nullish path.
        assert!(
            result.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined
                }
            )),
            "optional member must emit LoadLiteral Undefined"
        );
    }

    #[test]
    fn optional_member_computed_property_lowers_to_ir1() {
        // arr?.[0]
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("arr".to_string())),
            property: Box::new(Expression::NumericLiteral(0)),
            computed: true,
        });
        let result = lower_ir0_to_ir1(&ir0).expect("optional computed member should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
            "computed optional member must emit JumpIfNullish"
        );
        assert!(
            result.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Dynamic
                }
            )),
            "computed optional member must emit dynamic GetProperty"
        );
    }

    #[test]
    fn optional_call_lowers_to_ir1() {
        // fn?.()
        let ir0 = expr_ir0(Expression::OptionalCall {
            callee: Box::new(Expression::Identifier("fn_val".to_string())),
            arguments: vec![],
        });
        let result = lower_ir0_to_ir1(&ir0).expect("optional call should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfNullish { .. })),
            "optional call must emit JumpIfNullish"
        );
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Call { arg_count: 0 })),
            "optional call must emit Call with 0 args"
        );
        assert!(
            result.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined
                }
            )),
            "optional call must emit LoadLiteral Undefined"
        );
    }

    #[test]
    fn optional_call_with_args_lowers_to_ir1() {
        // maybe?.(1, 2)
        let ir0 = expr_ir0(Expression::OptionalCall {
            callee: Box::new(Expression::Identifier("maybe".to_string())),
            arguments: vec![Expression::NumericLiteral(1), Expression::NumericLiteral(2)],
        });
        let result = lower_ir0_to_ir1(&ir0).expect("optional call with args should lower");
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::Call { arg_count: 2 })),
            "optional call must emit Call with 2 args"
        );
    }

    #[test]
    fn optional_member_lowers_through_full_pipeline() {
        // obj?.prop — full IR0 → IR3 pipeline
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(Expression::Identifier("obj".to_string())),
            property: Box::new(Expression::Identifier("prop".to_string())),
            computed: false,
        });
        let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0→IR1");
        let ir2 = lower_ir1_to_ir2(&ir1.module).expect("IR1→IR2");
        let ir3 = lower_ir2_to_ir3(&ir2.module).expect("IR2→IR3");
        // IR3 should contain JumpIfNullish.
        assert!(
            ir3.module
                .instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::JumpIfNullish { .. })),
            "IR3 must contain JumpIfNullish for optional member"
        );
        // IR3 should contain GetProperty.
        assert!(
            ir3.module
                .instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::GetProperty { .. })),
            "IR3 must contain GetProperty for optional member"
        );
        // IR3 should contain LoadUndefined.
        assert!(
            ir3.module
                .instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::LoadUndefined { .. })),
            "IR3 must contain LoadUndefined for nullish short-circuit"
        );
    }

    #[test]
    fn optional_call_lowers_through_full_pipeline() {
        // fn?.() — full IR0 → IR3 pipeline
        let ir0 = expr_ir0(Expression::OptionalCall {
            callee: Box::new(Expression::Identifier("fn_val".to_string())),
            arguments: vec![Expression::NumericLiteral(42)],
        });
        let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0→IR1");
        let ir2 = lower_ir1_to_ir2(&ir1.module).expect("IR1→IR2");
        let ir3 = lower_ir2_to_ir3(&ir2.module).expect("IR2→IR3");
        assert!(
            ir3.module
                .instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::JumpIfNullish { .. })),
            "IR3 must contain JumpIfNullish for optional call"
        );
        // Optional calls must lower to a real call instruction at IR3.
        assert!(
            ir3.module
                .instructions
                .iter()
                .any(|i| matches!(i, Ir3Instruction::Call { .. })),
            "IR3 must contain Call for optional call"
        );
    }

    #[test]
    fn nested_optional_member_chain_lowers() {
        // a?.b?.c — nested optional members
        let inner = Expression::OptionalMember {
            object: Box::new(Expression::Identifier("a".to_string())),
            property: Box::new(Expression::Identifier("b".to_string())),
            computed: false,
        };
        let ir0 = expr_ir0(Expression::OptionalMember {
            object: Box::new(inner),
            property: Box::new(Expression::Identifier("c".to_string())),
            computed: false,
        });
        let ir1 = lower_ir0_to_ir1(&ir0).expect("nested optional chain should lower");
        // Should emit two JumpIfNullish ops (one per ?. in the chain).
        let nullish_count = ir1
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::JumpIfNullish { .. }))
            .count();
        assert_eq!(
            nullish_count, 2,
            "nested chain a?.b?.c must emit 2 JumpIfNullish ops"
        );
    }

    // -----------------------------------------------------------------------
    // Destructuring completeness tests (bd-6a61n.1.5)
    // -----------------------------------------------------------------------

    #[test]
    fn object_destructuring_emits_get_property() {
        // const { a, b } = source
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ObjectPattern(vec![
                    ObjectPatternProperty {
                        key: Expression::Identifier("a".into()),
                        value: BindingPattern::Identifier("a".into()),
                        computed: false,
                        shorthand: true,
                    },
                    ObjectPatternProperty {
                        key: Expression::Identifier("b".into()),
                        value: BindingPattern::Identifier("b".into()),
                        computed: false,
                        shorthand: true,
                    },
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let get_props: Vec<_> = result
            .module
            .ops
            .iter()
            .filter_map(|op| {
                if let Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(k),
                } = op
                {
                    Some(k.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            get_props.contains(&"a"),
            "should emit GetProperty for 'a', got: {get_props:?}"
        );
        assert!(
            get_props.contains(&"b"),
            "should emit GetProperty for 'b', got: {get_props:?}"
        );
    }

    #[test]
    fn object_destructuring_rename_emits_correct_key() {
        // const { a: x } = source — key is "a", binding is "x"
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                    key: Expression::Identifier("a".into()),
                    value: BindingPattern::Identifier("x".into()),
                    computed: false,
                    shorthand: false,
                }]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let get_props: Vec<_> = result
            .module
            .ops
            .iter()
            .filter_map(|op| {
                if let Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(k),
                } = op
                {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            get_props.contains(&"a".to_string()),
            "should emit GetProperty for key 'a', got: {get_props:?}"
        );
        // Verify binding "x" exists.
        let scope = result.module.scopes.first().expect("root scope");
        assert!(scope.bindings.iter().any(|b| b.name == "x"));
    }

    #[test]
    fn array_destructuring_emits_indexed_get_property() {
        // const [a, b] = source
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ArrayPattern(vec![
                    Some(BindingPattern::Identifier("a".into())),
                    Some(BindingPattern::Identifier("b".into())),
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let get_props: Vec<_> = result
            .module
            .ops
            .iter()
            .filter_map(|op| {
                if let Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(k),
                } = op
                {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            get_props.contains(&"0".to_string()),
            "should emit GetProperty for index '0'"
        );
        assert!(
            get_props.contains(&"1".to_string()),
            "should emit GetProperty for index '1'"
        );
    }

    #[test]
    fn array_destructuring_with_hole() {
        // const [, b] = source — first element is a hole
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ArrayPattern(vec![
                    None, // hole
                    Some(BindingPattern::Identifier("b".into())),
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let get_props: Vec<_> = result
            .module
            .ops
            .iter()
            .filter_map(|op| {
                if let Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(k),
                } = op
                {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        // Should only have index "1" (skipping hole at 0).
        assert!(
            get_props.contains(&"1".to_string()),
            "should emit GetProperty for index '1', got: {get_props:?}"
        );
        assert!(
            !get_props.contains(&"0".to_string()),
            "should NOT emit GetProperty for hole at index '0'"
        );
    }

    #[test]
    fn array_destructuring_rest_lowers_to_runtime_slice() {
        // const [head, ...tail] = source
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ArrayPattern(vec![
                    Some(BindingPattern::Identifier("head".into())),
                    Some(BindingPattern::Rest(Box::new(BindingPattern::Identifier(
                        "tail".into(),
                    )))),
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);

        let ir1 = lower_ir0_to_ir1(&ir0).expect("array rest should lower to IR1");
        let slice_index = ir1
            .module
            .ops
            .iter()
            .position(|op| matches!(op, Ir1Op::ArraySlice))
            .expect("array rest must emit ArraySlice");

        assert!(
            ir1.module.ops[..slice_index].iter().any(|op| matches!(
                op,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(1)
                }
            )),
            "array rest should load the current destructuring index as slice start"
        );
        assert!(
            !ir1.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Undefined
                }
            )),
            "array rest must not preserve the old Undefined placeholder"
        );

        let ctx = LoweringContext::new("trace-array-rest", "decision-array-rest", "policy");
        let ir3 = lower_ir0_to_ir3(&ir0, &ctx)
            .expect("array rest should lower through IR3")
            .ir3;
        assert!(
            ir3.instructions
                .iter()
                .any(|instr| matches!(instr, Ir3Instruction::ArraySlice { .. })),
            "array rest must lower to an executable IR3 ArraySlice"
        );
    }

    #[test]
    fn nested_object_destructuring_emits_nested_get_property() {
        // const { a: { b } } = source
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                    key: Expression::Identifier("a".into()),
                    value: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                        key: Expression::Identifier("b".into()),
                        value: BindingPattern::Identifier("b".into()),
                        computed: false,
                        shorthand: true,
                    }]),
                    computed: false,
                    shorthand: false,
                }]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let get_props: Vec<_> = result
            .module
            .ops
            .iter()
            .filter_map(|op| {
                if let Ir1Op::GetProperty {
                    key: Ir1PropertyKey::Static(k),
                } = op
                {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        assert!(
            get_props.contains(&"a".to_string()),
            "should emit GetProperty for outer key 'a'"
        );
        assert!(
            get_props.contains(&"b".to_string()),
            "should emit GetProperty for nested key 'b'"
        );
    }

    #[test]
    fn nested_array_destructuring_emits_nested_get_property() {
        // const [, [b]] = source — nested array destructuring
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ArrayPattern(vec![
                    None,
                    Some(BindingPattern::ArrayPattern(vec![Some(
                        BindingPattern::Identifier("b".into()),
                    )])),
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let mut index_zero = 0usize;
        let mut index_one = 0usize;
        for op in &result.module.ops {
            if let Ir1Op::GetProperty {
                key: Ir1PropertyKey::Static(k),
            } = op
            {
                if k == "0" {
                    index_zero += 1;
                } else if k == "1" {
                    index_one += 1;
                }
            }
        }
        assert_eq!(index_one, 1, "should emit GetProperty for outer index '1'");
        assert_eq!(
            index_zero, 1,
            "should emit GetProperty for nested index '0'"
        );
    }

    #[test]
    fn destructuring_assignment_pattern_emits_default_check() {
        // const { a = 1 } = source
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ObjectPattern(vec![ObjectPatternProperty {
                    key: Expression::Identifier("a".into()),
                    value: BindingPattern::AssignmentPattern {
                        left: Box::new(BindingPattern::Identifier("a".into())),
                        right: Expression::NumericLiteral(1),
                    },
                    computed: false,
                    shorthand: true,
                }]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        assert!(
            result.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::BinaryOp {
                    operator: BinaryOperator::StrictEqual
                }
            )),
            "should emit strict-equal check against undefined"
        );
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfTruthy { .. })),
            "should emit JumpIfTruthy for default branch"
        );
        assert!(
            result.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(1)
                }
            )),
            "should load the default literal"
        );
    }

    #[test]
    fn array_destructuring_assignment_pattern_emits_default_check() {
        // const [a = 2] = source
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ArrayPattern(vec![Some(
                    BindingPattern::AssignmentPattern {
                        left: Box::new(BindingPattern::Identifier("a".into())),
                        right: Expression::NumericLiteral(2),
                    },
                )]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        assert!(
            result.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::BinaryOp {
                    operator: BinaryOperator::StrictEqual
                }
            )),
            "should emit strict-equal check against undefined"
        );
        assert!(
            result
                .module
                .ops
                .iter()
                .any(|op| matches!(op, Ir1Op::JumpIfTruthy { .. })),
            "should emit JumpIfTruthy for default branch"
        );
        assert!(
            result.module.ops.iter().any(|op| matches!(
                op,
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(2)
                }
            )),
            "should load the default literal"
        );
    }

    #[test]
    fn destructuring_allocates_all_named_bindings() {
        // const { a, b: c } = source — should allocate both "a" and "c"
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ObjectPattern(vec![
                    ObjectPatternProperty {
                        key: Expression::Identifier("a".into()),
                        value: BindingPattern::Identifier("a".into()),
                        computed: false,
                        shorthand: true,
                    },
                    ObjectPatternProperty {
                        key: Expression::Identifier("b".into()),
                        value: BindingPattern::Identifier("c".into()),
                        computed: false,
                        shorthand: false,
                    },
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let scope = result.module.scopes.first().expect("root scope");
        let names: Vec<&str> = scope.bindings.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"a"), "binding 'a' should exist");
        assert!(names.contains(&"c"), "binding 'c' should exist");
    }

    #[test]
    fn destructuring_uses_internal_source_binding() {
        let ir0 = stmt_ir0(vec![Statement::VariableDeclaration(VariableDeclaration {
            kind: VariableDeclarationKind::Const,
            declarations: vec![VariableDeclarator {
                pattern: BindingPattern::ObjectPattern(vec![
                    ObjectPatternProperty {
                        key: Expression::Identifier("a".into()),
                        value: BindingPattern::Identifier("a".into()),
                        computed: false,
                        shorthand: true,
                    },
                    ObjectPatternProperty {
                        key: Expression::Identifier("b".into()),
                        value: BindingPattern::Identifier("b".into()),
                        computed: false,
                        shorthand: true,
                    },
                ]),
                initializer: Some(Expression::Identifier("source".into())),
                span: span(),
            }],
            span: span(),
        })]);
        let result = lower_ir0_to_ir1(&ir0).expect("should lower");
        let scope = result.module.scopes.first().expect("root scope");
        let internal_source = scope
            .bindings
            .iter()
            .find(|binding| binding.name.contains("destructure_source"))
            .expect("destructuring should allocate an internal source binding");
        let a_binding = scope
            .bindings
            .iter()
            .find(|binding| binding.name == "a")
            .expect("binding a should exist");
        assert_ne!(
            internal_source.binding_id, a_binding.binding_id,
            "source binding must not alias the first user binding"
        );
        let first_store = result
            .module
            .ops
            .iter()
            .find_map(|op| match op {
                Ir1Op::StoreBinding { binding_id } => Some(*binding_id),
                _ => None,
            })
            .expect("destructuring should store the initializer");
        assert_eq!(
            first_store, internal_source.binding_id,
            "initializer should land in the internal source binding"
        );
    }
}
