#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ast::{
    ArrowBody, BinaryOperator, BindingPattern, ExportKind, Expression, ParseGoal, SourceSpan,
    Statement, VariableDeclarationKind,
};
use crate::flow_lattice::{
    Clearance, DeclassificationObligation, FlowCheckResult as LatticeFlowCheckResult,
    Ir2FlowLattice, LabelClass,
};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::{Label, ProofMethod};
use crate::ir_contract::{
    BindingId, BindingKind, CapabilityTag, EffectBoundary, FlowAnnotation, Ir0Module, Ir1Literal,
    Ir1Module, Ir1Op, Ir2Module, Ir2Op, Ir3FunctionDesc, Ir3Instruction, Ir3Module, IrError,
    IrLevel, Reg, RegRange, ResolvedBinding, ScopeId, ScopeKind, ScopeNode, verify_ir1_source,
    verify_ir3_specialization,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowInferenceMetrics {
    total_flow_ops: u64,
    static_proven_ops: u64,
    runtime_check_ops: u64,
}

impl FlowInferenceMetrics {
    fn static_coverage_millionths(self) -> u64 {
        if self.total_flow_ops == 0 {
            return 1_000_000;
        }
        (self.static_proven_ops.saturating_mul(1_000_000)) / self.total_flow_ops
    }
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
    pub source_label: Label,
    pub sink_clearance: Label,
    pub capability: Option<String>,
    pub proof_method: ProofMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeniedFlowArtifactEntry {
    pub op_index: u64,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub capability: Option<String>,
    pub reason: String,
    pub error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequiredDeclassificationArtifactEntry {
    pub op_index: u64,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub capability: Option<String>,
    pub obligation_id: String,
    #[serde(default)]
    pub decision_contract_id: String,
    #[serde(default)]
    pub requires_operator_approval: bool,
    #[serde(default)]
    pub receipt_linkage_required: bool,
    #[serde(default)]
    pub replay_command_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeCheckpointArtifactEntry {
    pub op_index: u64,
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
}

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
    message_template: &str,
    span: Option<SourceSpan>,
) -> LoweringPipelineError {
    LoweringPipelineError::UnsupportedSyntax(Box::new(UnsupportedSyntaxDiagnostic {
        schema_version: UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.to_string(),
        taxonomy_version: PARSER_DIAGNOSTIC_TAXONOMY_VERSION.to_string(),
        hash_algorithm: PARSER_DIAGNOSTIC_HASH_ALGORITHM.to_string(),
        hash_prefix: PARSER_DIAGNOSTIC_HASH_PREFIX.to_string(),
        parse_error_code: ParseErrorCode::UnsupportedSyntax,
        diagnostic_code: "FE-LOWER-OPTIONAL-CHAIN-0001".to_string(),
        category: ParseDiagnosticCategory::Syntax,
        severity: ParseDiagnosticSeverity::Error,
        message_template: message_template.to_string(),
        source_label: "ir0".to_string(),
        span,
        site_id: "lower_ir0_to_ir1.optional_chaining_frontier".to_string(),
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
                if let Some(binding_name) = &import.binding {
                    if let Some(existing_kind) = seen_bindings.get(binding_name) {
                        let conflict = check_binding_conflict(*existing_kind, BindingKind::Import);
                        if let BindingConflict::Error(code) = conflict {
                            result.add_error(SemanticError::new(
                                code,
                                Some(binding_name.clone()),
                                Some(import.span.clone()),
                            ));
                        }
                    }
                    seen_bindings.insert(binding_name.clone(), BindingKind::Import);
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
            | Statement::FunctionDeclaration(_) => {
                // Control flow and function declarations: static semantic
                // analysis for these is handled recursively as needed.
            }
        }
    }

    result
}

pub fn lower_ir0_to_ir1(
    ir0: &Ir0Module,
) -> Result<LoweringPassResult<Ir1Module>, LoweringPipelineError> {
    if ir0.tree.body.is_empty() {
        return Err(LoweringPipelineError::EmptyIr0Body);
    }

    let ir0_hash = ir0.content_hash();
    let mut ir1 = Ir1Module::new(ir0_hash.clone(), ir0.header.source_label.clone());
    let mut binding_index = 0u32;
    let root_scope_id = ScopeId { depth: 0, index: 0 };
    let root_scope_kind = match ir0.tree.goal {
        ParseGoal::Script => ScopeKind::Global,
        ParseGoal::Module => ScopeKind::Module,
    };
    let mut bindings = Vec::<ResolvedBinding>::new();
    let mut binding_lookup = BTreeMap::<String, BindingId>::new();
    let declared_root_bindings =
        reserve_root_scope_bindings(&ir0.tree.body, &mut binding_lookup, &mut binding_index);
    let mut synthetic_export_index = 0u32;
    let mut label_counter = 0u32;

    for statement in &ir0.tree.body {
        match statement {
            Statement::Import(import) => {
                ir1.ops.push(Ir1Op::ImportModule {
                    specifier: import.source.clone(),
                });
                if let Some(binding_name) = &import.binding {
                    let binding_id = alloc_binding(
                        &mut bindings,
                        &mut binding_lookup,
                        &mut binding_index,
                        root_scope_id,
                        binding_name,
                        BindingKind::Import,
                    )
                    .map_err(LoweringPipelineError::SemanticViolation)?;
                    ir1.ops.push(Ir1Op::StoreBinding { binding_id });
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
                }
                ExportKind::NamedClause(clause) => {
                    for (local_name, exported_name) in parse_named_export_clause_bindings(clause) {
                        if !declared_root_bindings.contains(local_name.as_str()) {
                            return Err(LoweringPipelineError::SemanticViolation(
                                SemanticError::new(
                                    SemanticErrorCode::UndeclaredExportBinding,
                                    Some(local_name.clone()),
                                    Some(export.span.clone()),
                                ),
                            ));
                        }
                        let binding_id = binding_lookup.get(local_name.as_str()).copied().ok_or(
                            LoweringPipelineError::InvariantViolation {
                                detail: "reserved root binding missing from binding lookup",
                            },
                        )?;
                        ir1.ops.push(Ir1Op::ExportBinding {
                            name: exported_name,
                            binding_id,
                        });
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
    *counter = counter.saturating_add(1);
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
                if let Some(binding_name) = &import.binding {
                    reserve_binding_id(binding_lookup, binding_index, binding_name);
                    declared.insert(binding_name.clone());
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
            _ => {}
        }
    }

    declared
}

fn parse_named_export_clause_bindings(clause: &str) -> Vec<(String, String)> {
    let trimmed = clause.trim();
    let local_clause = trimmed
        .split_once(" from ")
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

fn alloc_pattern_primary_binding(
    bindings: &mut Vec<ResolvedBinding>,
    binding_lookup: &mut BTreeMap<String, BindingId>,
    binding_index: &mut BindingId,
    scope_id: ScopeId,
    pattern: &BindingPattern,
    binding_kind: BindingKind,
) -> Result<BindingId, SemanticError> {
    let names = pattern.binding_names();
    let primary_name = names.first().copied().unwrap_or("_");
    let primary_binding = alloc_binding(
        bindings,
        binding_lookup,
        binding_index,
        scope_id,
        primary_name,
        binding_kind,
    )?;
    for extra_name in names.iter().skip(1) {
        let _ = alloc_binding(
            bindings,
            binding_lookup,
            binding_index,
            scope_id,
            extra_name,
            binding_kind,
        )?;
    }
    Ok(primary_binding)
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
                let bid = alloc_pattern_primary_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    &d.pattern,
                    binding_kind,
                )
                .map_err(LoweringPipelineError::SemanticViolation)?;
                if let Some(init) = &d.initializer {
                    lower_expression_to_ir1(
                        init,
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
                ops.push(Ir1Op::StoreBinding { binding_id: bid });
            }
        }
        Statement::Block(block) => {
            for inner in &block.body {
                lower_statement_to_ir1_with_flow(
                    inner,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    control_flow,
                )?;
            }
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
        }
        Statement::ForIn(for_in_stmt) => {
            return Err(unsupported_syntax_error(
                ParserGapSiteId::ForInStatementPlaceholder,
                Some(for_in_stmt.span.clone()),
            ));
        }
        Statement::ForOf(for_of_stmt) => {
            return Err(unsupported_syntax_error(
                ParserGapSiteId::ForOfStatementPlaceholder,
                Some(for_of_stmt.span.clone()),
            ));
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
            let catch_label = alloc_label(label_counter);
            let end_label = alloc_label(label_counter);
            ops.push(Ir1Op::BeginTry { catch_label });
            for inner in &tc.block.body {
                lower_statement_to_ir1_with_flow(
                    inner,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    scope_id,
                    label_counter,
                    control_flow,
                )?;
            }
            ops.push(Ir1Op::EndTry);
            ops.push(Ir1Op::Jump {
                label_id: end_label,
            });
            ops.push(Ir1Op::Label { id: catch_label });
            if let Some(handler) = &tc.handler {
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
                        control_flow,
                    )?;
                }
            }
            ops.push(Ir1Op::Label { id: end_label });
            if let Some(finalizer) = &tc.finalizer {
                for inner in &finalizer.body {
                    lower_statement_to_ir1_with_flow(
                        inner,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        scope_id,
                        label_counter,
                        control_flow,
                    )?;
                }
            }
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
            ops.push(Ir1Op::DeclareFunction {
                name,
                binding_id: bid,
            });
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
}

fn binding_kind_for_variable_declaration(kind: VariableDeclarationKind) -> BindingKind {
    match kind {
        VariableDeclarationKind::Var => BindingKind::Var,
        VariableDeclarationKind::Let => BindingKind::Let,
        VariableDeclarationKind::Const => BindingKind::Const,
    }
}

pub fn lower_ir1_to_ir2(
    ir1: &Ir1Module,
) -> Result<LoweringPassResult<Ir2Module>, LoweringPipelineError> {
    let ir1_hash = ir1.content_hash();
    let mut ir2 = Ir2Module::new(ir1_hash.clone(), ir1.header.source_label.clone());
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
    ir2.required_capabilities = required_capabilities
        .into_iter()
        .map(CapabilityTag)
        .collect();
    let flow_metrics = infer_ir2_flow_annotations(&mut ir2);

    let source_hash_matches = ir2.header.source_hash.as_ref() == Some(&ir1_hash);
    let hostcall_effects_have_capability = ir2
        .ops
        .iter()
        .filter(|op| matches!(op.effect, EffectBoundary::HostcallEffect))
        .all(|op| op.required_capability.is_some());
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

pub fn lower_ir2_to_ir3(
    ir2: &Ir2Module,
) -> Result<LoweringPassResult<Ir3Module>, LoweringPipelineError> {
    enum PendingJump {
        Unconditional {
            instruction_index: usize,
            label_id: u32,
        },
        JumpIfFalsy {
            truthy_skip_index: usize,
            falsy_jump_index: usize,
            label_id: u32,
        },
    }

    let ir2_hash = ir2.content_hash();
    let mut ir3 = Ir3Module::new(ir2_hash.clone(), ir2.header.source_label.clone());
    let mut register_cursor: Reg = 0;
    let mut binding_registers = BTreeMap::<BindingId, Reg>::new();
    let mut required_capabilities = BTreeSet::<String>::new();
    let mut value_stack: Vec<Reg> = Vec::new();
    let mut label_targets = BTreeMap::<u32, u32>::new();
    let mut pending_jumps = Vec::<PendingJump>::new();

    for op in &ir2.ops {
        if matches!(op.effect, EffectBoundary::HostcallEffect) {
            let capability = op
                .required_capability
                .clone()
                .unwrap_or_else(|| CapabilityTag("hostcall.invoke".to_string()));
            
            // Reconstruct logic for HostCall intercept
            // If it's a Call, we should pop args. If not, we just pop 1 as a fallback.
            let (start_reg, arg_count) = if let Ir1Op::Call { arg_count } = &op.inner {
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
                    ir3.instructions.push(Ir3Instruction::Move { dst, src: arg_reg });
                }
                (start, count)
            } else {
                let hostcall_arg = value_stack.pop().unwrap_or(0);
                let start = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::Move { dst: start, src: hostcall_arg });
                (start, 1)
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
            Ir1Op::StoreBinding { binding_id } => {
                let dst = *binding_registers
                    .entry(*binding_id)
                    .or_insert_with(|| alloc_register(&mut register_cursor));
                let src = value_stack.pop().unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Move { dst, src });
                value_stack.push(dst);
            }
            Ir1Op::Call { arg_count } => {
                let mut args = Vec::new();
                for _ in 0..*arg_count {
                    args.push(value_stack.pop().unwrap_or(0));
                }
                args.reverse();
                let callee = value_stack.pop().unwrap_or(0);
                
                let start_reg = register_cursor;
                for arg_reg in args {
                    let dst = alloc_register(&mut register_cursor);
                    ir3.instructions.push(Ir3Instruction::Move { dst, src: arg_reg });
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
            Ir1Op::ImportModule { specifier } => {
                let string_reg = alloc_register(&mut register_cursor);
                let pool_index = push_constant(&mut ir3.constant_pool, specifier);
                ir3.instructions.push(Ir3Instruction::LoadStr {
                    dst: string_reg,
                    pool_index,
                });
                value_stack.push(string_reg);
            }
            Ir1Op::ExportBinding { .. } => {
                let register = value_stack.pop().unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Move {
                    dst: register,
                    src: register,
                });
                value_stack.push(register);
            }
            Ir1Op::Await => {
                let current = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions
                    .push(Ir3Instruction::Move { dst, src: current });
                value_stack.push(dst);
            }
            Ir1Op::Return => {
                let value = value_stack.pop().unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Return { value });
            }
            Ir1Op::Nop | Ir1Op::Pop | Ir1Op::BeginTry { .. } | Ir1Op::EndTry => {
                let register = value_stack.pop().unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Move {
                    dst: register,
                    src: register,
                });
                if matches!(op.inner, Ir1Op::Nop | Ir1Op::BeginTry { .. } | Ir1Op::EndTry) {
                    value_stack.push(register);
                }
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
                    _ => {
                        Ir3Instruction::Add { dst, lhs, rhs }
                    }
                };
                ir3.instructions.push(instr);
                value_stack.push(dst);
            }
            Ir1Op::UnaryOp { .. } => {
                let src = value_stack.pop().unwrap_or(0);
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::Move { dst, src });
                value_stack.push(dst);
            }
            Ir1Op::AssignOp { binding_id, .. } => {
                let dst = *binding_registers
                    .entry(*binding_id)
                    .or_insert_with(|| alloc_register(&mut register_cursor));
                let src = value_stack.pop().unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Move { dst, src });
                value_stack.push(dst);
            }
            Ir1Op::Label { id } => {
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
            Ir1Op::GetProperty { key } => {
                let obj = value_stack.pop().unwrap_or(0);
                let key_reg = alloc_register(&mut register_cursor);
                let pool_index = push_constant(&mut ir3.constant_pool, key);
                ir3.instructions.push(Ir3Instruction::LoadStr {
                    dst: key_reg,
                    pool_index,
                });
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
                let obj = value_stack.pop().unwrap_or(0);
                let key_reg = alloc_register(&mut register_cursor);
                let pool_index = push_constant(&mut ir3.constant_pool, key);
                ir3.instructions.push(Ir3Instruction::LoadStr {
                    dst: key_reg,
                    pool_index,
                });
                ir3.instructions.push(Ir3Instruction::SetProperty {
                    obj,
                    key: key_reg,
                    val,
                });
                value_stack.push(val);
            }
            Ir1Op::NewArray { count } => {
                let mut elements = Vec::new();
                for _ in 0..*count {
                    elements.push(value_stack.pop().unwrap_or(0));
                }
                elements.reverse();
                
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::NewArray { dst });
                
                for (i, val_reg) in elements.into_iter().enumerate() {
                    let key_str = i.to_string();
                    let key_reg = alloc_register(&mut register_cursor);
                    let pool_index = push_constant(&mut ir3.constant_pool, key_str);
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
                let mut properties = Vec::new();
                for _ in 0..*count {
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
            Ir1Op::Throw => {
                let value = value_stack.pop().unwrap_or(0);
                ir3.instructions.push(Ir3Instruction::Return { value });
            }
            Ir1Op::LoadThis => {
                let dst = alloc_register(&mut register_cursor);
                ir3.instructions.push(Ir3Instruction::LoadUndefined { dst });
                value_stack.push(dst);
            }
            Ir1Op::DeclareFunction { binding_id, name } => {
                let dst = *binding_registers
                    .entry(*binding_id)
                    .or_insert_with(|| alloc_register(&mut register_cursor));
                let pool_index = push_constant(&mut ir3.constant_pool, name);
                ir3.instructions
                    .push(Ir3Instruction::LoadStr { dst, pool_index });
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
    });
    ir3.required_capabilities = required_capabilities
        .into_iter()
        .map(CapabilityTag)
        .collect();

    verify_ir3_specialization(&ir3).map_err(lowering_error_from_ir_error)?;

    let source_hash_matches = ir3.header.source_hash.as_ref() == Some(&ir2_hash);
    let has_main_function = !ir3.function_table.is_empty();
    let has_terminal_halt = matches!(ir3.instructions.last(), Some(Ir3Instruction::Halt));
    let instruction_len = ir3.instructions.len();
    let control_flow_targets_resolved =
        ir3.instructions
            .iter()
            .all(|instruction| match instruction {
                Ir3Instruction::Jump { target } | Ir3Instruction::JumpIf { target, .. } => {
                    (*target as usize) < instruction_len
                }
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
    let mut lattice = Ir2FlowLattice::new(context.policy_id.clone());
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

    for (op_index, op) in ir2.ops.iter().enumerate() {
        let Some(flow) = op.flow.as_ref() else {
            continue;
        };
        let op_index_u64 = op_index as u64;
        let source_label = flow.data_label.clone();
        let sink_clearance_label = flow.sink_clearance.clone();
        let source_class = LabelClass::from_label(&source_label);
        let sink_clearance = sink_label_to_clearance(&sink_clearance_label);
        let capability = op.required_capability.as_ref().map(|cap| cap.0.clone());

        if flow.declassification_required
            && let Some(required_capability) = op.required_capability.as_ref()
            && flow_capability_supports_declassification(required_capability)
        {
            let obligation_id = format!("declass-op-{op_index}");
            if !lattice.obligations().contains_key(&obligation_id) {
                lattice
                    .register_obligation(DeclassificationObligation {
                        obligation_id,
                        source_label: source_class.clone(),
                        target_clearance: sink_clearance.clone(),
                        decision_contract_id: context.decision_id.clone(),
                        requires_operator_approval: true,
                        max_uses: 0,
                        use_count: 0,
                    })
                    .map_err(|err| LoweringPipelineError::FlowLatticeFailure {
                        detail: err.to_string(),
                    })?;
            }
        }

        if let Some(required_capability) = op.required_capability.as_ref()
            && flow_requires_runtime_checkpoint(Some(flow), required_capability)
        {
            artifact
                .runtime_checkpoints
                .push(RuntimeCheckpointArtifactEntry {
                    op_index: op_index_u64,
                    source_label,
                    sink_clearance: sink_clearance_label,
                    capability,
                    reason: runtime_checkpoint_reason(flow, required_capability),
                });
            continue;
        }

        match lattice.check_flow(&source_class, &sink_clearance, &context.trace_id) {
            LatticeFlowCheckResult::LegalByLattice => {
                artifact.proved_flows.push(FlowProofArtifactEntry {
                    op_index: op_index_u64,
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
                        source_label,
                        sink_clearance: sink_clearance_label,
                        capability,
                        obligation_id,
                        decision_contract_id: obligation.decision_contract_id.clone(),
                        requires_operator_approval: obligation.requires_operator_approval,
                        receipt_linkage_required: true,
                        replay_command_hint: format!(
                            "frankenctl replay run --trace {} --obligation {}",
                            context.trace_id, obligation.obligation_id
                        ),
                    });
            }
            LatticeFlowCheckResult::Blocked { .. } => {
                artifact.denied_flows.push(DeniedFlowArtifactEntry {
                    op_index: op_index_u64,
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
    let encoded = serde_json::to_vec(&preimage).unwrap_or_default();
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
        Expression::Raw(raw) => {
            ops.push(Ir1Op::LoadLiteral {
                value: Ir1Literal::String(raw.clone()),
            });
            if raw.contains('(') {
                ops.push(Ir1Op::Call { arg_count: 0 });
            }
        }
        Expression::Binary {
            operator,
            left,
            right,
        } => {
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
        Expression::Assignment {
            operator,
            left,
            right,
        } => {
            if let Expression::Identifier(name) = left.as_ref() {
                lower_expression_to_ir1(
                    right,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
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
                ops.push(Ir1Op::AssignOp {
                    binding_id,
                    operator: *operator,
                });
            } else if let Expression::Member { object, property, computed: _ } = left.as_ref() {
                lower_expression_to_ir1(
                    object,
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
                let key = match property.as_ref() {
                    Expression::Identifier(name) => name.clone(),
                    Expression::StringLiteral(s) => s.clone(),
                    _ => "unknown".to_string(),
                };
                ops.push(Ir1Op::SetProperty { key });
            } else {
                lower_expression_to_ir1(
                    right,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
                ops.push(Ir1Op::Nop);
            }
        }
        Expression::Conditional {
            test,
            consequent,
            alternate,
        } => {
            // Ternaries must preserve branch selection; lowering both arms eagerly
            // changes side effects and discards the consequent value.
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
            lower_expression_to_ir1(
                consequent,
                ops,
                bindings,
                binding_lookup,
                binding_index,
                root_scope_id,
                label_counter,
            )?;
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
            ops.push(Ir1Op::Label { id: end_label });
        }
        Expression::Call { callee, arguments } => {
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
        Expression::Member {
            object,
            property,
            computed: _,
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
            // Extract property key as string.
            let key = match property.as_ref() {
                Expression::Identifier(name) => name.clone(),
                Expression::StringLiteral(s) => s.clone(),
                _ => "unknown".to_string(),
            };
            ops.push(Ir1Op::GetProperty { key });
        }
        Expression::OptionalCall { .. } | Expression::OptionalMember { .. } => {
            return Err(unsupported_frontier_expression_error(
                "optional_chaining",
                "optional chaining lowering is not implemented; fail-closed frontier contract rejected the expression",
                None,
            ));
        }
        Expression::This => {
            ops.push(Ir1Op::LoadThis);
        }
        Expression::ArrayLiteral(elements) => {
            for elem in elements.iter().flatten() {
                lower_expression_to_ir1(
                    elem,
                    ops,
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    label_counter,
                )?;
            }
            ops.push(Ir1Op::NewArray {
                count: elements.len() as u32,
            });
        }
        Expression::ObjectLiteral(properties) => {
            for prop in properties {
                // Extract key as string from the key expression.
                let key_str = match &prop.key {
                    Expression::Identifier(name) => name.clone(),
                    Expression::StringLiteral(s) => s.clone(),
                    other => format!("{other:?}"),
                };
                ops.push(Ir1Op::LoadLiteral {
                    value: Ir1Literal::String(key_str),
                });
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
        Expression::ArrowFunction { params, body, .. } => {
            for param in params {
                let _binding_id = alloc_binding(
                    bindings,
                    binding_lookup,
                    binding_index,
                    root_scope_id,
                    param
                        .pattern
                        .binding_names()
                        .first()
                        .copied()
                        .unwrap_or("_"),
                    BindingKind::Let,
                )
                .map_err(LoweringPipelineError::SemanticViolation)?;
            }
            match body {
                ArrowBody::Expression(expr) => {
                    lower_expression_to_ir1(
                        expr,
                        ops,
                        bindings,
                        binding_lookup,
                        binding_index,
                        root_scope_id,
                        label_counter,
                    )?;
                }
                ArrowBody::Block(block) => {
                    for stmt in &block.body {
                        lower_statement_to_ir1(
                            stmt,
                            ops,
                            bindings,
                            binding_lookup,
                            binding_index,
                            root_scope_id,
                            label_counter,
                        )?;
                    }
                }
            }
            ops.push(Ir1Op::Return);
        }
        Expression::New { callee, arguments } => {
            let _ = (callee, arguments);
            return Err(unsupported_syntax_error(
                ParserGapSiteId::NewExpressionCallPlaceholder,
                None,
            ));
        }
        Expression::TemplateLiteral {
            quasis,
            expressions,
        } => {
            let _ = (quasis, expressions);
            return Err(unsupported_syntax_error(
                ParserGapSiteId::TemplateLiteralRawPlaceholder,
                None,
            ));
        }
    }
    Ok(())
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
        Ir1Op::Call { .. } => (
            EffectBoundary::HostcallEffect,
            Some(CapabilityTag("hostcall.invoke".to_string())),
            Some(FlowAnnotation {
                data_label: Label::Confidential,
                sink_clearance: Label::Confidential,
                declassification_required: false,
            }),
        ),
        Ir1Op::Await => (
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
        Ir1Op::Throw | Ir1Op::BeginTry { .. } | Ir1Op::EndTry => (
            EffectBoundary::ReadEffect,
            None,
            Some(FlowAnnotation {
                data_label: Label::Internal,
                sink_clearance: Label::Internal,
                declassification_required: false,
            }),
        ),
        Ir1Op::GetProperty { .. } | Ir1Op::SetProperty { .. } => {
            (EffectBoundary::ReadEffect, None, None)
        }
        _ => (EffectBoundary::Pure, None, None),
    }
}

fn infer_ir2_flow_annotations(ir2: &mut Ir2Module) -> FlowInferenceMetrics {
    let mut binding_labels = BTreeMap::<BindingId, Label>::new();
    let mut last_label = Label::Public;
    let mut metrics = FlowInferenceMetrics {
        total_flow_ops: 0,
        static_proven_ops: 0,
        runtime_check_ops: 0,
    };

    for op in &mut ir2.ops {
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
        Ir1Op::ImportModule { .. } | Ir1Op::Await => Label::Internal,
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
    let marker = "hostcall<\"";
    let start = raw.find(marker)?;
    let remainder = &raw[start + marker.len()..];
    let end = remainder.find("\">")?;
    let capability = remainder[..end].trim();
    if capability.is_empty() {
        None
    } else {
        Some(capability.to_string())
    }
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
        Ir1Literal::Boolean(value) => {
            instructions.push(Ir3Instruction::LoadBool { dst, value: *value })
        }
        Ir1Literal::Null => instructions.push(Ir3Instruction::LoadNull { dst }),
        Ir1Literal::Undefined => instructions.push(Ir3Instruction::LoadUndefined { dst }),
    }
}

fn push_constant(pool: &mut Vec<String>, value: &str) -> u32 {
    if let Some(index) = pool.iter().position(|entry| entry == value) {
        return index as u32;
    }

    pool.push(value.to_string());
    (pool.len() - 1) as u32
}

fn alloc_register(cursor: &mut Reg) -> Reg {
    let register = *cursor;
    *cursor = cursor.saturating_add(1);
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
        FunctionDeclaration, FunctionParam, IfStatement, ImportDeclaration, ObjectPatternProperty,
        ObjectProperty, ParseGoal, ReturnStatement, SourceSpan, Statement, SwitchCase,
        SwitchStatement, SyntaxTree, ThrowStatement, TryCatchStatement, UnaryOperator,
        VariableDeclaration, VariableDeclarationKind, VariableDeclarator, WhileStatement,
    };
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

        assert!(matches!(
            ir3.instructions.get(1),
            Some(Ir3Instruction::JumpIf { cond: 0, target: 3 })
        ));
        assert!(matches!(
            ir3.instructions.get(2),
            Some(Ir3Instruction::Jump { target: 5 })
        ));
        assert!(
            ir3.instructions
                .iter()
                .all(|instruction| match instruction {
                    Ir3Instruction::Jump { target } | Ir3Instruction::JumpIf { target, .. } => {
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
    fn lower_ir2_to_ir3_treats_begin_try_as_noop_until_ir3_support_exists() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"begin-try"), "begin_try.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::BeginTry { catch_label: 9 },
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
            inner: Ir1Op::Return,
            effect: EffectBoundary::Pure,
            required_capability: None,
            flow: None,
        });

        let ir3 = lower_ir2_to_ir3(&ir2)
            .expect("IR2->IR3 should preserve linear execution for try placeholders")
            .module;

        assert!(matches!(
            ir3.instructions.first(),
            Some(Ir3Instruction::Move { dst: 0, src: 0 })
        ));
        assert_eq!(
            ir3.instructions
                .iter()
                .filter(|instruction| {
                    matches!(
                        instruction,
                        Ir3Instruction::Jump { .. } | Ir3Instruction::JumpIf { .. }
                    )
                })
                .count(),
            0
        );
    }

    #[test]
    fn dynamic_hostcall_paths_insert_runtime_ifc_guard() {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"flow-ir0"), "dynamic_flow.js");
        ir1.ops.push(Ir1Op::LoadLiteral {
            value: Ir1Literal::String("secret_token".to_string()),
        });
        ir1.ops.push(Ir1Op::Call { arg_count: 1 });
        ir1.ops.push(Ir1Op::Return);

        let ir2 = lower_ir1_to_ir2(&ir1)
            .expect("IR1->IR2 should succeed")
            .module;
        let call_op = ir2
            .ops
            .iter()
            .find(|op| matches!(op.inner, Ir1Op::Call { .. }))
            .expect("call op");
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
        ir1.ops.push(Ir1Op::Call { arg_count: 1 });
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
            inner: Ir1Op::Call { arg_count: 1 },
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
        assert!(artifact.required_declassifications[0].requires_operator_approval);
        assert!(artifact.required_declassifications[0].receipt_linkage_required);
        assert_eq!(
            artifact.required_declassifications[0].replay_command_hint,
            "frankenctl replay run --trace trace-declass --obligation declass-op-0"
        );
    }

    #[test]
    fn ir2_flow_proof_artifact_rejects_unauthorized_static_flow() {
        let mut ir2 = Ir2Module::new(ContentHash::compute(b"ir1"), "denied_fixture.js");
        ir2.ops.push(Ir2Op {
            inner: Ir1Op::Call { arg_count: 1 },
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
            inner: Ir1Op::Call { arg_count: 1 },
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
        let first_json = serde_json::to_string(&first).expect("serialize first");
        let second_json = serde_json::to_string(&second).expect("serialize second");
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
    fn flow_inference_metrics_zero_ops_returns_million() {
        let metrics = FlowInferenceMetrics {
            total_flow_ops: 0,
            static_proven_ops: 0,
            runtime_check_ops: 0,
        };
        assert_eq!(metrics.static_coverage_millionths(), 1_000_000);
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
        assert_eq!(effect, EffectBoundary::HostcallEffect);
        assert!(cap.is_some());
        assert_eq!(cap.unwrap().0, "hostcall.invoke");
        assert!(flow.is_some());
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
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::Integer(1)
                },
                Ir1Op::StoreBinding {
                    binding_id: store_x_binding_id
                },
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
    fn lower_assignment_to_member_emits_nop() {
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
        assert!(result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
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
        assert!(!result.module.ops.iter().any(|op| matches!(op, Ir1Op::Pop)));
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
            Ir1Op::GetProperty { key } if key == "key"
        )));
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
        let return_count = result
            .module
            .ops
            .iter()
            .filter(|op| matches!(op, Ir1Op::Return))
            .count();
        assert!(return_count >= 2); // inner return + outer return
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
    fn lower_new_expression_fails_closed() {
        let ir0 = expr_ir0(Expression::New {
            callee: Box::new(Expression::Identifier("Foo".into())),
            arguments: vec![Expression::NumericLiteral(1)],
        });
        let err = lower_ir0_to_ir1(&ir0).expect_err("new must fail closed");
        assert!(matches!(
            err,
            LoweringPipelineError::UnsupportedSyntax(ref diagnostic)
                if diagnostic.site_id
                    == ParserGapSiteId::NewExpressionCallPlaceholder.as_str()
                && diagnostic.diagnostic_code
                    == ParserGapSiteId::NewExpressionCallPlaceholder.diagnostic_code()
        ));
    }

    #[test]
    fn lower_template_literal_fails_closed() {
        let ir0 = expr_ir0(Expression::TemplateLiteral {
            quasis: vec!["hello ".into(), " world".into()],
            expressions: vec![Expression::Identifier("name".into())],
        });
        let err = lower_ir0_to_ir1(&ir0).expect_err("template literal must fail closed");
        assert!(matches!(
            err,
            LoweringPipelineError::UnsupportedSyntax(ref diagnostic)
                if diagnostic.site_id
                    == ParserGapSiteId::TemplateLiteralRawPlaceholder.as_str()
                && diagnostic.diagnostic_code
                    == ParserGapSiteId::TemplateLiteralRawPlaceholder.diagnostic_code()
        ));
    }

    #[test]
    fn lower_member_assignment_currently_emits_nop_placeholder() {
        let ir0 = expr_ir0(Expression::Assignment {
            operator: AssignmentOperator::Assign,
            left: Box::new(Expression::Member {
                object: Box::new(Expression::Identifier("obj".into())),
                property: Box::new(Expression::Identifier("field".into())),
                computed: false,
            }),
            right: Box::new(Expression::NumericLiteral(7)),
        });
        let result = lower_ir0_to_ir1(&ir0).expect("member assignment currently lowers");
        assert!(result.module.ops.iter().any(|op| matches!(op, Ir1Op::Nop)));
    }

    #[test]
    fn lower_non_arithmetic_binary_currently_collapses_to_add_placeholder() {
        let ir0 = expr_ir0(Expression::Binary {
            operator: BinaryOperator::LessThan,
            left: Box::new(Expression::NumericLiteral(1)),
            right: Box::new(Expression::NumericLiteral(2)),
        });
        let ctx = LoweringContext::new("trace-gap", "decision-gap", "policy-gap");
        let output = lower_ir0_to_ir3(&ir0, &ctx).expect("comparison currently lowers");
        assert!(output.ir3.instructions.iter().any(|instruction| matches!(
            instruction,
            crate::ir_contract::Ir3Instruction::Add { .. }
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
    fn lower_for_in_statement_fails_closed() {
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
        let err = lower_ir0_to_ir1(&ir0).expect_err("for-in must fail closed");
        assert!(matches!(
            err,
            LoweringPipelineError::UnsupportedSyntax(ref diagnostic)
                if diagnostic.site_id
                    == ParserGapSiteId::ForInStatementPlaceholder.as_str()
                && diagnostic.diagnostic_code
                    == ParserGapSiteId::ForInStatementPlaceholder.diagnostic_code()
                && diagnostic.span == Some(span())
        ));
    }

    #[test]
    fn lower_for_of_statement_fails_closed() {
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
        let err = lower_ir0_to_ir1(&ir0).expect_err("for-of must fail closed");
        assert!(matches!(
            err,
            LoweringPipelineError::UnsupportedSyntax(ref diagnostic)
                if diagnostic.site_id
                    == ParserGapSiteId::ForOfStatementPlaceholder.as_str()
                && diagnostic.diagnostic_code
                    == ParserGapSiteId::ForOfStatementPlaceholder.diagnostic_code()
                && diagnostic.span == Some(span())
        ));
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
    fn for_in_without_binding_kind_fails_closed() {
        let ir0 = stmt_ir0(vec![Statement::ForIn(ForInStatement {
            binding: BindingPattern::Identifier("k".into()),
            binding_kind: None,
            object: Expression::Identifier("obj".into()),
            body: Box::new(Statement::Expression(ExpressionStatement {
                expression: Expression::NumericLiteral(1),
                span: span(),
            })),
            span: span(),
        })]);
        let err = lower_ir0_to_ir1(&ir0).expect_err("for-in default binding must fail closed");
        assert!(matches!(
            err,
            LoweringPipelineError::UnsupportedSyntax(ref diagnostic)
                if diagnostic.site_id
                    == ParserGapSiteId::ForInStatementPlaceholder.as_str()
        ));
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
    fn classify_ir1_op_call_is_hostcall() {
        let (boundary, cap, _flow) = classify_ir1_op(&Ir1Op::Call { arg_count: 1 });
        assert_eq!(boundary, EffectBoundary::HostcallEffect);
        assert!(cap.is_some());
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
            source_label: Label::Confidential,
            sink_clearance: Label::Public,
            capability: Some("ifc.declassify".to_string()),
            obligation_id: "obl-42".to_string(),
            decision_contract_id: "decision-42".to_string(),
            requires_operator_approval: true,
            receipt_linkage_required: true,
            replay_command_hint: "frankenctl replay run --trace trace-42 --obligation obl-42"
                .to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: RequiredDeclassificationArtifactEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn runtime_checkpoint_artifact_entry_serde_roundtrip() {
        let entry = RuntimeCheckpointArtifactEntry {
            op_index: 9,
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
        assert!(display.contains("lattice merge diverged"));
        assert!(display.contains("flow lattice"));
    }

    #[test]
    fn lowering_pipeline_error_display_unauthorized_flow() {
        let err = LoweringPipelineError::UnauthorizedFlow {
            op_index: 42,
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            detail: "no route".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("42"));
        assert!(display.contains("no route"));
        assert!(display.contains("unauthorized flow"));
    }

    #[test]
    fn lowering_pipeline_error_display_semantic_violation() {
        let err = LoweringPipelineError::SemanticViolation(SemanticError::new(
            SemanticErrorCode::ConstWithoutInitializer,
            Some("x".to_string()),
            None,
        ));
        let display = err.to_string();
        assert!(display.contains("static semantics violation"));
    }

    #[test]
    fn lowering_event_without_error_code_serde() {
        let event = LoweringEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "lowering_pipeline".to_string(),
            event: "success_event".to_string(),
            outcome: "pass".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let parsed: LoweringEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
        assert!(json.contains("null"));
    }

    #[test]
    fn invariant_check_failed_serde() {
        let check = InvariantCheck {
            name: "binding_uniqueness".to_string(),
            passed: false,
            detail: "duplicate binding ID 3 in scope 0".to_string(),
        };
        let json = serde_json::to_string(&check).unwrap();
        let parsed: InvariantCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, parsed);
        assert!(!parsed.passed);
    }

    #[test]
    fn classify_ir1_op_get_property_is_read_effect() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::GetProperty {
            key: "length".to_string(),
        });
        assert_eq!(boundary, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_ir1_op_set_property_is_read_effect() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::SetProperty {
            key: "x".to_string(),
        });
        assert_eq!(boundary, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn classify_ir1_op_begin_try_is_read_effect() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::BeginTry { catch_label: 0 });
        assert_eq!(boundary, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
        assert!(flow.is_some());
    }

    #[test]
    fn classify_ir1_op_end_try_is_read_effect() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::EndTry);
        assert_eq!(boundary, EffectBoundary::ReadEffect);
        assert!(cap.is_none());
        assert!(flow.is_some());
    }

    #[test]
    fn classify_ir1_op_import_module_has_flow_annotation() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::ImportModule {
            specifier: "fs".to_string(),
        });
        assert_eq!(boundary, EffectBoundary::ReadEffect);
        assert_eq!(cap.unwrap().0, "module.import");
        let annotation = flow.unwrap();
        assert_eq!(annotation.data_label, Label::Internal);
        assert_eq!(annotation.sink_clearance, Label::Internal);
        assert!(!annotation.declassification_required);
    }

    #[test]
    fn classify_ir1_op_load_literal_hostcall_string() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hostcall<\"fs.read\">".to_string()),
        });
        assert_eq!(boundary, EffectBoundary::HostcallEffect);
        assert_eq!(cap.unwrap().0, "fs.read");
        let annotation = flow.unwrap();
        assert_eq!(annotation.data_label, Label::Confidential);
    }

    #[test]
    fn classify_ir1_op_load_literal_plain_string_is_pure() {
        let (boundary, cap, flow) = classify_ir1_op(&Ir1Op::LoadLiteral {
            value: Ir1Literal::String("hello world".to_string()),
        });
        assert_eq!(boundary, EffectBoundary::Pure);
        assert!(cap.is_none());
        assert!(flow.is_none());
    }

    #[test]
    fn flow_requires_runtime_checkpoint_dynamic_capability() {
        let cap = CapabilityTag("hostcall.invoke".to_string());
        assert!(flow_requires_runtime_checkpoint(None, &cap));
    }

    #[test]
    fn flow_requires_runtime_checkpoint_custom_data_label() {
        let flow = FlowAnnotation {
            data_label: Label::Custom {
                name: "pii".to_string(),
                level: 2,
            },
            sink_clearance: Label::Public,
            declassification_required: false,
        };
        let cap = CapabilityTag("ifc.check_flow".to_string());
        assert!(flow_requires_runtime_checkpoint(Some(&flow), &cap));
    }

    #[test]
    fn flow_requires_runtime_checkpoint_custom_sink() {
        let flow = FlowAnnotation {
            data_label: Label::Public,
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
}
