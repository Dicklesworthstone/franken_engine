#![forbid(unsafe_code)]

extern crate self as frankenengine_engine;

pub mod activation_lifecycle;
pub mod adversarial_campaign;
pub mod adversarial_coevolution_harness;
pub mod alloc_domain;
pub mod ambient_authority;
pub mod anti_entropy;
pub mod assumptions_ledger;
pub mod ast;
pub mod attack_surface_game_model;
pub mod attestation_handshake;
pub mod attested_execution_cell;
pub mod baseline_interpreter;
pub mod bayesian_error_recovery;
pub mod bayesian_posterior;
pub mod benchmark_denominator;
pub mod benchmark_e2e;
pub mod bifurcation_boundary_scanner;
pub mod budgeted_optimization;
pub mod bulkhead;
pub mod bytecode_vm;
pub mod cancel_mask;
pub mod cancellation_lifecycle;
pub mod canonical_encoding;
pub mod canonical_evidence_emitter;
pub mod capability;
pub mod capability_token;
pub mod capability_witness;
pub mod catastrophic_tail_tournament_gate;
pub mod causal_regret_evidence_gate;
pub mod causal_replay;
pub mod checkpoint;
pub mod checkpoint_frontier;
pub mod closure_model;
pub mod compiler_policy;
pub mod conformance_catalog;
pub mod conformance_harness;
pub mod conformance_vector_gen;
pub mod constrained_ambient_benchmark_lane;
pub mod containment_executor;
pub mod control_plane;
pub mod control_plane_benchmark_split_gate;
pub mod controller_composition_matrix;
pub mod controller_interference_guard;
pub mod counterexample_synthesizer;
pub mod counterfactual_evaluator;
pub mod counterfactual_replay_engine;
pub mod cross_repo_contract;
pub mod cut_line_automation;
pub mod cx_threading;
pub mod declassification_pipeline;
pub mod delegate_cell_harness;
pub mod delegation_chain;
pub mod demo_claim_linkage_gate;
pub mod demotion_rollback;
pub mod deterministic_replay;
pub mod deterministic_serde;
pub mod disruption_scorecard;
pub mod dp_budget_accountant;
pub mod dual_backend_parser;
pub mod e2e_harness;
pub mod engine_object_id;
pub mod entropy_evidence_compressor;
pub mod epoch_barrier;
pub mod epoch_invalidation;
pub mod eprocess_guardrail;
pub mod error_code;
pub mod esm_loader;
pub mod evidence_contract;
pub mod evidence_emission;
pub mod evidence_ledger;
pub mod evidence_ordering;
pub mod evidence_replay_checker;
pub mod execution_cell;
pub mod execution_orchestrator;
pub mod expected_loss_selector;
pub mod extension_host_authority_guard;
pub mod extension_host_lifecycle;
pub mod extension_lifecycle_manager;
pub mod extension_registry;
pub mod feature_parity_tracker;
pub mod flamegraph_pipeline;
pub mod fleet_convergence;
pub mod fleet_immune_protocol;
pub mod flow_envelope;
pub mod flow_lattice;
pub mod forensic_replayer;
pub mod fork_detection;
pub mod frankenlab_extension_lifecycle;
pub mod frankenlab_release_gate;
pub mod frankentui_adapter;
pub mod frir_schema;
pub mod frontier_demo_gate;
pub mod frx_lockstep_oracle;
pub mod galaxy_brain_explainability;
pub mod gc;
pub mod gc_pause;
pub mod global_coherence_checker;
pub mod golden_vectors;
pub mod governance_hooks;
pub mod governance_mechanism;
pub mod governance_scorecard;
pub mod guardplane_calibration;
pub mod hash_tiers;
pub mod hook_effect_contract;
pub mod hostcall_telemetry;
pub mod hybrid_lane_router;
pub mod idempotency_key;
pub mod ifc_artifacts;
pub mod ifc_provenance_index;
pub mod incentive_governance_mechanism;
pub mod incident_replay_bundle;
pub mod interleaving_explorer;
pub mod ir_contract;
pub mod js_runtime_lane;
pub mod key_attestation;
pub mod key_derivation;
pub mod lab_runtime;
pub mod lease_tracker;
pub mod lowering_gap_inventory;
pub mod lowering_pipeline;
pub mod marker_stream;
pub mod migration_compatibility;
pub mod migration_contract;
pub mod migration_kit;
pub mod milestone_release_test_evidence_integrator;
pub mod mmr_proof;
pub mod module_cache;
pub mod module_compatibility_matrix;
pub mod module_resolver;
pub mod monitor_scheduler;
pub mod moonshot_contract;
pub mod northstar_scorecard;
pub mod npm_compatibility_matrix;
pub mod object_model;
pub mod obligation_channel;
pub mod obligation_integration;
pub mod obligation_leak_policy;
pub mod observability_channel_model;
pub mod observability_probe_design;
pub mod observability_quality_sentinel;
pub mod obstruction_certificate;
pub mod offline_synthesis_pipeline;
pub mod one_lever_policy;
pub mod opportunity_matrix;
pub mod optimal_stopping;
pub mod optimization_baseline;
pub mod parallel_interference_gate;
pub mod parallel_parser;
pub mod parser;
pub mod parser_api_stability;
pub mod parser_arena;
pub mod parser_error_recovery;
pub mod parser_evidence_indexer;
pub mod parser_gap_inventory;
pub mod parser_multi_engine_harness;
pub mod parser_oracle;
pub mod performance_regression_gate;
pub mod performance_statistical_validation;
pub mod phase_gate;
pub mod plas_benchmark_bundle;
pub mod plas_burn_in_gate;
pub mod plas_lockstep;
pub mod plas_release_gate;
pub mod policy_as_data_security;
pub mod policy_checkpoint;
pub mod policy_controller;
pub mod policy_theorem_compiler;
pub mod portfolio_governor;
pub mod primitive_adoption_schema;
pub mod principal_key_roles;
pub mod privacy_learning_contract;
pub mod promise_model;
pub mod promotion_gate_runner;
pub mod proof_ingestion;
pub mod proof_obligations;
pub mod proof_release_gate;
pub mod proof_schema;
pub mod proof_specialization_linkage;
pub mod proof_specialization_receipt;
pub mod quarantine_mesh_gate;
pub mod receipt_verifier_pipeline;
pub mod recovery_artifact;
pub mod regime_detector;
pub mod region_lifecycle;
pub mod regret_bounded_router;
pub mod release_checklist_gate;
pub mod release_gate;
pub mod remote_capability_gate;
pub mod remote_computation_registry;
pub mod replacement_lineage_log;
pub mod reproducibility_provenance_pack;
pub mod reputation;
pub mod revocation_chain;
pub mod revocation_enforcement;
pub mod revocation_freshness;
pub mod rgc_execution_waves;
pub mod rgc_test_harness;
pub mod rollback_safemode_synthesizer;
pub mod runtime_comparison_gate;
pub mod runtime_decision_core;
pub mod runtime_decision_theory;
pub mod runtime_diagnostics_cli;
pub mod runtime_hotspot_optimization_campaign;
pub mod runtime_kernel_lane_charter;
pub mod runtime_observability;
pub mod safe_mode_fallback;
pub mod safety_decision_router;
pub mod saga_orchestrator;
pub mod scheduler_invariants;
pub mod scheduler_lane;
pub mod security_conformance;
pub mod security_e2e;
pub mod security_epoch;
pub mod self_replacement;
pub mod semantic_contract_baseline;
pub mod semantic_transport_ledger;
pub mod semantic_twin;
pub mod semantic_twin_state_space;
pub mod seqlock_candidate_inventory;
pub mod seqlock_fastpath;
pub mod session_hostcall_channel;
pub mod shadow_ablation_engine;
pub mod sibling_integration_benchmark_gate;
pub mod signature_preimage;
pub mod simd_lexer;
pub mod slot_differential;
pub mod slot_registry;
pub mod sorted_multisig;
pub mod specialization_conformance;
pub mod specialization_index;
pub mod specialization_lane_gate;
pub mod specialization_perf_release_gate;
pub mod spectral_fleet_convergence;
pub mod static_analysis_graph;
pub mod static_authority_analyzer;
pub mod static_semantics;
pub mod stdlib;
pub mod storage_adapter;
pub mod structural_causal_model;
pub mod succinct_witness_compiler;
pub mod supervision;
pub mod swarm_control_loop;
pub mod synthesis_budget;
pub mod tee_attestation_policy;
pub mod test262_release_gate;
pub mod test_depth_gate;
pub mod test_flake_quarantine_workflow;
pub mod test_logging_schema;
pub mod test_taxonomy;
pub mod third_party_verifier;
pub mod threshold_signing;
pub mod tier_up_profiler;
pub mod translation_validation;
pub mod tropical_semiring;
pub mod trust_card;
pub mod trust_economics;
pub mod trust_zone;
pub mod ts_module_resolution;
pub mod ts_normalization;
pub mod unit_test_taxonomy;
pub mod version_matrix_lane;
pub mod wasm_runtime_lane;
pub mod wave_handoff_contract;

use std::{cmp::Ordering, error::Error, fmt};

use crate::ast::{ParseGoal, SourceSpan};
use crate::baseline_interpreter::{InterpreterError, LaneChoice, LaneRouter};
use crate::hash_tiers::ContentHash;
use crate::ir_contract::Ir0Module;
use crate::lowering_pipeline::{LoweringContext, LoweringPipelineError, lower_ir0_to_ir3};
use crate::parser::{CanonicalEs2020Parser, ParseError, ParseErrorCode, ParserOptions};
use serde::{Deserialize, Serialize};

/// Canonical error classes for deterministic VM semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvalErrorClass {
    Parse,
    Resolution,
    Policy,
    Capability,
    Runtime,
    Hostcall,
    Invariant,
}

impl EvalErrorClass {
    const fn sort_rank(self) -> u8 {
        match self {
            Self::Parse => 0,
            Self::Resolution => 1,
            Self::Policy => 2,
            Self::Capability => 3,
            Self::Runtime => 4,
            Self::Hostcall => 5,
            Self::Invariant => 6,
        }
    }

    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Resolution => "resolution",
            Self::Policy => "policy",
            Self::Capability => "capability",
            Self::Runtime => "runtime",
            Self::Hostcall => "hostcall",
            Self::Invariant => "invariant",
        }
    }
}

impl fmt::Display for EvalErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvalErrorCode {
    EmptySource,
    ParseFailure,
    ResolutionFailure,
    PolicyDenied,
    CapabilityDenied,
    RuntimeFault,
    HostcallFault,
    InvariantViolation,
}

impl EvalErrorCode {
    const fn sort_rank(self) -> u8 {
        match self {
            Self::EmptySource => 0,
            Self::ParseFailure => 1,
            Self::ResolutionFailure => 2,
            Self::PolicyDenied => 3,
            Self::CapabilityDenied => 4,
            Self::RuntimeFault => 5,
            Self::HostcallFault => 6,
            Self::InvariantViolation => 7,
        }
    }

    pub const fn class(self) -> EvalErrorClass {
        match self {
            Self::EmptySource | Self::ParseFailure => EvalErrorClass::Parse,
            Self::ResolutionFailure => EvalErrorClass::Resolution,
            Self::PolicyDenied => EvalErrorClass::Policy,
            Self::CapabilityDenied => EvalErrorClass::Capability,
            Self::RuntimeFault => EvalErrorClass::Runtime,
            Self::HostcallFault => EvalErrorClass::Hostcall,
            Self::InvariantViolation => EvalErrorClass::Invariant,
        }
    }

    pub const fn stable_namespace(self) -> &'static str {
        match self {
            Self::EmptySource => "eval.parse.empty_source",
            Self::ParseFailure => "eval.parse.failure",
            Self::ResolutionFailure => "eval.resolution.failure",
            Self::PolicyDenied => "eval.policy.denied",
            Self::CapabilityDenied => "eval.capability.denied",
            Self::RuntimeFault => "eval.runtime.fault",
            Self::HostcallFault => "eval.hostcall.fault",
            Self::InvariantViolation => "eval.invariant.violation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalCorrelationIds {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalSourceLocation {
    pub source_label: String,
    pub start_line: u64,
    pub start_column: u64,
    pub end_line: u64,
    pub end_column: u64,
}

impl EvalSourceLocation {
    fn from_source_span(source_label: impl Into<String>, span: &SourceSpan) -> Self {
        Self {
            source_label: source_label.into(),
            start_line: span.start_line,
            start_column: span.start_column,
            end_line: span.end_line,
            end_column: span.end_column,
        }
    }

    fn stable_display(&self) -> String {
        format!(
            "{}:{}:{}-{}:{}",
            self.source_label, self.start_line, self.start_column, self.end_line, self.end_column
        )
    }
}

impl fmt::Display for EvalSourceLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.stable_display())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalStackFrame {
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<EvalSourceLocation>,
}

impl EvalStackFrame {
    fn stage(stage: &str, location: Option<EvalSourceLocation>) -> Self {
        Self {
            stage: stage.to_string(),
            boundary: None,
            location,
        }
    }

    fn boundary_transition(
        boundary: ExceptionBoundary,
        location: Option<EvalSourceLocation>,
    ) -> Self {
        Self {
            stage: "boundary_transition".to_string(),
            boundary: Some(boundary.stable_label().to_string()),
            location,
        }
    }

    fn stable_trace_fragment(&self) -> String {
        let mut fragment = self.stage.clone();
        if let Some(boundary) = self.boundary.as_deref() {
            fragment.push('[');
            fragment.push_str(boundary);
            fragment.push(']');
        }
        if let Some(location) = self.location.as_ref() {
            fragment.push('@');
            fragment.push_str(&location.stable_display());
        }
        fragment
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalError {
    pub code: EvalErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_ids: Option<EvalCorrelationIds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<EvalSourceLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_frames: Vec<EvalStackFrame>,
}

impl EvalError {
    pub fn new(code: EvalErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            correlation_ids: None,
            location: None,
            stack_frames: Vec::new(),
        }
    }

    fn empty_source() -> Self {
        Self::new(EvalErrorCode::EmptySource, "source is empty")
    }

    pub fn parse_failure(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::ParseFailure, message)
    }

    pub fn resolution_failure(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::ResolutionFailure, message)
    }

    pub fn policy_denied(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::PolicyDenied, message)
    }

    pub fn capability_denied(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::CapabilityDenied, message)
    }

    pub fn runtime_fault(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::RuntimeFault, message)
    }

    pub fn hostcall_fault(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::HostcallFault, message)
    }

    pub fn invariant_violation(message: impl Into<String>) -> Self {
        Self::new(EvalErrorCode::InvariantViolation, message)
    }

    pub fn class(&self) -> EvalErrorClass {
        self.code.class()
    }

    pub fn stable_namespace(&self) -> &'static str {
        self.code.stable_namespace()
    }

    pub fn with_correlation_ids(
        mut self,
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Self {
        self.correlation_ids = Some(EvalCorrelationIds {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
        });
        self
    }

    pub fn with_location(mut self, location: EvalSourceLocation) -> Self {
        self.location = Some(location);
        self
    }

    pub fn push_stack_frame(&mut self, frame: EvalStackFrame) {
        self.stack_frames.push(frame);
    }

    pub fn formatted_stack_trace(&self) -> Vec<String> {
        self.stack_frames
            .iter()
            .map(EvalStackFrame::stable_trace_fragment)
            .collect()
    }

    pub fn diagnostic_summary(&self) -> String {
        let mut rendered = format!(
            "{} [{}]: {}",
            self.stable_namespace(),
            self.class(),
            self.message
        );

        if let Some(location) = self.location.as_ref() {
            rendered.push_str(" @ ");
            rendered.push_str(&location.stable_display());
        }

        if let Some(correlation) = self.correlation_ids.as_ref() {
            rendered.push_str(" [trace_id=");
            rendered.push_str(&correlation.trace_id);
            rendered.push_str(" decision_id=");
            rendered.push_str(&correlation.decision_id);
            rendered.push_str(" policy_id=");
            rendered.push_str(&correlation.policy_id);
            rendered.push(']');
        }

        if !self.stack_frames.is_empty() {
            rendered.push_str(" [stack=");
            rendered.push_str(&self.formatted_stack_trace().join(" -> "));
            rendered.push(']');
        }

        rendered
    }
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.diagnostic_summary())
    }
}

impl Error for EvalError {}

// Rich deterministic diagnostics intentionally make EvalError structurally large.
#[allow(clippy::result_large_err)]
pub type EvalResult<T> = std::result::Result<T, EvalError>;

/// Migration note for deterministic error semantics in bd-2tx.
pub const EVAL_ERROR_MIGRATION_NOTES: &str = "Migrated from ad-hoc eval string failures to a \
typed deterministic taxonomy (`EvalErrorClass` + `EvalErrorCode`) with stable namespace codes, \
stable sorting for multi-error contexts, and explicit propagation helpers for sync/async/hostcall \
boundaries.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExceptionBoundary {
    SyncCallframe,
    AsyncJob,
    Hostcall,
}

impl ExceptionBoundary {
    pub const fn stable_label(self) -> &'static str {
        match self {
            Self::SyncCallframe => "sync_callframe",
            Self::AsyncJob => "async_job",
            Self::Hostcall => "hostcall",
        }
    }
}

impl fmt::Display for ExceptionBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_label())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionTransitionEvent {
    pub trace_id: String,
    pub decision_id: Option<String>,
    pub policy_id: Option<String>,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_class: String,
    pub error_code: String,
    pub boundary: ExceptionBoundary,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<EvalSourceLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stack_frames: Vec<EvalStackFrame>,
}

pub fn emit_exception_transition_event(
    trace_id: impl Into<String>,
    decision_id: Option<String>,
    policy_id: Option<String>,
    component: impl Into<String>,
    boundary: ExceptionBoundary,
    error: &EvalError,
) -> ExceptionTransitionEvent {
    ExceptionTransitionEvent {
        trace_id: trace_id.into(),
        decision_id,
        policy_id,
        component: component.into(),
        event: "exception_transition".to_string(),
        outcome: "error".to_string(),
        error_class: error.class().stable_label().to_string(),
        error_code: error.stable_namespace().to_string(),
        boundary,
        message: error.message.clone(),
        location: error.location.clone(),
        stack_frames: error.stack_frames.clone(),
    }
}

fn compare_eval_errors(lhs: &EvalError, rhs: &EvalError) -> Ordering {
    lhs.class()
        .sort_rank()
        .cmp(&rhs.class().sort_rank())
        .then(lhs.code.sort_rank().cmp(&rhs.code.sort_rank()))
        .then(lhs.message.as_bytes().cmp(rhs.message.as_bytes()))
}

pub fn stable_sort_eval_errors(errors: &mut [EvalError]) {
    errors.sort_by(compare_eval_errors);
}

pub fn sorted_eval_errors(mut errors: Vec<EvalError>) -> Vec<EvalError> {
    stable_sort_eval_errors(&mut errors);
    errors
}

pub fn propagate_error_across_boundary(error: EvalError, boundary: ExceptionBoundary) -> EvalError {
    let mut propagated = error;
    let mut message = propagated.message;
    if !message.is_empty() {
        message.push_str(" | ");
    }
    message.push_str("boundary=");
    message.push_str(boundary.stable_label());
    propagated.message = message;
    let location = propagated.location.clone();
    propagated.push_stack_frame(EvalStackFrame::boundary_transition(boundary, location));
    propagated
}

#[allow(clippy::result_large_err)]
pub fn propagate_result_across_boundary<T>(
    result: EvalResult<T>,
    boundary: ExceptionBoundary,
) -> EvalResult<T> {
    result.map_err(|error| propagate_error_across_boundary(error, boundary))
}

/// Execution lanes are de novo native Rust implementations inspired by
/// proven ideas from QuickJS and V8, not FFI wrappers over external engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineKind {
    QuickJsInspiredNative,
    V8InspiredNative,
    Hybrid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteReason {
    DirectEngineInvocation,
    ContainsImportKeyword,
    ContainsAwaitKeyword,
    DefaultQuickJsPath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalOutcome {
    pub engine: EngineKind,
    pub value: String,
    pub route_reason: RouteReason,
}

#[allow(clippy::result_large_err)]
pub trait JsEngine {
    fn kind(&self) -> EngineKind;
    fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome>;
}

#[derive(Debug, Default)]
pub struct QuickJsInspiredNativeEngine;

#[derive(Debug, Default)]
pub struct V8InspiredNativeEngine;

impl JsEngine for QuickJsInspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::QuickJsInspiredNative
    }

    fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let normalized = normalize_source(source)?;
        let parse_goal = infer_parse_goal(normalized);
        eval_with_lane(
            normalized,
            parse_goal,
            LaneChoice::QuickJs,
            RouteReason::DirectEngineInvocation,
            "quickjs",
        )
    }
}

impl JsEngine for V8InspiredNativeEngine {
    fn kind(&self) -> EngineKind {
        EngineKind::V8InspiredNative
    }

    fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let normalized = normalize_source(source)?;
        let parse_goal = infer_parse_goal(normalized);
        eval_with_lane(
            normalized,
            parse_goal,
            LaneChoice::V8,
            RouteReason::DirectEngineInvocation,
            "v8",
        )
    }
}

#[derive(Debug)]
pub struct HybridRouter {
    quickjs_lineage: QuickJsInspiredNativeEngine,
    v8_lineage: V8InspiredNativeEngine,
}

impl Default for HybridRouter {
    fn default() -> Self {
        Self {
            quickjs_lineage: QuickJsInspiredNativeEngine,
            v8_lineage: V8InspiredNativeEngine,
        }
    }
}

impl HybridRouter {
    #[allow(clippy::result_large_err)]
    pub fn eval(&mut self, source: &str) -> EvalResult<EvalOutcome> {
        let normalized = normalize_source(source)?;
        let route_reason = route_reason_for_source(normalized);
        let mut outcome = match route_reason {
            RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword => {
                self.v8_lineage.eval(normalized)?
            }
            RouteReason::DefaultQuickJsPath => self.quickjs_lineage.eval(normalized)?,
            RouteReason::DirectEngineInvocation => unreachable!("router never emits direct route"),
        };
        outcome.route_reason = route_reason;
        Ok(outcome)
    }
}

#[allow(clippy::result_large_err)]
fn normalize_source(source: &str) -> EvalResult<&str> {
    let normalized = source.trim();
    if normalized.is_empty() {
        return Err(EvalError::empty_source());
    }
    Ok(normalized)
}

fn route_reason_for_source(source: &str) -> RouteReason {
    if source.contains("import ") {
        RouteReason::ContainsImportKeyword
    } else if source.contains("await ") {
        RouteReason::ContainsAwaitKeyword
    } else {
        RouteReason::DefaultQuickJsPath
    }
}

fn infer_parse_goal(source: &str) -> ParseGoal {
    match route_reason_for_source(source) {
        RouteReason::ContainsImportKeyword | RouteReason::ContainsAwaitKeyword => ParseGoal::Module,
        RouteReason::DirectEngineInvocation | RouteReason::DefaultQuickJsPath => ParseGoal::Script,
    }
}

#[allow(clippy::result_large_err)]
fn eval_with_lane(
    source: &str,
    parse_goal: ParseGoal,
    lane: LaneChoice,
    route_reason: RouteReason,
    trace_scope: &str,
) -> EvalResult<EvalOutcome> {
    let value = eval_via_native_pipeline(source, parse_goal, lane, trace_scope)?;
    Ok(EvalOutcome {
        engine: engine_kind_for_lane(lane),
        value,
        route_reason,
    })
}

fn engine_kind_for_lane(lane: LaneChoice) -> EngineKind {
    match lane {
        LaneChoice::QuickJs => EngineKind::QuickJsInspiredNative,
        LaneChoice::V8 => EngineKind::V8InspiredNative,
    }
}

#[allow(clippy::result_large_err)]
fn eval_via_native_pipeline(
    source: &str,
    parse_goal: ParseGoal,
    lane: LaneChoice,
    trace_scope: &str,
) -> EvalResult<String> {
    let source_hash = ContentHash::compute(source.as_bytes()).to_hex();
    let trace_suffix = &source_hash[..16];
    let trace_id = format!("eval-{trace_scope}-{trace_suffix}");
    let decision_id = format!("eval-decision-{trace_suffix}");
    let policy_id = format!("eval-policy-{trace_scope}");

    let parser = CanonicalEs2020Parser;
    let syntax_tree = parser
        .parse_with_options(source, parse_goal, &ParserOptions::default())
        .map_err(map_parse_error)
        .map_err(|error| attach_eval_correlation(error, &trace_id, &decision_id, &policy_id))?;

    let lowering_context =
        LoweringContext::new(trace_id.as_str(), decision_id.as_str(), policy_id.as_str());
    let ir0 = Ir0Module::from_syntax_tree(syntax_tree, "<eval>");
    let lowering_output = lower_ir0_to_ir3(&ir0, &lowering_context)
        .map_err(map_lowering_error)
        .map_err(|error| attach_eval_correlation(error, &trace_id, &decision_id, &policy_id))?;

    let lane_router = LaneRouter::new();
    let routed = lane_router
        .execute(&lowering_output.ir3, trace_id.as_str(), Some(lane))
        .map_err(map_interpreter_error)
        .map_err(|error| attach_eval_correlation(error, &trace_id, &decision_id, &policy_id))?;

    Ok(routed.result.value.to_string())
}

fn parse_error_location(error: &ParseError) -> Option<EvalSourceLocation> {
    error
        .span
        .as_ref()
        .map(|span| EvalSourceLocation::from_source_span(error.source_label.as_str(), span))
}

fn annotate_error_stage(
    mut error: EvalError,
    stage: &str,
    location: Option<EvalSourceLocation>,
) -> EvalError {
    if error.location.is_none()
        && let Some(existing) = location.clone()
    {
        error.location = Some(existing);
    }
    error.push_stack_frame(EvalStackFrame::stage(stage, location));
    error
}

fn attach_eval_correlation(
    error: EvalError,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
) -> EvalError {
    error.with_correlation_ids(trace_id, decision_id, policy_id)
}

fn map_parse_error(error: ParseError) -> EvalError {
    let mapped = match error.code {
        ParseErrorCode::EmptySource => EvalError::empty_source(),
        _ => EvalError::parse_failure(error.to_string()),
    };
    annotate_error_stage(mapped, "parse", parse_error_location(&error))
}

fn map_lowering_error(error: LoweringPipelineError) -> EvalError {
    let mapped = if matches!(error, LoweringPipelineError::SemanticViolation(_)) {
        EvalError::resolution_failure(error.to_string())
    } else if matches!(error, LoweringPipelineError::FlowLatticeFailure { .. }) {
        EvalError::policy_denied(error.to_string())
    } else if matches!(error, LoweringPipelineError::UnauthorizedFlow { .. }) {
        EvalError::capability_denied(error.to_string())
    } else if matches!(error, LoweringPipelineError::UnsupportedSyntax(_)) {
        EvalError::parse_failure(error.to_string())
    } else {
        EvalError::invariant_violation(error.to_string())
    };
    annotate_error_stage(mapped, "lowering", None)
}

fn map_interpreter_error(error: InterpreterError) -> EvalError {
    let mapped = match error {
        err @ InterpreterError::CapabilityDenied { .. } => {
            EvalError::capability_denied(err.to_string())
        }
        err => EvalError::runtime_fault(err.to_string()),
    };
    annotate_error_stage(mapped, "execute", None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    #[test]
    fn hybrid_routes_simple_input_to_quickjs() {
        let mut router = HybridRouter::default();
        let out = router.eval("1 + 1").expect("eval");
        assert_eq!(out.engine, EngineKind::QuickJsInspiredNative);
        assert_eq!(out.route_reason, RouteReason::DefaultQuickJsPath);
    }

    #[test]
    fn hybrid_routes_import_to_v8() {
        let route_reason = route_reason_for_source("import x from 'y'");
        assert_eq!(route_reason, RouteReason::ContainsImportKeyword);
        assert_eq!(infer_parse_goal("import x from 'y'"), ParseGoal::Module);
    }

    #[test]
    fn hybrid_routes_await_to_v8() {
        let route_reason = route_reason_for_source("await job()");
        assert_eq!(route_reason, RouteReason::ContainsAwaitKeyword);
        assert_eq!(infer_parse_goal("await job()"), ParseGoal::Module);
    }

    #[test]
    fn direct_lanes_reject_empty_source_with_stable_error_code() {
        let mut quickjs = QuickJsInspiredNativeEngine;
        let mut v8 = V8InspiredNativeEngine;

        let quickjs_err = quickjs.eval(" ").expect_err("expected empty source error");
        let v8_err = v8.eval("\t").expect_err("expected empty source error");

        assert_eq!(quickjs_err.code, EvalErrorCode::EmptySource);
        assert_eq!(v8_err.code, EvalErrorCode::EmptySource);
        assert_eq!(quickjs_err.class(), EvalErrorClass::Parse);
        assert_eq!(v8_err.class(), EvalErrorClass::Parse);
        assert_eq!(quickjs_err.stable_namespace(), "eval.parse.empty_source");
        assert_eq!(v8_err.stable_namespace(), "eval.parse.empty_source");
    }

    #[test]
    fn hybrid_rejects_empty_source_with_stable_error_code() {
        let mut router = HybridRouter::default();
        let err = router.eval(" ").expect_err("expected empty source error");
        assert_eq!(err.code, EvalErrorCode::EmptySource);
        assert_eq!(err.class(), EvalErrorClass::Parse);
        assert_eq!(err.stable_namespace(), "eval.parse.empty_source");
    }

    #[test]
    fn equivalent_empty_source_failures_are_identical_across_lanes() {
        let mut quickjs = QuickJsInspiredNativeEngine;
        let mut v8 = V8InspiredNativeEngine;
        let mut hybrid = HybridRouter::default();

        let quickjs_err = quickjs
            .eval("")
            .expect_err("quickjs must reject empty source");
        let v8_err = v8.eval(" ").expect_err("v8 must reject empty source");
        let hybrid_err = hybrid
            .eval("\n\t")
            .expect_err("hybrid must reject empty source");

        let quickjs_shape = (
            quickjs_err.code,
            quickjs_err.class(),
            quickjs_err.stable_namespace(),
            quickjs_err.message,
        );
        let v8_shape = (
            v8_err.code,
            v8_err.class(),
            v8_err.stable_namespace(),
            v8_err.message,
        );
        let hybrid_shape = (
            hybrid_err.code,
            hybrid_err.class(),
            hybrid_err.stable_namespace(),
            hybrid_err.message,
        );

        assert_eq!(quickjs_shape, v8_shape);
        assert_eq!(v8_shape, hybrid_shape);
    }

    #[test]
    fn eval_error_code_class_mappings_are_deterministic() {
        let expected = [
            (EvalErrorCode::EmptySource, EvalErrorClass::Parse),
            (EvalErrorCode::ParseFailure, EvalErrorClass::Parse),
            (EvalErrorCode::ResolutionFailure, EvalErrorClass::Resolution),
            (EvalErrorCode::PolicyDenied, EvalErrorClass::Policy),
            (EvalErrorCode::CapabilityDenied, EvalErrorClass::Capability),
            (EvalErrorCode::RuntimeFault, EvalErrorClass::Runtime),
            (EvalErrorCode::HostcallFault, EvalErrorClass::Hostcall),
            (EvalErrorCode::InvariantViolation, EvalErrorClass::Invariant),
        ];

        for (code, class) in expected {
            assert_eq!(code.class(), class);
            assert!(
                code.stable_namespace().starts_with("eval."),
                "stable namespace must be in eval.* namespace"
            );
        }
    }

    #[test]
    fn stable_sort_for_multi_error_context_is_deterministic() {
        let mut errors = vec![
            EvalError::runtime_fault("panic in optimizer"),
            EvalError::capability_denied("fs_write not granted"),
            EvalError::parse_failure("unexpected token `}`"),
            EvalError::empty_source(),
            EvalError::hostcall_fault("bridge timeout"),
            EvalError::policy_denied("policy denied extension"),
        ];

        stable_sort_eval_errors(&mut errors);

        let namespaces: Vec<&str> = errors.iter().map(EvalError::stable_namespace).collect();
        assert_eq!(
            namespaces,
            vec![
                "eval.parse.empty_source",
                "eval.parse.failure",
                "eval.policy.denied",
                "eval.capability.denied",
                "eval.runtime.fault",
                "eval.hostcall.fault"
            ]
        );
    }

    #[test]
    fn propagation_across_sync_async_hostcall_boundaries_is_stable() {
        let parse_error = EvalError::parse_failure("unexpected token");

        let propagated =
            propagate_error_across_boundary(parse_error, ExceptionBoundary::SyncCallframe);
        let propagated = propagate_error_across_boundary(propagated, ExceptionBoundary::AsyncJob);
        let propagated = propagate_error_across_boundary(propagated, ExceptionBoundary::Hostcall);

        assert_eq!(propagated.code, EvalErrorCode::ParseFailure);
        assert_eq!(
            propagated.message,
            "unexpected token | boundary=sync_callframe | boundary=async_job | boundary=hostcall"
        );
        assert_eq!(propagated.stack_frames.len(), 3);
        assert_eq!(propagated.stack_frames[0].stage, "boundary_transition");
        assert_eq!(
            propagated.stack_frames[0].boundary.as_deref(),
            Some("sync_callframe")
        );
        assert_eq!(
            propagated.stack_frames[1].boundary.as_deref(),
            Some("async_job")
        );
        assert_eq!(
            propagated.stack_frames[2].boundary.as_deref(),
            Some("hostcall")
        );
    }

    #[test]
    fn exception_transition_event_emits_structured_deterministic_fields() {
        let err = EvalError::policy_denied("policy denied extension");
        let event = emit_exception_transition_event(
            "trace-01",
            Some("decision-17".to_string()),
            Some("policy-main".to_string()),
            "hybrid_router",
            ExceptionBoundary::SyncCallframe,
            &err,
        );

        assert_eq!(event.trace_id, "trace-01");
        assert_eq!(event.decision_id.as_deref(), Some("decision-17"));
        assert_eq!(event.policy_id.as_deref(), Some("policy-main"));
        assert_eq!(event.component, "hybrid_router");
        assert_eq!(event.event, "exception_transition");
        assert_eq!(event.outcome, "error");
        assert_eq!(event.error_class, "policy");
        assert_eq!(event.error_code, "eval.policy.denied");
        assert_eq!(event.boundary, ExceptionBoundary::SyncCallframe);
        assert_eq!(event.message, "policy denied extension");
        assert!(event.location.is_none());
        assert!(event.stack_frames.is_empty());

        let encoded = serde_json::to_string(&event).expect("serialize event");
        let decoded: ExceptionTransitionEvent =
            serde_json::from_str(&encoded).expect("deserialize event");
        assert_eq!(decoded, event);
    }

    #[test]
    fn parse_failures_capture_correlation_and_parse_stage_stack_frame() {
        let mut quickjs = QuickJsInspiredNativeEngine;
        let err = quickjs.eval("let").expect_err("expected parse failure");

        let correlation = err
            .correlation_ids
            .as_ref()
            .expect("correlation ids should be attached");
        assert!(correlation.trace_id.starts_with("eval-quickjs-"));
        assert!(correlation.decision_id.starts_with("eval-decision-"));
        assert_eq!(correlation.policy_id, "eval-policy-quickjs");

        assert!(!err.stack_frames.is_empty());
        assert_eq!(err.stack_frames[0].stage, "parse");
        assert!(err.stack_frames[0].boundary.is_none());

        let location = err
            .location
            .expect("parse failures should include location");
        assert!(!location.source_label.is_empty());
        assert!(location.start_line >= 1);
        assert!(location.start_column >= 1);
    }

    #[test]
    fn boundary_propagation_preserves_correlation_ids() {
        let err = EvalError::runtime_fault("runtime panic").with_correlation_ids(
            "trace-1",
            "decision-1",
            "policy-1",
        );

        let propagated = propagate_error_across_boundary(err, ExceptionBoundary::AsyncJob);
        let correlation = propagated
            .correlation_ids
            .expect("correlation ids should survive boundary propagation");
        assert_eq!(correlation.trace_id, "trace-1");
        assert_eq!(correlation.decision_id, "decision-1");
        assert_eq!(correlation.policy_id, "policy-1");
    }

    // -----------------------------------------------------------------------
    // EvalError factory methods
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_factory_methods_produce_correct_codes() {
        let cases: Vec<(EvalError, EvalErrorCode)> = vec![
            (EvalError::parse_failure("x"), EvalErrorCode::ParseFailure),
            (
                EvalError::resolution_failure("x"),
                EvalErrorCode::ResolutionFailure,
            ),
            (EvalError::policy_denied("x"), EvalErrorCode::PolicyDenied),
            (
                EvalError::capability_denied("x"),
                EvalErrorCode::CapabilityDenied,
            ),
            (EvalError::runtime_fault("x"), EvalErrorCode::RuntimeFault),
            (EvalError::hostcall_fault("x"), EvalErrorCode::HostcallFault),
            (
                EvalError::invariant_violation("x"),
                EvalErrorCode::InvariantViolation,
            ),
        ];
        for (error, expected_code) in cases {
            assert_eq!(error.code, expected_code, "factory for {:?}", expected_code);
        }
    }

    // -----------------------------------------------------------------------
    // EvalError Display format
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_display_format_includes_namespace_class_message() {
        let err = EvalError::runtime_fault("stack overflow");
        let display = format!("{err}");
        assert!(display.contains("eval.runtime.fault"));
        assert!(display.contains("runtime"));
        assert!(display.contains("stack overflow"));
    }

    #[test]
    fn eval_error_display_includes_location_correlation_and_stack_trace() {
        let location = EvalSourceLocation {
            source_label: "<eval>".to_string(),
            start_line: 2,
            start_column: 4,
            end_line: 2,
            end_column: 8,
        };
        let mut err = EvalError::runtime_fault("boom")
            .with_correlation_ids("trace-a", "decision-a", "policy-a")
            .with_location(location.clone());
        err.push_stack_frame(EvalStackFrame::stage("parse", Some(location.clone())));
        err.push_stack_frame(EvalStackFrame::boundary_transition(
            ExceptionBoundary::Hostcall,
            Some(location),
        ));

        let display = format!("{err}");
        assert!(display.contains("<eval>:2:4-2:8"));
        assert!(display.contains("trace_id=trace-a"));
        assert!(display.contains("decision_id=decision-a"));
        assert!(display.contains("policy_id=policy-a"));
        assert!(display.contains("stack=parse@<eval>:2:4-2:8"));
        assert!(display.contains("boundary_transition[hostcall]@<eval>:2:4-2:8"));
    }

    #[test]
    fn boundary_propagation_copies_error_location_to_boundary_frame() {
        let location = EvalSourceLocation {
            source_label: "mod.ts".to_string(),
            start_line: 9,
            start_column: 3,
            end_line: 9,
            end_column: 11,
        };
        let err = EvalError::runtime_fault("boom").with_location(location.clone());
        let propagated = propagate_error_across_boundary(err, ExceptionBoundary::AsyncJob);
        assert_eq!(propagated.stack_frames.len(), 1);
        assert_eq!(propagated.stack_frames[0].stage, "boundary_transition");
        assert_eq!(
            propagated.stack_frames[0].location.as_ref(),
            Some(&location)
        );
    }

    // -----------------------------------------------------------------------
    // Serde round-trips for core types
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_class_serde_round_trip() {
        let classes = [
            EvalErrorClass::Parse,
            EvalErrorClass::Resolution,
            EvalErrorClass::Policy,
            EvalErrorClass::Capability,
            EvalErrorClass::Runtime,
            EvalErrorClass::Hostcall,
            EvalErrorClass::Invariant,
        ];
        for class in &classes {
            let json = serde_json::to_string(class).expect("serialize");
            let decoded: EvalErrorClass = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, class);
        }
    }

    #[test]
    fn eval_error_code_serde_round_trip() {
        let codes = [
            EvalErrorCode::EmptySource,
            EvalErrorCode::ParseFailure,
            EvalErrorCode::ResolutionFailure,
            EvalErrorCode::PolicyDenied,
            EvalErrorCode::CapabilityDenied,
            EvalErrorCode::RuntimeFault,
            EvalErrorCode::HostcallFault,
            EvalErrorCode::InvariantViolation,
        ];
        for code in &codes {
            let json = serde_json::to_string(code).expect("serialize");
            let decoded: EvalErrorCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, code);
        }
    }

    #[test]
    fn engine_kind_serde_round_trip() {
        for kind in &[
            EngineKind::QuickJsInspiredNative,
            EngineKind::V8InspiredNative,
            EngineKind::Hybrid,
        ] {
            let json = serde_json::to_string(kind).expect("serialize");
            let decoded: EngineKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, kind);
        }
    }

    #[test]
    fn route_reason_serde_round_trip() {
        let reasons = [
            RouteReason::DirectEngineInvocation,
            RouteReason::ContainsImportKeyword,
            RouteReason::ContainsAwaitKeyword,
            RouteReason::DefaultQuickJsPath,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).expect("serialize");
            let decoded: RouteReason = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, reason);
        }
    }

    #[test]
    fn eval_error_serde_round_trip() {
        let err = EvalError::policy_denied("extension blocked");
        let json = serde_json::to_string(&err).expect("serialize");
        let decoded: EvalError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, err);
    }

    #[test]
    fn eval_outcome_serde_round_trip() {
        let outcome = EvalOutcome {
            engine: EngineKind::V8InspiredNative,
            value: "42".to_string(),
            route_reason: RouteReason::ContainsAwaitKeyword,
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        let decoded: EvalOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, outcome);
    }

    // -----------------------------------------------------------------------
    // sorted_eval_errors (non-in-place variant)
    // -----------------------------------------------------------------------

    #[test]
    fn sorted_eval_errors_returns_new_sorted_vec() {
        let errors = vec![EvalError::runtime_fault("b"), EvalError::parse_failure("a")];
        let sorted = sorted_eval_errors(errors);
        assert_eq!(sorted[0].code, EvalErrorCode::ParseFailure);
        assert_eq!(sorted[1].code, EvalErrorCode::RuntimeFault);
    }

    // -----------------------------------------------------------------------
    // propagate_result_across_boundary
    // -----------------------------------------------------------------------

    #[test]
    fn propagate_result_ok_passes_through() {
        let result: EvalResult<i32> = Ok(42);
        let propagated = propagate_result_across_boundary(result, ExceptionBoundary::AsyncJob);
        assert_eq!(propagated.unwrap(), 42);
    }

    #[test]
    fn propagate_result_err_annotates_boundary() {
        let result: EvalResult<i32> = Err(EvalError::runtime_fault("oops"));
        let propagated = propagate_result_across_boundary(result, ExceptionBoundary::Hostcall);
        let err = propagated.unwrap_err();
        assert!(err.message.contains("boundary=hostcall"));
        assert_eq!(err.code, EvalErrorCode::RuntimeFault);
    }

    // -----------------------------------------------------------------------
    // ExceptionBoundary
    // -----------------------------------------------------------------------

    #[test]
    fn exception_boundary_stable_labels() {
        assert_eq!(
            ExceptionBoundary::SyncCallframe.stable_label(),
            "sync_callframe"
        );
        assert_eq!(ExceptionBoundary::AsyncJob.stable_label(), "async_job");
        assert_eq!(ExceptionBoundary::Hostcall.stable_label(), "hostcall");
    }

    #[test]
    fn exception_boundary_display_matches_stable_label() {
        for boundary in &[
            ExceptionBoundary::SyncCallframe,
            ExceptionBoundary::AsyncJob,
            ExceptionBoundary::Hostcall,
        ] {
            assert_eq!(format!("{boundary}"), boundary.stable_label());
        }
    }

    #[test]
    fn exception_boundary_serde_round_trip() {
        for boundary in &[
            ExceptionBoundary::SyncCallframe,
            ExceptionBoundary::AsyncJob,
            ExceptionBoundary::Hostcall,
        ] {
            let json = serde_json::to_string(boundary).expect("serialize");
            let decoded: ExceptionBoundary = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, boundary);
        }
    }

    // -----------------------------------------------------------------------
    // EvalErrorClass stable_label
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_class_stable_labels_are_all_lowercase() {
        let classes = [
            EvalErrorClass::Parse,
            EvalErrorClass::Resolution,
            EvalErrorClass::Policy,
            EvalErrorClass::Capability,
            EvalErrorClass::Runtime,
            EvalErrorClass::Hostcall,
            EvalErrorClass::Invariant,
        ];
        for class in &classes {
            let label = class.stable_label();
            assert_eq!(
                label,
                label.to_lowercase(),
                "stable_label must be lowercase: {label}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // EvalErrorCode stable_namespace uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn eval_error_code_stable_namespaces_are_unique() {
        use std::collections::BTreeSet;
        let codes = [
            EvalErrorCode::EmptySource,
            EvalErrorCode::ParseFailure,
            EvalErrorCode::ResolutionFailure,
            EvalErrorCode::PolicyDenied,
            EvalErrorCode::CapabilityDenied,
            EvalErrorCode::RuntimeFault,
            EvalErrorCode::HostcallFault,
            EvalErrorCode::InvariantViolation,
        ];
        let namespaces: BTreeSet<&str> = codes.iter().map(|c| c.stable_namespace()).collect();
        assert_eq!(
            namespaces.len(),
            codes.len(),
            "all stable namespaces must be unique"
        );
    }

    // -----------------------------------------------------------------------
    // Direct engine eval executes JS semantics through parse/lower/execute
    // -----------------------------------------------------------------------

    #[test]
    fn quickjs_engine_executes_expression_instead_of_echoing_source() {
        let mut engine = QuickJsInspiredNativeEngine;
        let out = engine.eval("'hello'").unwrap();
        assert_eq!(out.value, "hello");
        assert_eq!(out.engine, EngineKind::QuickJsInspiredNative);
    }

    #[test]
    fn v8_engine_executes_expression_instead_of_echoing_source() {
        let mut engine = V8InspiredNativeEngine;
        let out = engine.eval("\"world\"").unwrap();
        assert_eq!(out.value, "world");
        assert_eq!(out.engine, EngineKind::V8InspiredNative);
    }

    #[test]
    fn control_plane_adoption_adr_contains_required_sections() {
        let adr_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/adr/ADR-0001-control-plane-adoption-asupersync.md");
        let adr = fs::read_to_string(&adr_path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", adr_path.display()));

        let required_sections = [
            "## Canonical Imported Types",
            "## Version Policy",
            "## Escalation Path for Missing APIs",
        ];
        for section in required_sections {
            assert!(
                adr.contains(section),
                "ADR must contain required section: {section}"
            );
        }

        let required_types = [
            "Cx",
            "TraceId",
            "DecisionId",
            "PolicyId",
            "SchemaVersion",
            "Budget",
        ];
        for type_name in required_types {
            assert!(
                adr.contains(&format!("`{type_name}`")),
                "ADR must reference canonical type `{type_name}`"
            );
        }
    }
}
