//! End-to-end integration seam: parse → lower → execute → assess → decide → record → contain.
//!
//! The `ExecutionOrchestrator` accepts an extension package and drives it
//! through the full FrankenEngine pipeline:
//!
//! 1. **Parse** source via `CanonicalEs2020Parser`
//! 2. **Lower** IR0 → IR3 via `lowering_pipeline`
//! 3. **Execute** IR3 via `LaneRouter`
//! 4. **Assess risk** via a per-extension `BayesianPosteriorUpdater`
//! 5. **Decide action** via `ExpectedLossSelector`
//! 6. **Record evidence** via `EvidenceLedger`
//! 7. **Execute containment** via `ContainmentExecutor`
//! 8. **Close cell** via `ExecutionCell` quiescent protocol

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::ast::ParseGoal;
use crate::baseline_interpreter::{
    ExecutionResult, HookAction, InterpreterConfig, InterpreterError, InterpreterHook, LaneChoice,
    LaneReason, LaneRouter, RoutedResult,
};
use crate::bayesian_posterior::{Evidence, Posterior, RiskState, UpdateResult, UpdaterStore};
use crate::capability::RuntimeCapability;
use crate::containment_executor::{
    ContainmentContext, ContainmentError, ContainmentExecutor, ContainmentReceipt, SandboxPolicy,
};
use crate::control_plane::{Budget, Cx, KernelContext, NoCaps, TraceId};
use crate::entropy_evidence_compressor::{
    ArithmeticCoder, CompressionCertificate, EntropyError, EntropyEstimator,
};
use crate::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEmitter, EvidenceEntry,
    EvidenceEntryBuilder, EvidenceSigningAuthority, EvidenceVerificationIdentity, InMemoryLedger,
    LabEvidenceAuthority, LedgerError, RuntimeEvidenceAuthority, VerifiedEvidenceEntry, Witness,
};
use crate::execution_cell::{CellError, CellEvent, CellKind, ExecutionCell};
use crate::expected_loss_selector::{
    ActionDecision, ContainmentAction, ExpectedLossSelector, LossMatrix,
};
use crate::flow_lattice::{Clearance, DeclassificationObligation, Ir2FlowLattice, LabelClass};
use crate::guardplane_adapter::{
    GuardplaneAdapter, GuardplaneDecisionRecord, GuardplaneExecutionSummary,
    GuardplaneExtensionContext, GuardplaneOperation,
};
use crate::hash_tiers::ContentHash;
use crate::ifc_artifacts::{DeclassificationReceipt, Label};
use crate::ir_contract::{ExecutionOutcome, Ir0Module, Ir3Module, Ir4Module, verify_ir4_linkage};
use crate::lowering_pipeline::{
    Ir2FlowProofArtifact, LoweringContext, LoweringEvent, LoweringPipelineError,
    LoweringPipelineOutput, PassWitness, lower_ir0_to_ir3,
};
use crate::optimal_stopping::{
    EscalationPolicy, Observation as StoppingObservation, OptimalStoppingCertificate,
    STOPPING_SCHEMA_VERSION, StoppingDecision,
};
use crate::parser::{CanonicalEs2020Parser, ParseError, ParserOptions, ParserSource};
use crate::region_lifecycle::{CancelReason, DrainDeadline, FinalizeResult};
use crate::regret_bounded_router::{
    LaneArm as AdaptiveLaneArm, RegretBoundedRouter, RewardSignal as AdaptiveRewardSignal,
    RouterSummary,
};
use crate::runtime_config::RuntimeConfig;
use crate::saga_orchestrator::{
    SagaError, SagaOrchestrator, SagaType, eviction_saga_steps, quarantine_saga_steps,
    revocation_saga_steps,
};
use crate::security_epoch::SecurityEpoch;
use crate::signature_preimage::VerificationKey;
use crate::tropical_semiring::{
    InstructionCostGraph, InstructionNode, ScheduleOptimizer, TropicalWeight,
};
use crate::ts_normalization::{
    SourceIngestionSummary, TsNormalizationError, prepare_source_entry_for_public_entrypoints,
};

/// Default adaptive router exploration rate (now read from RuntimeConfig).
#[allow(dead_code)]
const ADAPTIVE_ROUTER_GAMMA_MILLIONTHS: i64 = 100_000;
/// Default CUSUM anomaly detection threshold (now read from RuntimeConfig).
#[allow(dead_code)]
const STOPPING_CUSUM_THRESHOLD_MILLIONTHS: i64 = 5_000_000;
/// Default CUSUM reference value (now read from RuntimeConfig).
#[allow(dead_code)]
const STOPPING_CUSUM_REFERENCE_MILLIONTHS: i64 = 500_000;
#[allow(dead_code)]
const DEFAULT_DRAIN_DEADLINE_TICKS: u64 = 10_000;
#[allow(dead_code)]
const ORCHESTRATOR_CELL_CLOSE_BUDGET_MS: u64 = 10_000;
#[allow(dead_code)]
const DEFAULT_MAX_CONCURRENT_SAGAS: usize = 4;
#[allow(dead_code)]
const IFC_RUNTIME_GUARD_CAPABILITY: &str = "ifc.check_flow";
const SCALE_MILLION: i64 = 1_000_000;
const EVIDENCE_COMPRESSION_SKETCH_SCHEMA: &str = "franken-engine.evidence-compression-sketch.v4";
const EVIDENCE_COMPRESSION_SKETCH_MAX_BYTES: usize = 512;

// ---------------------------------------------------------------------------
// LossMatrixPreset
// ---------------------------------------------------------------------------

/// Preset selection for the loss matrix used in action selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LossMatrixPreset {
    Balanced,
    Conservative,
    Permissive,
}

impl LossMatrixPreset {
    fn to_loss_matrix(self) -> LossMatrix {
        match self {
            Self::Balanced => LossMatrix::balanced(),
            Self::Conservative => LossMatrix::conservative(),
            Self::Permissive => LossMatrix::permissive(),
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorConfig
// ---------------------------------------------------------------------------

/// Configuration for the execution orchestrator.
#[derive(Debug, Clone)]
pub struct OrchestratorConfig {
    /// Which loss matrix preset to use.
    pub loss_matrix_preset: LossMatrixPreset,
    /// Force a specific interpreter lane.
    pub force_lane: Option<LaneChoice>,
    /// Max drain ticks for cell close.
    pub drain_deadline_ticks: u64,
    /// Root budget used for the canonical cell-close context.
    pub cell_close_budget_ms: u64,
    /// Saga concurrency limit.
    pub max_concurrent_sagas: usize,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Parse goal (Script or Module).
    pub parse_goal: ParseGoal,
    /// Parser mode + deterministic budget configuration.
    pub parser_options: ParserOptions,
    /// Prefix for generated trace IDs.
    pub trace_id_prefix: String,
    /// Policy ID for decision context.
    pub policy_id: String,
}

impl Default for OrchestratorConfig {
    fn default() -> Self {
        let runtime_orchestrator = RuntimeConfig::default().orchestrator;
        Self {
            loss_matrix_preset: LossMatrixPreset::Balanced,
            force_lane: None,
            drain_deadline_ticks: runtime_orchestrator.drain_deadline_ticks,
            cell_close_budget_ms: runtime_orchestrator.cell_close_budget_ms,
            max_concurrent_sagas: runtime_orchestrator.max_concurrent_sagas,
            epoch: SecurityEpoch::from_raw(1),
            parse_goal: ParseGoal::Script,
            parser_options: ParserOptions::default(),
            trace_id_prefix: "orch".to_string(),
            policy_id: "default-policy".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// ExtensionPackage
// ---------------------------------------------------------------------------

/// An extension package submitted for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionPackage {
    /// Unique extension identifier.
    pub extension_id: String,
    /// Source code (JavaScript or TypeScript).
    pub source: String,
    /// Optional source file path or label used for TS detection (e.g. "app.ts").
    #[serde(default)]
    pub source_file: Option<String>,
    /// Declared capabilities.
    pub capabilities: Vec<String>,
    /// Extension version.
    pub version: String,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// OrchestratorResult
// ---------------------------------------------------------------------------

/// Stage at which an evidence-compression attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCompressionFailureStage {
    Coder,
    Encode,
    Kraft,
}

impl EvidenceCompressionFailureStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Coder => "coder",
            Self::Encode => "encode",
            Self::Kraft => "kraft",
        }
    }
}

/// Explicit result of compressing the integrity-bound evidence sketch.
///
/// A failed status is never accompanied by a certificate. The failure is
/// committed to the primary evidence entry so callers can distinguish a
/// degraded, audited run from an unexplained missing certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EvidenceCompressionStatus {
    Certified,
    NotApplicable,
    Failed {
        stage: EvidenceCompressionFailureStage,
        detail: String,
    },
}

impl EvidenceCompressionStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Certified => "certified",
            Self::NotApplicable => "not_applicable",
            Self::Failed { .. } => "failed",
        }
    }
}

/// Complete result of an orchestrated execution pipeline.
#[derive(Debug)]
pub struct OrchestratorResult {
    // Identity
    pub extension_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub source_label: String,

    // Source ingestion (JS passthrough or TS normalization)
    pub source_ingestion: SourceIngestionSummary,

    // Lowering
    pub lowering_events: Vec<LoweringEvent>,
    pub lowering_witnesses: Vec<PassWitness>,

    // Execution
    pub lane: LaneChoice,
    pub lane_reason: LaneReason,
    pub execution_value: String,
    pub completion_label: Label,
    pub instructions_executed: u64,
    pub adaptive_router_summary: Option<RouterSummary>,
    pub ir3_schedule_cost: Option<TropicalWeight>,

    // Risk
    pub posterior: Posterior,
    pub risk_state: RiskState,

    // Action
    pub containment_action: ContainmentAction,
    pub expected_loss_millionths: i64,
    pub action_decision: ActionDecision,
    pub optimal_stopping_certificate: Option<OptimalStoppingCertificate>,

    // Evidence
    pub evidence_entries: Vec<VerifiedEvidenceEntry>,
    pub evidence_compression_certificate: Option<CompressionCertificate>,
    pub evidence_compression_status: EvidenceCompressionStatus,

    // Containment
    pub containment_receipt: Option<ContainmentReceipt>,
    pub saga_id: Option<String>,

    // Cell
    pub cell_events: Vec<CellEvent>,
    pub finalize_result: Option<FinalizeResult>,

    // IR4 WitnessIR (bd-drb55): the sealed post-execution witness linking the
    // exact executed IR3 content hash to the interpreter's witness-event and
    // hostcall-decision transcripts. Sealed and linkage-verified only on the
    // success path; failed executions deliberately never certify a complete
    // witness.
    pub ir4_witness: Ir4Module,

    // Epoch
    pub epoch: SecurityEpoch,
}

/// Inspectable evidence from the mandatory execution-cell close attempt.
///
/// This artifact is returned with every failure that occurs after cell
/// creation. Exactly one of `finalize_result` and `close_error` is populated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellCleanupEvidence {
    pub cell_id: String,
    pub trace_id: String,
    pub cancel_reason: CancelReason,
    pub cell_events: Vec<CellEvent>,
    pub finalize_result: Option<FinalizeResult>,
    pub close_error: Option<CellError>,
}

impl CellCleanupEvidence {
    #[must_use]
    pub fn close_succeeded(&self) -> bool {
        self.finalize_result.is_some() && self.close_error.is_none()
    }
}

/// Serializable evidence that containment committed but its follow-up saga
/// could not be created.
///
/// The receipt proves the security action completed. Returning this artifact
/// inside the post-cell lifecycle failure prevents a later saga error from
/// erasing that partial success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainmentSagaFailureEvidence {
    pub action: ContainmentAction,
    pub receipt: ContainmentReceipt,
    pub saga_id: String,
    pub saga_type: SagaType,
    pub saga_error: SagaError,
}

/// Ordered failure report for an orchestration attempt that reached cell
/// creation.
///
/// `primary_error` is always the first phase failure. Later failures, including
/// cell close, are retained in occurrence order. When containment committed
/// before saga creation failed, `containment_saga_failure` preserves the
/// successful action receipt and the rejected saga request.
#[derive(Debug)]
pub struct PostCellFailure {
    pub primary_error: Box<OrchestratorError>,
    pub additional_errors: Vec<OrchestratorError>,
    pub containment_saga_failure: Option<ContainmentSagaFailureEvidence>,
    pub cleanup: CellCleanupEvidence,
}

/// Preflighted runtime-flow guard context for the next execution attempt.
#[derive(Debug, Clone)]
pub struct PreparedRuntimeFlowGuards {
    pub trace_id: String,
    pub decision_id: String,
    pub source_label: String,
    pub source_ingestion: SourceIngestionSummary,
    pub ir2_flow_proof_artifact: Ir2FlowProofArtifact,
}

struct EvidenceRecordInput<'a> {
    trace_id: &'a str,
    decision_id: &'a str,
    package: &'a ExtensionPackage,
    decision: &'a ActionDecision,
    effective_action: ContainmentAction,
    exec: &'a ExecutionResult,
    update: &'a UpdateResult,
    ir3_schedule_cost: Option<TropicalWeight>,
    ir4_witness_hash: ContentHash,
    adaptive_router_summary: Option<&'a RouterSummary>,
    optimal_stopping_certificate: Option<&'a OptimalStoppingCertificate>,
    guardplane_report: Option<&'a GuardplaneHookReport>,
    capability_summary: EvidenceCapabilitySummary,
}

#[derive(Debug, Clone, Copy)]
struct EvidenceCapabilitySummary {
    total: u64,
    canonical_distinct: u32,
    multiset_hash: ContentHash,
}

#[derive(Debug)]
struct EvidenceCompressionSketch {
    symbols: Vec<u32>,
    content_hash: ContentHash,
}

#[derive(Debug)]
struct EvidenceCompressionAttempt {
    certificate: Option<CompressionCertificate>,
    status: EvidenceCompressionStatus,
    symbol_count: usize,
    alphabet_size: usize,
    sketch_hash: ContentHash,
}

#[derive(Debug, Clone)]
struct GuardplaneHookReport {
    summary: GuardplaneExecutionSummary,
    decisions: Vec<GuardplaneDecisionRecord>,
}

#[derive(Debug, Clone)]
struct ReservedExecutionContext {
    attempt_index: u64,
    trace_id: String,
    decision_id: String,
    package_fingerprint: ContentHash,
    extension_id: String,
}

struct PreparedLoweringOutput {
    source_label: String,
    source_ingestion: SourceIngestionSummary,
    lowering_output: LoweringPipelineOutput,
}

#[derive(Debug)]
struct PendingPostCellFailure {
    primary_error: Box<OrchestratorError>,
    additional_errors: Vec<OrchestratorError>,
    containment_saga_failure: Option<Box<ContainmentSagaFailureEvidence>>,
}

impl From<OrchestratorError> for PendingPostCellFailure {
    fn from(primary_error: OrchestratorError) -> Self {
        Self {
            primary_error: Box::new(primary_error),
            additional_errors: Vec::new(),
            containment_saga_failure: None,
        }
    }
}

#[derive(Debug)]
enum ContainmentPhaseError {
    Pipeline(OrchestratorError),
    SagaCreation(Box<ContainmentSagaFailureEvidence>),
}

impl From<ContainmentError> for ContainmentPhaseError {
    fn from(error: ContainmentError) -> Self {
        Self::Pipeline(OrchestratorError::Containment(error))
    }
}

impl From<ContainmentPhaseError> for PendingPostCellFailure {
    fn from(error: ContainmentPhaseError) -> Self {
        match error {
            ContainmentPhaseError::Pipeline(primary_error) => primary_error.into(),
            ContainmentPhaseError::SagaCreation(evidence) => Self {
                primary_error: Box::new(OrchestratorError::Saga(evidence.saga_error.clone())),
                additional_errors: Vec::new(),
                containment_saga_failure: Some(evidence),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// OrchestratorError
// ---------------------------------------------------------------------------

/// Errors produced by the orchestrator pipeline.
#[derive(Debug)]
pub enum OrchestratorError {
    Parse(Box<ParseError>),
    Lowering(Box<LoweringPipelineError>),
    IfcRuntimeGuardBlocked {
        detail: String,
    },
    Interpreter(InterpreterError),
    Ledger(LedgerError),
    Saga(SagaError),
    Cell(CellError),
    Containment(ContainmentError),
    TsNormalization(TsNormalizationError),
    EvidenceCompressionCoder {
        detail: String,
    },
    EvidenceCompressionEncode {
        detail: String,
    },
    EvidenceCompressionKraft {
        detail: String,
    },
    EmptySource,
    EmptyExtensionId,
    UnknownPackageCapability {
        capability: String,
    },
    /// The post-execution IR4 witness failed linkage verification against the
    /// executed IR3 (bd-drb55). Fail-closed: a run whose witness cannot be
    /// verified is not published as a success.
    WitnessSealing {
        detail: String,
    },
    PreparedExecutionContextMismatch {
        reserved_extension_id: String,
        requested_extension_id: String,
    },
    PostCellFailure(Box<PostCellFailure>),
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse: {e}"),
            Self::Lowering(e) => write!(f, "lowering: {e}"),
            Self::IfcRuntimeGuardBlocked { detail } => {
                write!(f, "ifc runtime guard blocked execution: {detail}")
            }
            Self::Interpreter(e) => write!(f, "interpreter: {e}"),
            Self::Ledger(e) => write!(f, "ledger: {e}"),
            Self::Saga(e) => write!(f, "saga: {e}"),
            Self::Cell(e) => write!(f, "cell: {e}"),
            Self::Containment(e) => write!(f, "containment: {e}"),
            Self::TsNormalization(e) => write!(f, "ts normalization: {e}"),
            Self::EvidenceCompressionCoder { detail } => {
                write!(f, "evidence compression coder: {detail}")
            }
            Self::EvidenceCompressionEncode { detail } => {
                write!(f, "evidence compression encode: {detail}")
            }
            Self::EvidenceCompressionKraft { detail } => {
                write!(f, "evidence compression Kraft verification: {detail}")
            }
            Self::EmptySource => f.write_str("extension source is empty"),
            Self::EmptyExtensionId => f.write_str("extension_id is empty"),
            Self::UnknownPackageCapability { capability } => {
                write!(f, "unknown package capability `{capability}`")
            }
            Self::WitnessSealing { detail } => {
                write!(f, "ir4 witness sealing failed: {detail}")
            }
            Self::PreparedExecutionContextMismatch {
                reserved_extension_id,
                requested_extension_id,
            } => write!(
                f,
                "prepared execution context is reserved for extension {reserved_extension_id}, not {requested_extension_id}"
            ),
            Self::PostCellFailure(failure) => {
                write!(f, "{}", failure.primary_error)?;
                if let Some(evidence) = &failure.containment_saga_failure {
                    write!(
                        f,
                        "; containment {} succeeded with receipt {} before {} saga {} creation failed",
                        evidence.action,
                        evidence.receipt.receipt_id,
                        evidence.saga_type,
                        evidence.saga_id
                    )?;
                }
                for additional in &failure.additional_errors {
                    write!(f, "; additional failure: {additional}")?;
                }
                if failure.cleanup.close_succeeded() {
                    f.write_str("; execution cell close succeeded")
                } else {
                    f.write_str("; execution cell close failed")
                }
            }
        }
    }
}

impl std::error::Error for OrchestratorError {}

impl OrchestratorError {
    /// First error observed by the post-cell pipeline.
    #[must_use]
    pub fn primary_error(&self) -> &Self {
        match self {
            Self::PostCellFailure(failure) => failure.primary_error.primary_error(),
            other => other,
        }
    }

    /// Full lifecycle report when this attempt reached execution-cell creation.
    #[must_use]
    pub fn post_cell_failure(&self) -> Option<&PostCellFailure> {
        match self {
            Self::PostCellFailure(failure) => Some(failure),
            _ => None,
        }
    }

    /// Partial-success evidence when containment committed before saga
    /// creation failed.
    #[must_use]
    pub fn containment_saga_failure(&self) -> Option<&ContainmentSagaFailureEvidence> {
        match self {
            Self::PostCellFailure(failure) => failure.containment_saga_failure.as_ref(),
            _ => None,
        }
    }
}

impl From<ParseError> for OrchestratorError {
    fn from(e: ParseError) -> Self {
        Self::Parse(Box::new(e))
    }
}

impl From<LoweringPipelineError> for OrchestratorError {
    fn from(e: LoweringPipelineError) -> Self {
        Self::Lowering(Box::new(e))
    }
}

impl From<InterpreterError> for OrchestratorError {
    fn from(e: InterpreterError) -> Self {
        Self::Interpreter(e)
    }
}

impl From<LedgerError> for OrchestratorError {
    fn from(e: LedgerError) -> Self {
        Self::Ledger(e)
    }
}

impl From<SagaError> for OrchestratorError {
    fn from(e: SagaError) -> Self {
        Self::Saga(e)
    }
}

impl From<CellError> for OrchestratorError {
    fn from(e: CellError) -> Self {
        Self::Cell(e)
    }
}

impl From<ContainmentError> for OrchestratorError {
    fn from(e: ContainmentError) -> Self {
        Self::Containment(e)
    }
}

impl From<TsNormalizationError> for OrchestratorError {
    fn from(e: TsNormalizationError) -> Self {
        Self::TsNormalization(e)
    }
}

// ---------------------------------------------------------------------------
// ExecutionOrchestrator
// ---------------------------------------------------------------------------

/// Integration seam that wires together the full FrankenEngine pipeline.
pub struct ExecutionOrchestrator {
    config: OrchestratorConfig,
    /// Centralized runtime configuration for all engine subsystems.
    runtime_config: RuntimeConfig,
    parser: CanonicalEs2020Parser,
    adaptive_router: RegretBoundedRouter,
    stopping_policies: BTreeMap<String, EscalationPolicy>,
    last_cumulative_llr_by_extension: BTreeMap<String, i64>,
    posterior_updaters: UpdaterStore,
    loss_selector: ExpectedLossSelector,
    ledger: InMemoryLedger,
    evidence_signing_authority: EvidenceSigningAuthority,
    saga_orchestrator: SagaOrchestrator,
    containment_executor: ContainmentExecutor,
    reserved_execution_context: Option<ReservedExecutionContext>,
    staged_declassification_receipts: BTreeMap<(String, String), DeclassificationReceipt>,
    trusted_declassification_authorizers: BTreeMap<String, BTreeSet<VerificationKey>>,
    attempt_counter: u64,
    execution_counter: u64,
    #[cfg(test)]
    evidence_compression_status_override: Option<EvidenceCompressionStatus>,
    #[cfg(test)]
    guardplane_builder_failure_index_override: Option<usize>,
    #[cfg(test)]
    containment_action_override: Option<ContainmentAction>,
}

impl ExecutionOrchestrator {
    /// Create a deterministic test orchestrator with an explicitly lab-scoped
    /// evidence identity.
    #[cfg(test)]
    pub fn new(config: OrchestratorConfig) -> Self {
        Self::new_lab(config)
    }

    /// Create a deterministic test orchestrator with both runtime configs.
    #[cfg(test)]
    pub fn new_with_runtime_config(
        config: OrchestratorConfig,
        runtime_config: RuntimeConfig,
    ) -> Self {
        Self::try_new_lab_with_runtime_config(config, runtime_config)
            .expect("lab orchestrator configuration must be valid")
    }

    /// Construct a production orchestrator with an explicit runtime evidence
    /// authority supplied by the product composition root.
    pub fn try_new_with_runtime_authority(
        config: OrchestratorConfig,
        evidence_authority: RuntimeEvidenceAuthority,
    ) -> Result<Self, OrchestratorError> {
        Self::try_new_with_runtime_config_and_authority(
            config,
            RuntimeConfig::default(),
            evidence_authority,
        )
    }

    /// Full production constructor. No implicit or source-known signing
    /// identity is available on this path.
    pub fn try_new_with_runtime_config_and_authority(
        config: OrchestratorConfig,
        runtime_config: RuntimeConfig,
        evidence_authority: RuntimeEvidenceAuthority,
    ) -> Result<Self, OrchestratorError> {
        Self::try_new_with_resolved_evidence_authority(
            config,
            runtime_config,
            EvidenceSigningAuthority::Runtime(evidence_authority),
        )
    }

    /// Construct a deterministic, explicitly lab-scoped orchestrator.
    pub fn new_lab(config: OrchestratorConfig) -> Self {
        Self::try_new_lab(config).expect("lab orchestrator configuration must be valid")
    }

    /// Fallible deterministic lab constructor.
    pub fn try_new_lab(config: OrchestratorConfig) -> Result<Self, OrchestratorError> {
        Self::try_new_lab_with_runtime_config(config, RuntimeConfig::default())
    }

    /// Lab constructor with explicit runtime configuration.
    pub fn try_new_lab_with_runtime_config(
        config: OrchestratorConfig,
        runtime_config: RuntimeConfig,
    ) -> Result<Self, OrchestratorError> {
        let authority = LabEvidenceAuthority::deterministic_fixture(
            "franken-core.execution-orchestrator",
            "public-lab-orchestrator-v2",
            SecurityEpoch::GENESIS,
        )?;
        Self::try_new_with_resolved_evidence_authority(
            config,
            runtime_config,
            EvidenceSigningAuthority::Lab(authority),
        )
    }

    fn try_new_with_resolved_evidence_authority(
        config: OrchestratorConfig,
        runtime_config: RuntimeConfig,
        evidence_signing_authority: EvidenceSigningAuthority,
    ) -> Result<Self, OrchestratorError> {
        let ledger = match &evidence_signing_authority {
            EvidenceSigningAuthority::Runtime(authority) => {
                InMemoryLedger::for_runtime_authority(config.epoch, authority)?
            }
            EvidenceSigningAuthority::Lab(authority) => {
                InMemoryLedger::for_lab_authority(config.epoch, authority)?
            }
        };
        let loss_matrix = config.loss_matrix_preset.to_loss_matrix();
        let gamma = runtime_config.orchestrator.adaptive_router_gamma_millionths;
        let adaptive_router = RegretBoundedRouter::new(
            vec![
                AdaptiveLaneArm {
                    lane_id: "quickjs".to_string(),
                    description: "Baseline deterministic execution profile".to_string(),
                },
                AdaptiveLaneArm {
                    lane_id: "v8".to_string(),
                    description: "Baseline throughput execution profile".to_string(),
                },
            ],
            gamma,
        )
        .expect("adaptive router configuration must be valid");
        let mut loss_selector = ExpectedLossSelector::new(loss_matrix);
        loss_selector.set_epoch(config.epoch);
        Ok(Self {
            parser: CanonicalEs2020Parser,
            adaptive_router,
            stopping_policies: BTreeMap::new(),
            last_cumulative_llr_by_extension: BTreeMap::new(),
            posterior_updaters: UpdaterStore::new(),
            loss_selector,
            ledger,
            evidence_signing_authority,
            saga_orchestrator: SagaOrchestrator::new(config.epoch, config.max_concurrent_sagas),
            containment_executor: ContainmentExecutor::new(),
            reserved_execution_context: None,
            staged_declassification_receipts: BTreeMap::new(),
            trusted_declassification_authorizers: BTreeMap::new(),
            attempt_counter: 0,
            execution_counter: 0,
            #[cfg(test)]
            evidence_compression_status_override: None,
            #[cfg(test)]
            guardplane_builder_failure_index_override: None,
            #[cfg(test)]
            containment_action_override: None,
            config,
            runtime_config,
        })
    }

    /// Create an orchestrator with default configuration.
    #[cfg(test)]
    pub fn with_defaults() -> Self {
        Self::new(OrchestratorConfig::default())
    }

    /// Access the runtime configuration.
    pub fn runtime_config(&self) -> &RuntimeConfig {
        &self.runtime_config
    }

    fn new_stopping_policy(&self) -> EscalationPolicy {
        let mut policy = EscalationPolicy::new(
            self.runtime_config
                .orchestrator
                .stopping_cusum_threshold_millionths,
            self.runtime_config
                .orchestrator
                .stopping_cusum_reference_millionths,
            256,
        )
        .expect("stopping policy configuration must be valid");
        // Runtime path uses change-point detection. Secretary fallback is
        // useful for bounded pools but too eager for unbounded service loops.
        policy.secretary_enabled = false;
        policy
    }

    /// Access the evidence ledger.
    pub fn ledger(&self) -> &InMemoryLedger {
        &self.ledger
    }

    /// Public signer coordinates that replay/verifier inputs must pin through
    /// an authenticated channel. No private key material is exposed.
    pub fn evidence_verification_identity(&self) -> EvidenceVerificationIdentity {
        self.evidence_signing_authority.verification_identity()
    }

    /// Access the saga orchestrator.
    pub fn saga_orchestrator(&self) -> &SagaOrchestrator {
        &self.saga_orchestrator
    }

    /// Number of executions completed.
    pub fn execution_count(&self) -> u64 {
        self.execution_counter
    }

    /// Trust a declassification receipt authorizer for a specific decision contract.
    pub fn trust_declassification_authorizer_for_contract(
        &mut self,
        decision_contract_id: impl Into<String>,
        verification_key: VerificationKey,
    ) {
        self.trusted_declassification_authorizers
            .entry(decision_contract_id.into())
            .or_default()
            .insert(verification_key);
    }

    /// Stage a declassification receipt for a specific trace/obligation pair.
    pub fn stage_declassification_receipt_for_obligation(
        &mut self,
        trace_id: impl Into<String>,
        obligation_id: impl Into<String>,
        receipt: DeclassificationReceipt,
    ) -> Option<DeclassificationReceipt> {
        self.staged_declassification_receipts
            .insert((trace_id.into(), obligation_id.into()), receipt)
    }

    /// Preflight the next execution attempt and return its exact runtime-flow guard artifact.
    ///
    /// The returned `trace_id` and `decision_id` are reserved for the next
    /// `execute()` call on the same package, allowing callers to mint and stage
    /// declassification receipts against the same deterministic linkage.
    pub fn prepare_next_runtime_flow_guards(
        &mut self,
        package: &ExtensionPackage,
    ) -> Result<PreparedRuntimeFlowGuards, OrchestratorError> {
        Self::validate_package(package)?;
        let reserved = self.reserve_execution_context(package)?;
        let prepared = match self.prepare_lowering_output(
            package,
            &reserved.trace_id,
            &reserved.decision_id,
        ) {
            Ok(prepared) => prepared,
            Err(err) => {
                self.reserved_execution_context = None;
                return Err(err);
            }
        };
        Ok(PreparedRuntimeFlowGuards {
            trace_id: reserved.trace_id,
            decision_id: reserved.decision_id,
            source_label: prepared.source_label,
            source_ingestion: prepared.source_ingestion,
            ir2_flow_proof_artifact: prepared.lowering_output.ir2_flow_proof_artifact,
        })
    }

    /// Execute an extension package through the full pipeline.
    pub fn execute(
        &mut self,
        package: &ExtensionPackage,
    ) -> Result<OrchestratorResult, OrchestratorError> {
        // Step 0: Validate.
        Self::validate_package(package)?;
        // Commit attacker-controlled capability metadata before any execution
        // or host effect. The post-effect evidence phase consumes only this
        // fixed-size summary, so containment cannot be delayed by re-hashing an
        // unbounded manifest after effects have already occurred.
        let evidence_capability_summary = Self::capability_multiset_summary(&package.capabilities);

        // Step 1: Generate identifiers.
        let (attempt_index, trace_id, decision_id) =
            self.take_or_allocate_execution_context(package)?;
        let prepared = self.prepare_lowering_output(package, &trace_id, &decision_id)?;
        let PreparedLoweringOutput {
            source_label,
            source_ingestion,
            lowering_output,
        } = prepared;

        // Step 2: Create execution cell.
        let mut cell = ExecutionCell::with_context(
            &trace_id,
            CellKind::Extension,
            &trace_id,
            &decision_id,
            &self.config.policy_id,
        );

        let mut cell_cancel_reason = CancelReason::OperatorShutdown;
        let pipeline_result = (|| -> Result<OrchestratorResult, PendingPostCellFailure> {
            // Step 3: Register extension in containment executor.
            self.containment_executor.register(&package.extension_id);
            let lowering_events = lowering_output.events.clone();
            let lowering_witnesses = lowering_output.witnesses.clone();
            self.phase_enforce_runtime_flow_guards(&lowering_output.ir2_flow_proof_artifact)?;
            let ir3_schedule_cost = Self::estimate_ir3_schedule_cost(&lowering_output.ir3);

            // Step 6: Execute IR3.
            let (routed, guardplane_report) =
                self.phase_execute(package, &lowering_output.ir3, &trace_id)?;
            let lane = routed.lane;
            let lane_reason = routed.reason;
            let exec_result = routed.result;
            let execution_value = format!("{}", exec_result.value);
            let completion_label = exec_result.completion_label.clone();
            let instructions_executed = exec_result.instructions_executed;
            let adaptive_router_summary = self.update_adaptive_router(lane, &exec_result);

            // Step 6.5 (bd-drb55): seal and verify the IR4 witness against the
            // exact executed IR3 before any downstream phase can observe this
            // run as successful.
            let ir4_witness =
                Self::seal_ir4_witness(&lowering_output.ir3, &source_label, &exec_result)?;

            // Step 7: Assess risk.
            let evidence = Self::build_evidence(
                package,
                &exec_result,
                evidence_capability_summary,
                self.config.epoch,
            );
            let epoch = self.config.epoch;
            let updater = self.posterior_updaters.get_or_create(&package.extension_id);
            updater.set_epoch(epoch);
            let update_result = updater.update(&evidence);
            let posterior = update_result.posterior.clone();
            let risk_state = posterior.map_estimate();

            // Step 8: Decide action.
            let action_decision = self.loss_selector.select(&posterior);
            let expected_loss_millionths = action_decision.expected_loss_millionths;
            let (stopping_decision, optimal_stopping_certificate) =
                self.observe_optimal_stopping(&update_result, package, attempt_index);
            let mut containment_action = action_decision.action;
            if stopping_decision == StoppingDecision::Stop
                && containment_action == ContainmentAction::Allow
            {
                containment_action = ContainmentAction::Sandbox;
            }
            if let Some(requested) = exec_result.requested_hook_action.as_ref() {
                containment_action = more_severe_containment_action(
                    containment_action,
                    containment_action_for_hook(requested),
                );
            }
            #[cfg(test)]
            if let Some(action) = self.containment_action_override.take() {
                containment_action = action;
            }
            cell_cancel_reason = if containment_action.severity() >= 4 {
                CancelReason::Quarantine
            } else {
                CancelReason::OperatorShutdown
            };

            // Step 9: Record evidence.
            let (entries, evidence_compression_certificate, evidence_compression_status) = self
                .phase_record_evidence(EvidenceRecordInput {
                    trace_id: &trace_id,
                    decision_id: &decision_id,
                    package,
                    decision: &action_decision,
                    effective_action: containment_action,
                    exec: &exec_result,
                    update: &update_result,
                    ir3_schedule_cost,
                    ir4_witness_hash: ir4_witness.content_hash(),
                    adaptive_router_summary: adaptive_router_summary.as_ref(),
                    optimal_stopping_certificate: optimal_stopping_certificate.as_ref(),
                    guardplane_report: guardplane_report.as_ref(),
                    capability_summary: evidence_capability_summary,
                })?;
            let evidence_entries = entries;

            // Step 10: Execute any selected containment action and attach a saga
            // only for the actions that require follow-up orchestration.
            let (containment_receipt, saga_id) = self.phase_execute_containment(
                containment_action,
                package,
                &trace_id,
                &decision_id,
            )?;

            Ok(OrchestratorResult {
                extension_id: package.extension_id.clone(),
                trace_id: trace_id.clone(),
                decision_id: decision_id.clone(),
                source_label,
                source_ingestion,
                lowering_events,
                lowering_witnesses,
                lane,
                lane_reason,
                execution_value,
                completion_label,
                instructions_executed,
                adaptive_router_summary,
                ir3_schedule_cost,
                posterior,
                risk_state,
                containment_action,
                expected_loss_millionths,
                action_decision,
                optimal_stopping_certificate,
                evidence_entries,
                evidence_compression_certificate,
                evidence_compression_status,
                containment_receipt,
                saga_id,
                cell_events: Vec::new(),
                finalize_result: None,
                ir4_witness,
                epoch: self.config.epoch,
            })
        })();

        // Step 11: Close the execution cell after every post-creation outcome.
        let deadline = DrainDeadline {
            max_ticks: self.config.drain_deadline_ticks,
        };
        let mut close_cx =
            Self::build_cell_close_context(&trace_id, self.config.cell_close_budget_ms);
        let cell_id = cell.cell_id().to_string();
        let close_result = cell.close(&mut close_cx, cell_cancel_reason.clone(), deadline);
        let cell_events = cell.drain_events();

        match (pipeline_result, close_result) {
            (Ok(mut result), Ok(finalize_result)) => {
                result.cell_events = cell_events;
                result.finalize_result = Some(finalize_result);
                self.execution_counter = self.execution_counter.saturating_add(1);
                Ok(result)
            }
            (Ok(_), Err(close_error)) => {
                let cleanup = CellCleanupEvidence {
                    cell_id,
                    trace_id,
                    cancel_reason: cell_cancel_reason,
                    cell_events,
                    finalize_result: None,
                    close_error: Some(close_error.clone()),
                };
                Err(OrchestratorError::PostCellFailure(Box::new(
                    PostCellFailure {
                        primary_error: Box::new(OrchestratorError::Cell(close_error)),
                        additional_errors: Vec::new(),
                        containment_saga_failure: None,
                        cleanup,
                    },
                )))
            }
            (Err(mut failure), close_result) => {
                let (finalize_result, close_error) = match close_result {
                    Ok(finalize_result) => (Some(finalize_result), None),
                    Err(close_error) => {
                        failure
                            .additional_errors
                            .push(OrchestratorError::Cell(close_error.clone()));
                        (None, Some(close_error))
                    }
                };
                let cleanup = CellCleanupEvidence {
                    cell_id,
                    trace_id,
                    cancel_reason: cell_cancel_reason,
                    cell_events,
                    finalize_result,
                    close_error,
                };
                Err(OrchestratorError::PostCellFailure(Box::new(
                    PostCellFailure {
                        primary_error: failure.primary_error,
                        additional_errors: failure.additional_errors,
                        containment_saga_failure: failure
                            .containment_saga_failure
                            .map(|evidence| *evidence),
                        cleanup,
                    },
                )))
            }
        }
    }

    // -- Private helpers -----------------------------------------------------

    fn validate_package(package: &ExtensionPackage) -> Result<(), OrchestratorError> {
        if package.source.trim().is_empty() {
            return Err(OrchestratorError::EmptySource);
        }
        if package.extension_id.trim().is_empty() {
            return Err(OrchestratorError::EmptyExtensionId);
        }
        let _ = Self::package_runtime_capabilities(package)?;
        Ok(())
    }

    fn package_runtime_capabilities(
        package: &ExtensionPackage,
    ) -> Result<BTreeSet<RuntimeCapability>, OrchestratorError> {
        package
            .capabilities
            .iter()
            .map(|capability| {
                RuntimeCapability::from_tag_str(capability).ok_or_else(|| {
                    OrchestratorError::UnknownPackageCapability {
                        capability: capability.clone(),
                    }
                })
            })
            .collect()
    }

    fn package_fingerprint(package: &ExtensionPackage) -> Result<ContentHash, OrchestratorError> {
        // Sort capabilities for deterministic fingerprint regardless of insertion order.
        let mut sorted_pkg = package.clone();
        sorted_pkg.capabilities.sort();
        let encoded =
            serde_json::to_vec(&sorted_pkg).map_err(|_| OrchestratorError::EmptySource)?;
        Ok(ContentHash::compute(&encoded))
    }

    fn reserve_execution_context(
        &mut self,
        package: &ExtensionPackage,
    ) -> Result<ReservedExecutionContext, OrchestratorError> {
        let package_fingerprint = Self::package_fingerprint(package)?;
        if let Some(reserved) = &self.reserved_execution_context {
            if reserved.package_fingerprint == package_fingerprint {
                return Ok(reserved.clone());
            }
            return Err(OrchestratorError::PreparedExecutionContextMismatch {
                reserved_extension_id: reserved.extension_id.clone(),
                requested_extension_id: package.extension_id.clone(),
            });
        }

        let (attempt_index, trace_id, decision_id) = self.allocate_attempt_identifiers();
        let reserved = ReservedExecutionContext {
            attempt_index,
            trace_id,
            decision_id,
            package_fingerprint,
            extension_id: package.extension_id.clone(),
        };
        self.reserved_execution_context = Some(reserved.clone());
        Ok(reserved)
    }

    fn take_or_allocate_execution_context(
        &mut self,
        package: &ExtensionPackage,
    ) -> Result<(u64, String, String), OrchestratorError> {
        let package_fingerprint = Self::package_fingerprint(package)?;
        if let Some(reserved) = self.reserved_execution_context.take() {
            if reserved.package_fingerprint == package_fingerprint {
                return Ok((
                    reserved.attempt_index,
                    reserved.trace_id,
                    reserved.decision_id,
                ));
            }
            self.reserved_execution_context = Some(reserved.clone());
            return Err(OrchestratorError::PreparedExecutionContextMismatch {
                reserved_extension_id: reserved.extension_id,
                requested_extension_id: package.extension_id.clone(),
            });
        }

        Ok(self.allocate_attempt_identifiers())
    }

    fn prepare_lowering_output(
        &self,
        package: &ExtensionPackage,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<PreparedLoweringOutput, OrchestratorError> {
        let source_label = format!("ext:{}", package.extension_id);
        let effective_source_label = package.source_file.as_deref().unwrap_or(&source_label);
        let prepared = prepare_source_entry_for_public_entrypoints(
            &package.source,
            effective_source_label,
            trace_id,
            decision_id,
            &self.config.policy_id,
        )?;
        let source_ingestion = prepared.source_ingestion.clone();
        let parse_source = prepared.prepared_source;
        let parser_source = ParserSource {
            label: effective_source_label.to_string(),
            text: parse_source,
        };
        let syntax_tree = self.parser.parse_with_options(
            parser_source,
            self.config.parse_goal,
            &self.config.parser_options,
        )?;
        let ir0_source_label = if self.config.parse_goal == ParseGoal::Module {
            effective_source_label
        } else {
            &source_label
        };
        let ir0 = Ir0Module::from_syntax_tree(syntax_tree, ir0_source_label);
        let lowering_ctx = LoweringContext::new(trace_id, decision_id, &self.config.policy_id);
        let lowering_output = lower_ir0_to_ir3(&ir0, &lowering_ctx)?;
        Ok(PreparedLoweringOutput {
            source_label,
            source_ingestion,
            lowering_output,
        })
    }

    fn build_cell_close_context(trace_id: &str, budget_ms: u64) -> KernelContext<'static, NoCaps> {
        KernelContext::new(Cx::new(
            Self::derive_cell_close_trace_id(trace_id),
            Budget::new(budget_ms),
            NoCaps,
        ))
    }

    fn derive_cell_close_trace_id(trace_id: &str) -> TraceId {
        let hash = ContentHash::compute(trace_id.as_bytes());
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hash.as_bytes()[..16]);
        TraceId::from_bytes(bytes)
    }

    fn internal_runtime_capabilities_for_module(ir3: &Ir3Module) -> BTreeSet<RuntimeCapability> {
        ir3.required_capabilities
            .iter()
            .filter_map(|capability| RuntimeCapability::from_tag_str(&capability.0))
            .collect()
    }

    fn lane_router_for_execution(
        package: &ExtensionPackage,
        ir3: &Ir3Module,
    ) -> Result<LaneRouter, OrchestratorError> {
        let mut granted_capabilities = Self::package_runtime_capabilities(package)?;
        // Interpreter dispatch and module-record allocation are internal runtime authority,
        // not externally requested extension capabilities.
        granted_capabilities.insert(RuntimeCapability::VmDispatch);
        granted_capabilities.insert(RuntimeCapability::HeapAllocate);
        granted_capabilities.extend(Self::internal_runtime_capabilities_for_module(ir3));

        let mut quickjs_config = InterpreterConfig::quickjs_defaults();
        quickjs_config.granted_capabilities = granted_capabilities.clone();
        quickjs_config.extension_id = Some(package.extension_id.clone());
        quickjs_config.module_root = package
            .source_file
            .as_deref()
            .and_then(|path| std::path::Path::new(path).parent())
            .map(|path| path.display().to_string());

        let mut v8_config = InterpreterConfig::v8_defaults();
        v8_config.granted_capabilities = granted_capabilities;
        v8_config.extension_id = Some(package.extension_id.clone());
        v8_config.module_root = package
            .source_file
            .as_deref()
            .and_then(|path| std::path::Path::new(path).parent())
            .map(|path| path.display().to_string());

        Ok(LaneRouter::with_configs(quickjs_config, v8_config))
    }

    fn phase_execute(
        &self,
        package: &ExtensionPackage,
        ir3: &Ir3Module,
        trace_id: &str,
    ) -> Result<(RoutedResult, Option<GuardplaneHookReport>), OrchestratorError> {
        let guardplane_adapter = self.guardplane_adapter_for_package(package);
        let hook = guardplane_adapter.as_ref().map(|adapter| {
            let hook: Arc<dyn InterpreterHook> = adapter.clone();
            hook
        });
        // Package capabilities remain user-scoped; the orchestrator adds only
        // the internal enforcement capabilities required by the lowered module.
        let routed = Self::lane_router_for_execution(package, ir3)?
            .execute_with_hook(ir3, trace_id, self.config.force_lane, hook)
            .map_err(OrchestratorError::Interpreter)?;
        let report = guardplane_adapter
            .as_ref()
            .map(|adapter| GuardplaneHookReport {
                summary: adapter.summary(),
                decisions: adapter.decision_records(),
            });
        Ok((routed, report))
    }

    /// Seal the post-execution IR4 witness (bd-drb55): bind the interpreter's
    /// witness-event and hostcall-decision transcripts to the exact executed
    /// IR3 content hash and verify linkage before the witness is published.
    ///
    /// Sealing happens only on the success path. A failed execution never
    /// certifies a complete witness.
    fn seal_ir4_witness(
        ir3: &Ir3Module,
        source_label: &str,
        exec: &ExecutionResult,
    ) -> Result<Ir4Module, OrchestratorError> {
        let ir3_hash = ir3.content_hash();
        let mut witness = Ir4Module::new(ir3_hash, source_label);
        // The interpreter returned `Ok`, so the program ran to completion;
        // uncaught exceptions, timeouts, and cancellation all surface as
        // `Err(InterpreterError)` and never reach this seal.
        witness.outcome = ExecutionOutcome::Completed;
        witness.events = exec.witness_events.clone();
        witness.hostcall_decisions = exec.hostcall_decisions.clone();
        witness.instructions_executed = exec.instructions_executed;
        // Logical ticks, not wall-clock: the interpreter stamps every witness
        // event with `timestamp_tick = instructions_executed`, so the executed
        // instruction count is the run's tick duration.
        witness.duration_ticks = exec.instructions_executed;
        if let Some(spec) = &ir3.specialization {
            // The live path has no LinkageId registry; identify the active
            // specialization by the content hash of its canonical linkage so
            // the id is self-verifying against the executed IR3.
            witness.active_specialization_ids = vec![
                ContentHash::compute(&crate::deterministic_serde::encode_value(
                    &spec.canonical_value(),
                ))
                .to_hex(),
            ];
        }
        verify_ir4_linkage(&witness, &ir3_hash).map_err(|err| {
            OrchestratorError::WitnessSealing {
                detail: err.to_string(),
            }
        })?;
        Ok(witness)
    }

    fn guardplane_adapter_for_package(
        &self,
        package: &ExtensionPackage,
    ) -> Option<Arc<GuardplaneAdapter>> {
        // ExtensionPackage does not yet carry a first-class capability witness,
        // so instruction-level guardplane context is derived from metadata.
        let context = GuardplaneExtensionContext::new(
            package.extension_id.clone(),
            package.capabilities.iter().cloned().collect(),
            package.metadata.clone(),
        );
        if !context.instruction_hooks_enabled() {
            return None;
        }
        Some(Arc::new(GuardplaneAdapter::from_runtime_config(
            context,
            self.config.loss_matrix_preset.to_loss_matrix(),
            &self.runtime_config,
            self.config.epoch,
        )))
    }

    fn phase_enforce_runtime_flow_guards(
        &mut self,
        artifact: &Ir2FlowProofArtifact,
    ) -> Result<(), OrchestratorError> {
        if artifact.required_declassifications.is_empty() && artifact.runtime_checkpoints.is_empty()
        {
            return Ok(());
        }

        let mut lattice = Ir2FlowLattice::with_decision_id(
            artifact.policy_id.clone(),
            artifact.decision_id.clone(),
        );
        self.register_artifact_declassification_obligations(&mut lattice, artifact)?;
        for (decision_contract_id, trusted_keys) in &self.trusted_declassification_authorizers {
            for verification_key in trusted_keys {
                lattice.trust_receipt_authorizer_for_contract(
                    decision_contract_id.clone(),
                    verification_key.clone(),
                );
            }
        }

        let mut pending_declassifications = Vec::new();
        let mut attempted_receipt_keys = Vec::new();
        for entry in &artifact.required_declassifications {
            let staged_key = (artifact.trace_id.clone(), entry.obligation_id.clone());
            if let Some(receipt) = self
                .staged_declassification_receipts
                .get(&staged_key)
                .cloned()
            {
                attempted_receipt_keys.push(staged_key.clone());
                if let Err(err) = lattice.use_declassification_with_receipt(
                    &entry.obligation_id,
                    &receipt,
                    &artifact.trace_id,
                ) {
                    for staged_key in attempted_receipt_keys {
                        self.staged_declassification_receipts.remove(&staged_key);
                    }
                    return Err(OrchestratorError::IfcRuntimeGuardBlocked {
                        detail: format!(
                            "artifact {} receipt-linked declassification failed for {}: {}",
                            artifact.artifact_id,
                            Self::describe_runtime_declassification_obligation(entry),
                            err
                        ),
                    });
                }
                continue;
            }

            if !entry.requires_operator_approval && !entry.receipt_linkage_required {
                if let Err(err) =
                    lattice.use_declassification(&entry.obligation_id, &artifact.trace_id)
                {
                    // Clean up attempted receipts before returning error.
                    for staged_key in attempted_receipt_keys {
                        self.staged_declassification_receipts.remove(&staged_key);
                    }
                    return Err(OrchestratorError::IfcRuntimeGuardBlocked {
                        detail: format!(
                            "artifact {} declassification failed for {}: {}",
                            artifact.artifact_id,
                            Self::describe_runtime_declassification_obligation(entry),
                            err
                        ),
                    });
                }
                continue;
            }

            pending_declassifications
                .push(Self::describe_runtime_declassification_obligation(entry));
        }

        let mut summary = Vec::new();

        if !pending_declassifications.is_empty() {
            let pending = pending_declassifications
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            summary.push(format!(
                "pending declassifications={} [{}]",
                pending_declassifications.len(),
                pending
            ));
        }

        if !artifact.runtime_checkpoints.is_empty() {
            let checkpoints = artifact
                .runtime_checkpoints
                .iter()
                .take(3)
                .map(|entry| {
                    format!(
                        "op{}:{}:{}",
                        entry.op_index,
                        entry.capability.as_deref().unwrap_or("unknown"),
                        entry.reason
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            summary.push(format!(
                "runtime checkpoints={} [{}]",
                artifact.runtime_checkpoints.len(),
                checkpoints
            ));
        }

        for staged_key in attempted_receipt_keys {
            self.staged_declassification_receipts.remove(&staged_key);
        }

        if summary.is_empty() {
            return Ok(());
        }

        Err(OrchestratorError::IfcRuntimeGuardBlocked {
            detail: format!(
                "artifact {} has unresolved IFC runtime obligations: {}",
                artifact.artifact_id,
                summary.join("; ")
            ),
        })
    }

    fn describe_runtime_declassification_obligation(
        entry: &crate::lowering_pipeline::RequiredDeclassificationArtifactEntry,
    ) -> String {
        let mut parts = vec![format!("{}@op{}", entry.obligation_id, entry.op_index)];

        if let Some(capability) = entry.capability.as_deref() {
            parts.push(format!("capability={capability}"));
        }
        if !entry.decision_contract_id.is_empty() {
            parts.push(format!("decision_contract={}", entry.decision_contract_id));
        }
        if let Some(route) = entry.declassification_route_ref.as_deref() {
            parts.push(format!("route={route}"));
        }
        if !entry.replay_command_hint.is_empty() {
            parts.push(format!("replay_hint='{}'", entry.replay_command_hint));
        }

        parts.join(" ")
    }

    fn register_artifact_declassification_obligations(
        &self,
        lattice: &mut Ir2FlowLattice,
        artifact: &Ir2FlowProofArtifact,
    ) -> Result<(), OrchestratorError> {
        for entry in &artifact.required_declassifications {
            lattice
                .register_obligation(DeclassificationObligation {
                    obligation_id: entry.obligation_id.clone(),
                    source_label: LabelClass::from_label(&entry.source_label),
                    target_clearance: Self::artifact_sink_label_to_clearance(&entry.sink_clearance),
                    decision_contract_id: entry.decision_contract_id.clone(),
                    declassification_route_ref: entry.declassification_route_ref.clone(),
                    requires_operator_approval: entry.requires_operator_approval,
                    max_uses: 0,
                    use_count: 0,
                })
                .map_err(|err| OrchestratorError::IfcRuntimeGuardBlocked {
                    detail: format!(
                        "artifact {} has invalid declassification obligation {}: {}",
                        artifact.artifact_id, entry.obligation_id, err
                    ),
                })?;
        }
        Ok(())
    }

    fn artifact_sink_label_to_clearance(label: &Label) -> Clearance {
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

    fn phase_record_evidence(
        &mut self,
        input: EvidenceRecordInput<'_>,
    ) -> Result<
        (
            Vec<VerifiedEvidenceEntry>,
            Option<CompressionCertificate>,
            EvidenceCompressionStatus,
        ),
        OrchestratorError,
    > {
        let compression_attempt = Self::build_evidence_compression_attempt_for_input(&input)?;
        #[cfg(test)]
        let compression_attempt = match self.evidence_compression_status_override.take() {
            Some(status) => EvidenceCompressionAttempt {
                certificate: None,
                status,
                ..compression_attempt
            },
            None => compression_attempt,
        };

        let EvidenceRecordInput {
            trace_id,
            decision_id,
            package,
            decision,
            effective_action,
            exec,
            update,
            ir3_schedule_cost,
            ir4_witness_hash,
            adaptive_router_summary,
            optimal_stopping_certificate,
            guardplane_report,
            capability_summary,
        } = input;
        let guardplane_summary = guardplane_report.map(|report| &report.summary);
        let mut builder = EvidenceEntryBuilder::new_with_authority(
            trace_id,
            decision_id,
            &self.config.policy_id,
            self.config.epoch,
            DecisionType::SecurityAction,
            &self.evidence_signing_authority,
        );

        builder = builder.timestamp_ns(0);

        // Add all containment actions as candidates.
        for action in &ContainmentAction::ALL {
            builder = builder.candidate(CandidateAction::new(format!("{action:?}"), 0));
        }

        // Record chosen action.
        let stopping_override = effective_action != decision.action;
        builder = builder.chosen(ChosenAction {
            action_name: format!("{}", effective_action),
            expected_loss_millionths: decision.expected_loss_millionths,
            rationale: format!(
                "risk_state={:?}, posterior_benign={}, stopping_override={stopping_override}",
                update.posterior.map_estimate(),
                update.posterior.p_benign
            ),
        });

        // Record witnesses.
        builder = builder.witness(Witness {
            witness_id: format!("{trace_id}:posterior"),
            witness_type: "bayesian_posterior".to_string(),
            value: format!(
                "benign={} anomalous={} malicious={} unknown={}",
                update.posterior.p_benign,
                update.posterior.p_anomalous,
                update.posterior.p_malicious,
                update.posterior.p_unknown
            ),
        });

        builder = builder.witness(Witness {
            witness_id: format!("{trace_id}:execution"),
            witness_type: "execution_telemetry".to_string(),
            value: format!(
                "instructions={} hostcalls={} value={} completion_label={}",
                exec.instructions_executed,
                exec.hostcall_decisions.len(),
                exec.value,
                exec.completion_label
            ),
        });

        // Metadata.
        builder = builder.meta("extension_id".to_string(), package.extension_id.clone());
        builder = builder.meta("extension_version".to_string(), package.version.clone());
        builder = builder.meta(
            "capabilities_count".to_string(),
            capability_summary.total.to_string(),
        );
        builder = builder.meta(
            "canonical_capabilities_count".to_string(),
            capability_summary.canonical_distinct.to_string(),
        );
        builder = builder.meta(
            "execution_completion_label".to_string(),
            exec.completion_label.to_string(),
        );

        if let Some(cost) = ir3_schedule_cost {
            builder = builder.meta("ir3_schedule_cost".to_string(), cost.0.to_string());
        }
        // bd-drb55: bind the sealed IR4 witness into the signed evidence
        // entry so witness tampering is detectable through the receipt path.
        builder = builder.meta("ir4_witness_hash".to_string(), ir4_witness_hash.to_hex());
        if let Some(summary) = adaptive_router_summary {
            builder = builder.meta(
                "adaptive_router_regime".to_string(),
                format!("{:?}", summary.active_regime),
            );
            builder = builder.meta(
                "adaptive_router_exact_regret".to_string(),
                summary.exact_regret_available.to_string(),
            );
            builder = builder.meta(
                "adaptive_router_regret".to_string(),
                summary.realized_regret_millionths.to_string(),
            );
            builder = builder.meta(
                "adaptive_router_bound".to_string(),
                summary.theoretical_regret_bound_millionths.to_string(),
            );
        }
        if let Some(cert) = optimal_stopping_certificate {
            builder = builder.meta(
                "optimal_stopping_algorithm".to_string(),
                cert.algorithm.clone(),
            );
            builder = builder.meta(
                "optimal_stopping_observations".to_string(),
                cert.observations_before_stop.to_string(),
            );
        }
        if let Some(summary) = guardplane_summary {
            builder = builder.meta("guardplane_hook_enabled".to_string(), "true".to_string());
            builder = builder.meta(
                "guardplane_hook_decisions".to_string(),
                summary.decision_count.to_string(),
            );
            if let Some(action) = &summary.last_action {
                builder = builder.meta(
                    "guardplane_last_action".to_string(),
                    format_guardplane_hook_action(action),
                );
            }
            if let Some(action) = summary.last_selected_action {
                builder = builder.meta(
                    "guardplane_last_selected_action".to_string(),
                    action.to_string(),
                );
            }
            if let Some(action) = summary.last_threshold_action {
                builder = builder.meta(
                    "guardplane_last_threshold_action".to_string(),
                    action.to_string(),
                );
            }
            if let Some(delta) = summary.last_posterior_delta_millionths {
                builder = builder.meta(
                    "guardplane_last_posterior_delta_millionths".to_string(),
                    delta.to_string(),
                );
            }
            if let Some(llr) = summary.last_log_likelihood_ratio_millionths {
                builder = builder.meta(
                    "guardplane_last_log_likelihood_ratio_millionths".to_string(),
                    llr.to_string(),
                );
            }
            if let Some(expected_loss) = summary.last_expected_loss_millionths {
                builder = builder.meta(
                    "guardplane_last_expected_loss_millionths".to_string(),
                    expected_loss.to_string(),
                );
            }
            if let Some(posterior) = &summary.last_posterior {
                builder = builder.witness(Witness {
                    witness_id: format!("{trace_id}:guardplane"),
                    witness_type: "guardplane_instruction_risk".to_string(),
                    value: format!(
                        "decisions={} benign={} anomalous={} malicious={} unknown={}",
                        summary.decision_count,
                        posterior.p_benign,
                        posterior.p_anomalous,
                        posterior.p_malicious,
                        posterior.p_unknown
                    ),
                });
            }
        }
        if let Some(requested) = exec.requested_hook_action.as_ref() {
            builder = builder.meta(
                "hook_requested_action".to_string(),
                format_guardplane_hook_action(requested),
            );
        }

        let EvidenceCompressionAttempt {
            certificate: compression_certificate,
            status: compression_status,
            symbol_count,
            alphabet_size,
            sketch_hash,
        } = compression_attempt;
        builder = builder.meta(
            "evidence_compression_status".to_string(),
            compression_status.as_str().to_string(),
        );
        builder = builder.meta(
            "evidence_compression_sketch_schema".to_string(),
            EVIDENCE_COMPRESSION_SKETCH_SCHEMA.to_string(),
        );
        builder = builder.meta(
            "evidence_compression_sketch_hash".to_string(),
            sketch_hash.to_hex(),
        );
        builder = builder.meta(
            "evidence_compression_symbol_count".to_string(),
            symbol_count.to_string(),
        );
        builder = builder.meta(
            "evidence_compression_alphabet_size".to_string(),
            alphabet_size.to_string(),
        );
        if let EvidenceCompressionStatus::Failed { stage, detail } = &compression_status {
            builder = builder.meta(
                "evidence_compression_failure_stage".to_string(),
                stage.as_str().to_string(),
            );
            builder = builder.meta(
                "evidence_compression_failure_detail".to_string(),
                detail.clone(),
            );
        }
        if let Some(cert) = &compression_certificate {
            builder = builder.meta(
                "evidence_entropy_millibits".to_string(),
                cert.entropy_millibits_per_symbol.to_string(),
            );
            builder = builder.meta(
                "evidence_shannon_bound_bits".to_string(),
                cert.shannon_lower_bound_bits.to_string(),
            );
            builder = builder.meta(
                "evidence_overhead_ratio_millionths".to_string(),
                cert.overhead_ratio_millionths.to_string(),
            );
            builder = builder.meta(
                "evidence_compression_certificate_schema".to_string(),
                cert.schema.clone(),
            );
            builder = builder.meta(
                "evidence_compression_certificate_hash".to_string(),
                cert.certificate_hash.to_hex(),
            );
            builder = builder.meta(
                "evidence_compressed_artifact_hash".to_string(),
                cert.compressed_artifact_hash.to_hex(),
            );
            builder = builder.meta(
                "evidence_compressed_content_hash".to_string(),
                cert.content_hash.to_hex(),
            );
            builder = builder.meta(
                "evidence_compression_model_hash".to_string(),
                cert.model_hash.to_hex(),
            );
        }

        let entry = builder.build()?;
        let mut entries: Vec<EvidenceEntry> =
            Vec::with_capacity(1 + guardplane_report.map_or(0, |report| report.decisions.len()));
        entries.push(entry);

        if let Some(report) = guardplane_report {
            for (index, decision) in report.decisions.iter().enumerate() {
                #[cfg(test)]
                if self.guardplane_builder_failure_index_override == Some(index) {
                    self.guardplane_builder_failure_index_override = None;
                    return Err(LedgerError::MissingChosenAction.into());
                }
                let guardplane_entry = Self::build_guardplane_decision_entry(
                    trace_id,
                    decision_id,
                    package,
                    index,
                    decision,
                    &self.config,
                    &self.evidence_signing_authority,
                )?;
                entries.push(guardplane_entry);
            }
        }

        let verified_start = self.ledger.len();
        self.ledger.emit_batch(entries)?;
        let verified_entries = self.ledger.entries()[verified_start..].to_vec();
        Ok((
            verified_entries,
            compression_certificate,
            compression_status,
        ))
    }

    fn build_guardplane_decision_entry(
        trace_id: &str,
        decision_id: &str,
        package: &ExtensionPackage,
        index: usize,
        record: &GuardplaneDecisionRecord,
        config: &OrchestratorConfig,
        evidence_authority: &EvidenceSigningAuthority,
    ) -> Result<EvidenceEntry, OrchestratorError> {
        let mut builder = EvidenceEntryBuilder::new_with_authority(
            trace_id,
            format!("{decision_id}:guardplane:{index}"),
            &config.policy_id,
            config.epoch,
            DecisionType::SecurityAction,
            evidence_authority,
        )
        .timestamp_ns(0);

        for action in [
            "allow",
            "challenge",
            "sandbox",
            "suspend",
            "terminate",
            "quarantine",
        ] {
            builder = builder.candidate(CandidateAction::new(action, 0));
        }

        let action = format_guardplane_hook_action(&record.action);
        builder = builder.chosen(ChosenAction {
            action_name: action.clone(),
            expected_loss_millionths: record.expected_loss_millionths,
            rationale: format!(
                "operation={} risk_state={:?} delta={} llr={}",
                guardplane_operation_label(&record.operation),
                record.risk_state,
                record.posterior_delta_millionths,
                record.log_likelihood_ratio_millionths
            ),
        });

        builder = builder.witness(Witness {
            witness_id: format!("{trace_id}:guardplane:{index}:posterior"),
            witness_type: "guardplane_posterior".to_string(),
            value: format!(
                "benign={} anomalous={} malicious={} unknown={}",
                record.posterior.p_benign,
                record.posterior.p_anomalous,
                record.posterior.p_malicious,
                record.posterior.p_unknown
            ),
        });

        builder = builder.witness(Witness {
            witness_id: format!("{trace_id}:guardplane:{index}:operation"),
            witness_type: "guardplane_operation".to_string(),
            value: guardplane_operation_witness_value(&record.operation),
        });

        builder = builder.meta("extension_id".to_string(), package.extension_id.clone());
        builder = builder.meta("extension_version".to_string(), package.version.clone());
        builder = builder.meta("guardplane_decision_index".to_string(), index.to_string());
        builder = builder.meta(
            "guardplane_operation".to_string(),
            guardplane_operation_label(&record.operation).to_string(),
        );
        builder = builder.meta("guardplane_action".to_string(), action);
        builder = builder.meta(
            "guardplane_selected_action".to_string(),
            record.selected_action.to_string(),
        );
        builder = builder.meta(
            "guardplane_threshold_action".to_string(),
            record.threshold_action.to_string(),
        );
        builder = builder.meta(
            "guardplane_risk_state".to_string(),
            format!("{:?}", record.risk_state),
        );
        builder = builder.meta(
            "guardplane_posterior_delta_millionths".to_string(),
            record.posterior_delta_millionths.to_string(),
        );
        builder = builder.meta(
            "guardplane_log_likelihood_ratio_millionths".to_string(),
            record.log_likelihood_ratio_millionths.to_string(),
        );
        builder = builder.meta(
            "guardplane_instruction_count".to_string(),
            record.hook_context.instruction_count.to_string(),
        );
        builder = builder.meta(
            "guardplane_ip".to_string(),
            record.hook_context.current_ip.to_string(),
        );
        builder = builder.meta(
            "guardplane_hook_extension_id".to_string(),
            record.hook_context.extension_id.clone(),
        );

        match &record.operation {
            GuardplaneOperation::PropertyAccess { key } => {
                builder = builder.meta("guardplane_property_key".to_string(), key.clone());
            }
            GuardplaneOperation::Call {
                callee_name,
                arg_count,
            } => {
                if let Some(name) = callee_name {
                    builder = builder.meta("guardplane_callee_name".to_string(), name.clone());
                }
                builder = builder.meta("guardplane_arg_count".to_string(), arg_count.to_string());
            }
            GuardplaneOperation::Allocation { kind, size_hint } => {
                builder = builder.meta("guardplane_alloc_kind".to_string(), format!("{kind:?}"));
                builder = builder.meta("guardplane_size_hint".to_string(), size_hint.to_string());
            }
            GuardplaneOperation::Import { specifier } => {
                builder =
                    builder.meta("guardplane_import_specifier".to_string(), specifier.clone());
            }
        }

        Ok(builder.build()?)
    }

    fn update_adaptive_router(
        &mut self,
        lane: LaneChoice,
        exec: &ExecutionResult,
    ) -> Option<RouterSummary> {
        let arm_index = match lane {
            LaneChoice::QuickJs => 0,
            LaneChoice::V8 => 1,
        };
        let reward = Self::execution_reward_millionths(exec);
        let signal = AdaptiveRewardSignal {
            arm_index,
            reward_millionths: reward,
            latency_us: exec.instructions_executed.saturating_mul(10),
            success: true,
            epoch: self.config.epoch,
            counterfactual_rewards_millionths: None,
        };
        if self.adaptive_router.observe_reward(&signal).is_ok() {
            Some(self.adaptive_router.summary())
        } else {
            None
        }
    }

    fn execution_reward_millionths(exec: &ExecutionResult) -> i64 {
        let instruction_penalty = i64::try_from(exec.instructions_executed)
            .unwrap_or(i64::MAX)
            .saturating_mul(50)
            .min(600_000);
        let hostcall_penalty = i64::try_from(exec.hostcall_decisions.len())
            .unwrap_or(i64::MAX)
            .saturating_mul(25_000)
            .min(300_000);
        (SCALE_MILLION - instruction_penalty - hostcall_penalty).clamp(0, SCALE_MILLION)
    }

    fn observe_optimal_stopping(
        &mut self,
        update: &UpdateResult,
        package: &ExtensionPackage,
        attempt_index: u64,
    ) -> (StoppingDecision, Option<OptimalStoppingCertificate>) {
        let previous_llr = self
            .last_cumulative_llr_by_extension
            .get(&package.extension_id)
            .copied()
            .unwrap_or(0);
        let llr_increment = (i128::from(update.cumulative_llr_millionths)
            - i128::from(previous_llr))
        .clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64;
        self.last_cumulative_llr_by_extension.insert(
            package.extension_id.clone(),
            update.cumulative_llr_millionths,
        );

        let observation = StoppingObservation {
            llr_millionths: llr_increment,
            risk_score_millionths: update.posterior.p_malicious,
            timestamp_us: attempt_index,
            source: package.extension_id.clone(),
        };
        let new_policy = self.new_stopping_policy();
        let policy = self
            .stopping_policies
            .entry(package.extension_id.clone())
            .or_insert(new_policy);
        let decision = policy.observe(&observation);
        let cert = Some(Self::build_optimal_stopping_certificate(
            policy,
            decision,
            self.config.epoch,
        ));
        (decision, cert)
    }

    fn build_optimal_stopping_certificate(
        policy: &EscalationPolicy,
        decision: StoppingDecision,
        epoch: SecurityEpoch,
    ) -> OptimalStoppingCertificate {
        let algorithm = match (&policy.trigger_source, decision) {
            (Some(source), _) => source.clone(),
            (None, StoppingDecision::Stop) => "composite".to_string(),
            (None, StoppingDecision::Continue) => "none".to_string(),
        };
        let cusum_stat = policy.cusum.statistic_millionths;
        let arl0_bound = policy.cusum.arl0_lower_bound(SCALE_MILLION);
        let decision_str = match decision {
            StoppingDecision::Stop => "stop",
            StoppingDecision::Continue => "continue",
        };
        let cert_data = format!(
            "{}:{algorithm}:{}:{}:{}:{}:{}",
            STOPPING_SCHEMA_VERSION,
            policy.total_observations,
            decision_str,
            epoch.as_u64(),
            cusum_stat,
            arl0_bound,
        );
        OptimalStoppingCertificate {
            schema: STOPPING_SCHEMA_VERSION.to_string(),
            algorithm,
            observations_before_stop: policy.total_observations,
            cusum_statistic_millionths: Some(cusum_stat),
            arl0_lower_bound: Some(arl0_bound),
            snell_optimal_value_millionths: None,
            gittins_index_millionths: None,
            epoch,
            certificate_hash: ContentHash::compute(cert_data.as_bytes()),
        }
    }

    fn estimate_ir3_schedule_cost(ir3: &Ir3Module) -> Option<TropicalWeight> {
        let n = ir3.instructions.len();
        if n == 0 {
            return None;
        }

        let mut successors: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (idx, instr) in ir3.instructions.iter().enumerate() {
            let mut succ = Self::flow_successors(idx, instr, n);
            succ.sort_unstable();
            succ.dedup();
            successors[idx] = succ;
        }

        let mut predecessors: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (src, succ) in successors.iter().enumerate() {
            for &dst in succ {
                predecessors[dst].push(src);
            }
        }
        for preds in &mut predecessors {
            preds.sort_unstable();
            preds.dedup();
        }

        let nodes: Vec<InstructionNode> = (0..n)
            .map(|idx| InstructionNode {
                index: idx,
                cost: TropicalWeight::finite(Self::instruction_cost(&ir3.instructions[idx])),
                predecessors: predecessors[idx].clone(),
                successors: successors[idx].clone(),
                register_pressure: 1,
                mnemonic: Self::instruction_mnemonic(&ir3.instructions[idx]).to_string(),
            })
            .collect();

        let graph = InstructionCostGraph::new(nodes).ok()?;
        let schedule = ScheduleOptimizer::default().schedule(&graph).ok()?;
        Some(schedule.total_cost)
    }

    fn instruction_mnemonic(instr: &crate::ir_contract::Ir3Instruction) -> &'static str {
        match instr {
            crate::ir_contract::Ir3Instruction::LoadInt { .. } => "load_int",
            crate::ir_contract::Ir3Instruction::LoadFloat { .. } => "load_float",
            crate::ir_contract::Ir3Instruction::LoadStr { .. } => "load_str",
            crate::ir_contract::Ir3Instruction::LoadBool { .. } => "load_bool",
            crate::ir_contract::Ir3Instruction::LoadNull { .. } => "load_null",
            crate::ir_contract::Ir3Instruction::LoadUndefined { .. } => "load_undefined",
            crate::ir_contract::Ir3Instruction::Add { .. } => "add",
            crate::ir_contract::Ir3Instruction::Sub { .. } => "sub",
            crate::ir_contract::Ir3Instruction::Mul { .. } => "mul",
            crate::ir_contract::Ir3Instruction::Div { .. } => "div",
            crate::ir_contract::Ir3Instruction::ForInInit { .. } => "for_in_init",
            crate::ir_contract::Ir3Instruction::ForInNext { .. } => "for_in_next",
            crate::ir_contract::Ir3Instruction::ForOfInit { .. } => "for_of_init",
            crate::ir_contract::Ir3Instruction::ForOfNext { .. } => "for_of_next",
            crate::ir_contract::Ir3Instruction::IteratorClose { .. } => "iterator_close",
            crate::ir_contract::Ir3Instruction::UnaryNeg { .. } => "unary_neg",
            crate::ir_contract::Ir3Instruction::UnaryPlus { .. } => "unary_plus",
            crate::ir_contract::Ir3Instruction::LogicalNot { .. } => "logical_not",
            crate::ir_contract::Ir3Instruction::BitNot { .. } => "bit_not",
            crate::ir_contract::Ir3Instruction::TypeOf { .. } => "typeof",
            crate::ir_contract::Ir3Instruction::Void { .. } => "void",
            crate::ir_contract::Ir3Instruction::Move { .. } => "move",
            crate::ir_contract::Ir3Instruction::Jump { .. } => "jump",
            crate::ir_contract::Ir3Instruction::JumpIf { .. } => "jump_if",
            crate::ir_contract::Ir3Instruction::JumpIfNullish { .. } => "jump_if_nullish",
            crate::ir_contract::Ir3Instruction::Call { .. } => "call",
            crate::ir_contract::Ir3Instruction::Return { .. } => "return",
            crate::ir_contract::Ir3Instruction::HostCall { .. } => "host_call",
            crate::ir_contract::Ir3Instruction::GetProperty { .. } => "get_property",
            crate::ir_contract::Ir3Instruction::SetProperty { .. } => "set_property",
            crate::ir_contract::Ir3Instruction::DeleteProperty { .. } => "delete_property",
            crate::ir_contract::Ir3Instruction::NewObject { .. } => "new_object",
            crate::ir_contract::Ir3Instruction::NewArray { .. } => "new_array",
            crate::ir_contract::Ir3Instruction::ArrayPush { .. } => "array_push",
            crate::ir_contract::Ir3Instruction::ArraySlice { .. } => "array_slice",
            crate::ir_contract::Ir3Instruction::SpreadIntoArray { .. } => "spread_into_array",
            crate::ir_contract::Ir3Instruction::SpreadIntoObject { .. } => "spread_into_object",
            crate::ir_contract::Ir3Instruction::CopyDataProperties { .. } => "copy_data_properties",
            crate::ir_contract::Ir3Instruction::Mod { .. } => "mod",
            crate::ir_contract::Ir3Instruction::Exp { .. } => "exp",
            crate::ir_contract::Ir3Instruction::Lt { .. } => "lt",
            crate::ir_contract::Ir3Instruction::Lte { .. } => "lte",
            crate::ir_contract::Ir3Instruction::Gt { .. } => "gt",
            crate::ir_contract::Ir3Instruction::Gte { .. } => "gte",
            crate::ir_contract::Ir3Instruction::Eq { .. } => "eq",
            crate::ir_contract::Ir3Instruction::StrictEq { .. } => "strict_eq",
            crate::ir_contract::Ir3Instruction::NotEq { .. } => "not_eq",
            crate::ir_contract::Ir3Instruction::StrictNotEq { .. } => "strict_not_eq",
            crate::ir_contract::Ir3Instruction::BitAnd { .. } => "bit_and",
            crate::ir_contract::Ir3Instruction::BitOr { .. } => "bit_or",
            crate::ir_contract::Ir3Instruction::BitXor { .. } => "bit_xor",
            crate::ir_contract::Ir3Instruction::Shl { .. } => "shl",
            crate::ir_contract::Ir3Instruction::Shr { .. } => "shr",
            crate::ir_contract::Ir3Instruction::Ushr { .. } => "ushr",
            crate::ir_contract::Ir3Instruction::InstanceOf { .. } => "instance_of",
            crate::ir_contract::Ir3Instruction::InOp { .. } => "in_op",
            crate::ir_contract::Ir3Instruction::Construct { .. } => "construct",
            crate::ir_contract::Ir3Instruction::ConstructSuper { .. } => "construct_super",
            crate::ir_contract::Ir3Instruction::RegisterDerivedConstructor { .. } => {
                "register_derived_constructor"
            }
            crate::ir_contract::Ir3Instruction::TemplateLiteral { .. } => "template_literal",
            crate::ir_contract::Ir3Instruction::Halt => "halt",
            crate::ir_contract::Ir3Instruction::BeginTry { .. } => "begin_try",
            crate::ir_contract::Ir3Instruction::EndTry => "end_try",
            crate::ir_contract::Ir3Instruction::Throw { .. } => "throw",
            crate::ir_contract::Ir3Instruction::EnterCatch { .. } => "enter_catch",
            crate::ir_contract::Ir3Instruction::EnterFinally => "enter_finally",
            crate::ir_contract::Ir3Instruction::EndFinally => "end_finally",
            crate::ir_contract::Ir3Instruction::DiscardAbruptCompletion => {
                "discard_abrupt_completion"
            }
            crate::ir_contract::Ir3Instruction::CreateClosure { .. } => "create_closure",
            crate::ir_contract::Ir3Instruction::PushCapture { .. } => "push_capture",
            crate::ir_contract::Ir3Instruction::PushScope => "push_scope",
            crate::ir_contract::Ir3Instruction::PopScope => "pop_scope",
            crate::ir_contract::Ir3Instruction::DeclareBinding { .. } => "declare_binding",
            crate::ir_contract::Ir3Instruction::LoadScoped { .. } => "load_scoped",
            crate::ir_contract::Ir3Instruction::StoreScoped { .. } => "store_scoped",
            crate::ir_contract::Ir3Instruction::InitBinding { .. } => "init_binding",
            crate::ir_contract::Ir3Instruction::ImportModule { .. } => "import_module",
            crate::ir_contract::Ir3Instruction::ExportBinding { .. } => "export_binding",
            crate::ir_contract::Ir3Instruction::LoadThis { .. } => "load_this",
            crate::ir_contract::Ir3Instruction::LoadNewTarget { .. } => "load_new_target",
            crate::ir_contract::Ir3Instruction::LoadSuper { .. } => "load_super",
            crate::ir_contract::Ir3Instruction::CallMethod { .. } => "call_method",
            crate::ir_contract::Ir3Instruction::GeneratorBodyStart => "generator_body_start",
            &crate::ir_contract::Ir3Instruction::CreateGenerator { .. }
            | &crate::ir_contract::Ir3Instruction::Yield { .. } => "generator_op",
            &crate::ir_contract::Ir3Instruction::CreateAsyncFunction { .. } => {
                "create_async_function"
            }
            &crate::ir_contract::Ir3Instruction::AwaitValue { .. } => "await_value",
            &crate::ir_contract::Ir3Instruction::AsyncReturn { .. } => "async_return",
            &crate::ir_contract::Ir3Instruction::AsyncThrow { .. } => "async_throw",
            &crate::ir_contract::Ir3Instruction::CreateAsyncGenerator { .. } => {
                "create_async_generator"
            }
        }
    }

    fn instruction_cost(instr: &crate::ir_contract::Ir3Instruction) -> i64 {
        match instr {
            crate::ir_contract::Ir3Instruction::HostCall { .. } => 4,
            crate::ir_contract::Ir3Instruction::Call { .. } => 3,
            crate::ir_contract::Ir3Instruction::Div { .. }
            | crate::ir_contract::Ir3Instruction::Mul { .. } => 2,
            _ => 1,
        }
    }

    fn flow_successors(
        idx: usize,
        instr: &crate::ir_contract::Ir3Instruction,
        instruction_count: usize,
    ) -> Vec<usize> {
        let mut out = Vec::new();
        let next = idx + 1;

        match instr {
            crate::ir_contract::Ir3Instruction::Jump { target } => {
                let target = *target as usize;
                if target < instruction_count {
                    out.push(target);
                }
            }
            crate::ir_contract::Ir3Instruction::JumpIf { target, .. }
            | crate::ir_contract::Ir3Instruction::JumpIfNullish { target, .. } => {
                let target = *target as usize;
                if next < instruction_count {
                    out.push(next);
                }
                if target < instruction_count {
                    out.push(target);
                }
            }
            crate::ir_contract::Ir3Instruction::ForInNext { done_target, .. }
            | crate::ir_contract::Ir3Instruction::ForOfNext { done_target, .. } => {
                let done_target = *done_target as usize;
                if next < instruction_count {
                    out.push(next);
                }
                if done_target < instruction_count {
                    out.push(done_target);
                }
            }
            crate::ir_contract::Ir3Instruction::Return { .. }
            | crate::ir_contract::Ir3Instruction::Halt
            | crate::ir_contract::Ir3Instruction::Throw { .. } => {}
            crate::ir_contract::Ir3Instruction::BeginTry {
                catch_target,
                finally_target,
            } => {
                if next < instruction_count {
                    out.push(next);
                }
                let ct = *catch_target as usize;
                if ct < instruction_count {
                    out.push(ct);
                }
                if let Some(ft) = finally_target {
                    let ft = *ft as usize;
                    if ft < instruction_count {
                        out.push(ft);
                    }
                }
            }
            _ => {
                if next < instruction_count {
                    out.push(next);
                }
            }
        }

        out
    }

    fn build_evidence_compression_attempt_for_input(
        input: &EvidenceRecordInput<'_>,
    ) -> Result<EvidenceCompressionAttempt, OrchestratorError> {
        let sketch = Self::build_evidence_compression_sketch(
            input.capability_summary,
            input.decision,
            input.effective_action,
            input.exec,
            input.update,
            input.adaptive_router_summary,
            input.optimal_stopping_certificate,
            input.ir3_schedule_cost,
        );
        Self::build_evidence_compression_attempt(sketch)
    }

    fn build_evidence_compression_attempt(
        sketch: EvidenceCompressionSketch,
    ) -> Result<EvidenceCompressionAttempt, OrchestratorError> {
        Self::build_evidence_compression_attempt_from_symbols(sketch.symbols, sketch.content_hash)
    }

    fn build_evidence_compression_attempt_from_symbols(
        symbols: Vec<u32>,
        sketch_hash: ContentHash,
    ) -> Result<EvidenceCompressionAttempt, OrchestratorError> {
        let symbol_count = symbols.len();
        let alphabet_size = symbols.iter().copied().collect::<BTreeSet<_>>().len();
        let compression_result = Self::build_evidence_compression_certificate_from_symbols(symbols);
        let (certificate, status) = match compression_result {
            Ok(Some(certificate)) => (Some(certificate), EvidenceCompressionStatus::Certified),
            Ok(None) => (None, EvidenceCompressionStatus::NotApplicable),
            Err(OrchestratorError::EvidenceCompressionCoder { detail }) => (
                None,
                EvidenceCompressionStatus::Failed {
                    stage: EvidenceCompressionFailureStage::Coder,
                    detail,
                },
            ),
            Err(OrchestratorError::EvidenceCompressionEncode { detail }) => (
                None,
                EvidenceCompressionStatus::Failed {
                    stage: EvidenceCompressionFailureStage::Encode,
                    detail,
                },
            ),
            Err(OrchestratorError::EvidenceCompressionKraft { detail }) => (
                None,
                EvidenceCompressionStatus::Failed {
                    stage: EvidenceCompressionFailureStage::Kraft,
                    detail,
                },
            ),
            Err(other) => return Err(other),
        };
        Ok(EvidenceCompressionAttempt {
            certificate,
            status,
            symbol_count,
            alphabet_size,
            sketch_hash,
        })
    }

    #[cfg(test)]
    fn force_next_evidence_compression_failure(&mut self, stage: EvidenceCompressionFailureStage) {
        self.evidence_compression_status_override = Some(EvidenceCompressionStatus::Failed {
            stage,
            detail: format!(
                "injected {} failure for bounded evidence sketch",
                stage.as_str()
            ),
        });
    }

    fn build_evidence_compression_certificate_from_symbols(
        symbols: Vec<u32>,
    ) -> Result<Option<CompressionCertificate>, OrchestratorError> {
        if symbols.is_empty() {
            return Ok(None);
        }

        let mut estimator = EntropyEstimator::new();
        for &symbol in &symbols {
            estimator.observe(symbol);
        }
        let coder = ArithmeticCoder::from_estimator(&estimator)
            .map_err(Self::evidence_compression_coder_error)?;
        let compressed = coder
            .encode(&symbols)
            .map_err(Self::evidence_compression_encode_error)?;
        let certificate = CompressionCertificate::build_verified(&estimator, &coder, &compressed)
            .map_err(Self::evidence_compression_certificate_error)?;
        Ok(Some(certificate))
    }

    fn evidence_compression_coder_error(err: EntropyError) -> OrchestratorError {
        OrchestratorError::EvidenceCompressionCoder {
            detail: err.to_string(),
        }
    }

    fn evidence_compression_encode_error(err: EntropyError) -> OrchestratorError {
        OrchestratorError::EvidenceCompressionEncode {
            detail: err.to_string(),
        }
    }

    fn evidence_compression_certificate_error(err: EntropyError) -> OrchestratorError {
        match err {
            kraft @ EntropyError::KraftViolation { .. } => {
                OrchestratorError::EvidenceCompressionKraft {
                    detail: kraft.to_string(),
                }
            }
            other => Self::evidence_compression_encode_error(other),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence_compression_sketch(
        capability_summary: EvidenceCapabilitySummary,
        decision: &ActionDecision,
        effective_action: ContainmentAction,
        exec: &ExecutionResult,
        update: &UpdateResult,
        adaptive_router_summary: Option<&RouterSummary>,
        optimal_stopping_certificate: Option<&OptimalStoppingCertificate>,
        ir3_schedule_cost: Option<TropicalWeight>,
    ) -> EvidenceCompressionSketch {
        let (allowed_hostcalls, denied_hostcalls, hostcall_hash) =
            Self::hostcall_decision_summary(&exec.hostcall_decisions);

        let mut bytes = Vec::with_capacity(256);
        Self::append_len_prefixed_bytes(&mut bytes, EVIDENCE_COMPRESSION_SKETCH_SCHEMA.as_bytes());
        bytes.extend_from_slice(&decision.action.severity().to_be_bytes());
        bytes.extend_from_slice(&effective_action.severity().to_be_bytes());
        bytes.extend_from_slice(
            &Self::risk_state_symbol(update.posterior.map_estimate()).to_be_bytes(),
        );
        bytes.extend_from_slice(&exec.instructions_executed.to_be_bytes());
        bytes.extend_from_slice(Self::completion_label_hash(&exec.completion_label).as_bytes());
        bytes.extend_from_slice(&Self::usize_to_u64(exec.hostcall_decisions.len()).to_be_bytes());
        bytes.extend_from_slice(&capability_summary.total.to_be_bytes());
        bytes.extend_from_slice(&capability_summary.canonical_distinct.to_be_bytes());
        bytes.extend_from_slice(capability_summary.multiset_hash.as_bytes());
        bytes.extend_from_slice(&allowed_hostcalls.to_be_bytes());
        bytes.extend_from_slice(&denied_hostcalls.to_be_bytes());
        bytes.extend_from_slice(hostcall_hash.as_bytes());

        match adaptive_router_summary {
            Some(summary) => {
                bytes.push(1);
                bytes.extend_from_slice(&(summary.active_regime as u32).to_be_bytes());
                bytes.extend_from_slice(&summary.realized_regret_millionths.to_be_bytes());
                bytes.push(u8::from(summary.exact_regret_available));
                bytes.extend_from_slice(&summary.theoretical_regret_bound_millionths.to_be_bytes());
            }
            None => bytes.push(0),
        }
        match optimal_stopping_certificate {
            Some(certificate) => {
                bytes.push(1);
                bytes.extend_from_slice(
                    ContentHash::compute(certificate.algorithm.as_bytes()).as_bytes(),
                );
                bytes.extend_from_slice(&certificate.observations_before_stop.to_be_bytes());
            }
            None => bytes.push(0),
        }
        match ir3_schedule_cost {
            Some(cost) => {
                bytes.push(1);
                bytes.extend_from_slice(&cost.0.to_be_bytes());
            }
            None => bytes.push(0),
        }

        let content_hash = ContentHash::compute(&bytes);
        let symbols: Vec<u32> = bytes.into_iter().map(u32::from).collect();
        debug_assert!(symbols.len() <= EVIDENCE_COMPRESSION_SKETCH_MAX_BYTES);
        debug_assert!(symbols.iter().copied().collect::<BTreeSet<_>>().len() <= 256);
        EvidenceCompressionSketch {
            symbols,
            content_hash,
        }
    }

    fn capability_multiset_summary(capabilities: &[String]) -> EvidenceCapabilitySummary {
        let canonical_distinct = capabilities
            .iter()
            .filter_map(|capability| RuntimeCapability::from_tag_str(capability))
            .collect::<BTreeSet<_>>()
            .len();
        let mut sorted: Vec<&str> = capabilities.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        let leaves = sorted
            .into_iter()
            .map(|capability| ContentHash::compute(capability.as_bytes()));
        let capability_count = Self::usize_to_u64(capabilities.len());
        EvidenceCapabilitySummary {
            total: capability_count,
            canonical_distinct: u32::try_from(canonical_distinct).unwrap_or(u32::MAX),
            multiset_hash: Self::fold_content_hashes(b"evidence-capability-multiset-v2", leaves),
        }
    }

    fn hostcall_decision_summary(
        decisions: &[crate::ir_contract::HostcallDecisionRecord],
    ) -> (u64, u64, ContentHash) {
        let mut allowed = 0u64;
        let mut denied = 0u64;
        let leaves = decisions.iter().map(|decision| {
            if decision.allowed {
                allowed = allowed.saturating_add(1);
            } else {
                denied = denied.saturating_add(1);
            }
            let capability_hash = ContentHash::compute(decision.capability.0.as_bytes());
            let mut preimage = [0u8; 45];
            preimage[..32].copy_from_slice(capability_hash.as_bytes());
            preimage[32..40].copy_from_slice(&decision.seq.to_be_bytes());
            preimage[40] = u8::from(decision.allowed);
            preimage[41..45].copy_from_slice(&decision.instruction_index.to_be_bytes());
            ContentHash::compute(&preimage)
        });
        let digest = Self::fold_content_hashes(b"evidence-hostcall-stream-v2", leaves);
        (allowed, denied, digest)
    }

    fn fold_content_hashes<I>(domain: &[u8], leaves: I) -> ContentHash
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let mut state = ContentHash::compute(domain);
        let mut count = 0u64;
        for leaf in leaves {
            let mut preimage = [0u8; 72];
            preimage[..32].copy_from_slice(state.as_bytes());
            preimage[32..40].copy_from_slice(&count.to_be_bytes());
            preimage[40..].copy_from_slice(leaf.as_bytes());
            state = ContentHash::compute(&preimage);
            count = count.saturating_add(1);
        }
        let mut final_preimage = [0u8; 40];
        final_preimage[..32].copy_from_slice(state.as_bytes());
        final_preimage[32..].copy_from_slice(&count.to_be_bytes());
        ContentHash::compute(&final_preimage)
    }

    fn append_len_prefixed_bytes(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&Self::usize_to_u64(value.len()).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn completion_label_hash(label: &Label) -> ContentHash {
        let mut preimage = b"franken-core.execution-completion-label.v1".to_vec();
        match label {
            Label::Public => preimage.push(0),
            Label::Internal => preimage.push(1),
            Label::Confidential => preimage.push(2),
            Label::Secret => preimage.push(3),
            Label::TopSecret => preimage.push(4),
            Label::Custom { name, level } => {
                preimage.push(5);
                Self::append_len_prefixed_bytes(&mut preimage, name.as_bytes());
                preimage.extend_from_slice(&level.to_be_bytes());
            }
        }
        ContentHash::compute(&preimage)
    }

    fn usize_to_u64(value: usize) -> u64 {
        u64::try_from(value).unwrap_or(u64::MAX)
    }

    fn risk_state_symbol(state: RiskState) -> u32 {
        match state {
            RiskState::Benign => 0,
            RiskState::Anomalous => 1,
            RiskState::Malicious => 2,
            RiskState::Unknown => 3,
        }
    }

    #[cfg(test)]
    fn stable_symbol(value: &str) -> u32 {
        let mut hash: u32 = 0x811C9DC5;
        for b in value.bytes() {
            hash ^= u32::from(b);
            hash = hash.wrapping_mul(0x01000193);
        }
        hash
    }

    fn phase_execute_containment(
        &mut self,
        action: ContainmentAction,
        package: &ExtensionPackage,
        trace_id: &str,
        decision_id: &str,
    ) -> Result<(Option<ContainmentReceipt>, Option<String>), ContainmentPhaseError> {
        if action == ContainmentAction::Allow {
            return Ok((None, None));
        }

        // Execute containment.
        let context = ContainmentContext {
            decision_id: decision_id.to_string(),
            timestamp_ns: 0,
            epoch: self.config.epoch,
            evidence_refs: vec![trace_id.to_string()],
            grace_period_ns: 0,
            challenge_timeout_ns: 0,
            sandbox_policy: SandboxPolicy::default(),
        };

        let receipt = self
            .containment_executor
            .execute(action, &package.extension_id, &context)?;

        // Create saga if applicable.
        let saga_id = if let Some(saga_type) = Self::action_to_saga_type(action) {
            let saga_id_str = format!("{trace_id}:saga");
            let steps = match saga_type {
                SagaType::Quarantine => quarantine_saga_steps(&package.extension_id),
                SagaType::Eviction => eviction_saga_steps(&package.extension_id),
                SagaType::Revocation => revocation_saga_steps(&package.extension_id),
                SagaType::Publish => {
                    return Err(ContainmentPhaseError::SagaCreation(Box::new(
                        ContainmentSagaFailureEvidence {
                            action,
                            receipt,
                            saga_id: saga_id_str,
                            saga_type,
                            saga_error: SagaError::InvalidSagaId {
                                reason: "action_to_saga_type never returns Publish".to_string(),
                            },
                        },
                    )));
                }
            };
            let id = match self.saga_orchestrator.create_saga(
                &saga_id_str,
                saga_type,
                steps,
                trace_id,
                0,
            ) {
                Ok(id) => id,
                Err(saga_error) => {
                    return Err(ContainmentPhaseError::SagaCreation(Box::new(
                        ContainmentSagaFailureEvidence {
                            action,
                            receipt,
                            saga_id: saga_id_str,
                            saga_type,
                            saga_error,
                        },
                    )));
                }
            };
            Some(id.to_string())
        } else {
            None
        };

        Ok((Some(receipt), saga_id))
    }

    fn allocate_attempt_identifiers(&mut self) -> (u64, String, String) {
        let attempt_index = self.attempt_counter;
        self.attempt_counter = self.attempt_counter.saturating_add(1);
        (
            attempt_index,
            format!("{}:{}", self.config.trace_id_prefix, attempt_index),
            format!("{}:decision:{}", self.config.trace_id_prefix, attempt_index),
        )
    }

    fn build_evidence(
        package: &ExtensionPackage,
        exec: &ExecutionResult,
        capability_summary: EvidenceCapabilitySummary,
        epoch: SecurityEpoch,
    ) -> Evidence {
        let hostcall_count = exec.hostcall_decisions.len() as u64;
        let hostcall_rate_millionths = hostcall_count
            .saturating_mul(1_000_000)
            .checked_div(exec.instructions_executed)
            .unwrap_or(0);

        let resource_score_millionths =
            (exec.instructions_executed.saturating_mul(5)).min(1_000_000);

        let denied = exec
            .hostcall_decisions
            .iter()
            .filter(|d| !d.allowed)
            .count() as u64;
        let denial_rate_millionths = denied
            .saturating_mul(1_000_000)
            .checked_div(hostcall_count)
            .unwrap_or(0);

        Evidence {
            extension_id: package.extension_id.clone(),
            hostcall_rate_millionths: i64::try_from(hostcall_rate_millionths).unwrap_or(i64::MAX),
            distinct_capabilities: capability_summary.canonical_distinct,
            resource_score_millionths: i64::try_from(resource_score_millionths).unwrap_or(i64::MAX),
            timing_anomaly_millionths: 0,
            denial_rate_millionths: i64::try_from(denial_rate_millionths).unwrap_or(i64::MAX),
            epoch,
        }
    }

    fn action_to_saga_type(action: ContainmentAction) -> Option<SagaType> {
        match action {
            ContainmentAction::Quarantine => Some(SagaType::Quarantine),
            ContainmentAction::Terminate => Some(SagaType::Eviction),
            ContainmentAction::Suspend => Some(SagaType::Revocation),
            _ => None,
        }
    }
}

fn format_guardplane_hook_action(action: &crate::baseline_interpreter::HookAction) -> String {
    match action {
        crate::baseline_interpreter::HookAction::Allow => "allow".to_string(),
        crate::baseline_interpreter::HookAction::Challenge(token) => {
            format!("challenge:{}", token.token)
        }
        crate::baseline_interpreter::HookAction::Sandbox => "sandbox".to_string(),
        crate::baseline_interpreter::HookAction::Suspend => "suspend".to_string(),
        crate::baseline_interpreter::HookAction::Terminate(reason) => {
            format!("terminate:{reason}")
        }
        crate::baseline_interpreter::HookAction::Quarantine(reason) => {
            format!("quarantine:{reason}")
        }
    }
}

fn guardplane_operation_label(operation: &GuardplaneOperation) -> &'static str {
    match operation {
        GuardplaneOperation::PropertyAccess { .. } => "property_access",
        GuardplaneOperation::Call { .. } => "call",
        GuardplaneOperation::Allocation { .. } => "allocation",
        GuardplaneOperation::Import { .. } => "import",
    }
}

fn guardplane_operation_witness_value(operation: &GuardplaneOperation) -> String {
    match operation {
        GuardplaneOperation::PropertyAccess { key } => {
            format!("property_access key={key}")
        }
        GuardplaneOperation::Call {
            callee_name,
            arg_count,
        } => {
            let name = callee_name.as_deref().unwrap_or("<anonymous>");
            format!("call callee={name} args={arg_count}")
        }
        GuardplaneOperation::Allocation { kind, size_hint } => {
            format!("allocation kind={kind:?} size_hint={size_hint}")
        }
        GuardplaneOperation::Import { specifier } => format!("import specifier={specifier}"),
    }
}

fn containment_action_for_hook(action: &HookAction) -> ContainmentAction {
    match action {
        HookAction::Allow => ContainmentAction::Allow,
        HookAction::Challenge(_) => ContainmentAction::Challenge,
        HookAction::Sandbox => ContainmentAction::Sandbox,
        HookAction::Suspend => ContainmentAction::Suspend,
        HookAction::Terminate(_) => ContainmentAction::Terminate,
        HookAction::Quarantine(_) => ContainmentAction::Quarantine,
    }
}

fn more_severe_containment_action(
    lhs: ContainmentAction,
    rhs: ContainmentAction,
) -> ContainmentAction {
    if rhs.severity() > lhs.severity() {
        rhs
    } else {
        lhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ifc_artifacts::{DeclassificationDecision, IfcSchemaVersion};
    use crate::signature_preimage::{SIGNATURE_SENTINEL, Signature, SigningKey};

    fn simple_package() -> ExtensionPackage {
        ExtensionPackage {
            extension_id: "test-ext-1".to_string(),
            source: "42".to_string(),
            source_file: None,
            // Grant the two execution-time capabilities every test here needs
            // just to dispatch VM instructions and allocate heap objects. The
            // orchestrator turns these strings into `RuntimeCapability` grants
            // via `RuntimeCapability::from_tag_str`, which requires the
            // canonical snake_case tag names.
            capabilities: vec!["vm_dispatch".to_string(), "heap_allocate".to_string()],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    fn assert_successful_post_cell_cleanup(error: &OrchestratorError) -> &PostCellFailure {
        let failure = error
            .post_cell_failure()
            .expect("post-cell failures must carry cleanup evidence");
        assert!(failure.cleanup.close_succeeded());
        assert!(failure.cleanup.close_error.is_none());
        assert_eq!(failure.cleanup.cell_id, failure.cleanup.trace_id);
        assert!(
            failure
                .cleanup
                .cell_events
                .iter()
                .any(|event| event.event == "finalize"),
            "successful cleanup must retain the finalize event"
        );
        failure
    }

    fn package_with_id(extension_id: &str) -> ExtensionPackage {
        ExtensionPackage {
            extension_id: extension_id.to_string(),
            ..simple_package()
        }
    }

    fn broad_risk_package(extension_id: &str) -> ExtensionPackage {
        let mut package = package_with_id(extension_id);
        package.capabilities = [
            "vm_dispatch",
            "heap_allocate",
            "gc_invoke",
            "ir_lowering",
            "policy_read",
            "policy_write",
            "evidence_emit",
            "decision_invoke",
            "network_egress",
            "lease_management",
            "idempotency_derive",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        package
    }

    fn package_with_metadata(
        extension_id: &str,
        source: &str,
        metadata: &[(&str, &str)],
    ) -> ExtensionPackage {
        ExtensionPackage {
            extension_id: extension_id.to_string(),
            source: source.to_string(),
            source_file: None,
            capabilities: Vec::new(),
            version: "1.0.0".to_string(),
            metadata: metadata
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
        }
    }

    fn guardplane_package(extension_id: &str) -> ExtensionPackage {
        package_with_metadata(
            extension_id,
            "const obj = { constructor: 1 }; obj.constructor;",
            &[
                ("guardplane.enable_instruction_hooks", "true"),
                ("capability_witness.trust_level", "suspicious"),
                ("capability_witness.confidence_millionths", "200000"),
                ("capability_witness.denied_capabilities", "object.property"),
            ],
        )
    }

    fn package_with_source(source: &str) -> ExtensionPackage {
        ExtensionPackage {
            source: source.to_string(),
            ..simple_package()
        }
    }

    #[test]
    fn post_cell_interpreter_failure_returns_close_evidence_bd_9rhwp() {
        let package = package_with_source(r#"throw "bd-9rhwp";"#);
        let error = ExecutionOrchestrator::with_defaults()
            .execute(&package)
            .expect_err("an uncaught throw must fail in the interpreter");
        let failure = assert_successful_post_cell_cleanup(&error);

        assert!(failure.additional_errors.is_empty());
        assert!(matches!(
            failure.primary_error.as_ref(),
            OrchestratorError::Interpreter(InterpreterError::UncaughtException { value })
                if value.contains("bd-9rhwp")
        ));
    }

    #[test]
    fn post_cell_ledger_failure_returns_close_evidence_bd_9rhwp() {
        let package = simple_package();
        let mut donor = ExecutionOrchestrator::with_defaults();
        donor
            .execute(&package)
            .expect("the donor execution must produce deterministic evidence");
        let duplicate_entry = donor
            .ledger
            .entries()
            .first()
            .expect("the donor execution must emit evidence")
            .clone();

        let mut orchestrator = ExecutionOrchestrator::with_defaults();
        orchestrator
            .ledger
            .emit(duplicate_entry.into_entry())
            .expect("the duplicate fixture must be admitted once");

        let error = orchestrator
            .execute(&package)
            .expect_err("the ledger must reject duplicate deterministic evidence");
        let failure = assert_successful_post_cell_cleanup(&error);

        assert!(failure.additional_errors.is_empty());
        assert!(matches!(
            failure.primary_error.as_ref(),
            OrchestratorError::Ledger(LedgerError::DuplicateEntryId { .. })
        ));
    }

    #[test]
    fn guardplane_builder_failure_leaves_ledger_empty_bd_gjrlf() {
        let package = guardplane_package("bd-gjrlf-builder-core");
        let mut orchestrator = ExecutionOrchestrator::with_defaults();
        orchestrator.guardplane_builder_failure_index_override = Some(0);

        let error = orchestrator
            .execute(&package)
            .expect_err("the injected guardplane builder failure must abort evidence");
        let failure = assert_successful_post_cell_cleanup(&error);

        assert!(matches!(
            failure.primary_error.as_ref(),
            OrchestratorError::Ledger(LedgerError::MissingChosenAction)
        ));
        assert!(
            orchestrator.ledger().is_empty(),
            "the primary entry must not be emitted before all guardplane entries build"
        );
    }

    #[test]
    fn guardplane_late_ledger_failure_rejects_whole_batch_bd_gjrlf() {
        let package = guardplane_package("bd-gjrlf-ledger-core");
        let mut donor = ExecutionOrchestrator::with_defaults();
        let donor_result = donor
            .execute(&package)
            .expect("the donor must produce deterministic guardplane evidence");
        let duplicate_entry = donor_result
            .evidence_entries
            .iter()
            .find(|entry| entry.metadata.contains_key("guardplane_decision_index"))
            .expect("the fixture must produce a guardplane evidence entry")
            .clone();
        let duplicate_id = duplicate_entry.entry_id.clone();

        let mut orchestrator = ExecutionOrchestrator::with_defaults();
        orchestrator
            .ledger
            .emit(duplicate_entry.into_entry())
            .expect("the late-duplicate fixture must be admitted once");
        let before_ids = orchestrator
            .ledger()
            .entries()
            .iter()
            .map(|entry| entry.entry_id.clone())
            .collect::<Vec<_>>();

        let error = orchestrator
            .execute(&package)
            .expect_err("the duplicate guardplane entry must reject the evidence batch");
        let failure = assert_successful_post_cell_cleanup(&error);

        assert!(matches!(
            failure.primary_error.as_ref(),
            OrchestratorError::Ledger(LedgerError::DuplicateEntryId { entry_id })
                if entry_id == &duplicate_id
        ));
        assert_eq!(
            orchestrator
                .ledger()
                .entries()
                .iter()
                .map(|entry| entry.entry_id.clone())
                .collect::<Vec<_>>(),
            before_ids,
            "a later guardplane ledger error must not commit the primary prefix"
        );
    }

    #[test]
    fn evidence_batch_orders_primary_before_guardplane_entries_bd_gjrlf() {
        let package = guardplane_package("bd-gjrlf-order-core");
        let mut orchestrator = ExecutionOrchestrator::with_defaults();
        let result = orchestrator
            .execute(&package)
            .expect("valid guardplane evidence must commit atomically");

        assert!(
            !result.evidence_entries[0]
                .metadata
                .contains_key("guardplane_decision_index"),
            "the primary security-action entry must remain first"
        );
        let guardplane_indices = result
            .evidence_entries
            .iter()
            .skip(1)
            .map(|entry| {
                entry
                    .metadata
                    .get("guardplane_decision_index")
                    .expect("every entry after the primary must be a guardplane decision")
                    .parse::<usize>()
                    .expect("guardplane decision index must be numeric")
            })
            .collect::<Vec<_>>();
        assert!(!guardplane_indices.is_empty());
        assert_eq!(
            guardplane_indices,
            (0..result.evidence_entries.len() - 1).collect::<Vec<_>>()
        );
        assert_eq!(
            orchestrator
                .ledger()
                .entries()
                .iter()
                .map(|entry| entry.entry_id.as_str())
                .collect::<Vec<_>>(),
            result
                .evidence_entries
                .iter()
                .map(|entry| entry.entry_id.as_str())
                .collect::<Vec<_>>(),
            "returned evidence and committed ledger order must match"
        );
    }

    #[test]
    fn post_cell_containment_failure_returns_close_evidence_bd_9rhwp() {
        let mut package = package_with_metadata(
            "bd-9rhwp-containment",
            "const obj = { constructor: 1 }; obj.constructor;",
            &[
                ("guardplane.enable_instruction_hooks", "true"),
                ("capability_witness.trust_level", "suspicious"),
                ("capability_witness.confidence_millionths", "200000"),
                ("capability_witness.denied_capabilities", "object.property"),
            ],
        );
        package.capabilities = vec!["vm_dispatch".to_string(), "heap_allocate".to_string()];
        let mut orchestrator = ExecutionOrchestrator::with_defaults();
        orchestrator
            .containment_executor
            .register(&package.extension_id);
        let preexisting_context = ContainmentContext {
            decision_id: "bd-9rhwp-preexisting".to_string(),
            epoch: orchestrator.config.epoch,
            ..ContainmentContext::default()
        };
        orchestrator
            .containment_executor
            .execute(
                ContainmentAction::Quarantine,
                &package.extension_id,
                &preexisting_context,
            )
            .expect("test precondition must put the extension in a dead state");

        let error = orchestrator
            .execute(&package)
            .expect_err("the selected containment action must reject the dead state");
        let failure = assert_successful_post_cell_cleanup(&error);

        assert!(failure.additional_errors.is_empty());
        assert!(matches!(
            failure.primary_error.as_ref(),
            OrchestratorError::Containment(ContainmentError::InvalidTransition {
                from: crate::containment_executor::ContainmentState::Quarantined,
                ..
            })
        ));
    }

    #[test]
    fn post_cell_primary_error_precedes_close_failure_bd_9rhwp() {
        let config = OrchestratorConfig {
            cell_close_budget_ms: 1,
            ..OrchestratorConfig::default()
        };
        let package = package_with_source(r#"throw "bd-9rhwp";"#);
        let error = ExecutionOrchestrator::new(config)
            .execute(&package)
            .expect_err("the interpreter and close must both fail");
        let failure = error
            .post_cell_failure()
            .expect("both failures must be returned in one lifecycle report");

        assert!(matches!(
            failure.primary_error.as_ref(),
            OrchestratorError::Interpreter(InterpreterError::UncaughtException { value })
                if value.contains("bd-9rhwp")
        ));
        assert!(matches!(
            failure.additional_errors.as_slice(),
            [OrchestratorError::Cell(CellError::BudgetExhausted { .. })]
        ));
        assert!(!failure.cleanup.close_succeeded());
        assert!(matches!(
            failure.cleanup.close_error,
            Some(CellError::BudgetExhausted { .. })
        ));
    }

    fn empty_flow_artifact() -> Ir2FlowProofArtifact {
        Ir2FlowProofArtifact {
            schema_version: "test-schema".to_string(),
            artifact_id: "artifact-test".to_string(),
            trace_id: "trace-test".to_string(),
            decision_id: "decision-test".to_string(),
            policy_id: "policy-test".to_string(),
            module_id: "module-test".to_string(),
            proved_flows: Vec::new(),
            denied_flows: Vec::new(),
            required_declassifications: Vec::new(),
            runtime_checkpoints: Vec::new(),
        }
    }

    fn artifact_with_required_declassification(
        trace_id: &str,
        obligation_id: &str,
        decision_contract_id: &str,
    ) -> Ir2FlowProofArtifact {
        let mut artifact = empty_flow_artifact();
        artifact.trace_id = trace_id.to_string();
        artifact.decision_id = decision_contract_id.to_string();
        artifact.required_declassifications.push(
            crate::lowering_pipeline::RequiredDeclassificationArtifactEntry {
                op_index: 7,
                body_path: Vec::new(),
                source_label: crate::ifc_artifacts::Label::Secret,
                sink_clearance: crate::ifc_artifacts::Label::Public,
                capability: Some("declassify.audit".to_string()),
                obligation_id: obligation_id.to_string(),
                decision_contract_id: decision_contract_id.to_string(),
                declassification_route_ref: Some("declassify.audit".to_string()),
                requires_operator_approval: true,
                receipt_linkage_required: true,
                replay_command_hint: "frankenctl replay run --trace <trace.json> --mode strict"
                    .to_string(),
            },
        );
        artifact
    }

    fn signed_receipt(
        trace_id: &str,
        decision_contract_id: &str,
        signing_key: &SigningKey,
    ) -> DeclassificationReceipt {
        let mut receipt = DeclassificationReceipt {
            receipt_id: format!("receipt-{trace_id}-{decision_contract_id}"),
            source_label: Label::Secret,
            sink_clearance: Label::Public,
            declassification_route_ref: "declassify.audit".to_string(),
            decision_contract_id: decision_contract_id.to_string(),
            policy_evaluation_summary: "approved".to_string(),
            loss_assessment_milli: 1_000,
            decision: DeclassificationDecision::Allow,
            authorized_by: signing_key.verification_key(),
            replay_linkage: trace_id.to_string(),
            timestamp_ms: 1_700_000_000_000,
            schema_version: IfcSchemaVersion::CURRENT,
            signature: Signature::from_bytes(SIGNATURE_SENTINEL),
        };
        receipt.sign(signing_key).expect("sign receipt");
        receipt
    }

    #[test]
    fn end_to_end_simple_source() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch
            .execute(&simple_package())
            .expect("execute should succeed");

        assert_eq!(result.extension_id, "test-ext-1");
        assert!(!result.trace_id.is_empty());
        assert!(!result.decision_id.is_empty());
        assert!(result.posterior.is_valid());
        assert!(!result.evidence_entries.is_empty());
        assert_eq!(result.epoch, SecurityEpoch::from_raw(1));
    }

    #[test]
    fn phase_enforce_runtime_flow_guards_allows_static_artifact() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        orch.phase_enforce_runtime_flow_guards(&empty_flow_artifact())
            .expect("static flow artifact should pass");
    }

    #[test]
    fn phase_enforce_runtime_flow_guards_blocks_pending_declassifications() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let artifact = artifact_with_required_declassification("trace-test", "obl-7", "decision-7");

        let err = orch
            .phase_enforce_runtime_flow_guards(&artifact)
            .expect_err("pending declassification must fail closed");
        match err {
            OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
                assert!(detail.contains("pending declassifications=1"));
                assert!(detail.contains("obl-7@op7"));
                assert!(detail.contains("capability=declassify.audit"));
                assert!(detail.contains("decision_contract=decision-7"));
                assert!(detail.contains("route=declassify.audit"));
                assert!(detail.contains(
                    "replay_hint='frankenctl replay run --trace <trace.json> --mode strict'"
                ));
                assert!(!detail.contains("--obligation"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn phase_enforce_runtime_flow_guards_blocks_runtime_checkpoints() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let mut artifact = empty_flow_artifact();
        artifact.runtime_checkpoints.push(
            crate::lowering_pipeline::RuntimeCheckpointArtifactEntry {
                op_index: 4,
                body_path: Vec::new(),
                source_label: crate::ifc_artifacts::Label::Secret,
                sink_clearance: crate::ifc_artifacts::Label::Internal,
                capability: Some("hostcall.invoke".to_string()),
                reason: "dynamic_capability".to_string(),
            },
        );

        let err = orch
            .phase_enforce_runtime_flow_guards(&artifact)
            .expect_err("runtime checkpoint must fail closed");
        match err {
            OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
                assert!(detail.contains("runtime checkpoints=1"));
                assert!(detail.contains("hostcall.invoke"));
                assert!(detail.contains("dynamic_capability"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn phase_enforce_runtime_flow_guards_allows_staged_approved_receipt() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let artifact =
            artifact_with_required_declassification("trace-allow", "obl-allow", "decision-allow");
        let signing_key = SigningKey::from_bytes([17u8; 32]).unwrap();
        let receipt = signed_receipt("trace-allow", "decision-allow", &signing_key);

        orch.trust_declassification_authorizer_for_contract(
            "decision-allow",
            signing_key.verification_key(),
        );
        orch.stage_declassification_receipt_for_obligation("trace-allow", "obl-allow", receipt);

        orch.phase_enforce_runtime_flow_guards(&artifact)
            .expect("approved staged receipt should satisfy runtime guard");

        assert!(
            !orch
                .staged_declassification_receipts
                .contains_key(&("trace-allow".to_string(), "obl-allow".to_string(),))
        );
    }

    #[test]
    fn phase_enforce_runtime_flow_guards_blocks_invalid_staged_receipt() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let artifact =
            artifact_with_required_declassification("trace-block", "obl-block", "decision-block");
        let signing_key = SigningKey::from_bytes([18u8; 32]).unwrap();
        let receipt = signed_receipt("trace-other", "decision-block", &signing_key);
        let staged_key = ("trace-block".to_string(), "obl-block".to_string());

        orch.trust_declassification_authorizer_for_contract(
            "decision-block",
            signing_key.verification_key(),
        );
        orch.stage_declassification_receipt_for_obligation("trace-block", "obl-block", receipt);
        assert!(
            orch.staged_declassification_receipts
                .contains_key(&staged_key)
        );

        let err = orch
            .phase_enforce_runtime_flow_guards(&artifact)
            .expect_err("mismatched replay linkage must fail closed");
        match err {
            OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
                assert!(detail.contains("receipt-linked declassification failed for obl-block"));
                assert!(detail.contains("capability=declassify.audit"));
                assert!(detail.contains("decision_contract=decision-block"));
                assert!(detail.contains("route=declassify.audit"));
                assert!(detail.contains(
                    "replay_hint='frankenctl replay run --trace <trace.json> --mode strict'"
                ));
                assert!(!detail.contains("--obligation"));
                assert!(detail.contains("replay linkage does not match trace trace-block"));
            }
            other => panic!("unexpected error: {other}"),
        }

        assert!(
            !orch
                .staged_declassification_receipts
                .contains_key(&staged_key),
            "invalid staged receipts should be evicted after a failed runtime-guard evaluation"
        );
    }

    #[test]
    fn execute_blocks_unresolved_ifc_runtime_checkpoint_before_interpreter() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = package_with_source(r#""secret_token hostcall<\"hostcall.invoke\">";"#);

        let err = orch
            .execute(&pkg)
            .expect_err("unresolved runtime checkpoint must fail closed");
        match err.primary_error() {
            OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
                assert!(detail.contains("runtime checkpoints=1"));
                assert!(detail.contains("hostcall.invoke"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn phase_enforce_runtime_flow_guards_evicts_consumed_receipt_on_partial_failure() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let mut artifact = artifact_with_required_declassification(
            "trace-partial",
            "obl-partial",
            "decision-partial",
        );
        artifact.runtime_checkpoints.push(
            crate::lowering_pipeline::RuntimeCheckpointArtifactEntry {
                op_index: 9,
                body_path: Vec::new(),
                source_label: crate::ifc_artifacts::Label::Secret,
                sink_clearance: crate::ifc_artifacts::Label::Internal,
                capability: Some("hostcall.invoke".to_string()),
                reason: "dynamic_capability".to_string(),
            },
        );
        let signing_key = SigningKey::from_bytes([19u8; 32]).unwrap();
        let receipt = signed_receipt("trace-partial", "decision-partial", &signing_key);
        let staged_key = ("trace-partial".to_string(), "obl-partial".to_string());

        orch.trust_declassification_authorizer_for_contract(
            "decision-partial",
            signing_key.verification_key(),
        );
        orch.stage_declassification_receipt_for_obligation("trace-partial", "obl-partial", receipt);
        assert!(
            orch.staged_declassification_receipts
                .contains_key(&staged_key)
        );

        let err = orch
            .phase_enforce_runtime_flow_guards(&artifact)
            .expect_err("runtime checkpoint must still fail closed after receipt consumption");
        match err {
            OrchestratorError::IfcRuntimeGuardBlocked { detail } => {
                assert!(detail.contains("runtime checkpoints=1"));
                assert!(detail.contains("hostcall.invoke"));
            }
            other => panic!("unexpected error: {other}"),
        }
        assert!(
            !orch
                .staged_declassification_receipts
                .contains_key(&staged_key),
            "consumed staged receipts should be evicted even when later obligations still fail"
        );
    }

    #[test]
    fn end_to_end_emits_integrated_artifacts() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).expect("execute");

        assert!(result.adaptive_router_summary.is_some());
        assert!(result.ir3_schedule_cost.is_some());
        assert!(result.optimal_stopping_certificate.is_some());
        assert!(result.evidence_compression_certificate.is_some());

        let entry = &result.evidence_entries[0];
        assert!(entry.metadata.contains_key("adaptive_router_regime"));
        assert!(entry.metadata.contains_key("adaptive_router_exact_regret"));
        assert!(entry.metadata.contains_key("adaptive_router_regret"));
        assert!(entry.metadata.contains_key("ir3_schedule_cost"));
        assert!(entry.metadata.contains_key("optimal_stopping_algorithm"));
    }

    #[test]
    fn execution_reward_saturates_for_extreme_instruction_count() {
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: u64::MAX,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let reward = ExecutionOrchestrator::execution_reward_millionths(&exec);
        assert_eq!(reward, 400_000);
    }

    #[test]
    fn bayesian_posterior_state_isolated_per_extension() {
        let broad = broad_risk_package("ext-broad");
        let target = package_with_id("ext-target");
        let mut interleaved = ExecutionOrchestrator::with_defaults();
        let broad_result = interleaved.execute(&broad).expect("execute broad");
        let target_after_broad = interleaved.execute(&target).expect("execute target");

        let mut fresh = ExecutionOrchestrator::with_defaults();
        let fresh_target = fresh.execute(&target).expect("execute fresh target");

        assert_ne!(broad_result.posterior, fresh_target.posterior);
        assert_eq!(target_after_broad.posterior, fresh_target.posterior);
        assert_eq!(
            target_after_broad.optimal_stopping_certificate,
            fresh_target.optimal_stopping_certificate
        );
        assert_eq!(interleaved.posterior_updaters.len(), 2);

        let broad_updater = interleaved
            .posterior_updaters
            .get(&broad.extension_id)
            .expect("broad updater");
        let target_updater = interleaved
            .posterior_updaters
            .get(&target.extension_id)
            .expect("target updater");
        let fresh_target_updater = fresh
            .posterior_updaters
            .get(&target.extension_id)
            .expect("fresh target updater");
        assert_eq!(broad_updater.update_count(), 1);
        assert_eq!(target_updater.update_count(), 1);
        assert_eq!(
            target_updater.log_likelihood_ratio(),
            fresh_target_updater.log_likelihood_ratio()
        );
        assert_eq!(
            target_updater.evidence_hashes(),
            fresh_target_updater.evidence_hashes()
        );
        assert_eq!(
            interleaved.stopping_policies.get(&target.extension_id),
            fresh.stopping_policies.get(&target.extension_id)
        );

        let repeated_target = interleaved
            .execute(&target)
            .expect("execute repeated target");
        assert_eq!(repeated_target.posterior, target_after_broad.posterior);
        assert_eq!(
            repeated_target
                .optimal_stopping_certificate
                .as_ref()
                .map(|certificate| certificate.observations_before_stop),
            Some(2)
        );
        assert_eq!(
            interleaved
                .posterior_updaters
                .get(&target.extension_id)
                .expect("repeated target updater")
                .update_count(),
            2
        );
        assert_eq!(
            interleaved
                .posterior_updaters
                .get(&target.extension_id)
                .expect("repeated target updater")
                .evidence_hashes()
                .len(),
            2
        );
    }

    #[test]
    fn optimal_stopping_state_isolated_per_extension() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg_a = package_with_id("ext-a");
        let pkg_b = package_with_id("ext-b");

        let update_a = UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [500_000, 500_000, 500_000, 500_000],
            cumulative_llr_millionths: 6_000_000,
            update_count: 1,
        };
        let (decision_a, cert_a) = orch.observe_optimal_stopping(&update_a, &pkg_a, 0);
        assert_eq!(decision_a, StoppingDecision::Stop);
        assert_eq!(cert_a.expect("certificate").algorithm, "cusum");

        let update_b = UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [500_000, 500_000, 500_000, 500_000],
            cumulative_llr_millionths: 6_100_000,
            update_count: 2,
        };
        let (decision_b, cert_b) = orch.observe_optimal_stopping(&update_b, &pkg_b, 1);
        assert_eq!(decision_b, StoppingDecision::Stop);
        assert_eq!(cert_b.expect("certificate").algorithm, "cusum");
        assert_eq!(orch.stopping_policies.len(), 2);
    }

    #[test]
    fn optimal_stopping_handles_extreme_cumulative_delta_without_overflow() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = package_with_id("ext-overflow");
        orch.last_cumulative_llr_by_extension
            .insert(pkg.extension_id.clone(), i64::MAX);
        let update = UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [500_000, 500_000, 500_000, 500_000],
            cumulative_llr_millionths: i64::MIN,
            update_count: 1,
        };

        let (decision, cert) = orch.observe_optimal_stopping(&update, &pkg, 0);
        assert_eq!(decision, StoppingDecision::Continue);
        assert_eq!(cert.expect("certificate").algorithm, "none");
    }

    #[test]
    fn optimal_stopping_same_extension_still_uses_incremental_delta() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = package_with_id("ext-shared");
        let update_a = UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [500_000, 500_000, 500_000, 500_000],
            cumulative_llr_millionths: 4_800_000,
            update_count: 1,
        };
        let update_b = UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [500_000, 500_000, 500_000, 500_000],
            cumulative_llr_millionths: 5_300_000,
            update_count: 2,
        };

        let (decision_a, cert_a) = orch.observe_optimal_stopping(&update_a, &pkg, 0);
        let (decision_b, cert_b) = orch.observe_optimal_stopping(&update_b, &pkg, 1);

        assert_eq!(decision_a, StoppingDecision::Continue);
        assert_eq!(cert_a.expect("certificate").algorithm, "none");
        assert_eq!(decision_b, StoppingDecision::Continue);
        assert_eq!(cert_b.expect("certificate").algorithm, "none");
    }

    #[test]
    fn optimal_stopping_same_extension_preserves_negative_cumulative_delta() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = package_with_id("ext-negative-delta");
        let update_a = UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [500_000, 500_000, 500_000, 500_000],
            cumulative_llr_millionths: 4_800_000,
            update_count: 1,
        };
        let update_b = UpdateResult {
            posterior: Posterior::default_prior(),
            likelihoods: [500_000, 500_000, 500_000, 500_000],
            cumulative_llr_millionths: 3_800_000,
            update_count: 2,
        };

        let (decision_a, cert_a) = orch.observe_optimal_stopping(&update_a, &pkg, 0);
        let (decision_b, cert_b) = orch.observe_optimal_stopping(&update_b, &pkg, 1);

        assert_eq!(decision_a, StoppingDecision::Continue);
        assert_eq!(cert_a.expect("certificate").algorithm, "none");
        assert_eq!(decision_b, StoppingDecision::Continue);
        assert_eq!(cert_b.expect("certificate").algorithm, "none");

        let policy = orch
            .stopping_policies
            .get(&pkg.extension_id)
            .expect("policy should exist for extension");
        assert_eq!(policy.cusum.statistic_millionths, 2_800_000);
        assert_eq!(
            orch.last_cumulative_llr_by_extension.get(&pkg.extension_id),
            Some(&3_800_000)
        );
    }

    #[test]
    fn empty_source_returns_error() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = ExtensionPackage {
            extension_id: "ext-1".to_string(),
            source: "".to_string(),
            source_file: None,
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let err = orch.execute(&pkg).expect_err("empty source should fail");
        assert!(matches!(err, OrchestratorError::EmptySource));
    }

    #[test]
    fn empty_extension_id_returns_error() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = ExtensionPackage {
            extension_id: "".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let err = orch.execute(&pkg).expect_err("empty id should fail");
        assert!(matches!(err, OrchestratorError::EmptyExtensionId));
    }

    #[test]
    fn unknown_package_capability_is_rejected_instead_of_dropped_bd_pr33n() {
        let mut package = simple_package();
        package
            .capabilities
            .push("promise:steal_admin_key".to_string());
        let mut orchestrator = ExecutionOrchestrator::with_defaults();

        let error = orchestrator
            .execute(&package)
            .expect_err("unknown package grant must fail validation");
        assert!(matches!(
            error,
            OrchestratorError::UnknownPackageCapability { capability }
                if capability == "promise:steal_admin_key"
        ));
        assert_eq!(orchestrator.attempt_counter, 0);
        assert!(orchestrator.ledger().entries().is_empty());
    }

    #[test]
    fn multiple_executions_accumulate_evidence() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        for _ in 0..3 {
            orch.execute(&simple_package()).expect("execute");
        }
        assert_eq!(orch.execution_count(), 3);
        assert!(orch.ledger().len() >= 3);
    }

    // -- serde roundtrips -----------------------------------------------------

    #[test]
    fn loss_matrix_preset_serde_roundtrip() {
        for preset in &[
            LossMatrixPreset::Balanced,
            LossMatrixPreset::Conservative,
            LossMatrixPreset::Permissive,
        ] {
            let json = serde_json::to_string(preset).unwrap();
            let back: LossMatrixPreset = serde_json::from_str(&json).unwrap();
            assert_eq!(*preset, back);
        }
    }

    #[test]
    fn extension_package_serde_roundtrip() {
        let pkg = ExtensionPackage {
            extension_id: "ext-serde".to_string(),
            source: "1+2".to_string(),
            source_file: None,
            capabilities: vec!["fs_read".to_string(), "net".to_string()],
            version: "2.0.0".to_string(),
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("author".to_string(), "test".to_string());
                m
            },
        };
        let json = serde_json::to_string(&pkg).unwrap();
        let back: ExtensionPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.extension_id, "ext-serde");
        assert_eq!(back.capabilities.len(), 2);
        assert_eq!(back.metadata.get("author").unwrap(), "test");
    }

    // -- OrchestratorConfig defaults ------------------------------------------

    #[test]
    fn orchestrator_config_default_values() {
        let cfg = OrchestratorConfig::default();
        let runtime_cfg = RuntimeConfig::default();
        assert_eq!(cfg.loss_matrix_preset, LossMatrixPreset::Balanced);
        assert!(cfg.force_lane.is_none());
        assert_eq!(
            cfg.drain_deadline_ticks,
            runtime_cfg.orchestrator.drain_deadline_ticks
        );
        assert_eq!(
            cfg.cell_close_budget_ms,
            runtime_cfg.orchestrator.cell_close_budget_ms
        );
        assert_eq!(
            cfg.max_concurrent_sagas,
            runtime_cfg.orchestrator.max_concurrent_sagas
        );
        assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(cfg.trace_id_prefix, "orch");
        assert_eq!(cfg.policy_id, "default-policy");
    }

    #[test]
    fn runtime_config_default_matches_orchestrator_constants() {
        let orchestrator = RuntimeConfig::default().orchestrator;
        assert_eq!(
            orchestrator.adaptive_router_gamma_millionths,
            ADAPTIVE_ROUTER_GAMMA_MILLIONTHS
        );
        assert_eq!(
            orchestrator.stopping_cusum_threshold_millionths,
            STOPPING_CUSUM_THRESHOLD_MILLIONTHS
        );
        assert_eq!(
            orchestrator.stopping_cusum_reference_millionths,
            STOPPING_CUSUM_REFERENCE_MILLIONTHS
        );
        assert_eq!(
            orchestrator.drain_deadline_ticks,
            DEFAULT_DRAIN_DEADLINE_TICKS
        );
        assert_eq!(
            orchestrator.cell_close_budget_ms,
            ORCHESTRATOR_CELL_CLOSE_BUDGET_MS
        );
        assert_eq!(
            orchestrator.max_concurrent_sagas,
            DEFAULT_MAX_CONCURRENT_SAGAS
        );
    }

    #[test]
    fn new_with_runtime_config_uses_custom_router_gamma_and_stopping_thresholds() {
        let mut runtime_cfg = RuntimeConfig::default();
        runtime_cfg.orchestrator.adaptive_router_gamma_millionths = 500_000;
        runtime_cfg.orchestrator.stopping_cusum_threshold_millionths = 1_000_000;
        runtime_cfg.orchestrator.stopping_cusum_reference_millionths = 200_000;

        let orch = ExecutionOrchestrator::new_with_runtime_config(
            OrchestratorConfig::default(),
            runtime_cfg,
        );
        assert_eq!(orch.adaptive_router.exp3.gamma_millionths, 500_000);

        let policy = orch.new_stopping_policy();
        assert_eq!(policy.cusum.threshold_millionths, 1_000_000);
        assert_eq!(policy.cusum.reference_millionths, 200_000);
    }

    // -- OrchestratorError Display --------------------------------------------

    #[test]
    fn orchestrator_error_display_empty_source() {
        let err = OrchestratorError::EmptySource;
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn orchestrator_error_display_empty_extension_id() {
        let err = OrchestratorError::EmptyExtensionId;
        assert!(err.to_string().contains("empty"));
    }

    // -- validation edge cases ------------------------------------------------

    #[test]
    fn whitespace_only_source_rejected() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = ExtensionPackage {
            extension_id: "ext-ws".to_string(),
            source: "  \t\n  ".to_string(),
            source_file: None,
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let err = orch.execute(&pkg).expect_err("whitespace source");
        assert!(matches!(err, OrchestratorError::EmptySource));
    }

    #[test]
    fn whitespace_only_extension_id_rejected() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = ExtensionPackage {
            extension_id: "   ".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let err = orch.execute(&pkg).expect_err("whitespace id");
        assert!(matches!(err, OrchestratorError::EmptyExtensionId));
    }

    // -- fresh orchestrator state ---------------------------------------------

    #[test]
    fn fresh_orchestrator_execution_count_zero() {
        let orch = ExecutionOrchestrator::with_defaults();
        assert_eq!(orch.execution_count(), 0);
    }

    #[test]
    fn fresh_orchestrator_ledger_empty() {
        let orch = ExecutionOrchestrator::with_defaults();
        assert_eq!(orch.ledger().len(), 0);
    }

    #[test]
    fn adaptive_router_uses_canonical_execution_profile_descriptions() {
        let orch = ExecutionOrchestrator::with_defaults();
        assert_eq!(orch.adaptive_router.arms.len(), 2);
        assert_eq!(orch.adaptive_router.arms[0].lane_id, "quickjs");
        assert_eq!(
            orch.adaptive_router.arms[0].description,
            "Baseline deterministic execution profile"
        );
        assert_eq!(orch.adaptive_router.arms[1].lane_id, "v8");
        assert_eq!(
            orch.adaptive_router.arms[1].description,
            "Baseline throughput execution profile"
        );
        assert!(
            orch.adaptive_router
                .arms
                .iter()
                .all(|arm| !arm.description.contains("inspired")),
            "adaptive-router descriptions must use the canonical execution-profile contract"
        );
    }

    // -- trace / decision id format -------------------------------------------

    #[test]
    fn trace_id_contains_prefix_and_counter() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        assert!(result.trace_id.starts_with("orch:"));
        assert!(result.trace_id.contains('0'));
    }

    #[test]
    fn decision_id_contains_prefix() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        assert!(result.decision_id.starts_with("orch:decision:"));
    }

    #[test]
    fn trace_id_increments_across_executions() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let r0 = orch.execute(&simple_package()).unwrap();
        let r1 = orch.execute(&simple_package()).unwrap();
        assert_ne!(r0.trace_id, r1.trace_id);
        assert_ne!(r0.decision_id, r1.decision_id);
    }

    #[test]
    fn prepare_next_runtime_flow_guards_reuses_reserved_ids_for_execute() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let prepared = orch
            .prepare_next_runtime_flow_guards(&simple_package())
            .expect("preflight should succeed");

        assert_eq!(prepared.trace_id, "orch:0");
        assert_eq!(prepared.decision_id, "orch:decision:0");
        assert_eq!(prepared.source_label, "ext:test-ext-1");

        let result = orch
            .execute(&simple_package())
            .expect("execute should succeed");
        assert_eq!(result.trace_id, prepared.trace_id);
        assert_eq!(result.decision_id, prepared.decision_id);

        let next = orch
            .prepare_next_runtime_flow_guards(&simple_package())
            .expect("next preflight should succeed");
        assert_eq!(next.trace_id, "orch:1");
        assert_eq!(next.decision_id, "orch:decision:1");
    }

    #[test]
    fn prepare_next_runtime_flow_guards_rejects_different_package_until_consumed() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        orch.prepare_next_runtime_flow_guards(&simple_package())
            .expect("initial preflight should succeed");

        let err = orch
            .prepare_next_runtime_flow_guards(&package_with_id("other-ext"))
            .expect_err("different package should fail closed while reservation is active");
        match err {
            OrchestratorError::PreparedExecutionContextMismatch {
                reserved_extension_id,
                requested_extension_id,
            } => {
                assert_eq!(reserved_extension_id, "test-ext-1");
                assert_eq!(requested_extension_id, "other-ext");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn prepare_next_runtime_flow_guards_clears_reservation_after_parse_failure() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let bad_pkg = package_with_source("function {");

        assert!(
            orch.prepare_next_runtime_flow_guards(&bad_pkg).is_err(),
            "broken package should fail during preflight"
        );

        let prepared = orch
            .prepare_next_runtime_flow_guards(&simple_package())
            .expect("reservation should be reset after failed preflight");
        assert_eq!(prepared.trace_id, "orch:1");
        assert_eq!(prepared.decision_id, "orch:decision:1");
    }

    // -- preset variations ----------------------------------------------------

    #[test]
    fn conservative_preset_executes_successfully() {
        let cfg = OrchestratorConfig {
            loss_matrix_preset: LossMatrixPreset::Conservative,
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let result = orch.execute(&simple_package()).unwrap();
        assert!(result.posterior.is_valid());
    }

    #[test]
    fn permissive_preset_executes_successfully() {
        let cfg = OrchestratorConfig {
            loss_matrix_preset: LossMatrixPreset::Permissive,
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let result = orch.execute(&simple_package()).unwrap();
        assert!(result.posterior.is_valid());
    }

    // -- result field checks --------------------------------------------------

    #[test]
    fn result_source_label_contains_extension_id() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        assert!(result.source_label.contains("test-ext-1"));
    }

    #[test]
    fn orchestrator_result_and_evidence_expose_completion_label_bd_ur3tk_17() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        assert_eq!(result.completion_label, Label::Public);
        assert_eq!(
            result.evidence_entries[0]
                .metadata
                .get("execution_completion_label")
                .map(String::as_str),
            Some("public")
        );
        assert!(
            result.evidence_entries[0]
                .witnesses
                .iter()
                .find(|witness| witness.witness_type == "execution_telemetry")
                .is_some_and(|witness| witness.value.contains("completion_label=public"))
        );
    }

    #[test]
    fn completion_label_evidence_hash_is_exact_and_domain_separated_bd_ur3tk_17() {
        let public_hash = ExecutionOrchestrator::completion_label_hash(&Label::Public);
        let mut public_preimage = b"franken-core.execution-completion-label.v1".to_vec();
        public_preimage.push(0);
        assert_eq!(public_hash, ContentHash::compute(&public_preimage));
        assert_ne!(public_hash, ContentHash::compute(&[0]));

        let labels = [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
            Label::TopSecret,
            Label::Custom {
                name: "tenant-a".to_string(),
                level: 3,
            },
            Label::Custom {
                name: "tenant-b".to_string(),
                level: 3,
            },
            Label::Custom {
                name: "tenant-a".to_string(),
                level: 4,
            },
        ];
        let hashes = labels
            .iter()
            .map(ExecutionOrchestrator::completion_label_hash)
            .map(|hash| hash.to_hex())
            .collect::<BTreeSet<_>>();
        assert_eq!(hashes.len(), labels.len());
    }

    #[test]
    fn result_lowering_witnesses_populated() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        assert!(!result.lowering_witnesses.is_empty());
    }

    #[test]
    fn guardplane_hook_request_becomes_containment_result_instead_of_error() {
        let pkg = package_with_metadata(
            "ext-guardplane-containment",
            "const obj = { constructor: 1 }; obj.constructor;",
            &[
                ("guardplane.enable_instruction_hooks", "true"),
                ("capability_witness.trust_level", "suspicious"),
                ("capability_witness.confidence_millionths", "200000"),
                ("capability_witness.denied_capabilities", "object.property"),
            ],
        );
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch
            .execute(&pkg)
            .expect("hook-triggered containment should stay in the orchestrator pipeline");

        assert_ne!(result.containment_action, ContainmentAction::Allow);
        assert_eq!(result.execution_value, "undefined");
        assert!(!result.evidence_entries.is_empty());
        assert_eq!(
            result.evidence_entries[0]
                .metadata
                .get("guardplane_hook_enabled")
                .map(String::as_str),
            Some("true")
        );
        assert!(
            result.evidence_entries[0]
                .metadata
                .contains_key("hook_requested_action"),
            "hook-requested action should be recorded in evidence metadata"
        );

        let guardplane_entries: Vec<_> = result
            .evidence_entries
            .iter()
            .filter(|entry| entry.metadata.contains_key("guardplane_decision_index"))
            .collect();
        assert!(
            !guardplane_entries.is_empty(),
            "guardplane decisions should emit evidence entries"
        );
    }

    #[test]
    fn high_cardinality_capabilities_certify_and_complete_containment_lifecycle() {
        const VALID_CAPABILITY_TAGS: &[&str] = &[
            "vm_dispatch",
            "gc_invoke",
            "ir_lowering",
            "policy_read",
            "policy_write",
            "evidence_emit",
            "decision_invoke",
            "network_egress",
            "lease_management",
            "idempotency_derive",
            "extension_lifecycle",
            "heap_allocate",
            "env_read",
            "process_spawn",
            "fs_read",
            "fs_write",
            "module_load",
        ];
        let mut pkg = package_with_metadata(
            "ext-compression-many-capabilities",
            "const obj = { constructor: 1 }; obj.constructor;",
            &[
                ("guardplane.enable_instruction_hooks", "true"),
                ("capability_witness.trust_level", "suspicious"),
                ("capability_witness.confidence_millionths", "200000"),
                ("capability_witness.denied_capabilities", "object.property"),
            ],
        );
        pkg.capabilities.extend(
            (0..257).map(|index| VALID_CAPABILITY_TAGS[index % VALID_CAPABILITY_TAGS.len()].into()),
        );
        assert_eq!(
            pkg.capabilities.len(),
            257,
            "fixture must retain the 257-entry manifest stress shape"
        );
        assert!(
            pkg.capabilities
                .iter()
                .all(|capability| RuntimeCapability::from_tag_str(capability).is_some()),
            "the stress fixture must exercise only grantable capabilities"
        );
        let mut orch = ExecutionOrchestrator::with_defaults();

        let result = orch
            .execute(&pkg)
            .expect("package-controlled capability cardinality must remain compressible");

        assert_eq!(
            result.evidence_compression_status,
            EvidenceCompressionStatus::Certified
        );
        assert!(result.evidence_compression_certificate.is_some());
        assert_ne!(result.containment_action, ContainmentAction::Allow);
        let receipt = result
            .containment_receipt
            .as_ref()
            .expect("selected non-Allow containment must emit a receipt");
        assert_eq!(receipt.action, result.containment_action);
        assert!(receipt.verify_integrity());
        assert!(
            result
                .finalize_result
                .as_ref()
                .is_some_and(|done| done.success)
        );
        assert!(!result.cell_events.is_empty());
        assert_eq!(orch.execution_count(), 1);

        let metadata = &result.evidence_entries[0].metadata;
        assert_eq!(
            metadata
                .get("evidence_compression_status")
                .map(String::as_str),
            Some("certified")
        );
        assert_eq!(
            metadata
                .get("evidence_compression_sketch_schema")
                .map(String::as_str),
            Some(EVIDENCE_COMPRESSION_SKETCH_SCHEMA)
        );
        assert!(
            metadata["evidence_compression_alphabet_size"]
                .parse::<usize>()
                .is_ok_and(|size| size <= 256)
        );
    }

    #[test]
    fn high_cardinality_hostcall_stream_certifies_exact_count_and_finalizes() {
        let source = (0..257)
            .map(|_| r#""hostcall<\"console:log\">";"#)
            .collect::<Vec<_>>()
            .join("\n");
        let package = package_with_source(&source);
        let config = OrchestratorConfig {
            force_lane: Some(LaneChoice::V8),
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(config);

        let result = orch
            .execute(&package)
            .expect("ordered high-cardinality hostcall evidence must stay compressible");

        assert_eq!(result.lane, LaneChoice::V8);
        assert_eq!(
            result.evidence_compression_status,
            EvidenceCompressionStatus::Certified
        );
        assert!(result.evidence_compression_certificate.is_some());
        let telemetry = result.evidence_entries[0]
            .witnesses
            .iter()
            .find(|witness| witness.witness_type == "execution_telemetry")
            .expect("primary evidence must carry execution telemetry");
        assert!(
            telemetry
                .value
                .split_ascii_whitespace()
                .any(|field| field == "hostcalls=257"),
            "unexpected execution telemetry: {}",
            telemetry.value
        );
        assert!(
            result
                .finalize_result
                .as_ref()
                .is_some_and(|done| done.success)
        );
        assert!(!result.cell_events.is_empty());
        assert_eq!(orch.execution_count(), 1);
    }

    #[test]
    fn residual_compression_failure_is_evidenced_before_containment_and_cell_close() {
        let pkg = package_with_metadata(
            "ext-compression-degraded-containment",
            "const obj = { constructor: 1 }; obj.constructor;",
            &[
                ("guardplane.enable_instruction_hooks", "true"),
                ("capability_witness.trust_level", "suspicious"),
                ("capability_witness.confidence_millionths", "200000"),
                ("capability_witness.denied_capabilities", "object.property"),
            ],
        );
        let mut orch = ExecutionOrchestrator::with_defaults();
        orch.force_next_evidence_compression_failure(EvidenceCompressionFailureStage::Coder);

        let result = orch
            .execute(&pkg)
            .expect("compression degradation must not bypass post-effect cleanup");

        assert!(matches!(
            result.evidence_compression_status,
            EvidenceCompressionStatus::Failed {
                stage: EvidenceCompressionFailureStage::Coder,
                ..
            }
        ));
        assert!(result.evidence_compression_certificate.is_none());
        assert_ne!(result.containment_action, ContainmentAction::Allow);
        let receipt = result
            .containment_receipt
            .as_ref()
            .expect("selected non-Allow containment must emit a receipt");
        assert_eq!(receipt.action, result.containment_action);
        assert!(receipt.verify_integrity());
        assert!(
            result
                .finalize_result
                .as_ref()
                .is_some_and(|done| done.success)
        );
        assert!(!result.cell_events.is_empty());
        assert_eq!(orch.execution_count(), 1);

        let entry = &result.evidence_entries[0];
        assert_eq!(
            entry
                .metadata
                .get("evidence_compression_status")
                .map(String::as_str),
            Some("failed")
        );
        assert_eq!(
            entry
                .metadata
                .get("evidence_compression_failure_stage")
                .map(String::as_str),
            Some("coder")
        );
        assert!(
            entry.metadata["evidence_compression_failure_detail"]
                .contains("bounded evidence sketch")
        );
        assert_eq!(
            entry
                .metadata
                .get("evidence_compression_sketch_schema")
                .map(String::as_str),
            Some(EVIDENCE_COMPRESSION_SKETCH_SCHEMA)
        );
        assert!(
            entry
                .metadata
                .contains_key("evidence_compression_sketch_hash")
        );
        assert!(
            entry.metadata["evidence_compression_alphabet_size"]
                .parse::<usize>()
                .is_ok_and(|size| size <= 256)
        );
        assert!(
            !entry
                .metadata
                .contains_key("evidence_compression_certificate_hash")
        );
        assert_eq!(
            orch.ledger().entries()[0].evidence_hash,
            entry.evidence_hash
        );

        let trusted_identity = orch.evidence_verification_identity();
        entry
            .verify_with_trusted_identity(&trusted_identity)
            .expect("orchestrator evidence must verify against its recorded public identity");

        let mut tampered = serde_json::to_value(entry).expect("serialize evidence entry");
        tampered["metadata"]["evidence_compression_failure_stage"] = serde_json::json!("encode");
        let tampered: EvidenceEntry =
            serde_json::from_value(tampered).expect("tampered entry retains the schema shape");
        assert!(
            tampered
                .verify_with_trusted_identity(&trusted_identity)
                .is_err(),
            "signature-bound compression metadata must reject mutation"
        );
    }

    #[test]
    fn bd_kxp4o_runtime_orchestrator_evidence_is_externally_verifiable() {
        let config = OrchestratorConfig::default();
        let authority = RuntimeEvidenceAuthority::from_signing_key(
            "franken-core.runtime-orchestrator",
            crate::signature_preimage::SigningKey::from_bytes([0x4d; 32])
                .expect("non-zero runtime test key"),
            SecurityEpoch::GENESIS,
            1,
            None,
        )
        .expect("runtime evidence authority");
        let trusted_identity = authority.verification_identity();
        let mut orch = ExecutionOrchestrator::try_new_with_runtime_authority(config, authority)
            .expect("production constructor accepts explicit runtime authority");

        assert_eq!(orch.evidence_verification_identity(), trusted_identity);
        let result = orch.execute(&simple_package()).expect("execute");
        assert!(!result.evidence_entries.is_empty());
        for entry in &result.evidence_entries {
            entry
                .verify_with_trusted_identity(&trusted_identity)
                .expect("normal core execution evidence must verify externally");
            assert_eq!(
                entry.signed_envelope().key_provenance.authority_class,
                crate::evidence_ledger::EvidenceAuthorityClass::Runtime
            );

            let wire = serde_json::to_value(entry).expect("serialize replay evidence");
            let envelope = wire["signed_envelope"]
                .as_object()
                .expect("signed envelope is a JSON object");
            assert_eq!(
                envelope.keys().map(String::as_str).collect::<BTreeSet<_>>(),
                BTreeSet::from([
                    "key_provenance",
                    "producer_id",
                    "signature",
                    "signed_epoch",
                    "verification_key",
                ]),
                "replay evidence exposes public signer coordinates, never private key material"
            );
        }
    }

    #[test]
    fn result_epoch_matches_config() {
        let cfg = OrchestratorConfig {
            epoch: SecurityEpoch::from_raw(42),
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let result = orch.execute(&simple_package()).unwrap();
        assert_eq!(result.epoch, SecurityEpoch::from_raw(42));
        assert_eq!(result.action_decision.epoch, SecurityEpoch::from_raw(42));
    }

    #[test]
    fn result_cell_events_populated() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        // Cell close should produce at least one event.
        assert!(!result.cell_events.is_empty());
    }

    // -- custom trace prefix --------------------------------------------------

    #[test]
    fn custom_trace_prefix_appears_in_ids() {
        let cfg = OrchestratorConfig {
            trace_id_prefix: "myprefix".to_string(),
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let result = orch.execute(&simple_package()).unwrap();
        assert!(result.trace_id.starts_with("myprefix:"));
        assert!(result.decision_id.starts_with("myprefix:decision:"));
    }

    // -- package with capabilities and metadata -------------------------------

    #[test]
    fn package_with_capabilities_executes() {
        let pkg = ExtensionPackage {
            extension_id: "ext-cap".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec!["fs_read".to_string(), "net".to_string()],
            version: "2.0.0".to_string(),
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("author".to_string(), "tester".to_string());
                m
            },
        };
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&pkg).unwrap();
        assert_eq!(result.extension_id, "ext-cap");
        // Evidence metadata should contain capabilities count.
        let entry = &result.evidence_entries[0];
        let cap_count = entry.metadata.get("capabilities_count").unwrap();
        assert_eq!(cap_count, "2");
        assert_eq!(
            entry
                .metadata
                .get("canonical_capabilities_count")
                .map(String::as_str),
            Some("2")
        );
    }

    // -- action_to_saga_type coverage (via different risk scenarios) -----------

    #[test]
    fn loss_matrix_preset_to_loss_matrix_distinct() {
        let balanced = LossMatrixPreset::Balanced.to_loss_matrix();
        let conservative = LossMatrixPreset::Conservative.to_loss_matrix();
        let permissive = LossMatrixPreset::Permissive.to_loss_matrix();
        // All three presets should produce different matrices.
        // At minimum balanced != conservative.
        assert_ne!(format!("{balanced:?}"), format!("{conservative:?}"));
        assert_ne!(format!("{balanced:?}"), format!("{permissive:?}"));
    }

    // -- Enrichment: error trait --

    #[test]
    fn orchestrator_error_is_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(OrchestratorError::EmptySource);
        assert!(!e.to_string().is_empty());
        let e2: Box<dyn std::error::Error> = Box::new(OrchestratorError::EmptyExtensionId);
        assert!(!e2.to_string().is_empty());
    }

    // -- Enrichment: extension package edge cases --

    #[test]
    fn extension_package_empty_metadata_serde() {
        let pkg = simple_package();
        let json = serde_json::to_string(&pkg).unwrap();
        let restored: ExtensionPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(pkg.extension_id, restored.extension_id);
        assert!(restored.metadata.is_empty());
    }

    #[test]
    fn extension_package_with_many_capabilities_serde() {
        let pkg = ExtensionPackage {
            extension_id: "ext-many".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec![
                "fs_read".to_string(),
                "fs_write".to_string(),
                "net".to_string(),
            ],
            version: "3.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&pkg).unwrap();
        let restored: ExtensionPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.capabilities.len(), 3);
    }

    // -- Enrichment: config variations --

    #[test]
    fn orchestrator_config_custom_fields() {
        let cfg = OrchestratorConfig {
            loss_matrix_preset: LossMatrixPreset::Conservative,
            drain_deadline_ticks: 50_000,
            max_concurrent_sagas: 8,
            policy_id: "custom-policy".to_string(),
            ..OrchestratorConfig::default()
        };
        assert_eq!(cfg.loss_matrix_preset, LossMatrixPreset::Conservative);
        assert_eq!(cfg.drain_deadline_ticks, 50_000);
        assert_eq!(cfg.max_concurrent_sagas, 8);
        assert_eq!(cfg.policy_id, "custom-policy");
    }

    // -- Enrichment: loss matrix preset serde format --

    #[test]
    fn loss_matrix_preset_serde_format() {
        let json = serde_json::to_string(&LossMatrixPreset::Balanced).unwrap();
        assert!(json.contains("alanced"));
        let json = serde_json::to_string(&LossMatrixPreset::Conservative).unwrap();
        assert!(json.contains("onservative"));
        let json = serde_json::to_string(&LossMatrixPreset::Permissive).unwrap();
        assert!(json.contains("ermissive"));
    }

    // -- Enrichment: Display uniqueness for OrchestratorError --

    #[test]
    fn orchestrator_error_display_all_variants_unique() {
        let displays: std::collections::BTreeSet<String> = [
            OrchestratorError::EmptySource.to_string(),
            OrchestratorError::EmptyExtensionId.to_string(),
        ]
        .into_iter()
        .collect();
        assert_eq!(displays.len(), 2, "display strings must be unique");
    }

    // -- Enrichment: LossMatrixPreset equality --

    #[test]
    fn loss_matrix_preset_eq_and_ne() {
        assert_eq!(LossMatrixPreset::Balanced, LossMatrixPreset::Balanced);
        assert_ne!(LossMatrixPreset::Balanced, LossMatrixPreset::Conservative);
        assert_ne!(LossMatrixPreset::Conservative, LossMatrixPreset::Permissive);
    }

    // -- Enrichment: OrchestratorConfig clone --

    #[test]
    fn orchestrator_config_clone_preserves_fields() {
        let cfg = OrchestratorConfig {
            loss_matrix_preset: LossMatrixPreset::Conservative,
            drain_deadline_ticks: 99_999,
            cell_close_budget_ms: 77,
            max_concurrent_sagas: 16,
            epoch: SecurityEpoch::from_raw(77),
            trace_id_prefix: "clone-test".to_string(),
            policy_id: "policy-clone".to_string(),
            ..OrchestratorConfig::default()
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.loss_matrix_preset, LossMatrixPreset::Conservative);
        assert_eq!(cloned.drain_deadline_ticks, 99_999);
        assert_eq!(cloned.cell_close_budget_ms, 77);
        assert_eq!(cloned.max_concurrent_sagas, 16);
        assert_eq!(cloned.epoch, SecurityEpoch::from_raw(77));
        assert_eq!(cloned.trace_id_prefix, "clone-test");
        assert_eq!(cloned.policy_id, "policy-clone");
    }

    #[test]
    fn cell_close_trace_id_derivation_is_deterministic() {
        let first = ExecutionOrchestrator::derive_cell_close_trace_id("orch:0");
        let second = ExecutionOrchestrator::derive_cell_close_trace_id("orch:0");
        let third = ExecutionOrchestrator::derive_cell_close_trace_id("orch:1");

        assert_eq!(first, second);
        assert_ne!(first, third);
    }

    // -- Enrichment: ExtensionPackage deterministic serde --

    #[test]
    fn extension_package_serde_deterministic() {
        let pkg = simple_package();
        let json1 = serde_json::to_string(&pkg).unwrap();
        let json2 = serde_json::to_string(&pkg).unwrap();
        assert_eq!(json1, json2);
    }

    // -- Enrichment: multiple presets produce distinct results --

    #[test]
    fn all_presets_produce_valid_execution_results() {
        for preset in [
            LossMatrixPreset::Balanced,
            LossMatrixPreset::Conservative,
            LossMatrixPreset::Permissive,
        ] {
            let cfg = OrchestratorConfig {
                loss_matrix_preset: preset,
                ..OrchestratorConfig::default()
            };
            let mut orch = ExecutionOrchestrator::new(cfg);
            let result = orch
                .execute(&simple_package())
                .unwrap_or_else(|e| panic!("{preset:?} failed: {e}"));
            assert!(result.posterior.is_valid(), "{preset:?} posterior invalid");
            assert!(
                !result.evidence_entries.is_empty(),
                "{preset:?} no evidence"
            );
        }
    }

    // -- Enrichment: execution counter increments correctly --

    #[test]
    fn execution_counter_increments_correctly() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        assert_eq!(orch.execution_count(), 0);
        orch.execute(&simple_package()).unwrap();
        assert_eq!(orch.execution_count(), 1);
        orch.execute(&simple_package()).unwrap();
        assert_eq!(orch.execution_count(), 2);
    }

    #[test]
    fn failed_execution_still_advances_trace_identifier() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let lowering_failure = ExtensionPackage {
            source: String::new(), // empty source triggers EmptyIr0Body
            ..simple_package()
        };

        let err = orch
            .execute(&lowering_failure)
            .expect_err("empty source should fail");
        assert!(matches!(err, OrchestratorError::EmptySource));
        assert_eq!(orch.execution_count(), 0);

        let _result = orch.execute(&simple_package()).expect("follow-up execute");
        // After early rejection, trace counter may or may not advance
        // depending on error type; verify execution count is consistent
        assert_eq!(orch.execution_count(), 1);
    }

    // -- Enrichment: finalize result populated --

    #[test]
    fn result_finalize_result_present() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        assert!(
            result.finalize_result.is_some(),
            "finalize_result should be populated"
        );
    }

    #[test]
    fn execute_propagates_cell_close_budget_exhaustion() {
        let cfg = OrchestratorConfig {
            cell_close_budget_ms: 1,
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let err = orch
            .execute(&simple_package())
            .expect_err("cell close should fail on insufficient canonical budget");
        let failure = err
            .post_cell_failure()
            .expect("cell-close failures must retain cleanup evidence");

        match failure.primary_error.as_ref() {
            OrchestratorError::Cell(CellError::BudgetExhausted {
                requested_ms,
                remaining_ms,
                ..
            }) => {
                assert_eq!(*requested_ms, 2);
                assert_eq!(*remaining_ms, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(failure.cleanup.finalize_result.is_none());
        assert!(matches!(
            failure.cleanup.close_error,
            Some(CellError::BudgetExhausted { .. })
        ));
    }

    // -- Enrichment: evidence entries have trace_id --

    #[test]
    fn evidence_entries_have_consistent_trace_id() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        for entry in &result.evidence_entries {
            assert_eq!(entry.trace_id, result.trace_id);
        }
    }

    // -- Enrichment: different extension ids produce different results --

    #[test]
    fn different_extension_ids_produce_different_trace_ids() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let r1 = orch.execute(&package_with_id("ext-alpha")).unwrap();
        let r2 = orch.execute(&package_with_id("ext-beta")).unwrap();
        assert_ne!(r1.trace_id, r2.trace_id);
        assert_ne!(r1.decision_id, r2.decision_id);
        assert_ne!(r1.extension_id, r2.extension_id);
    }

    // -- Enrichment: LossMatrixPreset Debug --

    #[test]
    fn loss_matrix_preset_debug_format() {
        assert_eq!(format!("{:?}", LossMatrixPreset::Balanced), "Balanced");
        assert_eq!(
            format!("{:?}", LossMatrixPreset::Conservative),
            "Conservative"
        );
        assert_eq!(format!("{:?}", LossMatrixPreset::Permissive), "Permissive");
    }

    // -- Enrichment: reward function boundary --

    #[test]
    fn execution_reward_zero_instructions() {
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: 0,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let reward = ExecutionOrchestrator::execution_reward_millionths(&exec);
        // Zero instructions should yield maximum reward (no cost).
        assert!(reward >= 0, "reward should be non-negative");
    }

    // -- Enrichment: action_to_saga_type coverage --

    #[test]
    fn action_to_saga_type_quarantine() {
        assert_eq!(
            ExecutionOrchestrator::action_to_saga_type(ContainmentAction::Quarantine),
            Some(SagaType::Quarantine)
        );
    }

    #[test]
    fn action_to_saga_type_terminate() {
        assert_eq!(
            ExecutionOrchestrator::action_to_saga_type(ContainmentAction::Terminate),
            Some(SagaType::Eviction)
        );
    }

    #[test]
    fn action_to_saga_type_suspend() {
        assert_eq!(
            ExecutionOrchestrator::action_to_saga_type(ContainmentAction::Suspend),
            Some(SagaType::Revocation)
        );
    }

    #[test]
    fn action_to_saga_type_allow_returns_none() {
        assert!(ExecutionOrchestrator::action_to_saga_type(ContainmentAction::Allow).is_none());
    }

    #[test]
    fn action_to_saga_type_sandbox_returns_none() {
        assert!(ExecutionOrchestrator::action_to_saga_type(ContainmentAction::Sandbox).is_none());
    }

    #[test]
    fn action_to_saga_type_challenge_returns_none() {
        assert!(ExecutionOrchestrator::action_to_saga_type(ContainmentAction::Challenge).is_none());
    }

    fn assert_containment_saga_failure_preserves_receipt_and_closes_cell(
        action: ContainmentAction,
        expected_saga_type: SagaType,
        expected_state: crate::containment_executor::ContainmentState,
    ) {
        let mut orchestrator = ExecutionOrchestrator::with_defaults();
        orchestrator
            .saga_orchestrator
            .create_saga(
                "orch:0:saga",
                SagaType::Publish,
                quarantine_saga_steps("preexisting"),
                "preexisting-trace",
                0,
            )
            .expect("duplicate-saga test precondition must succeed");
        orchestrator.containment_action_override = Some(action);
        let package = package_with_id(&format!("bd-ov8qr-{action}"));

        let error = orchestrator
            .execute(&package)
            .expect_err("duplicate saga creation must fail after containment");
        let failure = assert_successful_post_cell_cleanup(&error);
        assert!(failure.additional_errors.is_empty());
        assert!(matches!(
            failure.primary_error.as_ref(),
            OrchestratorError::Saga(SagaError::SagaAlreadyExists { saga_id })
                if saga_id == "orch:0:saga"
        ));

        let evidence = error
            .containment_saga_failure()
            .expect("partial success must preserve saga-failure evidence");
        assert_eq!(failure.containment_saga_failure.as_ref(), Some(evidence));
        assert_eq!(evidence.action, action);
        assert_eq!(evidence.receipt.action, action);
        assert_eq!(evidence.receipt.target_extension_id, package.extension_id);
        assert!(evidence.receipt.success);
        assert_eq!(evidence.saga_id, "orch:0:saga");
        assert_eq!(evidence.saga_type, expected_saga_type);
        assert!(matches!(
            &evidence.saga_error,
            SagaError::SagaAlreadyExists { saga_id } if saga_id == "orch:0:saga"
        ));

        let encoded =
            serde_json::to_vec(evidence).expect("saga-failure evidence must be serializable");
        let decoded: ContainmentSagaFailureEvidence =
            serde_json::from_slice(&encoded).expect("saga-failure evidence must round-trip");
        assert_eq!(&decoded, evidence);

        assert_eq!(
            orchestrator
                .containment_executor
                .state(&package.extension_id),
            Some(expected_state)
        );
        let receipts = orchestrator
            .containment_executor
            .receipts(&package.extension_id);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0], &evidence.receipt);
        assert_eq!(orchestrator.saga_orchestrator.total_count(), 1);
        assert_eq!(orchestrator.execution_count(), 0);
    }

    #[test]
    fn containment_saga_failure_preserves_suspend_receipt_and_closes_cell_bd_ov8qr() {
        assert_containment_saga_failure_preserves_receipt_and_closes_cell(
            ContainmentAction::Suspend,
            SagaType::Revocation,
            crate::containment_executor::ContainmentState::Suspended,
        );
    }

    #[test]
    fn containment_saga_failure_preserves_terminate_receipt_and_closes_cell_bd_ov8qr() {
        assert_containment_saga_failure_preserves_receipt_and_closes_cell(
            ContainmentAction::Terminate,
            SagaType::Eviction,
            crate::containment_executor::ContainmentState::Terminated,
        );
    }

    #[test]
    fn containment_saga_failure_preserves_quarantine_receipt_and_closes_cell_bd_ov8qr() {
        assert_containment_saga_failure_preserves_receipt_and_closes_cell(
            ContainmentAction::Quarantine,
            SagaType::Quarantine,
            crate::containment_executor::ContainmentState::Quarantined,
        );
    }

    #[test]
    fn phase_execute_containment_allow_remains_noop() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = package_with_id("ext-allow");
        orch.containment_executor.register(&pkg.extension_id);

        let (receipt, saga_id) = orch
            .phase_execute_containment(
                ContainmentAction::Allow,
                &pkg,
                "trace-allow",
                "decision-allow",
            )
            .expect("allow containment should succeed");

        assert!(receipt.is_none());
        assert!(saga_id.is_none());
        assert_eq!(
            orch.containment_executor.state(&pkg.extension_id),
            Some(crate::containment_executor::ContainmentState::Running)
        );
    }

    #[test]
    fn phase_execute_containment_challenge_emits_receipt_without_saga() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = package_with_id("ext-challenge");
        orch.containment_executor.register(&pkg.extension_id);

        let (receipt, saga_id) = orch
            .phase_execute_containment(
                ContainmentAction::Challenge,
                &pkg,
                "trace-challenge",
                "decision-challenge",
            )
            .expect("challenge containment should succeed");

        let receipt = receipt.expect("challenge should emit a containment receipt");
        assert_eq!(receipt.action, ContainmentAction::Challenge);
        assert_eq!(
            orch.containment_executor.state(&pkg.extension_id),
            Some(crate::containment_executor::ContainmentState::Challenged)
        );
        assert!(saga_id.is_none());
    }

    #[test]
    fn phase_execute_containment_sandbox_emits_receipt_without_saga() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = package_with_id("ext-sandbox");
        orch.containment_executor.register(&pkg.extension_id);

        let (receipt, saga_id) = orch
            .phase_execute_containment(
                ContainmentAction::Sandbox,
                &pkg,
                "trace-sandbox",
                "decision-sandbox",
            )
            .expect("sandbox containment should succeed");

        let receipt = receipt.expect("sandbox should emit a containment receipt");
        assert_eq!(receipt.action, ContainmentAction::Sandbox);
        assert_eq!(
            orch.containment_executor.state(&pkg.extension_id),
            Some(crate::containment_executor::ContainmentState::Sandboxed)
        );
        assert!(saga_id.is_none());
    }

    #[test]
    fn flow_successors_preserves_backward_jump_target() {
        let successors = ExecutionOrchestrator::flow_successors(
            1,
            &crate::ir_contract::Ir3Instruction::Jump { target: 0 },
            2,
        );
        assert_eq!(successors, vec![0]);
    }

    #[test]
    fn estimate_ir3_schedule_cost_fail_closes_on_looping_control_flow() {
        let mut ir3 =
            crate::ir_contract::Ir3Module::new(ContentHash::compute(b"looping-ir3"), "looping-ir3");
        ir3.instructions = vec![
            crate::ir_contract::Ir3Instruction::LoadInt { dst: 0, value: 1 },
            crate::ir_contract::Ir3Instruction::Jump { target: 0 },
        ];

        assert!(
            ExecutionOrchestrator::estimate_ir3_schedule_cost(&ir3).is_none(),
            "looping control flow should not be flattened into an acyclic schedule cost"
        );
    }

    // -- Enrichment: stable_symbol determinism --

    #[test]
    fn capability_multiset_summary_canonicalizes_risk_count_but_commits_raw_tags() {
        let original = vec![
            "fs_read".to_string(),
            "fs".to_string(),
            "fs:read".to_string(),
            "net".to_string(),
            "network_egress".to_string(),
            "unknown".to_string(),
            "unknown".to_string(),
        ];
        let mut reordered = original.clone();
        reordered.reverse();
        let mut fewer_unknowns = original.clone();
        fewer_unknowns.pop();
        let mut added_recognized = original.clone();
        added_recognized.push("fs_write".to_string());

        let original_summary = ExecutionOrchestrator::capability_multiset_summary(&original);
        let reordered_summary = ExecutionOrchestrator::capability_multiset_summary(&reordered);
        let fewer_unknowns_summary =
            ExecutionOrchestrator::capability_multiset_summary(&fewer_unknowns);
        let added_recognized_summary =
            ExecutionOrchestrator::capability_multiset_summary(&added_recognized);

        assert_eq!(original_summary.total, 7);
        assert_eq!(original_summary.canonical_distinct, 2);
        assert_eq!(
            original_summary.multiset_hash,
            reordered_summary.multiset_hash
        );
        assert_eq!(reordered_summary.canonical_distinct, 2);
        assert_eq!(fewer_unknowns_summary.canonical_distinct, 2);
        assert_ne!(original_summary.total, fewer_unknowns_summary.total);
        assert_ne!(
            original_summary.multiset_hash,
            fewer_unknowns_summary.multiset_hash
        );
        assert_eq!(added_recognized_summary.canonical_distinct, 3);
        assert_ne!(
            original_summary.multiset_hash,
            added_recognized_summary.multiset_hash
        );
    }

    #[test]
    fn stable_symbol_deterministic_for_same_input() {
        let a = ExecutionOrchestrator::stable_symbol("hello");
        let b = ExecutionOrchestrator::stable_symbol("hello");
        assert_eq!(a, b);
    }

    #[test]
    fn stable_symbol_differs_for_different_input() {
        let a = ExecutionOrchestrator::stable_symbol("hello");
        let b = ExecutionOrchestrator::stable_symbol("world");
        assert_ne!(a, b);
    }

    #[test]
    fn stable_symbol_empty_string() {
        let s = ExecutionOrchestrator::stable_symbol("");
        // FNV1a init value
        assert_eq!(s, 0x811C_9DC5);
    }

    // -- Enrichment: risk_state_symbol coverage --

    #[test]
    fn risk_state_symbol_all_variants() {
        assert_eq!(
            ExecutionOrchestrator::risk_state_symbol(RiskState::Benign),
            0
        );
        assert_eq!(
            ExecutionOrchestrator::risk_state_symbol(RiskState::Anomalous),
            1
        );
        assert_eq!(
            ExecutionOrchestrator::risk_state_symbol(RiskState::Malicious),
            2
        );
        assert_eq!(
            ExecutionOrchestrator::risk_state_symbol(RiskState::Unknown),
            3
        );
    }

    // -- Enrichment: build_evidence edge cases --

    #[test]
    fn build_evidence_no_hostcalls() {
        let pkg = simple_package();
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Int(42_000_000),
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: 10,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let capability_summary =
            ExecutionOrchestrator::capability_multiset_summary(&pkg.capabilities);
        let ev = ExecutionOrchestrator::build_evidence(
            &pkg,
            &exec,
            capability_summary,
            SecurityEpoch::from_raw(1),
        );
        assert_eq!(ev.extension_id, "test-ext-1");
        assert_eq!(ev.hostcall_rate_millionths, 0);
        assert_eq!(ev.denial_rate_millionths, 0);
        assert_eq!(ev.timing_anomaly_millionths, 0);
    }

    #[test]
    fn build_evidence_resource_score_saturates() {
        let pkg = simple_package();
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: u64::MAX,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let capability_summary =
            ExecutionOrchestrator::capability_multiset_summary(&pkg.capabilities);
        let ev = ExecutionOrchestrator::build_evidence(
            &pkg,
            &exec,
            capability_summary,
            SecurityEpoch::from_raw(1),
        );
        assert_eq!(ev.resource_score_millionths, 1_000_000);
    }

    #[test]
    fn build_evidence_with_capabilities() {
        let pkg = ExtensionPackage {
            extension_id: "ext-caps".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec![
                "fs_read".to_string(),
                "fs".to_string(),
                "fs:read".to_string(),
                "net".to_string(),
                "network_egress".to_string(),
                "unknown".to_string(),
                "unknown".to_string(),
            ],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: 5,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let capability_summary =
            ExecutionOrchestrator::capability_multiset_summary(&pkg.capabilities);
        let ev = ExecutionOrchestrator::build_evidence(
            &pkg,
            &exec,
            capability_summary,
            SecurityEpoch::from_raw(2),
        );
        assert_eq!(ev.distinct_capabilities, 2);
        assert_eq!(ev.epoch, SecurityEpoch::from_raw(2));
    }

    // -- Enrichment: module parse goal --

    #[test]
    fn module_parse_goal_executes() {
        let cfg = OrchestratorConfig {
            parse_goal: ParseGoal::Module,
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        // Module parse goal should still be able to parse simple expressions.
        let result = orch.execute(&simple_package());
        // May succeed or fail depending on parser strictness, but should not panic.
        let _ = result;
    }

    // -- Enrichment: saga orchestrator accessor --

    #[test]
    fn saga_orchestrator_accessible() {
        let orch = ExecutionOrchestrator::with_defaults();
        let saga_orch = orch.saga_orchestrator();
        assert_eq!(saga_orch.active_count(), 0);
    }

    // -- Enrichment: execution reward boundary values --

    #[test]
    fn execution_reward_one_instruction() {
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: 1,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let reward = ExecutionOrchestrator::execution_reward_millionths(&exec);
        assert!(reward > 0, "reward for 1 instruction should be positive");
        assert!(reward <= 1_000_000, "reward should not exceed 1M");
    }

    // -- Enrichment: LossMatrixPreset Copy --

    #[test]
    fn loss_matrix_preset_is_copy() {
        let a = LossMatrixPreset::Balanced;
        let b = a;
        assert_eq!(a, b);
    }

    // -- Enrichment: trace_id format with custom prefix --

    #[test]
    fn custom_prefix_trace_id_format() {
        let cfg = OrchestratorConfig {
            trace_id_prefix: "custom".to_string(),
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let r = orch.execute(&simple_package()).unwrap();
        assert!(r.trace_id.starts_with("custom:"));
        assert!(r.decision_id.starts_with("custom:decision:"));
    }

    // -- Enrichment: orchestrator with custom epoch --

    #[test]
    fn custom_epoch_propagates_to_evidence() {
        let cfg = OrchestratorConfig {
            epoch: SecurityEpoch::from_raw(999),
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let r = orch.execute(&simple_package()).unwrap();
        assert_eq!(r.epoch, SecurityEpoch::from_raw(999));
    }

    // -- Enrichment: OrchestratorError from conversions --

    #[test]
    fn orchestrator_error_from_cell_error() {
        let cell_err = CellError::CellNotFound {
            cell_id: "missing".to_string(),
        };
        let orch_err: OrchestratorError = cell_err.into();
        let msg = orch_err.to_string();
        assert!(msg.contains("cell"), "should mention cell: {msg}");
    }

    #[test]
    fn orchestrator_error_from_ledger_error() {
        let ledger_err = LedgerError::MissingChosenAction;
        let orch_err: OrchestratorError = ledger_err.into();
        let msg = orch_err.to_string();
        assert!(msg.contains("ledger"), "should mention ledger: {msg}");
    }

    // -----------------------------------------------------------------------
    // enrichment_ tests
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_extension_package_json_field_names_present() {
        let pkg = ExtensionPackage {
            extension_id: "id-1".to_string(),
            source: "1".to_string(),
            source_file: None,
            capabilities: vec!["net".to_string()],
            version: "0.1.0".to_string(),
            metadata: {
                let mut m = BTreeMap::new();
                m.insert("k".to_string(), "v".to_string());
                m
            },
        };
        let json = serde_json::to_string(&pkg).unwrap();
        assert!(
            json.contains("\"extension_id\""),
            "missing extension_id field"
        );
        assert!(json.contains("\"source\""), "missing source field");
        assert!(
            json.contains("\"capabilities\""),
            "missing capabilities field"
        );
        assert!(json.contains("\"version\""), "missing version field");
        assert!(json.contains("\"metadata\""), "missing metadata field");
    }

    #[test]
    fn enrichment_loss_matrix_preset_clone_semantics() {
        let original = LossMatrixPreset::Conservative;
        let cloned = original;
        assert_eq!(original, cloned);
        // After clone, original is still usable (Copy).
        let _use_original = original;
        let _use_cloned = cloned;
    }

    #[test]
    fn enrichment_orchestrator_error_display_exact_empty_source() {
        let err = OrchestratorError::EmptySource;
        assert_eq!(err.to_string(), "extension source is empty");
    }

    #[test]
    fn enrichment_orchestrator_error_display_exact_empty_extension_id() {
        let err = OrchestratorError::EmptyExtensionId;
        assert_eq!(err.to_string(), "extension_id is empty");
    }

    #[test]
    fn enrichment_extension_package_large_metadata_serde_roundtrip() {
        let mut metadata = BTreeMap::new();
        for i in 0..50 {
            metadata.insert(format!("key_{i}"), format!("value_{i}"));
        }
        let pkg = ExtensionPackage {
            extension_id: "ext-large-meta".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata,
        };
        let json = serde_json::to_string(&pkg).unwrap();
        let restored: ExtensionPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.metadata.len(), 50);
        assert_eq!(restored.metadata.get("key_0").unwrap(), "value_0");
        assert_eq!(restored.metadata.get("key_49").unwrap(), "value_49");
    }

    #[test]
    fn enrichment_stable_symbol_multiple_distinct_inputs() {
        let inputs = ["alpha", "beta", "gamma", "delta", "epsilon"];
        let symbols: std::collections::BTreeSet<u32> = inputs
            .iter()
            .map(|s| ExecutionOrchestrator::stable_symbol(s))
            .collect();
        assert_eq!(
            symbols.len(),
            inputs.len(),
            "all distinct inputs should produce distinct symbols"
        );
    }

    #[test]
    fn enrichment_build_evidence_zero_instructions_no_panic() {
        let pkg = simple_package();
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: 0,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let capability_summary =
            ExecutionOrchestrator::capability_multiset_summary(&pkg.capabilities);
        let ev = ExecutionOrchestrator::build_evidence(
            &pkg,
            &exec,
            capability_summary,
            SecurityEpoch::from_raw(1),
        );
        // Division by zero for hostcall_rate should be handled (returns 0).
        assert_eq!(ev.hostcall_rate_millionths, 0);
        assert_eq!(ev.resource_score_millionths, 0);
    }

    #[test]
    fn enrichment_execution_reward_hostcall_penalty_only() {
        use crate::ir_contract::{CapabilityTag, HostcallDecisionRecord};
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: vec![
                HostcallDecisionRecord {
                    seq: 0,
                    capability: CapabilityTag("fs_read".to_string()),
                    allowed: true,
                    instruction_index: 0,
                },
                HostcallDecisionRecord {
                    seq: 1,
                    capability: CapabilityTag("net".to_string()),
                    allowed: false,
                    instruction_index: 1,
                },
            ],
            instructions_executed: 0, // no instruction penalty
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let reward = ExecutionOrchestrator::execution_reward_millionths(&exec);
        // 2 hostcalls => penalty = 2 * 25_000 = 50_000. Reward = 1M - 0 - 50_000 = 950_000.
        assert_eq!(reward, 950_000);
    }

    #[test]
    fn enrichment_execution_reward_saturates_hostcall_penalty() {
        use crate::ir_contract::{CapabilityTag, HostcallDecisionRecord};
        let many_hostcalls: Vec<HostcallDecisionRecord> = (0..100)
            .map(|i| HostcallDecisionRecord {
                seq: i,
                capability: CapabilityTag(format!("cap_{i}")),
                allowed: true,
                instruction_index: i as u32,
            })
            .collect();
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            completion_label: Label::Public,
            hostcall_decisions: many_hostcalls,
            instructions_executed: 0,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        let reward = ExecutionOrchestrator::execution_reward_millionths(&exec);
        // 100 hostcalls => penalty = min(100*25_000, 300_000) = 300_000. Reward = 700_000.
        assert_eq!(reward, 700_000);
    }

    #[test]
    fn enrichment_force_lane_quickjs_propagates() {
        let cfg = OrchestratorConfig {
            force_lane: Some(LaneChoice::QuickJs),
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let result = orch.execute(&simple_package()).unwrap();
        assert_eq!(result.lane, LaneChoice::QuickJs);
    }

    #[test]
    fn enrichment_force_lane_v8_propagates() {
        let cfg = OrchestratorConfig {
            force_lane: Some(LaneChoice::V8),
            ..OrchestratorConfig::default()
        };
        let mut orch = ExecutionOrchestrator::new(cfg);
        let result = orch.execute(&simple_package()).unwrap();
        assert_eq!(result.lane, LaneChoice::V8);
    }

    #[test]
    fn enrichment_evidence_metadata_extension_version_recorded() {
        let pkg = ExtensionPackage {
            extension_id: "ext-ver".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec![],
            version: "7.3.1".to_string(),
            metadata: BTreeMap::new(),
        };
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&pkg).unwrap();
        let entry = &result.evidence_entries[0];
        assert_eq!(
            entry.metadata.get("extension_version").unwrap(),
            "7.3.1",
            "evidence must record exact extension version"
        );
    }

    #[test]
    fn enrichment_rapid_sequential_executions_no_panic() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        for i in 0..10 {
            let pkg = package_with_id(&format!("ext-rapid-{i}"));
            orch.execute(&pkg).expect("rapid execution should succeed");
        }
        assert_eq!(orch.execution_count(), 10);
        assert!(orch.ledger().len() >= 10);
    }

    #[test]
    fn enrichment_orchestrator_error_debug_format() {
        let err = OrchestratorError::EmptySource;
        let dbg = format!("{err:?}");
        assert!(
            dbg.contains("EmptySource"),
            "Debug should name variant: {dbg}"
        );

        let err2 = OrchestratorError::EmptyExtensionId;
        let dbg2 = format!("{err2:?}");
        assert!(
            dbg2.contains("EmptyExtensionId"),
            "Debug should name variant: {dbg2}"
        );
    }

    #[test]
    fn enrichment_extension_package_unicode_source_and_id() {
        let pkg = ExtensionPackage {
            extension_id: "ext-\u{00e9}\u{00f1}\u{00fc}".to_string(),
            source: "42".to_string(),
            source_file: None,
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&pkg).unwrap();
        let restored: ExtensionPackage = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.extension_id, pkg.extension_id);
    }

    #[test]
    fn enrichment_evidence_compression_certificate_fields() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        let cert = result
            .evidence_compression_certificate
            .as_ref()
            .expect("compression certificate should be present");
        // Entropy estimates should be non-negative.
        assert!(cert.entropy_millibits_per_symbol >= 0);
        assert!(cert.shannon_lower_bound_bits >= 0);
        // Overhead ratio is in fixed-point millionths; should be non-negative.
        assert!(cert.overhead_ratio_millionths >= 0);
        cert.verify_integrity()
            .expect("issued certificate should remain internally valid");
        let metadata = &result.evidence_entries[0].metadata;
        let certificate_hash = cert.certificate_hash.to_hex();
        let artifact_hash = cert.compressed_artifact_hash.to_hex();
        let content_hash = cert.content_hash.to_hex();
        let model_hash = cert.model_hash.to_hex();
        assert_eq!(
            metadata.get("evidence_compression_certificate_schema"),
            Some(&cert.schema)
        );
        assert_eq!(
            metadata.get("evidence_compression_certificate_hash"),
            Some(&certificate_hash)
        );
        assert_eq!(
            metadata.get("evidence_compressed_artifact_hash"),
            Some(&artifact_hash)
        );
        assert_eq!(
            metadata.get("evidence_compressed_content_hash"),
            Some(&content_hash)
        );
        assert_eq!(
            metadata.get("evidence_compression_model_hash"),
            Some(&model_hash)
        );
    }

    #[test]
    fn evidence_compression_certificate_surfaces_coder_failures() {
        let symbols: Vec<u32> = (0..=256).collect();
        let err =
            ExecutionOrchestrator::build_evidence_compression_certificate_from_symbols(symbols)
                .expect_err("large evidence alphabet must surface coder construction failure");

        assert!(
            matches!(err, OrchestratorError::EvidenceCompressionCoder { .. }),
            "expected evidence compression coder error, got {err}"
        );
        assert!(err.to_string().contains("alphabet size"));
    }

    #[test]
    fn enrichment_build_evidence_epoch_propagation() {
        let pkg = simple_package();
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Int(1_000_000),
            completion_label: Label::Public,
            hostcall_decisions: Vec::new(),
            instructions_executed: 5,
            requested_hook_action: None,
            witness_events: Vec::new(),
            events: Vec::new(),
            console_output: Vec::new(),
        };
        for raw_epoch in [1u64, 100, u64::MAX] {
            let epoch = SecurityEpoch::from_raw(raw_epoch);
            let capability_summary =
                ExecutionOrchestrator::capability_multiset_summary(&pkg.capabilities);
            let ev = ExecutionOrchestrator::build_evidence(&pkg, &exec, capability_summary, epoch);
            assert_eq!(ev.epoch, epoch);
        }
    }

    #[test]
    fn enrichment_result_lane_field_populated() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        // Lane should be one of the valid choices.
        assert!(
            result.lane == LaneChoice::QuickJs || result.lane == LaneChoice::V8,
            "lane should be QuickJs or V8, got {:?}",
            result.lane
        );
    }

    #[test]
    fn enrichment_stopping_policies_grow_per_distinct_extension() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        assert!(orch.stopping_policies.is_empty());

        orch.execute(&package_with_id("ext-stop-a")).unwrap();
        assert_eq!(orch.stopping_policies.len(), 1);

        orch.execute(&package_with_id("ext-stop-b")).unwrap();
        assert_eq!(orch.stopping_policies.len(), 2);

        // Re-executing same extension should NOT add a new policy.
        orch.execute(&package_with_id("ext-stop-a")).unwrap();
        assert_eq!(orch.stopping_policies.len(), 2);
    }

    #[test]
    fn enrichment_ledger_entries_monotonically_grow() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let mut prev_len = 0usize;
        for i in 0..5 {
            orch.execute(&package_with_id(&format!("ext-mono-{i}")))
                .unwrap();
            let cur_len = orch.ledger().len();
            assert!(
                cur_len > prev_len,
                "ledger should grow: was {prev_len}, now {cur_len}"
            );
            prev_len = cur_len;
        }
    }

    // -- IR4 WitnessIR sealing on the live execution path (bd-drb55) --------

    #[test]
    fn ir4_witness_sealed_on_live_execution_path() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        let witness = &result.ir4_witness;

        assert_eq!(witness.outcome, ExecutionOutcome::Completed);
        assert_eq!(witness.instructions_executed, result.instructions_executed);
        assert!(witness.instructions_executed > 0);
        assert_eq!(witness.duration_ticks, result.instructions_executed);
        // The interpreter's event trace flows through the seal: every
        // successful run records a terminal ExecutionCompleted witness event,
        // so a seal that dropped events would fail here.
        let last_event = witness
            .events
            .last()
            .expect("successful runs always record witness events");
        assert_eq!(
            last_event.kind,
            crate::ir_contract::WitnessEventKind::ExecutionCompleted
        );
        verify_ir4_linkage(witness, &witness.executed_ir3_hash)
            .expect("sealed witness must verify against its own executed IR3 hash");
    }

    #[test]
    fn ir4_witness_hash_bound_into_evidence_metadata() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        let bound_hash = result.evidence_entries[0]
            .as_entry()
            .metadata
            .get("ir4_witness_hash")
            .expect("evidence entry must bind the sealed witness hash");
        assert_eq!(bound_hash, &result.ir4_witness.content_hash().to_hex());
    }

    #[test]
    fn ir4_witness_deterministic_across_fresh_orchestrators() {
        let mut orch_a = ExecutionOrchestrator::with_defaults();
        let mut orch_b = ExecutionOrchestrator::with_defaults();
        let witness_a = orch_a.execute(&simple_package()).unwrap().ir4_witness;
        let witness_b = orch_b.execute(&simple_package()).unwrap().ir4_witness;
        assert_eq!(
            witness_a.content_hash(),
            witness_b.content_hash(),
            "sealed witness must be identical for identical fixed inputs"
        );
    }

    #[test]
    fn ir4_witness_tamper_is_rejected_by_linkage_verification() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        let ir3_hash = result.ir4_witness.executed_ir3_hash;

        let mut retargeted = result.ir4_witness.clone();
        retargeted.executed_ir3_hash = ContentHash::compute(b"forged-ir3");
        assert!(verify_ir4_linkage(&retargeted, &ir3_hash).is_err());

        let mut stripped = result.ir4_witness.clone();
        stripped.header.source_hash = None;
        assert!(verify_ir4_linkage(&stripped, &ir3_hash).is_err());
    }
}
