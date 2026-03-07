//! End-to-end integration seam: parse → lower → execute → assess → decide → record → contain.
//!
//! The `ExecutionOrchestrator` accepts an extension package and drives it
//! through the full FrankenEngine pipeline:
//!
//! 1. **Parse** source via `CanonicalEs2020Parser`
//! 2. **Lower** IR0 → IR3 via `lowering_pipeline`
//! 3. **Execute** IR3 via `LaneRouter`
//! 4. **Assess risk** via `BayesianPosteriorUpdater`
//! 5. **Decide action** via `ExpectedLossSelector`
//! 6. **Record evidence** via `EvidenceLedger`
//! 7. **Execute containment** via `ContainmentExecutor`
//! 8. **Close cell** via `ExecutionCell` quiescent protocol

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ast::ParseGoal;
use crate::baseline_interpreter::{
    ExecutionResult, InterpreterError, LaneChoice, LaneReason, LaneRouter, RoutedResult,
};
use crate::bayesian_posterior::{
    BayesianPosteriorUpdater, Evidence, Posterior, RiskState, UpdateResult,
};
use crate::containment_executor::{
    ContainmentContext, ContainmentError, ContainmentExecutor, ContainmentReceipt, SandboxPolicy,
};
use crate::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};
use crate::entropy_evidence_compressor::{
    ArithmeticCoder, CompressionCertificate, EntropyEstimator,
};
use crate::evidence_ledger::{
    CandidateAction, ChosenAction, DecisionType, EvidenceEmitter, EvidenceEntry,
    EvidenceEntryBuilder, InMemoryLedger, LedgerError, Witness,
};
use crate::execution_cell::{CellError, CellEvent, CellKind, ExecutionCell};
use crate::expected_loss_selector::{
    ActionDecision, ContainmentAction, ExpectedLossSelector, LossMatrix,
};
use crate::hash_tiers::ContentHash;
use crate::ir_contract::{Ir0Module, Ir3Module};
use crate::lowering_pipeline::{
    LoweringContext, LoweringEvent, LoweringPipelineError, PassWitness, lower_ir0_to_ir3,
};
use crate::optimal_stopping::{
    EscalationPolicy, Observation as StoppingObservation, OptimalStoppingCertificate,
    STOPPING_SCHEMA_VERSION, StoppingDecision,
};
use crate::parser::{CanonicalEs2020Parser, ParseError, ParserOptions};
use crate::region_lifecycle::{CancelReason, DrainDeadline, FinalizeResult};
use crate::regret_bounded_router::{
    LaneArm as AdaptiveLaneArm, RegretBoundedRouter, RewardSignal as AdaptiveRewardSignal,
    RouterSummary,
};
use crate::saga_orchestrator::{
    SagaError, SagaOrchestrator, SagaType, eviction_saga_steps, quarantine_saga_steps,
    revocation_saga_steps,
};
use crate::security_epoch::SecurityEpoch;
use crate::tropical_semiring::{
    InstructionCostGraph, InstructionNode, ScheduleOptimizer, TropicalWeight,
};

const ADAPTIVE_ROUTER_GAMMA_MILLIONTHS: i64 = 100_000;
const STOPPING_CUSUM_THRESHOLD_MILLIONTHS: i64 = 5_000_000;
const STOPPING_CUSUM_REFERENCE_MILLIONTHS: i64 = 500_000;
const SCALE_MILLION: i64 = 1_000_000;

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
        Self {
            loss_matrix_preset: LossMatrixPreset::Balanced,
            force_lane: None,
            drain_deadline_ticks: 10_000,
            max_concurrent_sagas: 4,
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
    /// JavaScript source code.
    pub source: String,
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

/// Complete result of an orchestrated execution pipeline.
#[derive(Debug)]
pub struct OrchestratorResult {
    // Identity
    pub extension_id: String,
    pub trace_id: String,
    pub decision_id: String,
    pub source_label: String,

    // Lowering
    pub lowering_events: Vec<LoweringEvent>,
    pub lowering_witnesses: Vec<PassWitness>,

    // Execution
    pub lane: LaneChoice,
    pub lane_reason: LaneReason,
    pub execution_value: String,
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
    pub evidence_entries: Vec<EvidenceEntry>,
    pub evidence_compression_certificate: Option<CompressionCertificate>,

    // Containment
    pub containment_receipt: Option<ContainmentReceipt>,
    pub saga_id: Option<String>,

    // Cell
    pub cell_events: Vec<CellEvent>,
    pub finalize_result: Option<FinalizeResult>,

    // Epoch
    pub epoch: SecurityEpoch,
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
    adaptive_router_summary: Option<&'a RouterSummary>,
    optimal_stopping_certificate: Option<&'a OptimalStoppingCertificate>,
}

// ---------------------------------------------------------------------------
// OrchestratorError
// ---------------------------------------------------------------------------

/// Errors produced by the orchestrator pipeline.
#[derive(Debug)]
pub enum OrchestratorError {
    Parse(Box<ParseError>),
    Lowering(Box<LoweringPipelineError>),
    Interpreter(InterpreterError),
    Ledger(LedgerError),
    Saga(SagaError),
    Cell(CellError),
    Containment(ContainmentError),
    EmptySource,
    EmptyExtensionId,
}

impl fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse: {e}"),
            Self::Lowering(e) => write!(f, "lowering: {e}"),
            Self::Interpreter(e) => write!(f, "interpreter: {e}"),
            Self::Ledger(e) => write!(f, "ledger: {e}"),
            Self::Saga(e) => write!(f, "saga: {e}"),
            Self::Cell(e) => write!(f, "cell: {e}"),
            Self::Containment(e) => write!(f, "containment: {e}"),
            Self::EmptySource => f.write_str("extension source is empty"),
            Self::EmptyExtensionId => f.write_str("extension_id is empty"),
        }
    }
}

impl std::error::Error for OrchestratorError {}

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

// ---------------------------------------------------------------------------
// ExecutionOrchestrator
// ---------------------------------------------------------------------------

/// Integration seam that wires together the full FrankenEngine pipeline.
pub struct ExecutionOrchestrator {
    config: OrchestratorConfig,
    parser: CanonicalEs2020Parser,
    lane_router: LaneRouter,
    adaptive_router: RegretBoundedRouter,
    stopping_policies: BTreeMap<String, EscalationPolicy>,
    last_cumulative_llr_by_extension: BTreeMap<String, i64>,
    posterior_updater: BayesianPosteriorUpdater,
    loss_selector: ExpectedLossSelector,
    ledger: InMemoryLedger,
    saga_orchestrator: SagaOrchestrator,
    containment_executor: ContainmentExecutor,
    attempt_counter: u64,
    execution_counter: u64,
}

impl ExecutionOrchestrator {
    /// Create a new orchestrator with the given configuration.
    pub fn new(config: OrchestratorConfig) -> Self {
        let loss_matrix = config.loss_matrix_preset.to_loss_matrix();
        let prior = Posterior::default_prior();
        let adaptive_router = RegretBoundedRouter::new(
            vec![
                AdaptiveLaneArm {
                    lane_id: "quickjs".to_string(),
                    description: "QuickJs-inspired deterministic lane".to_string(),
                },
                AdaptiveLaneArm {
                    lane_id: "v8".to_string(),
                    description: "V8-inspired throughput lane".to_string(),
                },
            ],
            ADAPTIVE_ROUTER_GAMMA_MILLIONTHS,
        )
        .expect("adaptive router configuration must be valid");
        Self {
            parser: CanonicalEs2020Parser,
            lane_router: LaneRouter::new(),
            adaptive_router,
            stopping_policies: BTreeMap::new(),
            last_cumulative_llr_by_extension: BTreeMap::new(),
            posterior_updater: BayesianPosteriorUpdater::new(prior, "orchestrator"),
            loss_selector: ExpectedLossSelector::new(loss_matrix),
            ledger: InMemoryLedger::new(),
            saga_orchestrator: SagaOrchestrator::new(config.epoch, config.max_concurrent_sagas),
            containment_executor: ContainmentExecutor::new(),
            attempt_counter: 0,
            execution_counter: 0,
            config,
        }
    }

    /// Create an orchestrator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(OrchestratorConfig::default())
    }

    fn new_stopping_policy() -> EscalationPolicy {
        let mut policy = EscalationPolicy::new(
            STOPPING_CUSUM_THRESHOLD_MILLIONTHS,
            STOPPING_CUSUM_REFERENCE_MILLIONTHS,
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

    /// Access the saga orchestrator.
    pub fn saga_orchestrator(&self) -> &SagaOrchestrator {
        &self.saga_orchestrator
    }

    /// Number of executions completed.
    pub fn execution_count(&self) -> u64 {
        self.execution_counter
    }

    /// Execute an extension package through the full pipeline.
    pub fn execute(
        &mut self,
        package: &ExtensionPackage,
    ) -> Result<OrchestratorResult, OrchestratorError> {
        // Step 0: Validate.
        Self::validate_package(package)?;

        // Step 1: Generate identifiers.
        let (attempt_index, trace_id, decision_id) = self.allocate_attempt_identifiers();
        let source_label = format!("ext:{}", package.extension_id);

        // Step 2: Create execution cell.
        let mut cell = ExecutionCell::with_context(
            &trace_id,
            CellKind::Extension,
            &trace_id,
            &decision_id,
            &self.config.policy_id,
        );

        // Step 3: Register extension in containment executor.
        self.containment_executor.register(&package.extension_id);

        // Step 4: Parse source.
        let syntax_tree = self.parser.parse_with_options(
            package.source.as_str(),
            self.config.parse_goal,
            &self.config.parser_options,
        )?;

        // Step 5: Lower IR0 → IR3.
        let ir0 = Ir0Module::from_syntax_tree(syntax_tree, &source_label);
        let lowering_ctx = LoweringContext::new(&trace_id, &decision_id, &self.config.policy_id);
        let lowering_output = lower_ir0_to_ir3(&ir0, &lowering_ctx)?;
        let lowering_events = lowering_output.events.clone();
        let lowering_witnesses = lowering_output.witnesses.clone();
        let ir3_schedule_cost = Self::estimate_ir3_schedule_cost(&lowering_output.ir3);

        // Step 6: Execute IR3.
        let routed = self.phase_execute(&lowering_output.ir3, &trace_id)?;
        let lane = routed.lane;
        let lane_reason = routed.reason;
        let exec_result = routed.result;
        let execution_value = format!("{}", exec_result.value);
        let instructions_executed = exec_result.instructions_executed;
        let adaptive_router_summary = self.update_adaptive_router(lane, &exec_result);

        // Step 7: Assess risk.
        let evidence = Self::build_evidence(package, &exec_result, self.config.epoch);
        let update_result = self.posterior_updater.update(&evidence);
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

        // Step 9: Record evidence.
        let (entry, evidence_compression_certificate) =
            self.phase_record_evidence(EvidenceRecordInput {
                trace_id: &trace_id,
                decision_id: &decision_id,
                package,
                decision: &action_decision,
                effective_action: containment_action,
                exec: &exec_result,
                update: &update_result,
                ir3_schedule_cost,
                adaptive_router_summary: adaptive_router_summary.as_ref(),
                optimal_stopping_certificate: optimal_stopping_certificate.as_ref(),
            })?;
        let evidence_entries = vec![entry];

        // Step 10: Execute any selected containment action and attach a saga
        // only for the actions that require follow-up orchestration.
        let (containment_receipt, saga_id) =
            self.phase_execute_containment(containment_action, package, &trace_id, &decision_id)?;

        // Step 11: Close execution cell.
        let cancel_reason = if containment_action.severity() >= 4 {
            CancelReason::Quarantine
        } else {
            CancelReason::OperatorShutdown
        };
        let deadline = DrainDeadline {
            max_ticks: self.config.drain_deadline_ticks,
        };
        let trace_seed = attempt_index.wrapping_add(1000);
        let mut cx = MockCx::new(trace_id_from_seed(trace_seed), MockBudget::new(10_000));
        let finalize_result = cell.close(&mut cx, cancel_reason, deadline).ok();

        // Step 12: Drain cell events and assemble result.
        let cell_events = cell.drain_events();

        self.execution_counter += 1;

        Ok(OrchestratorResult {
            extension_id: package.extension_id.clone(),
            trace_id,
            decision_id,
            source_label,
            lowering_events,
            lowering_witnesses,
            lane,
            lane_reason,
            execution_value,
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
            containment_receipt,
            saga_id,
            cell_events,
            finalize_result,
            epoch: self.config.epoch,
        })
    }

    // -- Private helpers -----------------------------------------------------

    fn validate_package(package: &ExtensionPackage) -> Result<(), OrchestratorError> {
        if package.source.trim().is_empty() {
            return Err(OrchestratorError::EmptySource);
        }
        if package.extension_id.trim().is_empty() {
            return Err(OrchestratorError::EmptyExtensionId);
        }
        Ok(())
    }

    fn phase_execute(
        &self,
        ir3: &Ir3Module,
        trace_id: &str,
    ) -> Result<RoutedResult, OrchestratorError> {
        self.lane_router
            .execute(ir3, trace_id, self.config.force_lane)
            .map_err(OrchestratorError::Interpreter)
    }

    fn phase_record_evidence(
        &mut self,
        input: EvidenceRecordInput<'_>,
    ) -> Result<(EvidenceEntry, Option<CompressionCertificate>), OrchestratorError> {
        let EvidenceRecordInput {
            trace_id,
            decision_id,
            package,
            decision,
            effective_action,
            exec,
            update,
            ir3_schedule_cost,
            adaptive_router_summary,
            optimal_stopping_certificate,
        } = input;
        let mut builder = EvidenceEntryBuilder::new(
            trace_id,
            decision_id,
            &self.config.policy_id,
            self.config.epoch,
            DecisionType::SecurityAction,
        );

        builder = builder.timestamp_ns(0);

        // Add all containment actions as candidates.
        for action in &ContainmentAction::ALL {
            builder = builder.candidate(CandidateAction::new(format!("{action:?}"), 0));
        }

        // Record chosen action.
        let stopping_override = effective_action != decision.action;
        builder = builder.chosen(ChosenAction {
            action_name: format!("{:?}", effective_action),
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
                "instructions={} hostcalls={} value={}",
                exec.instructions_executed,
                exec.hostcall_decisions.len(),
                exec.value
            ),
        });

        // Metadata.
        builder = builder.meta("extension_id".to_string(), package.extension_id.clone());
        builder = builder.meta("extension_version".to_string(), package.version.clone());
        builder = builder.meta(
            "capabilities_count".to_string(),
            package.capabilities.len().to_string(),
        );

        if let Some(cost) = ir3_schedule_cost {
            builder = builder.meta("ir3_schedule_cost".to_string(), cost.0.to_string());
        }
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

        let compression_certificate = Self::build_evidence_compression_certificate(
            package,
            decision,
            effective_action,
            exec,
            update,
            adaptive_router_summary,
            optimal_stopping_certificate,
            ir3_schedule_cost,
        );
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
        }

        let entry = builder.build()?;
        self.ledger.emit(entry.clone())?;
        Ok((entry, compression_certificate))
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
        let llr_increment = update
            .cumulative_llr_millionths
            .saturating_sub(previous_llr);
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
        let policy = self
            .stopping_policies
            .entry(package.extension_id.clone())
            .or_insert_with(Self::new_stopping_policy);
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
        let cert_data = format!(
            "{algorithm}:{}:{:?}:{}",
            policy.total_observations,
            decision,
            epoch.as_u64()
        );
        OptimalStoppingCertificate {
            schema: STOPPING_SCHEMA_VERSION.to_string(),
            algorithm,
            observations_before_stop: policy.total_observations,
            cusum_statistic_millionths: Some(policy.cusum.statistic_millionths),
            arl0_lower_bound: Some(policy.cusum.arl0_lower_bound(SCALE_MILLION)),
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
            crate::ir_contract::Ir3Instruction::LoadStr { .. } => "load_str",
            crate::ir_contract::Ir3Instruction::LoadBool { .. } => "load_bool",
            crate::ir_contract::Ir3Instruction::LoadNull { .. } => "load_null",
            crate::ir_contract::Ir3Instruction::LoadUndefined { .. } => "load_undefined",
            crate::ir_contract::Ir3Instruction::Add { .. } => "add",
            crate::ir_contract::Ir3Instruction::Sub { .. } => "sub",
            crate::ir_contract::Ir3Instruction::Mul { .. } => "mul",
            crate::ir_contract::Ir3Instruction::Div { .. } => "div",
            crate::ir_contract::Ir3Instruction::Move { .. } => "move",
            crate::ir_contract::Ir3Instruction::Jump { .. } => "jump",
            crate::ir_contract::Ir3Instruction::JumpIf { .. } => "jump_if",
            crate::ir_contract::Ir3Instruction::Call { .. } => "call",
            crate::ir_contract::Ir3Instruction::Return { .. } => "return",
            crate::ir_contract::Ir3Instruction::HostCall { .. } => "host_call",
            crate::ir_contract::Ir3Instruction::GetProperty { .. } => "get_property",
            crate::ir_contract::Ir3Instruction::SetProperty { .. } => "set_property",
            crate::ir_contract::Ir3Instruction::Halt => "halt",
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
            crate::ir_contract::Ir3Instruction::JumpIf { target, .. } => {
                let target = *target as usize;
                if next < instruction_count {
                    out.push(next);
                }
                if target < instruction_count {
                    out.push(target);
                }
            }
            crate::ir_contract::Ir3Instruction::Return { .. }
            | crate::ir_contract::Ir3Instruction::Halt => {}
            _ => {
                if next < instruction_count {
                    out.push(next);
                }
            }
        }

        out
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence_compression_certificate(
        package: &ExtensionPackage,
        decision: &ActionDecision,
        effective_action: ContainmentAction,
        exec: &ExecutionResult,
        update: &UpdateResult,
        adaptive_router_summary: Option<&RouterSummary>,
        optimal_stopping_certificate: Option<&OptimalStoppingCertificate>,
        ir3_schedule_cost: Option<TropicalWeight>,
    ) -> Option<CompressionCertificate> {
        let symbols = Self::build_evidence_symbols(
            package,
            decision,
            effective_action,
            exec,
            update,
            adaptive_router_summary,
            optimal_stopping_certificate,
            ir3_schedule_cost,
        );
        if symbols.is_empty() {
            return None;
        }

        let mut estimator = EntropyEstimator::new();
        for &symbol in &symbols {
            estimator.observe(symbol);
        }
        let coder = ArithmeticCoder::from_estimator(&estimator).ok()?;
        let compressed = coder.encode(&symbols).ok()?;
        let kraft_sum = coder.verify_kraft_inequality().ok()?;
        Some(CompressionCertificate::build(
            &estimator,
            &compressed,
            kraft_sum,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn build_evidence_symbols(
        package: &ExtensionPackage,
        decision: &ActionDecision,
        effective_action: ContainmentAction,
        exec: &ExecutionResult,
        update: &UpdateResult,
        adaptive_router_summary: Option<&RouterSummary>,
        optimal_stopping_certificate: Option<&OptimalStoppingCertificate>,
        ir3_schedule_cost: Option<TropicalWeight>,
    ) -> Vec<u32> {
        let mut symbols = vec![
            10 + decision.action.severity(),
            20 + effective_action.severity(),
            30 + Self::risk_state_symbol(update.posterior.map_estimate()),
            40 + (exec.instructions_executed.min(u32::MAX as u64) as u32 % 1000),
            50 + (exec.hostcall_decisions.len() as u32 % 1000),
        ];

        for capability in &package.capabilities {
            symbols.push(1_000 + (Self::stable_symbol(capability) % 10_000));
        }
        for decision in &exec.hostcall_decisions {
            symbols.push(20_000 + (Self::stable_symbol(&decision.capability.0) % 10_000));
        }

        if let Some(summary) = adaptive_router_summary {
            symbols.push(30_000 + summary.active_regime as u32);
            symbols.push(31_000 + (summary.realized_regret_millionths.max(0) as u32 % 10_000));
        }
        if let Some(cert) = optimal_stopping_certificate {
            symbols.push(40_000 + (Self::stable_symbol(&cert.algorithm) % 10_000));
            symbols.push(41_000 + (cert.observations_before_stop as u32 % 10_000));
        }
        if let Some(cost) = ir3_schedule_cost {
            symbols.push(50_000 + (cost.0.max(0) as u32 % 10_000));
        }

        symbols
    }

    fn risk_state_symbol(state: RiskState) -> u32 {
        match state {
            RiskState::Benign => 0,
            RiskState::Anomalous => 1,
            RiskState::Malicious => 2,
            RiskState::Unknown => 3,
        }
    }

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
    ) -> Result<(Option<ContainmentReceipt>, Option<String>), OrchestratorError> {
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
            let steps = match saga_type {
                SagaType::Quarantine => quarantine_saga_steps(&package.extension_id),
                SagaType::Eviction => eviction_saga_steps(&package.extension_id),
                SagaType::Revocation => revocation_saga_steps(&package.extension_id),
                SagaType::Publish => unreachable!("action_to_saga_type never returns Publish"),
            };
            let saga_id_str = format!("{trace_id}:saga");
            let id =
                self.saga_orchestrator
                    .create_saga(&saga_id_str, saga_type, steps, trace_id, 0)?;
            Some(id.to_string())
        } else {
            None
        };

        Ok((Some(receipt), saga_id))
    }

    fn allocate_attempt_identifiers(&mut self) -> (u64, String, String) {
        let attempt_index = self.attempt_counter;
        self.attempt_counter = self.attempt_counter.wrapping_add(1);
        (
            attempt_index,
            format!("{}:{}", self.config.trace_id_prefix, attempt_index),
            format!("{}:decision:{}", self.config.trace_id_prefix, attempt_index),
        )
    }

    fn build_evidence(
        package: &ExtensionPackage,
        exec: &ExecutionResult,
        epoch: SecurityEpoch,
    ) -> Evidence {
        let hostcall_count = exec.hostcall_decisions.len() as u64;
        let hostcall_rate_millionths = hostcall_count
            .saturating_mul(1_000_000)
            .checked_div(exec.instructions_executed)
            .unwrap_or(0);

        let distinct_capabilities = package.capabilities.len() as u32;

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
            distinct_capabilities,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_package() -> ExtensionPackage {
        ExtensionPackage {
            extension_id: "test-ext-1".to_string(),
            source: "42".to_string(),
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    fn package_with_id(extension_id: &str) -> ExtensionPackage {
        ExtensionPackage {
            extension_id: extension_id.to_string(),
            ..simple_package()
        }
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
            hostcall_decisions: Vec::new(),
            instructions_executed: u64::MAX,
            witness_events: Vec::new(),
            events: Vec::new(),
        };
        let reward = ExecutionOrchestrator::execution_reward_millionths(&exec);
        assert_eq!(reward, 400_000);
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
    fn empty_source_returns_error() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let pkg = ExtensionPackage {
            extension_id: "ext-1".to_string(),
            source: "".to_string(),
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
            capabilities: vec![],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let err = orch.execute(&pkg).expect_err("empty id should fail");
        assert!(matches!(err, OrchestratorError::EmptyExtensionId));
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
        assert_eq!(cfg.loss_matrix_preset, LossMatrixPreset::Balanced);
        assert!(cfg.force_lane.is_none());
        assert_eq!(cfg.drain_deadline_ticks, 10_000);
        assert_eq!(cfg.max_concurrent_sagas, 4);
        assert_eq!(cfg.epoch, SecurityEpoch::from_raw(1));
        assert_eq!(cfg.trace_id_prefix, "orch");
        assert_eq!(cfg.policy_id, "default-policy");
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
    fn result_lowering_witnesses_populated() {
        let mut orch = ExecutionOrchestrator::with_defaults();
        let result = orch.execute(&simple_package()).unwrap();
        assert!(!result.lowering_witnesses.is_empty());
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
        let json = serde_json::to_string(&pkg).expect("serialize");
        let restored: ExtensionPackage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(pkg.extension_id, restored.extension_id);
        assert!(restored.metadata.is_empty());
    }

    #[test]
    fn extension_package_with_many_capabilities_serde() {
        let pkg = ExtensionPackage {
            extension_id: "ext-many".to_string(),
            source: "42".to_string(),
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
            max_concurrent_sagas: 16,
            epoch: SecurityEpoch::from_raw(77),
            trace_id_prefix: "clone-test".to_string(),
            policy_id: "policy-clone".to_string(),
            ..OrchestratorConfig::default()
        };
        let cloned = cfg.clone();
        assert_eq!(cloned.loss_matrix_preset, LossMatrixPreset::Conservative);
        assert_eq!(cloned.drain_deadline_ticks, 99_999);
        assert_eq!(cloned.max_concurrent_sagas, 16);
        assert_eq!(cloned.epoch, SecurityEpoch::from_raw(77));
        assert_eq!(cloned.trace_id_prefix, "clone-test");
        assert_eq!(cloned.policy_id, "policy-clone");
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
            source: "new Date()".to_string(),
            ..simple_package()
        };

        let err = orch
            .execute(&lowering_failure)
            .expect_err("lowering should fail");
        assert!(matches!(err, OrchestratorError::Lowering(_)));
        assert_eq!(orch.execution_count(), 0);

        let result = orch.execute(&simple_package()).expect("follow-up execute");
        assert_eq!(result.trace_id, "orch:1");
        assert_eq!(result.decision_id, "orch:decision:1");
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
            hostcall_decisions: Vec::new(),
            instructions_executed: 0,
            witness_events: Vec::new(),
            events: Vec::new(),
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
        let mut ir3 = crate::ir_contract::Ir3Module::new(
            ContentHash::compute(b"looping-ir3"),
            "looping-ir3",
        );
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
        assert_eq!(s, 0x811C9DC5);
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
            hostcall_decisions: Vec::new(),
            instructions_executed: 10,
            witness_events: Vec::new(),
            events: Vec::new(),
        };
        let ev = ExecutionOrchestrator::build_evidence(&pkg, &exec, SecurityEpoch::from_raw(1));
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
            hostcall_decisions: Vec::new(),
            instructions_executed: u64::MAX,
            witness_events: Vec::new(),
            events: Vec::new(),
        };
        let ev = ExecutionOrchestrator::build_evidence(&pkg, &exec, SecurityEpoch::from_raw(1));
        assert_eq!(ev.resource_score_millionths, 1_000_000);
    }

    #[test]
    fn build_evidence_with_capabilities() {
        let pkg = ExtensionPackage {
            extension_id: "ext-caps".to_string(),
            source: "42".to_string(),
            capabilities: vec!["fs".to_string(), "net".to_string(), "crypto".to_string()],
            version: "1.0.0".to_string(),
            metadata: BTreeMap::new(),
        };
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
            hostcall_decisions: Vec::new(),
            instructions_executed: 5,
            witness_events: Vec::new(),
            events: Vec::new(),
        };
        let ev = ExecutionOrchestrator::build_evidence(&pkg, &exec, SecurityEpoch::from_raw(2));
        assert_eq!(ev.distinct_capabilities, 3);
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
            hostcall_decisions: Vec::new(),
            instructions_executed: 1,
            witness_events: Vec::new(),
            events: Vec::new(),
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
        let cloned = original.clone();
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
            hostcall_decisions: Vec::new(),
            instructions_executed: 0,
            witness_events: Vec::new(),
            events: Vec::new(),
        };
        let ev = ExecutionOrchestrator::build_evidence(&pkg, &exec, SecurityEpoch::from_raw(1));
        // Division by zero for hostcall_rate should be handled (returns 0).
        assert_eq!(ev.hostcall_rate_millionths, 0);
        assert_eq!(ev.resource_score_millionths, 0);
    }

    #[test]
    fn enrichment_execution_reward_hostcall_penalty_only() {
        use crate::ir_contract::{CapabilityTag, HostcallDecisionRecord};
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Null,
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
            witness_events: Vec::new(),
            events: Vec::new(),
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
            hostcall_decisions: many_hostcalls,
            instructions_executed: 0,
            witness_events: Vec::new(),
            events: Vec::new(),
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
    }

    #[test]
    fn enrichment_build_evidence_epoch_propagation() {
        let pkg = simple_package();
        let exec = ExecutionResult {
            value: crate::baseline_interpreter::Value::Int(1_000_000),
            hostcall_decisions: Vec::new(),
            instructions_executed: 5,
            witness_events: Vec::new(),
            events: Vec::new(),
        };
        for raw_epoch in [1u64, 100, u64::MAX] {
            let epoch = SecurityEpoch::from_raw(raw_epoch);
            let ev = ExecutionOrchestrator::build_evidence(&pkg, &exec, epoch);
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
}
