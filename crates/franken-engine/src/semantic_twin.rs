//! [FRX-19.1] Semantic Twin State Space and Causal Graph Specification
//!
//! This module defines an executable semantic twin for lane/router decisions:
//! - versioned twin state variable dictionary with concrete runtime/FRIR signal bindings
//! - deterministic transition contract over twin variables
//! - causal adjustment strategies for key decision-outcome effects
//! - identifiability assumptions wired to falsification monitors via assumptions ledger

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::assumptions_ledger::{
    Assumption, AssumptionCategory, AssumptionLedger, AssumptionOrigin, AssumptionStatus,
    DemotionAction, DemotionPolicy, FalsificationMonitor, LedgerError, MonitorKind, MonitorOp,
    ViolationSeverity,
};
use crate::structural_causal_model::{
    BackdoorResult, ScmError, StructuralCausalModel, VariableDomain, build_lane_decision_dag,
};

/// Semantic twin state dictionary schema.
pub const SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION: &str =
    "franken-engine.semantic-twin.state-space.v1";
/// Causal adjustment strategy schema.
pub const SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION: &str =
    "franken-engine.semantic-twin.causal-adjustment.v1";
/// Structured log schema for semantic twin monitor events.
pub const SEMANTIC_TWIN_LOG_SCHEMA_VERSION: &str = "franken-engine.semantic-twin.log-event.v1";
/// Stable component identifier for semantic twin events.
pub const SEMANTIC_TWIN_COMPONENT: &str = "semantic_twin_state_space";

/// Runtime/FRIR namespace for a mapped telemetry signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalNamespace {
    Frir,
    RuntimeDecisionCore,
    RuntimeObservability,
    PolicyController,
    AssumptionsLedger,
}

impl SignalNamespace {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Frir => "frir",
            Self::RuntimeDecisionCore => "runtime_decision_core",
            Self::RuntimeObservability => "runtime_observability",
            Self::PolicyController => "policy_controller",
            Self::AssumptionsLedger => "assumptions_ledger",
        }
    }
}

/// Concrete telemetry binding for a semantic twin variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryContractRef {
    pub namespace: SignalNamespace,
    pub signal_key: String,
    pub units: String,
    pub deterministic: bool,
    pub required: bool,
}

impl TelemetryContractRef {
    pub fn validate(&self) -> Result<(), SemanticTwinError> {
        if self.signal_key.trim().is_empty() {
            return Err(SemanticTwinError::MissingTelemetrySignalKey {
                namespace: self.namespace.as_str().to_string(),
            });
        }
        if self.units.trim().is_empty() {
            return Err(SemanticTwinError::MissingTelemetryUnits {
                signal_key: self.signal_key.clone(),
            });
        }
        Ok(())
    }
}

/// One variable in the semantic twin state dictionary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinStateVariable {
    pub id: String,
    pub label: String,
    pub description: String,
    pub domain: VariableDomain,
    pub observable: bool,
    pub telemetry: TelemetryContractRef,
}

/// Guard condition for deterministic transition activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionGuard {
    pub variable: String,
    pub op: MonitorOp,
    pub threshold_millionths: i64,
}

/// Deterministic transition relation between semantic twin variables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwinStateTransition {
    pub transition_id: String,
    pub source_variable: String,
    pub target_variable: String,
    pub trigger_event: String,
    pub telemetry_contract: String,
    #[serde(default)]
    pub guard: Option<TransitionGuard>,
}

/// Adjustment strategy for a specific treatment→outcome causal effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalAdjustmentStrategy {
    pub effect_id: String,
    pub treatment: String,
    pub outcome: String,
    pub identified: bool,
    pub adjustment_set: BTreeSet<String>,
    pub blocked_confounding_paths: Vec<Vec<String>>,
    pub strategy_note: String,
}

/// Explicit identifiability assumption mapped to telemetry + monitor contracts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifiabilityAssumption {
    pub assumption_id: String,
    pub description: String,
    pub category: AssumptionCategory,
    pub origin: AssumptionOrigin,
    pub decision_effect_id: String,
    pub telemetry_contract: String,
    pub monitor_kind: MonitorKind,
    pub monitor_variable: String,
    pub monitor_op: MonitorOp,
    pub monitor_threshold_millionths: i64,
    pub trigger_count: u32,
    pub violation_severity: ViolationSeverity,
}

/// [FRX-19.1] executable semantic twin specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinSpecification {
    pub schema_version: String,
    pub causal_adjustment_schema_version: String,
    pub state_variables: Vec<TwinStateVariable>,
    pub transitions: Vec<TwinStateTransition>,
    pub adjustment_strategies: Vec<CausalAdjustmentStrategy>,
    pub assumptions: Vec<IdentifiabilityAssumption>,
    pub causal_model: StructuralCausalModel,
}

/// Structured semantic twin monitor event with stable fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinLogEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub variable: String,
    pub observed_value_millionths: i64,
    pub assumption_id: Option<String>,
    pub monitor_id: Option<String>,
    pub action: Option<String>,
}

/// Outcome of observing one semantic twin telemetry value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinObservationResult {
    pub actions: Vec<DemotionAction>,
    pub events: Vec<SemanticTwinLogEvent>,
}

/// Runtime wrapper that enforces semantic twin assumptions via monitors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTwinRuntime {
    specification: SemanticTwinSpecification,
    ledger: AssumptionLedger,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    tick: u64,
}

/// Semantic twin failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticTwinError {
    Scm(ScmError),
    Ledger(LedgerError),
    DuplicateVariable(String),
    MissingTelemetrySignalKey {
        namespace: String,
    },
    MissingTelemetryUnits {
        signal_key: String,
    },
    TransitionMissingVariable {
        transition_id: String,
        variable: String,
    },
    AdjustmentNotIdentified {
        effect_id: String,
    },
    AdjustmentMismatch {
        effect_id: String,
        expected: BTreeSet<String>,
        actual: BTreeSet<String>,
    },
    AssumptionMissingVariable {
        assumption_id: String,
        variable: String,
    },
    AssumptionMissingEffect {
        assumption_id: String,
        effect_id: String,
    },
    InvalidAssumptionTriggerCount {
        assumption_id: String,
    },
}

impl std::fmt::Display for SemanticTwinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scm(err) => write!(f, "scm error: {err}"),
            Self::Ledger(err) => write!(f, "assumptions ledger error: {err}"),
            Self::DuplicateVariable(id) => write!(f, "duplicate semantic twin variable: {id}"),
            Self::MissingTelemetrySignalKey { namespace } => {
                write!(f, "missing telemetry signal key for namespace {namespace}")
            }
            Self::MissingTelemetryUnits { signal_key } => {
                write!(f, "missing telemetry units for signal {signal_key}")
            }
            Self::TransitionMissingVariable {
                transition_id,
                variable,
            } => write!(
                f,
                "transition {transition_id} references unknown variable {variable}"
            ),
            Self::AdjustmentNotIdentified { effect_id } => {
                write!(f, "causal effect {effect_id} is not identified")
            }
            Self::AdjustmentMismatch {
                effect_id,
                expected,
                actual,
            } => write!(
                f,
                "adjustment mismatch for {effect_id}: expected {:?}, actual {:?}",
                expected, actual
            ),
            Self::AssumptionMissingVariable {
                assumption_id,
                variable,
            } => write!(
                f,
                "assumption {assumption_id} references unknown monitor variable {variable}"
            ),
            Self::AssumptionMissingEffect {
                assumption_id,
                effect_id,
            } => write!(
                f,
                "assumption {assumption_id} references unknown effect {effect_id}"
            ),
            Self::InvalidAssumptionTriggerCount { assumption_id } => {
                write!(f, "assumption {assumption_id} has trigger_count=0")
            }
        }
    }
}

impl std::error::Error for SemanticTwinError {}

impl From<ScmError> for SemanticTwinError {
    fn from(value: ScmError) -> Self {
        Self::Scm(value)
    }
}

impl From<LedgerError> for SemanticTwinError {
    fn from(value: LedgerError) -> Self {
        Self::Ledger(value)
    }
}

impl SemanticTwinSpecification {
    /// Build canonical [FRX-19.1] semantic twin specification.
    pub fn frx_19_1_default() -> Result<Self, SemanticTwinError> {
        let causal_model = build_lane_decision_dag()?;

        let state_variables = default_state_variables();
        let transitions = default_transitions(&causal_model);

        let adjustment_strategies = vec![
            adjustment_strategy(
                &causal_model,
                "effect_lane_choice_to_latency",
                "lane_choice",
                "latency_outcome",
                "Backdoor adjustment blocks regime/workload/load confounding before estimating lane latency effect.",
            )?,
            adjustment_strategy(
                &causal_model,
                "effect_lane_choice_to_correctness",
                "lane_choice",
                "correctness_outcome",
                "Backdoor adjustment blocks regime/workload confounding before estimating lane correctness effect.",
            )?,
        ];

        let assumptions = vec![
            IdentifiabilityAssumption {
                assumption_id: "asm-regime-observability".to_string(),
                description: "Regime labels are observed and linked to each routing decision".to_string(),
                category: AssumptionCategory::Structural,
                origin: AssumptionOrigin::Runtime,
                decision_effect_id: "effect_lane_choice_to_latency".to_string(),
                telemetry_contract: "runtime_observability.regime_observed_millionths"
                    .to_string(),
                monitor_kind: MonitorKind::Invariant,
                monitor_variable: "regime_observed_millionths".to_string(),
                monitor_op: MonitorOp::Ge,
                monitor_threshold_millionths: 1_000_000,
                trigger_count: 1,
                violation_severity: ViolationSeverity::Critical,
            },
            IdentifiabilityAssumption {
                assumption_id: "asm-latency-conounder-stability".to_string(),
                description:
                    "Environment load drift remains bounded for latency-effect identifiability"
                        .to_string(),
                category: AssumptionCategory::Statistical,
                origin: AssumptionOrigin::Inferred,
                decision_effect_id: "effect_lane_choice_to_latency".to_string(),
                telemetry_contract: "runtime_observability.environment_load_drift_millionths"
                    .to_string(),
                monitor_kind: MonitorKind::Drift,
                monitor_variable: "environment_load_drift_millionths".to_string(),
                monitor_op: MonitorOp::Le,
                monitor_threshold_millionths: 150_000,
                trigger_count: 2,
                violation_severity: ViolationSeverity::Warning,
            },
            IdentifiabilityAssumption {
                assumption_id: "asm-risk-calibration-error".to_string(),
                description:
                    "Risk posterior calibration error remains below configured bound for correctness attribution"
                        .to_string(),
                category: AssumptionCategory::Statistical,
                origin: AssumptionOrigin::Runtime,
                decision_effect_id: "effect_lane_choice_to_correctness".to_string(),
                telemetry_contract: "runtime_decision_core.risk_calibration_error_millionths"
                    .to_string(),
                monitor_kind: MonitorKind::Coverage,
                monitor_variable: "risk_calibration_error_millionths".to_string(),
                monitor_op: MonitorOp::Le,
                monitor_threshold_millionths: 120_000,
                trigger_count: 1,
                violation_severity: ViolationSeverity::Critical,
            },
            IdentifiabilityAssumption {
                assumption_id: "asm-frir-witness-linkage".to_string(),
                description: "FRIR witness linkage is present for each twin state transition"
                    .to_string(),
                category: AssumptionCategory::Behavioral,
                origin: AssumptionOrigin::CompileTime,
                decision_effect_id: "effect_lane_choice_to_correctness".to_string(),
                telemetry_contract: "frir_schema.witness_linkage_ratio_millionths".to_string(),
                monitor_kind: MonitorKind::Invariant,
                monitor_variable: "frir_witness_linkage_millionths".to_string(),
                monitor_op: MonitorOp::Ge,
                monitor_threshold_millionths: 1_000_000,
                trigger_count: 1,
                violation_severity: ViolationSeverity::Fatal,
            },
        ];

        let spec = Self {
            schema_version: SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION.to_string(),
            causal_adjustment_schema_version: SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION
                .to_string(),
            state_variables,
            transitions,
            adjustment_strategies,
            assumptions,
            causal_model,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validate semantic twin dictionary, transitions, adjustment strategy, and assumptions.
    pub fn validate(&self) -> Result<(), SemanticTwinError> {
        let mut variable_index = BTreeMap::new();
        for variable in &self.state_variables {
            if variable_index.insert(variable.id.clone(), true).is_some() {
                return Err(SemanticTwinError::DuplicateVariable(variable.id.clone()));
            }
            variable.telemetry.validate()?;
        }

        for transition in &self.transitions {
            if !variable_index.contains_key(&transition.source_variable) {
                return Err(SemanticTwinError::TransitionMissingVariable {
                    transition_id: transition.transition_id.clone(),
                    variable: transition.source_variable.clone(),
                });
            }
            if !variable_index.contains_key(&transition.target_variable) {
                return Err(SemanticTwinError::TransitionMissingVariable {
                    transition_id: transition.transition_id.clone(),
                    variable: transition.target_variable.clone(),
                });
            }
            if let Some(guard) = &transition.guard
                && !variable_index.contains_key(&guard.variable)
            {
                return Err(SemanticTwinError::TransitionMissingVariable {
                    transition_id: transition.transition_id.clone(),
                    variable: guard.variable.clone(),
                });
            }
        }

        let mut effect_ids = BTreeMap::new();
        for strategy in &self.adjustment_strategies {
            effect_ids.insert(strategy.effect_id.clone(), true);

            if !strategy.identified {
                return Err(SemanticTwinError::AdjustmentNotIdentified {
                    effect_id: strategy.effect_id.clone(),
                });
            }

            let check = self
                .causal_model
                .backdoor_criterion(&strategy.treatment, &strategy.outcome)?;
            if !check.identified {
                return Err(SemanticTwinError::AdjustmentNotIdentified {
                    effect_id: strategy.effect_id.clone(),
                });
            }
            if check.adjustment_set != strategy.adjustment_set {
                return Err(SemanticTwinError::AdjustmentMismatch {
                    effect_id: strategy.effect_id.clone(),
                    expected: strategy.adjustment_set.clone(),
                    actual: check.adjustment_set,
                });
            }
        }

        for assumption in &self.assumptions {
            if !effect_ids.contains_key(&assumption.decision_effect_id) {
                return Err(SemanticTwinError::AssumptionMissingEffect {
                    assumption_id: assumption.assumption_id.clone(),
                    effect_id: assumption.decision_effect_id.clone(),
                });
            }
            if !variable_index.contains_key(&assumption.monitor_variable) {
                return Err(SemanticTwinError::AssumptionMissingVariable {
                    assumption_id: assumption.assumption_id.clone(),
                    variable: assumption.monitor_variable.clone(),
                });
            }
            if assumption.trigger_count == 0 {
                return Err(SemanticTwinError::InvalidAssumptionTriggerCount {
                    assumption_id: assumption.assumption_id.clone(),
                });
            }
        }

        Ok(())
    }

    /// Build assumptions ledger and register falsification monitors from this spec.
    pub fn build_assumption_ledger(
        &self,
        decision_id: &str,
        epoch: u64,
        demotion_policy: DemotionPolicy,
    ) -> Result<AssumptionLedger, SemanticTwinError> {
        let mut ledger = AssumptionLedger::new(demotion_policy);

        for assumption in &self.assumptions {
            let mut dependencies = BTreeSet::new();
            dependencies.insert(assumption.decision_effect_id.clone());
            dependencies.insert(assumption.monitor_variable.clone());

            let assumption_row = Assumption {
                id: assumption.assumption_id.clone(),
                category: assumption.category,
                origin: assumption.origin,
                status: AssumptionStatus::Active,
                description: assumption.description.clone(),
                decision_id: decision_id.to_string(),
                epoch,
                dependencies,
                violation_severity: assumption.violation_severity,
                predicate_hash: predicate_hash(
                    assumption.assumption_id.as_str(),
                    assumption.monitor_variable.as_str(),
                    assumption.monitor_threshold_millionths,
                ),
            };
            ledger.record_assumption(assumption_row)?;

            ledger.register_monitor(FalsificationMonitor {
                monitor_id: format!("monitor-{}", assumption.assumption_id),
                assumption_id: assumption.assumption_id.clone(),
                kind: assumption.monitor_kind,
                variable: assumption.monitor_variable.clone(),
                threshold_millionths: assumption.monitor_threshold_millionths,
                op: assumption.monitor_op,
                trigger_count: assumption.trigger_count,
                current_violations: 0,
                triggered: false,
            })?;
        }

        Ok(ledger)
    }
}

impl SemanticTwinRuntime {
    /// Create runtime semantic twin monitor execution context.
    pub fn new(
        specification: SemanticTwinSpecification,
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        epoch: u64,
        demotion_policy: DemotionPolicy,
    ) -> Result<Self, SemanticTwinError> {
        specification.validate()?;
        let decision_id = decision_id.into();
        let ledger =
            specification.build_assumption_ledger(decision_id.as_str(), epoch, demotion_policy)?;
        Ok(Self {
            specification,
            ledger,
            trace_id: trace_id.into(),
            decision_id,
            policy_id: policy_id.into(),
            tick: 0,
        })
    }

    /// Observe one variable value and run falsification monitors deterministically.
    pub fn observe(
        &mut self,
        variable: &str,
        value_millionths: i64,
        epoch: u64,
    ) -> SemanticTwinObservationResult {
        let history_before = self.ledger.falsification_history().len();
        self.tick = self.tick.saturating_add(1);

        let actions = self
            .ledger
            .observe(variable, value_millionths, epoch, self.tick);
        let new_evidence = &self.ledger.falsification_history()[history_before..];

        let mut events = Vec::new();
        if new_evidence.is_empty() {
            events.push(SemanticTwinLogEvent {
                schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
                trace_id: self.trace_id.clone(),
                decision_id: self.decision_id.clone(),
                policy_id: self.policy_id.clone(),
                component: SEMANTIC_TWIN_COMPONENT.to_string(),
                event: "assumption_monitor_evaluate".to_string(),
                outcome: "ok".to_string(),
                error_code: None,
                variable: variable.to_string(),
                observed_value_millionths: value_millionths,
                assumption_id: None,
                monitor_id: None,
                action: None,
            });
        } else {
            for (index, evidence) in new_evidence.iter().enumerate() {
                events.push(SemanticTwinLogEvent {
                    schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
                    trace_id: self.trace_id.clone(),
                    decision_id: self.decision_id.clone(),
                    policy_id: self.policy_id.clone(),
                    component: SEMANTIC_TWIN_COMPONENT.to_string(),
                    event: "assumption_falsified".to_string(),
                    outcome: "falsified".to_string(),
                    error_code: Some("FE-SEMANTIC-TWIN-0001".to_string()),
                    variable: variable.to_string(),
                    observed_value_millionths: value_millionths,
                    assumption_id: Some(evidence.assumption_id.clone()),
                    monitor_id: Some(evidence.monitor_id.clone()),
                    action: actions.get(index).map(action_label),
                });
            }
        }

        SemanticTwinObservationResult { actions, events }
    }

    /// Access current semantic twin specification.
    pub fn specification(&self) -> &SemanticTwinSpecification {
        &self.specification
    }

    /// Access assumptions ledger state.
    pub fn ledger(&self) -> &AssumptionLedger {
        &self.ledger
    }
}

fn adjustment_strategy(
    causal_model: &StructuralCausalModel,
    effect_id: &str,
    treatment: &str,
    outcome: &str,
    strategy_note: &str,
) -> Result<CausalAdjustmentStrategy, SemanticTwinError> {
    let BackdoorResult {
        identified,
        adjustment_set,
        confounding_paths,
        ..
    } = causal_model.backdoor_criterion(treatment, outcome)?;

    Ok(CausalAdjustmentStrategy {
        effect_id: effect_id.to_string(),
        treatment: treatment.to_string(),
        outcome: outcome.to_string(),
        identified,
        adjustment_set,
        blocked_confounding_paths: confounding_paths,
        strategy_note: strategy_note.to_string(),
    })
}

fn default_state_variables() -> Vec<TwinStateVariable> {
    vec![
        state_variable(
            "workload_complexity",
            "Workload complexity score",
            "Deterministic complexity score extracted from FRIR workload profile.",
            VariableDomain::WorkloadCharacteristic,
            true,
            SignalNamespace::Frir,
            "workload.profile.complexity_millionths",
            "millionths",
        ),
        state_variable(
            "component_count",
            "Component count",
            "Count of component units in FRIR graph for the current route payload.",
            VariableDomain::WorkloadCharacteristic,
            true,
            SignalNamespace::Frir,
            "workload.profile.component_count_millionths",
            "millionths",
        ),
        state_variable(
            "effect_depth",
            "Effect depth",
            "Maximum deterministic effect-chain depth from FRIR normalization.",
            VariableDomain::WorkloadCharacteristic,
            true,
            SignalNamespace::Frir,
            "workload.profile.effect_depth_millionths",
            "millionths",
        ),
        state_variable(
            "environment_load",
            "Environment load",
            "Runtime observability aggregate load score for attribution windows.",
            VariableDomain::EnvironmentFactor,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.load_millionths",
            "millionths",
        ),
        state_variable(
            "regime",
            "Operating regime",
            "Regime detector output used as confounder adjustment signal.",
            VariableDomain::Regime,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.regime_millionths",
            "millionths",
        ),
        state_variable(
            "risk_belief",
            "Risk belief posterior",
            "Posterior risk belief driving expected-loss lane selection.",
            VariableDomain::RiskBelief,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.risk_belief_millionths",
            "millionths",
        ),
        state_variable(
            "loss_matrix_weight",
            "Loss matrix weight",
            "Policy controller risk/cost weight active for routing decision.",
            VariableDomain::PolicySetting,
            true,
            SignalNamespace::PolicyController,
            "policy.loss_weight_millionths",
            "millionths",
        ),
        state_variable(
            "lane_choice",
            "Lane choice",
            "Selected execution lane encoded as deterministic lane score.",
            VariableDomain::LaneChoice,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.selected_lane_millionths",
            "millionths",
        ),
        state_variable(
            "calibration_quality",
            "Calibration quality",
            "Calibration confidence quality emitted by decision core.",
            VariableDomain::CalibrationMetric,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.calibration_quality_millionths",
            "millionths",
        ),
        state_variable(
            "latency_outcome",
            "Latency outcome",
            "Observed end-to-end latency outcome for attributed request window.",
            VariableDomain::ObservedOutcome,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.latency_outcome_millionths",
            "millionths",
        ),
        state_variable(
            "correctness_outcome",
            "Correctness outcome",
            "Observed correctness/compliance score for attributed request window.",
            VariableDomain::ObservedOutcome,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.correctness_outcome_millionths",
            "millionths",
        ),
        state_variable(
            "regime_observed_millionths",
            "Regime observability ratio",
            "Coverage ratio indicating regime labels are recorded for decisions.",
            VariableDomain::Regime,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.regime_observed_millionths",
            "millionths",
        ),
        state_variable(
            "environment_load_drift_millionths",
            "Environment load drift",
            "Windowed drift score for environment load stability assumption.",
            VariableDomain::EnvironmentFactor,
            true,
            SignalNamespace::RuntimeObservability,
            "runtime.environment_load_drift_millionths",
            "millionths",
        ),
        state_variable(
            "risk_calibration_error_millionths",
            "Risk calibration error",
            "Calibration error used for identifiability of correctness effects.",
            VariableDomain::CalibrationMetric,
            true,
            SignalNamespace::RuntimeDecisionCore,
            "router.risk_calibration_error_millionths",
            "millionths",
        ),
        state_variable(
            "frir_witness_linkage_millionths",
            "FRIR witness linkage ratio",
            "Coverage ratio for FRIR witness linkage between transitions and decisions.",
            VariableDomain::PolicySetting,
            true,
            SignalNamespace::Frir,
            "frir_schema.witness_linkage_ratio_millionths",
            "millionths",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn state_variable(
    id: &str,
    label: &str,
    description: &str,
    domain: VariableDomain,
    observable: bool,
    namespace: SignalNamespace,
    signal_key: &str,
    units: &str,
) -> TwinStateVariable {
    TwinStateVariable {
        id: id.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        domain,
        observable,
        telemetry: TelemetryContractRef {
            namespace,
            signal_key: signal_key.to_string(),
            units: units.to_string(),
            deterministic: true,
            required: true,
        },
    }
}

fn default_transitions(causal_model: &StructuralCausalModel) -> Vec<TwinStateTransition> {
    causal_model
        .edges()
        .iter()
        .map(|edge| TwinStateTransition {
            transition_id: format!("transition-{}-to-{}", edge.source, edge.target),
            source_variable: edge.source.clone(),
            target_variable: edge.target.clone(),
            trigger_event: transition_trigger(edge.source.as_str(), edge.target.as_str()),
            telemetry_contract: transition_contract(edge.source.as_str(), edge.target.as_str()),
            guard: transition_guard(edge.source.as_str(), edge.target.as_str()),
        })
        .collect()
}

fn transition_trigger(source: &str, target: &str) -> String {
    match (source, target) {
        ("workload_complexity", "risk_belief")
        | ("component_count", "risk_belief")
        | ("effect_depth", "risk_belief") => "frir_workload_profile_emitted".to_string(),
        ("environment_load", "risk_belief") | ("environment_load", "latency_outcome") => {
            "runtime_load_window_sampled".to_string()
        }
        ("regime", "loss_matrix_weight") | ("regime", "lane_choice") => {
            "regime_detector_updated".to_string()
        }
        ("risk_belief", "lane_choice") => "risk_posterior_updated".to_string(),
        ("loss_matrix_weight", "lane_choice") => "policy_loss_matrix_reloaded".to_string(),
        ("lane_choice", "calibration_quality")
        | ("lane_choice", "latency_outcome")
        | ("lane_choice", "correctness_outcome") => "router_action_selected".to_string(),
        ("calibration_quality", "correctness_outcome") => "calibration_ledger_updated".to_string(),
        _ => "semantic_twin_transition_observed".to_string(),
    }
}

fn transition_contract(source: &str, target: &str) -> String {
    format!("{}->{}", source, target)
}

fn transition_guard(source: &str, target: &str) -> Option<TransitionGuard> {
    match (source, target) {
        ("risk_belief", "lane_choice") => Some(TransitionGuard {
            variable: "risk_belief".to_string(),
            op: MonitorOp::Ge,
            threshold_millionths: 400_000,
        }),
        ("regime", "lane_choice") => Some(TransitionGuard {
            variable: "regime_observed_millionths".to_string(),
            op: MonitorOp::Ge,
            threshold_millionths: 1_000_000,
        }),
        ("loss_matrix_weight", "lane_choice") => Some(TransitionGuard {
            variable: "loss_matrix_weight".to_string(),
            op: MonitorOp::Ge,
            threshold_millionths: 50_000,
        }),
        _ => None,
    }
}

fn predicate_hash(assumption_id: &str, variable: &str, threshold_millionths: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(assumption_id.as_bytes());
    hasher.update(b":");
    hasher.update(variable.as_bytes());
    hasher.update(b":");
    hasher.update(threshold_millionths.to_string().as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

fn action_label(action: &DemotionAction) -> String {
    match action {
        DemotionAction::EnterSafeMode { .. } => "enter_safe_mode".to_string(),
        DemotionAction::DemoteLane { .. } => "demote_lane".to_string(),
        DemotionAction::SuspendAdaptive { .. } => "suspend_adaptive".to_string(),
        DemotionAction::EscalateToOperator { .. } => "escalate_to_operator".to_string(),
        DemotionAction::NoAction => "no_action".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frx_19_1_default_spec_validates() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.validate().expect("spec validates");
        assert_eq!(
            spec.schema_version,
            SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION
        );
        assert!(spec.state_variables.len() >= 10);
        assert!(spec.transitions.len() >= 10);
    }

    #[test]
    fn adjustment_strategies_are_identified_with_non_empty_adjustment_set() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        for strategy in &spec.adjustment_strategies {
            assert!(
                strategy.identified,
                "effect {} should be identified",
                strategy.effect_id
            );
            assert!(
                !strategy.adjustment_set.is_empty()
                    || strategy.blocked_confounding_paths.is_empty(),
                "effect {} must either expose an adjustment set or have no confounding paths",
                strategy.effect_id
            );
        }
    }

    #[test]
    fn assumption_ledger_is_built_with_monitor_contracts() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let ledger = spec
            .build_assumption_ledger("decision-1", 9, DemotionPolicy::default())
            .expect("ledger");
        assert_eq!(ledger.assumption_count(), spec.assumptions.len());
        assert_eq!(ledger.monitors().len(), spec.assumptions.len());
        assert_eq!(ledger.active_count(), spec.assumptions.len());
    }

    #[test]
    fn runtime_observe_emits_ok_event_when_assumptions_hold() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let mut runtime = SemanticTwinRuntime::new(
            spec,
            "trace-semantic-twin",
            "decision-semantic-twin",
            "policy-semantic-twin",
            5,
            DemotionPolicy::default(),
        )
        .expect("runtime");

        let result = runtime.observe("risk_calibration_error_millionths", 80_000, 5);
        assert!(result.actions.is_empty());
        assert_eq!(result.events.len(), 1);
        assert_eq!(
            result.events[0].schema_version,
            SEMANTIC_TWIN_LOG_SCHEMA_VERSION
        );
        assert_eq!(result.events[0].event, "assumption_monitor_evaluate");
        assert_eq!(result.events[0].outcome, "ok");
    }

    #[test]
    fn runtime_observe_emits_falsification_event_and_action() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let mut runtime = SemanticTwinRuntime::new(
            spec,
            "trace-semantic-twin",
            "decision-semantic-twin",
            "policy-semantic-twin",
            5,
            DemotionPolicy::default(),
        )
        .expect("runtime");

        // This variable maps to warning-level assumption with trigger_count=2.
        let first = runtime.observe("environment_load_drift_millionths", 200_000, 5);
        assert!(first.actions.is_empty());

        let second = runtime.observe("environment_load_drift_millionths", 220_000, 5);
        assert_eq!(second.actions.len(), 1);
        assert!(matches!(
            second.actions[0],
            DemotionAction::SuspendAdaptive { .. }
        ));
        assert_eq!(second.events.len(), 1);
        assert_eq!(second.events[0].event, "assumption_falsified");
        assert_eq!(second.events[0].outcome, "falsified");
        assert_eq!(
            second.events[0].error_code.as_deref(),
            Some("FE-SEMANTIC-TWIN-0001")
        );
        assert!(second.events[0].assumption_id.is_some());
        assert!(second.events[0].monitor_id.is_some());
    }

    #[test]
    fn validate_rejects_assumption_missing_effect() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.assumptions[0].decision_effect_id = "unknown-effect".to_string();
        let err = spec.validate().expect_err("must fail");
        assert!(matches!(
            err,
            SemanticTwinError::AssumptionMissingEffect { .. }
        ));
    }

    #[test]
    fn validate_rejects_adjustment_set_mismatch() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.adjustment_strategies[0].adjustment_set.clear();
        let err = spec.validate().expect_err("must fail");
        assert!(matches!(err, SemanticTwinError::AdjustmentMismatch { .. }));
    }

    // ── SignalNamespace coverage ──────────────────────────────────

    #[test]
    fn signal_namespace_as_str_all_variants() {
        let expected = [
            (SignalNamespace::Frir, "frir"),
            (
                SignalNamespace::RuntimeDecisionCore,
                "runtime_decision_core",
            ),
            (
                SignalNamespace::RuntimeObservability,
                "runtime_observability",
            ),
            (SignalNamespace::PolicyController, "policy_controller"),
            (SignalNamespace::AssumptionsLedger, "assumptions_ledger"),
        ];
        for (ns, name) in expected {
            assert_eq!(ns.as_str(), name);
        }
    }

    #[test]
    fn signal_namespace_serde_roundtrip() {
        let variants = [
            SignalNamespace::Frir,
            SignalNamespace::RuntimeDecisionCore,
            SignalNamespace::RuntimeObservability,
            SignalNamespace::PolicyController,
            SignalNamespace::AssumptionsLedger,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let back: SignalNamespace = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    // ── TelemetryContractRef validation ──────────────────────────

    #[test]
    fn telemetry_ref_valid() {
        let tcr = TelemetryContractRef {
            namespace: SignalNamespace::Frir,
            signal_key: "workload.complexity".to_string(),
            units: "millionths".to_string(),
            deterministic: true,
            required: true,
        };
        assert_eq!(tcr.validate(), Ok(()));
    }

    #[test]
    fn telemetry_ref_empty_signal_key_fails() {
        let tcr = TelemetryContractRef {
            namespace: SignalNamespace::RuntimeDecisionCore,
            signal_key: "  ".to_string(),
            units: "millionths".to_string(),
            deterministic: true,
            required: true,
        };
        let err = tcr.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::MissingTelemetrySignalKey { .. }
        ));
    }

    #[test]
    fn telemetry_ref_empty_units_fails() {
        let tcr = TelemetryContractRef {
            namespace: SignalNamespace::Frir,
            signal_key: "some.signal".to_string(),
            units: String::new(),
            deterministic: true,
            required: true,
        };
        let err = tcr.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::MissingTelemetryUnits { .. }
        ));
    }

    #[test]
    fn telemetry_ref_serde_roundtrip() {
        let tcr = TelemetryContractRef {
            namespace: SignalNamespace::PolicyController,
            signal_key: "policy.weight".to_string(),
            units: "millionths".to_string(),
            deterministic: false,
            required: false,
        };
        let json = serde_json::to_string(&tcr).unwrap();
        let back: TelemetryContractRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tcr);
    }

    // ── SemanticTwinSpecification validate edge cases ────────────

    #[test]
    fn validate_rejects_duplicate_variable() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let dup = spec.state_variables[0].clone();
        spec.state_variables.push(dup);
        let err = spec.validate().unwrap_err();
        assert!(matches!(err, SemanticTwinError::DuplicateVariable(..)));
    }

    #[test]
    fn validate_rejects_transition_source_missing() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.transitions[0].source_variable = "nonexistent_var".to_string();
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::TransitionMissingVariable { .. }
        ));
    }

    #[test]
    fn validate_rejects_transition_target_missing() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.transitions[0].target_variable = "nonexistent_var".to_string();
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::TransitionMissingVariable { .. }
        ));
    }

    #[test]
    fn validate_rejects_transition_guard_missing_variable() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        // Find a transition with a guard and corrupt the variable
        for transition in &mut spec.transitions {
            if let Some(guard) = transition.guard.as_mut() {
                guard.variable = "missing_guard_var".to_string();
                break;
            }
        }
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::TransitionMissingVariable { .. }
        ));
    }

    #[test]
    fn validate_rejects_assumption_missing_variable() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.assumptions[0].monitor_variable = "nonexistent_monitor_var".to_string();
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::AssumptionMissingVariable { .. }
        ));
    }

    #[test]
    fn validate_rejects_assumption_zero_trigger_count() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.assumptions[0].trigger_count = 0;
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::InvalidAssumptionTriggerCount { .. }
        ));
    }

    #[test]
    fn validate_rejects_adjustment_not_identified() {
        let mut spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        spec.adjustment_strategies[0].identified = false;
        let err = spec.validate().unwrap_err();
        assert!(matches!(
            err,
            SemanticTwinError::AdjustmentNotIdentified { .. }
        ));
    }

    // ── Structural assertions on default spec ────────────────────

    #[test]
    fn default_spec_has_two_adjustment_strategies() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        assert_eq!(spec.adjustment_strategies.len(), 2);
    }

    #[test]
    fn default_spec_has_four_assumptions() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        assert_eq!(spec.assumptions.len(), 4);
    }

    #[test]
    fn default_spec_causal_adjustment_schema_version() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        assert_eq!(
            spec.causal_adjustment_schema_version,
            SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION
        );
    }

    #[test]
    fn default_spec_has_at_least_fifteen_state_variables() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        assert!(spec.state_variables.len() >= 15);
    }

    #[test]
    fn default_spec_variable_ids_unique() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let ids: BTreeSet<&str> = spec.state_variables.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids.len(), spec.state_variables.len());
    }

    #[test]
    fn default_spec_all_telemetry_refs_valid() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        for variable in &spec.state_variables {
            variable
                .telemetry
                .validate()
                // SAFETY: Test-only panic to validate variable telemetry in twin state transition
                // expects valid telemetry from test data construction
                .unwrap_or_else(|e| panic!("variable {} telemetry invalid: {}", variable.id, e));
        }
    }

    // ── SemanticTwinRuntime ──────────────────────────────────────

    #[test]
    fn runtime_specification_accessor() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let var_count = spec.state_variables.len();
        let runtime = SemanticTwinRuntime::new(
            spec,
            "trace-rt",
            "decision-rt",
            "policy-rt",
            1,
            DemotionPolicy::default(),
        )
        .expect("runtime");
        assert_eq!(runtime.specification().state_variables.len(), var_count);
    }

    #[test]
    fn runtime_ledger_accessor_matches_assumption_count() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let assumption_count = spec.assumptions.len();
        let runtime = SemanticTwinRuntime::new(
            spec,
            "trace-rt",
            "decision-rt",
            "policy-rt",
            1,
            DemotionPolicy::default(),
        )
        .expect("runtime");
        assert_eq!(runtime.ledger().assumption_count(), assumption_count);
    }

    #[test]
    fn runtime_multiple_ok_observations_accumulate_tick() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let mut runtime = SemanticTwinRuntime::new(
            spec,
            "trace-tick",
            "decision-tick",
            "policy-tick",
            1,
            DemotionPolicy::default(),
        )
        .expect("runtime");

        for _ in 0..5 {
            let result = runtime.observe("regime_observed_millionths", 1_000_000, 1);
            assert!(result.actions.is_empty());
            assert_eq!(result.events.len(), 1);
            assert_eq!(result.events[0].outcome, "ok");
        }
    }

    // ── SemanticTwinError Display ────────────────────────────────

    #[test]
    fn error_display_scm() {
        let err = SemanticTwinError::Scm(ScmError::NodeNotFound("x".to_string()));
        let msg = format!("{err}");
        assert!(msg.contains("scm error"));
    }

    #[test]
    fn error_display_duplicate_variable() {
        let err = SemanticTwinError::DuplicateVariable("foo".to_string());
        let msg = format!("{err}");
        assert!(msg.contains("duplicate"));
        assert!(msg.contains("foo"));
    }

    #[test]
    fn error_display_transition_missing_variable() {
        let err = SemanticTwinError::TransitionMissingVariable {
            transition_id: "t1".to_string(),
            variable: "v1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("t1"));
        assert!(msg.contains("v1"));
    }

    #[test]
    fn error_display_adjustment_not_identified() {
        let err = SemanticTwinError::AdjustmentNotIdentified {
            effect_id: "e1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("e1"));
        assert!(msg.contains("not identified"));
    }

    #[test]
    fn error_display_adjustment_mismatch() {
        let err = SemanticTwinError::AdjustmentMismatch {
            effect_id: "e1".to_string(),
            expected: BTreeSet::from(["a".to_string()]),
            actual: BTreeSet::from(["b".to_string()]),
        };
        let msg = format!("{err}");
        assert!(msg.contains("mismatch"));
    }

    #[test]
    fn error_display_assumption_missing_variable() {
        let err = SemanticTwinError::AssumptionMissingVariable {
            assumption_id: "a1".to_string(),
            variable: "v1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("a1"));
        assert!(msg.contains("v1"));
    }

    #[test]
    fn error_display_assumption_missing_effect() {
        let err = SemanticTwinError::AssumptionMissingEffect {
            assumption_id: "a1".to_string(),
            effect_id: "e1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("a1"));
        assert!(msg.contains("e1"));
    }

    #[test]
    fn error_display_invalid_trigger_count() {
        let err = SemanticTwinError::InvalidAssumptionTriggerCount {
            assumption_id: "a1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("a1"));
        assert!(msg.contains("trigger_count"));
    }

    #[test]
    fn error_display_missing_telemetry_signal_key() {
        let err = SemanticTwinError::MissingTelemetrySignalKey {
            namespace: "frir".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("frir"));
    }

    #[test]
    fn error_display_missing_telemetry_units() {
        let err = SemanticTwinError::MissingTelemetryUnits {
            signal_key: "sig1".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("sig1"));
    }

    // ── Serde roundtrips for core types ──────────────────────────

    #[test]
    fn twin_state_variable_serde_roundtrip() {
        let variable = TwinStateVariable {
            id: "test_var".to_string(),
            label: "Test".to_string(),
            description: "A test variable".to_string(),
            domain: VariableDomain::WorkloadCharacteristic,
            observable: true,
            telemetry: TelemetryContractRef {
                namespace: SignalNamespace::Frir,
                signal_key: "test.key".to_string(),
                units: "millionths".to_string(),
                deterministic: true,
                required: true,
            },
        };
        let json = serde_json::to_string(&variable).unwrap();
        let back: TwinStateVariable = serde_json::from_str(&json).unwrap();
        assert_eq!(back, variable);
    }

    #[test]
    fn causal_adjustment_strategy_serde_roundtrip() {
        let strategy = CausalAdjustmentStrategy {
            effect_id: "effect_1".to_string(),
            treatment: "lane_choice".to_string(),
            outcome: "latency".to_string(),
            identified: true,
            adjustment_set: BTreeSet::from(["regime".to_string()]),
            blocked_confounding_paths: vec![vec!["a".to_string(), "b".to_string()]],
            strategy_note: "test note".to_string(),
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let back: CausalAdjustmentStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, strategy);
    }

    #[test]
    fn semantic_twin_log_event_serde_roundtrip() {
        let event = SemanticTwinLogEvent {
            schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: SEMANTIC_TWIN_COMPONENT.to_string(),
            event: "assumption_monitor_evaluate".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            variable: "risk_belief".to_string(),
            observed_value_millionths: 500_000,
            assumption_id: None,
            monitor_id: None,
            action: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: SemanticTwinLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, event);
    }

    #[test]
    fn semantic_twin_specification_serde_roundtrip() {
        let spec = SemanticTwinSpecification::frx_19_1_default().expect("spec");
        let json = serde_json::to_string(&spec).unwrap();
        let back: SemanticTwinSpecification = serde_json::from_str(&json).unwrap();
        assert_eq!(back, spec);
    }

    // ── Constants verification ───────────────────────────────────

    #[test]
    fn schema_version_constants_contain_semantic_twin() {
        assert!(SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION.contains("semantic-twin"));
        assert!(SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION.contains("semantic-twin"));
        assert!(SEMANTIC_TWIN_LOG_SCHEMA_VERSION.contains("semantic-twin"));
    }

    #[test]
    fn component_constant_matches_module_name() {
        assert_eq!(SEMANTIC_TWIN_COMPONENT, "semantic_twin_state_space");
    }

    // ── From impls ───────────────────────────────────────────────

    #[test]
    fn from_scm_error() {
        let scm_err = ScmError::NodeNotFound("test".to_string());
        let twin_err: SemanticTwinError = scm_err.into();
        assert!(matches!(twin_err, SemanticTwinError::Scm(..)));
    }

    #[test]
    fn from_ledger_error() {
        let ledger_err = LedgerError::DuplicateAssumption("dup".to_string());
        let twin_err: SemanticTwinError = ledger_err.into();
        assert!(matches!(twin_err, SemanticTwinError::Ledger(..)));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn transition_guard_serde_roundtrip() {
        let guard = TransitionGuard {
            variable: "risk_belief".to_string(),
            op: MonitorOp::Ge,
            threshold_millionths: 500_000,
        };
        let json = serde_json::to_string(&guard).unwrap();
        let back: TransitionGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(back, guard);
    }

    #[test]
    fn twin_state_transition_serde_roundtrip() {
        let transition = TwinStateTransition {
            transition_id: "t1".to_string(),
            source_variable: "regime".to_string(),
            target_variable: "risk_belief".to_string(),
            trigger_event: "regime_change".to_string(),
            telemetry_contract: "runtime_decision_core.regime".to_string(),
            guard: Some(TransitionGuard {
                variable: "regime".to_string(),
                op: MonitorOp::Ge,
                threshold_millionths: 0,
            }),
        };
        let json = serde_json::to_string(&transition).unwrap();
        let back: TwinStateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(back, transition);
    }

    #[test]
    fn twin_state_transition_no_guard_serde_roundtrip() {
        let transition = TwinStateTransition {
            transition_id: "t2".to_string(),
            source_variable: "a".to_string(),
            target_variable: "b".to_string(),
            trigger_event: "evt".to_string(),
            telemetry_contract: "ns.signal".to_string(),
            guard: None,
        };
        let json = serde_json::to_string(&transition).unwrap();
        let back: TwinStateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(back, transition);
        assert!(back.guard.is_none());
    }

    #[test]
    fn semantic_twin_error_serde_roundtrip_all_variants() {
        let variants: Vec<SemanticTwinError> = vec![
            SemanticTwinError::DuplicateVariable("v1".to_string()),
            SemanticTwinError::MissingTelemetrySignalKey {
                namespace: "frir".to_string(),
            },
            SemanticTwinError::MissingTelemetryUnits {
                signal_key: "key".to_string(),
            },
            SemanticTwinError::TransitionMissingVariable {
                transition_id: "t1".to_string(),
                variable: "x".to_string(),
            },
            SemanticTwinError::AdjustmentNotIdentified {
                effect_id: "e1".to_string(),
            },
            SemanticTwinError::AdjustmentMismatch {
                effect_id: "e2".to_string(),
                expected: BTreeSet::from(["a".to_string()]),
                actual: BTreeSet::from(["b".to_string()]),
            },
            SemanticTwinError::AssumptionMissingVariable {
                assumption_id: "a1".to_string(),
                variable: "v2".to_string(),
            },
            SemanticTwinError::AssumptionMissingEffect {
                assumption_id: "a2".to_string(),
                effect_id: "e3".to_string(),
            },
            SemanticTwinError::InvalidAssumptionTriggerCount {
                assumption_id: "a3".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SemanticTwinError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 9);
    }

    #[test]
    fn semantic_twin_error_is_std_error() {
        let err = SemanticTwinError::DuplicateVariable("x".to_string());
        let dyn_err: &dyn std::error::Error = &err;
        assert!(!dyn_err.to_string().is_empty());
    }

    #[test]
    fn signal_namespace_ordering_is_deterministic() {
        let mut namespaces = vec![
            SignalNamespace::RuntimeObservability,
            SignalNamespace::Frir,
            SignalNamespace::PolicyController,
            SignalNamespace::AssumptionsLedger,
            SignalNamespace::RuntimeDecisionCore,
        ];
        let original = namespaces.clone();
        namespaces.sort();
        namespaces.sort();
        let second = namespaces.clone();
        assert_eq!(namespaces, second);
        // Verify all 5 variants are present
        assert_eq!(original.len(), 5);
    }

    // ── Enrichment: SignalNamespace ───────────────────────────────────

    #[test]
    fn signal_namespace_as_str_all_unique() {
        let variants = [
            SignalNamespace::Frir,
            SignalNamespace::RuntimeDecisionCore,
            SignalNamespace::RuntimeObservability,
            SignalNamespace::PolicyController,
            SignalNamespace::AssumptionsLedger,
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(v.as_str());
        }
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn signal_namespace_serde_roundtrip_all_variants() {
        for v in [
            SignalNamespace::Frir,
            SignalNamespace::RuntimeDecisionCore,
            SignalNamespace::RuntimeObservability,
            SignalNamespace::PolicyController,
            SignalNamespace::AssumptionsLedger,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let back: SignalNamespace = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn signal_namespace_in_btree_set() {
        let mut set = BTreeSet::new();
        set.insert(SignalNamespace::Frir);
        set.insert(SignalNamespace::Frir); // duplicate
        set.insert(SignalNamespace::PolicyController);
        assert_eq!(set.len(), 2);
    }

    // ── Enrichment: TelemetryContractRef ─────────────────────────────

    #[test]
    fn telemetry_contract_ref_serde_roundtrip() {
        let tcr = TelemetryContractRef {
            namespace: SignalNamespace::RuntimeObservability,
            signal_key: "latency.p99_millionths".to_string(),
            units: "microseconds".to_string(),
            deterministic: true,
            required: true,
        };
        let json = serde_json::to_string(&tcr).unwrap();
        let back: TelemetryContractRef = serde_json::from_str(&json).unwrap();
        assert_eq!(tcr, back);
    }

    #[test]
    fn telemetry_contract_ref_validate_whitespace_only_units() {
        let tcr = TelemetryContractRef {
            namespace: SignalNamespace::Frir,
            signal_key: "valid_key".to_string(),
            units: "   ".to_string(),
            deterministic: false,
            required: false,
        };
        assert!(tcr.validate().is_err());
    }

    #[test]
    fn telemetry_contract_ref_validate_whitespace_only_signal_key() {
        let tcr = TelemetryContractRef {
            namespace: SignalNamespace::Frir,
            signal_key: "  ".to_string(),
            units: "ms".to_string(),
            deterministic: false,
            required: false,
        };
        assert!(tcr.validate().is_err());
    }

    // ── Enrichment: TwinStateVariable ────────────────────────────────

    #[test]
    fn twin_state_variable_serde_roundtrip_alt() {
        let var = TwinStateVariable {
            id: "v1".to_string(),
            label: "Latency".to_string(),
            description: "P99 latency metric".to_string(),
            domain: VariableDomain::ObservedOutcome,
            observable: true,
            telemetry: TelemetryContractRef {
                namespace: SignalNamespace::RuntimeObservability,
                signal_key: "latency".to_string(),
                units: "us".to_string(),
                deterministic: true,
                required: true,
            },
        };
        let json = serde_json::to_string(&var).unwrap();
        let back: TwinStateVariable = serde_json::from_str(&json).unwrap();
        assert_eq!(var, back);
    }

    #[test]
    fn twin_state_variable_label_distinct_from_description() {
        let var = TwinStateVariable {
            id: "v2".to_string(),
            label: "Label".to_string(),
            description: "Description".to_string(),
            domain: VariableDomain::WorkloadCharacteristic,
            observable: false,
            telemetry: TelemetryContractRef {
                namespace: SignalNamespace::Frir,
                signal_key: "key".to_string(),
                units: "unit".to_string(),
                deterministic: false,
                required: false,
            },
        };
        assert_ne!(var.label, var.description);
    }

    // ── Enrichment: TransitionGuard ──────────────────────────────────

    #[test]
    fn transition_guard_serde_roundtrip_alt() {
        let guard = TransitionGuard {
            variable: "env_load".to_string(),
            op: MonitorOp::Le,
            threshold_millionths: 500_000,
        };
        let json = serde_json::to_string(&guard).unwrap();
        let back: TransitionGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(guard, back);
    }

    // ── Enrichment: CausalAdjustmentStrategy ─────────────────────────

    #[test]
    fn causal_adjustment_strategy_serde_roundtrip_alt() {
        let strategy = CausalAdjustmentStrategy {
            effect_id: "eff1".to_string(),
            treatment: "lane_choice".to_string(),
            outcome: "latency_outcome".to_string(),
            identified: true,
            adjustment_set: BTreeSet::from(["regime".to_string(), "workload".to_string()]),
            blocked_confounding_paths: vec![vec!["a".into(), "b".into()]],
            strategy_note: "backdoor adjustment".to_string(),
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let back: CausalAdjustmentStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(strategy, back);
    }

    #[test]
    fn causal_adjustment_strategy_empty_adjustment_set() {
        let strategy = CausalAdjustmentStrategy {
            effect_id: "eff2".to_string(),
            treatment: "t".to_string(),
            outcome: "o".to_string(),
            identified: false,
            adjustment_set: BTreeSet::new(),
            blocked_confounding_paths: vec![],
            strategy_note: "no confounders".to_string(),
        };
        let json = serde_json::to_string(&strategy).unwrap();
        let back: CausalAdjustmentStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(strategy, back);
        assert!(back.adjustment_set.is_empty());
    }

    // ── Enrichment: IdentifiabilityAssumption ────────────────────────

    #[test]
    fn identifiability_assumption_serde_roundtrip() {
        let asm = IdentifiabilityAssumption {
            assumption_id: "asm-test".to_string(),
            description: "test assumption".to_string(),
            category: AssumptionCategory::Structural,
            origin: AssumptionOrigin::Runtime,
            decision_effect_id: "eff1".to_string(),
            telemetry_contract: "rt.signal".to_string(),
            monitor_kind: MonitorKind::Invariant,
            monitor_variable: "var1".to_string(),
            monitor_op: MonitorOp::Ge,
            monitor_threshold_millionths: 1_000_000,
            trigger_count: 1,
            violation_severity: ViolationSeverity::Critical,
        };
        let json = serde_json::to_string(&asm).unwrap();
        let back: IdentifiabilityAssumption = serde_json::from_str(&json).unwrap();
        assert_eq!(asm, back);
    }

    // ── Enrichment: SemanticTwinLogEvent ──────────────────────────────

    #[test]
    fn semantic_twin_log_event_all_none_fields_serde() {
        let ev = SemanticTwinLogEvent {
            schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            component: SEMANTIC_TWIN_COMPONENT.to_string(),
            event: "observation_ok".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            variable: "v1".to_string(),
            observed_value_millionths: 500_000,
            assumption_id: None,
            monitor_id: None,
            action: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: SemanticTwinLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn semantic_twin_log_event_all_some_fields_serde() {
        let ev = SemanticTwinLogEvent {
            schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
            trace_id: "t2".to_string(),
            decision_id: "d2".to_string(),
            policy_id: "p2".to_string(),
            component: SEMANTIC_TWIN_COMPONENT.to_string(),
            event: "assumption_violated".to_string(),
            outcome: "falsified".to_string(),
            error_code: Some("FE-ST-001".to_string()),
            variable: "drift_var".to_string(),
            observed_value_millionths: 200_000,
            assumption_id: Some("asm-1".to_string()),
            monitor_id: Some("mon-1".to_string()),
            action: Some("demote".to_string()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: SemanticTwinLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // ── Enrichment: SemanticTwinObservationResult ─────────────────────

    #[test]
    fn semantic_twin_observation_result_serde_roundtrip() {
        let result = SemanticTwinObservationResult {
            actions: vec![],
            events: vec![SemanticTwinLogEvent {
                schema_version: SEMANTIC_TWIN_LOG_SCHEMA_VERSION.to_string(),
                trace_id: "t".into(),
                decision_id: "d".into(),
                policy_id: "p".into(),
                component: SEMANTIC_TWIN_COMPONENT.into(),
                event: "observation_ok".into(),
                outcome: "ok".into(),
                error_code: None,
                variable: "v".into(),
                observed_value_millionths: 0,
                assumption_id: None,
                monitor_id: None,
                action: None,
            }],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: SemanticTwinObservationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // ── Enrichment: SemanticTwinError display ────────────────────────

    #[test]
    fn semantic_twin_error_display_all_unique() {
        let variants = vec![
            SemanticTwinError::DuplicateVariable("x".to_string()),
            SemanticTwinError::MissingTelemetrySignalKey {
                namespace: "ns".to_string(),
            },
            SemanticTwinError::MissingTelemetryUnits {
                signal_key: "k".to_string(),
            },
            SemanticTwinError::TransitionMissingVariable {
                transition_id: "t1".to_string(),
                variable: "v1".to_string(),
            },
            SemanticTwinError::AdjustmentNotIdentified {
                effect_id: "e1".to_string(),
            },
            SemanticTwinError::AssumptionMissingVariable {
                assumption_id: "a1".to_string(),
                variable: "v2".to_string(),
            },
            SemanticTwinError::AssumptionMissingEffect {
                assumption_id: "a2".to_string(),
                effect_id: "e2".to_string(),
            },
            SemanticTwinError::InvalidAssumptionTriggerCount {
                assumption_id: "a3".to_string(),
            },
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    // ── Enrichment: schema version constants ─────────────────────────

    #[test]
    fn schema_version_constants_consistent_prefix() {
        assert!(
            SEMANTIC_TWIN_STATE_SPACE_SCHEMA_VERSION.starts_with("franken-engine.semantic-twin.")
        );
        assert!(
            SEMANTIC_TWIN_CAUSAL_ADJUSTMENT_SCHEMA_VERSION
                .starts_with("franken-engine.semantic-twin.")
        );
        assert!(SEMANTIC_TWIN_LOG_SCHEMA_VERSION.starts_with("franken-engine.semantic-twin."));
    }

    // ── Enrichment: TwinStateTransition ──────────────────────────────

    #[test]
    fn twin_state_transition_serde_with_guard() {
        let t = TwinStateTransition {
            transition_id: "tr-1".to_string(),
            source_variable: "lane_choice".to_string(),
            target_variable: "latency_outcome".to_string(),
            trigger_event: "routing_decision".to_string(),
            telemetry_contract: "rt.signal".to_string(),
            guard: Some(TransitionGuard {
                variable: "env_load".to_string(),
                op: MonitorOp::Le,
                threshold_millionths: 800_000,
            }),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: TwinStateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn twin_state_transition_serde_without_guard() {
        let t = TwinStateTransition {
            transition_id: "tr-2".to_string(),
            source_variable: "a".to_string(),
            target_variable: "b".to_string(),
            trigger_event: "ev".to_string(),
            telemetry_contract: "c".to_string(),
            guard: None,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: TwinStateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
        assert!(back.guard.is_none());
    }
}
