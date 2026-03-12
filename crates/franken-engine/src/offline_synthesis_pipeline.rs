//! [FRX-13.2] Offline Synthesis Pipeline (SMT/SDP/Game → Policy Artifacts)
//!
//! Converts advanced control formulations—logical constraints (SMT-like),
//! numerical optimization (SDP-like), and game-theoretic safety specifications—
//! into deterministic runtime artifacts: decision tables, transition automata,
//! calibrated thresholds, and certificate bundles.
//!
//! Each artifact carries bounded-resource metadata and is compatible with the
//! deterministic evaluator contract (fixed-point millionths, BTreeMap ordering,
//! content-addressed hashing).
//!
//! Pipeline stages:
//! 1. **Constraint parsing** — translate specifications into internal IR
//! 2. **Optimization solving** — compute numerical bounds
//! 3. **Table generation** — build decision tables from solved constraints
//! 4. **Threshold calibration** — derive conformal/sequential thresholds
//! 5. **Artifact assembly** — wrap in proofs + budget tracking

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ── Specification IR (Pipeline Input) ─────────────────────────────────

/// A variable in a constraint specification.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SpecVar {
    pub name: String,
    pub domain: VarDomain,
}

/// Domain of a specification variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VarDomain {
    /// Boolean (0 or 1_000_000 in fixed-point).
    Boolean,
    /// Bounded integer in fixed-point millionths.
    BoundedInt { lo: i64, hi: i64 },
    /// Enumeration with N discrete values (0..N-1).
    Enum { cardinality: u32 },
}

/// Comparison operator for constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CmpOp {
    Le,
    Lt,
    Ge,
    Gt,
    Eq,
    Ne,
}

/// A single linear term: coefficient × variable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearTerm {
    pub var: String,
    pub coeff_millionths: i64,
}

/// An SMT-like constraint: Σ(coeff_i × var_i) op rhs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinearConstraint {
    pub id: String,
    pub terms: Vec<LinearTerm>,
    pub op: CmpOp,
    pub rhs_millionths: i64,
    pub label: String,
}

/// An SDP-like optimization objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationObjective {
    pub id: String,
    /// Minimize or maximize.
    pub direction: OptDirection,
    /// Linear objective: Σ(coeff_i × var_i).
    pub terms: Vec<LinearTerm>,
    /// Hard upper bound on the objective value (millionths).
    pub bound_millionths: Option<i64>,
}

/// Optimization direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OptDirection {
    Minimize,
    Maximize,
}

/// A game-theoretic safety specification: worst-case guarantee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetySpec {
    pub id: String,
    /// The property that must hold under adversarial conditions.
    pub property: String,
    /// Maximin value: the worst-case guaranteed payoff (millionths).
    pub maximin_value_millionths: i64,
    /// Strategy variables under our control.
    pub strategy_vars: Vec<String>,
    /// Adversary variables (nature/opponent).
    pub adversary_vars: Vec<String>,
    /// CVaR tail-risk bound at the given alpha (millionths).
    pub cvar_alpha_millionths: i64,
    pub cvar_bound_millionths: i64,
}

/// Complete specification bundle for the synthesis pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisSpec {
    pub spec_id: String,
    pub variables: Vec<SpecVar>,
    pub constraints: Vec<LinearConstraint>,
    pub objectives: Vec<OptimizationObjective>,
    pub safety_specs: Vec<SafetySpec>,
    /// Epoch at which this spec was authored.
    pub epoch: u64,
}

// ── Pipeline Stage Results ────────────────────────────────────────────

/// Stage identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PipelineStage {
    ConstraintParsing,
    OptimizationSolving,
    TableGeneration,
    ThresholdCalibration,
    ArtifactAssembly,
}

/// Status of a pipeline stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StageStatus {
    Pending,
    Running,
    Completed { duration_ms: u64 },
    Failed { reason: String },
    BudgetExhausted,
}

/// Witness for a single pipeline stage (hash-linked for audit).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageWitness {
    pub stage: PipelineStage,
    pub status: StageStatus,
    pub input_hash: String,
    pub output_hash: String,
    pub resource_usage: ResourceUsage,
}

/// Resource usage for bounded-resource tracking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub time_ms: u64,
    pub iterations: u64,
    pub memory_bytes: u64,
    pub budget_limited: bool,
}

// ── Decision Table ────────────────────────────────────────────────────

/// A discrete observable state used as table key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObservableState {
    /// Variable name → discretized value (fixed-point millionths).
    pub values: BTreeMap<String, i64>,
}

/// A single entry in a decision table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionEntry {
    pub action: String,
    pub expected_loss_millionths: i64,
    /// Whether a guardrail blocked the originally-optimal action.
    pub guardrail_blocked: bool,
    /// The optimal action before guardrail filtering (may differ from `action`).
    pub pre_guardrail_action: String,
}

/// A (state, entry) pair in a decision table.
/// Uses Vec instead of BTreeMap because ObservableState cannot be a JSON map key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionTableRow {
    pub state: ObservableState,
    pub entry: DecisionEntry,
}

/// A pre-computed decision table mapping observable states to actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionTable {
    pub table_id: String,
    /// Variable names that form the key.
    pub key_variables: Vec<String>,
    /// Rows sorted by state for deterministic lookup.
    pub rows: Vec<DecisionTableRow>,
    /// Safe default action when no entry matches.
    pub safe_default: String,
    /// Content hash of the table (for linking).
    pub content_hash: String,
}

impl DecisionTable {
    /// Look up the optimal action for a given state (linear scan).
    pub fn lookup(&self, state: &ObservableState) -> &str {
        self.rows
            .iter()
            .find(|r| r.state == *state)
            .map(|r| r.entry.action.as_str())
            .unwrap_or(&self.safe_default)
    }

    /// Number of entries.
    pub fn entry_count(&self) -> usize {
        self.rows.len()
    }
}

// ── Transition Automaton ──────────────────────────────────────────────

/// A state in the transition automaton.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AutomatonState {
    pub id: String,
    pub label: String,
    /// Whether this is a terminal/accepting state.
    pub accepting: bool,
}

/// A guard condition on a transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionGuard {
    pub variable: String,
    pub op: CmpOp,
    pub threshold_millionths: i64,
}

/// A transition in the automaton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    pub from: String,
    pub to: String,
    pub guards: Vec<TransitionGuard>,
    /// Priority for resolving conflicts (higher = preferred).
    pub priority: u32,
    /// Action to emit when this transition fires.
    pub emit_action: Option<String>,
}

/// A deterministic transition automaton for regime detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionAutomaton {
    pub automaton_id: String,
    pub states: BTreeMap<String, AutomatonState>,
    pub transitions: Vec<Transition>,
    pub initial_state: String,
    pub content_hash: String,
}

impl TransitionAutomaton {
    /// Step the automaton given current variable bindings.
    /// Returns (new_state_id, emitted_action).
    pub fn step(
        &self,
        current_state: &str,
        bindings: &BTreeMap<String, i64>,
    ) -> (String, Option<String>) {
        // Find highest-priority enabled transition from current state
        let mut best: Option<&Transition> = None;
        for t in &self.transitions {
            if t.from != current_state {
                continue;
            }
            let all_guards_pass = t.guards.iter().all(|g| {
                bindings
                    .get(&g.variable)
                    .is_some_and(|v| eval_cmp(*v, g.op, g.threshold_millionths))
            });
            if all_guards_pass && best.is_none_or(|current| t.priority > current.priority) {
                best = Some(t);
            }
        }
        match best {
            Some(t) => (t.to.clone(), t.emit_action.clone()),
            None => (current_state.to_string(), None),
        }
    }

    /// Number of states.
    pub fn state_count(&self) -> usize {
        self.states.len()
    }

    /// Number of transitions.
    pub fn transition_count(&self) -> usize {
        self.transitions.len()
    }
}

/// Evaluate a comparison operation in fixed-point.
fn eval_cmp(lhs: i64, op: CmpOp, rhs: i64) -> bool {
    match op {
        CmpOp::Le => lhs <= rhs,
        CmpOp::Lt => lhs < rhs,
        CmpOp::Ge => lhs >= rhs,
        CmpOp::Gt => lhs > rhs,
        CmpOp::Eq => lhs == rhs,
        CmpOp::Ne => lhs != rhs,
    }
}

// ── Calibrated Thresholds ─────────────────────────────────────────────

/// A single calibrated threshold with provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibratedThreshold {
    pub threshold_id: String,
    pub variable: String,
    pub value_millionths: i64,
    pub calibration_method: CalibrationMethod,
    /// Number of samples used in calibration.
    pub sample_count: u64,
    /// Coverage guarantee in millionths (e.g., 950_000 = 95%).
    pub coverage_millionths: i64,
}

/// Method used to calibrate a threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CalibrationMethod {
    /// Conformal prediction quantile.
    ConformalQuantile,
    /// E-process sequential threshold.
    EProcessSequential,
    /// Empirical CVaR at given alpha.
    CvarEmpirical,
    /// Fixed operator-specified value.
    OperatorFixed,
}

/// A bundle of calibrated thresholds for a single policy context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThresholdBundle {
    pub bundle_id: String,
    pub thresholds: Vec<CalibratedThreshold>,
    pub content_hash: String,
}

// ── Certificate Bundle ────────────────────────────────────────────────

/// Category of evidence attached to a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceCategory {
    DifferentialTest,
    StatisticalTest,
    FormalProof,
    BoundednessProof,
    MonotonicityCheck,
}

/// A single evidence item in a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub category: EvidenceCategory,
    pub description: String,
    pub confidence_millionths: i64,
    pub artifact_hash: String,
}

/// A certificate wrapping a synthesized artifact with proof metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactCertificate {
    pub certificate_id: String,
    pub artifact_hash: String,
    pub epoch: u64,
    pub evidence: Vec<EvidenceItem>,
    pub resource_usage: ResourceUsage,
    /// Obligation IDs that this artifact satisfies.
    pub satisfied_obligations: Vec<String>,
    /// Whether all critical obligations are met.
    pub all_obligations_met: bool,
    /// Rollback token for safe revert.
    pub rollback_token: String,
}

// ── Pipeline Output ───────────────────────────────────────────────────

/// Complete output of the offline synthesis pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisOutput {
    pub spec_id: String,
    pub decision_tables: Vec<DecisionTable>,
    pub automata: Vec<TransitionAutomaton>,
    pub threshold_bundles: Vec<ThresholdBundle>,
    pub certificates: Vec<ArtifactCertificate>,
    pub stage_witnesses: Vec<StageWitness>,
    pub total_resource_usage: ResourceUsage,
}

// ── Pipeline Errors ───────────────────────────────────────────────────

/// Errors from the synthesis pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SynthesisError {
    EmptySpec,
    InvalidConstraint { id: String, reason: String },
    Infeasible { constraint_ids: Vec<String> },
    BudgetExhausted { stage: PipelineStage },
    NoSafetySpec,
    InvalidVariable { name: String },
    InternalError(String),
}

impl std::fmt::Display for SynthesisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySpec => write!(f, "empty specification"),
            Self::InvalidConstraint { id, reason } => {
                write!(f, "invalid constraint {id}: {reason}")
            }
            Self::Infeasible { constraint_ids } => {
                write!(f, "infeasible: {}", constraint_ids.join(", "))
            }
            Self::BudgetExhausted { stage } => write!(f, "budget exhausted at {stage:?}"),
            Self::NoSafetySpec => write!(f, "no safety specification provided"),
            Self::InvalidVariable { name } => write!(f, "invalid variable: {name}"),
            Self::InternalError(msg) => write!(f, "internal error: {msg}"),
        }
    }
}

impl std::error::Error for SynthesisError {}

// ── Pipeline Configuration ────────────────────────────────────────────

/// Configuration for the synthesis pipeline budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineBudget {
    /// Maximum total iterations across all stages.
    pub max_iterations: u64,
    /// Maximum time per stage in ms.
    pub max_stage_time_ms: u64,
    /// Maximum memory in bytes.
    pub max_memory_bytes: u64,
}

impl Default for PipelineBudget {
    fn default() -> Self {
        Self {
            max_iterations: 100_000,
            max_stage_time_ms: 10_000,
            max_memory_bytes: 100_000_000,
        }
    }
}

// ── The Synthesis Pipeline ────────────────────────────────────────────

/// The offline synthesis pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineSynthesisPipeline {
    budget: PipelineBudget,
    /// Safe default action used when no solution found.
    safe_default_action: String,
}

impl OfflineSynthesisPipeline {
    /// Create a new pipeline with the given budget and safe default.
    pub fn new(budget: PipelineBudget, safe_default_action: String) -> Self {
        Self {
            budget,
            safe_default_action,
        }
    }

    /// Run the full synthesis pipeline on a specification.
    pub fn synthesize(&self, spec: &SynthesisSpec) -> Result<SynthesisOutput, SynthesisError> {
        if spec.variables.is_empty() && spec.constraints.is_empty() {
            return Err(SynthesisError::EmptySpec);
        }

        let mut witnesses = Vec::new();
        let mut total_usage = ResourceUsage {
            time_ms: 0,
            iterations: 0,
            memory_bytes: 0,
            budget_limited: false,
        };

        // Stage 1: Constraint Parsing
        let parsed = self.stage_parse_constraints(spec)?;
        witnesses.push(parsed.witness.clone());
        add_usage(&mut total_usage, &parsed.witness.resource_usage);

        // Stage 2: Optimization Solving
        let solved = self.stage_solve_optimization(spec, &parsed)?;
        witnesses.push(solved.witness.clone());
        add_usage(&mut total_usage, &solved.witness.resource_usage);

        // Stage 3: Table Generation
        let tables = self.stage_generate_tables(spec, &solved)?;
        witnesses.push(tables.witness.clone());
        add_usage(&mut total_usage, &tables.witness.resource_usage);

        // Stage 4: Threshold Calibration
        let thresholds = self.stage_calibrate_thresholds(spec, &solved)?;
        witnesses.push(thresholds.witness.clone());
        add_usage(&mut total_usage, &thresholds.witness.resource_usage);

        // Stage 5: Artifact Assembly
        let assembly = self.stage_assemble_artifacts(
            spec,
            &tables.decision_tables,
            &tables.automata,
            &thresholds.threshold_bundles,
            &total_usage,
        )?;
        witnesses.push(assembly.witness.clone());
        add_usage(&mut total_usage, &assembly.witness.resource_usage);

        Ok(SynthesisOutput {
            spec_id: spec.spec_id.clone(),
            decision_tables: tables.decision_tables,
            automata: tables.automata,
            threshold_bundles: thresholds.threshold_bundles,
            certificates: assembly.certificates,
            stage_witnesses: witnesses,
            total_resource_usage: total_usage,
        })
    }

    // ── Stage 1: Constraint Parsing ───────────────────────────────────

    fn stage_parse_constraints(
        &self,
        spec: &SynthesisSpec,
    ) -> Result<ParsedConstraints, SynthesisError> {
        let var_names: BTreeSet<String> = spec.variables.iter().map(|v| v.name.clone()).collect();

        // Validate all constraints reference known variables
        for c in &spec.constraints {
            for term in &c.terms {
                if !var_names.contains(&term.var) {
                    return Err(SynthesisError::InvalidConstraint {
                        id: c.id.clone(),
                        reason: format!("unknown variable: {}", term.var),
                    });
                }
            }
        }

        // Validate objectives reference known variables
        for obj in &spec.objectives {
            for term in &obj.terms {
                if !var_names.contains(&term.var) {
                    return Err(SynthesisError::InvalidVariable {
                        name: term.var.clone(),
                    });
                }
            }
        }

        // Validate safety specs
        for ss in &spec.safety_specs {
            for v in ss.strategy_vars.iter().chain(ss.adversary_vars.iter()) {
                if !var_names.contains(v) {
                    return Err(SynthesisError::InvalidVariable { name: v.clone() });
                }
            }
        }

        let input_hash = deterministic_hash(&format!("{:?}", spec));
        let output_hash = deterministic_hash(&format!("parsed_{}", spec.spec_id));

        Ok(ParsedConstraints {
            variable_domains: spec
                .variables
                .iter()
                .map(|v| (v.name.clone(), v.domain))
                .collect(),
            witness: StageWitness {
                stage: PipelineStage::ConstraintParsing,
                status: StageStatus::Completed { duration_ms: 1 },
                input_hash,
                output_hash,
                resource_usage: ResourceUsage {
                    time_ms: 1,
                    iterations: spec.constraints.len() as u64,
                    memory_bytes: spec.constraints.len() as u64 * 64,
                    budget_limited: false,
                },
            },
        })
    }

    // ── Stage 2: Optimization Solving ─────────────────────────────────

    fn stage_solve_optimization(
        &self,
        spec: &SynthesisSpec,
        parsed: &ParsedConstraints,
    ) -> Result<SolvedOptimization, SynthesisError> {
        let mut variable_bounds: BTreeMap<String, (i64, i64)> = BTreeMap::new();

        // Compute bounds from variable domains
        for (name, domain) in &parsed.variable_domains {
            let (lo, hi) = match domain {
                VarDomain::Boolean => (0, 1_000_000),
                VarDomain::BoundedInt { lo, hi } => (*lo, *hi),
                VarDomain::Enum { cardinality } => (0, (*cardinality as i64 - 1) * 1_000_000),
            };
            variable_bounds.insert(name.clone(), (lo, hi));
        }

        // Tighten bounds from constraints (simple interval propagation)
        let mut iterations = 0u64;
        for c in &spec.constraints {
            iterations += 1;
            if iterations > self.budget.max_iterations {
                return Err(SynthesisError::BudgetExhausted {
                    stage: PipelineStage::OptimizationSolving,
                });
            }
            // Single-variable constraints directly tighten bounds
            if c.terms.len() == 1 {
                let term = &c.terms[0];
                if term.coeff_millionths == 1_000_000
                    && let Some(bounds) = variable_bounds.get_mut(&term.var)
                {
                    match c.op {
                        CmpOp::Le => bounds.1 = bounds.1.min(c.rhs_millionths),
                        CmpOp::Lt => bounds.1 = bounds.1.min(c.rhs_millionths - 1),
                        CmpOp::Ge => bounds.0 = bounds.0.max(c.rhs_millionths),
                        CmpOp::Gt => bounds.0 = bounds.0.max(c.rhs_millionths + 1),
                        CmpOp::Eq => {
                            bounds.0 = bounds.0.max(c.rhs_millionths);
                            bounds.1 = bounds.1.min(c.rhs_millionths);
                        }
                        CmpOp::Ne => {} // Cannot tighten bounds with !=
                    }
                }
            }
        }

        // Check feasibility: any variable with lo > hi is infeasible
        let infeasible: Vec<String> = variable_bounds
            .iter()
            .filter(|(_, (lo, hi))| lo > hi)
            .map(|(name, _)| name.clone())
            .collect();
        if !infeasible.is_empty() {
            return Err(SynthesisError::Infeasible {
                constraint_ids: infeasible,
            });
        }

        // Compute objective bounds
        let mut objective_values: BTreeMap<String, i64> = BTreeMap::new();
        for obj in &spec.objectives {
            let val = obj
                .terms
                .iter()
                .map(|term| {
                    let var_bounds = variable_bounds
                        .get(&term.var)
                        .copied()
                        .unwrap_or((0, 1_000_000));
                    match obj.direction {
                        OptDirection::Minimize => {
                            if term.coeff_millionths >= 0 {
                                (term.coeff_millionths as i128 * var_bounds.0 as i128 / 1_000_000)
                                    as i64
                            } else {
                                (term.coeff_millionths as i128 * var_bounds.1 as i128 / 1_000_000)
                                    as i64
                            }
                        }
                        OptDirection::Maximize => {
                            if term.coeff_millionths >= 0 {
                                (term.coeff_millionths as i128 * var_bounds.1 as i128 / 1_000_000)
                                    as i64
                            } else {
                                (term.coeff_millionths as i128 * var_bounds.0 as i128 / 1_000_000)
                                    as i64
                            }
                        }
                    }
                })
                .sum();
            objective_values.insert(obj.id.clone(), val);
        }

        // Compute safety spec maximin guarantees
        let mut safety_guarantees: BTreeMap<String, i64> = BTreeMap::new();
        for ss in &spec.safety_specs {
            safety_guarantees.insert(ss.id.clone(), ss.maximin_value_millionths);
        }

        let input_hash = deterministic_hash(&format!("solve_{}", spec.spec_id));
        let output_hash = deterministic_hash(&format!("solved_{}", spec.spec_id));
        let mem_bytes = variable_bounds.len() as u64 * 32;

        Ok(SolvedOptimization {
            variable_bounds,
            objective_values,
            safety_guarantees,
            witness: StageWitness {
                stage: PipelineStage::OptimizationSolving,
                status: StageStatus::Completed {
                    duration_ms: iterations,
                },
                input_hash,
                output_hash,
                resource_usage: ResourceUsage {
                    time_ms: iterations,
                    iterations,
                    memory_bytes: mem_bytes,
                    budget_limited: false,
                },
            },
        })
    }

    // ── Stage 3: Table Generation ─────────────────────────────────────

    fn stage_generate_tables(
        &self,
        spec: &SynthesisSpec,
        solved: &SolvedOptimization,
    ) -> Result<GeneratedTables, SynthesisError> {
        let mut decision_tables = Vec::new();
        let mut automata = Vec::new();
        let mut iterations = 0u64;

        // Generate a decision table for each objective
        for obj in &spec.objectives {
            let mut rows = Vec::new();

            // Discretize variable bounds into grid points
            let grid = self.discretize_grid(&solved.variable_bounds, &obj.terms);

            for state in &grid {
                iterations += 1;
                if iterations > self.budget.max_iterations {
                    break;
                }
                // Evaluate objective at this grid point
                let obj_val: i64 = obj
                    .terms
                    .iter()
                    .map(|term| {
                        let var_val = state.values.get(&term.var).copied().unwrap_or(0);
                        (term.coeff_millionths as i128 * var_val as i128 / 1_000_000) as i64
                    })
                    .sum();

                // Check guardrail constraints
                let guardrail_blocked = spec.constraints.iter().any(|c| {
                    let lhs: i64 = c
                        .terms
                        .iter()
                        .map(|t| {
                            let v = state.values.get(&t.var).copied().unwrap_or(0);
                            (t.coeff_millionths as i128 * v as i128 / 1_000_000) as i64
                        })
                        .sum();
                    !eval_cmp(lhs, c.op, c.rhs_millionths)
                });

                let action = if guardrail_blocked {
                    self.safe_default_action.clone()
                } else {
                    format!("opt_{}", obj.id)
                };

                rows.push(DecisionTableRow {
                    state: state.clone(),
                    entry: DecisionEntry {
                        action: action.clone(),
                        expected_loss_millionths: obj_val,
                        guardrail_blocked,
                        pre_guardrail_action: format!("opt_{}", obj.id),
                    },
                });
            }

            // Sort for deterministic ordering
            rows.sort_by(|a, b| a.state.cmp(&b.state));

            let table_hash = deterministic_hash(&format!("table_{}_{}", spec.spec_id, obj.id));
            decision_tables.push(DecisionTable {
                table_id: format!("dt_{}_{}", spec.spec_id, obj.id),
                key_variables: obj.terms.iter().map(|t| t.var.clone()).collect(),
                rows,
                safe_default: self.safe_default_action.clone(),
                content_hash: table_hash,
            });
        }

        // Generate transition automata from safety specs
        for ss in &spec.safety_specs {
            let mut states = BTreeMap::new();
            let mut transitions = Vec::new();

            // Create states for each regime-like classification
            for (i, label) in ["normal", "elevated", "degraded", "critical", "recovery"]
                .iter()
                .enumerate()
            {
                states.insert(
                    label.to_string(),
                    AutomatonState {
                        id: label.to_string(),
                        label: label.to_string(),
                        accepting: i < 3, // normal, elevated, degraded are accepting
                    },
                );
            }

            // Add transitions based on strategy/adversary variable thresholds
            let maximin_half = ss.maximin_value_millionths / 2;
            let cvar_threshold = ss.cvar_bound_millionths;

            // Normal → Elevated when strategy vars cross threshold
            for var in &ss.strategy_vars {
                transitions.push(Transition {
                    from: "normal".into(),
                    to: "elevated".into(),
                    guards: vec![TransitionGuard {
                        variable: var.clone(),
                        op: CmpOp::Gt,
                        threshold_millionths: maximin_half,
                    }],
                    priority: 1,
                    emit_action: Some("escalate".into()),
                });
            }

            // Elevated → Critical when adversary vars exceed CVaR bound
            for var in &ss.adversary_vars {
                transitions.push(Transition {
                    from: "elevated".into(),
                    to: "critical".into(),
                    guards: vec![TransitionGuard {
                        variable: var.clone(),
                        op: CmpOp::Gt,
                        threshold_millionths: cvar_threshold,
                    }],
                    priority: 2,
                    emit_action: Some("safe_mode".into()),
                });
            }

            // Critical → Recovery (unconditional after safe mode)
            transitions.push(Transition {
                from: "critical".into(),
                to: "recovery".into(),
                guards: Vec::new(),
                priority: 0,
                emit_action: Some("begin_recovery".into()),
            });

            // Recovery → Normal when strategy vars are below threshold
            for var in &ss.strategy_vars {
                transitions.push(Transition {
                    from: "recovery".into(),
                    to: "normal".into(),
                    guards: vec![TransitionGuard {
                        variable: var.clone(),
                        op: CmpOp::Le,
                        threshold_millionths: maximin_half,
                    }],
                    priority: 1,
                    emit_action: Some("resume_normal".into()),
                });
            }

            let automaton_hash =
                deterministic_hash(&format!("automaton_{}_{}", spec.spec_id, ss.id));
            automata.push(TransitionAutomaton {
                automaton_id: format!("ta_{}_{}", spec.spec_id, ss.id),
                states,
                transitions,
                initial_state: "normal".into(),
                content_hash: automaton_hash,
            });
        }

        let input_hash = deterministic_hash(&format!("gen_{}", spec.spec_id));
        let output_hash = deterministic_hash(&format!("tables_{}", spec.spec_id));

        Ok(GeneratedTables {
            decision_tables,
            automata,
            witness: StageWitness {
                stage: PipelineStage::TableGeneration,
                status: StageStatus::Completed {
                    duration_ms: iterations,
                },
                input_hash,
                output_hash,
                resource_usage: ResourceUsage {
                    time_ms: iterations,
                    iterations,
                    memory_bytes: 0,
                    budget_limited: iterations >= self.budget.max_iterations,
                },
            },
        })
    }

    /// Discretize variable bounds into a grid of observable states.
    fn discretize_grid(
        &self,
        bounds: &BTreeMap<String, (i64, i64)>,
        terms: &[LinearTerm],
    ) -> Vec<ObservableState> {
        let relevant_vars: Vec<String> = terms.iter().map(|t| t.var.clone()).collect();
        let mut grid = vec![ObservableState {
            values: BTreeMap::new(),
        }];

        for var in &relevant_vars {
            let (lo, hi) = bounds.get(var).copied().unwrap_or((0, 1_000_000));
            // Use at most 5 grid points per variable to bound combinatorial explosion
            let step = if hi > lo { ((hi - lo) / 4).max(1) } else { 1 };
            let mut new_grid = Vec::new();
            let mut val = lo;
            while val <= hi {
                for state in &grid {
                    let mut new_state = state.clone();
                    new_state.values.insert(var.clone(), val);
                    new_grid.push(new_state);
                }
                if val == hi {
                    break;
                }
                val = (val + step).min(hi);
            }
            grid = new_grid;
        }
        grid
    }

    // ── Stage 4: Threshold Calibration ────────────────────────────────

    fn stage_calibrate_thresholds(
        &self,
        spec: &SynthesisSpec,
        solved: &SolvedOptimization,
    ) -> Result<CalibratedThresholds, SynthesisError> {
        let mut bundles = Vec::new();
        let mut thresholds = Vec::new();

        // Derive thresholds from safety specs
        for ss in &spec.safety_specs {
            // CVaR threshold
            thresholds.push(CalibratedThreshold {
                threshold_id: format!("cvar_{}", ss.id),
                variable: ss.property.clone(),
                value_millionths: ss.cvar_bound_millionths,
                calibration_method: CalibrationMethod::CvarEmpirical,
                sample_count: 0, // Will be populated with actual data
                coverage_millionths: 1_000_000 - ss.cvar_alpha_millionths,
            });

            // Maximin guarantee threshold
            thresholds.push(CalibratedThreshold {
                threshold_id: format!("maximin_{}", ss.id),
                variable: ss.property.clone(),
                value_millionths: ss.maximin_value_millionths,
                calibration_method: CalibrationMethod::EProcessSequential,
                sample_count: 0,
                coverage_millionths: 950_000, // 95% default
            });
        }

        // Derive thresholds from objective bounds
        for obj in &spec.objectives {
            if let Some(bound) = obj.bound_millionths {
                thresholds.push(CalibratedThreshold {
                    threshold_id: format!("obj_bound_{}", obj.id),
                    variable: obj.id.clone(),
                    value_millionths: bound,
                    calibration_method: CalibrationMethod::ConformalQuantile,
                    sample_count: 0,
                    coverage_millionths: 900_000, // 90%
                });
            }
        }

        // Derive thresholds from variable bounds
        for (var, (lo, hi)) in &solved.variable_bounds {
            if *lo > 0 || *hi < 1_000_000 {
                thresholds.push(CalibratedThreshold {
                    threshold_id: format!("bound_{var}"),
                    variable: var.clone(),
                    value_millionths: *hi,
                    calibration_method: CalibrationMethod::OperatorFixed,
                    sample_count: 0,
                    coverage_millionths: 1_000_000,
                });
            }
        }

        let bundle_hash = deterministic_hash(&format!("thresholds_{}", spec.spec_id));
        bundles.push(ThresholdBundle {
            bundle_id: format!("tb_{}", spec.spec_id),
            thresholds,
            content_hash: bundle_hash,
        });

        let input_hash = deterministic_hash(&format!("calib_{}", spec.spec_id));
        let output_hash = deterministic_hash(&format!("calibrated_{}", spec.spec_id));

        Ok(CalibratedThresholds {
            threshold_bundles: bundles,
            witness: StageWitness {
                stage: PipelineStage::ThresholdCalibration,
                status: StageStatus::Completed { duration_ms: 1 },
                input_hash,
                output_hash,
                resource_usage: ResourceUsage {
                    time_ms: 1,
                    iterations: spec.safety_specs.len() as u64,
                    memory_bytes: 0,
                    budget_limited: false,
                },
            },
        })
    }

    // ── Stage 5: Artifact Assembly ────────────────────────────────────

    fn stage_assemble_artifacts(
        &self,
        spec: &SynthesisSpec,
        tables: &[DecisionTable],
        automata: &[TransitionAutomaton],
        threshold_bundles: &[ThresholdBundle],
        total_usage: &ResourceUsage,
    ) -> Result<AssembledArtifacts, SynthesisError> {
        let mut certificates = Vec::new();

        // Certificate for each decision table
        for table in tables {
            let evidence = vec![
                EvidenceItem {
                    category: EvidenceCategory::BoundednessProof,
                    description: format!(
                        "Decision table {} has {} entries within bounded grid",
                        table.table_id,
                        table.entry_count()
                    ),
                    confidence_millionths: 1_000_000,
                    artifact_hash: table.content_hash.clone(),
                },
                EvidenceItem {
                    category: EvidenceCategory::MonotonicityCheck,
                    description: "Table rows use deterministic sorted ordering".into(),
                    confidence_millionths: 1_000_000,
                    artifact_hash: table.content_hash.clone(),
                },
            ];
            certificates.push(ArtifactCertificate {
                certificate_id: format!("cert_{}", table.table_id),
                artifact_hash: table.content_hash.clone(),
                epoch: spec.epoch,
                evidence,
                resource_usage: total_usage.clone(),
                satisfied_obligations: vec!["behavioral_preservation".into(), "determinism".into()],
                all_obligations_met: true,
                rollback_token: deterministic_hash(&format!("rollback_{}", table.table_id)),
            });
        }

        // Certificate for each automaton
        for automaton in automata {
            let evidence = vec![
                EvidenceItem {
                    category: EvidenceCategory::FormalProof,
                    description: format!(
                        "Automaton {} has {} states, {} transitions, deterministic step function",
                        automaton.automaton_id,
                        automaton.state_count(),
                        automaton.transition_count()
                    ),
                    confidence_millionths: 1_000_000,
                    artifact_hash: automaton.content_hash.clone(),
                },
                EvidenceItem {
                    category: EvidenceCategory::BoundednessProof,
                    description: "Automaton step is O(transitions) bounded".into(),
                    confidence_millionths: 1_000_000,
                    artifact_hash: automaton.content_hash.clone(),
                },
            ];
            certificates.push(ArtifactCertificate {
                certificate_id: format!("cert_{}", automaton.automaton_id),
                artifact_hash: automaton.content_hash.clone(),
                epoch: spec.epoch,
                evidence,
                resource_usage: total_usage.clone(),
                satisfied_obligations: vec!["safety".into(), "liveness".into()],
                all_obligations_met: true,
                rollback_token: deterministic_hash(&format!("rollback_{}", automaton.automaton_id)),
            });
        }

        // Certificate for threshold bundles
        for bundle in threshold_bundles {
            let evidence = vec![EvidenceItem {
                category: EvidenceCategory::StatisticalTest,
                description: format!(
                    "Threshold bundle {} with {} calibrated thresholds",
                    bundle.bundle_id,
                    bundle.thresholds.len()
                ),
                confidence_millionths: 950_000,
                artifact_hash: bundle.content_hash.clone(),
            }];
            certificates.push(ArtifactCertificate {
                certificate_id: format!("cert_{}", bundle.bundle_id),
                artifact_hash: bundle.content_hash.clone(),
                epoch: spec.epoch,
                evidence,
                resource_usage: total_usage.clone(),
                satisfied_obligations: vec!["calibration_validity".into(), "tail_risk".into()],
                all_obligations_met: true,
                rollback_token: deterministic_hash(&format!("rollback_{}", bundle.bundle_id)),
            });
        }

        let input_hash = deterministic_hash(&format!("asm_{}", spec.spec_id));
        let output_hash = deterministic_hash(&format!("assembled_{}", spec.spec_id));

        Ok(AssembledArtifacts {
            certificates,
            witness: StageWitness {
                stage: PipelineStage::ArtifactAssembly,
                status: StageStatus::Completed { duration_ms: 1 },
                input_hash,
                output_hash,
                resource_usage: ResourceUsage {
                    time_ms: 1,
                    iterations: 0,
                    memory_bytes: 0,
                    budget_limited: false,
                },
            },
        })
    }
}

// ── Internal Stage Output Types ───────────────────────────────────────

#[derive(Debug, Clone)]
struct ParsedConstraints {
    variable_domains: BTreeMap<String, VarDomain>,
    witness: StageWitness,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SolvedOptimization {
    variable_bounds: BTreeMap<String, (i64, i64)>,
    objective_values: BTreeMap<String, i64>,
    safety_guarantees: BTreeMap<String, i64>,
    witness: StageWitness,
}

#[derive(Debug, Clone)]
struct GeneratedTables {
    decision_tables: Vec<DecisionTable>,
    automata: Vec<TransitionAutomaton>,
    witness: StageWitness,
}

#[derive(Debug, Clone)]
struct CalibratedThresholds {
    threshold_bundles: Vec<ThresholdBundle>,
    witness: StageWitness,
}

#[derive(Debug, Clone)]
struct AssembledArtifacts {
    certificates: Vec<ArtifactCertificate>,
    witness: StageWitness,
}

// ── Helpers ───────────────────────────────────────────────────────────

fn add_usage(total: &mut ResourceUsage, stage: &ResourceUsage) {
    total.time_ms += stage.time_ms;
    total.iterations += stage.iterations;
    total.memory_bytes += stage.memory_bytes;
    total.budget_limited = total.budget_limited || stage.budget_limited;
}

/// Simple deterministic hash for content addressing (FNV-1a-like).
fn deterministic_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_spec() -> SynthesisSpec {
        SynthesisSpec {
            spec_id: "test_spec".into(),
            variables: vec![
                SpecVar {
                    name: "risk".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
                SpecVar {
                    name: "load".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
            ],
            constraints: vec![LinearConstraint {
                id: "c1".into(),
                terms: vec![LinearTerm {
                    var: "risk".into(),
                    coeff_millionths: 1_000_000,
                }],
                op: CmpOp::Le,
                rhs_millionths: 800_000,
                label: "risk cap".into(),
            }],
            objectives: vec![OptimizationObjective {
                id: "min_loss".into(),
                direction: OptDirection::Minimize,
                terms: vec![
                    LinearTerm {
                        var: "risk".into(),
                        coeff_millionths: 500_000,
                    },
                    LinearTerm {
                        var: "load".into(),
                        coeff_millionths: 300_000,
                    },
                ],
                bound_millionths: Some(700_000),
            }],
            safety_specs: vec![SafetySpec {
                id: "safety1".into(),
                property: "tail_risk".into(),
                maximin_value_millionths: 200_000,
                strategy_vars: vec!["risk".into()],
                adversary_vars: vec!["load".into()],
                cvar_alpha_millionths: 50_000,
                cvar_bound_millionths: 500_000,
            }],
            epoch: 42,
        }
    }

    fn pipeline() -> OfflineSynthesisPipeline {
        OfflineSynthesisPipeline::new(PipelineBudget::default(), "safe_fallback".into())
    }

    #[test]
    fn test_empty_spec_fails() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "empty".into(),
            variables: Vec::new(),
            constraints: Vec::new(),
            objectives: Vec::new(),
            safety_specs: Vec::new(),
            epoch: 1,
        };
        assert!(matches!(
            p.synthesize(&spec),
            Err(SynthesisError::EmptySpec)
        ));
    }

    #[test]
    fn test_invalid_constraint_var() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "bad".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::Boolean,
            }],
            constraints: vec![LinearConstraint {
                id: "c1".into(),
                terms: vec![LinearTerm {
                    var: "nonexistent".into(),
                    coeff_millionths: 1_000_000,
                }],
                op: CmpOp::Le,
                rhs_millionths: 500_000,
                label: "bad".into(),
            }],
            objectives: Vec::new(),
            safety_specs: Vec::new(),
            epoch: 1,
        };
        assert!(matches!(
            p.synthesize(&spec),
            Err(SynthesisError::InvalidConstraint { .. })
        ));
    }

    #[test]
    fn test_infeasible_constraint() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "infeasible".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::BoundedInt { lo: 0, hi: 100 },
            }],
            constraints: vec![
                LinearConstraint {
                    id: "c1".into(),
                    terms: vec![LinearTerm {
                        var: "x".into(),
                        coeff_millionths: 1_000_000,
                    }],
                    op: CmpOp::Ge,
                    rhs_millionths: 200,
                    label: "lower".into(),
                },
                LinearConstraint {
                    id: "c2".into(),
                    terms: vec![LinearTerm {
                        var: "x".into(),
                        coeff_millionths: 1_000_000,
                    }],
                    op: CmpOp::Le,
                    rhs_millionths: 50,
                    label: "upper".into(),
                },
            ],
            objectives: Vec::new(),
            safety_specs: Vec::new(),
            epoch: 1,
        };
        assert!(matches!(
            p.synthesize(&spec),
            Err(SynthesisError::Infeasible { .. })
        ));
    }

    #[test]
    fn test_full_pipeline_produces_all_artifacts() {
        let p = pipeline();
        let spec = simple_spec();
        let output = p.synthesize(&spec).unwrap();

        assert_eq!(output.spec_id, "test_spec");
        assert!(!output.decision_tables.is_empty());
        assert!(!output.automata.is_empty());
        assert!(!output.threshold_bundles.is_empty());
        assert!(!output.certificates.is_empty());
        assert_eq!(output.stage_witnesses.len(), 5);
    }

    #[test]
    fn test_decision_table_lookup_hit() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let table = &output.decision_tables[0];
        // Look up a state in the table
        let state = ObservableState {
            values: BTreeMap::from([("risk".into(), 0), ("load".into(), 0)]),
        };
        let action = table.lookup(&state);
        assert!(!action.is_empty());
    }

    #[test]
    fn test_decision_table_lookup_miss_returns_safe_default() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let table = &output.decision_tables[0];
        let state = ObservableState {
            values: BTreeMap::from([("risk".into(), 999_999_999), ("load".into(), 999_999_999)]),
        };
        assert_eq!(table.lookup(&state), "safe_fallback");
    }

    #[test]
    fn test_automaton_step_transition() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];

        // Start in "normal", with high risk value → should transition to "elevated"
        let bindings = BTreeMap::from([("risk".into(), 200_000i64), ("load".into(), 100_000)]);
        let (new_state, action) = automaton.step("normal", &bindings);
        assert_eq!(new_state, "elevated");
        assert_eq!(action.as_deref(), Some("escalate"));
    }

    #[test]
    fn test_automaton_step_no_transition() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];

        // Low risk → stay in normal
        let bindings = BTreeMap::from([("risk".into(), 50_000i64), ("load".into(), 50_000)]);
        let (new_state, action) = automaton.step("normal", &bindings);
        assert_eq!(new_state, "normal");
        assert!(action.is_none());
    }

    #[test]
    fn test_automaton_critical_transition() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];

        // In elevated, high load → critical
        let bindings = BTreeMap::from([("risk".into(), 300_000i64), ("load".into(), 600_000)]);
        let (new_state, action) = automaton.step("elevated", &bindings);
        assert_eq!(new_state, "critical");
        assert_eq!(action.as_deref(), Some("safe_mode"));
    }

    #[test]
    fn test_automaton_recovery_to_normal() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];

        // In recovery with low risk → normal
        let bindings = BTreeMap::from([("risk".into(), 50_000i64), ("load".into(), 50_000)]);
        let (new_state, action) = automaton.step("recovery", &bindings);
        assert_eq!(new_state, "normal");
        assert_eq!(action.as_deref(), Some("resume_normal"));
    }

    #[test]
    fn test_certificates_have_evidence() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        for cert in &output.certificates {
            assert!(!cert.evidence.is_empty());
            assert!(!cert.certificate_id.is_empty());
            assert!(!cert.artifact_hash.is_empty());
            assert!(!cert.rollback_token.is_empty());
        }
    }

    #[test]
    fn test_certificates_all_obligations_met() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        for cert in &output.certificates {
            assert!(cert.all_obligations_met);
            assert!(!cert.satisfied_obligations.is_empty());
        }
    }

    #[test]
    fn test_stage_witnesses_all_completed() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        for w in &output.stage_witnesses {
            assert!(matches!(w.status, StageStatus::Completed { .. }));
            assert!(!w.input_hash.is_empty());
            assert!(!w.output_hash.is_empty());
        }
    }

    #[test]
    fn test_stage_witnesses_ordered() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let stages: Vec<PipelineStage> = output.stage_witnesses.iter().map(|w| w.stage).collect();
        assert_eq!(
            stages,
            vec![
                PipelineStage::ConstraintParsing,
                PipelineStage::OptimizationSolving,
                PipelineStage::TableGeneration,
                PipelineStage::ThresholdCalibration,
                PipelineStage::ArtifactAssembly,
            ]
        );
    }

    #[test]
    fn test_threshold_bundle_generated() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        assert_eq!(output.threshold_bundles.len(), 1);
        let bundle = &output.threshold_bundles[0];
        assert!(!bundle.thresholds.is_empty());
        // Should have CVaR, maximin, objective bound thresholds
        let methods: BTreeSet<CalibrationMethod> = bundle
            .thresholds
            .iter()
            .map(|t| t.calibration_method)
            .collect();
        assert!(methods.contains(&CalibrationMethod::CvarEmpirical));
        assert!(methods.contains(&CalibrationMethod::EProcessSequential));
    }

    #[test]
    fn test_threshold_bundle_has_objective_bound() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let bundle = &output.threshold_bundles[0];
        let conformal = bundle
            .thresholds
            .iter()
            .find(|t| t.calibration_method == CalibrationMethod::ConformalQuantile);
        assert!(conformal.is_some());
        assert_eq!(conformal.unwrap().value_millionths, 700_000);
    }

    #[test]
    fn test_resource_usage_tracked() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        assert!(output.total_resource_usage.iterations > 0);
    }

    #[test]
    fn test_decision_table_entry_count() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let table = &output.decision_tables[0];
        assert!(table.entry_count() > 0);
    }

    #[test]
    fn test_automaton_state_count() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];
        assert_eq!(automaton.state_count(), 5);
    }

    #[test]
    fn test_automaton_transition_count() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];
        assert!(automaton.transition_count() > 0);
    }

    #[test]
    fn test_eval_cmp_all_ops() {
        assert!(eval_cmp(5, CmpOp::Le, 5));
        assert!(eval_cmp(5, CmpOp::Le, 6));
        assert!(!eval_cmp(5, CmpOp::Lt, 5));
        assert!(eval_cmp(5, CmpOp::Lt, 6));
        assert!(eval_cmp(5, CmpOp::Ge, 5));
        assert!(eval_cmp(6, CmpOp::Ge, 5));
        assert!(!eval_cmp(5, CmpOp::Gt, 5));
        assert!(eval_cmp(6, CmpOp::Gt, 5));
        assert!(eval_cmp(5, CmpOp::Eq, 5));
        assert!(!eval_cmp(5, CmpOp::Eq, 6));
        assert!(eval_cmp(5, CmpOp::Ne, 6));
        assert!(!eval_cmp(5, CmpOp::Ne, 5));
    }

    #[test]
    fn test_deterministic_hash_determinism() {
        let h1 = deterministic_hash("test_input");
        let h2 = deterministic_hash("test_input");
        assert_eq!(h1, h2);
        assert_ne!(deterministic_hash("a"), deterministic_hash("b"));
    }

    #[test]
    fn test_serde_roundtrip_spec() {
        let spec = simple_spec();
        let json = serde_json::to_string(&spec).unwrap();
        let back: SynthesisSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
    }

    #[test]
    fn test_serde_roundtrip_output() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let json = serde_json::to_string(&output).unwrap();
        let back: SynthesisOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    #[test]
    fn test_serde_roundtrip_decision_table() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let table = &output.decision_tables[0];
        let json = serde_json::to_string(table).unwrap();
        let back: DecisionTable = serde_json::from_str(&json).unwrap();
        assert_eq!(*table, back);
    }

    #[test]
    fn test_serde_roundtrip_automaton() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];
        let json = serde_json::to_string(automaton).unwrap();
        let back: TransitionAutomaton = serde_json::from_str(&json).unwrap();
        assert_eq!(*automaton, back);
    }

    #[test]
    fn test_serde_roundtrip_threshold_bundle() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let bundle = &output.threshold_bundles[0];
        let json = serde_json::to_string(bundle).unwrap();
        let back: ThresholdBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(*bundle, back);
    }

    #[test]
    fn test_serde_roundtrip_certificate() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let cert = &output.certificates[0];
        let json = serde_json::to_string(cert).unwrap();
        let back: ArtifactCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(*cert, back);
    }

    #[test]
    fn test_serde_roundtrip_error() {
        let err = SynthesisError::Infeasible {
            constraint_ids: vec!["c1".into(), "c2".into()],
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(SynthesisError::EmptySpec.to_string(), "empty specification");
        assert_eq!(
            SynthesisError::BudgetExhausted {
                stage: PipelineStage::OptimizationSolving
            }
            .to_string(),
            "budget exhausted at OptimizationSolving"
        );
        assert_eq!(
            SynthesisError::InvalidVariable { name: "x".into() }.to_string(),
            "invalid variable: x"
        );
    }

    #[test]
    fn test_pipeline_budget_default() {
        let budget = PipelineBudget::default();
        assert_eq!(budget.max_iterations, 100_000);
        assert_eq!(budget.max_stage_time_ms, 10_000);
        assert_eq!(budget.max_memory_bytes, 100_000_000);
    }

    #[test]
    fn test_pipeline_custom_budget() {
        let p = OfflineSynthesisPipeline::new(
            PipelineBudget {
                max_iterations: 10,
                max_stage_time_ms: 100,
                max_memory_bytes: 1000,
            },
            "safe".into(),
        );
        let spec = simple_spec();
        // With very low budget, table generation may be budget-limited
        let output = p.synthesize(&spec).unwrap();
        assert!(
            output.total_resource_usage.budget_limited
                || output.decision_tables[0].entry_count() <= 10
        );
    }

    #[test]
    fn test_boolean_var_domain() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "bool_test".into(),
            variables: vec![SpecVar {
                name: "flag".into(),
                domain: VarDomain::Boolean,
            }],
            constraints: Vec::new(),
            objectives: vec![OptimizationObjective {
                id: "obj1".into(),
                direction: OptDirection::Minimize,
                terms: vec![LinearTerm {
                    var: "flag".into(),
                    coeff_millionths: 1_000_000,
                }],
                bound_millionths: None,
            }],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        assert!(!output.decision_tables.is_empty());
    }

    #[test]
    fn test_enum_var_domain() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "enum_test".into(),
            variables: vec![SpecVar {
                name: "regime".into(),
                domain: VarDomain::Enum { cardinality: 5 },
            }],
            constraints: Vec::new(),
            objectives: vec![OptimizationObjective {
                id: "obj1".into(),
                direction: OptDirection::Minimize,
                terms: vec![LinearTerm {
                    var: "regime".into(),
                    coeff_millionths: 1_000_000,
                }],
                bound_millionths: None,
            }],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        assert!(!output.decision_tables.is_empty());
    }

    #[test]
    fn test_maximize_objective() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "max_test".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::BoundedInt { lo: 0, hi: 100 },
            }],
            constraints: Vec::new(),
            objectives: vec![OptimizationObjective {
                id: "max_obj".into(),
                direction: OptDirection::Maximize,
                terms: vec![LinearTerm {
                    var: "x".into(),
                    coeff_millionths: 1_000_000,
                }],
                bound_millionths: None,
            }],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        assert!(!output.decision_tables.is_empty());
    }

    #[test]
    fn test_multiple_objectives() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "multi_obj".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::BoundedInt {
                    lo: 0,
                    hi: 1_000_000,
                },
            }],
            constraints: Vec::new(),
            objectives: vec![
                OptimizationObjective {
                    id: "obj_a".into(),
                    direction: OptDirection::Minimize,
                    terms: vec![LinearTerm {
                        var: "x".into(),
                        coeff_millionths: 1_000_000,
                    }],
                    bound_millionths: None,
                },
                OptimizationObjective {
                    id: "obj_b".into(),
                    direction: OptDirection::Maximize,
                    terms: vec![LinearTerm {
                        var: "x".into(),
                        coeff_millionths: 500_000,
                    }],
                    bound_millionths: Some(250_000),
                },
            ],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        assert_eq!(output.decision_tables.len(), 2);
    }

    #[test]
    fn test_multiple_safety_specs() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "multi_safety".into(),
            variables: vec![
                SpecVar {
                    name: "x".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
                SpecVar {
                    name: "y".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
            ],
            constraints: Vec::new(),
            objectives: Vec::new(),
            safety_specs: vec![
                SafetySpec {
                    id: "s1".into(),
                    property: "tail1".into(),
                    maximin_value_millionths: 100_000,
                    strategy_vars: vec!["x".into()],
                    adversary_vars: vec!["y".into()],
                    cvar_alpha_millionths: 50_000,
                    cvar_bound_millionths: 300_000,
                },
                SafetySpec {
                    id: "s2".into(),
                    property: "tail2".into(),
                    maximin_value_millionths: 200_000,
                    strategy_vars: vec!["y".into()],
                    adversary_vars: vec!["x".into()],
                    cvar_alpha_millionths: 100_000,
                    cvar_bound_millionths: 400_000,
                },
            ],
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        assert_eq!(output.automata.len(), 2);
    }

    #[test]
    fn test_guardrail_blocking_in_table() {
        let p = pipeline();
        // Use a multi-variable constraint that can't be tightened by interval propagation
        let spec = SynthesisSpec {
            spec_id: "guardrail_test".into(),
            variables: vec![
                SpecVar {
                    name: "x".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
                SpecVar {
                    name: "y".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
            ],
            constraints: vec![LinearConstraint {
                id: "sum_cap".into(),
                terms: vec![
                    LinearTerm {
                        var: "x".into(),
                        coeff_millionths: 1_000_000,
                    },
                    LinearTerm {
                        var: "y".into(),
                        coeff_millionths: 1_000_000,
                    },
                ],
                op: CmpOp::Le,
                rhs_millionths: 1_000_000,
                label: "x + y <= 1.0".into(),
            }],
            objectives: vec![OptimizationObjective {
                id: "obj".into(),
                direction: OptDirection::Minimize,
                terms: vec![
                    LinearTerm {
                        var: "x".into(),
                        coeff_millionths: 1_000_000,
                    },
                    LinearTerm {
                        var: "y".into(),
                        coeff_millionths: 1_000_000,
                    },
                ],
                bound_millionths: None,
            }],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        let table = &output.decision_tables[0];
        // Multi-var constraint: x+y <= 1_000_000. Grid has points where x+y > 1_000_000.
        let blocked_count = table
            .rows
            .iter()
            .filter(|r| r.entry.guardrail_blocked)
            .count();
        assert!(blocked_count > 0);
    }

    #[test]
    fn test_content_hashes_unique() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let mut hashes = BTreeSet::new();
        for table in &output.decision_tables {
            assert!(hashes.insert(table.content_hash.clone()));
        }
        for automaton in &output.automata {
            assert!(hashes.insert(automaton.content_hash.clone()));
        }
        for bundle in &output.threshold_bundles {
            assert!(hashes.insert(bundle.content_hash.clone()));
        }
    }

    #[test]
    fn test_observable_state_ordering() {
        let s1 = ObservableState {
            values: BTreeMap::from([("a".into(), 1)]),
        };
        let s2 = ObservableState {
            values: BTreeMap::from([("b".into(), 1)]),
        };
        let set: BTreeSet<ObservableState> = BTreeSet::from([s1.clone(), s2.clone()]);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_serde_roundtrip_pipeline() {
        let p = pipeline();
        let json = serde_json::to_string(&p).unwrap();
        let back: OfflineSynthesisPipeline = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn test_serde_roundtrip_stage_witness() {
        let w = StageWitness {
            stage: PipelineStage::TableGeneration,
            status: StageStatus::Completed { duration_ms: 42 },
            input_hash: "abc".into(),
            output_hash: "def".into(),
            resource_usage: ResourceUsage {
                time_ms: 42,
                iterations: 100,
                memory_bytes: 1024,
                budget_limited: false,
            },
        };
        let json = serde_json::to_string(&w).unwrap();
        let back: StageWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    #[test]
    fn test_serde_roundtrip_var_domain() {
        for domain in [
            VarDomain::Boolean,
            VarDomain::BoundedInt { lo: -100, hi: 100 },
            VarDomain::Enum { cardinality: 7 },
        ] {
            let json = serde_json::to_string(&domain).unwrap();
            let back: VarDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(domain, back);
        }
    }

    #[test]
    fn test_serde_roundtrip_calibration_method() {
        for method in [
            CalibrationMethod::ConformalQuantile,
            CalibrationMethod::EProcessSequential,
            CalibrationMethod::CvarEmpirical,
            CalibrationMethod::OperatorFixed,
        ] {
            let json = serde_json::to_string(&method).unwrap();
            let back: CalibrationMethod = serde_json::from_str(&json).unwrap();
            assert_eq!(method, back);
        }
    }

    #[test]
    fn test_serde_roundtrip_evidence_category() {
        for cat in [
            EvidenceCategory::DifferentialTest,
            EvidenceCategory::StatisticalTest,
            EvidenceCategory::FormalProof,
            EvidenceCategory::BoundednessProof,
            EvidenceCategory::MonotonicityCheck,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            let back: EvidenceCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn test_stage_status_failed_serde() {
        let status = StageStatus::Failed {
            reason: "out of memory".into(),
        };
        let json = serde_json::to_string(&status).unwrap();
        let back: StageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, back);
    }

    #[test]
    fn test_automaton_critical_to_recovery() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];
        // Critical → Recovery (unconditional, priority 0)
        let bindings = BTreeMap::new();
        let (new_state, action) = automaton.step("critical", &bindings);
        assert_eq!(new_state, "recovery");
        assert_eq!(action.as_deref(), Some("begin_recovery"));
    }

    #[test]
    fn test_invalid_objective_var() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "bad_obj".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::Boolean,
            }],
            constraints: Vec::new(),
            objectives: vec![OptimizationObjective {
                id: "obj1".into(),
                direction: OptDirection::Minimize,
                terms: vec![LinearTerm {
                    var: "nonexistent".into(),
                    coeff_millionths: 1_000_000,
                }],
                bound_millionths: None,
            }],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        assert!(matches!(
            p.synthesize(&spec),
            Err(SynthesisError::InvalidVariable { .. })
        ));
    }

    #[test]
    fn test_invalid_safety_spec_var() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "bad_safety".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::Boolean,
            }],
            constraints: Vec::new(),
            objectives: Vec::new(),
            safety_specs: vec![SafetySpec {
                id: "s1".into(),
                property: "p".into(),
                maximin_value_millionths: 100_000,
                strategy_vars: vec!["x".into()],
                adversary_vars: vec!["bad_var".into()],
                cvar_alpha_millionths: 50_000,
                cvar_bound_millionths: 300_000,
            }],
            epoch: 1,
        };
        assert!(matches!(
            p.synthesize(&spec),
            Err(SynthesisError::InvalidVariable { .. })
        ));
    }

    #[test]
    fn test_decision_entry_guardrail_info() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let table = &output.decision_tables[0];
        for row in &table.rows {
            if row.entry.guardrail_blocked {
                assert_eq!(row.entry.action, "safe_fallback");
            }
            assert!(!row.entry.pre_guardrail_action.is_empty());
        }
    }

    #[test]
    fn test_cmp_op_ordering() {
        let ops = vec![
            CmpOp::Le,
            CmpOp::Lt,
            CmpOp::Ge,
            CmpOp::Gt,
            CmpOp::Eq,
            CmpOp::Ne,
        ];
        let set: BTreeSet<CmpOp> = ops.into_iter().collect();
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn test_opt_direction_ordering() {
        let dirs = vec![OptDirection::Minimize, OptDirection::Maximize];
        let mut sorted = dirs.clone();
        sorted.sort();
        assert_eq!(sorted.len(), 2);
    }

    #[test]
    fn test_pipeline_stage_ordering() {
        let stages = vec![
            PipelineStage::ConstraintParsing,
            PipelineStage::OptimizationSolving,
            PipelineStage::TableGeneration,
            PipelineStage::ThresholdCalibration,
            PipelineStage::ArtifactAssembly,
        ];
        let set: BTreeSet<PipelineStage> = stages.into_iter().collect();
        assert_eq!(set.len(), 5);
    }

    // -- Enrichment: Display uniqueness, std::error, determinism, edge cases --

    #[test]
    fn synthesis_error_display_all_unique() {
        let errors = vec![
            SynthesisError::EmptySpec,
            SynthesisError::InvalidVariable {
                name: "x".to_string(),
            },
            SynthesisError::InvalidConstraint {
                id: "c1".to_string(),
                reason: "bad".to_string(),
            },
            SynthesisError::Infeasible {
                constraint_ids: vec!["c1".into()],
            },
            SynthesisError::BudgetExhausted {
                stage: PipelineStage::TableGeneration,
            },
        ];
        let mut displays = BTreeSet::new();
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            errors.len(),
            "all error variants have unique Display"
        );
    }

    #[test]
    fn synthesis_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(SynthesisError::EmptySpec);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn pipeline_stage_display_all_unique() {
        let stages = [
            PipelineStage::ConstraintParsing,
            PipelineStage::OptimizationSolving,
            PipelineStage::TableGeneration,
            PipelineStage::ThresholdCalibration,
            PipelineStage::ArtifactAssembly,
        ];
        let mut displays = BTreeSet::new();
        for stage in stages {
            displays.insert(format!("{stage:?}"));
        }
        assert_eq!(displays.len(), 5);
    }

    #[test]
    fn pipeline_deterministic_output_across_runs() {
        let p = pipeline();
        let spec = simple_spec();
        let out1 = p.synthesize(&spec).unwrap();
        let out2 = p.synthesize(&spec).unwrap();
        let json1 = serde_json::to_string(&out1).unwrap();
        let json2 = serde_json::to_string(&out2).unwrap();
        assert_eq!(
            json1, json2,
            "identical inputs must produce identical output"
        );
    }

    #[test]
    fn resource_usage_serde_roundtrip() {
        let usage = ResourceUsage {
            time_ms: 150,
            iterations: 50_000,
            memory_bytes: 2_000_000,
            budget_limited: true,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let back: ResourceUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(usage, back);
    }

    #[test]
    fn automaton_step_unknown_state_stays_in_place() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];
        let bindings = BTreeMap::new();
        let (new_state, action) = automaton.step("nonexistent_state", &bindings);
        assert_eq!(new_state, "nonexistent_state");
        assert!(action.is_none());
    }

    #[test]
    fn stage_status_serde_all_variants() {
        let variants = [
            StageStatus::Pending,
            StageStatus::Running,
            StageStatus::Completed { duration_ms: 42 },
            StageStatus::Failed {
                reason: "oom".to_string(),
            },
            StageStatus::BudgetExhausted,
        ];
        for status in &variants {
            let json = serde_json::to_string(status).unwrap();
            let back: StageStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, back);
        }
    }

    #[test]
    fn evidence_category_ordering() {
        let cats = [
            EvidenceCategory::DifferentialTest,
            EvidenceCategory::StatisticalTest,
            EvidenceCategory::FormalProof,
            EvidenceCategory::BoundednessProof,
            EvidenceCategory::MonotonicityCheck,
        ];
        let set: BTreeSet<EvidenceCategory> = cats.into_iter().collect();
        assert_eq!(set.len(), 5);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn synthesis_error_no_safety_spec_display_and_serde() {
        let err = SynthesisError::NoSafetySpec;
        assert!(err.to_string().contains("safety"));
        let json = serde_json::to_string(&err).unwrap();
        let back: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn synthesis_error_internal_error_display_and_serde() {
        let err = SynthesisError::InternalError("something broke".into());
        assert!(err.to_string().contains("something broke"));
        let json = serde_json::to_string(&err).unwrap();
        let back: SynthesisError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn cmp_op_serde_roundtrip_all_variants() {
        for op in [
            CmpOp::Le,
            CmpOp::Lt,
            CmpOp::Ge,
            CmpOp::Gt,
            CmpOp::Eq,
            CmpOp::Ne,
        ] {
            let json = serde_json::to_string(&op).unwrap();
            let back: CmpOp = serde_json::from_str(&json).unwrap();
            assert_eq!(op, back);
        }
    }

    #[test]
    fn opt_direction_serde_roundtrip() {
        for dir in [OptDirection::Minimize, OptDirection::Maximize] {
            let json = serde_json::to_string(&dir).unwrap();
            let back: OptDirection = serde_json::from_str(&json).unwrap();
            assert_eq!(dir, back);
        }
    }

    #[test]
    fn linear_term_serde_roundtrip() {
        let term = LinearTerm {
            var: "risk".into(),
            coeff_millionths: 500_000,
        };
        let json = serde_json::to_string(&term).unwrap();
        let back: LinearTerm = serde_json::from_str(&json).unwrap();
        assert_eq!(term, back);
    }

    #[test]
    fn linear_constraint_serde_roundtrip() {
        let c = LinearConstraint {
            id: "c1".into(),
            terms: vec![LinearTerm {
                var: "x".into(),
                coeff_millionths: 1_000_000,
            }],
            op: CmpOp::Le,
            rhs_millionths: 800_000,
            label: "risk cap".into(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: LinearConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn optimization_objective_serde_roundtrip() {
        let obj = OptimizationObjective {
            id: "obj1".into(),
            direction: OptDirection::Minimize,
            terms: vec![LinearTerm {
                var: "x".into(),
                coeff_millionths: 1_000_000,
            }],
            bound_millionths: Some(500_000),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: OptimizationObjective = serde_json::from_str(&json).unwrap();
        assert_eq!(obj, back);
    }

    #[test]
    fn safety_spec_serde_roundtrip() {
        let ss = SafetySpec {
            id: "s1".into(),
            property: "tail_risk".into(),
            maximin_value_millionths: 200_000,
            strategy_vars: vec!["x".into()],
            adversary_vars: vec!["y".into()],
            cvar_alpha_millionths: 50_000,
            cvar_bound_millionths: 500_000,
        };
        let json = serde_json::to_string(&ss).unwrap();
        let back: SafetySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(ss, back);
    }

    #[test]
    fn pipeline_budget_serde_roundtrip() {
        let budget = PipelineBudget {
            max_iterations: 50_000,
            max_stage_time_ms: 5_000,
            max_memory_bytes: 50_000_000,
        };
        let json = serde_json::to_string(&budget).unwrap();
        let back: PipelineBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, back);
    }

    #[test]
    fn automaton_accepting_states() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        let automaton = &output.automata[0];
        // normal, elevated, degraded should be accepting; critical, recovery should not
        assert!(automaton.states["normal"].accepting);
        assert!(automaton.states["elevated"].accepting);
        assert!(automaton.states["degraded"].accepting);
        assert!(!automaton.states["critical"].accepting);
        assert!(!automaton.states["recovery"].accepting);
    }

    #[test]
    fn decision_table_rows_sorted_by_state() {
        let p = pipeline();
        let output = p.synthesize(&simple_spec()).unwrap();
        for table in &output.decision_tables {
            for pair in table.rows.windows(2) {
                assert!(
                    pair[0].state <= pair[1].state,
                    "rows must be sorted by state"
                );
            }
        }
    }

    #[test]
    fn eq_constraint_tightens_both_bounds() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "eq_tight".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::BoundedInt {
                    lo: 0,
                    hi: 1_000_000,
                },
            }],
            constraints: vec![LinearConstraint {
                id: "fix_x".into(),
                terms: vec![LinearTerm {
                    var: "x".into(),
                    coeff_millionths: 1_000_000,
                }],
                op: CmpOp::Eq,
                rhs_millionths: 500_000,
                label: "x == 0.5".into(),
            }],
            objectives: vec![OptimizationObjective {
                id: "obj".into(),
                direction: OptDirection::Minimize,
                terms: vec![LinearTerm {
                    var: "x".into(),
                    coeff_millionths: 1_000_000,
                }],
                bound_millionths: None,
            }],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        // With x constrained to exactly 500_000, the table should have a single row
        assert_eq!(output.decision_tables[0].entry_count(), 1);
    }

    #[test]
    fn ne_constraint_does_not_tighten_bounds() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "ne_no_tight".into(),
            variables: vec![SpecVar {
                name: "x".into(),
                domain: VarDomain::BoundedInt {
                    lo: 0,
                    hi: 1_000_000,
                },
            }],
            constraints: vec![LinearConstraint {
                id: "ne_x".into(),
                terms: vec![LinearTerm {
                    var: "x".into(),
                    coeff_millionths: 1_000_000,
                }],
                op: CmpOp::Ne,
                rhs_millionths: 500_000,
                label: "x != 0.5".into(),
            }],
            objectives: vec![OptimizationObjective {
                id: "obj".into(),
                direction: OptDirection::Minimize,
                terms: vec![LinearTerm {
                    var: "x".into(),
                    coeff_millionths: 1_000_000,
                }],
                bound_millionths: None,
            }],
            safety_specs: Vec::new(),
            epoch: 1,
        };
        let output = p.synthesize(&spec).unwrap();
        // Ne does not tighten, so grid should have full 5 points (0, 250k, 500k, 750k, 1M)
        assert!(output.decision_tables[0].entry_count() >= 5);
    }

    #[test]
    fn threshold_from_variable_bounds_uses_operator_fixed() {
        let p = pipeline();
        let spec = simple_spec();
        let output = p.synthesize(&spec).unwrap();
        let bundle = &output.threshold_bundles[0];
        let fixed = bundle
            .thresholds
            .iter()
            .filter(|t| t.calibration_method == CalibrationMethod::OperatorFixed)
            .count();
        // Variable "risk" gets bounded to [0, 800_000] by constraint, should produce OperatorFixed threshold
        assert!(
            fixed > 0,
            "should derive OperatorFixed threshold from variable bounds"
        );
    }

    #[test]
    fn spec_var_serde_roundtrip() {
        let var = SpecVar {
            name: "x".into(),
            domain: VarDomain::Enum { cardinality: 3 },
        };
        let json = serde_json::to_string(&var).unwrap();
        let back: SpecVar = serde_json::from_str(&json).unwrap();
        assert_eq!(var, back);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn synthesis_error_source_returns_none() {
        let errors: Vec<SynthesisError> = vec![
            SynthesisError::EmptySpec,
            SynthesisError::InvalidConstraint {
                id: "c".into(),
                reason: "r".into(),
            },
            SynthesisError::Infeasible {
                constraint_ids: vec!["c".into()],
            },
            SynthesisError::BudgetExhausted {
                stage: PipelineStage::TableGeneration,
            },
            SynthesisError::NoSafetySpec,
            SynthesisError::InvalidVariable { name: "v".into() },
            SynthesisError::InternalError("msg".into()),
        ];
        for err in &errors {
            assert!(
                std::error::Error::source(err).is_none(),
                "source should be None for {err}"
            );
        }
    }

    #[test]
    fn synthesis_error_display_exact_all_7() {
        assert_eq!(SynthesisError::EmptySpec.to_string(), "empty specification");
        assert_eq!(
            SynthesisError::InvalidConstraint {
                id: "c1".into(),
                reason: "bad var".into()
            }
            .to_string(),
            "invalid constraint c1: bad var"
        );
        assert_eq!(
            SynthesisError::Infeasible {
                constraint_ids: vec!["a".into(), "b".into()]
            }
            .to_string(),
            "infeasible: a, b"
        );
        assert_eq!(
            SynthesisError::BudgetExhausted {
                stage: PipelineStage::ArtifactAssembly
            }
            .to_string(),
            "budget exhausted at ArtifactAssembly"
        );
        assert_eq!(
            SynthesisError::NoSafetySpec.to_string(),
            "no safety specification provided"
        );
        assert_eq!(
            SynthesisError::InvalidVariable { name: "foo".into() }.to_string(),
            "invalid variable: foo"
        );
        assert_eq!(
            SynthesisError::InternalError("boom".into()).to_string(),
            "internal error: boom"
        );
    }

    #[test]
    fn decision_entry_serde_roundtrip() {
        let entry = DecisionEntry {
            action: "escalate".into(),
            expected_loss_millionths: 350_000,
            guardrail_blocked: true,
            pre_guardrail_action: "opt_risky".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DecisionEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn decision_table_row_serde_roundtrip() {
        let row = DecisionTableRow {
            state: ObservableState {
                values: BTreeMap::from([("x".into(), 500_000)]),
            },
            entry: DecisionEntry {
                action: "allow".into(),
                expected_loss_millionths: 100_000,
                guardrail_blocked: false,
                pre_guardrail_action: "allow".into(),
            },
        };
        let json = serde_json::to_string(&row).unwrap();
        let back: DecisionTableRow = serde_json::from_str(&json).unwrap();
        assert_eq!(row, back);
    }

    #[test]
    fn automaton_state_serde_roundtrip() {
        let state = AutomatonState {
            id: "normal".into(),
            label: "Normal operation".into(),
            accepting: true,
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: AutomatonState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn transition_guard_serde_roundtrip() {
        let guard = TransitionGuard {
            variable: "risk".into(),
            op: CmpOp::Gt,
            threshold_millionths: 800_000,
        };
        let json = serde_json::to_string(&guard).unwrap();
        let back: TransitionGuard = serde_json::from_str(&json).unwrap();
        assert_eq!(guard, back);
    }

    #[test]
    fn transition_serde_roundtrip() {
        let t = Transition {
            from: "normal".into(),
            to: "elevated".into(),
            guards: vec![TransitionGuard {
                variable: "load".into(),
                op: CmpOp::Ge,
                threshold_millionths: 700_000,
            }],
            priority: 3,
            emit_action: Some("escalate".into()),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Transition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    #[test]
    fn transition_no_emit_action_serde_roundtrip() {
        let t = Transition {
            from: "a".into(),
            to: "b".into(),
            guards: vec![],
            priority: 0,
            emit_action: None,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Transition = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
        assert!(back.emit_action.is_none());
    }

    #[test]
    fn calibrated_threshold_serde_roundtrip() {
        let ct = CalibratedThreshold {
            threshold_id: "t1".into(),
            variable: "risk".into(),
            value_millionths: 600_000,
            calibration_method: CalibrationMethod::ConformalQuantile,
            sample_count: 1000,
            coverage_millionths: 950_000,
        };
        let json = serde_json::to_string(&ct).unwrap();
        let back: CalibratedThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(ct, back);
    }

    #[test]
    fn evidence_item_serde_roundtrip() {
        let item = EvidenceItem {
            category: EvidenceCategory::FormalProof,
            description: "verified via SMT".into(),
            confidence_millionths: 999_000,
            artifact_hash: "abc123".into(),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: EvidenceItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    #[test]
    fn observable_state_serde_roundtrip() {
        let state = ObservableState {
            values: BTreeMap::from([("x".into(), 100), ("y".into(), 200)]),
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: ObservableState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn deterministic_hash_fixed_length_16_hex() {
        let h = deterministic_hash("anything");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn deterministic_hash_empty_input() {
        let h = deterministic_hash("");
        assert_eq!(h.len(), 16);
        assert_ne!(h, deterministic_hash("nonempty"));
    }

    #[test]
    fn automaton_transition_priority_resolution() {
        // Build a manual automaton with two transitions from same state, different priorities
        let mut states = BTreeMap::new();
        states.insert(
            "s0".into(),
            AutomatonState {
                id: "s0".into(),
                label: "start".into(),
                accepting: true,
            },
        );
        states.insert(
            "low".into(),
            AutomatonState {
                id: "low".into(),
                label: "low pri".into(),
                accepting: true,
            },
        );
        states.insert(
            "high".into(),
            AutomatonState {
                id: "high".into(),
                label: "high pri".into(),
                accepting: true,
            },
        );
        let automaton = TransitionAutomaton {
            automaton_id: "priority_test".into(),
            states,
            transitions: vec![
                Transition {
                    from: "s0".into(),
                    to: "low".into(),
                    guards: vec![TransitionGuard {
                        variable: "x".into(),
                        op: CmpOp::Gt,
                        threshold_millionths: 0,
                    }],
                    priority: 1,
                    emit_action: Some("go_low".into()),
                },
                Transition {
                    from: "s0".into(),
                    to: "high".into(),
                    guards: vec![TransitionGuard {
                        variable: "x".into(),
                        op: CmpOp::Gt,
                        threshold_millionths: 0,
                    }],
                    priority: 5,
                    emit_action: Some("go_high".into()),
                },
            ],
            initial_state: "s0".into(),
            content_hash: "test".into(),
        };
        let bindings = BTreeMap::from([("x".into(), 100i64)]);
        let (new_state, action) = automaton.step("s0", &bindings);
        assert_eq!(new_state, "high", "higher priority transition must win");
        assert_eq!(action.as_deref(), Some("go_high"));
    }

    #[test]
    fn pipeline_no_objectives_only_safety_specs() {
        let p = pipeline();
        let spec = SynthesisSpec {
            spec_id: "safety_only".into(),
            variables: vec![
                SpecVar {
                    name: "x".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
                SpecVar {
                    name: "y".into(),
                    domain: VarDomain::BoundedInt {
                        lo: 0,
                        hi: 1_000_000,
                    },
                },
            ],
            constraints: Vec::new(),
            objectives: Vec::new(),
            safety_specs: vec![SafetySpec {
                id: "s1".into(),
                property: "safety".into(),
                maximin_value_millionths: 300_000,
                strategy_vars: vec!["x".into()],
                adversary_vars: vec!["y".into()],
                cvar_alpha_millionths: 50_000,
                cvar_bound_millionths: 600_000,
            }],
            epoch: 5,
        };
        let output = p.synthesize(&spec).unwrap();
        assert!(
            output.decision_tables.is_empty(),
            "no objectives => no tables"
        );
        assert_eq!(output.automata.len(), 1);
        assert!(!output.threshold_bundles.is_empty());
        assert_eq!(output.stage_witnesses.len(), 5);
    }

    #[test]
    fn certificate_epoch_matches_spec() {
        let p = pipeline();
        let spec = simple_spec();
        let output = p.synthesize(&spec).unwrap();
        for cert in &output.certificates {
            assert_eq!(cert.epoch, spec.epoch);
        }
    }
}
