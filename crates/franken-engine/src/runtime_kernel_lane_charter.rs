//! Lane Charter: Runtime Kernel Ownership Surface — FRX-10.3
//!
//! Defines the runtime lane charter as owner of execution-kernel semantics,
//! scheduler safety, and failover behavior across JS and WASM lanes.
//!
//! The charter specifies:
//! - Ownership boundaries for JS lane, WASM lane, and hybrid router
//! - Input/output contracts for each lane
//! - Failure policies and deterministic fallback rules
//! - Footprint budgets and scheduler determinism invariants
//! - Incident bundle requirements for verification and governance

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for charter artifacts.
const SCHEMA_VERSION: &str = "0.1.0";

// ---------------------------------------------------------------------------
// Lane identity
// ---------------------------------------------------------------------------

/// Runtime lane variants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RuntimeLane {
    /// JS interpreter lane — default for small apps.
    Js,
    /// WASM lane — signal graph + deterministic scheduler.
    Wasm,
    /// Hybrid router that selects between JS and WASM per-component.
    HybridRouter,
}

impl fmt::Display for RuntimeLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Js => write!(f, "js"),
            Self::Wasm => write!(f, "wasm"),
            Self::HybridRouter => write!(f, "hybrid_router"),
        }
    }
}

/// Ownership domain within the runtime kernel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OwnershipDomain {
    /// Execution correctness — output matches React semantics.
    ExecutionCorrectness,
    /// Footprint budget — memory/CPU within defined limits.
    FootprintBudget,
    /// Scheduler determinism — same inputs always produce same schedule.
    SchedulerDeterminism,
    /// ABI stability — WASM interface compatibility.
    AbiStability,
    /// Failover behavior — safe-mode activation and fallback.
    FailoverBehavior,
    /// Routing policy — lane selection logic and calibration.
    RoutingPolicy,
    /// Trace emission — runtime trace and evidence output.
    TraceEmission,
    /// Incident response — incident bundle generation.
    IncidentResponse,
}

impl fmt::Display for OwnershipDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExecutionCorrectness => write!(f, "execution_correctness"),
            Self::FootprintBudget => write!(f, "footprint_budget"),
            Self::SchedulerDeterminism => write!(f, "scheduler_determinism"),
            Self::AbiStability => write!(f, "abi_stability"),
            Self::FailoverBehavior => write!(f, "failover_behavior"),
            Self::RoutingPolicy => write!(f, "routing_policy"),
            Self::TraceEmission => write!(f, "trace_emission"),
            Self::IncidentResponse => write!(f, "incident_response"),
        }
    }
}

// ---------------------------------------------------------------------------
// Footprint budget
// ---------------------------------------------------------------------------

/// Resource budget for a single lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FootprintBudget {
    /// Lane this budget applies to.
    pub lane: RuntimeLane,
    /// Max heap bytes.
    pub max_heap_bytes: u64,
    /// Max stack frames.
    pub max_stack_frames: u32,
    /// Max CPU microseconds per update cycle.
    pub max_update_cycle_micros: u64,
    /// Max DOM patches per cycle.
    pub max_dom_patches_per_cycle: u32,
    /// Max concurrent timers/callbacks.
    pub max_concurrent_callbacks: u32,
}

impl FootprintBudget {
    /// Default budget for JS lane (small-app default).
    pub fn js_default() -> Self {
        Self {
            lane: RuntimeLane::Js,
            max_heap_bytes: 16 * 1024 * 1024, // 16 MiB
            max_stack_frames: 256,
            max_update_cycle_micros: 16_000, // 16ms = 60fps budget
            max_dom_patches_per_cycle: 1_000,
            max_concurrent_callbacks: 64,
        }
    }

    /// Default budget for WASM lane.
    pub fn wasm_default() -> Self {
        Self {
            lane: RuntimeLane::Wasm,
            max_heap_bytes: 64 * 1024 * 1024, // 64 MiB
            max_stack_frames: 512,
            max_update_cycle_micros: 8_000, // 8ms target
            max_dom_patches_per_cycle: 5_000,
            max_concurrent_callbacks: 128,
        }
    }

    /// Default budget for hybrid router overhead.
    pub fn hybrid_router_default() -> Self {
        Self {
            lane: RuntimeLane::HybridRouter,
            max_heap_bytes: 4 * 1024 * 1024, // 4 MiB for router state
            max_stack_frames: 32,
            max_update_cycle_micros: 500, // 0.5ms routing overhead
            max_dom_patches_per_cycle: 0, // router doesn't patch DOM
            max_concurrent_callbacks: 16,
        }
    }

    /// Check if resource usage is within budget.
    pub fn check_usage(&self, usage: &ResourceUsage) -> BudgetCheckResult {
        let mut violations = Vec::new();

        if usage.heap_bytes > self.max_heap_bytes {
            violations.push(BudgetViolation {
                resource: "heap_bytes".into(),
                limit: self.max_heap_bytes,
                observed: usage.heap_bytes,
            });
        }
        if usage.stack_frames > self.max_stack_frames {
            violations.push(BudgetViolation {
                resource: "stack_frames".into(),
                limit: self.max_stack_frames as u64,
                observed: usage.stack_frames as u64,
            });
        }
        if usage.update_cycle_micros > self.max_update_cycle_micros {
            violations.push(BudgetViolation {
                resource: "update_cycle_micros".into(),
                limit: self.max_update_cycle_micros,
                observed: usage.update_cycle_micros,
            });
        }
        if usage.dom_patches > self.max_dom_patches_per_cycle {
            violations.push(BudgetViolation {
                resource: "dom_patches".into(),
                limit: self.max_dom_patches_per_cycle as u64,
                observed: usage.dom_patches as u64,
            });
        }

        BudgetCheckResult {
            lane: self.lane.clone(),
            within_budget: violations.is_empty(),
            violations,
        }
    }
}

/// Observed resource usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub heap_bytes: u64,
    pub stack_frames: u32,
    pub update_cycle_micros: u64,
    pub dom_patches: u32,
}

/// A single budget violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetViolation {
    pub resource: String,
    pub limit: u64,
    pub observed: u64,
}

/// Result of checking resource usage against budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetCheckResult {
    pub lane: RuntimeLane,
    pub within_budget: bool,
    pub violations: Vec<BudgetViolation>,
}

// ---------------------------------------------------------------------------
// Input/output contracts
// ---------------------------------------------------------------------------

/// Input contract for a runtime lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneInputContract {
    /// Which lane this contract applies to.
    pub lane: RuntimeLane,
    /// Required input artifact kinds.
    pub required_inputs: BTreeSet<String>,
    /// Accepted FRIR plan versions.
    pub accepted_frir_versions: BTreeSet<String>,
    /// Whether compiler witness data is required.
    pub requires_compiler_witness: bool,
    /// Whether semantics constraints must be attached.
    pub requires_semantics_constraints: bool,
}

impl LaneInputContract {
    /// Default input contract for JS lane.
    pub fn js_default() -> Self {
        Self {
            lane: RuntimeLane::Js,
            required_inputs: ["frir_plan", "component_manifest"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            accepted_frir_versions: ["0.1.0", "0.2.0"].iter().map(|s| s.to_string()).collect(),
            requires_compiler_witness: false,
            requires_semantics_constraints: true,
        }
    }

    /// Default input contract for WASM lane.
    pub fn wasm_default() -> Self {
        Self {
            lane: RuntimeLane::Wasm,
            required_inputs: ["frir_plan", "component_manifest", "wasm_module"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            accepted_frir_versions: ["0.2.0"].iter().map(|s| s.to_string()).collect(),
            requires_compiler_witness: true,
            requires_semantics_constraints: true,
        }
    }

    /// Default input contract for hybrid router.
    pub fn hybrid_router_default() -> Self {
        Self {
            lane: RuntimeLane::HybridRouter,
            required_inputs: [
                "frir_plan",
                "component_manifest",
                "routing_policy",
                "calibration_data",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            accepted_frir_versions: ["0.1.0", "0.2.0"].iter().map(|s| s.to_string()).collect(),
            requires_compiler_witness: false,
            requires_semantics_constraints: true,
        }
    }

    /// Validate that all required inputs are present.
    pub fn validate_inputs(&self, provided: &BTreeSet<String>) -> InputValidation {
        let missing: BTreeSet<String> =
            self.required_inputs.difference(provided).cloned().collect();
        InputValidation {
            lane: self.lane.clone(),
            satisfied: missing.is_empty(),
            missing_inputs: missing,
        }
    }
}

/// Result of input validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputValidation {
    pub lane: RuntimeLane,
    pub satisfied: bool,
    pub missing_inputs: BTreeSet<String>,
}

/// Output contract for a runtime lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneOutputContract {
    /// Which lane this contract applies to.
    pub lane: RuntimeLane,
    /// Required output artifact kinds.
    pub required_outputs: BTreeSet<String>,
    /// Whether deterministic trace is mandatory.
    pub requires_deterministic_trace: bool,
    /// Whether evidence IDs must be attached to all outputs.
    pub requires_evidence_ids: bool,
    /// Whether incident bundles must be emitted on failure.
    pub requires_incident_bundle_on_failure: bool,
}

impl LaneOutputContract {
    /// Default output contract for JS lane.
    pub fn js_default() -> Self {
        Self {
            lane: RuntimeLane::Js,
            required_outputs: ["dom_patch_log", "execution_trace", "timing_profile"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            requires_deterministic_trace: true,
            requires_evidence_ids: true,
            requires_incident_bundle_on_failure: true,
        }
    }

    /// Default output contract for WASM lane.
    pub fn wasm_default() -> Self {
        Self {
            lane: RuntimeLane::Wasm,
            required_outputs: [
                "dom_patch_log",
                "execution_trace",
                "timing_profile",
                "signal_graph_snapshot",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            requires_deterministic_trace: true,
            requires_evidence_ids: true,
            requires_incident_bundle_on_failure: true,
        }
    }

    /// Default output contract for hybrid router.
    pub fn hybrid_router_default() -> Self {
        Self {
            lane: RuntimeLane::HybridRouter,
            required_outputs: [
                "lane_selection_log",
                "routing_decision_receipt",
                "fallback_event_log",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            requires_deterministic_trace: true,
            requires_evidence_ids: true,
            requires_incident_bundle_on_failure: true,
        }
    }

    /// Validate that all required outputs are present.
    pub fn validate_outputs(&self, provided: &BTreeSet<String>) -> OutputValidation {
        let missing: BTreeSet<String> = self
            .required_outputs
            .difference(provided)
            .cloned()
            .collect();
        OutputValidation {
            lane: self.lane.clone(),
            satisfied: missing.is_empty(),
            missing_outputs: missing,
        }
    }
}

/// Result of output validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputValidation {
    pub lane: RuntimeLane,
    pub satisfied: bool,
    pub missing_outputs: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Failure policy
// ---------------------------------------------------------------------------

/// What to do when an invariant is violated at runtime.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailureAction {
    /// Log warning and continue.
    LogAndContinue,
    /// Degrade to fallback lane.
    FallbackToLane(RuntimeLane),
    /// Activate safe-mode with all extensions denied.
    ActivateSafeMode,
    /// Force terminate and emit incident bundle.
    ForceTerminate,
}

impl fmt::Display for FailureAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LogAndContinue => write!(f, "log_and_continue"),
            Self::FallbackToLane(lane) => write!(f, "fallback_to_{lane}"),
            Self::ActivateSafeMode => write!(f, "activate_safe_mode"),
            Self::ForceTerminate => write!(f, "force_terminate"),
        }
    }
}

/// Invariant kind that can be violated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum InvariantKind {
    /// Execution output diverges from expected React semantics.
    SemanticDivergence,
    /// Scheduler produces non-deterministic ordering.
    SchedulerNondeterminism,
    /// Resource budget exceeded.
    BudgetExceeded,
    /// ABI version mismatch.
    AbiMismatch,
    /// Trace emission failure.
    TraceEmissionFailure,
    /// Routing decision inconsistency.
    RoutingInconsistency,
}

impl fmt::Display for InvariantKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SemanticDivergence => write!(f, "semantic_divergence"),
            Self::SchedulerNondeterminism => write!(f, "scheduler_nondeterminism"),
            Self::BudgetExceeded => write!(f, "budget_exceeded"),
            Self::AbiMismatch => write!(f, "abi_mismatch"),
            Self::TraceEmissionFailure => write!(f, "trace_emission_failure"),
            Self::RoutingInconsistency => write!(f, "routing_inconsistency"),
        }
    }
}

/// Failure policy mapping invariant violations to actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailurePolicy {
    /// Per-invariant action rules.
    pub rules: BTreeMap<InvariantKind, FailureAction>,
    /// Default action when no specific rule matches.
    pub default_action: FailureAction,
    /// Whether to emit incident bundle for all failures.
    pub always_emit_incident_bundle: bool,
    /// Max consecutive failures before force terminate.
    pub max_consecutive_failures: u32,
}

impl FailurePolicy {
    /// Default strict failure policy.
    pub fn strict() -> Self {
        let mut rules = BTreeMap::new();
        rules.insert(
            InvariantKind::SemanticDivergence,
            FailureAction::FallbackToLane(RuntimeLane::Js),
        );
        rules.insert(
            InvariantKind::SchedulerNondeterminism,
            FailureAction::ActivateSafeMode,
        );
        rules.insert(
            InvariantKind::BudgetExceeded,
            FailureAction::FallbackToLane(RuntimeLane::Js),
        );
        rules.insert(InvariantKind::AbiMismatch, FailureAction::ForceTerminate);
        rules.insert(
            InvariantKind::TraceEmissionFailure,
            FailureAction::LogAndContinue,
        );
        rules.insert(
            InvariantKind::RoutingInconsistency,
            FailureAction::FallbackToLane(RuntimeLane::Js),
        );
        Self {
            rules,
            default_action: FailureAction::ActivateSafeMode,
            always_emit_incident_bundle: true,
            max_consecutive_failures: 3,
        }
    }

    /// Look up the action for a given invariant violation.
    pub fn action_for(&self, kind: &InvariantKind) -> &FailureAction {
        self.rules.get(kind).unwrap_or(&self.default_action)
    }
}

// ---------------------------------------------------------------------------
// Charter
// ---------------------------------------------------------------------------

/// The full runtime kernel lane charter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeKernelCharter {
    /// Charter identifier.
    pub charter_id: EngineObjectId,
    /// Schema version.
    pub schema_version: String,
    /// Security epoch when charter was created.
    pub epoch: SecurityEpoch,
    /// Ownership domains covered by this charter.
    pub ownership_domains: BTreeSet<OwnershipDomain>,
    /// Lane-specific footprint budgets.
    pub footprint_budgets: Vec<FootprintBudget>,
    /// Lane-specific input contracts.
    pub input_contracts: Vec<LaneInputContract>,
    /// Lane-specific output contracts.
    pub output_contracts: Vec<LaneOutputContract>,
    /// Failure policy.
    pub failure_policy: FailurePolicy,
    /// Scheduler determinism invariants.
    pub scheduler_invariants: Vec<SchedulerInvariant>,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

/// A determinism invariant for the scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerInvariant {
    /// Invariant identifier.
    pub invariant_id: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this is a hard invariant (violation = failure) or soft (warning).
    pub hard: bool,
    /// Which lanes this invariant applies to.
    pub applies_to: BTreeSet<RuntimeLane>,
}

/// Builder for RuntimeKernelCharter.
pub struct CharterBuilder {
    epoch: SecurityEpoch,
    ownership_domains: BTreeSet<OwnershipDomain>,
    footprint_budgets: Vec<FootprintBudget>,
    input_contracts: Vec<LaneInputContract>,
    output_contracts: Vec<LaneOutputContract>,
    failure_policy: FailurePolicy,
    scheduler_invariants: Vec<SchedulerInvariant>,
}

impl CharterBuilder {
    /// Create a new charter builder.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            epoch,
            ownership_domains: BTreeSet::new(),
            footprint_budgets: Vec::new(),
            input_contracts: Vec::new(),
            output_contracts: Vec::new(),
            failure_policy: FailurePolicy::strict(),
            scheduler_invariants: Vec::new(),
        }
    }

    /// Add an ownership domain.
    pub fn ownership(mut self, domain: OwnershipDomain) -> Self {
        self.ownership_domains.insert(domain);
        self
    }

    /// Add a footprint budget.
    pub fn footprint_budget(mut self, budget: FootprintBudget) -> Self {
        self.footprint_budgets.push(budget);
        self
    }

    /// Add an input contract.
    pub fn input_contract(mut self, contract: LaneInputContract) -> Self {
        self.input_contracts.push(contract);
        self
    }

    /// Add an output contract.
    pub fn output_contract(mut self, contract: LaneOutputContract) -> Self {
        self.output_contracts.push(contract);
        self
    }

    /// Set failure policy.
    pub fn failure_policy(mut self, policy: FailurePolicy) -> Self {
        self.failure_policy = policy;
        self
    }

    /// Add a scheduler invariant.
    pub fn scheduler_invariant(mut self, invariant: SchedulerInvariant) -> Self {
        self.scheduler_invariants.push(invariant);
        self
    }

    /// Build the charter.
    pub fn build(self) -> RuntimeKernelCharter {
        let content_hash = {
            let mut data = Vec::new();
            data.extend_from_slice(SCHEMA_VERSION.as_bytes());
            data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
            for domain in &self.ownership_domains {
                data.extend_from_slice(domain.to_string().as_bytes());
            }
            for budget in &self.footprint_budgets {
                data.extend_from_slice(budget.lane.to_string().as_bytes());
                data.extend_from_slice(&budget.max_heap_bytes.to_le_bytes());
            }
            for inv in &self.scheduler_invariants {
                data.extend_from_slice(inv.invariant_id.as_bytes());
            }
            ContentHash::compute(&data)
        };

        let charter_id = {
            use crate::engine_object_id::{ObjectDomain, SchemaId, derive_id};
            derive_id(
                ObjectDomain::PolicyObject,
                "runtime_kernel_charter",
                &SchemaId::from_definition(b"runtime_kernel_lane_charter:0.1.0"),
                content_hash.as_bytes(),
            )
            .unwrap_or_default()
        };

        RuntimeKernelCharter {
            charter_id,
            schema_version: SCHEMA_VERSION.to_string(),
            epoch: self.epoch,
            ownership_domains: self.ownership_domains,
            footprint_budgets: self.footprint_budgets,
            input_contracts: self.input_contracts,
            output_contracts: self.output_contracts,
            failure_policy: self.failure_policy,
            scheduler_invariants: self.scheduler_invariants,
            content_hash,
        }
    }
}

/// Build the canonical runtime kernel charter with all defaults.
pub fn canonical_charter(epoch: SecurityEpoch) -> RuntimeKernelCharter {
    let all_lanes: BTreeSet<RuntimeLane> = [
        RuntimeLane::Js,
        RuntimeLane::Wasm,
        RuntimeLane::HybridRouter,
    ]
    .into_iter()
    .collect();

    CharterBuilder::new(epoch)
        .ownership(OwnershipDomain::ExecutionCorrectness)
        .ownership(OwnershipDomain::FootprintBudget)
        .ownership(OwnershipDomain::SchedulerDeterminism)
        .ownership(OwnershipDomain::AbiStability)
        .ownership(OwnershipDomain::FailoverBehavior)
        .ownership(OwnershipDomain::RoutingPolicy)
        .ownership(OwnershipDomain::TraceEmission)
        .ownership(OwnershipDomain::IncidentResponse)
        .footprint_budget(FootprintBudget::js_default())
        .footprint_budget(FootprintBudget::wasm_default())
        .footprint_budget(FootprintBudget::hybrid_router_default())
        .input_contract(LaneInputContract::js_default())
        .input_contract(LaneInputContract::wasm_default())
        .input_contract(LaneInputContract::hybrid_router_default())
        .output_contract(LaneOutputContract::js_default())
        .output_contract(LaneOutputContract::wasm_default())
        .output_contract(LaneOutputContract::hybrid_router_default())
        .scheduler_invariant(SchedulerInvariant {
            invariant_id: "sched-det-001".into(),
            description: "Same FRIR plan + same initial state = same update schedule".into(),
            hard: true,
            applies_to: all_lanes.clone(),
        })
        .scheduler_invariant(SchedulerInvariant {
            invariant_id: "sched-det-002".into(),
            description: "Hook ordering matches React semantics (useEffect cleanup before effect)"
                .into(),
            hard: true,
            applies_to: all_lanes.clone(),
        })
        .scheduler_invariant(SchedulerInvariant {
            invariant_id: "sched-det-003".into(),
            description: "State updates within same batch produce identical commit order".into(),
            hard: true,
            applies_to: all_lanes.clone(),
        })
        .scheduler_invariant(SchedulerInvariant {
            invariant_id: "sched-fair-001".into(),
            description: "No starvation: every queued update must complete within budget window"
                .into(),
            hard: false,
            applies_to: all_lanes,
        })
        .build()
}

// ---------------------------------------------------------------------------
// Charter compliance check
// ---------------------------------------------------------------------------

/// Result of checking a lane's compliance against the charter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Charter that was checked against.
    pub charter_id: EngineObjectId,
    /// Lane that was checked.
    pub lane: RuntimeLane,
    /// Input validation result.
    pub input_validation: InputValidation,
    /// Output validation result.
    pub output_validation: OutputValidation,
    /// Budget check result.
    pub budget_check: BudgetCheckResult,
    /// Invariant check results.
    pub invariant_checks: Vec<InvariantCheck>,
    /// Overall compliance.
    pub compliant: bool,
    /// Report hash.
    pub report_hash: ContentHash,
}

/// Result of checking a single invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantCheck {
    pub invariant_id: String,
    pub satisfied: bool,
    pub detail: String,
}

/// Check compliance of a lane against the charter.
pub fn check_compliance(
    charter: &RuntimeKernelCharter,
    lane: &RuntimeLane,
    provided_inputs: &BTreeSet<String>,
    provided_outputs: &BTreeSet<String>,
    usage: &ResourceUsage,
    invariant_results: &[(String, bool, String)],
) -> ComplianceReport {
    let input_validation = charter
        .input_contracts
        .iter()
        .find(|c| c.lane == *lane)
        .map(|c| c.validate_inputs(provided_inputs))
        .unwrap_or(InputValidation {
            lane: lane.clone(),
            satisfied: true,
            missing_inputs: BTreeSet::new(),
        });

    let output_validation = charter
        .output_contracts
        .iter()
        .find(|c| c.lane == *lane)
        .map(|c| c.validate_outputs(provided_outputs))
        .unwrap_or(OutputValidation {
            lane: lane.clone(),
            satisfied: true,
            missing_outputs: BTreeSet::new(),
        });

    let budget_check = charter
        .footprint_budgets
        .iter()
        .find(|b| b.lane == *lane)
        .map(|b| b.check_usage(usage))
        .unwrap_or(BudgetCheckResult {
            lane: lane.clone(),
            within_budget: true,
            violations: Vec::new(),
        });

    let invariant_checks: Vec<InvariantCheck> = invariant_results
        .iter()
        .map(|(id, satisfied, detail)| InvariantCheck {
            invariant_id: id.clone(),
            satisfied: *satisfied,
            detail: detail.clone(),
        })
        .collect();

    let compliant = input_validation.satisfied
        && output_validation.satisfied
        && budget_check.within_budget
        && invariant_checks.iter().all(|c| c.satisfied);

    let report_hash = {
        let mut data = Vec::new();
        data.extend_from_slice(charter.content_hash.as_bytes());
        data.extend_from_slice(lane.to_string().as_bytes());
        data.extend_from_slice(&[if compliant { 1 } else { 0 }]);
        ContentHash::compute(&data)
    };

    ComplianceReport {
        charter_id: charter.charter_id.clone(),
        lane: lane.clone(),
        input_validation,
        output_validation,
        budget_check,
        invariant_checks,
        compliant,
        report_hash,
    }
}

// ---------------------------------------------------------------------------
// Charter registry
// ---------------------------------------------------------------------------

/// Registry tracking charter versions and compliance history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CharterRegistry {
    /// Active charter.
    pub active_charter: RuntimeKernelCharter,
    /// Compliance history (lane, report).
    pub compliance_history: Vec<ComplianceReport>,
    /// Events.
    pub events: Vec<CharterEvent>,
    seq: u64,
}

/// Charter lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CharterEvent {
    pub seq: u64,
    pub tick_ns: u64,
    pub kind: CharterEventKind,
    pub summary: String,
}

/// Charter event kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CharterEventKind {
    /// Charter activated.
    Activated { charter_id: EngineObjectId },
    /// Compliance check completed.
    ComplianceChecked { lane: RuntimeLane, compliant: bool },
    /// Failure policy triggered.
    FailurePolicyTriggered {
        invariant: InvariantKind,
        action: FailureAction,
    },
}

impl CharterRegistry {
    /// Create a new registry with the canonical charter.
    pub fn new(epoch: SecurityEpoch) -> Self {
        let charter = canonical_charter(epoch);
        let charter_id = charter.charter_id.clone();
        let mut registry = Self {
            active_charter: charter,
            compliance_history: Vec::new(),
            events: Vec::new(),
            seq: 0,
        };
        registry.emit(
            0,
            CharterEventKind::Activated { charter_id },
            "charter activated".into(),
        );
        registry
    }

    /// Record a compliance check.
    pub fn record_compliance(&mut self, report: ComplianceReport, tick_ns: u64) {
        let lane = report.lane.clone();
        let compliant = report.compliant;
        self.compliance_history.push(report);
        self.emit(
            tick_ns,
            CharterEventKind::ComplianceChecked {
                lane: lane.clone(),
                compliant,
            },
            format!(
                "compliance check for {lane}: {}",
                if compliant { "pass" } else { "fail" }
            ),
        );
    }

    /// Handle an invariant violation per the failure policy.
    pub fn handle_violation(&self, invariant: &InvariantKind) -> &FailureAction {
        self.active_charter.failure_policy.action_for(invariant)
    }

    /// Get compliance pass rate (millionths) for a lane.
    pub fn pass_rate_millionths(&self, lane: &RuntimeLane) -> i64 {
        let total = self
            .compliance_history
            .iter()
            .filter(|r| r.lane == *lane)
            .count();
        if total == 0 {
            return MILLION;
        }
        let passed = self
            .compliance_history
            .iter()
            .filter(|r| r.lane == *lane && r.compliant)
            .count();
        (passed as i64 * MILLION) / total as i64
    }

    fn emit(&mut self, tick_ns: u64, kind: CharterEventKind, summary: String) {
        self.seq += 1;
        self.events.push(CharterEvent {
            seq: self.seq,
            tick_ns,
            kind,
            summary,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    // -- RuntimeLane --

    #[test]
    fn lane_display() {
        assert_eq!(RuntimeLane::Js.to_string(), "js");
        assert_eq!(RuntimeLane::Wasm.to_string(), "wasm");
        assert_eq!(RuntimeLane::HybridRouter.to_string(), "hybrid_router");
    }

    #[test]
    fn lane_ordering() {
        assert!(RuntimeLane::Js < RuntimeLane::Wasm);
        assert!(RuntimeLane::Wasm < RuntimeLane::HybridRouter);
    }

    // -- OwnershipDomain --

    #[test]
    fn ownership_domain_display() {
        assert_eq!(
            OwnershipDomain::ExecutionCorrectness.to_string(),
            "execution_correctness"
        );
        assert_eq!(
            OwnershipDomain::SchedulerDeterminism.to_string(),
            "scheduler_determinism"
        );
    }

    #[test]
    fn ownership_domain_count() {
        // Verify all 8 domains exist.
        let domains = [
            OwnershipDomain::ExecutionCorrectness,
            OwnershipDomain::FootprintBudget,
            OwnershipDomain::SchedulerDeterminism,
            OwnershipDomain::AbiStability,
            OwnershipDomain::FailoverBehavior,
            OwnershipDomain::RoutingPolicy,
            OwnershipDomain::TraceEmission,
            OwnershipDomain::IncidentResponse,
        ];
        let set: BTreeSet<_> = domains.into_iter().collect();
        assert_eq!(set.len(), 8);
    }

    // -- FootprintBudget --

    #[test]
    fn js_budget_defaults() {
        let b = FootprintBudget::js_default();
        assert_eq!(b.lane, RuntimeLane::Js);
        assert_eq!(b.max_heap_bytes, 16 * 1024 * 1024);
        assert_eq!(b.max_update_cycle_micros, 16_000);
    }

    #[test]
    fn wasm_budget_defaults() {
        let b = FootprintBudget::wasm_default();
        assert_eq!(b.lane, RuntimeLane::Wasm);
        assert!(b.max_heap_bytes > FootprintBudget::js_default().max_heap_bytes);
    }

    #[test]
    fn router_budget_defaults() {
        let b = FootprintBudget::hybrid_router_default();
        assert_eq!(b.lane, RuntimeLane::HybridRouter);
        assert_eq!(b.max_dom_patches_per_cycle, 0); // Router doesn't patch DOM.
    }

    #[test]
    fn budget_check_within() {
        let b = FootprintBudget::js_default();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let result = b.check_usage(&usage);
        assert!(result.within_budget);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn budget_check_exceeded() {
        let b = FootprintBudget::js_default();
        let usage = ResourceUsage {
            heap_bytes: 100 * 1024 * 1024, // 100 MiB > 16 MiB limit
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let result = b.check_usage(&usage);
        assert!(!result.within_budget);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].resource, "heap_bytes");
    }

    #[test]
    fn budget_check_multiple_violations() {
        let b = FootprintBudget::js_default();
        let usage = ResourceUsage {
            heap_bytes: 100 * 1024 * 1024,
            stack_frames: 1000,
            update_cycle_micros: 50_000,
            dom_patches: 5000,
        };
        let result = b.check_usage(&usage);
        assert!(!result.within_budget);
        assert_eq!(result.violations.len(), 4);
    }

    // -- LaneInputContract --

    #[test]
    fn js_input_contract_defaults() {
        let c = LaneInputContract::js_default();
        assert_eq!(c.lane, RuntimeLane::Js);
        assert!(c.required_inputs.contains("frir_plan"));
        assert!(!c.requires_compiler_witness);
    }

    #[test]
    fn wasm_input_contract_requires_witness() {
        let c = LaneInputContract::wasm_default();
        assert!(c.requires_compiler_witness);
        assert!(c.required_inputs.contains("wasm_module"));
    }

    #[test]
    fn input_validation_satisfied() {
        let c = LaneInputContract::js_default();
        let provided: BTreeSet<String> = ["frir_plan", "component_manifest", "extra"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let v = c.validate_inputs(&provided);
        assert!(v.satisfied);
        assert!(v.missing_inputs.is_empty());
    }

    #[test]
    fn input_validation_missing() {
        let c = LaneInputContract::js_default();
        let provided: BTreeSet<String> = ["frir_plan"].iter().map(|s| s.to_string()).collect();
        let v = c.validate_inputs(&provided);
        assert!(!v.satisfied);
        assert!(v.missing_inputs.contains("component_manifest"));
    }

    // -- LaneOutputContract --

    #[test]
    fn js_output_contract_defaults() {
        let c = LaneOutputContract::js_default();
        assert_eq!(c.lane, RuntimeLane::Js);
        assert!(c.requires_deterministic_trace);
        assert!(c.requires_incident_bundle_on_failure);
    }

    #[test]
    fn output_validation_satisfied() {
        let c = LaneOutputContract::js_default();
        let provided: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let v = c.validate_outputs(&provided);
        assert!(v.satisfied);
    }

    #[test]
    fn output_validation_missing() {
        let c = LaneOutputContract::wasm_default();
        let provided: BTreeSet<String> = ["dom_patch_log"].iter().map(|s| s.to_string()).collect();
        let v = c.validate_outputs(&provided);
        assert!(!v.satisfied);
        assert!(v.missing_outputs.len() >= 2);
    }

    // -- FailurePolicy --

    #[test]
    fn strict_policy() {
        let p = FailurePolicy::strict();
        assert!(p.always_emit_incident_bundle);
        assert_eq!(p.max_consecutive_failures, 3);
    }

    #[test]
    fn policy_action_for_known() {
        let p = FailurePolicy::strict();
        let action = p.action_for(&InvariantKind::SemanticDivergence);
        assert_eq!(*action, FailureAction::FallbackToLane(RuntimeLane::Js));
    }

    #[test]
    fn policy_action_for_abi_mismatch() {
        let p = FailurePolicy::strict();
        let action = p.action_for(&InvariantKind::AbiMismatch);
        assert_eq!(*action, FailureAction::ForceTerminate);
    }

    #[test]
    fn failure_action_display() {
        assert_eq!(
            FailureAction::LogAndContinue.to_string(),
            "log_and_continue"
        );
        assert_eq!(
            FailureAction::FallbackToLane(RuntimeLane::Js).to_string(),
            "fallback_to_js"
        );
        assert_eq!(
            FailureAction::ActivateSafeMode.to_string(),
            "activate_safe_mode"
        );
    }

    #[test]
    fn invariant_kind_display() {
        assert_eq!(
            InvariantKind::SemanticDivergence.to_string(),
            "semantic_divergence"
        );
        assert_eq!(InvariantKind::BudgetExceeded.to_string(), "budget_exceeded");
    }

    // -- CharterBuilder --

    #[test]
    fn builder_minimal() {
        let charter = CharterBuilder::new(test_epoch())
            .ownership(OwnershipDomain::ExecutionCorrectness)
            .build();
        assert_eq!(charter.schema_version, SCHEMA_VERSION);
        assert_eq!(charter.ownership_domains.len(), 1);
    }

    #[test]
    fn builder_with_budgets() {
        let charter = CharterBuilder::new(test_epoch())
            .footprint_budget(FootprintBudget::js_default())
            .footprint_budget(FootprintBudget::wasm_default())
            .build();
        assert_eq!(charter.footprint_budgets.len(), 2);
    }

    #[test]
    fn builder_hash_deterministic() {
        let c1 = CharterBuilder::new(test_epoch())
            .ownership(OwnershipDomain::ExecutionCorrectness)
            .build();
        let c2 = CharterBuilder::new(test_epoch())
            .ownership(OwnershipDomain::ExecutionCorrectness)
            .build();
        assert_eq!(c1.content_hash, c2.content_hash);
        assert_eq!(c1.charter_id, c2.charter_id);
    }

    // -- canonical_charter --

    #[test]
    fn canonical_charter_has_all_domains() {
        let charter = canonical_charter(test_epoch());
        assert_eq!(charter.ownership_domains.len(), 8);
    }

    #[test]
    fn canonical_charter_has_three_budgets() {
        let charter = canonical_charter(test_epoch());
        assert_eq!(charter.footprint_budgets.len(), 3);
    }

    #[test]
    fn canonical_charter_has_three_input_contracts() {
        let charter = canonical_charter(test_epoch());
        assert_eq!(charter.input_contracts.len(), 3);
    }

    #[test]
    fn canonical_charter_has_three_output_contracts() {
        let charter = canonical_charter(test_epoch());
        assert_eq!(charter.output_contracts.len(), 3);
    }

    #[test]
    fn canonical_charter_has_scheduler_invariants() {
        let charter = canonical_charter(test_epoch());
        assert_eq!(charter.scheduler_invariants.len(), 4);
        // First 3 are hard, last is soft.
        assert!(charter.scheduler_invariants[0].hard);
        assert!(charter.scheduler_invariants[1].hard);
        assert!(charter.scheduler_invariants[2].hard);
        assert!(!charter.scheduler_invariants[3].hard);
    }

    // -- check_compliance --

    #[test]
    fn compliance_passes_when_all_satisfied() {
        let charter = canonical_charter(test_epoch());
        let inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let invariants = vec![("sched-det-001".into(), true, "ok".into())];
        let report = check_compliance(
            &charter,
            &RuntimeLane::Js,
            &inputs,
            &outputs,
            &usage,
            &invariants,
        );
        assert!(report.compliant);
    }

    #[test]
    fn compliance_fails_on_missing_input() {
        let charter = canonical_charter(test_epoch());
        let inputs: BTreeSet<String> = BTreeSet::new();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let report = check_compliance(&charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        assert!(!report.compliant);
        assert!(!report.input_validation.satisfied);
    }

    #[test]
    fn compliance_fails_on_budget_exceeded() {
        let charter = canonical_charter(test_epoch());
        let inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 100 * 1024 * 1024, // exceeds JS 16 MiB
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let report = check_compliance(&charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        assert!(!report.compliant);
        assert!(!report.budget_check.within_budget);
    }

    #[test]
    fn compliance_fails_on_invariant_violation() {
        let charter = canonical_charter(test_epoch());
        let inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let invariants = vec![(
            "sched-det-001".into(),
            false,
            "nondeterministic ordering detected".into(),
        )];
        let report = check_compliance(
            &charter,
            &RuntimeLane::Js,
            &inputs,
            &outputs,
            &usage,
            &invariants,
        );
        assert!(!report.compliant);
    }

    #[test]
    fn compliance_report_hash_deterministic() {
        let charter = canonical_charter(test_epoch());
        let inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let r1 = check_compliance(&charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        let r2 = check_compliance(&charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    // -- CharterRegistry --

    #[test]
    fn registry_new() {
        let registry = CharterRegistry::new(test_epoch());
        assert!(!registry.events.is_empty());
        assert!(matches!(
            registry.events[0].kind,
            CharterEventKind::Activated { .. }
        ));
    }

    #[test]
    fn registry_record_compliance() {
        let mut registry = CharterRegistry::new(test_epoch());
        let charter = &registry.active_charter.clone();
        let inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let report = check_compliance(charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        registry.record_compliance(report, 1000);
        assert_eq!(registry.compliance_history.len(), 1);
    }

    #[test]
    fn registry_pass_rate() {
        let mut registry = CharterRegistry::new(test_epoch());
        let charter = registry.active_charter.clone();
        let inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        // 2 passing, 1 failing.
        let r1 = check_compliance(&charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        registry.record_compliance(r1, 1000);

        let r2 = check_compliance(&charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        registry.record_compliance(r2, 2000);

        let bad_usage = ResourceUsage {
            heap_bytes: 100 * 1024 * 1024,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let r3 = check_compliance(
            &charter,
            &RuntimeLane::Js,
            &inputs,
            &outputs,
            &bad_usage,
            &[],
        );
        registry.record_compliance(r3, 3000);

        let rate = registry.pass_rate_millionths(&RuntimeLane::Js);
        assert_eq!(rate, 666_666); // 2/3
    }

    #[test]
    fn registry_pass_rate_no_history() {
        let registry = CharterRegistry::new(test_epoch());
        assert_eq!(registry.pass_rate_millionths(&RuntimeLane::Js), MILLION);
    }

    #[test]
    fn registry_handle_violation() {
        let registry = CharterRegistry::new(test_epoch());
        let action = registry.handle_violation(&InvariantKind::SemanticDivergence);
        assert_eq!(*action, FailureAction::FallbackToLane(RuntimeLane::Js));
    }

    // -- Serde round-trips --

    #[test]
    fn serde_runtime_lane() {
        let lane = RuntimeLane::Wasm;
        let json = serde_json::to_string(&lane).unwrap();
        let lane2: RuntimeLane = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, lane2);
    }

    #[test]
    fn serde_footprint_budget() {
        let b = FootprintBudget::js_default();
        let json = serde_json::to_string(&b).unwrap();
        let b2: FootprintBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(b, b2);
    }

    #[test]
    fn serde_failure_policy() {
        let p = FailurePolicy::strict();
        let json = serde_json::to_string(&p).unwrap();
        let p2: FailurePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn serde_charter() {
        let charter = canonical_charter(test_epoch());
        let json = serde_json::to_string(&charter).unwrap();
        let c2: RuntimeKernelCharter = serde_json::from_str(&json).unwrap();
        assert_eq!(charter, c2);
    }

    #[test]
    fn serde_compliance_report() {
        let charter = canonical_charter(test_epoch());
        let inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let usage = ResourceUsage {
            heap_bytes: 1_000_000,
            stack_frames: 10,
            update_cycle_micros: 5000,
            dom_patches: 50,
        };
        let report = check_compliance(&charter, &RuntimeLane::Js, &inputs, &outputs, &usage, &[]);
        let json = serde_json::to_string(&report).unwrap();
        let r2: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, r2);
    }

    // -- Integration --

    #[test]
    fn integration_full_lifecycle() {
        // Build canonical charter.
        let charter = canonical_charter(test_epoch());
        assert_eq!(charter.ownership_domains.len(), 8);

        // Simulate JS lane compliance — passes.
        let js_inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let js_outputs: BTreeSet<String> = ["dom_patch_log", "execution_trace", "timing_profile"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let js_usage = ResourceUsage {
            heap_bytes: 8 * 1024 * 1024,
            stack_frames: 50,
            update_cycle_micros: 10_000,
            dom_patches: 200,
        };
        let js_report = check_compliance(
            &charter,
            &RuntimeLane::Js,
            &js_inputs,
            &js_outputs,
            &js_usage,
            &[("sched-det-001".into(), true, "ok".into())],
        );
        assert!(js_report.compliant);

        // Simulate WASM lane compliance — fails (missing wasm_module input).
        let wasm_inputs: BTreeSet<String> = ["frir_plan", "component_manifest"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let wasm_outputs: BTreeSet<String> = [
            "dom_patch_log",
            "execution_trace",
            "timing_profile",
            "signal_graph_snapshot",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let wasm_usage = ResourceUsage {
            heap_bytes: 32 * 1024 * 1024,
            stack_frames: 100,
            update_cycle_micros: 4_000,
            dom_patches: 500,
        };
        let wasm_report = check_compliance(
            &charter,
            &RuntimeLane::Wasm,
            &wasm_inputs,
            &wasm_outputs,
            &wasm_usage,
            &[],
        );
        assert!(!wasm_report.compliant);
        assert!(
            wasm_report
                .input_validation
                .missing_inputs
                .contains("wasm_module")
        );

        // Handle invariant violation.
        let action = charter
            .failure_policy
            .action_for(&InvariantKind::SemanticDivergence);
        assert_eq!(*action, FailureAction::FallbackToLane(RuntimeLane::Js));

        // Registry lifecycle.
        let mut registry = CharterRegistry::new(test_epoch());
        registry.record_compliance(js_report, 1000);
        registry.record_compliance(wasm_report, 2000);
        assert_eq!(registry.pass_rate_millionths(&RuntimeLane::Js), MILLION);
        assert_eq!(registry.pass_rate_millionths(&RuntimeLane::Wasm), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn ownership_domain_display_uniqueness_btreeset() {
        let domains = [
            OwnershipDomain::ExecutionCorrectness,
            OwnershipDomain::FootprintBudget,
            OwnershipDomain::SchedulerDeterminism,
            OwnershipDomain::AbiStability,
            OwnershipDomain::FailoverBehavior,
            OwnershipDomain::RoutingPolicy,
            OwnershipDomain::TraceEmission,
            OwnershipDomain::IncidentResponse,
        ];
        let mut displays = BTreeSet::new();
        for d in &domains {
            displays.insert(d.to_string());
        }
        assert_eq!(
            displays.len(),
            8,
            "all 8 OwnershipDomain variants produce distinct Display strings"
        );
    }

    #[test]
    fn runtime_lane_serde_roundtrip() {
        for lane in [
            RuntimeLane::Js,
            RuntimeLane::Wasm,
            RuntimeLane::HybridRouter,
        ] {
            let json = serde_json::to_string(&lane).unwrap();
            let back: RuntimeLane = serde_json::from_str(&json).unwrap();
            assert_eq!(lane, back);
        }
    }

    #[test]
    fn footprint_budget_serde_roundtrip() {
        let budget = FootprintBudget::js_default();
        let json = serde_json::to_string(&budget).unwrap();
        let back: FootprintBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, back);
    }

    #[test]
    fn wasm_budget_defaults_differ_from_js() {
        let js = FootprintBudget::js_default();
        let wasm = FootprintBudget::wasm_default();
        assert_ne!(js.lane, wasm.lane);
        assert_ne!(js.max_heap_bytes, wasm.max_heap_bytes);
    }

    #[test]
    fn ownership_domain_serde_roundtrip() {
        for d in [
            OwnershipDomain::ExecutionCorrectness,
            OwnershipDomain::FootprintBudget,
            OwnershipDomain::SchedulerDeterminism,
            OwnershipDomain::AbiStability,
            OwnershipDomain::FailoverBehavior,
            OwnershipDomain::RoutingPolicy,
            OwnershipDomain::TraceEmission,
            OwnershipDomain::IncidentResponse,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let back: OwnershipDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(d, back);
        }
    }

    #[test]
    fn lane_display_uniqueness_btreeset() {
        let lanes = [
            RuntimeLane::Js,
            RuntimeLane::Wasm,
            RuntimeLane::HybridRouter,
        ];
        let mut displays = BTreeSet::new();
        for l in &lanes {
            displays.insert(l.to_string());
        }
        assert_eq!(
            displays.len(),
            3,
            "all RuntimeLane variants produce distinct Display strings"
        );
    }

    #[test]
    fn enrichment_charter_schema_version_matches_constant() {
        let charter = CharterBuilder::new(test_epoch())
            .ownership(OwnershipDomain::ExecutionCorrectness)
            .build();
        assert_eq!(charter.schema_version, SCHEMA_VERSION);
    }

    // ── Enrichment: FailureAction serde ──────────────────────────────

    #[test]
    fn failure_action_fallback_to_lane_serde_roundtrip() {
        let action = FailureAction::FallbackToLane(RuntimeLane::Wasm);
        let json = serde_json::to_string(&action).unwrap();
        let back: FailureAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, back);
    }

    #[test]
    fn failure_action_all_variants_serde_roundtrip() {
        let variants = [
            FailureAction::LogAndContinue,
            FailureAction::FallbackToLane(RuntimeLane::Js),
            FailureAction::FallbackToLane(RuntimeLane::Wasm),
            FailureAction::ActivateSafeMode,
            FailureAction::ForceTerminate,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: FailureAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn failure_action_display_all_unique() {
        let variants = [
            FailureAction::LogAndContinue,
            FailureAction::FallbackToLane(RuntimeLane::Js),
            FailureAction::FallbackToLane(RuntimeLane::Wasm),
            FailureAction::ActivateSafeMode,
            FailureAction::ForceTerminate,
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    // ── Enrichment: InvariantKind ────────────────────────────────────

    #[test]
    fn invariant_kind_serde_roundtrip_all() {
        let variants = [
            InvariantKind::SemanticDivergence,
            InvariantKind::SchedulerNondeterminism,
            InvariantKind::BudgetExceeded,
            InvariantKind::AbiMismatch,
            InvariantKind::TraceEmissionFailure,
            InvariantKind::RoutingInconsistency,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: InvariantKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn invariant_kind_display_all_unique() {
        let variants = [
            InvariantKind::SemanticDivergence,
            InvariantKind::SchedulerNondeterminism,
            InvariantKind::BudgetExceeded,
            InvariantKind::AbiMismatch,
            InvariantKind::TraceEmissionFailure,
            InvariantKind::RoutingInconsistency,
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), 6);
    }

    #[test]
    fn invariant_kind_ordering() {
        assert!(InvariantKind::SemanticDivergence < InvariantKind::SchedulerNondeterminism);
        assert!(InvariantKind::BudgetExceeded < InvariantKind::AbiMismatch);
    }

    // ── Enrichment: OwnershipDomain ordering ─────────────────────────

    #[test]
    fn ownership_domain_ordering_chain() {
        assert!(OwnershipDomain::ExecutionCorrectness < OwnershipDomain::FootprintBudget);
        assert!(OwnershipDomain::FootprintBudget < OwnershipDomain::SchedulerDeterminism);
    }

    #[test]
    fn ownership_domain_display_all_unique() {
        let domains = [
            OwnershipDomain::ExecutionCorrectness,
            OwnershipDomain::FootprintBudget,
            OwnershipDomain::SchedulerDeterminism,
            OwnershipDomain::AbiStability,
            OwnershipDomain::FailoverBehavior,
            OwnershipDomain::RoutingPolicy,
            OwnershipDomain::TraceEmission,
            OwnershipDomain::IncidentResponse,
        ];
        let mut set = BTreeSet::new();
        for d in &domains {
            set.insert(d.to_string());
        }
        assert_eq!(set.len(), 8);
    }

    // ── Enrichment: FootprintBudget check_usage ──────────────────────

    #[test]
    fn budget_check_usage_exact_boundary_passes() {
        let budget = FootprintBudget::js_default();
        let usage = ResourceUsage {
            heap_bytes: budget.max_heap_bytes,
            stack_frames: budget.max_stack_frames,
            update_cycle_micros: budget.max_update_cycle_micros,
            dom_patches: budget.max_dom_patches_per_cycle,
        };
        let result = budget.check_usage(&usage);
        assert!(result.within_budget);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn budget_check_usage_single_dom_patch_violation() {
        let budget = FootprintBudget::js_default();
        let usage = ResourceUsage {
            heap_bytes: 0,
            stack_frames: 0,
            update_cycle_micros: 0,
            dom_patches: budget.max_dom_patches_per_cycle + 1,
        };
        let result = budget.check_usage(&usage);
        assert!(!result.within_budget);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.violations[0].resource, "dom_patches");
    }

    #[test]
    fn budget_check_usage_all_zeros_passes() {
        let budget = FootprintBudget::wasm_default();
        let usage = ResourceUsage {
            heap_bytes: 0,
            stack_frames: 0,
            update_cycle_micros: 0,
            dom_patches: 0,
        };
        let result = budget.check_usage(&usage);
        assert!(result.within_budget);
    }

    // ── Enrichment: LaneInputContract ────────────────────────────────

    #[test]
    fn js_and_wasm_input_contracts_differ() {
        let js = LaneInputContract::js_default();
        let wasm = LaneInputContract::wasm_default();
        assert_ne!(js, wasm);
        // WASM requires compiler witness; JS does not
        assert!(!js.requires_compiler_witness);
        assert!(wasm.requires_compiler_witness);
    }

    #[test]
    fn input_contract_serde_roundtrip() {
        let contract = LaneInputContract::hybrid_router_default();
        let json = serde_json::to_string(&contract).unwrap();
        let back: LaneInputContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract, back);
    }

    // ── Enrichment: LaneOutputContract ───────────────────────────────

    #[test]
    fn hybrid_router_output_contract_no_signal_graph() {
        let out = LaneOutputContract::hybrid_router_default();
        assert!(!out.required_outputs.contains("signal_graph_snapshot"));
    }

    #[test]
    fn output_contract_serde_roundtrip() {
        let contract = LaneOutputContract::wasm_default();
        let json = serde_json::to_string(&contract).unwrap();
        let back: LaneOutputContract = serde_json::from_str(&json).unwrap();
        assert_eq!(contract, back);
    }

    // ── Enrichment: BudgetViolation / BudgetCheckResult serde ────────

    #[test]
    fn budget_violation_serde_roundtrip() {
        let v = BudgetViolation {
            resource: "heap_bytes".into(),
            limit: 1024,
            observed: 2048,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: BudgetViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn budget_check_result_serde_roundtrip() {
        let r = BudgetCheckResult {
            lane: RuntimeLane::Js,
            within_budget: false,
            violations: vec![BudgetViolation {
                resource: "stack_frames".into(),
                limit: 256,
                observed: 300,
            }],
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: BudgetCheckResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // ── Enrichment: InputValidation / OutputValidation serde ─────────

    #[test]
    fn input_validation_serde_roundtrip() {
        let iv = InputValidation {
            lane: RuntimeLane::Wasm,
            satisfied: false,
            missing_inputs: BTreeSet::from(["wasm_module".to_string()]),
        };
        let json = serde_json::to_string(&iv).unwrap();
        let back: InputValidation = serde_json::from_str(&json).unwrap();
        assert_eq!(iv, back);
    }

    #[test]
    fn output_validation_serde_roundtrip() {
        let ov = OutputValidation {
            lane: RuntimeLane::Js,
            satisfied: true,
            missing_outputs: BTreeSet::new(),
        };
        let json = serde_json::to_string(&ov).unwrap();
        let back: OutputValidation = serde_json::from_str(&json).unwrap();
        assert_eq!(ov, back);
    }

    // ── Enrichment: RuntimeLane serde ────────────────────────────────

    #[test]
    fn runtime_lane_serde_roundtrip_all() {
        for lane in [
            RuntimeLane::Js,
            RuntimeLane::Wasm,
            RuntimeLane::HybridRouter,
        ] {
            let json = serde_json::to_string(&lane).unwrap();
            let back: RuntimeLane = serde_json::from_str(&json).unwrap();
            assert_eq!(lane, back);
        }
    }
}
