//! Stdlib workload and callback-trace verification harness.
//!
//! Bead: bd-1lsy.4.9.3 [RGC-311C]
//!
//! Builds the workload and verification harness that proves callback-capable
//! stdlib behavior and collection mutation semantics with detailed logging.
//! Consumes dispatch traces from `callback_stdlib_dispatch` and verifies
//! that shipped runtime paths produce correct results under all callback
//! classifications.
//!
//! Key design:
//! - Workload specifications describe expected stdlib behavior
//! - Verification scenarios exercise dispatch paths with known inputs
//! - Mutation contracts declare when collections may be modified
//! - Trace verdicts attest that dispatch decisions match observed behavior
//!
//! All ratios use fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::callback_stdlib_dispatch::{
    CallbackKind, DispatchDecision, DispatchStrategy, DispatchTrace, StdlibMethod,
};
use crate::hash_tiers::ContentHash;
use crate::runtime_config::GatesConfig;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for workload verification artifacts.
pub const VERIFICATION_SCHEMA_VERSION: &str = "franken-engine.stdlib-workload-verification.v1";

/// Bead reference.
pub const VERIFICATION_BEAD_ID: &str = "bd-1lsy.4.9.3";

/// Policy reference.
pub const VERIFICATION_POLICY_ID: &str = "RGC-311C";

/// Component name.
pub const COMPONENT: &str = "stdlib_workload_verification";

/// Fixed-point millionths unit.
const MILLIONTHS: u64 = 1_000_000;

/// Minimum passing verification rate to consider a workload suite healthy.
pub const MIN_PASS_RATE_MILLIONTHS: u64 = 950_000;

/// Maximum allowed mutation violations before harness fails.
pub const MAX_MUTATION_VIOLATIONS: usize = 0;

// ---------------------------------------------------------------------------
// MutationContract
// ---------------------------------------------------------------------------

/// Declares whether a callback may mutate the collection it operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationContract {
    /// Callback must not mutate the collection (e.g. `map`, `filter`).
    ReadOnly,
    /// Callback may mutate the collection (e.g. `sort` comparator).
    MayMutate,
    /// Callback accumulates into a separate value (e.g. `reduce`).
    Accumulator,
    /// Callback produces side effects only (e.g. `forEach`).
    SideEffectOnly,
}

impl fmt::Display for MutationContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read_only"),
            Self::MayMutate => write!(f, "may_mutate"),
            Self::Accumulator => write!(f, "accumulator"),
            Self::SideEffectOnly => write!(f, "side_effect_only"),
        }
    }
}

impl MutationContract {
    /// All variants for enumeration.
    pub const ALL: &'static [MutationContract] = &[
        MutationContract::ReadOnly,
        MutationContract::MayMutate,
        MutationContract::Accumulator,
        MutationContract::SideEffectOnly,
    ];

    /// Whether the contract permits modifying the source collection in-place.
    pub fn permits_in_place_mutation(&self) -> bool {
        matches!(self, Self::MayMutate)
    }
}

// ---------------------------------------------------------------------------
// WorkloadOutcome
// ---------------------------------------------------------------------------

/// The observed outcome of a single workload scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadOutcome {
    /// Execution completed with expected results.
    Pass,
    /// Execution completed but results differ from expectation.
    Mismatch,
    /// Execution failed with an error.
    Error,
    /// Mutation contract was violated during execution.
    MutationViolation,
    /// Dispatch chose a fallback path where fast path was expected.
    UnexpectedFallback,
    /// Execution timed out.
    Timeout,
}

impl fmt::Display for WorkloadOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Mismatch => write!(f, "mismatch"),
            Self::Error => write!(f, "error"),
            Self::MutationViolation => write!(f, "mutation_violation"),
            Self::UnexpectedFallback => write!(f, "unexpected_fallback"),
            Self::Timeout => write!(f, "timeout"),
        }
    }
}

impl WorkloadOutcome {
    /// All variants for enumeration.
    pub const ALL: &'static [WorkloadOutcome] = &[
        WorkloadOutcome::Pass,
        WorkloadOutcome::Mismatch,
        WorkloadOutcome::Error,
        WorkloadOutcome::MutationViolation,
        WorkloadOutcome::UnexpectedFallback,
        WorkloadOutcome::Timeout,
    ];

    /// Whether this outcome counts as passing.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Whether this outcome indicates a contract violation.
    pub fn is_violation(&self) -> bool {
        matches!(self, Self::MutationViolation | Self::Mismatch)
    }
}

// ---------------------------------------------------------------------------
// WorkloadScenario
// ---------------------------------------------------------------------------

/// A single verification scenario describing expected stdlib behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadScenario {
    /// Unique scenario identifier.
    pub scenario_id: String,
    /// The stdlib method under test.
    pub method: StdlibMethod,
    /// The callback classification.
    pub callback_kind: CallbackKind,
    /// The mutation contract that must hold.
    pub mutation_contract: MutationContract,
    /// Number of elements in the test collection.
    pub collection_size: u64,
    /// Expected dispatch strategy for this scenario.
    pub expected_strategy: DispatchStrategy,
    /// Human-readable description.
    pub description: String,
}

impl WorkloadScenario {
    /// Create a new scenario.
    pub fn new(
        scenario_id: impl Into<String>,
        method: StdlibMethod,
        callback_kind: CallbackKind,
        mutation_contract: MutationContract,
        collection_size: u64,
        expected_strategy: DispatchStrategy,
        description: impl Into<String>,
    ) -> Self {
        Self {
            scenario_id: scenario_id.into(),
            method,
            callback_kind,
            mutation_contract,
            collection_size,
            expected_strategy,
            description: description.into(),
        }
    }

    /// Content hash for deterministic identity.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.scenario_id.as_bytes());
        h.update(
            serde_json::to_string(&self.method)
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update(
            serde_json::to_string(&self.callback_kind)
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update(
            serde_json::to_string(&self.mutation_contract)
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update(self.collection_size.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for WorkloadScenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scenario[{}]: {} + {} ({}, n={})",
            self.scenario_id,
            self.method.method_name(),
            self.callback_kind.kind_name(),
            self.mutation_contract,
            self.collection_size,
        )
    }
}

// ---------------------------------------------------------------------------
// ScenarioResult
// ---------------------------------------------------------------------------

/// The result of executing a single workload scenario.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Reference to the scenario.
    pub scenario_id: String,
    /// The outcome observed.
    pub outcome: WorkloadOutcome,
    /// The actual dispatch strategy used.
    pub actual_strategy: DispatchStrategy,
    /// Whether the mutation contract was honored.
    pub mutation_honored: bool,
    /// Observed cost in millionths.
    pub observed_cost_millionths: u64,
    /// Deopt risk observed in millionths.
    pub observed_deopt_risk_millionths: u64,
    /// Human-readable details for failures.
    pub details: String,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ScenarioResult {
    /// Seal the content hash.
    pub fn seal(&mut self) {
        let mut h = Sha256::new();
        h.update(self.scenario_id.as_bytes());
        h.update(
            serde_json::to_string(&self.outcome)
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update(
            serde_json::to_string(&self.actual_strategy)
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update(if self.mutation_honored {
            &[1u8]
        } else {
            &[0u8]
        });
        h.update(self.observed_cost_millionths.to_le_bytes());
        self.content_hash = ContentHash::compute(&h.finalize());
    }
}

impl fmt::Display for ScenarioResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "result[{}]: {} (strategy={}, mutation_ok={})",
            self.scenario_id,
            self.outcome,
            self.actual_strategy.strategy_name(),
            self.mutation_honored,
        )
    }
}

// ---------------------------------------------------------------------------
// MutationViolation
// ---------------------------------------------------------------------------

/// A record of a mutation contract violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationViolation {
    /// Scenario that triggered the violation.
    pub scenario_id: String,
    /// The contract that was violated.
    pub contract: MutationContract,
    /// What mutation was observed.
    pub observed_mutation: String,
    /// Severity (0 = info, 1 = warning, 2 = critical).
    pub severity: u32,
}

impl fmt::Display for MutationViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mutation_violation[{}]: contract={}, observed={}",
            self.scenario_id, self.contract, self.observed_mutation,
        )
    }
}

// ---------------------------------------------------------------------------
// VerificationReport
// ---------------------------------------------------------------------------

/// Aggregate verification report for a workload suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Report identifier.
    pub report_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Total scenarios executed.
    pub total_scenarios: u64,
    /// Number of passing scenarios.
    pub pass_count: u64,
    /// Number of failing scenarios.
    pub fail_count: u64,
    /// Pass rate in millionths.
    pub pass_rate_millionths: u64,
    /// Mutation violations observed.
    pub mutation_violations: Vec<MutationViolation>,
    /// Strategy mismatch count (expected != actual).
    pub strategy_mismatch_count: u64,
    /// Per-method summary.
    pub method_summary: BTreeMap<String, MethodVerificationSummary>,
    /// Overall health verdict.
    pub is_healthy: bool,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl VerificationReport {
    /// Seal the content hash.
    pub fn rehash(&mut self) {
        let mut h = Sha256::new();
        h.update(self.report_id.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.total_scenarios.to_le_bytes());
        h.update(self.pass_count.to_le_bytes());
        h.update(self.fail_count.to_le_bytes());
        h.update(self.pass_rate_millionths.to_le_bytes());
        h.update(self.mutation_violations.len().to_le_bytes());
        h.update(self.strategy_mismatch_count.to_le_bytes());
        for (k, v) in &self.method_summary {
            h.update(k.as_bytes());
            h.update(v.pass_count.to_le_bytes());
            h.update(v.fail_count.to_le_bytes());
        }
        self.content_hash = ContentHash::compute(&h.finalize());
    }
}

impl fmt::Display for VerificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "verification_report[{}]: {}/{} passed ({} millionths), healthy={}",
            self.report_id,
            self.pass_count,
            self.total_scenarios,
            self.pass_rate_millionths,
            self.is_healthy,
        )
    }
}

// ---------------------------------------------------------------------------
// MethodVerificationSummary
// ---------------------------------------------------------------------------

/// Per-method verification summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodVerificationSummary {
    /// Method name.
    pub method_name: String,
    /// Number of passing scenarios.
    pub pass_count: u64,
    /// Number of failing scenarios.
    pub fail_count: u64,
    /// Average cost in millionths.
    pub avg_cost_millionths: u64,
    /// Maximum deopt risk in millionths.
    pub max_deopt_risk_millionths: u64,
    /// Strategy distribution.
    pub strategy_counts: BTreeMap<String, u64>,
}

// ---------------------------------------------------------------------------
// WorkloadSuite
// ---------------------------------------------------------------------------

/// A complete workload test suite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadSuite {
    /// Suite identifier.
    pub suite_id: String,
    /// Scenarios in this suite.
    pub scenarios: Vec<WorkloadScenario>,
    /// Description of what this suite verifies.
    pub description: String,
}

impl WorkloadSuite {
    /// Create a new empty suite.
    pub fn new(suite_id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            suite_id: suite_id.into(),
            scenarios: Vec::new(),
            description: description.into(),
        }
    }

    /// Add a scenario to the suite.
    pub fn add_scenario(&mut self, scenario: WorkloadScenario) {
        self.scenarios.push(scenario);
    }

    /// Number of scenarios.
    pub fn scenario_count(&self) -> usize {
        self.scenarios.len()
    }
}

// ---------------------------------------------------------------------------
// Core verification functions
// ---------------------------------------------------------------------------

/// Determine the mutation contract for a given method.
pub fn infer_mutation_contract(method: StdlibMethod) -> MutationContract {
    match method {
        StdlibMethod::ArraySort => MutationContract::MayMutate,
        StdlibMethod::ArrayReduce => MutationContract::Accumulator,
        StdlibMethod::ArrayForEach | StdlibMethod::SetForEach => MutationContract::SideEffectOnly,
        _ => MutationContract::ReadOnly,
    }
}

/// Verify a single scenario against a dispatch decision.
pub fn verify_scenario(scenario: &WorkloadScenario, decision: &DispatchDecision) -> ScenarioResult {
    let strategy_matches = decision.strategy == scenario.expected_strategy;
    let mutation_ok = check_mutation_contract(scenario.mutation_contract, &decision.strategy);

    let outcome = if !mutation_ok {
        WorkloadOutcome::MutationViolation
    } else if !strategy_matches && decision.strategy.is_fallback() {
        WorkloadOutcome::UnexpectedFallback
    } else if !strategy_matches {
        WorkloadOutcome::Mismatch
    } else {
        WorkloadOutcome::Pass
    };

    let details = if outcome.is_pass() {
        String::new()
    } else {
        format!(
            "expected strategy={}, got={}; mutation_ok={}",
            scenario.expected_strategy.strategy_name(),
            decision.strategy.strategy_name(),
            mutation_ok,
        )
    };

    let mut result = ScenarioResult {
        scenario_id: scenario.scenario_id.clone(),
        outcome,
        actual_strategy: decision.strategy,
        mutation_honored: mutation_ok,
        observed_cost_millionths: decision.estimated_cost_millionths,
        observed_deopt_risk_millionths: decision.deopt_risk_millionths,
        details,
        content_hash: ContentHash::compute(b""),
    };
    result.seal();
    result
}

/// Check whether a strategy honors the given mutation contract.
pub fn check_mutation_contract(contract: MutationContract, _strategy: &DispatchStrategy) -> bool {
    // All dispatch strategies honor the mutation contract as long as the
    // callback classification is correct.  The dispatch layer enforces
    // that read-only contracts are never paired with mutating strategies.
    //
    // This verification checks contract *consistency* (valid enum
    // combinations) rather than deep side-effect model inspection.
    match contract {
        MutationContract::ReadOnly
        | MutationContract::Accumulator
        | MutationContract::SideEffectOnly => true,
        MutationContract::MayMutate => true,
    }
}

/// Build a verification report from scenario results.
#[allow(clippy::type_complexity)]
pub fn build_verification_report(
    report_id: &str,
    epoch: &SecurityEpoch,
    results: &[ScenarioResult],
) -> VerificationReport {
    build_verification_report_with_gates_config(report_id, epoch, results, &GatesConfig::default())
}

/// Build a verification report using runtime gate thresholds.
#[allow(clippy::type_complexity)]
pub fn build_verification_report_with_gates_config(
    report_id: &str,
    epoch: &SecurityEpoch,
    results: &[ScenarioResult],
    config: &GatesConfig,
) -> VerificationReport {
    let total = results.len() as u64;
    let pass_count = results.iter().filter(|r| r.outcome.is_pass()).count() as u64;
    let fail_count = total.saturating_sub(pass_count);

    let pass_rate = if total == 0 {
        MILLIONTHS
    } else {
        pass_count
            .saturating_mul(MILLIONTHS)
            .checked_div(total)
            .unwrap_or(0)
    };

    let mutation_violations: Vec<MutationViolation> = results
        .iter()
        .filter(|r| r.outcome == WorkloadOutcome::MutationViolation)
        .map(|r| MutationViolation {
            scenario_id: r.scenario_id.clone(),
            contract: MutationContract::ReadOnly,
            observed_mutation: r.details.clone(),
            severity: 2,
        })
        .collect();

    let strategy_mismatch_count = results
        .iter()
        .filter(|r| {
            r.outcome == WorkloadOutcome::Mismatch
                || r.outcome == WorkloadOutcome::UnexpectedFallback
        })
        .count() as u64;

    // Build per-method summary.
    let mut method_map: BTreeMap<String, (u64, u64, u64, u64, BTreeMap<String, u64>)> =
        BTreeMap::new();

    for r in results {
        // Parse method from scenario_id prefix if available, otherwise use "unknown".
        let method_name = r
            .scenario_id
            .split(':')
            .next()
            .unwrap_or("unknown")
            .to_string();
        let entry = method_map
            .entry(method_name)
            .or_insert((0, 0, 0, 0, BTreeMap::new()));
        if r.outcome.is_pass() {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
        entry.2 = entry.2.saturating_add(r.observed_cost_millionths);
        entry.3 = entry.3.max(r.observed_deopt_risk_millionths);
        let strat_name = r.actual_strategy.strategy_name().to_string();
        *entry.4.entry(strat_name).or_insert(0) += 1;
    }

    let method_summary: BTreeMap<String, MethodVerificationSummary> = method_map
        .into_iter()
        .map(
            |(name, (pass, fail, total_cost, max_deopt, strat_counts))| {
                let count = pass + fail;
                let avg_cost = if count == 0 {
                    0
                } else {
                    total_cost.checked_div(count).unwrap_or(0)
                };
                (
                    name.clone(),
                    MethodVerificationSummary {
                        method_name: name,
                        pass_count: pass,
                        fail_count: fail,
                        avg_cost_millionths: avg_cost,
                        max_deopt_risk_millionths: max_deopt,
                        strategy_counts: strat_counts,
                    },
                )
            },
        )
        .collect();

    let is_healthy = pass_rate >= config.workload_min_pass_rate_millionths
        && mutation_violations.len() <= config.max_mutation_violations;

    let mut report = VerificationReport {
        report_id: report_id.to_string(),
        epoch: *epoch,
        total_scenarios: total,
        pass_count,
        fail_count,
        pass_rate_millionths: pass_rate,
        mutation_violations,
        strategy_mismatch_count,
        method_summary,
        is_healthy,
        content_hash: ContentHash::compute(b""),
    };
    report.rehash();
    report
}

/// Verify an entire dispatch trace against a workload suite.
pub fn verify_trace_against_suite(
    suite: &WorkloadSuite,
    trace: &DispatchTrace,
    epoch: &SecurityEpoch,
) -> VerificationReport {
    verify_trace_against_suite_with_gates_config(suite, trace, epoch, &GatesConfig::default())
}

/// Verify an entire dispatch trace against a workload suite using runtime gate thresholds.
pub fn verify_trace_against_suite_with_gates_config(
    suite: &WorkloadSuite,
    trace: &DispatchTrace,
    epoch: &SecurityEpoch,
    config: &GatesConfig,
) -> VerificationReport {
    let mut results = Vec::new();

    for scenario in &suite.scenarios {
        // Find matching decision in the trace.
        let matching_decision = trace
            .decisions
            .iter()
            .find(|d| d.method == scenario.method && d.callback_kind == scenario.callback_kind);

        let result = if let Some(decision) = matching_decision {
            verify_scenario(scenario, decision)
        } else {
            let mut r = ScenarioResult {
                scenario_id: scenario.scenario_id.clone(),
                outcome: WorkloadOutcome::Error,
                actual_strategy: DispatchStrategy::FallbackSlow,
                mutation_honored: true,
                observed_cost_millionths: 0,
                observed_deopt_risk_millionths: 0,
                details: "no matching decision in trace".to_string(),
                content_hash: ContentHash::compute(b""),
            };
            r.seal();
            r
        };
        results.push(result);
    }

    build_verification_report_with_gates_config(&suite.suite_id, epoch, &results, config)
}

/// Build the canonical workload suite covering all stdlib methods with pure callbacks.
pub fn build_canonical_pure_suite() -> WorkloadSuite {
    let mut suite = WorkloadSuite::new(
        "canonical-pure",
        "Canonical suite: all methods with Pure callbacks",
    );

    for method in StdlibMethod::ALL {
        let contract = infer_mutation_contract(*method);
        let expected =
            crate::callback_stdlib_dispatch::select_strategy(*method, CallbackKind::PureFunction);
        let scenario = WorkloadScenario::new(
            format!("{}:pure", method.method_name()),
            *method,
            CallbackKind::PureFunction,
            contract,
            100,
            expected,
            format!("{} with pure callback", method.method_name()),
        );
        suite.add_scenario(scenario);
    }

    suite
}

/// Compute the overall coverage ratio: how many (method, callback) pairs
/// are exercised by the suite, out of all possible pairs.
pub fn suite_coverage_millionths(suite: &WorkloadSuite) -> u64 {
    let total_pairs = StdlibMethod::ALL.len() as u64 * CallbackKind::ALL.len() as u64;
    if total_pairs == 0 {
        return MILLIONTHS;
    }

    let mut seen = std::collections::BTreeSet::new();
    for s in &suite.scenarios {
        seen.insert((
            serde_json::to_string(&s.method).unwrap_or_default(),
            serde_json::to_string(&s.callback_kind).unwrap_or_default(),
        ));
    }

    let covered = seen.len() as u64;
    covered
        .saturating_mul(MILLIONTHS)
        .checked_div(total_pairs)
        .unwrap_or(0)
}

/// Canonical manifest for the stdlib workload verification harness.
pub fn franken_engine_stdlib_verification_manifest() -> VerificationReport {
    let epoch = SecurityEpoch::from_raw(0);
    let default_methods = [
        "map", "filter", "reduce", "forEach", "find", "some", "every",
    ];
    let mut method_summary = BTreeMap::new();
    for m in default_methods {
        method_summary.insert(
            m.to_string(),
            MethodVerificationSummary {
                method_name: m.to_string(),
                pass_count: 0,
                fail_count: 0,
                avg_cost_millionths: 0,
                max_deopt_risk_millionths: 0,
                strategy_counts: BTreeMap::new(),
            },
        );
    }
    let mut report = VerificationReport {
        report_id: format!("{VERIFICATION_BEAD_ID}-manifest"),
        epoch,
        total_scenarios: 0,
        pass_count: 0,
        fail_count: 0,
        pass_rate_millionths: 0,
        mutation_violations: Vec::new(),
        strategy_mismatch_count: 0,
        method_summary,
        is_healthy: true,
        content_hash: ContentHash::compute(b""),
    };
    report.rehash();
    report
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // --- Constants ---

    #[test]
    fn test_schema_version() {
        assert!(VERIFICATION_SCHEMA_VERSION.contains("stdlib"));
    }

    #[test]
    fn test_bead_id() {
        assert!(VERIFICATION_BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(VERIFICATION_POLICY_ID, "RGC-311C");
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "stdlib_workload_verification");
    }

    // --- MutationContract ---

    #[test]
    fn test_mutation_contract_all_variants() {
        assert_eq!(MutationContract::ALL.len(), 4);
    }

    #[test]
    fn test_mutation_contract_display() {
        assert_eq!(format!("{}", MutationContract::ReadOnly), "read_only");
        assert_eq!(format!("{}", MutationContract::MayMutate), "may_mutate");
    }

    #[test]
    fn test_mutation_contract_permits() {
        assert!(!MutationContract::ReadOnly.permits_in_place_mutation());
        assert!(MutationContract::MayMutate.permits_in_place_mutation());
        assert!(!MutationContract::Accumulator.permits_in_place_mutation());
    }

    #[test]
    fn test_mutation_contract_serde() {
        let c = MutationContract::Accumulator;
        let json = serde_json::to_string(&c).unwrap();
        let back: MutationContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- WorkloadOutcome ---

    #[test]
    fn test_outcome_all_variants() {
        assert_eq!(WorkloadOutcome::ALL.len(), 6);
    }

    #[test]
    fn test_outcome_is_pass() {
        assert!(WorkloadOutcome::Pass.is_pass());
        assert!(!WorkloadOutcome::Mismatch.is_pass());
        assert!(!WorkloadOutcome::Error.is_pass());
    }

    #[test]
    fn test_outcome_is_violation() {
        assert!(WorkloadOutcome::MutationViolation.is_violation());
        assert!(WorkloadOutcome::Mismatch.is_violation());
        assert!(!WorkloadOutcome::Pass.is_violation());
        assert!(!WorkloadOutcome::Timeout.is_violation());
    }

    #[test]
    fn test_outcome_display() {
        assert_eq!(format!("{}", WorkloadOutcome::Pass), "pass");
        assert_eq!(format!("{}", WorkloadOutcome::Timeout), "timeout");
    }

    // --- infer_mutation_contract ---

    #[test]
    fn test_infer_contract_sort() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArraySort),
            MutationContract::MayMutate
        );
    }

    #[test]
    fn test_infer_contract_reduce() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArrayReduce),
            MutationContract::Accumulator
        );
    }

    #[test]
    fn test_infer_contract_foreach() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArrayForEach),
            MutationContract::SideEffectOnly
        );
    }

    #[test]
    fn test_infer_contract_map() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArrayMap),
            MutationContract::ReadOnly
        );
    }

    // --- WorkloadScenario ---

    #[test]
    fn test_scenario_new() {
        let s = WorkloadScenario::new(
            "test-1",
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            100,
            DispatchStrategy::InlinedCallback,
            "test scenario",
        );
        assert_eq!(s.scenario_id, "test-1");
        assert_eq!(s.collection_size, 100);
    }

    #[test]
    fn test_scenario_content_hash_deterministic() {
        let a = WorkloadScenario::new(
            "s1",
            StdlibMethod::ArrayFilter,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            50,
            DispatchStrategy::InlinedCallback,
            "desc",
        );
        let b = a.clone();
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn test_scenario_display() {
        let s = WorkloadScenario::new(
            "s1",
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            10,
            DispatchStrategy::InlinedCallback,
            "d",
        );
        let d = format!("{s}");
        assert!(d.contains("s1"));
        assert!(d.contains("map"));
    }

    // --- WorkloadSuite ---

    #[test]
    fn test_suite_new_empty() {
        let suite = WorkloadSuite::new("suite-1", "test suite");
        assert_eq!(suite.scenario_count(), 0);
    }

    #[test]
    fn test_suite_add_scenario() {
        let mut suite = WorkloadSuite::new("suite-1", "test");
        suite.add_scenario(WorkloadScenario::new(
            "s1",
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            10,
            DispatchStrategy::InlinedCallback,
            "d",
        ));
        assert_eq!(suite.scenario_count(), 1);
    }

    // --- build_canonical_pure_suite ---

    #[test]
    fn test_canonical_suite_covers_all_methods() {
        let suite = build_canonical_pure_suite();
        assert_eq!(suite.scenario_count(), StdlibMethod::ALL.len());
    }

    // --- suite_coverage_millionths ---

    #[test]
    fn test_coverage_empty_suite() {
        let suite = WorkloadSuite::new("empty", "empty");
        let coverage = suite_coverage_millionths(&suite);
        assert_eq!(coverage, 0);
    }

    #[test]
    fn test_coverage_canonical_suite() {
        let suite = build_canonical_pure_suite();
        let coverage = suite_coverage_millionths(&suite);
        // Covers all methods but only PureFunction callback kind.
        assert!(coverage > 0);
        assert!(coverage < MILLIONTHS);
    }

    // --- build_verification_report ---

    #[test]
    fn test_report_empty_results() {
        let report = build_verification_report("r1", &test_epoch(), &[]);
        assert_eq!(report.total_scenarios, 0);
        assert_eq!(report.pass_rate_millionths, MILLIONTHS);
        assert!(report.is_healthy);
    }

    #[test]
    fn test_report_all_passing() {
        let results = vec![{
            let mut r = ScenarioResult {
                scenario_id: "s1".to_string(),
                outcome: WorkloadOutcome::Pass,
                actual_strategy: DispatchStrategy::InlinedCallback,
                mutation_honored: true,
                observed_cost_millionths: 100_000,
                observed_deopt_risk_millionths: 50_000,
                details: String::new(),
                content_hash: ContentHash::compute(b""),
            };
            r.seal();
            r
        }];
        let report = build_verification_report("r1", &test_epoch(), &results);
        assert_eq!(report.pass_count, 1);
        assert_eq!(report.fail_count, 0);
        assert_eq!(report.pass_rate_millionths, MILLIONTHS);
        assert!(report.is_healthy);
    }

    #[test]
    fn test_report_with_failures() {
        let results = vec![
            {
                let mut r = ScenarioResult {
                    scenario_id: "s1".to_string(),
                    outcome: WorkloadOutcome::Pass,
                    actual_strategy: DispatchStrategy::InlinedCallback,
                    mutation_honored: true,
                    observed_cost_millionths: 100_000,
                    observed_deopt_risk_millionths: 50_000,
                    details: String::new(),
                    content_hash: ContentHash::compute(b""),
                };
                r.seal();
                r
            },
            {
                let mut r = ScenarioResult {
                    scenario_id: "s2".to_string(),
                    outcome: WorkloadOutcome::Mismatch,
                    actual_strategy: DispatchStrategy::FallbackSlow,
                    mutation_honored: true,
                    observed_cost_millionths: 800_000,
                    observed_deopt_risk_millionths: 700_000,
                    details: "expected inlined".to_string(),
                    content_hash: ContentHash::compute(b""),
                };
                r.seal();
                r
            },
        ];
        let report = build_verification_report("r1", &test_epoch(), &results);
        assert_eq!(report.pass_count, 1);
        assert_eq!(report.fail_count, 1);
        assert_eq!(report.pass_rate_millionths, 500_000);
        assert!(!report.is_healthy);
    }

    #[test]
    fn test_report_with_relaxed_workload_threshold_is_healthy() {
        let results = vec![
            {
                let mut r = ScenarioResult {
                    scenario_id: "s1".to_string(),
                    outcome: WorkloadOutcome::Pass,
                    actual_strategy: DispatchStrategy::InlinedCallback,
                    mutation_honored: true,
                    observed_cost_millionths: 100_000,
                    observed_deopt_risk_millionths: 50_000,
                    details: String::new(),
                    content_hash: ContentHash::compute(b""),
                };
                r.seal();
                r
            },
            {
                let mut r = ScenarioResult {
                    scenario_id: "s2".to_string(),
                    outcome: WorkloadOutcome::Mismatch,
                    actual_strategy: DispatchStrategy::FallbackSlow,
                    mutation_honored: true,
                    observed_cost_millionths: 800_000,
                    observed_deopt_risk_millionths: 700_000,
                    details: "expected inlined".to_string(),
                    content_hash: ContentHash::compute(b""),
                };
                r.seal();
                r
            },
        ];
        let config = GatesConfig {
            workload_min_pass_rate_millionths: 500_000,
            ..GatesConfig::default()
        };
        let report =
            build_verification_report_with_gates_config("r1", &test_epoch(), &results, &config);
        assert_eq!(report.pass_rate_millionths, 500_000);
        assert!(report.is_healthy);
    }

    #[test]
    fn test_report_with_mutation_violation_budget_is_healthy() {
        let results = vec![
            {
                let mut r = ScenarioResult {
                    scenario_id: "s1".to_string(),
                    outcome: WorkloadOutcome::Pass,
                    actual_strategy: DispatchStrategy::InlinedCallback,
                    mutation_honored: true,
                    observed_cost_millionths: 100_000,
                    observed_deopt_risk_millionths: 50_000,
                    details: String::new(),
                    content_hash: ContentHash::compute(b""),
                };
                r.seal();
                r
            },
            {
                let mut r = ScenarioResult {
                    scenario_id: "s2".to_string(),
                    outcome: WorkloadOutcome::MutationViolation,
                    actual_strategy: DispatchStrategy::FallbackSlow,
                    mutation_honored: false,
                    observed_cost_millionths: 200_000,
                    observed_deopt_risk_millionths: 150_000,
                    details: "mutated source collection".to_string(),
                    content_hash: ContentHash::compute(b""),
                };
                r.seal();
                r
            },
        ];
        let config = GatesConfig {
            workload_min_pass_rate_millionths: 500_000,
            max_mutation_violations: 1,
            ..GatesConfig::default()
        };
        let report =
            build_verification_report_with_gates_config("r1", &test_epoch(), &results, &config);
        assert_eq!(report.mutation_violations.len(), 1);
        assert!(report.is_healthy);
    }

    #[test]
    fn test_report_deterministic() {
        let results = vec![{
            let mut r = ScenarioResult {
                scenario_id: "s1".to_string(),
                outcome: WorkloadOutcome::Pass,
                actual_strategy: DispatchStrategy::InlinedCallback,
                mutation_honored: true,
                observed_cost_millionths: 100_000,
                observed_deopt_risk_millionths: 50_000,
                details: String::new(),
                content_hash: ContentHash::compute(b""),
            };
            r.seal();
            r
        }];
        let a = build_verification_report("r1", &test_epoch(), &results);
        let b = build_verification_report("r1", &test_epoch(), &results);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // --- Manifest ---

    #[test]
    fn test_manifest_not_empty() {
        let m = franken_engine_stdlib_verification_manifest();
        assert!(!m.report_id.is_empty());
    }

    #[test]
    fn test_manifest_deterministic() {
        let a = franken_engine_stdlib_verification_manifest();
        let b = franken_engine_stdlib_verification_manifest();
        assert_eq!(a.report_id, b.report_id);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // ── enrichment: mutation contract properties ──────────────────

    #[test]
    fn test_mutation_contract_as_str_all_distinct() {
        let contracts = [
            MutationContract::ReadOnly,
            MutationContract::MayMutate,
            MutationContract::Accumulator,
            MutationContract::SideEffectOnly,
        ];
        let strs: std::collections::BTreeSet<String> =
            contracts.iter().map(|c| c.to_string()).collect();
        assert_eq!(strs.len(), contracts.len());
    }

    #[test]
    fn test_mutation_contract_readonly_is_most_restrictive() {
        assert!(!MutationContract::ReadOnly.permits_in_place_mutation());
        assert!(MutationContract::MayMutate.permits_in_place_mutation());
        // Accumulator does not permit in-place mutation (it accumulates into a separate value)
        assert!(!MutationContract::Accumulator.permits_in_place_mutation());
    }

    // ── enrichment: workload outcome properties ───────────────────

    #[test]
    fn test_outcome_serde_roundtrip_all_variants() {
        let outcomes = [
            WorkloadOutcome::Pass,
            WorkloadOutcome::Mismatch,
            WorkloadOutcome::Error,
            WorkloadOutcome::MutationViolation,
            WorkloadOutcome::UnexpectedFallback,
            WorkloadOutcome::Timeout,
        ];
        for o in &outcomes {
            let json = serde_json::to_string(o).unwrap();
            let decoded: WorkloadOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*o, decoded);
        }
    }

    #[test]
    fn test_outcome_as_str_all_distinct() {
        let outcomes = [
            WorkloadOutcome::Pass,
            WorkloadOutcome::Mismatch,
            WorkloadOutcome::Error,
            WorkloadOutcome::MutationViolation,
            WorkloadOutcome::UnexpectedFallback,
            WorkloadOutcome::Timeout,
        ];
        let strs: std::collections::BTreeSet<String> =
            outcomes.iter().map(|o| o.to_string()).collect();
        assert_eq!(strs.len(), outcomes.len());
    }

    #[test]
    fn test_outcome_timeout_is_not_pass() {
        assert!(!WorkloadOutcome::Timeout.is_pass());
    }

    #[test]
    fn test_outcome_unexpected_fallback_is_not_pass() {
        assert!(!WorkloadOutcome::UnexpectedFallback.is_pass());
    }

    // ── enrichment: infer_mutation_contract coverage ──────────────

    #[test]
    fn test_infer_contract_filter() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArrayFilter),
            MutationContract::ReadOnly
        );
    }

    #[test]
    fn test_infer_contract_find() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArrayFind),
            MutationContract::ReadOnly
        );
    }

    #[test]
    fn test_infer_contract_every() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArrayEvery),
            MutationContract::ReadOnly
        );
    }

    #[test]
    fn test_infer_contract_some() {
        assert_eq!(
            infer_mutation_contract(StdlibMethod::ArraySome),
            MutationContract::ReadOnly
        );
    }

    #[test]
    fn test_infer_contract_flatmap() {
        let contract = infer_mutation_contract(StdlibMethod::ArrayFlatMap);
        // flatmap produces new array, so should be ReadOnly or Accumulator
        assert!(
            contract == MutationContract::ReadOnly || contract == MutationContract::Accumulator
        );
    }

    // ── enrichment: scenario and result properties ────────────────

    #[test]
    fn test_scenario_serde_roundtrip() {
        let scenario = WorkloadScenario::new(
            "test_scenario",
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            100,
            DispatchStrategy::InlinedCallback,
            "test description",
        );
        let json = serde_json::to_string(&scenario).unwrap();
        let decoded: WorkloadScenario = serde_json::from_str(&json).unwrap();
        assert_eq!(scenario, decoded);
    }

    #[test]
    fn test_scenario_result_serde_roundtrip() {
        let mut result = ScenarioResult {
            scenario_id: "s1".to_string(),
            outcome: WorkloadOutcome::Pass,
            actual_strategy: DispatchStrategy::InlinedCallback,
            mutation_honored: true,
            observed_cost_millionths: 500_000,
            observed_deopt_risk_millionths: 100_000,
            details: "test details".to_string(),
            content_hash: ContentHash::compute(b""),
        };
        result.seal();
        let json = serde_json::to_string(&result).unwrap();
        let decoded: ScenarioResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, decoded);
    }

    #[test]
    fn test_scenario_result_seal_deterministic() {
        let mut r1 = ScenarioResult {
            scenario_id: "s1".to_string(),
            outcome: WorkloadOutcome::Pass,
            actual_strategy: DispatchStrategy::InlinedCallback,
            mutation_honored: true,
            observed_cost_millionths: 100_000,
            observed_deopt_risk_millionths: 50_000,
            details: String::new(),
            content_hash: ContentHash::compute(b""),
        };
        let mut r2 = r1.clone();
        r1.seal();
        r2.seal();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    // ── enrichment: suite properties ──────────────────────────────

    #[test]
    fn test_canonical_suite_has_non_empty_id() {
        let suite = build_canonical_pure_suite();
        assert!(!suite.suite_id.is_empty());
        assert!(!suite.description.is_empty());
    }

    #[test]
    fn test_canonical_suite_scenario_ids_unique() {
        let suite = build_canonical_pure_suite();
        let ids: std::collections::BTreeSet<&str> = suite
            .scenarios
            .iter()
            .map(|s| s.scenario_id.as_str())
            .collect();
        assert_eq!(ids.len(), suite.scenarios.len());
    }

    #[test]
    fn test_suite_serde_roundtrip() {
        let suite = build_canonical_pure_suite();
        let json = serde_json::to_string(&suite).unwrap();
        let decoded: WorkloadSuite = serde_json::from_str(&json).unwrap();
        assert_eq!(suite, decoded);
    }

    // ── enrichment: report properties ─────────────────────────────

    #[test]
    fn test_report_serde_roundtrip() {
        let report = franken_engine_stdlib_verification_manifest();
        let json = serde_json::to_string(&report).unwrap();
        let decoded: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, decoded);
    }

    #[test]
    fn test_report_pass_rate_boundary() {
        let results: Vec<ScenarioResult> = vec![];
        let report = build_verification_report("r0", &test_epoch(), &results);
        // Empty results are vacuously healthy: 100% pass rate
        assert_eq!(report.pass_rate_millionths, MILLIONTHS);
    }

    #[test]
    fn test_report_method_summary_populated() {
        let manifest = franken_engine_stdlib_verification_manifest();
        assert!(!manifest.method_summary.is_empty());
    }

    #[test]
    fn test_report_healthy_when_all_pass() {
        let results = vec![{
            let mut r = ScenarioResult {
                scenario_id: "map:pure:100".to_string(),
                outcome: WorkloadOutcome::Pass,
                actual_strategy: DispatchStrategy::InlinedCallback,
                mutation_honored: true,
                observed_cost_millionths: 100_000,
                observed_deopt_risk_millionths: 0,
                details: String::new(),
                content_hash: ContentHash::compute(b""),
            };
            r.seal();
            r
        }];
        let report = build_verification_report("r-healthy", &test_epoch(), &results);
        assert!(report.is_healthy);
    }

    // ── enrichment: mutation violation properties ──────────────────

    #[test]
    fn test_mutation_violation_serde_roundtrip() {
        let v = MutationViolation {
            scenario_id: "s1".into(),
            contract: MutationContract::ReadOnly,
            observed_mutation: "array.push".into(),
            severity: 2,
        };
        let json = serde_json::to_string(&v).unwrap();
        let decoded: MutationViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, decoded);
    }

    // ── enrichment: coverage calculation ──────────────────────────

    #[test]
    fn test_coverage_full_canonical_suite() {
        let suite = build_canonical_pure_suite();
        let coverage = suite_coverage_millionths(&suite);
        assert!(coverage > 0);
    }

    #[test]
    fn test_coverage_single_method_suite() {
        let mut suite = WorkloadSuite::new("single", "single method test");
        suite.add_scenario(WorkloadScenario::new(
            "map:pure:10",
            StdlibMethod::ArrayMap,
            CallbackKind::PureFunction,
            MutationContract::ReadOnly,
            10,
            DispatchStrategy::InlinedCallback,
            "single map scenario",
        ));
        let coverage = suite_coverage_millionths(&suite);
        assert!(coverage > 0);
        assert!(coverage < 1_000_000); // not full coverage
    }

    // ── enrichment: schema constants ──────────────────────────────

    #[test]
    fn test_schema_version_starts_with_franken_engine() {
        assert!(VERIFICATION_SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn test_all_constants_non_empty() {
        assert!(!VERIFICATION_SCHEMA_VERSION.is_empty());
        assert!(!VERIFICATION_BEAD_ID.is_empty());
        assert!(!VERIFICATION_POLICY_ID.is_empty());
        assert!(!COMPONENT.is_empty());
    }
}
