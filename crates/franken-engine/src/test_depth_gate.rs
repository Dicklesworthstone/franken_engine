// FRX-20.2: Unit-Test Depth Gate — Coverage, Mutation, and Failure-Mode Obligations
//
// Implements objective unit-test quality gates that block promotion when tests
// are shallow or brittle. Uses the test_taxonomy types from FRX-20.1.
//
// Plan reference: bd-mjh3.20.2

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use crate::test_taxonomy::{TestClass, TestSurface};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

pub const DEPTH_GATE_SCHEMA_VERSION: &str = "0.1.0";
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Coverage targets
// ---------------------------------------------------------------------------

/// Coverage metric kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoverageKind {
    /// Statement (line) coverage.
    Statement,
    /// Branch (decision) coverage.
    Branch,
    /// Path coverage (all feasible execution paths).
    Path,
}

impl CoverageKind {
    pub const ALL: &'static [CoverageKind] = &[
        CoverageKind::Statement,
        CoverageKind::Branch,
        CoverageKind::Path,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Statement => "statement",
            Self::Branch => "branch",
            Self::Path => "path",
        }
    }
}

impl fmt::Display for CoverageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Coverage target for a specific subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageTarget {
    /// Which surface this target applies to.
    pub surface: TestSurface,
    /// Coverage kind (statement, branch, path).
    pub kind: CoverageKind,
    /// Minimum coverage in millionths (1_000_000 = 100%).
    pub min_coverage_millionths: i64,
    /// Whether this target is a hard gate (blocks promotion).
    pub hard_gate: bool,
}

impl CoverageTarget {
    /// Validate internal consistency.
    #[must_use]
    pub fn validate(&self) -> Vec<DepthGateViolation> {
        let mut violations = Vec::new();
        if self.min_coverage_millionths < 0 {
            violations.push(DepthGateViolation {
                field: "min_coverage_millionths".to_string(),
                message: "coverage target must be non-negative".to_string(),
            });
        }
        if self.min_coverage_millionths > MILLION {
            violations.push(DepthGateViolation {
                field: "min_coverage_millionths".to_string(),
                message: "coverage target cannot exceed 100%".to_string(),
            });
        }
        violations
    }

    /// Check whether observed coverage meets this target.
    #[must_use]
    pub fn is_met(&self, observed_millionths: i64) -> bool {
        observed_millionths >= self.min_coverage_millionths
    }
}

/// Default coverage targets per surface.
#[must_use]
pub fn default_coverage_targets() -> Vec<CoverageTarget> {
    let mut targets = Vec::new();
    for surface in TestSurface::ALL {
        let (stmt, branch, path) = default_thresholds_for_surface(*surface);
        targets.push(CoverageTarget {
            surface: *surface,
            kind: CoverageKind::Statement,
            min_coverage_millionths: stmt,
            hard_gate: true,
        });
        targets.push(CoverageTarget {
            surface: *surface,
            kind: CoverageKind::Branch,
            min_coverage_millionths: branch,
            hard_gate: true,
        });
        targets.push(CoverageTarget {
            surface: *surface,
            kind: CoverageKind::Path,
            min_coverage_millionths: path,
            hard_gate: false, // path coverage is advisory
        });
    }
    targets
}

/// Default minimum coverage thresholds per surface (statement, branch, path) in millionths.
const fn default_thresholds_for_surface(surface: TestSurface) -> (i64, i64, i64) {
    match surface {
        // Critical security/governance surfaces require higher coverage
        TestSurface::Security => (900_000, 850_000, 500_000),
        TestSurface::Governance => (900_000, 850_000, 500_000),
        TestSurface::Evidence => (850_000, 800_000, 400_000),
        // Core execution surfaces
        TestSurface::Runtime => (850_000, 800_000, 400_000),
        TestSurface::Compiler => (850_000, 800_000, 400_000),
        TestSurface::Router => (800_000, 750_000, 350_000),
        TestSurface::Parser => (800_000, 750_000, 350_000),
        TestSurface::Scheduler => (800_000, 750_000, 350_000),
    }
}

// ---------------------------------------------------------------------------
// Mutation testing policy
// ---------------------------------------------------------------------------

/// Mutation testing severity tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MutationTier {
    /// Critical: any surviving mutant blocks promotion.
    Critical,
    /// High: mutation score must exceed threshold.
    High,
    /// Standard: mutation score tracked but advisory.
    Standard,
}

impl MutationTier {
    pub const ALL: &'static [MutationTier] = &[
        MutationTier::Critical,
        MutationTier::High,
        MutationTier::Standard,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Standard => "standard",
        }
    }

    /// Default mutation score threshold for this tier (in millionths).
    #[must_use]
    pub const fn default_threshold_millionths(&self) -> i64 {
        match self {
            Self::Critical => MILLION, // 100% — zero surviving mutants
            Self::High => 900_000,     // 90%
            Self::Standard => 750_000, // 75%
        }
    }
}

impl fmt::Display for MutationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Mutation testing policy for a subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationPolicy {
    /// Which surface this policy applies to.
    pub surface: TestSurface,
    /// Mutation tier.
    pub tier: MutationTier,
    /// Minimum mutation score in millionths (1_000_000 = 100%).
    pub min_score_millionths: i64,
    /// Whether this is a hard gate.
    pub hard_gate: bool,
    /// Module paths considered critical for this policy.
    pub critical_modules: BTreeSet<String>,
}

impl MutationPolicy {
    /// Validate internal consistency.
    #[must_use]
    pub fn validate(&self) -> Vec<DepthGateViolation> {
        let mut violations = Vec::new();
        if self.min_score_millionths < 0 {
            violations.push(DepthGateViolation {
                field: "min_score_millionths".to_string(),
                message: "mutation score threshold must be non-negative".to_string(),
            });
        }
        if self.min_score_millionths > MILLION {
            violations.push(DepthGateViolation {
                field: "min_score_millionths".to_string(),
                message: "mutation score cannot exceed 100%".to_string(),
            });
        }
        if self.tier == MutationTier::Critical && self.min_score_millionths < MILLION {
            violations.push(DepthGateViolation {
                field: "min_score_millionths".to_string(),
                message: "critical tier requires 100% mutation kill rate".to_string(),
            });
        }
        violations
    }

    /// Check whether observed mutation score meets this policy.
    #[must_use]
    pub fn is_met(&self, observed_score_millionths: i64) -> bool {
        observed_score_millionths >= self.min_score_millionths
    }
}

/// Default mutation policies for each surface.
#[must_use]
pub fn default_mutation_policies() -> Vec<MutationPolicy> {
    let mut policies = Vec::new();
    for surface in TestSurface::ALL {
        let (tier, hard) = default_mutation_tier_for_surface(*surface);
        policies.push(MutationPolicy {
            surface: *surface,
            tier,
            min_score_millionths: tier.default_threshold_millionths(),
            hard_gate: hard,
            critical_modules: BTreeSet::new(),
        });
    }
    policies
}

const fn default_mutation_tier_for_surface(surface: TestSurface) -> (MutationTier, bool) {
    match surface {
        TestSurface::Security | TestSurface::Governance => (MutationTier::Critical, true),
        TestSurface::Evidence | TestSurface::Runtime | TestSurface::Compiler => {
            (MutationTier::High, true)
        }
        TestSurface::Router | TestSurface::Parser | TestSurface::Scheduler => {
            (MutationTier::Standard, false)
        }
    }
}

// ---------------------------------------------------------------------------
// Failure-mode obligation taxonomy
// ---------------------------------------------------------------------------

/// Mandatory failure-mode test categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FailureMode {
    /// Timeout handling and deadline enforcement.
    Timeout,
    /// Cancellation propagation and cleanup.
    Cancellation,
    /// Semantic drift detection.
    Drift,
    /// Malformed or adversarial input handling.
    MalformedInput,
    /// Fallback trigger and safe-mode entry.
    FallbackTrigger,
    /// Resource exhaustion (memory, CPU budget).
    ResourceExhaustion,
    /// Concurrent/parallel interference.
    Interference,
    /// Rollback and undo correctness.
    Rollback,
}

impl FailureMode {
    pub const ALL: &'static [FailureMode] = &[
        FailureMode::Timeout,
        FailureMode::Cancellation,
        FailureMode::Drift,
        FailureMode::MalformedInput,
        FailureMode::FallbackTrigger,
        FailureMode::ResourceExhaustion,
        FailureMode::Interference,
        FailureMode::Rollback,
    ];

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Cancellation => "cancellation",
            Self::Drift => "drift",
            Self::MalformedInput => "malformed_input",
            Self::FallbackTrigger => "fallback_trigger",
            Self::ResourceExhaustion => "resource_exhaustion",
            Self::Interference => "interference",
            Self::Rollback => "rollback",
        }
    }

    /// Whether this failure mode is mandatory for a given surface.
    #[must_use]
    pub const fn is_mandatory_for(&self, surface: TestSurface) -> bool {
        match (self, surface) {
            // All surfaces must handle timeout, cancellation, malformed input
            (Self::Timeout, _) => true,
            (Self::Cancellation, _) => true,
            (Self::MalformedInput, _) => true,
            // Drift is mandatory for runtime, router, scheduler
            (Self::Drift, TestSurface::Runtime) => true,
            (Self::Drift, TestSurface::Router) => true,
            (Self::Drift, TestSurface::Scheduler) => true,
            (Self::Drift, _) => false,
            // Fallback is mandatory for runtime, router, security
            (Self::FallbackTrigger, TestSurface::Runtime) => true,
            (Self::FallbackTrigger, TestSurface::Router) => true,
            (Self::FallbackTrigger, TestSurface::Security) => true,
            (Self::FallbackTrigger, _) => false,
            // Resource exhaustion for runtime, scheduler, parser
            (Self::ResourceExhaustion, TestSurface::Runtime) => true,
            (Self::ResourceExhaustion, TestSurface::Scheduler) => true,
            (Self::ResourceExhaustion, TestSurface::Parser) => true,
            (Self::ResourceExhaustion, _) => false,
            // Interference for runtime, parser, scheduler
            (Self::Interference, TestSurface::Runtime) => true,
            (Self::Interference, TestSurface::Parser) => true,
            (Self::Interference, TestSurface::Scheduler) => true,
            (Self::Interference, _) => false,
            // Rollback for governance, evidence, security
            (Self::Rollback, TestSurface::Governance) => true,
            (Self::Rollback, TestSurface::Evidence) => true,
            (Self::Rollback, TestSurface::Security) => true,
            (Self::Rollback, _) => false,
        }
    }
}

impl fmt::Display for FailureMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Failure-mode obligation for a surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureModeObligation {
    /// Surface this obligation applies to.
    pub surface: TestSurface,
    /// Required failure modes.
    pub required_modes: BTreeSet<FailureMode>,
    /// Minimum test count per failure mode.
    pub min_tests_per_mode: u64,
}

impl FailureModeObligation {
    /// Build the default obligation for a surface.
    #[must_use]
    pub fn for_surface(surface: TestSurface) -> Self {
        let required_modes: BTreeSet<FailureMode> = FailureMode::ALL
            .iter()
            .filter(|fm| fm.is_mandatory_for(surface))
            .copied()
            .collect();
        Self {
            surface,
            required_modes,
            min_tests_per_mode: 2,
        }
    }

    /// Check which failure modes are missing given observed coverage.
    #[must_use]
    pub fn missing_modes(&self, observed: &BTreeMap<FailureMode, u64>) -> Vec<FailureModeMissing> {
        let mut missing = Vec::new();
        for mode in &self.required_modes {
            let count = observed.get(mode).copied().unwrap_or(0);
            if count < self.min_tests_per_mode {
                missing.push(FailureModeMissing {
                    mode: *mode,
                    required: self.min_tests_per_mode,
                    observed: count,
                });
            }
        }
        missing
    }
}

/// A missing failure-mode test obligation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureModeMissing {
    pub mode: FailureMode,
    pub required: u64,
    pub observed: u64,
}

// ---------------------------------------------------------------------------
// CI regression policy
// ---------------------------------------------------------------------------

/// Direction of a coverage/mutation metric change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RegressionDirection {
    /// Coverage or score decreased.
    Decrease,
    /// Coverage or score unchanged.
    Stable,
    /// Coverage or score increased.
    Increase,
}

impl RegressionDirection {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Decrease => "decrease",
            Self::Stable => "stable",
            Self::Increase => "increase",
        }
    }
}

impl fmt::Display for RegressionDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CI regression policy for coverage and mutation metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionPolicy {
    /// Maximum allowed coverage decrease in millionths before blocking.
    pub max_coverage_decrease_millionths: i64,
    /// Maximum allowed mutation score decrease in millionths before blocking.
    pub max_mutation_decrease_millionths: i64,
    /// Whether to block on any decrease (zero-regression policy).
    pub zero_regression: bool,
}

impl RegressionPolicy {
    /// Strict zero-regression policy.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_coverage_decrease_millionths: 0,
            max_mutation_decrease_millionths: 0,
            zero_regression: true,
        }
    }

    /// Permissive policy with tolerance for small decreases.
    #[must_use]
    pub fn permissive(coverage_tolerance: i64, mutation_tolerance: i64) -> Self {
        Self {
            max_coverage_decrease_millionths: coverage_tolerance,
            max_mutation_decrease_millionths: mutation_tolerance,
            zero_regression: false,
        }
    }

    /// Check a coverage delta. Returns violation if regression exceeds tolerance.
    #[must_use]
    pub fn check_coverage_delta(&self, delta_millionths: i64) -> Option<DepthGateViolation> {
        let decrease = delta_millionths.saturating_neg();
        if delta_millionths < 0
            && (self.zero_regression || decrease > self.max_coverage_decrease_millionths)
        {
            return Some(DepthGateViolation {
                field: "coverage_regression".to_string(),
                message: format!(
                    "coverage decreased by {} millionths (tolerance: {})",
                    decrease, self.max_coverage_decrease_millionths
                ),
            });
        }
        None
    }

    /// Check a mutation score delta. Returns violation if regression exceeds tolerance.
    #[must_use]
    pub fn check_mutation_delta(&self, delta_millionths: i64) -> Option<DepthGateViolation> {
        let decrease = delta_millionths.saturating_neg();
        if delta_millionths < 0
            && (self.zero_regression || decrease > self.max_mutation_decrease_millionths)
        {
            return Some(DepthGateViolation {
                field: "mutation_regression".to_string(),
                message: format!(
                    "mutation score decreased by {} millionths (tolerance: {})",
                    decrease, self.max_mutation_decrease_millionths
                ),
            });
        }
        None
    }

    /// Classify the direction of a metric change.
    #[must_use]
    pub fn classify_delta(delta: i64) -> RegressionDirection {
        match delta.cmp(&0) {
            std::cmp::Ordering::Less => RegressionDirection::Decrease,
            std::cmp::Ordering::Equal => RegressionDirection::Stable,
            std::cmp::Ordering::Greater => RegressionDirection::Increase,
        }
    }
}

// ---------------------------------------------------------------------------
// Depth gate evaluation
// ---------------------------------------------------------------------------

/// Observed metrics for a single surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedMetrics {
    pub surface: TestSurface,
    /// Coverage observations by kind (in millionths).
    pub coverage: BTreeMap<CoverageKind, i64>,
    /// Mutation score in millionths.
    pub mutation_score_millionths: i64,
    /// Failure-mode test counts.
    pub failure_mode_counts: BTreeMap<FailureMode, u64>,
    /// Total tests executed.
    pub total_tests: u64,
    /// Tests by class.
    pub tests_by_class: BTreeMap<TestClass, u64>,
}

/// Outcome of a depth gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateOutcome {
    /// All gates pass.
    Pass,
    /// Advisory warnings but no hard failures.
    Warn,
    /// Hard gate failure — promotion blocked.
    Block,
}

impl GateOutcome {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }

    #[must_use]
    pub const fn is_blocking(&self) -> bool {
        matches!(self, Self::Block)
    }
}

impl fmt::Display for GateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Full result of a depth gate evaluation for one surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    pub surface: TestSurface,
    pub outcome: GateOutcome,
    pub coverage_violations: Vec<DepthGateViolation>,
    pub mutation_violations: Vec<DepthGateViolation>,
    pub failure_mode_missing: Vec<FailureModeMissing>,
    pub regression_violations: Vec<DepthGateViolation>,
}

impl GateResult {
    /// Derive an EngineObjectId for this result.
    pub fn derive_id(&self) -> Result<EngineObjectId, crate::engine_object_id::IdError> {
        let schema = SchemaId::from_definition(b"franken-engine.test-depth-gate.gate-result.v1");
        let canonical = format!(
            "{}|{}|cov={}|mut={}|fm={}",
            self.surface.as_str(),
            self.outcome.as_str(),
            self.coverage_violations.len(),
            self.mutation_violations.len(),
            self.failure_mode_missing.len(),
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            &format!("depth-gate:{}", self.surface.as_str()),
            &schema,
            canonical.as_bytes(),
        )
    }
}

/// Aggregated depth gate summary across all surfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthGateSummary {
    pub schema: String,
    pub overall_outcome: GateOutcome,
    pub results: Vec<GateResult>,
    pub total_violations: u64,
    pub blocking_violations: u64,
    pub advisory_violations: u64,
}

impl DepthGateSummary {
    /// Whether promotion is allowed.
    #[must_use]
    pub fn promotion_allowed(&self) -> bool {
        !self.overall_outcome.is_blocking()
    }
}

// ---------------------------------------------------------------------------
// Depth gate evaluator
// ---------------------------------------------------------------------------

/// Configuration for the depth gate evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthGateConfig {
    pub schema: String,
    pub coverage_targets: Vec<CoverageTarget>,
    pub mutation_policies: Vec<MutationPolicy>,
    pub failure_mode_obligations: Vec<FailureModeObligation>,
    pub regression_policy: RegressionPolicy,
}

impl DepthGateConfig {
    /// Build default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        let failure_mode_obligations: Vec<FailureModeObligation> = TestSurface::ALL
            .iter()
            .map(|s| FailureModeObligation::for_surface(*s))
            .collect();

        Self {
            schema: DEPTH_GATE_SCHEMA_VERSION.to_string(),
            coverage_targets: default_coverage_targets(),
            mutation_policies: default_mutation_policies(),
            failure_mode_obligations,
            regression_policy: RegressionPolicy::strict(),
        }
    }

    /// Validate all internal policies.
    #[must_use]
    pub fn validate(&self) -> Vec<DepthGateViolation> {
        let mut violations = Vec::new();
        for target in &self.coverage_targets {
            violations.extend(target.validate());
        }
        for policy in &self.mutation_policies {
            violations.extend(policy.validate());
        }
        violations
    }

    /// Evaluate a surface against configured gates.
    #[must_use]
    pub fn evaluate_surface(
        &self,
        metrics: &ObservedMetrics,
        previous_coverage: Option<&BTreeMap<CoverageKind, i64>>,
        previous_mutation: Option<i64>,
    ) -> GateResult {
        let mut coverage_violations = Vec::new();
        let mut mutation_violations = Vec::new();
        let mut regression_violations = Vec::new();

        // Check coverage targets
        for target in &self.coverage_targets {
            if target.surface != metrics.surface {
                continue;
            }
            if let Some(&observed) = metrics.coverage.get(&target.kind)
                && !target.is_met(observed)
            {
                coverage_violations.push(DepthGateViolation {
                    field: format!("coverage.{}", target.kind.as_str()),
                    message: format!(
                        "{} {} coverage {}/1M below minimum {}/1M",
                        metrics.surface, target.kind, observed, target.min_coverage_millionths,
                    ),
                });
            }
        }

        // Check mutation policies
        for policy in &self.mutation_policies {
            if policy.surface != metrics.surface {
                continue;
            }
            if !policy.is_met(metrics.mutation_score_millionths) {
                mutation_violations.push(DepthGateViolation {
                    field: "mutation_score".to_string(),
                    message: format!(
                        "{} mutation score {}/1M below {} tier minimum {}/1M",
                        metrics.surface,
                        metrics.mutation_score_millionths,
                        policy.tier,
                        policy.min_score_millionths,
                    ),
                });
            }
        }

        // Check failure-mode obligations
        let mut failure_mode_missing = Vec::new();
        for obligation in &self.failure_mode_obligations {
            if obligation.surface != metrics.surface {
                continue;
            }
            failure_mode_missing.extend(obligation.missing_modes(&metrics.failure_mode_counts));
        }

        // Check regression
        if let Some(prev_cov) = previous_coverage {
            for (&kind, &current) in &metrics.coverage {
                if let Some(&prev) = prev_cov.get(&kind) {
                    let delta = current.saturating_sub(prev);
                    if let Some(v) = self.regression_policy.check_coverage_delta(delta) {
                        regression_violations.push(v);
                    }
                }
            }
        }
        if let Some(prev_mut) = previous_mutation {
            let delta = metrics.mutation_score_millionths.saturating_sub(prev_mut);
            if let Some(v) = self.regression_policy.check_mutation_delta(delta) {
                regression_violations.push(v);
            }
        }

        // Determine outcome
        let has_hard_coverage_fail = self
            .coverage_targets
            .iter()
            .filter(|t| t.surface == metrics.surface && t.hard_gate)
            .any(|t| metrics.coverage.get(&t.kind).is_none_or(|&v| !t.is_met(v)));
        let has_hard_mutation_fail = self
            .mutation_policies
            .iter()
            .filter(|p| p.surface == metrics.surface && p.hard_gate)
            .any(|p| !p.is_met(metrics.mutation_score_millionths));

        let outcome = if has_hard_coverage_fail
            || has_hard_mutation_fail
            || !regression_violations.is_empty()
        {
            GateOutcome::Block
        } else if !coverage_violations.is_empty()
            || !mutation_violations.is_empty()
            || !failure_mode_missing.is_empty()
        {
            GateOutcome::Warn
        } else {
            GateOutcome::Pass
        };

        GateResult {
            surface: metrics.surface,
            outcome,
            coverage_violations,
            mutation_violations,
            failure_mode_missing,
            regression_violations,
        }
    }

    /// Evaluate all surfaces and produce aggregate summary.
    #[must_use]
    pub fn evaluate_all(
        &self,
        all_metrics: &[ObservedMetrics],
        previous_coverages: &BTreeMap<TestSurface, BTreeMap<CoverageKind, i64>>,
        previous_mutations: &BTreeMap<TestSurface, i64>,
    ) -> DepthGateSummary {
        let mut results = Vec::new();
        let mut total_violations: u64 = 0;
        let mut blocking_violations: u64 = 0;
        let mut advisory_violations: u64 = 0;

        for metrics in all_metrics {
            let prev_cov = previous_coverages.get(&metrics.surface);
            let prev_mut = previous_mutations.get(&metrics.surface).copied();
            let result = self.evaluate_surface(metrics, prev_cov, prev_mut);

            let v_count = (result.coverage_violations.len()
                + result.mutation_violations.len()
                + result.failure_mode_missing.len()
                + result.regression_violations.len()) as u64;
            total_violations += v_count;
            if result.outcome.is_blocking() {
                blocking_violations += v_count;
            } else if result.outcome == GateOutcome::Warn {
                advisory_violations += v_count;
            }
            results.push(result);
        }

        let overall_outcome = if results.iter().any(|r| r.outcome == GateOutcome::Block) {
            GateOutcome::Block
        } else if results.iter().any(|r| r.outcome == GateOutcome::Warn) {
            GateOutcome::Warn
        } else {
            GateOutcome::Pass
        };

        DepthGateSummary {
            schema: DEPTH_GATE_SCHEMA_VERSION.to_string(),
            overall_outcome,
            results,
            total_violations,
            blocking_violations,
            advisory_violations,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A violation found during depth gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepthGateViolation {
    pub field: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CoverageKind --

    #[test]
    fn coverage_kind_all_count() {
        assert_eq!(CoverageKind::ALL.len(), 3);
    }

    #[test]
    fn coverage_kind_as_str_unique() {
        let mut strs = BTreeSet::new();
        for kind in CoverageKind::ALL {
            assert!(strs.insert(kind.as_str()));
        }
    }

    #[test]
    fn coverage_kind_display() {
        assert_eq!(CoverageKind::Statement.to_string(), "statement");
        assert_eq!(CoverageKind::Branch.to_string(), "branch");
        assert_eq!(CoverageKind::Path.to_string(), "path");
    }

    #[test]
    fn coverage_kind_serde_roundtrip() {
        for kind in CoverageKind::ALL {
            let json = serde_json::to_string(kind).expect("serde deserialization should succeed");
            let back: CoverageKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn coverage_kind_ordering() {
        assert!(CoverageKind::Statement < CoverageKind::Branch);
        assert!(CoverageKind::Branch < CoverageKind::Path);
    }

    // -- CoverageTarget --

    #[test]
    fn coverage_target_valid() {
        let t = CoverageTarget {
            surface: TestSurface::Parser,
            kind: CoverageKind::Statement,
            min_coverage_millionths: 800_000,
            hard_gate: true,
        };
        assert!(t.validate().is_empty());
    }

    #[test]
    fn coverage_target_negative_invalid() {
        let t = CoverageTarget {
            surface: TestSurface::Parser,
            kind: CoverageKind::Statement,
            min_coverage_millionths: -1,
            hard_gate: true,
        };
        assert!(!t.validate().is_empty());
    }

    #[test]
    fn coverage_target_over_100_invalid() {
        let t = CoverageTarget {
            surface: TestSurface::Parser,
            kind: CoverageKind::Statement,
            min_coverage_millionths: MILLION + 1,
            hard_gate: true,
        };
        assert!(!t.validate().is_empty());
    }

    #[test]
    fn coverage_target_is_met() {
        let t = CoverageTarget {
            surface: TestSurface::Parser,
            kind: CoverageKind::Statement,
            min_coverage_millionths: 800_000,
            hard_gate: true,
        };
        assert!(t.is_met(800_000));
        assert!(t.is_met(900_000));
        assert!(!t.is_met(799_999));
    }

    #[test]
    fn coverage_target_serde_roundtrip() {
        let t = CoverageTarget {
            surface: TestSurface::Security,
            kind: CoverageKind::Branch,
            min_coverage_millionths: 850_000,
            hard_gate: true,
        };
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        let back: CoverageTarget =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(t, back);
    }

    // -- default_coverage_targets --

    #[test]
    fn default_coverage_targets_count() {
        let targets = default_coverage_targets();
        // 8 surfaces × 3 kinds = 24
        assert_eq!(targets.len(), 24);
    }

    #[test]
    fn default_coverage_targets_all_valid() {
        for target in default_coverage_targets() {
            assert!(target.validate().is_empty(), "invalid target: {target:?}");
        }
    }

    #[test]
    fn default_coverage_targets_security_highest() {
        let targets = default_coverage_targets();
        let sec_stmt = targets
            .iter()
            .find(|t| t.surface == TestSurface::Security && t.kind == CoverageKind::Statement)
            .expect("serde deserialization should succeed");
        let parser_stmt = targets
            .iter()
            .find(|t| t.surface == TestSurface::Parser && t.kind == CoverageKind::Statement)
            .expect("serde deserialization should succeed");
        assert!(sec_stmt.min_coverage_millionths >= parser_stmt.min_coverage_millionths);
    }

    #[test]
    fn default_coverage_path_is_advisory() {
        let targets = default_coverage_targets();
        for t in targets.iter().filter(|t| t.kind == CoverageKind::Path) {
            assert!(
                !t.hard_gate,
                "path coverage should be advisory for {}",
                t.surface
            );
        }
    }

    // -- MutationTier --

    #[test]
    fn mutation_tier_all_count() {
        assert_eq!(MutationTier::ALL.len(), 3);
    }

    #[test]
    fn mutation_tier_display_unique() {
        let mut strs = BTreeSet::new();
        for tier in MutationTier::ALL {
            assert!(strs.insert(tier.as_str()));
        }
    }

    #[test]
    fn mutation_tier_critical_threshold_is_100pct() {
        assert_eq!(
            MutationTier::Critical.default_threshold_millionths(),
            MILLION
        );
    }

    #[test]
    fn mutation_tier_ordering() {
        assert!(MutationTier::Critical < MutationTier::High);
        assert!(MutationTier::High < MutationTier::Standard);
    }

    #[test]
    fn mutation_tier_thresholds_monotone_decreasing() {
        assert!(
            MutationTier::Critical.default_threshold_millionths()
                >= MutationTier::High.default_threshold_millionths()
        );
        assert!(
            MutationTier::High.default_threshold_millionths()
                >= MutationTier::Standard.default_threshold_millionths()
        );
    }

    #[test]
    fn mutation_tier_serde_roundtrip() {
        for tier in MutationTier::ALL {
            let json = serde_json::to_string(tier).expect("serde deserialization should succeed");
            let back: MutationTier =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*tier, back);
        }
    }

    // -- MutationPolicy --

    #[test]
    fn mutation_policy_valid() {
        let p = MutationPolicy {
            surface: TestSurface::Security,
            tier: MutationTier::Critical,
            min_score_millionths: MILLION,
            hard_gate: true,
            critical_modules: BTreeSet::new(),
        };
        assert!(p.validate().is_empty());
    }

    #[test]
    fn mutation_policy_critical_requires_100pct() {
        let p = MutationPolicy {
            surface: TestSurface::Security,
            tier: MutationTier::Critical,
            min_score_millionths: 999_999,
            hard_gate: true,
            critical_modules: BTreeSet::new(),
        };
        let violations = p.validate();
        assert!(!violations.is_empty());
    }

    #[test]
    fn mutation_policy_negative_invalid() {
        let p = MutationPolicy {
            surface: TestSurface::Parser,
            tier: MutationTier::Standard,
            min_score_millionths: -1,
            hard_gate: false,
            critical_modules: BTreeSet::new(),
        };
        assert!(!p.validate().is_empty());
    }

    #[test]
    fn mutation_policy_is_met() {
        let p = MutationPolicy {
            surface: TestSurface::Parser,
            tier: MutationTier::Standard,
            min_score_millionths: 750_000,
            hard_gate: false,
            critical_modules: BTreeSet::new(),
        };
        assert!(p.is_met(750_000));
        assert!(p.is_met(MILLION));
        assert!(!p.is_met(749_999));
    }

    #[test]
    fn mutation_policy_serde_roundtrip() {
        let p = MutationPolicy {
            surface: TestSurface::Compiler,
            tier: MutationTier::High,
            min_score_millionths: 900_000,
            hard_gate: true,
            critical_modules: BTreeSet::from(["ir_contract".to_string(), "lowering".to_string()]),
        };
        let json = serde_json::to_string(&p).expect("serde deserialization should succeed");
        let back: MutationPolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(p, back);
    }

    // -- default_mutation_policies --

    #[test]
    fn default_mutation_policies_count() {
        let policies = default_mutation_policies();
        assert_eq!(policies.len(), 8); // one per surface
    }

    #[test]
    fn default_mutation_policies_all_valid() {
        for policy in default_mutation_policies() {
            assert!(policy.validate().is_empty(), "invalid policy: {policy:?}");
        }
    }

    #[test]
    fn default_mutation_security_is_critical() {
        let policies = default_mutation_policies();
        let sec = policies
            .iter()
            .find(|p| p.surface == TestSurface::Security)
            .expect("serde deserialization should succeed");
        assert_eq!(sec.tier, MutationTier::Critical);
        assert!(sec.hard_gate);
    }

    // -- FailureMode --

    #[test]
    fn failure_mode_all_count() {
        assert_eq!(FailureMode::ALL.len(), 8);
    }

    #[test]
    fn failure_mode_display_unique() {
        let mut strs = BTreeSet::new();
        for fm in FailureMode::ALL {
            assert!(strs.insert(fm.as_str()), "duplicate: {}", fm.as_str());
        }
    }

    #[test]
    fn failure_mode_timeout_mandatory_for_all() {
        for surface in TestSurface::ALL {
            assert!(
                FailureMode::Timeout.is_mandatory_for(*surface),
                "Timeout should be mandatory for {surface}"
            );
        }
    }

    #[test]
    fn failure_mode_cancellation_mandatory_for_all() {
        for surface in TestSurface::ALL {
            assert!(
                FailureMode::Cancellation.is_mandatory_for(*surface),
                "Cancellation should be mandatory for {surface}"
            );
        }
    }

    #[test]
    fn failure_mode_malformed_input_mandatory_for_all() {
        for surface in TestSurface::ALL {
            assert!(
                FailureMode::MalformedInput.is_mandatory_for(*surface),
                "MalformedInput should be mandatory for {surface}"
            );
        }
    }

    #[test]
    fn failure_mode_drift_mandatory_for_runtime() {
        assert!(FailureMode::Drift.is_mandatory_for(TestSurface::Runtime));
        assert!(FailureMode::Drift.is_mandatory_for(TestSurface::Router));
        assert!(!FailureMode::Drift.is_mandatory_for(TestSurface::Compiler));
    }

    #[test]
    fn failure_mode_rollback_mandatory_for_governance() {
        assert!(FailureMode::Rollback.is_mandatory_for(TestSurface::Governance));
        assert!(FailureMode::Rollback.is_mandatory_for(TestSurface::Evidence));
        assert!(FailureMode::Rollback.is_mandatory_for(TestSurface::Security));
        assert!(!FailureMode::Rollback.is_mandatory_for(TestSurface::Parser));
    }

    #[test]
    fn failure_mode_serde_roundtrip() {
        for fm in FailureMode::ALL {
            let json = serde_json::to_string(fm).expect("serde deserialization should succeed");
            let back: FailureMode =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*fm, back);
        }
    }

    // -- FailureModeObligation --

    #[test]
    fn obligation_for_runtime_has_many_modes() {
        let o = FailureModeObligation::for_surface(TestSurface::Runtime);
        assert!(o.required_modes.len() >= 5);
        assert!(o.required_modes.contains(&FailureMode::Timeout));
        assert!(o.required_modes.contains(&FailureMode::Drift));
        assert!(o.required_modes.contains(&FailureMode::Interference));
    }

    #[test]
    fn obligation_for_compiler_has_universal_modes() {
        let o = FailureModeObligation::for_surface(TestSurface::Compiler);
        assert!(o.required_modes.contains(&FailureMode::Timeout));
        assert!(o.required_modes.contains(&FailureMode::Cancellation));
        assert!(o.required_modes.contains(&FailureMode::MalformedInput));
    }

    #[test]
    fn obligation_missing_modes_all_missing() {
        let o = FailureModeObligation::for_surface(TestSurface::Parser);
        let observed = BTreeMap::new();
        let missing = o.missing_modes(&observed);
        assert_eq!(missing.len(), o.required_modes.len());
    }

    #[test]
    fn obligation_missing_modes_all_met() {
        let o = FailureModeObligation::for_surface(TestSurface::Parser);
        let mut observed = BTreeMap::new();
        for mode in &o.required_modes {
            observed.insert(*mode, o.min_tests_per_mode);
        }
        assert!(o.missing_modes(&observed).is_empty());
    }

    #[test]
    fn obligation_missing_modes_partially_met() {
        let o = FailureModeObligation::for_surface(TestSurface::Runtime);
        let mut observed = BTreeMap::new();
        observed.insert(FailureMode::Timeout, 5);
        // Missing all others
        let missing = o.missing_modes(&observed);
        assert!(missing.len() < o.required_modes.len());
        assert!(!missing.is_empty());
    }

    #[test]
    fn obligation_serde_roundtrip() {
        let o = FailureModeObligation::for_surface(TestSurface::Security);
        let json = serde_json::to_string(&o).expect("serde deserialization should succeed");
        let back: FailureModeObligation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(o, back);
    }

    // -- RegressionPolicy --

    #[test]
    fn regression_strict_blocks_any_decrease() {
        let p = RegressionPolicy::strict();
        assert!(p.check_coverage_delta(-1).is_some());
        assert!(p.check_mutation_delta(-1).is_some());
    }

    #[test]
    fn regression_strict_allows_increase() {
        let p = RegressionPolicy::strict();
        assert!(p.check_coverage_delta(1000).is_none());
        assert!(p.check_mutation_delta(1000).is_none());
    }

    #[test]
    fn regression_strict_allows_stable() {
        let p = RegressionPolicy::strict();
        assert!(p.check_coverage_delta(0).is_none());
        assert!(p.check_mutation_delta(0).is_none());
    }

    #[test]
    fn regression_permissive_allows_small_decrease() {
        let p = RegressionPolicy::permissive(5000, 5000);
        assert!(p.check_coverage_delta(-5000).is_none());
        assert!(p.check_mutation_delta(-5000).is_none());
    }

    #[test]
    fn regression_permissive_blocks_large_decrease() {
        let p = RegressionPolicy::permissive(5000, 5000);
        assert!(p.check_coverage_delta(-5001).is_some());
        assert!(p.check_mutation_delta(-5001).is_some());
    }

    #[test]
    fn regression_classify_delta() {
        assert_eq!(
            RegressionPolicy::classify_delta(-1),
            RegressionDirection::Decrease
        );
        assert_eq!(
            RegressionPolicy::classify_delta(0),
            RegressionDirection::Stable
        );
        assert_eq!(
            RegressionPolicy::classify_delta(1),
            RegressionDirection::Increase
        );
    }

    #[test]
    fn regression_direction_display() {
        assert_eq!(RegressionDirection::Decrease.to_string(), "decrease");
        assert_eq!(RegressionDirection::Stable.to_string(), "stable");
        assert_eq!(RegressionDirection::Increase.to_string(), "increase");
    }

    #[test]
    fn regression_policy_serde_roundtrip() {
        let p = RegressionPolicy::strict();
        let json = serde_json::to_string(&p).expect("serde deserialization should succeed");
        let back: RegressionPolicy =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(p, back);
    }

    // -- GateOutcome --

    #[test]
    fn gate_outcome_display() {
        assert_eq!(GateOutcome::Pass.to_string(), "pass");
        assert_eq!(GateOutcome::Warn.to_string(), "warn");
        assert_eq!(GateOutcome::Block.to_string(), "block");
    }

    #[test]
    fn gate_outcome_is_blocking() {
        assert!(!GateOutcome::Pass.is_blocking());
        assert!(!GateOutcome::Warn.is_blocking());
        assert!(GateOutcome::Block.is_blocking());
    }

    #[test]
    fn gate_outcome_serde_roundtrip() {
        for outcome in [GateOutcome::Pass, GateOutcome::Warn, GateOutcome::Block] {
            let json =
                serde_json::to_string(&outcome).expect("serde deserialization should succeed");
            let back: GateOutcome =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(outcome, back);
        }
    }

    // -- DepthGateConfig --

    #[test]
    fn default_config_valid() {
        let cfg = DepthGateConfig::default_config();
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn default_config_schema() {
        let cfg = DepthGateConfig::default_config();
        assert_eq!(cfg.schema, DEPTH_GATE_SCHEMA_VERSION);
    }

    #[test]
    fn default_config_has_all_surfaces() {
        let cfg = DepthGateConfig::default_config();
        let surfaces: BTreeSet<TestSurface> =
            cfg.coverage_targets.iter().map(|t| t.surface).collect();
        for s in TestSurface::ALL {
            assert!(surfaces.contains(s), "missing coverage target for {s}");
        }
    }

    #[test]
    fn default_config_serde_roundtrip() {
        let cfg = DepthGateConfig::default_config();
        let json = serde_json::to_string(&cfg).expect("serde deserialization should succeed");
        let back: DepthGateConfig =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(cfg, back);
    }

    // -- Evaluation helpers --

    fn make_passing_metrics(surface: TestSurface) -> ObservedMetrics {
        let mut coverage = BTreeMap::new();
        coverage.insert(CoverageKind::Statement, 950_000);
        coverage.insert(CoverageKind::Branch, 900_000);
        coverage.insert(CoverageKind::Path, 600_000);

        let obligation = FailureModeObligation::for_surface(surface);
        let mut failure_mode_counts = BTreeMap::new();
        for mode in &obligation.required_modes {
            failure_mode_counts.insert(*mode, 5);
        }

        ObservedMetrics {
            surface,
            coverage,
            mutation_score_millionths: MILLION,
            failure_mode_counts,
            total_tests: 100,
            tests_by_class: BTreeMap::from([
                (TestClass::Core, 50),
                (TestClass::Edge, 20),
                (TestClass::Adversarial, 15),
                (TestClass::Regression, 10),
                (TestClass::FaultInjection, 5),
            ]),
        }
    }

    fn make_failing_metrics(surface: TestSurface) -> ObservedMetrics {
        ObservedMetrics {
            surface,
            coverage: BTreeMap::from([
                (CoverageKind::Statement, 500_000),
                (CoverageKind::Branch, 400_000),
                (CoverageKind::Path, 100_000),
            ]),
            mutation_score_millionths: 300_000,
            failure_mode_counts: BTreeMap::new(),
            total_tests: 10,
            tests_by_class: BTreeMap::from([(TestClass::Core, 10)]),
        }
    }

    // -- evaluate_surface --

    #[test]
    fn evaluate_passing_surface() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_passing_metrics(TestSurface::Parser);
        let result = cfg.evaluate_surface(&metrics, None, None);
        assert_eq!(result.outcome, GateOutcome::Pass);
        assert!(result.coverage_violations.is_empty());
        assert!(result.mutation_violations.is_empty());
        assert!(result.failure_mode_missing.is_empty());
    }

    #[test]
    fn evaluate_failing_coverage() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_failing_metrics(TestSurface::Parser);
        let result = cfg.evaluate_surface(&metrics, None, None);
        assert_eq!(result.outcome, GateOutcome::Block);
        assert!(!result.coverage_violations.is_empty());
    }

    #[test]
    fn evaluate_failing_mutation() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_failing_metrics(TestSurface::Security);
        let result = cfg.evaluate_surface(&metrics, None, None);
        assert_eq!(result.outcome, GateOutcome::Block);
        assert!(!result.mutation_violations.is_empty());
    }

    #[test]
    fn evaluate_missing_failure_modes() {
        let cfg = DepthGateConfig::default_config();
        let mut metrics = make_passing_metrics(TestSurface::Runtime);
        metrics.failure_mode_counts.clear();
        let result = cfg.evaluate_surface(&metrics, None, None);
        assert!(!result.failure_mode_missing.is_empty());
    }

    #[test]
    fn evaluate_with_coverage_regression() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_passing_metrics(TestSurface::Parser);
        let prev_cov = BTreeMap::from([
            (CoverageKind::Statement, 960_000),
            (CoverageKind::Branch, 910_000),
        ]);
        let result = cfg.evaluate_surface(&metrics, Some(&prev_cov), None);
        assert_eq!(result.outcome, GateOutcome::Block);
        assert!(!result.regression_violations.is_empty());
    }

    #[test]
    fn evaluate_with_mutation_regression() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_passing_metrics(TestSurface::Parser);
        let result = cfg.evaluate_surface(&metrics, None, Some(MILLION + 1));
        assert_eq!(result.outcome, GateOutcome::Block);
        assert!(!result.regression_violations.is_empty());
    }

    #[test]
    fn evaluate_no_regression_on_improvement() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_passing_metrics(TestSurface::Parser);
        let prev_cov = BTreeMap::from([
            (CoverageKind::Statement, 900_000),
            (CoverageKind::Branch, 800_000),
        ]);
        let result = cfg.evaluate_surface(&metrics, Some(&prev_cov), Some(900_000));
        assert!(result.regression_violations.is_empty());
    }

    // -- evaluate_all --

    #[test]
    fn evaluate_all_all_passing() {
        let cfg = DepthGateConfig::default_config();
        let all_metrics: Vec<ObservedMetrics> = TestSurface::ALL
            .iter()
            .map(|s| make_passing_metrics(*s))
            .collect();
        let summary = cfg.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(summary.overall_outcome, GateOutcome::Pass);
        assert!(summary.promotion_allowed());
        assert_eq!(summary.total_violations, 0);
    }

    #[test]
    fn evaluate_all_one_failing() {
        let cfg = DepthGateConfig::default_config();
        let mut all_metrics: Vec<ObservedMetrics> = TestSurface::ALL
            .iter()
            .map(|s| make_passing_metrics(*s))
            .collect();
        all_metrics.push(make_failing_metrics(TestSurface::Security));
        let summary = cfg.evaluate_all(&all_metrics, &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(summary.overall_outcome, GateOutcome::Block);
        assert!(!summary.promotion_allowed());
        assert!(summary.blocking_violations > 0);
    }

    #[test]
    fn evaluate_all_empty() {
        let cfg = DepthGateConfig::default_config();
        let summary = cfg.evaluate_all(&[], &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(summary.overall_outcome, GateOutcome::Pass);
        assert!(summary.results.is_empty());
    }

    // -- GateResult --

    #[test]
    fn gate_result_derive_id_deterministic() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_passing_metrics(TestSurface::Parser);
        let result = cfg.evaluate_surface(&metrics, None, None);
        let id1 = result
            .derive_id()
            .expect("serde deserialization should succeed");
        let id2 = result
            .derive_id()
            .expect("serde deserialization should succeed");
        assert_eq!(id1, id2);
    }

    #[test]
    fn gate_result_serde_roundtrip() {
        let cfg = DepthGateConfig::default_config();
        let metrics = make_failing_metrics(TestSurface::Security);
        let result = cfg.evaluate_surface(&metrics, None, None);
        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: GateResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    // -- DepthGateSummary --

    #[test]
    fn summary_serde_roundtrip() {
        let cfg = DepthGateConfig::default_config();
        let metrics = vec![
            make_passing_metrics(TestSurface::Parser),
            make_failing_metrics(TestSurface::Security),
        ];
        let summary = cfg.evaluate_all(&metrics, &BTreeMap::new(), &BTreeMap::new());
        let json = serde_json::to_string(&summary).expect("serde deserialization should succeed");
        let back: DepthGateSummary =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(summary, back);
    }

    #[test]
    fn summary_violation_counts_consistent() {
        let cfg = DepthGateConfig::default_config();
        let metrics = vec![
            make_passing_metrics(TestSurface::Parser),
            make_failing_metrics(TestSurface::Security),
        ];
        let summary = cfg.evaluate_all(&metrics, &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(
            summary.total_violations,
            summary.blocking_violations + summary.advisory_violations
        );
    }

    // -- Cross-cutting --

    #[test]
    fn schema_version_set() {
        assert!(!DEPTH_GATE_SCHEMA_VERSION.is_empty());
    }

    #[test]
    fn observed_metrics_serde_roundtrip() {
        let m = make_passing_metrics(TestSurface::Compiler);
        let json = serde_json::to_string(&m).expect("serde deserialization should succeed");
        let back: ObservedMetrics =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(m, back);
    }

    #[test]
    fn depth_gate_violation_serde_roundtrip() {
        let v = DepthGateViolation {
            field: "test".to_string(),
            message: "msg".to_string(),
        };
        let json = serde_json::to_string(&v).expect("serde deserialization should succeed");
        let back: DepthGateViolation =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(v, back);
    }

    #[test]
    fn failure_mode_missing_serde_roundtrip() {
        let m = FailureModeMissing {
            mode: FailureMode::Timeout,
            required: 2,
            observed: 0,
        };
        let json = serde_json::to_string(&m).expect("serde deserialization should succeed");
        let back: FailureModeMissing =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(m, back);
    }

    #[test]
    fn end_to_end_depth_gate_pipeline() {
        let cfg = DepthGateConfig::default_config();
        assert!(cfg.validate().is_empty());

        // All surfaces passing
        let all_passing: Vec<ObservedMetrics> = TestSurface::ALL
            .iter()
            .map(|s| make_passing_metrics(*s))
            .collect();
        let summary = cfg.evaluate_all(&all_passing, &BTreeMap::new(), &BTreeMap::new());
        assert!(summary.promotion_allowed());
        assert_eq!(summary.results.len(), 8);

        // Now add regression
        let prev_cov: BTreeMap<TestSurface, BTreeMap<CoverageKind, i64>> = TestSurface::ALL
            .iter()
            .map(|s| {
                let mut cov = BTreeMap::new();
                cov.insert(CoverageKind::Statement, 960_000);
                (*s, cov)
            })
            .collect();
        let summary_with_regression = cfg.evaluate_all(&all_passing, &prev_cov, &BTreeMap::new());
        assert!(!summary_with_regression.promotion_allowed());
    }

    #[test]
    fn permissive_regression_allows_small_drop() {
        let mut cfg = DepthGateConfig::default_config();
        cfg.regression_policy = RegressionPolicy::permissive(10_000, 10_000);

        let metrics = make_passing_metrics(TestSurface::Parser);
        let prev_cov = BTreeMap::from([(CoverageKind::Statement, 955_000)]);
        let result = cfg.evaluate_surface(&metrics, Some(&prev_cov), None);
        assert!(result.regression_violations.is_empty());
    }

    #[test]
    fn hard_gate_vs_soft_gate_distinction() {
        let mut cfg = DepthGateConfig::default_config();
        // Make all coverage targets advisory
        for target in &mut cfg.coverage_targets {
            target.hard_gate = false;
        }
        // Make all mutation policies advisory
        for policy in &mut cfg.mutation_policies {
            policy.hard_gate = false;
        }
        cfg.regression_policy = RegressionPolicy::permissive(MILLION, MILLION);

        let metrics = make_failing_metrics(TestSurface::Security);
        let result = cfg.evaluate_surface(&metrics, None, None);
        // With all gates advisory and permissive regression, should be Warn not Block
        assert_eq!(result.outcome, GateOutcome::Warn);
    }

    // -- Enrichment: serde roundtrip for untested type (PearlTower 2026-02-26) --

    #[test]
    fn regression_direction_serde_roundtrip_all_variants() {
        let variants = [
            RegressionDirection::Decrease,
            RegressionDirection::Stable,
            RegressionDirection::Increase,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serde deserialization should succeed");
            let back: RegressionDirection =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*v, back);
        }
    }
}
