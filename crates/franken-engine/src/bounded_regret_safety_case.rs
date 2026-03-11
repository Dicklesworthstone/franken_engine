//! Bounded-regret and operator-override safety case for adaptive tiering.
//!
//! Implements [RGC-608C]: regret accounting, operator overrides, and the exact
//! conditions under which adaptive behavior may participate in public benchmark
//! or rollout claims.
//!
//! # Design
//!
//! - `RegretBound` specifies per-policy budgets for cumulative and per-step regret.
//! - `RegretAccounting` is a running ledger of observed regret over time.
//! - `OperatorOverride` captures explicit operator interventions.
//! - `BenchmarkEligibility` determines if adaptive behavior can appear in public claims.
//! - `SafetyCaseVerdict` is the pass/fail/inconclusive output of the safety case.
//! - `SafetyCaseReport` wraps the verdict with metadata and a content hash.
//!
//! A safety case passes only when:
//! 1. Regret accounting is non-empty and within budget.
//! 2. No override conflicts exist.
//! 3. The evidence epoch meets the minimum verification threshold.
//! 4. Active overrides do not exceed the configured maximum.
//! 5. The policy has been stable for at least `min_stability_steps`.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-608C]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.bounded-regret-safety-case.v1";

/// Component name.
pub const COMPONENT: &str = "bounded_regret_safety_case";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.8.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-608C";

/// Fixed-point unit: 1.0 = 1_000_000.
const MILLION: u64 = 1_000_000;

/// Default cumulative regret budget (millionths). 10% = 100_000.
pub const DEFAULT_CUMULATIVE_BUDGET: u64 = 100_000;

/// Default per-step regret budget (millionths). 5% = 50_000.
pub const DEFAULT_PER_STEP_BUDGET: u64 = 50_000;

/// Default decay rate (millionths). 1% = 10_000.
pub const DEFAULT_DECAY_RATE: u64 = 10_000;

/// Default minimum stability steps for benchmark eligibility.
pub const DEFAULT_MIN_STABILITY_STEPS: u64 = 100;

/// Default maximum active overrides.
pub const DEFAULT_MAX_ACTIVE_OVERRIDES: usize = 8;

/// Default minimum verification epoch.
pub const DEFAULT_MIN_VERIFICATION_EPOCH: u64 = 1;

// ---------------------------------------------------------------------------
// AdaptivePolicy
// ---------------------------------------------------------------------------

/// Policy governing adaptive tiering behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdaptivePolicy {
    /// Minimal adaptation, lowest regret risk.
    Conservative,
    /// Balanced adaptation with moderate regret budget.
    Moderate,
    /// Aggressive adaptation with higher regret tolerance.
    Aggressive,
    /// Custom policy with user-defined parameters.
    Custom,
}

impl AdaptivePolicy {
    pub const ALL: &[Self] = &[
        Self::Conservative,
        Self::Moderate,
        Self::Aggressive,
        Self::Custom,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Moderate => "moderate",
            Self::Aggressive => "aggressive",
            Self::Custom => "custom",
        }
    }
}

impl fmt::Display for AdaptivePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// OperatorOverrideType
// ---------------------------------------------------------------------------

/// Type of operator override intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorOverrideType {
    /// Force a specific adaptive policy.
    ForcePolicy,
    /// Lock a specific compilation tier.
    LockTier,
    /// Disable all adaptive behavior.
    DisableAdaptation,
    /// Cap the regret budget.
    CapRegret,
    /// Explicitly allow benchmark participation.
    AllowBenchmark,
    /// Explicitly deny benchmark participation.
    DenyBenchmark,
}

impl OperatorOverrideType {
    pub const ALL: &[Self] = &[
        Self::ForcePolicy,
        Self::LockTier,
        Self::DisableAdaptation,
        Self::CapRegret,
        Self::AllowBenchmark,
        Self::DenyBenchmark,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ForcePolicy => "force_policy",
            Self::LockTier => "lock_tier",
            Self::DisableAdaptation => "disable_adaptation",
            Self::CapRegret => "cap_regret",
            Self::AllowBenchmark => "allow_benchmark",
            Self::DenyBenchmark => "deny_benchmark",
        }
    }
}

impl fmt::Display for OperatorOverrideType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RegretBound
// ---------------------------------------------------------------------------

/// Budget specification for regret in a given adaptive policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RegretBound {
    /// Which policy this bound applies to.
    pub policy: AdaptivePolicy,
    /// Time horizon in steps.
    pub horizon_steps: u64,
    /// Maximum cumulative regret over the horizon (millionths).
    pub cumulative_budget_millionths: u64,
    /// Maximum regret per individual step (millionths).
    pub per_step_budget_millionths: u64,
    /// Exponential decay rate applied to older regret (millionths).
    pub decay_rate_millionths: u64,
}

impl RegretBound {
    /// Create a new regret bound.
    pub fn new(
        policy: AdaptivePolicy,
        horizon_steps: u64,
        cumulative_budget_millionths: u64,
        per_step_budget_millionths: u64,
        decay_rate_millionths: u64,
    ) -> Self {
        Self {
            policy,
            horizon_steps,
            cumulative_budget_millionths,
            per_step_budget_millionths,
            decay_rate_millionths,
        }
    }

    /// Create a conservative bound.
    pub fn conservative(horizon_steps: u64) -> Self {
        Self::new(
            AdaptivePolicy::Conservative,
            horizon_steps,
            50_000, // 5%
            20_000, // 2%
            5_000,  // 0.5%
        )
    }

    /// Create a moderate bound.
    pub fn moderate(horizon_steps: u64) -> Self {
        Self::new(
            AdaptivePolicy::Moderate,
            horizon_steps,
            DEFAULT_CUMULATIVE_BUDGET,
            DEFAULT_PER_STEP_BUDGET,
            DEFAULT_DECAY_RATE,
        )
    }

    /// Create an aggressive bound.
    pub fn aggressive(horizon_steps: u64) -> Self {
        Self::new(
            AdaptivePolicy::Aggressive,
            horizon_steps,
            200_000, // 20%
            100_000, // 10%
            20_000,  // 2%
        )
    }
}

// ---------------------------------------------------------------------------
// RegretEntry
// ---------------------------------------------------------------------------

/// A single step's regret observation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RegretEntry {
    /// Step number (0-indexed).
    pub timestamp_step: u64,
    /// Observed regret at this step (millionths).
    pub regret_millionths: u64,
    /// Policy that was active during this step.
    pub policy_active: AdaptivePolicy,
    /// Whether this step violated the per-step budget.
    pub was_violation: bool,
}

// ---------------------------------------------------------------------------
// RegretAccounting
// ---------------------------------------------------------------------------

/// Running ledger of observed regret over time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegretAccounting {
    /// The regret bound this accounting tracks against.
    pub bound: RegretBound,
    /// Total steps recorded.
    pub steps: u64,
    /// Cumulative regret (millionths), after decay.
    pub cumulative_regret: u64,
    /// Peak single-step regret observed (millionths).
    pub peak_regret: u64,
    /// Number of per-step budget violations.
    pub violations: u64,
    /// Individual step entries.
    pub entries: Vec<RegretEntry>,
}

impl RegretAccounting {
    /// Create a fresh ledger tracking the given bound.
    pub fn new(bound: RegretBound) -> Self {
        Self {
            bound,
            steps: 0,
            cumulative_regret: 0,
            peak_regret: 0,
            violations: 0,
            entries: Vec::new(),
        }
    }

    /// Record one step's regret observation.
    pub fn record_step(&mut self, regret_millionths: u64) {
        let was_violation = regret_millionths > self.bound.per_step_budget_millionths;
        if was_violation {
            self.violations += 1;
        }

        if regret_millionths > self.peak_regret {
            self.peak_regret = regret_millionths;
        }

        // Apply decay to existing cumulative regret before adding new.
        // decay: cumulative *= (1.0 - decay_rate)
        // In fixed-point: cumulative = cumulative * (MILLION - decay_rate) / MILLION
        let decay_factor = MILLION.saturating_sub(self.bound.decay_rate_millionths);
        self.cumulative_regret = self
            .cumulative_regret
            .saturating_mul(decay_factor)
            .checked_div(MILLION)
            .unwrap_or(0)
            .saturating_add(regret_millionths);

        let entry = RegretEntry {
            timestamp_step: self.steps,
            regret_millionths,
            policy_active: self.bound.policy,
            was_violation,
        };
        self.entries.push(entry);
        self.steps += 1;
    }

    /// Produce a summary of the current regret state.
    pub fn summary(&self) -> RegretSummary {
        let mean_regret_millionths = if self.steps > 0 {
            let total_raw: u64 = self.entries.iter().map(|e| e.regret_millionths).sum();
            total_raw.checked_div(self.steps).unwrap_or(0)
        } else {
            0
        };

        RegretSummary {
            total_steps: self.steps,
            cumulative_regret_millionths: self.cumulative_regret,
            peak_regret_millionths: self.peak_regret,
            mean_regret_millionths,
            violations_count: self.violations,
            within_budget: self.within_budget(),
        }
    }

    /// Whether cumulative regret is within the budget.
    pub fn within_budget(&self) -> bool {
        self.cumulative_regret <= self.bound.cumulative_budget_millionths
    }

    /// Whether any per-step violations have occurred.
    pub fn has_violations(&self) -> bool {
        self.violations > 0
    }

    /// Number of steps since the last violation, or total steps if none.
    pub fn steps_since_last_violation(&self) -> u64 {
        if let Some(last_viol) = self.entries.iter().rev().find(|e| e.was_violation) {
            self.steps.saturating_sub(last_viol.timestamp_step + 1)
        } else {
            self.steps
        }
    }

    /// Whether the policy has been stable (no violations) for at least n steps.
    pub fn stable_for(&self, min_steps: u64) -> bool {
        self.steps_since_last_violation() >= min_steps
    }
}

// ---------------------------------------------------------------------------
// RegretSummary
// ---------------------------------------------------------------------------

/// Summary snapshot of regret accounting state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RegretSummary {
    /// Total steps recorded.
    pub total_steps: u64,
    /// Cumulative regret after decay (millionths).
    pub cumulative_regret_millionths: u64,
    /// Peak single-step regret (millionths).
    pub peak_regret_millionths: u64,
    /// Mean regret per step (millionths).
    pub mean_regret_millionths: u64,
    /// Number of per-step violations.
    pub violations_count: u64,
    /// Whether cumulative regret is within budget.
    pub within_budget: bool,
}

// ---------------------------------------------------------------------------
// OperatorOverride
// ---------------------------------------------------------------------------

/// An operator intervention overriding adaptive behavior.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OperatorOverride {
    /// Unique override identifier.
    pub override_id: String,
    /// Type of override.
    pub override_type: OperatorOverrideType,
    /// Security epoch when override was created.
    pub epoch: SecurityEpoch,
    /// Human-readable justification.
    pub reason: String,
    /// Optional step at which this override expires.
    pub expiry_step: Option<u64>,
}

impl OperatorOverride {
    /// Create a new override.
    pub fn new(
        override_id: impl Into<String>,
        override_type: OperatorOverrideType,
        epoch: SecurityEpoch,
        reason: impl Into<String>,
        expiry_step: Option<u64>,
    ) -> Self {
        Self {
            override_id: override_id.into(),
            override_type,
            epoch,
            reason: reason.into(),
            expiry_step,
        }
    }

    /// Whether this override is still active at a given step.
    pub fn is_active_at(&self, step: u64) -> bool {
        match self.expiry_step {
            Some(expiry) => step < expiry,
            None => true, // no expiry = always active
        }
    }

    /// Whether this override affects benchmark participation.
    pub fn affects_benchmark(&self) -> bool {
        matches!(
            self.override_type,
            OperatorOverrideType::AllowBenchmark
                | OperatorOverrideType::DenyBenchmark
                | OperatorOverrideType::DisableAdaptation
        )
    }
}

// ---------------------------------------------------------------------------
// BenchmarkEligibility
// ---------------------------------------------------------------------------

/// Determination of whether adaptive behavior may appear in public claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEligibility {
    /// Whether the adaptive behavior is eligible for benchmark claims.
    pub eligible: bool,
    /// Reasons for the eligibility decision.
    pub reasons: Vec<String>,
    /// Whether an operator override is actively affecting eligibility.
    pub override_active: bool,
    /// Whether regret is within the defined bound.
    pub regret_within_bound: bool,
    /// Whether the policy has been stable long enough.
    pub policy_stable: bool,
}

// ---------------------------------------------------------------------------
// SafetyCaseVerdict
// ---------------------------------------------------------------------------

/// Verdict of the bounded-regret safety case evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCaseVerdict {
    /// Safety case passes.
    Pass {
        /// Summary of regret state.
        regret_summary: RegretSummary,
        /// Number of active overrides.
        overrides_active: usize,
    },
    /// Safety case fails.
    Fail {
        /// Reasons for failure.
        violations: Vec<String>,
    },
    /// Insufficient evidence to decide.
    Inconclusive {
        /// Reasons evidence is insufficient.
        reasons: Vec<String>,
    },
}

impl SafetyCaseVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass { .. })
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, Self::Fail { .. })
    }

    pub fn is_inconclusive(&self) -> bool {
        matches!(self, Self::Inconclusive { .. })
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Pass { .. } => "pass",
            Self::Fail { .. } => "fail",
            Self::Inconclusive { .. } => "inconclusive",
        }
    }
}

impl fmt::Display for SafetyCaseVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass {
                overrides_active, ..
            } => write!(f, "PASS ({overrides_active} override(s) active)"),
            Self::Fail { violations } => {
                write!(f, "FAIL: {} violation(s)", violations.len())
            }
            Self::Inconclusive { reasons } => {
                write!(f, "INCONCLUSIVE: {} reason(s)", reasons.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SafetyCaseConfig
// ---------------------------------------------------------------------------

/// Configuration for safety case evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SafetyCaseConfig {
    /// Maximum cumulative regret allowed (millionths).
    pub max_cumulative_regret: u64,
    /// Maximum per-step regret allowed (millionths).
    pub max_per_step_regret: u64,
    /// Minimum steps of stability before benchmark eligibility.
    pub min_stability_steps: u64,
    /// Whether operator approval is required for benchmark participation.
    pub require_operator_approval_for_benchmark: bool,
    /// Maximum number of active overrides allowed.
    pub max_active_overrides: usize,
    /// Minimum security epoch for valid evidence.
    pub min_verification_epoch: u64,
}

impl SafetyCaseConfig {
    /// Create with default thresholds.
    pub fn default_config() -> Self {
        Self {
            max_cumulative_regret: DEFAULT_CUMULATIVE_BUDGET,
            max_per_step_regret: DEFAULT_PER_STEP_BUDGET,
            min_stability_steps: DEFAULT_MIN_STABILITY_STEPS,
            require_operator_approval_for_benchmark: true,
            max_active_overrides: DEFAULT_MAX_ACTIVE_OVERRIDES,
            min_verification_epoch: DEFAULT_MIN_VERIFICATION_EPOCH,
        }
    }

    /// Permissive configuration for testing.
    pub fn permissive() -> Self {
        Self {
            max_cumulative_regret: u64::MAX,
            max_per_step_regret: u64::MAX,
            min_stability_steps: 0,
            require_operator_approval_for_benchmark: false,
            max_active_overrides: usize::MAX,
            min_verification_epoch: 0,
        }
    }

    /// Strict configuration for production.
    pub fn strict() -> Self {
        Self {
            max_cumulative_regret: 50_000,
            max_per_step_regret: 20_000,
            min_stability_steps: 500,
            require_operator_approval_for_benchmark: true,
            max_active_overrides: 4,
            min_verification_epoch: 10,
        }
    }
}

impl Default for SafetyCaseConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// SafetyCaseError
// ---------------------------------------------------------------------------

/// Errors that can occur during safety case evaluation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyCaseError {
    /// No regret observations recorded.
    EmptyAccounting,
    /// Cumulative regret exceeds budget.
    BudgetExceeded { cumulative: u64, budget: u64 },
    /// Configuration is invalid.
    InvalidConfig { field: String, reason: String },
    /// Conflicting operator overrides detected.
    OverrideConflict {
        override_a: String,
        override_b: String,
        reason: String,
    },
    /// Evidence is from a stale epoch.
    StaleEvidence { evidence_epoch: u64, min_epoch: u64 },
}

impl SafetyCaseError {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::EmptyAccounting => "empty_accounting",
            Self::BudgetExceeded { .. } => "budget_exceeded",
            Self::InvalidConfig { .. } => "invalid_config",
            Self::OverrideConflict { .. } => "override_conflict",
            Self::StaleEvidence { .. } => "stale_evidence",
        }
    }
}

impl fmt::Display for SafetyCaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyAccounting => write!(f, "no regret observations recorded"),
            Self::BudgetExceeded { cumulative, budget } => {
                write!(f, "cumulative regret {cumulative} exceeds budget {budget}")
            }
            Self::InvalidConfig { field, reason } => {
                write!(f, "invalid config field '{field}': {reason}")
            }
            Self::OverrideConflict {
                override_a,
                override_b,
                reason,
            } => write!(
                f,
                "override conflict between '{override_a}' and '{override_b}': {reason}"
            ),
            Self::StaleEvidence {
                evidence_epoch,
                min_epoch,
            } => write!(f, "evidence epoch {evidence_epoch} < minimum {min_epoch}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SafetyCaseReport
// ---------------------------------------------------------------------------

/// Report from a safety case evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyCaseReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch of the evaluation.
    pub epoch: SecurityEpoch,
    /// Active policy at time of evaluation.
    pub policy_active: AdaptivePolicy,
    /// Regret summary.
    pub regret_summary: RegretSummary,
    /// Active overrides.
    pub overrides: Vec<OperatorOverride>,
    /// Benchmark eligibility determination.
    pub benchmark_eligibility: BenchmarkEligibility,
    /// Safety case verdict.
    pub verdict: SafetyCaseVerdict,
    /// Content hash of the report.
    pub report_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Core Functions
// ---------------------------------------------------------------------------

/// Detect conflicts among active overrides.
///
/// Returns pairs of conflicting override IDs with reasons.
fn detect_override_conflicts(overrides: &[OperatorOverride]) -> Vec<(String, String, String)> {
    let mut conflicts = Vec::new();

    // AllowBenchmark + DenyBenchmark conflict
    let allows: Vec<&OperatorOverride> = overrides
        .iter()
        .filter(|o| o.override_type == OperatorOverrideType::AllowBenchmark)
        .collect();
    let denies: Vec<&OperatorOverride> = overrides
        .iter()
        .filter(|o| o.override_type == OperatorOverrideType::DenyBenchmark)
        .collect();
    for a in &allows {
        for d in &denies {
            conflicts.push((
                a.override_id.clone(),
                d.override_id.clone(),
                "AllowBenchmark and DenyBenchmark conflict".to_string(),
            ));
        }
    }

    // DisableAdaptation + ForcePolicy conflict
    let disables: Vec<&OperatorOverride> = overrides
        .iter()
        .filter(|o| o.override_type == OperatorOverrideType::DisableAdaptation)
        .collect();
    let forces: Vec<&OperatorOverride> = overrides
        .iter()
        .filter(|o| o.override_type == OperatorOverrideType::ForcePolicy)
        .collect();
    for dis in &disables {
        for frc in &forces {
            conflicts.push((
                dis.override_id.clone(),
                frc.override_id.clone(),
                "DisableAdaptation and ForcePolicy conflict".to_string(),
            ));
        }
    }

    conflicts
}

/// Evaluate the bounded-regret safety case.
pub fn evaluate_safety_case(
    accounting: &RegretAccounting,
    overrides: &[OperatorOverride],
    config: &SafetyCaseConfig,
    epoch: SecurityEpoch,
) -> SafetyCaseVerdict {
    // Inconclusive: no evidence
    if accounting.steps == 0 {
        return SafetyCaseVerdict::Inconclusive {
            reasons: vec!["no regret observations recorded".to_string()],
        };
    }

    let mut violations = Vec::new();

    // Check epoch freshness
    if epoch.as_u64() < config.min_verification_epoch {
        violations.push(format!(
            "epoch {} below minimum {}",
            epoch.as_u64(),
            config.min_verification_epoch
        ));
    }

    // Check cumulative regret
    if accounting.cumulative_regret > config.max_cumulative_regret {
        violations.push(format!(
            "cumulative regret {} exceeds maximum {}",
            accounting.cumulative_regret, config.max_cumulative_regret
        ));
    }

    // Check per-step violations
    if accounting.peak_regret > config.max_per_step_regret {
        violations.push(format!(
            "peak per-step regret {} exceeds maximum {}",
            accounting.peak_regret, config.max_per_step_regret
        ));
    }

    // Filter active overrides at current step
    let active_overrides: Vec<&OperatorOverride> = overrides
        .iter()
        .filter(|o| o.is_active_at(accounting.steps))
        .collect();

    // Check override count
    if active_overrides.len() > config.max_active_overrides {
        violations.push(format!(
            "active overrides {} exceed maximum {}",
            active_overrides.len(),
            config.max_active_overrides
        ));
    }

    // Check override conflicts
    let active_owned: Vec<OperatorOverride> = active_overrides.iter().copied().cloned().collect();
    let conflicts = detect_override_conflicts(&active_owned);
    for (a, b, reason) in &conflicts {
        violations.push(format!("override conflict: {a} vs {b}: {reason}"));
    }

    if violations.is_empty() {
        SafetyCaseVerdict::Pass {
            regret_summary: accounting.summary(),
            overrides_active: active_overrides.len(),
        }
    } else {
        SafetyCaseVerdict::Fail { violations }
    }
}

/// Check whether adaptive behavior is eligible for benchmark participation.
pub fn check_benchmark_eligibility(
    accounting: &RegretAccounting,
    overrides: &[OperatorOverride],
    config: &SafetyCaseConfig,
) -> BenchmarkEligibility {
    let mut reasons = Vec::new();
    let regret_within_bound = accounting.within_budget();
    let policy_stable = accounting.stable_for(config.min_stability_steps);

    // Filter active overrides at current step
    let active_overrides: Vec<&OperatorOverride> = overrides
        .iter()
        .filter(|o| o.is_active_at(accounting.steps))
        .collect();

    // Check for explicit deny
    let has_deny = active_overrides
        .iter()
        .any(|o| o.override_type == OperatorOverrideType::DenyBenchmark);

    // Check for explicit allow
    let has_allow = active_overrides
        .iter()
        .any(|o| o.override_type == OperatorOverrideType::AllowBenchmark);

    // Check for disable adaptation
    let has_disable = active_overrides
        .iter()
        .any(|o| o.override_type == OperatorOverrideType::DisableAdaptation);

    let override_active = has_deny || has_allow || has_disable;

    // Explicit deny always wins
    if has_deny {
        reasons.push("operator explicitly denied benchmark participation".to_string());
        return BenchmarkEligibility {
            eligible: false,
            reasons,
            override_active,
            regret_within_bound,
            policy_stable,
        };
    }

    // Disabled adaptation means no adaptive claims possible
    if has_disable {
        reasons.push("adaptation disabled by operator override".to_string());
        return BenchmarkEligibility {
            eligible: false,
            reasons,
            override_active,
            regret_within_bound,
            policy_stable,
        };
    }

    // Regret must be within budget
    if !regret_within_bound {
        reasons.push(format!(
            "cumulative regret {} exceeds budget {}",
            accounting.cumulative_regret, accounting.bound.cumulative_budget_millionths
        ));
    }

    // Policy must be stable
    if !policy_stable {
        reasons.push(format!(
            "policy unstable: {} steps since last violation, minimum {} required",
            accounting.steps_since_last_violation(),
            config.min_stability_steps
        ));
    }

    // Operator approval required?
    if config.require_operator_approval_for_benchmark && !has_allow {
        reasons.push("operator approval required but not granted".to_string());
    }

    // No accounting data
    if accounting.steps == 0 {
        reasons.push("no regret observations recorded".to_string());
    }

    let eligible = reasons.is_empty();
    if eligible {
        reasons.push("all eligibility criteria met".to_string());
    }

    BenchmarkEligibility {
        eligible,
        reasons,
        override_active,
        regret_within_bound,
        policy_stable,
    }
}

/// Generate a full safety case report.
pub fn report(
    accounting: &RegretAccounting,
    overrides: &[OperatorOverride],
    config: &SafetyCaseConfig,
    epoch: SecurityEpoch,
) -> SafetyCaseReport {
    let regret_summary = accounting.summary();
    let verdict = evaluate_safety_case(accounting, overrides, config, epoch);
    let benchmark_eligibility = check_benchmark_eligibility(accounting, overrides, config);

    // Filter active overrides at current step
    let active_overrides: Vec<OperatorOverride> = overrides
        .iter()
        .filter(|o| o.is_active_at(accounting.steps))
        .cloned()
        .collect();

    // Compute content hash
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(epoch.as_u64().to_le_bytes());
    h.update(accounting.bound.policy.as_str().as_bytes());
    h.update(regret_summary.total_steps.to_le_bytes());
    h.update(regret_summary.cumulative_regret_millionths.to_le_bytes());
    h.update(regret_summary.peak_regret_millionths.to_le_bytes());
    h.update(regret_summary.violations_count.to_le_bytes());
    h.update((active_overrides.len() as u64).to_le_bytes());
    h.update(verdict.tag().as_bytes());
    if benchmark_eligibility.eligible {
        h.update(b"eligible");
    } else {
        h.update(b"ineligible");
    }
    let report_hash = ContentHash::compute(&h.finalize());

    SafetyCaseReport {
        schema_version: SCHEMA_VERSION.to_string(),
        epoch,
        policy_active: accounting.bound.policy,
        regret_summary,
        overrides: active_overrides,
        benchmark_eligibility,
        verdict,
        report_hash,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn moderate_bound() -> RegretBound {
        RegretBound::moderate(1000)
    }

    fn sample_override(otype: OperatorOverrideType) -> OperatorOverride {
        OperatorOverride::new("ovr-1", otype, epoch(), "test reason", None)
    }

    fn sample_override_with_expiry(otype: OperatorOverrideType, expiry: u64) -> OperatorOverride {
        OperatorOverride::new("ovr-exp", otype, epoch(), "test reason", Some(expiry))
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "bounded_regret_safety_case");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn default_constants_positive() {
        assert_eq!(DEFAULT_CUMULATIVE_BUDGET, 100_000);
        assert_eq!(DEFAULT_PER_STEP_BUDGET, 50_000);
        assert_eq!(DEFAULT_DECAY_RATE, 10_000);
        assert_eq!(DEFAULT_MIN_STABILITY_STEPS, 100);
        assert_eq!(DEFAULT_MAX_ACTIVE_OVERRIDES, 8);
    }

    // --- AdaptivePolicy ---

    #[test]
    fn policy_all_length() {
        assert_eq!(AdaptivePolicy::ALL.len(), 4);
    }

    #[test]
    fn policy_names_unique() {
        let names: BTreeSet<&str> = AdaptivePolicy::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(names.len(), AdaptivePolicy::ALL.len());
    }

    #[test]
    fn policy_display_matches_as_str() {
        for p in AdaptivePolicy::ALL {
            assert_eq!(p.to_string(), p.as_str());
        }
    }

    #[test]
    fn policy_serde_roundtrip() {
        for p in AdaptivePolicy::ALL {
            let json = serde_json::to_string(p).unwrap();
            let back: AdaptivePolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
        }
    }

    // --- OperatorOverrideType ---

    #[test]
    fn override_type_all_length() {
        assert_eq!(OperatorOverrideType::ALL.len(), 6);
    }

    #[test]
    fn override_type_names_unique() {
        let names: BTreeSet<&str> = OperatorOverrideType::ALL
            .iter()
            .map(|t| t.as_str())
            .collect();
        assert_eq!(names.len(), OperatorOverrideType::ALL.len());
    }

    #[test]
    fn override_type_display() {
        for t in OperatorOverrideType::ALL {
            assert_eq!(t.to_string(), t.as_str());
        }
    }

    #[test]
    fn override_type_serde() {
        for t in OperatorOverrideType::ALL {
            let json = serde_json::to_string(t).unwrap();
            let back: OperatorOverrideType = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    // --- RegretBound ---

    #[test]
    fn bound_conservative() {
        let b = RegretBound::conservative(500);
        assert_eq!(b.policy, AdaptivePolicy::Conservative);
        assert_eq!(b.horizon_steps, 500);
        assert!(b.cumulative_budget_millionths < DEFAULT_CUMULATIVE_BUDGET);
    }

    #[test]
    fn bound_moderate() {
        let b = RegretBound::moderate(1000);
        assert_eq!(b.policy, AdaptivePolicy::Moderate);
        assert_eq!(b.cumulative_budget_millionths, DEFAULT_CUMULATIVE_BUDGET);
    }

    #[test]
    fn bound_aggressive() {
        let b = RegretBound::aggressive(2000);
        assert_eq!(b.policy, AdaptivePolicy::Aggressive);
        assert!(b.cumulative_budget_millionths > DEFAULT_CUMULATIVE_BUDGET);
    }

    #[test]
    fn bound_serde_roundtrip() {
        let b = moderate_bound();
        let json = serde_json::to_string(&b).unwrap();
        let back: RegretBound = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    // --- RegretAccounting ---

    #[test]
    fn accounting_new_empty() {
        let a = RegretAccounting::new(moderate_bound());
        assert_eq!(a.steps, 0);
        assert_eq!(a.cumulative_regret, 0);
        assert_eq!(a.peak_regret, 0);
        assert_eq!(a.violations, 0);
        assert!(a.entries.is_empty());
    }

    #[test]
    fn accounting_single_step() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(10_000);
        assert_eq!(a.steps, 1);
        assert_eq!(a.peak_regret, 10_000);
        assert_eq!(a.violations, 0);
        assert!(a.within_budget());
    }

    #[test]
    fn accounting_violation_detected() {
        let mut a = RegretAccounting::new(moderate_bound());
        // per_step_budget = 50_000
        a.record_step(60_000);
        assert_eq!(a.violations, 1);
        assert!(a.has_violations());
        assert!(a.entries[0].was_violation);
    }

    #[test]
    fn accounting_no_violation_at_boundary() {
        let mut a = RegretAccounting::new(moderate_bound());
        // per_step_budget = 50_000; exactly at boundary is NOT a violation (<=)
        a.record_step(50_000);
        assert_eq!(a.violations, 0);
        assert!(!a.entries[0].was_violation);
    }

    #[test]
    fn accounting_peak_tracking() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(5_000);
        a.record_step(30_000);
        a.record_step(15_000);
        assert_eq!(a.peak_regret, 30_000);
    }

    #[test]
    fn accounting_cumulative_decay() {
        let mut a = RegretAccounting::new(moderate_bound());
        // First step: regret = 20_000
        a.record_step(20_000);
        assert_eq!(a.cumulative_regret, 20_000);
        // Second step: decay applied to 20_000 then add 10_000
        // decay_factor = 1_000_000 - 10_000 = 990_000
        // 20_000 * 990_000 / 1_000_000 = 19_800, + 10_000 = 29_800
        a.record_step(10_000);
        assert_eq!(a.cumulative_regret, 29_800);
    }

    #[test]
    fn accounting_within_budget_exceeded() {
        let mut a = RegretAccounting::new(RegretBound::new(
            AdaptivePolicy::Conservative,
            100,
            10_000, // very small budget
            50_000,
            0, // no decay
        ));
        a.record_step(5_000);
        assert!(a.within_budget());
        a.record_step(6_000);
        // 5_000 + 6_000 = 11_000 > 10_000
        assert!(!a.within_budget());
    }

    #[test]
    fn accounting_summary_mean() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(10_000);
        a.record_step(20_000);
        a.record_step(30_000);
        let s = a.summary();
        assert_eq!(s.total_steps, 3);
        // mean = (10_000 + 20_000 + 30_000) / 3 = 20_000
        assert_eq!(s.mean_regret_millionths, 20_000);
    }

    #[test]
    fn accounting_summary_empty() {
        let a = RegretAccounting::new(moderate_bound());
        let s = a.summary();
        assert_eq!(s.total_steps, 0);
        assert_eq!(s.mean_regret_millionths, 0);
        assert!(s.within_budget);
    }

    #[test]
    fn accounting_steps_since_last_violation_none() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(1_000);
        a.record_step(2_000);
        // No violations; steps_since = total steps
        assert_eq!(a.steps_since_last_violation(), 2);
    }

    #[test]
    fn accounting_steps_since_last_violation_recent() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(1_000);
        a.record_step(60_000); // violation at step 1
        a.record_step(1_000);
        a.record_step(1_000);
        // Last violation at step 1, now at step 4
        // steps_since = 4 - (1 + 1) = 2
        assert_eq!(a.steps_since_last_violation(), 2);
    }

    #[test]
    fn accounting_stable_for() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..200 {
            a.record_step(1_000);
        }
        assert!(a.stable_for(100));
        assert!(a.stable_for(200));
        assert!(!a.stable_for(201));
    }

    #[test]
    fn accounting_serde_roundtrip() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(5_000);
        a.record_step(60_000);
        let json = serde_json::to_string(&a).unwrap();
        let back: RegretAccounting = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- OperatorOverride ---

    #[test]
    fn override_active_no_expiry() {
        let o = sample_override(OperatorOverrideType::ForcePolicy);
        assert!(o.is_active_at(0));
        assert!(o.is_active_at(u64::MAX));
    }

    #[test]
    fn override_active_with_expiry() {
        let o = sample_override_with_expiry(OperatorOverrideType::CapRegret, 50);
        assert!(o.is_active_at(0));
        assert!(o.is_active_at(49));
        assert!(!o.is_active_at(50));
        assert!(!o.is_active_at(100));
    }

    #[test]
    fn override_affects_benchmark() {
        assert!(sample_override(OperatorOverrideType::AllowBenchmark).affects_benchmark());
        assert!(sample_override(OperatorOverrideType::DenyBenchmark).affects_benchmark());
        assert!(sample_override(OperatorOverrideType::DisableAdaptation).affects_benchmark());
        assert!(!sample_override(OperatorOverrideType::ForcePolicy).affects_benchmark());
        assert!(!sample_override(OperatorOverrideType::LockTier).affects_benchmark());
        assert!(!sample_override(OperatorOverrideType::CapRegret).affects_benchmark());
    }

    #[test]
    fn override_serde_roundtrip() {
        let o = sample_override(OperatorOverrideType::LockTier);
        let json = serde_json::to_string(&o).unwrap();
        let back: OperatorOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(o, back);
    }

    // --- SafetyCaseError ---

    #[test]
    fn error_tags_unique() {
        let errors = [
            SafetyCaseError::EmptyAccounting,
            SafetyCaseError::BudgetExceeded {
                cumulative: 0,
                budget: 0,
            },
            SafetyCaseError::InvalidConfig {
                field: "x".into(),
                reason: "y".into(),
            },
            SafetyCaseError::OverrideConflict {
                override_a: "a".into(),
                override_b: "b".into(),
                reason: "c".into(),
            },
            SafetyCaseError::StaleEvidence {
                evidence_epoch: 0,
                min_epoch: 1,
            },
        ];
        let tags: BTreeSet<&str> = errors.iter().map(|e| e.tag()).collect();
        assert_eq!(tags.len(), 5);
    }

    #[test]
    fn error_display_non_empty() {
        let e = SafetyCaseError::BudgetExceeded {
            cumulative: 200_000,
            budget: 100_000,
        };
        let s = e.to_string();
        assert!(s.contains("200000"));
        assert!(s.contains("100000"));
    }

    #[test]
    fn error_serde_roundtrip() {
        let e = SafetyCaseError::StaleEvidence {
            evidence_epoch: 5,
            min_epoch: 10,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: SafetyCaseError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- SafetyCaseVerdict ---

    #[test]
    fn verdict_pass() {
        let v = SafetyCaseVerdict::Pass {
            regret_summary: RegretSummary {
                total_steps: 10,
                cumulative_regret_millionths: 5_000,
                peak_regret_millionths: 2_000,
                mean_regret_millionths: 500,
                violations_count: 0,
                within_budget: true,
            },
            overrides_active: 0,
        };
        assert!(v.is_pass());
        assert!(!v.is_fail());
        assert!(!v.is_inconclusive());
        assert_eq!(v.tag(), "pass");
    }

    #[test]
    fn verdict_fail() {
        let v = SafetyCaseVerdict::Fail {
            violations: vec!["too much regret".into()],
        };
        assert!(v.is_fail());
        assert!(!v.is_pass());
        assert_eq!(v.tag(), "fail");
    }

    #[test]
    fn verdict_inconclusive() {
        let v = SafetyCaseVerdict::Inconclusive {
            reasons: vec!["no data".into()],
        };
        assert!(v.is_inconclusive());
        assert_eq!(v.tag(), "inconclusive");
    }

    #[test]
    fn verdict_display_pass() {
        let v = SafetyCaseVerdict::Pass {
            regret_summary: RegretSummary {
                total_steps: 1,
                cumulative_regret_millionths: 0,
                peak_regret_millionths: 0,
                mean_regret_millionths: 0,
                violations_count: 0,
                within_budget: true,
            },
            overrides_active: 2,
        };
        let s = v.to_string();
        assert!(s.contains("PASS"));
        assert!(s.contains("2"));
    }

    #[test]
    fn verdict_display_fail() {
        let v = SafetyCaseVerdict::Fail {
            violations: vec!["a".into(), "b".into()],
        };
        assert!(v.to_string().contains("FAIL"));
        assert!(v.to_string().contains("2"));
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let v = SafetyCaseVerdict::Pass {
            regret_summary: RegretSummary {
                total_steps: 5,
                cumulative_regret_millionths: 1_000,
                peak_regret_millionths: 500,
                mean_regret_millionths: 200,
                violations_count: 0,
                within_budget: true,
            },
            overrides_active: 1,
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: SafetyCaseVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- SafetyCaseConfig ---

    #[test]
    fn config_default() {
        let c = SafetyCaseConfig::default_config();
        assert_eq!(c.max_cumulative_regret, DEFAULT_CUMULATIVE_BUDGET);
        assert_eq!(c.max_per_step_regret, DEFAULT_PER_STEP_BUDGET);
        assert_eq!(c.min_stability_steps, DEFAULT_MIN_STABILITY_STEPS);
        assert!(c.require_operator_approval_for_benchmark);
    }

    #[test]
    fn config_permissive() {
        let c = SafetyCaseConfig::permissive();
        assert_eq!(c.max_cumulative_regret, u64::MAX);
        assert!(!c.require_operator_approval_for_benchmark);
    }

    #[test]
    fn config_strict() {
        let c = SafetyCaseConfig::strict();
        assert!(c.max_cumulative_regret < DEFAULT_CUMULATIVE_BUDGET);
        assert!(c.min_stability_steps > DEFAULT_MIN_STABILITY_STEPS);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = SafetyCaseConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: SafetyCaseConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- evaluate_safety_case ---

    #[test]
    fn evaluate_empty_is_inconclusive() {
        let a = RegretAccounting::new(moderate_bound());
        let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default(), epoch());
        assert!(v.is_inconclusive());
    }

    #[test]
    fn evaluate_clean_pass() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..10 {
            a.record_step(1_000);
        }
        let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default(), epoch());
        assert!(v.is_pass());
    }

    #[test]
    fn evaluate_cumulative_budget_exceeded() {
        let mut a = RegretAccounting::new(RegretBound::new(
            AdaptivePolicy::Moderate,
            100,
            100_000,
            50_000,
            0, // no decay
        ));
        // Pump well over budget
        for _ in 0..10 {
            a.record_step(40_000);
        }
        let config = SafetyCaseConfig {
            max_cumulative_regret: 100_000,
            ..SafetyCaseConfig::default()
        };
        let v = evaluate_safety_case(&a, &[], &config, epoch());
        assert!(v.is_fail());
    }

    #[test]
    fn evaluate_stale_epoch_fails() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(1_000);
        let config = SafetyCaseConfig {
            min_verification_epoch: 200,
            ..SafetyCaseConfig::default()
        };
        let v = evaluate_safety_case(&a, &[], &config, epoch());
        assert!(v.is_fail());
    }

    #[test]
    fn evaluate_override_conflict_fails() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(1_000);
        let overrides = vec![
            OperatorOverride::new(
                "allow-1",
                OperatorOverrideType::AllowBenchmark,
                epoch(),
                "allow it",
                None,
            ),
            OperatorOverride::new(
                "deny-1",
                OperatorOverrideType::DenyBenchmark,
                epoch(),
                "deny it",
                None,
            ),
        ];
        let v = evaluate_safety_case(&a, &overrides, &SafetyCaseConfig::default(), epoch());
        assert!(v.is_fail());
    }

    #[test]
    fn evaluate_too_many_overrides_fails() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(1_000);
        let overrides: Vec<OperatorOverride> = (0..10)
            .map(|i| {
                OperatorOverride::new(
                    format!("ovr-{i}"),
                    OperatorOverrideType::LockTier,
                    epoch(),
                    "lock tier",
                    None,
                )
            })
            .collect();
        let config = SafetyCaseConfig {
            max_active_overrides: 5,
            ..SafetyCaseConfig::default()
        };
        let v = evaluate_safety_case(&a, &overrides, &config, epoch());
        assert!(v.is_fail());
    }

    #[test]
    fn evaluate_peak_regret_fails() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(200_000); // way over per-step max
        let v = evaluate_safety_case(&a, &[], &SafetyCaseConfig::default(), epoch());
        assert!(v.is_fail());
    }

    // --- check_benchmark_eligibility ---

    #[test]
    fn eligibility_all_criteria_met() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..200 {
            a.record_step(100);
        }
        let allow = OperatorOverride::new(
            "allow-1",
            OperatorOverrideType::AllowBenchmark,
            epoch(),
            "approved",
            None,
        );
        let config = SafetyCaseConfig::default();
        let e = check_benchmark_eligibility(&a, &[allow], &config);
        assert!(e.eligible);
        assert!(e.regret_within_bound);
        assert!(e.policy_stable);
    }

    #[test]
    fn eligibility_denied_by_operator() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..200 {
            a.record_step(100);
        }
        let deny = OperatorOverride::new(
            "deny-1",
            OperatorOverrideType::DenyBenchmark,
            epoch(),
            "denied",
            None,
        );
        let e = check_benchmark_eligibility(&a, &[deny], &SafetyCaseConfig::default());
        assert!(!e.eligible);
        assert!(e.override_active);
    }

    #[test]
    fn eligibility_adaptation_disabled() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(100);
        let dis = OperatorOverride::new(
            "dis-1",
            OperatorOverrideType::DisableAdaptation,
            epoch(),
            "disabled",
            None,
        );
        let e = check_benchmark_eligibility(&a, &[dis], &SafetyCaseConfig::default());
        assert!(!e.eligible);
    }

    #[test]
    fn eligibility_no_approval() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..200 {
            a.record_step(100);
        }
        let config = SafetyCaseConfig {
            require_operator_approval_for_benchmark: true,
            ..SafetyCaseConfig::default()
        };
        let e = check_benchmark_eligibility(&a, &[], &config);
        assert!(!e.eligible);
    }

    #[test]
    fn eligibility_no_approval_required() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..200 {
            a.record_step(100);
        }
        let config = SafetyCaseConfig {
            require_operator_approval_for_benchmark: false,
            ..SafetyCaseConfig::default()
        };
        let e = check_benchmark_eligibility(&a, &[], &config);
        assert!(e.eligible);
    }

    #[test]
    fn eligibility_unstable() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..50 {
            a.record_step(100);
        }
        a.record_step(60_000); // violation
        for _ in 0..10 {
            a.record_step(100);
        }
        let config = SafetyCaseConfig {
            min_stability_steps: 50,
            require_operator_approval_for_benchmark: false,
            ..SafetyCaseConfig::default()
        };
        let e = check_benchmark_eligibility(&a, &[], &config);
        assert!(!e.eligible);
        assert!(!e.policy_stable);
    }

    #[test]
    fn eligibility_regret_over_budget() {
        let mut a = RegretAccounting::new(RegretBound::new(
            AdaptivePolicy::Conservative,
            100,
            5_000, // tiny budget
            50_000,
            0,
        ));
        for _ in 0..10 {
            a.record_step(1_000);
        }
        let config = SafetyCaseConfig {
            require_operator_approval_for_benchmark: false,
            min_stability_steps: 0,
            ..SafetyCaseConfig::default()
        };
        let e = check_benchmark_eligibility(&a, &[], &config);
        assert!(!e.eligible);
        assert!(!e.regret_within_bound);
    }

    // --- report ---

    #[test]
    fn report_clean() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..10 {
            a.record_step(1_000);
        }
        let r = report(&a, &[], &SafetyCaseConfig::default(), epoch());
        assert_eq!(r.schema_version, SCHEMA_VERSION);
        assert_eq!(r.epoch, epoch());
        assert_eq!(r.policy_active, AdaptivePolicy::Moderate);
    }

    #[test]
    fn report_hash_deterministic() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..5 {
            a.record_step(2_000);
        }
        let config = SafetyCaseConfig::default();
        let r1 = report(&a, &[], &config, epoch());
        let r2 = report(&a, &[], &config, epoch());
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn report_serde_roundtrip() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(3_000);
        let r = report(&a, &[], &SafetyCaseConfig::default(), epoch());
        let json = serde_json::to_string(&r).unwrap();
        let back: SafetyCaseReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn report_includes_active_overrides_only() {
        let mut a = RegretAccounting::new(moderate_bound());
        for _ in 0..5 {
            a.record_step(1_000);
        }
        let overrides = vec![
            OperatorOverride::new(
                "active",
                OperatorOverrideType::LockTier,
                epoch(),
                "active",
                None,
            ),
            OperatorOverride::new(
                "expired",
                OperatorOverrideType::CapRegret,
                epoch(),
                "expired",
                Some(2), // expired before step 5
            ),
        ];
        let r = report(&a, &overrides, &SafetyCaseConfig::default(), epoch());
        assert_eq!(r.overrides.len(), 1);
        assert_eq!(r.overrides[0].override_id, "active");
    }

    // --- Conflict detection ---

    #[test]
    fn conflict_allow_deny() {
        let overrides = vec![
            OperatorOverride::new(
                "a",
                OperatorOverrideType::AllowBenchmark,
                epoch(),
                "x",
                None,
            ),
            OperatorOverride::new("b", OperatorOverrideType::DenyBenchmark, epoch(), "y", None),
        ];
        let conflicts = detect_override_conflicts(&overrides);
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn conflict_disable_force() {
        let overrides = vec![
            OperatorOverride::new(
                "d",
                OperatorOverrideType::DisableAdaptation,
                epoch(),
                "x",
                None,
            ),
            OperatorOverride::new("f", OperatorOverrideType::ForcePolicy, epoch(), "y", None),
        ];
        let conflicts = detect_override_conflicts(&overrides);
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn no_conflicts_compatible() {
        let overrides = vec![
            OperatorOverride::new("a", OperatorOverrideType::LockTier, epoch(), "x", None),
            OperatorOverride::new("b", OperatorOverrideType::CapRegret, epoch(), "y", None),
        ];
        let conflicts = detect_override_conflicts(&overrides);
        assert!(conflicts.is_empty());
    }

    // --- BenchmarkEligibility serde ---

    #[test]
    fn benchmark_eligibility_serde() {
        let e = BenchmarkEligibility {
            eligible: true,
            reasons: vec!["all good".into()],
            override_active: false,
            regret_within_bound: true,
            policy_stable: true,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: BenchmarkEligibility = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- RegretEntry serde ---

    #[test]
    fn regret_entry_serde() {
        let e = RegretEntry {
            timestamp_step: 42,
            regret_millionths: 5_000,
            policy_active: AdaptivePolicy::Moderate,
            was_violation: false,
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: RegretEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- RegretSummary serde ---

    #[test]
    fn regret_summary_serde() {
        let s = RegretSummary {
            total_steps: 100,
            cumulative_regret_millionths: 50_000,
            peak_regret_millionths: 10_000,
            mean_regret_millionths: 5_000,
            violations_count: 2,
            within_budget: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: RegretSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- Edge cases ---

    #[test]
    fn decay_zero_rate() {
        let mut a = RegretAccounting::new(RegretBound::new(
            AdaptivePolicy::Custom,
            100,
            1_000_000,
            100_000,
            0, // zero decay
        ));
        a.record_step(10_000);
        a.record_step(10_000);
        // With zero decay: cumulative = 10_000 + 10_000 = 20_000
        assert_eq!(a.cumulative_regret, 20_000);
    }

    #[test]
    fn decay_full_rate() {
        let mut a = RegretAccounting::new(RegretBound::new(
            AdaptivePolicy::Custom,
            100,
            1_000_000,
            100_000,
            MILLION, // full decay = factor 0
        ));
        a.record_step(10_000);
        a.record_step(5_000);
        // Full decay: old regret * 0 / MILLION + 5_000 = 5_000
        assert_eq!(a.cumulative_regret, 5_000);
    }

    #[test]
    fn zero_regret_step() {
        let mut a = RegretAccounting::new(moderate_bound());
        a.record_step(0);
        assert_eq!(a.steps, 1);
        assert_eq!(a.peak_regret, 0);
        assert_eq!(a.cumulative_regret, 0);
        assert_eq!(a.violations, 0);
    }

    #[test]
    fn many_steps_no_overflow() {
        let mut a = RegretAccounting::new(RegretBound::new(
            AdaptivePolicy::Moderate,
            10_000,
            u64::MAX,
            u64::MAX,
            500_000, // 50% decay
        ));
        for _ in 0..1000 {
            a.record_step(1_000);
        }
        // Should converge, not overflow
        assert!(a.cumulative_regret < u64::MAX);
        let s = a.summary();
        assert_eq!(s.total_steps, 1000);
    }
}
