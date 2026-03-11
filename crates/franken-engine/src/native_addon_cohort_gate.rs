//! Bead: bd-1lsy.5.9.3 [RGC-407C]
//!
//! Parity, security, throughput, and support-surface gates for native-addon
//! cohorts.
//!
//! Gates compatibility progress for native Node-API addons on evidence-backed
//! metrics instead of anecdotal claims:
//!
//! 1. **Parity** — API surface, memory safety, thread safety, error semantics,
//!    lifecycle compliance, and ABI stability coverage across addons.
//! 2. **Security** — memory isolation, resource bounding, capability
//!    restriction, sandbox escape prevention, input validation, and output
//!    sanitization verdicts per addon.
//! 3. **Throughput** — call latency, batch throughput, memory overhead, GC
//!    pressure, context-switch cost, and startup penalty relative to baseline.
//! 4. **Governance** — tier-aware adoption decisions derived from the combined
//!    parity, security, and throughput evidence.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-407C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for native-addon cohort gate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.native-addon-cohort-gate.v1";

/// Component name for structured logging.
pub const COMPONENT: &str = "native_addon_cohort_gate";

/// Bead originating this module.
pub const BEAD_ID: &str = "bd-1lsy.5.9.3";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-407C";

/// Fixed-point unit: 1.0 in millionths.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// CohortTier
// ---------------------------------------------------------------------------

/// Classification tier for a native addon based on ecosystem importance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortTier {
    /// Top-100 npm native addons.
    Critical,
    /// Top-1000 npm native addons.
    High,
    /// Community-maintained addons with significant usage.
    Medium,
    /// Niche addons with limited usage.
    Low,
    /// Experimental or pre-release addons.
    Experimental,
    /// Tier not yet determined.
    Unknown,
}

impl CohortTier {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::Critical,
        Self::High,
        Self::Medium,
        Self::Low,
        Self::Experimental,
        Self::Unknown,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Experimental => "experimental",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for CohortTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityDimension
// ---------------------------------------------------------------------------

/// A dimension along which parity is evaluated between native addon behaviour
/// under FrankenEngine and the reference Node.js runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityDimension {
    /// Public API surface coverage.
    ApiSurface,
    /// Memory-safety guarantees.
    MemorySafety,
    /// Thread-safety guarantees.
    ThreadSafety,
    /// Error semantics and propagation fidelity.
    ErrorSemantics,
    /// Addon lifecycle (init/cleanup) compliance.
    LifecycleCompliance,
    /// ABI stability across engine versions.
    AbiStability,
}

impl ParityDimension {
    pub const ALL: &[Self] = &[
        Self::ApiSurface,
        Self::MemorySafety,
        Self::ThreadSafety,
        Self::ErrorSemantics,
        Self::LifecycleCompliance,
        Self::AbiStability,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ApiSurface => "api_surface",
            Self::MemorySafety => "memory_safety",
            Self::ThreadSafety => "thread_safety",
            Self::ErrorSemantics => "error_semantics",
            Self::LifecycleCompliance => "lifecycle_compliance",
            Self::AbiStability => "abi_stability",
        }
    }
}

impl fmt::Display for ParityDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SecurityClass
// ---------------------------------------------------------------------------

/// Security classification dimension for a native addon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityClass {
    /// Memory isolation between addon and host.
    MemoryIsolation,
    /// Resource bounding (CPU, memory, handles).
    ResourceBounding,
    /// Capability restriction enforcement.
    CapabilityRestriction,
    /// Sandbox escape prevention.
    SandboxEscapePrevention,
    /// Input validation on data crossing the boundary.
    InputValidation,
    /// Output sanitization on data returned to JavaScript.
    OutputSanitization,
}

impl SecurityClass {
    pub const ALL: &[Self] = &[
        Self::MemoryIsolation,
        Self::ResourceBounding,
        Self::CapabilityRestriction,
        Self::SandboxEscapePrevention,
        Self::InputValidation,
        Self::OutputSanitization,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MemoryIsolation => "memory_isolation",
            Self::ResourceBounding => "resource_bounding",
            Self::CapabilityRestriction => "capability_restriction",
            Self::SandboxEscapePrevention => "sandbox_escape_prevention",
            Self::InputValidation => "input_validation",
            Self::OutputSanitization => "output_sanitization",
        }
    }
}

impl fmt::Display for SecurityClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ThroughputMetric
// ---------------------------------------------------------------------------

/// A throughput/performance metric measured for native addon calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputMetric {
    /// Per-call latency overhead.
    CallLatency,
    /// Batch throughput (calls/sec).
    BatchThroughput,
    /// Memory overhead per addon instance.
    MemoryOverhead,
    /// GC pressure imposed by the addon.
    GcPressure,
    /// Cost of context switching into/out of addon.
    ContextSwitchCost,
    /// One-time startup penalty for addon initialization.
    StartupPenalty,
}

impl ThroughputMetric {
    pub const ALL: &[Self] = &[
        Self::CallLatency,
        Self::BatchThroughput,
        Self::MemoryOverhead,
        Self::GcPressure,
        Self::ContextSwitchCost,
        Self::StartupPenalty,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CallLatency => "call_latency",
            Self::BatchThroughput => "batch_throughput",
            Self::MemoryOverhead => "memory_overhead",
            Self::GcPressure => "gc_pressure",
            Self::ContextSwitchCost => "context_switch_cost",
            Self::StartupPenalty => "startup_penalty",
        }
    }
}

impl fmt::Display for ThroughputMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Verdict from a gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// All criteria met.
    Pass,
    /// Criteria met with caveats requiring follow-up.
    ConditionalPass,
    /// One or more hard criteria violated.
    Fail,
    /// Not enough evidence to render a verdict.
    InsufficientEvidence,
}

impl GateVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ConditionalPass => "conditional_pass",
            Self::Fail => "fail",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }

    /// Whether this verdict allows adoption (possibly with conditions).
    pub fn is_adoptable(&self) -> bool {
        matches!(self, Self::Pass | Self::ConditionalPass)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SecurityVerdict
// ---------------------------------------------------------------------------

/// Security-specific verdict for an addon or cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityVerdict {
    /// No known vulnerabilities; all classes pass.
    Secure,
    /// Some classes pass with caveats.
    ConditionallySecure,
    /// At least one class reports a vulnerability.
    Vulnerable,
    /// No security assessment has been performed.
    Unassessed,
}

impl SecurityVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::ConditionallySecure => "conditionally_secure",
            Self::Vulnerable => "vulnerable",
            Self::Unassessed => "unassessed",
        }
    }
}

impl fmt::Display for SecurityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

/// Governance-level action derived from gate verdicts and tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    /// Addon may be adopted without restrictions.
    AllowAdoption,
    /// Adoption allowed with conditions (e.g. monitoring).
    ConditionalAdoption,
    /// Adoption blocked; must remediate first.
    BlockAdoption,
    /// A security audit is required before adoption.
    RequireAudit,
    /// Tier should be downgraded due to evidence.
    DowngradeTier,
    /// Specific remediation steps are required.
    RequireRemediation,
}

impl GovernanceAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowAdoption => "allow_adoption",
            Self::ConditionalAdoption => "conditional_adoption",
            Self::BlockAdoption => "block_adoption",
            Self::RequireAudit => "require_audit",
            Self::DowngradeTier => "downgrade_tier",
            Self::RequireRemediation => "require_remediation",
        }
    }
}

impl fmt::Display for GovernanceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AddonDescriptor
// ---------------------------------------------------------------------------

/// Description of a native addon under evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddonDescriptor {
    /// NPM package name.
    pub name: String,
    /// Semver version string.
    pub version: String,
    /// Ecosystem importance tier.
    pub tier: CohortTier,
    /// Node-API (N-API) version targeted.
    pub napi_version: u32,
    /// Number of distinct Node-API calls used.
    pub node_api_calls: u32,
    /// Whether the addon uses worker threads.
    pub has_worker_threads: bool,
    /// Whether the addon uses async hooks.
    pub has_async_hooks: bool,
}

// ---------------------------------------------------------------------------
// ParityFinding
// ---------------------------------------------------------------------------

/// A single parity finding for one addon along one dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityFinding {
    /// Which dimension was evaluated.
    pub dimension: ParityDimension,
    /// Name of the addon this finding applies to.
    pub addon_name: String,
    /// Whether parity was achieved on this dimension.
    pub is_parity_achieved: bool,
    /// Number of divergences found.
    pub divergence_count: u32,
    /// Total checks performed.
    pub total_checks: u32,
    /// Human-readable detail string.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// SecurityFinding
// ---------------------------------------------------------------------------

/// A single security finding for one addon along one security class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Which security class was evaluated.
    pub class: SecurityClass,
    /// Name of the addon this finding applies to.
    pub addon_name: String,
    /// Security verdict for this class.
    pub verdict: SecurityVerdict,
    /// Number of vulnerabilities found.
    pub vulnerability_count: u32,
    /// Human-readable detail string.
    pub detail: String,
    /// Content hash of the evidence backing this finding.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ThroughputSample
// ---------------------------------------------------------------------------

/// A throughput measurement sample for one addon on one metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputSample {
    /// Which metric was measured.
    pub metric: ThroughputMetric,
    /// Name of the addon this sample applies to.
    pub addon_name: String,
    /// Baseline measurement in millionths.
    pub baseline_millionths: u64,
    /// Candidate measurement in millionths.
    pub candidate_millionths: u64,
    /// Number of samples collected.
    pub sample_count: u32,
    /// Security epoch at measurement time.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// CohortResult
// ---------------------------------------------------------------------------

/// Aggregated gate result for a single addon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortResult {
    /// The addon under evaluation.
    pub addon: AddonDescriptor,
    /// All parity findings for this addon.
    pub parity_findings: Vec<ParityFinding>,
    /// All security findings for this addon.
    pub security_findings: Vec<SecurityFinding>,
    /// All throughput samples for this addon.
    pub throughput_samples: Vec<ThroughputSample>,
    /// Parity sub-verdict.
    pub parity_verdict: GateVerdict,
    /// Security sub-verdict.
    pub security_verdict: SecurityVerdict,
    /// Throughput sub-verdict.
    pub throughput_verdict: GateVerdict,
    /// Overall verdict combining all sub-verdicts.
    pub overall_verdict: GateVerdict,
    /// Recommended governance action.
    pub governance_action: GovernanceAction,
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the native-addon cohort gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum parity coverage in millionths (default 800_000 = 80%).
    pub min_parity_coverage_millionths: u64,
    /// Maximum allowed throughput regression in millionths (default 100_000 = 10%).
    pub max_throughput_regression_millionths: u64,
    /// Whether a security audit is required for adoption.
    pub require_security_audit: bool,
    /// Set of tiers that must be evaluated.
    pub required_tiers: BTreeSet<CohortTier>,
    /// Minimum number of throughput samples for statistical validity.
    pub min_sample_count: u32,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_parity_coverage_millionths: 800_000,
            max_throughput_regression_millionths: 100_000,
            require_security_audit: true,
            required_tiers: BTreeSet::new(),
            min_sample_count: 30,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Tamper-evident receipt for a gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version of this receipt.
    pub schema_version: String,
    /// Component that produced this receipt.
    pub component: String,
    /// Bead reference.
    pub bead_id: String,
    /// Policy reference.
    pub policy_id: String,
    /// Security epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Hash of the input data.
    pub input_hash: ContentHash,
    /// Hash of the verdict.
    pub verdict_hash: ContentHash,
    /// Timestamp in microseconds since epoch.
    pub timestamp_micros: u64,
}

// ---------------------------------------------------------------------------
// GateReport
// ---------------------------------------------------------------------------

/// Full report produced by the cohort gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// Per-addon results.
    pub cohort_results: Vec<CohortResult>,
    /// Overall verdict across the entire cohort.
    pub overall_verdict: GateVerdict,
    /// Recommended governance action for the cohort.
    pub governance_action: GovernanceAction,
    /// Total number of addons evaluated.
    pub total_addons: usize,
    /// Number of addons that passed.
    pub passing_addons: usize,
    /// Number of addons that failed.
    pub failing_addons: usize,
    /// Parity coverage per tier (tier, coverage_millionths).
    pub coverage_by_tier: Vec<(CohortTier, u64)>,
    /// Tamper-evident receipt.
    pub receipt: DecisionReceipt,
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Compute parity verdict from a set of parity findings.
///
/// If no findings are supplied, returns `InsufficientEvidence`.
/// Otherwise, computes the fraction of findings where parity was achieved
/// and compares against `min_coverage` (in millionths).
pub fn compute_parity_verdict(findings: &[ParityFinding], min_coverage: u64) -> GateVerdict {
    if findings.is_empty() {
        return GateVerdict::InsufficientEvidence;
    }

    let achieved = findings.iter().filter(|f| f.is_parity_achieved).count() as u64;
    let total = findings.len() as u64;
    let coverage = achieved.saturating_mul(MILLIONTHS) / total;

    if coverage >= min_coverage {
        GateVerdict::Pass
    } else if coverage >= min_coverage / 2 {
        GateVerdict::ConditionalPass
    } else {
        GateVerdict::Fail
    }
}

/// Compute security verdict from a set of security findings.
///
/// If no findings are supplied, returns `Unassessed`.
/// Any `Vulnerable` finding yields `Vulnerable`.
/// Any `ConditionallySecure` finding (with no `Vulnerable`) yields
/// `ConditionallySecure`. All `Secure` yields `Secure`.
pub fn compute_security_verdict(findings: &[SecurityFinding]) -> SecurityVerdict {
    if findings.is_empty() {
        return SecurityVerdict::Unassessed;
    }

    let mut has_conditional = false;
    let mut has_unassessed = false;

    for f in findings {
        match f.verdict {
            SecurityVerdict::Vulnerable => return SecurityVerdict::Vulnerable,
            SecurityVerdict::ConditionallySecure => has_conditional = true,
            SecurityVerdict::Unassessed => has_unassessed = true,
            SecurityVerdict::Secure => {}
        }
    }

    if has_conditional {
        SecurityVerdict::ConditionallySecure
    } else if has_unassessed {
        SecurityVerdict::Unassessed
    } else {
        SecurityVerdict::Secure
    }
}

/// Compute throughput verdict from a set of throughput samples.
///
/// If no samples are supplied or the sample count is below `min_samples`,
/// returns `InsufficientEvidence`.
/// Otherwise checks whether the candidate-to-baseline regression exceeds
/// `max_regression` millionths.
pub fn compute_throughput_verdict(
    samples: &[ThroughputSample],
    max_regression: u64,
    min_samples: u32,
) -> GateVerdict {
    if samples.is_empty() {
        return GateVerdict::InsufficientEvidence;
    }

    let total_sample_count: u64 = samples.iter().map(|s| s.sample_count as u64).sum();
    if total_sample_count < min_samples as u64 {
        return GateVerdict::InsufficientEvidence;
    }

    let mut worst_regression: u64 = 0;

    for s in samples {
        if s.baseline_millionths == 0 {
            continue;
        }
        // Regression = how much worse the candidate is vs baseline.
        // For latency/overhead metrics, higher candidate = worse.
        if s.candidate_millionths > s.baseline_millionths {
            let delta = s.candidate_millionths - s.baseline_millionths;
            let regression = delta.saturating_mul(MILLIONTHS) / s.baseline_millionths;
            if regression > worst_regression {
                worst_regression = regression;
            }
        }
    }

    if worst_regression > max_regression {
        GateVerdict::Fail
    } else if worst_regression > max_regression / 2 {
        GateVerdict::ConditionalPass
    } else {
        GateVerdict::Pass
    }
}

/// Derive a governance action from the overall gate verdict, security verdict,
/// and addon tier.
pub fn derive_governance_action(
    overall: &GateVerdict,
    security: &SecurityVerdict,
    tier: &CohortTier,
) -> GovernanceAction {
    // Vulnerable security always blocks critical/high tiers.
    if *security == SecurityVerdict::Vulnerable {
        return match tier {
            CohortTier::Critical | CohortTier::High => GovernanceAction::BlockAdoption,
            _ => GovernanceAction::RequireRemediation,
        };
    }

    // Unassessed security on critical/high tiers requires audit.
    if *security == SecurityVerdict::Unassessed
        && matches!(tier, CohortTier::Critical | CohortTier::High)
    {
        return GovernanceAction::RequireAudit;
    }

    match overall {
        GateVerdict::Pass => {
            if *security == SecurityVerdict::ConditionallySecure {
                GovernanceAction::ConditionalAdoption
            } else {
                GovernanceAction::AllowAdoption
            }
        }
        GateVerdict::ConditionalPass => GovernanceAction::ConditionalAdoption,
        GateVerdict::Fail => match tier {
            CohortTier::Critical | CohortTier::High => GovernanceAction::BlockAdoption,
            CohortTier::Medium => GovernanceAction::RequireRemediation,
            _ => GovernanceAction::DowngradeTier,
        },
        GateVerdict::InsufficientEvidence => match tier {
            CohortTier::Critical | CohortTier::High => GovernanceAction::RequireAudit,
            _ => GovernanceAction::ConditionalAdoption,
        },
    }
}

/// Compute per-tier coverage from cohort results.
///
/// Returns a sorted vec of `(CohortTier, coverage_millionths)` where
/// coverage is the fraction of addons in that tier that passed.
pub fn compute_tier_coverage(results: &[CohortResult]) -> Vec<(CohortTier, u64)> {
    let mut tier_total: Vec<(CohortTier, u64, u64)> = Vec::new();

    for r in results {
        let entry = tier_total.iter_mut().find(|(t, _, _)| *t == r.addon.tier);
        if let Some(e) = entry {
            e.1 += 1;
            if r.overall_verdict.is_adoptable() {
                e.2 += 1;
            }
        } else {
            let passed = if r.overall_verdict.is_adoptable() {
                1u64
            } else {
                0
            };
            tier_total.push((r.addon.tier, 1, passed));
        }
    }

    tier_total.sort_by_key(|(t, _, _)| *t);

    tier_total
        .into_iter()
        .map(|(tier, total, passed)| {
            let coverage = passed
                .saturating_mul(MILLIONTHS)
                .checked_div(total)
                .unwrap_or(0);
            (tier, coverage)
        })
        .collect()
}

/// Compute a tamper-evident decision receipt.
pub fn compute_receipt(
    input_hash: ContentHash,
    verdict: &GateVerdict,
    epoch: SecurityEpoch,
) -> DecisionReceipt {
    let mut buf = Vec::new();
    append_str(&mut buf, SCHEMA_VERSION);
    append_str(&mut buf, COMPONENT);
    append_str(&mut buf, verdict.as_str());
    buf.extend_from_slice(input_hash.as_bytes());
    append_u64(&mut buf, epoch.as_u64());
    let verdict_hash = ContentHash::compute(&buf);

    DecisionReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        epoch,
        input_hash,
        verdict_hash,
        timestamp_micros: 0,
    }
}

/// Evaluate a single addon against the gate configuration.
pub fn evaluate_addon(
    addon: &AddonDescriptor,
    parity: &[ParityFinding],
    security: &[SecurityFinding],
    throughput: &[ThroughputSample],
    config: &GateConfig,
) -> CohortResult {
    let addon_parity: Vec<ParityFinding> = parity
        .iter()
        .filter(|f| f.addon_name == addon.name)
        .cloned()
        .collect();
    let addon_security: Vec<SecurityFinding> = security
        .iter()
        .filter(|f| f.addon_name == addon.name)
        .cloned()
        .collect();
    let addon_throughput: Vec<ThroughputSample> = throughput
        .iter()
        .filter(|s| s.addon_name == addon.name)
        .cloned()
        .collect();

    let parity_verdict =
        compute_parity_verdict(&addon_parity, config.min_parity_coverage_millionths);
    let security_verdict = compute_security_verdict(&addon_security);
    let throughput_verdict = compute_throughput_verdict(
        &addon_throughput,
        config.max_throughput_regression_millionths,
        config.min_sample_count,
    );

    let overall_verdict = combine_verdicts(&parity_verdict, &security_verdict, &throughput_verdict);
    let governance_action =
        derive_governance_action(&overall_verdict, &security_verdict, &addon.tier);

    CohortResult {
        addon: addon.clone(),
        parity_findings: addon_parity,
        security_findings: addon_security,
        throughput_samples: addon_throughput,
        parity_verdict,
        security_verdict,
        throughput_verdict,
        overall_verdict,
        governance_action,
    }
}

/// Combine parity, security, and throughput verdicts into an overall verdict.
fn combine_verdicts(
    parity: &GateVerdict,
    security: &SecurityVerdict,
    throughput: &GateVerdict,
) -> GateVerdict {
    // Vulnerable security always yields Fail.
    if *security == SecurityVerdict::Vulnerable {
        return GateVerdict::Fail;
    }

    // Any hard failure in parity or throughput yields Fail.
    if *parity == GateVerdict::Fail || *throughput == GateVerdict::Fail {
        return GateVerdict::Fail;
    }

    // Insufficient evidence in any sub-verdict propagates.
    if *parity == GateVerdict::InsufficientEvidence
        || *throughput == GateVerdict::InsufficientEvidence
        || *security == SecurityVerdict::Unassessed
    {
        return GateVerdict::InsufficientEvidence;
    }

    // Conditional in any sub-verdict yields conditional.
    if *parity == GateVerdict::ConditionalPass
        || *throughput == GateVerdict::ConditionalPass
        || *security == SecurityVerdict::ConditionallySecure
    {
        return GateVerdict::ConditionalPass;
    }

    GateVerdict::Pass
}

/// Evaluate the entire cohort gate.
///
/// Processes all addons against the configuration, computing per-addon
/// results and an aggregate cohort verdict with governance action.
pub fn evaluate_cohort_gate(
    config: &GateConfig,
    addons: &[AddonDescriptor],
    parity_findings: &[ParityFinding],
    security_findings: &[SecurityFinding],
    throughput_samples: &[ThroughputSample],
    epoch: SecurityEpoch,
) -> GateReport {
    if addons.is_empty() {
        let input_hash = ContentHash::compute(b"empty_cohort");
        let receipt = compute_receipt(input_hash, &GateVerdict::InsufficientEvidence, epoch);
        return GateReport {
            cohort_results: Vec::new(),
            overall_verdict: GateVerdict::InsufficientEvidence,
            governance_action: GovernanceAction::RequireAudit,
            total_addons: 0,
            passing_addons: 0,
            failing_addons: 0,
            coverage_by_tier: Vec::new(),
            receipt,
        };
    }

    let mut results = Vec::with_capacity(addons.len());
    for addon in addons {
        results.push(evaluate_addon(
            addon,
            parity_findings,
            security_findings,
            throughput_samples,
            config,
        ));
    }

    let passing = results
        .iter()
        .filter(|r| r.overall_verdict.is_adoptable())
        .count();
    let failing = results
        .iter()
        .filter(|r| r.overall_verdict == GateVerdict::Fail)
        .count();

    let coverage_by_tier = compute_tier_coverage(&results);

    // Aggregate overall verdict: any critical/high failure => Fail,
    // otherwise ratio-based.
    let has_critical_failure = results.iter().any(|r| {
        r.overall_verdict == GateVerdict::Fail
            && matches!(r.addon.tier, CohortTier::Critical | CohortTier::High)
    });

    let overall_verdict = if has_critical_failure {
        GateVerdict::Fail
    } else if failing > 0 {
        GateVerdict::ConditionalPass
    } else if passing == results.len() {
        GateVerdict::Pass
    } else {
        GateVerdict::InsufficientEvidence
    };

    let worst_security = results
        .iter()
        .map(|r| r.security_verdict)
        .min()
        .unwrap_or(SecurityVerdict::Unassessed);

    let worst_tier = results
        .iter()
        .filter(|r| !r.overall_verdict.is_adoptable())
        .map(|r| r.addon.tier)
        .min()
        .unwrap_or(CohortTier::Unknown);

    let governance_action =
        derive_governance_action(&overall_verdict, &worst_security, &worst_tier);

    // Compute input hash from all addon names.
    let mut input_buf = Vec::new();
    for addon in addons {
        append_str(&mut input_buf, &addon.name);
        append_str(&mut input_buf, &addon.version);
    }
    append_u64(&mut input_buf, epoch.as_u64());
    let input_hash = ContentHash::compute(&input_buf);

    let receipt = compute_receipt(input_hash, &overall_verdict, epoch);

    GateReport {
        cohort_results: results,
        overall_verdict,
        governance_action,
        total_addons: addons.len(),
        passing_addons: passing,
        failing_addons: failing,
        coverage_by_tier,
        receipt,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addon(name: &str, tier: CohortTier) -> AddonDescriptor {
        AddonDescriptor {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            tier,
            napi_version: 8,
            node_api_calls: 42,
            has_worker_threads: false,
            has_async_hooks: false,
        }
    }

    fn make_parity(
        addon: &str,
        dim: ParityDimension,
        achieved: bool,
        divergences: u32,
        total: u32,
    ) -> ParityFinding {
        ParityFinding {
            dimension: dim,
            addon_name: addon.to_string(),
            is_parity_achieved: achieved,
            divergence_count: divergences,
            total_checks: total,
            detail: format!("{} on {}", dim, addon),
        }
    }

    fn make_security(
        addon: &str,
        class: SecurityClass,
        verdict: SecurityVerdict,
        vulns: u32,
    ) -> SecurityFinding {
        SecurityFinding {
            class,
            addon_name: addon.to_string(),
            verdict,
            vulnerability_count: vulns,
            detail: format!("{} on {}", class, addon),
            content_hash: ContentHash::compute(addon.as_bytes()),
        }
    }

    fn make_throughput(
        addon: &str,
        metric: ThroughputMetric,
        baseline: u64,
        candidate: u64,
        count: u32,
    ) -> ThroughputSample {
        ThroughputSample {
            metric,
            addon_name: addon.to_string(),
            baseline_millionths: baseline,
            candidate_millionths: candidate,
            sample_count: count,
            epoch: SecurityEpoch::from_raw(1),
        }
    }

    fn default_config() -> GateConfig {
        GateConfig::default()
    }

    // ----- Empty / InsufficientEvidence -----

    #[test]
    fn empty_addons_returns_insufficient_evidence() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);
        let report = evaluate_cohort_gate(&config, &[], &[], &[], &[], epoch);
        assert_eq!(report.overall_verdict, GateVerdict::InsufficientEvidence);
        assert_eq!(report.total_addons, 0);
        assert_eq!(report.passing_addons, 0);
        assert_eq!(report.failing_addons, 0);
    }

    #[test]
    fn addon_with_no_findings_is_insufficient_evidence() {
        let config = default_config();
        let addon = make_addon("empty-addon", CohortTier::Medium);
        let result = evaluate_addon(&addon, &[], &[], &[], &config);
        assert_eq!(result.parity_verdict, GateVerdict::InsufficientEvidence);
        assert_eq!(result.security_verdict, SecurityVerdict::Unassessed);
        assert_eq!(result.throughput_verdict, GateVerdict::InsufficientEvidence);
        assert_eq!(result.overall_verdict, GateVerdict::InsufficientEvidence);
    }

    // ----- Single addon passing all gates -----

    #[test]
    fn single_addon_all_pass() {
        let config = default_config();
        let addon = make_addon("good-addon", CohortTier::Medium);
        let parity: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .map(|d| make_parity("good-addon", *d, true, 0, 100))
            .collect();
        let security: Vec<SecurityFinding> = SecurityClass::ALL
            .iter()
            .map(|c| make_security("good-addon", *c, SecurityVerdict::Secure, 0))
            .collect();
        let throughput: Vec<ThroughputSample> = ThroughputMetric::ALL
            .iter()
            .map(|m| make_throughput("good-addon", *m, MILLIONTHS, MILLIONTHS, 10))
            .collect();
        let result = evaluate_addon(&addon, &parity, &security, &throughput, &config);
        assert_eq!(result.parity_verdict, GateVerdict::Pass);
        assert_eq!(result.security_verdict, SecurityVerdict::Secure);
        assert_eq!(result.throughput_verdict, GateVerdict::Pass);
        assert_eq!(result.overall_verdict, GateVerdict::Pass);
        assert_eq!(result.governance_action, GovernanceAction::AllowAdoption);
    }

    // ----- Critical tier + security failure => BlockAdoption -----

    #[test]
    fn critical_addon_security_vulnerable_blocks() {
        let config = default_config();
        let addon = make_addon("vuln-addon", CohortTier::Critical);
        let security = vec![make_security(
            "vuln-addon",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Vulnerable,
            3,
        )];
        let result = evaluate_addon(&addon, &[], &security, &[], &config);
        assert_eq!(result.security_verdict, SecurityVerdict::Vulnerable);
        assert_eq!(result.overall_verdict, GateVerdict::Fail);
        assert_eq!(result.governance_action, GovernanceAction::BlockAdoption);
    }

    #[test]
    fn high_addon_security_vulnerable_blocks() {
        let config = default_config();
        let addon = make_addon("vuln-high", CohortTier::High);
        let security = vec![make_security(
            "vuln-high",
            SecurityClass::SandboxEscapePrevention,
            SecurityVerdict::Vulnerable,
            1,
        )];
        let result = evaluate_addon(&addon, &[], &security, &[], &config);
        assert_eq!(result.governance_action, GovernanceAction::BlockAdoption);
    }

    // ----- Throughput regression above threshold => Fail -----

    #[test]
    fn throughput_regression_above_threshold_fails() {
        let config = default_config();
        // 20% regression: baseline 1_000_000, candidate 1_200_000.
        // max allowed is 100_000 (10%).
        let samples = vec![make_throughput(
            "slow-addon",
            ThroughputMetric::CallLatency,
            MILLIONTHS,
            1_200_000,
            30,
        )];
        let verdict = compute_throughput_verdict(
            &samples,
            config.max_throughput_regression_millionths,
            config.min_sample_count,
        );
        assert_eq!(verdict, GateVerdict::Fail);
    }

    #[test]
    fn throughput_regression_below_half_threshold_passes() {
        let config = default_config();
        // 3% regression: baseline 1_000_000, candidate 1_030_000.
        // max allowed is 100_000 (10%), half is 50_000 (5%).
        let samples = vec![make_throughput(
            "ok-addon",
            ThroughputMetric::CallLatency,
            MILLIONTHS,
            1_030_000,
            30,
        )];
        let verdict = compute_throughput_verdict(
            &samples,
            config.max_throughput_regression_millionths,
            config.min_sample_count,
        );
        assert_eq!(verdict, GateVerdict::Pass);
    }

    #[test]
    fn throughput_regression_between_half_and_full_is_conditional() {
        let config = default_config();
        // 7% regression: baseline 1_000_000, candidate 1_070_000.
        let samples = vec![make_throughput(
            "mid-addon",
            ThroughputMetric::CallLatency,
            MILLIONTHS,
            1_070_000,
            30,
        )];
        let verdict = compute_throughput_verdict(
            &samples,
            config.max_throughput_regression_millionths,
            config.min_sample_count,
        );
        assert_eq!(verdict, GateVerdict::ConditionalPass);
    }

    // ----- Parity coverage below threshold => Fail -----

    #[test]
    fn parity_below_threshold_fails() {
        // 2 of 6 achieved = 333_333, well below 800_000.
        let findings: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .enumerate()
            .map(|(i, d)| make_parity("test-addon", *d, i < 2, if i >= 2 { 5 } else { 0 }, 100))
            .collect();
        let verdict = compute_parity_verdict(&findings, 800_000);
        assert_eq!(verdict, GateVerdict::Fail);
    }

    #[test]
    fn parity_at_threshold_passes() {
        // 5 of 6 achieved = 833_333 >= 800_000.
        let findings: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .enumerate()
            .map(|(i, d)| make_parity("test-addon", *d, i < 5, if i >= 5 { 1 } else { 0 }, 100))
            .collect();
        let verdict = compute_parity_verdict(&findings, 800_000);
        assert_eq!(verdict, GateVerdict::Pass);
    }

    #[test]
    fn parity_at_half_threshold_conditional() {
        // 3 of 6 achieved = 500_000. Half of 800_000 = 400_000. 500_000 >= 400_000.
        let findings: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .enumerate()
            .map(|(i, d)| make_parity("test-addon", *d, i < 3, if i >= 3 { 2 } else { 0 }, 100))
            .collect();
        let verdict = compute_parity_verdict(&findings, 800_000);
        assert_eq!(verdict, GateVerdict::ConditionalPass);
    }

    #[test]
    fn parity_empty_findings_insufficient() {
        let verdict = compute_parity_verdict(&[], 800_000);
        assert_eq!(verdict, GateVerdict::InsufficientEvidence);
    }

    // ----- CohortTier classification -----

    #[test]
    fn cohort_tier_critical() {
        let tier = CohortTier::Critical;
        assert_eq!(tier.as_str(), "critical");
        assert_eq!(format!("{tier}"), "critical");
    }

    #[test]
    fn cohort_tier_high() {
        assert_eq!(CohortTier::High.as_str(), "high");
    }

    #[test]
    fn cohort_tier_medium() {
        assert_eq!(CohortTier::Medium.as_str(), "medium");
    }

    #[test]
    fn cohort_tier_low() {
        assert_eq!(CohortTier::Low.as_str(), "low");
    }

    #[test]
    fn cohort_tier_experimental() {
        assert_eq!(CohortTier::Experimental.as_str(), "experimental");
    }

    #[test]
    fn cohort_tier_unknown() {
        assert_eq!(CohortTier::Unknown.as_str(), "unknown");
    }

    // ----- ParityDimension -----

    #[test]
    fn parity_dimension_all_variants() {
        assert_eq!(ParityDimension::ALL.len(), 6);
        assert_eq!(ParityDimension::ApiSurface.as_str(), "api_surface");
        assert_eq!(ParityDimension::MemorySafety.as_str(), "memory_safety");
        assert_eq!(ParityDimension::ThreadSafety.as_str(), "thread_safety");
        assert_eq!(ParityDimension::ErrorSemantics.as_str(), "error_semantics");
        assert_eq!(
            ParityDimension::LifecycleCompliance.as_str(),
            "lifecycle_compliance"
        );
        assert_eq!(ParityDimension::AbiStability.as_str(), "abi_stability");
    }

    // ----- SecurityClass -----

    #[test]
    fn security_class_all_variants() {
        assert_eq!(SecurityClass::ALL.len(), 6);
        assert_eq!(SecurityClass::MemoryIsolation.as_str(), "memory_isolation");
        assert_eq!(
            SecurityClass::ResourceBounding.as_str(),
            "resource_bounding"
        );
        assert_eq!(
            SecurityClass::CapabilityRestriction.as_str(),
            "capability_restriction"
        );
        assert_eq!(
            SecurityClass::SandboxEscapePrevention.as_str(),
            "sandbox_escape_prevention"
        );
        assert_eq!(SecurityClass::InputValidation.as_str(), "input_validation");
        assert_eq!(
            SecurityClass::OutputSanitization.as_str(),
            "output_sanitization"
        );
    }

    // ----- ThroughputMetric -----

    #[test]
    fn throughput_metric_all_variants() {
        assert_eq!(ThroughputMetric::ALL.len(), 6);
        assert_eq!(ThroughputMetric::CallLatency.as_str(), "call_latency");
        assert_eq!(
            ThroughputMetric::BatchThroughput.as_str(),
            "batch_throughput"
        );
        assert_eq!(ThroughputMetric::MemoryOverhead.as_str(), "memory_overhead");
        assert_eq!(ThroughputMetric::GcPressure.as_str(), "gc_pressure");
        assert_eq!(
            ThroughputMetric::ContextSwitchCost.as_str(),
            "context_switch_cost"
        );
        assert_eq!(ThroughputMetric::StartupPenalty.as_str(), "startup_penalty");
    }

    // ----- GateVerdict -----

    #[test]
    fn gate_verdict_adoptability() {
        assert!(GateVerdict::Pass.is_adoptable());
        assert!(GateVerdict::ConditionalPass.is_adoptable());
        assert!(!GateVerdict::Fail.is_adoptable());
        assert!(!GateVerdict::InsufficientEvidence.is_adoptable());
    }

    #[test]
    fn gate_verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Pass), "pass");
        assert_eq!(
            format!("{}", GateVerdict::ConditionalPass),
            "conditional_pass"
        );
        assert_eq!(format!("{}", GateVerdict::Fail), "fail");
        assert_eq!(
            format!("{}", GateVerdict::InsufficientEvidence),
            "insufficient_evidence"
        );
    }

    // ----- SecurityVerdict -----

    #[test]
    fn security_verdict_display() {
        assert_eq!(SecurityVerdict::Secure.as_str(), "secure");
        assert_eq!(
            SecurityVerdict::ConditionallySecure.as_str(),
            "conditionally_secure"
        );
        assert_eq!(SecurityVerdict::Vulnerable.as_str(), "vulnerable");
        assert_eq!(SecurityVerdict::Unassessed.as_str(), "unassessed");
    }

    #[test]
    fn security_verdict_all_secure() {
        let findings = vec![
            make_security(
                "a",
                SecurityClass::MemoryIsolation,
                SecurityVerdict::Secure,
                0,
            ),
            make_security(
                "a",
                SecurityClass::InputValidation,
                SecurityVerdict::Secure,
                0,
            ),
        ];
        assert_eq!(compute_security_verdict(&findings), SecurityVerdict::Secure);
    }

    #[test]
    fn security_verdict_one_vulnerable() {
        let findings = vec![
            make_security(
                "a",
                SecurityClass::MemoryIsolation,
                SecurityVerdict::Secure,
                0,
            ),
            make_security(
                "a",
                SecurityClass::InputValidation,
                SecurityVerdict::Vulnerable,
                2,
            ),
        ];
        assert_eq!(
            compute_security_verdict(&findings),
            SecurityVerdict::Vulnerable
        );
    }

    #[test]
    fn security_verdict_conditionally_secure() {
        let findings = vec![
            make_security(
                "a",
                SecurityClass::MemoryIsolation,
                SecurityVerdict::Secure,
                0,
            ),
            make_security(
                "a",
                SecurityClass::OutputSanitization,
                SecurityVerdict::ConditionallySecure,
                0,
            ),
        ];
        assert_eq!(
            compute_security_verdict(&findings),
            SecurityVerdict::ConditionallySecure
        );
    }

    #[test]
    fn security_verdict_empty_is_unassessed() {
        assert_eq!(compute_security_verdict(&[]), SecurityVerdict::Unassessed);
    }

    #[test]
    fn security_verdict_unassessed_propagates() {
        let findings = vec![
            make_security(
                "a",
                SecurityClass::MemoryIsolation,
                SecurityVerdict::Secure,
                0,
            ),
            make_security(
                "a",
                SecurityClass::ResourceBounding,
                SecurityVerdict::Unassessed,
                0,
            ),
        ];
        assert_eq!(
            compute_security_verdict(&findings),
            SecurityVerdict::Unassessed
        );
    }

    // ----- GovernanceAction derivation -----

    #[test]
    fn governance_pass_secure_allows() {
        let action = derive_governance_action(
            &GateVerdict::Pass,
            &SecurityVerdict::Secure,
            &CohortTier::Medium,
        );
        assert_eq!(action, GovernanceAction::AllowAdoption);
    }

    #[test]
    fn governance_pass_conditional_security() {
        let action = derive_governance_action(
            &GateVerdict::Pass,
            &SecurityVerdict::ConditionallySecure,
            &CohortTier::Medium,
        );
        assert_eq!(action, GovernanceAction::ConditionalAdoption);
    }

    #[test]
    fn governance_conditional_pass() {
        let action = derive_governance_action(
            &GateVerdict::ConditionalPass,
            &SecurityVerdict::Secure,
            &CohortTier::High,
        );
        assert_eq!(action, GovernanceAction::ConditionalAdoption);
    }

    #[test]
    fn governance_fail_critical_blocks() {
        let action = derive_governance_action(
            &GateVerdict::Fail,
            &SecurityVerdict::Secure,
            &CohortTier::Critical,
        );
        assert_eq!(action, GovernanceAction::BlockAdoption);
    }

    #[test]
    fn governance_fail_medium_remediates() {
        let action = derive_governance_action(
            &GateVerdict::Fail,
            &SecurityVerdict::Secure,
            &CohortTier::Medium,
        );
        assert_eq!(action, GovernanceAction::RequireRemediation);
    }

    #[test]
    fn governance_fail_low_downgrades() {
        let action = derive_governance_action(
            &GateVerdict::Fail,
            &SecurityVerdict::Secure,
            &CohortTier::Low,
        );
        assert_eq!(action, GovernanceAction::DowngradeTier);
    }

    #[test]
    fn governance_vulnerable_critical_blocks() {
        let action = derive_governance_action(
            &GateVerdict::Pass,
            &SecurityVerdict::Vulnerable,
            &CohortTier::Critical,
        );
        assert_eq!(action, GovernanceAction::BlockAdoption);
    }

    #[test]
    fn governance_vulnerable_low_remediates() {
        let action = derive_governance_action(
            &GateVerdict::Pass,
            &SecurityVerdict::Vulnerable,
            &CohortTier::Low,
        );
        assert_eq!(action, GovernanceAction::RequireRemediation);
    }

    #[test]
    fn governance_insufficient_critical_audits() {
        let action = derive_governance_action(
            &GateVerdict::InsufficientEvidence,
            &SecurityVerdict::Secure,
            &CohortTier::Critical,
        );
        assert_eq!(action, GovernanceAction::RequireAudit);
    }

    #[test]
    fn governance_insufficient_experimental_conditional() {
        let action = derive_governance_action(
            &GateVerdict::InsufficientEvidence,
            &SecurityVerdict::Secure,
            &CohortTier::Experimental,
        );
        assert_eq!(action, GovernanceAction::ConditionalAdoption);
    }

    #[test]
    fn governance_unassessed_critical_audits() {
        let action = derive_governance_action(
            &GateVerdict::Pass,
            &SecurityVerdict::Unassessed,
            &CohortTier::High,
        );
        assert_eq!(action, GovernanceAction::RequireAudit);
    }

    // ----- Receipt computation -----

    #[test]
    fn receipt_determinism() {
        let hash = ContentHash::compute(b"test-input");
        let epoch = SecurityEpoch::from_raw(5);
        let r1 = compute_receipt(hash.clone(), &GateVerdict::Pass, epoch);
        let r2 = compute_receipt(hash, &GateVerdict::Pass, epoch);
        assert_eq!(r1.verdict_hash, r2.verdict_hash);
        assert_eq!(r1.schema_version, SCHEMA_VERSION);
        assert_eq!(r1.component, COMPONENT);
        assert_eq!(r1.bead_id, BEAD_ID);
        assert_eq!(r1.policy_id, POLICY_ID);
    }

    #[test]
    fn receipt_different_verdicts_differ() {
        let hash = ContentHash::compute(b"test-input");
        let epoch = SecurityEpoch::from_raw(5);
        let r1 = compute_receipt(hash.clone(), &GateVerdict::Pass, epoch);
        let r2 = compute_receipt(hash, &GateVerdict::Fail, epoch);
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn receipt_different_epochs_differ() {
        let hash = ContentHash::compute(b"test-input");
        let r1 = compute_receipt(hash.clone(), &GateVerdict::Pass, SecurityEpoch::from_raw(1));
        let r2 = compute_receipt(hash, &GateVerdict::Pass, SecurityEpoch::from_raw(2));
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    // ----- Config defaults -----

    #[test]
    fn config_defaults() {
        let config = GateConfig::default();
        assert_eq!(config.min_parity_coverage_millionths, 800_000);
        assert_eq!(config.max_throughput_regression_millionths, 100_000);
        assert!(config.require_security_audit);
        assert!(config.required_tiers.is_empty());
        assert_eq!(config.min_sample_count, 30);
    }

    // ----- Tier coverage -----

    #[test]
    fn tier_coverage_empty_results() {
        let coverage = compute_tier_coverage(&[]);
        assert!(coverage.is_empty());
    }

    #[test]
    fn tier_coverage_single_tier_all_pass() {
        let config = default_config();
        let addon = make_addon("a1", CohortTier::Medium);
        let parity: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .map(|d| make_parity("a1", *d, true, 0, 100))
            .collect();
        let security: Vec<SecurityFinding> = SecurityClass::ALL
            .iter()
            .map(|c| make_security("a1", *c, SecurityVerdict::Secure, 0))
            .collect();
        let throughput: Vec<ThroughputSample> = ThroughputMetric::ALL
            .iter()
            .map(|m| make_throughput("a1", *m, MILLIONTHS, MILLIONTHS, 10))
            .collect();
        let result = evaluate_addon(&addon, &parity, &security, &throughput, &config);
        let coverage = compute_tier_coverage(&[result]);
        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0].0, CohortTier::Medium);
        assert_eq!(coverage[0].1, MILLIONTHS); // 100%
    }

    // ----- Mixed multi-addon scenarios -----

    #[test]
    fn mixed_cohort_some_pass_some_fail() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);

        let addons = vec![
            make_addon("good", CohortTier::Medium),
            make_addon("bad", CohortTier::Medium),
        ];

        let parity: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .flat_map(|d| {
                vec![
                    make_parity("good", *d, true, 0, 100),
                    make_parity("bad", *d, false, 10, 100),
                ]
            })
            .collect();

        let security: Vec<SecurityFinding> = SecurityClass::ALL
            .iter()
            .flat_map(|c| {
                vec![
                    make_security("good", *c, SecurityVerdict::Secure, 0),
                    make_security("bad", *c, SecurityVerdict::Secure, 0),
                ]
            })
            .collect();

        let throughput: Vec<ThroughputSample> = ThroughputMetric::ALL
            .iter()
            .flat_map(|m| {
                vec![
                    make_throughput("good", *m, MILLIONTHS, MILLIONTHS, 10),
                    make_throughput("bad", *m, MILLIONTHS, MILLIONTHS, 10),
                ]
            })
            .collect();

        let report = evaluate_cohort_gate(&config, &addons, &parity, &security, &throughput, epoch);
        assert_eq!(report.total_addons, 2);
        // "good" passes, "bad" fails parity => overall cohort conditional
        assert_eq!(report.cohort_results[0].overall_verdict, GateVerdict::Pass);
        assert_eq!(report.cohort_results[1].overall_verdict, GateVerdict::Fail);
        assert_eq!(report.overall_verdict, GateVerdict::ConditionalPass);
    }

    #[test]
    fn critical_failure_propagates_to_cohort() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(1);

        let addons = vec![make_addon("critical-fail", CohortTier::Critical)];
        let security = vec![make_security(
            "critical-fail",
            SecurityClass::MemoryIsolation,
            SecurityVerdict::Vulnerable,
            5,
        )];

        let report = evaluate_cohort_gate(&config, &addons, &[], &security, &[], epoch);
        assert_eq!(report.overall_verdict, GateVerdict::Fail);
        assert_eq!(report.governance_action, GovernanceAction::BlockAdoption);
    }

    // ----- Boundary cases -----

    #[test]
    fn throughput_no_regression_passes() {
        let samples = vec![make_throughput(
            "fast",
            ThroughputMetric::CallLatency,
            MILLIONTHS,
            MILLIONTHS,
            30,
        )];
        let verdict = compute_throughput_verdict(&samples, 100_000, 30);
        assert_eq!(verdict, GateVerdict::Pass);
    }

    #[test]
    fn throughput_candidate_better_than_baseline_passes() {
        let samples = vec![make_throughput(
            "faster",
            ThroughputMetric::CallLatency,
            MILLIONTHS,
            900_000,
            30,
        )];
        let verdict = compute_throughput_verdict(&samples, 100_000, 30);
        assert_eq!(verdict, GateVerdict::Pass);
    }

    #[test]
    fn throughput_insufficient_sample_count() {
        let samples = vec![make_throughput(
            "few",
            ThroughputMetric::CallLatency,
            MILLIONTHS,
            1_200_000,
            5,
        )];
        let verdict = compute_throughput_verdict(&samples, 100_000, 30);
        assert_eq!(verdict, GateVerdict::InsufficientEvidence);
    }

    #[test]
    fn throughput_empty_samples() {
        let verdict = compute_throughput_verdict(&[], 100_000, 30);
        assert_eq!(verdict, GateVerdict::InsufficientEvidence);
    }

    #[test]
    fn throughput_zero_baseline_skipped() {
        let samples = vec![make_throughput(
            "zero-base",
            ThroughputMetric::CallLatency,
            0,
            1_200_000,
            30,
        )];
        let verdict = compute_throughput_verdict(&samples, 100_000, 30);
        assert_eq!(verdict, GateVerdict::Pass);
    }

    // ----- Parity exactly at boundaries -----

    #[test]
    fn parity_all_achieved_passes() {
        let findings = vec![make_parity("a", ParityDimension::ApiSurface, true, 0, 100)];
        let verdict = compute_parity_verdict(&findings, MILLIONTHS);
        assert_eq!(verdict, GateVerdict::Pass);
    }

    #[test]
    fn parity_none_achieved_fails() {
        let findings = vec![make_parity(
            "a",
            ParityDimension::ApiSurface,
            false,
            50,
            100,
        )];
        let verdict = compute_parity_verdict(&findings, 800_000);
        assert_eq!(verdict, GateVerdict::Fail);
    }

    // ----- High-tier conditional pass scenario -----

    #[test]
    fn high_tier_conditional_pass() {
        let config = default_config();
        let addon = make_addon("cond-addon", CohortTier::High);
        // Parity: 4 of 6 achieved = 666_666. Half of 800_000 = 400_000 => conditional.
        let parity: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .enumerate()
            .map(|(i, d)| make_parity("cond-addon", *d, i < 4, if i >= 4 { 3 } else { 0 }, 100))
            .collect();
        let security: Vec<SecurityFinding> = SecurityClass::ALL
            .iter()
            .map(|c| make_security("cond-addon", *c, SecurityVerdict::Secure, 0))
            .collect();
        let throughput: Vec<ThroughputSample> = ThroughputMetric::ALL
            .iter()
            .map(|m| make_throughput("cond-addon", *m, MILLIONTHS, MILLIONTHS, 10))
            .collect();
        let result = evaluate_addon(&addon, &parity, &security, &throughput, &config);
        assert_eq!(result.parity_verdict, GateVerdict::ConditionalPass);
        assert_eq!(result.overall_verdict, GateVerdict::ConditionalPass);
        assert_eq!(
            result.governance_action,
            GovernanceAction::ConditionalAdoption
        );
    }

    // ----- GovernanceAction display -----

    #[test]
    fn governance_action_display() {
        assert_eq!(GovernanceAction::AllowAdoption.as_str(), "allow_adoption");
        assert_eq!(
            GovernanceAction::ConditionalAdoption.as_str(),
            "conditional_adoption"
        );
        assert_eq!(GovernanceAction::BlockAdoption.as_str(), "block_adoption");
        assert_eq!(GovernanceAction::RequireAudit.as_str(), "require_audit");
        assert_eq!(GovernanceAction::DowngradeTier.as_str(), "downgrade_tier");
        assert_eq!(
            GovernanceAction::RequireRemediation.as_str(),
            "require_remediation"
        );
    }

    // ----- Constants -----

    #[test]
    fn constants_correct() {
        assert_eq!(SCHEMA_VERSION, "franken-engine.native-addon-cohort-gate.v1");
        assert_eq!(COMPONENT, "native_addon_cohort_gate");
        assert_eq!(BEAD_ID, "bd-1lsy.5.9.3");
        assert_eq!(POLICY_ID, "RGC-407C");
    }

    // ----- Combine verdicts -----

    #[test]
    fn combine_all_pass() {
        let v = combine_verdicts(
            &GateVerdict::Pass,
            &SecurityVerdict::Secure,
            &GateVerdict::Pass,
        );
        assert_eq!(v, GateVerdict::Pass);
    }

    #[test]
    fn combine_parity_fail() {
        let v = combine_verdicts(
            &GateVerdict::Fail,
            &SecurityVerdict::Secure,
            &GateVerdict::Pass,
        );
        assert_eq!(v, GateVerdict::Fail);
    }

    #[test]
    fn combine_throughput_fail() {
        let v = combine_verdicts(
            &GateVerdict::Pass,
            &SecurityVerdict::Secure,
            &GateVerdict::Fail,
        );
        assert_eq!(v, GateVerdict::Fail);
    }

    #[test]
    fn combine_security_vulnerable() {
        let v = combine_verdicts(
            &GateVerdict::Pass,
            &SecurityVerdict::Vulnerable,
            &GateVerdict::Pass,
        );
        assert_eq!(v, GateVerdict::Fail);
    }

    #[test]
    fn combine_parity_conditional() {
        let v = combine_verdicts(
            &GateVerdict::ConditionalPass,
            &SecurityVerdict::Secure,
            &GateVerdict::Pass,
        );
        assert_eq!(v, GateVerdict::ConditionalPass);
    }

    #[test]
    fn combine_security_unassessed_propagates() {
        let v = combine_verdicts(
            &GateVerdict::Pass,
            &SecurityVerdict::Unassessed,
            &GateVerdict::Pass,
        );
        assert_eq!(v, GateVerdict::InsufficientEvidence);
    }

    // ----- Addon descriptor fields -----

    #[test]
    fn addon_descriptor_fields() {
        let addon = AddonDescriptor {
            name: "sharp".to_string(),
            version: "0.33.0".to_string(),
            tier: CohortTier::Critical,
            napi_version: 9,
            node_api_calls: 127,
            has_worker_threads: true,
            has_async_hooks: true,
        };
        assert_eq!(addon.name, "sharp");
        assert_eq!(addon.tier, CohortTier::Critical);
        assert!(addon.has_worker_threads);
        assert!(addon.has_async_hooks);
        assert_eq!(addon.napi_version, 9);
        assert_eq!(addon.node_api_calls, 127);
    }

    // ----- Serde round-trip -----

    #[test]
    fn cohort_tier_serde_roundtrip() {
        let tier = CohortTier::Critical;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"critical\"");
        let parsed: CohortTier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tier);
    }

    #[test]
    fn gate_verdict_serde_roundtrip() {
        let verdict = GateVerdict::ConditionalPass;
        let json = serde_json::to_string(&verdict).unwrap();
        assert_eq!(json, "\"conditional_pass\"");
        let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, verdict);
    }

    // ----- Full cohort gate with all addons passing -----

    #[test]
    fn full_cohort_all_pass() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(3);
        let addons = vec![
            make_addon("a1", CohortTier::Critical),
            make_addon("a2", CohortTier::High),
        ];

        let parity: Vec<ParityFinding> = addons
            .iter()
            .flat_map(|a| {
                ParityDimension::ALL
                    .iter()
                    .map(move |d| make_parity(&a.name, *d, true, 0, 100))
            })
            .collect();

        let security: Vec<SecurityFinding> = addons
            .iter()
            .flat_map(|a| {
                SecurityClass::ALL
                    .iter()
                    .map(move |c| make_security(&a.name, *c, SecurityVerdict::Secure, 0))
            })
            .collect();

        let throughput: Vec<ThroughputSample> = addons
            .iter()
            .flat_map(|a| {
                ThroughputMetric::ALL
                    .iter()
                    .map(move |m| make_throughput(&a.name, *m, MILLIONTHS, MILLIONTHS, 10))
            })
            .collect();

        let report = evaluate_cohort_gate(&config, &addons, &parity, &security, &throughput, epoch);
        assert_eq!(report.overall_verdict, GateVerdict::Pass);
        assert_eq!(report.governance_action, GovernanceAction::AllowAdoption);
        assert_eq!(report.total_addons, 2);
        assert_eq!(report.passing_addons, 2);
        assert_eq!(report.failing_addons, 0);
        assert_eq!(report.coverage_by_tier.len(), 2);
    }

    // ----- Tier coverage with mixed tiers -----

    #[test]
    fn tier_coverage_mixed() {
        let config = default_config();
        let a1 = make_addon("pass-crit", CohortTier::Critical);
        let a2 = make_addon("fail-crit", CohortTier::Critical);

        let p1: Vec<ParityFinding> = ParityDimension::ALL
            .iter()
            .map(|d| make_parity("pass-crit", *d, true, 0, 100))
            .collect();
        let s1: Vec<SecurityFinding> = SecurityClass::ALL
            .iter()
            .map(|c| make_security("pass-crit", *c, SecurityVerdict::Secure, 0))
            .collect();
        let t1: Vec<ThroughputSample> = ThroughputMetric::ALL
            .iter()
            .map(|m| make_throughput("pass-crit", *m, MILLIONTHS, MILLIONTHS, 10))
            .collect();

        let r1 = evaluate_addon(&a1, &p1, &s1, &t1, &config);
        let r2 = evaluate_addon(&a2, &[], &[], &[], &config); // no findings

        let coverage = compute_tier_coverage(&[r1, r2]);
        assert_eq!(coverage.len(), 1); // both Critical
        assert_eq!(coverage[0].0, CohortTier::Critical);
        // 1 of 2 pass => 500_000
        assert_eq!(coverage[0].1, 500_000);
    }

    // ----- Governance fail experimental downgrades -----

    #[test]
    fn governance_fail_experimental_downgrades() {
        let action = derive_governance_action(
            &GateVerdict::Fail,
            &SecurityVerdict::Secure,
            &CohortTier::Experimental,
        );
        assert_eq!(action, GovernanceAction::DowngradeTier);
    }

    // ----- Report receipt is populated -----

    #[test]
    fn report_receipt_populated() {
        let config = default_config();
        let epoch = SecurityEpoch::from_raw(7);
        let addons = vec![make_addon("r", CohortTier::Low)];
        let report = evaluate_cohort_gate(&config, &addons, &[], &[], &[], epoch);
        assert_eq!(report.receipt.epoch, epoch);
        assert_eq!(report.receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(report.receipt.bead_id, BEAD_ID);
    }
}
