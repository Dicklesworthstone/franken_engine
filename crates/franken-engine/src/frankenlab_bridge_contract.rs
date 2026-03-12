#![forbid(unsafe_code)]
//! Upstream frankenlab bridge contract for deterministic lab integration.
//!
//! Bead: bd-3nr.1.4.1 \[10.13X.D1\]
//!
//! Defines the explicit contract surface between FrankenEngine's local lab
//! infrastructure (`lab_runtime`, `deterministic_replay`, `evidence_replay_checker`)
//! and upstream `asupersync::lab` semantics. The bridge enforces a narrow,
//! auditable API boundary through which scenario execution, evidence linkage,
//! replay determinism, and fault injection flow without either side leaking
//! implementation internals.
//!
//! The contract covers five integration seams:
//! 1. Scenario execution — mapping upstream scenario manifests to local
//!    `LabRuntime` runs with evidence linkage.
//! 2. Replay determinism — verifying `TraceCertificateSnapshot` equivalence
//!    across seeds and binary versions.
//! 3. Evidence linkage — connecting scenario run results to the canonical
//!    evidence ledger via `EngineObjectId`.
//! 4. Fault injection — mapping upstream fault actions to local `FaultKind`
//!    with policy-bounded injection.
//! 5. Oracle dispatch — routing oracle invariant checks through the bridge
//!    with fail-closed enforcement.
//!
//! Plan references: Section 10.13X item D1.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the bridge contract format.
pub const BRIDGE_CONTRACT_SCHEMA_VERSION: &str = "franken-engine.frankenlab-bridge-contract.v1";

/// Bead identifier for this module.
pub const BRIDGE_CONTRACT_BEAD_ID: &str = "bd-3nr.1.4.1";

/// Fixed-point scale factor (1_000_000 = 1.0).
const SCALE: u64 = 1_000_000;

/// Default minimum acceptable replay confidence (95%).
const DEFAULT_MIN_REPLAY_CONFIDENCE: u64 = 950_000;

/// Default maximum oracle failures before bridge failure.
const DEFAULT_MAX_ORACLE_FAILURES: usize = 0;

/// Default fault injection budget per scenario run (ms).
const DEFAULT_FAULT_INJECTION_BUDGET_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// BridgeMode — how the bridge connects local to upstream
// ---------------------------------------------------------------------------

/// How the bridge routes between local and upstream lab surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeMode {
    /// Route through upstream crate directly (direct dependency).
    DirectDependency,
    /// Route through a narrow adapter that translates types.
    ThinAdapter,
    /// Use local implementation with upstream validation overlay.
    LocalWithUpstreamValidation,
    /// Local-only — upstream not yet available or deferred.
    LocalOnly,
}

impl fmt::Display for BridgeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectDependency => write!(f, "direct_dependency"),
            Self::ThinAdapter => write!(f, "thin_adapter"),
            Self::LocalWithUpstreamValidation => write!(f, "local_with_upstream_validation"),
            Self::LocalOnly => write!(f, "local_only"),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeSeam — the five integration seams
// ---------------------------------------------------------------------------

/// The five integration seams covered by the bridge contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeSeam {
    /// Scenario execution: manifests → LabRuntime runs.
    ScenarioExecution,
    /// Replay determinism: TraceCertificate equivalence across runs.
    ReplayDeterminism,
    /// Evidence linkage: run results → evidence ledger entries.
    EvidenceLinkage,
    /// Fault injection: upstream faults → local FaultKind.
    FaultInjection,
    /// Oracle dispatch: invariant checks with fail-closed enforcement.
    OracleDispatch,
}

impl BridgeSeam {
    /// All seams in deterministic order.
    pub const ALL: [Self; 5] = [
        Self::ScenarioExecution,
        Self::ReplayDeterminism,
        Self::EvidenceLinkage,
        Self::FaultInjection,
        Self::OracleDispatch,
    ];
}

impl fmt::Display for BridgeSeam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScenarioExecution => write!(f, "scenario_execution"),
            Self::ReplayDeterminism => write!(f, "replay_determinism"),
            Self::EvidenceLinkage => write!(f, "evidence_linkage"),
            Self::FaultInjection => write!(f, "fault_injection"),
            Self::OracleDispatch => write!(f, "oracle_dispatch"),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeSeamConfig — per-seam configuration
// ---------------------------------------------------------------------------

/// Configuration for a single bridge seam.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSeamConfig {
    /// Which seam this configures.
    pub seam: BridgeSeam,
    /// Bridge routing mode for this seam.
    pub mode: BridgeMode,
    /// Whether this seam is fail-closed (blocks on any error).
    pub fail_closed: bool,
    /// Maximum tolerated latency for this seam in milliseconds.
    pub max_latency_ms: u64,
    /// Whether to emit evidence entries for bridge transitions.
    pub emit_evidence: bool,
    /// Human-readable rationale for the chosen mode.
    pub rationale: String,
}

impl BridgeSeamConfig {
    /// Create a fail-closed seam config with default settings.
    pub fn fail_closed(seam: BridgeSeam, mode: BridgeMode) -> Self {
        Self {
            seam,
            mode,
            fail_closed: true,
            max_latency_ms: 5_000,
            emit_evidence: true,
            rationale: String::new(),
        }
    }

    /// Create a lenient seam config (fail-open, no evidence).
    pub fn lenient(seam: BridgeSeam, mode: BridgeMode) -> Self {
        Self {
            seam,
            mode,
            fail_closed: false,
            max_latency_ms: 30_000,
            emit_evidence: false,
            rationale: String::new(),
        }
    }

    /// Set the rationale.
    pub fn with_rationale(mut self, rationale: &str) -> Self {
        self.rationale = rationale.to_owned();
        self
    }
}

// ---------------------------------------------------------------------------
// ScenarioManifest — upstream scenario descriptor
// ---------------------------------------------------------------------------

/// Describes an upstream scenario manifest for bridge execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioManifest {
    /// Unique scenario identifier.
    pub scenario_id: String,
    /// Schema version of the scenario format.
    pub schema_version: u32,
    /// Human-readable description.
    pub description: String,
    /// Deterministic seed for the scenario.
    pub seed: u64,
    /// Maximum steps allowed before timeout.
    pub max_steps: u64,
    /// Whether to panic on obligation leaks.
    pub panic_on_obligation_leak: bool,
    /// Fault injection specs (fault_name → injection_at_ms).
    pub fault_schedule: BTreeMap<String, u64>,
    /// Oracle invariants to check.
    pub oracle_invariants: BTreeSet<String>,
    /// Cancellation targets (region_id → cancel_at_ms).
    pub cancellation_schedule: BTreeMap<String, u64>,
}

impl ScenarioManifest {
    /// Create a minimal scenario manifest.
    pub fn new(scenario_id: &str, seed: u64) -> Self {
        Self {
            scenario_id: scenario_id.to_owned(),
            schema_version: 1,
            description: String::new(),
            seed,
            max_steps: 100_000,
            panic_on_obligation_leak: true,
            fault_schedule: BTreeMap::new(),
            oracle_invariants: BTreeSet::new(),
            cancellation_schedule: BTreeMap::new(),
        }
    }

    /// Add a fault to the schedule.
    pub fn add_fault(&mut self, fault_name: &str, at_ms: u64) {
        self.fault_schedule.insert(fault_name.to_owned(), at_ms);
    }

    /// Add an oracle invariant to check.
    pub fn add_oracle(&mut self, invariant: &str) {
        self.oracle_invariants.insert(invariant.to_owned());
    }

    /// Add a cancellation target.
    pub fn add_cancellation(&mut self, region_id: &str, at_ms: u64) {
        self.cancellation_schedule
            .insert(region_id.to_owned(), at_ms);
    }

    /// Whether this manifest has any fault injection.
    pub fn has_faults(&self) -> bool {
        !self.fault_schedule.is_empty()
    }

    /// Whether this manifest has oracle checks.
    pub fn has_oracles(&self) -> bool {
        !self.oracle_invariants.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TraceCertificate — determinism proof for a single run
// ---------------------------------------------------------------------------

/// Determinism proof: fingerprint of event sequence and schedule for one run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceCertificate {
    /// Hash of the event sequence.
    pub event_hash: ContentHash,
    /// Hash of the schedule transcript.
    pub schedule_hash: ContentHash,
    /// Total number of steps executed.
    pub steps: u64,
    /// Combined trace fingerprint.
    pub trace_fingerprint: ContentHash,
    /// Seed used for this run.
    pub seed: u64,
}

impl TraceCertificate {
    /// Create a certificate from raw hashes.
    pub fn new(
        event_hash: ContentHash,
        schedule_hash: ContentHash,
        steps: u64,
        trace_fingerprint: ContentHash,
        seed: u64,
    ) -> Self {
        Self {
            event_hash,
            schedule_hash,
            steps,
            trace_fingerprint,
            seed,
        }
    }

    /// Check equivalence with another certificate (same-seed replay).
    pub fn is_equivalent(&self, other: &Self) -> bool {
        self.event_hash == other.event_hash
            && self.schedule_hash == other.schedule_hash
            && self.steps == other.steps
            && self.trace_fingerprint == other.trace_fingerprint
    }
}

// ---------------------------------------------------------------------------
// ReplayVerdict — result of replay determinism check
// ---------------------------------------------------------------------------

/// Result of comparing two runs for replay determinism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayVerdict {
    /// Both runs produced identical certificates.
    Deterministic,
    /// Runs diverged.
    Diverged {
        event_match: bool,
        schedule_match: bool,
        step_match: bool,
        fingerprint_match: bool,
    },
    /// One or both runs failed before producing a certificate.
    InfrastructureFailure { detail: String },
}

impl ReplayVerdict {
    /// Whether this verdict indicates determinism.
    pub fn is_deterministic(&self) -> bool {
        matches!(self, Self::Deterministic)
    }

    /// Whether this verdict is a hard failure.
    pub fn is_failure(&self) -> bool {
        !self.is_deterministic()
    }
}

impl fmt::Display for ReplayVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deterministic => write!(f, "deterministic"),
            Self::Diverged {
                event_match,
                schedule_match,
                step_match,
                fingerprint_match,
            } => {
                write!(
                    f,
                    "diverged(event={event_match}, schedule={schedule_match}, \
                     steps={step_match}, fingerprint={fingerprint_match})"
                )
            }
            Self::InfrastructureFailure { detail } => {
                write!(f, "infrastructure_failure: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OracleResult — result of a single oracle invariant check
// ---------------------------------------------------------------------------

/// Result of checking a single oracle invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleResult {
    /// Name of the oracle invariant.
    pub invariant_name: String,
    /// Whether the invariant held.
    pub passed: bool,
    /// Diagnostic detail (empty if passed).
    pub detail: String,
    /// Virtual time at which the check was performed.
    pub checked_at_vt: u64,
}

impl OracleResult {
    /// Create a passing result.
    pub fn pass(invariant_name: &str, checked_at_vt: u64) -> Self {
        Self {
            invariant_name: invariant_name.to_owned(),
            passed: true,
            detail: String::new(),
            checked_at_vt,
        }
    }

    /// Create a failing result with detail.
    pub fn fail(invariant_name: &str, detail: &str, checked_at_vt: u64) -> Self {
        Self {
            invariant_name: invariant_name.to_owned(),
            passed: false,
            detail: detail.to_owned(),
            checked_at_vt,
        }
    }
}

// ---------------------------------------------------------------------------
// FaultInjectionSpec — policy-bounded fault injection
// ---------------------------------------------------------------------------

/// Specifies a fault injection constrained by bridge policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultInjectionSpec {
    /// Fault category (maps to local FaultKind).
    pub fault_category: FaultCategory,
    /// Virtual time at which to inject.
    pub inject_at_vt: u64,
    /// Target task or region (if applicable).
    pub target: FaultTarget,
    /// Budget consumed by this injection (ms).
    pub budget_cost_ms: u64,
}

/// Fault categories that map to local `FaultKind` variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultCategory {
    /// Task panic at next step.
    TaskPanic,
    /// Channel disconnection between components.
    ChannelDisconnect,
    /// Obligation not resolved within deadline.
    ObligationLeak,
    /// Deadline expiration for a region/task.
    DeadlineExpiry,
    /// Forced region close.
    RegionClose,
    /// Network partition (upstream only, mapped to channel disconnect locally).
    NetworkPartition,
    /// Resource exhaustion (upstream only, mapped to deadline expiry locally).
    ResourceExhaustion,
}

impl FaultCategory {
    /// All variants in deterministic order.
    pub const ALL: [Self; 7] = [
        Self::TaskPanic,
        Self::ChannelDisconnect,
        Self::ObligationLeak,
        Self::DeadlineExpiry,
        Self::RegionClose,
        Self::NetworkPartition,
        Self::ResourceExhaustion,
    ];

    /// Whether this category has a direct local `FaultKind` equivalent.
    pub fn has_local_equivalent(&self) -> bool {
        matches!(
            self,
            Self::TaskPanic
                | Self::ChannelDisconnect
                | Self::ObligationLeak
                | Self::DeadlineExpiry
                | Self::RegionClose
        )
    }

    /// The local mapping for upstream-only categories.
    pub fn local_fallback(&self) -> Option<Self> {
        match self {
            Self::NetworkPartition => Some(Self::ChannelDisconnect),
            Self::ResourceExhaustion => Some(Self::DeadlineExpiry),
            _ => None,
        }
    }
}

impl fmt::Display for FaultCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TaskPanic => write!(f, "task_panic"),
            Self::ChannelDisconnect => write!(f, "channel_disconnect"),
            Self::ObligationLeak => write!(f, "obligation_leak"),
            Self::DeadlineExpiry => write!(f, "deadline_expiry"),
            Self::RegionClose => write!(f, "region_close"),
            Self::NetworkPartition => write!(f, "network_partition"),
            Self::ResourceExhaustion => write!(f, "resource_exhaustion"),
        }
    }
}

/// Target for fault injection.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultTarget {
    /// Specific task by ID.
    Task { task_id: u64 },
    /// Specific region by name.
    Region { region_id: String },
    /// All tasks in a region.
    AllInRegion { region_id: String },
    /// Global (affects entire runtime).
    Global,
}

impl fmt::Display for FaultTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Task { task_id } => write!(f, "task:{task_id}"),
            Self::Region { region_id } => write!(f, "region:{region_id}"),
            Self::AllInRegion { region_id } => write!(f, "all_in_region:{region_id}"),
            Self::Global => write!(f, "global"),
        }
    }
}

// ---------------------------------------------------------------------------
// EvidenceLinkageEntry — connecting runs to evidence ledger
// ---------------------------------------------------------------------------

/// A single evidence linkage connecting a scenario run artifact to
/// the canonical evidence ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLinkageEntry {
    /// Scenario that produced this evidence.
    pub scenario_id: String,
    /// Seed used for the run.
    pub seed: u64,
    /// Content hash of the run artifact.
    pub artifact_hash: ContentHash,
    /// Category of evidence produced.
    pub evidence_category: EvidenceCategory,
    /// Trace ID linking to the control-plane context.
    pub trace_id_hex: String,
    /// Virtual time at which evidence was captured.
    pub captured_at_vt: u64,
    /// Whether this entry has been verified against the upstream ledger.
    pub upstream_verified: bool,
}

/// Category of evidence produced by a bridge scenario run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    /// Scenario execution result.
    ScenarioResult,
    /// Replay determinism certificate.
    ReplayCertificate,
    /// Oracle invariant check result.
    OracleCheck,
    /// Fault injection event.
    FaultInjectionEvent,
    /// Cancellation lifecycle event.
    CancellationEvent,
    /// Budget consumption trace.
    BudgetTrace,
}

impl EvidenceCategory {
    /// All variants in deterministic order.
    pub const ALL: [Self; 6] = [
        Self::ScenarioResult,
        Self::ReplayCertificate,
        Self::OracleCheck,
        Self::FaultInjectionEvent,
        Self::CancellationEvent,
        Self::BudgetTrace,
    ];
}

impl fmt::Display for EvidenceCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ScenarioResult => write!(f, "scenario_result"),
            Self::ReplayCertificate => write!(f, "replay_certificate"),
            Self::OracleCheck => write!(f, "oracle_check"),
            Self::FaultInjectionEvent => write!(f, "fault_injection_event"),
            Self::CancellationEvent => write!(f, "cancellation_event"),
            Self::BudgetTrace => write!(f, "budget_trace"),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeContractPolicy — overall bridge policy
// ---------------------------------------------------------------------------

/// Overall policy governing the frankenlab bridge contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeContractPolicy {
    /// Per-seam configuration.
    pub seam_configs: BTreeMap<String, BridgeSeamConfig>,
    /// Minimum replay confidence in millionths.
    pub min_replay_confidence_millionths: u64,
    /// Maximum oracle failures before bridge blocks release.
    pub max_oracle_failures: usize,
    /// Total fault injection budget per scenario run (ms).
    pub fault_injection_budget_ms: u64,
    /// Whether to require upstream verification of evidence entries.
    pub require_upstream_evidence_verification: bool,
    /// Security epoch at which this policy was established.
    pub policy_epoch: SecurityEpoch,
}

impl BridgeContractPolicy {
    /// Create a policy with strict defaults (fail-closed everywhere).
    pub fn strict(epoch: SecurityEpoch) -> Self {
        let mut seam_configs = BTreeMap::new();
        for seam in BridgeSeam::ALL {
            let config = BridgeSeamConfig::fail_closed(seam, BridgeMode::ThinAdapter);
            seam_configs.insert(seam.to_string(), config);
        }

        Self {
            seam_configs,
            min_replay_confidence_millionths: DEFAULT_MIN_REPLAY_CONFIDENCE,
            max_oracle_failures: DEFAULT_MAX_ORACLE_FAILURES,
            fault_injection_budget_ms: DEFAULT_FAULT_INJECTION_BUDGET_MS,
            require_upstream_evidence_verification: true,
            policy_epoch: epoch,
        }
    }

    /// Create a lenient policy (fail-open, local-only).
    pub fn lenient(epoch: SecurityEpoch) -> Self {
        let mut seam_configs = BTreeMap::new();
        for seam in BridgeSeam::ALL {
            let config = BridgeSeamConfig::lenient(seam, BridgeMode::LocalOnly);
            seam_configs.insert(seam.to_string(), config);
        }

        Self {
            seam_configs,
            min_replay_confidence_millionths: 500_000,
            max_oracle_failures: 5,
            fault_injection_budget_ms: 60_000,
            require_upstream_evidence_verification: false,
            policy_epoch: epoch,
        }
    }

    /// Get the config for a specific seam.
    pub fn seam_config(&self, seam: BridgeSeam) -> Option<&BridgeSeamConfig> {
        self.seam_configs.get(&seam.to_string())
    }

    /// Whether a specific seam is fail-closed.
    pub fn is_seam_fail_closed(&self, seam: BridgeSeam) -> bool {
        self.seam_config(seam)
            .map(|c| c.fail_closed)
            .unwrap_or(true)
    }

    /// Bridge mode for a specific seam.
    pub fn seam_mode(&self, seam: BridgeSeam) -> BridgeMode {
        self.seam_config(seam)
            .map(|c| c.mode)
            .unwrap_or(BridgeMode::LocalOnly)
    }
}

// ---------------------------------------------------------------------------
// BridgeViolation — contract violation
// ---------------------------------------------------------------------------

/// A violation of the bridge contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeViolation {
    /// Which seam was violated.
    pub seam: BridgeSeam,
    /// Violation category.
    pub kind: BridgeViolationKind,
    /// Human-readable description.
    pub description: String,
    /// Whether this violation blocks release.
    pub release_blocking: bool,
    /// Scenario that triggered the violation (if applicable).
    pub scenario_id: Option<String>,
    /// Seed that triggered the violation (if applicable).
    pub seed: Option<u64>,
}

/// Categories of bridge contract violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeViolationKind {
    /// Replay produced divergent certificates.
    ReplayDivergence,
    /// Oracle invariant failed.
    OracleInvariantFailure,
    /// Fault injection exceeded policy budget.
    FaultBudgetExceeded,
    /// Evidence entry not verified against upstream.
    EvidenceUnverified,
    /// Scenario execution timed out.
    ScenarioTimeout,
    /// Bridge seam returned infrastructure error.
    InfrastructureError,
    /// Upstream crate version mismatch.
    VersionMismatch,
    /// Type mapping failure between local and upstream.
    TypeMappingFailure,
}

impl fmt::Display for BridgeViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReplayDivergence => write!(f, "replay_divergence"),
            Self::OracleInvariantFailure => write!(f, "oracle_invariant_failure"),
            Self::FaultBudgetExceeded => write!(f, "fault_budget_exceeded"),
            Self::EvidenceUnverified => write!(f, "evidence_unverified"),
            Self::ScenarioTimeout => write!(f, "scenario_timeout"),
            Self::InfrastructureError => write!(f, "infrastructure_error"),
            Self::VersionMismatch => write!(f, "version_mismatch"),
            Self::TypeMappingFailure => write!(f, "type_mapping_failure"),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeContractValidator — validates the bridge contract
// ---------------------------------------------------------------------------

/// Validates the frankenlab bridge contract across all seams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeContractValidator {
    /// Governing policy.
    policy: BridgeContractPolicy,
    /// Accumulated violations.
    violations: Vec<BridgeViolation>,
    /// Replay verdicts collected.
    replay_verdicts: Vec<ReplayVerdict>,
    /// Oracle results collected.
    oracle_results: Vec<OracleResult>,
    /// Evidence linkage entries collected.
    evidence_entries: Vec<EvidenceLinkageEntry>,
    /// Total fault injection budget consumed (ms).
    fault_budget_consumed_ms: u64,
    /// Scenarios executed.
    scenarios_executed: Vec<String>,
}

impl BridgeContractValidator {
    /// Create a new validator with the given policy.
    pub fn new(policy: BridgeContractPolicy) -> Self {
        Self {
            policy,
            violations: Vec::new(),
            replay_verdicts: Vec::new(),
            oracle_results: Vec::new(),
            evidence_entries: Vec::new(),
            fault_budget_consumed_ms: 0,
            scenarios_executed: Vec::new(),
        }
    }

    /// Create a validator with strict defaults.
    pub fn strict(epoch: SecurityEpoch) -> Self {
        Self::new(BridgeContractPolicy::strict(epoch))
    }

    /// Record a scenario execution.
    pub fn record_scenario_execution(&mut self, scenario_id: &str) {
        self.scenarios_executed.push(scenario_id.to_owned());
    }

    /// Record a replay determinism verdict.
    pub fn record_replay_verdict(
        &mut self,
        scenario_id: &str,
        seed: u64,
        cert_a: &TraceCertificate,
        cert_b: &TraceCertificate,
    ) {
        let verdict = if cert_a.is_equivalent(cert_b) {
            ReplayVerdict::Deterministic
        } else {
            ReplayVerdict::Diverged {
                event_match: cert_a.event_hash == cert_b.event_hash,
                schedule_match: cert_a.schedule_hash == cert_b.schedule_hash,
                step_match: cert_a.steps == cert_b.steps,
                fingerprint_match: cert_a.trace_fingerprint == cert_b.trace_fingerprint,
            }
        };

        if verdict.is_failure()
            && self
                .policy
                .is_seam_fail_closed(BridgeSeam::ReplayDeterminism)
        {
            self.violations.push(BridgeViolation {
                seam: BridgeSeam::ReplayDeterminism,
                kind: BridgeViolationKind::ReplayDivergence,
                description: format!(
                    "Replay divergence for scenario '{}' seed {}",
                    scenario_id, seed
                ),
                release_blocking: true,
                scenario_id: Some(scenario_id.to_owned()),
                seed: Some(seed),
            });
        }

        self.replay_verdicts.push(verdict);
    }

    /// Record an oracle invariant result.
    pub fn record_oracle_result(&mut self, scenario_id: &str, result: OracleResult) {
        if !result.passed && self.policy.is_seam_fail_closed(BridgeSeam::OracleDispatch) {
            self.violations.push(BridgeViolation {
                seam: BridgeSeam::OracleDispatch,
                kind: BridgeViolationKind::OracleInvariantFailure,
                description: format!(
                    "Oracle '{}' failed for scenario '{}': {}",
                    result.invariant_name, scenario_id, result.detail
                ),
                release_blocking: true,
                scenario_id: Some(scenario_id.to_owned()),
                seed: None,
            });
        }

        self.oracle_results.push(result);
    }

    /// Record a fault injection and check budget.
    pub fn record_fault_injection(&mut self, scenario_id: &str, spec: &FaultInjectionSpec) {
        self.fault_budget_consumed_ms += spec.budget_cost_ms;

        if self.fault_budget_consumed_ms > self.policy.fault_injection_budget_ms
            && self.policy.is_seam_fail_closed(BridgeSeam::FaultInjection)
        {
            self.violations.push(BridgeViolation {
                seam: BridgeSeam::FaultInjection,
                kind: BridgeViolationKind::FaultBudgetExceeded,
                description: format!(
                    "Fault injection budget exceeded: {}ms consumed > {}ms allowed for scenario '{}'",
                    self.fault_budget_consumed_ms,
                    self.policy.fault_injection_budget_ms,
                    scenario_id,
                ),
                release_blocking: true,
                scenario_id: Some(scenario_id.to_owned()),
                seed: None,
            });
        }
    }

    /// Record an evidence linkage entry.
    pub fn record_evidence_linkage(&mut self, entry: EvidenceLinkageEntry) {
        if !entry.upstream_verified
            && self.policy.require_upstream_evidence_verification
            && self.policy.is_seam_fail_closed(BridgeSeam::EvidenceLinkage)
        {
            self.violations.push(BridgeViolation {
                seam: BridgeSeam::EvidenceLinkage,
                kind: BridgeViolationKind::EvidenceUnverified,
                description: format!(
                    "Evidence entry for scenario '{}' seed {} not verified against upstream",
                    entry.scenario_id, entry.seed,
                ),
                release_blocking: true,
                scenario_id: Some(entry.scenario_id.clone()),
                seed: Some(entry.seed),
            });
        }

        self.evidence_entries.push(entry);
    }

    /// Record a scenario timeout.
    pub fn record_scenario_timeout(&mut self, scenario_id: &str, elapsed_ms: u64, max_ms: u64) {
        if self
            .policy
            .is_seam_fail_closed(BridgeSeam::ScenarioExecution)
        {
            self.violations.push(BridgeViolation {
                seam: BridgeSeam::ScenarioExecution,
                kind: BridgeViolationKind::ScenarioTimeout,
                description: format!(
                    "Scenario '{}' timed out: {}ms > {}ms",
                    scenario_id, elapsed_ms, max_ms,
                ),
                release_blocking: true,
                scenario_id: Some(scenario_id.to_owned()),
                seed: None,
            });
        }
    }

    /// Record an infrastructure error on a seam.
    pub fn record_infrastructure_error(&mut self, seam: BridgeSeam, detail: &str) {
        let release_blocking = self.policy.is_seam_fail_closed(seam);
        self.violations.push(BridgeViolation {
            seam,
            kind: BridgeViolationKind::InfrastructureError,
            description: detail.to_owned(),
            release_blocking,
            scenario_id: None,
            seed: None,
        });
    }

    /// Whether any violations have been recorded.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Whether any release-blocking violations exist.
    pub fn has_release_blockers(&self) -> bool {
        self.violations.iter().any(|v| v.release_blocking)
    }

    /// All violations.
    pub fn violations(&self) -> &[BridgeViolation] {
        &self.violations
    }

    /// All replay verdicts.
    pub fn replay_verdicts(&self) -> &[ReplayVerdict] {
        &self.replay_verdicts
    }

    /// All oracle results.
    pub fn oracle_results(&self) -> &[OracleResult] {
        &self.oracle_results
    }

    /// All evidence entries.
    pub fn evidence_entries(&self) -> &[EvidenceLinkageEntry] {
        &self.evidence_entries
    }

    /// Replay confidence in millionths.
    pub fn replay_confidence_millionths(&self) -> u64 {
        if self.replay_verdicts.is_empty() {
            return 0;
        }

        let deterministic_count = self
            .replay_verdicts
            .iter()
            .filter(|v| v.is_deterministic())
            .count() as u64;

        let total = self.replay_verdicts.len() as u64;
        deterministic_count * SCALE / total
    }

    /// Oracle pass rate in millionths.
    pub fn oracle_pass_rate_millionths(&self) -> u64 {
        if self.oracle_results.is_empty() {
            return SCALE;
        }

        let passed = self.oracle_results.iter().filter(|r| r.passed).count() as u64;

        let total = self.oracle_results.len() as u64;
        passed * SCALE / total
    }

    /// Number of oracle failures.
    pub fn oracle_failure_count(&self) -> usize {
        self.oracle_results.iter().filter(|r| !r.passed).count()
    }

    /// Fault budget remaining (ms).
    pub fn fault_budget_remaining_ms(&self) -> u64 {
        self.policy
            .fault_injection_budget_ms
            .saturating_sub(self.fault_budget_consumed_ms)
    }

    /// Build the final bridge contract report.
    pub fn build_report(&self) -> BridgeContractReport {
        let mut seam_status = BTreeMap::new();
        for seam in BridgeSeam::ALL {
            let violations_for_seam = self.violations.iter().filter(|v| v.seam == seam).count();

            let status = if violations_for_seam == 0 {
                SeamStatus::Clean
            } else if self
                .violations
                .iter()
                .any(|v| v.seam == seam && v.release_blocking)
            {
                SeamStatus::ReleaseBlocked
            } else {
                SeamStatus::Warning
            };

            seam_status.insert(seam.to_string(), status);
        }

        let mut violation_counts = BTreeMap::new();
        for v in &self.violations {
            *violation_counts.entry(v.kind.to_string()).or_insert(0usize) += 1;
        }

        let content_bytes = serde_json::to_vec(&(
            &self.violations,
            &self.replay_verdicts,
            &self.oracle_results,
        ))
        .unwrap_or_default();
        let content_hash = ContentHash::compute(&content_bytes);

        BridgeContractReport {
            schema_version: BRIDGE_CONTRACT_SCHEMA_VERSION.to_owned(),
            policy_epoch: self.policy.policy_epoch,
            seam_status,
            total_violations: self.violations.len(),
            release_blocking_violations: self
                .violations
                .iter()
                .filter(|v| v.release_blocking)
                .count(),
            violation_counts,
            replay_confidence_millionths: self.replay_confidence_millionths(),
            oracle_pass_rate_millionths: self.oracle_pass_rate_millionths(),
            oracle_failure_count: self.oracle_failure_count(),
            fault_budget_consumed_ms: self.fault_budget_consumed_ms,
            fault_budget_limit_ms: self.policy.fault_injection_budget_ms,
            evidence_entries_total: self.evidence_entries.len(),
            evidence_entries_verified: self
                .evidence_entries
                .iter()
                .filter(|e| e.upstream_verified)
                .count(),
            scenarios_executed: self.scenarios_executed.len(),
            release_blocked: self.has_release_blockers(),
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// SeamStatus — status of a single seam
// ---------------------------------------------------------------------------

/// Status of a single bridge seam after validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeamStatus {
    /// No violations on this seam.
    Clean,
    /// Non-blocking violations exist.
    Warning,
    /// Release-blocking violations exist.
    ReleaseBlocked,
}

impl fmt::Display for SeamStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Warning => write!(f, "warning"),
            Self::ReleaseBlocked => write!(f, "release_blocked"),
        }
    }
}

// ---------------------------------------------------------------------------
// BridgeContractReport — final validation report
// ---------------------------------------------------------------------------

/// Report from validating the bridge contract across all seams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeContractReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub policy_epoch: SecurityEpoch,
    /// Per-seam status.
    pub seam_status: BTreeMap<String, SeamStatus>,
    /// Total number of violations.
    pub total_violations: usize,
    /// Number of release-blocking violations.
    pub release_blocking_violations: usize,
    /// Violation counts by kind.
    pub violation_counts: BTreeMap<String, usize>,
    /// Replay confidence in millionths.
    pub replay_confidence_millionths: u64,
    /// Oracle pass rate in millionths.
    pub oracle_pass_rate_millionths: u64,
    /// Total oracle failures.
    pub oracle_failure_count: usize,
    /// Fault injection budget consumed (ms).
    pub fault_budget_consumed_ms: u64,
    /// Fault injection budget limit (ms).
    pub fault_budget_limit_ms: u64,
    /// Total evidence entries.
    pub evidence_entries_total: usize,
    /// Evidence entries verified against upstream.
    pub evidence_entries_verified: usize,
    /// Number of scenarios executed.
    pub scenarios_executed: usize,
    /// Whether the bridge blocks release.
    pub release_blocked: bool,
    /// Content hash for deterministic comparison.
    pub content_hash: ContentHash,
}

impl BridgeContractReport {
    /// Whether the report shows a clean bridge.
    pub fn is_clean(&self) -> bool {
        self.total_violations == 0
    }

    /// Whether all evidence entries are verified.
    pub fn all_evidence_verified(&self) -> bool {
        self.evidence_entries_total > 0
            && self.evidence_entries_verified == self.evidence_entries_total
    }

    /// Whether replay confidence meets policy threshold.
    pub fn replay_confidence_sufficient(&self, threshold_millionths: u64) -> bool {
        self.replay_confidence_millionths >= threshold_millionths
    }
}

impl fmt::Display for BridgeContractReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BridgeContractReport(violations={}, release_blocked={}, \
             replay_confidence={}‰, oracles={}/{}, evidence={}/{}, scenarios={})",
            self.total_violations,
            self.release_blocked,
            self.replay_confidence_millionths / 1_000,
            self.oracle_pass_rate_millionths / 1_000,
            SCALE / 1_000,
            self.evidence_entries_verified,
            self.evidence_entries_total,
            self.scenarios_executed,
        )
    }
}

// ---------------------------------------------------------------------------
// BridgeTypeMapping — type mapping registry
// ---------------------------------------------------------------------------

/// Registry of type mappings between local and upstream representations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTypeMapping {
    /// Source type name (local).
    pub local_type: String,
    /// Target type name (upstream).
    pub upstream_type: String,
    /// Which seam this mapping serves.
    pub seam: BridgeSeam,
    /// Whether the mapping is lossless.
    pub lossless: bool,
    /// Description of any data lost in the mapping.
    pub loss_description: String,
}

/// Registry of all type mappings for the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTypeMappingRegistry {
    /// All registered mappings.
    pub mappings: Vec<BridgeTypeMapping>,
    /// Schema version.
    pub schema_version: String,
}

impl BridgeTypeMappingRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            mappings: Vec::new(),
            schema_version: BRIDGE_CONTRACT_SCHEMA_VERSION.to_owned(),
        }
    }

    /// Create a registry pre-populated with known local↔upstream mappings.
    pub fn with_defaults() -> Self {
        let mut reg = Self::new();

        // Lab runtime mappings
        reg.add_lossless(
            "lab_runtime::VirtualClock",
            "asupersync::lab::runtime::VirtualClock",
            BridgeSeam::ScenarioExecution,
        );
        reg.add_lossless(
            "lab_runtime::FaultKind",
            "asupersync::lab::injection::FaultAction",
            BridgeSeam::FaultInjection,
        );
        reg.add_lossless(
            "lab_runtime::ScheduleTranscript",
            "asupersync::lab::replay::ScheduleTranscript",
            BridgeSeam::ReplayDeterminism,
        );
        reg.add_lossless(
            "lab_runtime::Verdict",
            "asupersync::lab::scenario_runner::ScenarioVerdict",
            BridgeSeam::ScenarioExecution,
        );
        reg.add_lossless(
            "lab_runtime::LabEvent",
            "asupersync::lab::runtime::LabEvent",
            BridgeSeam::EvidenceLinkage,
        );

        // Control plane mappings
        reg.add_lossless(
            "control_plane::Budget",
            "franken_kernel::Budget",
            BridgeSeam::ScenarioExecution,
        );
        reg.add_lossless(
            "control_plane::TraceId",
            "franken_kernel::TraceId",
            BridgeSeam::EvidenceLinkage,
        );
        reg.add_lossless(
            "control_plane::Cx",
            "franken_kernel::Cx",
            BridgeSeam::ScenarioExecution,
        );

        // Evidence mappings
        reg.add_lossy(
            "deterministic_replay::NondeterminismTrace",
            "asupersync::lab::replay::ReplayTrace",
            BridgeSeam::ReplayDeterminism,
            "local trace captures component names; upstream uses module paths",
        );
        reg.add_lossy(
            "evidence_replay_checker::ReplayViolation",
            "asupersync::lab::replay::ReplayDivergence",
            BridgeSeam::ReplayDeterminism,
            "local violation includes calibration fields; upstream uses generic metadata",
        );

        reg
    }

    /// Add a lossless type mapping.
    pub fn add_lossless(&mut self, local_type: &str, upstream_type: &str, seam: BridgeSeam) {
        self.mappings.push(BridgeTypeMapping {
            local_type: local_type.to_owned(),
            upstream_type: upstream_type.to_owned(),
            seam,
            lossless: true,
            loss_description: String::new(),
        });
    }

    /// Add a lossy type mapping.
    pub fn add_lossy(
        &mut self,
        local_type: &str,
        upstream_type: &str,
        seam: BridgeSeam,
        loss_description: &str,
    ) {
        self.mappings.push(BridgeTypeMapping {
            local_type: local_type.to_owned(),
            upstream_type: upstream_type.to_owned(),
            seam,
            lossless: false,
            loss_description: loss_description.to_owned(),
        });
    }

    /// All mappings for a given seam.
    pub fn mappings_for_seam(&self, seam: BridgeSeam) -> Vec<&BridgeTypeMapping> {
        self.mappings.iter().filter(|m| m.seam == seam).collect()
    }

    /// All lossy mappings (require attention during migration).
    pub fn lossy_mappings(&self) -> Vec<&BridgeTypeMapping> {
        self.mappings.iter().filter(|m| !m.lossless).collect()
    }

    /// Count of lossless mappings.
    pub fn lossless_count(&self) -> usize {
        self.mappings.iter().filter(|m| m.lossless).count()
    }

    /// Count of lossy mappings.
    pub fn lossy_count(&self) -> usize {
        self.mappings.iter().filter(|m| !m.lossless).count()
    }
}

impl Default for BridgeTypeMappingRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(100)
    }

    fn test_content_hash(data: &[u8]) -> ContentHash {
        ContentHash::compute(data)
    }

    // -- BridgeMode tests --

    #[test]
    fn bridge_mode_display() {
        assert_eq!(
            BridgeMode::DirectDependency.to_string(),
            "direct_dependency"
        );
        assert_eq!(BridgeMode::ThinAdapter.to_string(), "thin_adapter");
        assert_eq!(
            BridgeMode::LocalWithUpstreamValidation.to_string(),
            "local_with_upstream_validation"
        );
        assert_eq!(BridgeMode::LocalOnly.to_string(), "local_only");
    }

    #[test]
    fn bridge_mode_serde_roundtrip() {
        for mode in [
            BridgeMode::DirectDependency,
            BridgeMode::ThinAdapter,
            BridgeMode::LocalWithUpstreamValidation,
            BridgeMode::LocalOnly,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let round: BridgeMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, round);
        }
    }

    // -- BridgeSeam tests --

    #[test]
    fn bridge_seam_all_has_five_variants() {
        assert_eq!(BridgeSeam::ALL.len(), 5);
    }

    #[test]
    fn bridge_seam_display() {
        assert_eq!(
            BridgeSeam::ScenarioExecution.to_string(),
            "scenario_execution"
        );
        assert_eq!(
            BridgeSeam::ReplayDeterminism.to_string(),
            "replay_determinism"
        );
        assert_eq!(BridgeSeam::EvidenceLinkage.to_string(), "evidence_linkage");
        assert_eq!(BridgeSeam::FaultInjection.to_string(), "fault_injection");
        assert_eq!(BridgeSeam::OracleDispatch.to_string(), "oracle_dispatch");
    }

    #[test]
    fn bridge_seam_serde_roundtrip() {
        for seam in BridgeSeam::ALL {
            let json = serde_json::to_string(&seam).unwrap();
            let round: BridgeSeam = serde_json::from_str(&json).unwrap();
            assert_eq!(seam, round);
        }
    }

    // -- ScenarioManifest tests --

    #[test]
    fn scenario_manifest_new() {
        let m = ScenarioManifest::new("test-scenario", 42);
        assert_eq!(m.scenario_id, "test-scenario");
        assert_eq!(m.seed, 42);
        assert_eq!(m.max_steps, 100_000);
        assert!(m.panic_on_obligation_leak);
        assert!(!m.has_faults());
        assert!(!m.has_oracles());
    }

    #[test]
    fn scenario_manifest_add_fault() {
        let mut m = ScenarioManifest::new("s1", 1);
        m.add_fault("panic", 100);
        m.add_fault("disconnect", 200);
        assert!(m.has_faults());
        assert_eq!(m.fault_schedule.len(), 2);
        assert_eq!(*m.fault_schedule.get("panic").unwrap(), 100);
    }

    #[test]
    fn scenario_manifest_add_oracle() {
        let mut m = ScenarioManifest::new("s1", 1);
        m.add_oracle("safety_invariant");
        m.add_oracle("liveness_invariant");
        assert!(m.has_oracles());
        assert_eq!(m.oracle_invariants.len(), 2);
    }

    #[test]
    fn scenario_manifest_add_cancellation() {
        let mut m = ScenarioManifest::new("s1", 1);
        m.add_cancellation("region-a", 500);
        assert_eq!(m.cancellation_schedule.len(), 1);
    }

    #[test]
    fn scenario_manifest_serde_roundtrip() {
        let mut m = ScenarioManifest::new("roundtrip", 99);
        m.add_fault("panic", 100);
        m.add_oracle("safety");
        m.add_cancellation("r1", 50);
        let json = serde_json::to_string(&m).unwrap();
        let round: ScenarioManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m, round);
    }

    // -- TraceCertificate tests --

    #[test]
    fn trace_certificate_equivalence() {
        let h1 = test_content_hash(b"events-1");
        let h2 = test_content_hash(b"schedule-1");
        let h3 = test_content_hash(b"fingerprint-1");

        let a = TraceCertificate::new(h1.clone(), h2.clone(), 100, h3.clone(), 42);
        let b = TraceCertificate::new(h1, h2, 100, h3, 42);
        assert!(a.is_equivalent(&b));
    }

    #[test]
    fn trace_certificate_divergence() {
        let h1 = test_content_hash(b"events-1");
        let h2 = test_content_hash(b"schedule-1");
        let h3 = test_content_hash(b"fingerprint-1");
        let h4 = test_content_hash(b"fingerprint-2");

        let a = TraceCertificate::new(h1.clone(), h2.clone(), 100, h3, 42);
        let b = TraceCertificate::new(h1, h2, 100, h4, 42);
        assert!(!a.is_equivalent(&b));
    }

    #[test]
    fn trace_certificate_serde_roundtrip() {
        let cert = TraceCertificate::new(
            test_content_hash(b"e"),
            test_content_hash(b"s"),
            50,
            test_content_hash(b"f"),
            7,
        );
        let json = serde_json::to_string(&cert).unwrap();
        let round: TraceCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, round);
    }

    // -- ReplayVerdict tests --

    #[test]
    fn replay_verdict_deterministic() {
        let v = ReplayVerdict::Deterministic;
        assert!(v.is_deterministic());
        assert!(!v.is_failure());
    }

    #[test]
    fn replay_verdict_diverged() {
        let v = ReplayVerdict::Diverged {
            event_match: true,
            schedule_match: false,
            step_match: true,
            fingerprint_match: false,
        };
        assert!(!v.is_deterministic());
        assert!(v.is_failure());
    }

    #[test]
    fn replay_verdict_infrastructure() {
        let v = ReplayVerdict::InfrastructureFailure {
            detail: "worker died".to_owned(),
        };
        assert!(!v.is_deterministic());
        assert!(v.is_failure());
    }

    // -- OracleResult tests --

    #[test]
    fn oracle_result_pass() {
        let r = OracleResult::pass("safety", 100);
        assert!(r.passed);
        assert!(r.detail.is_empty());
    }

    #[test]
    fn oracle_result_fail() {
        let r = OracleResult::fail("liveness", "deadlock detected", 200);
        assert!(!r.passed);
        assert_eq!(r.detail, "deadlock detected");
    }

    // -- FaultCategory tests --

    #[test]
    fn fault_category_all_has_seven_variants() {
        assert_eq!(FaultCategory::ALL.len(), 7);
    }

    #[test]
    fn fault_category_local_equivalence() {
        assert!(FaultCategory::TaskPanic.has_local_equivalent());
        assert!(FaultCategory::ChannelDisconnect.has_local_equivalent());
        assert!(FaultCategory::ObligationLeak.has_local_equivalent());
        assert!(FaultCategory::DeadlineExpiry.has_local_equivalent());
        assert!(FaultCategory::RegionClose.has_local_equivalent());
        assert!(!FaultCategory::NetworkPartition.has_local_equivalent());
        assert!(!FaultCategory::ResourceExhaustion.has_local_equivalent());
    }

    #[test]
    fn fault_category_local_fallback() {
        assert_eq!(
            FaultCategory::NetworkPartition.local_fallback(),
            Some(FaultCategory::ChannelDisconnect)
        );
        assert_eq!(
            FaultCategory::ResourceExhaustion.local_fallback(),
            Some(FaultCategory::DeadlineExpiry)
        );
        assert_eq!(FaultCategory::TaskPanic.local_fallback(), None);
    }

    #[test]
    fn fault_category_serde_roundtrip() {
        for cat in FaultCategory::ALL {
            let json = serde_json::to_string(&cat).unwrap();
            let round: FaultCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, round);
        }
    }

    // -- FaultTarget tests --

    #[test]
    fn fault_target_display() {
        assert_eq!(FaultTarget::Task { task_id: 5 }.to_string(), "task:5");
        assert_eq!(
            FaultTarget::Region {
                region_id: "r1".to_owned()
            }
            .to_string(),
            "region:r1"
        );
        assert_eq!(FaultTarget::Global.to_string(), "global");
    }

    // -- EvidenceCategory tests --

    #[test]
    fn evidence_category_all_has_six_variants() {
        assert_eq!(EvidenceCategory::ALL.len(), 6);
    }

    // -- BridgeContractPolicy tests --

    #[test]
    fn strict_policy_all_seams_fail_closed() {
        let policy = BridgeContractPolicy::strict(test_epoch());
        for seam in BridgeSeam::ALL {
            assert!(
                policy.is_seam_fail_closed(seam),
                "seam {} not fail-closed",
                seam
            );
        }
    }

    #[test]
    fn strict_policy_all_seams_thin_adapter() {
        let policy = BridgeContractPolicy::strict(test_epoch());
        for seam in BridgeSeam::ALL {
            assert_eq!(policy.seam_mode(seam), BridgeMode::ThinAdapter);
        }
    }

    #[test]
    fn lenient_policy_all_seams_local_only() {
        let policy = BridgeContractPolicy::lenient(test_epoch());
        for seam in BridgeSeam::ALL {
            assert_eq!(policy.seam_mode(seam), BridgeMode::LocalOnly);
        }
    }

    #[test]
    fn lenient_policy_lower_thresholds() {
        let policy = BridgeContractPolicy::lenient(test_epoch());
        assert_eq!(policy.min_replay_confidence_millionths, 500_000);
        assert_eq!(policy.max_oracle_failures, 5);
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = BridgeContractPolicy::strict(test_epoch());
        let json = serde_json::to_string(&policy).unwrap();
        let round: BridgeContractPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, round);
    }

    // -- BridgeContractValidator tests --

    #[test]
    fn validator_clean_start() {
        let v = BridgeContractValidator::strict(test_epoch());
        assert!(!v.has_violations());
        assert!(!v.has_release_blockers());
        assert_eq!(v.replay_confidence_millionths(), 0);
        assert_eq!(v.oracle_pass_rate_millionths(), SCALE);
    }

    #[test]
    fn validator_deterministic_replay() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        let h1 = test_content_hash(b"e");
        let h2 = test_content_hash(b"s");
        let h3 = test_content_hash(b"f");
        let cert = TraceCertificate::new(h1, h2, 10, h3, 42);
        v.record_replay_verdict("s1", 42, &cert, &cert);
        assert!(!v.has_violations());
        assert_eq!(v.replay_confidence_millionths(), SCALE);
    }

    #[test]
    fn validator_divergent_replay() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        let cert_a = TraceCertificate::new(
            test_content_hash(b"e1"),
            test_content_hash(b"s1"),
            10,
            test_content_hash(b"f1"),
            42,
        );
        let cert_b = TraceCertificate::new(
            test_content_hash(b"e2"),
            test_content_hash(b"s2"),
            10,
            test_content_hash(b"f2"),
            42,
        );
        v.record_replay_verdict("s1", 42, &cert_a, &cert_b);
        assert!(v.has_violations());
        assert!(v.has_release_blockers());
        assert_eq!(v.replay_confidence_millionths(), 0);
    }

    #[test]
    fn validator_oracle_pass() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        v.record_oracle_result("s1", OracleResult::pass("safety", 100));
        assert!(!v.has_violations());
        assert_eq!(v.oracle_pass_rate_millionths(), SCALE);
        assert_eq!(v.oracle_failure_count(), 0);
    }

    #[test]
    fn validator_oracle_fail() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        v.record_oracle_result("s1", OracleResult::fail("safety", "bad", 100));
        assert!(v.has_violations());
        assert_eq!(v.oracle_pass_rate_millionths(), 0);
        assert_eq!(v.oracle_failure_count(), 1);
    }

    #[test]
    fn validator_fault_budget() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        let spec = FaultInjectionSpec {
            fault_category: FaultCategory::TaskPanic,
            inject_at_vt: 100,
            target: FaultTarget::Task { task_id: 1 },
            budget_cost_ms: 5_000,
        };
        v.record_fault_injection("s1", &spec);
        assert!(!v.has_violations());
        assert_eq!(v.fault_budget_remaining_ms(), 25_000);
    }

    #[test]
    fn validator_fault_budget_exceeded() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        let spec = FaultInjectionSpec {
            fault_category: FaultCategory::TaskPanic,
            inject_at_vt: 100,
            target: FaultTarget::Global,
            budget_cost_ms: 31_000,
        };
        v.record_fault_injection("s1", &spec);
        assert!(v.has_violations());
        assert_eq!(v.fault_budget_remaining_ms(), 0);
    }

    #[test]
    fn validator_evidence_unverified() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        let entry = EvidenceLinkageEntry {
            scenario_id: "s1".to_owned(),
            seed: 42,
            artifact_hash: test_content_hash(b"artifact"),
            evidence_category: EvidenceCategory::ScenarioResult,
            trace_id_hex: "deadbeef".to_owned(),
            captured_at_vt: 100,
            upstream_verified: false,
        };
        v.record_evidence_linkage(entry);
        assert!(v.has_violations());
    }

    #[test]
    fn validator_evidence_verified() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        let entry = EvidenceLinkageEntry {
            scenario_id: "s1".to_owned(),
            seed: 42,
            artifact_hash: test_content_hash(b"artifact"),
            evidence_category: EvidenceCategory::ScenarioResult,
            trace_id_hex: "deadbeef".to_owned(),
            captured_at_vt: 100,
            upstream_verified: true,
        };
        v.record_evidence_linkage(entry);
        assert!(!v.has_violations());
    }

    #[test]
    fn validator_scenario_timeout() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        v.record_scenario_timeout("s1", 10_000, 5_000);
        assert!(v.has_violations());
        assert!(v.has_release_blockers());
    }

    #[test]
    fn validator_infrastructure_error() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        v.record_infrastructure_error(BridgeSeam::ScenarioExecution, "worker crashed");
        assert!(v.has_violations());
    }

    // -- Report tests --

    #[test]
    fn report_clean() {
        let v = BridgeContractValidator::strict(test_epoch());
        let report = v.build_report();
        assert!(report.is_clean());
        assert!(!report.release_blocked);
        assert_eq!(report.total_violations, 0);
    }

    #[test]
    fn report_with_violations() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        v.record_scenario_timeout("s1", 10_000, 5_000);
        v.record_scenario_execution("s1");
        let report = v.build_report();
        assert!(!report.is_clean());
        assert!(report.release_blocked);
        assert_eq!(report.total_violations, 1);
        assert_eq!(report.scenarios_executed, 1);
    }

    #[test]
    fn report_seam_status_clean() {
        let v = BridgeContractValidator::strict(test_epoch());
        let report = v.build_report();
        for seam in BridgeSeam::ALL {
            assert_eq!(
                *report.seam_status.get(&seam.to_string()).unwrap(),
                SeamStatus::Clean,
            );
        }
    }

    #[test]
    fn report_seam_status_blocked() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        v.record_scenario_timeout("s1", 10_000, 5_000);
        let report = v.build_report();
        assert_eq!(
            *report
                .seam_status
                .get(&BridgeSeam::ScenarioExecution.to_string())
                .unwrap(),
            SeamStatus::ReleaseBlocked,
        );
    }

    #[test]
    fn report_serde_roundtrip() {
        let mut v = BridgeContractValidator::strict(test_epoch());
        v.record_oracle_result("s1", OracleResult::pass("safety", 100));
        v.record_scenario_execution("s1");
        let report = v.build_report();
        let json = serde_json::to_string_pretty(&report).unwrap();
        let round: BridgeContractReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, round);
    }

    #[test]
    fn report_content_hash_deterministic() {
        let make_report = || {
            let mut v = BridgeContractValidator::strict(test_epoch());
            v.record_oracle_result("s1", OracleResult::pass("safety", 100));
            v.build_report()
        };
        let r1 = make_report();
        let r2 = make_report();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_display() {
        let v = BridgeContractValidator::strict(test_epoch());
        let report = v.build_report();
        let display = format!("{report}");
        assert!(display.contains("BridgeContractReport"));
    }

    // -- BridgeTypeMappingRegistry tests --

    #[test]
    fn type_mapping_registry_defaults() {
        let reg = BridgeTypeMappingRegistry::with_defaults();
        assert!(!reg.mappings.is_empty());
        assert!(reg.lossless_count() > 0);
        assert!(reg.lossy_count() > 0);
    }

    #[test]
    fn type_mapping_registry_seam_filter() {
        let reg = BridgeTypeMappingRegistry::with_defaults();
        let scenario_mappings = reg.mappings_for_seam(BridgeSeam::ScenarioExecution);
        assert!(!scenario_mappings.is_empty());
    }

    #[test]
    fn type_mapping_registry_lossy_filter() {
        let reg = BridgeTypeMappingRegistry::with_defaults();
        let lossy = reg.lossy_mappings();
        for m in &lossy {
            assert!(!m.lossless);
            assert!(!m.loss_description.is_empty());
        }
    }

    #[test]
    fn type_mapping_registry_serde_roundtrip() {
        let reg = BridgeTypeMappingRegistry::with_defaults();
        let json = serde_json::to_string(&reg).unwrap();
        let round: BridgeTypeMappingRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, round);
    }

    // -- BridgeSeamConfig tests --

    #[test]
    fn seam_config_fail_closed() {
        let c = BridgeSeamConfig::fail_closed(BridgeSeam::OracleDispatch, BridgeMode::ThinAdapter);
        assert!(c.fail_closed);
        assert!(c.emit_evidence);
        assert_eq!(c.max_latency_ms, 5_000);
    }

    #[test]
    fn seam_config_lenient() {
        let c = BridgeSeamConfig::lenient(BridgeSeam::OracleDispatch, BridgeMode::LocalOnly);
        assert!(!c.fail_closed);
        assert!(!c.emit_evidence);
        assert_eq!(c.max_latency_ms, 30_000);
    }

    #[test]
    fn seam_config_with_rationale() {
        let c = BridgeSeamConfig::fail_closed(BridgeSeam::OracleDispatch, BridgeMode::ThinAdapter)
            .with_rationale("upstream provides stronger guarantees");
        assert_eq!(c.rationale, "upstream provides stronger guarantees");
    }

    // -- E2E tests --

    #[test]
    fn e2e_clean_scenario_run() {
        let mut v = BridgeContractValidator::strict(test_epoch());

        // Execute scenario
        v.record_scenario_execution("lifecycle-startup");

        // Record passing replay
        let h = test_content_hash(b"data");
        let cert = TraceCertificate::new(h.clone(), h.clone(), 50, h.clone(), 42);
        v.record_replay_verdict("lifecycle-startup", 42, &cert, &cert);

        // Record passing oracle
        v.record_oracle_result("lifecycle-startup", OracleResult::pass("safety", 100));

        // Record verified evidence
        v.record_evidence_linkage(EvidenceLinkageEntry {
            scenario_id: "lifecycle-startup".to_owned(),
            seed: 42,
            artifact_hash: test_content_hash(b"artifact"),
            evidence_category: EvidenceCategory::ScenarioResult,
            trace_id_hex: "abc123".to_owned(),
            captured_at_vt: 100,
            upstream_verified: true,
        });

        let report = v.build_report();
        assert!(report.is_clean());
        assert!(!report.release_blocked);
        assert_eq!(report.scenarios_executed, 1);
        assert_eq!(report.replay_confidence_millionths, SCALE);
        assert!(report.all_evidence_verified());
    }

    #[test]
    fn e2e_mixed_results() {
        let mut v = BridgeContractValidator::strict(test_epoch());

        // Two scenarios
        v.record_scenario_execution("s1");
        v.record_scenario_execution("s2");

        // s1: deterministic replay
        let h = test_content_hash(b"data");
        let cert = TraceCertificate::new(h.clone(), h.clone(), 50, h.clone(), 42);
        v.record_replay_verdict("s1", 42, &cert, &cert);

        // s2: divergent replay
        let cert_b = TraceCertificate::new(test_content_hash(b"different"), h.clone(), 50, h, 42);
        v.record_replay_verdict("s2", 42, &cert, &cert_b);

        let report = v.build_report();
        assert!(!report.is_clean());
        assert!(report.release_blocked);
        assert_eq!(report.replay_confidence_millionths, 500_000);
    }

    #[test]
    fn e2e_lenient_policy_allows_failures() {
        let mut v = BridgeContractValidator::new(BridgeContractPolicy::lenient(test_epoch()));

        // Unverified evidence — lenient policy doesn't block
        v.record_evidence_linkage(EvidenceLinkageEntry {
            scenario_id: "s1".to_owned(),
            seed: 42,
            artifact_hash: test_content_hash(b"a"),
            evidence_category: EvidenceCategory::ScenarioResult,
            trace_id_hex: "abc".to_owned(),
            captured_at_vt: 50,
            upstream_verified: false,
        });

        assert!(!v.has_violations());
    }
}
