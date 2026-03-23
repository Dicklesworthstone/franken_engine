//! Benchmark freshness gate for rollout trust and claim confidence.
//!
//! Bead: bd-1lsy.8.6.3 [RGC-706C]
//!
//! Gates benchmark freshness and rollout trust on live-shift alarms and
//! acquisition evidence so stale corpora stop powering ambitious claims.
//! If live evidence says the board is drifting away from reality and the
//! acquisition program is not burning down that debt fast enough, the system
//! must downgrade benchmark claims, rollout confidence, and support promises.
//! Silence is not an acceptable freshness state.
//!
//! # Design
//!
//! - `ShiftAlarm` captures a live-workload shift event with severity and evidence.
//! - `AcquisitionEvidence` documents the pace of corpus expansion and debt burndown.
//! - `FreshnessVerdict` is the pass/hold/downgrade result of the gate evaluation.
//! - `FreshnessGate` evaluates claims against shift alarms and acquisition evidence.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.benchmark-freshness-gate.v1";

/// Component name.
pub const COMPONENT: &str = "benchmark_freshness_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.6.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-706C";

/// Maximum alarm age in epochs before alarm is considered stale (default 100).
pub const DEFAULT_MAX_ALARM_AGE_EPOCHS: u64 = 100;

/// Minimum acquisition burndown ratio to maintain full freshness (millionths).
/// 50% burndown = 500_000.
pub const DEFAULT_MIN_BURNDOWN_RATIO: u64 = 500_000;

/// Severity threshold for a single alarm to trigger immediate downgrade (millionths).
/// 80% = 800_000.
pub const DEFAULT_CRITICAL_SEVERITY: u64 = 800_000;

/// Maximum accumulated alarm severity before automatic downgrade (millionths).
/// 1.5 = 1_500_000.
pub const DEFAULT_MAX_CUMULATIVE_SEVERITY: u64 = 1_500_000;

/// Minimum number of acquisition samples for evidence to be considered valid.
pub const DEFAULT_MIN_ACQUISITION_SAMPLES: u64 = 10;

/// Default silence timeout in epochs — freshness degrades if no signal arrives.
pub const DEFAULT_SILENCE_TIMEOUT_EPOCHS: u64 = 50;

/// Maximum batch size for gate evaluation.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 256;

/// One in fixed-point millionths.
pub const FIXED_ONE: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// ShiftSeverity
// ---------------------------------------------------------------------------

/// Severity level of a workload shift alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftSeverity {
    /// Informational — small drift detected but within normal bounds.
    Info,
    /// Warning — measurable drift that may affect benchmark validity.
    Warning,
    /// Critical — large shift that invalidates current benchmark assumptions.
    Critical,
    /// Emergency — fundamental workload change requiring immediate action.
    Emergency,
}

impl ShiftSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }

    /// Numeric weight in millionths.
    pub fn weight(&self) -> u64 {
        match self {
            Self::Info => 100_000,
            Self::Warning => 400_000,
            Self::Critical => 800_000,
            Self::Emergency => 1_000_000,
        }
    }

    /// Whether this severity alone warrants an immediate downgrade.
    pub fn is_immediate_downgrade(&self) -> bool {
        matches!(self, Self::Critical | Self::Emergency)
    }
}

impl fmt::Display for ShiftSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ShiftDomain
// ---------------------------------------------------------------------------

/// Domain of a workload shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftDomain {
    /// Shift in distribution of program sizes.
    ProgramSize,
    /// Shift in API usage patterns.
    ApiUsage,
    /// Shift in control-flow complexity.
    ControlFlow,
    /// Shift in module/dependency topology.
    ModuleTopology,
    /// Shift in concurrency patterns.
    Concurrency,
    /// Shift in memory allocation patterns.
    MemoryAllocation,
    /// Shift in I/O behavior.
    IoPattern,
    /// General/unclassified shift.
    General,
}

impl fmt::Display for ShiftDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ShiftDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProgramSize => "program_size",
            Self::ApiUsage => "api_usage",
            Self::ControlFlow => "control_flow",
            Self::ModuleTopology => "module_topology",
            Self::Concurrency => "concurrency",
            Self::MemoryAllocation => "memory_allocation",
            Self::IoPattern => "io_pattern",
            Self::General => "general",
        }
    }
}

// ---------------------------------------------------------------------------
// ShiftAlarm
// ---------------------------------------------------------------------------

/// A live-workload shift alarm raised by distribution monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShiftAlarm {
    /// Unique alarm identifier.
    pub alarm_id: String,
    /// Domain of the detected shift.
    pub domain: ShiftDomain,
    /// Severity of the shift.
    pub severity: ShiftSeverity,
    /// Epoch when the alarm was raised.
    pub raised_epoch: SecurityEpoch,
    /// Magnitude of the drift in millionths (0 = no drift, 1_000_000 = complete change).
    pub drift_magnitude: u64,
    /// Description of the shift for human readers.
    pub description: String,
    /// Whether this alarm has been acknowledged by the acquisition program.
    pub acknowledged: bool,
    /// Content hash of the alarm evidence.
    pub evidence_hash: ContentHash,
}

impl ShiftAlarm {
    /// Create a new shift alarm.
    pub fn new(
        alarm_id: impl Into<String>,
        domain: ShiftDomain,
        severity: ShiftSeverity,
        raised_epoch: SecurityEpoch,
        drift_magnitude: u64,
        description: impl Into<String>,
    ) -> Self {
        let alarm_id = alarm_id.into();
        let description = description.into();
        let mut hasher = Sha256::new();
        hasher.update(alarm_id.as_bytes());
        hasher.update(domain.as_str().as_bytes());
        hasher.update(severity.as_str().as_bytes());
        hasher.update(raised_epoch.as_u64().to_le_bytes());
        hasher.update(drift_magnitude.to_le_bytes());
        hasher.update(description.as_bytes());
        let evidence_hash = ContentHash::compute(&hasher.finalize());
        Self {
            alarm_id,
            domain,
            severity,
            raised_epoch,
            drift_magnitude,
            description,
            acknowledged: false,
            evidence_hash,
        }
    }

    /// Acknowledge this alarm (e.g. after acquisition response).
    pub fn acknowledge(&mut self) {
        self.acknowledged = true;
    }

    /// Weighted severity in millionths, incorporating drift magnitude.
    pub fn weighted_severity(&self) -> u64 {
        let base = self.severity.weight();
        // Scale by drift magnitude (both in millionths, so divide by FIXED_ONE).
        base.saturating_mul(self.drift_magnitude) / FIXED_ONE
    }

    /// Whether this alarm is stale (older than max age from current epoch).
    pub fn is_stale(&self, current_epoch: SecurityEpoch, max_age: u64) -> bool {
        current_epoch
            .as_u64()
            .saturating_sub(self.raised_epoch.as_u64())
            > max_age
    }
}

// ---------------------------------------------------------------------------
// AcquisitionStatus
// ---------------------------------------------------------------------------

/// Status of the acquisition program's response to workload shifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionStatus {
    /// Acquisition is actively expanding coverage into shifted regions.
    Active,
    /// Acquisition is paused or resource-constrained.
    Paused,
    /// Acquisition is complete for this shift domain.
    Complete,
    /// Acquisition has stalled — no progress in recent epochs.
    Stalled,
    /// No acquisition program is running for this domain.
    Absent,
}

impl AcquisitionStatus {
    /// Whether this status contributes to freshness.
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Active | Self::Complete)
    }
}

impl fmt::Display for AcquisitionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Complete => write!(f, "complete"),
            Self::Stalled => write!(f, "stalled"),
            Self::Absent => write!(f, "absent"),
        }
    }
}

// ---------------------------------------------------------------------------
// AcquisitionEvidence
// ---------------------------------------------------------------------------

/// Evidence of the acquisition program's progress against detected shifts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionEvidence {
    /// Domain this evidence covers.
    pub domain: ShiftDomain,
    /// Number of new samples acquired in response to the shift.
    pub samples_acquired: u64,
    /// Total samples needed to cover the shifted region.
    pub samples_needed: u64,
    /// Burndown ratio: samples_acquired / samples_needed in millionths.
    pub burndown_ratio: u64,
    /// Current status of the acquisition effort.
    pub status: AcquisitionStatus,
    /// Epoch of the most recent acquisition activity.
    pub last_activity_epoch: SecurityEpoch,
    /// Velocity: samples per epoch in millionths.
    pub acquisition_velocity: u64,
    /// Content hash of the evidence.
    pub evidence_hash: ContentHash,
}

impl AcquisitionEvidence {
    /// Create new acquisition evidence.
    pub fn new(
        domain: ShiftDomain,
        samples_acquired: u64,
        samples_needed: u64,
        status: AcquisitionStatus,
        last_activity_epoch: SecurityEpoch,
        acquisition_velocity: u64,
    ) -> Self {
        let burndown_ratio = samples_acquired
            .saturating_mul(FIXED_ONE)
            .checked_div(samples_needed)
            .unwrap_or(FIXED_ONE);
        let mut hasher = Sha256::new();
        hasher.update(b"acquisition_evidence");
        hasher.update(domain.as_str().as_bytes());
        hasher.update(format!("{status:?}").as_bytes());
        hasher.update(samples_acquired.to_le_bytes());
        hasher.update(samples_needed.to_le_bytes());
        hasher.update(last_activity_epoch.as_u64().to_le_bytes());
        hasher.update(acquisition_velocity.to_le_bytes());
        let evidence_hash = ContentHash::compute(&hasher.finalize());
        Self {
            domain,
            samples_acquired,
            samples_needed,
            burndown_ratio,
            status,
            last_activity_epoch,
            acquisition_velocity,
            evidence_hash,
        }
    }

    /// Whether burndown meets the minimum threshold.
    pub fn meets_burndown_threshold(&self, min_ratio: u64) -> bool {
        self.burndown_ratio >= min_ratio
    }

    /// Estimated epochs to completion at current velocity.
    pub fn estimated_epochs_to_completion(&self) -> Option<u64> {
        let remaining = self.samples_needed.saturating_sub(self.samples_acquired);
        let remaining_scaled = remaining.saturating_mul(FIXED_ONE);
        remaining_scaled.checked_div(self.acquisition_velocity)
    }
}

// ---------------------------------------------------------------------------
// FreshnessLevel
// ---------------------------------------------------------------------------

/// Level of benchmark freshness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessLevel {
    /// Benchmarks are fresh — corpus matches live workload.
    Fresh,
    /// Benchmarks are aging — minor drift detected, acquisition in progress.
    Aging,
    /// Benchmarks are stale — significant drift, acquisition lagging.
    Stale,
    /// Benchmarks are invalid — fundamental shift, no acquisition response.
    Invalid,
}

impl FreshnessLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Aging => "aging",
            Self::Stale => "stale",
            Self::Invalid => "invalid",
        }
    }

    /// Whether claims at full confidence are permitted.
    pub fn permits_full_confidence(&self) -> bool {
        matches!(self, Self::Fresh)
    }

    /// Confidence multiplier in millionths.
    pub fn confidence_multiplier(&self) -> u64 {
        match self {
            Self::Fresh => FIXED_ONE,
            Self::Aging => 750_000,
            Self::Stale => 400_000,
            Self::Invalid => 0,
        }
    }
}

impl fmt::Display for FreshnessLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ClaimSurface
// ---------------------------------------------------------------------------

/// Surface on which a benchmark claim is being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSurface {
    /// Performance benchmarks (latency, throughput).
    Performance,
    /// Correctness claims (test pass rates).
    Correctness,
    /// Memory efficiency claims.
    Memory,
    /// Cold-start time claims.
    ColdStart,
    /// Compilation speed claims.
    CompilationSpeed,
    /// Compatibility claims (browser, runtime parity).
    Compatibility,
    /// Supremacy claims against competitors.
    Supremacy,
}

impl fmt::Display for ClaimSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Performance => write!(f, "performance"),
            Self::Correctness => write!(f, "correctness"),
            Self::Memory => write!(f, "memory"),
            Self::ColdStart => write!(f, "cold_start"),
            Self::CompilationSpeed => write!(f, "compilation_speed"),
            Self::Compatibility => write!(f, "compatibility"),
            Self::Supremacy => write!(f, "supremacy"),
        }
    }
}

// ---------------------------------------------------------------------------
// BenchmarkClaim
// ---------------------------------------------------------------------------

/// A benchmark claim that needs freshness verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkClaim {
    /// Unique claim identifier.
    pub claim_id: String,
    /// Surface of the claim.
    pub surface: ClaimSurface,
    /// Original confidence in millionths.
    pub original_confidence: u64,
    /// Domains this claim depends on for freshness.
    pub dependent_domains: BTreeSet<ShiftDomain>,
    /// Epoch when the claim was established.
    pub established_epoch: SecurityEpoch,
    /// Description of the claim.
    pub description: String,
}

impl BenchmarkClaim {
    /// Create a new benchmark claim.
    pub fn new(
        claim_id: impl Into<String>,
        surface: ClaimSurface,
        original_confidence: u64,
        established_epoch: SecurityEpoch,
        description: impl Into<String>,
    ) -> Self {
        Self {
            claim_id: claim_id.into(),
            surface,
            original_confidence,
            dependent_domains: BTreeSet::new(),
            established_epoch,
            description: description.into(),
        }
    }

    /// Add a domain dependency.
    pub fn with_domain(mut self, domain: ShiftDomain) -> Self {
        self.dependent_domains.insert(domain);
        self
    }

    /// Add multiple domain dependencies.
    pub fn with_domains(mut self, domains: impl IntoIterator<Item = ShiftDomain>) -> Self {
        self.dependent_domains.extend(domains);
        self
    }
}

// ---------------------------------------------------------------------------
// FreshnessVerdict
// ---------------------------------------------------------------------------

/// Result of freshness gate evaluation for a single claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessVerdict {
    /// Claim identifier.
    pub claim_id: String,
    /// Determined freshness level.
    pub freshness: FreshnessLevel,
    /// Adjusted confidence in millionths (original * freshness multiplier).
    pub adjusted_confidence: u64,
    /// Original confidence for comparison.
    pub original_confidence: u64,
    /// Alarm IDs that contributed to the verdict.
    pub contributing_alarms: Vec<String>,
    /// Domain-level freshness breakdown.
    pub domain_freshness: BTreeMap<String, FreshnessLevel>,
    /// Reasons for the verdict.
    pub reasons: Vec<String>,
    /// Whether rollout is permitted at this freshness level.
    pub rollout_permitted: bool,
    /// Epoch of the evaluation.
    pub evaluation_epoch: SecurityEpoch,
    /// Content hash of the verdict.
    pub verdict_hash: ContentHash,
}

impl FreshnessVerdict {
    /// Whether the claim passed at full confidence.
    pub fn is_full_confidence(&self) -> bool {
        self.freshness == FreshnessLevel::Fresh
    }

    /// Whether the claim was downgraded.
    pub fn is_downgraded(&self) -> bool {
        self.adjusted_confidence < self.original_confidence
    }

    /// Downgrade fraction in millionths.
    pub fn downgrade_fraction(&self) -> u64 {
        self.adjusted_confidence
            .saturating_mul(FIXED_ONE)
            .checked_div(self.original_confidence)
            .map(|ratio| FIXED_ONE.saturating_sub(ratio))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the freshness gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum alarm age before it is considered stale.
    pub max_alarm_age_epochs: u64,
    /// Minimum burndown ratio for full freshness.
    pub min_burndown_ratio: u64,
    /// Single-alarm severity that triggers immediate downgrade.
    pub critical_severity_threshold: u64,
    /// Cumulative severity threshold for automatic downgrade.
    pub max_cumulative_severity: u64,
    /// Minimum acquisition samples for evidence to be valid.
    pub min_acquisition_samples: u64,
    /// Silence timeout: epochs without any signal trigger degradation.
    pub silence_timeout_epochs: u64,
    /// Maximum batch size.
    pub max_batch_size: usize,
    /// Domains that must always have active acquisition.
    pub required_active_domains: BTreeSet<ShiftDomain>,
    /// Whether to permit rollout during aging state.
    pub permit_rollout_when_aging: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            max_alarm_age_epochs: DEFAULT_MAX_ALARM_AGE_EPOCHS,
            min_burndown_ratio: DEFAULT_MIN_BURNDOWN_RATIO,
            critical_severity_threshold: DEFAULT_CRITICAL_SEVERITY,
            max_cumulative_severity: DEFAULT_MAX_CUMULATIVE_SEVERITY,
            min_acquisition_samples: DEFAULT_MIN_ACQUISITION_SAMPLES,
            silence_timeout_epochs: DEFAULT_SILENCE_TIMEOUT_EPOCHS,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            required_active_domains: BTreeSet::new(),
            permit_rollout_when_aging: true,
        }
    }
}

// ---------------------------------------------------------------------------
// AlarmLedger
// ---------------------------------------------------------------------------

/// Persistent ledger of shift alarms and their resolution state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlarmLedger {
    /// Active (non-stale, unresolved) alarms by ID.
    pub active_alarms: BTreeMap<String, ShiftAlarm>,
    /// Resolved alarm IDs with resolution epoch.
    pub resolved_alarms: BTreeMap<String, u64>,
    /// Total alarms ever recorded.
    pub total_alarms_recorded: u64,
    /// Cumulative severity of active alarms in millionths.
    pub cumulative_severity: u64,
}

impl AlarmLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self {
            active_alarms: BTreeMap::new(),
            resolved_alarms: BTreeMap::new(),
            total_alarms_recorded: 0,
            cumulative_severity: 0,
        }
    }

    /// Record a new alarm.
    pub fn record_alarm(&mut self, alarm: ShiftAlarm) {
        self.cumulative_severity = self
            .cumulative_severity
            .saturating_add(alarm.weighted_severity());
        self.total_alarms_recorded += 1;
        self.active_alarms.insert(alarm.alarm_id.clone(), alarm);
    }

    /// Resolve an alarm.
    pub fn resolve_alarm(&mut self, alarm_id: &str, epoch: u64) -> bool {
        if let Some(alarm) = self.active_alarms.remove(alarm_id) {
            self.cumulative_severity = self
                .cumulative_severity
                .saturating_sub(alarm.weighted_severity());
            self.resolved_alarms.insert(alarm_id.to_string(), epoch);
            true
        } else {
            false
        }
    }

    /// Prune stale alarms that exceed max age.
    pub fn prune_stale(&mut self, current_epoch: SecurityEpoch, max_age: u64) -> usize {
        let stale_ids: Vec<String> = self
            .active_alarms
            .iter()
            .filter(|(_, alarm)| alarm.is_stale(current_epoch, max_age))
            .map(|(id, _)| id.clone())
            .collect();
        let count = stale_ids.len();
        for id in &stale_ids {
            if let Some(alarm) = self.active_alarms.remove(id) {
                self.cumulative_severity = self
                    .cumulative_severity
                    .saturating_sub(alarm.weighted_severity());
            }
            self.resolved_alarms
                .insert(id.clone(), current_epoch.as_u64());
        }
        count
    }

    /// Count active alarms in a specific domain.
    pub fn active_count_in_domain(&self, domain: ShiftDomain) -> usize {
        self.active_alarms
            .values()
            .filter(|a| a.domain == domain)
            .count()
    }

    /// Worst active severity in a domain.
    pub fn worst_severity_in_domain(&self, domain: ShiftDomain) -> Option<ShiftSeverity> {
        self.active_alarms
            .values()
            .filter(|a| a.domain == domain)
            .map(|a| a.severity)
            .max()
    }

    /// Whether any active alarm is critical or emergency.
    pub fn has_immediate_downgrade_alarm(&self) -> bool {
        self.active_alarms
            .values()
            .any(|a| a.severity.is_immediate_downgrade())
    }

    /// Active alarm count.
    pub fn active_count(&self) -> usize {
        self.active_alarms.len()
    }

    /// Content hash of the ledger state.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"alarm_ledger");
        hasher.update(self.total_alarms_recorded.to_le_bytes());
        hasher.update(self.cumulative_severity.to_le_bytes());
        hasher.update((self.active_alarms.len() as u64).to_le_bytes());
        // Include individual alarm details (BTreeMap iterates deterministically).
        for (id, alarm) in &self.active_alarms {
            hasher.update(id.as_bytes());
            hasher.update(alarm.domain.as_str().as_bytes());
            hasher.update(alarm.severity.as_str().as_bytes());
            hasher.update(alarm.drift_magnitude.to_le_bytes());
        }
        // Include resolved alarm history.
        for (id, resolved_epoch) in &self.resolved_alarms {
            hasher.update(b"resolved:");
            hasher.update(id.as_bytes());
            hasher.update(resolved_epoch.to_le_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

impl Default for AlarmLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AcquisitionLedger
// ---------------------------------------------------------------------------

/// Tracks acquisition evidence across domains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquisitionLedger {
    /// Evidence by domain (serialized as string key).
    pub evidence: Vec<AcquisitionEvidence>,
    /// Overall burndown ratio in millionths.
    pub overall_burndown_ratio: u64,
    /// Domains with stalled acquisition.
    pub stalled_domains: BTreeSet<String>,
}

impl AcquisitionLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self {
            evidence: Vec::new(),
            overall_burndown_ratio: FIXED_ONE,
            stalled_domains: BTreeSet::new(),
        }
    }

    /// Record acquisition evidence for a domain.
    pub fn record_evidence(&mut self, ev: AcquisitionEvidence) {
        let domain_str = ev.domain.to_string();
        if ev.status == AcquisitionStatus::Stalled {
            self.stalled_domains.insert(domain_str.clone());
        } else {
            self.stalled_domains.remove(&domain_str);
        }
        // Replace existing evidence for this domain or add new.
        if let Some(existing) = self.evidence.iter_mut().find(|e| e.domain == ev.domain) {
            *existing = ev;
        } else {
            self.evidence.push(ev);
        }
        self.recompute_overall();
    }

    /// Recompute overall burndown ratio.
    fn recompute_overall(&mut self) {
        if self.evidence.is_empty() {
            self.overall_burndown_ratio = FIXED_ONE;
            return;
        }
        let total: u64 = self.evidence.iter().map(|e| e.burndown_ratio).sum();
        self.overall_burndown_ratio = total / self.evidence.len() as u64;
    }

    /// Get evidence for a domain.
    pub fn get_domain_evidence(&self, domain: ShiftDomain) -> Option<&AcquisitionEvidence> {
        self.evidence.iter().find(|e| e.domain == domain)
    }

    /// Whether all required domains are actively being addressed.
    pub fn all_domains_healthy(&self, required: &BTreeSet<ShiftDomain>) -> bool {
        required.iter().all(|d| {
            self.evidence
                .iter()
                .any(|e| e.domain == *d && e.status.is_healthy())
        })
    }

    /// Whether any domain has stalled.
    pub fn has_stalled_domains(&self) -> bool {
        !self.stalled_domains.is_empty()
    }
}

impl Default for AcquisitionLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SilenceTracker
// ---------------------------------------------------------------------------

/// Tracks silence (absence of signals) to detect dead monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilenceTracker {
    /// Last epoch any alarm or acquisition evidence was received.
    pub last_signal_epoch: Option<SecurityEpoch>,
    /// Whether silence timeout has been exceeded.
    pub silence_exceeded: bool,
    /// Number of consecutive silent epochs.
    pub silent_epochs: u64,
}

impl SilenceTracker {
    /// Create a new silence tracker.
    pub fn new() -> Self {
        Self {
            last_signal_epoch: None,
            silence_exceeded: false,
            silent_epochs: 0,
        }
    }

    /// Record a signal (alarm or acquisition evidence).
    pub fn record_signal(&mut self, epoch: SecurityEpoch) {
        self.last_signal_epoch = Some(epoch);
        self.silence_exceeded = false;
        self.silent_epochs = 0;
    }

    /// Check and update silence state.
    pub fn check_silence(&mut self, current_epoch: SecurityEpoch, timeout: u64) -> bool {
        match self.last_signal_epoch {
            Some(last) => {
                self.silent_epochs = current_epoch.as_u64().saturating_sub(last.as_u64());
                self.silence_exceeded = self.silent_epochs > timeout;
            }
            None => {
                self.silent_epochs = current_epoch.as_u64();
                self.silence_exceeded = current_epoch.as_u64() > timeout;
            }
        }
        self.silence_exceeded
    }
}

impl Default for SilenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RolloutTrustLevel
// ---------------------------------------------------------------------------

/// Level of trust for rollout decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutTrustLevel {
    /// Full trust — proceed with rollout.
    Full,
    /// Conditional trust — rollout with monitoring.
    Conditional,
    /// Reduced trust — rollout requires manual approval.
    Reduced,
    /// No trust — rollout blocked.
    Blocked,
}

impl RolloutTrustLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Conditional => "conditional",
            Self::Reduced => "reduced",
            Self::Blocked => "blocked",
        }
    }

    /// From freshness level.
    pub fn from_freshness(freshness: FreshnessLevel, permit_aging: bool) -> Self {
        match freshness {
            FreshnessLevel::Fresh => Self::Full,
            FreshnessLevel::Aging if permit_aging => Self::Conditional,
            FreshnessLevel::Aging => Self::Reduced,
            FreshnessLevel::Stale => Self::Reduced,
            FreshnessLevel::Invalid => Self::Blocked,
        }
    }
}

impl fmt::Display for RolloutTrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BatchVerdict
// ---------------------------------------------------------------------------

/// Aggregate result of evaluating a batch of claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchVerdict {
    /// Individual verdicts by claim ID.
    pub verdicts: BTreeMap<String, FreshnessVerdict>,
    /// Overall freshness across all claims.
    pub overall_freshness: FreshnessLevel,
    /// Overall rollout trust.
    pub rollout_trust: RolloutTrustLevel,
    /// Summary statistics.
    pub claims_total: usize,
    /// Claims at full confidence.
    pub claims_full_confidence: usize,
    /// Claims downgraded.
    pub claims_downgraded: usize,
    /// Claims invalidated.
    pub claims_invalidated: usize,
    /// Evaluation epoch.
    pub evaluation_epoch: SecurityEpoch,
    /// Content hash of the batch verdict.
    pub batch_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// FreshnessGate
// ---------------------------------------------------------------------------

/// The freshness gate that evaluates claims against shift alarms and acquisition evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreshnessGate {
    /// Configuration.
    pub config: GateConfig,
    /// Alarm ledger.
    pub alarm_ledger: AlarmLedger,
    /// Acquisition ledger.
    pub acquisition_ledger: AcquisitionLedger,
    /// Silence tracker.
    pub silence_tracker: SilenceTracker,
    /// Current epoch.
    pub current_epoch: SecurityEpoch,
    /// Total evaluations performed.
    pub total_evaluations: u64,
}

impl FreshnessGate {
    /// Create a new freshness gate with default configuration.
    pub fn new(current_epoch: SecurityEpoch) -> Self {
        Self {
            config: GateConfig::default(),
            alarm_ledger: AlarmLedger::new(),
            acquisition_ledger: AcquisitionLedger::new(),
            silence_tracker: SilenceTracker::new(),
            current_epoch,
            total_evaluations: 0,
        }
    }

    /// Create with custom configuration.
    pub fn with_config(config: GateConfig, current_epoch: SecurityEpoch) -> Self {
        Self {
            config,
            alarm_ledger: AlarmLedger::new(),
            acquisition_ledger: AcquisitionLedger::new(),
            silence_tracker: SilenceTracker::new(),
            current_epoch,
            total_evaluations: 0,
        }
    }

    /// Advance the gate to a new epoch.
    pub fn advance_epoch(&mut self, epoch: SecurityEpoch) {
        self.current_epoch = epoch;
        self.alarm_ledger
            .prune_stale(epoch, self.config.max_alarm_age_epochs);
    }

    /// Record a new shift alarm.
    pub fn record_alarm(&mut self, alarm: ShiftAlarm) {
        self.silence_tracker.record_signal(alarm.raised_epoch);
        self.alarm_ledger.record_alarm(alarm);
    }

    /// Record acquisition evidence.
    pub fn record_acquisition(&mut self, evidence: AcquisitionEvidence) {
        self.silence_tracker
            .record_signal(evidence.last_activity_epoch);
        self.acquisition_ledger.record_evidence(evidence);
    }

    /// Resolve an alarm by ID.
    pub fn resolve_alarm(&mut self, alarm_id: &str) -> bool {
        self.alarm_ledger
            .resolve_alarm(alarm_id, self.current_epoch.as_u64())
    }

    /// Determine freshness level for a set of domains.
    pub fn determine_freshness(&self, domains: &BTreeSet<ShiftDomain>) -> FreshnessLevel {
        // Check silence first — silence is not acceptable.
        if self.silence_tracker.silence_exceeded {
            return FreshnessLevel::Stale;
        }

        // Check for immediate downgrade alarms.
        if self.alarm_ledger.has_immediate_downgrade_alarm() {
            // Check if acquisition is addressing it.
            let all_addressed = self
                .alarm_ledger
                .active_alarms
                .values()
                .filter(|a| a.severity.is_immediate_downgrade())
                .all(|a| {
                    self.acquisition_ledger
                        .get_domain_evidence(a.domain)
                        .is_some_and(|e| {
                            e.status.is_healthy()
                                && e.burndown_ratio >= self.config.min_burndown_ratio
                        })
                });
            if !all_addressed {
                return FreshnessLevel::Invalid;
            }
        }

        // Check cumulative severity.
        if self.alarm_ledger.cumulative_severity > self.config.max_cumulative_severity {
            return FreshnessLevel::Stale;
        }

        // Check domain-specific freshness.
        let mut worst = FreshnessLevel::Fresh;
        for domain in domains {
            let domain_freshness = self.domain_freshness(*domain);
            if domain_freshness > worst {
                worst = domain_freshness;
            }
        }

        // Check required active domains.
        if !self
            .acquisition_ledger
            .all_domains_healthy(&self.config.required_active_domains)
            && worst < FreshnessLevel::Aging
        {
            worst = FreshnessLevel::Aging;
        }

        worst
    }

    /// Determine freshness for a single domain.
    pub fn domain_freshness(&self, domain: ShiftDomain) -> FreshnessLevel {
        let alarm_count = self.alarm_ledger.active_count_in_domain(domain);
        let worst_severity = self.alarm_ledger.worst_severity_in_domain(domain);

        if alarm_count == 0 {
            return FreshnessLevel::Fresh;
        }

        let acquisition = self.acquisition_ledger.get_domain_evidence(domain);

        match worst_severity {
            Some(ShiftSeverity::Emergency) => FreshnessLevel::Invalid,
            Some(ShiftSeverity::Critical) => {
                // Critical requires active acquisition with good burndown.
                match acquisition {
                    Some(ev)
                        if ev.status.is_healthy()
                            && ev.burndown_ratio >= self.config.min_burndown_ratio =>
                    {
                        FreshnessLevel::Aging
                    }
                    _ => FreshnessLevel::Stale,
                }
            }
            Some(ShiftSeverity::Warning) => match acquisition {
                Some(ev) if ev.status.is_healthy() => FreshnessLevel::Aging,
                _ => FreshnessLevel::Stale,
            },
            Some(ShiftSeverity::Info) => FreshnessLevel::Aging,
            None => FreshnessLevel::Fresh,
        }
    }

    /// Evaluate a single claim.
    pub fn evaluate_claim(&mut self, claim: &BenchmarkClaim) -> FreshnessVerdict {
        self.total_evaluations += 1;

        let freshness = self.determine_freshness(&claim.dependent_domains);
        let multiplier = freshness.confidence_multiplier();
        let adjusted_confidence = claim.original_confidence.saturating_mul(multiplier) / FIXED_ONE;

        let rollout_trust =
            RolloutTrustLevel::from_freshness(freshness, self.config.permit_rollout_when_aging);
        let rollout_permitted = matches!(
            rollout_trust,
            RolloutTrustLevel::Full | RolloutTrustLevel::Conditional
        );

        // Collect contributing alarms.
        let contributing_alarms: Vec<String> = self
            .alarm_ledger
            .active_alarms
            .values()
            .filter(|a| claim.dependent_domains.contains(&a.domain))
            .map(|a| a.alarm_id.clone())
            .collect();

        // Build domain freshness map.
        let mut domain_freshness = BTreeMap::new();
        for domain in &claim.dependent_domains {
            domain_freshness.insert(domain.to_string(), self.domain_freshness(*domain));
        }

        // Build reasons.
        let mut reasons = Vec::new();
        if freshness == FreshnessLevel::Fresh {
            reasons.push("All dependent domains are fresh".to_string());
        } else {
            if self.silence_tracker.silence_exceeded {
                reasons.push(format!(
                    "Silence exceeded: {} epochs without signal (timeout: {})",
                    self.silence_tracker.silent_epochs, self.config.silence_timeout_epochs
                ));
            }
            for (dom, level) in &domain_freshness {
                if *level != FreshnessLevel::Fresh {
                    reasons.push(format!("Domain {} is {}", dom, level));
                }
            }
            if self.acquisition_ledger.has_stalled_domains() {
                reasons.push("Some acquisition domains have stalled".to_string());
            }
        }

        let mut hasher = Sha256::new();
        hasher.update(claim.claim_id.as_bytes());
        hasher.update(self.current_epoch.as_u64().to_le_bytes());
        hasher.update(adjusted_confidence.to_le_bytes());
        hasher.update(claim.original_confidence.to_le_bytes());
        hasher.update(freshness.as_str().as_bytes());
        hasher.update(if rollout_permitted { &[1u8] } else { &[0u8] });
        for alarm_id in &contributing_alarms {
            hasher.update(alarm_id.as_bytes());
        }
        for (dom, level) in &domain_freshness {
            hasher.update(dom.as_str().as_bytes());
            hasher.update(level.as_str().as_bytes());
        }
        for reason in &reasons {
            hasher.update(reason.as_bytes());
        }
        let verdict_hash = ContentHash::compute(&hasher.finalize());

        FreshnessVerdict {
            claim_id: claim.claim_id.clone(),
            freshness,
            adjusted_confidence,
            original_confidence: claim.original_confidence,
            contributing_alarms,
            domain_freshness,
            reasons,
            rollout_permitted,
            evaluation_epoch: self.current_epoch,
            verdict_hash,
        }
    }

    /// Evaluate a batch of claims.
    pub fn evaluate_batch(&mut self, claims: &[BenchmarkClaim]) -> BatchVerdict {
        let mut verdicts = BTreeMap::new();
        let mut worst_freshness = FreshnessLevel::Fresh;
        let mut full_count = 0usize;
        let mut downgraded_count = 0usize;
        let mut invalid_count = 0usize;

        let batch_claims = if claims.len() > self.config.max_batch_size {
            &claims[..self.config.max_batch_size]
        } else {
            claims
        };

        for claim in batch_claims {
            let verdict = self.evaluate_claim(claim);
            if verdict.is_full_confidence() {
                full_count += 1;
            } else if verdict.freshness == FreshnessLevel::Invalid {
                invalid_count += 1;
            } else {
                downgraded_count += 1;
            }
            if verdict.freshness > worst_freshness {
                worst_freshness = verdict.freshness;
            }
            verdicts.insert(claim.claim_id.clone(), verdict);
        }

        let rollout_trust = RolloutTrustLevel::from_freshness(
            worst_freshness,
            self.config.permit_rollout_when_aging,
        );

        let mut hasher = Sha256::new();
        hasher.update(b"batch_verdict");
        hasher.update(self.current_epoch.as_u64().to_le_bytes());
        hasher.update((batch_claims.len() as u64).to_le_bytes());
        hasher.update(worst_freshness.to_string().as_bytes());
        hasher.update(rollout_trust.to_string().as_bytes());
        hasher.update(full_count.to_le_bytes());
        hasher.update(downgraded_count.to_le_bytes());
        hasher.update(invalid_count.to_le_bytes());
        // Include individual verdict hashes (BTreeMap iterates deterministically).
        for (claim_id, verdict) in &verdicts {
            hasher.update(claim_id.as_bytes());
            hasher.update(verdict.verdict_hash.as_bytes());
        }
        let batch_hash = ContentHash::compute(&hasher.finalize());

        BatchVerdict {
            verdicts,
            overall_freshness: worst_freshness,
            rollout_trust,
            claims_total: batch_claims.len(),
            claims_full_confidence: full_count,
            claims_downgraded: downgraded_count,
            claims_invalidated: invalid_count,
            evaluation_epoch: self.current_epoch,
            batch_hash,
        }
    }

    /// Get a summary of the current gate state.
    pub fn summary(&self) -> GateSummary {
        let silence_ok = !self.silence_tracker.silence_exceeded;
        let active_alarms = self.alarm_ledger.active_count();
        let cumulative_severity = self.alarm_ledger.cumulative_severity;
        let overall_burndown = self.acquisition_ledger.overall_burndown_ratio;
        let stalled_domains = self.acquisition_ledger.stalled_domains.len();

        GateSummary {
            current_epoch: self.current_epoch,
            active_alarms,
            cumulative_severity,
            overall_burndown,
            stalled_domains,
            silence_ok,
            total_evaluations: self.total_evaluations,
        }
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary of the gate state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Current epoch.
    pub current_epoch: SecurityEpoch,
    /// Number of active alarms.
    pub active_alarms: usize,
    /// Cumulative severity of active alarms.
    pub cumulative_severity: u64,
    /// Overall burndown ratio.
    pub overall_burndown: u64,
    /// Number of stalled domains.
    pub stalled_domains: usize,
    /// Whether silence is within bounds.
    pub silence_ok: bool,
    /// Total evaluations performed.
    pub total_evaluations: u64,
}

impl GateSummary {
    /// Whether the gate is in a healthy state.
    pub fn is_healthy(&self) -> bool {
        self.silence_ok && self.active_alarms == 0 && self.stalled_domains == 0
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// A serializable decision receipt for audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Claim being evaluated.
    pub claim_id: String,
    /// Gate component.
    pub component: String,
    /// Policy reference.
    pub policy_id: String,
    /// Verdict freshness level.
    pub freshness: FreshnessLevel,
    /// Adjusted confidence.
    pub adjusted_confidence: u64,
    /// Rollout trust level.
    pub rollout_trust: RolloutTrustLevel,
    /// Contributing alarm count.
    pub alarm_count: usize,
    /// Evaluation epoch.
    pub epoch: SecurityEpoch,
    /// Content hash.
    pub receipt_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a receipt from a verdict.
    pub fn from_verdict(verdict: &FreshnessVerdict, config: &GateConfig) -> Self {
        let rollout_trust =
            RolloutTrustLevel::from_freshness(verdict.freshness, config.permit_rollout_when_aging);

        let mut hasher = Sha256::new();
        hasher.update(b"decision_receipt");
        hasher.update(verdict.claim_id.as_bytes());
        hasher.update(verdict.evaluation_epoch.as_u64().to_le_bytes());
        let receipt_hash = ContentHash::compute(&hasher.finalize());

        Self {
            receipt_id: format!(
                "receipt-{}-{}",
                verdict.claim_id,
                verdict.evaluation_epoch.as_u64()
            ),
            claim_id: verdict.claim_id.clone(),
            component: COMPONENT.to_string(),
            policy_id: POLICY_ID.to_string(),
            freshness: verdict.freshness,
            adjusted_confidence: verdict.adjusted_confidence,
            rollout_trust,
            alarm_count: verdict.contributing_alarms.len(),
            epoch: verdict.evaluation_epoch,
            receipt_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn make_alarm(id: &str, domain: ShiftDomain, severity: ShiftSeverity, ep: u64) -> ShiftAlarm {
        ShiftAlarm::new(id, domain, severity, epoch(ep), 500_000, "test alarm")
    }

    fn make_claim(id: &str, surface: ClaimSurface, domains: &[ShiftDomain]) -> BenchmarkClaim {
        let mut claim = BenchmarkClaim::new(id, surface, 900_000, epoch(1), "test claim");
        for d in domains {
            claim.dependent_domains.insert(*d);
        }
        claim
    }

    fn make_acquisition(
        domain: ShiftDomain,
        acquired: u64,
        needed: u64,
        status: AcquisitionStatus,
    ) -> AcquisitionEvidence {
        AcquisitionEvidence::new(domain, acquired, needed, status, epoch(10), 100_000)
    }

    // --- ShiftSeverity ---

    #[test]
    fn test_severity_weights_increase() {
        assert!(ShiftSeverity::Info.weight() < ShiftSeverity::Warning.weight());
        assert!(ShiftSeverity::Warning.weight() < ShiftSeverity::Critical.weight());
        assert!(ShiftSeverity::Critical.weight() < ShiftSeverity::Emergency.weight());
    }

    #[test]
    fn test_severity_immediate_downgrade() {
        assert!(!ShiftSeverity::Info.is_immediate_downgrade());
        assert!(!ShiftSeverity::Warning.is_immediate_downgrade());
        assert!(ShiftSeverity::Critical.is_immediate_downgrade());
        assert!(ShiftSeverity::Emergency.is_immediate_downgrade());
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(ShiftSeverity::Info.to_string(), "info");
        assert_eq!(ShiftSeverity::Info.as_str(), "info");
        assert_eq!(ShiftSeverity::Emergency.to_string(), "emergency");
        assert_eq!(ShiftSeverity::Emergency.as_str(), "emergency");
    }

    // --- ShiftAlarm ---

    #[test]
    fn test_alarm_creation() {
        let alarm = make_alarm("a1", ShiftDomain::ApiUsage, ShiftSeverity::Warning, 5);
        assert_eq!(alarm.alarm_id, "a1");
        assert_eq!(alarm.domain, ShiftDomain::ApiUsage);
        assert!(!alarm.acknowledged);
    }

    #[test]
    fn test_alarm_acknowledge() {
        let mut alarm = make_alarm("a1", ShiftDomain::General, ShiftSeverity::Info, 1);
        assert!(!alarm.acknowledged);
        alarm.acknowledge();
        assert!(alarm.acknowledged);
    }

    #[test]
    fn test_alarm_weighted_severity() {
        let alarm = make_alarm("a1", ShiftDomain::General, ShiftSeverity::Warning, 1);
        // weight=400_000, drift=500_000 -> 400_000 * 500_000 / 1_000_000 = 200_000
        assert_eq!(alarm.weighted_severity(), 200_000);
    }

    #[test]
    fn test_alarm_staleness() {
        let alarm = make_alarm("a1", ShiftDomain::General, ShiftSeverity::Info, 10);
        assert!(!alarm.is_stale(epoch(50), 100));
        assert!(alarm.is_stale(epoch(200), 100));
    }

    #[test]
    fn test_alarm_evidence_hash_deterministic() {
        let a1 = make_alarm("x", ShiftDomain::General, ShiftSeverity::Info, 5);
        let a2 = make_alarm("x", ShiftDomain::General, ShiftSeverity::Info, 5);
        assert_eq!(a1.evidence_hash, a2.evidence_hash);
    }

    // --- AcquisitionEvidence ---

    #[test]
    fn test_acquisition_burndown_ratio() {
        let ev = make_acquisition(ShiftDomain::ApiUsage, 50, 100, AcquisitionStatus::Active);
        assert_eq!(ev.burndown_ratio, 500_000); // 50%
    }

    #[test]
    fn test_acquisition_full_burndown() {
        let ev = make_acquisition(ShiftDomain::General, 100, 100, AcquisitionStatus::Complete);
        assert_eq!(ev.burndown_ratio, FIXED_ONE);
    }

    #[test]
    fn test_acquisition_zero_needed() {
        let ev = make_acquisition(ShiftDomain::General, 0, 0, AcquisitionStatus::Complete);
        assert_eq!(ev.burndown_ratio, FIXED_ONE);
    }

    #[test]
    fn test_acquisition_meets_threshold() {
        let ev = make_acquisition(ShiftDomain::General, 60, 100, AcquisitionStatus::Active);
        assert!(ev.meets_burndown_threshold(500_000));
        assert!(!ev.meets_burndown_threshold(700_000));
    }

    #[test]
    fn test_acquisition_estimated_completion() {
        let ev = make_acquisition(ShiftDomain::General, 50, 100, AcquisitionStatus::Active);
        // remaining=50, velocity=100_000 -> 50*1M/100_000 = 500
        assert_eq!(ev.estimated_epochs_to_completion(), Some(500));
    }

    #[test]
    fn test_acquisition_zero_velocity() {
        let ev = AcquisitionEvidence::new(
            ShiftDomain::General,
            10,
            100,
            AcquisitionStatus::Stalled,
            epoch(5),
            0,
        );
        assert_eq!(ev.estimated_epochs_to_completion(), None);
    }

    // --- FreshnessLevel ---

    #[test]
    fn test_freshness_confidence_multipliers() {
        assert_eq!(FreshnessLevel::Fresh.confidence_multiplier(), FIXED_ONE);
        assert_eq!(FreshnessLevel::Aging.confidence_multiplier(), 750_000);
        assert_eq!(FreshnessLevel::Stale.confidence_multiplier(), 400_000);
        assert_eq!(FreshnessLevel::Invalid.confidence_multiplier(), 0);
    }

    #[test]
    fn test_freshness_permits_full_confidence() {
        assert!(FreshnessLevel::Fresh.permits_full_confidence());
        assert!(!FreshnessLevel::Aging.permits_full_confidence());
        assert!(!FreshnessLevel::Stale.permits_full_confidence());
        assert!(!FreshnessLevel::Invalid.permits_full_confidence());
    }

    #[test]
    fn test_freshness_ordering() {
        assert!(FreshnessLevel::Fresh < FreshnessLevel::Aging);
        assert!(FreshnessLevel::Aging < FreshnessLevel::Stale);
        assert!(FreshnessLevel::Stale < FreshnessLevel::Invalid);
    }

    #[test]
    fn test_freshness_as_str_matches_display() {
        for freshness in [
            FreshnessLevel::Fresh,
            FreshnessLevel::Aging,
            FreshnessLevel::Stale,
            FreshnessLevel::Invalid,
        ] {
            assert_eq!(freshness.as_str(), freshness.to_string());
        }
    }

    // --- BenchmarkClaim ---

    #[test]
    fn test_claim_creation() {
        let claim = BenchmarkClaim::new("c1", ClaimSurface::Performance, 900_000, epoch(1), "perf");
        assert_eq!(claim.claim_id, "c1");
        assert!(claim.dependent_domains.is_empty());
    }

    #[test]
    fn test_claim_with_domains() {
        let claim = BenchmarkClaim::new("c1", ClaimSurface::Memory, 800_000, epoch(1), "mem")
            .with_domain(ShiftDomain::MemoryAllocation)
            .with_domain(ShiftDomain::ApiUsage);
        assert_eq!(claim.dependent_domains.len(), 2);
    }

    #[test]
    fn test_claim_with_domains_bulk() {
        let claim = BenchmarkClaim::new("c1", ClaimSurface::Supremacy, 950_000, epoch(1), "sup")
            .with_domains([
                ShiftDomain::General,
                ShiftDomain::ControlFlow,
                ShiftDomain::IoPattern,
            ]);
        assert_eq!(claim.dependent_domains.len(), 3);
    }

    // --- AlarmLedger ---

    #[test]
    fn test_ledger_empty() {
        let ledger = AlarmLedger::new();
        assert_eq!(ledger.active_count(), 0);
        assert_eq!(ledger.cumulative_severity, 0);
    }

    #[test]
    fn test_ledger_record_alarm() {
        let mut ledger = AlarmLedger::new();
        ledger.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Warning,
            1,
        ));
        assert_eq!(ledger.active_count(), 1);
        assert_eq!(ledger.total_alarms_recorded, 1);
        assert!(ledger.cumulative_severity > 0);
    }

    #[test]
    fn test_ledger_resolve_alarm() {
        let mut ledger = AlarmLedger::new();
        ledger.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Info,
            1,
        ));
        assert!(ledger.resolve_alarm("a1", 5));
        assert_eq!(ledger.active_count(), 0);
        assert!(!ledger.resolve_alarm("a1", 6)); // already resolved
    }

    #[test]
    fn test_ledger_prune_stale() {
        let mut ledger = AlarmLedger::new();
        ledger.record_alarm(make_alarm(
            "old",
            ShiftDomain::General,
            ShiftSeverity::Info,
            1,
        ));
        ledger.record_alarm(make_alarm(
            "new",
            ShiftDomain::General,
            ShiftSeverity::Info,
            90,
        ));
        let pruned = ledger.prune_stale(epoch(110), 50);
        assert_eq!(pruned, 1); // only "old" is stale
        assert_eq!(ledger.active_count(), 1);
    }

    #[test]
    fn test_ledger_domain_count() {
        let mut ledger = AlarmLedger::new();
        ledger.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Info,
            1,
        ));
        ledger.record_alarm(make_alarm(
            "a2",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Warning,
            2,
        ));
        ledger.record_alarm(make_alarm(
            "a3",
            ShiftDomain::General,
            ShiftSeverity::Info,
            3,
        ));
        assert_eq!(ledger.active_count_in_domain(ShiftDomain::ApiUsage), 2);
        assert_eq!(ledger.active_count_in_domain(ShiftDomain::General), 1);
        assert_eq!(ledger.active_count_in_domain(ShiftDomain::IoPattern), 0);
    }

    #[test]
    fn test_ledger_worst_severity() {
        let mut ledger = AlarmLedger::new();
        ledger.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Info,
            1,
        ));
        ledger.record_alarm(make_alarm(
            "a2",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Critical,
            2,
        ));
        assert_eq!(
            ledger.worst_severity_in_domain(ShiftDomain::ApiUsage),
            Some(ShiftSeverity::Critical)
        );
    }

    #[test]
    fn test_ledger_immediate_downgrade() {
        let mut ledger = AlarmLedger::new();
        ledger.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Warning,
            1,
        ));
        assert!(!ledger.has_immediate_downgrade_alarm());
        ledger.record_alarm(make_alarm(
            "a2",
            ShiftDomain::General,
            ShiftSeverity::Critical,
            2,
        ));
        assert!(ledger.has_immediate_downgrade_alarm());
    }

    #[test]
    fn test_ledger_content_hash_deterministic() {
        let mut l1 = AlarmLedger::new();
        let mut l2 = AlarmLedger::new();
        l1.record_alarm(make_alarm(
            "a",
            ShiftDomain::General,
            ShiftSeverity::Info,
            1,
        ));
        l2.record_alarm(make_alarm(
            "a",
            ShiftDomain::General,
            ShiftSeverity::Info,
            1,
        ));
        assert_eq!(l1.content_hash(), l2.content_hash());
    }

    // --- AcquisitionLedger ---

    #[test]
    fn test_acq_ledger_empty() {
        let ledger = AcquisitionLedger::new();
        assert_eq!(ledger.overall_burndown_ratio, FIXED_ONE);
        assert!(!ledger.has_stalled_domains());
    }

    #[test]
    fn test_acq_ledger_record_evidence() {
        let mut ledger = AcquisitionLedger::new();
        ledger.record_evidence(make_acquisition(
            ShiftDomain::ApiUsage,
            50,
            100,
            AcquisitionStatus::Active,
        ));
        assert_eq!(ledger.evidence.len(), 1);
        assert_eq!(ledger.overall_burndown_ratio, 500_000);
    }

    #[test]
    fn test_acq_ledger_replace_domain() {
        let mut ledger = AcquisitionLedger::new();
        ledger.record_evidence(make_acquisition(
            ShiftDomain::General,
            10,
            100,
            AcquisitionStatus::Active,
        ));
        assert_eq!(ledger.overall_burndown_ratio, 100_000);
        ledger.record_evidence(make_acquisition(
            ShiftDomain::General,
            80,
            100,
            AcquisitionStatus::Active,
        ));
        assert_eq!(ledger.evidence.len(), 1);
        assert_eq!(ledger.overall_burndown_ratio, 800_000);
    }

    #[test]
    fn test_acq_ledger_stalled_domains() {
        let mut ledger = AcquisitionLedger::new();
        ledger.record_evidence(make_acquisition(
            ShiftDomain::General,
            10,
            100,
            AcquisitionStatus::Stalled,
        ));
        assert!(ledger.has_stalled_domains());
        assert!(ledger.stalled_domains.contains("general"));
    }

    #[test]
    fn test_acq_ledger_all_domains_healthy() {
        let mut ledger = AcquisitionLedger::new();
        let mut required = BTreeSet::new();
        required.insert(ShiftDomain::General);
        assert!(!ledger.all_domains_healthy(&required));
        ledger.record_evidence(make_acquisition(
            ShiftDomain::General,
            50,
            100,
            AcquisitionStatus::Active,
        ));
        assert!(ledger.all_domains_healthy(&required));
    }

    // --- SilenceTracker ---

    #[test]
    fn test_silence_tracker_initial() {
        let tracker = SilenceTracker::new();
        assert!(tracker.last_signal_epoch.is_none());
        assert!(!tracker.silence_exceeded);
    }

    #[test]
    fn test_silence_tracker_record_signal() {
        let mut tracker = SilenceTracker::new();
        tracker.record_signal(epoch(10));
        assert_eq!(tracker.last_signal_epoch, Some(epoch(10)));
        assert_eq!(tracker.silent_epochs, 0);
    }

    #[test]
    fn test_silence_tracker_timeout() {
        let mut tracker = SilenceTracker::new();
        tracker.record_signal(epoch(10));
        assert!(!tracker.check_silence(epoch(30), 50));
        assert!(tracker.check_silence(epoch(100), 50));
    }

    #[test]
    fn test_silence_tracker_no_signal_timeout() {
        let mut tracker = SilenceTracker::new();
        assert!(tracker.check_silence(epoch(100), 50));
    }

    // --- RolloutTrustLevel ---

    #[test]
    fn test_rollout_trust_from_freshness() {
        assert_eq!(
            RolloutTrustLevel::from_freshness(FreshnessLevel::Fresh, true),
            RolloutTrustLevel::Full
        );
        assert_eq!(
            RolloutTrustLevel::from_freshness(FreshnessLevel::Aging, true),
            RolloutTrustLevel::Conditional
        );
        assert_eq!(
            RolloutTrustLevel::from_freshness(FreshnessLevel::Aging, false),
            RolloutTrustLevel::Reduced
        );
        assert_eq!(
            RolloutTrustLevel::from_freshness(FreshnessLevel::Invalid, true),
            RolloutTrustLevel::Blocked
        );
    }

    // --- FreshnessGate ---

    #[test]
    fn test_gate_creation() {
        let gate = FreshnessGate::new(epoch(1));
        assert_eq!(gate.current_epoch, epoch(1));
        assert_eq!(gate.total_evaluations, 0);
    }

    #[test]
    fn test_gate_fresh_when_no_alarms() {
        let mut gate = FreshnessGate::new(epoch(1));
        gate.silence_tracker.record_signal(epoch(1));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(verdict.freshness, FreshnessLevel::Fresh);
        assert_eq!(verdict.adjusted_confidence, 900_000);
        assert!(verdict.rollout_permitted);
    }

    #[test]
    fn test_gate_downgrade_on_warning() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Warning,
            9,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::ApiUsage]);
        let verdict = gate.evaluate_claim(&claim);
        // Warning without acquisition -> Stale
        assert_eq!(verdict.freshness, FreshnessLevel::Stale);
        // 900_000 * 400_000 / 1_000_000 = 360_000
        assert_eq!(verdict.adjusted_confidence, 360_000);
    }

    #[test]
    fn test_gate_aging_with_acquisition() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Warning,
            9,
        ));
        gate.record_acquisition(make_acquisition(
            ShiftDomain::ApiUsage,
            50,
            100,
            AcquisitionStatus::Active,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::ApiUsage]);
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(verdict.freshness, FreshnessLevel::Aging);
        // 900_000 * 750_000 / 1_000_000 = 675_000
        assert_eq!(verdict.adjusted_confidence, 675_000);
    }

    #[test]
    fn test_gate_invalid_on_emergency() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Emergency,
            9,
        ));
        let claim = make_claim("c1", ClaimSurface::Supremacy, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(verdict.freshness, FreshnessLevel::Invalid);
        assert_eq!(verdict.adjusted_confidence, 0);
        assert!(!verdict.rollout_permitted);
    }

    #[test]
    fn test_gate_silence_degrades() {
        let mut gate = FreshnessGate::new(epoch(100));
        // No signals ever recorded, silence timeout triggers
        gate.silence_tracker
            .check_silence(epoch(100), gate.config.silence_timeout_epochs);
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(verdict.freshness, FreshnessLevel::Stale);
    }

    #[test]
    fn test_gate_resolve_alarm_improves_freshness() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Warning,
            9,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);

        let v1 = gate.evaluate_claim(&claim);
        assert_eq!(v1.freshness, FreshnessLevel::Stale);

        gate.resolve_alarm("a1");
        let v2 = gate.evaluate_claim(&claim);
        assert_eq!(v2.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn test_gate_advance_epoch_prunes() {
        let mut gate = FreshnessGate::new(epoch(1));
        gate.record_alarm(make_alarm(
            "old",
            ShiftDomain::General,
            ShiftSeverity::Info,
            1,
        ));
        gate.advance_epoch(epoch(200));
        assert_eq!(gate.alarm_ledger.active_count(), 0);
    }

    #[test]
    fn test_gate_multiple_domains() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Info,
            9,
        ));
        // ApiUsage has alarm -> Aging, General is Fresh
        let claim = make_claim(
            "c1",
            ClaimSurface::Performance,
            &[ShiftDomain::ApiUsage, ShiftDomain::General],
        );
        let verdict = gate.evaluate_claim(&claim);
        // Worst domain wins -> Aging
        assert_eq!(verdict.freshness, FreshnessLevel::Aging);
    }

    #[test]
    fn test_gate_batch_evaluation() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Warning,
            9,
        ));

        let claims = vec![
            make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]),
            make_claim("c2", ClaimSurface::Memory, &[ShiftDomain::ApiUsage]),
        ];
        let batch = gate.evaluate_batch(&claims);
        assert_eq!(batch.claims_total, 2);
        assert_eq!(batch.claims_full_confidence, 1); // c1
        assert_eq!(batch.claims_downgraded, 1); // c2
    }

    #[test]
    fn test_gate_batch_max_size() {
        let mut gate = FreshnessGate::new(epoch(1));
        gate.silence_tracker.record_signal(epoch(1));
        gate.config.max_batch_size = 2;
        let claims: Vec<BenchmarkClaim> = (0..5)
            .map(|i| make_claim(&format!("c{}", i), ClaimSurface::Performance, &[]))
            .collect();
        let batch = gate.evaluate_batch(&claims);
        assert_eq!(batch.claims_total, 2);
    }

    #[test]
    fn test_gate_critical_with_good_acquisition() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Critical,
            9,
        ));
        gate.record_acquisition(make_acquisition(
            ShiftDomain::General,
            60,
            100,
            AcquisitionStatus::Active,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        // Critical with healthy acquisition above burndown threshold -> Aging (not Invalid)
        assert_eq!(verdict.freshness, FreshnessLevel::Aging);
    }

    #[test]
    fn test_gate_critical_without_acquisition() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Critical,
            9,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        // Critical without acquisition -> Invalid
        assert_eq!(verdict.freshness, FreshnessLevel::Invalid);
    }

    #[test]
    fn test_gate_cumulative_severity_threshold() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        // Add many warning alarms to exceed cumulative threshold
        for i in 0..20 {
            gate.record_alarm(make_alarm(
                &format!("a{}", i),
                ShiftDomain::General,
                ShiftSeverity::Warning,
                9,
            ));
        }
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(verdict.freshness, FreshnessLevel::Stale);
    }

    // --- FreshnessVerdict ---

    #[test]
    fn test_verdict_downgrade_fraction() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        let claim = make_claim("c1", ClaimSurface::Performance, &[]);
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(verdict.downgrade_fraction(), 0); // Fresh -> no downgrade
    }

    #[test]
    fn test_verdict_downgrade_fraction_nonzero() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Info,
            9,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        assert!(verdict.downgrade_fraction() > 0);
    }

    #[test]
    fn test_verdict_is_full_confidence() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        let claim = make_claim("c1", ClaimSurface::Performance, &[]);
        let verdict = gate.evaluate_claim(&claim);
        assert!(verdict.is_full_confidence());
        assert!(!verdict.is_downgraded());
    }

    // --- DecisionReceipt ---

    #[test]
    fn test_decision_receipt_from_verdict() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        let claim = make_claim("c1", ClaimSurface::Performance, &[]);
        let verdict = gate.evaluate_claim(&claim);
        let receipt = DecisionReceipt::from_verdict(&verdict, &gate.config);
        assert_eq!(receipt.claim_id, "c1");
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.policy_id, POLICY_ID);
        assert_eq!(receipt.freshness, FreshnessLevel::Fresh);
    }

    // --- GateSummary ---

    #[test]
    fn test_summary_healthy() {
        let mut gate = FreshnessGate::new(epoch(1));
        gate.silence_tracker.record_signal(epoch(1));
        let summary = gate.summary();
        assert!(summary.is_healthy());
        assert_eq!(summary.active_alarms, 0);
    }

    #[test]
    fn test_summary_unhealthy_with_alarms() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Warning,
            9,
        ));
        let summary = gate.summary();
        assert!(!summary.is_healthy());
        assert_eq!(summary.active_alarms, 1);
    }

    // --- Serialization ---

    #[test]
    fn test_severity_serde_roundtrip() {
        let severity = ShiftSeverity::Critical;
        let json = serde_json::to_string(&severity).unwrap();
        let back: ShiftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(severity, back);
    }

    #[test]
    fn test_alarm_serde_roundtrip() {
        let alarm = make_alarm("a1", ShiftDomain::ApiUsage, ShiftSeverity::Warning, 5);
        let json = serde_json::to_string(&alarm).unwrap();
        let back: ShiftAlarm = serde_json::from_str(&json).unwrap();
        assert_eq!(alarm, back);
    }

    #[test]
    fn test_acquisition_serde_roundtrip() {
        let ev = make_acquisition(ShiftDomain::General, 50, 100, AcquisitionStatus::Active);
        let json = serde_json::to_string(&ev).unwrap();
        let back: AcquisitionEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]);
        let verdict = gate.evaluate_claim(&claim);
        let json = serde_json::to_string(&verdict).unwrap();
        let back: FreshnessVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }

    #[test]
    fn test_gate_serde_roundtrip() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::General,
            ShiftSeverity::Info,
            5,
        ));
        let json = serde_json::to_string(&gate).unwrap();
        let back: FreshnessGate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.alarm_ledger.active_count(), 1);
    }

    #[test]
    fn test_batch_verdict_serde_roundtrip() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        let claims = vec![make_claim("c1", ClaimSurface::Performance, &[])];
        let batch = gate.evaluate_batch(&claims);
        let json = serde_json::to_string(&batch).unwrap();
        let back: BatchVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(batch.claims_total, back.claims_total);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        let claim = make_claim("c1", ClaimSurface::Performance, &[]);
        let verdict = gate.evaluate_claim(&claim);
        let receipt = DecisionReceipt::from_verdict(&verdict, &gate.config);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // --- Edge Cases ---

    #[test]
    fn test_claim_no_domains_always_fresh() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Critical,
            9,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[]);
        let verdict = gate.evaluate_claim(&claim);
        // Claim has no dependent domains, but gate has critical alarm -> Invalid via immediate downgrade
        assert_eq!(verdict.freshness, FreshnessLevel::Invalid);
    }

    #[test]
    fn test_required_active_domains() {
        let mut config = GateConfig::default();
        config.required_active_domains.insert(ShiftDomain::ApiUsage);
        let mut gate = FreshnessGate::with_config(config, epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        let claim = make_claim("c1", ClaimSurface::Performance, &[]);
        let verdict = gate.evaluate_claim(&claim);
        // Required domain not covered -> at least Aging
        assert!(verdict.freshness >= FreshnessLevel::Aging);
    }

    #[test]
    fn test_total_evaluations_counter() {
        let mut gate = FreshnessGate::new(epoch(1));
        gate.silence_tracker.record_signal(epoch(1));
        let claim = make_claim("c1", ClaimSurface::Performance, &[]);
        gate.evaluate_claim(&claim);
        gate.evaluate_claim(&claim);
        gate.evaluate_claim(&claim);
        assert_eq!(gate.total_evaluations, 3);
    }

    #[test]
    fn test_gate_with_custom_config() {
        let config = GateConfig {
            max_alarm_age_epochs: 10,
            min_burndown_ratio: 900_000,
            critical_severity_threshold: 500_000,
            max_cumulative_severity: 500_000,
            min_acquisition_samples: 5,
            silence_timeout_epochs: 20,
            max_batch_size: 50,
            required_active_domains: BTreeSet::new(),
            permit_rollout_when_aging: false,
        };
        let gate = FreshnessGate::with_config(config.clone(), epoch(1));
        assert_eq!(gate.config.max_alarm_age_epochs, 10);
        assert!(!gate.config.permit_rollout_when_aging);
    }

    #[test]
    fn test_contributing_alarms_in_verdict() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Info,
            9,
        ));
        gate.record_alarm(make_alarm(
            "a2",
            ShiftDomain::General,
            ShiftSeverity::Info,
            9,
        ));
        let claim = make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::ApiUsage]);
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(verdict.contributing_alarms.len(), 1);
        assert_eq!(verdict.contributing_alarms[0], "a1");
    }

    #[test]
    fn test_domain_freshness_map_in_verdict() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Info,
            9,
        ));
        let claim = make_claim(
            "c1",
            ClaimSurface::Performance,
            &[ShiftDomain::ApiUsage, ShiftDomain::General],
        );
        let verdict = gate.evaluate_claim(&claim);
        assert_eq!(
            verdict.domain_freshness.get("api_usage"),
            Some(&FreshnessLevel::Aging)
        );
        assert_eq!(
            verdict.domain_freshness.get("general"),
            Some(&FreshnessLevel::Fresh)
        );
    }

    #[test]
    fn test_acquisition_status_healthy() {
        assert!(AcquisitionStatus::Active.is_healthy());
        assert!(AcquisitionStatus::Complete.is_healthy());
        assert!(!AcquisitionStatus::Paused.is_healthy());
        assert!(!AcquisitionStatus::Stalled.is_healthy());
        assert!(!AcquisitionStatus::Absent.is_healthy());
    }

    #[test]
    fn test_shift_domain_display() {
        assert_eq!(ShiftDomain::ProgramSize.to_string(), "program_size");
        assert_eq!(ShiftDomain::ProgramSize.as_str(), "program_size");
        assert_eq!(ShiftDomain::ApiUsage.to_string(), "api_usage");
        assert_eq!(ShiftDomain::ApiUsage.as_str(), "api_usage");
        assert_eq!(ShiftDomain::ControlFlow.to_string(), "control_flow");
        assert_eq!(ShiftDomain::ControlFlow.as_str(), "control_flow");
    }

    #[test]
    fn test_claim_surface_display() {
        assert_eq!(ClaimSurface::Performance.to_string(), "performance");
        assert_eq!(ClaimSurface::Supremacy.to_string(), "supremacy");
    }

    #[test]
    fn test_rollout_trust_as_str_matches_display() {
        for trust in [
            RolloutTrustLevel::Full,
            RolloutTrustLevel::Conditional,
            RolloutTrustLevel::Reduced,
            RolloutTrustLevel::Blocked,
        ] {
            assert_eq!(trust.as_str(), trust.to_string());
        }
    }

    #[test]
    fn test_batch_overall_freshness_worst_of_all() {
        let mut gate = FreshnessGate::new(epoch(10));
        gate.silence_tracker.record_signal(epoch(10));
        gate.record_alarm(make_alarm(
            "a1",
            ShiftDomain::ApiUsage,
            ShiftSeverity::Emergency,
            9,
        ));
        let claims = vec![
            make_claim("c1", ClaimSurface::Performance, &[ShiftDomain::General]),
            make_claim("c2", ClaimSurface::Memory, &[ShiftDomain::ApiUsage]),
        ];
        let batch = gate.evaluate_batch(&claims);
        // Emergency alarm makes overall Invalid even though c1's domain is fine
        assert_eq!(batch.overall_freshness, FreshnessLevel::Invalid);
        assert_eq!(batch.rollout_trust, RolloutTrustLevel::Blocked);
    }
}
