//! Observability Channel Model and Rate-Distortion Constitution.
//!
//! Defines a formal channel model for evidence generation and transport
//! across compiler, runtime, and control-plane paths.  Every evidence
//! payload family has explicit utility functions, distortion metrics,
//! rate-distortion envelopes, and failure budgets.
//!
//! The constitutional policy forbids:
//! - uncapped telemetry (every channel has a rate budget),
//! - unverifiable lossy compression (distortion must be measurable),
//! - evidence emission without backpressure bounds.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic cross-platform computation.
//!
//! Plan reference: FRX-17.1 (Observability Channel Model).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

/// Schema version for channel model artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.observability-channel.v1";

// ---------------------------------------------------------------------------
// PayloadFamily — evidence payload taxonomy
// ---------------------------------------------------------------------------

/// Evidence payload family classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadFamily {
    /// Decision evidence: lane routing, containment, fallback decisions.
    Decision,
    /// Replay evidence: deterministic replay transcripts and traces.
    Replay,
    /// Optimization evidence: compilation pass witnesses, e-graph logs.
    Optimization,
    /// Security evidence: capability grants, revocations, incident records.
    Security,
    /// Legal provenance: audit chains, compliance artifacts, retention records.
    LegalProvenance,
}

impl PayloadFamily {
    pub const ALL: [PayloadFamily; 5] = [
        PayloadFamily::Decision,
        PayloadFamily::Replay,
        PayloadFamily::Optimization,
        PayloadFamily::Security,
        PayloadFamily::LegalProvenance,
    ];
}

impl fmt::Display for PayloadFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decision => write!(f, "decision"),
            Self::Replay => write!(f, "replay"),
            Self::Optimization => write!(f, "optimization"),
            Self::Security => write!(f, "security"),
            Self::LegalProvenance => write!(f, "legal_provenance"),
        }
    }
}

// ---------------------------------------------------------------------------
// DistortionMetric — how we measure information loss
// ---------------------------------------------------------------------------

/// Metric used to quantify distortion when compressing or sampling evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistortionMetric {
    /// Hamming distortion: fraction of symbols that differ.
    Hamming,
    /// Squared error distortion (for quantile-valued payloads).
    SquaredError,
    /// Log-loss distortion (for probability-valued payloads).
    LogLoss,
    /// Edit distance distortion (for structured trace payloads).
    EditDistance,
    /// Binary: either lossless or total loss (for legal provenance).
    BinaryFidelity,
}

impl fmt::Display for DistortionMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hamming => write!(f, "hamming"),
            Self::SquaredError => write!(f, "squared_error"),
            Self::LogLoss => write!(f, "log_loss"),
            Self::EditDistance => write!(f, "edit_distance"),
            Self::BinaryFidelity => write!(f, "binary_fidelity"),
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelPath — where evidence flows
// ---------------------------------------------------------------------------

/// The pipeline path through which evidence travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPath {
    /// Compiler output → evidence ledger.
    CompilerToLedger,
    /// Runtime controller → evidence ledger.
    RuntimeToLedger,
    /// Control plane → governance audit.
    ControlPlaneToAudit,
    /// Cross-lane replay → deterministic verifier.
    ReplayToVerifier,
    /// Any path → external compliance archive.
    ToComplianceArchive,
}

impl ChannelPath {
    pub const ALL: [ChannelPath; 5] = [
        ChannelPath::CompilerToLedger,
        ChannelPath::RuntimeToLedger,
        ChannelPath::ControlPlaneToAudit,
        ChannelPath::ReplayToVerifier,
        ChannelPath::ToComplianceArchive,
    ];
}

impl fmt::Display for ChannelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompilerToLedger => write!(f, "compiler_to_ledger"),
            Self::RuntimeToLedger => write!(f, "runtime_to_ledger"),
            Self::ControlPlaneToAudit => write!(f, "control_plane_to_audit"),
            Self::ReplayToVerifier => write!(f, "replay_to_verifier"),
            Self::ToComplianceArchive => write!(f, "to_compliance_archive"),
        }
    }
}

// ---------------------------------------------------------------------------
// RateDistortionPoint — a single operating point on the R(D) curve
// ---------------------------------------------------------------------------

/// A single point on the rate-distortion frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateDistortionPoint {
    /// Distortion level (millionths of the distortion metric's unit).
    pub distortion_millionths: i64,
    /// Rate in millibits per symbol (millionths of bits).
    pub rate_millibits: i64,
}

// ---------------------------------------------------------------------------
// RateDistortionEnvelope — the achievable frontier for a family
// ---------------------------------------------------------------------------

/// Rate-distortion envelope for one payload family.
///
/// Defines the minimum rate (bits) needed to represent the payload at
/// each distortion level, plus operational constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateDistortionEnvelope {
    /// Which payload family this envelope covers.
    pub family: PayloadFamily,
    /// The distortion metric used.
    pub metric: DistortionMetric,
    /// Frontier points (sorted by increasing distortion).
    pub frontier: Vec<RateDistortionPoint>,
    /// Maximum tolerable distortion (millionths).  Above this, the
    /// evidence is considered unverifiable and must be rejected.
    pub max_distortion_millionths: i64,
    /// Minimum required rate (millibits per symbol).  Below this,
    /// the compression is considered insufficient quality.
    pub min_rate_millibits: i64,
}

impl RateDistortionEnvelope {
    /// Interpolate the frontier to find the rate for a given distortion.
    ///
    /// Returns `None` if distortion exceeds `max_distortion_millionths`
    /// or if the frontier is empty.
    pub fn rate_at_distortion(&self, distortion_millionths: i64) -> Option<i64> {
        if distortion_millionths > self.max_distortion_millionths {
            return None;
        }
        if self.frontier.is_empty() {
            return None;
        }
        // Find surrounding points and linearly interpolate.
        let mut prev: Option<&RateDistortionPoint> = None;
        for pt in &self.frontier {
            if pt.distortion_millionths >= distortion_millionths {
                if let Some(p) = prev {
                    // Linear interpolation.
                    let dd = pt.distortion_millionths - p.distortion_millionths;
                    if dd == 0 {
                        return Some(pt.rate_millibits);
                    }
                    let frac = distortion_millionths - p.distortion_millionths;
                    let dr = pt.rate_millibits - p.rate_millibits;
                    return Some(p.rate_millibits + (dr * frac) / dd);
                }
                return Some(pt.rate_millibits);
            }
            prev = Some(pt);
        }
        // Past last point — use last point's rate.
        self.frontier.last().map(|pt| pt.rate_millibits)
    }

    /// Check if a given (rate, distortion) operating point is within the
    /// achievable region.
    pub fn is_achievable(&self, rate_millibits: i64, distortion_millionths: i64) -> bool {
        if distortion_millionths > self.max_distortion_millionths {
            return false;
        }
        match self.rate_at_distortion(distortion_millionths) {
            Some(min_rate) => rate_millibits >= min_rate,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// FailureBudget — how many evidence losses per epoch we tolerate
// ---------------------------------------------------------------------------

/// Failure budget for a channel: how many evidence items can be lost
/// or degraded per epoch before triggering a policy violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureBudget {
    /// Maximum dropped evidence items per epoch.
    pub max_drops_per_epoch: u64,
    /// Maximum degraded (high-distortion) items per epoch.
    pub max_degraded_per_epoch: u64,
    /// Distortion threshold (millionths) above which an item is "degraded".
    pub degradation_threshold_millionths: i64,
    /// Whether exceeding the budget triggers immediate demotion.
    pub fail_closed: bool,
}

impl Default for FailureBudget {
    fn default() -> Self {
        Self {
            max_drops_per_epoch: 0,
            max_degraded_per_epoch: 10,
            degradation_threshold_millionths: 100_000, // 10%
            fail_closed: true,
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelSpec — full specification for one observability channel
// ---------------------------------------------------------------------------

/// Complete specification for one observability channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSpec {
    /// Channel identifier.
    pub channel_id: String,
    /// Payload family this channel transports.
    pub family: PayloadFamily,
    /// The pipeline path.
    pub path: ChannelPath,
    /// Rate-distortion envelope.
    pub envelope: RateDistortionEnvelope,
    /// Failure budget.
    pub failure_budget: FailureBudget,
    /// Maximum emission rate: items per epoch.
    pub max_items_per_epoch: u64,
    /// Backpressure buffer limit.
    pub buffer_capacity: u64,
    /// Whether lossy compression is permitted (constitutional constraint).
    pub lossy_permitted: bool,
    /// Tags for filtering.
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// DistortionRiskEntry — distortion-to-risk conversion
// ---------------------------------------------------------------------------

/// Maps a distortion level to a risk score for governance consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistortionRiskEntry {
    /// Distortion level (millionths).
    pub distortion_millionths: i64,
    /// Risk score (millionths, 0 = no risk, MILLION = maximum risk).
    pub risk_millionths: i64,
    /// Human-readable consequence description.
    pub consequence: String,
}

// ---------------------------------------------------------------------------
// DistortionRiskLedger — distortion-to-risk conversion table
// ---------------------------------------------------------------------------

/// Conversion table from distortion to risk for a payload family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistortionRiskLedger {
    pub family: PayloadFamily,
    pub entries: Vec<DistortionRiskEntry>,
}

impl DistortionRiskLedger {
    /// Interpolate risk for a given distortion level.
    pub fn risk_at_distortion(&self, distortion_millionths: i64) -> i64 {
        if self.entries.is_empty() {
            return 0;
        }
        let mut prev: Option<&DistortionRiskEntry> = None;
        for entry in &self.entries {
            if entry.distortion_millionths >= distortion_millionths {
                if let Some(p) = prev {
                    let dd = entry.distortion_millionths - p.distortion_millionths;
                    if dd == 0 {
                        return entry.risk_millionths;
                    }
                    let frac = distortion_millionths - p.distortion_millionths;
                    let dr = entry.risk_millionths - p.risk_millionths;
                    return p.risk_millionths + (dr * frac) / dd;
                }
                return entry.risk_millionths;
            }
            prev = Some(entry);
        }
        self.entries.last().map(|e| e.risk_millionths).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// PolicyViolation — when constitutional constraints are breached
// ---------------------------------------------------------------------------

/// A violation of the observability constitution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub channel_id: String,
    pub epoch: SecurityEpoch,
    pub violation_kind: ViolationKind,
    pub detail: String,
}

/// Kind of constitutional violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    /// Telemetry rate exceeded without budget.
    UncappedTelemetry,
    /// Lossy compression applied without verifiable distortion bound.
    UnverifiableLoss,
    /// Evidence dropped beyond failure budget.
    DropBudgetExceeded,
    /// Degradation budget exceeded.
    DegradationBudgetExceeded,
    /// Backpressure buffer overflow.
    BackpressureOverflow,
}

impl fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UncappedTelemetry => write!(f, "uncapped_telemetry"),
            Self::UnverifiableLoss => write!(f, "unverifiable_loss"),
            Self::DropBudgetExceeded => write!(f, "drop_budget_exceeded"),
            Self::DegradationBudgetExceeded => write!(f, "degradation_budget_exceeded"),
            Self::BackpressureOverflow => write!(f, "backpressure_overflow"),
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelState — runtime state for a channel
// ---------------------------------------------------------------------------

/// Runtime state for an observability channel within an epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelState {
    pub channel_id: String,
    pub epoch: SecurityEpoch,
    pub items_emitted: u64,
    pub items_dropped: u64,
    pub items_degraded: u64,
    pub buffer_used: u64,
    pub violations: Vec<PolicyViolation>,
}

impl ChannelState {
    pub fn new(channel_id: String, epoch: SecurityEpoch) -> Self {
        Self {
            channel_id,
            epoch,
            items_emitted: 0,
            items_dropped: 0,
            items_degraded: 0,
            buffer_used: 0,
            violations: Vec::new(),
        }
    }

    /// Record an emission.  Returns `Err` with a violation if the emission
    /// would breach the channel spec's constitutional constraints.
    pub fn emit(
        &mut self,
        spec: &ChannelSpec,
        distortion_millionths: i64,
    ) -> Result<(), PolicyViolation> {
        // Check rate cap.
        if self.items_emitted >= spec.max_items_per_epoch {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::UncappedTelemetry,
                detail: format!(
                    "rate cap {} exceeded at {}",
                    spec.max_items_per_epoch, self.items_emitted,
                ),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Check backpressure.
        if self.buffer_used >= spec.buffer_capacity {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::BackpressureOverflow,
                detail: format!("buffer full: {}/{}", self.buffer_used, spec.buffer_capacity,),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Check lossy compression constitutional constraint.
        if distortion_millionths > 0 && !spec.lossy_permitted {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::UnverifiableLoss,
                detail: format!(
                    "lossy emission (distortion={distortion_millionths}) on lossless-only channel",
                ),
            };
            self.violations.push(violation.clone());
            return Err(violation);
        }

        // Track degradation.
        if distortion_millionths > spec.failure_budget.degradation_threshold_millionths {
            self.items_degraded += 1;
            if self.items_degraded > spec.failure_budget.max_degraded_per_epoch {
                let violation = PolicyViolation {
                    channel_id: self.channel_id.clone(),
                    epoch: self.epoch,
                    violation_kind: ViolationKind::DegradationBudgetExceeded,
                    detail: format!(
                        "degraded items {} exceed budget {}",
                        self.items_degraded, spec.failure_budget.max_degraded_per_epoch,
                    ),
                };
                self.violations.push(violation.clone());
                if spec.failure_budget.fail_closed {
                    return Err(violation);
                }
            }
        }

        self.items_emitted += 1;
        self.buffer_used += 1;
        Ok(())
    }

    /// Record a dropped evidence item.
    pub fn record_drop(&mut self, spec: &ChannelSpec) -> Result<(), PolicyViolation> {
        self.items_dropped += 1;
        if self.items_dropped > spec.failure_budget.max_drops_per_epoch {
            let violation = PolicyViolation {
                channel_id: self.channel_id.clone(),
                epoch: self.epoch,
                violation_kind: ViolationKind::DropBudgetExceeded,
                detail: format!(
                    "drops {} exceed budget {}",
                    self.items_dropped, spec.failure_budget.max_drops_per_epoch,
                ),
            };
            self.violations.push(violation.clone());
            if spec.failure_budget.fail_closed {
                return Err(violation);
            }
        }
        Ok(())
    }

    /// Drain one item from the buffer.
    pub fn drain_one(&mut self) {
        self.buffer_used = self.buffer_used.saturating_sub(1);
    }

    /// Reset all counters for a new epoch.
    pub fn epoch_reset(&mut self, new_epoch: SecurityEpoch) {
        self.epoch = new_epoch;
        self.items_emitted = 0;
        self.items_dropped = 0;
        self.items_degraded = 0;
        self.buffer_used = 0;
        self.violations.clear();
    }

    /// Check if the channel is in a healthy state.
    pub fn is_healthy(&self, spec: &ChannelSpec) -> bool {
        self.items_dropped <= spec.failure_budget.max_drops_per_epoch
            && self.items_degraded <= spec.failure_budget.max_degraded_per_epoch
            && self.violations.is_empty()
    }
}

// ---------------------------------------------------------------------------
// ChannelReport — CI-readable report for all channels
// ---------------------------------------------------------------------------

/// Health report for the observability channel model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelReport {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub channels: Vec<ChannelHealthEntry>,
    pub total_violations: u64,
    pub gate_pass: bool,
    pub content_hash: String,
    pub summary: String,
}

/// Health entry for one channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelHealthEntry {
    pub channel_id: String,
    pub family: PayloadFamily,
    pub path: ChannelPath,
    pub items_emitted: u64,
    pub items_dropped: u64,
    pub items_degraded: u64,
    pub utilization_millionths: i64,
    pub healthy: bool,
    pub violation_count: u64,
}

/// Generate a channel report from specs and states.
pub fn generate_report(
    specs: &[ChannelSpec],
    states: &BTreeMap<String, ChannelState>,
    epoch: SecurityEpoch,
) -> ChannelReport {
    let mut entries = Vec::new();
    let mut total_violations = 0u64;
    let mut any_unhealthy = false;

    for spec in specs {
        let state = states.get(&spec.channel_id);
        let (emitted, dropped, degraded, violations, healthy) = match state {
            Some(s) => {
                let h = s.is_healthy(spec);
                (
                    s.items_emitted,
                    s.items_dropped,
                    s.items_degraded,
                    s.violations.len() as u64,
                    h,
                )
            }
            None => (0, 0, 0, 0, true),
        };

        let utilization = if spec.max_items_per_epoch > 0 {
            (emitted as i128 * MILLION as i128 / spec.max_items_per_epoch as i128) as i64
        } else {
            0
        };

        if !healthy {
            any_unhealthy = true;
        }
        total_violations += violations;

        entries.push(ChannelHealthEntry {
            channel_id: spec.channel_id.clone(),
            family: spec.family,
            path: spec.path,
            items_emitted: emitted,
            items_dropped: dropped,
            items_degraded: degraded,
            utilization_millionths: utilization,
            healthy,
            violation_count: violations,
        });
    }

    let canonical = serde_json::to_string(&entries).unwrap_or_default();
    let hash = Sha256::digest(canonical.as_bytes());
    let content_hash = hex::encode(hash);

    let healthy_count = entries.iter().filter(|e| e.healthy).count();
    let summary = format!(
        "{}/{} channels healthy, {} violations — gate {}",
        healthy_count,
        entries.len(),
        total_violations,
        if !any_unhealthy { "PASS" } else { "FAIL" },
    );

    ChannelReport {
        schema_version: SCHEMA_VERSION.to_string(),
        epoch,
        channels: entries,
        total_violations,
        gate_pass: !any_unhealthy,
        content_hash,
        summary,
    }
}

// ---------------------------------------------------------------------------
// Default channel specs — canonical channel configuration
// ---------------------------------------------------------------------------

/// Build the canonical set of observability channel specifications.
pub fn canonical_channel_specs() -> Vec<ChannelSpec> {
    vec![
        ChannelSpec {
            channel_id: "ch-decision-ledger".to_string(),
            family: PayloadFamily::Decision,
            path: ChannelPath::RuntimeToLedger,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Decision,
                metric: DistortionMetric::LogLoss,
                frontier: vec![
                    RateDistortionPoint {
                        distortion_millionths: 0,
                        rate_millibits: 2_000_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 50_000,
                        rate_millibits: 1_200_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 100_000,
                        rate_millibits: 800_000,
                    },
                ],
                max_distortion_millionths: 100_000, // 10%
                min_rate_millibits: 500_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 5,
                degradation_threshold_millionths: 50_000,
                fail_closed: true,
            },
            max_items_per_epoch: 100_000,
            buffer_capacity: 4096,
            lossy_permitted: true,
            tags: vec!["decision".to_string(), "runtime".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-replay-verifier".to_string(),
            family: PayloadFamily::Replay,
            path: ChannelPath::ReplayToVerifier,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Replay,
                metric: DistortionMetric::Hamming,
                frontier: vec![RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 8_000_000,
                }],
                max_distortion_millionths: 0, // lossless only
                min_rate_millibits: 8_000_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 0,
                degradation_threshold_millionths: 0,
                fail_closed: true,
            },
            max_items_per_epoch: 50_000,
            buffer_capacity: 2048,
            lossy_permitted: false,
            tags: vec!["replay".to_string(), "lossless".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-optimization-ledger".to_string(),
            family: PayloadFamily::Optimization,
            path: ChannelPath::CompilerToLedger,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Optimization,
                metric: DistortionMetric::SquaredError,
                frontier: vec![
                    RateDistortionPoint {
                        distortion_millionths: 0,
                        rate_millibits: 4_000_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 100_000,
                        rate_millibits: 2_000_000,
                    },
                    RateDistortionPoint {
                        distortion_millionths: 200_000,
                        rate_millibits: 1_000_000,
                    },
                ],
                max_distortion_millionths: 200_000, // 20%
                min_rate_millibits: 500_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 10,
                max_degraded_per_epoch: 50,
                degradation_threshold_millionths: 100_000,
                fail_closed: false,
            },
            max_items_per_epoch: 200_000,
            buffer_capacity: 8192,
            lossy_permitted: true,
            tags: vec!["optimization".to_string(), "compiler".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-security-audit".to_string(),
            family: PayloadFamily::Security,
            path: ChannelPath::ControlPlaneToAudit,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::Security,
                metric: DistortionMetric::BinaryFidelity,
                frontier: vec![RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 1_000_000,
                }],
                max_distortion_millionths: 0, // lossless only
                min_rate_millibits: 1_000_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 0,
                degradation_threshold_millionths: 0,
                fail_closed: true,
            },
            max_items_per_epoch: 10_000,
            buffer_capacity: 1024,
            lossy_permitted: false,
            tags: vec!["security".to_string(), "audit".to_string()],
        },
        ChannelSpec {
            channel_id: "ch-legal-archive".to_string(),
            family: PayloadFamily::LegalProvenance,
            path: ChannelPath::ToComplianceArchive,
            envelope: RateDistortionEnvelope {
                family: PayloadFamily::LegalProvenance,
                metric: DistortionMetric::BinaryFidelity,
                frontier: vec![RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 500_000,
                }],
                max_distortion_millionths: 0, // lossless only
                min_rate_millibits: 500_000,
            },
            failure_budget: FailureBudget {
                max_drops_per_epoch: 0,
                max_degraded_per_epoch: 0,
                degradation_threshold_millionths: 0,
                fail_closed: true,
            },
            max_items_per_epoch: 5_000,
            buffer_capacity: 512,
            lossy_permitted: false,
            tags: vec!["legal".to_string(), "compliance".to_string()],
        },
    ]
}

/// Build the canonical distortion-to-risk conversion ledger.
pub fn canonical_risk_ledgers() -> Vec<DistortionRiskLedger> {
    vec![
        DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "lossless decision evidence".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 50_000,
                    risk_millionths: 200_000,
                    consequence: "minor precision loss in loss estimates".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 100_000,
                    risk_millionths: 600_000,
                    consequence: "significant decision audit degradation".to_string(),
                },
            ],
        },
        DistortionRiskLedger {
            family: PayloadFamily::Security,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "lossless security evidence".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 1,
                    risk_millionths: MILLION,
                    consequence: "any loss in security evidence is maximum risk".to_string(),
                },
            ],
        },
    ]
}

// ---------------------------------------------------------------------------
// Engine telemetry observability contract surfaces
// ---------------------------------------------------------------------------

/// Schema version for the engine observability channel policy artifact.
pub const ENGINE_OBSERVABILITY_CHANNEL_POLICY_SCHEMA_VERSION: &str =
    "franken-engine.engine-observability-channel-policy.v1";
/// Schema version for the operator mode contract artifact.
pub const OPERATOR_MODE_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.operator-mode-contract.v1";
/// Schema version for the telemetry site policy matrix artifact.
pub const TELEMETRY_SITE_POLICY_MATRIX_SCHEMA_VERSION: &str =
    "franken-engine.telemetry-site-policy-matrix.v1";
/// Schema version for the telemetry sampling contract artifact.
pub const TELEMETRY_SAMPLING_CONTRACT_SCHEMA_VERSION: &str =
    "franken-engine.telemetry-sampling-contract.v1";
/// Schema version for the sketch error envelope artifact.
pub const SKETCH_ERROR_ENVELOPE_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.sketch-error-envelope-report.v1";
/// Schema version for the sampling replay fixture matrix artifact.
pub const SAMPLING_SEED_REPLAY_FIXTURE_MATRIX_SCHEMA_VERSION: &str =
    "franken-engine.sampling-seed-replay-fixture-matrix.v1";

/// Operator-visible observability modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservabilityMode {
    /// Default shipped capture mode.
    DefaultCapture,
    /// Exact-shadow validation mode.
    ExactShadow,
    /// Degraded fallback mode for bounded-loss telemetry families.
    Degraded,
    /// Incident mode that forces full-fidelity capture.
    IncidentFullCapture,
    /// Support-bundle export mode.
    SupportBundleExport,
}

impl ObservabilityMode {
    pub const ALL: [Self; 5] = [
        Self::DefaultCapture,
        Self::ExactShadow,
        Self::Degraded,
        Self::IncidentFullCapture,
        Self::SupportBundleExport,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DefaultCapture => "default_capture",
            Self::ExactShadow => "exact_shadow",
            Self::Degraded => "degraded",
            Self::IncidentFullCapture => "incident_full_capture",
            Self::SupportBundleExport => "support_bundle_export",
        }
    }
}

impl fmt::Display for ObservabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Approximate sketch families permitted for budgeted telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SketchFamily {
    CountMin,
    HyperLogLog,
    Kll,
    HeavyHitter,
    NitroSketchWeighted,
}

impl SketchFamily {
    pub const ALL: [Self; 5] = [
        Self::CountMin,
        Self::HyperLogLog,
        Self::Kll,
        Self::HeavyHitter,
        Self::NitroSketchWeighted,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CountMin => "count_min",
            Self::HyperLogLog => "hyper_log_log",
            Self::Kll => "kll",
            Self::HeavyHitter => "heavy_hitter",
            Self::NitroSketchWeighted => "nitro_sketch_weighted",
        }
    }
}

impl fmt::Display for SketchFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Sampling strategy used by an engine telemetry site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingStrategy {
    DeterministicStride,
    GeometricWeightedSkip,
}

impl SamplingStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicStride => "deterministic_stride",
            Self::GeometricWeightedSkip => "geometric_weighted_skip",
        }
    }
}

impl fmt::Display for SamplingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Seed-material field used when deriving replay-stable sampling decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SamplingSeedField {
    TraceId,
    WorkloadId,
    ManifestHash,
    SiteId,
    Mode,
}

impl SamplingSeedField {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TraceId => "trace_id",
            Self::WorkloadId => "workload_id",
            Self::ManifestHash => "manifest_hash",
            Self::SiteId => "site_id",
            Self::Mode => "mode",
        }
    }
}

impl fmt::Display for SamplingSeedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level channel policy for engine telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineObservabilityChannelPolicy {
    pub schema_version: String,
    pub required_lossless_families: Vec<PayloadFamily>,
    pub approximate_allowed_families: Vec<PayloadFamily>,
    pub redaction_must_precede_sampling: bool,
    pub required_structured_log_fields: Vec<String>,
    pub exported_artifacts: Vec<String>,
}

/// Mode-level policy row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorModePolicy {
    pub mode: ObservabilityMode,
    pub precedence: u8,
    pub approximate_allowed: bool,
    pub lossless_required: bool,
    pub requires_calibration: bool,
    pub description: String,
}

/// Contract defining precedence and semantics for operator-visible modes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorModeContract {
    pub schema_version: String,
    pub modes: Vec<OperatorModePolicy>,
}

impl OperatorModeContract {
    pub fn precedence_of(&self, mode: ObservabilityMode) -> Option<u8> {
        self.modes
            .iter()
            .find(|entry| entry.mode == mode)
            .map(|entry| entry.precedence)
    }
}

/// Site-level policy row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySitePolicy {
    pub site_id: String,
    pub component: String,
    pub family: PayloadFamily,
    pub default_mode: ObservabilityMode,
    pub allowed_modes: Vec<ObservabilityMode>,
    pub allowed_sketch_families: Vec<SketchFamily>,
    pub lossless_required: bool,
    pub requires_redaction: bool,
    pub distortion_budget_millionths: i64,
}

/// Matrix of site-level telemetry policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySitePolicyMatrix {
    pub schema_version: String,
    pub sites: Vec<TelemetrySitePolicy>,
}

impl TelemetrySitePolicyMatrix {
    pub fn site(&self, site_id: &str) -> Option<&TelemetrySitePolicy> {
        self.sites.iter().find(|site| site.site_id == site_id)
    }
}

/// Sampling rule for a telemetry site.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySamplingRule {
    pub site_id: String,
    pub strategy: SamplingStrategy,
    pub base_interval: u64,
    pub max_burst_samples: u64,
    pub seed_fields: Vec<SamplingSeedField>,
    pub precision_target_millionths: i64,
    pub replay_stable: bool,
}

/// Contract defining deterministic sampling rules for the engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySamplingContract {
    pub schema_version: String,
    pub rules: Vec<TelemetrySamplingRule>,
}

impl TelemetrySamplingContract {
    pub fn rule_for(&self, site_id: &str) -> Option<&TelemetrySamplingRule> {
        self.rules.iter().find(|rule| rule.site_id == site_id)
    }
}

/// Error envelope for one approximate sketch family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SketchErrorEnvelope {
    pub sketch_family: SketchFamily,
    pub family: PayloadFamily,
    pub bias_bound_millionths: i64,
    pub variance_bound_millionths: i64,
    pub collision_bound_millionths: i64,
    pub quantile_error_bound_millionths: i64,
    pub required_exact_shadow_samples: u64,
}

/// Aggregate sketch error envelope report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SketchErrorEnvelopeReport {
    pub schema_version: String,
    pub envelopes: Vec<SketchErrorEnvelope>,
}

/// Replay-stable sampling fixture for deterministic contract checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingReplayFixture {
    pub fixture_id: String,
    pub trace_id: String,
    pub workload_id: String,
    pub manifest_hash: String,
    pub site_id: String,
    pub mode: ObservabilityMode,
    pub expected_seed_hex: String,
    pub expected_interval: u64,
}

/// Matrix of deterministic sampling fixtures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingSeedReplayFixtureMatrix {
    pub schema_version: String,
    pub fixtures: Vec<SamplingReplayFixture>,
}

/// Derive a replay-stable sampling seed from canonical telemetry context.
pub fn derive_sampling_seed_hex(
    trace_id: &str,
    workload_id: &str,
    manifest_hash: &str,
    site_id: &str,
    mode: ObservabilityMode,
) -> String {
    let canonical = format!(
        "{trace_id}\n{workload_id}\n{manifest_hash}\n{site_id}\n{}",
        mode.as_str()
    );
    hex::encode(Sha256::digest(canonical.as_bytes()))
}

/// Convert a seed into a deterministic capture interval.
pub fn deterministic_sampling_interval(
    seed_hex: &str,
    base_interval: u64,
    max_burst_samples: u64,
) -> u64 {
    if base_interval <= 1 {
        return 1;
    }

    let prefix = seed_hex.get(..16).unwrap_or("0");
    let seed_prefix = u64::from_str_radix(prefix, 16).unwrap_or(0);
    let burst = max_burst_samples.max(1);
    let window = base_interval.saturating_mul(burst);
    let offset = if window == 0 { 0 } else { seed_prefix % window };
    offset / burst + 1
}

/// Resolve the effective observability mode using site policy and precedence.
pub fn resolve_observability_mode(
    site_policy: &TelemetrySitePolicy,
    requested_modes: &[ObservabilityMode],
    mode_contract: &OperatorModeContract,
) -> Option<ObservabilityMode> {
    let candidates = if requested_modes.is_empty() {
        vec![site_policy.default_mode]
    } else {
        requested_modes
            .iter()
            .copied()
            .filter(|mode| site_policy.allowed_modes.contains(mode))
            .collect::<Vec<_>>()
    };

    candidates
        .into_iter()
        .max_by_key(|mode| mode_contract.precedence_of(*mode).unwrap_or(0))
}

/// Canonical engine-level policy for deterministic telemetry contracts.
pub fn canonical_engine_observability_channel_policy() -> EngineObservabilityChannelPolicy {
    EngineObservabilityChannelPolicy {
        schema_version: ENGINE_OBSERVABILITY_CHANNEL_POLICY_SCHEMA_VERSION.to_string(),
        required_lossless_families: vec![
            PayloadFamily::Replay,
            PayloadFamily::Security,
            PayloadFamily::LegalProvenance,
        ],
        approximate_allowed_families: vec![
            PayloadFamily::Decision,
            PayloadFamily::Optimization,
        ],
        redaction_must_precede_sampling: true,
        required_structured_log_fields: vec![
            "trace_id".to_string(),
            "decision_id".to_string(),
            "policy_id".to_string(),
            "component".to_string(),
            "event".to_string(),
            "outcome".to_string(),
            "error_code".to_string(),
            "observability_mode".to_string(),
            "sampling_seed".to_string(),
            "site_id".to_string(),
        ],
        exported_artifacts: vec![
            "engine_observability_channel_policy.json".to_string(),
            "operator_mode_contract.json".to_string(),
            "telemetry_site_policy_matrix.json".to_string(),
            "telemetry_sampling_contract.json".to_string(),
            "sketch_error_envelope_report.json".to_string(),
            "sampling_seed_replay_fixture_matrix.json".to_string(),
        ],
    }
}

/// Canonical mode contract for engine telemetry.
pub fn canonical_operator_mode_contract() -> OperatorModeContract {
    OperatorModeContract {
        schema_version: OPERATOR_MODE_CONTRACT_SCHEMA_VERSION.to_string(),
        modes: vec![
            OperatorModePolicy {
                mode: ObservabilityMode::DefaultCapture,
                precedence: 10,
                approximate_allowed: true,
                lossless_required: false,
                requires_calibration: true,
                description: "Default shipped capture path for declared telemetry sites."
                    .to_string(),
            },
            OperatorModePolicy {
                mode: ObservabilityMode::Degraded,
                precedence: 60,
                approximate_allowed: true,
                lossless_required: false,
                requires_calibration: true,
                description:
                    "Bounded-loss degraded path for approximate families when overhead budgets are tight."
                        .to_string(),
            },
            OperatorModePolicy {
                mode: ObservabilityMode::ExactShadow,
                precedence: 80,
                approximate_allowed: false,
                lossless_required: true,
                requires_calibration: false,
                description:
                    "Exact-shadow validation path used to calibrate approximate telemetry decisions."
                        .to_string(),
            },
            OperatorModePolicy {
                mode: ObservabilityMode::SupportBundleExport,
                precedence: 90,
                approximate_allowed: false,
                lossless_required: true,
                requires_calibration: false,
                description:
                    "Support-bundle export path that forbids silent downsampling during export."
                        .to_string(),
            },
            OperatorModePolicy {
                mode: ObservabilityMode::IncidentFullCapture,
                precedence: 100,
                approximate_allowed: false,
                lossless_required: true,
                requires_calibration: false,
                description:
                    "Incident mode forces full-fidelity capture for replay and operator triage."
                        .to_string(),
            },
        ],
    }
}

/// Canonical telemetry-site matrix for engine observability.
pub fn canonical_telemetry_site_policy_matrix() -> TelemetrySitePolicyMatrix {
    TelemetrySitePolicyMatrix {
        schema_version: TELEMETRY_SITE_POLICY_MATRIX_SCHEMA_VERSION.to_string(),
        sites: vec![
            TelemetrySitePolicy {
                site_id: "runtime_observability.auth_failure_total".to_string(),
                component: "runtime_observability".to_string(),
                family: PayloadFamily::Security,
                default_mode: ObservabilityMode::DefaultCapture,
                allowed_modes: vec![
                    ObservabilityMode::DefaultCapture,
                    ObservabilityMode::ExactShadow,
                    ObservabilityMode::IncidentFullCapture,
                    ObservabilityMode::SupportBundleExport,
                ],
                allowed_sketch_families: Vec::new(),
                lossless_required: true,
                requires_redaction: true,
                distortion_budget_millionths: 0,
            },
            TelemetrySitePolicy {
                site_id: "runtime_observability.capability_denial_total".to_string(),
                component: "runtime_observability".to_string(),
                family: PayloadFamily::Security,
                default_mode: ObservabilityMode::DefaultCapture,
                allowed_modes: vec![
                    ObservabilityMode::DefaultCapture,
                    ObservabilityMode::ExactShadow,
                    ObservabilityMode::IncidentFullCapture,
                    ObservabilityMode::SupportBundleExport,
                ],
                allowed_sketch_families: Vec::new(),
                lossless_required: true,
                requires_redaction: true,
                distortion_budget_millionths: 0,
            },
            TelemetrySitePolicy {
                site_id: "runtime_observability.replay_drop_total".to_string(),
                component: "runtime_observability".to_string(),
                family: PayloadFamily::Replay,
                default_mode: ObservabilityMode::DefaultCapture,
                allowed_modes: vec![
                    ObservabilityMode::DefaultCapture,
                    ObservabilityMode::ExactShadow,
                    ObservabilityMode::IncidentFullCapture,
                    ObservabilityMode::SupportBundleExport,
                ],
                allowed_sketch_families: Vec::new(),
                lossless_required: true,
                requires_redaction: true,
                distortion_budget_millionths: 0,
            },
            TelemetrySitePolicy {
                site_id: "observability_channel_model.decision_lattice".to_string(),
                component: "observability_channel_model".to_string(),
                family: PayloadFamily::Decision,
                default_mode: ObservabilityMode::DefaultCapture,
                allowed_modes: vec![
                    ObservabilityMode::DefaultCapture,
                    ObservabilityMode::Degraded,
                    ObservabilityMode::ExactShadow,
                    ObservabilityMode::IncidentFullCapture,
                    ObservabilityMode::SupportBundleExport,
                ],
                allowed_sketch_families: vec![
                    SketchFamily::CountMin,
                    SketchFamily::HeavyHitter,
                    SketchFamily::NitroSketchWeighted,
                ],
                lossless_required: false,
                requires_redaction: true,
                distortion_budget_millionths: 100_000,
            },
            TelemetrySitePolicy {
                site_id: "entropy_evidence_compressor.optimization_entropy".to_string(),
                component: "entropy_evidence_compressor".to_string(),
                family: PayloadFamily::Optimization,
                default_mode: ObservabilityMode::DefaultCapture,
                allowed_modes: vec![
                    ObservabilityMode::DefaultCapture,
                    ObservabilityMode::Degraded,
                    ObservabilityMode::ExactShadow,
                    ObservabilityMode::IncidentFullCapture,
                    ObservabilityMode::SupportBundleExport,
                ],
                allowed_sketch_families: vec![
                    SketchFamily::CountMin,
                    SketchFamily::HyperLogLog,
                    SketchFamily::Kll,
                    SketchFamily::NitroSketchWeighted,
                ],
                lossless_required: false,
                requires_redaction: true,
                distortion_budget_millionths: 200_000,
            },
            TelemetrySitePolicy {
                site_id: "observability_channel_model.legal_archive".to_string(),
                component: "observability_channel_model".to_string(),
                family: PayloadFamily::LegalProvenance,
                default_mode: ObservabilityMode::DefaultCapture,
                allowed_modes: vec![
                    ObservabilityMode::DefaultCapture,
                    ObservabilityMode::ExactShadow,
                    ObservabilityMode::IncidentFullCapture,
                    ObservabilityMode::SupportBundleExport,
                ],
                allowed_sketch_families: Vec::new(),
                lossless_required: true,
                requires_redaction: true,
                distortion_budget_millionths: 0,
            },
        ],
    }
}

/// Canonical deterministic sampling contract for the engine.
pub fn canonical_telemetry_sampling_contract() -> TelemetrySamplingContract {
    TelemetrySamplingContract {
        schema_version: TELEMETRY_SAMPLING_CONTRACT_SCHEMA_VERSION.to_string(),
        rules: vec![
            TelemetrySamplingRule {
                site_id: "runtime_observability.auth_failure_total".to_string(),
                strategy: SamplingStrategy::DeterministicStride,
                base_interval: 1,
                max_burst_samples: 1,
                seed_fields: vec![
                    SamplingSeedField::TraceId,
                    SamplingSeedField::SiteId,
                    SamplingSeedField::Mode,
                ],
                precision_target_millionths: 0,
                replay_stable: true,
            },
            TelemetrySamplingRule {
                site_id: "runtime_observability.replay_drop_total".to_string(),
                strategy: SamplingStrategy::DeterministicStride,
                base_interval: 1,
                max_burst_samples: 1,
                seed_fields: vec![
                    SamplingSeedField::TraceId,
                    SamplingSeedField::SiteId,
                    SamplingSeedField::Mode,
                ],
                precision_target_millionths: 0,
                replay_stable: true,
            },
            TelemetrySamplingRule {
                site_id: "observability_channel_model.decision_lattice".to_string(),
                strategy: SamplingStrategy::GeometricWeightedSkip,
                base_interval: 16,
                max_burst_samples: 4,
                seed_fields: vec![
                    SamplingSeedField::TraceId,
                    SamplingSeedField::WorkloadId,
                    SamplingSeedField::ManifestHash,
                    SamplingSeedField::SiteId,
                    SamplingSeedField::Mode,
                ],
                precision_target_millionths: 80_000,
                replay_stable: true,
            },
            TelemetrySamplingRule {
                site_id: "entropy_evidence_compressor.optimization_entropy".to_string(),
                strategy: SamplingStrategy::GeometricWeightedSkip,
                base_interval: 32,
                max_burst_samples: 8,
                seed_fields: vec![
                    SamplingSeedField::TraceId,
                    SamplingSeedField::WorkloadId,
                    SamplingSeedField::ManifestHash,
                    SamplingSeedField::SiteId,
                    SamplingSeedField::Mode,
                ],
                precision_target_millionths: 150_000,
                replay_stable: true,
            },
        ],
    }
}

/// Canonical sketch error envelopes for approximate telemetry families.
pub fn canonical_sketch_error_envelope_report() -> SketchErrorEnvelopeReport {
    SketchErrorEnvelopeReport {
        schema_version: SKETCH_ERROR_ENVELOPE_REPORT_SCHEMA_VERSION.to_string(),
        envelopes: vec![
            SketchErrorEnvelope {
                sketch_family: SketchFamily::CountMin,
                family: PayloadFamily::Decision,
                bias_bound_millionths: 40_000,
                variance_bound_millionths: 25_000,
                collision_bound_millionths: 10_000,
                quantile_error_bound_millionths: 0,
                required_exact_shadow_samples: 512,
            },
            SketchErrorEnvelope {
                sketch_family: SketchFamily::HeavyHitter,
                family: PayloadFamily::Decision,
                bias_bound_millionths: 30_000,
                variance_bound_millionths: 20_000,
                collision_bound_millionths: 5_000,
                quantile_error_bound_millionths: 0,
                required_exact_shadow_samples: 512,
            },
            SketchErrorEnvelope {
                sketch_family: SketchFamily::NitroSketchWeighted,
                family: PayloadFamily::Decision,
                bias_bound_millionths: 50_000,
                variance_bound_millionths: 40_000,
                collision_bound_millionths: 15_000,
                quantile_error_bound_millionths: 0,
                required_exact_shadow_samples: 1024,
            },
            SketchErrorEnvelope {
                sketch_family: SketchFamily::HyperLogLog,
                family: PayloadFamily::Optimization,
                bias_bound_millionths: 35_000,
                variance_bound_millionths: 45_000,
                collision_bound_millionths: 20_000,
                quantile_error_bound_millionths: 0,
                required_exact_shadow_samples: 1024,
            },
            SketchErrorEnvelope {
                sketch_family: SketchFamily::Kll,
                family: PayloadFamily::Optimization,
                bias_bound_millionths: 25_000,
                variance_bound_millionths: 35_000,
                collision_bound_millionths: 0,
                quantile_error_bound_millionths: 50_000,
                required_exact_shadow_samples: 1024,
            },
        ],
    }
}

/// Canonical replay fixtures proving deterministic schedule reproduction.
pub fn canonical_sampling_seed_replay_fixture_matrix() -> SamplingSeedReplayFixtureMatrix {
    let fixtures = vec![
        (
            "decision_default_capture",
            "trace-rgc-066a-001",
            "workload-react-dashboard",
            "manifest-optimization-alpha",
            "observability_channel_model.decision_lattice",
            ObservabilityMode::DefaultCapture,
        ),
        (
            "decision_degraded",
            "trace-rgc-066a-002",
            "workload-react-dashboard",
            "manifest-optimization-alpha",
            "observability_channel_model.decision_lattice",
            ObservabilityMode::Degraded,
        ),
        (
            "optimization_exact_shadow",
            "trace-rgc-066a-003",
            "workload-benchmark-suite",
            "manifest-optimization-beta",
            "entropy_evidence_compressor.optimization_entropy",
            ObservabilityMode::ExactShadow,
        ),
        (
            "security_support_bundle",
            "trace-rgc-066a-004",
            "workload-incident-replay",
            "manifest-security-gamma",
            "runtime_observability.auth_failure_total",
            ObservabilityMode::SupportBundleExport,
        ),
    ];
    let sampling_contract = canonical_telemetry_sampling_contract();

    SamplingSeedReplayFixtureMatrix {
        schema_version: SAMPLING_SEED_REPLAY_FIXTURE_MATRIX_SCHEMA_VERSION.to_string(),
        fixtures: fixtures
            .into_iter()
            .map(
                |(fixture_id, trace_id, workload_id, manifest_hash, site_id, mode)| {
                    let seed_hex =
                        derive_sampling_seed_hex(trace_id, workload_id, manifest_hash, site_id, mode);
                    let interval = sampling_contract
                        .rule_for(site_id)
                        .map(|rule| {
                            deterministic_sampling_interval(
                                &seed_hex,
                                rule.base_interval,
                                rule.max_burst_samples,
                            )
                        })
                        .unwrap_or(1);
                    SamplingReplayFixture {
                        fixture_id: fixture_id.to_string(),
                        trace_id: trace_id.to_string(),
                        workload_id: workload_id.to_string(),
                        manifest_hash: manifest_hash.to_string(),
                        site_id: site_id.to_string(),
                        mode,
                        expected_seed_hex: seed_hex,
                        expected_interval: interval,
                    }
                },
            )
            .collect(),
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

    // -- PayloadFamily --

    #[test]
    fn payload_family_all_five() {
        assert_eq!(PayloadFamily::ALL.len(), 5);
    }

    #[test]
    fn payload_family_display() {
        assert_eq!(PayloadFamily::Decision.to_string(), "decision");
        assert_eq!(PayloadFamily::Replay.to_string(), "replay");
        assert_eq!(PayloadFamily::Optimization.to_string(), "optimization");
        assert_eq!(PayloadFamily::Security.to_string(), "security");
        assert_eq!(
            PayloadFamily::LegalProvenance.to_string(),
            "legal_provenance"
        );
    }

    #[test]
    fn payload_family_serde_roundtrip() {
        for fam in PayloadFamily::ALL {
            let json = serde_json::to_string(&fam).unwrap();
            let back: PayloadFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(back, fam);
        }
    }

    // -- DistortionMetric --

    #[test]
    fn distortion_metric_display() {
        assert_eq!(DistortionMetric::Hamming.to_string(), "hamming");
        assert_eq!(DistortionMetric::SquaredError.to_string(), "squared_error");
        assert_eq!(DistortionMetric::LogLoss.to_string(), "log_loss");
        assert_eq!(DistortionMetric::EditDistance.to_string(), "edit_distance");
        assert_eq!(
            DistortionMetric::BinaryFidelity.to_string(),
            "binary_fidelity"
        );
    }

    // -- ChannelPath --

    #[test]
    fn channel_path_all_five() {
        assert_eq!(ChannelPath::ALL.len(), 5);
    }

    #[test]
    fn channel_path_display() {
        assert_eq!(
            ChannelPath::CompilerToLedger.to_string(),
            "compiler_to_ledger"
        );
        assert_eq!(
            ChannelPath::RuntimeToLedger.to_string(),
            "runtime_to_ledger"
        );
    }

    // -- RateDistortionEnvelope --

    #[test]
    fn envelope_rate_at_zero_distortion() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        assert_eq!(env.rate_at_distortion(0), Some(2_000_000));
    }

    #[test]
    fn envelope_rate_interpolation() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        // Midpoint: distortion 50_000 → rate ~1_500_000
        assert_eq!(env.rate_at_distortion(50_000), Some(1_500_000));
    }

    #[test]
    fn envelope_rate_exceeds_max_distortion() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 2_000_000,
            }],
            max_distortion_millionths: 50_000,
            min_rate_millibits: 500_000,
        };
        assert_eq!(env.rate_at_distortion(100_000), None);
    }

    #[test]
    fn envelope_empty_frontier() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        assert_eq!(env.rate_at_distortion(0), None);
    }

    #[test]
    fn envelope_is_achievable() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 2_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 100_000,
                    rate_millibits: 1_000_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        // Above the R(D) curve: achievable.
        assert!(env.is_achievable(2_000_000, 0));
        assert!(env.is_achievable(1_500_000, 50_000));
        // Below the R(D) curve: not achievable.
        assert!(!env.is_achievable(500_000, 0));
        // Beyond max distortion: not achievable.
        assert!(!env.is_achievable(2_000_000, 200_000));
    }

    // -- DistortionRiskLedger --

    #[test]
    fn risk_ledger_interpolation() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "none".to_string(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 100_000,
                    risk_millionths: MILLION,
                    consequence: "max".to_string(),
                },
            ],
        };
        assert_eq!(ledger.risk_at_distortion(0), 0);
        assert_eq!(ledger.risk_at_distortion(50_000), 500_000);
        assert_eq!(ledger.risk_at_distortion(100_000), MILLION);
    }

    #[test]
    fn risk_ledger_empty() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![],
        };
        assert_eq!(ledger.risk_at_distortion(50_000), 0);
    }

    #[test]
    fn risk_ledger_security_binary() {
        let ledgers = canonical_risk_ledgers();
        let sec = ledgers
            .iter()
            .find(|l| l.family == PayloadFamily::Security)
            .unwrap();
        assert_eq!(sec.risk_at_distortion(0), 0);
        assert_eq!(sec.risk_at_distortion(1), MILLION);
    }

    // -- ChannelState --

    #[test]
    fn channel_state_emit_within_budget() {
        let spec = &canonical_channel_specs()[0]; // decision channel
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(spec, 0).is_ok());
        assert_eq!(state.items_emitted, 1);
        assert_eq!(state.buffer_used, 1);
    }

    #[test]
    fn channel_state_emit_rate_exceeded() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.max_items_per_epoch = 2;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(&spec, 0).is_ok());
        assert!(state.emit(&spec, 0).is_ok());
        let result = state.emit(&spec, 0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::UncappedTelemetry
        );
    }

    #[test]
    fn channel_state_backpressure() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.buffer_capacity = 1;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(&spec, 0).is_ok());
        let result = state.emit(&spec, 0);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::BackpressureOverflow
        );
    }

    #[test]
    fn channel_state_drain_releases_buffer() {
        let spec = &canonical_channel_specs()[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        state.emit(spec, 0).unwrap();
        assert_eq!(state.buffer_used, 1);
        state.drain_one();
        assert_eq!(state.buffer_used, 0);
    }

    #[test]
    fn channel_state_lossy_on_lossless_channel() {
        let spec = &canonical_channel_specs()[1]; // replay channel (lossless)
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let result = state.emit(spec, 10_000); // nonzero distortion
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::UnverifiableLoss
        );
    }

    #[test]
    fn channel_state_lossy_on_lossy_channel() {
        let spec = &canonical_channel_specs()[0]; // decision channel (lossy ok)
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.emit(spec, 10_000).is_ok());
    }

    #[test]
    fn channel_state_degradation_tracked() {
        let spec = &canonical_channel_specs()[0]; // degradation threshold 50_000
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // Below threshold.
        state.emit(spec, 40_000).unwrap();
        assert_eq!(state.items_degraded, 0);
        // Above threshold.
        state.emit(spec, 60_000).unwrap();
        assert_eq!(state.items_degraded, 1);
    }

    #[test]
    fn channel_state_drop_budget() {
        let spec = &canonical_channel_specs()[0]; // max_drops = 0
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let result = state.record_drop(spec);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::DropBudgetExceeded
        );
    }

    #[test]
    fn channel_state_drop_budget_with_tolerance() {
        let spec = &canonical_channel_specs()[2]; // optimization: max_drops = 10
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        for _ in 0..10 {
            assert!(state.record_drop(spec).is_ok());
        }
        // 11th drop exceeds budget but fail_closed=false so no error.
        assert!(state.record_drop(spec).is_ok());
    }

    #[test]
    fn channel_state_healthy() {
        let spec = &canonical_channel_specs()[0];
        let state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        assert!(state.is_healthy(spec));
    }

    #[test]
    fn channel_state_unhealthy_after_violation() {
        let spec = &canonical_channel_specs()[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let _ = state.record_drop(spec); // violates drop budget
        assert!(!state.is_healthy(spec));
    }

    // -- Report --

    #[test]
    fn report_all_healthy() {
        let specs = canonical_channel_specs();
        let states = BTreeMap::new();
        let report = generate_report(&specs, &states, epoch(1));
        assert!(report.gate_pass);
        assert_eq!(report.total_violations, 0);
        assert_eq!(report.channels.len(), specs.len());
    }

    #[test]
    fn report_with_violation() {
        let specs = canonical_channel_specs();
        let mut states = BTreeMap::new();
        let mut state = ChannelState::new("ch-decision-ledger".to_string(), epoch(1));
        let _ = state.record_drop(&specs[0]);
        states.insert("ch-decision-ledger".to_string(), state);

        let report = generate_report(&specs, &states, epoch(1));
        assert!(!report.gate_pass);
        assert!(report.total_violations > 0);
    }

    #[test]
    fn report_content_hash_deterministic() {
        let specs = canonical_channel_specs();
        let states = BTreeMap::new();
        let r1 = generate_report(&specs, &states, epoch(1));
        let r2 = generate_report(&specs, &states, epoch(1));
        assert_eq!(r1.content_hash, r2.content_hash);
        assert!(!r1.content_hash.is_empty());
    }

    #[test]
    fn report_schema_version() {
        let specs = canonical_channel_specs();
        let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_summary_format() {
        let specs = canonical_channel_specs();
        let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
        assert!(report.summary.contains("healthy"));
        assert!(report.summary.contains("PASS"));
    }

    #[test]
    fn report_utilization_computed() {
        let specs = canonical_channel_specs();
        let mut states = BTreeMap::new();
        let spec = &specs[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // Emit 1000 items out of 100_000 capacity.
        for _ in 0..1000 {
            state.emit(spec, 0).unwrap();
            state.drain_one();
        }
        states.insert(spec.channel_id.clone(), state);

        let report = generate_report(&specs, &states, epoch(1));
        let entry = report
            .channels
            .iter()
            .find(|e| e.channel_id == "ch-decision-ledger")
            .unwrap();
        assert_eq!(entry.items_emitted, 1000);
        // 1000/100_000 = 10_000 millionths = 1%
        assert_eq!(entry.utilization_millionths, 10_000);
    }

    // -- Canonical specs --

    #[test]
    fn canonical_specs_cover_all_families() {
        let specs = canonical_channel_specs();
        let families: std::collections::BTreeSet<_> = specs.iter().map(|s| s.family).collect();
        for fam in PayloadFamily::ALL {
            assert!(families.contains(&fam), "missing family: {fam}");
        }
    }

    #[test]
    fn canonical_specs_unique_ids() {
        let specs = canonical_channel_specs();
        let ids: std::collections::BTreeSet<_> = specs.iter().map(|s| &s.channel_id).collect();
        assert_eq!(ids.len(), specs.len());
    }

    #[test]
    fn canonical_specs_security_and_legal_are_lossless() {
        let specs = canonical_channel_specs();
        for spec in &specs {
            if spec.family == PayloadFamily::Security
                || spec.family == PayloadFamily::LegalProvenance
            {
                assert!(
                    !spec.lossy_permitted,
                    "{} should be lossless",
                    spec.channel_id
                );
                assert_eq!(
                    spec.envelope.max_distortion_millionths, 0,
                    "{} should have zero max distortion",
                    spec.channel_id,
                );
            }
        }
    }

    #[test]
    fn canonical_specs_replay_is_lossless() {
        let specs = canonical_channel_specs();
        let replay = specs
            .iter()
            .find(|s| s.family == PayloadFamily::Replay)
            .unwrap();
        assert!(!replay.lossy_permitted);
    }

    // -- Serde roundtrips --

    #[test]
    fn channel_spec_serde_roundtrip() {
        let specs = canonical_channel_specs();
        let json = serde_json::to_string(&specs).unwrap();
        let back: Vec<ChannelSpec> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), specs.len());
    }

    #[test]
    fn channel_state_serde_roundtrip() {
        let mut state = ChannelState::new("test".to_string(), epoch(1));
        state.items_emitted = 42;
        let json = serde_json::to_string(&state).unwrap();
        let back: ChannelState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.items_emitted, 42);
    }

    #[test]
    fn channel_report_serde_roundtrip() {
        let specs = canonical_channel_specs();
        let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
        let json = serde_json::to_string(&report).unwrap();
        let back: ChannelReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.gate_pass, report.gate_pass);
        assert_eq!(back.content_hash, report.content_hash);
    }

    #[test]
    fn violation_kind_display() {
        assert_eq!(
            ViolationKind::UncappedTelemetry.to_string(),
            "uncapped_telemetry"
        );
        assert_eq!(
            ViolationKind::UnverifiableLoss.to_string(),
            "unverifiable_loss"
        );
        assert_eq!(
            ViolationKind::DropBudgetExceeded.to_string(),
            "drop_budget_exceeded"
        );
        assert_eq!(
            ViolationKind::DegradationBudgetExceeded.to_string(),
            "degradation_budget_exceeded"
        );
        assert_eq!(
            ViolationKind::BackpressureOverflow.to_string(),
            "backpressure_overflow"
        );
    }

    #[test]
    fn failure_budget_default() {
        let budget = FailureBudget::default();
        assert_eq!(budget.max_drops_per_epoch, 0);
        assert_eq!(budget.max_degraded_per_epoch, 10);
        assert!(budget.fail_closed);
    }

    // -- Enrichment: Display uniqueness via BTreeSet --

    #[test]
    fn payload_family_display_all_unique() {
        let displays: std::collections::BTreeSet<String> =
            PayloadFamily::ALL.iter().map(|f| f.to_string()).collect();
        assert_eq!(displays.len(), PayloadFamily::ALL.len());
    }

    #[test]
    fn channel_path_display_all_unique() {
        let displays: std::collections::BTreeSet<String> =
            ChannelPath::ALL.iter().map(|p| p.to_string()).collect();
        assert_eq!(displays.len(), ChannelPath::ALL.len());
    }

    #[test]
    fn distortion_metric_display_all_unique() {
        let metrics = [
            DistortionMetric::Hamming,
            DistortionMetric::SquaredError,
            DistortionMetric::LogLoss,
            DistortionMetric::EditDistance,
            DistortionMetric::BinaryFidelity,
        ];
        let displays: std::collections::BTreeSet<String> =
            metrics.iter().map(|m| m.to_string()).collect();
        assert_eq!(displays.len(), metrics.len());
    }

    #[test]
    fn violation_kind_serde_roundtrip() {
        let kinds = [
            ViolationKind::UncappedTelemetry,
            ViolationKind::UnverifiableLoss,
            ViolationKind::DropBudgetExceeded,
            ViolationKind::DegradationBudgetExceeded,
            ViolationKind::BackpressureOverflow,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let back: ViolationKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn violation_kind_display_all_unique() {
        let kinds = [
            ViolationKind::UncappedTelemetry,
            ViolationKind::UnverifiableLoss,
            ViolationKind::DropBudgetExceeded,
            ViolationKind::DegradationBudgetExceeded,
            ViolationKind::BackpressureOverflow,
        ];
        let displays: std::collections::BTreeSet<String> =
            kinds.iter().map(|k| k.to_string()).collect();
        assert_eq!(displays.len(), kinds.len());
    }

    #[test]
    fn rate_distortion_envelope_serde_roundtrip() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Security,
            metric: DistortionMetric::BinaryFidelity,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 500_000,
            }],
            max_distortion_millionths: 0,
            min_rate_millibits: 500_000,
        };
        let json = serde_json::to_string(&env).unwrap();
        let back: RateDistortionEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn channel_state_epoch_reset_clears_counters() {
        let spec = &canonical_channel_specs()[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        state.emit(spec, 0).unwrap();
        assert_eq!(state.items_emitted, 1);
        state.epoch_reset(epoch(2));
        assert_eq!(state.items_emitted, 0);
        assert_eq!(state.buffer_used, 0);
        assert_eq!(state.epoch, epoch(2));
    }

    #[test]
    fn report_with_different_states_produces_different_hashes() {
        let specs = canonical_channel_specs();
        let mut states1 = BTreeMap::new();
        let mut states2 = BTreeMap::new();
        let mut s1 = ChannelState::new(specs[0].channel_id.clone(), epoch(1));
        s1.items_emitted = 10;
        states1.insert(specs[0].channel_id.clone(), s1);
        let s2 = ChannelState::new(specs[0].channel_id.clone(), epoch(1));
        states2.insert(specs[0].channel_id.clone(), s2);
        let r1 = generate_report(&specs, &states1, epoch(1));
        let r2 = generate_report(&specs, &states2, epoch(1));
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn channel_spec_clone_equality() {
        let spec = &canonical_channel_specs()[0];
        let cloned = spec.clone();
        assert_eq!(spec, &cloned);
    }

    #[test]
    fn channel_state_clone_equality() {
        let spec = &canonical_channel_specs()[0];
        let state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let cloned = state.clone();
        assert_eq!(state, cloned);
    }

    #[test]
    fn policy_violation_clone_equality() {
        let v = PolicyViolation {
            channel_id: "ch-0".into(),
            violation_kind: ViolationKind::UncappedTelemetry,
            epoch: epoch(1),
            detail: "test".into(),
        };
        let cloned = v.clone();
        assert_eq!(v, cloned);
    }

    #[test]
    fn rate_distortion_point_clone_equality() {
        let p = RateDistortionPoint {
            distortion_millionths: 100_000,
            rate_millibits: 500_000,
        };
        let cloned = p.clone();
        assert_eq!(p, cloned);
    }

    #[test]
    fn failure_budget_clone_equality() {
        let fb = FailureBudget {
            max_drops_per_epoch: 10,
            max_degraded_per_epoch: 50,
            degradation_threshold_millionths: 100_000,
            fail_closed: true,
        };
        let cloned = fb.clone();
        assert_eq!(fb, cloned);
    }

    #[test]
    fn channel_spec_json_field_presence() {
        let spec = &canonical_channel_specs()[0];
        let json = serde_json::to_string(spec).unwrap();
        assert!(json.contains("\"channel_id\""));
        assert!(json.contains("\"max_items_per_epoch\""));
        assert!(json.contains("\"failure_budget\""));
    }

    #[test]
    fn policy_violation_json_field_presence() {
        let v = PolicyViolation {
            channel_id: "ch-0".into(),
            violation_kind: ViolationKind::UncappedTelemetry,
            epoch: epoch(1),
            detail: "d".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("\"channel_id\""));
        assert!(json.contains("\"violation_kind\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"detail\""));
    }

    #[test]
    fn rate_distortion_envelope_json_field_presence() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 500_000,
            }],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 250_000,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"family\""));
        assert!(json.contains("\"metric\""));
        assert!(json.contains("\"frontier\""));
        assert!(json.contains("\"rate_millibits\""));
        assert!(json.contains("\"distortion_millionths\""));
    }

    #[test]
    fn channel_state_fresh_has_zero_counters() {
        let state = ChannelState::new("fresh".into(), epoch(1));
        assert_eq!(state.items_emitted, 0);
        assert_eq!(state.items_dropped, 0);
        assert_eq!(state.items_degraded, 0);
        assert_eq!(state.buffer_used, 0);
        assert!(state.violations.is_empty());
    }

    #[test]
    fn distortion_metric_serde_roundtrip_all() {
        for dm in [
            DistortionMetric::Hamming,
            DistortionMetric::SquaredError,
            DistortionMetric::LogLoss,
            DistortionMetric::EditDistance,
            DistortionMetric::BinaryFidelity,
        ] {
            let json = serde_json::to_string(&dm).unwrap();
            let back: DistortionMetric = serde_json::from_str(&json).unwrap();
            assert_eq!(dm, back);
        }
    }

    #[test]
    fn channel_path_serde_roundtrip_all() {
        for cp in ChannelPath::ALL {
            let json = serde_json::to_string(&cp).unwrap();
            let back: ChannelPath = serde_json::from_str(&json).unwrap();
            assert_eq!(cp, back);
        }
    }

    #[test]
    fn rate_distortion_envelope_clone_equality() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Replay,
            metric: DistortionMetric::Hamming,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 100_000,
                rate_millibits: 500_000,
            }],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 100_000,
        };
        let cloned = env.clone();
        assert_eq!(env, cloned);
    }

    // -- Enrichment batch --

    #[test]
    fn envelope_rate_past_last_frontier_point() {
        // Query distortion between last frontier point and max_distortion should
        // return last frontier point's rate.
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Optimization,
            metric: DistortionMetric::SquaredError,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 0,
                    rate_millibits: 4_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 50_000,
                    rate_millibits: 2_000_000,
                },
            ],
            max_distortion_millionths: 200_000,
            min_rate_millibits: 500_000,
        };
        // 100_000 > 50_000 (last point) but <= 200_000 (max), returns last rate.
        assert_eq!(env.rate_at_distortion(100_000), Some(2_000_000));
        assert_eq!(env.rate_at_distortion(200_000), Some(2_000_000));
    }

    #[test]
    fn envelope_rate_duplicate_distortion_points() {
        // Two frontier points with same distortion: first match has no prev, so
        // returns first point's rate directly.
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![
                RateDistortionPoint {
                    distortion_millionths: 50_000,
                    rate_millibits: 3_000_000,
                },
                RateDistortionPoint {
                    distortion_millionths: 50_000,
                    rate_millibits: 1_500_000,
                },
            ],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        // First point matches (50k >= 50k), prev is None → returns first point rate.
        assert_eq!(env.rate_at_distortion(50_000), Some(3_000_000));
    }

    #[test]
    fn envelope_single_point_frontier_query_below() {
        // Single frontier point at distortion=50k, query at 0 → before first point,
        // first point distortion (50k) >= 0 so returns first point rate with no prev.
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 50_000,
                rate_millibits: 1_000_000,
            }],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        assert_eq!(env.rate_at_distortion(0), Some(1_000_000));
    }

    #[test]
    fn is_achievable_empty_frontier() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![],
            max_distortion_millionths: 100_000,
            min_rate_millibits: 500_000,
        };
        assert!(!env.is_achievable(2_000_000, 0));
    }

    #[test]
    fn is_achievable_exact_boundary_rate() {
        let env = RateDistortionEnvelope {
            family: PayloadFamily::Decision,
            metric: DistortionMetric::LogLoss,
            frontier: vec![RateDistortionPoint {
                distortion_millionths: 0,
                rate_millibits: 1_000_000,
            }],
            max_distortion_millionths: 0,
            min_rate_millibits: 1_000_000,
        };
        // Exactly at frontier: achievable (rate >= min_rate).
        assert!(env.is_achievable(1_000_000, 0));
        // One below: not achievable.
        assert!(!env.is_achievable(999_999, 0));
    }

    #[test]
    fn risk_at_distortion_past_last_entry() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "none".into(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 100_000,
                    risk_millionths: 500_000,
                    consequence: "half".into(),
                },
            ],
        };
        // Beyond last entry: returns last entry's risk.
        assert_eq!(ledger.risk_at_distortion(200_000), 500_000);
    }

    #[test]
    fn risk_at_distortion_single_entry() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Security,
            entries: vec![DistortionRiskEntry {
                distortion_millionths: 50_000,
                risk_millionths: 800_000,
                consequence: "high".into(),
            }],
        };
        // Query below single entry: returns that entry's risk (no prev, first point matches).
        assert_eq!(ledger.risk_at_distortion(0), 800_000);
        // Query at the entry: returns that entry's risk.
        assert_eq!(ledger.risk_at_distortion(50_000), 800_000);
        // Query past: returns last entry's risk.
        assert_eq!(ledger.risk_at_distortion(100_000), 800_000);
    }

    #[test]
    fn risk_at_distortion_duplicate_distortion_entries() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 50_000,
                    risk_millionths: 100_000,
                    consequence: "first".into(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 50_000,
                    risk_millionths: 900_000,
                    consequence: "second".into(),
                },
            ],
        };
        // First entry matches (50k >= 50k), prev is None → returns first entry's risk.
        assert_eq!(ledger.risk_at_distortion(50_000), 100_000);
    }

    #[test]
    fn distortion_risk_ledger_serde_roundtrip() {
        let ledger = DistortionRiskLedger {
            family: PayloadFamily::Decision,
            entries: vec![
                DistortionRiskEntry {
                    distortion_millionths: 0,
                    risk_millionths: 0,
                    consequence: "none".into(),
                },
                DistortionRiskEntry {
                    distortion_millionths: 100_000,
                    risk_millionths: MILLION,
                    consequence: "max".into(),
                },
            ],
        };
        let json = serde_json::to_string(&ledger).unwrap();
        let back: DistortionRiskLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    #[test]
    fn distortion_risk_entry_serde_roundtrip() {
        let entry = DistortionRiskEntry {
            distortion_millionths: 42_000,
            risk_millionths: 750_000,
            consequence: "moderate risk".into(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: DistortionRiskEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn failure_budget_serde_roundtrip() {
        let fb = FailureBudget {
            max_drops_per_epoch: 5,
            max_degraded_per_epoch: 20,
            degradation_threshold_millionths: 200_000,
            fail_closed: false,
        };
        let json = serde_json::to_string(&fb).unwrap();
        let back: FailureBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, back);
    }

    #[test]
    fn drain_one_on_empty_buffer_stays_zero() {
        let mut state = ChannelState::new("ch-test".into(), epoch(1));
        assert_eq!(state.buffer_used, 0);
        state.drain_one();
        assert_eq!(state.buffer_used, 0);
        // Double drain stays at zero.
        state.drain_one();
        assert_eq!(state.buffer_used, 0);
    }

    #[test]
    fn emit_drain_emit_cycle_relieves_backpressure() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.buffer_capacity = 2;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // Fill buffer.
        state.emit(&spec, 0).unwrap();
        state.emit(&spec, 0).unwrap();
        // Buffer full: next emit fails.
        assert!(state.emit(&spec, 0).is_err());
        // Drain one: relieves backpressure.
        state.drain_one();
        assert_eq!(state.buffer_used, 1);
        // Now emit succeeds.
        assert!(state.emit(&spec, 0).is_ok());
        assert_eq!(state.buffer_used, 2);
    }

    #[test]
    fn degradation_at_exact_threshold_not_degraded() {
        // degradation check uses `>` not `>=`, so exactly at threshold is not degraded.
        let spec = &canonical_channel_specs()[0]; // degradation threshold 50_000
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        state.emit(spec, 50_000).unwrap();
        assert_eq!(state.items_degraded, 0);
    }

    #[test]
    fn degradation_budget_exceeded_fail_open() {
        // Optimization channel: fail_closed=false, max_degraded=50, threshold=100_000
        let spec = &canonical_channel_specs()[2];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // Exceed degradation budget: distortion above 100_000 threshold.
        for _ in 0..51 {
            state.emit(spec, 150_000).unwrap();
        }
        // 51 items degraded, budget is 50, but fail_closed=false so all Ok.
        assert_eq!(state.items_degraded, 51);
        // But a violation was recorded.
        assert!(!state.violations.is_empty());
        assert_eq!(
            state.violations.last().unwrap().violation_kind,
            ViolationKind::DegradationBudgetExceeded
        );
    }

    #[test]
    fn degradation_budget_exceeded_fail_closed() {
        // Decision channel: fail_closed=true, max_degraded=5, threshold=50_000
        let spec = &canonical_channel_specs()[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // 5 degraded items within budget.
        for _ in 0..5 {
            state.emit(spec, 60_000).unwrap();
        }
        assert_eq!(state.items_degraded, 5);
        // 6th exceeds budget and fail_closed=true → error.
        let result = state.emit(spec, 60_000);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().violation_kind,
            ViolationKind::DegradationBudgetExceeded
        );
    }

    #[test]
    fn multiple_violations_accumulate() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.buffer_capacity = 1;
        spec.max_items_per_epoch = 100;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // First violation: backpressure (emit fills buffer, second triggers overflow).
        state.emit(&spec, 0).unwrap();
        let _ = state.emit(&spec, 0); // BackpressureOverflow
        assert_eq!(state.violations.len(), 1);
        // Drain so we can try another violation.
        state.drain_one();
        state.drain_one();
        // Record a drop: DropBudgetExceeded (max_drops=0).
        let _ = state.record_drop(&spec);
        assert_eq!(state.violations.len(), 2);
        assert_eq!(
            state.violations[0].violation_kind,
            ViolationKind::BackpressureOverflow
        );
        assert_eq!(
            state.violations[1].violation_kind,
            ViolationKind::DropBudgetExceeded
        );
    }

    #[test]
    fn epoch_reset_clears_violations() {
        let spec = &canonical_channel_specs()[0];
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let _ = state.record_drop(spec); // triggers violation
        assert!(!state.violations.is_empty());
        state.epoch_reset(epoch(2));
        assert!(state.violations.is_empty());
        assert_eq!(state.items_dropped, 0);
    }

    #[test]
    fn emit_violation_detail_contains_rate_cap() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.max_items_per_epoch = 1;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        state.emit(&spec, 0).unwrap();
        let err = state.emit(&spec, 0).unwrap_err();
        assert!(err.detail.contains("rate cap"));
        assert!(err.detail.contains("1")); // the cap value
    }

    #[test]
    fn record_drop_violation_detail_contains_budget() {
        let spec = &canonical_channel_specs()[0]; // max_drops=0
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let err = state.record_drop(spec).unwrap_err();
        assert!(err.detail.contains("drops"));
        assert!(err.detail.contains("exceed budget"));
    }

    #[test]
    fn lossy_emission_violation_detail_contains_distortion() {
        let spec = &canonical_channel_specs()[1]; // lossless replay channel
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        let err = state.emit(spec, 42_000).unwrap_err();
        assert!(err.detail.contains("42000"));
        assert!(err.detail.contains("lossless-only"));
    }

    #[test]
    fn report_empty_specs_passes() {
        let report = generate_report(&[], &BTreeMap::new(), epoch(1));
        assert!(report.gate_pass);
        assert_eq!(report.total_violations, 0);
        assert!(report.channels.is_empty());
        assert!(report.summary.contains("PASS"));
    }

    #[test]
    fn report_summary_contains_fail_on_unhealthy() {
        let specs = canonical_channel_specs();
        let mut states = BTreeMap::new();
        let mut state = ChannelState::new(specs[0].channel_id.clone(), epoch(1));
        let _ = state.record_drop(&specs[0]);
        states.insert(specs[0].channel_id.clone(), state);
        let report = generate_report(&specs, &states, epoch(1));
        assert!(!report.gate_pass);
        assert!(report.summary.contains("FAIL"));
    }

    #[test]
    fn report_utilization_zero_for_zero_capacity_spec() {
        let mut specs = canonical_channel_specs();
        specs[0].max_items_per_epoch = 0;
        let report = generate_report(&specs, &BTreeMap::new(), epoch(1));
        let entry = report
            .channels
            .iter()
            .find(|e| e.channel_id == specs[0].channel_id)
            .unwrap();
        assert_eq!(entry.utilization_millionths, 0);
    }

    #[test]
    fn channel_health_entry_serde_roundtrip() {
        let entry = ChannelHealthEntry {
            channel_id: "ch-test".into(),
            family: PayloadFamily::Security,
            path: ChannelPath::ControlPlaneToAudit,
            items_emitted: 100,
            items_dropped: 2,
            items_degraded: 5,
            utilization_millionths: 10_000,
            healthy: true,
            violation_count: 0,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ChannelHealthEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn canonical_risk_ledgers_cover_decision_and_security() {
        let ledgers = canonical_risk_ledgers();
        assert_eq!(ledgers.len(), 2);
        let families: std::collections::BTreeSet<_> = ledgers.iter().map(|l| l.family).collect();
        assert!(families.contains(&PayloadFamily::Decision));
        assert!(families.contains(&PayloadFamily::Security));
    }

    #[test]
    fn canonical_risk_ledgers_decision_has_three_entries() {
        let ledgers = canonical_risk_ledgers();
        let dec = ledgers
            .iter()
            .find(|l| l.family == PayloadFamily::Decision)
            .unwrap();
        assert_eq!(dec.entries.len(), 3);
    }

    #[test]
    fn payload_family_ordering_is_deterministic() {
        // Ord is derived, so variant order matches declaration order.
        assert!(PayloadFamily::Decision < PayloadFamily::Replay);
        assert!(PayloadFamily::Replay < PayloadFamily::Optimization);
        assert!(PayloadFamily::Optimization < PayloadFamily::Security);
        assert!(PayloadFamily::Security < PayloadFamily::LegalProvenance);
    }

    #[test]
    fn channel_path_ordering_is_deterministic() {
        assert!(ChannelPath::CompilerToLedger < ChannelPath::RuntimeToLedger);
        assert!(ChannelPath::RuntimeToLedger < ChannelPath::ControlPlaneToAudit);
        assert!(ChannelPath::ControlPlaneToAudit < ChannelPath::ReplayToVerifier);
        assert!(ChannelPath::ReplayToVerifier < ChannelPath::ToComplianceArchive);
    }

    #[test]
    fn is_healthy_false_when_drops_exceed_budget() {
        let spec = &canonical_channel_specs()[2]; // optimization: max_drops=10, fail_closed=false
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        // 11 drops exceeds budget.
        for _ in 0..11 {
            let _ = state.record_drop(spec);
        }
        // Violations accumulated; is_healthy checks violations vec.
        assert!(!state.is_healthy(spec));
    }

    #[test]
    fn report_epoch_propagated() {
        let specs = canonical_channel_specs();
        let report = generate_report(&specs, &BTreeMap::new(), epoch(42));
        assert_eq!(report.epoch, epoch(42));
    }

    #[test]
    fn policy_violation_serde_roundtrip() {
        let v = PolicyViolation {
            channel_id: "ch-x".into(),
            epoch: epoch(5),
            violation_kind: ViolationKind::BackpressureOverflow,
            detail: "buffer full".into(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: PolicyViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn distortion_risk_entry_clone_equality() {
        let entry = DistortionRiskEntry {
            distortion_millionths: 50_000,
            risk_millionths: 300_000,
            consequence: "moderate".into(),
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn channel_health_entry_clone_equality() {
        let entry = ChannelHealthEntry {
            channel_id: "ch-test".into(),
            family: PayloadFamily::Replay,
            path: ChannelPath::ReplayToVerifier,
            items_emitted: 0,
            items_dropped: 0,
            items_degraded: 0,
            utilization_millionths: 0,
            healthy: true,
            violation_count: 0,
        };
        let cloned = entry.clone();
        assert_eq!(entry, cloned);
    }

    #[test]
    fn canonical_specs_optimization_is_lossy_permitted() {
        let specs = canonical_channel_specs();
        let opt = specs
            .iter()
            .find(|s| s.family == PayloadFamily::Optimization)
            .unwrap();
        assert!(opt.lossy_permitted);
    }

    #[test]
    fn canonical_specs_all_have_nonempty_tags() {
        let specs = canonical_channel_specs();
        for spec in &specs {
            assert!(
                !spec.tags.is_empty(),
                "{} should have tags",
                spec.channel_id
            );
        }
    }

    #[test]
    fn backpressure_violation_detail_contains_buffer_info() {
        let mut spec = canonical_channel_specs()[0].clone();
        spec.buffer_capacity = 1;
        let mut state = ChannelState::new(spec.channel_id.clone(), epoch(1));
        state.emit(&spec, 0).unwrap();
        let err = state.emit(&spec, 0).unwrap_err();
        assert!(err.detail.contains("buffer full"));
        assert!(err.detail.contains("1")); // capacity
    }
}
