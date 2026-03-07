//! Automatic demotion/rollback mechanism for post-promotion divergence.
//!
//! After a native cell is promoted into a slot, the [`AutoDemotionMonitor`]
//! continuously evaluates demotion triggers against incoming monitoring data.
//! When a trigger fires, the monitor produces a signed [`DemotionReceipt`] and
//! atomically switches the slot back to the previously promoted cell using the
//! `rollback_token` from the original [`ReplacementReceipt`].
//!
//! Trigger categories:
//! - **Semantic divergence**: any output difference not covered by a waiver.
//! - **Performance breach**: sustained degradation below configured thresholds.
//! - **Risk-threshold breach**: sentinel risk score elevation above limit.
//! - **Capability violation**: attempt to exceed the slot's authority envelope.
//!
//! Post-demotion, re-promotion of the same candidate is blocked until a new
//! promotion gate pass succeeds.
//!
//! Plan reference: Section 10.15 item 5 of 9I.6 (`bd-27i1`).
//! Cross-refs: bd-7rwi (ReplacementReceipt + rollback_token), bd-1g5c
//! (promotion gate runner verifies rollback before promotion), bd-kr99
//! (lineage log records demotion events).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::self_replacement::{ReplacementReceipt, SchemaVersion};
use crate::signature_preimage::{self, Signature, SigningKey, VerificationKey};
use crate::slot_registry::SlotId;

// ---------------------------------------------------------------------------
// Schema hash
// ---------------------------------------------------------------------------

fn demotion_receipt_schema_hash() -> crate::deterministic_serde::SchemaHash {
    crate::deterministic_serde::SchemaHash::from_definition(b"self-replacement.demotion-receipt.v1")
}

// ---------------------------------------------------------------------------
// DemotionReason — why a demotion was triggered
// ---------------------------------------------------------------------------

/// Classification of the event that triggered demotion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DemotionReason {
    /// Output difference between native and reference not covered by a waiver.
    SemanticDivergence {
        /// Number of divergent outputs observed.
        divergence_count: u64,
        /// Content hash of the first divergent input/output pair artifact.
        first_divergence_artifact: ContentHash,
    },
    /// Native cell performance degraded below configured threshold for the
    /// required sustained duration.
    PerformanceBreach {
        /// Metric that breached (e.g. "latency_p99_ns", "throughput_ops_sec").
        metric_name: String,
        /// Observed value (fixed-point millionths).
        observed_millionths: u64,
        /// Threshold value (fixed-point millionths).
        threshold_millionths: u64,
        /// Duration the breach was sustained (nanoseconds).
        sustained_duration_ns: u64,
    },
    /// Sentinel risk assessment exceeded configured threshold.
    RiskThresholdBreach {
        /// Observed risk score (fixed-point millionths, 1_000_000 = 1.0).
        observed_risk_millionths: u64,
        /// Configured maximum risk score (fixed-point millionths).
        max_risk_millionths: u64,
    },
    /// Native cell attempted a capability outside its authority envelope.
    CapabilityViolation {
        /// String description of the attempted capability.
        attempted_capability: String,
        /// Authority envelope digest for reference.
        envelope_digest: ContentHash,
    },
    /// Operator-initiated manual demotion.
    OperatorInitiated {
        /// Operator identifier.
        operator_id: String,
        /// Free-form reason text.
        reason: String,
    },
}

impl DemotionReason {
    /// Canonical string tag for the demotion reason category.
    pub fn category(&self) -> &'static str {
        match self {
            Self::SemanticDivergence { .. } => "semantic_divergence",
            Self::PerformanceBreach { .. } => "performance_breach",
            Self::RiskThresholdBreach { .. } => "risk_threshold_breach",
            Self::CapabilityViolation { .. } => "capability_violation",
            Self::OperatorInitiated { .. } => "operator_initiated",
        }
    }

    fn append_canonical_bytes(&self, buf: &mut Vec<u8>) {
        append_length_prefixed_str(buf, self.category());
        match self {
            Self::SemanticDivergence {
                divergence_count,
                first_divergence_artifact,
            } => {
                buf.extend_from_slice(&divergence_count.to_be_bytes());
                buf.extend_from_slice(first_divergence_artifact.as_bytes());
            }
            Self::PerformanceBreach {
                metric_name,
                observed_millionths,
                threshold_millionths,
                sustained_duration_ns,
            } => {
                append_length_prefixed_str(buf, metric_name);
                buf.extend_from_slice(&observed_millionths.to_be_bytes());
                buf.extend_from_slice(&threshold_millionths.to_be_bytes());
                buf.extend_from_slice(&sustained_duration_ns.to_be_bytes());
            }
            Self::RiskThresholdBreach {
                observed_risk_millionths,
                max_risk_millionths,
            } => {
                buf.extend_from_slice(&observed_risk_millionths.to_be_bytes());
                buf.extend_from_slice(&max_risk_millionths.to_be_bytes());
            }
            Self::CapabilityViolation {
                attempted_capability,
                envelope_digest,
            } => {
                append_length_prefixed_str(buf, attempted_capability);
                buf.extend_from_slice(envelope_digest.as_bytes());
            }
            Self::OperatorInitiated {
                operator_id,
                reason,
            } => {
                append_length_prefixed_str(buf, operator_id);
                append_length_prefixed_str(buf, reason);
            }
        }
    }
}

impl fmt::Display for DemotionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SemanticDivergence {
                divergence_count, ..
            } => write!(f, "semantic divergence ({divergence_count} outputs)"),
            Self::PerformanceBreach {
                metric_name,
                observed_millionths,
                threshold_millionths,
                ..
            } => write!(
                f,
                "performance breach: {metric_name} observed={observed_millionths} threshold={threshold_millionths}"
            ),
            Self::RiskThresholdBreach {
                observed_risk_millionths,
                max_risk_millionths,
            } => write!(
                f,
                "risk threshold breach: observed={observed_risk_millionths} max={max_risk_millionths}"
            ),
            Self::CapabilityViolation {
                attempted_capability,
                ..
            } => write!(f, "capability violation: {attempted_capability}"),
            Self::OperatorInitiated { operator_id, .. } => {
                write!(f, "operator-initiated: {operator_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DemotionSeverity — urgency of demotion
// ---------------------------------------------------------------------------

/// Severity level determining rollback urgency and alerting behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DemotionSeverity {
    /// Advisory: log and alert but do not auto-demote.
    Advisory,
    /// Warning: alert operator, schedule demotion if not resolved.
    Warning,
    /// Critical: immediate automatic demotion.
    Critical,
}

impl DemotionSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for DemotionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DemotionEvidence — collected evidence for the demotion
// ---------------------------------------------------------------------------

/// A single piece of evidence supporting a demotion decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionEvidenceItem {
    /// Content hash of the evidence artifact.
    pub artifact_hash: ContentHash,
    /// Category tag for the evidence (e.g. "divergence_trace", "latency_sample").
    pub category: String,
    /// Monotonic timestamp when the evidence was collected (nanoseconds).
    pub collected_at_ns: u64,
    /// Human-readable summary.
    pub summary: String,
}

impl DemotionEvidenceItem {
    fn append_canonical_bytes(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.artifact_hash.as_bytes());
        append_length_prefixed_str(buf, self.category.as_str());
        buf.extend_from_slice(&self.collected_at_ns.to_be_bytes());
        append_length_prefixed_str(buf, self.summary.as_str());
    }
}

fn append_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn append_length_prefixed_str(buf: &mut Vec<u8>, value: &str) {
    append_length_prefixed_bytes(buf, value.as_bytes());
}

// ---------------------------------------------------------------------------
// DemotionReceipt — signed demotion artifact
// ---------------------------------------------------------------------------

/// Signed receipt recording a demotion event.
///
/// Analogous to [`ReplacementReceipt`] for promotions, but records the
/// reverse operation: native cell demoted back to previously promoted cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionReceipt {
    /// Content-addressed receipt identifier.
    pub receipt_id: crate::engine_object_id::EngineObjectId,
    /// Schema version.
    pub schema_version: SchemaVersion,
    /// Slot affected by the demotion.
    pub slot_id: SlotId,
    /// Digest of the demoted native cell.
    pub demoted_cell_digest: String,
    /// Digest of the cell being restored (rollback target).
    pub restored_cell_digest: String,
    /// The rollback token from the original promotion receipt.
    pub rollback_token_used: String,
    /// Reason classification for the demotion.
    pub demotion_reason: DemotionReason,
    /// Severity level.
    pub severity: DemotionSeverity,
    /// Evidence items supporting the demotion.
    pub evidence: Vec<DemotionEvidenceItem>,
    /// Timestamp of the demotion (nanoseconds, monotonic).
    pub timestamp_ns: u64,
    /// Security epoch at demotion time.
    pub epoch: SecurityEpoch,
    /// Zone scoping.
    pub zone: String,
    /// Signature over receipt contents.
    pub signature: Signature,
}

impl DemotionReceipt {
    /// Derive receipt ID from canonical fields.
    pub fn derive_receipt_id(
        slot_id: &SlotId,
        demoted_digest: &str,
        restored_digest: &str,
        timestamp_ns: u64,
        zone: &str,
    ) -> Result<crate::engine_object_id::EngineObjectId, crate::engine_object_id::IdError> {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"demotion|");
        canonical.extend_from_slice(slot_id.as_str().as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(zone.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(demoted_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(restored_digest.as_bytes());
        canonical.push(b'|');
        canonical.extend_from_slice(&timestamp_ns.to_be_bytes());
        let schema_id = crate::engine_object_id::SchemaId::from_definition(
            demotion_receipt_schema_hash().0.as_slice(),
        );
        crate::engine_object_id::derive_id(
            crate::engine_object_id::ObjectDomain::CheckpointArtifact,
            zone,
            &schema_id,
            &canonical,
        )
    }

    /// Create a signed demotion receipt.
    pub fn create_signed(
        signing_key: &SigningKey,
        input: CreateDemotionReceiptInput<'_>,
    ) -> Result<Self, DemotionError> {
        let receipt_id = Self::derive_receipt_id(
            input.slot_id,
            input.demoted_cell_digest,
            input.restored_cell_digest,
            input.timestamp_ns,
            input.zone,
        )
        .map_err(DemotionError::IdDerivationFailed)?;

        let preimage_bytes = Self::compute_preimage_bytes(
            SchemaVersion::V1,
            &receipt_id,
            input.slot_id,
            input.demoted_cell_digest,
            input.restored_cell_digest,
            input.rollback_token_used,
            input.demotion_reason,
            input.severity,
            input.evidence,
            input.timestamp_ns,
            input.epoch,
            input.zone,
        );

        let sig = signature_preimage::sign_preimage(signing_key, &preimage_bytes)
            .map_err(DemotionError::SignatureFailed)?;

        Ok(Self {
            receipt_id,
            schema_version: SchemaVersion::V1,
            slot_id: input.slot_id.clone(),
            demoted_cell_digest: input.demoted_cell_digest.to_string(),
            restored_cell_digest: input.restored_cell_digest.to_string(),
            rollback_token_used: input.rollback_token_used.to_string(),
            demotion_reason: input.demotion_reason.clone(),
            severity: input.severity,
            evidence: input.evidence.to_vec(),
            timestamp_ns: input.timestamp_ns,
            epoch: input.epoch,
            zone: input.zone.to_string(),
            signature: sig,
        })
    }

    /// Verify the receipt signature.
    pub fn verify_signature(&self, vk: &VerificationKey) -> Result<(), DemotionError> {
        let preimage_bytes = Self::compute_preimage_bytes(
            self.schema_version,
            &self.receipt_id,
            &self.slot_id,
            &self.demoted_cell_digest,
            &self.restored_cell_digest,
            &self.rollback_token_used,
            &self.demotion_reason,
            self.severity,
            &self.evidence,
            self.timestamp_ns,
            self.epoch,
            &self.zone,
        );

        signature_preimage::verify_signature(vk, &preimage_bytes, &self.signature).map_err(|_| {
            DemotionError::SignatureInvalid {
                receipt_id: format!("{}", self.receipt_id),
            }
        })
    }

    /// Compute the canonical preimage bytes for signing/verification.
    #[allow(clippy::too_many_arguments)]
    fn compute_preimage_bytes(
        schema_version: SchemaVersion,
        receipt_id: &crate::engine_object_id::EngineObjectId,
        slot_id: &SlotId,
        demoted_digest: &str,
        restored_digest: &str,
        rollback_token: &str,
        reason: &DemotionReason,
        severity: DemotionSeverity,
        evidence: &[DemotionEvidenceItem],
        timestamp_ns: u64,
        epoch: SecurityEpoch,
        zone: &str,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"demotion-receipt-v1|");
        append_length_prefixed_str(&mut buf, &schema_version.to_string());
        append_length_prefixed_bytes(&mut buf, receipt_id.as_bytes());
        append_length_prefixed_str(&mut buf, slot_id.as_str());
        append_length_prefixed_str(&mut buf, demoted_digest);
        append_length_prefixed_str(&mut buf, restored_digest);
        append_length_prefixed_str(&mut buf, rollback_token);
        reason.append_canonical_bytes(&mut buf);
        append_length_prefixed_str(&mut buf, severity.as_str());
        buf.extend_from_slice(&timestamp_ns.to_be_bytes());
        buf.extend_from_slice(&epoch.as_u64().to_be_bytes());
        append_length_prefixed_str(&mut buf, zone);
        buf.extend_from_slice(&(evidence.len() as u64).to_be_bytes());
        for item in evidence {
            item.append_canonical_bytes(&mut buf);
        }
        buf
    }

    /// Content hash of this receipt for lineage-log chaining.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Self::compute_preimage_bytes(
            self.schema_version,
            &self.receipt_id,
            &self.slot_id,
            &self.demoted_cell_digest,
            &self.restored_cell_digest,
            &self.rollback_token_used,
            &self.demotion_reason,
            self.severity,
            &self.evidence,
            self.timestamp_ns,
            self.epoch,
            &self.zone,
        );
        buf.extend_from_slice(&self.signature.to_bytes());
        ContentHash::compute(&buf)
    }
}

/// Input for creating a demotion receipt.
pub struct CreateDemotionReceiptInput<'a> {
    pub slot_id: &'a SlotId,
    pub demoted_cell_digest: &'a str,
    pub restored_cell_digest: &'a str,
    pub rollback_token_used: &'a str,
    pub demotion_reason: &'a DemotionReason,
    pub severity: DemotionSeverity,
    pub evidence: &'a [DemotionEvidenceItem],
    pub timestamp_ns: u64,
    pub epoch: SecurityEpoch,
    pub zone: &'a str,
}

// ---------------------------------------------------------------------------
// DemotionPolicy — configurable demotion thresholds
// ---------------------------------------------------------------------------

/// Performance threshold configuration for a single metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceThreshold {
    /// Metric name (e.g. "latency_p99_ns").
    pub metric_name: String,
    /// Maximum acceptable value (fixed-point millionths).
    pub max_value_millionths: u64,
    /// Minimum required sustained duration before triggering (nanoseconds).
    pub sustained_duration_ns: u64,
}

/// Configurable demotion policy for a slot.
///
/// Defines the thresholds and severity mappings for each demotion trigger
/// category. Each trigger can be individually enabled/disabled and mapped
/// to a severity level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionPolicy {
    /// Slot this policy applies to.
    pub slot_id: SlotId,
    /// Whether semantic divergence triggers are enabled.
    pub semantic_divergence_enabled: bool,
    /// Severity for semantic divergence. Defaults to Critical.
    pub semantic_divergence_severity: DemotionSeverity,
    /// Maximum allowed divergence count before triggering (0 = any divergence).
    pub max_divergence_count: u64,
    /// Whether performance breach triggers are enabled.
    pub performance_breach_enabled: bool,
    /// Severity for performance breach. Defaults to Warning.
    pub performance_breach_severity: DemotionSeverity,
    /// Per-metric performance thresholds.
    pub performance_thresholds: Vec<PerformanceThreshold>,
    /// Whether risk-threshold triggers are enabled.
    pub risk_threshold_enabled: bool,
    /// Severity for risk-threshold breach. Defaults to Critical.
    pub risk_threshold_severity: DemotionSeverity,
    /// Maximum acceptable risk score (fixed-point millionths).
    pub max_risk_millionths: u64,
    /// Whether capability-violation triggers are enabled.
    pub capability_violation_enabled: bool,
    /// Severity for capability violation. Defaults to Critical.
    pub capability_violation_severity: DemotionSeverity,
    /// Burn-in period after promotion during which monitoring is active (ns).
    /// After burn-in, monitoring may be relaxed per operator policy.
    pub burn_in_duration_ns: u64,
    /// Maximum allowed rollback latency (nanoseconds).
    pub max_rollback_latency_ns: u64,
    /// Set of candidate digests blocked from re-promotion.
    pub blocked_candidates: BTreeSet<String>,
}

impl DemotionPolicy {
    /// Create a default strict policy for a slot.
    pub fn strict(slot_id: SlotId) -> Self {
        Self {
            slot_id,
            semantic_divergence_enabled: true,
            semantic_divergence_severity: DemotionSeverity::Critical,
            max_divergence_count: 0,
            performance_breach_enabled: true,
            performance_breach_severity: DemotionSeverity::Warning,
            performance_thresholds: Vec::new(),
            risk_threshold_enabled: true,
            risk_threshold_severity: DemotionSeverity::Critical,
            max_risk_millionths: 800_000, // 0.8 risk score
            capability_violation_enabled: true,
            capability_violation_severity: DemotionSeverity::Critical,
            burn_in_duration_ns: 300_000_000_000,   // 5 minutes
            max_rollback_latency_ns: 1_000_000_000, // 1 second
            blocked_candidates: BTreeSet::new(),
        }
    }

    /// Whether a candidate is blocked from re-promotion.
    pub fn is_candidate_blocked(&self, candidate_digest: &str) -> bool {
        self.blocked_candidates.contains(candidate_digest)
    }

    /// Block a candidate from re-promotion.
    pub fn block_candidate(&mut self, candidate_digest: String) {
        self.blocked_candidates.insert(candidate_digest);
    }

    /// Unblock a candidate (e.g. after a new gate pass).
    pub fn unblock_candidate(&mut self, candidate_digest: &str) -> bool {
        self.blocked_candidates.remove(candidate_digest)
    }
}

// ---------------------------------------------------------------------------
// MonitoringObservation — data fed into the monitor
// ---------------------------------------------------------------------------

/// A single monitoring observation fed to the demotion monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitoringObservation {
    /// Output comparison between native and reference.
    OutputComparison {
        /// Whether outputs matched.
        matched: bool,
        /// Input hash for the test case.
        input_hash: ContentHash,
        /// Output hash from the native cell.
        native_output_hash: ContentHash,
        /// Output hash from the reference cell.
        reference_output_hash: ContentHash,
        /// Whether this divergence is covered by a platform-difference waiver.
        waiver_covered: bool,
        /// Timestamp (nanoseconds).
        timestamp_ns: u64,
    },
    /// Performance metric sample.
    PerformanceSample {
        /// Metric name.
        metric_name: String,
        /// Observed value (fixed-point millionths).
        value_millionths: u64,
        /// Timestamp (nanoseconds).
        timestamp_ns: u64,
    },
    /// Risk score update from sentinel.
    RiskScoreUpdate {
        /// Current risk score (fixed-point millionths).
        risk_millionths: u64,
        /// Timestamp (nanoseconds).
        timestamp_ns: u64,
    },
    /// Capability usage event.
    CapabilityEvent {
        /// Capability that was attempted.
        capability: String,
        /// Whether the capability is within the authority envelope.
        within_envelope: bool,
        /// Envelope digest for reference.
        envelope_digest: ContentHash,
        /// Timestamp (nanoseconds).
        timestamp_ns: u64,
    },
}

impl MonitoringObservation {
    /// Extract the timestamp from any observation variant.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            Self::OutputComparison { timestamp_ns, .. }
            | Self::PerformanceSample { timestamp_ns, .. }
            | Self::RiskScoreUpdate { timestamp_ns, .. }
            | Self::CapabilityEvent { timestamp_ns, .. } => *timestamp_ns,
        }
    }
}

// ---------------------------------------------------------------------------
// TriggerEvaluation — result of evaluating a single trigger
// ---------------------------------------------------------------------------

/// Result of evaluating a single demotion trigger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriggerEvaluation {
    /// Whether this trigger fired.
    pub fired: bool,
    /// The demotion reason if fired.
    pub reason: Option<DemotionReason>,
    /// Severity if fired.
    pub severity: DemotionSeverity,
    /// Evidence items collected for this trigger.
    pub evidence: Vec<DemotionEvidenceItem>,
}

// ---------------------------------------------------------------------------
// MonitorState — internal state of the demotion monitor
// ---------------------------------------------------------------------------

/// Accumulated state for performance breach detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PerformanceBreachState {
    /// Metric name.
    metric_name: String,
    /// Timestamp when the breach condition first started (nanoseconds).
    breach_start_ns: Option<u64>,
    /// Most recent observed value (millionths).
    last_value_millionths: u64,
    /// Most recent timestamp.
    last_timestamp_ns: u64,
}

/// Internal state of the auto-demotion monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorState {
    /// Slot being monitored.
    slot_id: SlotId,
    /// Digest of the currently promoted native cell.
    native_cell_digest: String,
    /// Digest of the previous (rollback target) cell.
    previous_cell_digest: String,
    /// Rollback token from the promotion receipt.
    rollback_token: String,
    /// Timestamp when monitoring started (nanoseconds).
    monitoring_start_ns: u64,
    /// Running count of unwaived semantic divergences.
    divergence_count: u64,
    /// Content hash of the first divergence artifact (if any).
    first_divergence_artifact: Option<ContentHash>,
    /// Per-metric performance breach tracking.
    performance_breach_states: Vec<PerformanceBreachState>,
    /// Most recent risk score.
    latest_risk_millionths: u64,
    /// Total observations processed.
    observations_processed: u64,
    /// Whether a demotion has already been triggered.
    demotion_triggered: bool,
}

// ---------------------------------------------------------------------------
// AutoDemotionMonitor — the main demotion evaluation engine
// ---------------------------------------------------------------------------

/// Automatic demotion monitor that evaluates observations against policy.
///
/// Constructed from a promotion receipt and demotion policy. Feed monitoring
/// observations via [`process_observation`] and check for triggered demotions.
///
/// The monitor is deterministic: identical observation sequences produce
/// identical trigger evaluations regardless of wall-clock time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoDemotionMonitor {
    /// Demotion policy configuration.
    policy: DemotionPolicy,
    /// Internal monitoring state.
    state: MonitorState,
}

/// Result from processing a single observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationResult {
    /// Whether any demotion trigger fired on this observation.
    pub trigger_fired: bool,
    /// If a trigger fired, the evaluation details.
    pub evaluation: Option<TriggerEvaluation>,
    /// Total observations processed so far.
    pub observations_processed: u64,
}

impl AutoDemotionMonitor {
    /// Create a new monitor from a promotion receipt and policy.
    pub fn new(
        promotion_receipt: &ReplacementReceipt,
        policy: DemotionPolicy,
        monitoring_start_ns: u64,
    ) -> Result<Self, DemotionError> {
        if policy.slot_id != promotion_receipt.slot_id {
            return Err(DemotionError::SlotMismatch {
                expected: policy.slot_id.as_str().to_string(),
                got: promotion_receipt.slot_id.as_str().to_string(),
            });
        }

        let state = MonitorState {
            slot_id: promotion_receipt.slot_id.clone(),
            native_cell_digest: promotion_receipt.new_cell_digest.clone(),
            previous_cell_digest: promotion_receipt.old_cell_digest.clone(),
            rollback_token: promotion_receipt.rollback_token.clone(),
            monitoring_start_ns,
            divergence_count: 0,
            first_divergence_artifact: None,
            performance_breach_states: policy
                .performance_thresholds
                .iter()
                .map(|t| PerformanceBreachState {
                    metric_name: t.metric_name.clone(),
                    breach_start_ns: None,
                    last_value_millionths: 0,
                    last_timestamp_ns: monitoring_start_ns,
                })
                .collect(),
            latest_risk_millionths: 0,
            observations_processed: 0,
            demotion_triggered: false,
        };

        Ok(Self { policy, state })
    }

    /// Process a monitoring observation and check for trigger activation.
    pub fn process_observation(
        &mut self,
        observation: &MonitoringObservation,
    ) -> ObservationResult {
        self.state.observations_processed += 1;

        if self.state.demotion_triggered {
            return ObservationResult {
                trigger_fired: false,
                evaluation: None,
                observations_processed: self.state.observations_processed,
            };
        }

        let evaluation = match observation {
            MonitoringObservation::OutputComparison { .. } => {
                self.evaluate_semantic_divergence(observation)
            }
            MonitoringObservation::PerformanceSample { .. } => {
                self.evaluate_performance_breach(observation)
            }
            MonitoringObservation::RiskScoreUpdate { .. } => {
                self.evaluate_risk_threshold(observation)
            }
            MonitoringObservation::CapabilityEvent { .. } => {
                self.evaluate_capability_violation(observation)
            }
        };

        let trigger_fired = evaluation.fired;
        if trigger_fired {
            self.state.demotion_triggered = true;
        }

        ObservationResult {
            trigger_fired,
            evaluation: if trigger_fired {
                Some(evaluation)
            } else {
                None
            },
            observations_processed: self.state.observations_processed,
        }
    }

    /// Whether a demotion has been triggered.
    pub fn is_demotion_triggered(&self) -> bool {
        self.state.demotion_triggered
    }

    /// Whether we are still in the burn-in period.
    pub fn is_burn_in(&self, current_ns: u64) -> bool {
        current_ns.saturating_sub(self.state.monitoring_start_ns) < self.policy.burn_in_duration_ns
    }

    /// Current slot ID.
    pub fn slot_id(&self) -> &SlotId {
        &self.state.slot_id
    }

    /// Digest of the native cell being monitored.
    pub fn native_cell_digest(&self) -> &str {
        &self.state.native_cell_digest
    }

    /// Digest of the rollback-target cell.
    pub fn previous_cell_digest(&self) -> &str {
        &self.state.previous_cell_digest
    }

    /// Rollback token for executing the demotion.
    pub fn rollback_token(&self) -> &str {
        &self.state.rollback_token
    }

    /// Total observations processed.
    pub fn observations_processed(&self) -> u64 {
        self.state.observations_processed
    }

    /// Current count of unwaived divergences.
    pub fn divergence_count(&self) -> u64 {
        self.state.divergence_count
    }

    /// Latest risk score.
    pub fn latest_risk_millionths(&self) -> u64 {
        self.state.latest_risk_millionths
    }

    /// Access the current policy.
    pub fn policy(&self) -> &DemotionPolicy {
        &self.policy
    }

    // --- Private evaluation methods ---

    fn evaluate_semantic_divergence(
        &mut self,
        observation: &MonitoringObservation,
    ) -> TriggerEvaluation {
        let no_fire = TriggerEvaluation {
            fired: false,
            reason: None,
            severity: self.policy.semantic_divergence_severity,
            evidence: Vec::new(),
        };

        if !self.policy.semantic_divergence_enabled {
            return no_fire;
        }

        let (matched, input_hash, native_hash, reference_hash, waiver_covered, ts) =
            match observation {
                MonitoringObservation::OutputComparison {
                    matched,
                    input_hash,
                    native_output_hash,
                    reference_output_hash,
                    waiver_covered,
                    timestamp_ns,
                } => (
                    *matched,
                    input_hash,
                    native_output_hash,
                    reference_output_hash,
                    *waiver_covered,
                    *timestamp_ns,
                ),
                _ => return no_fire,
            };

        if matched || waiver_covered {
            return no_fire;
        }

        // Unwaived divergence
        self.state.divergence_count += 1;
        if self.state.first_divergence_artifact.is_none() {
            // Use input hash as the artifact reference
            self.state.first_divergence_artifact = Some(input_hash.clone());
        }

        let artifact_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(input_hash.as_bytes());
            buf.push(b'|');
            buf.extend_from_slice(native_hash.as_bytes());
            buf.push(b'|');
            buf.extend_from_slice(reference_hash.as_bytes());
            ContentHash::compute(&buf)
        };

        if self.state.divergence_count >= self.policy.max_divergence_count {
            let first_artifact = self
                .state
                .first_divergence_artifact
                .clone()
                .unwrap_or_else(|| ContentHash::compute(b"unknown"));

            TriggerEvaluation {
                fired: true,
                reason: Some(DemotionReason::SemanticDivergence {
                    divergence_count: self.state.divergence_count,
                    first_divergence_artifact: first_artifact,
                }),
                severity: self.policy.semantic_divergence_severity,
                evidence: vec![DemotionEvidenceItem {
                    artifact_hash,
                    category: "divergence_trace".to_string(),
                    collected_at_ns: ts,
                    summary: format!(
                        "divergence #{} on slot {}",
                        self.state.divergence_count,
                        self.state.slot_id.as_str()
                    ),
                }],
            }
        } else {
            no_fire
        }
    }

    fn evaluate_performance_breach(
        &mut self,
        observation: &MonitoringObservation,
    ) -> TriggerEvaluation {
        let no_fire = TriggerEvaluation {
            fired: false,
            reason: None,
            severity: self.policy.performance_breach_severity,
            evidence: Vec::new(),
        };

        if !self.policy.performance_breach_enabled {
            return no_fire;
        }

        let (metric_name, value, ts) = match observation {
            MonitoringObservation::PerformanceSample {
                metric_name,
                value_millionths,
                timestamp_ns,
            } => (metric_name.as_str(), *value_millionths, *timestamp_ns),
            _ => return no_fire,
        };

        // Find matching threshold
        let threshold_config = self
            .policy
            .performance_thresholds
            .iter()
            .find(|t| t.metric_name == metric_name);

        let threshold = match threshold_config {
            Some(t) => t,
            None => return no_fire,
        };

        // Find or create breach state for this metric
        let breach_state = self
            .state
            .performance_breach_states
            .iter_mut()
            .find(|s| s.metric_name == metric_name);

        let breach_state = match breach_state {
            Some(s) => s,
            None => {
                self.state
                    .performance_breach_states
                    .push(PerformanceBreachState {
                        metric_name: metric_name.to_string(),
                        breach_start_ns: None,
                        last_value_millionths: value,
                        last_timestamp_ns: ts,
                    });
                self.state.performance_breach_states.last_mut().unwrap()
            }
        };

        breach_state.last_value_millionths = value;
        breach_state.last_timestamp_ns = ts;

        if value > threshold.max_value_millionths {
            // Breaching: start or continue tracking
            if breach_state.breach_start_ns.is_none() {
                breach_state.breach_start_ns = Some(ts);
            }

            let sustained = ts.saturating_sub(breach_state.breach_start_ns.unwrap_or(ts));
            if sustained >= threshold.sustained_duration_ns {
                return TriggerEvaluation {
                    fired: true,
                    reason: Some(DemotionReason::PerformanceBreach {
                        metric_name: metric_name.to_string(),
                        observed_millionths: value,
                        threshold_millionths: threshold.max_value_millionths,
                        sustained_duration_ns: sustained,
                    }),
                    severity: self.policy.performance_breach_severity,
                    evidence: vec![DemotionEvidenceItem {
                        artifact_hash: ContentHash::compute(
                            format!("perf|{metric_name}|{value}|{ts}").as_bytes(),
                        ),
                        category: "performance_sample".to_string(),
                        collected_at_ns: ts,
                        summary: format!(
                            "{metric_name}={value} exceeds threshold {} for {sustained}ns",
                            threshold.max_value_millionths
                        ),
                    }],
                };
            }
        } else {
            // Not breaching: reset tracking
            breach_state.breach_start_ns = None;
        }

        no_fire
    }

    fn evaluate_risk_threshold(
        &mut self,
        observation: &MonitoringObservation,
    ) -> TriggerEvaluation {
        let no_fire = TriggerEvaluation {
            fired: false,
            reason: None,
            severity: self.policy.risk_threshold_severity,
            evidence: Vec::new(),
        };

        if !self.policy.risk_threshold_enabled {
            return no_fire;
        }

        let (risk, ts) = match observation {
            MonitoringObservation::RiskScoreUpdate {
                risk_millionths,
                timestamp_ns,
            } => (*risk_millionths, *timestamp_ns),
            _ => return no_fire,
        };

        self.state.latest_risk_millionths = risk;

        if risk > self.policy.max_risk_millionths {
            TriggerEvaluation {
                fired: true,
                reason: Some(DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: risk,
                    max_risk_millionths: self.policy.max_risk_millionths,
                }),
                severity: self.policy.risk_threshold_severity,
                evidence: vec![DemotionEvidenceItem {
                    artifact_hash: ContentHash::compute(format!("risk|{risk}|{ts}").as_bytes()),
                    category: "risk_score".to_string(),
                    collected_at_ns: ts,
                    summary: format!(
                        "risk score {risk} exceeds max {}",
                        self.policy.max_risk_millionths
                    ),
                }],
            }
        } else {
            no_fire
        }
    }

    fn evaluate_capability_violation(
        &mut self,
        observation: &MonitoringObservation,
    ) -> TriggerEvaluation {
        let no_fire = TriggerEvaluation {
            fired: false,
            reason: None,
            severity: self.policy.capability_violation_severity,
            evidence: Vec::new(),
        };

        if !self.policy.capability_violation_enabled {
            return no_fire;
        }

        let (capability, within_envelope, envelope_digest, ts) = match observation {
            MonitoringObservation::CapabilityEvent {
                capability,
                within_envelope,
                envelope_digest,
                timestamp_ns,
            } => (
                capability.as_str(),
                *within_envelope,
                envelope_digest,
                *timestamp_ns,
            ),
            _ => return no_fire,
        };

        if within_envelope {
            return no_fire;
        }

        TriggerEvaluation {
            fired: true,
            reason: Some(DemotionReason::CapabilityViolation {
                attempted_capability: capability.to_string(),
                envelope_digest: envelope_digest.clone(),
            }),
            severity: self.policy.capability_violation_severity,
            evidence: vec![DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(format!("cap|{capability}|{ts}").as_bytes()),
                category: "capability_violation".to_string(),
                collected_at_ns: ts,
                summary: format!("capability violation: {capability}"),
            }],
        }
    }
}

// ---------------------------------------------------------------------------
// DemotionError
// ---------------------------------------------------------------------------

/// Errors from demotion/rollback operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DemotionError {
    /// ID derivation failed.
    IdDerivationFailed(crate::engine_object_id::IdError),
    /// Signature creation or verification failed.
    SignatureFailed(crate::signature_preimage::SignatureError),
    /// Signature verification failed.
    SignatureInvalid { receipt_id: String },
    /// Slot mismatch between policy and receipt.
    SlotMismatch { expected: String, got: String },
    /// Candidate is blocked from re-promotion.
    CandidateBlocked { candidate_digest: String },
    /// Rollback not possible: no previous cell to restore.
    NoPreviousCell { slot_id: String },
    /// Demotion already triggered.
    AlreadyDemoted { slot_id: String },
}

impl fmt::Display for DemotionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdDerivationFailed(e) => write!(f, "id derivation failed: {e}"),
            Self::SignatureFailed(e) => write!(f, "signature error: {e}"),
            Self::SignatureInvalid { receipt_id } => {
                write!(f, "invalid signature on demotion receipt {receipt_id}")
            }
            Self::SlotMismatch { expected, got } => {
                write!(f, "slot mismatch: expected {expected}, got {got}")
            }
            Self::CandidateBlocked { candidate_digest } => {
                write!(
                    f,
                    "candidate {candidate_digest} is blocked from re-promotion"
                )
            }
            Self::NoPreviousCell { slot_id } => {
                write!(f, "no previous cell to restore for slot {slot_id}")
            }
            Self::AlreadyDemoted { slot_id } => {
                write!(f, "demotion already triggered for slot {slot_id}")
            }
        }
    }
}

impl std::error::Error for DemotionError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;
    use crate::security_epoch::SecurityEpoch;
    use crate::self_replacement::{
        CreateReceiptInput, ReplacementReceipt, ValidationArtifactKind, ValidationArtifactRef,
    };
    use crate::signature_preimage::SigningKey;
    use crate::slot_registry::SlotId;

    // --- Test helpers ---

    fn test_slot() -> SlotId {
        SlotId::new("test-slot-001").expect("valid slot id")
    }

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes([42u8; 32])
    }

    fn test_promotion_receipt() -> ReplacementReceipt {
        let artifacts = vec![ValidationArtifactRef {
            kind: ValidationArtifactKind::EquivalenceResult,
            artifact_digest: "equiv-001".to_string(),
            passed: true,
            summary: "all tests passed".to_string(),
        }];

        ReplacementReceipt::create_unsigned(CreateReceiptInput {
            slot_id: &test_slot(),
            old_cell_digest: "old-delegate-digest-aaa",
            new_cell_digest: "new-native-digest-bbb",
            validation_artifacts: &artifacts,
            rollback_token: "rollback-token-xyz",
            promotion_rationale: "gate pass",
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
            zone: "test-zone",
            required_signatures: 0,
        })
        .expect("create receipt")
    }

    fn test_policy() -> DemotionPolicy {
        let mut policy = DemotionPolicy::strict(test_slot());
        policy.performance_thresholds.push(PerformanceThreshold {
            metric_name: "latency_p99_ns".to_string(),
            max_value_millionths: 50_000_000,      // 50ms
            sustained_duration_ns: 10_000_000_000, // 10 seconds
        });
        policy
    }

    fn test_monitor() -> AutoDemotionMonitor {
        let receipt = test_promotion_receipt();
        let policy = test_policy();
        AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create monitor")
    }

    // --- DemotionReceipt tests ---

    #[test]
    fn demotion_receipt_create_and_verify() {
        let key = test_signing_key();
        let evidence = vec![DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"test-evidence"),
            category: "divergence_trace".to_string(),
            collected_at_ns: 2_000_000_000,
            summary: "test divergence".to_string(),
        }];

        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-digest-bbb",
                restored_cell_digest: "old-delegate-digest-aaa",
                rollback_token_used: "rollback-token-xyz",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"divergence-1"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &evidence,
                timestamp_ns: 2_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test-zone",
            },
        )
        .expect("create demotion receipt");

        assert_eq!(receipt.slot_id, test_slot());
        assert_eq!(receipt.demoted_cell_digest, "native-digest-bbb");
        assert_eq!(receipt.restored_cell_digest, "old-delegate-digest-aaa");
        assert_eq!(receipt.severity, DemotionSeverity::Critical);

        // Verify signature
        receipt
            .verify_signature(&key.verification_key())
            .expect("signature should verify");
    }

    #[test]
    fn demotion_receipt_signature_fails_with_wrong_key() {
        let key = test_signing_key();
        let wrong_key = SigningKey::from_bytes([99u8; 32]);

        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-bbb",
                restored_cell_digest: "old-aaa",
                rollback_token_used: "token",
                demotion_reason: &DemotionReason::OperatorInitiated {
                    operator_id: "op-1".to_string(),
                    reason: "test".to_string(),
                },
                severity: DemotionSeverity::Warning,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test-zone",
            },
        )
        .expect("create receipt");

        assert!(
            receipt
                .verify_signature(&wrong_key.verification_key())
                .is_err()
        );
    }

    #[test]
    fn demotion_receipt_content_hash_is_deterministic() {
        let key = test_signing_key();
        let input = CreateDemotionReceiptInput {
            slot_id: &test_slot(),
            demoted_cell_digest: "native-bbb",
            restored_cell_digest: "old-aaa",
            rollback_token_used: "token",
            demotion_reason: &DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 800_000,
            },
            severity: DemotionSeverity::Critical,
            evidence: &[],
            timestamp_ns: 5_000_000_000,
            epoch: SecurityEpoch::from_raw(2),
            zone: "prod",
        };

        let r1 = DemotionReceipt::create_signed(&key, input).expect("create receipt");
        // Re-create with same key to get different signature (since sign has randomness)
        // but content hash should be identical since it doesn't include signature
        let hash1 = r1.content_hash();

        // Content hash depends only on receipt_id, slot_id, digests, timestamp
        // not on the signature itself
        assert_eq!(hash1, r1.content_hash());
    }

    // --- DemotionReason tests ---

    #[test]
    fn demotion_reason_categories() {
        assert_eq!(
            DemotionReason::SemanticDivergence {
                divergence_count: 0,
                first_divergence_artifact: ContentHash::compute(b"x"),
            }
            .category(),
            "semantic_divergence"
        );
        assert_eq!(
            DemotionReason::PerformanceBreach {
                metric_name: "x".to_string(),
                observed_millionths: 0,
                threshold_millionths: 0,
                sustained_duration_ns: 0,
            }
            .category(),
            "performance_breach"
        );
        assert_eq!(
            DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 0,
                max_risk_millionths: 0,
            }
            .category(),
            "risk_threshold_breach"
        );
        assert_eq!(
            DemotionReason::CapabilityViolation {
                attempted_capability: "x".to_string(),
                envelope_digest: ContentHash::compute(b"x"),
            }
            .category(),
            "capability_violation"
        );
        assert_eq!(
            DemotionReason::OperatorInitiated {
                operator_id: "x".to_string(),
                reason: "y".to_string(),
            }
            .category(),
            "operator_initiated"
        );
    }

    // --- DemotionSeverity tests ---

    #[test]
    fn demotion_severity_ordering() {
        assert!(DemotionSeverity::Advisory < DemotionSeverity::Warning);
        assert!(DemotionSeverity::Warning < DemotionSeverity::Critical);
    }

    // --- DemotionPolicy tests ---

    #[test]
    fn policy_strict_defaults() {
        let policy = DemotionPolicy::strict(test_slot());
        assert!(policy.semantic_divergence_enabled);
        assert!(policy.risk_threshold_enabled);
        assert!(policy.capability_violation_enabled);
        assert!(policy.performance_breach_enabled);
        assert_eq!(policy.max_divergence_count, 0);
        assert_eq!(policy.max_risk_millionths, 800_000);
        assert!(policy.blocked_candidates.is_empty());
    }

    #[test]
    fn policy_block_unblock_candidate() {
        let mut policy = DemotionPolicy::strict(test_slot());
        let digest = "candidate-abc".to_string();

        assert!(!policy.is_candidate_blocked(&digest));
        policy.block_candidate(digest.clone());
        assert!(policy.is_candidate_blocked(&digest));
        assert!(policy.unblock_candidate(&digest));
        assert!(!policy.is_candidate_blocked(&digest));
    }

    // --- AutoDemotionMonitor creation tests ---

    #[test]
    fn monitor_creation_with_valid_input() {
        let monitor = test_monitor();
        assert_eq!(monitor.slot_id(), &test_slot());
        assert_eq!(monitor.native_cell_digest(), "new-native-digest-bbb");
        assert_eq!(monitor.previous_cell_digest(), "old-delegate-digest-aaa");
        assert_eq!(monitor.rollback_token(), "rollback-token-xyz");
        assert_eq!(monitor.observations_processed(), 0);
        assert!(!monitor.is_demotion_triggered());
    }

    #[test]
    fn monitor_creation_rejects_slot_mismatch() {
        let receipt = test_promotion_receipt();
        let wrong_policy =
            DemotionPolicy::strict(SlotId::new("wrong-slot").expect("valid slot id"));

        let result = AutoDemotionMonitor::new(&receipt, wrong_policy, 1_000_000_000);
        assert!(result.is_err());
        match result.unwrap_err() {
            DemotionError::SlotMismatch { expected, got } => {
                assert_eq!(expected, "wrong-slot");
                assert_eq!(got, "test-slot-001");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // --- Semantic divergence trigger tests ---

    #[test]
    fn semantic_divergence_fires_on_unwaived_mismatch() {
        let mut monitor = test_monitor();
        // max_divergence_count = 0, so first unwaived mismatch fires

        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"input-1"),
            native_output_hash: ContentHash::compute(b"native-out-1"),
            reference_output_hash: ContentHash::compute(b"ref-out-1"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };

        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        assert!(monitor.is_demotion_triggered());

        let eval = result.evaluation.unwrap();
        assert_eq!(eval.severity, DemotionSeverity::Critical);
        match eval.reason.unwrap() {
            DemotionReason::SemanticDivergence {
                divergence_count, ..
            } => assert_eq!(divergence_count, 1),
            other => panic!("unexpected reason: {other}"),
        }
    }

    #[test]
    fn semantic_divergence_ignores_waived_mismatch() {
        let mut monitor = test_monitor();

        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"input-1"),
            native_output_hash: ContentHash::compute(b"native-1"),
            reference_output_hash: ContentHash::compute(b"ref-1"),
            waiver_covered: true,
            timestamp_ns: 2_000_000_000,
        };

        let result = monitor.process_observation(&obs);
        assert!(!result.trigger_fired);
        assert!(!monitor.is_demotion_triggered());
        assert_eq!(monitor.divergence_count(), 0);
    }

    #[test]
    fn semantic_divergence_ignores_matching_output() {
        let mut monitor = test_monitor();
        let hash = ContentHash::compute(b"same-output");

        let obs = MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"input"),
            native_output_hash: hash.clone(),
            reference_output_hash: hash,
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };

        let result = monitor.process_observation(&obs);
        assert!(!result.trigger_fired);
    }

    #[test]
    fn semantic_divergence_respects_max_count() {
        let receipt = test_promotion_receipt();
        let mut policy = test_policy();
        policy.max_divergence_count = 3; // Trigger on 3rd divergence

        let mut monitor =
            AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create");

        // First divergence: no fire
        let obs1 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"input-1"),
            native_output_hash: ContentHash::compute(b"native-1"),
            reference_output_hash: ContentHash::compute(b"ref-1"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs1).trigger_fired);
        assert_eq!(monitor.divergence_count(), 1);

        // Second divergence: no fire (still within tolerance)
        let obs2 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"input-2"),
            native_output_hash: ContentHash::compute(b"native-2"),
            reference_output_hash: ContentHash::compute(b"ref-2"),
            waiver_covered: false,
            timestamp_ns: 3_000_000_000,
        };
        assert!(!monitor.process_observation(&obs2).trigger_fired);
        assert_eq!(monitor.divergence_count(), 2);

        // Third divergence: fires
        let obs3 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"input-3"),
            native_output_hash: ContentHash::compute(b"native-3"),
            reference_output_hash: ContentHash::compute(b"ref-3"),
            waiver_covered: false,
            timestamp_ns: 4_000_000_000,
        };
        assert!(monitor.process_observation(&obs3).trigger_fired);
        assert!(monitor.is_demotion_triggered());
    }

    // --- Performance breach trigger tests ---

    #[test]
    fn performance_breach_fires_after_sustained_duration() {
        let mut monitor = test_monitor();

        // Start breaching (50ms threshold, need 10s sustained)
        let obs1 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000, // 60ms > 50ms threshold
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs1).trigger_fired);

        // Still breaching, not sustained long enough
        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 70_000_000,
            timestamp_ns: 8_000_000_000, // 6s since breach start
        };
        assert!(!monitor.process_observation(&obs2).trigger_fired);

        // Sustained long enough: fires
        let obs3 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 65_000_000,
            timestamp_ns: 13_000_000_000, // 11s since breach start
        };
        let result = monitor.process_observation(&obs3);
        assert!(result.trigger_fired);
        assert!(monitor.is_demotion_triggered());

        let eval = result.evaluation.unwrap();
        match eval.reason.unwrap() {
            DemotionReason::PerformanceBreach {
                metric_name,
                observed_millionths,
                ..
            } => {
                assert_eq!(metric_name, "latency_p99_ns");
                assert_eq!(observed_millionths, 65_000_000);
            }
            other => panic!("unexpected reason: {other}"),
        }
    }

    #[test]
    fn performance_breach_resets_on_recovery() {
        let mut monitor = test_monitor();

        // Start breaching
        let obs1 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000,
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs1).trigger_fired);

        // Recover below threshold
        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 30_000_000, // Below threshold
            timestamp_ns: 8_000_000_000,
        };
        assert!(!monitor.process_observation(&obs2).trigger_fired);

        // Breach again — but duration counter restarted
        let obs3 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000,
            timestamp_ns: 13_000_000_000,
        };
        assert!(!monitor.process_observation(&obs3).trigger_fired);

        // Not enough sustained time from new breach start
        let obs4 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000,
            timestamp_ns: 20_000_000_000, // 7s from new breach start
        };
        assert!(!monitor.process_observation(&obs4).trigger_fired);
        assert!(!monitor.is_demotion_triggered());
    }

    #[test]
    fn performance_breach_ignores_unknown_metric() {
        let mut monitor = test_monitor();

        let obs = MonitoringObservation::PerformanceSample {
            metric_name: "unknown_metric".to_string(),
            value_millionths: 999_999_999,
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs).trigger_fired);
    }

    // --- Risk threshold trigger tests ---

    #[test]
    fn risk_threshold_fires_above_limit() {
        let mut monitor = test_monitor();

        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 900_000, // 0.9 > 0.8 threshold
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        assert!(monitor.is_demotion_triggered());
        assert_eq!(monitor.latest_risk_millionths(), 900_000);
    }

    #[test]
    fn risk_threshold_passes_below_limit() {
        let mut monitor = test_monitor();

        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 500_000, // 0.5 < 0.8 threshold
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs).trigger_fired);
        assert_eq!(monitor.latest_risk_millionths(), 500_000);
    }

    #[test]
    fn risk_threshold_boundary_does_not_fire() {
        let mut monitor = test_monitor();

        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 800_000, // Exactly at threshold: not above
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs).trigger_fired);
    }

    // --- Capability violation trigger tests ---

    #[test]
    fn capability_violation_fires_on_envelope_breach() {
        let mut monitor = test_monitor();

        let obs = MonitoringObservation::CapabilityEvent {
            capability: "network_send".to_string(),
            within_envelope: false,
            envelope_digest: ContentHash::compute(b"envelope"),
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        assert!(monitor.is_demotion_triggered());

        let eval = result.evaluation.unwrap();
        match eval.reason.unwrap() {
            DemotionReason::CapabilityViolation {
                attempted_capability,
                ..
            } => assert_eq!(attempted_capability, "network_send"),
            other => panic!("unexpected reason: {other}"),
        }
    }

    #[test]
    fn capability_within_envelope_does_not_fire() {
        let mut monitor = test_monitor();

        let obs = MonitoringObservation::CapabilityEvent {
            capability: "fs_read".to_string(),
            within_envelope: true,
            envelope_digest: ContentHash::compute(b"envelope"),
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs).trigger_fired);
    }

    // --- Monitor behavior after demotion ---

    #[test]
    fn monitor_ignores_observations_after_demotion() {
        let mut monitor = test_monitor();

        // Trigger demotion
        let obs1 = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 999_999,
            timestamp_ns: 2_000_000_000,
        };
        assert!(monitor.process_observation(&obs1).trigger_fired);
        assert!(monitor.is_demotion_triggered());

        // Subsequent observations are ignored
        let obs2 = MonitoringObservation::CapabilityEvent {
            capability: "evil".to_string(),
            within_envelope: false,
            envelope_digest: ContentHash::compute(b"x"),
            timestamp_ns: 3_000_000_000,
        };
        let result = monitor.process_observation(&obs2);
        assert!(!result.trigger_fired);
        assert!(result.evaluation.is_none());
    }

    // --- Burn-in period tests ---

    #[test]
    fn burn_in_period_detection() {
        let monitor = test_monitor();
        // monitoring_start_ns = 1_000_000_000, burn_in = 300_000_000_000

        assert!(monitor.is_burn_in(2_000_000_000)); // 1s in
        assert!(monitor.is_burn_in(100_000_000_000)); // 99s in
        assert!(monitor.is_burn_in(300_999_999_999)); // just before end
        assert!(!monitor.is_burn_in(301_000_000_001)); // after burn-in
    }

    // --- Disabled trigger tests ---

    #[test]
    fn disabled_triggers_do_not_fire() {
        let receipt = test_promotion_receipt();
        let mut policy = test_policy();
        policy.semantic_divergence_enabled = false;
        policy.risk_threshold_enabled = false;
        policy.capability_violation_enabled = false;
        policy.performance_breach_enabled = false;

        let mut monitor =
            AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create");

        // None of these should fire
        let obs1 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"x"),
            native_output_hash: ContentHash::compute(b"y"),
            reference_output_hash: ContentHash::compute(b"z"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs1).trigger_fired);

        let obs2 = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 999_999,
            timestamp_ns: 3_000_000_000,
        };
        assert!(!monitor.process_observation(&obs2).trigger_fired);

        let obs3 = MonitoringObservation::CapabilityEvent {
            capability: "evil".to_string(),
            within_envelope: false,
            envelope_digest: ContentHash::compute(b"x"),
            timestamp_ns: 4_000_000_000,
        };
        assert!(!monitor.process_observation(&obs3).trigger_fired);

        assert!(!monitor.is_demotion_triggered());
    }

    // --- Determinism tests ---

    #[test]
    fn identical_observation_sequences_produce_identical_results() {
        let receipt = test_promotion_receipt();
        let policy = test_policy();

        let observations = vec![
            MonitoringObservation::RiskScoreUpdate {
                risk_millionths: 500_000,
                timestamp_ns: 2_000_000_000,
            },
            MonitoringObservation::OutputComparison {
                matched: true,
                input_hash: ContentHash::compute(b"in"),
                native_output_hash: ContentHash::compute(b"out"),
                reference_output_hash: ContentHash::compute(b"out"),
                waiver_covered: false,
                timestamp_ns: 3_000_000_000,
            },
            MonitoringObservation::PerformanceSample {
                metric_name: "latency_p99_ns".to_string(),
                value_millionths: 30_000_000,
                timestamp_ns: 4_000_000_000,
            },
        ];

        let mut m1 = AutoDemotionMonitor::new(&receipt, policy.clone(), 1_000_000_000).expect("m1");
        let mut m2 = AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("m2");

        for obs in &observations {
            let r1 = m1.process_observation(obs);
            let r2 = m2.process_observation(obs);
            assert_eq!(r1.trigger_fired, r2.trigger_fired);
            assert_eq!(r1.observations_processed, r2.observations_processed);
        }

        assert_eq!(m1.divergence_count(), m2.divergence_count());
        assert_eq!(m1.latest_risk_millionths(), m2.latest_risk_millionths());
        assert_eq!(m1.is_demotion_triggered(), m2.is_demotion_triggered());
    }

    // --- MonitoringObservation tests ---

    #[test]
    fn observation_timestamp_extraction() {
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 0,
            timestamp_ns: 42,
        };
        assert_eq!(obs.timestamp_ns(), 42);

        let obs2 = MonitoringObservation::CapabilityEvent {
            capability: String::new(),
            within_envelope: true,
            envelope_digest: ContentHash::compute(b""),
            timestamp_ns: 99,
        };
        assert_eq!(obs2.timestamp_ns(), 99);
    }

    // --- DemotionError display tests ---

    #[test]
    fn demotion_error_display() {
        let err = DemotionError::SlotMismatch {
            expected: "a".to_string(),
            got: "b".to_string(),
        };
        assert!(err.to_string().contains("slot mismatch"));

        let err2 = DemotionError::CandidateBlocked {
            candidate_digest: "abc".to_string(),
        };
        assert!(err2.to_string().contains("blocked"));
    }

    // --- Serialization round-trip tests ---

    #[test]
    fn demotion_receipt_serde_roundtrip() {
        let key = test_signing_key();
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "token",
                demotion_reason: &DemotionReason::CapabilityViolation {
                    attempted_capability: "net_send".to_string(),
                    envelope_digest: ContentHash::compute(b"env"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test",
            },
        )
        .expect("create");

        let json = serde_json::to_string(&receipt).expect("serialize");
        let restored: DemotionReceipt = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(receipt, restored);
    }

    #[test]
    fn demotion_policy_serde_roundtrip() {
        let mut policy = test_policy();
        policy.block_candidate("blocked-digest".to_string());

        let json = serde_json::to_string(&policy).expect("serialize");
        let restored: DemotionPolicy = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(policy, restored);
    }

    #[test]
    fn monitor_state_serde_roundtrip() {
        let mut monitor = test_monitor();
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 500_000,
            timestamp_ns: 2_000_000_000,
        };
        monitor.process_observation(&obs);

        let json = serde_json::to_string(&monitor).expect("serialize");
        let restored: AutoDemotionMonitor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(monitor, restored);
    }

    // -- DemotionReason Display all 5 variants --

    #[test]
    fn demotion_reason_display_all_variants() {
        let reasons = [
            (
                DemotionReason::SemanticDivergence {
                    divergence_count: 3,
                    first_divergence_artifact: ContentHash::compute(b"a"),
                },
                "semantic divergence",
            ),
            (
                DemotionReason::PerformanceBreach {
                    metric_name: "latency".to_string(),
                    observed_millionths: 100,
                    threshold_millionths: 50,
                    sustained_duration_ns: 1000,
                },
                "performance breach",
            ),
            (
                DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: 900_000,
                    max_risk_millionths: 500_000,
                },
                "risk threshold breach",
            ),
            (
                DemotionReason::CapabilityViolation {
                    attempted_capability: "fs.write".to_string(),
                    envelope_digest: ContentHash::compute(b"e"),
                },
                "capability violation",
            ),
            (
                DemotionReason::OperatorInitiated {
                    operator_id: "admin".to_string(),
                    reason: "manual".to_string(),
                },
                "operator-initiated",
            ),
        ];
        for (reason, expected_substr) in reasons {
            let s = reason.to_string();
            assert!(
                s.contains(expected_substr),
                "'{s}' should contain '{expected_substr}'"
            );
        }
    }

    // -- DemotionSeverity Display and as_str --

    #[test]
    fn demotion_severity_display_and_as_str() {
        assert_eq!(DemotionSeverity::Advisory.to_string(), "advisory");
        assert_eq!(DemotionSeverity::Warning.to_string(), "warning");
        assert_eq!(DemotionSeverity::Critical.to_string(), "critical");
        assert_eq!(DemotionSeverity::Advisory.as_str(), "advisory");
        assert_eq!(DemotionSeverity::Warning.as_str(), "warning");
        assert_eq!(DemotionSeverity::Critical.as_str(), "critical");
    }

    // -- DemotionError Display remaining variants --

    #[test]
    fn demotion_error_display_all_variants() {
        let errors: Vec<(DemotionError, &str)> = vec![
            (
                DemotionError::SignatureInvalid {
                    receipt_id: "r-1".to_string(),
                },
                "invalid signature",
            ),
            (
                DemotionError::NoPreviousCell {
                    slot_id: "s-1".to_string(),
                },
                "no previous cell",
            ),
            (
                DemotionError::AlreadyDemoted {
                    slot_id: "s-1".to_string(),
                },
                "already triggered",
            ),
        ];
        for (err, expected_substr) in errors {
            let s = err.to_string();
            assert!(
                s.contains(expected_substr),
                "'{s}' should contain '{expected_substr}'"
            );
        }
    }

    // -- DemotionReason category all 5 --

    #[test]
    fn demotion_reason_category_all_variants() {
        assert_eq!(
            DemotionReason::SemanticDivergence {
                divergence_count: 0,
                first_divergence_artifact: ContentHash::compute(b""),
            }
            .category(),
            "semantic_divergence"
        );
        assert_eq!(
            DemotionReason::PerformanceBreach {
                metric_name: "x".to_string(),
                observed_millionths: 0,
                threshold_millionths: 0,
                sustained_duration_ns: 0,
            }
            .category(),
            "performance_breach"
        );
        assert_eq!(
            DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 0,
                max_risk_millionths: 0,
            }
            .category(),
            "risk_threshold_breach"
        );
        assert_eq!(
            DemotionReason::CapabilityViolation {
                attempted_capability: "x".to_string(),
                envelope_digest: ContentHash::compute(b""),
            }
            .category(),
            "capability_violation"
        );
        assert_eq!(
            DemotionReason::OperatorInitiated {
                operator_id: "x".to_string(),
                reason: "y".to_string(),
            }
            .category(),
            "operator_initiated"
        );
    }

    // -- Serde roundtrips --

    #[test]
    fn demotion_reason_serde_roundtrip() {
        let reasons = vec![
            DemotionReason::SemanticDivergence {
                divergence_count: 3,
                first_divergence_artifact: ContentHash::compute(b"a"),
            },
            DemotionReason::PerformanceBreach {
                metric_name: "latency".to_string(),
                observed_millionths: 100,
                threshold_millionths: 50,
                sustained_duration_ns: 1000,
            },
            DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 500_000,
            },
            DemotionReason::CapabilityViolation {
                attempted_capability: "fs.write".to_string(),
                envelope_digest: ContentHash::compute(b"e"),
            },
            DemotionReason::OperatorInitiated {
                operator_id: "admin".to_string(),
                reason: "manual".to_string(),
            },
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let back: DemotionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(reason, back);
        }
    }

    #[test]
    fn demotion_severity_serde_roundtrip() {
        for sev in [
            DemotionSeverity::Advisory,
            DemotionSeverity::Warning,
            DemotionSeverity::Critical,
        ] {
            let json = serde_json::to_value(sev).unwrap();
            let back: DemotionSeverity = serde_json::from_value(json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn demotion_error_serde_roundtrip() {
        let errors = vec![
            DemotionError::SignatureInvalid {
                receipt_id: "r-1".to_string(),
            },
            DemotionError::SlotMismatch {
                expected: "a".to_string(),
                got: "b".to_string(),
            },
            DemotionError::CandidateBlocked {
                candidate_digest: "abc".to_string(),
            },
            DemotionError::NoPreviousCell {
                slot_id: "s-1".to_string(),
            },
            DemotionError::AlreadyDemoted {
                slot_id: "s-1".to_string(),
            },
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let back: DemotionError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    #[test]
    fn demotion_evidence_item_serde_roundtrip() {
        let item = DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"evidence"),
            category: "divergence_trace".to_string(),
            collected_at_ns: 1_000_000,
            summary: "divergent output".to_string(),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: DemotionEvidenceItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    // -- Observation timestamp for all variants --

    #[test]
    fn observation_timestamp_all_variants() {
        let obs1 = MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"n"),
            reference_output_hash: ContentHash::compute(b"r"),
            waiver_covered: false,
            timestamp_ns: 10,
        };
        assert_eq!(obs1.timestamp_ns(), 10);

        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "latency".to_string(),
            value_millionths: 100,
            timestamp_ns: 20,
        };
        assert_eq!(obs2.timestamp_ns(), 20);
    }

    // -- Policy blocked candidates --

    #[test]
    fn policy_block_and_check_candidate() {
        let mut policy = test_policy();
        assert!(!policy.is_candidate_blocked("some-digest"));
        policy.block_candidate("some-digest".to_string());
        assert!(policy.is_candidate_blocked("some-digest"));
        assert!(!policy.is_candidate_blocked("other-digest"));
    }

    // -- DemotionPolicy strict defaults --

    #[test]
    fn strict_policy_has_all_triggers_enabled() {
        let policy = DemotionPolicy::strict(test_slot());
        assert!(policy.semantic_divergence_enabled);
        assert!(policy.performance_breach_enabled);
        assert!(policy.risk_threshold_enabled);
        assert!(policy.capability_violation_enabled);
    }

    // -----------------------------------------------------------------------
    // Enrichment: remaining serde and edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn monitoring_observation_serde_roundtrip_all_variants() {
        let observations = vec![
            MonitoringObservation::OutputComparison {
                matched: false,
                input_hash: ContentHash::compute(b"in"),
                native_output_hash: ContentHash::compute(b"n"),
                reference_output_hash: ContentHash::compute(b"r"),
                waiver_covered: true,
                timestamp_ns: 100,
            },
            MonitoringObservation::PerformanceSample {
                metric_name: "latency_p99_ns".to_string(),
                value_millionths: 50_000_000,
                timestamp_ns: 200,
            },
            MonitoringObservation::RiskScoreUpdate {
                risk_millionths: 600_000,
                timestamp_ns: 300,
            },
            MonitoringObservation::CapabilityEvent {
                capability: "fs:read".to_string(),
                within_envelope: true,
                envelope_digest: ContentHash::compute(b"env"),
                timestamp_ns: 400,
            },
        ];
        for obs in &observations {
            let json = serde_json::to_string(obs).unwrap();
            let restored: MonitoringObservation = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, obs);
        }
    }

    #[test]
    fn performance_threshold_serde_roundtrip() {
        let pt = PerformanceThreshold {
            metric_name: "throughput_ops_sec".to_string(),
            max_value_millionths: 100_000_000,
            sustained_duration_ns: 5_000_000_000,
        };
        let json = serde_json::to_string(&pt).unwrap();
        let restored: PerformanceThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, pt);
    }

    #[test]
    fn demotion_receipt_content_hash_deterministic() {
        let key = test_signing_key();
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-a",
                restored_cell_digest: "delegate-b",
                rollback_token_used: "token-z",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"div"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test",
            },
        )
        .expect("create");

        let h1 = receipt.content_hash();
        let h2 = receipt.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn demotion_receipt_signature_verifies() {
        let key = test_signing_key();
        let vk = key.verification_key();
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "nat",
                restored_cell_digest: "del",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::OperatorInitiated {
                    operator_id: "admin".to_string(),
                    reason: "manual test".to_string(),
                },
                severity: DemotionSeverity::Warning,
                evidence: &[DemotionEvidenceItem {
                    artifact_hash: ContentHash::compute(b"ev"),
                    category: "manual".to_string(),
                    collected_at_ns: 100,
                    summary: "test evidence".to_string(),
                }],
                timestamp_ns: 2_000_000_000,
                epoch: SecurityEpoch::from_raw(5),
                zone: "prod",
            },
        )
        .expect("create");

        assert!(receipt.verify_signature(&vk).is_ok());

        // Wrong key should fail.
        let wrong_vk = VerificationKey([0xAB; 32]);
        assert!(receipt.verify_signature(&wrong_vk).is_err());
    }

    #[test]
    fn demotion_receipt_derive_id_deterministic() {
        let id1 = DemotionReceipt::derive_receipt_id(
            &test_slot(),
            "native",
            "delegate",
            1_000_000_000,
            "zone-a",
        )
        .unwrap();
        let id2 = DemotionReceipt::derive_receipt_id(
            &test_slot(),
            "native",
            "delegate",
            1_000_000_000,
            "zone-a",
        )
        .unwrap();
        assert_eq!(id1, id2);

        // Different timestamp -> different ID.
        let id3 = DemotionReceipt::derive_receipt_id(
            &test_slot(),
            "native",
            "delegate",
            2_000_000_000,
            "zone-a",
        )
        .unwrap();
        assert_ne!(id1, id3);
    }

    #[test]
    fn policy_unblock_nonexistent_returns_false() {
        let mut policy = DemotionPolicy::strict(test_slot());
        assert!(!policy.unblock_candidate("never-blocked"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: struct serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn trigger_evaluation_serde_roundtrip() {
        let te = TriggerEvaluation {
            fired: true,
            reason: Some(DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 800_000,
            }),
            severity: DemotionSeverity::Critical,
            evidence: vec![DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"risk"),
                category: "risk".to_string(),
                collected_at_ns: 1000,
                summary: "risk breach".to_string(),
            }],
        };
        let json = serde_json::to_string(&te).unwrap();
        let restored: TriggerEvaluation = serde_json::from_str(&json).unwrap();
        assert_eq!(te, restored);
    }

    #[test]
    fn observation_result_serde_roundtrip() {
        let or = ObservationResult {
            trigger_fired: false,
            evaluation: None,
            observations_processed: 10,
        };
        let json = serde_json::to_string(&or).unwrap();
        let restored: ObservationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(or, restored);
    }

    #[test]
    fn auto_demotion_monitor_serde_roundtrip() {
        let monitor = test_monitor();
        let json = serde_json::to_string(&monitor).unwrap();
        let restored: AutoDemotionMonitor = serde_json::from_str(&json).unwrap();
        assert_eq!(monitor, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DemotionError is std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn demotion_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(DemotionError::AlreadyDemoted {
            slot_id: "s".to_string(),
        });
        assert!(!err.to_string().is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: DemotionReason ordering
    // -----------------------------------------------------------------------

    #[test]
    fn demotion_reason_ordering() {
        let a = DemotionReason::SemanticDivergence {
            divergence_count: 1,
            first_divergence_artifact: ContentHash::compute(b"a"),
        };
        let b = DemotionReason::OperatorInitiated {
            operator_id: "op".to_string(),
            reason: "manual".to_string(),
        };
        // SemanticDivergence < OperatorInitiated by enum declaration order
        assert!(a < b);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DemotionSeverity full ordering chain
    // -----------------------------------------------------------------------

    #[test]
    fn demotion_severity_full_ordering_chain() {
        assert!(DemotionSeverity::Advisory < DemotionSeverity::Warning);
        assert!(DemotionSeverity::Warning < DemotionSeverity::Critical);
    }

    // -----------------------------------------------------------------------
    // Enrichment: getter method coverage
    // -----------------------------------------------------------------------

    #[test]
    fn monitor_native_cell_digest_matches_receipt() {
        let monitor = test_monitor();
        let receipt = test_promotion_receipt();
        assert_eq!(monitor.native_cell_digest(), receipt.new_cell_digest);
    }

    #[test]
    fn monitor_previous_cell_digest_matches_receipt() {
        let monitor = test_monitor();
        let receipt = test_promotion_receipt();
        assert_eq!(monitor.previous_cell_digest(), receipt.old_cell_digest);
    }

    #[test]
    fn monitor_rollback_token_matches_receipt() {
        let monitor = test_monitor();
        let receipt = test_promotion_receipt();
        assert_eq!(monitor.rollback_token(), receipt.rollback_token);
    }

    #[test]
    fn monitor_policy_matches_construction() {
        let policy = test_policy();
        let monitor = test_monitor();
        assert_eq!(monitor.policy(), &policy);
    }

    #[test]
    fn monitor_fresh_divergence_count_is_zero() {
        let monitor = test_monitor();
        assert_eq!(monitor.divergence_count(), 0);
    }

    #[test]
    fn monitor_fresh_observations_processed_is_zero() {
        let monitor = test_monitor();
        assert_eq!(monitor.observations_processed(), 0);
    }

    #[test]
    fn demotion_receipt_schema_hash_deterministic() {
        let h1 = demotion_receipt_schema_hash();
        let h2 = demotion_receipt_schema_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn monitor_clone_equals_original() {
        let monitor = test_monitor();
        let cloned = monitor.clone();
        assert_eq!(monitor, cloned);
    }

    // ── Enrichment: Display uniqueness ──────────────────────────

    #[test]
    fn demotion_reason_category_all_unique() {
        let categories: std::collections::BTreeSet<&str> = [
            DemotionReason::SemanticDivergence {
                divergence_count: 1,
                first_divergence_artifact: ContentHash::compute(b"test"),
            },
            DemotionReason::PerformanceBreach {
                metric_name: "lat".into(),
                observed_millionths: 100,
                threshold_millionths: 50,
                sustained_duration_ns: 1000,
            },
            DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 500_000,
            },
            DemotionReason::CapabilityViolation {
                attempted_capability: "fs_write".into(),
                envelope_digest: ContentHash::compute(b"env"),
            },
            DemotionReason::OperatorInitiated {
                operator_id: "ops".into(),
                reason: "maintenance".into(),
            },
        ]
        .iter()
        .map(|r| r.category())
        .collect();
        assert_eq!(categories.len(), 5);
    }

    #[test]
    fn demotion_severity_display_all_unique() {
        let displays: std::collections::BTreeSet<String> = [
            DemotionSeverity::Advisory,
            DemotionSeverity::Warning,
            DemotionSeverity::Critical,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(displays.len(), 3);
    }

    // ── Enrichment: DemotionReason serde roundtrip ──────────────

    #[test]
    fn demotion_reason_serde_all_variants() {
        let reasons = vec![
            DemotionReason::SemanticDivergence {
                divergence_count: 5,
                first_divergence_artifact: ContentHash::compute(b"div"),
            },
            DemotionReason::PerformanceBreach {
                metric_name: "latency_p99".into(),
                observed_millionths: 800_000,
                threshold_millionths: 500_000,
                sustained_duration_ns: 5_000_000_000,
            },
            DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 700_000,
            },
            DemotionReason::CapabilityViolation {
                attempted_capability: "network_egress".into(),
                envelope_digest: ContentHash::compute(b"env"),
            },
            DemotionReason::OperatorInitiated {
                operator_id: "ops-42".into(),
                reason: "security patch".into(),
            },
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: DemotionReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    // ── Enrichment: DemotionSeverity serde ──────────────────────

    #[test]
    fn demotion_severity_serde_all_variants() {
        for severity in [
            DemotionSeverity::Advisory,
            DemotionSeverity::Warning,
            DemotionSeverity::Critical,
        ] {
            let json = serde_json::to_string(&severity).unwrap();
            let back: DemotionSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(severity, back);
        }
    }

    // ── Enrichment: DemotionSeverity ordering ───────────────────

    #[test]
    fn enrichment_demotion_severity_ordering() {
        assert!(DemotionSeverity::Advisory < DemotionSeverity::Warning);
        assert!(DemotionSeverity::Warning < DemotionSeverity::Critical);
    }

    // ── Enrichment: DemotionEvidenceItem serde ──────────────────

    #[test]
    fn enrichment_demotion_evidence_item_serde_roundtrip() {
        let item = DemotionEvidenceItem {
            artifact_hash: ContentHash::compute(b"evidence-data"),
            category: "divergence_trace".into(),
            collected_at_ns: 123_456_789,
            summary: "Found 3 output differences".into(),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: DemotionEvidenceItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    // ── Enrichment: DemotionReason Display ──────────────────────

    #[test]
    fn enrichment_demotion_reason_display_all_variants() {
        let reasons = [
            DemotionReason::SemanticDivergence {
                divergence_count: 3,
                first_divergence_artifact: ContentHash::compute(b"x"),
            },
            DemotionReason::PerformanceBreach {
                metric_name: "throughput".into(),
                observed_millionths: 100,
                threshold_millionths: 200,
                sustained_duration_ns: 1000,
            },
            DemotionReason::RiskThresholdBreach {
                observed_risk_millionths: 900_000,
                max_risk_millionths: 500_000,
            },
            DemotionReason::CapabilityViolation {
                attempted_capability: "spawn".into(),
                envelope_digest: ContentHash::compute(b"env"),
            },
            DemotionReason::OperatorInitiated {
                operator_id: "admin".into(),
                reason: "patching".into(),
            },
        ];
        let displays: std::collections::BTreeSet<String> =
            reasons.iter().map(|r| r.to_string()).collect();
        assert_eq!(displays.len(), 5, "all 5 variants produce distinct Display");
    }

    // ── Enrichment: DemotionPolicy serde roundtrip ──────────────

    #[test]
    fn enrichment_demotion_policy_serde_roundtrip() {
        let policy = test_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let back: DemotionPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-26
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_performance_thresholds_independent() {
        let receipt = test_promotion_receipt();
        let mut policy = test_policy();
        policy.performance_thresholds.push(PerformanceThreshold {
            metric_name: "throughput_ops_sec".to_string(),
            max_value_millionths: 100_000_000,
            sustained_duration_ns: 5_000_000_000,
        });
        let mut monitor =
            AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create");

        // Breach latency but not throughput
        let obs = MonitoringObservation::PerformanceSample {
            metric_name: "throughput_ops_sec".to_string(),
            value_millionths: 50_000_000, // Below threshold, OK
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs).trigger_fired);

        // Breach throughput
        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "throughput_ops_sec".to_string(),
            value_millionths: 150_000_000, // Above 100M threshold
            timestamp_ns: 3_000_000_000,
        };
        assert!(!monitor.process_observation(&obs2).trigger_fired);

        // Sustained throughput breach
        let obs3 = MonitoringObservation::PerformanceSample {
            metric_name: "throughput_ops_sec".to_string(),
            value_millionths: 150_000_000,
            timestamp_ns: 9_000_000_000, // 6s sustained > 5s threshold
        };
        assert!(monitor.process_observation(&obs3).trigger_fired);
    }

    #[test]
    fn performance_breach_at_exact_threshold_does_not_fire() {
        let mut monitor = test_monitor();
        // Exactly at threshold (50M): not a breach (breach requires > threshold)
        let obs = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 50_000_000,
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs).trigger_fired);

        // Long sustained at exact threshold
        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 50_000_000,
            timestamp_ns: 20_000_000_000,
        };
        assert!(!monitor.process_observation(&obs2).trigger_fired);
    }

    #[test]
    fn semantic_divergence_tracks_first_artifact() {
        let receipt = test_promotion_receipt();
        let mut policy = test_policy();
        policy.max_divergence_count = 5;
        let mut monitor =
            AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create");

        let input1_hash = ContentHash::compute(b"first-input");
        let obs1 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: input1_hash.clone(),
            native_output_hash: ContentHash::compute(b"n1"),
            reference_output_hash: ContentHash::compute(b"r1"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };
        monitor.process_observation(&obs1);
        assert_eq!(monitor.divergence_count(), 1);

        // Second divergence with different input
        let obs2 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"second-input"),
            native_output_hash: ContentHash::compute(b"n2"),
            reference_output_hash: ContentHash::compute(b"r2"),
            waiver_covered: false,
            timestamp_ns: 3_000_000_000,
        };
        monitor.process_observation(&obs2);
        assert_eq!(monitor.divergence_count(), 2);
    }

    #[test]
    fn observations_processed_increments_across_mixed_types() {
        let mut monitor = test_monitor();

        let obs1 = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 100_000,
            timestamp_ns: 2_000_000_000,
        };
        monitor.process_observation(&obs1);
        assert_eq!(monitor.observations_processed(), 1);

        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 10_000_000,
            timestamp_ns: 3_000_000_000,
        };
        monitor.process_observation(&obs2);
        assert_eq!(monitor.observations_processed(), 2);

        let obs3 = MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"out"),
            reference_output_hash: ContentHash::compute(b"out"),
            waiver_covered: false,
            timestamp_ns: 4_000_000_000,
        };
        monitor.process_observation(&obs3);
        assert_eq!(monitor.observations_processed(), 3);

        let obs4 = MonitoringObservation::CapabilityEvent {
            capability: "fs_read".to_string(),
            within_envelope: true,
            envelope_digest: ContentHash::compute(b"env"),
            timestamp_ns: 5_000_000_000,
        };
        monitor.process_observation(&obs4);
        assert_eq!(monitor.observations_processed(), 4);
    }

    #[test]
    fn risk_updates_track_latest_value() {
        let mut monitor = test_monitor();

        for (risk, ts) in [
            (100_000, 2_000_000_000),
            (300_000, 3_000_000_000),
            (500_000, 4_000_000_000),
        ] {
            let obs = MonitoringObservation::RiskScoreUpdate {
                risk_millionths: risk,
                timestamp_ns: ts,
            };
            monitor.process_observation(&obs);
            assert_eq!(monitor.latest_risk_millionths(), risk);
        }
    }

    #[test]
    fn monitor_serde_after_demotion_trigger() {
        let mut monitor = test_monitor();
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 900_000,
            timestamp_ns: 2_000_000_000,
        };
        assert!(monitor.process_observation(&obs).trigger_fired);
        assert!(monitor.is_demotion_triggered());

        let json = serde_json::to_string(&monitor).unwrap();
        let restored: AutoDemotionMonitor = serde_json::from_str(&json).unwrap();
        assert!(restored.is_demotion_triggered());
        assert_eq!(restored.latest_risk_millionths(), 900_000);
        assert_eq!(restored.observations_processed(), 1);
    }

    #[test]
    fn observations_still_counted_after_demotion() {
        let mut monitor = test_monitor();
        let obs1 = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 900_000,
            timestamp_ns: 2_000_000_000,
        };
        assert!(monitor.process_observation(&obs1).trigger_fired);
        assert_eq!(monitor.observations_processed(), 1);

        // Post-demotion observations are still counted
        let obs2 = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 100_000,
            timestamp_ns: 3_000_000_000,
        };
        let result = monitor.process_observation(&obs2);
        assert!(!result.trigger_fired);
        assert_eq!(result.observations_processed, 2);
    }

    #[test]
    fn multiple_blocked_candidates() {
        let mut policy = DemotionPolicy::strict(test_slot());
        policy.block_candidate("digest-a".to_string());
        policy.block_candidate("digest-b".to_string());
        policy.block_candidate("digest-c".to_string());

        assert!(policy.is_candidate_blocked("digest-a"));
        assert!(policy.is_candidate_blocked("digest-b"));
        assert!(policy.is_candidate_blocked("digest-c"));
        assert!(!policy.is_candidate_blocked("digest-d"));

        // Unblock one
        assert!(policy.unblock_candidate("digest-b"));
        assert!(policy.is_candidate_blocked("digest-a"));
        assert!(!policy.is_candidate_blocked("digest-b"));
        assert!(policy.is_candidate_blocked("digest-c"));
    }

    #[test]
    fn semantic_divergence_evidence_has_correct_category() {
        let mut monitor = test_monitor();
        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"input"),
            native_output_hash: ContentHash::compute(b"native"),
            reference_output_hash: ContentHash::compute(b"ref"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        let eval = result.evaluation.unwrap();
        assert!(!eval.evidence.is_empty());
        assert_eq!(eval.evidence[0].category, "divergence_trace");
        assert!(eval.evidence[0].summary.contains("divergence"));
    }

    #[test]
    fn capability_violation_evidence_has_correct_category() {
        let mut monitor = test_monitor();
        let obs = MonitoringObservation::CapabilityEvent {
            capability: "network_send".to_string(),
            within_envelope: false,
            envelope_digest: ContentHash::compute(b"envelope"),
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        let eval = result.evaluation.unwrap();
        assert!(!eval.evidence.is_empty());
        assert_eq!(eval.evidence[0].category, "capability_violation");
        assert!(eval.evidence[0].summary.contains("network_send"));
    }

    #[test]
    fn risk_threshold_evidence_has_correct_category() {
        let mut monitor = test_monitor();
        let obs = MonitoringObservation::RiskScoreUpdate {
            risk_millionths: 900_000,
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        let eval = result.evaluation.unwrap();
        assert!(!eval.evidence.is_empty());
        assert_eq!(eval.evidence[0].category, "risk_score");
    }

    #[test]
    fn receipt_with_performance_breach_reason() {
        let key = test_signing_key();
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-x",
                restored_cell_digest: "delegate-y",
                rollback_token_used: "token-z",
                demotion_reason: &DemotionReason::PerformanceBreach {
                    metric_name: "latency_p99_ns".to_string(),
                    observed_millionths: 80_000_000,
                    threshold_millionths: 50_000_000,
                    sustained_duration_ns: 15_000_000_000,
                },
                severity: DemotionSeverity::Warning,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(3),
                zone: "staging",
            },
        )
        .expect("create receipt");

        assert_eq!(receipt.severity, DemotionSeverity::Warning);
        assert!(matches!(
            receipt.demotion_reason,
            DemotionReason::PerformanceBreach { .. }
        ));
        receipt
            .verify_signature(&key.verification_key())
            .expect("signature valid");
    }

    #[test]
    fn receipt_with_capability_violation_reason() {
        let key = test_signing_key();
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-a",
                restored_cell_digest: "delegate-b",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::CapabilityViolation {
                    attempted_capability: "exec_shell".to_string(),
                    envelope_digest: ContentHash::compute(b"restricted-env"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 3_000_000_000,
                epoch: SecurityEpoch::from_raw(2),
                zone: "prod",
            },
        )
        .expect("create receipt");

        assert!(matches!(
            receipt.demotion_reason,
            DemotionReason::CapabilityViolation { .. }
        ));
        receipt
            .verify_signature(&key.verification_key())
            .expect("signature valid");
    }

    #[test]
    fn receipt_id_differs_by_zone() {
        let id_a = DemotionReceipt::derive_receipt_id(
            &test_slot(),
            "native",
            "delegate",
            1_000_000_000,
            "zone-a",
        )
        .unwrap();
        let id_b = DemotionReceipt::derive_receipt_id(
            &test_slot(),
            "native",
            "delegate",
            1_000_000_000,
            "zone-b",
        )
        .unwrap();
        assert_ne!(
            id_a, id_b,
            "different zones should produce different receipt IDs"
        );
    }

    #[test]
    fn receipt_id_differs_by_digest() {
        let id_a = DemotionReceipt::derive_receipt_id(
            &test_slot(),
            "native-a",
            "delegate",
            1_000_000_000,
            "zone",
        )
        .unwrap();
        let id_b = DemotionReceipt::derive_receipt_id(
            &test_slot(),
            "native-b",
            "delegate",
            1_000_000_000,
            "zone",
        )
        .unwrap();
        assert_ne!(
            id_a, id_b,
            "different digests should produce different receipt IDs"
        );
    }

    #[test]
    fn policy_custom_severity_mappings() {
        let receipt = test_promotion_receipt();
        let mut policy = test_policy();
        policy.semantic_divergence_severity = DemotionSeverity::Advisory;
        policy.risk_threshold_severity = DemotionSeverity::Warning;

        let mut monitor =
            AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create");

        // Divergence fires with Advisory severity
        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"n"),
            reference_output_hash: ContentHash::compute(b"r"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        assert_eq!(
            result.evaluation.unwrap().severity,
            DemotionSeverity::Advisory
        );
    }

    #[test]
    fn burn_in_boundary_exact() {
        let monitor = test_monitor();
        // monitoring_start_ns = 1_000_000_000, burn_in = 300_000_000_000
        let end = 1_000_000_000 + 300_000_000_000;
        assert!(monitor.is_burn_in(end - 1));
        assert!(!monitor.is_burn_in(end));
        assert!(!monitor.is_burn_in(end + 1));
    }

    #[test]
    fn receipt_with_multiple_evidence_items() {
        let key = test_signing_key();
        let evidence = vec![
            DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"ev-1"),
                category: "divergence_trace".to_string(),
                collected_at_ns: 1_000_000,
                summary: "first divergence".to_string(),
            },
            DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"ev-2"),
                category: "latency_sample".to_string(),
                collected_at_ns: 2_000_000,
                summary: "p99 spike".to_string(),
            },
            DemotionEvidenceItem {
                artifact_hash: ContentHash::compute(b"ev-3"),
                category: "risk_score".to_string(),
                collected_at_ns: 3_000_000,
                summary: "risk escalation".to_string(),
            },
        ];
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "token",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"div"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &evidence,
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test",
            },
        )
        .expect("create receipt");

        assert_eq!(receipt.evidence.len(), 3);
        assert_eq!(receipt.evidence[0].category, "divergence_trace");
        assert_eq!(receipt.evidence[1].category, "latency_sample");
        assert_eq!(receipt.evidence[2].category, "risk_score");

        // Serde roundtrip preserves all evidence
        let json = serde_json::to_string(&receipt).unwrap();
        let restored: DemotionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.evidence.len(), 3);
    }

    #[test]
    fn content_hash_differs_for_different_receipts() {
        let key = test_signing_key();
        let r1 = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-a",
                restored_cell_digest: "delegate-a",
                rollback_token_used: "token",
                demotion_reason: &DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: 900_000,
                    max_risk_millionths: 800_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test",
            },
        )
        .expect("r1");

        let r2 = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-b",
                restored_cell_digest: "delegate-b",
                rollback_token_used: "token",
                demotion_reason: &DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: 900_000,
                    max_risk_millionths: 800_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 2_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test",
            },
        )
        .expect("r2");

        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn policy_slot_id_matches() {
        let policy = DemotionPolicy::strict(test_slot());
        assert_eq!(policy.slot_id, test_slot());
    }

    #[test]
    fn demotion_error_display_id_derivation_and_signature() {
        let err1 = DemotionError::IdDerivationFailed(
            crate::engine_object_id::IdError::EmptyCanonicalBytes,
        );
        assert!(err1.to_string().contains("id derivation failed"));

        let err2 = DemotionError::SignatureFailed(
            crate::signature_preimage::SignatureError::InvalidSigningKey,
        );
        assert!(err2.to_string().contains("signature error"));
    }

    // -- Enrichment: PearlTower 2026-02-26 session 4 --

    #[test]
    fn receipt_schema_version_is_v1() {
        let key = test_signing_key();
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"d"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("create");
        assert_eq!(receipt.schema_version, SchemaVersion::V1);
    }

    #[test]
    fn strict_policy_burn_in_and_latency_defaults() {
        let policy = DemotionPolicy::strict(test_slot());
        // 5-minute burn-in
        assert_eq!(policy.burn_in_duration_ns, 300_000_000_000);
        // 1-second max rollback latency
        assert_eq!(policy.max_rollback_latency_ns, 1_000_000_000);
        // No performance thresholds configured by default
        assert!(policy.performance_thresholds.is_empty());
        // Severity defaults
        assert_eq!(
            policy.semantic_divergence_severity,
            DemotionSeverity::Critical
        );
        assert_eq!(
            policy.performance_breach_severity,
            DemotionSeverity::Warning
        );
        assert_eq!(policy.risk_threshold_severity, DemotionSeverity::Critical);
        assert_eq!(
            policy.capability_violation_severity,
            DemotionSeverity::Critical
        );
    }

    #[test]
    fn content_hash_depends_on_reason_details() {
        let key = test_signing_key();
        let r1 = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::PerformanceBreach {
                    metric_name: "latency_p99_ns".to_string(),
                    observed_millionths: 80_000_000,
                    threshold_millionths: 50_000_000,
                    sustained_duration_ns: 15_000_000_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("r1");

        let r2 = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::PerformanceBreach {
                    metric_name: "latency_p99_ns".to_string(),
                    observed_millionths: 81_000_000,
                    threshold_millionths: 50_000_000,
                    sustained_duration_ns: 15_000_000_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("r2");

        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn content_hash_depends_on_evidence() {
        let key = test_signing_key();
        let no_evidence = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: 900_000,
                    max_risk_millionths: 800_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("no evidence");
        let with_evidence = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::RiskThresholdBreach {
                    observed_risk_millionths: 900_000,
                    max_risk_millionths: 800_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[DemotionEvidenceItem {
                    artifact_hash: ContentHash::compute(b"trace"),
                    category: "risk_snapshot".to_string(),
                    collected_at_ns: 5_000_000_010,
                    summary: "snapshot before rollback".to_string(),
                }],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("with evidence");

        assert_ne!(no_evidence.content_hash(), with_evidence.content_hash());
    }

    #[test]
    fn signature_verification_fails_when_reason_detail_is_tampered() {
        let key = test_signing_key();
        let mut receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::PerformanceBreach {
                    metric_name: "latency_p99_ns".to_string(),
                    observed_millionths: 80_000_000,
                    threshold_millionths: 50_000_000,
                    sustained_duration_ns: 15_000_000_000,
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("create");

        if let DemotionReason::PerformanceBreach {
            observed_millionths,
            ..
        } = &mut receipt.demotion_reason
        {
            *observed_millionths += 1;
        }

        assert!(matches!(
            receipt.verify_signature(&key.verification_key()),
            Err(DemotionError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn signature_verification_fails_when_evidence_is_tampered() {
        let key = test_signing_key();
        let mut receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"d"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[DemotionEvidenceItem {
                    artifact_hash: ContentHash::compute(b"trace"),
                    category: "divergence_trace".to_string(),
                    collected_at_ns: 1_000_000_010,
                    summary: "first divergent trace".to_string(),
                }],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("create");

        receipt.evidence[0].summary = "tampered summary".to_string();

        assert!(matches!(
            receipt.verify_signature(&key.verification_key()),
            Err(DemotionError::SignatureInvalid { .. })
        ));
    }

    #[test]
    fn operator_initiated_receipt_verify_succeeds() {
        let key = test_signing_key();
        let receipt = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native",
                restored_cell_digest: "delegate",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::OperatorInitiated {
                    operator_id: "admin-42".to_string(),
                    reason: "emergency rollback".to_string(),
                },
                severity: DemotionSeverity::Warning,
                evidence: &[],
                timestamp_ns: 1_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "test-zone",
            },
        )
        .expect("create");
        // Preimage includes reason.category() == "operator_initiated",
        // so this exercises a distinct preimage path from the main test.
        receipt
            .verify_signature(&key.verification_key())
            .expect("verify should succeed");
    }

    #[test]
    fn non_firing_observation_result_evaluation_is_none() {
        let mut monitor = test_monitor();
        // A matched output comparison should not fire any trigger.
        let obs = MonitoringObservation::OutputComparison {
            matched: true,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"same"),
            reference_output_hash: ContentHash::compute(b"same"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(!result.trigger_fired);
        assert!(result.evaluation.is_none());
        assert_eq!(result.observations_processed, 1);
    }

    #[test]
    fn semantic_divergence_evidence_summary_includes_slot() {
        let mut monitor = test_monitor();
        // Policy max_divergence_count = 0, so the first divergence fires.
        let obs = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in"),
            native_output_hash: ContentHash::compute(b"n"),
            reference_output_hash: ContentHash::compute(b"r"),
            waiver_covered: false,
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        let eval = result.evaluation.unwrap();
        assert_eq!(eval.evidence.len(), 1);
        let summary = &eval.evidence[0].summary;
        assert!(
            summary.contains("test-slot-001"),
            "evidence summary should include slot id, got: {summary}"
        );
        assert!(
            summary.contains("divergence #1"),
            "evidence summary should include divergence count, got: {summary}"
        );
    }

    #[test]
    fn capability_violation_evidence_summary_includes_capability() {
        let mut monitor = test_monitor();
        let obs = MonitoringObservation::CapabilityEvent {
            capability: "net.outbound".to_string(),
            within_envelope: false,
            envelope_digest: ContentHash::compute(b"env"),
            timestamp_ns: 2_000_000_000,
        };
        let result = monitor.process_observation(&obs);
        assert!(result.trigger_fired);
        let eval = result.evaluation.unwrap();
        assert_eq!(eval.evidence.len(), 1);
        let summary = &eval.evidence[0].summary;
        assert!(
            summary.contains("net.outbound"),
            "evidence summary should include capability name, got: {summary}"
        );
        assert_eq!(eval.evidence[0].category, "capability_violation");
    }

    // -- Enrichment: PearlTower 2026-02-26 session 8 --

    #[test]
    fn performance_breach_evidence_has_correct_category() {
        let mut monitor = test_monitor();
        // Start breach
        let obs1 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000,
            timestamp_ns: 2_000_000_000,
        };
        monitor.process_observation(&obs1);
        // Sustained long enough to fire (>10s)
        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000,
            timestamp_ns: 13_000_000_000,
        };
        let result = monitor.process_observation(&obs2);
        assert!(result.trigger_fired);
        let eval = result.evaluation.unwrap();
        assert!(!eval.evidence.is_empty());
        assert_eq!(eval.evidence[0].category, "performance_sample");
    }

    #[test]
    fn receipt_id_differs_by_slot() {
        let slot_a = SlotId::new("parser").unwrap();
        let slot_b = SlotId::new("interpreter").unwrap();
        let id_a =
            DemotionReceipt::derive_receipt_id(&slot_a, "native", "delegate", 1_000_000_000, "z")
                .unwrap();
        let id_b =
            DemotionReceipt::derive_receipt_id(&slot_b, "native", "delegate", 1_000_000_000, "z")
                .unwrap();
        assert_ne!(id_a, id_b, "different slots should produce different IDs");
    }

    #[test]
    fn performance_breach_fires_at_exact_sustained_boundary() {
        let mut monitor = test_monitor();
        // Start breach at t=2s
        let obs1 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000,
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&obs1).trigger_fired);
        // Exactly 10s sustained (threshold = 10_000_000_000ns)
        let obs2 = MonitoringObservation::PerformanceSample {
            metric_name: "latency_p99_ns".to_string(),
            value_millionths: 60_000_000,
            timestamp_ns: 12_000_000_000, // 10s after breach start
        };
        let result = monitor.process_observation(&obs2);
        assert!(
            result.trigger_fired,
            "should fire when sustained duration equals threshold"
        );
    }

    #[test]
    fn burn_in_underflow_is_always_in_burn_in() {
        let monitor = test_monitor();
        // monitoring_start_ns = 1_000_000_000
        // current_ns=0 < monitoring_start_ns, saturating_sub → 0 < burn_in_duration
        assert!(
            monitor.is_burn_in(0),
            "time before start should be within burn-in"
        );
    }

    #[test]
    fn content_hash_changes_with_restored_digest_only() {
        let key = test_signing_key();
        let r1 = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-same",
                restored_cell_digest: "delegate-alpha",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"d"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("r1");
        let r2 = DemotionReceipt::create_signed(
            &key,
            CreateDemotionReceiptInput {
                slot_id: &test_slot(),
                demoted_cell_digest: "native-same",
                restored_cell_digest: "delegate-beta",
                rollback_token_used: "tok",
                demotion_reason: &DemotionReason::SemanticDivergence {
                    divergence_count: 1,
                    first_divergence_artifact: ContentHash::compute(b"d"),
                },
                severity: DemotionSeverity::Critical,
                evidence: &[],
                timestamp_ns: 5_000_000_000,
                epoch: SecurityEpoch::from_raw(1),
                zone: "z",
            },
        )
        .expect("r2");
        assert_ne!(
            r1.content_hash(),
            r2.content_hash(),
            "different restored_cell_digest should change content_hash"
        );
    }

    #[test]
    fn performance_breach_display_includes_metric_and_values() {
        let reason = DemotionReason::PerformanceBreach {
            metric_name: "latency_p99_ns".to_string(),
            observed_millionths: 80_000_000,
            threshold_millionths: 50_000_000,
            sustained_duration_ns: 15_000_000_000,
        };
        let s = reason.to_string();
        assert!(s.contains("latency_p99_ns"), "should contain metric name");
        assert!(s.contains("80000000"), "should contain observed value");
        assert!(s.contains("50000000"), "should contain threshold value");
    }

    #[test]
    fn risk_threshold_breach_display_includes_scores() {
        let reason = DemotionReason::RiskThresholdBreach {
            observed_risk_millionths: 950_000,
            max_risk_millionths: 800_000,
        };
        let s = reason.to_string();
        assert!(s.contains("950000"), "should contain observed risk");
        assert!(s.contains("800000"), "should contain max risk");
    }

    #[test]
    fn waived_divergence_not_counted_toward_threshold() {
        let receipt = test_promotion_receipt();
        let mut policy = test_policy();
        policy.max_divergence_count = 2; // Fire on 2nd unwaived divergence

        let mut monitor =
            AutoDemotionMonitor::new(&receipt, policy, 1_000_000_000).expect("create");

        // Waived divergence — should NOT increment count
        let waived = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in-waived"),
            native_output_hash: ContentHash::compute(b"n-waived"),
            reference_output_hash: ContentHash::compute(b"r-waived"),
            waiver_covered: true,
            timestamp_ns: 2_000_000_000,
        };
        assert!(!monitor.process_observation(&waived).trigger_fired);
        assert_eq!(monitor.divergence_count(), 0);

        // First unwaived divergence
        let unwaived1 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in-1"),
            native_output_hash: ContentHash::compute(b"n-1"),
            reference_output_hash: ContentHash::compute(b"r-1"),
            waiver_covered: false,
            timestamp_ns: 3_000_000_000,
        };
        assert!(!monitor.process_observation(&unwaived1).trigger_fired);
        assert_eq!(monitor.divergence_count(), 1);

        // Another waived — still count=1
        let waived2 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in-waived-2"),
            native_output_hash: ContentHash::compute(b"n-waived-2"),
            reference_output_hash: ContentHash::compute(b"r-waived-2"),
            waiver_covered: true,
            timestamp_ns: 4_000_000_000,
        };
        assert!(!monitor.process_observation(&waived2).trigger_fired);
        assert_eq!(monitor.divergence_count(), 1);

        // Second unwaived — fires (count=2 >= max=2)
        let unwaived2 = MonitoringObservation::OutputComparison {
            matched: false,
            input_hash: ContentHash::compute(b"in-2"),
            native_output_hash: ContentHash::compute(b"n-2"),
            reference_output_hash: ContentHash::compute(b"r-2"),
            waiver_covered: false,
            timestamp_ns: 5_000_000_000,
        };
        assert!(monitor.process_observation(&unwaived2).trigger_fired);
        assert_eq!(monitor.divergence_count(), 2);
    }
}
