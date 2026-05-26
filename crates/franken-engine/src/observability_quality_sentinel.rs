//! Observability Quality Sentinel and Deterministic Demotion Policy.
//!
//! Runtime monitors that continuously test whether compressed/budgeted
//! observability remains sufficient for reliable decisions and forensic replay.
//! Detects degradation regimes (silent blind spots, reconstruction ambiguity,
//! tail-event undercoverage) and triggers deterministic demotion to richer
//! evidence modes when quality bounds break.
//!
//! Plan reference: FRX-17.4 (Observability Quality Sentinel).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

pub const SCHEMA_VERSION: &str = "franken-engine.observability-quality-sentinel.v1";

/// Default minimum fidelity (millionths) before demotion triggers.
pub const DEFAULT_MIN_FIDELITY: i64 = 800_000;

/// Default maximum tolerated blind-spot ratio (millionths).
pub const DEFAULT_MAX_BLIND_SPOT_RATIO: i64 = 50_000;

/// Default reconstruction ambiguity ceiling (millionths).
pub const DEFAULT_MAX_RECONSTRUCTION_AMBIGUITY: i64 = 100_000;

/// Default tail-event undercoverage ceiling (millionths).
pub const DEFAULT_MAX_TAIL_UNDERCOVERAGE: i64 = 150_000;

/// Minimum observation count before sequential tests become active.
pub const MIN_OBSERVATIONS_FOR_TEST: u64 = 10;

// ---------------------------------------------------------------------------
// Quality dimensions
// ---------------------------------------------------------------------------

/// Dimension along which observability quality is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum QualityDimension {
    /// Signal fidelity after compression/budget constraints.
    SignalFidelity,
    /// Fraction of event space with zero coverage.
    BlindSpotRatio,
    /// Ambiguity in reconstructing original events from compressed form.
    ReconstructionAmbiguity,
    /// Fraction of tail events (rare/extreme) not covered by probes.
    TailUndercoverage,
    /// Staleness of evidence relative to decision cadence.
    EvidenceStaleness,
}

impl QualityDimension {
    pub const ALL: [QualityDimension; 5] = [
        QualityDimension::SignalFidelity,
        QualityDimension::BlindSpotRatio,
        QualityDimension::ReconstructionAmbiguity,
        QualityDimension::TailUndercoverage,
        QualityDimension::EvidenceStaleness,
    ];
}

impl fmt::Display for QualityDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignalFidelity => write!(f, "signal_fidelity"),
            Self::BlindSpotRatio => write!(f, "blind_spot_ratio"),
            Self::ReconstructionAmbiguity => write!(f, "reconstruction_ambiguity"),
            Self::TailUndercoverage => write!(f, "tail_undercoverage"),
            Self::EvidenceStaleness => write!(f, "evidence_staleness"),
        }
    }
}

// ---------------------------------------------------------------------------
// Degradation regime
// ---------------------------------------------------------------------------

/// Classification of detected degradation regime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum DegradationRegime {
    Nominal,
    Elevated,
    Breached,
    Emergency,
}

impl fmt::Display for DegradationRegime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nominal => write!(f, "nominal"),
            Self::Elevated => write!(f, "elevated"),
            Self::Breached => write!(f, "breached"),
            Self::Emergency => write!(f, "emergency"),
        }
    }
}

// ---------------------------------------------------------------------------
// Demotion mode
// ---------------------------------------------------------------------------

/// Target evidence mode after demotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum DemotionTarget {
    IncreasedSampling,
    UncompressedEvidence,
    FullReplayCapture,
    EmergencyRingBuffer,
}

impl DemotionTarget {
    pub fn severity_rank(self) -> u32 {
        match self {
            Self::IncreasedSampling => 1,
            Self::UncompressedEvidence => 2,
            Self::FullReplayCapture => 3,
            Self::EmergencyRingBuffer => 4,
        }
    }
}

impl fmt::Display for DemotionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncreasedSampling => write!(f, "increased_sampling"),
            Self::UncompressedEvidence => write!(f, "uncompressed_evidence"),
            Self::FullReplayCapture => write!(f, "full_replay_capture"),
            Self::EmergencyRingBuffer => write!(f, "emergency_ring_buffer"),
        }
    }
}

// ---------------------------------------------------------------------------
// Quality observation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityObservation {
    pub dimension: QualityDimension,
    pub value_millionths: i64,
    pub timestamp_ns: u64,
    pub channel_id: String,
}

// ---------------------------------------------------------------------------
// Quality threshold
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualityThreshold {
    pub dimension: QualityDimension,
    pub limit_millionths: i64,
    pub warning_millionths: i64,
}

impl QualityThreshold {
    pub fn is_breached(&self, value_millionths: i64) -> bool {
        match self.dimension {
            QualityDimension::SignalFidelity => value_millionths < self.limit_millionths,
            _ => value_millionths > self.limit_millionths,
        }
    }

    pub fn is_warning(&self, value_millionths: i64) -> bool {
        if self.is_breached(value_millionths) {
            return false;
        }
        match self.dimension {
            QualityDimension::SignalFidelity => value_millionths < self.warning_millionths,
            _ => value_millionths > self.warning_millionths,
        }
    }
}

// ---------------------------------------------------------------------------
// Sequential validity test (e-process / CUSUM)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequentialTestState {
    pub dimension: QualityDimension,
    pub cusum_millionths: i64,
    pub e_value_millionths: i64,
    pub observation_count: u64,
    pub rejected: bool,
    pub rejection_threshold_millionths: i64,
}

impl SequentialTestState {
    pub fn new(dimension: QualityDimension) -> Self {
        Self {
            dimension,
            cusum_millionths: 0,
            e_value_millionths: MILLION,
            observation_count: 0,
            rejected: false,
            rejection_threshold_millionths: 20 * MILLION,
        }
    }

    pub fn update(&mut self, threshold: &QualityThreshold, value_millionths: i64) -> bool {
        self.observation_count += 1;
        let deviation = match self.dimension {
            QualityDimension::SignalFidelity => threshold.limit_millionths - value_millionths,
            _ => value_millionths - threshold.limit_millionths,
        };
        self.cusum_millionths = (self.cusum_millionths + deviation).max(0);
        if deviation > 0 && self.observation_count >= MIN_OBSERVATIONS_FOR_TEST {
            let lr = MILLION + deviation.min(2 * MILLION);
            self.e_value_millionths = saturating_mul_div(self.e_value_millionths, lr, MILLION);
        } else if deviation <= 0 {
            let decay = MILLION - ((-deviation).min(MILLION / 2));
            self.e_value_millionths = saturating_mul_div(self.e_value_millionths, decay, MILLION);
            self.e_value_millionths = self.e_value_millionths.max(MILLION);
        }
        let was = self.rejected;
        if self.e_value_millionths >= self.rejection_threshold_millionths
            && self.observation_count >= MIN_OBSERVATIONS_FOR_TEST
        {
            self.rejected = true;
        }
        !was && self.rejected
    }

    pub fn reset(&mut self) {
        self.cusum_millionths = 0;
        self.e_value_millionths = MILLION;
        self.observation_count = 0;
        self.rejected = false;
    }
}

// ---------------------------------------------------------------------------
// Demotion rule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemotionRule {
    pub rule_id: String,
    pub trigger_dimension: QualityDimension,
    pub trigger_regime: DegradationRegime,
    pub target: DemotionTarget,
    pub cooldown_epochs: u64,
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Demotion policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemotionPolicy {
    pub policy_id: String,
    pub epoch: SecurityEpoch,
    pub thresholds: Vec<QualityThreshold>,
    pub rules: Vec<DemotionRule>,
}

impl DemotionPolicy {
    pub fn compute_id(epoch: SecurityEpoch, rules: &[DemotionRule]) -> String {
        let mut h = Sha256::new();
        h.update(b"demotion-policy:");
        h.update(epoch.as_u64().to_le_bytes());
        for r in rules {
            h.update(r.rule_id.as_bytes());
        }
        format!("dp-{}", hex::encode(&h.finalize()[..8]))
    }

    pub fn threshold_for(&self, dim: QualityDimension) -> Option<&QualityThreshold> {
        self.thresholds.iter().find(|t| t.dimension == dim)
    }

    pub fn rules_for(
        &self,
        dim: QualityDimension,
        regime: DegradationRegime,
    ) -> Vec<&DemotionRule> {
        self.rules
            .iter()
            .filter(|r| r.trigger_dimension == dim && r.trigger_regime == regime)
            .collect()
    }

    pub fn max_demotion_severity(&self) -> Option<DemotionTarget> {
        self.rules
            .iter()
            .map(|r| r.target)
            .max_by_key(|t| t.severity_rank())
    }
}

// ---------------------------------------------------------------------------
// Degradation artifact
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DegradationArtifact {
    pub artifact_id: String,
    pub epoch: SecurityEpoch,
    pub dimension: QualityDimension,
    pub regime: DegradationRegime,
    pub observed_value_millionths: i64,
    pub threshold_millionths: i64,
    pub e_value_millionths: i64,
    pub cusum_millionths: i64,
    pub observation_count: u64,
    pub timestamp_ns: u64,
    pub channel_id: String,
    pub content_hash: String,
}

impl DegradationArtifact {
    pub fn compute_hash(
        epoch: SecurityEpoch,
        dimension: QualityDimension,
        regime: DegradationRegime,
        observed_millionths: i64,
        timestamp_ns: u64,
    ) -> String {
        let mut h = Sha256::new();
        h.update(b"degradation-artifact:");
        h.update(epoch.as_u64().to_le_bytes());
        h.update(dimension.to_string().as_bytes());
        h.update(regime.to_string().as_bytes());
        h.update(observed_millionths.to_le_bytes());
        h.update(timestamp_ns.to_le_bytes());
        hex::encode(&h.finalize()[..16])
    }

    pub fn compute_id(
        epoch: SecurityEpoch,
        dimension: QualityDimension,
        timestamp_ns: u64,
    ) -> String {
        let mut h = Sha256::new();
        h.update(b"degrad-id:");
        h.update(epoch.as_u64().to_le_bytes());
        h.update(dimension.to_string().as_bytes());
        h.update(timestamp_ns.to_le_bytes());
        format!("da-{}", hex::encode(&h.finalize()[..8]))
    }
}

// ---------------------------------------------------------------------------
// Demotion receipt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemotionReceipt {
    pub receipt_id: String,
    pub epoch: SecurityEpoch,
    pub trigger_artifact_id: String,
    pub dimension: QualityDimension,
    pub previous_mode: String,
    pub new_mode: DemotionTarget,
    pub rule_id: String,
    pub timestamp_ns: u64,
    pub content_hash: String,
}

impl DemotionReceipt {
    pub fn compute_id(epoch: SecurityEpoch, rule_id: &str, timestamp_ns: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"demotion-receipt:");
        h.update(epoch.as_u64().to_le_bytes());
        h.update(rule_id.as_bytes());
        h.update(timestamp_ns.to_le_bytes());
        format!("dr-{}", hex::encode(&h.finalize()[..8]))
    }

    pub fn compute_hash(
        epoch: SecurityEpoch,
        dimension: QualityDimension,
        new_mode: DemotionTarget,
        timestamp_ns: u64,
    ) -> String {
        let mut h = Sha256::new();
        h.update(b"demotion-hash:");
        h.update(epoch.as_u64().to_le_bytes());
        h.update(dimension.to_string().as_bytes());
        h.update(new_mode.to_string().as_bytes());
        h.update(timestamp_ns.to_le_bytes());
        hex::encode(&h.finalize()[..16])
    }
}

// ---------------------------------------------------------------------------
// Sentinel state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionState {
    pub dimension: QualityDimension,
    pub current_regime: DegradationRegime,
    pub sequential_test: SequentialTestState,
    pub last_value_millionths: Option<i64>,
    pub last_demotion_epoch: Option<SecurityEpoch>,
    pub active_demotion_target: Option<DemotionTarget>,
    pub degradation_count: u64,
    pub demotion_count: u64,
}

impl DimensionState {
    pub fn new(dimension: QualityDimension) -> Self {
        Self {
            dimension,
            current_regime: DegradationRegime::Nominal,
            sequential_test: SequentialTestState::new(dimension),
            last_value_millionths: None,
            last_demotion_epoch: None,
            active_demotion_target: None,
            degradation_count: 0,
            demotion_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Sentinel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservabilityQualitySentinel {
    pub policy: DemotionPolicy,
    pub dimension_states: Vec<DimensionState>,
    pub epoch: SecurityEpoch,
    pub total_observations: u64,
    pub total_degradation_artifacts: u64,
    pub total_demotion_receipts: u64,
}

impl ObservabilityQualitySentinel {
    pub fn new(policy: DemotionPolicy) -> Self {
        let epoch = policy.epoch;
        let dimension_states = policy
            .thresholds
            .iter()
            .map(|t| DimensionState::new(t.dimension))
            .collect();
        Self {
            policy,
            dimension_states,
            epoch,
            total_observations: 0,
            total_degradation_artifacts: 0,
            total_demotion_receipts: 0,
        }
    }

    pub fn observe(
        &mut self,
        obs: &QualityObservation,
    ) -> (Vec<DegradationArtifact>, Vec<DemotionReceipt>) {
        self.total_observations += 1;
        let mut artifacts = Vec::new();
        let mut receipts = Vec::new();

        let dim_state = match self
            .dimension_states
            .iter_mut()
            .find(|s| s.dimension == obs.dimension)
        {
            Some(s) => s,
            None => return (artifacts, receipts),
        };

        let threshold = match self.policy.threshold_for(obs.dimension) {
            Some(t) => t.clone(),
            None => return (artifacts, receipts),
        };

        dim_state.last_value_millionths = Some(obs.value_millionths);

        let new_regime = if threshold.is_breached(obs.value_millionths) {
            let emergency = match obs.dimension {
                QualityDimension::SignalFidelity => {
                    obs.value_millionths < threshold.limit_millionths / 2
                }
                _ => obs.value_millionths > threshold.limit_millionths * 2,
            };
            if emergency {
                DegradationRegime::Emergency
            } else {
                DegradationRegime::Breached
            }
        } else if threshold.is_warning(obs.value_millionths) {
            DegradationRegime::Elevated
        } else {
            DegradationRegime::Nominal
        };

        let newly_rejected = dim_state
            .sequential_test
            .update(&threshold, obs.value_millionths);
        let regime_worsened =
            regime_severity(new_regime) > regime_severity(dim_state.current_regime);
        dim_state.current_regime = new_regime;

        if regime_worsened || newly_rejected {
            dim_state.degradation_count += 1;
            self.total_degradation_artifacts += 1;

            let artifact_id =
                DegradationArtifact::compute_id(self.epoch, obs.dimension, obs.timestamp_ns);
            let content_hash = DegradationArtifact::compute_hash(
                self.epoch,
                obs.dimension,
                new_regime,
                obs.value_millionths,
                obs.timestamp_ns,
            );

            artifacts.push(DegradationArtifact {
                artifact_id: artifact_id.clone(),
                epoch: self.epoch,
                dimension: obs.dimension,
                regime: new_regime,
                observed_value_millionths: obs.value_millionths,
                threshold_millionths: threshold.limit_millionths,
                e_value_millionths: dim_state.sequential_test.e_value_millionths,
                cusum_millionths: dim_state.sequential_test.cusum_millionths,
                observation_count: dim_state.sequential_test.observation_count,
                timestamp_ns: obs.timestamp_ns,
                channel_id: obs.channel_id.clone(),
                content_hash,
            });

            let matching_rules: Vec<_> = self
                .policy
                .rules
                .iter()
                .filter(|r| r.trigger_dimension == obs.dimension && r.trigger_regime == new_regime)
                .collect();

            for rule in matching_rules {
                if let Some(last_epoch) = dim_state.last_demotion_epoch
                    && self.epoch.as_u64().saturating_sub(last_epoch.as_u64())
                        < rule.cooldown_epochs
                {
                    continue;
                }

                let receipt_id =
                    DemotionReceipt::compute_id(self.epoch, &rule.rule_id, obs.timestamp_ns);
                let content_hash = DemotionReceipt::compute_hash(
                    self.epoch,
                    obs.dimension,
                    rule.target,
                    obs.timestamp_ns,
                );
                let previous_mode = dim_state
                    .active_demotion_target
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "compressed".into());

                receipts.push(DemotionReceipt {
                    receipt_id,
                    epoch: self.epoch,
                    trigger_artifact_id: artifact_id.clone(),
                    dimension: obs.dimension,
                    previous_mode,
                    new_mode: rule.target,
                    rule_id: rule.rule_id.clone(),
                    timestamp_ns: obs.timestamp_ns,
                    content_hash,
                });

                dim_state.active_demotion_target = Some(rule.target);
                dim_state.last_demotion_epoch = Some(self.epoch);
                dim_state.demotion_count += 1;
                self.total_demotion_receipts += 1;
            }
        }

        if new_regime == DegradationRegime::Nominal {
            dim_state.sequential_test.reset();
            dim_state.active_demotion_target = None;
        }

        (artifacts, receipts)
    }

    pub fn advance_epoch(&mut self, new_epoch: SecurityEpoch) {
        self.epoch = new_epoch;
    }

    pub fn regime_for(&self, dim: QualityDimension) -> Option<DegradationRegime> {
        self.dimension_states
            .iter()
            .find(|s| s.dimension == dim)
            .map(|s| s.current_regime)
    }

    pub fn worst_regime(&self) -> DegradationRegime {
        self.dimension_states
            .iter()
            .map(|s| s.current_regime)
            .max_by_key(|r| regime_severity(*r))
            .unwrap_or(DegradationRegime::Nominal)
    }

    pub fn is_degraded(&self) -> bool {
        self.dimension_states.iter().any(|s| {
            regime_severity(s.current_regime) >= regime_severity(DegradationRegime::Breached)
        })
    }
}

// ---------------------------------------------------------------------------
// Sentinel report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionSummary {
    pub dimension: QualityDimension,
    pub current_regime: DegradationRegime,
    pub last_value_millionths: Option<i64>,
    pub e_value_millionths: i64,
    pub observation_count: u64,
    pub degradation_count: u64,
    pub demotion_count: u64,
    pub active_demotion: Option<DemotionTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelReport {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub overall_regime: DegradationRegime,
    pub total_observations: u64,
    pub total_degradation_artifacts: u64,
    pub total_demotion_receipts: u64,
    pub dimensions: Vec<DimensionSummary>,
    pub gate_pass: bool,
    pub content_hash: String,
}

impl SentinelReport {
    pub fn compute_hash(epoch: SecurityEpoch, gate_pass: bool, total_obs: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"sentinel-report:");
        h.update(epoch.as_u64().to_le_bytes());
        h.update(if gate_pass { b"pass" } else { b"fail" });
        h.update(total_obs.to_le_bytes());
        hex::encode(&h.finalize()[..16])
    }
}

pub fn generate_report(sentinel: &ObservabilityQualitySentinel) -> SentinelReport {
    let dimensions: Vec<DimensionSummary> = sentinel
        .dimension_states
        .iter()
        .map(|ds| DimensionSummary {
            dimension: ds.dimension,
            current_regime: ds.current_regime,
            last_value_millionths: ds.last_value_millionths,
            e_value_millionths: ds.sequential_test.e_value_millionths,
            observation_count: ds.sequential_test.observation_count,
            degradation_count: ds.degradation_count,
            demotion_count: ds.demotion_count,
            active_demotion: ds.active_demotion_target,
        })
        .collect();

    let overall = sentinel.worst_regime();
    let gate_pass = !sentinel.is_degraded();
    let content_hash =
        SentinelReport::compute_hash(sentinel.epoch, gate_pass, sentinel.total_observations);

    SentinelReport {
        schema_version: SCHEMA_VERSION.into(),
        epoch: sentinel.epoch,
        overall_regime: overall,
        total_observations: sentinel.total_observations,
        total_degradation_artifacts: sentinel.total_degradation_artifacts,
        total_demotion_receipts: sentinel.total_demotion_receipts,
        dimensions,
        gate_pass,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Canonical policy
// ---------------------------------------------------------------------------

pub fn canonical_demotion_policy(epoch: SecurityEpoch) -> DemotionPolicy {
    let thresholds = vec![
        QualityThreshold {
            dimension: QualityDimension::SignalFidelity,
            limit_millionths: DEFAULT_MIN_FIDELITY,
            warning_millionths: 900_000,
        },
        QualityThreshold {
            dimension: QualityDimension::BlindSpotRatio,
            limit_millionths: DEFAULT_MAX_BLIND_SPOT_RATIO,
            warning_millionths: 30_000,
        },
        QualityThreshold {
            dimension: QualityDimension::ReconstructionAmbiguity,
            limit_millionths: DEFAULT_MAX_RECONSTRUCTION_AMBIGUITY,
            warning_millionths: 70_000,
        },
        QualityThreshold {
            dimension: QualityDimension::TailUndercoverage,
            limit_millionths: DEFAULT_MAX_TAIL_UNDERCOVERAGE,
            warning_millionths: 100_000,
        },
        QualityThreshold {
            dimension: QualityDimension::EvidenceStaleness,
            limit_millionths: 200_000,
            warning_millionths: 150_000,
        },
    ];

    let rules = vec![
        DemotionRule {
            rule_id: "fidelity-breached-sampling".into(),
            trigger_dimension: QualityDimension::SignalFidelity,
            trigger_regime: DegradationRegime::Breached,
            target: DemotionTarget::IncreasedSampling,
            cooldown_epochs: 2,
            rationale: "Low fidelity triggers increased sampling".into(),
        },
        DemotionRule {
            rule_id: "fidelity-emergency-replay".into(),
            trigger_dimension: QualityDimension::SignalFidelity,
            trigger_regime: DegradationRegime::Emergency,
            target: DemotionTarget::FullReplayCapture,
            cooldown_epochs: 1,
            rationale: "Catastrophic fidelity loss triggers full replay".into(),
        },
        DemotionRule {
            rule_id: "blind-spot-breached-uncompressed".into(),
            trigger_dimension: QualityDimension::BlindSpotRatio,
            trigger_regime: DegradationRegime::Breached,
            target: DemotionTarget::UncompressedEvidence,
            cooldown_epochs: 3,
            rationale: "Blind spots require uncompressed evidence".into(),
        },
        DemotionRule {
            rule_id: "reconstruction-breached-uncompressed".into(),
            trigger_dimension: QualityDimension::ReconstructionAmbiguity,
            trigger_regime: DegradationRegime::Breached,
            target: DemotionTarget::UncompressedEvidence,
            cooldown_epochs: 3,
            rationale: "Ambiguous reconstruction requires raw evidence".into(),
        },
        DemotionRule {
            rule_id: "tail-breached-sampling".into(),
            trigger_dimension: QualityDimension::TailUndercoverage,
            trigger_regime: DegradationRegime::Breached,
            target: DemotionTarget::IncreasedSampling,
            cooldown_epochs: 2,
            rationale: "Tail undercoverage triggers increased sampling".into(),
        },
        DemotionRule {
            rule_id: "staleness-breached-replay".into(),
            trigger_dimension: QualityDimension::EvidenceStaleness,
            trigger_regime: DegradationRegime::Breached,
            target: DemotionTarget::FullReplayCapture,
            cooldown_epochs: 2,
            rationale: "Stale evidence triggers full replay capture".into(),
        },
    ];

    let policy_id = DemotionPolicy::compute_id(epoch, &rules);
    DemotionPolicy {
        policy_id,
        epoch,
        thresholds,
        rules,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn regime_severity(r: DegradationRegime) -> u32 {
    match r {
        DegradationRegime::Nominal => 0,
        DegradationRegime::Elevated => 1,
        DegradationRegime::Breached => 2,
        DegradationRegime::Emergency => 3,
    }
}

fn saturating_mul_div(a: i64, b: i64, c: i64) -> i64 {
    let result = (a as i128) * (b as i128) / (c as i128);
    result.clamp(i64::MIN as i128, i64::MAX as i128) as i64
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

    fn make_policy() -> DemotionPolicy {
        canonical_demotion_policy(test_epoch())
    }

    fn make_sentinel() -> ObservabilityQualitySentinel {
        ObservabilityQualitySentinel::new(make_policy())
    }

    fn qobs(dim: QualityDimension, value: i64, ts: u64) -> QualityObservation {
        QualityObservation {
            dimension: dim,
            value_millionths: value,
            timestamp_ns: ts,
            channel_id: "ch-test".into(),
        }
    }

    #[test]
    fn quality_dimension_all_five() {
        assert_eq!(QualityDimension::ALL.len(), 5);
    }

    #[test]
    fn quality_dimension_display() {
        assert_eq!(
            QualityDimension::SignalFidelity.to_string(),
            "signal_fidelity"
        );
        assert_eq!(
            QualityDimension::BlindSpotRatio.to_string(),
            "blind_spot_ratio"
        );
        assert_eq!(
            QualityDimension::ReconstructionAmbiguity.to_string(),
            "reconstruction_ambiguity"
        );
        assert_eq!(
            QualityDimension::TailUndercoverage.to_string(),
            "tail_undercoverage"
        );
        assert_eq!(
            QualityDimension::EvidenceStaleness.to_string(),
            "evidence_staleness"
        );
    }

    #[test]
    fn quality_dimension_serde_roundtrip() {
        for dim in &QualityDimension::ALL {
            let json = serde_json::to_string(dim).expect("serialize derived Serialize");
            let back: QualityDimension =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*dim, back);
        }
    }

    #[test]
    fn quality_dimension_ord() {
        assert!(QualityDimension::BlindSpotRatio > QualityDimension::SignalFidelity);
    }

    #[test]
    fn degradation_regime_display() {
        assert_eq!(DegradationRegime::Nominal.to_string(), "nominal");
        assert_eq!(DegradationRegime::Elevated.to_string(), "elevated");
        assert_eq!(DegradationRegime::Breached.to_string(), "breached");
        assert_eq!(DegradationRegime::Emergency.to_string(), "emergency");
    }

    #[test]
    fn degradation_regime_severity_ordering() {
        assert!(
            regime_severity(DegradationRegime::Emergency)
                > regime_severity(DegradationRegime::Breached)
        );
        assert!(
            regime_severity(DegradationRegime::Breached)
                > regime_severity(DegradationRegime::Elevated)
        );
        assert!(
            regime_severity(DegradationRegime::Elevated)
                > regime_severity(DegradationRegime::Nominal)
        );
    }

    #[test]
    fn degradation_regime_serde_roundtrip() {
        let json = serde_json::to_string(&DegradationRegime::Emergency)
            .expect("serialization should succeed");
        let back: DegradationRegime =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, DegradationRegime::Emergency);
    }

    #[test]
    fn demotion_target_severity_rank() {
        assert_eq!(DemotionTarget::IncreasedSampling.severity_rank(), 1);
        assert_eq!(DemotionTarget::UncompressedEvidence.severity_rank(), 2);
        assert_eq!(DemotionTarget::FullReplayCapture.severity_rank(), 3);
        assert_eq!(DemotionTarget::EmergencyRingBuffer.severity_rank(), 4);
    }

    #[test]
    fn demotion_target_display() {
        assert_eq!(
            DemotionTarget::IncreasedSampling.to_string(),
            "increased_sampling"
        );
        assert_eq!(
            DemotionTarget::FullReplayCapture.to_string(),
            "full_replay_capture"
        );
    }

    #[test]
    fn demotion_target_serde_roundtrip() {
        let json = serde_json::to_string(&DemotionTarget::UncompressedEvidence)
            .expect("serialization should succeed");
        let back: DemotionTarget =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back, DemotionTarget::UncompressedEvidence);
    }

    #[test]
    fn threshold_fidelity_breach_below() {
        let t = QualityThreshold {
            dimension: QualityDimension::SignalFidelity,
            limit_millionths: 800_000,
            warning_millionths: 900_000,
        };
        assert!(t.is_breached(700_000));
        assert!(!t.is_breached(900_000));
    }

    #[test]
    fn threshold_fidelity_warning() {
        let t = QualityThreshold {
            dimension: QualityDimension::SignalFidelity,
            limit_millionths: 800_000,
            warning_millionths: 900_000,
        };
        assert!(t.is_warning(850_000));
        assert!(!t.is_warning(950_000));
        assert!(!t.is_warning(700_000));
    }

    #[test]
    fn threshold_blind_spot_breach_above() {
        let t = QualityThreshold {
            dimension: QualityDimension::BlindSpotRatio,
            limit_millionths: 50_000,
            warning_millionths: 30_000,
        };
        assert!(t.is_breached(60_000));
        assert!(!t.is_breached(40_000));
    }

    #[test]
    fn threshold_blind_spot_warning() {
        let t = QualityThreshold {
            dimension: QualityDimension::BlindSpotRatio,
            limit_millionths: 50_000,
            warning_millionths: 30_000,
        };
        assert!(t.is_warning(40_000));
        assert!(!t.is_warning(20_000));
    }

    #[test]
    fn sequential_test_starts_not_rejected() {
        let st = SequentialTestState::new(QualityDimension::SignalFidelity);
        assert!(!st.rejected);
        assert_eq!(st.e_value_millionths, MILLION);
        assert_eq!(st.cusum_millionths, 0);
    }

    #[test]
    fn sequential_test_good_observations_no_rejection() {
        let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
        let threshold = QualityThreshold {
            dimension: QualityDimension::SignalFidelity,
            limit_millionths: 800_000,
            warning_millionths: 900_000,
        };
        for i in 0..20 {
            let rejected = st.update(&threshold, 950_000);
            assert!(!rejected, "should not reject on good observation {i}");
        }
        assert!(!st.rejected);
    }

    #[test]
    fn sequential_test_bad_observations_eventually_reject() {
        let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
        let threshold = QualityThreshold {
            dimension: QualityDimension::SignalFidelity,
            limit_millionths: 800_000,
            warning_millionths: 900_000,
        };
        let mut rejected = false;
        for _ in 0..50 {
            if st.update(&threshold, 500_000) {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        assert!(st.rejected);
    }

    #[test]
    fn sequential_test_reset_clears_state() {
        let mut st = SequentialTestState::new(QualityDimension::BlindSpotRatio);
        st.cusum_millionths = 500_000;
        st.e_value_millionths = 10 * MILLION;
        st.observation_count = 100;
        st.rejected = true;
        st.reset();
        assert_eq!(st.cusum_millionths, 0);
        assert_eq!(st.e_value_millionths, MILLION);
        assert_eq!(st.observation_count, 0);
        assert!(!st.rejected);
    }

    #[test]
    fn sequential_test_needs_min_observations() {
        let mut st = SequentialTestState::new(QualityDimension::SignalFidelity);
        let threshold = QualityThreshold {
            dimension: QualityDimension::SignalFidelity,
            limit_millionths: 800_000,
            warning_millionths: 900_000,
        };
        for _ in 0..MIN_OBSERVATIONS_FOR_TEST.saturating_sub(1) {
            st.update(&threshold, 0);
        }
        assert!(!st.rejected);
    }

    #[test]
    fn canonical_policy_has_all_dimensions() {
        let policy = make_policy();
        for dim in &QualityDimension::ALL {
            assert!(
                policy.threshold_for(*dim).is_some(),
                "missing threshold for {dim}"
            );
        }
    }

    #[test]
    fn canonical_policy_has_rules() {
        let policy = make_policy();
        assert_eq!(policy.rules.len(), 6);
    }

    #[test]
    fn policy_id_deterministic() {
        let p1 = make_policy();
        let p2 = make_policy();
        assert_eq!(p1.policy_id, p2.policy_id);
    }

    #[test]
    fn policy_rules_for_dimension() {
        let policy = make_policy();
        let rules = policy.rules_for(
            QualityDimension::SignalFidelity,
            DegradationRegime::Breached,
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].target, DemotionTarget::IncreasedSampling);
    }

    #[test]
    fn policy_max_demotion_severity() {
        let policy = make_policy();
        let max = policy
            .max_demotion_severity()
            .expect("operation should succeed for valid inputs");
        assert_eq!(max, DemotionTarget::FullReplayCapture);
    }

    #[test]
    fn degradation_artifact_id_deterministic() {
        let id1 =
            DegradationArtifact::compute_id(test_epoch(), QualityDimension::SignalFidelity, 1000);
        let id2 =
            DegradationArtifact::compute_id(test_epoch(), QualityDimension::SignalFidelity, 1000);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("da-"));
    }

    #[test]
    fn degradation_artifact_hash_deterministic() {
        let h1 = DegradationArtifact::compute_hash(
            test_epoch(),
            QualityDimension::BlindSpotRatio,
            DegradationRegime::Breached,
            60_000,
            1000,
        );
        let h2 = DegradationArtifact::compute_hash(
            test_epoch(),
            QualityDimension::BlindSpotRatio,
            DegradationRegime::Breached,
            60_000,
            1000,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn degradation_artifact_different_inputs_different_hash() {
        let h1 = DegradationArtifact::compute_hash(
            test_epoch(),
            QualityDimension::BlindSpotRatio,
            DegradationRegime::Breached,
            60_000,
            1000,
        );
        let h2 = DegradationArtifact::compute_hash(
            test_epoch(),
            QualityDimension::TailUndercoverage,
            DegradationRegime::Breached,
            60_000,
            1000,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn demotion_receipt_id_deterministic() {
        let id1 = DemotionReceipt::compute_id(test_epoch(), "rule-1", 1000);
        let id2 = DemotionReceipt::compute_id(test_epoch(), "rule-1", 1000);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("dr-"));
    }

    #[test]
    fn demotion_receipt_hash_deterministic() {
        let h1 = DemotionReceipt::compute_hash(
            test_epoch(),
            QualityDimension::SignalFidelity,
            DemotionTarget::IncreasedSampling,
            1000,
        );
        let h2 = DemotionReceipt::compute_hash(
            test_epoch(),
            QualityDimension::SignalFidelity,
            DemotionTarget::IncreasedSampling,
            1000,
        );
        assert_eq!(h1, h2);
    }

    #[test]
    fn sentinel_starts_nominal() {
        let sentinel = make_sentinel();
        assert_eq!(sentinel.worst_regime(), DegradationRegime::Nominal);
        assert!(!sentinel.is_degraded());
        assert_eq!(sentinel.total_observations, 0);
    }

    #[test]
    fn sentinel_good_observation_stays_nominal() {
        let mut sentinel = make_sentinel();
        let (artifacts, receipts) =
            sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 100));
        assert!(artifacts.is_empty());
        assert!(receipts.is_empty());
        assert_eq!(sentinel.worst_regime(), DegradationRegime::Nominal);
        assert_eq!(sentinel.total_observations, 1);
    }

    #[test]
    fn sentinel_breach_triggers_degradation_artifact() {
        let mut sentinel = make_sentinel();
        let (artifacts, _) =
            sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].regime, DegradationRegime::Breached);
    }

    #[test]
    fn sentinel_breach_triggers_demotion_receipt() {
        let mut sentinel = make_sentinel();
        let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].new_mode, DemotionTarget::IncreasedSampling);
    }

    #[test]
    fn sentinel_emergency_triggers_replay_capture() {
        let mut sentinel = make_sentinel();
        let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 300_000, 100));
        let replay: Vec<_> = receipts
            .iter()
            .filter(|r| r.new_mode == DemotionTarget::FullReplayCapture)
            .collect();
        assert!(!replay.is_empty());
    }

    #[test]
    fn sentinel_blind_spot_breach() {
        let mut sentinel = make_sentinel();
        let (artifacts, receipts) =
            sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 60_000, 100));
        assert_eq!(artifacts.len(), 1);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].new_mode, DemotionTarget::UncompressedEvidence);
    }

    #[test]
    fn sentinel_cooldown_prevents_repeated_demotion() {
        let mut sentinel = make_sentinel();
        let (_, r1) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        assert_eq!(r1.len(), 1);
        let (_, r2) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 650_000, 200));
        assert!(r2.is_empty());
    }

    #[test]
    fn sentinel_recovery_resets_to_nominal() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        assert_eq!(
            sentinel.regime_for(QualityDimension::SignalFidelity),
            Some(DegradationRegime::Breached)
        );
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 200));
        assert_eq!(
            sentinel.regime_for(QualityDimension::SignalFidelity),
            Some(DegradationRegime::Nominal)
        );
    }

    #[test]
    fn sentinel_advance_epoch() {
        let mut sentinel = make_sentinel();
        sentinel.advance_epoch(SecurityEpoch::from_raw(43));
        assert_eq!(sentinel.epoch.as_u64(), 43);
    }

    #[test]
    fn sentinel_is_degraded_when_breached() {
        let mut sentinel = make_sentinel();
        assert!(!sentinel.is_degraded());
        sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 60_000, 100));
        assert!(sentinel.is_degraded());
    }

    #[test]
    fn sentinel_worst_regime_across_dims() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 850_000, 100));
        sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 60_000, 200));
        assert_eq!(sentinel.worst_regime(), DegradationRegime::Breached);
    }

    #[test]
    fn sentinel_multiple_dimensions_independent() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        sentinel.observe(&qobs(QualityDimension::TailUndercoverage, 200_000, 200));
        assert_eq!(
            sentinel.regime_for(QualityDimension::SignalFidelity),
            Some(DegradationRegime::Breached)
        );
        assert_eq!(
            sentinel.regime_for(QualityDimension::TailUndercoverage),
            Some(DegradationRegime::Breached)
        );
    }

    #[test]
    fn sentinel_warning_regime_no_demotion() {
        let mut sentinel = make_sentinel();
        let (artifacts, receipts) =
            sentinel.observe(&qobs(QualityDimension::SignalFidelity, 850_000, 100));
        assert_eq!(artifacts.len(), 1);
        assert!(receipts.is_empty());
        assert_eq!(
            sentinel.regime_for(QualityDimension::SignalFidelity),
            Some(DegradationRegime::Elevated)
        );
    }

    #[test]
    fn sentinel_observation_count_increments() {
        let mut sentinel = make_sentinel();
        for i in 0..5 {
            sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, i * 100));
        }
        assert_eq!(sentinel.total_observations, 5);
    }

    #[test]
    fn report_nominal_gate_passes() {
        let sentinel = make_sentinel();
        let report = generate_report(&sentinel);
        assert!(report.gate_pass);
        assert_eq!(report.overall_regime, DegradationRegime::Nominal);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn report_degraded_gate_fails() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        let report = generate_report(&sentinel);
        assert!(!report.gate_pass);
        assert_eq!(report.overall_regime, DegradationRegime::Breached);
    }

    #[test]
    fn report_hash_deterministic() {
        let h1 = SentinelReport::compute_hash(test_epoch(), true, 100);
        let h2 = SentinelReport::compute_hash(test_epoch(), true, 100);
        assert_eq!(h1, h2);
    }

    #[test]
    fn report_hash_differs_on_gate_pass() {
        let h1 = SentinelReport::compute_hash(test_epoch(), true, 100);
        let h2 = SentinelReport::compute_hash(test_epoch(), false, 100);
        assert_ne!(h1, h2);
    }

    #[test]
    fn report_dimensions_match_policy() {
        let sentinel = make_sentinel();
        let report = generate_report(&sentinel);
        assert_eq!(report.dimensions.len(), 5);
    }

    #[test]
    fn report_serde_roundtrip() {
        let sentinel = make_sentinel();
        let report = generate_report(&sentinel);
        let json = serde_json::to_string(&report).expect("serialize derived Serialize");
        let back: SentinelReport =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.epoch.as_u64(), report.epoch.as_u64());
        assert_eq!(back.gate_pass, report.gate_pass);
    }

    #[test]
    fn report_captures_demotion_counts() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        let report = generate_report(&sentinel);
        assert!(report.total_demotion_receipts > 0);
        assert!(report.total_degradation_artifacts > 0);
    }

    #[test]
    fn saturating_mul_div_basic() {
        assert_eq!(
            saturating_mul_div(MILLION, 2 * MILLION, MILLION),
            2 * MILLION
        );
    }

    #[test]
    fn saturating_mul_div_no_overflow() {
        let result = saturating_mul_div(i64::MAX / 2, 2 * MILLION, MILLION);
        assert!(result > 0);
    }

    #[test]
    fn dimension_state_starts_nominal() {
        let ds = DimensionState::new(QualityDimension::SignalFidelity);
        assert_eq!(ds.current_regime, DegradationRegime::Nominal);
        assert_eq!(ds.degradation_count, 0);
        assert!(ds.last_value_millionths.is_none());
    }

    #[test]
    fn sequential_test_cusum_accumulates_bad() {
        let mut st = SequentialTestState::new(QualityDimension::BlindSpotRatio);
        let threshold = QualityThreshold {
            dimension: QualityDimension::BlindSpotRatio,
            limit_millionths: 50_000,
            warning_millionths: 30_000,
        };
        st.update(&threshold, 80_000);
        assert!(st.cusum_millionths > 0);
    }

    #[test]
    fn sequential_test_cusum_resets_on_good() {
        let mut st = SequentialTestState::new(QualityDimension::BlindSpotRatio);
        let threshold = QualityThreshold {
            dimension: QualityDimension::BlindSpotRatio,
            limit_millionths: 50_000,
            warning_millionths: 30_000,
        };
        st.update(&threshold, 80_000);
        st.update(&threshold, 10_000);
        assert_eq!(st.cusum_millionths, 0);
    }

    #[test]
    fn reconstruction_ambiguity_breach() {
        let mut sentinel = make_sentinel();
        let (artifacts, receipts) = sentinel.observe(&qobs(
            QualityDimension::ReconstructionAmbiguity,
            150_000,
            100,
        ));
        assert_eq!(artifacts.len(), 1);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].new_mode, DemotionTarget::UncompressedEvidence);
    }

    #[test]
    fn staleness_breach_triggers_replay() {
        let mut sentinel = make_sentinel();
        let (_, receipts) =
            sentinel.observe(&qobs(QualityDimension::EvidenceStaleness, 250_000, 100));
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].new_mode, DemotionTarget::FullReplayCapture);
    }

    #[test]
    fn epoch_cooldown_respected_after_advance() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 200));
        sentinel.advance_epoch(SecurityEpoch::from_raw(43));
        let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 300));
        assert!(receipts.is_empty(), "cooldown should prevent demotion");
    }

    #[test]
    fn epoch_cooldown_expires_after_enough_epochs() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 950_000, 200));
        sentinel.advance_epoch(SecurityEpoch::from_raw(45));
        let (_, receipts) = sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 300));
        assert!(!receipts.is_empty(), "cooldown should have expired");
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn quality_dimension_serde_all_variants() {
        for v in &QualityDimension::ALL {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: QualityDimension =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn quality_dimension_display_distinct() {
        let set: std::collections::BTreeSet<String> = QualityDimension::ALL
            .iter()
            .map(|d| format!("{d}"))
            .collect();
        assert_eq!(set.len(), QualityDimension::ALL.len());
    }

    #[test]
    fn degradation_regime_serde_all_variants() {
        let variants = [
            DegradationRegime::Nominal,
            DegradationRegime::Elevated,
            DegradationRegime::Breached,
            DegradationRegime::Emergency,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: DegradationRegime =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn degradation_regime_display_distinct() {
        let all = [
            DegradationRegime::Nominal,
            DegradationRegime::Elevated,
            DegradationRegime::Breached,
            DegradationRegime::Emergency,
        ];
        let set: std::collections::BTreeSet<String> = all.iter().map(|r| format!("{r}")).collect();
        assert_eq!(set.len(), all.len());
    }

    #[test]
    fn demotion_target_serde_all_variants() {
        let variants = [
            DemotionTarget::IncreasedSampling,
            DemotionTarget::UncompressedEvidence,
            DemotionTarget::FullReplayCapture,
            DemotionTarget::EmergencyRingBuffer,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).expect("serialize derived Serialize");
            let back: DemotionTarget =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn demotion_target_severity_rank_monotonic() {
        assert!(
            DemotionTarget::IncreasedSampling.severity_rank()
                < DemotionTarget::UncompressedEvidence.severity_rank()
        );
        assert!(
            DemotionTarget::UncompressedEvidence.severity_rank()
                < DemotionTarget::FullReplayCapture.severity_rank()
        );
        assert!(
            DemotionTarget::FullReplayCapture.severity_rank()
                < DemotionTarget::EmergencyRingBuffer.severity_rank()
        );
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn enrichment_quality_dimension_copy_semantics() {
        let a = QualityDimension::SignalFidelity;
        let b = a;
        assert_eq!(a, b);
        // a is still usable after copy
        assert_eq!(a.to_string(), "signal_fidelity");
    }

    #[test]
    fn enrichment_degradation_regime_copy_semantics() {
        let a = DegradationRegime::Emergency;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.to_string(), "emergency");
    }

    #[test]
    fn enrichment_demotion_target_copy_semantics() {
        let a = DemotionTarget::EmergencyRingBuffer;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(a.severity_rank(), 4);
    }

    #[test]
    fn enrichment_quality_dimension_hash_in_btreeset() {
        let mut set = std::collections::BTreeSet::new();
        for dim in &QualityDimension::ALL {
            assert!(set.insert(*dim));
        }
        assert_eq!(set.len(), 5);
        // inserting duplicates does not grow the set
        for dim in &QualityDimension::ALL {
            assert!(!set.insert(*dim));
        }
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn enrichment_degradation_regime_hash_in_btreeset() {
        let variants = [
            DegradationRegime::Nominal,
            DegradationRegime::Elevated,
            DegradationRegime::Breached,
            DegradationRegime::Emergency,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(set.insert(*v));
        }
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn enrichment_demotion_target_ord_deterministic() {
        let mut targets = vec![
            DemotionTarget::EmergencyRingBuffer,
            DemotionTarget::IncreasedSampling,
            DemotionTarget::FullReplayCapture,
            DemotionTarget::UncompressedEvidence,
        ];
        targets.sort();
        let sorted_again = {
            let mut v = targets.clone();
            v.sort();
            v
        };
        assert_eq!(targets, sorted_again);
    }

    #[test]
    fn enrichment_degradation_regime_ord_deterministic() {
        let mut regimes = vec![
            DegradationRegime::Emergency,
            DegradationRegime::Nominal,
            DegradationRegime::Breached,
            DegradationRegime::Elevated,
        ];
        regimes.sort();
        let first_sort = regimes.clone();
        regimes.sort();
        assert_eq!(regimes, first_sort);
    }

    #[test]
    fn enrichment_quality_observation_serde_roundtrip() {
        let obs = qobs(QualityDimension::TailUndercoverage, 123_456, 9999);
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        let back: QualityObservation =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.dimension, QualityDimension::TailUndercoverage);
        assert_eq!(back.value_millionths, 123_456);
        assert_eq!(back.timestamp_ns, 9999);
        assert_eq!(back.channel_id, "ch-test");
    }

    #[test]
    fn enrichment_quality_observation_json_field_names() {
        let obs = qobs(QualityDimension::SignalFidelity, 500_000, 42);
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        assert!(json.contains("\"dimension\""));
        assert!(json.contains("\"value_millionths\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"channel_id\""));
    }

    #[test]
    fn enrichment_quality_threshold_serde_roundtrip() {
        let t = QualityThreshold {
            dimension: QualityDimension::EvidenceStaleness,
            limit_millionths: 200_000,
            warning_millionths: 150_000,
        };
        let json = serde_json::to_string(&t).expect("serialize derived Serialize");
        let back: QualityThreshold =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.dimension, QualityDimension::EvidenceStaleness);
        assert_eq!(back.limit_millionths, 200_000);
        assert_eq!(back.warning_millionths, 150_000);
    }

    #[test]
    fn enrichment_threshold_at_exact_boundary_fidelity() {
        let t = QualityThreshold {
            dimension: QualityDimension::SignalFidelity,
            limit_millionths: 800_000,
            warning_millionths: 900_000,
        };
        // value exactly at limit: not breached (< is breach for fidelity)
        assert!(!t.is_breached(800_000));
        // value exactly at warning: not warning (< is warning for fidelity)
        assert!(!t.is_warning(900_000));
        // value one below limit: breached
        assert!(t.is_breached(799_999));
        // value one below warning but above limit: warning
        assert!(t.is_warning(899_999));
    }

    #[test]
    fn enrichment_threshold_at_exact_boundary_non_fidelity() {
        let t = QualityThreshold {
            dimension: QualityDimension::BlindSpotRatio,
            limit_millionths: 50_000,
            warning_millionths: 30_000,
        };
        // value exactly at limit: not breached (> is breach for non-fidelity)
        assert!(!t.is_breached(50_000));
        // value one above limit: breached
        assert!(t.is_breached(50_001));
        // value exactly at warning: not warning
        assert!(!t.is_warning(30_000));
        // value one above warning but below limit: warning
        assert!(t.is_warning(30_001));
    }

    #[test]
    fn enrichment_demotion_rule_serde_roundtrip() {
        let rule = DemotionRule {
            rule_id: "test-rule-42".into(),
            trigger_dimension: QualityDimension::ReconstructionAmbiguity,
            trigger_regime: DegradationRegime::Emergency,
            target: DemotionTarget::EmergencyRingBuffer,
            cooldown_epochs: 5,
            rationale: "test rationale".into(),
        };
        let json = serde_json::to_string(&rule).expect("serialize derived Serialize");
        let back: DemotionRule = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.rule_id, "test-rule-42");
        assert_eq!(
            back.trigger_dimension,
            QualityDimension::ReconstructionAmbiguity
        );
        assert_eq!(back.trigger_regime, DegradationRegime::Emergency);
        assert_eq!(back.target, DemotionTarget::EmergencyRingBuffer);
        assert_eq!(back.cooldown_epochs, 5);
        assert_eq!(back.rationale, "test rationale");
    }

    #[test]
    fn enrichment_demotion_policy_serde_roundtrip() {
        let policy = make_policy();
        let json = serde_json::to_string(&policy).expect("serialize derived Serialize");
        let back: DemotionPolicy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.policy_id, policy.policy_id);
        assert_eq!(back.epoch.as_u64(), policy.epoch.as_u64());
        assert_eq!(back.thresholds.len(), policy.thresholds.len());
        assert_eq!(back.rules.len(), policy.rules.len());
    }

    #[test]
    fn enrichment_demotion_policy_compute_id_varies_with_epoch() {
        let p1 = canonical_demotion_policy(SecurityEpoch::from_raw(1));
        let p2 = canonical_demotion_policy(SecurityEpoch::from_raw(2));
        assert_ne!(p1.policy_id, p2.policy_id);
    }

    #[test]
    fn enrichment_degradation_artifact_hash_varies_on_regime() {
        let h1 = DegradationArtifact::compute_hash(
            test_epoch(),
            QualityDimension::SignalFidelity,
            DegradationRegime::Breached,
            700_000,
            1000,
        );
        let h2 = DegradationArtifact::compute_hash(
            test_epoch(),
            QualityDimension::SignalFidelity,
            DegradationRegime::Emergency,
            700_000,
            1000,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn enrichment_demotion_receipt_hash_varies_on_target() {
        let h1 = DemotionReceipt::compute_hash(
            test_epoch(),
            QualityDimension::SignalFidelity,
            DemotionTarget::IncreasedSampling,
            1000,
        );
        let h2 = DemotionReceipt::compute_hash(
            test_epoch(),
            QualityDimension::SignalFidelity,
            DemotionTarget::FullReplayCapture,
            1000,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn enrichment_sentinel_observe_unknown_dimension_no_effect() {
        // Build a policy with only one threshold (SignalFidelity).
        let policy = DemotionPolicy {
            policy_id: "test".into(),
            epoch: test_epoch(),
            thresholds: vec![QualityThreshold {
                dimension: QualityDimension::SignalFidelity,
                limit_millionths: 800_000,
                warning_millionths: 900_000,
            }],
            rules: vec![],
        };
        let mut sentinel = ObservabilityQualitySentinel::new(policy);
        // Observe on a dimension not in the policy
        let (artifacts, receipts) =
            sentinel.observe(&qobs(QualityDimension::EvidenceStaleness, 999_999, 100));
        assert!(artifacts.is_empty());
        assert!(receipts.is_empty());
        // Observation count still increments
        assert_eq!(sentinel.total_observations, 1);
    }

    #[test]
    fn enrichment_dimension_state_clone_independence() {
        let mut ds = DimensionState::new(QualityDimension::BlindSpotRatio);
        ds.degradation_count = 7;
        ds.last_value_millionths = Some(42_000);
        let cloned = ds.clone();
        ds.degradation_count = 99;
        ds.last_value_millionths = Some(0);
        assert_eq!(ds.degradation_count, 99);
        assert_eq!(ds.last_value_millionths, Some(0));
        // Clone is independent of original mutations
        assert_eq!(cloned.degradation_count, 7);
        assert_eq!(cloned.last_value_millionths, Some(42_000));
    }

    #[test]
    fn enrichment_sentinel_serde_full_roundtrip() {
        let mut sentinel = make_sentinel();
        sentinel.observe(&qobs(QualityDimension::SignalFidelity, 700_000, 100));
        sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 60_000, 200));
        let json = serde_json::to_string(&sentinel).expect("serialize derived Serialize");
        let back: ObservabilityQualitySentinel =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.epoch.as_u64(), sentinel.epoch.as_u64());
        assert_eq!(back.total_observations, sentinel.total_observations);
        assert_eq!(
            back.total_degradation_artifacts,
            sentinel.total_degradation_artifacts
        );
        assert_eq!(
            back.total_demotion_receipts,
            sentinel.total_demotion_receipts
        );
        assert_eq!(back.dimension_states.len(), sentinel.dimension_states.len());
    }

    #[test]
    fn enrichment_dimension_summary_json_field_names() {
        let sentinel = make_sentinel();
        let report = generate_report(&sentinel);
        let json = serde_json::to_string(&report.dimensions[0])
            .expect("serialization should succeed");
        assert!(json.contains("\"dimension\""));
        assert!(json.contains("\"current_regime\""));
        assert!(json.contains("\"last_value_millionths\""));
        assert!(json.contains("\"e_value_millionths\""));
        assert!(json.contains("\"observation_count\""));
        assert!(json.contains("\"degradation_count\""));
        assert!(json.contains("\"demotion_count\""));
        assert!(json.contains("\"active_demotion\""));
    }

    #[test]
    fn enrichment_demotion_target_display_all_variants() {
        assert_eq!(
            DemotionTarget::UncompressedEvidence.to_string(),
            "uncompressed_evidence"
        );
        assert_eq!(
            DemotionTarget::EmergencyRingBuffer.to_string(),
            "emergency_ring_buffer"
        );
    }

    #[test]
    fn enrichment_report_hash_varies_on_total_obs() {
        let h1 = SentinelReport::compute_hash(test_epoch(), true, 100);
        let h2 = SentinelReport::compute_hash(test_epoch(), true, 101);
        assert_ne!(h1, h2);
    }

    #[test]
    fn enrichment_sentinel_emergency_fidelity_below_half_limit() {
        let mut sentinel = make_sentinel();
        // limit is 800_000; half is 400_000; value 399_999 should trigger Emergency
        let (artifacts, _) =
            sentinel.observe(&qobs(QualityDimension::SignalFidelity, 399_999, 100));
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].regime, DegradationRegime::Emergency);
    }

    #[test]
    fn enrichment_sentinel_non_fidelity_emergency_above_double_limit() {
        let mut sentinel = make_sentinel();
        // BlindSpotRatio limit is 50_000; double is 100_000; value 100_001 should trigger Emergency
        let (artifacts, _) =
            sentinel.observe(&qobs(QualityDimension::BlindSpotRatio, 100_001, 100));
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].regime, DegradationRegime::Emergency);
    }
}
