#![forbid(unsafe_code)]

//! Timescale-separation certificates and bifurcation detectors for controller
//! compositions.
//!
//! Bead: bd-1lsy.7.14.2 [RGC-614B]
//!
//! Turns controller telemetry into actionable stability evidence:
//! timescale-separation certificates that prove concurrent controllers operate
//! at safely distinct frequencies, instability precursors from spectral edge
//! drift, and concrete bifurcation witnesses that show exactly where a
//! composition would break.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const TIMESCALE_CERTIFICATE_SCHEMA_VERSION: &str =
    "franken-engine.timescale-separation-certificate.v1";
pub const TIMESCALE_CERTIFICATE_BEAD_ID: &str = "bd-1lsy.7.14.2";
pub const BIFURCATION_DETECTOR_SCHEMA_VERSION: &str =
    "franken-engine.composition-bifurcation-detector.v1";
pub const CERTIFICATE_BUNDLE_SCHEMA_VERSION: &str =
    "franken-engine.timescale-certificate-bundle.v1";
pub const STABILITY_WITNESS_SCHEMA_VERSION: &str =
    "franken-engine.composition-stability-witness.v1";

/// Minimum timescale ratio for "sufficient" separation (10x).
pub const DEFAULT_SUFFICIENT_RATIO_MILLIONTHS: u64 = 10_000_000;
/// Minimum ratio for "marginal" (between marginal and sufficient).
pub const DEFAULT_MARGINAL_RATIO_MILLIONTHS: u64 = 3_000_000;

// ---------------------------------------------------------------------------
// Controller pair identity
// ---------------------------------------------------------------------------

/// Identifies a pair of controllers in a composition.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ControllerPairId {
    /// The faster controller (shorter interval).
    pub fast_controller: String,
    /// The slower controller (longer interval).
    pub slow_controller: String,
}

impl fmt::Display for ControllerPairId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}↔{}", self.fast_controller, self.slow_controller)
    }
}

// ---------------------------------------------------------------------------
// Timescale measurement
// ---------------------------------------------------------------------------

/// Measured timescale characteristics of a controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerTimescaleProfile {
    /// Controller identifier.
    pub controller_id: String,
    /// Observation interval in fixed-point millionths of one second.
    pub observation_interval_millionths: i64,
    /// Write/mutation interval in fixed-point millionths of one second.
    pub write_interval_millionths: i64,
    /// Number of observations in the measurement window.
    pub sample_count: u64,
    /// Epoch at which this profile was measured.
    pub measured_epoch: u64,
}

/// Timescale ratio between two controllers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimescaleRatio {
    /// The pair being compared.
    pub pair: ControllerPairId,
    /// Ratio of slow interval to fast interval, in millionths.
    /// A value of 10_000_000 means the slow controller is 10x slower.
    pub ratio_millionths: u64,
    /// Which interval was used for the ratio (observation or write).
    pub ratio_basis: RatioBasis,
}

/// Which interval type was used for the ratio computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RatioBasis {
    /// Ratio of observation intervals.
    Observation,
    /// Ratio of write intervals.
    Write,
    /// Minimum of observation and write ratios (conservative).
    MinimumOf,
}

impl fmt::Display for RatioBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Observation => "observation",
            Self::Write => "write",
            Self::MinimumOf => "minimum_of",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Separation verdict
// ---------------------------------------------------------------------------

/// Verdict on whether two controllers have sufficient timescale separation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparationVerdict {
    /// Timescales are well-separated (ratio >= sufficient threshold).
    Sufficient,
    /// Timescales have some separation but below the safe threshold.
    Marginal,
    /// Timescales are too close — risk of coupled oscillation.
    Insufficient,
}

impl fmt::Display for SeparationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Sufficient => "sufficient",
            Self::Marginal => "marginal",
            Self::Insufficient => "insufficient",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Timescale-separation certificate
// ---------------------------------------------------------------------------

/// A certificate proving that a pair of controllers has (or lacks) sufficient
/// timescale separation for safe concurrent operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimescaleSeparationCertificate {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Unique certificate identifier.
    pub certificate_id: String,
    /// The controller pair.
    pub pair: ControllerPairId,
    /// Measured timescale ratio.
    pub ratio: TimescaleRatio,
    /// Verdict.
    pub verdict: SeparationVerdict,
    /// Sufficient-ratio threshold used (millionths).
    pub sufficient_threshold_millionths: u64,
    /// Marginal-ratio threshold used (millionths).
    pub marginal_threshold_millionths: u64,
    /// Fast controller profile snapshot.
    pub fast_profile: ControllerTimescaleProfile,
    /// Slow controller profile snapshot.
    pub slow_profile: ControllerTimescaleProfile,
    /// Epoch at which the certificate was issued.
    pub issued_epoch: u64,
    /// Evidence artifact IDs supporting this certificate.
    pub evidence_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Certificate bundle (for a full composition)
// ---------------------------------------------------------------------------

/// Bundle of all pairwise certificates for a controller composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateBundle {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// All pairwise certificates.
    pub certificates: Vec<TimescaleSeparationCertificate>,
    /// Overall verdict (worst-case across all pairs).
    pub overall_verdict: SeparationVerdict,
    /// Epoch at which the bundle was computed.
    pub bundle_epoch: u64,
    /// Number of controller pairs.
    pub pair_count: usize,
    /// Number of sufficient pairs.
    pub sufficient_count: usize,
    /// Number of marginal pairs.
    pub marginal_count: usize,
    /// Number of insufficient pairs.
    pub insufficient_count: usize,
}

// ---------------------------------------------------------------------------
// Bifurcation signal types
// ---------------------------------------------------------------------------

/// Classification of bifurcation signals in controller compositions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BifurcationSignalKind {
    /// Oscillation amplitude is growing between cycles.
    GrowingOscillation,
    /// Two controllers are drifting into the same timescale.
    TimescaleConvergence,
    /// A spectral edge is crossing the instability boundary.
    SpectralEdgeCrossing,
    /// Controller output variance is increasing across epochs.
    VarianceDivergence,
    /// The effective gain of a feedback loop exceeds unity.
    GainExceedance,
}

impl fmt::Display for BifurcationSignalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::GrowingOscillation => "growing_oscillation",
            Self::TimescaleConvergence => "timescale_convergence",
            Self::SpectralEdgeCrossing => "spectral_edge_crossing",
            Self::VarianceDivergence => "variance_divergence",
            Self::GainExceedance => "gain_exceedance",
        };
        write!(f, "{label}")
    }
}

/// Severity of a bifurcation signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalSeverity {
    /// Informational — early detection, no action needed yet.
    Info,
    /// Warning — approaching instability, monitoring recommended.
    Warning,
    /// Critical — at or past the bifurcation boundary.
    Critical,
}

impl fmt::Display for SignalSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        };
        write!(f, "{label}")
    }
}

/// A detected bifurcation signal in a controller composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BifurcationSignal {
    /// Signal identifier.
    pub signal_id: String,
    /// Which pair triggered the signal.
    pub pair: ControllerPairId,
    /// Kind of bifurcation signal.
    pub kind: BifurcationSignalKind,
    /// Severity level.
    pub severity: SignalSeverity,
    /// Measured value that triggered the signal (millionths).
    pub trigger_value_millionths: i64,
    /// Threshold value that was crossed (millionths).
    pub threshold_millionths: i64,
    /// Epoch at which the signal was detected.
    pub detected_epoch: u64,
    /// Human-readable description.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Stability witness
// ---------------------------------------------------------------------------

/// Minimal evidence of instability in a controller composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StabilityWitness {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Witness identifier.
    pub witness_id: String,
    /// The pair exhibiting instability.
    pub pair: ControllerPairId,
    /// The primary signal that evidences instability.
    pub primary_signal: BifurcationSignal,
    /// Supporting signals (corroborating evidence).
    pub supporting_signals: Vec<BifurcationSignal>,
    /// Recommended action.
    pub recommended_action: RecommendedAction,
    /// Epoch at which the witness was assembled.
    pub assembled_epoch: u64,
}

/// Recommended action in response to a stability witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Continue monitoring — signal is informational.
    Monitor,
    /// Increase timescale separation between the pair.
    IncreaseTimescaleSeparation,
    /// Reduce one controller's gain/aggressiveness.
    ReduceGain,
    /// Disable one of the conflicting controllers.
    DisableController,
    /// Fall back to safe-mode routing.
    SafeModeFallback,
}

impl fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Monitor => "monitor",
            Self::IncreaseTimescaleSeparation => "increase_timescale_separation",
            Self::ReduceGain => "reduce_gain",
            Self::DisableController => "disable_controller",
            Self::SafeModeFallback => "safe_mode_fallback",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Detector configuration
// ---------------------------------------------------------------------------

/// Configuration for bifurcation detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BifurcationDetectorConfig {
    /// Sufficient separation ratio threshold (millionths).
    pub sufficient_ratio_millionths: u64,
    /// Marginal separation ratio threshold (millionths).
    pub marginal_ratio_millionths: u64,
    /// Oscillation amplitude growth threshold (millionths per epoch).
    pub oscillation_growth_threshold_millionths: i64,
    /// Variance divergence threshold (millionths).
    pub variance_divergence_threshold_millionths: i64,
    /// Gain exceedance threshold (millionths, 1_000_000 = unity gain).
    pub gain_exceedance_threshold_millionths: i64,
}

impl Default for BifurcationDetectorConfig {
    fn default() -> Self {
        Self {
            sufficient_ratio_millionths: DEFAULT_SUFFICIENT_RATIO_MILLIONTHS,
            marginal_ratio_millionths: DEFAULT_MARGINAL_RATIO_MILLIONTHS,
            oscillation_growth_threshold_millionths: 50_000,
            variance_divergence_threshold_millionths: 200_000,
            gain_exceedance_threshold_millionths: 1_000_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Detector result
// ---------------------------------------------------------------------------

/// Result of running bifurcation detection on a controller composition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BifurcationDetectorResult {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// All detected signals.
    pub signals: Vec<BifurcationSignal>,
    /// All stability witnesses.
    pub witnesses: Vec<StabilityWitness>,
    /// Overall stability assessment.
    pub assessment: StabilityAssessment,
    /// Epoch at which detection ran.
    pub detection_epoch: u64,
}

/// Overall stability assessment of a controller composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StabilityAssessment {
    /// No signals detected — composition is stable.
    Stable,
    /// Informational signals only — monitoring is sufficient.
    MonitoringRecommended,
    /// Warning signals detected — intervention may be needed.
    InterventionRecommended,
    /// Critical signals — immediate action required.
    ImmediateActionRequired,
}

impl fmt::Display for StabilityAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Stable => "stable",
            Self::MonitoringRecommended => "monitoring_recommended",
            Self::InterventionRecommended => "intervention_recommended",
            Self::ImmediateActionRequired => "immediate_action_required",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Compute the timescale ratio between two controller profiles.
/// Returns the ratio of the slower interval to the faster interval.
pub fn compute_timescale_ratio(
    profile_a: &ControllerTimescaleProfile,
    profile_b: &ControllerTimescaleProfile,
) -> TimescaleRatio {
    let obs_a = profile_a.observation_interval_millionths.unsigned_abs();
    let obs_b = profile_b.observation_interval_millionths.unsigned_abs();
    let write_a = profile_a.write_interval_millionths.unsigned_abs();
    let write_b = profile_b.write_interval_millionths.unsigned_abs();

    let obs_ratio = if obs_a == 0 || obs_b == 0 {
        0
    } else if obs_a >= obs_b {
        obs_a * 1_000_000 / obs_b
    } else {
        obs_b * 1_000_000 / obs_a
    };

    let write_ratio = if write_a == 0 || write_b == 0 {
        0
    } else if write_a >= write_b {
        write_a * 1_000_000 / write_b
    } else {
        write_b * 1_000_000 / write_a
    };

    let (ratio, basis) = if obs_ratio <= write_ratio {
        (obs_ratio, RatioBasis::Observation)
    } else {
        (write_ratio, RatioBasis::Write)
    };

    // Determine fast/slow ordering (fast has shorter observation interval)
    let (fast, slow) = if obs_a <= obs_b {
        (&profile_a.controller_id, &profile_b.controller_id)
    } else {
        (&profile_b.controller_id, &profile_a.controller_id)
    };

    TimescaleRatio {
        pair: ControllerPairId {
            fast_controller: fast.clone(),
            slow_controller: slow.clone(),
        },
        ratio_millionths: ratio,
        ratio_basis: basis,
    }
}

/// Issue a timescale-separation certificate for a controller pair.
pub fn issue_separation_certificate(
    profile_a: &ControllerTimescaleProfile,
    profile_b: &ControllerTimescaleProfile,
    config: &BifurcationDetectorConfig,
    certificate_id: &str,
    epoch: u64,
    evidence_ids: Vec<String>,
) -> TimescaleSeparationCertificate {
    let ratio = compute_timescale_ratio(profile_a, profile_b);

    let verdict = if ratio.ratio_millionths >= config.sufficient_ratio_millionths {
        SeparationVerdict::Sufficient
    } else if ratio.ratio_millionths >= config.marginal_ratio_millionths {
        SeparationVerdict::Marginal
    } else {
        SeparationVerdict::Insufficient
    };

    let (fast_profile, slow_profile) = if ratio.pair.fast_controller == profile_a.controller_id {
        (profile_a.clone(), profile_b.clone())
    } else {
        (profile_b.clone(), profile_a.clone())
    };

    TimescaleSeparationCertificate {
        schema_version: TIMESCALE_CERTIFICATE_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        certificate_id: certificate_id.to_string(),
        pair: ratio.pair.clone(),
        ratio,
        verdict,
        sufficient_threshold_millionths: config.sufficient_ratio_millionths,
        marginal_threshold_millionths: config.marginal_ratio_millionths,
        fast_profile,
        slow_profile,
        issued_epoch: epoch,
        evidence_ids,
    }
}

/// Build a certificate bundle for all pairwise combinations.
pub fn build_certificate_bundle(
    profiles: &[ControllerTimescaleProfile],
    config: &BifurcationDetectorConfig,
    epoch: u64,
) -> CertificateBundle {
    let mut certificates = Vec::new();
    let mut cert_id = 0u64;

    for i in 0..profiles.len() {
        for j in (i + 1)..profiles.len() {
            cert_id += 1;
            let cert = issue_separation_certificate(
                &profiles[i],
                &profiles[j],
                config,
                &format!("cert-{cert_id}"),
                epoch,
                Vec::new(),
            );
            certificates.push(cert);
        }
    }

    let sufficient_count = certificates
        .iter()
        .filter(|c| c.verdict == SeparationVerdict::Sufficient)
        .count();
    let marginal_count = certificates
        .iter()
        .filter(|c| c.verdict == SeparationVerdict::Marginal)
        .count();
    let insufficient_count = certificates
        .iter()
        .filter(|c| c.verdict == SeparationVerdict::Insufficient)
        .count();

    let overall_verdict = if insufficient_count > 0 {
        SeparationVerdict::Insufficient
    } else if marginal_count > 0 {
        SeparationVerdict::Marginal
    } else {
        SeparationVerdict::Sufficient
    };

    CertificateBundle {
        schema_version: CERTIFICATE_BUNDLE_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        certificates,
        overall_verdict,
        bundle_epoch: epoch,
        pair_count: cert_id as usize,
        sufficient_count,
        marginal_count,
        insufficient_count,
    }
}

/// Detect bifurcation signals from telemetry observations.
///
/// Takes a sequence of per-epoch telemetry snapshots for each controller pair.
/// Each snapshot contains the measured timescale ratio and a variance estimate.
pub fn detect_bifurcation_signals(
    telemetry: &[PairTelemetrySnapshot],
    config: &BifurcationDetectorConfig,
    epoch: u64,
) -> BifurcationDetectorResult {
    let mut signals = Vec::new();
    let mut signal_seq = 0u64;

    // Group by pair
    let mut by_pair: BTreeMap<String, Vec<&PairTelemetrySnapshot>> = BTreeMap::new();
    for snapshot in telemetry {
        let key = format!(
            "{}↔{}",
            snapshot.pair.fast_controller, snapshot.pair.slow_controller
        );
        by_pair.entry(key).or_default().push(snapshot);
    }

    for snapshots in by_pair.values() {
        if snapshots.len() < 2 {
            continue;
        }

        let pair = &snapshots[0].pair;

        // Check for timescale convergence
        let first_ratio = snapshots.first().map(|s| s.ratio_millionths).unwrap_or(0);
        let last_ratio = snapshots.last().map(|s| s.ratio_millionths).unwrap_or(0);

        if last_ratio < first_ratio
            && first_ratio > 0
            && last_ratio < config.marginal_ratio_millionths
        {
            signal_seq += 1;
            signals.push(BifurcationSignal {
                signal_id: format!("sig-{signal_seq}"),
                pair: pair.clone(),
                kind: BifurcationSignalKind::TimescaleConvergence,
                severity: if last_ratio < config.marginal_ratio_millionths / 2 {
                    SignalSeverity::Critical
                } else {
                    SignalSeverity::Warning
                },
                trigger_value_millionths: last_ratio as i64,
                threshold_millionths: config.marginal_ratio_millionths as i64,
                detected_epoch: epoch,
                description: format!(
                    "Timescale ratio decreased from {} to {} (below marginal threshold {})",
                    first_ratio, last_ratio, config.marginal_ratio_millionths
                ),
            });
        }

        // Check for variance divergence
        if snapshots.len() >= 3 {
            let first_variance = snapshots
                .first()
                .map(|s| s.variance_millionths)
                .unwrap_or(0);
            let last_variance = snapshots.last().map(|s| s.variance_millionths).unwrap_or(0);
            let delta = last_variance - first_variance;

            if delta > config.variance_divergence_threshold_millionths {
                signal_seq += 1;
                signals.push(BifurcationSignal {
                    signal_id: format!("sig-{signal_seq}"),
                    pair: pair.clone(),
                    kind: BifurcationSignalKind::VarianceDivergence,
                    severity: if delta > config.variance_divergence_threshold_millionths * 2 {
                        SignalSeverity::Critical
                    } else {
                        SignalSeverity::Warning
                    },
                    trigger_value_millionths: delta,
                    threshold_millionths: config.variance_divergence_threshold_millionths,
                    detected_epoch: epoch,
                    description: format!(
                        "Variance increased by {} (threshold {})",
                        delta, config.variance_divergence_threshold_millionths
                    ),
                });
            }
        }

        // Check for gain exceedance
        for snapshot in snapshots.iter() {
            if snapshot.effective_gain_millionths > config.gain_exceedance_threshold_millionths {
                signal_seq += 1;
                signals.push(BifurcationSignal {
                    signal_id: format!("sig-{signal_seq}"),
                    pair: pair.clone(),
                    kind: BifurcationSignalKind::GainExceedance,
                    severity: SignalSeverity::Critical,
                    trigger_value_millionths: snapshot.effective_gain_millionths,
                    threshold_millionths: config.gain_exceedance_threshold_millionths,
                    detected_epoch: epoch,
                    description: format!(
                        "Effective gain {} exceeds unity threshold {}",
                        snapshot.effective_gain_millionths,
                        config.gain_exceedance_threshold_millionths
                    ),
                });
            }
        }
    }

    // Build stability witnesses for critical signals
    let witnesses = build_stability_witnesses(&signals, epoch);

    // Compute overall assessment
    let assessment = compute_assessment(&signals);

    BifurcationDetectorResult {
        schema_version: BIFURCATION_DETECTOR_SCHEMA_VERSION.to_string(),
        bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
        signals,
        witnesses,
        assessment,
        detection_epoch: epoch,
    }
}

/// Telemetry snapshot for a controller pair at a single epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairTelemetrySnapshot {
    /// The controller pair.
    pub pair: ControllerPairId,
    /// Measured timescale ratio (millionths).
    pub ratio_millionths: u64,
    /// Variance estimate of the interaction (millionths).
    pub variance_millionths: i64,
    /// Effective feedback gain (millionths; 1_000_000 = unity).
    pub effective_gain_millionths: i64,
    /// Epoch of this snapshot.
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_stability_witnesses(signals: &[BifurcationSignal], epoch: u64) -> Vec<StabilityWitness> {
    // Group critical signals by pair
    let mut critical_by_pair: BTreeMap<String, Vec<&BifurcationSignal>> = BTreeMap::new();
    for signal in signals {
        if signal.severity == SignalSeverity::Critical {
            let key = signal.pair.to_string();
            critical_by_pair.entry(key).or_default().push(signal);
        }
    }

    let mut witnesses = Vec::new();
    let mut witness_seq = 0u64;

    for pair_signals in critical_by_pair.values() {
        if pair_signals.is_empty() {
            continue;
        }
        witness_seq += 1;

        let primary = pair_signals[0].clone();
        let supporting: Vec<BifurcationSignal> =
            pair_signals[1..].iter().map(|s| (*s).clone()).collect();

        let action = recommend_action(&primary);

        witnesses.push(StabilityWitness {
            schema_version: STABILITY_WITNESS_SCHEMA_VERSION.to_string(),
            bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
            witness_id: format!("witness-{witness_seq}"),
            pair: primary.pair.clone(),
            primary_signal: primary,
            supporting_signals: supporting,
            recommended_action: action,
            assembled_epoch: epoch,
        });
    }

    witnesses
}

fn recommend_action(signal: &BifurcationSignal) -> RecommendedAction {
    match signal.kind {
        BifurcationSignalKind::TimescaleConvergence => {
            RecommendedAction::IncreaseTimescaleSeparation
        }
        BifurcationSignalKind::GainExceedance => RecommendedAction::ReduceGain,
        BifurcationSignalKind::SpectralEdgeCrossing => RecommendedAction::SafeModeFallback,
        BifurcationSignalKind::GrowingOscillation => RecommendedAction::DisableController,
        BifurcationSignalKind::VarianceDivergence => RecommendedAction::Monitor,
    }
}

fn compute_assessment(signals: &[BifurcationSignal]) -> StabilityAssessment {
    let has_critical = signals
        .iter()
        .any(|s| s.severity == SignalSeverity::Critical);
    let has_warning = signals
        .iter()
        .any(|s| s.severity == SignalSeverity::Warning);
    let has_info = signals.iter().any(|s| s.severity == SignalSeverity::Info);

    if has_critical {
        StabilityAssessment::ImmediateActionRequired
    } else if has_warning {
        StabilityAssessment::InterventionRecommended
    } else if has_info {
        StabilityAssessment::MonitoringRecommended
    } else {
        StabilityAssessment::Stable
    }
}

/// Render a human-readable summary of the detection result.
pub fn render_detector_summary(result: &BifurcationDetectorResult) -> String {
    let mut lines = vec![
        format!("schema_version: {}", result.schema_version),
        format!("detection_epoch: {}", result.detection_epoch),
        format!("assessment: {}", result.assessment),
        format!("signals: {}", result.signals.len()),
        format!("witnesses: {}", result.witnesses.len()),
    ];

    if !result.signals.is_empty() {
        lines.push("signal_kinds:".to_string());
        let mut kind_counts: BTreeMap<BifurcationSignalKind, usize> = BTreeMap::new();
        for signal in &result.signals {
            *kind_counts.entry(signal.kind).or_insert(0) += 1;
        }
        for (kind, count) in &kind_counts {
            lines.push(format!("  {kind}: {count}"));
        }
    }

    lines.join("\n")
}

/// Render a human-readable summary of a certificate bundle.
pub fn render_bundle_summary(bundle: &CertificateBundle) -> String {
    [
        format!("schema_version: {}", bundle.schema_version),
        format!("bundle_epoch: {}", bundle.bundle_epoch),
        format!("pair_count: {}", bundle.pair_count),
        format!("overall_verdict: {}", bundle.overall_verdict),
        format!("sufficient: {}", bundle.sufficient_count),
        format!("marginal: {}", bundle.marginal_count),
        format!("insufficient: {}", bundle.insufficient_count),
    ]
    .join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(id: &str, obs: i64, write: i64) -> ControllerTimescaleProfile {
        ControllerTimescaleProfile {
            controller_id: id.to_string(),
            observation_interval_millionths: obs,
            write_interval_millionths: write,
            sample_count: 100,
            measured_epoch: 0,
        }
    }

    fn pair(fast: &str, slow: &str) -> ControllerPairId {
        ControllerPairId {
            fast_controller: fast.to_string(),
            slow_controller: slow.to_string(),
        }
    }

    fn snapshot(
        fast: &str,
        slow: &str,
        ratio: u64,
        variance: i64,
        gain: i64,
        epoch: u64,
    ) -> PairTelemetrySnapshot {
        PairTelemetrySnapshot {
            pair: pair(fast, slow),
            ratio_millionths: ratio,
            variance_millionths: variance,
            effective_gain_millionths: gain,
            epoch,
        }
    }

    // -- Timescale ratio --

    #[test]
    fn ratio_10x_separation() {
        let fast = profile("router", 100_000, 200_000);
        let slow = profile("optimizer", 1_000_000, 2_000_000);
        let ratio = compute_timescale_ratio(&fast, &slow);
        assert_eq!(ratio.ratio_millionths, 10_000_000); // 10x
        assert_eq!(ratio.pair.fast_controller, "router");
        assert_eq!(ratio.pair.slow_controller, "optimizer");
    }

    #[test]
    fn ratio_same_timescale() {
        let a = profile("ctrl-a", 500_000, 500_000);
        let b = profile("ctrl-b", 500_000, 500_000);
        let ratio = compute_timescale_ratio(&a, &b);
        assert_eq!(ratio.ratio_millionths, 1_000_000); // 1x (no separation)
    }

    #[test]
    fn ratio_uses_minimum() {
        // obs ratio = 5x, write ratio = 2x → conservative = 2x (write)
        let fast = profile("fast", 100_000, 500_000);
        let slow = profile("slow", 500_000, 1_000_000);
        let ratio = compute_timescale_ratio(&fast, &slow);
        assert_eq!(ratio.ratio_millionths, 2_000_000);
        assert_eq!(ratio.ratio_basis, RatioBasis::Write);
    }

    #[test]
    fn ratio_zero_interval() {
        let a = profile("a", 0, 100_000);
        let b = profile("b", 100_000, 100_000);
        let ratio = compute_timescale_ratio(&a, &b);
        // When observation is 0, obs ratio = 0; write ratio = 1x; min = 0
        assert_eq!(ratio.ratio_millionths, 0);
    }

    // -- Separation certificate --

    #[test]
    fn certificate_sufficient() {
        let fast = profile("router", 100_000, 200_000);
        let slow = profile("monitor", 1_000_000, 2_000_000);
        let config = BifurcationDetectorConfig::default();
        let cert = issue_separation_certificate(&fast, &slow, &config, "cert-1", 0, vec![]);
        assert_eq!(cert.verdict, SeparationVerdict::Sufficient);
        assert_eq!(cert.pair.fast_controller, "router");
    }

    #[test]
    fn certificate_marginal() {
        // 5x separation (between 3x marginal and 10x sufficient)
        let fast = profile("a", 100_000, 100_000);
        let slow = profile("b", 500_000, 500_000);
        let config = BifurcationDetectorConfig::default();
        let cert = issue_separation_certificate(&fast, &slow, &config, "cert-2", 0, vec![]);
        assert_eq!(cert.verdict, SeparationVerdict::Marginal);
    }

    #[test]
    fn certificate_insufficient() {
        // 2x separation (below 3x marginal threshold)
        let fast = profile("x", 100_000, 100_000);
        let slow = profile("y", 200_000, 200_000);
        let config = BifurcationDetectorConfig::default();
        let cert = issue_separation_certificate(&fast, &slow, &config, "cert-3", 0, vec![]);
        assert_eq!(cert.verdict, SeparationVerdict::Insufficient);
    }

    // -- Certificate bundle --

    #[test]
    fn bundle_three_controllers() {
        let profiles = vec![
            profile("fast", 100_000, 100_000),
            profile("medium", 1_000_000, 1_000_000),
            profile("slow", 10_000_000, 10_000_000),
        ];
        let config = BifurcationDetectorConfig::default();
        let bundle = build_certificate_bundle(&profiles, &config, 1);
        assert_eq!(bundle.pair_count, 3); // C(3,2) = 3
        assert_eq!(bundle.certificates.len(), 3);
    }

    #[test]
    fn bundle_overall_verdict_worst_case() {
        let profiles = vec![
            profile("a", 100_000, 100_000),
            profile("b", 200_000, 200_000),       // insufficient to a
            profile("c", 10_000_000, 10_000_000), // sufficient to both
        ];
        let config = BifurcationDetectorConfig::default();
        let bundle = build_certificate_bundle(&profiles, &config, 0);
        assert_eq!(bundle.overall_verdict, SeparationVerdict::Insufficient);
        assert!(bundle.insufficient_count >= 1);
    }

    #[test]
    fn bundle_empty_profiles() {
        let config = BifurcationDetectorConfig::default();
        let bundle = build_certificate_bundle(&[], &config, 0);
        assert_eq!(bundle.pair_count, 0);
        assert_eq!(bundle.overall_verdict, SeparationVerdict::Sufficient);
    }

    #[test]
    fn bundle_single_profile() {
        let profiles = vec![profile("solo", 100_000, 100_000)];
        let config = BifurcationDetectorConfig::default();
        let bundle = build_certificate_bundle(&profiles, &config, 0);
        assert_eq!(bundle.pair_count, 0);
    }

    // -- Bifurcation detection --

    #[test]
    fn detect_no_signals_when_stable() {
        let telemetry = vec![
            snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
            snapshot("a", "b", 10_000_000, 55_000, 500_000, 1),
        ];
        let config = BifurcationDetectorConfig::default();
        let result = detect_bifurcation_signals(&telemetry, &config, 1);
        assert_eq!(result.assessment, StabilityAssessment::Stable);
        assert!(result.signals.is_empty());
    }

    #[test]
    fn detect_timescale_convergence() {
        let config = BifurcationDetectorConfig::default();
        let telemetry = vec![
            snapshot("a", "b", 5_000_000, 50_000, 500_000, 0),
            snapshot("a", "b", 2_000_000, 50_000, 500_000, 1),
        ];
        let result = detect_bifurcation_signals(&telemetry, &config, 1);
        assert!(!result.signals.is_empty());
        assert!(
            result
                .signals
                .iter()
                .any(|s| s.kind == BifurcationSignalKind::TimescaleConvergence)
        );
    }

    #[test]
    fn detect_variance_divergence() {
        let config = BifurcationDetectorConfig::default();
        let telemetry = vec![
            snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
            snapshot("a", "b", 10_000_000, 100_000, 500_000, 1),
            snapshot("a", "b", 10_000_000, 300_000, 500_000, 2),
        ];
        let result = detect_bifurcation_signals(&telemetry, &config, 2);
        assert!(
            result
                .signals
                .iter()
                .any(|s| s.kind == BifurcationSignalKind::VarianceDivergence)
        );
    }

    #[test]
    fn detect_gain_exceedance() {
        let config = BifurcationDetectorConfig::default();
        let telemetry = vec![
            snapshot("a", "b", 10_000_000, 50_000, 500_000, 0),
            snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 1),
        ];
        let result = detect_bifurcation_signals(&telemetry, &config, 1);
        assert!(
            result
                .signals
                .iter()
                .any(|s| s.kind == BifurcationSignalKind::GainExceedance)
        );
        assert_eq!(
            result.assessment,
            StabilityAssessment::ImmediateActionRequired
        );
    }

    #[test]
    fn stability_witness_for_critical_signals() {
        let config = BifurcationDetectorConfig::default();
        let telemetry = vec![
            snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0),
            snapshot("a", "b", 10_000_000, 50_000, 2_000_000, 1),
        ];
        let result = detect_bifurcation_signals(&telemetry, &config, 1);
        assert!(!result.witnesses.is_empty());
        let witness = &result.witnesses[0];
        assert_eq!(witness.pair, pair("a", "b"));
        assert!(matches!(
            witness.recommended_action,
            RecommendedAction::ReduceGain
        ));
    }

    // -- Display formatting --

    #[test]
    fn separation_verdict_display() {
        assert_eq!(SeparationVerdict::Sufficient.to_string(), "sufficient");
        assert_eq!(SeparationVerdict::Marginal.to_string(), "marginal");
        assert_eq!(SeparationVerdict::Insufficient.to_string(), "insufficient");
    }

    #[test]
    fn bifurcation_signal_kind_display() {
        assert_eq!(
            BifurcationSignalKind::GrowingOscillation.to_string(),
            "growing_oscillation"
        );
        assert_eq!(
            BifurcationSignalKind::TimescaleConvergence.to_string(),
            "timescale_convergence"
        );
        assert_eq!(
            BifurcationSignalKind::SpectralEdgeCrossing.to_string(),
            "spectral_edge_crossing"
        );
        assert_eq!(
            BifurcationSignalKind::VarianceDivergence.to_string(),
            "variance_divergence"
        );
        assert_eq!(
            BifurcationSignalKind::GainExceedance.to_string(),
            "gain_exceedance"
        );
    }

    #[test]
    fn signal_severity_display() {
        assert_eq!(SignalSeverity::Info.to_string(), "info");
        assert_eq!(SignalSeverity::Warning.to_string(), "warning");
        assert_eq!(SignalSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn recommended_action_display() {
        assert_eq!(RecommendedAction::Monitor.to_string(), "monitor");
        assert_eq!(
            RecommendedAction::IncreaseTimescaleSeparation.to_string(),
            "increase_timescale_separation"
        );
        assert_eq!(RecommendedAction::ReduceGain.to_string(), "reduce_gain");
        assert_eq!(
            RecommendedAction::DisableController.to_string(),
            "disable_controller"
        );
        assert_eq!(
            RecommendedAction::SafeModeFallback.to_string(),
            "safe_mode_fallback"
        );
    }

    #[test]
    fn stability_assessment_display() {
        assert_eq!(StabilityAssessment::Stable.to_string(), "stable");
        assert_eq!(
            StabilityAssessment::MonitoringRecommended.to_string(),
            "monitoring_recommended"
        );
        assert_eq!(
            StabilityAssessment::InterventionRecommended.to_string(),
            "intervention_recommended"
        );
        assert_eq!(
            StabilityAssessment::ImmediateActionRequired.to_string(),
            "immediate_action_required"
        );
    }

    #[test]
    fn controller_pair_id_display() {
        let p = pair("router", "optimizer");
        assert_eq!(p.to_string(), "router↔optimizer");
    }

    #[test]
    fn ratio_basis_display() {
        assert_eq!(RatioBasis::Observation.to_string(), "observation");
        assert_eq!(RatioBasis::Write.to_string(), "write");
        assert_eq!(RatioBasis::MinimumOf.to_string(), "minimum_of");
    }

    // -- Serde round-trips --

    #[test]
    fn certificate_serde_round_trip() {
        let fast = profile("router", 100_000, 200_000);
        let slow = profile("monitor", 1_000_000, 2_000_000);
        let config = BifurcationDetectorConfig::default();
        let cert = issue_separation_certificate(
            &fast,
            &slow,
            &config,
            "serde-cert",
            0,
            vec!["ev-1".to_string()],
        );
        let json = serde_json::to_string(&cert).expect("serialize");
        let deser: TimescaleSeparationCertificate =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cert, deser);
    }

    #[test]
    fn bundle_serde_round_trip() {
        let profiles = vec![
            profile("a", 100_000, 100_000),
            profile("b", 1_000_000, 1_000_000),
        ];
        let config = BifurcationDetectorConfig::default();
        let bundle = build_certificate_bundle(&profiles, &config, 0);
        let json = serde_json::to_string(&bundle).expect("serialize");
        let deser: CertificateBundle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(bundle, deser);
    }

    #[test]
    fn detector_result_serde_round_trip() {
        let config = BifurcationDetectorConfig::default();
        let telemetry = vec![snapshot("a", "b", 10_000_000, 50_000, 1_500_000, 0)];
        let result = detect_bifurcation_signals(&telemetry, &config, 0);
        let json = serde_json::to_string(&result).expect("serialize");
        let deser: BifurcationDetectorResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(result, deser);
    }

    #[test]
    fn bifurcation_signal_serde_round_trip() {
        let signal = BifurcationSignal {
            signal_id: "sig-test".to_string(),
            pair: pair("a", "b"),
            kind: BifurcationSignalKind::GrowingOscillation,
            severity: SignalSeverity::Warning,
            trigger_value_millionths: 100_000,
            threshold_millionths: 50_000,
            detected_epoch: 5,
            description: "test signal".to_string(),
        };
        let json = serde_json::to_string(&signal).expect("serialize");
        let deser: BifurcationSignal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(signal, deser);
    }

    #[test]
    fn config_serde_round_trip() {
        let config = BifurcationDetectorConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let deser: BifurcationDetectorConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, deser);
    }

    // -- Summary rendering --

    #[test]
    fn detector_summary_stable() {
        let result = BifurcationDetectorResult {
            schema_version: BIFURCATION_DETECTOR_SCHEMA_VERSION.to_string(),
            bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.to_string(),
            signals: vec![],
            witnesses: vec![],
            assessment: StabilityAssessment::Stable,
            detection_epoch: 0,
        };
        let summary = render_detector_summary(&result);
        assert!(summary.contains("assessment: stable"));
        assert!(summary.contains("signals: 0"));
    }

    #[test]
    fn bundle_summary_contents() {
        let profiles = vec![
            profile("a", 100_000, 100_000),
            profile("b", 1_000_000, 1_000_000),
        ];
        let config = BifurcationDetectorConfig::default();
        let bundle = build_certificate_bundle(&profiles, &config, 0);
        let summary = render_bundle_summary(&bundle);
        assert!(summary.contains("pair_count: 1"));
        assert!(summary.contains("overall_verdict:"));
    }

    // -- Default config --

    #[test]
    fn default_config_values() {
        let config = BifurcationDetectorConfig::default();
        assert_eq!(config.sufficient_ratio_millionths, 10_000_000);
        assert_eq!(config.marginal_ratio_millionths, 3_000_000);
        assert_eq!(config.gain_exceedance_threshold_millionths, 1_000_000);
    }

    // ── enrichment: serde round-trips for untested types ──────────

    #[test]
    fn controller_pair_id_serde_roundtrip() {
        let pair = ControllerPairId {
            fast_controller: "gc_pressure".into(),
            slow_controller: "policy_update".into(),
        };
        let json = serde_json::to_string(&pair).unwrap();
        let back: ControllerPairId = serde_json::from_str(&json).unwrap();
        assert_eq!(pair, back);
    }

    #[test]
    fn controller_timescale_profile_serde_roundtrip() {
        let profile = ControllerTimescaleProfile {
            controller_id: "gc_pressure".into(),
            observation_interval_millionths: 100_000,
            write_interval_millionths: 200_000,
            sample_count: 50,
            measured_epoch: 1,
        };
        let json = serde_json::to_string(&profile).unwrap();
        let back: ControllerTimescaleProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, back);
    }

    #[test]
    fn timescale_ratio_serde_roundtrip() {
        let ratio = TimescaleRatio {
            pair: ControllerPairId {
                fast_controller: "a".into(),
                slow_controller: "b".into(),
            },
            ratio_millionths: 10_000_000,
            ratio_basis: RatioBasis::Observation,
        };
        let json = serde_json::to_string(&ratio).unwrap();
        let back: TimescaleRatio = serde_json::from_str(&json).unwrap();
        assert_eq!(ratio, back);
    }

    // ── enrichment: ratio computation edge cases ──────────────────

    #[test]
    fn ratio_equal_timescales_is_one() {
        let fast = ControllerTimescaleProfile {
            controller_id: "fast".into(),
            observation_interval_millionths: 1_000_000,
            write_interval_millionths: 1_000_000,
            sample_count: 10,
            measured_epoch: 1,
        };
        let slow = fast.clone();
        let ratio = compute_timescale_ratio(&fast, &slow);
        assert_eq!(ratio.ratio_millionths, 1_000_000);
    }

    // ── enrichment: bundle pair counting ──────────────────────────

    #[test]
    fn bundle_two_controllers_one_pair() {
        let cfg = BifurcationDetectorConfig::default();
        let profiles = vec![
            ControllerTimescaleProfile {
                controller_id: "a".into(),
                observation_interval_millionths: 100_000,
                write_interval_millionths: 100_000,
                sample_count: 10,
                measured_epoch: 1,
            },
            ControllerTimescaleProfile {
                controller_id: "b".into(),
                observation_interval_millionths: 10_000_000,
                write_interval_millionths: 10_000_000,
                sample_count: 10,
                measured_epoch: 1,
            },
        ];
        let bundle = build_certificate_bundle(&profiles, &cfg, 1);
        assert_eq!(bundle.pair_count, 1);
        assert_eq!(bundle.certificates.len(), 1);
    }

    #[test]
    fn bundle_four_controllers_six_pairs() {
        let cfg = BifurcationDetectorConfig::default();
        let profiles: Vec<ControllerTimescaleProfile> = (0..4)
            .map(|i| ControllerTimescaleProfile {
                controller_id: format!("ctrl-{}", i),
                observation_interval_millionths: (i + 1) as i64 * 1_000_000,
                write_interval_millionths: (i + 1) as i64 * 1_000_000,
                sample_count: 10,
                measured_epoch: 1,
            })
            .collect();
        let bundle = build_certificate_bundle(&profiles, &cfg, 1);
        assert_eq!(bundle.pair_count, 6);
    }

    // ── enrichment: enum display completeness ─────────────────────

    #[test]
    fn signal_severity_all_distinct() {
        let variants = [
            SignalSeverity::Info,
            SignalSeverity::Warning,
            SignalSeverity::Critical,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|s| s.to_string()).collect();
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn recommended_action_all_distinct() {
        let variants = [
            RecommendedAction::Monitor,
            RecommendedAction::IncreaseTimescaleSeparation,
            RecommendedAction::ReduceGain,
            RecommendedAction::DisableController,
            RecommendedAction::SafeModeFallback,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|s| s.to_string()).collect();
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn stability_assessment_all_distinct() {
        let variants = [
            StabilityAssessment::Stable,
            StabilityAssessment::MonitoringRecommended,
            StabilityAssessment::InterventionRecommended,
            StabilityAssessment::ImmediateActionRequired,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|s| s.to_string()).collect();
        assert_eq!(displays.len(), variants.len());
    }

    #[test]
    fn bifurcation_signal_kind_all_distinct() {
        let variants = [
            BifurcationSignalKind::GrowingOscillation,
            BifurcationSignalKind::TimescaleConvergence,
            BifurcationSignalKind::SpectralEdgeCrossing,
            BifurcationSignalKind::VarianceDivergence,
            BifurcationSignalKind::GainExceedance,
        ];
        let displays: std::collections::BTreeSet<String> =
            variants.iter().map(|s| s.to_string()).collect();
        assert_eq!(displays.len(), variants.len());
    }

    // ── enrichment: detector summary rendering ────────────────────

    #[test]
    fn detector_summary_contains_assessment() {
        let result = BifurcationDetectorResult {
            schema_version: BIFURCATION_DETECTOR_SCHEMA_VERSION.into(),
            bead_id: TIMESCALE_CERTIFICATE_BEAD_ID.into(),
            signals: vec![],
            witnesses: vec![],
            assessment: StabilityAssessment::Stable,
            detection_epoch: 1,
        };
        let summary = render_detector_summary(&result);
        assert!(
            summary.contains("stable") || summary.contains("Stable"),
            "summary should contain assessment"
        );
    }
}
