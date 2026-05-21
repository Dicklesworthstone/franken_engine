//! Convergence SLO measurement and artifact publication for fleet quarantine propagation.
//!
//! Tracks time from quarantine decision to all-instances-enforced, computes statistical
//! analysis (p50/p95/p99), detects SLO violations, and publishes JSON artifacts.
//!
//! Plan reference: bd-6a61n.5.3

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
#[cfg(test)]
use std::time::Duration;
use std::time::{Instant, SystemTime};

use serde::{Deserialize, Serialize};

use crate::fleet_immune_protocol::NodeId;
use crate::hash_tiers::ContentHash;
use crate::quarantine_propagation::QuarantineDecision;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Configuration for convergence SLO measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceSloConfig {
    /// Maximum convergence time before SLO violation (default 500ms simulated).
    pub max_convergence_time_ms: u64,
    /// Artifact output directory.
    pub artifacts_directory: PathBuf,
    /// Whether to enable detailed per-instance tracking.
    pub detailed_tracking: bool,
    /// Statistical analysis configuration.
    pub statistical_analysis: StatisticalAnalysisConfig,
}

impl Default for ConvergenceSloConfig {
    fn default() -> Self {
        Self {
            max_convergence_time_ms: 500,
            artifacts_directory: PathBuf::from("artifacts/fleet_evidence"),
            detailed_tracking: true,
            statistical_analysis: StatisticalAnalysisConfig::default(),
        }
    }
}

/// Configuration for statistical analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticalAnalysisConfig {
    /// Number of events to collect for statistical analysis.
    pub min_sample_size: usize,
    /// Percentiles to compute.
    pub percentiles: Vec<f64>,
    /// Whether to detect outlier instances.
    pub outlier_detection: bool,
}

impl Default for StatisticalAnalysisConfig {
    fn default() -> Self {
        Self {
            min_sample_size: 10,
            percentiles: vec![50.0, 95.0, 99.0],
            outlier_detection: true,
        }
    }
}

/// Single convergence measurement for a quarantine event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceMeasurement {
    /// Evidence hash of the quarantine decision.
    pub decision_evidence_hash: ContentHash,
    /// Extension ID being quarantined.
    pub extension_id: String,
    /// Originating instance.
    pub originator_instance: NodeId,
    /// Decision start time. Not serialized — `Instant` is monotonic and
    /// meaningless across process boundaries.
    #[serde(skip, default = "Instant::now")]
    pub decision_start_time: Instant,
    /// Time when all instances acknowledged (convergence). Not serialized —
    /// monotonic.
    #[serde(skip)]
    pub convergence_time: Option<Instant>,
    /// Convergence duration in milliseconds.
    pub convergence_duration_ms: Option<u64>,
    /// Whether this event met the SLO.
    pub slo_met: Option<bool>,
    /// Per-instance acknowledgment times. Not serialized — monotonic.
    #[serde(skip)]
    pub instance_ack_times: BTreeMap<NodeId, Instant>,
    /// Number of participating instances.
    pub total_instances: usize,
    /// Measurement timestamp.
    pub measurement_timestamp: SystemTime,
}

impl ConvergenceMeasurement {
    /// Create a new convergence measurement from a quarantine decision.
    pub fn new(decision: &QuarantineDecision, total_instances: usize) -> Self {
        Self {
            decision_evidence_hash: decision.evidence_hash,
            extension_id: decision.extension_id.clone(),
            originator_instance: decision.originator_instance.clone(),
            decision_start_time: decision.decision_timestamp,
            convergence_time: None,
            convergence_duration_ms: None,
            slo_met: None,
            instance_ack_times: BTreeMap::new(),
            total_instances,
            measurement_timestamp: SystemTime::now(),
        }
    }

    /// Record acknowledgment from an instance.
    pub fn record_acknowledgment(&mut self, instance_id: NodeId, ack_time: Instant) {
        self.instance_ack_times.insert(instance_id, ack_time);

        // Check if converged (all instances except originator acknowledged)
        if self.instance_ack_times.len() >= self.total_instances.saturating_sub(1) {
            self.mark_converged();
        }
    }

    /// Mark the measurement as converged and compute duration.
    fn mark_converged(&mut self) {
        if let Some(latest_ack) = self.instance_ack_times.values().max() {
            self.convergence_time = Some(*latest_ack);
            self.convergence_duration_ms = Some(
                latest_ack
                    .duration_since(self.decision_start_time)
                    .as_millis() as u64,
            );
        }
    }

    /// Set SLO status based on convergence time and threshold.
    pub fn evaluate_slo(&mut self, max_convergence_time_ms: u64) {
        if let Some(duration_ms) = self.convergence_duration_ms {
            self.slo_met = Some(duration_ms <= max_convergence_time_ms);
        }
    }

    /// Check if this measurement has converged.
    pub fn is_converged(&self) -> bool {
        self.convergence_time.is_some()
    }

    /// Get convergence progress (acknowledged_count, total_expected).
    pub fn convergence_progress(&self) -> (usize, usize) {
        (
            self.instance_ack_times.len(),
            self.total_instances.saturating_sub(1),
        )
    }
}

/// Statistical analysis results for convergence measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceStatistics {
    /// Total number of measurements analyzed.
    pub total_measurements: usize,
    /// Number of measurements that converged.
    pub converged_count: usize,
    /// Number of SLO violations.
    pub slo_violations: usize,
    /// Percentile analysis of convergence times.
    pub percentiles: BTreeMap<String, u64>,
    /// Average convergence time in milliseconds.
    pub average_convergence_ms: f64,
    /// Minimum convergence time.
    pub min_convergence_ms: u64,
    /// Maximum convergence time.
    pub max_convergence_ms: u64,
    /// Outlier instances (if outlier detection enabled).
    pub outlier_instances: Vec<NodeId>,
    /// Analysis timestamp.
    pub analysis_timestamp: SystemTime,
}

/// Convergence SLO measurement engine.
#[derive(Debug)]
pub struct ConvergenceMeter {
    /// Configuration.
    pub config: ConvergenceSloConfig,
    /// Active measurements indexed by evidence hash.
    pub active_measurements: BTreeMap<ContentHash, ConvergenceMeasurement>,
    /// Completed measurements for statistical analysis.
    pub completed_measurements: Vec<ConvergenceMeasurement>,
    /// Latest statistical analysis.
    pub latest_statistics: Option<ConvergenceStatistics>,
    /// Measurement start time.
    pub measurement_start_time: SystemTime,
}

impl ConvergenceMeter {
    /// Create a new convergence meter.
    pub fn new(config: ConvergenceSloConfig) -> Self {
        Self {
            config,
            active_measurements: BTreeMap::new(),
            completed_measurements: Vec::new(),
            latest_statistics: None,
            measurement_start_time: SystemTime::now(),
        }
    }

    /// Start measuring convergence for a quarantine decision.
    pub fn start_measurement(
        &mut self,
        decision: &QuarantineDecision,
        total_instances: usize,
    ) -> Result<(), ConvergenceError> {
        let measurement = ConvergenceMeasurement::new(decision, total_instances);
        self.active_measurements
            .insert(decision.evidence_hash, measurement);
        Ok(())
    }

    /// Record acknowledgment for a quarantine decision.
    pub fn record_acknowledgment(
        &mut self,
        evidence_hash: ContentHash,
        instance_id: NodeId,
        ack_time: Instant,
    ) -> Result<bool, ConvergenceError> {
        let measurement = self
            .active_measurements
            .get_mut(&evidence_hash)
            .ok_or(ConvergenceError::MeasurementNotFound { evidence_hash })?;

        measurement.record_acknowledgment(instance_id, ack_time);

        // If converged, evaluate SLO and move to completed
        if measurement.is_converged() {
            let mut completed_measurement = measurement.clone();
            completed_measurement.evaluate_slo(self.config.max_convergence_time_ms);

            self.completed_measurements.push(completed_measurement);
            self.active_measurements.remove(&evidence_hash);

            return Ok(true); // Converged
        }

        Ok(false) // Not yet converged
    }

    /// Get convergence progress for a specific decision.
    pub fn get_convergence_progress(&self, evidence_hash: &ContentHash) -> Option<(usize, usize)> {
        self.active_measurements
            .get(evidence_hash)
            .map(|m| m.convergence_progress())
    }

    /// Check if a decision has converged.
    pub fn is_decision_converged(&self, evidence_hash: &ContentHash) -> bool {
        if let Some(measurement) = self.active_measurements.get(evidence_hash) {
            measurement.is_converged()
        } else {
            // Check completed measurements
            self.completed_measurements
                .iter()
                .any(|m| m.decision_evidence_hash == *evidence_hash && m.is_converged())
        }
    }

    /// Compute statistical analysis over completed measurements.
    pub fn compute_statistics(&mut self) -> Result<ConvergenceStatistics, ConvergenceError> {
        if self.completed_measurements.len() < self.config.statistical_analysis.min_sample_size {
            return Err(ConvergenceError::InsufficientSampleSize {
                required: self.config.statistical_analysis.min_sample_size,
                actual: self.completed_measurements.len(),
            });
        }

        let converged_measurements: Vec<_> = self
            .completed_measurements
            .iter()
            .filter(|m| m.is_converged())
            .collect();

        if converged_measurements.is_empty() {
            return Err(ConvergenceError::NoConvergedMeasurements);
        }

        let mut convergence_times: Vec<u64> = converged_measurements
            .iter()
            .filter_map(|m| m.convergence_duration_ms)
            .collect();

        convergence_times.sort_unstable();

        // Compute percentiles
        let mut percentiles = BTreeMap::new();
        for &p in &self.config.statistical_analysis.percentiles {
            let percentile_value = compute_percentile(&convergence_times, p);
            percentiles.insert(format!("p{}", p as u32), percentile_value);
        }

        // Compute basic statistics
        let total_measurements = self.completed_measurements.len();
        let converged_count = converged_measurements.len();
        let slo_violations = converged_measurements
            .iter()
            .filter(|m| m.slo_met == Some(false))
            .count();

        let sum: u64 = convergence_times.iter().sum();
        let average_convergence_ms = sum as f64 / convergence_times.len() as f64;

        let min_convergence_ms = convergence_times.first().copied().unwrap_or(0);
        let max_convergence_ms = convergence_times.last().copied().unwrap_or(0);

        // Outlier detection (simplified: instances in slowest 10% of measurements)
        let mut outlier_instances = Vec::new();
        if self.config.statistical_analysis.outlier_detection {
            outlier_instances = self.detect_outlier_instances(&converged_measurements);
        }

        let statistics = ConvergenceStatistics {
            total_measurements,
            converged_count,
            slo_violations,
            percentiles,
            average_convergence_ms,
            min_convergence_ms,
            max_convergence_ms,
            outlier_instances,
            analysis_timestamp: SystemTime::now(),
        };

        self.latest_statistics = Some(statistics.clone());
        Ok(statistics)
    }

    /// Detect outlier instances (simplified implementation).
    fn detect_outlier_instances(&self, measurements: &[&ConvergenceMeasurement]) -> Vec<NodeId> {
        let mut instance_avg_times: BTreeMap<NodeId, Vec<u64>> = BTreeMap::new();

        // Collect acknowledgment times per instance
        for measurement in measurements {
            for (instance_id, ack_time) in &measurement.instance_ack_times {
                let duration_ms = ack_time
                    .duration_since(measurement.decision_start_time)
                    .as_millis() as u64;

                instance_avg_times
                    .entry(instance_id.clone())
                    .or_default()
                    .push(duration_ms);
            }
        }

        // Find instances in the slowest 10%
        let mut instance_averages: Vec<(NodeId, f64)> = instance_avg_times
            .into_iter()
            .map(|(id, times)| {
                let avg = times.iter().sum::<u64>() as f64 / times.len() as f64;
                (id, avg)
            })
            .collect();

        instance_averages
            .sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let outlier_count = (instance_averages.len() as f64 * 0.1).ceil() as usize;
        instance_averages
            .into_iter()
            .take(outlier_count)
            .map(|(id, _)| id)
            .collect()
    }

    /// Publish convergence artifacts to the configured directory.
    pub fn publish_artifacts(&self) -> Result<ArtifactPublicationResult, ConvergenceError> {
        // Create artifacts directory
        fs::create_dir_all(&self.config.artifacts_directory).map_err(|e| {
            ConvergenceError::ArtifactPublicationFailed {
                reason: format!("Failed to create directory: {}", e),
            }
        })?;

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let convergence_dir = self
            .config
            .artifacts_directory
            .join(format!("convergence_{}", timestamp));
        fs::create_dir_all(&convergence_dir).map_err(|e| {
            ConvergenceError::ArtifactPublicationFailed {
                reason: format!("Failed to create convergence directory: {}", e),
            }
        })?;

        let mut published_files = Vec::new();

        // Publish convergence measurements
        let measurements_file = convergence_dir.join("convergence_measurements.json");
        let measurements_json = serde_json::to_string_pretty(&self.completed_measurements)
            .map_err(|e| ConvergenceError::ArtifactPublicationFailed {
                reason: format!("Failed to serialize measurements: {}", e),
            })?;

        fs::write(&measurements_file, measurements_json).map_err(|e| {
            ConvergenceError::ArtifactPublicationFailed {
                reason: format!("Failed to write measurements file: {}", e),
            }
        })?;
        published_files.push(measurements_file);

        // Publish statistics if available
        if let Some(ref statistics) = self.latest_statistics {
            let statistics_file = convergence_dir.join("convergence_statistics.json");
            let statistics_json = serde_json::to_string_pretty(statistics).map_err(|e| {
                ConvergenceError::ArtifactPublicationFailed {
                    reason: format!("Failed to serialize statistics: {}", e),
                }
            })?;

            fs::write(&statistics_file, statistics_json).map_err(|e| {
                ConvergenceError::ArtifactPublicationFailed {
                    reason: format!("Failed to write statistics file: {}", e),
                }
            })?;
            published_files.push(statistics_file);
        }

        // Publish SLO summary
        let slo_summary_file = convergence_dir.join("slo_summary.json");
        let slo_summary = self.generate_slo_summary();
        let slo_summary_json = serde_json::to_string_pretty(&slo_summary).map_err(|e| {
            ConvergenceError::ArtifactPublicationFailed {
                reason: format!("Failed to serialize SLO summary: {}", e),
            }
        })?;

        fs::write(&slo_summary_file, slo_summary_json).map_err(|e| {
            ConvergenceError::ArtifactPublicationFailed {
                reason: format!("Failed to write SLO summary file: {}", e),
            }
        })?;
        published_files.push(slo_summary_file);

        Ok(ArtifactPublicationResult {
            artifacts_directory: convergence_dir,
            published_files,
            publication_timestamp: SystemTime::now(),
        })
    }

    /// Generate SLO compliance summary.
    pub fn generate_slo_summary(&self) -> SloSummary {
        let total_measurements = self.completed_measurements.len();
        let slo_violations = self
            .completed_measurements
            .iter()
            .filter(|m| m.slo_met == Some(false))
            .count();

        let slo_compliance_percentage = if total_measurements > 0 {
            ((total_measurements - slo_violations) as f64 / total_measurements as f64) * 100.0
        } else {
            0.0
        };

        SloSummary {
            max_convergence_time_ms: self.config.max_convergence_time_ms,
            total_measurements,
            slo_violations,
            slo_compliance_percentage,
            measurement_period_start: self.measurement_start_time,
            measurement_period_end: SystemTime::now(),
        }
    }

    /// Get current measurement statistics.
    pub fn get_measurement_summary(&self) -> MeasurementSummary {
        MeasurementSummary {
            active_measurements: self.active_measurements.len(),
            completed_measurements: self.completed_measurements.len(),
            total_measurements: self.active_measurements.len() + self.completed_measurements.len(),
            latest_statistics_available: self.latest_statistics.is_some(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper types and functions
// ---------------------------------------------------------------------------

/// Artifact publication result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPublicationResult {
    /// Directory where artifacts were published.
    pub artifacts_directory: PathBuf,
    /// List of published files.
    pub published_files: Vec<PathBuf>,
    /// Publication timestamp.
    pub publication_timestamp: SystemTime,
}

/// SLO compliance summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloSummary {
    /// Maximum convergence time threshold.
    pub max_convergence_time_ms: u64,
    /// Total measurements in the period.
    pub total_measurements: usize,
    /// Number of SLO violations.
    pub slo_violations: usize,
    /// SLO compliance percentage.
    pub slo_compliance_percentage: f64,
    /// Measurement period start.
    pub measurement_period_start: SystemTime,
    /// Measurement period end.
    pub measurement_period_end: SystemTime,
}

/// Current measurement summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeasurementSummary {
    /// Number of active (in-progress) measurements.
    pub active_measurements: usize,
    /// Number of completed measurements.
    pub completed_measurements: usize,
    /// Total measurements (active + completed).
    pub total_measurements: usize,
    /// Whether statistical analysis is available.
    pub latest_statistics_available: bool,
}

/// Errors that can occur during convergence measurement.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ConvergenceError {
    #[error("Measurement not found for evidence hash: {evidence_hash:?}")]
    MeasurementNotFound { evidence_hash: ContentHash },
    #[error("Insufficient sample size: required {required}, actual {actual}")]
    InsufficientSampleSize { required: usize, actual: usize },
    #[error("No converged measurements available for analysis")]
    NoConvergedMeasurements,
    #[error("Artifact publication failed: {reason}")]
    ArtifactPublicationFailed { reason: String },
    #[error("Partition profile not found: {profile_name}")]
    PartitionProfileNotFound { profile_name: String },
    #[error("Convergence impossible due to partition profile: {profile_name} - {reason}")]
    ConvergenceImpossible {
        profile_name: String,
        reason: String,
    },
    #[error("Failed to load partition profiles: {reason}")]
    PartitionProfileLoadError { reason: String },
}

// ---------------------------------------------------------------------------
// Partition Profile Types for Convergence Gate
// ---------------------------------------------------------------------------

/// Fleet partition fault profile for testing convergence behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPartitionProfile {
    /// Profile description.
    pub description: String,
    /// Partition mode to simulate.
    pub partition_mode: String,
    /// Message success rate percentage.
    pub message_success_rate: u8,
    /// Local partition size (if applicable).
    pub local_partition_size: Option<usize>,
    /// Total fleet size (if applicable).
    pub total_fleet_size: Option<usize>,
    /// Whether convergence is expected under this profile.
    pub expected_convergence: bool,
    /// Convergence timeout in milliseconds.
    pub convergence_timeout_ms: Option<u64>,
    /// Reason why convergence is impossible (for negative test profiles).
    pub convergence_impossible_reason: Option<String>,
    /// Failure mode classification.
    pub failure_mode: Option<String>,
    /// Gate verdict to emit for this profile.
    pub gate_verdict: Option<String>,
}

/// Collection of fleet partition fault profiles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetPartitionProfiles {
    /// Schema version.
    pub schema_version: String,
    /// Description of the profiles.
    pub description: String,
    /// Creation timestamp.
    pub created_at: String,
    /// Profile definitions indexed by name.
    pub profiles: BTreeMap<String, FleetPartitionProfile>,
    /// Gate configuration.
    pub gate_configuration: PartitionGateConfig,
}

/// Configuration for the convergence gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionGateConfig {
    /// Quorum threshold percentage.
    pub quorum_threshold_percent: u8,
    /// Minimum required nodes.
    pub minimum_required_nodes: usize,
    /// Profile names that make convergence impossible.
    pub convergence_impossible_profiles: Vec<String>,
    /// Whether to block SLO publication when convergence is impossible.
    pub slo_publication_blocked_on_impossible: bool,
    /// Whether to report failure details in run manifest.
    pub manifest_failure_reporting: bool,
}

/// Result of convergence gate evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergenceGateResult {
    /// Profile name that was evaluated.
    pub profile_name: String,
    /// Gate verdict: "convergence-possible", "convergence-impossible", "convergence-degraded".
    pub gate_verdict: String,
    /// Whether convergence is possible under this profile.
    pub convergence_possible: bool,
    /// SLO publication status.
    pub slo_publication_status: String,
    /// Reason for the verdict.
    pub verdict_reason: String,
    /// Failure mode if applicable.
    pub failure_mode: Option<String>,
    /// Gate evaluation timestamp.
    pub evaluation_timestamp: SystemTime,
    /// Profile details that led to this result.
    pub profile_details: FleetPartitionProfile,
}

/// Convergence gate that evaluates partition profiles and emits verdicts.
#[derive(Debug)]
pub struct ConvergenceGate {
    /// Loaded partition profiles.
    pub partition_profiles: FleetPartitionProfiles,
    /// Path to the partition profiles file.
    pub profiles_file_path: PathBuf,
    /// Gate evaluation history.
    pub evaluation_history: Vec<ConvergenceGateResult>,
}

impl ConvergenceGate {
    /// Load convergence gate from partition profiles file.
    pub fn load_from_file(profiles_file_path: PathBuf) -> Result<Self, ConvergenceError> {
        let profiles_content = fs::read_to_string(&profiles_file_path).map_err(|e| {
            ConvergenceError::PartitionProfileLoadError {
                reason: format!("Failed to read profiles file: {}", e),
            }
        })?;

        let partition_profiles: FleetPartitionProfiles = serde_json::from_str(&profiles_content)
            .map_err(|e| ConvergenceError::PartitionProfileLoadError {
                reason: format!("Failed to parse profiles JSON: {}", e),
            })?;

        Ok(Self {
            partition_profiles,
            profiles_file_path,
            evaluation_history: Vec::new(),
        })
    }

    /// Evaluate convergence possibility under a given partition profile.
    ///
    /// This is the core gate logic that implements the NEGATIVE TEST requirement:
    /// under permanent_split profile, it MUST emit 'convergence-impossible' verdict.
    pub fn evaluate_profile(
        &mut self,
        profile_name: &str,
    ) -> Result<ConvergenceGateResult, ConvergenceError> {
        let profile = self
            .partition_profiles
            .profiles
            .get(profile_name)
            .ok_or_else(|| ConvergenceError::PartitionProfileNotFound {
                profile_name: profile_name.to_string(),
            })?
            .clone();

        // Determine gate verdict and convergence possibility
        let (gate_verdict, convergence_possible, verdict_reason, slo_publication_status) =
            if !profile.expected_convergence {
                // NEGATIVE TEST: Profile indicates convergence is impossible
                let verdict = profile
                    .gate_verdict
                    .as_deref()
                    .unwrap_or("convergence-impossible");
                let reason = profile
                    .convergence_impossible_reason
                    .as_deref()
                    .unwrap_or("partition profile indicates convergence impossible");
                let publication_status = if self
                    .partition_profiles
                    .gate_configuration
                    .slo_publication_blocked_on_impossible
                {
                    "blocked-convergence-impossible"
                } else {
                    "allowed-despite-impossible"
                };
                (
                    verdict.to_string(),
                    false,
                    reason.to_string(),
                    publication_status.to_string(),
                )
            } else if profile.message_success_rate < 50 {
                // Degraded but potentially possible
                (
                    "convergence-degraded".to_string(),
                    true,
                    format!(
                        "degraded conditions with {}% message success rate",
                        profile.message_success_rate
                    ),
                    "allowed-degraded-conditions".to_string(),
                )
            } else {
                // Normal convergence expected
                (
                    "convergence-possible".to_string(),
                    true,
                    "normal convergence conditions".to_string(),
                    "allowed-normal-conditions".to_string(),
                )
            };

        // Check quorum requirements if partition sizes are specified
        let (final_verdict, final_possible, final_reason) =
            if let (Some(local_size), Some(total_size)) =
                (profile.local_partition_size, profile.total_fleet_size)
            {
                let quorum_required = (total_size
                    * self
                        .partition_profiles
                        .gate_configuration
                        .quorum_threshold_percent as usize)
                    / 100;
                let min_required = self
                    .partition_profiles
                    .gate_configuration
                    .minimum_required_nodes;
                let effective_required = quorum_required.max(min_required);

                if local_size < effective_required {
                    // Quorum impossible - REFUSE convergence
                    (
                        "convergence-impossible".to_string(),
                        false,
                        format!(
                            "quorum impossible: local partition {} < required {}",
                            local_size, effective_required
                        ),
                    )
                } else {
                    (gate_verdict, convergence_possible, verdict_reason)
                }
            } else {
                (gate_verdict, convergence_possible, verdict_reason)
            };

        let result = ConvergenceGateResult {
            profile_name: profile_name.to_string(),
            gate_verdict: final_verdict,
            convergence_possible: final_possible,
            slo_publication_status,
            verdict_reason: final_reason,
            failure_mode: profile.failure_mode.clone(),
            evaluation_timestamp: SystemTime::now(),
            profile_details: profile,
        };

        // Store in evaluation history
        self.evaluation_history.push(result.clone());

        Ok(result)
    }

    /// Check if convergence is impossible under a profile (NEGATIVE TEST).
    pub fn is_convergence_impossible(
        &mut self,
        profile_name: &str,
    ) -> Result<bool, ConvergenceError> {
        let result = self.evaluate_profile(profile_name)?;
        Ok(!result.convergence_possible)
    }

    /// Generate run manifest entry for convergence gate results.
    pub fn generate_run_manifest_entry(&self, profile_name: &str) -> Option<serde_json::Value> {
        if let Some(latest_result) = self
            .evaluation_history
            .iter()
            .rev()
            .find(|r| r.profile_name == profile_name)
        {
            Some(serde_json::json!({
                "convergence_gate": {
                    "profile_name": latest_result.profile_name,
                    "gate_verdict": latest_result.gate_verdict,
                    "convergence_possible": latest_result.convergence_possible,
                    "slo_publication_status": latest_result.slo_publication_status,
                    "verdict_reason": latest_result.verdict_reason,
                    "failure_mode": latest_result.failure_mode,
                    "evaluation_timestamp": latest_result.evaluation_timestamp.duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0),
                    "partition_profile_file": self.profiles_file_path.to_string_lossy()
                }
            }))
        } else {
            None
        }
    }

    /// Get the latest evaluation result for a profile.
    pub fn get_latest_result(&self, profile_name: &str) -> Option<&ConvergenceGateResult> {
        self.evaluation_history
            .iter()
            .rev()
            .find(|r| r.profile_name == profile_name)
    }

    /// Check if SLO publication should be blocked for a profile.
    pub fn should_block_slo_publication(
        &mut self,
        profile_name: &str,
    ) -> Result<bool, ConvergenceError> {
        let result = self.evaluate_profile(profile_name)?;
        Ok(!result.convergence_possible
            && self
                .partition_profiles
                .gate_configuration
                .slo_publication_blocked_on_impossible)
    }
}

/// Compute percentile from sorted vector.
fn compute_percentile(sorted_values: &[u64], percentile: f64) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }

    let index = (percentile / 100.0) * (sorted_values.len() as f64 - 1.0);
    let lower_index = index.floor() as usize;
    let upper_index = index.ceil() as usize;

    if lower_index == upper_index {
        sorted_values[lower_index]
    } else {
        let weight = index - lower_index as f64;
        let lower_value = sorted_values[lower_index] as f64;
        let upper_value = sorted_values[upper_index] as f64;
        (lower_value + weight * (upper_value - lower_value)) as u64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config() -> ConvergenceSloConfig {
        let temp_dir = TempDir::new().expect("constructor with valid inputs");
        ConvergenceSloConfig {
            max_convergence_time_ms: 500,
            artifacts_directory: temp_dir.path().to_path_buf(),
            detailed_tracking: true,
            statistical_analysis: StatisticalAnalysisConfig::default(),
        }
    }

    fn test_decision() -> QuarantineDecision {
        use crate::security_epoch::SecurityEpoch;

        QuarantineDecision::new(
            "test-extension".to_string(),
            "Test quarantine".to_string(),
            NodeId("originator".to_string()),
            1,
            SecurityEpoch::from_raw(1),
        )
    }

    #[test]
    fn test_convergence_measurement_creation() {
        let decision = test_decision();
        let measurement = ConvergenceMeasurement::new(&decision, 3);

        assert_eq!(measurement.extension_id, "test-extension");
        assert_eq!(measurement.total_instances, 3);
        assert!(!measurement.is_converged());
        assert_eq!(measurement.convergence_progress(), (0, 2)); // 3 instances - 1 originator
    }

    #[test]
    fn test_measurement_convergence() {
        let decision = test_decision();
        let mut measurement = ConvergenceMeasurement::new(&decision, 3);

        let ack_time_1 = Instant::now();
        let ack_time_2 = ack_time_1 + Duration::from_millis(10);

        measurement.record_acknowledgment(NodeId("instance-1".to_string()), ack_time_1);
        assert!(!measurement.is_converged());
        assert_eq!(measurement.convergence_progress(), (1, 2));

        measurement.record_acknowledgment(NodeId("instance-2".to_string()), ack_time_2);
        assert!(measurement.is_converged());
        assert!(measurement.convergence_duration_ms.is_some());
    }

    #[test]
    fn test_slo_evaluation() {
        let decision = test_decision();
        let mut measurement = ConvergenceMeasurement::new(&decision, 2);

        let ack_time = measurement.decision_start_time + Duration::from_millis(100);
        measurement.record_acknowledgment(NodeId("instance-1".to_string()), ack_time);

        measurement.evaluate_slo(500);
        assert_eq!(measurement.slo_met, Some(true));

        measurement.evaluate_slo(50);
        assert_eq!(measurement.slo_met, Some(false));
    }

    #[test]
    fn test_convergence_meter_basic_flow() {
        let config = test_config();
        let mut meter = ConvergenceMeter::new(config);

        let decision = test_decision();
        meter
            .start_measurement(&decision, 3)
            .expect("serde deserialization should succeed");

        assert_eq!(meter.active_measurements.len(), 1);
        assert_eq!(meter.completed_measurements.len(), 0);

        let ack_time_1 = Instant::now();
        let ack_time_2 = ack_time_1 + Duration::from_millis(10);

        // First acknowledgment
        let converged = meter
            .record_acknowledgment(
                decision.evidence_hash,
                NodeId("instance-1".to_string()),
                ack_time_1,
            )
            .expect("serde deserialization should succeed");
        assert!(!converged);
        assert_eq!(meter.active_measurements.len(), 1);

        // Second acknowledgment - should trigger convergence
        let converged = meter
            .record_acknowledgment(
                decision.evidence_hash,
                NodeId("instance-2".to_string()),
                ack_time_2,
            )
            .expect("serde deserialization should succeed");
        assert!(converged);
        assert_eq!(meter.active_measurements.len(), 0);
        assert_eq!(meter.completed_measurements.len(), 1);
    }

    #[test]
    fn test_statistical_analysis() {
        let config = ConvergenceSloConfig {
            statistical_analysis: StatisticalAnalysisConfig {
                min_sample_size: 3,
                ..Default::default()
            },
            ..test_config()
        };
        let mut meter = ConvergenceMeter::new(config);

        // Add several completed measurements
        for i in 0..5 {
            let mut measurement = ConvergenceMeasurement::new(&test_decision(), 2);
            measurement.convergence_duration_ms = Some((i + 1) * 100); // 100, 200, 300, 400, 500ms
            measurement.convergence_time = Some(Instant::now());
            measurement.evaluate_slo(350);
            meter.completed_measurements.push(measurement);
        }

        let statistics = meter
            .compute_statistics()
            .expect("serde deserialization should succeed");
        assert_eq!(statistics.total_measurements, 5);
        assert_eq!(statistics.converged_count, 5);
        assert_eq!(statistics.slo_violations, 2); // 400ms and 500ms exceed 350ms threshold
        assert_eq!(statistics.min_convergence_ms, 100);
        assert_eq!(statistics.max_convergence_ms, 500);
        assert_eq!(statistics.average_convergence_ms, 300.0);
    }

    #[test]
    fn test_percentile_computation() {
        let values = vec![100, 200, 300, 400, 500];

        assert_eq!(compute_percentile(&values, 0.0), 100);
        assert_eq!(compute_percentile(&values, 50.0), 300);
        assert_eq!(compute_percentile(&values, 100.0), 500);
        assert_eq!(compute_percentile(&values, 25.0), 200);
        assert_eq!(compute_percentile(&values, 75.0), 400);
    }

    #[test]
    fn test_measurement_not_found_error() {
        let config = test_config();
        let mut meter = ConvergenceMeter::new(config);

        let nonexistent_hash = ContentHash::compute(b"nonexistent");
        let result = meter.record_acknowledgment(
            nonexistent_hash,
            NodeId("instance-1".to_string()),
            Instant::now(),
        );

        assert!(matches!(
            result,
            Err(ConvergenceError::MeasurementNotFound { .. })
        ));
    }

    #[test]
    fn test_insufficient_sample_size_error() {
        let config = ConvergenceSloConfig {
            statistical_analysis: StatisticalAnalysisConfig {
                min_sample_size: 10,
                ..Default::default()
            },
            ..test_config()
        };
        let mut meter = ConvergenceMeter::new(config);

        // Add only 5 measurements (less than required 10)
        for i in 0..5 {
            let mut measurement = ConvergenceMeasurement::new(&test_decision(), 2);
            measurement.convergence_duration_ms = Some((i + 1) * 100);
            measurement.convergence_time = Some(Instant::now());
            meter.completed_measurements.push(measurement);
        }

        let result = meter.compute_statistics();
        assert!(matches!(
            result,
            Err(ConvergenceError::InsufficientSampleSize { .. })
        ));
    }

    #[test]
    fn test_measurement_summary() {
        let config = test_config();
        let mut meter = ConvergenceMeter::new(config);

        // Add some active and completed measurements
        let decision = test_decision();
        meter
            .start_measurement(&decision, 3)
            .expect("serde deserialization should succeed");

        let mut completed_measurement = ConvergenceMeasurement::new(&decision, 2);
        completed_measurement.convergence_duration_ms = Some(100);
        completed_measurement.convergence_time = Some(Instant::now());
        meter.completed_measurements.push(completed_measurement);

        let summary = meter.get_measurement_summary();
        assert_eq!(summary.active_measurements, 1);
        assert_eq!(summary.completed_measurements, 1);
        assert_eq!(summary.total_measurements, 2);
        assert!(!summary.latest_statistics_available);
    }
}
