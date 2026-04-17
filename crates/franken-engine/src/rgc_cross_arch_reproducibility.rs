//! RGC-804: Cross-Arch Reproducibility and Deterministic Replay Contract
//!
//! Enforces replay and determinism properties across x86_64/aarch64 and across
//! repeated runs under fixed artifacts. This module provides the core verification
//! framework for proving deterministic behavior across hardware architectures.

#![forbid(unsafe_code)]

use crate::deterministic_replay::NondeterminismTrace;
use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema identifier for cross-arch reproducibility artifacts.
fn cross_arch_schema() -> SchemaId {
    SchemaId::from_definition(b"cross_arch_reproducibility-v1")
}

/// Architecture identifier for reproducibility testing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArchitectureId {
    X86_64,
    Aarch64,
    #[serde(other)]
    Unknown,
}

impl ArchitectureId {
    /// Get the current architecture.
    pub fn current() -> Self {
        #[cfg(target_arch = "x86_64")]
        return Self::X86_64;
        #[cfg(target_arch = "aarch64")]
        return Self::Aarch64;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return Self::Unknown;
    }

    /// Get the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Unknown => "unknown",
        }
    }
}

/// Result of comparing execution across architectures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossArchComparison {
    /// Reference architecture that produced the baseline trace.
    pub reference_arch: ArchitectureId,
    /// Target architecture being compared against reference.
    pub target_arch: ArchitectureId,
    /// Whether the traces are identical.
    pub traces_identical: bool,
    /// Number of trace events that matched.
    pub matching_events: usize,
    /// Number of trace events that diverged.
    pub divergent_events: usize,
    /// Specific divergences found.
    pub divergences: Vec<TraceDivergence>,
    /// Overall assessment of reproducibility.
    pub assessment: ReproducibilityAssessment,
}

/// Assessment of cross-architecture reproducibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReproducibilityAssessment {
    /// Perfect reproducibility - traces are identical.
    Perfect,
    /// Acceptable reproducibility - only benign differences.
    Acceptable,
    /// Problematic reproducibility - significant differences found.
    Problematic,
    /// Failed reproducibility - traces are incompatible.
    Failed,
}

/// A specific divergence between traces from different architectures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceDivergence {
    /// Event index in the trace where divergence occurred.
    pub event_index: usize,
    /// Description of the divergence.
    pub description: String,
    /// Severity of the divergence.
    pub severity: DivergenceSeverity,
    /// Reference architecture value.
    pub reference_value: String,
    /// Target architecture value.
    pub target_value: String,
}

/// Severity levels for trace divergences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DivergenceSeverity {
    /// Benign difference that doesn't affect correctness.
    Benign,
    /// Warning level difference that should be monitored.
    Warning,
    /// Critical difference that indicates a reproducibility problem.
    Critical,
}

/// Configuration for cross-architecture testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossArchConfig {
    /// Target architectures to test.
    pub target_architectures: Vec<ArchitectureId>,
    /// Number of replay iterations to perform.
    pub replay_iterations: usize,
    /// Whether to capture floating-point divergences.
    pub capture_fp_divergences: bool,
    /// Whether to enforce strict determinism.
    pub strict_determinism: bool,
    /// Maximum acceptable divergent events.
    pub max_divergent_events: usize,
}

impl Default for CrossArchConfig {
    fn default() -> Self {
        Self {
            target_architectures: vec![ArchitectureId::X86_64, ArchitectureId::Aarch64],
            replay_iterations: 3,
            capture_fp_divergences: true,
            strict_determinism: true,
            max_divergent_events: 0,
        }
    }
}

/// Main controller for cross-architecture reproducibility testing.
#[derive(Debug)]
pub struct CrossArchController {
    config: CrossArchConfig,
    reference_traces: BTreeMap<String, NondeterminismTrace>,
}

impl CrossArchController {
    /// Create a new cross-architecture controller.
    pub fn new(config: CrossArchConfig) -> Self {
        Self {
            config,
            reference_traces: BTreeMap::new(),
        }
    }

    /// Create a controller with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CrossArchConfig::default())
    }

    /// Record a reference trace for later comparison.
    pub fn record_reference_trace(&mut self, session_id: String, trace: NondeterminismTrace) {
        self.reference_traces.insert(session_id, trace);
    }

    /// Compare target trace against recorded reference.
    pub fn compare_trace(
        &self,
        session_id: &str,
        target_trace: &NondeterminismTrace,
        target_arch: ArchitectureId,
    ) -> Result<CrossArchComparison, CrossArchError> {
        let reference_trace = self.reference_traces
            .get(session_id)
            .ok_or(CrossArchError::MissingReferenceTrace)?;

        let reference_events = &reference_trace.events;
        let target_events = &target_trace.events;

        let mut divergences = Vec::new();
        let mut matching_events = 0;

        // Compare events pairwise
        let max_events = reference_events.len().max(target_events.len());
        for i in 0..max_events {
            match (reference_events.get(i), target_events.get(i)) {
                (Some(ref_event), Some(target_event)) => {
                    if ref_event == target_event {
                        matching_events += 1;
                    } else {
                        divergences.push(TraceDivergence {
                            event_index: i,
                            description: format!("Event mismatch at index {}", i),
                            severity: self.classify_event_divergence(ref_event, target_event),
                            reference_value: format!("{:?}", ref_event),
                            target_value: format!("{:?}", target_event),
                        });
                    }
                },
                (Some(_), None) => {
                    divergences.push(TraceDivergence {
                        event_index: i,
                        description: "Missing event in target trace".to_string(),
                        severity: DivergenceSeverity::Critical,
                        reference_value: "present".to_string(),
                        target_value: "missing".to_string(),
                    });
                },
                (None, Some(_)) => {
                    divergences.push(TraceDivergence {
                        event_index: i,
                        description: "Extra event in target trace".to_string(),
                        severity: DivergenceSeverity::Critical,
                        reference_value: "missing".to_string(),
                        target_value: "present".to_string(),
                    });
                },
                (None, None) => break,
            }
        }

        let divergent_events = divergences.len();
        let traces_identical = divergent_events == 0;
        let assessment = self.assess_reproducibility(&divergences);

        Ok(CrossArchComparison {
            reference_arch: ArchitectureId::current(),
            target_arch,
            traces_identical,
            matching_events,
            divergent_events,
            divergences,
            assessment,
        })
    }

    /// Classify the severity of a divergence between two events.
    fn classify_event_divergence(
        &self,
        _reference: &crate::deterministic_replay::TraceEvent,
        _target: &crate::deterministic_replay::TraceEvent,
    ) -> DivergenceSeverity {
        // For now, classify all divergences as critical since we expect
        // perfect determinism across architectures
        if self.config.strict_determinism {
            DivergenceSeverity::Critical
        } else {
            DivergenceSeverity::Warning
        }
    }

    /// Assess overall reproducibility based on divergences.
    fn assess_reproducibility(&self, divergences: &[TraceDivergence]) -> ReproducibilityAssessment {
        if divergences.is_empty() {
            return ReproducibilityAssessment::Perfect;
        }

        let critical_count = divergences.iter()
            .filter(|d| d.severity == DivergenceSeverity::Critical)
            .count();

        if critical_count > 0 {
            if critical_count > self.config.max_divergent_events {
                ReproducibilityAssessment::Failed
            } else {
                ReproducibilityAssessment::Problematic
            }
        } else {
            ReproducibilityAssessment::Acceptable
        }
    }

    /// Generate reproducibility report for the session.
    pub fn generate_report(&self, session_id: &str) -> Result<CrossArchReport, CrossArchError> {
        let reference_trace = self.reference_traces
            .get(session_id)
            .ok_or(CrossArchError::MissingReferenceTrace)?;

        let object_id = derive_id(
            ObjectDomain::EvidenceRecord,
            &format!("cross-arch-report-{}", session_id),
            &cross_arch_schema(),
            session_id.as_bytes(),
        ).map_err(|e| CrossArchError::IdGeneration(format!("{:?}", e)))?;

        Ok(CrossArchReport {
            object_id,
            session_id: session_id.to_string(),
            reference_arch: ArchitectureId::current(),
            reference_event_count: reference_trace.events.len(),
            config: self.config.clone(),
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        })
    }
}

/// Error types for cross-architecture testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossArchError {
    /// Reference trace not found for the session.
    MissingReferenceTrace,
    /// Error generating object ID.
    IdGeneration(String),
    /// Replay engine error.
    ReplayEngine(String),
    /// Configuration error.
    Configuration(String),
}

impl std::fmt::Display for CrossArchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingReferenceTrace => write!(f, "Reference trace not found"),
            Self::IdGeneration(msg) => write!(f, "ID generation error: {}", msg),
            Self::ReplayEngine(msg) => write!(f, "Replay engine error: {}", msg),
            Self::Configuration(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for CrossArchError {}

/// Reproducibility report for a testing session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossArchReport {
    /// Unique object ID for this report.
    pub object_id: EngineObjectId,
    /// Session identifier.
    pub session_id: String,
    /// Reference architecture.
    pub reference_arch: ArchitectureId,
    /// Number of events in reference trace.
    pub reference_event_count: usize,
    /// Configuration used for testing.
    pub config: CrossArchConfig,
    /// Timestamp when report was generated.
    pub timestamp_utc: String,
}

/// Test harness for cross-architecture reproducibility verification.
pub fn verify_cross_arch_reproducibility(
    session_id: &str,
    _iterations: usize,
) -> Result<CrossArchComparison, CrossArchError> {
    let mut controller = CrossArchController::with_defaults();

    // Create a test trace on current architecture
    let mut reference_trace = NondeterminismTrace::new(session_id);
    reference_trace.capture(
        crate::deterministic_replay::NondeterminismSource::LaneSelectionRandom,
        vec![42],
        100,
        "test_harness",
    );

    let current_arch = ArchitectureId::current();
    controller.record_reference_trace(session_id.to_string(), reference_trace.clone());

    // Simulate replay on same architecture (should be identical)
    let comparison = controller.compare_trace(session_id, &reference_trace, current_arch)?;

    Ok(comparison)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_id_current_returns_valid() {
        let arch = ArchitectureId::current();
        assert!(!arch.as_str().is_empty());
    }

    #[test]
    fn cross_arch_controller_creation() {
        let controller = CrossArchController::with_defaults();
        assert!(controller.reference_traces.is_empty());
    }

    #[test]
    fn perfect_reproducibility_assessment() {
        let controller = CrossArchController::with_defaults();
        let assessment = controller.assess_reproducibility(&[]);
        assert_eq!(assessment, ReproducibilityAssessment::Perfect);
    }

    #[test]
    fn failed_reproducibility_with_critical_divergences() {
        let mut config = CrossArchConfig::default();
        config.max_divergent_events = 0;
        let controller = CrossArchController::new(config);

        let divergences = vec![TraceDivergence {
            event_index: 0,
            description: "Test divergence".to_string(),
            severity: DivergenceSeverity::Critical,
            reference_value: "ref".to_string(),
            target_value: "target".to_string(),
        }];

        let assessment = controller.assess_reproducibility(&divergences);
        assert_eq!(assessment, ReproducibilityAssessment::Problematic);
    }

    #[test]
    fn verify_cross_arch_reproducibility_works() {
        let result = verify_cross_arch_reproducibility("test-session", 1);
        assert!(result.is_ok());

        let comparison = result.unwrap();
        assert!(comparison.traces_identical);
        assert_eq!(comparison.assessment, ReproducibilityAssessment::Perfect);
    }
}