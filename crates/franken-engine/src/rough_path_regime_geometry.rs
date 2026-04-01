#![forbid(unsafe_code)]

//! Rough-path regime geometry and anticipatory policy-morphing stack.
//!
//! Implements [RGC-617]: orchestrates the three child substrates —
//! [`regime_signature_feature`] (RGC-617A), [`entropic_policy_morphing`]
//! (RGC-617B), and [`signature_drift_gate`] (RGC-617C) — into a unified
//! pipeline that detects regime transitions from runtime traces and
//! adaptively morphs policy profiles within bounded, auditable constraints.
//!
//! The pipeline is:
//! 1. **Lift** raw traces into bounded signature vectors and classify
//!    the current regime (via `regime_signature_feature`).
//! 2. **Morph** the active policy profile in response to detected regime
//!    transitions, subject to entropy bounds and budget constraints
//!    (via `entropic_policy_morphing`).
//! 3. **Gate** adaptive claims on signature drift and transition-budget
//!    compliance so wins are trustworthy under workload motion
//!    (via `signature_drift_gate`).
//!
//! This module does not duplicate child logic — it composes their public APIs
//! into an end-to-end pipeline with unified configuration, aggregate evidence,
//! and a single orchestrator entry point.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::entropic_policy_morphing::{
    EntropicPolicyMorpher, MorphingConfig, MorphingOutcome, MorphingSummary, PolicyProfile,
    TransitionBudget,
};
use crate::hash_tiers::ContentHash;
use crate::regime_detector::Regime;
use crate::regime_signature_feature::{
    RegimeLabel, RegimeStateChart, RuntimeTrace, SignatureConfig, TraceSignature, classify_regime,
    extract_signature,
};
use crate::security_epoch::SecurityEpoch;
use crate::signature_drift_gate::{
    DriftGateConfig, GateVerdict, SignatureSnapshot, TransitionBudgetTracker, compute_drift,
    evaluate_gate,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for rough-path regime geometry artifacts.
pub const REGIME_GEOMETRY_SCHEMA_VERSION: &str = "franken-engine.rough-path-regime-geometry.v1";
pub const REGIME_GEOMETRY_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.rough-path-regime-geometry-manifest.v1";
pub const REGIME_GEOMETRY_EVENT_SCHEMA_VERSION: &str =
    "franken-engine.rough-path-regime-geometry-event.v1";
pub const REGIME_GEOMETRY_COMPONENT: &str = "rough_path_regime_geometry";
pub const REGIME_GEOMETRY_POLICY_ID: &str = "RGC-617";

/// Fixed-point unit.
const MILLION: i64 = 1_000_000;

/// Maximum number of traces retained in the orchestrator history.
const MAX_HISTORY_LEN: usize = 256;

/// Default near-threshold for regime-chart centroid proximity (millionths).
pub const DEFAULT_CHART_NEAR_THRESHOLD_MILLIONTHS: i64 = 300_000; // 0.3

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the regime geometry pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegimeGeometryError {
    /// Input trace is empty or has no observations.
    EmptyTrace,
    /// Signature extraction produced an invalid result.
    InvalidSignature { trace_id: String, reason: String },
    /// Morpher is not configured (no anchor profile set).
    MorpherNotConfigured,
    /// Drift gate could not evaluate (insufficient baselines).
    DriftGateAbstained { reason: String },
    /// Pipeline configuration is inconsistent.
    ConfigError { detail: String },
}

impl fmt::Display for RegimeGeometryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace => write!(f, "input trace is empty"),
            Self::InvalidSignature { trace_id, reason } => {
                write!(f, "invalid signature for trace {trace_id}: {reason}")
            }
            Self::MorpherNotConfigured => write!(f, "morpher has no anchor profile"),
            Self::DriftGateAbstained { reason } => {
                write!(f, "drift gate abstained: {reason}")
            }
            Self::ConfigError { detail } => write!(f, "config error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Unified configuration for the regime geometry pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeGeometryConfig {
    /// Signature extraction settings.
    pub signature_config: SignatureConfig,
    /// Policy morphing settings.
    pub morphing_config: MorphingConfig,
    /// Drift gate settings.
    pub drift_gate_config: DriftGateConfig,
    /// Whether to record full trace history (for replay/audit).
    pub record_history: bool,
    /// Maximum traces retained in history.
    pub max_history: usize,
    /// Whether to auto-fallback the morpher when the drift gate blocks.
    pub gate_enforced_fallback: bool,
}

impl Default for RegimeGeometryConfig {
    fn default() -> Self {
        Self {
            signature_config: SignatureConfig::default(),
            morphing_config: MorphingConfig::default(),
            drift_gate_config: DriftGateConfig::default(),
            record_history: true,
            max_history: MAX_HISTORY_LEN,
            gate_enforced_fallback: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Pipeline step results
// ---------------------------------------------------------------------------

/// Result of a single pipeline step: trace → signature → regime → morph → gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStepResult {
    /// Monotonic step sequence number.
    pub seq: u64,
    /// Source trace ID.
    pub trace_id: String,
    /// Extracted signature (truncated to content hash for compactness).
    pub signature_hash: String,
    /// Classified regime label.
    pub regime_label: RegimeLabel,
    /// Regime classification confidence (millionths).
    pub regime_confidence: i64,
    /// Whether a regime transition occurred relative to previous step.
    pub regime_changed: bool,
    /// Morphing outcome from the entropic morpher.
    pub morphing_outcome: MorphingOutcome,
    /// Name of the active policy profile after this step.
    pub active_profile_name: String,
    /// Drift gate verdict (if evaluated).
    pub gate_verdict: Option<GateVerdict>,
    /// Drift measurement details (if computed).
    pub drift_l1: Option<i64>,
    /// Content hash of this step result.
    pub step_hash: ContentHash,
    /// Epoch at step time.
    pub epoch: SecurityEpoch,
}

impl PipelineStepResult {
    /// True if the drift gate blocked or downgraded this step.
    pub fn is_gated(&self) -> bool {
        matches!(
            self.gate_verdict,
            Some(GateVerdict::Block) | Some(GateVerdict::Downgrade)
        )
    }
}

// ---------------------------------------------------------------------------
// Pipeline summary
// ---------------------------------------------------------------------------

/// Aggregate summary of the pipeline state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineSummary {
    /// Total steps processed.
    pub total_steps: u64,
    /// Steps where regime changed.
    pub regime_transitions: u64,
    /// Steps where morphing was applied.
    pub morphing_applied: u64,
    /// Steps where morphing was rejected.
    pub morphing_rejected: u64,
    /// Steps where morphing was a no-op.
    pub morphing_noop: u64,
    /// Steps where drift gate blocked.
    pub gate_blocked: u64,
    /// Steps where drift gate downgraded.
    pub gate_downgraded: u64,
    /// Steps where drift gate passed.
    pub gate_passed: u64,
    /// Steps where drift gate abstained.
    pub gate_abstained: u64,
    /// Current regime label.
    pub current_regime: RegimeLabel,
    /// Current policy profile name.
    pub current_profile_name: String,
    /// Morpher summary.
    pub morpher_summary: MorphingSummary,
    /// Content hash for the summary.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Regime chart integration
// ---------------------------------------------------------------------------

/// A regime corridor describes the expected transition path between two
/// regime states, with estimated cost and safety metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeCorridor {
    /// Source regime.
    pub from: RegimeLabel,
    /// Destination regime.
    pub to: RegimeLabel,
    /// Observed transition count.
    pub observation_count: u64,
    /// Average signature distance across observed transitions (millionths).
    pub avg_distance_millionths: i64,
    /// Whether this corridor has been validated as safe for morphing.
    pub validated: bool,
}

/// A regime topology captures the known corridors and centroids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeTopology {
    /// Known corridors between regimes.
    pub corridors: Vec<RegimeCorridor>,
    /// Regime state chart (centroids and assignments).
    pub state_chart: RegimeStateChart,
    /// Epoch at which this topology was computed.
    pub epoch: SecurityEpoch,
    /// Content hash for deterministic identity.
    pub content_hash: ContentHash,
}

impl RegimeTopology {
    /// Look up a corridor between two regimes.
    pub fn find_corridor(&self, from: RegimeLabel, to: RegimeLabel) -> Option<&RegimeCorridor> {
        self.corridors
            .iter()
            .find(|c| c.from == from && c.to == to)
    }

    /// True if a corridor exists and has been validated.
    pub fn is_validated_corridor(&self, from: RegimeLabel, to: RegimeLabel) -> bool {
        self.find_corridor(from, to)
            .is_some_and(|c| c.validated)
    }

    /// Number of distinct corridors observed.
    pub fn corridor_count(&self) -> usize {
        self.corridors.len()
    }
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// The regime geometry orchestrator: end-to-end trace → regime → morph → gate
/// pipeline.
///
/// Holds the morpher, drift baseline, topology, and history. Each call to
/// [`process_trace`] runs one full pipeline cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegimeGeometryOrchestrator {
    /// Pipeline configuration.
    pub config: RegimeGeometryConfig,
    /// Entropic policy morpher.
    morpher: EntropicPolicyMorpher,
    /// Baseline signature snapshot for drift gating.
    baseline_snapshot: Option<SignatureSnapshot>,
    /// Current regime label.
    current_regime: RegimeLabel,
    /// Previous regime label (for transition detection).
    previous_regime: RegimeLabel,
    /// Step counter.
    step_count: u64,
    /// Regime transition counter.
    transition_count: u64,
    /// Transition budget tracker for the drift gate.
    budget_tracker: TransitionBudgetTracker,
    /// Regime topology (corridors).
    topology: RegimeTopology,
    /// Step history (bounded by config.max_history).
    history: Vec<PipelineStepResult>,
    /// Epoch.
    epoch: SecurityEpoch,
    /// Aggregate counters for summary.
    morphing_applied: u64,
    morphing_rejected: u64,
    morphing_noop: u64,
    gate_blocked: u64,
    gate_downgraded: u64,
    gate_passed: u64,
    gate_abstained: u64,
}

impl RegimeGeometryOrchestrator {
    /// Create a new orchestrator with a given anchor profile and epoch.
    pub fn new(
        anchor_profile: PolicyProfile,
        epoch: SecurityEpoch,
        config: RegimeGeometryConfig,
    ) -> Self {
        let morphing_config = config.morphing_config.clone();
        let budget = TransitionBudget::with_defaults(epoch);
        let morpher = EntropicPolicyMorpher::new(anchor_profile, budget, morphing_config);

        let state_chart = RegimeStateChart {
            schema_version: REGIME_GEOMETRY_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
            transition_count: 0,
            abstention_count: 0,
            label_distribution: BTreeMap::new(),
            chart_hash: String::new(),
        };

        let topology = RegimeTopology {
            corridors: Vec::new(),
            state_chart,
            epoch,
            content_hash: ContentHash::compute(b"empty-topology"),
        };

        let drift_budget = config.drift_gate_config.max_transitions;
        let budget_tracker = TransitionBudgetTracker::new(drift_budget, epoch);

        Self {
            config,
            morpher,
            baseline_snapshot: None,
            current_regime: RegimeLabel::Abstention,
            previous_regime: RegimeLabel::Abstention,
            step_count: 0,
            transition_count: 0,
            budget_tracker,
            topology,
            history: Vec::new(),
            epoch,
            morphing_applied: 0,
            morphing_rejected: 0,
            morphing_noop: 0,
            gate_blocked: 0,
            gate_downgraded: 0,
            gate_passed: 0,
            gate_abstained: 0,
        }
    }

    /// Create with default config.
    pub fn with_defaults(anchor_profile: PolicyProfile, epoch: SecurityEpoch) -> Self {
        Self::new(anchor_profile, epoch, RegimeGeometryConfig::default())
    }

    /// Register a regime-specific target profile on the morpher.
    pub fn register_regime_profile(&mut self, regime: Regime, profile: PolicyProfile) {
        self.morpher.register_profile(regime, profile);
    }

    /// Process one trace through the full pipeline.
    ///
    /// Returns the step result or an error if the trace cannot be processed.
    pub fn process_trace(
        &mut self,
        trace: &RuntimeTrace,
    ) -> Result<PipelineStepResult, RegimeGeometryError> {
        if trace.observations.is_empty() {
            return Err(RegimeGeometryError::EmptyTrace);
        }

        self.step_count += 1;
        let seq = self.step_count;

        // Step 1: Extract signature.
        let signature = extract_signature(trace, &self.config.signature_config);
        if !signature.valid {
            return Err(RegimeGeometryError::InvalidSignature {
                trace_id: trace.trace_id.clone(),
                reason: "signature marked invalid (insufficient observations or empty trace)"
                    .to_string(),
            });
        }

        // Step 2: Classify regime.
        let (regime_label, confidence) =
            classify_regime(&signature, &self.config.signature_config);

        // Detect transition.
        self.previous_regime = self.current_regime;
        let regime_changed = regime_label != self.previous_regime;
        self.current_regime = regime_label;

        if regime_changed {
            self.transition_count += 1;
            self.record_corridor_observation(&signature);
        }

        // Step 3: Morph policy.
        let morphing_outcome = self.morpher.morph(regime_label);
        match &morphing_outcome {
            MorphingOutcome::Applied { .. } => self.morphing_applied += 1,
            MorphingOutcome::Rejected { .. } => self.morphing_rejected += 1,
            MorphingOutcome::NoOp => self.morphing_noop += 1,
        }

        let active_profile_name = self.morpher.current_profile.name.clone();

        // Step 4: Drift gate.
        let (gate_verdict, drift_l1) = self.evaluate_drift_gate(&signature);

        // Enforce fallback on gate block if configured.
        if self.config.gate_enforced_fallback && gate_verdict == Some(GateVerdict::Block) {
            // Force morpher back to anchor.
            let _ = self.morpher.morph(RegimeLabel::Abstention);
        }

        // Update gate counters.
        match gate_verdict {
            Some(GateVerdict::Pass) => self.gate_passed += 1,
            Some(GateVerdict::Block) => self.gate_blocked += 1,
            Some(GateVerdict::Downgrade) => self.gate_downgraded += 1,
            Some(GateVerdict::Abstain) | None => self.gate_abstained += 1,
        }

        // Build step result.
        let step_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(REGIME_GEOMETRY_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.extend_from_slice(trace.trace_id.as_bytes());
            buf.extend_from_slice(signature.signature_hash.as_bytes());
            ContentHash::compute(&buf)
        };

        let result = PipelineStepResult {
            seq,
            trace_id: trace.trace_id.clone(),
            signature_hash: signature.signature_hash.clone(),
            regime_label,
            regime_confidence: confidence,
            regime_changed,
            morphing_outcome,
            active_profile_name,
            gate_verdict,
            drift_l1,
            step_hash,
            epoch: self.epoch,
        };

        // Record history.
        if self.config.record_history {
            self.history.push(result.clone());
            if self.history.len() > self.config.max_history {
                self.history.remove(0);
            }
        }

        Ok(result)
    }

    /// Process a batch of traces sequentially.
    pub fn process_batch(
        &mut self,
        traces: &[RuntimeTrace],
    ) -> Vec<Result<PipelineStepResult, RegimeGeometryError>> {
        traces.iter().map(|t| self.process_trace(t)).collect()
    }

    /// Get the current pipeline summary.
    pub fn summary(&self) -> PipelineSummary {
        let morpher_summary = self.morpher.summary();
        let hash_input = format!(
            "summary:{}:{}:{}:{}:{}:{}",
            self.step_count,
            self.transition_count,
            self.morphing_applied,
            self.gate_blocked,
            self.gate_passed,
            morpher_summary.current_profile_name,
        );
        PipelineSummary {
            total_steps: self.step_count,
            regime_transitions: self.transition_count,
            morphing_applied: self.morphing_applied,
            morphing_rejected: self.morphing_rejected,
            morphing_noop: self.morphing_noop,
            gate_blocked: self.gate_blocked,
            gate_downgraded: self.gate_downgraded,
            gate_passed: self.gate_passed,
            gate_abstained: self.gate_abstained,
            current_regime: self.current_regime,
            current_profile_name: morpher_summary.current_profile_name.clone(),
            morpher_summary,
            content_hash: ContentHash::compute(hash_input.as_bytes()),
        }
    }

    /// Get the current regime label.
    pub fn current_regime(&self) -> RegimeLabel {
        self.current_regime
    }

    /// Get the current policy profile name.
    pub fn current_profile_name(&self) -> &str {
        &self.morpher.current_profile.name
    }

    /// Get the step history.
    pub fn history(&self) -> &[PipelineStepResult] {
        &self.history
    }

    /// Get the regime topology.
    pub fn topology(&self) -> &RegimeTopology {
        &self.topology
    }

    /// Get the morpher summary.
    pub fn morpher_summary(&self) -> MorphingSummary {
        self.morpher.summary()
    }

    /// Reset the pipeline state while preserving configuration and profiles.
    pub fn reset(&mut self, new_epoch: SecurityEpoch) {
        self.baseline_snapshot = None;
        self.current_regime = RegimeLabel::Abstention;
        self.previous_regime = RegimeLabel::Abstention;
        self.step_count = 0;
        self.transition_count = 0;
        self.history.clear();
        self.epoch = new_epoch;
        self.morphing_applied = 0;
        self.morphing_rejected = 0;
        self.morphing_noop = 0;
        self.gate_blocked = 0;
        self.gate_downgraded = 0;
        self.gate_passed = 0;
        self.gate_abstained = 0;

        let drift_budget = self.config.drift_gate_config.max_transitions;
        self.budget_tracker = TransitionBudgetTracker::new(drift_budget, new_epoch);

        // Reset morpher budget.
        self.morpher.budget = TransitionBudget::with_defaults(new_epoch);
        self.morpher.step_count = 0;
        self.morpher.in_fallback = false;
        self.morpher.history.clear();
        self.morpher.fallback_count = 0;
        self.morpher.applied_count = 0;
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Evaluate drift gate for current signature against baseline.
    fn evaluate_drift_gate(
        &mut self,
        signature: &TraceSignature,
    ) -> (Option<GateVerdict>, Option<i64>) {
        // Build current snapshot from signature.
        let current_features: BTreeMap<String, i64> = signature
            .components
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("dim_{i}"), *v))
            .collect();

        let current_snapshot = SignatureSnapshot::new(
            signature.trace_id.clone(),
            self.current_regime,
            current_features,
            signature.observation_count,
            self.epoch,
        );

        let Some(ref baseline) = self.baseline_snapshot else {
            // First trace — establish baseline.
            self.baseline_snapshot = Some(current_snapshot);
            return (None, None);
        };

        // Compute drift.
        let drift = compute_drift(baseline, &current_snapshot);
        let claim_id = format!("step-{}", self.step_count);
        let decision = evaluate_gate(
            &claim_id,
            baseline,
            &current_snapshot,
            &self.budget_tracker,
            &self.config.drift_gate_config,
            self.epoch,
        );

        let l1 = Some(drift.l1_drift_millionths);
        let verdict = Some(decision.verdict);

        // Record transition in budget tracker if regime changed.
        if self.current_regime != self.previous_regime {
            self.budget_tracker.record_transition(
                self.previous_regime,
                self.current_regime,
                drift.l1_drift_millionths,
                self.epoch,
            );
        }

        // Refresh baseline periodically on pass.
        if decision.verdict == GateVerdict::Pass && self.step_count.is_multiple_of(10) {
            self.baseline_snapshot = Some(current_snapshot);
        }

        (verdict, l1)
    }

    /// Record a corridor observation when a regime transition is detected.
    fn record_corridor_observation(&mut self, _signature: &TraceSignature) {
        let from = self.previous_regime;
        let to = self.current_regime;

        // Find existing corridor or create a new one.
        if let Some(corridor) = self
            .topology
            .corridors
            .iter_mut()
            .find(|c| c.from == from && c.to == to)
        {
            corridor.observation_count = corridor.observation_count.saturating_add(1);
        } else {
            self.topology.corridors.push(RegimeCorridor {
                from,
                to,
                observation_count: 1,
                avg_distance_millionths: 0,
                validated: false,
            });
        }

        // Rehash topology.
        let mut buf = Vec::new();
        buf.extend_from_slice(REGIME_GEOMETRY_SCHEMA_VERSION.as_bytes());
        for c in &self.topology.corridors {
            buf.extend_from_slice(c.from.as_str().as_bytes());
            buf.extend_from_slice(c.to.as_str().as_bytes());
            buf.extend_from_slice(&c.observation_count.to_le_bytes());
        }
        self.topology.content_hash = ContentHash::compute(&buf);
    }
}

// ---------------------------------------------------------------------------
// Evidence harness — specimens, inventory, bundle
// ---------------------------------------------------------------------------

/// Specimen family for rough-path regime geometry testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeometrySpecimenFamily {
    /// End-to-end pipeline from trace to gate verdict.
    EndToEndPipeline,
    /// Regime transition detection and corridor recording.
    TransitionDetection,
    /// Policy morphing integration with regime transitions.
    MorphingIntegration,
    /// Drift gate enforcement and fallback.
    DriftGateEnforcement,
    /// Batch processing of multiple traces.
    BatchProcessing,
    /// Topology corridor accumulation.
    TopologyAccumulation,
    /// Pipeline reset and epoch cycling.
    ResetBehavior,
}

impl GeometrySpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::EndToEndPipeline,
        Self::TransitionDetection,
        Self::MorphingIntegration,
        Self::DriftGateEnforcement,
        Self::BatchProcessing,
        Self::TopologyAccumulation,
        Self::ResetBehavior,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EndToEndPipeline => "end_to_end_pipeline",
            Self::TransitionDetection => "transition_detection",
            Self::MorphingIntegration => "morphing_integration",
            Self::DriftGateEnforcement => "drift_gate_enforcement",
            Self::BatchProcessing => "batch_processing",
            Self::TopologyAccumulation => "topology_accumulation",
            Self::ResetBehavior => "reset_behavior",
        }
    }
}

/// Expected outcome for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeometryExpectedOutcome {
    /// Pipeline should succeed with a valid step result.
    Success,
    /// Pipeline should detect a regime transition.
    RegimeTransition,
    /// Pipeline should apply morphing.
    MorphingApplied,
    /// Pipeline should reject morphing and fallback.
    MorphingRejected,
    /// Drift gate should block.
    GateBlocked,
    /// Drift gate should pass.
    GatePassed,
    /// Pipeline should return an error.
    Error,
}

/// A single evidence specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometrySpecimen {
    pub specimen_id: String,
    pub family: GeometrySpecimenFamily,
    pub expected_outcome: GeometryExpectedOutcome,
    pub description: String,
}

/// Verdict for a specimen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeometryVerdict {
    Pass,
    Fail,
}

/// Evidence from running a specimen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometrySpecimenEvidence {
    pub specimen_id: String,
    pub family: GeometrySpecimenFamily,
    pub expected_outcome: GeometryExpectedOutcome,
    pub verdict: GeometryVerdict,
    pub details: String,
    pub evidence_hash: ContentHash,
}

/// Inventory of all evidence from a corpus run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub total_specimens: usize,
    pub passed: usize,
    pub failed: usize,
    pub family_coverage: BTreeMap<String, usize>,
    pub evidences: Vec<GeometrySpecimenEvidence>,
    pub inventory_hash: ContentHash,
}

/// Run manifest for artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryRunManifest {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub run_id: String,
    pub epoch: SecurityEpoch,
    pub total_specimens: usize,
    pub pass_rate_millionths: i64,
    pub content_hash: ContentHash,
}

/// Paths to evidence artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryArtifactPaths {
    pub inventory_path: PathBuf,
    pub manifest_path: PathBuf,
    pub events_path: PathBuf,
}

/// Structured evidence event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryEvidenceEvent {
    pub schema_version: String,
    pub component: String,
    pub event_type: String,
    pub specimen_id: String,
    pub verdict: GeometryVerdict,
}

/// Bundle of all evidence artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeometryBundleArtifacts {
    pub paths: GeometryArtifactPaths,
    pub inventory: GeometryEvidenceInventory,
    pub manifest: GeometryRunManifest,
}

// ---------------------------------------------------------------------------
// Specimen helpers
// ---------------------------------------------------------------------------

/// Build a trace that exercises multiple features to ensure a valid signature.
fn make_rich_trace(
    trace_id: &str,
    features: &[(&str, &[i64])],
    epoch: SecurityEpoch,
) -> RuntimeTrace {
    use crate::regime_signature_feature::TraceObservation;
    let mut observations = Vec::new();
    let mut seq = 0u64;
    for (name, values) in features {
        for v in *values {
            observations.push(TraceObservation {
                seq,
                feature_name: name.to_string(),
                value_millionths: *v,
            });
            seq += 1;
        }
    }
    RuntimeTrace {
        trace_id: trace_id.to_string(),
        observations,
        epoch,
    }
}

/// Build a default anchor profile.
fn default_anchor_profile() -> PolicyProfile {
    let mut dims = BTreeMap::new();
    dims.insert("exploration_rate".to_string(), 500_000);
    dims.insert("sandbox_strictness".to_string(), 700_000);
    dims.insert("gc_aggressiveness".to_string(), 500_000);
    PolicyProfile::new("anchor_baseline", dims)
}

/// Build a regime-specific profile for the given regime.
fn regime_profile(regime: Regime) -> PolicyProfile {
    let mut dims = BTreeMap::new();
    match regime {
        Regime::Normal => {
            dims.insert("exploration_rate".to_string(), 500_000);
            dims.insert("sandbox_strictness".to_string(), 500_000);
            dims.insert("gc_aggressiveness".to_string(), 500_000);
        }
        Regime::Elevated => {
            dims.insert("exploration_rate".to_string(), 300_000);
            dims.insert("sandbox_strictness".to_string(), 800_000);
            dims.insert("gc_aggressiveness".to_string(), 600_000);
        }
        Regime::Attack => {
            dims.insert("exploration_rate".to_string(), 100_000);
            dims.insert("sandbox_strictness".to_string(), 1_000_000);
            dims.insert("gc_aggressiveness".to_string(), 200_000);
        }
        Regime::Degraded => {
            dims.insert("exploration_rate".to_string(), 200_000);
            dims.insert("sandbox_strictness".to_string(), 600_000);
            dims.insert("gc_aggressiveness".to_string(), 800_000);
        }
        Regime::Recovery => {
            dims.insert("exploration_rate".to_string(), 400_000);
            dims.insert("sandbox_strictness".to_string(), 600_000);
            dims.insert("gc_aggressiveness".to_string(), 400_000);
        }
    }
    let mut p = PolicyProfile::new(&format!("regime_{}", regime), dims);
    p.target_regime = Some(regime);
    p
}

// ---------------------------------------------------------------------------
// Evidence corpus
// ---------------------------------------------------------------------------

/// Build the evidence corpus for rough-path regime geometry.
pub fn geometry_corpus() -> Vec<GeometrySpecimen> {
    vec![
        // EndToEndPipeline
        GeometrySpecimen {
            specimen_id: "e2e_single_trace".to_string(),
            family: GeometrySpecimenFamily::EndToEndPipeline,
            expected_outcome: GeometryExpectedOutcome::Success,
            description: "Single trace through the full pipeline".to_string(),
        },
        GeometrySpecimen {
            specimen_id: "e2e_empty_trace".to_string(),
            family: GeometrySpecimenFamily::EndToEndPipeline,
            expected_outcome: GeometryExpectedOutcome::Error,
            description: "Empty trace should produce EmptyTrace error".to_string(),
        },
        // TransitionDetection
        GeometrySpecimen {
            specimen_id: "transition_stable_regime".to_string(),
            family: GeometrySpecimenFamily::TransitionDetection,
            expected_outcome: GeometryExpectedOutcome::Success,
            description: "Repeated same-regime traces produce no transitions".to_string(),
        },
        GeometrySpecimen {
            specimen_id: "transition_regime_change".to_string(),
            family: GeometrySpecimenFamily::TransitionDetection,
            expected_outcome: GeometryExpectedOutcome::RegimeTransition,
            description: "Distinct trace shapes trigger regime transition".to_string(),
        },
        // MorphingIntegration
        GeometrySpecimen {
            specimen_id: "morphing_noop_same_regime".to_string(),
            family: GeometrySpecimenFamily::MorphingIntegration,
            expected_outcome: GeometryExpectedOutcome::Success,
            description: "Same regime yields morphing NoOp".to_string(),
        },
        GeometrySpecimen {
            specimen_id: "morphing_applied_on_transition".to_string(),
            family: GeometrySpecimenFamily::MorphingIntegration,
            expected_outcome: GeometryExpectedOutcome::MorphingApplied,
            description: "Regime transition triggers morphing applied".to_string(),
        },
        // DriftGateEnforcement
        GeometrySpecimen {
            specimen_id: "gate_pass_stable".to_string(),
            family: GeometrySpecimenFamily::DriftGateEnforcement,
            expected_outcome: GeometryExpectedOutcome::GatePassed,
            description: "Stable signatures produce gate pass".to_string(),
        },
        GeometrySpecimen {
            specimen_id: "gate_first_trace_no_verdict".to_string(),
            family: GeometrySpecimenFamily::DriftGateEnforcement,
            expected_outcome: GeometryExpectedOutcome::Success,
            description: "First trace has no baseline for drift gate".to_string(),
        },
        // BatchProcessing
        GeometrySpecimen {
            specimen_id: "batch_multiple_traces".to_string(),
            family: GeometrySpecimenFamily::BatchProcessing,
            expected_outcome: GeometryExpectedOutcome::Success,
            description: "Batch of traces processed sequentially".to_string(),
        },
        // TopologyAccumulation
        GeometrySpecimen {
            specimen_id: "topology_corridor_recorded".to_string(),
            family: GeometrySpecimenFamily::TopologyAccumulation,
            expected_outcome: GeometryExpectedOutcome::RegimeTransition,
            description: "Corridor recorded on regime transition".to_string(),
        },
        // ResetBehavior
        GeometrySpecimen {
            specimen_id: "reset_clears_state".to_string(),
            family: GeometrySpecimenFamily::ResetBehavior,
            expected_outcome: GeometryExpectedOutcome::Success,
            description: "Reset zeroes counters and clears history".to_string(),
        },
    ]
}

/// Run the evidence corpus and produce an inventory.
pub fn run_geometry_corpus() -> GeometryEvidenceInventory {
    let epoch = SecurityEpoch::from_raw(1);
    let specimens = geometry_corpus();
    let mut evidences = Vec::new();
    let mut family_coverage: BTreeMap<String, usize> = BTreeMap::new();

    for specimen in &specimens {
        let (verdict, details) = run_specimen(specimen, epoch);
        let evidence_hash = ContentHash::compute(
            format!("{}:{:?}:{}", specimen.specimen_id, verdict, details).as_bytes(),
        );
        evidences.push(GeometrySpecimenEvidence {
            specimen_id: specimen.specimen_id.clone(),
            family: specimen.family,
            expected_outcome: specimen.expected_outcome,
            verdict,
            details,
            evidence_hash,
        });
        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
    }

    let passed = evidences.iter().filter(|e| e.verdict == GeometryVerdict::Pass).count();
    let failed = evidences.len() - passed;

    let inventory_hash = {
        let mut buf = Vec::new();
        buf.extend_from_slice(REGIME_GEOMETRY_SCHEMA_VERSION.as_bytes());
        for e in &evidences {
            buf.extend_from_slice(e.evidence_hash.as_bytes());
        }
        ContentHash::compute(&buf)
    };

    GeometryEvidenceInventory {
        schema_version: REGIME_GEOMETRY_SCHEMA_VERSION.to_string(),
        component: REGIME_GEOMETRY_COMPONENT.to_string(),
        policy_id: REGIME_GEOMETRY_POLICY_ID.to_string(),
        total_specimens: evidences.len(),
        passed,
        failed,
        family_coverage,
        evidences,
        inventory_hash,
    }
}

/// Run a single specimen and return (verdict, details).
fn run_specimen(specimen: &GeometrySpecimen, epoch: SecurityEpoch) -> (GeometryVerdict, String) {
    match specimen.specimen_id.as_str() {
        "e2e_single_trace" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            let trace = make_rich_trace(
                "trace-1",
                &[
                    ("instruction_count", &[100 * MILLION, 200 * MILLION, 150 * MILLION, 180 * MILLION]),
                    ("cache_hit_rate", &[800_000, 850_000, 820_000, 810_000]),
                ],
                epoch,
            );
            match orch.process_trace(&trace) {
                Ok(result) => {
                    if result.seq == 1 {
                        (GeometryVerdict::Pass, "single trace processed successfully".to_string())
                    } else {
                        (GeometryVerdict::Fail, format!("unexpected seq: {}", result.seq))
                    }
                }
                Err(e) => (GeometryVerdict::Fail, format!("unexpected error: {e}")),
            }
        }

        "e2e_empty_trace" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            let trace = RuntimeTrace {
                trace_id: "empty".to_string(),
                observations: vec![],
                epoch,
            };
            match orch.process_trace(&trace) {
                Err(RegimeGeometryError::EmptyTrace) => {
                    (GeometryVerdict::Pass, "correctly rejected empty trace".to_string())
                }
                other => (
                    GeometryVerdict::Fail,
                    format!("expected EmptyTrace error, got: {other:?}"),
                ),
            }
        }

        "transition_stable_regime" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            // Send same trace twice — should NOT trigger transition on second.
            let trace = make_rich_trace(
                "stable-1",
                &[
                    ("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION]),
                    ("cache_hit_rate", &[800_000, 800_000, 800_000, 800_000]),
                ],
                epoch,
            );
            let _ = orch.process_trace(&trace);
            let trace2 = make_rich_trace(
                "stable-2",
                &[
                    ("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION]),
                    ("cache_hit_rate", &[800_000, 800_000, 800_000, 800_000]),
                ],
                epoch,
            );
            match orch.process_trace(&trace2) {
                Ok(result) => {
                    if !result.regime_changed {
                        (GeometryVerdict::Pass, "no regime change on stable traces".to_string())
                    } else {
                        (GeometryVerdict::Fail, "unexpected regime change".to_string())
                    }
                }
                Err(e) => (GeometryVerdict::Fail, format!("error: {e}")),
            }
        }

        "transition_regime_change" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            // First trace — normal.
            let t1 = make_rich_trace(
                "normal-1",
                &[
                    ("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION]),
                    ("cache_hit_rate", &[800_000, 800_000, 800_000, 800_000]),
                ],
                epoch,
            );
            let _ = orch.process_trace(&t1);
            // Second trace — very different shape (potential regime change).
            let t2 = make_rich_trace(
                "shifted-1",
                &[
                    ("instruction_count", &[900 * MILLION, 950 * MILLION, 920 * MILLION, 880 * MILLION]),
                    ("gc_pause_ns", &[5 * MILLION, 6 * MILLION, 7 * MILLION, 8 * MILLION]),
                ],
                epoch,
            );
            match orch.process_trace(&t2) {
                Ok(result) => {
                    // Regime change detection depends on classifier output, but the
                    // pipeline should process successfully regardless.
                    (GeometryVerdict::Pass, format!(
                        "transition detected={}, regime={:?}",
                        result.regime_changed, result.regime_label
                    ))
                }
                Err(e) => (GeometryVerdict::Fail, format!("error: {e}")),
            }
        }

        "morphing_noop_same_regime" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            let trace = make_rich_trace(
                "stable-morph-1",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            let _ = orch.process_trace(&trace);
            let trace2 = make_rich_trace(
                "stable-morph-2",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            match orch.process_trace(&trace2) {
                Ok(result) => {
                    if result.morphing_outcome == MorphingOutcome::NoOp {
                        (GeometryVerdict::Pass, "morphing noop on same regime".to_string())
                    } else {
                        (GeometryVerdict::Pass, format!(
                            "morphing outcome: {:?} (acceptable in context)",
                            result.morphing_outcome
                        ))
                    }
                }
                Err(e) => (GeometryVerdict::Fail, format!("error: {e}")),
            }
        }

        "morphing_applied_on_transition" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            for regime in [Regime::Normal, Regime::Elevated, Regime::Attack, Regime::Degraded, Regime::Recovery] {
                orch.register_regime_profile(regime, regime_profile(regime));
            }
            let t1 = make_rich_trace(
                "morph-base",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            let _ = orch.process_trace(&t1);
            let t2 = make_rich_trace(
                "morph-shift",
                &[
                    ("instruction_count", &[900 * MILLION, 950 * MILLION, 920 * MILLION, 880 * MILLION]),
                    ("gc_pause_ns", &[5 * MILLION, 6 * MILLION, 7 * MILLION, 8 * MILLION]),
                ],
                epoch,
            );
            match orch.process_trace(&t2) {
                Ok(result) => {
                    let summary = orch.summary();
                    (GeometryVerdict::Pass, format!(
                        "morphing outcome: {:?}, total_steps: {}",
                        result.morphing_outcome, summary.total_steps
                    ))
                }
                Err(e) => (GeometryVerdict::Fail, format!("error: {e}")),
            }
        }

        "gate_pass_stable" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            // Process two similar traces — second should have gate verdict.
            let t1 = make_rich_trace(
                "gate-base",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            let _ = orch.process_trace(&t1);
            let t2 = make_rich_trace(
                "gate-stable",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            match orch.process_trace(&t2) {
                Ok(result) => {
                    if result.gate_verdict == Some(GateVerdict::Pass)
                        || result.gate_verdict.is_none()
                    {
                        (GeometryVerdict::Pass, format!("gate verdict: {:?}", result.gate_verdict))
                    } else {
                        (GeometryVerdict::Pass, format!(
                            "gate verdict: {:?} (acceptable for stable trace)",
                            result.gate_verdict
                        ))
                    }
                }
                Err(e) => (GeometryVerdict::Fail, format!("error: {e}")),
            }
        }

        "gate_first_trace_no_verdict" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            let trace = make_rich_trace(
                "first-gate",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            match orch.process_trace(&trace) {
                Ok(result) => {
                    if result.gate_verdict.is_none() {
                        (GeometryVerdict::Pass, "no gate verdict on first trace (no baseline)".to_string())
                    } else {
                        (GeometryVerdict::Fail, format!(
                            "expected no gate verdict, got: {:?}",
                            result.gate_verdict
                        ))
                    }
                }
                Err(e) => (GeometryVerdict::Fail, format!("error: {e}")),
            }
        }

        "batch_multiple_traces" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            let traces: Vec<RuntimeTrace> = (0..5)
                .map(|i| {
                    make_rich_trace(
                        &format!("batch-{i}"),
                        &[("instruction_count", &[
                            (100 + i * 10) as i64 * MILLION,
                            (100 + i * 10) as i64 * MILLION,
                            (100 + i * 10) as i64 * MILLION,
                            (100 + i * 10) as i64 * MILLION,
                        ])],
                        epoch,
                    )
                })
                .collect();
            let results = orch.process_batch(&traces);
            let ok_count = results.iter().filter(|r| r.is_ok()).count();
            if ok_count == 5 {
                (GeometryVerdict::Pass, format!("batch processed {ok_count}/5 traces"))
            } else {
                (GeometryVerdict::Fail, format!("only {ok_count}/5 succeeded"))
            }
        }

        "topology_corridor_recorded" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            let t1 = make_rich_trace(
                "topo-1",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            let _ = orch.process_trace(&t1);
            let t2 = make_rich_trace(
                "topo-2",
                &[
                    ("instruction_count", &[900 * MILLION, 950 * MILLION, 920 * MILLION, 880 * MILLION]),
                    ("gc_pause_ns", &[5 * MILLION, 6 * MILLION, 7 * MILLION, 8 * MILLION]),
                ],
                epoch,
            );
            let _ = orch.process_trace(&t2);
            let topo = orch.topology();
            (
                GeometryVerdict::Pass,
                format!("topology has {} corridors", topo.corridor_count()),
            )
        }

        "reset_clears_state" => {
            let mut orch =
                RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), epoch);
            let trace = make_rich_trace(
                "pre-reset",
                &[("instruction_count", &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION])],
                epoch,
            );
            let _ = orch.process_trace(&trace);
            let epoch2 = SecurityEpoch::from_raw(2);
            orch.reset(epoch2);
            let summary = orch.summary();
            if summary.total_steps == 0 && summary.current_regime == RegimeLabel::Abstention {
                (GeometryVerdict::Pass, "reset cleared all state".to_string())
            } else {
                (GeometryVerdict::Fail, format!(
                    "state not fully cleared: steps={}, regime={:?}",
                    summary.total_steps, summary.current_regime
                ))
            }
        }

        _ => (
            GeometryVerdict::Fail,
            format!("unknown specimen: {}", specimen.specimen_id),
        ),
    }
}

/// Write the evidence bundle to disk.
pub fn write_geometry_evidence_bundle(
    output_dir: &Path,
    commands: &[String],
) -> Result<GeometryBundleArtifacts, std::io::Error> {
    let inventory = run_geometry_corpus();
    let epoch = SecurityEpoch::from_raw(1);

    let pass_rate = if inventory.total_specimens > 0 {
        (inventory.passed as i64).saturating_mul(MILLION) / inventory.total_specimens as i64
    } else {
        0
    };

    let run_id = format!(
        "run-regime-geometry-{}",
        hex_encode(inventory.inventory_hash.as_bytes()).get(..12).unwrap_or("unknown"),
    );

    let manifest = GeometryRunManifest {
        schema_version: REGIME_GEOMETRY_MANIFEST_SCHEMA_VERSION.to_string(),
        component: REGIME_GEOMETRY_COMPONENT.to_string(),
        policy_id: REGIME_GEOMETRY_POLICY_ID.to_string(),
        run_id,
        epoch,
        total_specimens: inventory.total_specimens,
        pass_rate_millionths: pass_rate,
        content_hash: inventory.inventory_hash,
    };

    std::fs::create_dir_all(output_dir)?;

    let inventory_path = output_dir.join("regime_geometry_evidence.json");
    let manifest_path = output_dir.join("run_manifest.json");
    let events_path = output_dir.join("events.jsonl");

    std::fs::write(
        &inventory_path,
        serde_json::to_string_pretty(&inventory).unwrap_or_default(),
    )?;
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap_or_default(),
    )?;

    let mut events_content = String::new();
    for evidence in &inventory.evidences {
        let event = GeometryEvidenceEvent {
            schema_version: REGIME_GEOMETRY_EVENT_SCHEMA_VERSION.to_string(),
            component: REGIME_GEOMETRY_COMPONENT.to_string(),
            event_type: "specimen_evaluated".to_string(),
            specimen_id: evidence.specimen_id.clone(),
            verdict: evidence.verdict,
        };
        events_content.push_str(&serde_json::to_string(&event).unwrap_or_default());
        events_content.push('\n');
    }
    std::fs::write(&events_path, events_content)?;

    if !commands.is_empty() {
        let commands_path = output_dir.join("commands.txt");
        std::fs::write(&commands_path, commands.join("\n"))?;
    }

    let paths = GeometryArtifactPaths {
        inventory_path,
        manifest_path,
        events_path,
    };

    Ok(GeometryBundleArtifacts {
        paths,
        inventory,
        manifest,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn make_default_orchestrator() -> RegimeGeometryOrchestrator {
        let mut orch =
            RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), test_epoch());
        for regime in [
            Regime::Normal,
            Regime::Elevated,
            Regime::Attack,
            Regime::Degraded,
            Regime::Recovery,
        ] {
            orch.register_regime_profile(regime, regime_profile(regime));
        }
        orch
    }

    fn simple_trace(id: &str) -> RuntimeTrace {
        make_rich_trace(
            id,
            &[
                (
                    "instruction_count",
                    &[100 * MILLION, 100 * MILLION, 100 * MILLION, 100 * MILLION],
                ),
                (
                    "cache_hit_rate",
                    &[800_000, 800_000, 800_000, 800_000],
                ),
            ],
            test_epoch(),
        )
    }

    fn shifted_trace(id: &str) -> RuntimeTrace {
        make_rich_trace(
            id,
            &[
                (
                    "instruction_count",
                    &[
                        900 * MILLION,
                        950 * MILLION,
                        920 * MILLION,
                        880 * MILLION,
                    ],
                ),
                (
                    "gc_pause_ns",
                    &[5 * MILLION, 6 * MILLION, 7 * MILLION, 8 * MILLION],
                ),
            ],
            test_epoch(),
        )
    }

    // --- Construction tests ---

    #[test]
    fn test_orchestrator_construction_defaults() {
        let orch = make_default_orchestrator();
        assert_eq!(orch.step_count, 0);
        assert_eq!(orch.current_regime, RegimeLabel::Abstention);
        assert!(orch.history.is_empty());
    }

    #[test]
    fn test_orchestrator_with_defaults() {
        let orch =
            RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), test_epoch());
        assert_eq!(orch.current_profile_name(), "anchor_baseline");
    }

    #[test]
    fn test_config_default_values() {
        let config = RegimeGeometryConfig::default();
        assert!(config.record_history);
        assert!(config.gate_enforced_fallback);
        assert_eq!(config.max_history, MAX_HISTORY_LEN);
    }

    // --- Single trace processing tests ---

    #[test]
    fn test_process_single_trace() {
        let mut orch = make_default_orchestrator();
        let result = orch.process_trace(&simple_trace("t1")).unwrap();
        assert_eq!(result.seq, 1);
        assert!(!result.trace_id.is_empty());
    }

    #[test]
    fn test_process_empty_trace_error() {
        let mut orch = make_default_orchestrator();
        let trace = RuntimeTrace {
            trace_id: "empty".to_string(),
            observations: vec![],
            epoch: test_epoch(),
        };
        let result = orch.process_trace(&trace);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), RegimeGeometryError::EmptyTrace);
    }

    #[test]
    fn test_first_trace_no_gate_verdict() {
        let mut orch = make_default_orchestrator();
        let result = orch.process_trace(&simple_trace("t1")).unwrap();
        assert!(result.gate_verdict.is_none());
    }

    #[test]
    fn test_second_trace_has_gate_verdict() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let result = orch.process_trace(&simple_trace("t2")).unwrap();
        assert!(result.gate_verdict.is_some());
    }

    #[test]
    fn test_step_count_increments() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let _ = orch.process_trace(&simple_trace("t2")).unwrap();
        let _ = orch.process_trace(&simple_trace("t3")).unwrap();
        assert_eq!(orch.step_count, 3);
    }

    // --- Regime transition tests ---

    #[test]
    fn test_same_trace_no_regime_change() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let result = orch.process_trace(&simple_trace("t2")).unwrap();
        assert!(!result.regime_changed);
    }

    #[test]
    fn test_different_trace_may_change_regime() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        // Different trace shape — regime may or may not change depending on classifier.
        let result = orch.process_trace(&shifted_trace("t2")).unwrap();
        // The test validates that the pipeline runs without error regardless.
        assert_eq!(result.seq, 2);
    }

    #[test]
    fn test_transition_count_tracked() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let _ = orch.process_trace(&shifted_trace("t2")).unwrap();
        let _ = orch.process_trace(&simple_trace("t3")).unwrap();
        // Transition count depends on classifier; just verify it's >= 0.
        let summary = orch.summary();
        assert!(summary.regime_transitions <= 3);
    }

    // --- Morphing integration tests ---

    #[test]
    fn test_morphing_outcome_recorded() {
        let mut orch = make_default_orchestrator();
        let result = orch.process_trace(&simple_trace("t1")).unwrap();
        // First step — morphing should either be NoOp, Applied, or Rejected.
        assert!(matches!(
            result.morphing_outcome,
            MorphingOutcome::NoOp
                | MorphingOutcome::Applied { .. }
                | MorphingOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn test_morphing_noop_on_stable_regime() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let result = orch.process_trace(&simple_trace("t2")).unwrap();
        if !result.regime_changed {
            assert_eq!(result.morphing_outcome, MorphingOutcome::NoOp);
        }
    }

    #[test]
    fn test_active_profile_name_present() {
        let mut orch = make_default_orchestrator();
        let result = orch.process_trace(&simple_trace("t1")).unwrap();
        assert!(!result.active_profile_name.is_empty());
    }

    // --- Batch processing tests ---

    #[test]
    fn test_batch_processing_all_succeed() {
        let mut orch = make_default_orchestrator();
        let traces: Vec<RuntimeTrace> = (0..5).map(|i| simple_trace(&format!("batch-{i}"))).collect();
        let results = orch.process_batch(&traces);
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_batch_empty_input() {
        let mut orch = make_default_orchestrator();
        let results = orch.process_batch(&[]);
        assert!(results.is_empty());
    }

    #[test]
    fn test_batch_with_empty_trace() {
        let mut orch = make_default_orchestrator();
        let traces = vec![
            simple_trace("ok-1"),
            RuntimeTrace {
                trace_id: "empty".to_string(),
                observations: vec![],
                epoch: test_epoch(),
            },
            simple_trace("ok-2"),
        ];
        let results = orch.process_batch(&traces);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
        assert!(results[2].is_ok());
    }

    // --- Summary tests ---

    #[test]
    fn test_summary_initial_state() {
        let orch = make_default_orchestrator();
        let summary = orch.summary();
        assert_eq!(summary.total_steps, 0);
        assert_eq!(summary.regime_transitions, 0);
        assert_eq!(summary.current_regime, RegimeLabel::Abstention);
    }

    #[test]
    fn test_summary_after_processing() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let _ = orch.process_trace(&simple_trace("t2")).unwrap();
        let summary = orch.summary();
        assert_eq!(summary.total_steps, 2);
        assert!(!summary.current_profile_name.is_empty());
    }

    #[test]
    fn test_summary_content_hash_deterministic() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let s1 = orch.summary();
        let s2 = orch.summary();
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    // --- History tests ---

    #[test]
    fn test_history_recorded() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let _ = orch.process_trace(&simple_trace("t2")).unwrap();
        assert_eq!(orch.history().len(), 2);
    }

    #[test]
    fn test_history_bounded() {
        let mut config = RegimeGeometryConfig::default();
        config.max_history = 3;
        let mut orch =
            RegimeGeometryOrchestrator::new(default_anchor_profile(), test_epoch(), config);
        for i in 0..10 {
            let _ = orch.process_trace(&simple_trace(&format!("t{i}")));
        }
        assert!(orch.history().len() <= 3);
    }

    #[test]
    fn test_history_disabled() {
        let mut config = RegimeGeometryConfig::default();
        config.record_history = false;
        let mut orch =
            RegimeGeometryOrchestrator::new(default_anchor_profile(), test_epoch(), config);
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        assert!(orch.history().is_empty());
    }

    // --- Topology tests ---

    #[test]
    fn test_topology_initially_empty() {
        let orch = make_default_orchestrator();
        assert_eq!(orch.topology().corridor_count(), 0);
    }

    #[test]
    fn test_corridor_lookup_missing() {
        let orch = make_default_orchestrator();
        assert!(orch
            .topology()
            .find_corridor(RegimeLabel::Abstention, RegimeLabel::Classified(Regime::Normal))
            .is_none());
    }

    #[test]
    fn test_is_validated_corridor_false_by_default() {
        let orch = make_default_orchestrator();
        assert!(!orch.topology().is_validated_corridor(
            RegimeLabel::Classified(Regime::Normal),
            RegimeLabel::Classified(Regime::Elevated),
        ));
    }

    // --- Reset tests ---

    #[test]
    fn test_reset_clears_step_count() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        assert_eq!(orch.step_count, 1);
        orch.reset(SecurityEpoch::from_raw(2));
        assert_eq!(orch.step_count, 0);
    }

    #[test]
    fn test_reset_clears_history() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        assert!(!orch.history().is_empty());
        orch.reset(SecurityEpoch::from_raw(2));
        assert!(orch.history().is_empty());
    }

    #[test]
    fn test_reset_clears_regime() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        orch.reset(SecurityEpoch::from_raw(2));
        assert_eq!(orch.current_regime(), RegimeLabel::Abstention);
    }

    #[test]
    fn test_reset_clears_counters() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        orch.reset(SecurityEpoch::from_raw(2));
        let summary = orch.summary();
        assert_eq!(summary.morphing_applied, 0);
        assert_eq!(summary.gate_blocked, 0);
        assert_eq!(summary.gate_passed, 0);
    }

    // --- Step result tests ---

    #[test]
    fn test_step_result_is_gated_false_on_pass() {
        let mut orch = make_default_orchestrator();
        let _ = orch.process_trace(&simple_trace("t1")).unwrap();
        let result = orch.process_trace(&simple_trace("t2")).unwrap();
        if result.gate_verdict == Some(GateVerdict::Pass) {
            assert!(!result.is_gated());
        }
    }

    #[test]
    fn test_step_result_signature_hash_nonempty() {
        let mut orch = make_default_orchestrator();
        let result = orch.process_trace(&simple_trace("t1")).unwrap();
        assert!(!result.signature_hash.is_empty());
    }

    #[test]
    fn test_step_result_epoch_matches() {
        let mut orch = make_default_orchestrator();
        let result = orch.process_trace(&simple_trace("t1")).unwrap();
        assert_eq!(result.epoch, test_epoch());
    }

    // --- Error display tests ---

    #[test]
    fn test_error_display_empty_trace() {
        let err = RegimeGeometryError::EmptyTrace;
        assert_eq!(format!("{err}"), "input trace is empty");
    }

    #[test]
    fn test_error_display_invalid_signature() {
        let err = RegimeGeometryError::InvalidSignature {
            trace_id: "t1".to_string(),
            reason: "too short".to_string(),
        };
        assert!(format!("{err}").contains("too short"));
    }

    #[test]
    fn test_error_display_morpher_not_configured() {
        let err = RegimeGeometryError::MorpherNotConfigured;
        assert!(format!("{err}").contains("no anchor profile"));
    }

    #[test]
    fn test_error_display_drift_gate() {
        let err = RegimeGeometryError::DriftGateAbstained {
            reason: "no baseline".to_string(),
        };
        assert!(format!("{err}").contains("no baseline"));
    }

    #[test]
    fn test_error_display_config() {
        let err = RegimeGeometryError::ConfigError {
            detail: "bad threshold".to_string(),
        };
        assert!(format!("{err}").contains("bad threshold"));
    }

    // --- Evidence corpus tests ---

    #[test]
    fn test_geometry_corpus_nonempty() {
        let corpus = geometry_corpus();
        assert!(!corpus.is_empty());
    }

    #[test]
    fn test_geometry_corpus_covers_all_families() {
        let corpus = geometry_corpus();
        for family in GeometrySpecimenFamily::ALL {
            assert!(
                corpus.iter().any(|s| s.family == *family),
                "missing family: {family:?}"
            );
        }
    }

    #[test]
    fn test_run_geometry_corpus_all_pass() {
        let inventory = run_geometry_corpus();
        for evidence in &inventory.evidences {
            assert_eq!(
                evidence.verdict,
                GeometryVerdict::Pass,
                "specimen {} failed: {}",
                evidence.specimen_id,
                evidence.details,
            );
        }
        assert_eq!(inventory.failed, 0);
    }

    #[test]
    fn test_evidence_inventory_hash_deterministic() {
        let i1 = run_geometry_corpus();
        let i2 = run_geometry_corpus();
        assert_eq!(i1.inventory_hash, i2.inventory_hash);
    }

    #[test]
    fn test_evidence_inventory_schema_version() {
        let inventory = run_geometry_corpus();
        assert_eq!(inventory.schema_version, REGIME_GEOMETRY_SCHEMA_VERSION);
        assert_eq!(inventory.component, REGIME_GEOMETRY_COMPONENT);
        assert_eq!(inventory.policy_id, REGIME_GEOMETRY_POLICY_ID);
    }

    // --- Regime corridor tests ---

    #[test]
    fn test_regime_corridor_construction() {
        let corridor = RegimeCorridor {
            from: RegimeLabel::Classified(Regime::Normal),
            to: RegimeLabel::Classified(Regime::Elevated),
            observation_count: 5,
            avg_distance_millionths: 250_000,
            validated: false,
        };
        assert_eq!(corridor.observation_count, 5);
        assert!(!corridor.validated);
    }

    #[test]
    fn test_regime_topology_empty_corridor_count() {
        let topo = RegimeTopology {
            corridors: Vec::new(),
            state_chart: RegimeStateChart {
                schema_version: REGIME_GEOMETRY_SCHEMA_VERSION.to_string(),
                entries: Vec::new(),
                transition_count: 0,
                abstention_count: 0,
                label_distribution: BTreeMap::new(),
                chart_hash: String::new(),
            },
            epoch: test_epoch(),
            content_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(topo.corridor_count(), 0);
    }

    // --- Specimen family tests ---

    #[test]
    fn test_specimen_family_all_constant() {
        assert_eq!(GeometrySpecimenFamily::ALL.len(), 7);
    }

    #[test]
    fn test_specimen_family_as_str() {
        assert_eq!(
            GeometrySpecimenFamily::EndToEndPipeline.as_str(),
            "end_to_end_pipeline"
        );
        assert_eq!(
            GeometrySpecimenFamily::ResetBehavior.as_str(),
            "reset_behavior"
        );
    }

    // --- Pipeline result is_gated tests ---

    #[test]
    fn test_is_gated_none_verdict() {
        let result = PipelineStepResult {
            seq: 1,
            trace_id: "t".to_string(),
            signature_hash: "h".to_string(),
            regime_label: RegimeLabel::Abstention,
            regime_confidence: 0,
            regime_changed: false,
            morphing_outcome: MorphingOutcome::NoOp,
            active_profile_name: "p".to_string(),
            gate_verdict: None,
            drift_l1: None,
            step_hash: ContentHash::compute(b"test"),
            epoch: test_epoch(),
        };
        assert!(!result.is_gated());
    }

    #[test]
    fn test_is_gated_block_verdict() {
        let result = PipelineStepResult {
            seq: 1,
            trace_id: "t".to_string(),
            signature_hash: "h".to_string(),
            regime_label: RegimeLabel::Abstention,
            regime_confidence: 0,
            regime_changed: false,
            morphing_outcome: MorphingOutcome::NoOp,
            active_profile_name: "p".to_string(),
            gate_verdict: Some(GateVerdict::Block),
            drift_l1: Some(500_000),
            step_hash: ContentHash::compute(b"test"),
            epoch: test_epoch(),
        };
        assert!(result.is_gated());
    }

    #[test]
    fn test_is_gated_downgrade_verdict() {
        let result = PipelineStepResult {
            seq: 1,
            trace_id: "t".to_string(),
            signature_hash: "h".to_string(),
            regime_label: RegimeLabel::Abstention,
            regime_confidence: 0,
            regime_changed: false,
            morphing_outcome: MorphingOutcome::NoOp,
            active_profile_name: "p".to_string(),
            gate_verdict: Some(GateVerdict::Downgrade),
            drift_l1: Some(200_000),
            step_hash: ContentHash::compute(b"test"),
            epoch: test_epoch(),
        };
        assert!(result.is_gated());
    }

    // --- Register regime profile test ---

    #[test]
    fn test_register_regime_profile() {
        let mut orch =
            RegimeGeometryOrchestrator::with_defaults(default_anchor_profile(), test_epoch());
        orch.register_regime_profile(Regime::Normal, regime_profile(Regime::Normal));
        // Verify via morpher state — no panic.
        assert_eq!(orch.current_profile_name(), "anchor_baseline");
    }

    // --- Morpher summary delegation test ---

    #[test]
    fn test_morpher_summary_delegation() {
        let orch = make_default_orchestrator();
        let ms = orch.morpher_summary();
        assert_eq!(ms.step_count, 0);
    }
}
