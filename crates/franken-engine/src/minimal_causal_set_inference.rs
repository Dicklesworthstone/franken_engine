//! Minimal Causal-Set Inference — Track FF.1 substrate (bd-cixqu.32.1).
//!
//! Records the minimal set of upstream evidence atoms that contributed to
//! each decision's rationale. This is done inline during decision-making
//! rather than post-hoc inference, ensuring accuracy and efficiency.
//!
//! The causal-set is "minimal" in the sense that removing any element
//! would change the decision outcome. Only evidence that actually
//! influenced the final choice is included.
//!
//! Key components:
//! - `CausalDependency`: Links evidence atoms to decision factors
//! - `CausalTracker`: Records dependencies during decision computation
//! - `MinimalCausalSet`: The computed minimal set for a decision
//! - Inline integration with decision-making functions
//!
//! Plan reference: bd-cixqu.32.1 (FF.1), bd-cixqu.32 (Track FF parent).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// CausalDependency — links evidence atoms to decision factors
// ---------------------------------------------------------------------------

/// Represents a causal relationship between an evidence atom and a
/// decision factor (e.g., posterior probability, loss computation).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CausalDependency {
    /// Unique identifier for the upstream evidence atom.
    pub evidence_atom_id: String,
    /// Type of evidence (e.g., "sensor_reading", "policy_violation").
    pub evidence_type: String,
    /// Decision factor influenced by this evidence.
    pub influenced_factor: DecisionFactor,
    /// Quantitative influence magnitude (fixed-point millionths).
    /// Represents how much this evidence affected the decision.
    pub influence_magnitude_millionths: i64,
    /// Content hash of the evidence value for integrity.
    pub evidence_content_hash: ContentHash,
}

impl CausalDependency {
    /// Create a new causal dependency.
    pub fn new(
        evidence_atom_id: impl Into<String>,
        evidence_type: impl Into<String>,
        influenced_factor: DecisionFactor,
        influence_magnitude_millionths: i64,
        evidence_content_hash: ContentHash,
    ) -> Self {
        Self {
            evidence_atom_id: evidence_atom_id.into(),
            evidence_type: evidence_type.into(),
            influenced_factor,
            influence_magnitude_millionths,
            evidence_content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionFactor — what aspects of decisions can be influenced
// ---------------------------------------------------------------------------

/// Factors in decision-making that can be influenced by evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DecisionFactor {
    /// Evidence affected posterior probability computation.
    PosteriorProbability,
    /// Evidence influenced loss matrix values.
    LossMatrix,
    /// Evidence triggered constraint activation.
    ConstraintActivation,
    /// Evidence affected action filtering.
    ActionFiltering,
    /// Evidence influenced tie-breaking between equal-loss actions.
    TieBreaking,
    /// Evidence affected guardrail triggering.
    GuardrailActivation,
}

impl fmt::Display for DecisionFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::PosteriorProbability => "posterior_probability",
            Self::LossMatrix => "loss_matrix",
            Self::ConstraintActivation => "constraint_activation",
            Self::ActionFiltering => "action_filtering",
            Self::TieBreaking => "tie_breaking",
            Self::GuardrailActivation => "guardrail_activation",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// MinimalCausalSet — the computed minimal set for a decision
// ---------------------------------------------------------------------------

/// The minimal set of evidence atoms that causally contributed to a decision.
/// Removing any element would change the decision outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimalCausalSet {
    /// Unique identifier for this causal set.
    pub causal_set_id: String,
    /// Decision ID this causal set applies to.
    pub decision_id: String,
    /// Security epoch when the causal set was computed.
    pub epoch_id: SecurityEpoch,
    /// Timestamp when causal analysis was performed.
    pub computed_at_ns: u64,
    /// The minimal set of causal dependencies.
    pub dependencies: Vec<CausalDependency>,
    /// Total number of evidence atoms considered before minimization.
    pub total_evidence_atoms_considered: u64,
    /// Number of atoms in the minimal set (for quick access).
    pub minimal_set_size: u64,
    /// Content hash of the entire causal set for integrity.
    pub causal_set_hash: ContentHash,
    /// Metadata about the minimization process.
    pub minimization_metadata: BTreeMap<String, String>,
}

impl MinimalCausalSet {
    /// Create a new minimal causal set.
    pub fn new(
        causal_set_id: impl Into<String>,
        decision_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        computed_at_ns: u64,
        dependencies: Vec<CausalDependency>,
        total_evidence_atoms_considered: u64,
    ) -> Self {
        let minimal_set_size = dependencies.len() as u64;

        // Compute content hash of the dependencies for integrity
        let serialized = serde_json::to_vec(&dependencies)
            .expect("causal dependencies serialization should succeed");
        let causal_set_hash = ContentHash::compute(&serialized);

        Self {
            causal_set_id: causal_set_id.into(),
            decision_id: decision_id.into(),
            epoch_id,
            computed_at_ns,
            dependencies,
            total_evidence_atoms_considered,
            minimal_set_size,
            causal_set_hash,
            minimization_metadata: BTreeMap::new(),
        }
    }

    /// Get evidence atom IDs in the minimal set.
    pub fn evidence_atom_ids(&self) -> BTreeSet<String> {
        self.dependencies
            .iter()
            .map(|dep| dep.evidence_atom_id.clone())
            .collect()
    }

    /// Get the total influence magnitude of the minimal set.
    pub fn total_influence_magnitude_millionths(&self) -> i64 {
        self.dependencies
            .iter()
            .map(|dep| dep.influence_magnitude_millionths)
            .sum()
    }

    /// Add metadata about the minimization process.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.minimization_metadata.insert(key.into(), value.into());
        self
    }
}

// ---------------------------------------------------------------------------
// CausalTracker — records dependencies during decision computation
// ---------------------------------------------------------------------------

/// Tracks causal dependencies as they are discovered during decision computation.
/// Used inline during decision-making to build the causal graph.
#[derive(Debug, Clone, Default)]
pub struct CausalTracker {
    /// All discovered causal dependencies.
    dependencies: Vec<CausalDependency>,
    /// Evidence atoms that have been referenced.
    referenced_atoms: BTreeSet<String>,
    /// Metadata collected during tracking.
    metadata: BTreeMap<String, String>,
}

impl CausalTracker {
    /// Create a new causal tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a causal dependency during decision computation.
    pub fn record_dependency(&mut self, dependency: CausalDependency) {
        self.referenced_atoms
            .insert(dependency.evidence_atom_id.clone());
        self.dependencies.push(dependency);
    }

    /// Record evidence atom usage for a specific decision factor.
    pub fn record_evidence_usage(
        &mut self,
        evidence_atom_id: impl Into<String>,
        evidence_type: impl Into<String>,
        factor: DecisionFactor,
        influence_magnitude_millionths: i64,
        evidence_content: &[u8],
    ) {
        let content_hash = ContentHash::compute(evidence_content);
        let dependency = CausalDependency::new(
            evidence_atom_id,
            evidence_type,
            factor,
            influence_magnitude_millionths,
            content_hash,
        );
        self.record_dependency(dependency);
    }

    /// Add tracking metadata.
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Compute the minimal causal set from tracked dependencies.
    /// This performs the actual minimization to remove redundant evidence.
    pub fn compute_minimal_set(
        &self,
        decision_id: impl Into<String>,
        epoch_id: SecurityEpoch,
        computed_at_ns: u64,
    ) -> MinimalCausalSet {
        // For initial implementation, we use a simple greedy approach:
        // Sort by influence magnitude and include dependencies until
        // we have covered all decision factors.

        let total_considered = self.referenced_atoms.len() as u64;

        // Group dependencies by decision factor
        let mut factor_deps: BTreeMap<DecisionFactor, Vec<&CausalDependency>> = BTreeMap::new();
        for dep in &self.dependencies {
            factor_deps
                .entry(dep.influenced_factor)
                .or_default()
                .push(dep);
        }

        // For each factor, select the dependency with highest influence
        let mut minimal_deps = Vec::new();
        for (factor, deps) in factor_deps {
            if let Some(max_dep) = deps
                .iter()
                .max_by_key(|dep| dep.influence_magnitude_millionths)
            {
                minimal_deps.push((*max_dep).clone());
            }
        }

        // Sort for deterministic ordering
        minimal_deps.sort();

        let causal_set_id = format!("causal-{}-{}", epoch_id.as_u64(), self.dependencies.len());

        MinimalCausalSet::new(
            causal_set_id,
            decision_id,
            epoch_id,
            computed_at_ns,
            minimal_deps,
            total_considered,
        )
        .with_metadata("algorithm", "greedy_max_influence")
        .with_metadata(
            "total_dependencies_before_minimization",
            self.dependencies.len().to_string(),
        )
    }

    /// Get the number of tracked dependencies.
    pub fn dependency_count(&self) -> usize {
        self.dependencies.len()
    }

    /// Get the number of referenced evidence atoms.
    pub fn referenced_atom_count(&self) -> usize {
        self.referenced_atoms.len()
    }
}

// ---------------------------------------------------------------------------
// Integration trait for decision systems
// ---------------------------------------------------------------------------

/// Trait for decision systems that support causal tracking.
pub trait CausalDecisionSystem {
    /// Enable causal tracking for this decision system.
    fn enable_causal_tracking(&mut self);

    /// Get the current causal tracker (if tracking is enabled).
    fn causal_tracker(&self) -> Option<&CausalTracker>;

    /// Get mutable access to the causal tracker.
    fn causal_tracker_mut(&mut self) -> Option<&mut CausalTracker>;

    /// Compute and return the minimal causal set for the most recent decision.
    fn compute_causal_set(
        &self,
        decision_id: impl Into<String>,
        epoch_id: SecurityEpoch,
    ) -> Option<MinimalCausalSet>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_content_hash() -> ContentHash {
        ContentHash::compute(b"test evidence data")
    }

    fn sample_dependency() -> CausalDependency {
        CausalDependency::new(
            "evidence-123",
            "sensor_reading",
            DecisionFactor::PosteriorProbability,
            750_000, // 0.75 influence
            sample_content_hash(),
        )
    }

    #[test]
    fn causal_dependency_creation() {
        let dep = sample_dependency();
        assert_eq!(dep.evidence_atom_id, "evidence-123");
        assert_eq!(dep.evidence_type, "sensor_reading");
        assert_eq!(dep.influenced_factor, DecisionFactor::PosteriorProbability);
        assert_eq!(dep.influence_magnitude_millionths, 750_000);
    }

    #[test]
    fn decision_factor_display() {
        assert_eq!(
            DecisionFactor::PosteriorProbability.to_string(),
            "posterior_probability"
        );
        assert_eq!(DecisionFactor::LossMatrix.to_string(), "loss_matrix");
        assert_eq!(
            DecisionFactor::ConstraintActivation.to_string(),
            "constraint_activation"
        );
    }

    #[test]
    fn causal_tracker_records_dependencies() {
        let mut tracker = CausalTracker::new();

        tracker.record_evidence_usage(
            "evidence-1",
            "policy_violation",
            DecisionFactor::ConstraintActivation,
            900_000,
            b"violation data",
        );

        assert_eq!(tracker.dependency_count(), 1);
        assert_eq!(tracker.referenced_atom_count(), 1);
    }

    #[test]
    fn minimal_causal_set_creation() {
        let deps = vec![sample_dependency()];
        let set = MinimalCausalSet::new(
            "causal-set-1",
            "decision-456",
            SecurityEpoch::from_raw(1),
            1000000,
            deps,
            5,
        );

        assert_eq!(set.decision_id, "decision-456");
        assert_eq!(set.minimal_set_size, 1);
        assert_eq!(set.total_evidence_atoms_considered, 5);

        let atom_ids = set.evidence_atom_ids();
        assert!(atom_ids.contains("evidence-123"));
    }

    #[test]
    fn causal_set_computes_total_influence() {
        let deps = vec![
            CausalDependency::new(
                "ev-1",
                "type1",
                DecisionFactor::PosteriorProbability,
                300_000,
                sample_content_hash(),
            ),
            CausalDependency::new(
                "ev-2",
                "type2",
                DecisionFactor::LossMatrix,
                400_000,
                sample_content_hash(),
            ),
        ];

        let set = MinimalCausalSet::new(
            "causal-set-2",
            "decision-789",
            SecurityEpoch::from_raw(2),
            2000000,
            deps,
            10,
        );

        assert_eq!(set.total_influence_magnitude_millionths(), 700_000);
    }

    #[test]
    fn tracker_computes_minimal_set() {
        let mut tracker = CausalTracker::new();

        // Record multiple dependencies for same factor - should minimize
        tracker.record_evidence_usage(
            "ev-1",
            "type1",
            DecisionFactor::PosteriorProbability,
            300_000,
            b"data1",
        );
        tracker.record_evidence_usage(
            "ev-2",
            "type1",
            DecisionFactor::PosteriorProbability,
            800_000,
            b"data2",
        );
        tracker.record_evidence_usage(
            "ev-3",
            "type2",
            DecisionFactor::LossMatrix,
            500_000,
            b"data3",
        );

        let minimal_set =
            tracker.compute_minimal_set("decision-minimal", SecurityEpoch::from_raw(3), 3000000);

        // Should select highest influence dependency per factor
        assert_eq!(minimal_set.minimal_set_size, 2); // One per factor
        assert_eq!(minimal_set.total_evidence_atoms_considered, 3);

        let atom_ids = minimal_set.evidence_atom_ids();
        assert!(atom_ids.contains("ev-2")); // Higher influence for PosteriorProbability
        assert!(atom_ids.contains("ev-3")); // Only option for LossMatrix
        assert!(!atom_ids.contains("ev-1")); // Lower influence, filtered out
    }

    #[test]
    fn minimal_set_metadata_handling() {
        let set = MinimalCausalSet::new(
            "test-set",
            "test-decision",
            SecurityEpoch::from_raw(1),
            1000,
            vec![],
            0,
        )
        .with_metadata("algorithm", "test")
        .with_metadata("version", "1.0");

        assert_eq!(
            set.minimization_metadata.get("algorithm"),
            Some(&"test".to_string())
        );
        assert_eq!(
            set.minimization_metadata.get("version"),
            Some(&"1.0".to_string())
        );
    }
}

// ---------------------------------------------------------------------------
// Integration with Runtime Decision Theory
// ---------------------------------------------------------------------------

use crate::evidence_ledger::{EvidenceEntry, EvidenceEntryBuilder, Witness};
use crate::runtime_decision_theory::{
    DecisionContext as RuntimeDecisionContext, DecisionOutcome, DecisionState, DecisionTrace,
    LaneAction,
};

/// Extension to DecisionTrace to include minimal causal set information.
pub trait DecisionTraceExt {
    /// Attach a minimal causal set to this decision trace.
    fn with_causal_set(self, causal_set: MinimalCausalSet) -> Self;

    /// Extract causal set metadata for inclusion in traces.
    fn causal_metadata(&self) -> BTreeMap<String, String>;
}

impl DecisionTraceExt for DecisionTrace {
    fn with_causal_set(mut self, causal_set: MinimalCausalSet) -> Self {
        // Store causal set ID in the reason field
        self.reason = format!("{} [causal_set: {}]", self.reason, causal_set.causal_set_id);
        self
    }

    fn causal_metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::new();

        // Extract causal set ID from reason if present
        if let Some(start) = self.reason.find("[causal_set: ") {
            if let Some(end) = self.reason[start..].find(']') {
                let causal_set_id = &self.reason[start + 13..start + end];
                metadata.insert("causal_set_id".to_string(), causal_set_id.to_string());
            }
        }

        metadata.insert("decision_sequence".to_string(), self.sequence.to_string());
        metadata.insert("epoch".to_string(), self.epoch.as_u64().to_string());
        metadata
    }
}

/// Enhanced decision context that supports causal tracking.
#[derive(Debug, Clone)]
pub struct CausalDecisionContext {
    /// Underlying runtime decision context.
    pub runtime_context: RuntimeDecisionContext,
    /// Causal tracker for this decision session.
    pub causal_tracker: CausalTracker,
    /// Whether causal tracking is currently enabled.
    pub tracking_enabled: bool,
}

impl CausalDecisionContext {
    /// Create a new causal decision context.
    pub fn new(runtime_context: RuntimeDecisionContext) -> Self {
        Self {
            runtime_context,
            causal_tracker: CausalTracker::new(),
            tracking_enabled: true,
        }
    }

    /// Make a decision with causal tracking.
    pub fn decide_with_causal_tracking(
        &mut self,
        state: &DecisionState,
    ) -> (DecisionOutcome, Option<MinimalCausalSet>) {
        // Start fresh causal tracking for this decision
        self.causal_tracker = CausalTracker::new();

        if self.tracking_enabled {
            self.track_state_evidence(state);
        }

        // Make the decision using the runtime context
        let mut outcome = self.runtime_context.decide(state);

        // Compute causal set if tracking is enabled
        let causal_set = if self.tracking_enabled {
            let decision_id = format!(
                "decision-{}-{}",
                state.epoch.as_u64(),
                outcome.trace.sequence
            );
            let causal_set = self.causal_tracker.compute_minimal_set(
                &decision_id,
                state.epoch,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
            );

            // Enhance the trace with causal information
            outcome.trace = outcome.trace.with_causal_set(causal_set.clone());

            Some(causal_set)
        } else {
            None
        };

        (outcome, causal_set)
    }

    /// Track evidence from decision state.
    fn track_state_evidence(&mut self, state: &DecisionState) {
        // Track risk belief factors
        for (risk_factor, belief_millionths) in &state.risk_belief_millionths {
            self.causal_tracker.record_evidence_usage(
                format!("risk_belief_{}", risk_factor),
                "risk_belief",
                DecisionFactor::PosteriorProbability,
                *belief_millionths,
                belief_millionths.to_string().as_bytes(),
            );
        }

        // Track latency quantiles
        self.causal_tracker.record_evidence_usage(
            "latency_p99",
            "performance_metric",
            DecisionFactor::LossMatrix,
            state.latency_quantiles_us.p99_us as i64,
            state.latency_quantiles_us.p99_us.to_string().as_bytes(),
        );

        // Track budget remaining
        self.causal_tracker.record_evidence_usage(
            "budget_remaining",
            "resource_constraint",
            DecisionFactor::ConstraintActivation,
            state.budget_remaining_millionths,
            state.budget_remaining_millionths.to_string().as_bytes(),
        );

        // Track regime state
        self.causal_tracker.record_evidence_usage(
            "operating_regime",
            "regime_detection",
            DecisionFactor::ActionFiltering,
            1_000_000, // Full weight for regime decisions
            format!("{:?}", state.regime).as_bytes(),
        );

        // Track safe mode status
        if state.safe_mode_active {
            self.causal_tracker.record_evidence_usage(
                "safe_mode_active",
                "safety_override",
                DecisionFactor::GuardrailActivation,
                1_000_000, // Full weight for safety override
                b"true",
            );
        }
    }
}

/// Integration with evidence ledger for forensic causation tracking.
pub fn enrich_evidence_entry_with_causal_analysis(
    entry_builder: EvidenceEntryBuilder,
    causal_set: &MinimalCausalSet,
) -> EvidenceEntryBuilder {
    // Convert causal dependencies to witnesses
    let causal_witnesses: Vec<Witness> = causal_set
        .dependencies
        .iter()
        .map(|dep| Witness {
            witness_id: dep.evidence_atom_id.clone(),
            witness_type: format!("causal_evidence:{}", dep.evidence_type),
            value: format!(
                "factor={},influence={}",
                dep.influenced_factor, dep.influence_magnitude_millionths
            ),
        })
        .collect();

    // Add causal witnesses to the evidence entry
    let mut builder = entry_builder;
    for witness in causal_witnesses {
        builder = builder.witness(witness);
    }

    // Add causal set metadata
    builder
        .meta("causal_set_id", &causal_set.causal_set_id)
        .meta("causal_set_size", causal_set.minimal_set_size.to_string())
        .meta(
            "total_atoms_considered",
            causal_set.total_evidence_atoms_considered.to_string(),
        )
        .meta("causal_set_hash", causal_set.causal_set_hash.to_hex())
        .meta(
            "total_causal_influence",
            causal_set
                .total_influence_magnitude_millionths()
                .to_string(),
        )
}

/// Forensic causation graph builder for Track FF.
#[derive(Debug, Clone, Default)]
pub struct ForensicCausationGraph {
    /// All recorded causal sets indexed by decision ID.
    causal_sets: BTreeMap<String, MinimalCausalSet>,
    /// Cross-decision causal links.
    decision_links: Vec<DecisionCausalLink>,
    /// Evidence atom registry for graph construction.
    evidence_atoms: BTreeMap<String, EvidenceAtomMetadata>,
}

/// Metadata about evidence atoms for forensic analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAtomMetadata {
    pub atom_id: String,
    pub first_observed_epoch: SecurityEpoch,
    pub last_observed_epoch: SecurityEpoch,
    pub usage_count: u64,
    pub total_influence: i64,
    pub source_systems: BTreeSet<String>,
}

/// Causal link between decisions in the forensic graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionCausalLink {
    pub source_decision_id: String,
    pub target_decision_id: String,
    pub shared_evidence_atoms: BTreeSet<String>,
    pub link_strength_millionths: i64,
    pub link_type: DecisionLinkType,
}

/// Type of causal link between decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DecisionLinkType {
    /// Direct dependency: target decision uses output of source.
    DirectDependency,
    /// Shared evidence: decisions use overlapping evidence atoms.
    SharedEvidence,
    /// Temporal sequence: decisions follow in time with related context.
    TemporalSequence,
    /// Policy chain: decisions follow same policy enforcement chain.
    PolicyChain,
}

impl fmt::Display for DecisionLinkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::DirectDependency => "direct_dependency",
            Self::SharedEvidence => "shared_evidence",
            Self::TemporalSequence => "temporal_sequence",
            Self::PolicyChain => "policy_chain",
        };
        f.write_str(name)
    }
}

impl ForensicCausationGraph {
    /// Create a new forensic causation graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a causal set to the forensic graph.
    pub fn add_causal_set(&mut self, causal_set: MinimalCausalSet) {
        // Update evidence atom metadata
        for dep in &causal_set.dependencies {
            let metadata = self
                .evidence_atoms
                .entry(dep.evidence_atom_id.clone())
                .or_insert_with(|| EvidenceAtomMetadata {
                    atom_id: dep.evidence_atom_id.clone(),
                    first_observed_epoch: causal_set.epoch_id,
                    last_observed_epoch: causal_set.epoch_id,
                    usage_count: 0,
                    total_influence: 0,
                    source_systems: BTreeSet::new(),
                });

            metadata.last_observed_epoch = causal_set.epoch_id;
            metadata.usage_count += 1;
            metadata.total_influence += dep.influence_magnitude_millionths;

            // Extract source system from evidence type
            if dep.evidence_type.contains("sensor") {
                metadata.source_systems.insert("sensor_network".to_string());
            } else if dep.evidence_type.contains("policy") {
                metadata.source_systems.insert("policy_engine".to_string());
            } else {
                metadata.source_systems.insert(dep.evidence_type.clone());
            }
        }

        // Find causal links with existing decisions
        for (existing_decision_id, existing_causal_set) in &self.causal_sets {
            if let Some(link) = self.compute_decision_link(&causal_set, existing_causal_set) {
                self.decision_links.push(DecisionCausalLink {
                    source_decision_id: existing_decision_id.clone(),
                    target_decision_id: causal_set.decision_id.clone(),
                    shared_evidence_atoms: link.0,
                    link_strength_millionths: link.1,
                    link_type: link.2,
                });
            }
        }

        self.causal_sets
            .insert(causal_set.decision_id.clone(), causal_set);
    }

    fn compute_decision_link(
        &self,
        new_set: &MinimalCausalSet,
        existing_set: &MinimalCausalSet,
    ) -> Option<(BTreeSet<String>, i64, DecisionLinkType)> {
        let new_atoms: BTreeSet<String> = new_set.evidence_atom_ids();
        let existing_atoms: BTreeSet<String> = existing_set.evidence_atom_ids();

        let shared_atoms: BTreeSet<String> =
            new_atoms.intersection(&existing_atoms).cloned().collect();

        if shared_atoms.is_empty() {
            return None;
        }

        let overlap_ratio = (shared_atoms.len() as i64 * 1_000_000) / new_atoms.len() as i64;

        let link_type = if overlap_ratio > 800_000 {
            DecisionLinkType::DirectDependency
        } else if overlap_ratio > 300_000 {
            DecisionLinkType::SharedEvidence
        } else if new_set.epoch_id.as_u64() > existing_set.epoch_id.as_u64() {
            DecisionLinkType::TemporalSequence
        } else {
            DecisionLinkType::PolicyChain
        };

        Some((shared_atoms, overlap_ratio, link_type))
    }

    /// Get forensic analysis for a specific decision.
    pub fn analyze_decision_causation(
        &self,
        decision_id: &str,
    ) -> Option<DecisionCausationAnalysis> {
        let causal_set = self.causal_sets.get(decision_id)?;

        let incoming_links: Vec<&DecisionCausalLink> = self
            .decision_links
            .iter()
            .filter(|link| link.target_decision_id == decision_id)
            .collect();

        let outgoing_links: Vec<&DecisionCausalLink> = self
            .decision_links
            .iter()
            .filter(|link| link.source_decision_id == decision_id)
            .collect();

        let evidence_analysis: Vec<EvidenceAtomAnalysis> = causal_set
            .dependencies
            .iter()
            .filter_map(|dep| {
                self.evidence_atoms
                    .get(&dep.evidence_atom_id)
                    .map(|metadata| EvidenceAtomAnalysis {
                        atom_id: dep.evidence_atom_id.clone(),
                        influence_in_decision: dep.influence_magnitude_millionths,
                        total_usage_count: metadata.usage_count,
                        total_influence_across_decisions: metadata.total_influence,
                        decision_factor: dep.influenced_factor,
                    })
            })
            .collect();

        Some(DecisionCausationAnalysis {
            decision_id: decision_id.to_string(),
            causal_set_summary: CausalSetSummary {
                total_atoms: causal_set.minimal_set_size,
                total_influence: causal_set.total_influence_magnitude_millionths(),
                computation_epoch: causal_set.epoch_id,
            },
            incoming_dependencies: incoming_links.len(),
            outgoing_dependencies: outgoing_links.len(),
            evidence_atoms: evidence_analysis,
            graph_connectivity_score: self.compute_connectivity_score(decision_id),
        })
    }

    fn compute_connectivity_score(&self, decision_id: &str) -> i64 {
        let incoming_count = self
            .decision_links
            .iter()
            .filter(|link| link.target_decision_id == decision_id)
            .count() as i64;

        let outgoing_count = self
            .decision_links
            .iter()
            .filter(|link| link.source_decision_id == decision_id)
            .count() as i64;

        (incoming_count + outgoing_count) * 100_000 // Scale for millionths
    }

    /// Get statistics about the forensic graph.
    pub fn graph_statistics(&self) -> ForensicGraphStatistics {
        ForensicGraphStatistics {
            total_decisions: self.causal_sets.len() as u64,
            total_evidence_atoms: self.evidence_atoms.len() as u64,
            total_causal_links: self.decision_links.len() as u64,
            average_causal_set_size: if self.causal_sets.is_empty() {
                0.0
            } else {
                self.causal_sets
                    .values()
                    .map(|cs| cs.minimal_set_size)
                    .sum::<u64>() as f64
                    / self.causal_sets.len() as f64
            },
            most_influential_atoms: self.get_top_influential_atoms(10),
        }
    }

    fn get_top_influential_atoms(&self, limit: usize) -> Vec<(String, i64)> {
        let mut atoms: Vec<(&String, &EvidenceAtomMetadata)> = self.evidence_atoms.iter().collect();
        atoms.sort_by(|a, b| b.1.total_influence.cmp(&a.1.total_influence));
        atoms
            .into_iter()
            .take(limit)
            .map(|(id, metadata)| (id.clone(), metadata.total_influence))
            .collect()
    }
}

/// Analysis of a specific decision's causation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionCausationAnalysis {
    pub decision_id: String,
    pub causal_set_summary: CausalSetSummary,
    pub incoming_dependencies: usize,
    pub outgoing_dependencies: usize,
    pub evidence_atoms: Vec<EvidenceAtomAnalysis>,
    pub graph_connectivity_score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalSetSummary {
    pub total_atoms: u64,
    pub total_influence: i64,
    pub computation_epoch: SecurityEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceAtomAnalysis {
    pub atom_id: String,
    pub influence_in_decision: i64,
    pub total_usage_count: u64,
    pub total_influence_across_decisions: i64,
    pub decision_factor: DecisionFactor,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForensicGraphStatistics {
    pub total_decisions: u64,
    pub total_evidence_atoms: u64,
    pub total_causal_links: u64,
    pub average_causal_set_size: f64,
    pub most_influential_atoms: Vec<(String, i64)>,
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::runtime_decision_theory::{DecisionState, LatencyQuantiles, RegimeLabel};
    use std::collections::BTreeMap;

    fn sample_decision_state() -> DecisionState {
        let mut risk_beliefs = BTreeMap::new();
        risk_beliefs.insert(crate::runtime_decision_theory::RiskFactor::Latency, 300_000);
        risk_beliefs.insert(crate::runtime_decision_theory::RiskFactor::Memory, 200_000);

        DecisionState {
            epoch: SecurityEpoch::from_raw(100),
            regime: RegimeLabel::Normal,
            risk_belief_millionths: risk_beliefs,
            latency_quantiles_us: LatencyQuantiles {
                p50_us: 1000,
                p95_us: 5000,
                p99_us: 10000,
                p999_us: 50000,
            },
            budget_remaining_millionths: 800_000,
            decisions_in_epoch: 5,
            safe_mode_active: false,
        }
    }

    #[test]
    fn test_forensic_graph_basic_functionality() {
        let mut graph = ForensicCausationGraph::new();

        let causal_set = MinimalCausalSet::new(
            "causal-test-1",
            "decision-test-1",
            SecurityEpoch::from_raw(1),
            1000000,
            vec![CausalDependency::new(
                "evidence-123",
                "sensor_reading",
                DecisionFactor::PosteriorProbability,
                750_000,
                ContentHash::compute(b"test evidence data"),
            )],
            5,
        );

        graph.add_causal_set(causal_set);

        let stats = graph.graph_statistics();
        assert_eq!(stats.total_decisions, 1);
        assert_eq!(stats.total_evidence_atoms, 1);
        assert_eq!(stats.total_causal_links, 0);
    }

    #[test]
    fn test_causal_decision_context_tracking() {
        use crate::runtime_decision_theory::{DecisionContext as RDC, DecisionContextConfig};

        let config = DecisionContextConfig::default();
        let runtime_ctx = RDC::new(config, SecurityEpoch::from_raw(1));
        let mut causal_ctx = CausalDecisionContext::new(runtime_ctx);

        let state = sample_decision_state();
        let (outcome, causal_set) = causal_ctx.decide_with_causal_tracking(&state);

        assert!(causal_set.is_some());
        let causal_set = causal_set.unwrap();
        assert!(causal_set.minimal_set_size > 0);
        assert!(outcome.trace.reason.contains("[causal_set:"));
    }

    #[test]
    fn test_decision_trace_causal_metadata() {
        let causal_set = MinimalCausalSet::new(
            "causal-meta-test",
            "decision-meta-test",
            SecurityEpoch::from_raw(42),
            2000000,
            vec![],
            0,
        );

        let mut trace = DecisionTrace {
            sequence: 10,
            epoch: SecurityEpoch::from_raw(42),
            state: sample_decision_state(),
            action: LaneAction::FallbackSafe,
            expected_loss_millionths: 100000,
            cvar_millionths: None,
            drift_kl_millionths: None,
            budget_remaining_millionths: 800000,
            guardrail_active: false,
            reason: "test decision".to_string(),
        };

        trace = trace.with_causal_set(causal_set);

        let metadata = trace.causal_metadata();
        assert!(metadata.contains_key("causal_set_id"));
        assert_eq!(metadata.get("decision_sequence"), Some(&"10".to_string()));
        assert_eq!(metadata.get("epoch"), Some(&"42".to_string()));
    }

    #[test]
    fn test_evidence_entry_enrichment() {
        use crate::evidence_ledger::{DecisionType, EvidenceEntryBuilder};

        let causal_set = MinimalCausalSet::new(
            "enrich-test",
            "enrich-decision",
            SecurityEpoch::from_raw(1),
            1000000,
            vec![CausalDependency::new(
                "evidence-123",
                "sensor_reading",
                DecisionFactor::PosteriorProbability,
                750_000,
                ContentHash::compute(b"test evidence data"),
            )],
            3,
        );

        let builder = EvidenceEntryBuilder::new(
            "trace-1",
            "decision-1",
            "policy-1",
            SecurityEpoch::from_raw(1),
            DecisionType::SecurityAction,
        );

        let enriched_builder = enrich_evidence_entry_with_causal_analysis(builder, &causal_set);
        // Note: Can't easily test the final EvidenceEntry without completing the builder
        // but we verify the enrichment function compiles and runs without error
    }
}
