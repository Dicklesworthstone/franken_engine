//! Structural causal DAG, adjustment sets, and identifiability certificates.
//!
//! This module derives the structural causal model (SCM) for the optimization
//! questions that matter to FrankenEngine: tiering decisions, cache policy,
//! GC tuning, specialization triggers, and workload routing. It provides:
//!
//! - A directed acyclic graph of causal variables with typed edges
//! - Backdoor-criterion adjustment set computation
//! - Front-door and instrumental variable identification
//! - Identifiability certificates with explicit abstention reasons
//! - Integration with FrankenEngine's deterministic evidence substrate
//!
//! Every certificate carries a content hash and can be audited. Variables
//! that cannot be identified are marked with explicit impossibility reasons
//! rather than silently dropped.
//!
//! Reference: [RGC-615A]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for causal intervention certificates.
pub const CAUSAL_DAG_SCHEMA_VERSION: &str = "franken-engine.causal-intervention-dag.v1";
/// Component name for evidence linkage.
pub const CAUSAL_DAG_COMPONENT: &str = "causal_intervention_dag";
/// Policy ID binding.
pub const CAUSAL_DAG_POLICY_ID: &str = "RGC-615A";

// ---------------------------------------------------------------------------
// Causal Variable Types
// ---------------------------------------------------------------------------

/// A unique identifier for a causal variable in the SCM.
pub type VariableId = u32;

/// The domain of a causal variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableDomain {
    /// Optimization treatment: tiering level, cache policy, GC strategy.
    Treatment,
    /// Observable outcome: latency, throughput, memory, correctness.
    Outcome,
    /// Confounding variable: workload type, hardware, concurrency level.
    Confounder,
    /// Mediating variable: intermediate observable on the causal path.
    Mediator,
    /// Instrumental variable: affects treatment but not outcome directly.
    Instrument,
    /// Collider: caused by both treatment and outcome (conditioning opens paths).
    Collider,
}

impl VariableDomain {
    pub const ALL: &[Self] = &[
        Self::Treatment,
        Self::Outcome,
        Self::Confounder,
        Self::Mediator,
        Self::Instrument,
        Self::Collider,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Treatment => "treatment",
            Self::Outcome => "outcome",
            Self::Confounder => "confounder",
            Self::Mediator => "mediator",
            Self::Instrument => "instrument",
            Self::Collider => "collider",
        }
    }
}

impl fmt::Display for VariableDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The observability status of a causal variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observability {
    /// Directly measurable at runtime.
    Observable,
    /// Latent: cannot be directly measured, only inferred.
    Latent,
    /// Partially observable: proxy measurement available.
    Proxy,
}

/// The measurement scale of a causal variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementScale {
    /// Binary: on/off, enabled/disabled.
    Binary,
    /// Ordinal: tier levels, priority classes.
    Ordinal,
    /// Continuous: latency, throughput (millionths for determinism).
    Continuous,
    /// Categorical: workload type, policy class.
    Categorical,
}

/// A causal variable in the structural causal model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalVariable {
    /// Unique identifier.
    pub id: VariableId,
    /// Human-readable name.
    pub name: String,
    /// Domain classification.
    pub domain: VariableDomain,
    /// Whether this variable can be directly observed/measured.
    pub observability: Observability,
    /// Measurement scale.
    pub scale: MeasurementScale,
    /// Description of what this variable represents.
    pub description: String,
    /// FrankenEngine subsystem this variable belongs to.
    pub subsystem: String,
}

// ---------------------------------------------------------------------------
// Causal Edge Types
// ---------------------------------------------------------------------------

/// The type of a causal edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Direct causal effect: X -> Y means X causes Y.
    Direct,
    /// Mediated effect: X -> M -> Y (X causes Y through M).
    Mediated,
    /// Confounding path: X <- C -> Y (C confounds X and Y).
    Confounding,
    /// Instrumental path: Z -> X -> Y (Z is an instrument for X -> Y).
    Instrumental,
}

/// Strength confidence for an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeConfidence {
    /// Established by domain knowledge / specification.
    Structural,
    /// Supported by observational evidence.
    Empirical,
    /// Hypothesized but not yet validated.
    Hypothesized,
}

/// A directed edge in the causal DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalEdge {
    /// Source variable (cause).
    pub from: VariableId,
    /// Target variable (effect).
    pub to: VariableId,
    /// Edge type.
    pub kind: EdgeKind,
    /// Confidence level.
    pub confidence: EdgeConfidence,
    /// Description of the causal mechanism.
    pub mechanism: String,
}

// ---------------------------------------------------------------------------
// Causal DAG
// ---------------------------------------------------------------------------

/// A structural causal model represented as a directed acyclic graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalDag {
    /// All variables in the model.
    pub variables: BTreeMap<VariableId, CausalVariable>,
    /// All directed edges.
    pub edges: Vec<CausalEdge>,
    /// Adjacency list: from -> set of targets.
    pub children: BTreeMap<VariableId, BTreeSet<VariableId>>,
    /// Reverse adjacency: to -> set of sources (parents).
    pub parents: BTreeMap<VariableId, BTreeSet<VariableId>>,
    /// Content hash of the DAG structure.
    pub structure_hash: ContentHash,
}

/// Error building or querying the causal DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum CausalDagError {
    /// A variable referenced by an edge does not exist.
    UnknownVariable { id: VariableId },
    /// An edge would create a cycle.
    CycleDetected { from: VariableId, to: VariableId },
    /// Duplicate variable ID.
    DuplicateVariable { id: VariableId },
    /// No path exists between two variables.
    NoPath { from: VariableId, to: VariableId },
    /// The DAG is empty.
    EmptyDag,
}

impl fmt::Display for CausalDagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVariable { id } => write!(f, "unknown variable: {id}"),
            Self::CycleDetected { from, to } => {
                write!(f, "cycle detected: edge {from} -> {to}")
            }
            Self::DuplicateVariable { id } => write!(f, "duplicate variable: {id}"),
            Self::NoPath { from, to } => write!(f, "no path: {from} -> {to}"),
            Self::EmptyDag => write!(f, "empty DAG"),
        }
    }
}

/// Builder for constructing a causal DAG.
#[derive(Debug)]
pub struct CausalDagBuilder {
    variables: BTreeMap<VariableId, CausalVariable>,
    edges: Vec<CausalEdge>,
}

impl CausalDagBuilder {
    pub fn new() -> Self {
        Self {
            variables: BTreeMap::new(),
            edges: Vec::new(),
        }
    }

    /// Add a variable to the DAG.
    pub fn add_variable(&mut self, var: CausalVariable) -> Result<&mut Self, CausalDagError> {
        if self.variables.contains_key(&var.id) {
            return Err(CausalDagError::DuplicateVariable { id: var.id });
        }
        self.variables.insert(var.id, var);
        Ok(self)
    }

    /// Add a directed edge to the DAG.
    pub fn add_edge(&mut self, edge: CausalEdge) -> &mut Self {
        self.edges.push(edge);
        self
    }

    /// Build the causal DAG, validating acyclicity.
    pub fn build(self) -> Result<CausalDag, CausalDagError> {
        if self.variables.is_empty() {
            return Err(CausalDagError::EmptyDag);
        }

        let mut children: BTreeMap<VariableId, BTreeSet<VariableId>> = BTreeMap::new();
        let mut parents: BTreeMap<VariableId, BTreeSet<VariableId>> = BTreeMap::new();

        // Initialize adjacency for all variables
        for &id in self.variables.keys() {
            children.entry(id).or_default();
            parents.entry(id).or_default();
        }

        // Add edges, validating variable existence
        for edge in &self.edges {
            if !self.variables.contains_key(&edge.from) {
                return Err(CausalDagError::UnknownVariable { id: edge.from });
            }
            if !self.variables.contains_key(&edge.to) {
                return Err(CausalDagError::UnknownVariable { id: edge.to });
            }
            children.entry(edge.from).or_default().insert(edge.to);
            parents.entry(edge.to).or_default().insert(edge.from);
        }

        // Validate acyclicity via topological sort
        let mut in_degree: BTreeMap<VariableId, usize> = BTreeMap::new();
        for &id in self.variables.keys() {
            in_degree.insert(id, parents.get(&id).map_or(0, |p| p.len()));
        }
        let mut queue: Vec<VariableId> = in_degree
            .iter()
            .filter(|&(_, d)| *d == 0)
            .map(|(&id, _)| id)
            .collect();
        let mut visited = 0usize;

        while let Some(node) = queue.pop() {
            visited += 1;
            if let Some(ch) = children.get(&node) {
                for &child in ch {
                    if let Some(deg) = in_degree.get_mut(&child) {
                        *deg -= 1;
                        if *deg == 0 {
                            queue.push(child);
                        }
                    }
                }
            }
        }

        if visited != self.variables.len() {
            // Find a cycle edge — report the first edge where from has unresolved in-degree
            for edge in &self.edges {
                if in_degree.get(&edge.to).is_some_and(|&d| d > 0) {
                    return Err(CausalDagError::CycleDetected {
                        from: edge.from,
                        to: edge.to,
                    });
                }
            }
            // Fallback: report first edge
            if let Some(edge) = self.edges.first() {
                return Err(CausalDagError::CycleDetected {
                    from: edge.from,
                    to: edge.to,
                });
            }
        }

        // Compute structure hash
        let hash_input = serde_json::to_vec(&(&self.variables, &self.edges)).unwrap_or_default();
        let structure_hash = ContentHash::compute(&hash_input);

        Ok(CausalDag {
            variables: self.variables,
            edges: self.edges,
            children,
            parents,
            structure_hash,
        })
    }
}

impl Default for CausalDagBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Graph Queries
// ---------------------------------------------------------------------------

impl CausalDag {
    /// Get the ancestors (all nodes that can reach `target`) of a variable.
    pub fn ancestors(&self, target: VariableId) -> BTreeSet<VariableId> {
        let mut result = BTreeSet::new();
        let mut stack = vec![target];
        while let Some(node) = stack.pop() {
            if let Some(pars) = self.parents.get(&node) {
                for &p in pars {
                    if result.insert(p) {
                        stack.push(p);
                    }
                }
            }
        }
        result
    }

    /// Get the descendants (all nodes reachable from `source`) of a variable.
    pub fn descendants(&self, source: VariableId) -> BTreeSet<VariableId> {
        let mut result = BTreeSet::new();
        let mut stack = vec![source];
        while let Some(node) = stack.pop() {
            if let Some(ch) = self.children.get(&node) {
                for &c in ch {
                    if result.insert(c) {
                        stack.push(c);
                    }
                }
            }
        }
        result
    }

    /// Check if there is a directed path from `source` to `target`.
    pub fn has_path(&self, source: VariableId, target: VariableId) -> bool {
        if source == target {
            return true;
        }
        self.descendants(source).contains(&target)
    }

    /// Get all variables of a given domain.
    pub fn variables_by_domain(&self, domain: VariableDomain) -> Vec<VariableId> {
        self.variables
            .iter()
            .filter(|(_, v)| v.domain == domain)
            .map(|(&id, _)| id)
            .collect()
    }

    /// Get the variable count.
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    /// Get the edge count.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

// ---------------------------------------------------------------------------
// Adjustment Sets (Backdoor Criterion)
// ---------------------------------------------------------------------------

/// The result of computing an adjustment set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdjustmentSet {
    /// The treatment variable.
    pub treatment: VariableId,
    /// The outcome variable.
    pub outcome: VariableId,
    /// The set of variables to adjust for (condition on).
    pub variables: BTreeSet<VariableId>,
    /// Whether this set satisfies the backdoor criterion.
    pub is_valid: bool,
    /// Reason if invalid.
    pub reason: Option<String>,
}

/// The identification strategy used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentificationStrategy {
    /// Backdoor adjustment: condition on a set Z that blocks all backdoor paths.
    Backdoor,
    /// Front-door adjustment: via a mediator that satisfies specific conditions.
    FrontDoor,
    /// Instrumental variable: via a variable that affects treatment but not outcome.
    Instrumental,
    /// No valid identification strategy found.
    Unidentifiable,
}

impl IdentificationStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Backdoor => "backdoor",
            Self::FrontDoor => "front_door",
            Self::Instrumental => "instrumental",
            Self::Unidentifiable => "unidentifiable",
        }
    }
}

impl fmt::Display for IdentificationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reason why a causal effect cannot be identified.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnidentifiableReason {
    /// No valid backdoor set exists (latent confounders block all paths).
    NoBackdoorSet,
    /// No valid front-door path exists.
    NoFrontDoorPath,
    /// No valid instrument available.
    NoInstrument,
    /// Treatment and outcome are not connected.
    NotConnected,
    /// All confounders are latent.
    AllConfoundersLatent,
    /// Treatment is not observable.
    TreatmentNotObservable,
    /// Outcome is not observable.
    OutcomeNotObservable,
}

impl fmt::Display for UnidentifiableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBackdoorSet => write!(f, "no valid backdoor adjustment set"),
            Self::NoFrontDoorPath => write!(f, "no valid front-door path"),
            Self::NoInstrument => write!(f, "no valid instrument"),
            Self::NotConnected => write!(f, "treatment and outcome not connected"),
            Self::AllConfoundersLatent => write!(f, "all confounders are latent"),
            Self::TreatmentNotObservable => write!(f, "treatment not observable"),
            Self::OutcomeNotObservable => write!(f, "outcome not observable"),
        }
    }
}

// ---------------------------------------------------------------------------
// Identifiability Certificates
// ---------------------------------------------------------------------------

/// A certificate attesting whether a causal effect is identifiable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifiabilityCertificate {
    /// Schema version.
    pub schema_version: String,
    /// The treatment variable.
    pub treatment: VariableId,
    /// The outcome variable.
    pub outcome: VariableId,
    /// Whether the effect is identifiable.
    pub is_identifiable: bool,
    /// The identification strategy (if identifiable).
    pub strategy: IdentificationStrategy,
    /// The adjustment set (if using backdoor).
    pub adjustment_set: Option<AdjustmentSet>,
    /// The mediator (if using front-door).
    pub front_door_mediator: Option<VariableId>,
    /// The instrument (if using instrumental variable).
    pub instrument: Option<VariableId>,
    /// Reasons for non-identifiability.
    pub unidentifiable_reasons: Vec<UnidentifiableReason>,
    /// Content hash of the DAG at certificate time.
    pub dag_hash: ContentHash,
    /// Content hash of this certificate.
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Identification Algorithms
// ---------------------------------------------------------------------------

impl CausalDag {
    /// Compute the minimal backdoor adjustment set for the effect of
    /// `treatment` on `outcome`.
    ///
    /// The backdoor criterion requires finding a set Z such that:
    /// 1. Z does not contain any descendant of treatment
    /// 2. Z blocks all backdoor paths from treatment to outcome
    #[allow(clippy::collapsible_if)]
    pub fn backdoor_adjustment(&self, treatment: VariableId, outcome: VariableId) -> AdjustmentSet {
        // Get parents of treatment (potential confounders)
        let treatment_parents = self.parents.get(&treatment).cloned().unwrap_or_default();

        // Get descendants of treatment (cannot be in adjustment set)
        let treatment_descendants = self.descendants(treatment);

        // Candidate adjustment variables: parents of treatment that are
        // not descendants of treatment, and are observable
        let mut adjustment: BTreeSet<VariableId> = BTreeSet::new();

        for &parent in &treatment_parents {
            // Skip descendants of treatment
            if treatment_descendants.contains(&parent) {
                continue;
            }
            // Skip latent variables
            if let Some(var) = self.variables.get(&parent) {
                if var.observability == Observability::Latent {
                    continue;
                }
            }
            adjustment.insert(parent);
        }

        // Also include ancestors of outcome that are parents of treatment
        // to block all backdoor paths
        let outcome_ancestors = self.ancestors(outcome);
        for &anc in &outcome_ancestors {
            if treatment_parents.contains(&anc) && !treatment_descendants.contains(&anc) {
                if let Some(var) = self.variables.get(&anc) {
                    if var.observability != Observability::Latent {
                        adjustment.insert(anc);
                    }
                }
            }
        }

        // Validate: check that all confounding parents are covered
        let is_valid = treatment_parents.iter().all(|&p| {
            adjustment.contains(&p)
                || !self.has_path(p, outcome)
                || self
                    .variables
                    .get(&p)
                    .is_some_and(|v| v.domain == VariableDomain::Instrument)
        });

        let reason = if is_valid {
            None
        } else {
            Some("Latent confounders present; adjustment set may be insufficient".to_string())
        };

        AdjustmentSet {
            treatment,
            outcome,
            variables: adjustment,
            is_valid,
            reason,
        }
    }

    /// Check for front-door identification: find a mediator M such that
    /// treatment -> M -> outcome with no unblocked backdoor path T -> M.
    pub fn front_door_mediator(
        &self,
        treatment: VariableId,
        outcome: VariableId,
    ) -> Option<VariableId> {
        let treatment_children = self.children.get(&treatment).cloned().unwrap_or_default();

        for &candidate in &treatment_children {
            // Must be on the path to outcome
            if !self.has_path(candidate, outcome) {
                continue;
            }

            // Must be a mediator
            if let Some(var) = self.variables.get(&candidate) {
                if var.domain != VariableDomain::Mediator {
                    continue;
                }
                if var.observability == Observability::Latent {
                    continue;
                }
            } else {
                continue;
            }

            // No direct path from confounders to M that bypasses T
            let m_parents = self.parents.get(&candidate).cloned().unwrap_or_default();
            let all_m_parents_from_treatment = m_parents
                .iter()
                .all(|&p| p == treatment || self.has_path(treatment, p));

            if all_m_parents_from_treatment {
                return Some(candidate);
            }
        }
        None
    }

    /// Check for instrumental variable identification.
    #[allow(clippy::collapsible_if)]
    pub fn find_instrument(
        &self,
        treatment: VariableId,
        outcome: VariableId,
    ) -> Option<VariableId> {
        let instruments = self.variables_by_domain(VariableDomain::Instrument);

        for &inst in &instruments {
            // Instrument must affect treatment
            if !self.has_path(inst, treatment) {
                continue;
            }

            // Instrument must NOT have a direct path to outcome (only through treatment)
            // We verify this by searching for a path from `inst` to `outcome` that does NOT pass through `treatment`.
            let mut stack = vec![inst];
            let mut visited = BTreeSet::new();
            let mut has_direct_outcome_path = false;

            while let Some(node) = stack.pop() {
                if node == outcome {
                    has_direct_outcome_path = true;
                    break;
                }
                if node == treatment && node != inst {
                    continue; // Stop exploring this path, it goes through treatment
                }
                if visited.insert(node) {
                    if let Some(children) = self.children.get(&node) {
                        for &child in children {
                            stack.push(child);
                        }
                    }
                }
            }

            // Check: instrument -> treatment -> outcome, no inst -> outcome bypass
            if !has_direct_outcome_path {
                if let Some(var) = self.variables.get(&inst) {
                    if var.observability != Observability::Latent {
                        return Some(inst);
                    }
                }
            }
        }
        None
    }

    /// Compute a full identifiability certificate for the effect of
    /// treatment on outcome.
    #[allow(clippy::collapsible_if)]
    pub fn identify_effect(
        &self,
        treatment: VariableId,
        outcome: VariableId,
    ) -> IdentifiabilityCertificate {
        let mut reasons = Vec::new();

        // Check observability
        if let Some(t_var) = self.variables.get(&treatment) {
            if t_var.observability == Observability::Latent {
                reasons.push(UnidentifiableReason::TreatmentNotObservable);
            }
        }
        if let Some(o_var) = self.variables.get(&outcome) {
            if o_var.observability == Observability::Latent {
                reasons.push(UnidentifiableReason::OutcomeNotObservable);
            }
        }

        // Check connectivity
        if !self.has_path(treatment, outcome) {
            reasons.push(UnidentifiableReason::NotConnected);
            return self.build_unidentifiable_cert(treatment, outcome, reasons);
        }

        // Try backdoor criterion first
        let adj = self.backdoor_adjustment(treatment, outcome);
        if adj.is_valid {
            return self.build_identified_cert(
                treatment,
                outcome,
                IdentificationStrategy::Backdoor,
                Some(adj),
                None,
                None,
            );
        }
        reasons.push(UnidentifiableReason::NoBackdoorSet);

        // Try front-door criterion
        if let Some(mediator) = self.front_door_mediator(treatment, outcome) {
            return self.build_identified_cert(
                treatment,
                outcome,
                IdentificationStrategy::FrontDoor,
                None,
                Some(mediator),
                None,
            );
        }
        reasons.push(UnidentifiableReason::NoFrontDoorPath);

        // Try instrumental variable
        if let Some(instrument) = self.find_instrument(treatment, outcome) {
            return self.build_identified_cert(
                treatment,
                outcome,
                IdentificationStrategy::Instrumental,
                None,
                None,
                Some(instrument),
            );
        }
        reasons.push(UnidentifiableReason::NoInstrument);

        self.build_unidentifiable_cert(treatment, outcome, reasons)
    }

    fn build_identified_cert(
        &self,
        treatment: VariableId,
        outcome: VariableId,
        strategy: IdentificationStrategy,
        adjustment_set: Option<AdjustmentSet>,
        front_door_mediator: Option<VariableId>,
        instrument: Option<VariableId>,
    ) -> IdentifiabilityCertificate {
        let cert_data = serde_json::to_vec(&(
            treatment,
            outcome,
            &strategy,
            &adjustment_set,
            front_door_mediator,
            instrument,
        ))
        .unwrap_or_default();

        IdentifiabilityCertificate {
            schema_version: CAUSAL_DAG_SCHEMA_VERSION.to_string(),
            treatment,
            outcome,
            is_identifiable: true,
            strategy,
            adjustment_set,
            front_door_mediator,
            instrument,
            unidentifiable_reasons: Vec::new(),
            dag_hash: self.structure_hash,
            certificate_hash: ContentHash::compute(&cert_data),
        }
    }

    fn build_unidentifiable_cert(
        &self,
        treatment: VariableId,
        outcome: VariableId,
        reasons: Vec<UnidentifiableReason>,
    ) -> IdentifiabilityCertificate {
        let cert_data = serde_json::to_vec(&(treatment, outcome, &reasons)).unwrap_or_default();

        IdentifiabilityCertificate {
            schema_version: CAUSAL_DAG_SCHEMA_VERSION.to_string(),
            treatment,
            outcome,
            is_identifiable: false,
            strategy: IdentificationStrategy::Unidentifiable,
            adjustment_set: None,
            front_door_mediator: None,
            instrument: None,
            unidentifiable_reasons: reasons,
            dag_hash: self.structure_hash,
            certificate_hash: ContentHash::compute(&cert_data),
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence Corpus: FrankenEngine Optimization DAG
// ---------------------------------------------------------------------------

/// Build the canonical FrankenEngine optimization causal DAG.
///
/// This encodes the structural relationships between:
/// - Workload characteristics (confounders)
/// - Optimization decisions (treatments)
/// - Performance outcomes (outcomes)
/// - Intermediate measurements (mediators)
pub fn frankenengine_optimization_dag() -> Result<CausalDag, CausalDagError> {
    let mut builder = CausalDagBuilder::new();

    // --- Treatments ---
    builder.add_variable(CausalVariable {
        id: 1,
        name: "tiering_level".to_string(),
        domain: VariableDomain::Treatment,
        observability: Observability::Observable,
        scale: MeasurementScale::Ordinal,
        description: "Execution tier: baseline, quickened, or optimized".to_string(),
        subsystem: "tier_up_profiler".to_string(),
    })?;
    builder.add_variable(CausalVariable {
        id: 2,
        name: "cache_policy".to_string(),
        domain: VariableDomain::Treatment,
        observability: Observability::Observable,
        scale: MeasurementScale::Categorical,
        description: "Cache eviction/admission policy (S3-FIFO, LRU, etc.)".to_string(),
        subsystem: "persistent_cache_contract".to_string(),
    })?;
    builder.add_variable(CausalVariable {
        id: 3,
        name: "gc_strategy".to_string(),
        domain: VariableDomain::Treatment,
        observability: Observability::Observable,
        scale: MeasurementScale::Categorical,
        description: "GC scheduling and collection strategy".to_string(),
        subsystem: "alloc_domain".to_string(),
    })?;

    // --- Confounders ---
    builder.add_variable(CausalVariable {
        id: 10,
        name: "workload_type".to_string(),
        domain: VariableDomain::Confounder,
        observability: Observability::Observable,
        scale: MeasurementScale::Categorical,
        description: "Workload family: compute-bound, IO-bound, mixed".to_string(),
        subsystem: "workload_embedding".to_string(),
    })?;
    builder.add_variable(CausalVariable {
        id: 11,
        name: "concurrency_level".to_string(),
        domain: VariableDomain::Confounder,
        observability: Observability::Observable,
        scale: MeasurementScale::Continuous,
        description: "Number of concurrent extension invocations".to_string(),
        subsystem: "execution_orchestrator".to_string(),
    })?;
    builder.add_variable(CausalVariable {
        id: 12,
        name: "hardware_profile".to_string(),
        domain: VariableDomain::Confounder,
        observability: Observability::Proxy,
        scale: MeasurementScale::Categorical,
        description: "CPU/memory/cache characteristics of the host".to_string(),
        subsystem: "runtime_diagnostics_cli".to_string(),
    })?;

    // --- Mediators ---
    builder.add_variable(CausalVariable {
        id: 20,
        name: "compilation_time".to_string(),
        domain: VariableDomain::Mediator,
        observability: Observability::Observable,
        scale: MeasurementScale::Continuous,
        description: "Time spent in compilation/optimization passes".to_string(),
        subsystem: "lowering_pipeline".to_string(),
    })?;
    builder.add_variable(CausalVariable {
        id: 21,
        name: "cache_hit_rate".to_string(),
        domain: VariableDomain::Mediator,
        observability: Observability::Observable,
        scale: MeasurementScale::Continuous,
        description: "Fraction of code/data accesses served from cache".to_string(),
        subsystem: "persistent_cache_contract".to_string(),
    })?;

    // --- Outcomes ---
    builder.add_variable(CausalVariable {
        id: 30,
        name: "p99_latency".to_string(),
        domain: VariableDomain::Outcome,
        observability: Observability::Observable,
        scale: MeasurementScale::Continuous,
        description: "99th percentile request latency in millionths-of-seconds".to_string(),
        subsystem: "stage_envelope_certificate".to_string(),
    })?;
    builder.add_variable(CausalVariable {
        id: 31,
        name: "throughput".to_string(),
        domain: VariableDomain::Outcome,
        observability: Observability::Observable,
        scale: MeasurementScale::Continuous,
        description: "Operations per second sustained".to_string(),
        subsystem: "benchmark_e2e".to_string(),
    })?;
    builder.add_variable(CausalVariable {
        id: 32,
        name: "memory_usage".to_string(),
        domain: VariableDomain::Outcome,
        observability: Observability::Observable,
        scale: MeasurementScale::Continuous,
        description: "Peak RSS memory in bytes".to_string(),
        subsystem: "alloc_domain".to_string(),
    })?;

    // --- Instrument ---
    builder.add_variable(CausalVariable {
        id: 40,
        name: "randomized_tier_assignment".to_string(),
        domain: VariableDomain::Instrument,
        observability: Observability::Observable,
        scale: MeasurementScale::Binary,
        description: "Randomized tier assignment for A/B testing".to_string(),
        subsystem: "deterministic_sim_scheduler".to_string(),
    })?;

    // --- Edges ---
    // Confounders -> Treatments
    builder.add_edge(CausalEdge {
        from: 10,
        to: 1,
        kind: EdgeKind::Confounding,
        confidence: EdgeConfidence::Structural,
        mechanism: "Workload type influences optimal tiering level".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 10,
        to: 2,
        kind: EdgeKind::Confounding,
        confidence: EdgeConfidence::Structural,
        mechanism: "Workload type influences cache policy effectiveness".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 11,
        to: 1,
        kind: EdgeKind::Confounding,
        confidence: EdgeConfidence::Structural,
        mechanism: "Concurrency affects tiering pressure".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 12,
        to: 3,
        kind: EdgeKind::Confounding,
        confidence: EdgeConfidence::Empirical,
        mechanism: "Hardware profile influences GC strategy effectiveness".to_string(),
    });

    // Confounders -> Outcomes
    builder.add_edge(CausalEdge {
        from: 10,
        to: 30,
        kind: EdgeKind::Confounding,
        confidence: EdgeConfidence::Structural,
        mechanism: "Workload type directly affects p99 latency".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 11,
        to: 30,
        kind: EdgeKind::Confounding,
        confidence: EdgeConfidence::Structural,
        mechanism: "Concurrency directly affects tail latency".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 10,
        to: 31,
        kind: EdgeKind::Confounding,
        confidence: EdgeConfidence::Structural,
        mechanism: "Workload type directly affects throughput".to_string(),
    });

    // Treatments -> Mediators
    builder.add_edge(CausalEdge {
        from: 1,
        to: 20,
        kind: EdgeKind::Direct,
        confidence: EdgeConfidence::Structural,
        mechanism: "Higher tiers require more compilation time".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 2,
        to: 21,
        kind: EdgeKind::Direct,
        confidence: EdgeConfidence::Structural,
        mechanism: "Cache policy determines hit rate".to_string(),
    });

    // Mediators -> Outcomes
    builder.add_edge(CausalEdge {
        from: 20,
        to: 30,
        kind: EdgeKind::Mediated,
        confidence: EdgeConfidence::Structural,
        mechanism: "Compilation time contributes to initial latency".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 21,
        to: 30,
        kind: EdgeKind::Mediated,
        confidence: EdgeConfidence::Structural,
        mechanism: "Cache hit rate reduces repeated access latency".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 20,
        to: 31,
        kind: EdgeKind::Mediated,
        confidence: EdgeConfidence::Empirical,
        mechanism: "Compilation enables higher throughput optimizations".to_string(),
    });

    // Treatments -> Outcomes (direct)
    builder.add_edge(CausalEdge {
        from: 1,
        to: 31,
        kind: EdgeKind::Direct,
        confidence: EdgeConfidence::Structural,
        mechanism: "Tiering directly affects throughput via code quality".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 3,
        to: 32,
        kind: EdgeKind::Direct,
        confidence: EdgeConfidence::Structural,
        mechanism: "GC strategy directly affects memory usage".to_string(),
    });
    builder.add_edge(CausalEdge {
        from: 3,
        to: 30,
        kind: EdgeKind::Direct,
        confidence: EdgeConfidence::Empirical,
        mechanism: "GC pauses contribute to tail latency".to_string(),
    });

    // Instrument -> Treatment
    builder.add_edge(CausalEdge {
        from: 40,
        to: 1,
        kind: EdgeKind::Instrumental,
        confidence: EdgeConfidence::Structural,
        mechanism: "Randomized assignment determines tier (exogenous)".to_string(),
    });

    builder.build()
}

/// Run the evidence corpus over the canonical DAG and produce a manifest.
pub fn run_causal_dag_evidence() -> CausalDagEvidenceManifest {
    let dag = match frankenengine_optimization_dag() {
        Ok(d) => d,
        Err(e) => {
            return CausalDagEvidenceManifest {
                schema_version: CAUSAL_DAG_SCHEMA_VERSION.to_string(),
                dag_variable_count: 0,
                dag_edge_count: 0,
                certificates_generated: 0,
                identifiable_count: 0,
                unidentifiable_count: 0,
                certificates: Vec::new(),
                manifest_hash: ContentHash::compute(b"error"),
                error: Some(e.to_string()),
            };
        }
    };

    let treatments = dag.variables_by_domain(VariableDomain::Treatment);
    let outcomes = dag.variables_by_domain(VariableDomain::Outcome);

    let mut certificates = Vec::new();
    for &t in &treatments {
        for &o in &outcomes {
            let cert = dag.identify_effect(t, o);
            certificates.push(cert);
        }
    }

    let id_count = certificates.iter().filter(|c| c.is_identifiable).count() as u32;
    let unid_count = certificates.iter().filter(|c| !c.is_identifiable).count() as u32;

    let hash_data = serde_json::to_vec(&certificates).unwrap_or_default();

    CausalDagEvidenceManifest {
        schema_version: CAUSAL_DAG_SCHEMA_VERSION.to_string(),
        dag_variable_count: dag.variable_count() as u32,
        dag_edge_count: dag.edge_count() as u32,
        certificates_generated: certificates.len() as u32,
        identifiable_count: id_count,
        unidentifiable_count: unid_count,
        certificates,
        manifest_hash: ContentHash::compute(&hash_data),
        error: None,
    }
}

/// Evidence manifest for the causal DAG corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalDagEvidenceManifest {
    pub schema_version: String,
    pub dag_variable_count: u32,
    pub dag_edge_count: u32,
    pub certificates_generated: u32,
    pub identifiable_count: u32,
    pub unidentifiable_count: u32,
    pub certificates: Vec<IdentifiabilityCertificate>,
    pub manifest_hash: ContentHash,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_dag() -> CausalDag {
        let mut b = CausalDagBuilder::new();
        b.add_variable(CausalVariable {
            id: 1,
            name: "T".to_string(),
            domain: VariableDomain::Treatment,
            observability: Observability::Observable,
            scale: MeasurementScale::Binary,
            description: "treatment".to_string(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_variable(CausalVariable {
            id: 2,
            name: "Y".to_string(),
            domain: VariableDomain::Outcome,
            observability: Observability::Observable,
            scale: MeasurementScale::Continuous,
            description: "outcome".to_string(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_variable(CausalVariable {
            id: 3,
            name: "C".to_string(),
            domain: VariableDomain::Confounder,
            observability: Observability::Observable,
            scale: MeasurementScale::Categorical,
            description: "confounder".to_string(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(CausalEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "T -> Y".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "C -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "C -> Y".to_string(),
        });
        b.build().unwrap()
    }

    // --- Schema & Constants ---

    #[test]
    fn test_schema_constants() {
        assert!(!CAUSAL_DAG_SCHEMA_VERSION.is_empty());
        assert!(!CAUSAL_DAG_COMPONENT.is_empty());
        assert_eq!(CAUSAL_DAG_POLICY_ID, "RGC-615A");
    }

    // --- VariableDomain ---

    #[test]
    fn test_variable_domain_as_str() {
        for domain in VariableDomain::ALL {
            assert!(!domain.as_str().is_empty());
            assert_eq!(format!("{domain}"), domain.as_str());
        }
    }

    #[test]
    fn test_variable_domain_serde() {
        for domain in VariableDomain::ALL {
            let json = serde_json::to_string(domain).unwrap();
            let back: VariableDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*domain, back);
        }
    }

    // --- DAG Builder ---

    #[test]
    fn test_build_simple_dag() {
        let dag = simple_dag();
        assert_eq!(dag.variable_count(), 3);
        assert_eq!(dag.edge_count(), 3);
    }

    #[test]
    fn test_empty_dag_error() {
        let b = CausalDagBuilder::new();
        assert!(matches!(b.build(), Err(CausalDagError::EmptyDag)));
    }

    #[test]
    fn test_duplicate_variable_error() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(CausalVariable {
            id: 1,
            name: "A".to_string(),
            domain: VariableDomain::Treatment,
            observability: Observability::Observable,
            scale: MeasurementScale::Binary,
            description: "".to_string(),
            subsystem: "".to_string(),
        })
        .unwrap();
        let result = b.add_variable(CausalVariable {
            id: 1,
            name: "B".to_string(),
            domain: VariableDomain::Outcome,
            observability: Observability::Observable,
            scale: MeasurementScale::Continuous,
            description: "".to_string(),
            subsystem: "".to_string(),
        });
        assert!(matches!(
            result,
            Err(CausalDagError::DuplicateVariable { id: 1 })
        ));
    }

    #[test]
    fn test_unknown_variable_error() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(CausalVariable {
            id: 1,
            name: "A".to_string(),
            domain: VariableDomain::Treatment,
            observability: Observability::Observable,
            scale: MeasurementScale::Binary,
            description: "".to_string(),
            subsystem: "".to_string(),
        })
        .unwrap();
        b.add_edge(CausalEdge {
            from: 1,
            to: 99,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "".to_string(),
        });
        assert!(matches!(
            b.build(),
            Err(CausalDagError::UnknownVariable { id: 99 })
        ));
    }

    #[test]
    fn test_cycle_detection() {
        let mut b = CausalDagBuilder::new();
        for id in 1..=3 {
            b.add_variable(CausalVariable {
                id,
                name: format!("V{id}"),
                domain: VariableDomain::Treatment,
                observability: Observability::Observable,
                scale: MeasurementScale::Binary,
                description: "".to_string(),
                subsystem: "".to_string(),
            })
            .unwrap();
        }
        b.add_edge(CausalEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 2,
            to: 3,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "".to_string(),
        });
        assert!(matches!(
            b.build(),
            Err(CausalDagError::CycleDetected { .. })
        ));
    }

    // --- Graph Queries ---

    #[test]
    fn test_ancestors() {
        let dag = simple_dag();
        let anc = dag.ancestors(2); // outcome
        assert!(anc.contains(&1)); // treatment
        assert!(anc.contains(&3)); // confounder
    }

    #[test]
    fn test_descendants() {
        let dag = simple_dag();
        let desc = dag.descendants(3); // confounder
        assert!(desc.contains(&1)); // treatment
        assert!(desc.contains(&2)); // outcome
    }

    #[test]
    fn test_has_path() {
        let dag = simple_dag();
        assert!(dag.has_path(3, 2)); // C -> T -> Y
        assert!(dag.has_path(1, 2)); // T -> Y
        assert!(!dag.has_path(2, 1)); // no reverse path
    }

    #[test]
    fn test_variables_by_domain() {
        let dag = simple_dag();
        let treatments = dag.variables_by_domain(VariableDomain::Treatment);
        assert_eq!(treatments, vec![1]);
        let outcomes = dag.variables_by_domain(VariableDomain::Outcome);
        assert_eq!(outcomes, vec![2]);
    }

    // --- Backdoor Adjustment ---

    #[test]
    fn test_backdoor_adjustment_simple() {
        let dag = simple_dag();
        let adj = dag.backdoor_adjustment(1, 2);
        assert!(adj.is_valid);
        assert!(adj.variables.contains(&3)); // must adjust for confounder
    }

    #[test]
    fn test_backdoor_adjustment_no_confounders() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(CausalVariable {
            id: 1,
            name: "T".to_string(),
            domain: VariableDomain::Treatment,
            observability: Observability::Observable,
            scale: MeasurementScale::Binary,
            description: "".to_string(),
            subsystem: "".to_string(),
        })
        .unwrap();
        b.add_variable(CausalVariable {
            id: 2,
            name: "Y".to_string(),
            domain: VariableDomain::Outcome,
            observability: Observability::Observable,
            scale: MeasurementScale::Continuous,
            description: "".to_string(),
            subsystem: "".to_string(),
        })
        .unwrap();
        b.add_edge(CausalEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "".to_string(),
        });
        let dag = b.build().unwrap();
        let adj = dag.backdoor_adjustment(1, 2);
        assert!(adj.is_valid);
        assert!(adj.variables.is_empty()); // no confounders to adjust for
    }

    // --- Identifiability Certificates ---

    #[test]
    fn test_identify_effect_backdoor() {
        let dag = simple_dag();
        let cert = dag.identify_effect(1, 2);
        assert!(cert.is_identifiable);
        assert_eq!(cert.strategy, IdentificationStrategy::Backdoor);
        assert!(cert.adjustment_set.is_some());
    }

    #[test]
    fn test_identify_effect_not_connected() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(CausalVariable {
            id: 1,
            name: "T".to_string(),
            domain: VariableDomain::Treatment,
            observability: Observability::Observable,
            scale: MeasurementScale::Binary,
            description: "".to_string(),
            subsystem: "".to_string(),
        })
        .unwrap();
        b.add_variable(CausalVariable {
            id: 2,
            name: "Y".to_string(),
            domain: VariableDomain::Outcome,
            observability: Observability::Observable,
            scale: MeasurementScale::Continuous,
            description: "".to_string(),
            subsystem: "".to_string(),
        })
        .unwrap();
        let dag = b.build().unwrap();
        let cert = dag.identify_effect(1, 2);
        assert!(!cert.is_identifiable);
        assert!(
            cert.unidentifiable_reasons
                .contains(&UnidentifiableReason::NotConnected)
        );
    }

    #[test]
    fn test_certificate_hash_deterministic() {
        let dag = simple_dag();
        let c1 = dag.identify_effect(1, 2);
        let c2 = dag.identify_effect(1, 2);
        assert_eq!(c1.certificate_hash, c2.certificate_hash);
    }

    #[test]
    fn test_certificate_serde_roundtrip() {
        let dag = simple_dag();
        let cert = dag.identify_effect(1, 2);
        let json = serde_json::to_string(&cert).unwrap();
        let back: IdentifiabilityCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    // --- Instrumental Variable ---

    #[test]
    fn test_find_instrument() {
        let mut b = CausalDagBuilder::new();
        for (id, name, domain) in [
            (1, "T", VariableDomain::Treatment),
            (2, "Y", VariableDomain::Outcome),
            (3, "Z", VariableDomain::Instrument),
        ] {
            b.add_variable(CausalVariable {
                id,
                name: name.to_string(),
                domain,
                observability: Observability::Observable,
                scale: MeasurementScale::Binary,
                description: "".to_string(),
                subsystem: "".to_string(),
            })
            .unwrap();
        }
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Instrumental,
            confidence: EdgeConfidence::Structural,
            mechanism: "".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "".to_string(),
        });
        let dag = b.build().unwrap();
        let inst = dag.find_instrument(1, 2);
        assert_eq!(inst, Some(3));
    }

    // --- FrankenEngine Optimization DAG ---

    #[test]
    fn test_frankenengine_dag_builds() {
        let dag = frankenengine_optimization_dag().unwrap();
        assert!(dag.variable_count() >= 10);
        assert!(dag.edge_count() >= 10);
    }

    #[test]
    fn test_frankenengine_dag_has_treatments() {
        let dag = frankenengine_optimization_dag().unwrap();
        let treatments = dag.variables_by_domain(VariableDomain::Treatment);
        assert!(treatments.len() >= 3);
    }

    #[test]
    fn test_frankenengine_dag_has_outcomes() {
        let dag = frankenengine_optimization_dag().unwrap();
        let outcomes = dag.variables_by_domain(VariableDomain::Outcome);
        assert!(outcomes.len() >= 3);
    }

    #[test]
    fn test_frankenengine_dag_acyclic() {
        // If it builds, it's acyclic (validated by builder)
        assert!(frankenengine_optimization_dag().is_ok());
    }

    #[test]
    fn test_frankenengine_dag_hash_deterministic() {
        let d1 = frankenengine_optimization_dag().unwrap();
        let d2 = frankenengine_optimization_dag().unwrap();
        assert_eq!(d1.structure_hash, d2.structure_hash);
    }

    // --- Evidence Manifest ---

    #[test]
    fn test_evidence_manifest_runs() {
        let manifest = run_causal_dag_evidence();
        assert!(manifest.error.is_none());
        assert!(manifest.certificates_generated > 0);
        assert_eq!(
            manifest.identifiable_count + manifest.unidentifiable_count,
            manifest.certificates_generated
        );
    }

    #[test]
    fn test_evidence_manifest_deterministic() {
        let m1 = run_causal_dag_evidence();
        let m2 = run_causal_dag_evidence();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    #[test]
    fn test_evidence_manifest_has_identifiable() {
        let manifest = run_causal_dag_evidence();
        assert!(manifest.identifiable_count > 0);
    }

    // --- Error Display ---

    #[test]
    fn test_error_display() {
        assert!(format!("{}", CausalDagError::EmptyDag).contains("empty"));
        assert!(format!("{}", CausalDagError::UnknownVariable { id: 5 }).contains("5"));
        assert!(format!("{}", CausalDagError::CycleDetected { from: 1, to: 2 }).contains("cycle"));
    }

    // --- IdentificationStrategy ---

    #[test]
    fn test_identification_strategy_display() {
        for s in [
            IdentificationStrategy::Backdoor,
            IdentificationStrategy::FrontDoor,
            IdentificationStrategy::Instrumental,
            IdentificationStrategy::Unidentifiable,
        ] {
            assert!(!s.as_str().is_empty());
            assert_eq!(format!("{s}"), s.as_str());
        }
    }

    // --- UnidentifiableReason ---

    #[test]
    fn test_unidentifiable_reason_display() {
        for r in [
            UnidentifiableReason::NoBackdoorSet,
            UnidentifiableReason::NoFrontDoorPath,
            UnidentifiableReason::NoInstrument,
            UnidentifiableReason::NotConnected,
            UnidentifiableReason::AllConfoundersLatent,
            UnidentifiableReason::TreatmentNotObservable,
            UnidentifiableReason::OutcomeNotObservable,
        ] {
            assert!(!format!("{r}").is_empty());
        }
    }

    #[test]
    fn test_unidentifiable_reason_serde() {
        for r in [
            UnidentifiableReason::NoBackdoorSet,
            UnidentifiableReason::NotConnected,
        ] {
            let json = serde_json::to_string(&r).unwrap();
            let back: UnidentifiableReason = serde_json::from_str(&json).unwrap();
            assert_eq!(r, back);
        }
    }

    // --- DAG serde ---

    #[test]
    fn test_dag_serde_roundtrip() {
        let dag = simple_dag();
        let json = serde_json::to_string(&dag).unwrap();
        let back: CausalDag = serde_json::from_str(&json).unwrap();
        assert_eq!(dag.variable_count(), back.variable_count());
        assert_eq!(dag.edge_count(), back.edge_count());
        assert_eq!(dag.structure_hash, back.structure_hash);
    }

    #[test]
    fn test_causal_edge_serde() {
        let edge = CausalEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "test".to_string(),
        };
        let json = serde_json::to_string(&edge).unwrap();
        let back: CausalEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(edge, back);
    }

    // --- LoweringStats Default ---

    #[test]
    fn test_default_builder() {
        let b = CausalDagBuilder::default();
        assert!(matches!(b.build(), Err(CausalDagError::EmptyDag)));
    }

    // -----------------------------------------------------------------------
    // Deep enrichment tests (PearlTower 2026-03-18)
    // -----------------------------------------------------------------------

    fn make_var(id: VariableId, name: &str, domain: VariableDomain) -> CausalVariable {
        CausalVariable {
            id,
            name: name.to_string(),
            domain,
            observability: Observability::Observable,
            scale: MeasurementScale::Binary,
            description: String::new(),
            subsystem: "test".to_string(),
        }
    }

    fn make_edge(from: VariableId, to: VariableId) -> CausalEdge {
        CausalEdge {
            from,
            to,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: String::new(),
        }
    }

    #[test]
    fn test_has_path_reflexive() {
        let dag = simple_dag();
        assert!(dag.has_path(1, 1));
        assert!(dag.has_path(2, 2));
        assert!(dag.has_path(3, 3));
    }

    #[test]
    fn test_ancestors_of_root_empty() {
        // Variable 3 (confounder) has no parents in simple_dag, it's a root
        let dag = simple_dag();
        let anc = dag.ancestors(3);
        assert!(anc.is_empty());
    }

    #[test]
    fn test_descendants_of_leaf_empty() {
        // Variable 2 (outcome) has no children in simple_dag
        let dag = simple_dag();
        let desc = dag.descendants(2);
        assert!(desc.is_empty());
    }

    #[test]
    fn test_long_chain_path() {
        // Build a chain: 1 -> 2 -> 3 -> 4 -> 5
        let mut b = CausalDagBuilder::new();
        for id in 1..=5 {
            b.add_variable(make_var(id, &format!("V{id}"), VariableDomain::Treatment))
                .unwrap();
        }
        for from in 1..5 {
            b.add_edge(make_edge(from, from + 1));
        }
        let dag = b.build().unwrap();
        assert!(dag.has_path(1, 5));
        assert!(!dag.has_path(5, 1));
        let desc = dag.descendants(1);
        assert_eq!(desc.len(), 4); // 2, 3, 4, 5
        let anc = dag.ancestors(5);
        assert_eq!(anc.len(), 4); // 1, 2, 3, 4
    }

    #[test]
    fn test_isolated_variable_no_paths() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "B", VariableDomain::Outcome))
            .unwrap();
        // No edges
        let dag = b.build().unwrap();
        assert!(!dag.has_path(1, 2));
        assert!(!dag.has_path(2, 1));
        assert!(dag.ancestors(1).is_empty());
        assert!(dag.descendants(1).is_empty());
    }

    #[test]
    fn test_variables_by_domain_empty() {
        let dag = simple_dag();
        let instruments = dag.variables_by_domain(VariableDomain::Instrument);
        assert!(instruments.is_empty());
    }

    #[test]
    fn test_diamond_dag() {
        // Diamond: 1 -> 2 -> 4, 1 -> 3 -> 4
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "B", VariableDomain::Mediator))
            .unwrap();
        b.add_variable(make_var(3, "C", VariableDomain::Mediator))
            .unwrap();
        b.add_variable(make_var(4, "D", VariableDomain::Outcome))
            .unwrap();
        b.add_edge(make_edge(1, 2));
        b.add_edge(make_edge(1, 3));
        b.add_edge(make_edge(2, 4));
        b.add_edge(make_edge(3, 4));
        let dag = b.build().unwrap();
        assert!(dag.has_path(1, 4));
        let parents_of_4 = dag.parents.get(&4).unwrap();
        assert_eq!(parents_of_4.len(), 2);
        assert!(parents_of_4.contains(&2));
        assert!(parents_of_4.contains(&3));
    }

    #[test]
    fn test_backdoor_with_latent_confounder() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 3,
            name: "U".to_string(),
            domain: VariableDomain::Confounder,
            observability: Observability::Latent, // unobservable!
            scale: MeasurementScale::Continuous,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(make_edge(1, 2));
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> Y".to_string(),
        });
        let dag = b.build().unwrap();
        let adj = dag.backdoor_adjustment(1, 2);
        // Latent confounder should NOT be in adjustment set
        assert!(!adj.variables.contains(&3));
        // Adjustment should be invalid because latent confounder can't be conditioned on
        assert!(!adj.is_valid);
    }

    #[test]
    fn test_front_door_identification() {
        // T -> M -> Y, with U -> T and U -> Y (U is latent confounder)
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "M", VariableDomain::Mediator))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 4,
            name: "U".to_string(),
            domain: VariableDomain::Confounder,
            observability: Observability::Latent,
            scale: MeasurementScale::Continuous,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(make_edge(1, 3)); // T -> M
        b.add_edge(make_edge(3, 2)); // M -> Y
        b.add_edge(CausalEdge {
            from: 4,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 4,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> Y".to_string(),
        });
        let dag = b.build().unwrap();
        let mediator = dag.front_door_mediator(1, 2);
        assert_eq!(mediator, Some(3));
    }

    #[test]
    fn test_no_front_door_when_no_mediator() {
        let dag = simple_dag();
        let mediator = dag.front_door_mediator(1, 2);
        assert!(mediator.is_none());
    }

    #[test]
    fn test_find_instrument_returns_none_when_none() {
        let dag = simple_dag();
        assert!(dag.find_instrument(1, 2).is_none());
    }

    #[test]
    fn test_edge_kind_serde() {
        for kind in [
            EdgeKind::Direct,
            EdgeKind::Mediated,
            EdgeKind::Confounding,
            EdgeKind::Instrumental,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: EdgeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn test_edge_confidence_serde() {
        for conf in [
            EdgeConfidence::Structural,
            EdgeConfidence::Empirical,
            EdgeConfidence::Hypothesized,
        ] {
            let json = serde_json::to_string(&conf).unwrap();
            let back: EdgeConfidence = serde_json::from_str(&json).unwrap();
            assert_eq!(conf, back);
        }
    }

    #[test]
    fn test_observability_serde() {
        for obs in [
            Observability::Observable,
            Observability::Latent,
            Observability::Proxy,
        ] {
            let json = serde_json::to_string(&obs).unwrap();
            let back: Observability = serde_json::from_str(&json).unwrap();
            assert_eq!(obs, back);
        }
    }

    #[test]
    fn test_measurement_scale_serde() {
        for scale in [
            MeasurementScale::Binary,
            MeasurementScale::Ordinal,
            MeasurementScale::Continuous,
            MeasurementScale::Categorical,
        ] {
            let json = serde_json::to_string(&scale).unwrap();
            let back: MeasurementScale = serde_json::from_str(&json).unwrap();
            assert_eq!(scale, back);
        }
    }

    #[test]
    fn test_identification_strategy_serde() {
        for s in [
            IdentificationStrategy::Backdoor,
            IdentificationStrategy::FrontDoor,
            IdentificationStrategy::Instrumental,
            IdentificationStrategy::Unidentifiable,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let back: IdentificationStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn test_error_display_all_variants() {
        let errors = [
            CausalDagError::UnknownVariable { id: 42 },
            CausalDagError::CycleDetected { from: 1, to: 2 },
            CausalDagError::DuplicateVariable { id: 5 },
            CausalDagError::NoPath { from: 10, to: 20 },
            CausalDagError::EmptyDag,
        ];
        for e in &errors {
            assert!(!format!("{e}").is_empty());
        }
    }

    #[test]
    fn test_error_serde() {
        let err = CausalDagError::CycleDetected { from: 1, to: 2 };
        let json = serde_json::to_string(&err).unwrap();
        let back: CausalDagError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    #[test]
    fn test_single_variable_dag() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "lonely", VariableDomain::Treatment))
            .unwrap();
        let dag = b.build().unwrap();
        assert_eq!(dag.variable_count(), 1);
        assert_eq!(dag.edge_count(), 0);
    }

    #[test]
    fn test_structure_hash_changes_with_edges() {
        let mut b1 = CausalDagBuilder::new();
        b1.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b1.add_variable(make_var(2, "B", VariableDomain::Outcome))
            .unwrap();
        let dag1 = b1.build().unwrap();

        let mut b2 = CausalDagBuilder::new();
        b2.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b2.add_variable(make_var(2, "B", VariableDomain::Outcome))
            .unwrap();
        b2.add_edge(make_edge(1, 2));
        let dag2 = b2.build().unwrap();

        assert_ne!(dag1.structure_hash, dag2.structure_hash);
    }

    #[test]
    fn test_identify_effect_latent_treatment() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(CausalVariable {
            id: 1,
            name: "T".to_string(),
            domain: VariableDomain::Treatment,
            observability: Observability::Latent,
            scale: MeasurementScale::Binary,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_edge(make_edge(1, 2));
        let dag = b.build().unwrap();
        let cert = dag.identify_effect(1, 2);
        assert!(
            cert.unidentifiable_reasons
                .contains(&UnidentifiableReason::TreatmentNotObservable)
        );
    }

    #[test]
    fn test_variable_domain_all_count() {
        assert_eq!(VariableDomain::ALL.len(), 6);
    }

    #[test]
    fn test_causal_variable_serde() {
        let var = make_var(1, "test_var", VariableDomain::Confounder);
        let json = serde_json::to_string(&var).unwrap();
        let back: CausalVariable = serde_json::from_str(&json).unwrap();
        assert_eq!(var, back);
    }

    #[test]
    fn test_adjustment_set_serde() {
        let adj = AdjustmentSet {
            treatment: 1,
            outcome: 2,
            variables: [3, 4].into_iter().collect(),
            is_valid: true,
            reason: None,
        };
        let json = serde_json::to_string(&adj).unwrap();
        let back: AdjustmentSet = serde_json::from_str(&json).unwrap();
        assert_eq!(adj, back);
    }

    // -----------------------------------------------------------------------
    // Additional enrichment tests (PearlTower 2026-03-18, batch 2)
    // -----------------------------------------------------------------------

    #[test]
    fn test_self_loop_detected_as_cycle() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b.add_edge(make_edge(1, 1)); // self-loop
        assert!(matches!(
            b.build(),
            Err(CausalDagError::CycleDetected { .. })
        ));
    }

    #[test]
    fn test_two_node_cycle_detected() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "B", VariableDomain::Outcome))
            .unwrap();
        b.add_edge(make_edge(1, 2));
        b.add_edge(make_edge(2, 1));
        assert!(matches!(
            b.build(),
            Err(CausalDagError::CycleDetected { .. })
        ));
    }

    #[test]
    fn test_unknown_variable_in_edge_from() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b.add_edge(CausalEdge {
            from: 99,
            to: 1,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: String::new(),
        });
        assert!(matches!(
            b.build(),
            Err(CausalDagError::UnknownVariable { id: 99 })
        ));
    }

    #[test]
    fn test_identify_effect_latent_outcome() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 2,
            name: "Y".to_string(),
            domain: VariableDomain::Outcome,
            observability: Observability::Latent,
            scale: MeasurementScale::Continuous,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(make_edge(1, 2));
        let dag = b.build().unwrap();
        let cert = dag.identify_effect(1, 2);
        assert!(
            cert.unidentifiable_reasons
                .contains(&UnidentifiableReason::OutcomeNotObservable)
        );
    }

    #[test]
    fn test_front_door_latent_mediator_skipped() {
        // T -> M -> Y with M latent => front-door should fail
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 3,
            name: "M".to_string(),
            domain: VariableDomain::Mediator,
            observability: Observability::Latent,
            scale: MeasurementScale::Continuous,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(make_edge(1, 3));
        b.add_edge(make_edge(3, 2));
        let dag = b.build().unwrap();
        assert!(dag.front_door_mediator(1, 2).is_none());
    }

    #[test]
    fn test_front_door_non_mediator_domain_skipped() {
        // T -> C -> Y, C is Confounder domain (not Mediator), so front-door fails
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "C", VariableDomain::Confounder))
            .unwrap();
        b.add_edge(make_edge(1, 3));
        b.add_edge(make_edge(3, 2));
        let dag = b.build().unwrap();
        assert!(dag.front_door_mediator(1, 2).is_none());
    }

    #[test]
    fn test_instrument_with_direct_outcome_path_rejected() {
        // Z -> T -> Y, but also Z -> Y directly => instrument invalid
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "Z", VariableDomain::Instrument))
            .unwrap();
        b.add_edge(make_edge(3, 1)); // Z -> T
        b.add_edge(make_edge(1, 2)); // T -> Y
        b.add_edge(make_edge(3, 2)); // Z -> Y (violates exclusion restriction)
        let dag = b.build().unwrap();
        assert!(dag.find_instrument(1, 2).is_none());
    }

    #[test]
    fn test_instrument_latent_rejected() {
        // Z (latent) -> T -> Y: instrument is latent so should be rejected
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 3,
            name: "Z".to_string(),
            domain: VariableDomain::Instrument,
            observability: Observability::Latent,
            scale: MeasurementScale::Binary,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(make_edge(3, 1));
        b.add_edge(make_edge(1, 2));
        let dag = b.build().unwrap();
        assert!(dag.find_instrument(1, 2).is_none());
    }

    #[test]
    fn test_identify_effect_falls_through_to_instrumental() {
        // Latent confounder U -> T, U -> Y (no backdoor), no mediator,
        // but instrument Z -> T available
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 3,
            name: "U".to_string(),
            domain: VariableDomain::Confounder,
            observability: Observability::Latent,
            scale: MeasurementScale::Continuous,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_variable(make_var(4, "Z", VariableDomain::Instrument))
            .unwrap();
        b.add_edge(make_edge(1, 2)); // T -> Y
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> Y".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 4,
            to: 1,
            kind: EdgeKind::Instrumental,
            confidence: EdgeConfidence::Structural,
            mechanism: "Z -> T".to_string(),
        });
        let dag = b.build().unwrap();
        let cert = dag.identify_effect(1, 2);
        assert!(cert.is_identifiable);
        assert_eq!(cert.strategy, IdentificationStrategy::Instrumental);
        assert_eq!(cert.instrument, Some(4));
    }

    #[test]
    fn test_certificate_schema_version() {
        let dag = simple_dag();
        let cert = dag.identify_effect(1, 2);
        assert_eq!(cert.schema_version, CAUSAL_DAG_SCHEMA_VERSION);
    }

    #[test]
    fn test_evidence_manifest_serde_roundtrip() {
        let manifest = run_causal_dag_evidence();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: CausalDagEvidenceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
    }

    #[test]
    fn test_backdoor_multiple_confounders() {
        // Two observable confounders: C1 -> T, C1 -> Y, C2 -> T, C2 -> Y
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "C1", VariableDomain::Confounder))
            .unwrap();
        b.add_variable(make_var(4, "C2", VariableDomain::Confounder))
            .unwrap();
        b.add_edge(make_edge(1, 2));
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "C1 -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "C1 -> Y".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 4,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "C2 -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 4,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "C2 -> Y".to_string(),
        });
        let dag = b.build().unwrap();
        let adj = dag.backdoor_adjustment(1, 2);
        assert!(adj.is_valid);
        assert!(adj.variables.contains(&3));
        assert!(adj.variables.contains(&4));
        assert_eq!(adj.variables.len(), 2);
    }

    #[test]
    fn test_collider_domain_present_in_dag() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "Col", VariableDomain::Collider))
            .unwrap();
        b.add_edge(make_edge(1, 3)); // T -> Col
        b.add_edge(make_edge(2, 3)); // Y -> Col (collider)
        b.add_edge(make_edge(1, 2)); // T -> Y
        let dag = b.build().unwrap();
        let colliders = dag.variables_by_domain(VariableDomain::Collider);
        assert_eq!(colliders, vec![3]);
        // Collider should not appear in backdoor adjustment
        let adj = dag.backdoor_adjustment(1, 2);
        assert!(!adj.variables.contains(&3));
    }

    #[test]
    fn test_ancestors_disconnected_node() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "A", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "B", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "C", VariableDomain::Confounder))
            .unwrap();
        b.add_edge(make_edge(1, 2));
        // Node 3 is disconnected
        let dag = b.build().unwrap();
        assert!(dag.ancestors(3).is_empty());
        assert!(dag.descendants(3).is_empty());
        // Node 3 is not reachable from 1 or 2
        assert!(!dag.has_path(1, 3));
        assert!(!dag.has_path(3, 2));
    }

    #[test]
    fn test_parallel_edges_same_nodes() {
        // Two edges from 1 -> 2 with different kinds
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_edge(CausalEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Direct,
            confidence: EdgeConfidence::Structural,
            mechanism: "direct".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 1,
            to: 2,
            kind: EdgeKind::Mediated,
            confidence: EdgeConfidence::Empirical,
            mechanism: "mediated".to_string(),
        });
        let dag = b.build().unwrap();
        assert_eq!(dag.edge_count(), 2);
        // Children adjacency deduplicates (BTreeSet)
        let children_of_1 = dag.children.get(&1).unwrap();
        assert_eq!(children_of_1.len(), 1);
    }

    #[test]
    fn test_variables_by_domain_multiple_matches() {
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T1", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "T2", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(3, "T3", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(10, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_edge(make_edge(1, 10));
        let dag = b.build().unwrap();
        let treatments = dag.variables_by_domain(VariableDomain::Treatment);
        assert_eq!(treatments, vec![1, 2, 3]);
    }

    #[test]
    fn test_dag_hash_changes_with_variable_name() {
        let mut b1 = CausalDagBuilder::new();
        b1.add_variable(make_var(1, "Alpha", VariableDomain::Treatment))
            .unwrap();
        let dag1 = b1.build().unwrap();

        let mut b2 = CausalDagBuilder::new();
        b2.add_variable(make_var(1, "Beta", VariableDomain::Treatment))
            .unwrap();
        let dag2 = b2.build().unwrap();

        assert_ne!(dag1.structure_hash, dag2.structure_hash);
    }

    #[test]
    fn test_error_no_path_display() {
        let e = CausalDagError::NoPath { from: 10, to: 20 };
        let display = format!("{e}");
        assert!(display.contains("no path"));
        assert!(display.contains("10"));
        assert!(display.contains("20"));
    }

    #[test]
    fn test_error_duplicate_variable_display() {
        let e = CausalDagError::DuplicateVariable { id: 7 };
        let display = format!("{e}");
        assert!(display.contains("duplicate"));
        assert!(display.contains("7"));
    }

    #[test]
    fn test_unidentifiable_cert_structure() {
        // Build a fully unidentifiable scenario: latent confounder, no mediator,
        // no instrument
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 3,
            name: "U".to_string(),
            domain: VariableDomain::Confounder,
            observability: Observability::Latent,
            scale: MeasurementScale::Continuous,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(make_edge(1, 2));
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "U -> Y".to_string(),
        });
        let dag = b.build().unwrap();
        let cert = dag.identify_effect(1, 2);
        assert!(!cert.is_identifiable);
        assert_eq!(cert.strategy, IdentificationStrategy::Unidentifiable);
        assert!(cert.adjustment_set.is_none());
        assert!(cert.front_door_mediator.is_none());
        assert!(cert.instrument.is_none());
        // Should accumulate multiple unidentifiable reasons
        assert!(cert.unidentifiable_reasons.len() >= 3);
        assert!(
            cert.unidentifiable_reasons
                .contains(&UnidentifiableReason::NoBackdoorSet)
        );
        assert!(
            cert.unidentifiable_reasons
                .contains(&UnidentifiableReason::NoFrontDoorPath)
        );
        assert!(
            cert.unidentifiable_reasons
                .contains(&UnidentifiableReason::NoInstrument)
        );
    }

    #[test]
    fn test_backdoor_proxy_confounder_included() {
        // Proxy observability confounders should be included in adjustment set
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(CausalVariable {
            id: 3,
            name: "P".to_string(),
            domain: VariableDomain::Confounder,
            observability: Observability::Proxy,
            scale: MeasurementScale::Continuous,
            description: String::new(),
            subsystem: "test".to_string(),
        })
        .unwrap();
        b.add_edge(make_edge(1, 2));
        b.add_edge(CausalEdge {
            from: 3,
            to: 1,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "P -> T".to_string(),
        });
        b.add_edge(CausalEdge {
            from: 3,
            to: 2,
            kind: EdgeKind::Confounding,
            confidence: EdgeConfidence::Structural,
            mechanism: "P -> Y".to_string(),
        });
        let dag = b.build().unwrap();
        let adj = dag.backdoor_adjustment(1, 2);
        assert!(adj.is_valid);
        assert!(adj.variables.contains(&3));
    }

    #[test]
    fn test_wide_fan_out_topology() {
        // 1 -> 2, 1 -> 3, 1 -> 4, 1 -> 5, 1 -> 6
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "root", VariableDomain::Treatment))
            .unwrap();
        for id in 2..=6 {
            b.add_variable(make_var(id, &format!("leaf{id}"), VariableDomain::Outcome))
                .unwrap();
            b.add_edge(make_edge(1, id));
        }
        let dag = b.build().unwrap();
        let desc = dag.descendants(1);
        assert_eq!(desc.len(), 5);
        for id in 2..=6 {
            assert!(desc.contains(&id));
            assert!(dag.has_path(1, id));
        }
    }

    #[test]
    fn test_wide_fan_in_topology() {
        // 1 -> 6, 2 -> 6, 3 -> 6, 4 -> 6, 5 -> 6
        let mut b = CausalDagBuilder::new();
        for id in 1..=5 {
            b.add_variable(make_var(
                id,
                &format!("src{id}"),
                VariableDomain::Confounder,
            ))
            .unwrap();
            b.add_edge(make_edge(id, 6));
        }
        b.add_variable(make_var(6, "sink", VariableDomain::Outcome))
            .unwrap();
        let dag = b.build().unwrap();
        let anc = dag.ancestors(6);
        assert_eq!(anc.len(), 5);
        for id in 1..=5 {
            assert!(anc.contains(&id));
        }
        let parents_of_6 = dag.parents.get(&6).unwrap();
        assert_eq!(parents_of_6.len(), 5);
    }

    #[test]
    fn test_frankenengine_dag_has_instrument() {
        let dag = frankenengine_optimization_dag().unwrap();
        let instruments = dag.variables_by_domain(VariableDomain::Instrument);
        assert!(!instruments.is_empty());
        assert!(instruments.contains(&40));
    }

    #[test]
    fn test_frankenengine_dag_has_mediators() {
        let dag = frankenengine_optimization_dag().unwrap();
        let mediators = dag.variables_by_domain(VariableDomain::Mediator);
        assert!(mediators.len() >= 2);
    }

    #[test]
    fn test_frankenengine_dag_confounders_affect_treatments() {
        let dag = frankenengine_optimization_dag().unwrap();
        // workload_type (10) should be an ancestor of tiering_level (1)
        let ancestors_of_tier = dag.ancestors(1);
        assert!(ancestors_of_tier.contains(&10)); // workload_type
    }

    #[test]
    fn test_certificate_dag_hash_matches_dag_structure_hash() {
        let dag = simple_dag();
        let cert = dag.identify_effect(1, 2);
        assert_eq!(cert.dag_hash, dag.structure_hash);
    }

    #[test]
    fn test_different_treatment_outcome_pairs_different_certs() {
        let dag = frankenengine_optimization_dag().unwrap();
        let cert1 = dag.identify_effect(1, 30); // tiering -> p99
        let cert2 = dag.identify_effect(2, 31); // cache -> throughput
        assert_ne!(cert1.certificate_hash, cert2.certificate_hash);
        assert_eq!(cert1.dag_hash, cert2.dag_hash);
    }

    #[test]
    fn test_unidentifiable_reason_all_variants_serde() {
        let reasons = [
            UnidentifiableReason::NoBackdoorSet,
            UnidentifiableReason::NoFrontDoorPath,
            UnidentifiableReason::NoInstrument,
            UnidentifiableReason::NotConnected,
            UnidentifiableReason::AllConfoundersLatent,
            UnidentifiableReason::TreatmentNotObservable,
            UnidentifiableReason::OutcomeNotObservable,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: UnidentifiableReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    #[test]
    fn test_error_all_variants_serde_roundtrip() {
        let errors = [
            CausalDagError::UnknownVariable { id: 42 },
            CausalDagError::CycleDetected { from: 1, to: 2 },
            CausalDagError::DuplicateVariable { id: 5 },
            CausalDagError::NoPath { from: 10, to: 20 },
            CausalDagError::EmptyDag,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: CausalDagError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn test_evidence_manifest_schema_version() {
        let manifest = run_causal_dag_evidence();
        assert_eq!(manifest.schema_version, CAUSAL_DAG_SCHEMA_VERSION);
    }

    #[test]
    fn test_evidence_manifest_covers_all_treatment_outcome_pairs() {
        let dag = frankenengine_optimization_dag().unwrap();
        let treatments = dag.variables_by_domain(VariableDomain::Treatment);
        let outcomes = dag.variables_by_domain(VariableDomain::Outcome);
        let manifest = run_causal_dag_evidence();
        assert_eq!(
            manifest.certificates_generated,
            (treatments.len() * outcomes.len()) as u32
        );
    }

    #[test]
    fn test_front_door_with_confounded_mediator_rejected() {
        // T -> M -> Y, U -> M (confounder directly to mediator, not through T)
        // This violates the front-door condition
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "M", VariableDomain::Mediator))
            .unwrap();
        b.add_variable(make_var(4, "U", VariableDomain::Confounder))
            .unwrap();
        b.add_edge(make_edge(1, 3)); // T -> M
        b.add_edge(make_edge(3, 2)); // M -> Y
        b.add_edge(make_edge(4, 3)); // U -> M (confounds mediator directly)
        let dag = b.build().unwrap();
        // U is a parent of M but U is NOT reachable from T
        // so all_m_parents_from_treatment should be false
        assert!(dag.front_door_mediator(1, 2).is_none());
    }

    #[test]
    fn test_complex_four_node_cycle_detected() {
        // 1 -> 2 -> 3 -> 4 -> 1
        let mut b = CausalDagBuilder::new();
        for id in 1..=4 {
            b.add_variable(make_var(id, &format!("V{id}"), VariableDomain::Treatment))
                .unwrap();
        }
        b.add_edge(make_edge(1, 2));
        b.add_edge(make_edge(2, 3));
        b.add_edge(make_edge(3, 4));
        b.add_edge(make_edge(4, 1));
        assert!(matches!(
            b.build(),
            Err(CausalDagError::CycleDetected { .. })
        ));
    }

    #[test]
    fn test_backdoor_instrument_parent_excluded() {
        // Instrument Z -> T -> Y, Z is a parent of T but is an Instrument domain,
        // so backdoor validation should consider it valid even if Z is not in
        // the adjustment set
        let mut b = CausalDagBuilder::new();
        b.add_variable(make_var(1, "T", VariableDomain::Treatment))
            .unwrap();
        b.add_variable(make_var(2, "Y", VariableDomain::Outcome))
            .unwrap();
        b.add_variable(make_var(3, "Z", VariableDomain::Instrument))
            .unwrap();
        b.add_edge(make_edge(3, 1)); // Z -> T
        b.add_edge(make_edge(1, 2)); // T -> Y
        b.add_edge(make_edge(3, 2)); // Z -> Y (but instrument, so allowed)
        let dag = b.build().unwrap();
        let adj = dag.backdoor_adjustment(1, 2);
        // Instrument parent with path to outcome: the validation code exempts
        // instruments from requiring adjustment
        assert!(adj.is_valid);
    }

    #[test]
    fn test_adjustment_set_with_reason_serde() {
        let adj = AdjustmentSet {
            treatment: 1,
            outcome: 2,
            variables: BTreeSet::new(),
            is_valid: false,
            reason: Some("Latent confounders present".to_string()),
        };
        let json = serde_json::to_string(&adj).unwrap();
        let back: AdjustmentSet = serde_json::from_str(&json).unwrap();
        assert_eq!(adj, back);
        assert!(back.reason.is_some());
    }
}
