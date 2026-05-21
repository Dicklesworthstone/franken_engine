//! [FRX-15.1] Structural Causal Model for Lane Decisions and Outcome Attribution
//!
//! Provides an explicit directed acyclic graph (DAG) representation of causal
//! relationships among lane choices, workload characteristics, policy settings,
//! and observed outcomes. Delivers confounder taxonomy and intervention surfaces
//! for credible attribution of performance/safety outcomes to routing decisions.
//!
//! Key concepts:
//! - **Nodes** represent observable or latent variables (exogenous inputs,
//!   endogenous intermediaries, treatment/action variables, outcome variables).
//! - **Edges** encode direct causal influence with signed direction and
//!   optional strength in fixed-point millionths.
//! - **Interventions** (`do(X=x)`) remove incoming edges to the target node
//!   and fix its value, enabling counterfactual reasoning.
//! - **Backdoor criterion** identifies sufficient adjustment sets to block
//!   all non-causal (confounding) paths from treatment to outcome.
//! - **Attribution** decomposes an observed outcome delta into contributions
//!   from individual causal pathways.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ── Node and Edge Primitives ──────────────────────────────────────────

/// Unique identifier for a node in the causal DAG.
pub type NodeId = String;

/// Classification of a causal node's role in the DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NodeRole {
    /// Externally determined variable (no parents in the DAG).
    Exogenous,
    /// Internally determined by its parents.
    Endogenous,
    /// The treatment/action variable whose effect we want to estimate.
    Treatment,
    /// The outcome variable whose variation we want to attribute.
    Outcome,
    /// A variable that causally affects both treatment and outcome.
    Confounder,
    /// A variable on the causal path from treatment to outcome.
    Mediator,
    /// A variable that affects treatment but not outcome except through treatment.
    Instrument,
}

/// Semantic domain of a causal variable in the FrankenEngine context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum VariableDomain {
    /// Lane routing decision (which lane, fallback, demote).
    LaneChoice,
    /// Workload characteristics (bundle size, component count, effect depth).
    WorkloadCharacteristic,
    /// Policy setting (loss matrix weight, threshold, budget cap).
    PolicySetting,
    /// Observable outcome (latency, correctness, memory, conformance).
    ObservedOutcome,
    /// Risk belief state (posterior over risk factors).
    RiskBelief,
    /// Regime label (normal, elevated, degraded, attack).
    Regime,
    /// Calibration or statistical quality metric.
    CalibrationMetric,
    /// External/environmental factor (load, time-of-day, fleet composition).
    EnvironmentFactor,
}

/// A node in the structural causal model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalNode {
    pub id: NodeId,
    pub label: String,
    pub role: NodeRole,
    pub domain: VariableDomain,
    /// Whether the variable is directly observable (vs latent).
    pub observable: bool,
    /// Optional fixed-point millionths value for interventional fixing.
    pub fixed_value_millionths: Option<i64>,
}

/// Signed direction of causal influence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EdgeSign {
    Positive,
    Negative,
    Ambiguous,
}

/// A directed edge from `source` to `target` in the causal DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalEdge {
    pub source: NodeId,
    pub target: NodeId,
    pub sign: EdgeSign,
    /// Optional strength estimate in fixed-point millionths (0 = unknown).
    pub strength_millionths: i64,
    /// Human-readable mechanism description.
    pub mechanism: String,
}

// ── Confounder Taxonomy ───────────────────────────────────────────────

/// Classification of confounders by their mechanism and observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfounderClass {
    /// Observable confounder: can be measured and adjusted for.
    Observable,
    /// Latent confounder: cannot be directly measured; requires IV or bounds.
    Latent,
    /// Time-varying confounder: changes between treatment and outcome measurement.
    TimeVarying,
    /// Collider: conditioning on it opens a spurious path (should NOT adjust).
    Collider,
}

/// A classified confounder with its adjustment status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedConfounder {
    pub node_id: NodeId,
    pub class: ConfounderClass,
    /// Whether this confounder is currently included in the adjustment set.
    pub adjusted: bool,
    /// Estimated bias magnitude if NOT adjusted, in fixed-point millionths.
    pub bias_bound_millionths: i64,
    /// Human-readable description of the confounding mechanism.
    pub description: String,
}

// ── Intervention ──────────────────────────────────────────────────────

/// A do-calculus intervention: do(node_id = value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intervention {
    pub node_id: NodeId,
    /// Fixed-point millionths value to set.
    pub value_millionths: i64,
    /// Human-readable description of the intervention.
    pub description: String,
}

/// An intervention surface: a set of nodes that can be intervened upon
/// to achieve credible causal identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterventionSurface {
    pub name: String,
    /// Nodes in this surface.
    pub node_ids: BTreeSet<NodeId>,
    /// Whether this surface is sufficient for identification of the
    /// treatment→outcome effect (i.e. satisfies backdoor or IV criteria).
    pub sufficient_for_identification: bool,
    /// Human-readable justification.
    pub justification: String,
}

// ── Adjustment Sets and Identification ────────────────────────────────

/// Result of checking the backdoor criterion for a (treatment, outcome) pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackdoorResult {
    pub treatment: NodeId,
    pub outcome: NodeId,
    /// A minimal sufficient adjustment set (empty if none found).
    pub adjustment_set: BTreeSet<NodeId>,
    /// Whether identification is achievable via backdoor criterion.
    pub identified: bool,
    /// All confounding paths found between treatment and outcome.
    pub confounding_paths: Vec<Vec<NodeId>>,
}

// ── Causal Effect Estimation ──────────────────────────────────────────

/// Estimated causal effect of treatment on outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalEffect {
    pub treatment: NodeId,
    pub outcome: NodeId,
    /// Point estimate of Average Treatment Effect in fixed-point millionths.
    pub ate_millionths: i64,
    /// Adjustment set used for estimation.
    pub adjustment_set: BTreeSet<NodeId>,
    /// Number of observations used.
    pub sample_size: u64,
    /// Whether the estimate is considered credibly identified.
    pub identified: bool,
}

/// A single pathway contribution to outcome attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathwayContribution {
    /// Ordered sequence of nodes forming this causal pathway.
    pub path: Vec<NodeId>,
    /// Attributed effect through this pathway in fixed-point millionths.
    pub effect_millionths: i64,
    /// Fraction of total effect attributable to this pathway (millionths).
    pub fraction_millionths: i64,
}

/// Decomposition of an outcome change into causal pathways.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionDecomposition {
    pub treatment: NodeId,
    pub outcome: NodeId,
    /// Total observed outcome delta in fixed-point millionths.
    pub total_delta_millionths: i64,
    /// Per-pathway attribution.
    pub pathways: Vec<PathwayContribution>,
    /// Residual not attributed to any identified pathway.
    pub residual_millionths: i64,
}

// ── Observation Record ────────────────────────────────────────────────

/// A single observed data point mapping node values to their measurements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub epoch: u64,
    pub tick: u64,
    /// Node ID → observed value in fixed-point millionths.
    pub values: BTreeMap<NodeId, i64>,
}

// ── The Structural Causal Model ───────────────────────────────────────

/// Errors from SCM operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScmError {
    NodeNotFound(NodeId),
    EdgeAlreadyExists { source: NodeId, target: NodeId },
    CycleDetected { path: Vec<NodeId> },
    DuplicateNode(NodeId),
    NoTreatmentNode,
    NoOutcomeNode,
    InsufficientObservations { required: u64, available: u64 },
    NotIdentified { reason: String },
}

impl std::fmt::Display for ScmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeNotFound(id) => write!(f, "node not found: {id}"),
            Self::EdgeAlreadyExists { source, target } => {
                write!(f, "edge already exists: {source} -> {target}")
            }
            Self::CycleDetected { path } => write!(f, "cycle detected: {}", path.join(" -> ")),
            Self::DuplicateNode(id) => write!(f, "duplicate node: {id}"),
            Self::NoTreatmentNode => write!(f, "no treatment node in DAG"),
            Self::NoOutcomeNode => write!(f, "no outcome node in DAG"),
            Self::InsufficientObservations {
                required,
                available,
            } => {
                write!(f, "need {required} observations, have {available}")
            }
            Self::NotIdentified { reason } => write!(f, "not identified: {reason}"),
        }
    }
}

impl std::error::Error for ScmError {}

/// The structural causal model (DAG) for lane decisions and outcome attribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralCausalModel {
    nodes: BTreeMap<NodeId, CausalNode>,
    edges: Vec<CausalEdge>,
    /// Adjacency: parent → set of children.
    children: BTreeMap<NodeId, BTreeSet<NodeId>>,
    /// Reverse adjacency: child → set of parents.
    parents: BTreeMap<NodeId, BTreeSet<NodeId>>,
    /// Classified confounders.
    confounders: Vec<ClassifiedConfounder>,
    /// Identified intervention surfaces.
    intervention_surfaces: Vec<InterventionSurface>,
    /// Observation log for estimation.
    observations: Vec<Observation>,
}

impl StructuralCausalModel {
    /// Create an empty SCM.
    pub fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            children: BTreeMap::new(),
            parents: BTreeMap::new(),
            confounders: Vec::new(),
            intervention_surfaces: Vec::new(),
            observations: Vec::new(),
        }
    }

    /// Add a node to the DAG.
    pub fn add_node(&mut self, node: CausalNode) -> Result<(), ScmError> {
        if self.nodes.contains_key(&node.id) {
            return Err(ScmError::DuplicateNode(node.id));
        }
        let id = node.id.clone();
        self.nodes.insert(id.clone(), node);
        self.children.entry(id.clone()).or_default();
        self.parents.entry(id).or_default();
        Ok(())
    }

    /// Add a directed causal edge. Returns error if it would create a cycle.
    pub fn add_edge(&mut self, edge: CausalEdge) -> Result<(), ScmError> {
        if !self.nodes.contains_key(&edge.source) {
            return Err(ScmError::NodeNotFound(edge.source));
        }
        if !self.nodes.contains_key(&edge.target) {
            return Err(ScmError::NodeNotFound(edge.target));
        }
        if self
            .children
            .get(&edge.source)
            .is_some_and(|c| c.contains(&edge.target))
        {
            return Err(ScmError::EdgeAlreadyExists {
                source: edge.source,
                target: edge.target,
            });
        }
        // Check for cycles: would adding source→target create a path target→...→source?
        if self.has_path(&edge.target, &edge.source) {
            let mut path = vec![edge.target.clone()];
            self.find_path(&edge.target, &edge.source, &mut path);
            return Err(ScmError::CycleDetected { path });
        }
        self.children
            .entry(edge.source.clone())
            .or_default()
            .insert(edge.target.clone());
        self.parents
            .entry(edge.target.clone())
            .or_default()
            .insert(edge.source.clone());
        self.edges.push(edge);
        Ok(())
    }

    /// Check if there is a directed path from `from` to `to`.
    pub fn has_path(&self, from: &NodeId, to: &NodeId) -> bool {
        let mut visited = BTreeSet::new();
        let mut stack = vec![from.clone()];
        while let Some(current) = stack.pop() {
            if &current == to {
                return true;
            }
            if visited.insert(current.clone())
                && let Some(ch) = self.children.get(&current)
            {
                for c in ch {
                    stack.push(c.clone());
                }
            }
        }
        false
    }

    /// Find a directed path from `from` to `to` and append to `path`.
    fn find_path(&self, from: &NodeId, to: &NodeId, path: &mut Vec<NodeId>) -> bool {
        if from == to {
            return true;
        }
        if let Some(ch) = self.children.get(from) {
            for c in ch {
                if !path.contains(c) {
                    path.push(c.clone());
                    if self.find_path(c, to, path) {
                        return true;
                    }
                    path.pop();
                }
            }
        }
        false
    }

    /// Get a node by ID.
    pub fn node(&self, id: &str) -> Option<&CausalNode> {
        self.nodes.get(id)
    }

    /// Get all nodes.
    pub fn nodes(&self) -> &BTreeMap<NodeId, CausalNode> {
        &self.nodes
    }

    /// Get all edges.
    pub fn edges(&self) -> &[CausalEdge] {
        &self.edges
    }

    /// Get children (direct effects) of a node.
    pub fn children_of(&self, id: &str) -> BTreeSet<NodeId> {
        self.children.get(id).cloned().unwrap_or_default()
    }

    /// Get parents (direct causes) of a node.
    pub fn parents_of(&self, id: &str) -> BTreeSet<NodeId> {
        self.parents.get(id).cloned().unwrap_or_default()
    }

    /// Get all ancestors of a node (transitive parents).
    pub fn ancestors_of(&self, id: &str) -> BTreeSet<NodeId> {
        let mut result = BTreeSet::new();
        let mut stack: Vec<NodeId> = self.parents_of(id).into_iter().collect();
        while let Some(current) = stack.pop() {
            if result.insert(current.clone()) {
                for p in self.parents_of(&current) {
                    stack.push(p);
                }
            }
        }
        result
    }

    /// Get all descendants of a node (transitive children).
    pub fn descendants_of(&self, id: &str) -> BTreeSet<NodeId> {
        let mut result = BTreeSet::new();
        let mut stack: Vec<NodeId> = self.children_of(id).into_iter().collect();
        while let Some(current) = stack.pop() {
            if result.insert(current.clone()) {
                for c in self.children_of(&current) {
                    stack.push(c);
                }
            }
        }
        result
    }

    /// Record an observation.
    pub fn record_observation(&mut self, obs: Observation) {
        self.observations.push(obs);
    }

    /// Get all observations.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// Get the number of observations.
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    // ── Confounder Analysis ───────────────────────────────────────────

    /// Identify and classify all confounders between treatment and outcome nodes.
    pub fn classify_confounders(
        &mut self,
        treatment: &str,
        outcome: &str,
    ) -> Result<Vec<ClassifiedConfounder>, ScmError> {
        if !self.nodes.contains_key(treatment) {
            return Err(ScmError::NodeNotFound(treatment.to_string()));
        }
        if !self.nodes.contains_key(outcome) {
            return Err(ScmError::NodeNotFound(outcome.to_string()));
        }

        let treatment_ancestors = self.ancestors_of(treatment);
        let outcome_ancestors = self.ancestors_of(outcome);

        // A confounder is a common ancestor of both treatment and outcome
        // (or treatment/outcome themselves if they have common parents).
        let common_ancestors: BTreeSet<NodeId> = treatment_ancestors
            .intersection(&outcome_ancestors)
            .cloned()
            .collect();

        let mut classified = Vec::new();
        for node_id in &common_ancestors {
            if let Some(node) = self.nodes.get(node_id) {
                let class = if !node.observable {
                    ConfounderClass::Latent
                } else if node.domain == VariableDomain::Regime
                    || node.domain == VariableDomain::EnvironmentFactor
                {
                    // Time-varying confounders: regime and environment can change
                    ConfounderClass::TimeVarying
                } else {
                    ConfounderClass::Observable
                };
                classified.push(ClassifiedConfounder {
                    node_id: node_id.clone(),
                    class,
                    adjusted: class == ConfounderClass::Observable,
                    bias_bound_millionths: 0,
                    description: format!(
                        "{} ({:?}) confounds {} -> {}",
                        node.label, node.domain, treatment, outcome
                    ),
                });
            }
        }

        // Also check for colliders: nodes that are children of both treatment
        // and outcome (or their descendants). Conditioning on these opens spurious paths.
        let treatment_descendants = self.descendants_of(treatment);
        let outcome_descendants = self.descendants_of(outcome);
        let potential_colliders: BTreeSet<NodeId> = treatment_descendants
            .intersection(&outcome_descendants)
            .cloned()
            .collect();
        for node_id in &potential_colliders {
            // A collider must have at least two parents, one on a path from treatment
            // and one on a path from outcome
            let node_parents = self.parents_of(node_id);
            if node_parents.len() >= 2 {
                let has_treatment_path = node_parents.iter().any(|p| {
                    p == treatment || self.has_path(&treatment.to_string(), &p.to_string())
                });
                let has_outcome_path = node_parents
                    .iter()
                    .any(|p| p == outcome || self.has_path(&outcome.to_string(), &p.to_string()));
                if has_treatment_path
                    && has_outcome_path
                    && let Some(node) = self.nodes.get(node_id)
                {
                    classified.push(ClassifiedConfounder {
                        node_id: node_id.clone(),
                        class: ConfounderClass::Collider,
                        adjusted: false,
                        bias_bound_millionths: 0,
                        description: format!(
                            "{} ({:?}) is a collider between {} and {}; do NOT condition on it",
                            node.label, node.domain, treatment, outcome
                        ),
                    });
                }
            }
        }

        classified.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        self.confounders = classified.clone();
        Ok(classified)
    }

    /// Get the current confounder taxonomy.
    pub fn confounders(&self) -> &[ClassifiedConfounder] {
        &self.confounders
    }

    // ── Backdoor Criterion ────────────────────────────────────────────

    /// Check the backdoor criterion and return a minimal adjustment set.
    ///
    /// The backdoor criterion requires finding a set Z such that:
    /// 1. No node in Z is a descendant of treatment.
    /// 2. Z blocks every non-causal (backdoor) path from treatment to outcome.
    pub fn backdoor_criterion(
        &self,
        treatment: &str,
        outcome: &str,
    ) -> Result<BackdoorResult, ScmError> {
        if !self.nodes.contains_key(treatment) {
            return Err(ScmError::NodeNotFound(treatment.to_string()));
        }
        if !self.nodes.contains_key(outcome) {
            return Err(ScmError::NodeNotFound(outcome.to_string()));
        }

        let treatment_descendants = self.descendants_of(treatment);

        // Find all "backdoor paths": undirected paths from treatment to outcome
        // that have an arrow INTO treatment (i.e. start with parent→treatment).
        let confounding_paths = self.find_backdoor_paths(treatment, outcome);

        if confounding_paths.is_empty() {
            // No confounding: empty adjustment set suffices
            return Ok(BackdoorResult {
                treatment: treatment.to_string(),
                outcome: outcome.to_string(),
                adjustment_set: BTreeSet::new(),
                identified: true,
                confounding_paths: Vec::new(),
            });
        }

        // Candidate adjustment nodes: parents of treatment that are not descendants of treatment
        let treatment_parents = self.parents_of(treatment);
        let mut candidates: BTreeSet<NodeId> = BTreeSet::new();
        for p in &confounding_paths {
            for node in p {
                if node != treatment
                    && node != outcome
                    && !treatment_descendants.contains(node)
                    && self.nodes.get(node).is_some_and(|n| n.observable)
                {
                    candidates.insert(node.clone());
                }
            }
        }

        // Greedy: start with treatment parents (non-descendant, observable),
        // then add until all backdoor paths are blocked.
        let mut adjustment_set: BTreeSet<NodeId> = BTreeSet::new();

        // First add observable direct parents of treatment
        for p in &treatment_parents {
            if !treatment_descendants.contains(p) && self.nodes.get(p).is_some_and(|n| n.observable)
            {
                adjustment_set.insert(p.clone());
            }
        }

        // Check if all backdoor paths are blocked
        let all_blocked = confounding_paths.iter().all(|path| {
            path.iter()
                .any(|node| adjustment_set.contains(node) && node != treatment && node != outcome)
        });

        if !all_blocked {
            // Add remaining candidates
            for c in &candidates {
                if !adjustment_set.contains(c) {
                    adjustment_set.insert(c.clone());
                }
            }
        }

        // Re-check
        let identified = confounding_paths.iter().all(|path| {
            path.iter()
                .any(|node| adjustment_set.contains(node) && node != treatment && node != outcome)
        });

        Ok(BackdoorResult {
            treatment: treatment.to_string(),
            outcome: outcome.to_string(),
            adjustment_set,
            identified,
            confounding_paths,
        })
    }

    /// Find all backdoor paths (paths from treatment to outcome that start
    /// with an edge INTO treatment, i.e., parent → treatment).
    fn find_backdoor_paths(&self, treatment: &str, outcome: &str) -> Vec<Vec<NodeId>> {
        let mut all_paths = Vec::new();
        let treatment_parents = self.parents_of(treatment);

        for parent in &treatment_parents {
            let mut visited = BTreeSet::new();
            visited.insert(treatment.to_string());
            let mut current_path = vec![treatment.to_string(), parent.clone()];
            visited.insert(parent.clone());
            self.find_undirected_paths_to(
                parent,
                outcome,
                &mut visited,
                &mut current_path,
                &mut all_paths,
            );
        }
        all_paths
    }

    /// DFS to find all undirected paths from `current` to `target`.
    fn find_undirected_paths_to(
        &self,
        current: &str,
        target: &str,
        visited: &mut BTreeSet<NodeId>,
        path: &mut Vec<NodeId>,
        results: &mut Vec<Vec<NodeId>>,
    ) {
        if current == target {
            results.push(path.clone());
            return;
        }
        // Neighbors: both children and parents (undirected)
        let mut neighbors = self.children_of(current);
        for p in self.parents_of(current) {
            neighbors.insert(p);
        }
        for neighbor in neighbors {
            if !visited.contains(&neighbor) {
                visited.insert(neighbor.clone());
                path.push(neighbor.clone());
                self.find_undirected_paths_to(&neighbor, target, visited, path, results);
                path.pop();
                visited.remove(&neighbor);
            }
        }
    }

    // ── Intervention Surfaces ─────────────────────────────────────────

    /// Compute intervention surfaces for the DAG.
    pub fn compute_intervention_surfaces(
        &mut self,
        treatment: &str,
        outcome: &str,
    ) -> Result<Vec<InterventionSurface>, ScmError> {
        if !self.nodes.contains_key(treatment) {
            return Err(ScmError::NodeNotFound(treatment.to_string()));
        }
        if !self.nodes.contains_key(outcome) {
            return Err(ScmError::NodeNotFound(outcome.to_string()));
        }

        let backdoor = self.backdoor_criterion(treatment, outcome)?;
        let mut surfaces = Vec::new();

        // Surface 1: Direct intervention on treatment (always valid by do-calculus)
        surfaces.push(InterventionSurface {
            name: format!("direct_intervention_{treatment}"),
            node_ids: BTreeSet::from([treatment.to_string()]),
            sufficient_for_identification: true,
            justification: format!(
                "do({treatment}) removes all incoming edges, eliminating confounding by definition"
            ),
        });

        // Surface 2: Backdoor adjustment set (if identified)
        if backdoor.identified && !backdoor.adjustment_set.is_empty() {
            surfaces.push(InterventionSurface {
                name: format!("backdoor_adjustment_{treatment}_{outcome}"),
                node_ids: backdoor.adjustment_set.clone(),
                sufficient_for_identification: true,
                justification: format!(
                    "Backdoor criterion satisfied: conditioning on {{{}}} blocks all non-causal paths",
                    backdoor
                        .adjustment_set
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        // Surface 3: Instrumental variable surface (if any instrument nodes exist)
        let instrument_nodes: BTreeSet<NodeId> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.role == NodeRole::Instrument)
            .map(|(id, _)| id.clone())
            .collect();
        if !instrument_nodes.is_empty() {
            // Validate: instrument must affect treatment but not outcome except through treatment
            let mut valid_instruments = BTreeSet::new();
            for iv in &instrument_nodes {
                let affects_treatment = self.has_path(&iv.to_string(), &treatment.to_string());
                let has_outcome_path_outside_treatment = self
                    .all_directed_paths(iv, outcome)
                    .iter()
                    .any(|path| !path.iter().any(|node| node == treatment));
                if affects_treatment && !has_outcome_path_outside_treatment {
                    valid_instruments.insert(iv.clone());
                }
            }
            if !valid_instruments.is_empty() {
                surfaces.push(InterventionSurface {
                    name: format!("instrumental_variable_{treatment}"),
                    node_ids: valid_instruments,
                    sufficient_for_identification: true,
                    justification:
                        "IV affects treatment but has no direct path to outcome except through treatment"
                            .to_string(),
                });
            }
        }

        self.intervention_surfaces = surfaces.clone();
        Ok(surfaces)
    }

    /// Get the current intervention surfaces.
    pub fn intervention_surfaces(&self) -> &[InterventionSurface] {
        &self.intervention_surfaces
    }

    // ── Causal Effect Estimation ──────────────────────────────────────

    /// Apply a do-intervention and return the mutated model.
    /// `do(node_id = value)` removes all incoming edges to node_id and
    /// fixes its value.
    pub fn do_intervention(
        &self,
        intervention: &Intervention,
    ) -> Result<StructuralCausalModel, ScmError> {
        if !self.nodes.contains_key(&intervention.node_id) {
            return Err(ScmError::NodeNotFound(intervention.node_id.clone()));
        }

        let mut mutated = self.clone();

        // Fix the node's value
        if let Some(node) = mutated.nodes.get_mut(&intervention.node_id) {
            node.fixed_value_millionths = Some(intervention.value_millionths);
        }

        // Remove all incoming edges to the intervened node
        mutated.edges.retain(|e| e.target != intervention.node_id);
        mutated
            .parents
            .insert(intervention.node_id.clone(), BTreeSet::new());

        // Update children maps to remove references
        for _children_set in mutated.children.values_mut() {
            // We only remove parent→child from the parent side if target was removed
            // Actually we need to remove the source→target entries where target is intervention node
        }
        // Rebuild children from edges for correctness
        let mut new_children: BTreeMap<NodeId, BTreeSet<NodeId>> = BTreeMap::new();
        for id in mutated.nodes.keys() {
            new_children.entry(id.clone()).or_default();
        }
        for edge in &mutated.edges {
            new_children
                .entry(edge.source.clone())
                .or_default()
                .insert(edge.target.clone());
        }
        mutated.children = new_children;

        Ok(mutated)
    }

    /// Estimate the average treatment effect (ATE) using backdoor adjustment.
    ///
    /// Uses the adjustment formula:
    /// E[Y | do(T=1)] - E[Y | do(T=0)] ≈
    ///   Σ_z { E[Y | T=1, Z=z] - E[Y | T=0, Z=z] } × P(Z=z)
    ///
    /// `treatment_value_millionths` is the "treated" value;
    /// `control_value_millionths` is the "control" value.
    pub fn estimate_ate(
        &self,
        treatment: &str,
        outcome: &str,
        treatment_value_millionths: i64,
        control_value_millionths: i64,
        min_observations: u64,
    ) -> Result<CausalEffect, ScmError> {
        if !self.nodes.contains_key(treatment) {
            return Err(ScmError::NodeNotFound(treatment.to_string()));
        }
        if !self.nodes.contains_key(outcome) {
            return Err(ScmError::NodeNotFound(outcome.to_string()));
        }
        if (self.observations.len() as u64) < min_observations {
            return Err(ScmError::InsufficientObservations {
                required: min_observations,
                available: self.observations.len() as u64,
            });
        }

        let backdoor = self.backdoor_criterion(treatment, outcome)?;
        if !backdoor.identified && !backdoor.confounding_paths.is_empty() {
            return Err(ScmError::NotIdentified {
                reason: "backdoor criterion not satisfied and confounding paths exist".to_string(),
            });
        }

        // Simple difference-in-means when no confounding or empty adjustment set
        if backdoor.adjustment_set.is_empty() {
            let (treated_sum, treated_count, control_sum, control_count) = self
                .observations
                .iter()
                .fold((0i64, 0u64, 0i64, 0u64), |acc, obs| {
                    let t_val = obs.values.get(treatment).copied();
                    let y_val = obs.values.get(outcome).copied();
                    if let (Some(t), Some(y)) = (t_val, y_val) {
                        if t == treatment_value_millionths {
                            (acc.0.saturating_add(y), acc.1 + 1, acc.2, acc.3)
                        } else if t == control_value_millionths {
                            (acc.0, acc.1, acc.2.saturating_add(y), acc.3 + 1)
                        } else {
                            acc
                        }
                    } else {
                        acc
                    }
                });

            let ate = if treated_count > 0 && control_count > 0 {
                let treated_mean = treated_sum / treated_count as i64;
                let control_mean = control_sum / control_count as i64;
                treated_mean - control_mean
            } else {
                0
            };

            return Ok(CausalEffect {
                treatment: treatment.to_string(),
                outcome: outcome.to_string(),
                ate_millionths: ate,
                adjustment_set: BTreeSet::new(),
                sample_size: treated_count + control_count,
                identified: true,
            });
        }

        // Stratified estimation with adjustment set
        // Group observations by adjustment set values
        let mut strata: BTreeMap<Vec<i64>, (i64, u64, i64, u64)> = BTreeMap::new();
        let adj_keys: Vec<NodeId> = backdoor.adjustment_set.iter().cloned().collect();

        for obs in &self.observations {
            let t_val = obs.values.get(treatment).copied();
            let y_val = obs.values.get(outcome).copied();
            let z_vals: Option<Vec<i64>> = adj_keys
                .iter()
                .map(|k| obs.values.get(k).copied())
                .collect();

            if let (Some(t), Some(y), Some(z)) = (t_val, y_val, z_vals) {
                let entry = strata.entry(z).or_insert((0, 0, 0, 0));
                if t == treatment_value_millionths {
                    entry.0 = entry.0.saturating_add(y);
                    entry.1 += 1;
                } else if t == control_value_millionths {
                    entry.2 = entry.2.saturating_add(y);
                    entry.3 += 1;
                }
            }
        }

        // Weighted average of stratum-specific treatment effects
        let mut total_effect: i64 = 0;
        let mut total_weight: u64 = 0;
        for (treated_sum, treated_n, control_sum, control_n) in strata.values() {
            if *treated_n > 0 && *control_n > 0 {
                let stratum_effect =
                    treated_sum / *treated_n as i64 - control_sum / *control_n as i64;
                let stratum_weight = treated_n + control_n;
                total_effect = total_effect.saturating_add(stratum_effect * stratum_weight as i64);
                total_weight += stratum_weight;
            }
        }

        let ate = if total_weight > 0 {
            total_effect / total_weight as i64
        } else {
            0
        };

        Ok(CausalEffect {
            treatment: treatment.to_string(),
            outcome: outcome.to_string(),
            ate_millionths: ate,
            adjustment_set: backdoor.adjustment_set,
            sample_size: self.observations.len() as u64,
            identified: backdoor.identified,
        })
    }

    // ── Attribution Decomposition ─────────────────────────────────────

    /// Decompose the total treatment effect into pathway-specific contributions.
    ///
    /// Identifies all directed paths from treatment to outcome and estimates
    /// the contribution of each pathway using sequential mediation analysis.
    pub fn decompose_attribution(
        &self,
        treatment: &str,
        outcome: &str,
        total_delta_millionths: i64,
    ) -> Result<AttributionDecomposition, ScmError> {
        if !self.nodes.contains_key(treatment) {
            return Err(ScmError::NodeNotFound(treatment.to_string()));
        }
        if !self.nodes.contains_key(outcome) {
            return Err(ScmError::NodeNotFound(outcome.to_string()));
        }

        let paths = self.all_directed_paths(treatment, outcome);

        if paths.is_empty() {
            return Ok(AttributionDecomposition {
                treatment: treatment.to_string(),
                outcome: outcome.to_string(),
                total_delta_millionths,
                pathways: Vec::new(),
                residual_millionths: total_delta_millionths,
            });
        }

        // Attribute based on edge strengths along each path.
        // Path strength = product of edge strengths (in millionths arithmetic).
        let mut path_strengths: Vec<(Vec<NodeId>, i64)> = Vec::new();
        let mut total_strength: i64 = 0;

        for path in &paths {
            let mut strength: i64 = 1_000_000; // Start at 1.0 in fixed-point
            for window in path.windows(2) {
                let edge_strength = self
                    .edges
                    .iter()
                    .find(|e| e.source == window[0] && e.target == window[1])
                    .map(|e| {
                        if e.strength_millionths == 0 {
                            1_000_000 // Default to 1.0 if unknown
                        } else {
                            e.strength_millionths
                        }
                    })
                    .unwrap_or(1_000_000);
                // Multiply in fixed-point: (a/10^6) * (b/10^6) = ab/10^12, need ab/10^6
                strength = (strength as i128 * edge_strength as i128 / 1_000_000) as i64;
            }
            total_strength = total_strength.saturating_add(strength.abs());
            path_strengths.push((path.clone(), strength));
        }

        let mut pathways = Vec::new();
        let mut attributed: i64 = 0;

        for (path, strength) in &path_strengths {
            let fraction = if total_strength > 0 {
                (strength.abs() as i128 * 1_000_000 / total_strength as i128) as i64
            } else {
                0
            };
            let effect = (total_delta_millionths as i128 * fraction as i128 / 1_000_000) as i64;
            attributed = attributed.saturating_add(effect);
            pathways.push(PathwayContribution {
                path: path.clone(),
                effect_millionths: effect,
                fraction_millionths: fraction,
            });
        }

        let residual = total_delta_millionths - attributed;

        Ok(AttributionDecomposition {
            treatment: treatment.to_string(),
            outcome: outcome.to_string(),
            total_delta_millionths,
            pathways,
            residual_millionths: residual,
        })
    }

    /// Find all directed paths from `from` to `to`.
    pub fn all_directed_paths(&self, from: &str, to: &str) -> Vec<Vec<NodeId>> {
        let mut results = Vec::new();
        let mut path = vec![from.to_string()];
        let mut visited = BTreeSet::new();
        visited.insert(from.to_string());
        self.dfs_directed_paths(from, to, &mut visited, &mut path, &mut results);
        results
    }

    fn dfs_directed_paths(
        &self,
        current: &str,
        target: &str,
        visited: &mut BTreeSet<NodeId>,
        path: &mut Vec<NodeId>,
        results: &mut Vec<Vec<NodeId>>,
    ) {
        if current == target {
            results.push(path.clone());
            return;
        }
        for child in self.children_of(current) {
            if !visited.contains(&child) {
                visited.insert(child.clone());
                path.push(child.clone());
                self.dfs_directed_paths(&child, target, visited, path, results);
                path.pop();
                visited.remove(&child);
            }
        }
    }

    // ── Topological Sort ──────────────────────────────────────────────

    /// Return nodes in topological order.
    pub fn topological_order(&self) -> Vec<NodeId> {
        let mut in_degree: BTreeMap<NodeId, usize> = BTreeMap::new();
        for id in self.nodes.keys() {
            in_degree.insert(id.clone(), self.parents_of(id).len());
        }
        let mut queue: Vec<NodeId> = in_degree
            .iter()
            .filter(|&(_, &d)| d == 0)
            .map(|(id, _)| id.clone())
            .collect();
        queue.sort(); // Deterministic ordering
        let mut result = Vec::new();
        while let Some(node) = queue.first().cloned() {
            queue.remove(0);
            result.push(node.clone());
            for child in self.children_of(&node) {
                if let Some(deg) = in_degree.get_mut(&child) {
                    *deg -= 1;
                    if *deg == 0 {
                        // Insert in sorted position for determinism
                        let pos = queue.partition_point(|x| x < &child);
                        queue.insert(pos, child);
                    }
                }
            }
        }
        result
    }

    // ── Human-Readable Report ─────────────────────────────────────────

    /// Generate a human-readable summary of the SCM.
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push("=== Structural Causal Model Report ===".to_string());
        lines.push(format!("Nodes: {}", self.nodes.len()));
        lines.push(format!("Edges: {}", self.edges.len()));
        lines.push(format!("Observations: {}", self.observations.len()));

        lines.push(String::new());
        lines.push("-- Nodes --".to_string());
        for (id, node) in &self.nodes {
            lines.push(format!(
                "  {id}: {} [{:?}, {:?}, {}]",
                node.label,
                node.role,
                node.domain,
                if node.observable {
                    "observable"
                } else {
                    "latent"
                }
            ));
        }

        lines.push(String::new());
        lines.push("-- Edges --".to_string());
        for edge in &self.edges {
            lines.push(format!(
                "  {} -> {} [{:?}, strength={}]: {}",
                edge.source, edge.target, edge.sign, edge.strength_millionths, edge.mechanism
            ));
        }

        if !self.confounders.is_empty() {
            lines.push(String::new());
            lines.push("-- Confounders --".to_string());
            for c in &self.confounders {
                lines.push(format!(
                    "  {} [{:?}]: {}",
                    c.node_id, c.class, c.description
                ));
            }
        }

        if !self.intervention_surfaces.is_empty() {
            lines.push(String::new());
            lines.push("-- Intervention Surfaces --".to_string());
            for s in &self.intervention_surfaces {
                lines.push(format!(
                    "  {}: {{{}}} [sufficient={}]",
                    s.name,
                    s.node_ids.iter().cloned().collect::<Vec<_>>().join(", "),
                    s.sufficient_for_identification
                ));
                lines.push(format!("    {}", s.justification));
            }
        }

        lines.join("\n")
    }
}

impl Default for StructuralCausalModel {
    fn default() -> Self {
        Self::new()
    }
}

// ── Default Lane Decision DAG Builder ─────────────────────────────────

/// Build the canonical FrankenEngine lane-decision SCM with standard nodes
/// and edges representing the workload→policy→lane→outcome causal structure.
pub fn build_lane_decision_dag() -> Result<StructuralCausalModel, ScmError> {
    let mut scm = StructuralCausalModel::new();

    // Exogenous nodes
    scm.add_node(CausalNode {
        id: "workload_complexity".into(),
        label: "Workload Complexity".into(),
        role: NodeRole::Exogenous,
        domain: VariableDomain::WorkloadCharacteristic,
        observable: true,
        fixed_value_millionths: None,
    })?;
    scm.add_node(CausalNode {
        id: "component_count".into(),
        label: "Component Count".into(),
        role: NodeRole::Exogenous,
        domain: VariableDomain::WorkloadCharacteristic,
        observable: true,
        fixed_value_millionths: None,
    })?;
    scm.add_node(CausalNode {
        id: "effect_depth".into(),
        label: "Effect Chain Depth".into(),
        role: NodeRole::Exogenous,
        domain: VariableDomain::WorkloadCharacteristic,
        observable: true,
        fixed_value_millionths: None,
    })?;
    scm.add_node(CausalNode {
        id: "environment_load".into(),
        label: "Environment Load".into(),
        role: NodeRole::Exogenous,
        domain: VariableDomain::EnvironmentFactor,
        observable: true,
        fixed_value_millionths: None,
    })?;

    // Confounder: regime (affects both routing decision and outcomes)
    scm.add_node(CausalNode {
        id: "regime".into(),
        label: "Operating Regime".into(),
        role: NodeRole::Confounder,
        domain: VariableDomain::Regime,
        observable: true,
        fixed_value_millionths: None,
    })?;

    // Risk belief (endogenous, derived from workload + environment)
    scm.add_node(CausalNode {
        id: "risk_belief".into(),
        label: "Risk Belief Posterior".into(),
        role: NodeRole::Endogenous,
        domain: VariableDomain::RiskBelief,
        observable: true,
        fixed_value_millionths: None,
    })?;

    // Policy setting (endogenous, influenced by regime)
    scm.add_node(CausalNode {
        id: "loss_matrix_weight".into(),
        label: "Loss Matrix Weight".into(),
        role: NodeRole::Endogenous,
        domain: VariableDomain::PolicySetting,
        observable: true,
        fixed_value_millionths: None,
    })?;

    // Treatment: lane choice
    scm.add_node(CausalNode {
        id: "lane_choice".into(),
        label: "Lane Routing Decision".into(),
        role: NodeRole::Treatment,
        domain: VariableDomain::LaneChoice,
        observable: true,
        fixed_value_millionths: None,
    })?;

    // Mediator: calibration quality
    scm.add_node(CausalNode {
        id: "calibration_quality".into(),
        label: "Calibration Quality".into(),
        role: NodeRole::Mediator,
        domain: VariableDomain::CalibrationMetric,
        observable: true,
        fixed_value_millionths: None,
    })?;

    // Outcomes
    scm.add_node(CausalNode {
        id: "latency_outcome".into(),
        label: "Observed Latency".into(),
        role: NodeRole::Outcome,
        domain: VariableDomain::ObservedOutcome,
        observable: true,
        fixed_value_millionths: None,
    })?;
    scm.add_node(CausalNode {
        id: "correctness_outcome".into(),
        label: "Observed Correctness".into(),
        role: NodeRole::Outcome,
        domain: VariableDomain::ObservedOutcome,
        observable: true,
        fixed_value_millionths: None,
    })?;

    // Edges: workload → risk_belief
    scm.add_edge(CausalEdge {
        source: "workload_complexity".into(),
        target: "risk_belief".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 800_000,
        mechanism: "Higher workload complexity increases risk belief".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "component_count".into(),
        target: "risk_belief".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 600_000,
        mechanism: "More components increase risk of compatibility issues".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "effect_depth".into(),
        target: "risk_belief".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 700_000,
        mechanism: "Deeper effect chains increase risk of incorrect execution".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "environment_load".into(),
        target: "risk_belief".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 500_000,
        mechanism: "Higher environment load increases risk of resource exhaustion".into(),
    })?;

    // Regime → policy + lane_choice (confounder)
    scm.add_edge(CausalEdge {
        source: "regime".into(),
        target: "loss_matrix_weight".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 900_000,
        mechanism: "Operating regime determines loss matrix amplification".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "regime".into(),
        target: "lane_choice".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 700_000,
        mechanism: "Regime influences lane routing (e.g. attack → safe mode)".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "regime".into(),
        target: "latency_outcome".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 400_000,
        mechanism: "Regime directly affects latency (e.g. degraded → higher latency)".into(),
    })?;

    // Risk belief → lane_choice
    scm.add_edge(CausalEdge {
        source: "risk_belief".into(),
        target: "lane_choice".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 900_000,
        mechanism: "Risk posterior drives expected-loss-optimal lane selection".into(),
    })?;

    // Policy → lane_choice
    scm.add_edge(CausalEdge {
        source: "loss_matrix_weight".into(),
        target: "lane_choice".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 800_000,
        mechanism: "Loss matrix weights determine optimal action under posterior".into(),
    })?;

    // Lane choice → mediator → outcomes
    scm.add_edge(CausalEdge {
        source: "lane_choice".into(),
        target: "calibration_quality".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 700_000,
        mechanism: "Lane choice determines calibration methodology applied".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "lane_choice".into(),
        target: "latency_outcome".into(),
        sign: EdgeSign::Negative,
        strength_millionths: 800_000,
        mechanism: "Lane optimized for speed reduces latency (negative = decrease)".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "lane_choice".into(),
        target: "correctness_outcome".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 900_000,
        mechanism: "Lane choice directly determines correctness via execution strategy".into(),
    })?;

    // Mediator → outcome
    scm.add_edge(CausalEdge {
        source: "calibration_quality".into(),
        target: "correctness_outcome".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 600_000,
        mechanism: "Better calibration improves correctness through better decision boundaries"
            .into(),
    })?;

    // Workload → outcomes (direct effect, not just through lane choice)
    scm.add_edge(CausalEdge {
        source: "workload_complexity".into(),
        target: "latency_outcome".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 500_000,
        mechanism: "Complex workloads are inherently slower regardless of lane".into(),
    })?;
    scm.add_edge(CausalEdge {
        source: "environment_load".into(),
        target: "latency_outcome".into(),
        sign: EdgeSign::Positive,
        strength_millionths: 600_000,
        mechanism: "Higher system load increases latency regardless of lane".into(),
    })?;

    Ok(scm)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, role: NodeRole, domain: VariableDomain) -> CausalNode {
        CausalNode {
            id: id.to_string(),
            label: id.to_string(),
            role,
            domain,
            observable: true,
            fixed_value_millionths: None,
        }
    }

    fn edge(src: &str, tgt: &str, sign: EdgeSign, strength: i64) -> CausalEdge {
        CausalEdge {
            source: src.to_string(),
            target: tgt.to_string(),
            sign,
            strength_millionths: strength,
            mechanism: format!("{src} -> {tgt}"),
        }
    }

    fn simple_dag() -> StructuralCausalModel {
        // Confounder → Treatment → Outcome
        //           ↘ Outcome
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("C", NodeRole::Confounder, VariableDomain::Regime))
            .expect("serde deserialization should succeed");
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("C", "T", EdgeSign::Positive, 800_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("C", "Y", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Negative, 900_000))
            .expect("serde deserialization should succeed");
        scm
    }

    #[test]
    fn test_new_scm_is_empty() {
        let scm = StructuralCausalModel::new();
        assert!(scm.nodes().is_empty());
        assert!(scm.edges().is_empty());
        assert_eq!(scm.observation_count(), 0);
    }

    #[test]
    fn test_add_node() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        assert_eq!(scm.nodes().len(), 1);
        assert!(scm.node("A").is_some());
    }

    #[test]
    fn test_add_duplicate_node_fails() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        let err = scm
            .add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .unwrap_err();
        assert_eq!(err, ScmError::DuplicateNode("A".to_string()));
    }

    #[test]
    fn test_add_edge() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        assert_eq!(scm.edges().len(), 1);
        assert!(scm.children_of("A").contains("B"));
        assert!(scm.parents_of("B").contains("A"));
    }

    #[test]
    fn test_add_edge_missing_source() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        let err = scm
            .add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
            .unwrap_err();
        assert_eq!(err, ScmError::NodeNotFound("A".to_string()));
    }

    #[test]
    fn test_add_edge_missing_target() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        let err = scm
            .add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
            .unwrap_err();
        assert_eq!(err, ScmError::NodeNotFound("B".to_string()));
    }

    #[test]
    fn test_add_duplicate_edge_fails() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        let err = scm
            .add_edge(edge("A", "B", EdgeSign::Negative, 300_000))
            .unwrap_err();
        assert!(matches!(err, ScmError::EdgeAlreadyExists { .. }));
    }

    #[test]
    fn test_cycle_detection() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node("B", NodeRole::Endogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node("C", NodeRole::Endogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("A", "B", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("B", "C", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        let err = scm
            .add_edge(edge("C", "A", EdgeSign::Positive, 500_000))
            .unwrap_err();
        assert!(matches!(err, ScmError::CycleDetected { .. }));
    }

    #[test]
    fn test_has_path() {
        let scm = simple_dag();
        assert!(scm.has_path(&"C".to_string(), &"Y".to_string()));
        assert!(scm.has_path(&"T".to_string(), &"Y".to_string()));
        assert!(scm.has_path(&"C".to_string(), &"T".to_string()));
        assert!(!scm.has_path(&"Y".to_string(), &"C".to_string()));
        assert!(!scm.has_path(&"T".to_string(), &"C".to_string()));
    }

    #[test]
    fn test_ancestors_of() {
        let scm = simple_dag();
        let ancestors = scm.ancestors_of("Y");
        assert!(ancestors.contains("C"));
        assert!(ancestors.contains("T"));
        assert_eq!(ancestors.len(), 2);
    }

    #[test]
    fn test_descendants_of() {
        let scm = simple_dag();
        let desc = scm.descendants_of("C");
        assert!(desc.contains("T"));
        assert!(desc.contains("Y"));
        assert_eq!(desc.len(), 2);
    }

    #[test]
    fn test_topological_order() {
        let scm = simple_dag();
        let order = scm.topological_order();
        assert_eq!(order.len(), 3);
        // C must come before T and Y
        let c_pos = order
            .iter()
            .position(|n| n == "C")
            .expect("serde deserialization should succeed");
        let t_pos = order
            .iter()
            .position(|n| n == "T")
            .expect("serde deserialization should succeed");
        let y_pos = order
            .iter()
            .position(|n| n == "Y")
            .expect("serde deserialization should succeed");
        assert!(c_pos < t_pos);
        assert!(c_pos < y_pos);
        assert!(t_pos < y_pos);
    }

    #[test]
    fn test_classify_confounders_basic() {
        let mut scm = simple_dag();
        let confounders = scm
            .classify_confounders("T", "Y")
            .expect("serde deserialization should succeed");
        assert_eq!(confounders.len(), 1);
        assert_eq!(confounders[0].node_id, "C");
        // Regime domain → TimeVarying class
        assert_eq!(confounders[0].class, ConfounderClass::TimeVarying);
    }

    #[test]
    fn test_classify_confounders_no_confounding() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");
        let confounders = scm
            .classify_confounders("T", "Y")
            .expect("serde deserialization should succeed");
        assert!(confounders.is_empty());
    }

    #[test]
    fn test_classify_confounders_missing_node() {
        let mut scm = simple_dag();
        assert!(scm.classify_confounders("X", "Y").is_err());
    }

    #[test]
    fn test_collider_detection() {
        // T → M ← Y (M is a collider)
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node(
            "M",
            NodeRole::Endogenous,
            VariableDomain::CalibrationMetric,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "M", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("Y", "M", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        let confounders = scm
            .classify_confounders("T", "Y")
            .expect("serde deserialization should succeed");
        let colliders: Vec<_> = confounders
            .iter()
            .filter(|c| c.class == ConfounderClass::Collider)
            .collect();
        assert_eq!(colliders.len(), 1);
        assert_eq!(colliders[0].node_id, "M");
    }

    #[test]
    fn test_backdoor_criterion_with_confounder() {
        let scm = simple_dag();
        let result = scm
            .backdoor_criterion("T", "Y")
            .expect("serde deserialization should succeed");
        assert!(result.identified);
        assert!(result.adjustment_set.contains("C"));
    }

    #[test]
    fn test_backdoor_criterion_no_confounding() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");
        let result = scm
            .backdoor_criterion("T", "Y")
            .expect("serde deserialization should succeed");
        assert!(result.identified);
        assert!(result.adjustment_set.is_empty());
        assert!(result.confounding_paths.is_empty());
    }

    #[test]
    fn test_backdoor_criterion_latent_confounder() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(CausalNode {
            id: "U".into(),
            label: "Latent".into(),
            role: NodeRole::Confounder,
            domain: VariableDomain::EnvironmentFactor,
            observable: false,
            fixed_value_millionths: None,
        })
        .expect("serde deserialization should succeed");
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("U", "T", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("U", "Y", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");
        let result = scm
            .backdoor_criterion("T", "Y")
            .expect("serde deserialization should succeed");
        // Latent confounder is not observable, cannot be in adjustment set
        assert!(!result.adjustment_set.contains("U"));
        // If it's the only confounding path and U is not observable, identification fails
        assert!(!result.identified);
    }

    #[test]
    fn test_intervention_surfaces_direct() {
        let mut scm = simple_dag();
        let surfaces = scm
            .compute_intervention_surfaces("T", "Y")
            .expect("serde deserialization should succeed");
        assert!(
            surfaces
                .iter()
                .any(|s| s.name.contains("direct_intervention"))
        );
        assert!(surfaces.iter().all(|s| s.sufficient_for_identification));
    }

    #[test]
    fn test_intervention_surfaces_backdoor() {
        let mut scm = simple_dag();
        let surfaces = scm
            .compute_intervention_surfaces("T", "Y")
            .expect("serde deserialization should succeed");
        let backdoor_surface = surfaces
            .iter()
            .find(|s| s.name.contains("backdoor_adjustment"));
        assert!(backdoor_surface.is_some());
        assert!(
            backdoor_surface
                .expect("serde deserialization should succeed")
                .node_ids
                .contains("C")
        );
    }

    #[test]
    fn test_intervention_surfaces_iv() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node(
            "Z",
            NodeRole::Instrument,
            VariableDomain::PolicySetting,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("Z", "T", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");
        let surfaces = scm
            .compute_intervention_surfaces("T", "Y")
            .expect("serde deserialization should succeed");
        let iv_surface = surfaces
            .iter()
            .find(|s| s.name.contains("instrumental_variable"));
        assert!(iv_surface.is_some());
        assert!(
            iv_surface
                .expect("serde deserialization should succeed")
                .node_ids
                .contains("Z")
        );
    }

    #[test]
    fn test_intervention_surfaces_iv_allows_mediated_treatment_path() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node(
            "Z",
            NodeRole::Instrument,
            VariableDomain::PolicySetting,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node("M", NodeRole::Endogenous, VariableDomain::RiskBelief))
            .expect("serde deserialization should succeed");
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("Z", "M", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("M", "T", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");

        let surfaces = scm
            .compute_intervention_surfaces("T", "Y")
            .expect("serde deserialization should succeed");
        let iv_surface = surfaces
            .iter()
            .find(|s| s.name.contains("instrumental_variable"))
            .expect("mediated IV path should remain valid");
        assert!(iv_surface.node_ids.contains("Z"));
    }

    #[test]
    fn test_intervention_surfaces_iv_rejects_outcome_path_outside_treatment() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node(
            "Z",
            NodeRole::Instrument,
            VariableDomain::PolicySetting,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node("M", NodeRole::Endogenous, VariableDomain::RiskBelief))
            .expect("serde deserialization should succeed");
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("Z", "M", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("M", "T", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("M", "Y", EdgeSign::Positive, 400_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");

        let surfaces = scm
            .compute_intervention_surfaces("T", "Y")
            .expect("serde deserialization should succeed");
        assert!(
            !surfaces
                .iter()
                .any(|s| s.name.contains("instrumental_variable") && s.node_ids.contains("Z"))
        );
    }

    #[test]
    fn test_do_intervention_removes_incoming_edges() {
        let scm = simple_dag();
        let intervention = Intervention {
            node_id: "T".to_string(),
            value_millionths: 1_000_000,
            description: "Fix lane to JS lane".into(),
        };
        let mutated = scm
            .do_intervention(&intervention)
            .expect("serde deserialization should succeed");
        // T should have no parents in the mutated model
        assert!(mutated.parents_of("T").is_empty());
        // T should still have children
        assert!(mutated.children_of("T").contains("Y"));
        // Fixed value should be set
        assert_eq!(
            mutated
                .node("T")
                .expect("serde deserialization should succeed")
                .fixed_value_millionths,
            Some(1_000_000)
        );
    }

    #[test]
    fn test_do_intervention_missing_node() {
        let scm = simple_dag();
        let intervention = Intervention {
            node_id: "X".to_string(),
            value_millionths: 1_000_000,
            description: "bad".into(),
        };
        assert!(scm.do_intervention(&intervention).is_err());
    }

    #[test]
    fn test_record_observation() {
        let mut scm = simple_dag();
        let obs = Observation {
            epoch: 1,
            tick: 0,
            values: BTreeMap::from([
                ("C".to_string(), 500_000),
                ("T".to_string(), 1_000_000),
                ("Y".to_string(), 200_000),
            ]),
        };
        scm.record_observation(obs);
        assert_eq!(scm.observation_count(), 1);
    }

    #[test]
    fn test_estimate_ate_no_confounding() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");

        // Add observations: treated gets Y=800_000, control gets Y=200_000
        for i in 0..10 {
            scm.record_observation(Observation {
                epoch: 1,
                tick: i,
                values: BTreeMap::from([("T".to_string(), 1_000_000), ("Y".to_string(), 800_000)]),
            });
            scm.record_observation(Observation {
                epoch: 1,
                tick: i + 10,
                values: BTreeMap::from([("T".to_string(), 0), ("Y".to_string(), 200_000)]),
            });
        }

        let effect = scm
            .estimate_ate("T", "Y", 1_000_000, 0, 5)
            .expect("serde deserialization should succeed");
        assert_eq!(effect.ate_millionths, 600_000);
        assert!(effect.identified);
        assert_eq!(effect.sample_size, 20);
    }

    #[test]
    fn test_estimate_ate_with_confounding_adjustment() {
        let mut scm = simple_dag();

        // Stratum C=0: T=1→Y=700k, T=0→Y=300k (effect=400k)
        // Stratum C=1: T=1→Y=900k, T=0→Y=500k (effect=400k)
        for i in 0..5 {
            scm.record_observation(Observation {
                epoch: 1,
                tick: i,
                values: BTreeMap::from([
                    ("C".to_string(), 0),
                    ("T".to_string(), 1_000_000),
                    ("Y".to_string(), 700_000),
                ]),
            });
            scm.record_observation(Observation {
                epoch: 1,
                tick: i + 5,
                values: BTreeMap::from([
                    ("C".to_string(), 0),
                    ("T".to_string(), 0),
                    ("Y".to_string(), 300_000),
                ]),
            });
            scm.record_observation(Observation {
                epoch: 1,
                tick: i + 10,
                values: BTreeMap::from([
                    ("C".to_string(), 1_000_000),
                    ("T".to_string(), 1_000_000),
                    ("Y".to_string(), 900_000),
                ]),
            });
            scm.record_observation(Observation {
                epoch: 1,
                tick: i + 15,
                values: BTreeMap::from([
                    ("C".to_string(), 1_000_000),
                    ("T".to_string(), 0),
                    ("Y".to_string(), 500_000),
                ]),
            });
        }

        let effect = scm
            .estimate_ate("T", "Y", 1_000_000, 0, 5)
            .expect("serde deserialization should succeed");
        assert_eq!(effect.ate_millionths, 400_000);
        assert!(effect.identified);
        assert!(effect.adjustment_set.contains("C"));
    }

    #[test]
    fn test_estimate_ate_insufficient_observations() {
        let scm = simple_dag();
        let err = scm.estimate_ate("T", "Y", 1_000_000, 0, 100).unwrap_err();
        assert!(matches!(err, ScmError::InsufficientObservations { .. }));
    }

    #[test]
    fn test_estimate_ate_not_identified() {
        // Latent confounder: cannot be adjusted for
        let mut scm = StructuralCausalModel::new();
        scm.add_node(CausalNode {
            id: "U".into(),
            label: "Latent".into(),
            role: NodeRole::Confounder,
            domain: VariableDomain::EnvironmentFactor,
            observable: false,
            fixed_value_millionths: None,
        })
        .expect("serde deserialization should succeed");
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("U", "T", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("U", "Y", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");

        for i in 0..10 {
            scm.record_observation(Observation {
                epoch: 1,
                tick: i,
                values: BTreeMap::from([("T".to_string(), 1_000_000), ("Y".to_string(), 800_000)]),
            });
        }

        let err = scm.estimate_ate("T", "Y", 1_000_000, 0, 5).unwrap_err();
        assert!(matches!(err, ScmError::NotIdentified { .. }));
    }

    #[test]
    fn test_all_directed_paths() {
        let scm = simple_dag();
        let paths = scm.all_directed_paths("C", "Y");
        assert_eq!(paths.len(), 2); // C→Y direct, C→T→Y indirect
    }

    #[test]
    fn test_all_directed_paths_none() {
        let scm = simple_dag();
        let paths = scm.all_directed_paths("Y", "C");
        assert!(paths.is_empty());
    }

    #[test]
    fn test_decompose_attribution_single_path() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 1_000_000))
            .expect("serde deserialization should succeed");

        let decomp = scm
            .decompose_attribution("T", "Y", 500_000)
            .expect("serde deserialization should succeed");
        assert_eq!(decomp.pathways.len(), 1);
        assert_eq!(decomp.pathways[0].effect_millionths, 500_000);
        assert_eq!(decomp.pathways[0].fraction_millionths, 1_000_000);
        assert_eq!(decomp.residual_millionths, 0);
    }

    #[test]
    fn test_decompose_attribution_two_paths() {
        // T → M → Y and T → Y (direct)
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "M",
            NodeRole::Mediator,
            VariableDomain::CalibrationMetric,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "M", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("M", "Y", EdgeSign::Positive, 600_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 800_000))
            .expect("serde deserialization should succeed");

        let decomp = scm
            .decompose_attribution("T", "Y", 1_000_000)
            .expect("serde deserialization should succeed");
        assert_eq!(decomp.pathways.len(), 2);
        // T→M→Y strength = 0.5 * 0.6 = 0.3
        // T→Y strength = 0.8
        // Total = 1.1
        // T→M→Y fraction ≈ 0.3/1.1 ≈ 272727
        // T→Y fraction ≈ 0.8/1.1 ≈ 727272
        let total_fraction: i64 = decomp.pathways.iter().map(|p| p.fraction_millionths).sum();
        // Fractions should approximately sum to 1.0
        assert!((total_fraction - 1_000_000).abs() < 2);
    }

    #[test]
    fn test_decompose_attribution_no_path() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        // No edge between T and Y
        let decomp = scm
            .decompose_attribution("T", "Y", 500_000)
            .expect("serde deserialization should succeed");
        assert!(decomp.pathways.is_empty());
        assert_eq!(decomp.residual_millionths, 500_000);
    }

    #[test]
    fn test_build_lane_decision_dag() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        assert!(dag.nodes().len() >= 10);
        assert!(dag.edges().len() >= 10);
        // Verify key nodes exist
        assert!(dag.node("lane_choice").is_some());
        assert!(dag.node("latency_outcome").is_some());
        assert!(dag.node("correctness_outcome").is_some());
        assert!(dag.node("regime").is_some());
        assert!(dag.node("risk_belief").is_some());
    }

    #[test]
    fn test_lane_dag_is_acyclic() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        let topo = dag.topological_order();
        assert_eq!(topo.len(), dag.nodes().len());
    }

    #[test]
    fn test_lane_dag_regime_is_confounder() {
        let mut dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        let confounders = dag
            .classify_confounders("lane_choice", "latency_outcome")
            .expect("serde deserialization should succeed");
        let regime_confounder = confounders.iter().find(|c| c.node_id == "regime");
        assert!(regime_confounder.is_some());
    }

    #[test]
    fn test_lane_dag_backdoor_identified() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        let result = dag
            .backdoor_criterion("lane_choice", "latency_outcome")
            .expect("serde deserialization should succeed");
        assert!(result.identified);
    }

    #[test]
    fn test_report_nonempty() {
        let scm = simple_dag();
        let report = scm.report();
        assert!(report.contains("Structural Causal Model Report"));
        assert!(report.contains("Nodes: 3"));
        assert!(report.contains("Edges: 3"));
    }

    #[test]
    fn test_serde_roundtrip_node() {
        let n = node("test", NodeRole::Treatment, VariableDomain::LaneChoice);
        let json = serde_json::to_string(&n).expect("serialize derived Serialize");
        let back: CausalNode = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(n, back);
    }

    #[test]
    fn test_serde_roundtrip_edge() {
        let e = edge("A", "B", EdgeSign::Positive, 500_000);
        let json = serde_json::to_string(&e).expect("serialize derived Serialize");
        let back: CausalEdge = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(e, back);
    }

    #[test]
    fn test_serde_roundtrip_scm() {
        let scm = simple_dag();
        let json = serde_json::to_string(&scm).expect("serialize derived Serialize");
        let back: StructuralCausalModel =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(scm, back);
    }

    #[test]
    fn test_serde_roundtrip_observation() {
        let obs = Observation {
            epoch: 42,
            tick: 7,
            values: BTreeMap::from([("X".to_string(), 123_456)]),
        };
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        let back: Observation = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(obs, back);
    }

    #[test]
    fn test_serde_roundtrip_causal_effect() {
        let effect = CausalEffect {
            treatment: "T".to_string(),
            outcome: "Y".to_string(),
            ate_millionths: 300_000,
            adjustment_set: BTreeSet::from(["C".to_string()]),
            sample_size: 100,
            identified: true,
        };
        let json = serde_json::to_string(&effect).expect("serialize derived Serialize");
        let back: CausalEffect = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(effect, back);
    }

    #[test]
    fn test_serde_roundtrip_intervention() {
        let iv = Intervention {
            node_id: "T".to_string(),
            value_millionths: 1_000_000,
            description: "test".into(),
        };
        let json = serde_json::to_string(&iv).expect("serialize derived Serialize");
        let back: Intervention = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(iv, back);
    }

    #[test]
    fn test_serde_roundtrip_scm_error() {
        let err = ScmError::CycleDetected {
            path: vec!["A".into(), "B".into(), "A".into()],
        };
        let json = serde_json::to_string(&err).expect("serialize derived Serialize");
        let back: ScmError = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(err, back);
    }

    #[test]
    fn test_scm_error_display() {
        assert_eq!(
            ScmError::NodeNotFound("X".into()).to_string(),
            "node not found: X"
        );
        assert_eq!(
            ScmError::CycleDetected {
                path: vec!["A".into(), "B".into()]
            }
            .to_string(),
            "cycle detected: A -> B"
        );
        assert_eq!(
            ScmError::InsufficientObservations {
                required: 10,
                available: 3
            }
            .to_string(),
            "need 10 observations, have 3"
        );
    }

    #[test]
    fn test_node_role_ordering() {
        // Ensure all roles can be compared (BTreeSet/BTreeMap compatibility)
        let roles = vec![
            NodeRole::Exogenous,
            NodeRole::Endogenous,
            NodeRole::Treatment,
            NodeRole::Outcome,
            NodeRole::Confounder,
            NodeRole::Mediator,
            NodeRole::Instrument,
        ];
        let mut sorted = roles.clone();
        sorted.sort();
        assert_eq!(sorted.len(), 7);
    }

    #[test]
    fn test_variable_domain_ordering() {
        let domains = vec![
            VariableDomain::LaneChoice,
            VariableDomain::WorkloadCharacteristic,
            VariableDomain::PolicySetting,
            VariableDomain::ObservedOutcome,
            VariableDomain::RiskBelief,
            VariableDomain::Regime,
            VariableDomain::CalibrationMetric,
            VariableDomain::EnvironmentFactor,
        ];
        let mut sorted = domains.clone();
        sorted.sort();
        assert_eq!(sorted.len(), 8);
    }

    #[test]
    fn test_confounder_class_ordering() {
        let classes = vec![
            ConfounderClass::Observable,
            ConfounderClass::Latent,
            ConfounderClass::TimeVarying,
            ConfounderClass::Collider,
        ];
        let set: BTreeSet<ConfounderClass> = classes.into_iter().collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn test_children_and_parents_empty_node() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("A", NodeRole::Exogenous, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        assert!(scm.children_of("A").is_empty());
        assert!(scm.parents_of("A").is_empty());
    }

    #[test]
    fn test_children_parents_unknown_node() {
        let scm = StructuralCausalModel::new();
        assert!(scm.children_of("nonexistent").is_empty());
        assert!(scm.parents_of("nonexistent").is_empty());
    }

    #[test]
    fn test_ancestors_exogenous_node() {
        let scm = simple_dag();
        let ancestors = scm.ancestors_of("C");
        assert!(ancestors.is_empty());
    }

    #[test]
    fn test_descendants_leaf_node() {
        let scm = simple_dag();
        let desc = scm.descendants_of("Y");
        assert!(desc.is_empty());
    }

    #[test]
    fn test_multiple_confounders() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node(
            "C1",
            NodeRole::Confounder,
            VariableDomain::WorkloadCharacteristic,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node(
            "C2",
            NodeRole::Confounder,
            VariableDomain::WorkloadCharacteristic,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("C1", "T", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("C1", "Y", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("C2", "T", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("C2", "Y", EdgeSign::Positive, 500_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "Y", EdgeSign::Positive, 900_000))
            .expect("serde deserialization should succeed");

        let confounders = scm
            .classify_confounders("T", "Y")
            .expect("serde deserialization should succeed");
        assert_eq!(confounders.len(), 2);

        let result = scm
            .backdoor_criterion("T", "Y")
            .expect("serde deserialization should succeed");
        assert!(result.identified);
        assert!(result.adjustment_set.contains("C1"));
        assert!(result.adjustment_set.contains("C2"));
    }

    #[test]
    fn test_mediator_path() {
        // T → M → Y
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "M",
            NodeRole::Mediator,
            VariableDomain::CalibrationMetric,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "M", EdgeSign::Positive, 700_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("M", "Y", EdgeSign::Positive, 800_000))
            .expect("serde deserialization should succeed");

        let paths = scm.all_directed_paths("T", "Y");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec!["T", "M", "Y"]);
    }

    #[test]
    fn test_diamond_dag() {
        // T → A → Y and T → B → Y
        let mut scm = StructuralCausalModel::new();
        scm.add_node(node("T", NodeRole::Treatment, VariableDomain::LaneChoice))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "A",
            NodeRole::Mediator,
            VariableDomain::CalibrationMetric,
        ))
        .expect("serde deserialization should succeed");
        scm.add_node(node("B", NodeRole::Mediator, VariableDomain::RiskBelief))
            .expect("serde deserialization should succeed");
        scm.add_node(node(
            "Y",
            NodeRole::Outcome,
            VariableDomain::ObservedOutcome,
        ))
        .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "A", EdgeSign::Positive, 600_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("T", "B", EdgeSign::Negative, 400_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("A", "Y", EdgeSign::Positive, 800_000))
            .expect("serde deserialization should succeed");
        scm.add_edge(edge("B", "Y", EdgeSign::Positive, 700_000))
            .expect("serde deserialization should succeed");

        let paths = scm.all_directed_paths("T", "Y");
        assert_eq!(paths.len(), 2);

        let topo = scm.topological_order();
        assert_eq!(topo.len(), 4);
        let t_pos = topo
            .iter()
            .position(|n| n == "T")
            .expect("serde deserialization should succeed");
        let y_pos = topo
            .iter()
            .position(|n| n == "Y")
            .expect("serde deserialization should succeed");
        assert!(t_pos < y_pos);
    }

    #[test]
    fn test_edge_sign_serde() {
        for sign in [EdgeSign::Positive, EdgeSign::Negative, EdgeSign::Ambiguous] {
            let json = serde_json::to_string(&sign).expect("serialize derived Serialize");
            let back: EdgeSign = serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(sign, back);
        }
    }

    #[test]
    fn test_classified_confounder_serde() {
        let cc = ClassifiedConfounder {
            node_id: "regime".into(),
            class: ConfounderClass::TimeVarying,
            adjusted: true,
            bias_bound_millionths: 100_000,
            description: "test confounder".into(),
        };
        let json = serde_json::to_string(&cc).expect("serialize derived Serialize");
        let back: ClassifiedConfounder =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(cc, back);
    }

    #[test]
    fn test_intervention_surface_serde() {
        let surface = InterventionSurface {
            name: "test".into(),
            node_ids: BTreeSet::from(["T".into(), "C".into()]),
            sufficient_for_identification: true,
            justification: "test justification".into(),
        };
        let json = serde_json::to_string(&surface).expect("serialize derived Serialize");
        let back: InterventionSurface =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(surface, back);
    }

    #[test]
    fn test_backdoor_result_serde() {
        let result = BackdoorResult {
            treatment: "T".into(),
            outcome: "Y".into(),
            adjustment_set: BTreeSet::from(["C".into()]),
            identified: true,
            confounding_paths: vec![vec!["T".into(), "C".into(), "Y".into()]],
        };
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let back: BackdoorResult =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(result, back);
    }

    #[test]
    fn test_attribution_decomposition_serde() {
        let decomp = AttributionDecomposition {
            treatment: "T".into(),
            outcome: "Y".into(),
            total_delta_millionths: 500_000,
            pathways: vec![PathwayContribution {
                path: vec!["T".into(), "Y".into()],
                effect_millionths: 500_000,
                fraction_millionths: 1_000_000,
            }],
            residual_millionths: 0,
        };
        let json = serde_json::to_string(&decomp).expect("serialize derived Serialize");
        let back: AttributionDecomposition =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(decomp, back);
    }

    #[test]
    fn test_pathway_contribution_serde() {
        let pc = PathwayContribution {
            path: vec!["T".into(), "M".into(), "Y".into()],
            effect_millionths: 300_000,
            fraction_millionths: 600_000,
        };
        let json = serde_json::to_string(&pc).expect("serialize derived Serialize");
        let back: PathwayContribution =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(pc, back);
    }

    #[test]
    fn test_do_intervention_preserves_other_edges() {
        let scm = simple_dag();
        let intervention = Intervention {
            node_id: "T".to_string(),
            value_millionths: 1_000_000,
            description: "fix T".into(),
        };
        let mutated = scm
            .do_intervention(&intervention)
            .expect("serde deserialization should succeed");
        // C→Y edge should still exist
        assert!(mutated.has_path(&"C".to_string(), &"Y".to_string()));
        // C→T edge should be removed
        assert!(!mutated.children_of("C").contains("T"));
    }

    #[test]
    fn test_lane_dag_intervention_surfaces() {
        let mut dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        let surfaces = dag
            .compute_intervention_surfaces("lane_choice", "latency_outcome")
            .expect("serde deserialization should succeed");
        assert!(!surfaces.is_empty());
        // Direct intervention should always be present
        assert!(
            surfaces
                .iter()
                .any(|s| s.name.contains("direct_intervention"))
        );
    }

    #[test]
    fn test_lane_dag_topological_order_valid() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        let order = dag.topological_order();

        // For every edge, source must come before target
        for edge in dag.edges() {
            let src_pos = order
                .iter()
                .position(|n| n == &edge.source)
                .expect("serde deserialization should succeed");
            let tgt_pos = order
                .iter()
                .position(|n| n == &edge.target)
                .expect("serde deserialization should succeed");
            assert!(
                src_pos < tgt_pos,
                "Edge {} -> {} violates topological order",
                edge.source,
                edge.target
            );
        }
    }

    #[test]
    fn test_lane_dag_all_paths_lane_to_latency() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        let paths = dag.all_directed_paths("lane_choice", "latency_outcome");
        // Should have at least the direct path
        assert!(!paths.is_empty());
        for path in &paths {
            // SAFETY: causal paths are non-empty by construction; first() returns Some
            assert_eq!(
                path.first().expect("serde deserialization should succeed"),
                "lane_choice"
            );
            // SAFETY: causal paths are non-empty by construction; last() returns Some
            assert_eq!(
                path.last().expect("serde deserialization should succeed"),
                "latency_outcome"
            );
        }
    }

    #[test]
    fn test_lane_dag_workload_affects_outcome() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        assert!(dag.has_path(
            &"workload_complexity".to_string(),
            &"latency_outcome".to_string()
        ));
    }

    #[test]
    fn test_lane_dag_environment_affects_outcome() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        assert!(dag.has_path(
            &"environment_load".to_string(),
            &"latency_outcome".to_string()
        ));
    }

    #[test]
    fn test_lane_dag_report_content() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        let report = dag.report();
        assert!(report.contains("lane_choice"));
        assert!(report.contains("latency_outcome"));
        assert!(report.contains("regime"));
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn test_default_scm_is_empty() {
        let scm = StructuralCausalModel::default();
        assert!(scm.nodes().is_empty());
        assert!(scm.edges().is_empty());
        assert_eq!(scm.observation_count(), 0);
        assert!(scm.confounders().is_empty());
        assert!(scm.intervention_surfaces().is_empty());
    }

    #[test]
    fn test_self_loop_detected_as_cycle() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(CausalNode {
            id: "A".to_string(),
            label: "A".to_string(),
            role: NodeRole::Endogenous,
            domain: VariableDomain::ObservedOutcome,
            observable: true,
            fixed_value_millionths: None,
        })
        .expect("serde deserialization should succeed");
        let err = scm
            .add_edge(CausalEdge {
                source: "A".to_string(),
                target: "A".to_string(),
                sign: EdgeSign::Positive,
                strength_millionths: 500_000,
                mechanism: "self".to_string(),
            })
            .unwrap_err();
        assert!(matches!(err, ScmError::CycleDetected { .. }));
    }

    #[test]
    fn test_all_directed_paths_self_returns_trivial() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(CausalNode {
            id: "A".to_string(),
            label: "A".to_string(),
            role: NodeRole::Endogenous,
            domain: VariableDomain::ObservedOutcome,
            observable: true,
            fixed_value_millionths: None,
        })
        .expect("serde deserialization should succeed");
        let paths = scm.all_directed_paths("A", "A");
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec!["A".to_string()]);
    }

    #[test]
    fn test_do_intervention_preserves_original() {
        let mut scm = StructuralCausalModel::new();
        let nodes = ["T", "Y"];
        for id in &nodes {
            scm.add_node(CausalNode {
                id: id.to_string(),
                label: id.to_string(),
                role: if *id == "T" {
                    NodeRole::Treatment
                } else {
                    NodeRole::Outcome
                },
                domain: VariableDomain::LaneChoice,
                observable: true,
                fixed_value_millionths: None,
            })
            .expect("serde deserialization should succeed");
        }
        scm.add_edge(CausalEdge {
            source: "T".to_string(),
            target: "Y".to_string(),
            sign: EdgeSign::Positive,
            strength_millionths: 800_000,
            mechanism: "direct".to_string(),
        })
        .expect("serde deserialization should succeed");
        let intervention = Intervention {
            node_id: "T".to_string(),
            value_millionths: 1_000_000,
            description: "set T=1".to_string(),
        };
        let mutated = scm
            .do_intervention(&intervention)
            .expect("serde deserialization should succeed");
        // Original is unchanged
        assert!(
            scm.node("T")
                .expect("serde deserialization should succeed")
                .fixed_value_millionths
                .is_none()
        );
        assert_eq!(scm.edges().len(), 1);
        // Mutated has fixed value and no incoming edges
        assert_eq!(
            mutated
                .node("T")
                .expect("serde deserialization should succeed")
                .fixed_value_millionths,
            Some(1_000_000)
        );
        assert!(mutated.parents_of("T").is_empty());
    }

    #[test]
    fn test_confounders_persist_after_classify() {
        let mut scm = StructuralCausalModel::new();
        for (id, role) in [
            ("C", NodeRole::Confounder),
            ("T", NodeRole::Treatment),
            ("Y", NodeRole::Outcome),
        ] {
            scm.add_node(CausalNode {
                id: id.to_string(),
                label: id.to_string(),
                role,
                domain: VariableDomain::ObservedOutcome,
                observable: true,
                fixed_value_millionths: None,
            })
            .expect("serde deserialization should succeed");
        }
        scm.add_edge(CausalEdge {
            source: "C".to_string(),
            target: "T".to_string(),
            sign: EdgeSign::Positive,
            strength_millionths: 500_000,
            mechanism: "confound->treat".to_string(),
        })
        .expect("serde deserialization should succeed");
        scm.add_edge(CausalEdge {
            source: "C".to_string(),
            target: "Y".to_string(),
            sign: EdgeSign::Positive,
            strength_millionths: 500_000,
            mechanism: "confound->outcome".to_string(),
        })
        .expect("serde deserialization should succeed");
        scm.add_edge(CausalEdge {
            source: "T".to_string(),
            target: "Y".to_string(),
            sign: EdgeSign::Positive,
            strength_millionths: 800_000,
            mechanism: "direct".to_string(),
        })
        .expect("serde deserialization should succeed");
        assert!(scm.confounders().is_empty());
        let classified = scm
            .classify_confounders("T", "Y")
            .expect("serde deserialization should succeed");
        assert!(!classified.is_empty());
        // After classify, accessor returns persisted confounders
        assert_eq!(scm.confounders().len(), classified.len());
    }

    #[test]
    fn test_cycle_detection_error_contains_path() {
        let mut scm = StructuralCausalModel::new();
        for id in ["A", "B", "C"] {
            scm.add_node(CausalNode {
                id: id.to_string(),
                label: id.to_string(),
                role: NodeRole::Endogenous,
                domain: VariableDomain::ObservedOutcome,
                observable: true,
                fixed_value_millionths: None,
            })
            .expect("serde deserialization should succeed");
        }
        scm.add_edge(CausalEdge {
            source: "A".to_string(),
            target: "B".to_string(),
            sign: EdgeSign::Positive,
            strength_millionths: 1_000_000,
            mechanism: "A->B".to_string(),
        })
        .expect("serde deserialization should succeed");
        scm.add_edge(CausalEdge {
            source: "B".to_string(),
            target: "C".to_string(),
            sign: EdgeSign::Positive,
            strength_millionths: 1_000_000,
            mechanism: "B->C".to_string(),
        })
        .expect("serde deserialization should succeed");
        let err = scm
            .add_edge(CausalEdge {
                source: "C".to_string(),
                target: "A".to_string(),
                sign: EdgeSign::Positive,
                strength_millionths: 1_000_000,
                mechanism: "C->A".to_string(),
            })
            .unwrap_err();
        if let ScmError::CycleDetected { path } = &err {
            assert!(path.len() >= 3, "cycle path should have ≥3 nodes");
        } else {
            panic!("expected CycleDetected, got {err:?}");
        }
    }

    #[test]
    fn test_scm_error_display_cycle_shows_arrow() {
        let err = ScmError::CycleDetected {
            path: vec![
                "A".to_string(),
                "B".to_string(),
                "C".to_string(),
                "A".to_string(),
            ],
        };
        let display = err.to_string();
        assert!(
            display.contains("→") || display.contains("->"),
            "display: {display}"
        );
    }

    #[test]
    fn test_decompose_attribution_negative_strength() {
        let mut scm = StructuralCausalModel::new();
        for (id, role) in [("T", NodeRole::Treatment), ("Y", NodeRole::Outcome)] {
            scm.add_node(CausalNode {
                id: id.to_string(),
                label: id.to_string(),
                role,
                domain: VariableDomain::LaneChoice,
                observable: true,
                fixed_value_millionths: None,
            })
            .expect("serde deserialization should succeed");
        }
        scm.add_edge(CausalEdge {
            source: "T".to_string(),
            target: "Y".to_string(),
            sign: EdgeSign::Negative,
            strength_millionths: -500_000, // negative strength
            mechanism: "inhibitory".to_string(),
        })
        .expect("serde deserialization should succeed");
        let attr = scm
            .decompose_attribution("T", "Y", 1_000_000)
            .expect("serde deserialization should succeed");
        assert_eq!(attr.pathways.len(), 1);
        // Decomposition uses abs(strength) for fractions, so negative edge
        // still gets full attribution weight — effect equals total_delta
        assert_eq!(attr.pathways[0].fraction_millionths, 1_000_000);
        assert_eq!(attr.pathways[0].effect_millionths, 1_000_000);
    }

    #[test]
    fn test_observation_serde_with_multiple_values() {
        let mut values = BTreeMap::new();
        values.insert("T".to_string(), 1_000_000i64);
        values.insert("Y".to_string(), 500_000);
        values.insert("C".to_string(), 750_000);
        let obs = Observation {
            epoch: 5,
            tick: 100,
            values,
        };
        let json = serde_json::to_string(&obs).expect("serialize derived Serialize");
        let back: Observation = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(obs.epoch, back.epoch);
        assert_eq!(obs.tick, back.tick);
        assert_eq!(obs.values.len(), 3);
        assert_eq!(obs.values, back.values);
    }

    #[test]
    fn test_causal_node_fixed_value_serde_roundtrip() {
        let node = CausalNode {
            id: "T".to_string(),
            label: "Treatment".to_string(),
            role: NodeRole::Treatment,
            domain: VariableDomain::LaneChoice,
            observable: true,
            fixed_value_millionths: Some(750_000),
        };
        let json = serde_json::to_string(&node).expect("serialize derived Serialize");
        let back: CausalNode = serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(back.fixed_value_millionths, Some(750_000));
    }

    #[test]
    fn test_has_path_disconnected_nodes() {
        let mut scm = StructuralCausalModel::new();
        for id in ["A", "B"] {
            scm.add_node(CausalNode {
                id: id.to_string(),
                label: id.to_string(),
                role: NodeRole::Endogenous,
                domain: VariableDomain::ObservedOutcome,
                observable: true,
                fixed_value_millionths: None,
            })
            .expect("serde deserialization should succeed");
        }
        // No edges — no path
        assert!(!scm.has_path(&"A".to_string(), &"B".to_string()));
        assert!(!scm.has_path(&"B".to_string(), &"A".to_string()));
    }

    #[test]
    fn test_report_includes_edge_info() {
        let mut scm = StructuralCausalModel::new();
        for (id, role) in [("T", NodeRole::Treatment), ("Y", NodeRole::Outcome)] {
            scm.add_node(CausalNode {
                id: id.to_string(),
                label: id.to_string(),
                role,
                domain: VariableDomain::LaneChoice,
                observable: true,
                fixed_value_millionths: None,
            })
            .expect("serde deserialization should succeed");
        }
        scm.add_edge(CausalEdge {
            source: "T".to_string(),
            target: "Y".to_string(),
            sign: EdgeSign::Positive,
            strength_millionths: 800_000,
            mechanism: "direct-effect".to_string(),
        })
        .expect("serde deserialization should succeed");
        let report = scm.report();
        assert!(report.contains("T"), "report should mention T");
        assert!(report.contains("Y"), "report should mention Y");
    }

    #[test]
    fn test_scm_error_serde_all_variants_distinct() {
        let errors = [
            ScmError::NodeNotFound("x".to_string()),
            ScmError::EdgeAlreadyExists {
                source: "a".to_string(),
                target: "b".to_string(),
            },
            ScmError::CycleDetected {
                path: vec!["a".to_string(), "b".to_string()],
            },
            ScmError::DuplicateNode("d".to_string()),
            ScmError::NoTreatmentNode,
            ScmError::NoOutcomeNode,
            ScmError::InsufficientObservations {
                required: 10,
                available: 5,
            },
            ScmError::NotIdentified {
                reason: "test".to_string(),
            },
        ];
        let jsons: Vec<String> = errors
            .iter()
            .map(|e| serde_json::to_string(e).expect("serialize derived Serialize"))
            .collect();
        // All should be distinct
        let mut deduped = jsons.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(jsons.len(), deduped.len());
    }

    #[test]
    fn test_intervention_surfaces_persist_after_compute() {
        let dag = build_lane_decision_dag().expect("serde deserialization should succeed");
        assert!(dag.intervention_surfaces().is_empty());
        let mut dag = dag;
        let surfaces = dag
            .compute_intervention_surfaces("lane_choice", "latency_outcome")
            .expect("serde deserialization should succeed");
        assert!(!surfaces.is_empty());
        assert_eq!(dag.intervention_surfaces().len(), surfaces.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScmError Display — remaining 5 variants
    // -----------------------------------------------------------------------

    #[test]
    fn test_scm_error_display_edge_already_exists() {
        let err = ScmError::EdgeAlreadyExists {
            source: "A".into(),
            target: "B".into(),
        };
        let s = err.to_string();
        assert!(s.contains("A"));
        assert!(s.contains("B"));
        assert!(s.contains("edge already exists"));
    }

    #[test]
    fn test_scm_error_display_duplicate_node() {
        let err = ScmError::DuplicateNode("dup".into());
        assert_eq!(err.to_string(), "duplicate node: dup");
    }

    #[test]
    fn test_scm_error_display_no_treatment_node() {
        let err = ScmError::NoTreatmentNode;
        assert_eq!(err.to_string(), "no treatment node in DAG");
    }

    #[test]
    fn test_scm_error_display_no_outcome_node() {
        let err = ScmError::NoOutcomeNode;
        assert_eq!(err.to_string(), "no outcome node in DAG");
    }

    #[test]
    fn test_scm_error_display_not_identified() {
        let err = ScmError::NotIdentified {
            reason: "latent confounders".into(),
        };
        let s = err.to_string();
        assert!(s.contains("not identified"));
        assert!(s.contains("latent confounders"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScmError Display — all 8 variants unique
    // -----------------------------------------------------------------------

    #[test]
    fn test_scm_error_display_all_unique() {
        let errors = [
            ScmError::NodeNotFound("x".into()),
            ScmError::EdgeAlreadyExists {
                source: "a".into(),
                target: "b".into(),
            },
            ScmError::CycleDetected {
                path: vec!["a".into(), "b".into()],
            },
            ScmError::DuplicateNode("d".into()),
            ScmError::NoTreatmentNode,
            ScmError::NoOutcomeNode,
            ScmError::InsufficientObservations {
                required: 10,
                available: 5,
            },
            ScmError::NotIdentified {
                reason: "test".into(),
            },
        ];
        let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(displays.len(), errors.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: observations() accessor returns recorded observations
    // -----------------------------------------------------------------------

    #[test]
    fn test_observations_accessor() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(CausalNode {
            id: "X".into(),
            label: "X".into(),
            role: NodeRole::Treatment,
            domain: VariableDomain::LaneChoice,
            observable: true,
            fixed_value_millionths: None,
        })
        .expect("serde deserialization should succeed");
        let mut values = BTreeMap::new();
        values.insert("X".to_string(), 500_000_i64);
        let obs = Observation {
            epoch: 1,
            tick: 10,
            values,
        };
        scm.record_observation(obs.clone());
        let recorded = scm.observations();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].epoch, 1);
        assert_eq!(recorded[0].tick, 10);
        assert_eq!(
            *recorded[0]
                .values
                .get("X")
                .expect("serde deserialization should succeed"),
            500_000
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: empty SCM operations
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_scm_has_path_returns_false() {
        let scm = StructuralCausalModel::new();
        // has_path with nonexistent nodes should not panic
        assert!(!scm.has_path(&"A".to_string(), &"B".to_string()));
    }

    #[test]
    fn test_empty_scm_accessors() {
        let scm = StructuralCausalModel::new();
        assert!(scm.nodes().is_empty());
        assert!(scm.edges().is_empty());
        assert!(scm.observations().is_empty());
        assert_eq!(scm.observation_count(), 0);
        assert!(scm.confounders().is_empty());
        assert!(scm.intervention_surfaces().is_empty());
    }

    #[test]
    fn test_children_of_nonexistent_node() {
        let scm = StructuralCausalModel::new();
        let children = scm.children_of("missing");
        assert!(children.is_empty());
    }

    #[test]
    fn test_parents_of_nonexistent_node() {
        let scm = StructuralCausalModel::new();
        let parents = scm.parents_of("missing");
        assert!(parents.is_empty());
    }

    #[test]
    fn test_ancestors_of_isolated_node() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(CausalNode {
            id: "solo".into(),
            label: "solo".into(),
            role: NodeRole::Exogenous,
            domain: VariableDomain::EnvironmentFactor,
            observable: true,
            fixed_value_millionths: None,
        })
        .expect("serde deserialization should succeed");
        assert!(scm.ancestors_of("solo").is_empty());
    }

    #[test]
    fn test_descendants_of_isolated_node() {
        let mut scm = StructuralCausalModel::new();
        scm.add_node(CausalNode {
            id: "solo".into(),
            label: "solo".into(),
            role: NodeRole::Exogenous,
            domain: VariableDomain::EnvironmentFactor,
            observable: true,
            fixed_value_millionths: None,
        })
        .expect("serde deserialization should succeed");
        assert!(scm.descendants_of("solo").is_empty());
    }

    // -----------------------------------------------------------------------
    // Enrichment: NodeRole ordering covers all 7 variants
    // -----------------------------------------------------------------------

    #[test]
    fn test_node_role_serde_all_variants() {
        let roles = [
            NodeRole::Exogenous,
            NodeRole::Endogenous,
            NodeRole::Treatment,
            NodeRole::Outcome,
            NodeRole::Confounder,
            NodeRole::Mediator,
            NodeRole::Instrument,
        ];
        for role in &roles {
            let json = serde_json::to_string(role).expect("serialize derived Serialize");
            let back: NodeRole = serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*role, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: VariableDomain serde all 8 variants
    // -----------------------------------------------------------------------

    #[test]
    fn test_variable_domain_serde_all_variants() {
        let domains = [
            VariableDomain::LaneChoice,
            VariableDomain::WorkloadCharacteristic,
            VariableDomain::PolicySetting,
            VariableDomain::ObservedOutcome,
            VariableDomain::RiskBelief,
            VariableDomain::Regime,
            VariableDomain::CalibrationMetric,
            VariableDomain::EnvironmentFactor,
        ];
        for domain in &domains {
            let json = serde_json::to_string(domain).expect("serialize derived Serialize");
            let back: VariableDomain =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*domain, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ConfounderClass serde all 4 variants
    // -----------------------------------------------------------------------

    #[test]
    fn test_confounder_class_serde_all_variants() {
        let classes = [
            ConfounderClass::Observable,
            ConfounderClass::Latent,
            ConfounderClass::TimeVarying,
            ConfounderClass::Collider,
        ];
        for class in &classes {
            let json = serde_json::to_string(class).expect("serialize derived Serialize");
            let back: ConfounderClass =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(*class, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: EdgeSign serde all 3 variants
    // -----------------------------------------------------------------------

    #[test]
    fn test_edge_sign_serde_all_variants() {
        for sign in [EdgeSign::Positive, EdgeSign::Negative, EdgeSign::Ambiguous] {
            let json = serde_json::to_string(&sign).expect("serialize derived Serialize");
            let back: EdgeSign = serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(sign, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScmError is std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn test_scm_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ScmError::NodeNotFound("x".into()));
        assert!(err.to_string().contains("x"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: node accessor returns None for nonexistent
    // -----------------------------------------------------------------------

    #[test]
    fn test_node_accessor_none_for_missing() {
        let scm = StructuralCausalModel::new();
        assert!(scm.node("nonexistent").is_none());
    }

    // -----------------------------------------------------------------------
    // Enrichment: Default impl for StructuralCausalModel
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_equals_new() {
        let d = StructuralCausalModel::default();
        let n = StructuralCausalModel::new();
        assert_eq!(d, n);
    }
}
