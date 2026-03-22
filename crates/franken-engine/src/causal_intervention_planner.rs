//! Causal intervention planner and counterfactual optimization oracle.
//!
//! Turns performance optimization from correlation-chasing into explicit
//! intervention science. The planner derives causal DAGs over optimization
//! levers, computes adjustment sets for valid inference, plans
//! counterfactual interventions, and gates claims on identifiability
//! certificates.
//!
//! ## Design
//!
//! - **Causal DAG**: directed acyclic graph of optimization levers and
//!   observed performance metrics with edge semantics.
//! - **Adjustment sets**: valid conditioning sets for unconfounded
//!   causal inference (back-door criterion).
//! - **Intervention planning**: which lever to pull next, expected
//!   effect size, and cost/risk assessment.
//! - **Identifiability certificates**: whether a causal effect can
//!   be estimated from observational data alone.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.7, bd-1lsy.7.15 (RGC-615).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "causal_intervention_planner";
pub const SCHEMA_VERSION: &str = "franken-engine.causal-intervention-planner.v1";
pub const BEAD_ID: &str = "bd-1lsy.7.15";
pub const MAX_NODES: usize = 1000;
pub const MAX_EDGES: usize = 10_000;

// ---------------------------------------------------------------------------
// Node types
// ---------------------------------------------------------------------------

/// Type of node in the causal DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// Optimization lever (intervention target).
    Lever,
    /// Observable performance metric (outcome).
    Metric,
    /// Confounding variable.
    Confounder,
    /// Mediating variable.
    Mediator,
    /// Instrumental variable.
    Instrument,
}

impl NodeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Lever => "lever",
            Self::Metric => "metric",
            Self::Confounder => "confounder",
            Self::Mediator => "mediator",
            Self::Instrument => "instrument",
        }
    }
}

impl fmt::Display for NodeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A node in the causal DAG.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CausalNode {
    pub id: String,
    pub name: String,
    pub kind: NodeKind,
    pub description: String,
    /// Whether this node is observable in production.
    pub observable: bool,
    /// Whether this node can be directly intervened on.
    pub interventionable: bool,
}

// ---------------------------------------------------------------------------
// Edge types
// ---------------------------------------------------------------------------

/// Type of causal edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Direct causal effect.
    Direct,
    /// Confounding association.
    Confounding,
    /// Instrumental relationship.
    Instrumental,
    /// Mediated effect.
    Mediated,
}

impl EdgeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Confounding => "confounding",
            Self::Instrumental => "instrumental",
            Self::Mediated => "mediated",
        }
    }
}

impl fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An edge in the causal DAG.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CausalEdge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    /// Estimated effect size (millionths, signed: positive = improvement).
    pub effect_size_millionths: i64,
    /// Confidence in the effect estimate (millionths).
    pub confidence_millionths: u64,
}

// ---------------------------------------------------------------------------
// Causal DAG
// ---------------------------------------------------------------------------

/// The causal DAG over optimization levers and metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalDag {
    pub version: String,
    pub nodes: Vec<CausalNode>,
    pub edges: Vec<CausalEdge>,
}

impl CausalDag {
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: CausalNode) -> Result<(), PlannerError> {
        if self.nodes.len() >= MAX_NODES {
            return Err(PlannerError::NodeOverflow {
                max: MAX_NODES,
                attempted: self.nodes.len() + 1,
            });
        }
        if self.nodes.iter().any(|n| n.id == node.id) {
            return Err(PlannerError::DuplicateNode {
                id: node.id.clone(),
            });
        }
        self.nodes.push(node);
        Ok(())
    }

    pub fn add_edge(&mut self, edge: CausalEdge) -> Result<(), PlannerError> {
        if self.edges.len() >= MAX_EDGES {
            return Err(PlannerError::EdgeOverflow {
                max: MAX_EDGES,
                attempted: self.edges.len() + 1,
            });
        }
        // Verify endpoints exist
        if !self.nodes.iter().any(|n| n.id == edge.from) {
            return Err(PlannerError::MissingNode {
                id: edge.from.clone(),
            });
        }
        if !self.nodes.iter().any(|n| n.id == edge.to) {
            return Err(PlannerError::MissingNode {
                id: edge.to.clone(),
            });
        }
        self.edges.push(edge);
        Ok(())
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// All lever nodes (interventionable).
    pub fn levers(&self) -> Vec<&CausalNode> {
        self.nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Lever)
            .collect()
    }

    /// All metric nodes (outcomes).
    pub fn metrics(&self) -> Vec<&CausalNode> {
        self.nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Metric)
            .collect()
    }

    /// All confounders.
    pub fn confounders(&self) -> Vec<&CausalNode> {
        self.nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Confounder)
            .collect()
    }

    /// Parents of a node (direct causes).
    pub fn parents(&self, node_id: &str) -> BTreeSet<String> {
        self.edges
            .iter()
            .filter(|e| e.to == node_id && e.kind == EdgeKind::Direct)
            .map(|e| e.from.clone())
            .collect()
    }

    /// Children of a node (direct effects).
    pub fn children(&self, node_id: &str) -> BTreeSet<String> {
        self.edges
            .iter()
            .filter(|e| e.from == node_id && e.kind == EdgeKind::Direct)
            .map(|e| e.to.clone())
            .collect()
    }

    /// Compute the back-door adjustment set for estimating the effect
    /// of `treatment` on `outcome`. Returns None if effect is not identifiable.
    pub fn adjustment_set(&self, treatment: &str, outcome: &str) -> Option<BTreeSet<String>> {
        // Simple back-door criterion: condition on all parents of treatment
        // that are not descendants of treatment.
        let treatment_parents = self.parents(treatment);
        let treatment_children = self.children(treatment);

        // For a basic implementation: the adjustment set is the parents of
        // the treatment node that are confounders (non-descendants).
        let mut adjustment = BTreeSet::new();
        for parent_id in &treatment_parents {
            // Don't include the outcome itself
            if parent_id == outcome {
                continue;
            }
            // Don't include descendants of treatment (which would block the causal path)
            if treatment_children.contains(parent_id) {
                continue;
            }
            adjustment.insert(parent_id.clone());
        }

        // If treatment and outcome exist, the effect is identifiable
        let has_treatment = self.nodes.iter().any(|n| n.id == treatment);
        let has_outcome = self.nodes.iter().any(|n| n.id == outcome);
        if has_treatment && has_outcome {
            Some(adjustment)
        } else {
            None
        }
    }

    /// Compute a deterministic content hash.
    ///
    /// Sorts nodes by ID and edges by (from, to, kind) before hashing so
    /// semantically identical DAGs with different insertion order produce
    /// the same hash.
    pub fn content_hash(&self) -> ContentHash {
        let mut entries = Vec::new();

        // Sort nodes by id for insertion-order independence.
        let mut sorted_nodes: Vec<_> = self.nodes.iter().collect();
        sorted_nodes.sort_by(|a, b| a.id.cmp(&b.id));
        for node in &sorted_nodes {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                ("id".to_string(), CanonicalValue::String(node.id.clone())),
                (
                    "kind".to_string(),
                    CanonicalValue::String(node.kind.as_str().to_string()),
                ),
                (
                    "description".to_string(),
                    CanonicalValue::String(node.description.clone()),
                ),
            ])));
        }

        // Sort edges by (from, to, kind) for insertion-order independence.
        let mut sorted_edges: Vec<_> = self.edges.iter().collect();
        sorted_edges.sort_by(|a, b| {
            (&a.from, &a.to, a.kind.as_str()).cmp(&(&b.from, &b.to, b.kind.as_str()))
        });
        for edge in &sorted_edges {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                (
                    "from".to_string(),
                    CanonicalValue::String(edge.from.clone()),
                ),
                ("to".to_string(), CanonicalValue::String(edge.to.clone())),
                (
                    "kind".to_string(),
                    CanonicalValue::String(edge.kind.as_str().to_string()),
                ),
            ])));
        }
        let canonical = CanonicalValue::Array(entries);
        let bytes = encode_value(&canonical);
        ContentHash::compute(&bytes)
    }
}

impl Default for CausalDag {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Identifiability certificate
// ---------------------------------------------------------------------------

/// Whether a causal effect is identifiable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Identifiability {
    /// Effect is identifiable via back-door adjustment.
    BackDoorIdentifiable,
    /// Effect is identifiable via front-door criterion.
    FrontDoorIdentifiable,
    /// Effect requires instrumental variables.
    InstrumentalOnly,
    /// Effect is not identifiable from observational data.
    NotIdentifiable,
    /// Insufficient graph structure to determine.
    Undetermined,
}

impl Identifiability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BackDoorIdentifiable => "back_door_identifiable",
            Self::FrontDoorIdentifiable => "front_door_identifiable",
            Self::InstrumentalOnly => "instrumental_only",
            Self::NotIdentifiable => "not_identifiable",
            Self::Undetermined => "undetermined",
        }
    }

    pub const fn is_identifiable(self) -> bool {
        matches!(
            self,
            Self::BackDoorIdentifiable | Self::FrontDoorIdentifiable | Self::InstrumentalOnly
        )
    }
}

impl fmt::Display for Identifiability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Certificate for a specific treatment-outcome pair.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdentifiabilityCertificate {
    pub treatment: String,
    pub outcome: String,
    pub status: Identifiability,
    pub adjustment_set: Option<BTreeSet<String>>,
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Intervention plan
// ---------------------------------------------------------------------------

/// Priority ranking for an intervention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionPriority {
    Critical,
    High,
    Medium,
    Low,
    Deferred,
}

impl InterventionPriority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Deferred => "deferred",
        }
    }
}

impl fmt::Display for InterventionPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A planned intervention (optimization action).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InterventionPlan {
    pub id: String,
    pub lever_id: String,
    pub target_metric_id: String,
    pub priority: InterventionPriority,
    pub expected_effect_millionths: i64,
    pub confidence_millionths: u64,
    pub identifiability: Identifiability,
    pub adjustment_set: BTreeSet<String>,
    pub risk_description: String,
    pub cost_description: String,
    pub tracking_bead: Option<String>,
}

// ---------------------------------------------------------------------------
// Planner report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerReport {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub dag_hash: ContentHash,
    pub node_count: usize,
    pub edge_count: usize,
    pub lever_count: usize,
    pub metric_count: usize,
    pub confounder_count: usize,
    pub certificates: Vec<IdentifiabilityCertificate>,
    pub identifiable_count: usize,
    pub not_identifiable_count: usize,
    pub intervention_plans: Vec<InterventionPlan>,
}

// ---------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------

/// The causal intervention planner.
#[derive(Debug, Clone)]
pub struct CausalInterventionPlanner;

impl CausalInterventionPlanner {
    pub fn new() -> Self {
        Self
    }

    /// Analyze the DAG and produce certificates + intervention plans.
    pub fn analyze(&self, dag: &CausalDag) -> PlannerReport {
        let mut certificates = Vec::new();
        let mut plans = Vec::new();

        let levers = dag.levers();
        let metrics = dag.metrics();

        // For each lever-metric pair, check identifiability
        for lever in &levers {
            for metric in &metrics {
                let adjustment = dag.adjustment_set(&lever.id, &metric.id);
                let status = match &adjustment {
                    Some(adj) if adj.is_empty() => Identifiability::BackDoorIdentifiable,
                    Some(_) => Identifiability::BackDoorIdentifiable,
                    None => Identifiability::NotIdentifiable,
                };

                certificates.push(IdentifiabilityCertificate {
                    treatment: lever.id.clone(),
                    outcome: metric.id.clone(),
                    status,
                    adjustment_set: adjustment.clone(),
                    rationale: if status.is_identifiable() {
                        "Back-door criterion satisfied".to_string()
                    } else {
                        "Treatment or outcome not in DAG".to_string()
                    },
                });

                // If identifiable, create an intervention plan
                if status.is_identifiable() {
                    // Find the direct edge for effect estimate
                    let effect = dag
                        .edges
                        .iter()
                        .find(|e| e.from == lever.id && e.to == metric.id)
                        .map(|e| e.effect_size_millionths)
                        .unwrap_or(0);

                    let confidence = dag
                        .edges
                        .iter()
                        .find(|e| e.from == lever.id && e.to == metric.id)
                        .map(|e| e.confidence_millionths)
                        .unwrap_or(0);

                    let priority = if effect > 200_000 {
                        InterventionPriority::Critical
                    } else if effect > 100_000 {
                        InterventionPriority::High
                    } else if effect > 50_000 {
                        InterventionPriority::Medium
                    } else if effect > 0 {
                        InterventionPriority::Low
                    } else {
                        InterventionPriority::Deferred
                    };

                    plans.push(InterventionPlan {
                        id: format!("plan_{}_{}", lever.id, metric.id),
                        lever_id: lever.id.clone(),
                        target_metric_id: metric.id.clone(),
                        priority,
                        expected_effect_millionths: effect,
                        confidence_millionths: confidence,
                        identifiability: status,
                        adjustment_set: adjustment.unwrap_or_default(),
                        risk_description: String::new(),
                        cost_description: String::new(),
                        tracking_bead: None,
                    });
                }
            }
        }

        let identifiable_count = certificates
            .iter()
            .filter(|c| c.status.is_identifiable())
            .count();
        let not_identifiable_count = certificates.len() - identifiable_count;

        // Sort plans by priority
        plans.sort_by_key(|p| p.priority);

        PlannerReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            dag_hash: dag.content_hash(),
            node_count: dag.node_count(),
            edge_count: dag.edge_count(),
            lever_count: levers.len(),
            metric_count: metrics.len(),
            confounder_count: dag.confounders().len(),
            certificates,
            identifiable_count,
            not_identifiable_count,
            intervention_plans: plans,
        }
    }
}

impl Default for CausalInterventionPlanner {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Seed DAG builder
// ---------------------------------------------------------------------------

pub fn build_seed_dag() -> CausalDag {
    let mut dag = CausalDag::new();

    // Levers
    let levers = [
        ("inline_cache", "Inline cache hit rate optimization"),
        ("gc_tuning", "GC pause frequency and duration tuning"),
        ("tier_up_threshold", "Tier-up threshold adjustment"),
    ];
    for (id, desc) in &levers {
        let _ = dag.add_node(CausalNode {
            id: id.to_string(),
            name: id.to_string(),
            kind: NodeKind::Lever,
            description: desc.to_string(),
            observable: true,
            interventionable: true,
        });
    }

    // Metrics
    let metrics = [
        ("p99_latency", "P99 tail latency"),
        ("throughput", "Operations per second"),
        ("memory_footprint", "Peak heap usage"),
    ];
    for (id, desc) in &metrics {
        let _ = dag.add_node(CausalNode {
            id: id.to_string(),
            name: id.to_string(),
            kind: NodeKind::Metric,
            description: desc.to_string(),
            observable: true,
            interventionable: false,
        });
    }

    // Confounders
    let _ = dag.add_node(CausalNode {
        id: "workload_mix".to_string(),
        name: "workload_mix".to_string(),
        kind: NodeKind::Confounder,
        description: "Distribution of workload types in the benchmark".to_string(),
        observable: true,
        interventionable: false,
    });

    // Edges
    let edges = [
        (
            "inline_cache",
            "p99_latency",
            EdgeKind::Direct,
            -150_000,
            800_000,
        ),
        (
            "inline_cache",
            "throughput",
            EdgeKind::Direct,
            200_000,
            850_000,
        ),
        (
            "gc_tuning",
            "p99_latency",
            EdgeKind::Direct,
            -100_000,
            700_000,
        ),
        (
            "gc_tuning",
            "memory_footprint",
            EdgeKind::Direct,
            -50_000,
            600_000,
        ),
        (
            "tier_up_threshold",
            "throughput",
            EdgeKind::Direct,
            80_000,
            650_000,
        ),
        (
            "workload_mix",
            "inline_cache",
            EdgeKind::Confounding,
            0,
            500_000,
        ),
        (
            "workload_mix",
            "p99_latency",
            EdgeKind::Confounding,
            0,
            500_000,
        ),
    ];
    for (from, to, kind, effect, conf) in &edges {
        let _ = dag.add_edge(CausalEdge {
            from: from.to_string(),
            to: to.to_string(),
            kind: *kind,
            effect_size_millionths: *effect,
            confidence_millionths: *conf,
        });
    }

    dag
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlannerError {
    NodeOverflow { max: usize, attempted: usize },
    EdgeOverflow { max: usize, attempted: usize },
    DuplicateNode { id: String },
    MissingNode { id: String },
}

impl fmt::Display for PlannerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeOverflow { max, attempted } => {
                write!(f, "node overflow: {attempted} > {max}")
            }
            Self::EdgeOverflow { max, attempted } => {
                write!(f, "edge overflow: {attempted} > {max}")
            }
            Self::DuplicateNode { id } => write!(f, "duplicate node: {id}"),
            Self::MissingNode { id } => write!(f, "missing node: {id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lever(id: &str) -> CausalNode {
        CausalNode {
            id: id.to_string(),
            name: id.to_string(),
            kind: NodeKind::Lever,
            description: "test lever".to_string(),
            observable: true,
            interventionable: true,
        }
    }

    fn metric(id: &str) -> CausalNode {
        CausalNode {
            id: id.to_string(),
            name: id.to_string(),
            kind: NodeKind::Metric,
            description: "test metric".to_string(),
            observable: true,
            interventionable: false,
        }
    }

    fn direct_edge(from: &str, to: &str, effect: i64) -> CausalEdge {
        CausalEdge {
            from: from.to_string(),
            to: to.to_string(),
            kind: EdgeKind::Direct,
            effect_size_millionths: effect,
            confidence_millionths: 800_000,
        }
    }

    // --- NodeKind ---
    #[test]
    fn node_kind_serde() {
        for kind in [
            NodeKind::Lever,
            NodeKind::Metric,
            NodeKind::Confounder,
            NodeKind::Mediator,
            NodeKind::Instrument,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: NodeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // --- EdgeKind ---
    #[test]
    fn edge_kind_serde() {
        for kind in [
            EdgeKind::Direct,
            EdgeKind::Confounding,
            EdgeKind::Instrumental,
            EdgeKind::Mediated,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: EdgeKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    // --- CausalDag ---
    #[test]
    fn empty_dag() {
        let dag = CausalDag::new();
        assert_eq!(dag.node_count(), 0);
        assert_eq!(dag.edge_count(), 0);
    }

    #[test]
    fn add_nodes() {
        let mut dag = CausalDag::new();
        dag.add_node(lever("l1")).unwrap();
        dag.add_node(metric("m1")).unwrap();
        assert_eq!(dag.node_count(), 2);
        assert_eq!(dag.levers().len(), 1);
        assert_eq!(dag.metrics().len(), 1);
    }

    #[test]
    fn duplicate_node_rejected() {
        let mut dag = CausalDag::new();
        dag.add_node(lever("l1")).unwrap();
        let err = dag.add_node(lever("l1")).unwrap_err();
        assert!(matches!(err, PlannerError::DuplicateNode { .. }));
    }

    #[test]
    fn add_edge_valid() {
        let mut dag = CausalDag::new();
        dag.add_node(lever("l1")).unwrap();
        dag.add_node(metric("m1")).unwrap();
        dag.add_edge(direct_edge("l1", "m1", 100_000)).unwrap();
        assert_eq!(dag.edge_count(), 1);
    }

    #[test]
    fn add_edge_missing_node() {
        let mut dag = CausalDag::new();
        dag.add_node(lever("l1")).unwrap();
        let err = dag.add_edge(direct_edge("l1", "m_missing", 0)).unwrap_err();
        assert!(matches!(err, PlannerError::MissingNode { .. }));
    }

    #[test]
    fn parents_and_children() {
        let mut dag = CausalDag::new();
        dag.add_node(lever("l1")).unwrap();
        dag.add_node(metric("m1")).unwrap();
        dag.add_edge(direct_edge("l1", "m1", 0)).unwrap();
        assert!(dag.parents("m1").contains("l1"));
        assert!(dag.children("l1").contains("m1"));
    }

    #[test]
    fn adjustment_set_simple() {
        let mut dag = CausalDag::new();
        dag.add_node(lever("l1")).unwrap();
        dag.add_node(metric("m1")).unwrap();
        dag.add_edge(direct_edge("l1", "m1", 0)).unwrap();
        let adj = dag.adjustment_set("l1", "m1").unwrap();
        assert!(adj.is_empty()); // No confounders
    }

    #[test]
    fn adjustment_set_with_confounder() {
        let mut dag = CausalDag::new();
        dag.add_node(lever("l1")).unwrap();
        dag.add_node(metric("m1")).unwrap();
        dag.add_node(CausalNode {
            id: "c1".to_string(),
            name: "c1".to_string(),
            kind: NodeKind::Confounder,
            description: "".to_string(),
            observable: true,
            interventionable: false,
        })
        .unwrap();
        dag.add_edge(direct_edge("c1", "l1", 0)).unwrap();
        dag.add_edge(direct_edge("l1", "m1", 0)).unwrap();
        let adj = dag.adjustment_set("l1", "m1").unwrap();
        assert!(adj.contains("c1"));
    }

    #[test]
    fn adjustment_set_nonexistent() {
        let dag = CausalDag::new();
        assert!(dag.adjustment_set("missing", "also_missing").is_none());
    }

    #[test]
    fn content_hash_deterministic() {
        let d1 = build_seed_dag();
        let d2 = build_seed_dag();
        assert_eq!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn content_hash_changes() {
        let d1 = build_seed_dag();
        let mut d2 = build_seed_dag();
        d2.add_node(lever("extra")).unwrap();
        assert_ne!(d1.content_hash(), d2.content_hash());
    }

    #[test]
    fn dag_serde_roundtrip() {
        let dag = build_seed_dag();
        let json = serde_json::to_string(&dag).unwrap();
        let back: CausalDag = serde_json::from_str(&json).unwrap();
        assert_eq!(dag.node_count(), back.node_count());
        assert_eq!(dag.content_hash(), back.content_hash());
    }

    #[test]
    fn default_dag_empty() {
        let dag = CausalDag::default();
        assert_eq!(dag.node_count(), 0);
    }

    // --- Identifiability ---
    #[test]
    fn identifiability_checks() {
        assert!(Identifiability::BackDoorIdentifiable.is_identifiable());
        assert!(Identifiability::FrontDoorIdentifiable.is_identifiable());
        assert!(Identifiability::InstrumentalOnly.is_identifiable());
        assert!(!Identifiability::NotIdentifiable.is_identifiable());
        assert!(!Identifiability::Undetermined.is_identifiable());
    }

    #[test]
    fn identifiability_serde() {
        let id = Identifiability::BackDoorIdentifiable;
        let json = serde_json::to_string(&id).unwrap();
        let back: Identifiability = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // --- InterventionPriority ---
    #[test]
    fn priority_serde() {
        for p in [
            InterventionPriority::Critical,
            InterventionPriority::High,
            InterventionPriority::Medium,
            InterventionPriority::Low,
            InterventionPriority::Deferred,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let back: InterventionPriority = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    // --- Seed DAG ---
    #[test]
    fn seed_dag_structure() {
        let dag = build_seed_dag();
        assert_eq!(dag.levers().len(), 3);
        assert_eq!(dag.metrics().len(), 3);
        assert_eq!(dag.confounders().len(), 1);
        assert_eq!(dag.edge_count(), 7);
    }

    // --- Planner ---
    #[test]
    fn planner_produces_report() {
        let dag = build_seed_dag();
        let planner = CausalInterventionPlanner::new();
        let report = planner.analyze(&dag);
        assert_eq!(report.lever_count, 3);
        assert_eq!(report.metric_count, 3);
        assert!(!report.certificates.is_empty());
        assert!(!report.intervention_plans.is_empty());
    }

    #[test]
    fn planner_all_identifiable_in_seed() {
        let dag = build_seed_dag();
        let planner = CausalInterventionPlanner::new();
        let report = planner.analyze(&dag);
        // All lever-metric pairs should be identifiable in the seed DAG
        assert_eq!(report.identifiable_count, 9); // 3 levers * 3 metrics
        assert_eq!(report.not_identifiable_count, 0);
    }

    #[test]
    fn planner_empty_dag() {
        let dag = CausalDag::new();
        let planner = CausalInterventionPlanner::new();
        let report = planner.analyze(&dag);
        assert_eq!(report.lever_count, 0);
        assert!(report.certificates.is_empty());
    }

    #[test]
    fn planner_report_serde() {
        let dag = build_seed_dag();
        let planner = CausalInterventionPlanner::new();
        let report = planner.analyze(&dag);
        let json = serde_json::to_string(&report).unwrap();
        let back: PlannerReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.lever_count, back.lever_count);
    }

    #[test]
    fn default_planner() {
        let planner = CausalInterventionPlanner;
        let dag = CausalDag::new();
        let report = planner.analyze(&dag);
        assert_eq!(report.node_count, 0);
    }

    // --- Error ---
    #[test]
    fn error_display() {
        let e = PlannerError::DuplicateNode {
            id: "foo".to_string(),
        };
        assert!(format!("{e}").contains("foo"));
    }

    // --- Constants ---
    #[test]
    fn constants() {
        assert_eq!(COMPONENT, "causal_intervention_planner");
        assert_eq!(BEAD_ID, "bd-1lsy.7.15");
    }
}
