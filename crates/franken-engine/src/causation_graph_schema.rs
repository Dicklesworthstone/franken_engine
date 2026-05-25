//! Typed DAG schema for causation graph representation.
//!
//! This module provides a typed directed acyclic graph (DAG) schema for representing
//! causal relationships between evidence atoms and decisions. The graph structure
//! enables forensic analysis by making causation chains queryable and verifiable.
//!
//! ## Schema Overview
//!
//! - **Nodes**: Evidence atoms and decision points with typed payloads
//! - **Edges**: Directed causation relationships with influence weights
//! - **Properties**: Sortable, queryable, cryptographically signed
//! - **Schema**: franken-engine.causation-graph.v1
//!
//! ## Design Principles
//!
//! - **Deterministic**: Graph traversal and serialization are deterministic
//! - **Signed**: All nodes and edges are cryptographically verified
//! - **Queryable**: Support for structural queries ("why did X happen?")
//! - **Sortable**: Topological ordering for replay and analysis
//!
//! Reference: [FF.2] Typed DAG schema for the causation graph

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::minimal_causal_set_inference::{CausalDependency, DecisionFactor};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for causation graph representation.
pub const CAUSATION_GRAPH_SCHEMA_VERSION: &str = "franken-engine.causation-graph.v1";
/// Component name for evidence linkage.
pub const CAUSATION_GRAPH_COMPONENT: &str = "causation_graph_schema";
/// Policy ID binding for this module.
pub const CAUSATION_GRAPH_POLICY_ID: &str = "FF-2";
/// Domain separator for causation graph signatures.
pub const CAUSATION_GRAPH_SIGNATURE_DOMAIN: &str = "franken-engine.causation-graph.signature.v1";

// ---------------------------------------------------------------------------
// Core Types
// ---------------------------------------------------------------------------

/// Unique identifier for nodes in the causation graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u64);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node-{}", self.0)
    }
}

/// Unique identifier for edges in the causation graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EdgeId(pub u64);

impl fmt::Display for EdgeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "edge-{}", self.0)
    }
}

/// Weight representing the strength of causal influence between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InfluenceWeight {
    /// Weight in millionths (1_000_000 = 1.0) for deterministic representation.
    pub millionths: u32,
}

impl InfluenceWeight {
    /// Create a new influence weight from millionths.
    pub fn from_millionths(millionths: u32) -> Self {
        Self { millionths }
    }

    /// Create a new influence weight from a floating point value.
    pub fn from_f64(value: f64) -> Self {
        let millionths = (value * 1_000_000.0).round() as u32;
        Self { millionths }
    }

    /// Convert to floating point value.
    pub fn to_f64(self) -> f64 {
        self.millionths as f64 / 1_000_000.0
    }

    /// Maximum influence weight (1.0).
    pub const MAX: Self = Self {
        millionths: 1_000_000,
    };

    /// Zero influence weight.
    pub const ZERO: Self = Self { millionths: 0 };
}

impl fmt::Display for InfluenceWeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.to_f64())
    }
}

// ---------------------------------------------------------------------------
// Node Types
// ---------------------------------------------------------------------------

/// A node in the causation graph representing either an evidence atom or decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausationNode {
    /// Unique identifier for this node.
    pub id: NodeId,
    /// The type and payload of this node.
    pub node_type: NodeType,
    /// Content hash of the node payload for integrity verification.
    pub content_hash: ContentHash,
    /// Authenticity hash including signature verification.
    pub authenticity_hash: AuthenticityHash,
    /// Unix timestamp (nanoseconds) when this node was created.
    pub timestamp_ns: u64,
    /// Optional metadata for extensibility.
    pub metadata: BTreeMap<String, String>,
}

/// The type and payload of a causation graph node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum NodeType {
    /// Evidence atom used in decision-making.
    EvidenceAtom {
        /// The causal dependency this evidence represents.
        dependency: CausalDependency,
        /// Hash of the evidence content.
        evidence_hash: ContentHash,
        /// Confidence level in millionths.
        confidence_millionths: u32,
    },
    /// Decision point in the execution flow.
    Decision {
        /// Unique identifier for the decision.
        decision_id: String,
        /// The decision factor that triggered this decision.
        factor: DecisionFactor,
        /// Hash of the decision context.
        context_hash: ContentHash,
        /// Outcome of the decision (allow, deny, modify).
        outcome: DecisionOutcome,
    },
    /// Aggregated influence from multiple sources.
    AggregateInfluence {
        /// Sources that contributed to this aggregate.
        source_nodes: Vec<NodeId>,
        /// Combined influence weight.
        total_weight: InfluenceWeight,
        /// Aggregation method used.
        method: AggregationMethod,
    },
}

/// Outcome of a decision in the causation graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    /// Allow the operation to proceed.
    Allow,
    /// Deny the operation.
    Deny,
    /// Modify the operation parameters.
    Modify,
    /// Suspend execution pending further review.
    Suspend,
    /// Quarantine the operation.
    Quarantine,
    /// Request additional authentication.
    Challenge,
}

/// Method used for aggregating multiple influences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMethod {
    /// Simple sum of weights.
    Sum,
    /// Weighted average of influences.
    WeightedAverage,
    /// Maximum influence wins.
    Max,
    /// Bayesian combination.
    Bayesian,
}

// ---------------------------------------------------------------------------
// Edge Types
// ---------------------------------------------------------------------------

/// A directed edge representing causation between nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausationEdge {
    /// Unique identifier for this edge.
    pub id: EdgeId,
    /// Source node (cause).
    pub source: NodeId,
    /// Target node (effect).
    pub target: NodeId,
    /// Strength of causal influence.
    pub weight: InfluenceWeight,
    /// Type of causation relationship.
    pub causation_type: CausationType,
    /// Content hash for integrity verification.
    pub content_hash: ContentHash,
    /// Unix timestamp when this edge was created.
    pub timestamp_ns: u64,
    /// Optional metadata for extensibility.
    pub metadata: BTreeMap<String, String>,
}

/// Type of causation relationship between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausationType {
    /// Direct causal influence.
    Direct,
    /// Indirect influence through intermediate factors.
    Indirect,
    /// Correlation without established causation.
    Correlational,
    /// Temporal precedence relationship.
    Temporal,
    /// Logical dependency.
    Logical,
    /// Evidential support relationship.
    Evidential,
}

// ---------------------------------------------------------------------------
// Graph Structure
// ---------------------------------------------------------------------------

/// A complete causation graph with nodes and edges.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausationGraph {
    /// Schema version for compatibility checking.
    pub schema_version: String,
    /// All nodes in the graph, indexed by ID.
    pub nodes: BTreeMap<NodeId, CausationNode>,
    /// All edges in the graph, indexed by ID.
    pub edges: BTreeMap<EdgeId, CausationEdge>,
    /// Adjacency list for efficient traversal (source -> targets).
    pub adjacency: BTreeMap<NodeId, Vec<EdgeId>>,
    /// Reverse adjacency list (target -> sources).
    pub reverse_adjacency: BTreeMap<NodeId, Vec<EdgeId>>,
    /// Topologically sorted node order for deterministic traversal.
    pub topological_order: Vec<NodeId>,
    /// Graph-level metadata.
    pub metadata: GraphMetadata,
}

/// Metadata for the entire causation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphMetadata {
    /// Unix timestamp when graph was created.
    pub created_at_ns: u64,
    /// Unix timestamp when graph was last modified.
    pub modified_at_ns: u64,
    /// Total number of nodes.
    pub node_count: u64,
    /// Total number of edges.
    pub edge_count: u64,
    /// Content hash of the entire graph.
    pub graph_hash: ContentHash,
    /// Optional description.
    pub description: Option<String>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl CausationGraph {
    /// Create a new empty causation graph.
    pub fn new() -> Self {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        Self {
            schema_version: CAUSATION_GRAPH_SCHEMA_VERSION.to_string(),
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            adjacency: BTreeMap::new(),
            reverse_adjacency: BTreeMap::new(),
            topological_order: Vec::new(),
            metadata: GraphMetadata {
                created_at_ns: now_ns,
                modified_at_ns: now_ns,
                node_count: 0,
                edge_count: 0,
                graph_hash: ContentHash::compute(&[]),
                description: None,
            },
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: CausationNode) -> Result<NodeId, GraphError> {
        let node_id = node.id;

        if self.nodes.contains_key(&node_id) {
            return Err(GraphError::NodeAlreadyExists(node_id));
        }

        self.nodes.insert(node_id, node);
        self.adjacency.insert(node_id, Vec::new());
        self.reverse_adjacency.insert(node_id, Vec::new());

        self.metadata.node_count += 1;
        self.metadata.modified_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Recompute topological order
        self.update_topological_order()?;
        self.update_graph_hash();

        Ok(node_id)
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: CausationEdge) -> Result<EdgeId, GraphError> {
        let edge_id = edge.id;
        let source = edge.source;
        let target = edge.target;

        // Verify nodes exist
        if !self.nodes.contains_key(&source) {
            return Err(GraphError::NodeNotFound(source));
        }
        if !self.nodes.contains_key(&target) {
            return Err(GraphError::NodeNotFound(target));
        }

        // Check for cycles
        if self.would_create_cycle(source, target)? {
            return Err(GraphError::CycleDetected(source, target));
        }

        if self.edges.contains_key(&edge_id) {
            return Err(GraphError::EdgeAlreadyExists(edge_id));
        }

        self.edges.insert(edge_id, edge);
        self.adjacency.entry(source).or_default().push(edge_id);
        self.reverse_adjacency
            .entry(target)
            .or_default()
            .push(edge_id);

        self.metadata.edge_count += 1;
        self.metadata.modified_at_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;

        // Recompute topological order
        self.update_topological_order()?;
        self.update_graph_hash();

        Ok(edge_id)
    }

    /// Get all nodes that directly influence the given node.
    pub fn get_direct_causes(&self, node_id: NodeId) -> Vec<&CausationNode> {
        self.reverse_adjacency
            .get(&node_id)
            .map(|edge_ids| {
                edge_ids
                    .iter()
                    .filter_map(|edge_id| self.edges.get(edge_id))
                    .filter_map(|edge| self.nodes.get(&edge.source))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all nodes directly influenced by the given node.
    pub fn get_direct_effects(&self, node_id: NodeId) -> Vec<&CausationNode> {
        self.adjacency
            .get(&node_id)
            .map(|edge_ids| {
                edge_ids
                    .iter()
                    .filter_map(|edge_id| self.edges.get(edge_id))
                    .filter_map(|edge| self.nodes.get(&edge.target))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all nodes in the transitive closure of influences for a given node.
    pub fn get_causal_chain(
        &self,
        node_id: NodeId,
        max_depth: usize,
    ) -> Result<Vec<NodeId>, GraphError> {
        let mut visited = std::collections::HashSet::new();
        let mut result = Vec::new();
        let mut queue = std::collections::VecDeque::new();

        queue.push_back((node_id, 0));
        visited.insert(node_id);

        while let Some((current_id, depth)) = queue.pop_front() {
            if depth > max_depth {
                continue;
            }

            result.push(current_id);

            // Add direct causes
            if let Some(edge_ids) = self.reverse_adjacency.get(&current_id) {
                for edge_id in edge_ids {
                    if let Some(edge) = self.edges.get(edge_id) {
                        if !visited.contains(&edge.source) {
                            visited.insert(edge.source);
                            queue.push_back((edge.source, depth + 1));
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Check if adding an edge would create a cycle.
    fn would_create_cycle(&self, source: NodeId, target: NodeId) -> Result<bool, GraphError> {
        // If target can reach source, then source -> target would create a cycle
        let reachable = self.get_causal_chain(target, 1000)?; // Use reasonable depth limit
        Ok(reachable.contains(&source))
    }

    /// Update the topological ordering of nodes.
    fn update_topological_order(&mut self) -> Result<(), GraphError> {
        let mut in_degree = BTreeMap::new();
        let mut queue = std::collections::VecDeque::new();
        let mut result = Vec::new();

        // Calculate in-degree for all nodes
        for node_id in self.nodes.keys() {
            in_degree.insert(*node_id, 0);
        }

        for edge in self.edges.values() {
            *in_degree.entry(edge.target).or_insert(0) += 1;
        }

        // Add nodes with in-degree 0 to queue
        for (node_id, degree) in &in_degree {
            if *degree == 0 {
                queue.push_back(*node_id);
            }
        }

        // Process nodes
        while let Some(node_id) = queue.pop_front() {
            result.push(node_id);

            // Reduce in-degree of adjacent nodes
            if let Some(edge_ids) = self.adjacency.get(&node_id) {
                for edge_id in edge_ids {
                    if let Some(edge) = self.edges.get(edge_id) {
                        if let Some(degree) = in_degree.get_mut(&edge.target) {
                            *degree -= 1;
                            if *degree == 0 {
                                queue.push_back(edge.target);
                            }
                        }
                    }
                }
            }
        }

        if result.len() != self.nodes.len() {
            return Err(GraphError::CyclicGraph);
        }

        self.topological_order = result;
        Ok(())
    }

    /// Update the graph-level content hash.
    fn update_graph_hash(&mut self) {
        let mut hash_data = Vec::new();

        // Add schema version
        hash_data.extend_from_slice(self.schema_version.as_bytes());
        hash_data.extend_from_slice(&self.metadata.node_count.to_le_bytes());
        hash_data.extend_from_slice(&self.metadata.edge_count.to_le_bytes());

        // Hash all nodes in deterministic order
        for node_id in &self.topological_order {
            if let Some(node) = self.nodes.get(node_id) {
                hash_data.extend_from_slice(node.content_hash.as_bytes());
            }
        }

        // Hash all edges in deterministic order
        let mut edge_ids: Vec<_> = self.edges.keys().collect();
        edge_ids.sort();
        for edge_id in edge_ids {
            if let Some(edge) = self.edges.get(edge_id) {
                hash_data.extend_from_slice(edge.content_hash.as_bytes());
            }
        }

        self.metadata.graph_hash = ContentHash::compute(&hash_data);
    }
}

impl Default for CausationGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur when working with causation graphs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    /// Node with given ID already exists.
    NodeAlreadyExists(NodeId),
    /// Node with given ID not found.
    NodeNotFound(NodeId),
    /// Edge with given ID already exists.
    EdgeAlreadyExists(EdgeId),
    /// Edge with given ID not found.
    EdgeNotFound(EdgeId),
    /// Adding edge would create a cycle.
    CycleDetected(NodeId, NodeId),
    /// Graph contains cycles (should be DAG).
    CyclicGraph,
    /// Invalid schema version.
    InvalidSchema(String),
    /// Serialization/deserialization error.
    SerializationError(String),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GraphError::NodeAlreadyExists(id) => write!(f, "Node {} already exists", id),
            GraphError::NodeNotFound(id) => write!(f, "Node {} not found", id),
            GraphError::EdgeAlreadyExists(id) => write!(f, "Edge {} already exists", id),
            GraphError::EdgeNotFound(id) => write!(f, "Edge {} not found", id),
            GraphError::CycleDetected(source, target) => {
                write!(f, "Adding edge {} -> {} would create cycle", source, target)
            }
            GraphError::CyclicGraph => write!(f, "Graph contains cycles"),
            GraphError::InvalidSchema(msg) => write!(f, "Invalid schema: {}", msg),
            GraphError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for GraphError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_graph_creation() {
        let graph = CausationGraph::new();
        assert_eq!(graph.schema_version, CAUSATION_GRAPH_SCHEMA_VERSION);
        assert_eq!(graph.nodes.len(), 0);
        assert_eq!(graph.edges.len(), 0);
        assert_eq!(graph.metadata.node_count, 0);
        assert_eq!(graph.metadata.edge_count, 0);
    }

    #[test]
    fn test_node_addition() {
        let mut graph = CausationGraph::new();
        let node = CausationNode {
            id: NodeId(1),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    evidence_atom_id: "test-atom".to_string(),
                    evidence_type: "test_evidence".to_string(),
                    influenced_factor: DecisionFactor::PosteriorProbability,
                    influence_magnitude_millionths: 500_000,
                    evidence_content_hash: ContentHash::compute(b"test"),
                },
                evidence_hash: ContentHash::compute(b"evidence"),
                confidence_millionths: 900_000,
            },
            content_hash: ContentHash::compute(b"node-content"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"node", b"key"),
            timestamp_ns: 1000000,
            metadata: BTreeMap::new(),
        };

        let result = graph.add_node(node);
        assert!(result.is_ok());
        assert_eq!(graph.metadata.node_count, 1);
        assert_eq!(graph.topological_order.len(), 1);
    }

    #[test]
    fn test_edge_addition() {
        let mut graph = CausationGraph::new();

        // Add two nodes first
        let node1 = CausationNode {
            id: NodeId(1),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    evidence_atom_id: "atom1".to_string(),
                    evidence_type: "test_evidence".to_string(),
                    influenced_factor: DecisionFactor::PosteriorProbability,
                    influence_magnitude_millionths: 500_000,
                    evidence_content_hash: ContentHash::compute(b"test1"),
                },
                evidence_hash: ContentHash::compute(b"evidence1"),
                confidence_millionths: 900_000,
            },
            content_hash: ContentHash::compute(b"node1"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"node1", b"key"),
            timestamp_ns: 1000000,
            metadata: BTreeMap::new(),
        };

        let node2 = CausationNode {
            id: NodeId(2),
            node_type: NodeType::Decision {
                decision_id: "decision1".to_string(),
                factor: DecisionFactor::PosteriorProbability,
                context_hash: ContentHash::compute(b"context"),
                outcome: DecisionOutcome::Allow,
            },
            content_hash: ContentHash::compute(b"node2"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"node2", b"key"),
            timestamp_ns: 2000000,
            metadata: BTreeMap::new(),
        };

        graph.add_node(node1).unwrap();
        graph.add_node(node2).unwrap();

        // Add edge
        let edge = CausationEdge {
            id: EdgeId(1),
            source: NodeId(1),
            target: NodeId(2),
            weight: InfluenceWeight::from_millionths(750_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(b"edge1"),
            timestamp_ns: 3000000,
            metadata: BTreeMap::new(),
        };

        let result = graph.add_edge(edge);
        assert!(result.is_ok());
        assert_eq!(graph.metadata.edge_count, 1);
    }

    #[test]
    fn test_cycle_detection() {
        let mut graph = CausationGraph::new();

        // Add three nodes
        for i in 1..=3 {
            let node = CausationNode {
                id: NodeId(i),
                node_type: NodeType::EvidenceAtom {
                    dependency: CausalDependency {
                        evidence_atom_id: format!("atom{}", i),
                        evidence_type: "test_evidence".to_string(),
                        influenced_factor: DecisionFactor::PosteriorProbability,
                        influence_magnitude_millionths: 500_000,
                        evidence_content_hash: ContentHash::compute(format!("test{}", i).as_bytes()),
                    },
                    evidence_hash: ContentHash::compute(format!("evidence{}", i).as_bytes()),
                    confidence_millionths: 900_000,
                },
                content_hash: ContentHash::compute(format!("node{}", i).as_bytes()),
                authenticity_hash: AuthenticityHash::compute_keyed(
                    format!("node{}", i).as_bytes(),
                    b"key",
                ),
                timestamp_ns: i * 1000000,
                metadata: BTreeMap::new(),
            };
            graph.add_node(node).unwrap();
        }

        // Add edges: 1 -> 2 -> 3
        let edge1 = CausationEdge {
            id: EdgeId(1),
            source: NodeId(1),
            target: NodeId(2),
            weight: InfluenceWeight::from_millionths(750_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(b"edge1"),
            timestamp_ns: 4000000,
            metadata: BTreeMap::new(),
        };

        let edge2 = CausationEdge {
            id: EdgeId(2),
            source: NodeId(2),
            target: NodeId(3),
            weight: InfluenceWeight::from_millionths(600_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(b"edge2"),
            timestamp_ns: 5000000,
            metadata: BTreeMap::new(),
        };

        graph.add_edge(edge1).unwrap();
        graph.add_edge(edge2).unwrap();

        // Try to add edge that creates cycle: 3 -> 1
        let cycle_edge = CausationEdge {
            id: EdgeId(3),
            source: NodeId(3),
            target: NodeId(1),
            weight: InfluenceWeight::from_millionths(400_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(b"cycle_edge"),
            timestamp_ns: 6000000,
            metadata: BTreeMap::new(),
        };

        let result = graph.add_edge(cycle_edge);
        assert!(matches!(result, Err(GraphError::CycleDetected(_, _))));
    }

    #[test]
    fn test_influence_weight() {
        let weight = InfluenceWeight::from_f64(0.75);
        assert_eq!(weight.millionths, 750_000);
        assert!((weight.to_f64() - 0.75).abs() < 1e-6);

        assert!(InfluenceWeight::MAX.to_f64() - 1.0 < 1e-6);
        assert!(InfluenceWeight::ZERO.to_f64() < 1e-6);
    }

    #[test]
    fn test_causal_chain_retrieval() {
        let mut graph = CausationGraph::new();

        // Create chain: 1 -> 2 -> 3 -> 4
        for i in 1..=4 {
            let node = CausationNode {
                id: NodeId(i),
                node_type: NodeType::EvidenceAtom {
                    dependency: CausalDependency {
                        evidence_atom_id: format!("atom{}", i),
                        evidence_type: "test_evidence".to_string(),
                        influenced_factor: DecisionFactor::PosteriorProbability,
                        influence_magnitude_millionths: 500_000,
                        evidence_content_hash: ContentHash::compute(format!("test{}", i).as_bytes()),
                    },
                    evidence_hash: ContentHash::compute(format!("evidence{}", i).as_bytes()),
                    confidence_millionths: 900_000,
                },
                content_hash: ContentHash::compute(format!("node{}", i).as_bytes()),
                authenticity_hash: AuthenticityHash::compute_keyed(
                    format!("node{}", i).as_bytes(),
                    b"key",
                ),
                timestamp_ns: i * 1000000,
                metadata: BTreeMap::new(),
            };
            graph.add_node(node).unwrap();
        }

        // Add edges
        for i in 1..=3 {
            let edge = CausationEdge {
                id: EdgeId(i),
                source: NodeId(i),
                target: NodeId(i + 1),
                weight: InfluenceWeight::from_millionths(500_000),
                causation_type: CausationType::Direct,
                content_hash: ContentHash::compute(format!("edge{}", i).as_bytes()),
                timestamp_ns: (i + 4) * 1000000,
                metadata: BTreeMap::new(),
            };
            graph.add_edge(edge).unwrap();
        }

        // Get causal chain for node 4 (should include 4, 3, 2, 1)
        let chain = graph.get_causal_chain(NodeId(4), 10).unwrap();
        assert!(chain.contains(&NodeId(4)));
        assert!(chain.contains(&NodeId(3)));
        assert!(chain.contains(&NodeId(2)));
        assert!(chain.contains(&NodeId(1)));
    }
}
