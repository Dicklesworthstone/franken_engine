//! Typed DAG schema for forensic causation graphs — Track FF.2 substrate (bd-cixqu.32.2).
//!
//! Provides a formal directed acyclic graph (DAG) representation of causal relationships
//! between evidence atoms and decisions. Built on the minimal-causal-set infrastructure
//! from FF.1, this module enables forensic analysis through structured causation graphs.
//!
//! The schema follows franken-engine.causation-graph.v1 format and provides:
//! - Nodes: Evidence atoms and decision points
//! - Edges: Causal dependencies with influence magnitudes
//! - Sortable: Topological ordering and temporal sequencing
//! - Queryable: Path queries, dependency traversal, impact analysis
//! - Signed: Content integrity and authenticity verification
//!
//! Key components:
//! - `CausationGraph`: Main DAG structure with nodes and edges
//! - `GraphNode`: Union type for evidence atoms and decisions
//! - `CausationEdge`: Directed edge representing causal influence
//! - `GraphQuery`: Query interface for forensic analysis
//! - `GraphSignature`: Cryptographic integrity verification
//!
//! Plan reference: bd-cixqu.32.2 (FF.2), bd-cixqu.32 (Track FF parent).

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::{AuthenticityHash, ContentHash};
use crate::minimal_causal_set_inference::{CausalDependency, DecisionFactor, MinimalCausalSet};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema version constants
// ---------------------------------------------------------------------------

/// Schema version identifier for franken-engine.causation-graph.v1.
pub const CAUSATION_GRAPH_SCHEMA_VERSION: &str = "franken-engine.causation-graph.v1";

/// Schema compatibility version for backward compatibility checks.
pub const SCHEMA_COMPATIBILITY_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Graph node types — evidence atoms and decisions
// ---------------------------------------------------------------------------

/// A node in the causation graph, representing either an evidence atom or a decision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GraphNode {
    /// Evidence atom node.
    EvidenceAtom(EvidenceAtomNode),
    /// Decision node.
    Decision(DecisionNode),
}

impl GraphNode {
    /// Get the unique identifier for this node.
    pub fn id(&self) -> &str {
        match self {
            Self::EvidenceAtom(node) => &node.atom_id,
            Self::Decision(node) => &node.decision_id,
        }
    }

    /// Get the timestamp when this node was created.
    pub fn timestamp_ns(&self) -> u64 {
        match self {
            Self::EvidenceAtom(node) => node.timestamp_ns,
            Self::Decision(node) => node.timestamp_ns,
        }
    }

    /// Get the content hash of this node for integrity verification.
    pub fn content_hash(&self) -> &ContentHash {
        match self {
            Self::EvidenceAtom(node) => &node.content_hash,
            Self::Decision(node) => &node.content_hash,
        }
    }

    /// Check if this is an evidence atom node.
    pub fn is_evidence_atom(&self) -> bool {
        matches!(self, Self::EvidenceAtom(_))
    }

    /// Check if this is a decision node.
    pub fn is_decision(&self) -> bool {
        matches!(self, Self::Decision(_))
    }
}

/// Evidence atom node in the causation graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceAtomNode {
    /// Unique identifier for the evidence atom.
    pub atom_id: String,
    /// Type of evidence (e.g., "sensor_reading", "policy_violation").
    pub evidence_type: String,
    /// Timestamp when the evidence was recorded (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Security epoch when the evidence was recorded.
    pub epoch_id: SecurityEpoch,
    /// Content hash of the evidence value.
    pub content_hash: ContentHash,
    /// Source system or component that produced this evidence.
    pub source: String,
    /// Metadata associated with the evidence atom.
    pub metadata: BTreeMap<String, String>,
}

impl EvidenceAtomNode {
    /// Create a new evidence atom node.
    pub fn new(
        atom_id: impl Into<String>,
        evidence_type: impl Into<String>,
        timestamp_ns: u64,
        epoch_id: SecurityEpoch,
        content_hash: ContentHash,
        source: impl Into<String>,
    ) -> Self {
        Self {
            atom_id: atom_id.into(),
            evidence_type: evidence_type.into(),
            timestamp_ns,
            epoch_id,
            content_hash,
            source: source.into(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add metadata to the evidence atom.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Decision node in the causation graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DecisionNode {
    /// Unique identifier for the decision.
    pub decision_id: String,
    /// Type of decision (e.g., "access_control", "resource_allocation").
    pub decision_type: String,
    /// Timestamp when the decision was made (nanoseconds since epoch).
    pub timestamp_ns: u64,
    /// Security epoch when the decision was made.
    pub epoch_id: SecurityEpoch,
    /// Content hash of the decision outcome.
    pub content_hash: ContentHash,
    /// System or component that made the decision.
    pub decision_maker: String,
    /// The chosen action or outcome.
    pub outcome: String,
    /// Metadata associated with the decision.
    pub metadata: BTreeMap<String, String>,
}

impl DecisionNode {
    /// Create a new decision node.
    pub fn new(
        decision_id: impl Into<String>,
        decision_type: impl Into<String>,
        timestamp_ns: u64,
        epoch_id: SecurityEpoch,
        content_hash: ContentHash,
        decision_maker: impl Into<String>,
        outcome: impl Into<String>,
    ) -> Self {
        Self {
            decision_id: decision_id.into(),
            decision_type: decision_type.into(),
            timestamp_ns,
            epoch_id,
            content_hash,
            decision_maker: decision_maker.into(),
            outcome: outcome.into(),
            metadata: BTreeMap::new(),
        }
    }

    /// Add metadata to the decision.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Causation edges — directed causal relationships
// ---------------------------------------------------------------------------

/// A directed edge in the causation graph representing causal influence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CausationEdge {
    /// Source node ID (evidence atom or prior decision).
    pub source_id: String,
    /// Target node ID (decision influenced by the source).
    pub target_id: String,
    /// Decision factor influenced by this causal relationship.
    pub influenced_factor: DecisionFactor,
    /// Quantitative influence magnitude (fixed-point millionths).
    pub influence_magnitude_millionths: i64,
    /// Timestamp when the causal relationship was established.
    pub established_at_ns: u64,
    /// Content hash for integrity verification.
    pub edge_hash: ContentHash,
    /// Additional metadata about the causal relationship.
    pub metadata: BTreeMap<String, String>,
}

impl CausationEdge {
    /// Create a new causation edge.
    pub fn new(
        source_id: impl Into<String>,
        target_id: impl Into<String>,
        influenced_factor: DecisionFactor,
        influence_magnitude_millionths: i64,
        established_at_ns: u64,
    ) -> Self {
        let source_id = source_id.into();
        let target_id = target_id.into();

        // Compute content hash of the edge
        let edge_data = format!("{}->{};factor={};magnitude={};time={}",
            source_id, target_id, influenced_factor,
            influence_magnitude_millionths, established_at_ns);
        let edge_hash = ContentHash::compute(edge_data.as_bytes());

        Self {
            source_id,
            target_id,
            influenced_factor,
            influence_magnitude_millionths,
            established_at_ns,
            edge_hash,
            metadata: BTreeMap::new(),
        }
    }

    /// Create a causation edge from a causal dependency.
    pub fn from_causal_dependency(
        dependency: &CausalDependency,
        target_id: impl Into<String>,
        established_at_ns: u64,
    ) -> Self {
        Self::new(
            dependency.evidence_atom_id.clone(),
            target_id,
            dependency.influenced_factor,
            dependency.influence_magnitude_millionths,
            established_at_ns,
        )
    }

    /// Add metadata to the edge.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Causation graph — main DAG structure
// ---------------------------------------------------------------------------

/// Main causation graph structure representing a DAG of evidence atoms and decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausationGraph {
    /// Schema version identifier.
    pub schema_version: String,
    /// Unique identifier for this graph.
    pub graph_id: String,
    /// Timestamp when the graph was created.
    pub created_at_ns: u64,
    /// Security epoch for the graph.
    pub epoch_id: SecurityEpoch,
    /// All nodes in the graph (evidence atoms and decisions).
    pub nodes: BTreeMap<String, GraphNode>,
    /// All directed edges in the graph (causal relationships).
    pub edges: Vec<CausationEdge>,
    /// Graph-level metadata.
    pub metadata: BTreeMap<String, String>,
    /// Cryptographic signature for integrity verification.
    pub signature: Option<GraphSignature>,
}

impl CausationGraph {
    /// Create a new causation graph.
    pub fn new(graph_id: impl Into<String>, epoch_id: SecurityEpoch) -> Self {
        Self {
            schema_version: CAUSATION_GRAPH_SCHEMA_VERSION.to_string(),
            graph_id: graph_id.into(),
            created_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            epoch_id,
            nodes: BTreeMap::new(),
            edges: Vec::new(),
            metadata: BTreeMap::new(),
            signature: None,
        }
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: GraphNode) -> Result<(), GraphError> {
        let node_id = node.id().to_string();
        if self.nodes.contains_key(&node_id) {
            return Err(GraphError::DuplicateNode { node_id });
        }
        self.nodes.insert(node_id, node);
        Ok(())
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: CausationEdge) -> Result<(), GraphError> {
        // Verify that source and target nodes exist
        if !self.nodes.contains_key(&edge.source_id) {
            return Err(GraphError::NodeNotFound {
                node_id: edge.source_id.clone(),
            });
        }
        if !self.nodes.contains_key(&edge.target_id) {
            return Err(GraphError::NodeNotFound {
                node_id: edge.target_id.clone(),
            });
        }

        // Check for cycle creation
        if self.would_create_cycle(&edge) {
            return Err(GraphError::WouldCreateCycle {
                source: edge.source_id.clone(),
                target: edge.target_id.clone(),
            });
        }

        self.edges.push(edge);
        Ok(())
    }

    /// Build a causation graph from a minimal causal set.
    pub fn from_minimal_causal_set(
        causal_set: &MinimalCausalSet,
        evidence_atoms: &BTreeMap<String, EvidenceAtomNode>,
        decision_node: DecisionNode,
    ) -> Result<Self, GraphError> {
        let mut graph = Self::new(
            format!("graph-{}", causal_set.decision_id),
            causal_set.epoch_id,
        );

        // Add decision node
        graph.add_node(GraphNode::Decision(decision_node))?;

        // Add evidence atom nodes and edges
        for dependency in &causal_set.dependencies {
            // Add evidence atom node if it exists
            if let Some(evidence_node) = evidence_atoms.get(&dependency.evidence_atom_id) {
                graph.add_node(GraphNode::EvidenceAtom(evidence_node.clone()))?;

                // Add causation edge
                let edge = CausationEdge::from_causal_dependency(
                    dependency,
                    &causal_set.decision_id,
                    causal_set.computed_at_ns,
                );
                graph.add_edge(edge)?;
            }
        }

        // Add metadata from causal set
        for (key, value) in &causal_set.minimization_metadata {
            graph.metadata.insert(key.clone(), value.clone());
        }
        graph.metadata.insert("causal_set_id".to_string(), causal_set.causal_set_id.clone());
        graph.metadata.insert("total_evidence_considered".to_string(),
            causal_set.total_evidence_atoms_considered.to_string());

        Ok(graph)
    }

    /// Get all evidence atom nodes.
    pub fn evidence_atoms(&self) -> impl Iterator<Item = &EvidenceAtomNode> {
        self.nodes.values().filter_map(|node| {
            if let GraphNode::EvidenceAtom(atom) = node {
                Some(atom)
            } else {
                None
            }
        })
    }

    /// Get all decision nodes.
    pub fn decisions(&self) -> impl Iterator<Item = &DecisionNode> {
        self.nodes.values().filter_map(|node| {
            if let GraphNode::Decision(decision) = node {
                Some(decision)
            } else {
                None
            }
        })
    }

    /// Get edges pointing to a specific node.
    pub fn incoming_edges(&self, node_id: &str) -> impl Iterator<Item = &CausationEdge> {
        self.edges.iter().filter(move |edge| edge.target_id == node_id)
    }

    /// Get edges originating from a specific node.
    pub fn outgoing_edges(&self, node_id: &str) -> impl Iterator<Item = &CausationEdge> {
        self.edges.iter().filter(move |edge| edge.source_id == node_id)
    }

    /// Perform topological sort of the graph nodes.
    pub fn topological_sort(&self) -> Result<Vec<String>, GraphError> {
        let mut in_degree: BTreeMap<String, usize> = BTreeMap::new();
        let mut adj_list: BTreeMap<String, Vec<String>> = BTreeMap::new();

        // Initialize in-degree and adjacency list
        for node_id in self.nodes.keys() {
            in_degree.insert(node_id.clone(), 0);
            adj_list.insert(node_id.clone(), Vec::new());
        }

        // Build adjacency list and compute in-degrees
        for edge in &self.edges {
            adj_list
                .get_mut(&edge.source_id)
                .unwrap()
                .push(edge.target_id.clone());
            *in_degree.get_mut(&edge.target_id).unwrap() += 1;
        }

        // Kahn's algorithm
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut result: Vec<String> = Vec::new();

        // Start with nodes that have no incoming edges
        for (node_id, degree) in &in_degree {
            if *degree == 0 {
                queue.push_back(node_id.clone());
            }
        }

        while let Some(current) = queue.pop_front() {
            result.push(current.clone());

            // For each neighbor of current node
            if let Some(neighbors) = adj_list.get(&current) {
                for neighbor in neighbors {
                    let degree = in_degree.get_mut(neighbor).unwrap();
                    *degree -= 1;
                    if *degree == 0 {
                        queue.push_back(neighbor.clone());
                    }
                }
            }
        }

        // Check if there was a cycle
        if result.len() != self.nodes.len() {
            return Err(GraphError::CycleDetected);
        }

        Ok(result)
    }

    /// Sort nodes by timestamp (temporal ordering).
    pub fn temporal_sort(&self) -> Vec<String> {
        let mut nodes: Vec<(String, u64)> = self.nodes
            .iter()
            .map(|(id, node)| (id.clone(), node.timestamp_ns()))
            .collect();

        nodes.sort_by(|(_, a), (_, b)| a.cmp(b));
        nodes.into_iter().map(|(id, _)| id).collect()
    }

    /// Check if adding an edge would create a cycle.
    fn would_create_cycle(&self, new_edge: &CausationEdge) -> bool {
        // Use DFS to check if there's already a path from target to source
        self.has_path(&new_edge.target_id, &new_edge.source_id)
    }

    /// Check if there's a path from start to end node.
    fn has_path(&self, start: &str, end: &str) -> bool {
        if start == end {
            return true;
        }

        let mut visited: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<String> = vec![start.to_string()];

        while let Some(current) = stack.pop() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());

            for edge in self.outgoing_edges(&current) {
                if edge.target_id == end {
                    return true;
                }
                if !visited.contains(&edge.target_id) {
                    stack.push(edge.target_id.clone());
                }
            }
        }

        false
    }

    /// Add metadata to the graph.
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get the number of nodes in the graph.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the number of edges in the graph.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Validate the graph structure and integrity.
    pub fn validate(&self) -> Result<(), GraphError> {
        // Check schema version
        if self.schema_version != CAUSATION_GRAPH_SCHEMA_VERSION {
            return Err(GraphError::InvalidSchemaVersion {
                expected: CAUSATION_GRAPH_SCHEMA_VERSION.to_string(),
                got: self.schema_version.clone(),
            });
        }

        // Check that all edge endpoints exist
        for edge in &self.edges {
            if !self.nodes.contains_key(&edge.source_id) {
                return Err(GraphError::NodeNotFound {
                    node_id: edge.source_id.clone(),
                });
            }
            if !self.nodes.contains_key(&edge.target_id) {
                return Err(GraphError::NodeNotFound {
                    node_id: edge.target_id.clone(),
                });
            }
        }

        // Check for cycles (DAG property)
        self.topological_sort()?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Graph signature for integrity verification
// ---------------------------------------------------------------------------

/// Cryptographic signature for causation graph integrity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphSignature {
    /// Hash of the graph content (nodes + edges + metadata).
    pub content_hash: ContentHash,
    /// Authenticity hash for cryptographic verification.
    pub authenticity_hash: AuthenticityHash,
    /// Timestamp when the signature was created.
    pub signed_at_ns: u64,
    /// Identity of the signer.
    pub signer_id: String,
    /// Signature algorithm used.
    pub algorithm: String,
}

impl GraphSignature {
    /// Create a new graph signature.
    pub fn new(
        content_hash: ContentHash,
        authenticity_hash: AuthenticityHash,
        signer_id: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        Self {
            content_hash,
            authenticity_hash,
            signed_at_ns: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            signer_id: signer_id.into(),
            algorithm: algorithm.into(),
        }
    }

    /// Sign a causation graph.
    pub fn sign_graph(
        graph: &CausationGraph,
        signer_id: impl Into<String>,
        signing_key: &[u8],
    ) -> Result<Self, GraphError> {
        // Compute content hash of the entire graph (excluding signature)
        let graph_without_sig = CausationGraph {
            signature: None,
            ..graph.clone()
        };

        let serialized = serde_json::to_vec(&graph_without_sig)
            .map_err(|e| GraphError::SerializationError {
                message: e.to_string()
            })?;

        let content_hash = ContentHash::compute(&serialized);
        let authenticity_hash = AuthenticityHash::compute_keyed(&serialized, signing_key);

        Ok(Self::new(
            content_hash,
            authenticity_hash,
            signer_id,
            "HMAC-SHA256".to_string(),
        ))
    }

    /// Verify a graph signature.
    pub fn verify(
        &self,
        graph: &CausationGraph,
        verification_key: &[u8],
    ) -> Result<bool, GraphError> {
        // Compute content hash of the graph without signature
        let graph_without_sig = CausationGraph {
            signature: None,
            ..graph.clone()
        };

        let serialized = serde_json::to_vec(&graph_without_sig)
            .map_err(|e| GraphError::SerializationError {
                message: e.to_string()
            })?;

        let computed_content_hash = ContentHash::compute(&serialized);
        let computed_authenticity_hash = AuthenticityHash::compute_keyed(&serialized, verification_key);

        // Verify both hashes match
        Ok(computed_content_hash == self.content_hash &&
           computed_authenticity_hash == self.authenticity_hash)
    }
}

// ---------------------------------------------------------------------------
// Graph errors
// ---------------------------------------------------------------------------

/// Errors that can occur during causation graph operations.
#[derive(Debug, Clone)]
pub enum GraphError {
    /// Attempted to add a node that already exists.
    DuplicateNode { node_id: String },
    /// Referenced node does not exist.
    NodeNotFound { node_id: String },
    /// Adding edge would create a cycle (violate DAG property).
    WouldCreateCycle { source: String, target: String },
    /// Cycle detected in the graph.
    CycleDetected,
    /// Invalid schema version.
    InvalidSchemaVersion { expected: String, got: String },
    /// Serialization/deserialization error.
    SerializationError { message: String },
    /// Signature verification failed.
    SignatureVerificationFailed,
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateNode { node_id } => {
                write!(f, "Duplicate node: {}", node_id)
            }
            Self::NodeNotFound { node_id } => {
                write!(f, "Node not found: {}", node_id)
            }
            Self::WouldCreateCycle { source, target } => {
                write!(f, "Adding edge {} -> {} would create cycle", source, target)
            }
            Self::CycleDetected => {
                write!(f, "Cycle detected in graph")
            }
            Self::InvalidSchemaVersion { expected, got } => {
                write!(f, "Invalid schema version: expected {}, got {}", expected, got)
            }
            Self::SerializationError { message } => {
                write!(f, "Serialization error: {}", message)
            }
            Self::SignatureVerificationFailed => {
                write!(f, "Signature verification failed")
            }
        }
    }
}

impl std::error::Error for GraphError {}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_evidence_atom() -> EvidenceAtomNode {
        EvidenceAtomNode::new(
            "evidence-1",
            "sensor_reading",
            1000000000,
            SecurityEpoch::from_raw(1),
            ContentHash::compute(b"test evidence"),
            "sensor-01",
        )
    }

    fn create_test_decision() -> DecisionNode {
        DecisionNode::new(
            "decision-1",
            "access_control",
            2000000000,
            SecurityEpoch::from_raw(1),
            ContentHash::compute(b"allow"),
            "access-controller",
            "allow",
        )
    }

    #[test]
    fn test_graph_node_creation() {
        let evidence_node = create_test_evidence_atom();
        let decision_node = create_test_decision();

        assert_eq!(evidence_node.atom_id, "evidence-1");
        assert_eq!(evidence_node.evidence_type, "sensor_reading");
        assert_eq!(decision_node.decision_id, "decision-1");
        assert_eq!(decision_node.decision_type, "access_control");
    }

    #[test]
    fn test_causation_edge_creation() {
        let edge = CausationEdge::new(
            "evidence-1",
            "decision-1",
            DecisionFactor::PosteriorProbability,
            500_000, // 0.5 in millionths
            1500000000,
        );

        assert_eq!(edge.source_id, "evidence-1");
        assert_eq!(edge.target_id, "decision-1");
        assert_eq!(edge.influenced_factor, DecisionFactor::PosteriorProbability);
        assert_eq!(edge.influence_magnitude_millionths, 500_000);
    }

    #[test]
    fn test_graph_creation_and_basic_operations() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        // Add nodes
        let evidence_node = GraphNode::EvidenceAtom(create_test_evidence_atom());
        let decision_node = GraphNode::Decision(create_test_decision());

        graph.add_node(evidence_node).unwrap();
        graph.add_node(decision_node).unwrap();

        // Add edge
        let edge = CausationEdge::new(
            "evidence-1",
            "decision-1",
            DecisionFactor::PosteriorProbability,
            750_000,
            1500000000,
        );
        graph.add_edge(edge).unwrap();

        assert_eq!(graph.node_count(), 2);
        assert_eq!(graph.edge_count(), 1);
        assert!(graph.nodes.contains_key("evidence-1"));
        assert!(graph.nodes.contains_key("decision-1"));
    }

    #[test]
    fn test_duplicate_node_error() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));
        let evidence_node = GraphNode::EvidenceAtom(create_test_evidence_atom());

        graph.add_node(evidence_node.clone()).unwrap();
        let result = graph.add_node(evidence_node);

        assert!(matches!(result, Err(GraphError::DuplicateNode { .. })));
    }

    #[test]
    fn test_node_not_found_error() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        let edge = CausationEdge::new(
            "nonexistent-1",
            "nonexistent-2",
            DecisionFactor::ActionFiltering,
            100_000,
            1000000000,
        );

        let result = graph.add_edge(edge);
        assert!(matches!(result, Err(GraphError::NodeNotFound { .. })));
    }

    #[test]
    fn test_cycle_prevention() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        // Add three nodes
        let node1 = GraphNode::Decision(DecisionNode::new(
            "decision-1", "type1", 1000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"outcome1"), "maker1", "outcome1"
        ));
        let node2 = GraphNode::Decision(DecisionNode::new(
            "decision-2", "type2", 2000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"outcome2"), "maker2", "outcome2"
        ));
        let node3 = GraphNode::Decision(DecisionNode::new(
            "decision-3", "type3", 3000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"outcome3"), "maker3", "outcome3"
        ));

        graph.add_node(node1).unwrap();
        graph.add_node(node2).unwrap();
        graph.add_node(node3).unwrap();

        // Add edges to form a potential cycle: 1->2->3->1
        let edge1 = CausationEdge::new("decision-1", "decision-2", DecisionFactor::TieBreaking, 100_000, 1500);
        let edge2 = CausationEdge::new("decision-2", "decision-3", DecisionFactor::TieBreaking, 100_000, 2500);
        let edge3 = CausationEdge::new("decision-3", "decision-1", DecisionFactor::TieBreaking, 100_000, 3500); // This should fail

        graph.add_edge(edge1).unwrap();
        graph.add_edge(edge2).unwrap();

        let result = graph.add_edge(edge3);
        assert!(matches!(result, Err(GraphError::WouldCreateCycle { .. })));
    }

    #[test]
    fn test_topological_sort() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        // Create a simple DAG: A -> B -> C
        let node_a = GraphNode::EvidenceAtom(EvidenceAtomNode::new(
            "A", "type", 1000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"A"), "source"
        ));
        let node_b = GraphNode::Decision(DecisionNode::new(
            "B", "type", 2000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"B"), "maker", "outcome"
        ));
        let node_c = GraphNode::Decision(DecisionNode::new(
            "C", "type", 3000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"C"), "maker", "outcome"
        ));

        graph.add_node(node_a).unwrap();
        graph.add_node(node_b).unwrap();
        graph.add_node(node_c).unwrap();

        graph.add_edge(CausationEdge::new("A", "B", DecisionFactor::PosteriorProbability, 100_000, 1500)).unwrap();
        graph.add_edge(CausationEdge::new("B", "C", DecisionFactor::ActionFiltering, 200_000, 2500)).unwrap();

        let topo_order = graph.topological_sort().unwrap();

        // A should come before B, and B should come before C
        let a_pos = topo_order.iter().position(|x| x == "A").unwrap();
        let b_pos = topo_order.iter().position(|x| x == "B").unwrap();
        let c_pos = topo_order.iter().position(|x| x == "C").unwrap();

        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn test_temporal_sort() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        let node1 = GraphNode::EvidenceAtom(EvidenceAtomNode::new(
            "latest", "type", 3000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"latest"), "source"
        ));
        let node2 = GraphNode::EvidenceAtom(EvidenceAtomNode::new(
            "earliest", "type", 1000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"earliest"), "source"
        ));
        let node3 = GraphNode::EvidenceAtom(EvidenceAtomNode::new(
            "middle", "type", 2000, SecurityEpoch::from_raw(1),
            ContentHash::compute(b"middle"), "source"
        ));

        graph.add_node(node1).unwrap();
        graph.add_node(node2).unwrap();
        graph.add_node(node3).unwrap();

        let temporal_order = graph.temporal_sort();
        assert_eq!(temporal_order, vec!["earliest", "middle", "latest"]);
    }

    #[test]
    fn test_graph_validation() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        let evidence_node = GraphNode::EvidenceAtom(create_test_evidence_atom());
        let decision_node = GraphNode::Decision(create_test_decision());

        graph.add_node(evidence_node).unwrap();
        graph.add_node(decision_node).unwrap();

        let edge = CausationEdge::new(
            "evidence-1",
            "decision-1",
            DecisionFactor::PosteriorProbability,
            500_000,
            1500000000,
        );
        graph.add_edge(edge).unwrap();

        // Valid graph should pass validation
        assert!(graph.validate().is_ok());

        // Invalid schema version should fail
        graph.schema_version = "invalid-version".to_string();
        assert!(matches!(graph.validate(), Err(GraphError::InvalidSchemaVersion { .. })));
    }

    #[test]
    fn test_incoming_and_outgoing_edges() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        let evidence_node = GraphNode::EvidenceAtom(create_test_evidence_atom());
        let decision_node = GraphNode::Decision(create_test_decision());

        graph.add_node(evidence_node).unwrap();
        graph.add_node(decision_node).unwrap();

        let edge = CausationEdge::new(
            "evidence-1",
            "decision-1",
            DecisionFactor::LossMatrix,
            300_000,
            1500000000,
        );
        graph.add_edge(edge).unwrap();

        // Test incoming edges
        let incoming: Vec<_> = graph.incoming_edges("decision-1").collect();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].source_id, "evidence-1");

        // Test outgoing edges
        let outgoing: Vec<_> = graph.outgoing_edges("evidence-1").collect();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].target_id, "decision-1");
    }

    #[test]
    fn test_evidence_atoms_and_decisions_iterators() {
        let mut graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1));

        let evidence_node = GraphNode::EvidenceAtom(create_test_evidence_atom());
        let decision_node = GraphNode::Decision(create_test_decision());

        graph.add_node(evidence_node).unwrap();
        graph.add_node(decision_node).unwrap();

        let evidence_atoms: Vec<_> = graph.evidence_atoms().collect();
        let decisions: Vec<_> = graph.decisions().collect();

        assert_eq!(evidence_atoms.len(), 1);
        assert_eq!(decisions.len(), 1);
        assert_eq!(evidence_atoms[0].atom_id, "evidence-1");
        assert_eq!(decisions[0].decision_id, "decision-1");
    }

    #[test]
    fn test_graph_node_methods() {
        let evidence_node = GraphNode::EvidenceAtom(create_test_evidence_atom());
        let decision_node = GraphNode::Decision(create_test_decision());

        assert_eq!(evidence_node.id(), "evidence-1");
        assert_eq!(decision_node.id(), "decision-1");
        assert_eq!(evidence_node.timestamp_ns(), 1000000000);
        assert_eq!(decision_node.timestamp_ns(), 2000000000);
        assert!(evidence_node.is_evidence_atom());
        assert!(!evidence_node.is_decision());
        assert!(decision_node.is_decision());
        assert!(!decision_node.is_evidence_atom());
    }

    #[test]
    fn test_metadata_handling() {
        let evidence_node = create_test_evidence_atom()
            .with_metadata("sensor_type", "temperature")
            .with_metadata("location", "server_room");

        assert_eq!(evidence_node.metadata.get("sensor_type"), Some(&"temperature".to_string()));
        assert_eq!(evidence_node.metadata.get("location"), Some(&"server_room".to_string()));

        let edge = CausationEdge::new(
            "evidence-1", "decision-1", DecisionFactor::PosteriorProbability, 100_000, 1500
        ).with_metadata("confidence", "high");

        assert_eq!(edge.metadata.get("confidence"), Some(&"high".to_string()));

        let graph = CausationGraph::new("test-graph", SecurityEpoch::from_raw(1))
            .with_metadata("analysis_type", "forensic");

        assert_eq!(graph.metadata.get("analysis_type"), Some(&"forensic".to_string()));
    }
}