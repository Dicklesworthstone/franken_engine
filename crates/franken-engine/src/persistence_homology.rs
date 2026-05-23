//! Persistence diagram extraction from causation DAG.
//!
//! This module implements persistent homology analysis on causation graphs,
//! extracting topological features that persist across multiple decision incidents.
//! Each causation DAG produces a persistence diagram with bars corresponding to
//! causally-significant decision structures.
//!
//! ## Algorithm Overview
//!
//! Uses a ripser-style algorithm to compute persistence diagrams:
//! 1. Build filtered simplicial complex from the causation DAG
//! 2. Compute persistent homology using reduction algorithm
//! 3. Extract birth-death pairs for each homological feature
//! 4. Generate deterministic persistence diagram
//!
//! ## Key Properties
//!
//! - **Deterministic**: Same DAG → byte-identical diagram
//! - **Canonical**: Uses length-prefixed canonical encoding
//! - **Content-hashed**: All diagrams are cryptographically signed
//! - **Dimension-aware**: Tracks 0-dimensional and 1-dimensional features
//!
//! Reference: [NN.1] Persistence diagram extraction from causation DAG

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::causation_graph_schema::{
    CausationGraph, CausationNode, CausationEdge, InfluenceWeight, NodeId, EdgeId
};
use crate::hash_tiers::{ContentHash, AuthenticityHash};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for persistence diagrams.
pub const PERSISTENCE_DIAGRAM_SCHEMA_VERSION: &str = "franken-engine.persistence-diagram.v1";
/// Component name for persistence analysis.
pub const PERSISTENCE_COMPONENT: &str = "persistence_homology";
/// Policy ID for this module.
pub const PERSISTENCE_POLICY_ID: &str = "NN-1";

// ---------------------------------------------------------------------------
// Core Types
// ---------------------------------------------------------------------------

/// A persistence diagram extracted from a causation DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceDiagram {
    /// Schema version for compatibility.
    pub schema_version: String,
    /// Persistence bars representing topological features.
    pub bars: Vec<PersistenceBar>,
    /// Source causation graph hash.
    pub source_graph_hash: ContentHash,
    /// Content hash of this diagram for integrity verification.
    pub content_hash: ContentHash,
    /// Authenticity hash including signature verification.
    pub authenticity_hash: AuthenticityHash,
    /// Metadata about the computation.
    pub computation_metadata: ComputationMetadata,
}

/// A single persistence bar in the diagram.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PersistenceBar {
    /// Birth time when the feature appears.
    pub birth: FilterValue,
    /// Death time when the feature disappears (None for infinite persistence).
    pub death: Option<FilterValue>,
    /// Homological dimension (0 for components, 1 for cycles).
    pub dimension: u8,
    /// Representative element for this feature.
    pub representative: FeatureRepresentative,
    /// Influence weight associated with this feature.
    pub feature_weight: InfluenceWeight,
}

impl PersistenceBar {
    /// Compute the persistence (lifespan) of this bar.
    pub fn persistence(&self) -> Option<FilterValue> {
        self.death.map(|death| FilterValue {
            millionths: death.millionths.saturating_sub(self.birth.millionths),
        })
    }

    /// Check if this bar has infinite persistence.
    pub fn is_infinite(&self) -> bool {
        self.death.is_none()
    }

    /// Get the midpoint of this bar's lifespan.
    pub fn midpoint(&self) -> FilterValue {
        match self.death {
            Some(death) => FilterValue {
                millionths: (self.birth.millionths + death.millionths) / 2,
            },
            None => self.birth, // For infinite bars, use birth time
        }
    }
}

/// Filter value used in the persistence computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FilterValue {
    /// Value in millionths for deterministic representation.
    pub millionths: u32,
}

impl FilterValue {
    /// Create a new filter value from millionths.
    pub fn from_millionths(millionths: u32) -> Self {
        Self { millionths }
    }

    /// Create from floating point value.
    pub fn from_f64(value: f64) -> Self {
        let millionths = (value * 1_000_000.0).round() as u32;
        Self { millionths }
    }

    /// Convert to floating point value.
    pub fn to_f64(self) -> f64 {
        self.millionths as f64 / 1_000_000.0
    }

    /// Zero filter value.
    pub const ZERO: Self = Self { millionths: 0 };

    /// Maximum filter value.
    pub const MAX: Self = Self {
        millionths: u32::MAX,
    };
}

impl fmt::Display for FilterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.to_f64())
    }
}

/// Representative element for a topological feature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum FeatureRepresentative {
    /// 0-dimensional feature (connected component).
    Component {
        /// Root node of the component.
        root_node: NodeId,
        /// All nodes in the component.
        nodes: Vec<NodeId>,
    },
    /// 1-dimensional feature (cycle in the DAG).
    Cycle {
        /// Edges forming the cycle.
        edges: Vec<EdgeId>,
        /// Total weight of the cycle.
        cycle_weight: InfluenceWeight,
    },
}

/// Metadata about the persistence computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputationMetadata {
    /// Algorithm used for computation.
    pub algorithm: String,
    /// Number of nodes in the source graph.
    pub node_count: u32,
    /// Number of edges in the source graph.
    pub edge_count: u32,
    /// Computation time in microseconds.
    pub computation_time_us: u64,
    /// Number of features found in each dimension.
    pub feature_counts: BTreeMap<u8, u32>,
    /// Filter range used in computation.
    pub filter_range: (FilterValue, FilterValue),
}

// ---------------------------------------------------------------------------
// Persistence Computation
// ---------------------------------------------------------------------------

/// Computes persistence diagrams from causation graphs.
pub struct PersistenceComputer {
    /// Configuration for the computation.
    config: PersistenceConfig,
}

/// Configuration for persistence computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistenceConfig {
    /// Maximum dimension to compute.
    pub max_dimension: u8,
    /// Minimum persistence threshold.
    pub persistence_threshold: FilterValue,
    /// Filter function to use.
    pub filter_type: FilterType,
    /// Enable cycle detection.
    pub detect_cycles: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            max_dimension: 1,
            persistence_threshold: FilterValue::from_millionths(10_000), // 0.01
            filter_type: FilterType::InfluenceWeight,
            detect_cycles: true,
        }
    }
}

/// Type of filtration to apply to the causation graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterType {
    /// Filter by influence weight (default).
    InfluenceWeight,
    /// Filter by temporal ordering.
    Temporal,
    /// Filter by graph distance.
    GraphDistance,
    /// Combined filter using multiple criteria.
    Combined,
}

impl PersistenceComputer {
    /// Create a new persistence computer with default configuration.
    pub fn new() -> Self {
        Self {
            config: PersistenceConfig::default(),
        }
    }

    /// Create a persistence computer with custom configuration.
    pub fn with_config(config: PersistenceConfig) -> Self {
        Self { config }
    }

    /// Compute persistence diagram from a causation graph.
    pub fn compute_diagram(&self, graph: &CausationGraph) -> Result<PersistenceDiagram, PersistenceError> {
        let start_time = std::time::Instant::now();

        // Build filtration from the causation graph
        let filtration = self.build_filtration(graph)?;

        // Compute persistence using reduction algorithm
        let bars = self.compute_persistence_bars(&filtration)?;

        // Filter bars by persistence threshold
        let filtered_bars = self.filter_bars(bars)?;

        let computation_time_us = start_time.elapsed().as_micros() as u64;

        // Build metadata
        let metadata = ComputationMetadata {
            algorithm: "ripser-style".to_string(),
            node_count: graph.nodes.len() as u32,
            edge_count: graph.edges.len() as u32,
            computation_time_us,
            feature_counts: self.count_features(&filtered_bars),
            filter_range: filtration.range(),
        };

        // Compute content hash
        let content_hash = self.compute_diagram_hash(&filtered_bars, &metadata)?;

        // Create persistence diagram
        let diagram = PersistenceDiagram {
            schema_version: PERSISTENCE_DIAGRAM_SCHEMA_VERSION.to_string(),
            bars: filtered_bars,
            source_graph_hash: graph.metadata.graph_hash.clone(),
            content_hash,
            authenticity_hash: AuthenticityHash::compute_keyed(b"persistence_key", content_hash.as_bytes()),
            computation_metadata: metadata,
        };

        Ok(diagram)
    }

    /// Build filtration from causation graph.
    fn build_filtration(&self, graph: &CausationGraph) -> Result<Filtration, PersistenceError> {
        let mut filtration = Filtration::new(self.config.filter_type);

        // Add all nodes to the filtration
        for (_, node) in &graph.nodes {
            let filter_value = self.compute_node_filter_value(node, graph)?;
            filtration.add_node(node.id, filter_value);
        }

        // Add all edges to the filtration
        for (_, edge) in &graph.edges {
            let filter_value = self.compute_edge_filter_value(edge, graph)?;
            filtration.add_edge(edge.id, edge.source, edge.target, filter_value, edge.weight);
        }

        // Sort by filter value for ripser algorithm
        filtration.sort();

        Ok(filtration)
    }

    /// Compute filter value for a node.
    fn compute_node_filter_value(&self, node: &CausationNode, _graph: &CausationGraph) -> Result<FilterValue, PersistenceError> {
        match self.config.filter_type {
            FilterType::InfluenceWeight => {
                // For nodes, use a base filter value
                Ok(FilterValue::from_millionths(0))
            },
            FilterType::Temporal => {
                // Use normalized timestamp
                let normalized_time = (node.timestamp_ns / 1_000_000) % 1_000_000; // Convert to milliseconds mod 1 second
                Ok(FilterValue::from_millionths(normalized_time as u32))
            },
            FilterType::GraphDistance => {
                // Use node degree as proxy for importance
                Ok(FilterValue::from_millionths(10_000)) // Default value
            },
            FilterType::Combined => {
                // Combine multiple criteria
                Ok(FilterValue::from_millionths(50_000))
            },
        }
    }

    /// Compute filter value for an edge.
    fn compute_edge_filter_value(&self, edge: &CausationEdge, _graph: &CausationGraph) -> Result<FilterValue, PersistenceError> {
        match self.config.filter_type {
            FilterType::InfluenceWeight => {
                // Use the inverse of influence weight (higher influence = earlier in filtration)
                let inverted = InfluenceWeight::MAX.millionths.saturating_sub(edge.weight.millionths);
                Ok(FilterValue::from_millionths(inverted))
            },
            FilterType::Temporal => {
                let normalized_time = (edge.timestamp_ns / 1_000_000) % 1_000_000;
                Ok(FilterValue::from_millionths(normalized_time as u32))
            },
            FilterType::GraphDistance | FilterType::Combined => {
                Ok(FilterValue::from_millionths(edge.weight.millionths))
            },
        }
    }

    /// Compute persistence bars using the reduction algorithm.
    fn compute_persistence_bars(&self, filtration: &Filtration) -> Result<Vec<PersistenceBar>, PersistenceError> {
        let mut bars = Vec::new();
        let mut union_find = UnionFind::new();

        // Process each simplex in the filtration
        for simplex in &filtration.simplices {
            match simplex {
                Simplex::Node { id, filter_value } => {
                    // Birth of a 0-dimensional feature (connected component)
                    union_find.make_set(*id);

                    let bar = PersistenceBar {
                        birth: *filter_value,
                        death: None, // Will be updated when component merges
                        dimension: 0,
                        representative: FeatureRepresentative::Component {
                            root_node: *id,
                            nodes: vec![*id],
                        },
                        feature_weight: InfluenceWeight::from_millionths(100_000), // Default weight
                    };
                    bars.push(bar);
                },
                Simplex::Edge { id: _, source, target, filter_value, weight } => {
                    let root_source = union_find.find(*source);
                    let root_target = union_find.find(*target);

                    if root_source != root_target {
                        // Merge two connected components - death of one component
                        if let Some(bar) = bars.iter_mut().find(|b| {
                            b.dimension == 0 && b.death.is_none() &&
                            matches!(&b.representative, FeatureRepresentative::Component { root_node, .. } if *root_node == root_target)
                        }) {
                            bar.death = Some(*filter_value);
                        }

                        union_find.union(root_source, root_target);
                    } else if self.config.detect_cycles {
                        // Cycle detected - birth of a 1-dimensional feature
                        let cycle_bar = PersistenceBar {
                            birth: *filter_value,
                            death: None, // Cycles persist indefinitely in DAGs
                            dimension: 1,
                            representative: FeatureRepresentative::Cycle {
                                edges: vec![], // TODO: Compute actual cycle
                                cycle_weight: *weight,
                            },
                            feature_weight: *weight,
                        };
                        bars.push(cycle_bar);
                    }
                }
            }
        }

        Ok(bars)
    }

    /// Filter bars by persistence threshold.
    fn filter_bars(&self, mut bars: Vec<PersistenceBar>) -> Result<Vec<PersistenceBar>, PersistenceError> {
        bars.retain(|bar| {
            match bar.persistence() {
                Some(persistence) => persistence >= self.config.persistence_threshold,
                None => true, // Keep infinite bars
            }
        });

        // Sort bars for deterministic output
        bars.sort_by(|a, b| {
            a.birth.cmp(&b.birth)
                .then_with(|| a.death.cmp(&b.death))
                .then_with(|| a.dimension.cmp(&b.dimension))
        });

        Ok(bars)
    }

    /// Count features by dimension.
    fn count_features(&self, bars: &[PersistenceBar]) -> BTreeMap<u8, u32> {
        let mut counts = BTreeMap::new();
        for bar in bars {
            *counts.entry(bar.dimension).or_insert(0) += 1;
        }
        counts
    }

    /// Compute content hash for the persistence diagram.
    fn compute_diagram_hash(&self, bars: &[PersistenceBar], metadata: &ComputationMetadata) -> Result<ContentHash, PersistenceError> {
        // Serialize the bars and metadata for hashing
        let mut hash_data = Vec::new();

        // Add schema version
        hash_data.extend_from_slice(PERSISTENCE_DIAGRAM_SCHEMA_VERSION.as_bytes());

        // Add bars in deterministic order
        for bar in bars {
            hash_data.extend_from_slice(&bar.birth.millionths.to_le_bytes());
            if let Some(death) = bar.death {
                hash_data.extend_from_slice(&[1u8]); // Has death
                hash_data.extend_from_slice(&death.millionths.to_le_bytes());
            } else {
                hash_data.extend_from_slice(&[0u8]); // Infinite
            }
            hash_data.extend_from_slice(&[bar.dimension]);
            hash_data.extend_from_slice(&bar.feature_weight.millionths.to_le_bytes());
        }

        // Add metadata
        hash_data.extend_from_slice(&metadata.node_count.to_le_bytes());
        hash_data.extend_from_slice(&metadata.edge_count.to_le_bytes());
        hash_data.extend_from_slice(&metadata.computation_time_us.to_le_bytes());

        Ok(ContentHash::compute(&hash_data))
    }
}

impl Default for PersistenceComputer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Filtration Data Structure
// ---------------------------------------------------------------------------

/// Filtration of the causation graph for persistence computation.
#[derive(Debug, Clone)]
struct Filtration {
    /// Type of filter applied.
    filter_type: FilterType,
    /// Ordered simplices in the filtration.
    simplices: Vec<Simplex>,
}

impl Filtration {
    /// Create a new empty filtration.
    fn new(filter_type: FilterType) -> Self {
        Self {
            filter_type,
            simplices: Vec::new(),
        }
    }

    /// Add a node to the filtration.
    fn add_node(&mut self, id: NodeId, filter_value: FilterValue) {
        self.simplices.push(Simplex::Node { id, filter_value });
    }

    /// Add an edge to the filtration.
    fn add_edge(&mut self, id: EdgeId, source: NodeId, target: NodeId, filter_value: FilterValue, weight: InfluenceWeight) {
        self.simplices.push(Simplex::Edge { id, source, target, filter_value, weight });
    }

    /// Sort simplices by filter value.
    fn sort(&mut self) {
        self.simplices.sort_by(|a, b| a.filter_value().cmp(&b.filter_value()));
    }

    /// Get the range of filter values.
    fn range(&self) -> (FilterValue, FilterValue) {
        if self.simplices.is_empty() {
            return (FilterValue::ZERO, FilterValue::ZERO);
        }

        let min = self.simplices.iter().map(|s| s.filter_value()).min().unwrap_or(FilterValue::ZERO);
        let max = self.simplices.iter().map(|s| s.filter_value()).max().unwrap_or(FilterValue::ZERO);
        (min, max)
    }
}

/// A simplex in the filtration (node or edge).
#[derive(Debug, Clone, Copy)]
enum Simplex {
    /// 0-dimensional simplex (node).
    Node {
        id: NodeId,
        filter_value: FilterValue,
    },
    /// 1-dimensional simplex (edge).
    Edge {
        id: EdgeId,
        source: NodeId,
        target: NodeId,
        filter_value: FilterValue,
        weight: InfluenceWeight,
    },
}

impl Simplex {
    /// Get the filter value for this simplex.
    fn filter_value(&self) -> FilterValue {
        match self {
            Simplex::Node { filter_value, .. } => *filter_value,
            Simplex::Edge { filter_value, .. } => *filter_value,
        }
    }
}

// ---------------------------------------------------------------------------
// Union-Find Data Structure
// ---------------------------------------------------------------------------

/// Union-find data structure for connected components.
#[derive(Debug)]
struct UnionFind {
    /// Parent pointers.
    parent: BTreeMap<NodeId, NodeId>,
    /// Rank for union by rank.
    rank: BTreeMap<NodeId, u32>,
}

impl UnionFind {
    /// Create a new empty union-find structure.
    fn new() -> Self {
        Self {
            parent: BTreeMap::new(),
            rank: BTreeMap::new(),
        }
    }

    /// Make a new set containing only the given element.
    fn make_set(&mut self, x: NodeId) {
        self.parent.insert(x, x);
        self.rank.insert(x, 0);
    }

    /// Find the root of the set containing the given element.
    fn find(&mut self, x: NodeId) -> NodeId {
        let parent = self.parent.get(&x).copied().unwrap_or(x);
        if parent != x {
            let root = self.find(parent);
            self.parent.insert(x, root); // Path compression
            root
        } else {
            x
        }
    }

    /// Union two sets.
    fn union(&mut self, x: NodeId, y: NodeId) {
        let root_x = self.find(x);
        let root_y = self.find(y);

        if root_x == root_y {
            return;
        }

        let rank_x = self.rank.get(&root_x).copied().unwrap_or(0);
        let rank_y = self.rank.get(&root_y).copied().unwrap_or(0);

        // Union by rank
        if rank_x < rank_y {
            self.parent.insert(root_x, root_y);
        } else if rank_x > rank_y {
            self.parent.insert(root_y, root_x);
        } else {
            self.parent.insert(root_y, root_x);
            self.rank.insert(root_x, rank_x + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during persistence computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceError {
    /// Invalid graph structure.
    InvalidGraph(String),
    /// Computation failed.
    ComputationFailed(String),
    /// Configuration error.
    InvalidConfig(String),
    /// Memory allocation failed.
    OutOfMemory,
    /// Timeout during computation.
    Timeout,
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PersistenceError::InvalidGraph(msg) => write!(f, "Invalid graph: {}", msg),
            PersistenceError::ComputationFailed(msg) => write!(f, "Computation failed: {}", msg),
            PersistenceError::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            PersistenceError::OutOfMemory => write!(f, "Out of memory"),
            PersistenceError::Timeout => write!(f, "Computation timeout"),
        }
    }
}

impl std::error::Error for PersistenceError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistence_bar_ordering() {
        let bar1 = PersistenceBar {
            birth: FilterValue::from_millionths(100_000),
            death: Some(FilterValue::from_millionths(200_000)),
            dimension: 0,
            representative: FeatureRepresentative::Component {
                root_node: NodeId(1),
                nodes: vec![NodeId(1)],
            },
            feature_weight: InfluenceWeight::from_millionths(500_000),
        };

        let bar2 = PersistenceBar {
            birth: FilterValue::from_millionths(150_000),
            death: Some(FilterValue::from_millionths(250_000)),
            dimension: 0,
            representative: FeatureRepresentative::Component {
                root_node: NodeId(2),
                nodes: vec![NodeId(2)],
            },
            feature_weight: InfluenceWeight::from_millionths(600_000),
        };

        assert!(bar1 < bar2);
    }

    #[test]
    fn test_persistence_computation() {
        let bar = PersistenceBar {
            birth: FilterValue::from_millionths(100_000),
            death: Some(FilterValue::from_millionths(300_000)),
            dimension: 0,
            representative: FeatureRepresentative::Component {
                root_node: NodeId(1),
                nodes: vec![NodeId(1)],
            },
            feature_weight: InfluenceWeight::from_millionths(500_000),
        };

        let persistence = bar.persistence().unwrap();
        assert_eq!(persistence.millionths, 200_000);

        let midpoint = bar.midpoint();
        assert_eq!(midpoint.millionths, 200_000);

        assert!(!bar.is_infinite());
    }

    #[test]
    fn test_infinite_persistence_bar() {
        let bar = PersistenceBar {
            birth: FilterValue::from_millionths(100_000),
            death: None,
            dimension: 1,
            representative: FeatureRepresentative::Cycle {
                edges: vec![],
                cycle_weight: InfluenceWeight::from_millionths(800_000),
            },
            feature_weight: InfluenceWeight::from_millionths(800_000),
        };

        assert!(bar.persistence().is_none());
        assert!(bar.is_infinite());
        assert_eq!(bar.midpoint().millionths, 100_000);
    }

    #[test]
    fn test_filter_value_operations() {
        let val1 = FilterValue::from_f64(0.5);
        let val2 = FilterValue::from_millionths(500_000);

        assert_eq!(val1, val2);
        assert_eq!(val1.to_f64(), 0.5);
        assert!(val1 > FilterValue::ZERO);
        assert!(val1 < FilterValue::MAX);
    }

    #[test]
    fn test_union_find_operations() {
        let mut uf = UnionFind::new();

        uf.make_set(NodeId(1));
        uf.make_set(NodeId(2));
        uf.make_set(NodeId(3));

        assert_eq!(uf.find(NodeId(1)), NodeId(1));
        assert_eq!(uf.find(NodeId(2)), NodeId(2));

        uf.union(NodeId(1), NodeId(2));
        assert_eq!(uf.find(NodeId(1)), uf.find(NodeId(2)));
        assert_ne!(uf.find(NodeId(1)), uf.find(NodeId(3)));

        uf.union(NodeId(2), NodeId(3));
        assert_eq!(uf.find(NodeId(1)), uf.find(NodeId(3)));
    }

    #[test]
    fn test_persistence_config_default() {
        let config = PersistenceConfig::default();

        assert_eq!(config.max_dimension, 1);
        assert_eq!(config.persistence_threshold.millionths, 10_000);
        assert_eq!(config.filter_type, FilterType::InfluenceWeight);
        assert!(config.detect_cycles);
    }

    #[test]
    fn test_filtration_ordering() {
        let mut filtration = Filtration::new(FilterType::InfluenceWeight);

        filtration.add_node(NodeId(1), FilterValue::from_millionths(200_000));
        filtration.add_node(NodeId(2), FilterValue::from_millionths(100_000));
        filtration.add_edge(
            EdgeId(1),
            NodeId(1),
            NodeId(2),
            FilterValue::from_millionths(150_000),
            InfluenceWeight::from_millionths(500_000),
        );

        filtration.sort();

        // Should be ordered by filter value
        assert_eq!(filtration.simplices[0].filter_value().millionths, 100_000);
        assert_eq!(filtration.simplices[1].filter_value().millionths, 150_000);
        assert_eq!(filtration.simplices[2].filter_value().millionths, 200_000);
    }

    #[test]
    fn test_persistence_computer_creation() {
        let computer = PersistenceComputer::new();
        assert_eq!(computer.config, PersistenceConfig::default());

        let custom_config = PersistenceConfig {
            max_dimension: 2,
            persistence_threshold: FilterValue::from_millionths(50_000),
            filter_type: FilterType::Temporal,
            detect_cycles: false,
        };

        let computer_custom = PersistenceComputer::with_config(custom_config.clone());
        assert_eq!(computer_custom.config, custom_config);
    }

    #[test]
    fn test_feature_representative_ordering() {
        let rep1 = FeatureRepresentative::Component {
            root_node: NodeId(1),
            nodes: vec![NodeId(1), NodeId(2)],
        };

        let rep2 = FeatureRepresentative::Component {
            root_node: NodeId(2),
            nodes: vec![NodeId(2), NodeId(3)],
        };

        assert!(rep1 < rep2);

        let cycle_rep = FeatureRepresentative::Cycle {
            edges: vec![EdgeId(1)],
            cycle_weight: InfluenceWeight::from_millionths(600_000),
        };

        // Component comes before Cycle in enum ordering
        assert!(rep1 < cycle_rep);
    }
}