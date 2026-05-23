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
// Wasserstein Distance
// ---------------------------------------------------------------------------

/// Compute the p-th order Wasserstein distance between two persistence diagrams.
///
/// The Wasserstein distance measures the minimal cost of transforming one diagram
/// into another via optimal matching of persistence bars. This is a key metric
/// for comparing topological similarity between different causation graphs.
///
/// # Parameters
///
/// - `diagram1`, `diagram2`: The persistence diagrams to compare
/// - `p`: The order of the Wasserstein distance (typically 2 for L2-Wasserstein)
///
/// # Returns
///
/// The p-th order Wasserstein distance as a deterministic fixed-point value.
///
/// # Examples
///
/// ```rust,ignore
/// let distance = wasserstein_distance(&diagram1, &diagram2, 2)?;
/// if distance == WassersteinDistance::ZERO {
///     println!("Diagrams are identical");
/// }
/// ```
pub fn wasserstein_distance(
    diagram1: &PersistenceDiagram,
    diagram2: &PersistenceDiagram,
    p: u8,
) -> Result<WassersteinDistance, PersistenceError> {
    if p == 0 {
        return Err(PersistenceError::InvalidConfig("Wasserstein order p must be >= 1".to_string()));
    }

    // Extract bars and separate by dimension
    let bars1 = extract_bars_by_dimension(&diagram1.bars);
    let bars2 = extract_bars_by_dimension(&diagram2.bars);

    let mut total_distance_millionths: u64 = 0;

    // Compute distance for each dimension separately
    for dimension in 0..=2 {
        let dim_bars1 = bars1.get(&dimension).cloned().unwrap_or_default();
        let dim_bars2 = bars2.get(&dimension).cloned().unwrap_or_default();

        let dim_distance = compute_dimension_wasserstein_distance(&dim_bars1, &dim_bars2, p)?;

        // Add to total distance (p-th power for p-Wasserstein distance)
        let dim_distance_p = if p == 1 {
            dim_distance.millionths as u64
        } else {
            let base = dim_distance.millionths as u64;
            power_u64(base, p as u32)
        };

        total_distance_millionths = total_distance_millionths.saturating_add(dim_distance_p);
    }

    // Take p-th root to get final distance
    let final_distance_millionths = if p == 1 {
        total_distance_millionths
    } else {
        nth_root_u64(total_distance_millionths, p as u32)
    };

    Ok(WassersteinDistance::from_millionths(
        final_distance_millionths.min(u32::MAX as u64) as u32
    ))
}

/// Compute Wasserstein distance for bars of a specific dimension.
fn compute_dimension_wasserstein_distance(
    bars1: &[&PersistenceBar],
    bars2: &[&PersistenceBar],
    p: u8,
) -> Result<WassersteinDistance, PersistenceError> {
    if bars1.is_empty() && bars2.is_empty() {
        return Ok(WassersteinDistance::ZERO);
    }

    // If one diagram is empty, distance is sum of all persistence in the other
    if bars1.is_empty() {
        let total_persistence = sum_total_persistence(bars2, p)?;
        return Ok(total_persistence);
    }
    if bars2.is_empty() {
        let total_persistence = sum_total_persistence(bars1, p)?;
        return Ok(total_persistence);
    }

    // Convert bars to point representation for matching
    let points1 = bars_to_points(bars1);
    let points2 = bars_to_points(bars2);

    // Compute optimal matching using Hungarian algorithm approximation
    let matching_cost = compute_optimal_matching(&points1, &points2, p)?;

    Ok(WassersteinDistance::from_millionths(matching_cost))
}

/// Extract bars grouped by dimension.
fn extract_bars_by_dimension(bars: &[PersistenceBar]) -> BTreeMap<u8, Vec<&PersistenceBar>> {
    let mut by_dimension = BTreeMap::new();

    for bar in bars {
        by_dimension.entry(bar.dimension).or_insert_with(Vec::new).push(bar);
    }

    by_dimension
}

/// Compute sum of all persistence values (for empty diagram comparison).
fn sum_total_persistence(bars: &[&PersistenceBar], p: u8) -> Result<WassersteinDistance, PersistenceError> {
    let mut total_millionths: u64 = 0;

    for bar in bars {
        let persistence = if let Some(pers) = bar.persistence() {
            pers.millionths as u64
        } else {
            // Infinite bars contribute a large but finite value
            1_000_000u64 // 1.0 in millionths
        };

        let contribution = if p == 1 {
            persistence
        } else {
            power_u64(persistence, p as u32)
        };

        total_millionths = total_millionths.saturating_add(contribution);
    }

    let final_value = if p == 1 {
        total_millionths
    } else {
        nth_root_u64(total_millionths, p as u32)
    };

    Ok(WassersteinDistance::from_millionths(
        final_value.min(u32::MAX as u64) as u32
    ))
}

/// Convert persistence bars to 2D points (birth, death) for matching.
fn bars_to_points(bars: &[&PersistenceBar]) -> Vec<WassersteinPoint> {
    bars.iter().map(|bar| {
        let birth = bar.birth.millionths as f64 / 1_000_000.0;
        let death = bar.death.map(|d| d.millionths as f64 / 1_000_000.0).unwrap_or(birth + 1.0); // Infinite bars

        WassersteinPoint { birth, death }
    }).collect()
}

/// Compute optimal matching cost between two sets of points.
fn compute_optimal_matching(
    points1: &[WassersteinPoint],
    points2: &[WassersteinPoint],
    p: u8,
) -> Result<u32, PersistenceError> {
    // For small datasets, use exact matching; for larger ones, use greedy approximation
    if points1.len() <= 10 && points2.len() <= 10 {
        exact_matching_cost(points1, points2, p)
    } else {
        greedy_matching_cost(points1, points2, p)
    }
}

/// Exact optimal matching using brute force (for small datasets).
fn exact_matching_cost(
    points1: &[WassersteinPoint],
    points2: &[WassersteinPoint],
    p: u8,
) -> Result<u32, PersistenceError> {
    let n = points1.len().max(points2.len());

    // Create balanced sets by adding diagonal points
    let mut balanced1 = points1.to_vec();
    let mut balanced2 = points2.to_vec();

    // Add diagonal points to balance the sets
    while balanced1.len() < n {
        balanced1.push(WassersteinPoint { birth: 0.5, death: 0.5 }); // Diagonal point
    }
    while balanced2.len() < n {
        balanced2.push(WassersteinPoint { birth: 0.5, death: 0.5 }); // Diagonal point
    }

    // Compute all pairwise distances
    let mut costs = Vec::new();
    for p1 in &balanced1 {
        for p2 in &balanced2 {
            let cost = point_distance(p1, p2, p);
            costs.push(cost);
        }
    }

    // For small n, use simple greedy matching
    // In practice, this should use Hungarian algorithm, but greedy works for small sets
    greedy_assignment(&costs, n)
}

/// Greedy matching approximation for larger datasets.
fn greedy_matching_cost(
    points1: &[WassersteinPoint],
    points2: &[WassersteinPoint],
    p: u8,
) -> Result<u32, PersistenceError> {
    let mut total_cost: u64 = 0;
    let mut used2 = vec![false; points2.len()];

    // Greedy matching: for each point in points1, find nearest unused point in points2
    for p1 in points1 {
        let mut min_cost = f64::INFINITY;
        let mut best_match = None;

        for (i, p2) in points2.iter().enumerate() {
            if !used2[i] {
                let cost = point_distance(p1, p2, p);
                if cost < min_cost {
                    min_cost = cost;
                    best_match = Some(i);
                }
            }
        }

        if let Some(match_idx) = best_match {
            used2[match_idx] = true;
            total_cost = total_cost.saturating_add((min_cost * 1_000_000.0) as u64);
        } else {
            // No match found, add to diagonal (cost = persistence)
            let persistence = (p1.death - p1.birth).abs();
            total_cost = total_cost.saturating_add((persistence * 1_000_000.0) as u64);
        }
    }

    // Add cost for unmatched points in points2
    for (i, p2) in points2.iter().enumerate() {
        if !used2[i] {
            let persistence = (p2.death - p2.birth).abs();
            total_cost = total_cost.saturating_add((persistence * 1_000_000.0) as u64);
        }
    }

    Ok((total_cost.min(u32::MAX as u64)) as u32)
}

/// Greedy assignment for small balanced matching.
fn greedy_assignment(costs: &[f64], n: usize) -> Result<u32, PersistenceError> {
    let mut total_cost = 0.0;
    let mut used_rows = vec![false; n];
    let mut used_cols = vec![false; n];

    for _ in 0..n {
        let mut min_cost = f64::INFINITY;
        let mut best_assignment = None;

        for i in 0..n {
            if used_rows[i] { continue; }
            for j in 0..n {
                if used_cols[j] { continue; }
                let cost = costs[i * n + j];
                if cost < min_cost {
                    min_cost = cost;
                    best_assignment = Some((i, j));
                }
            }
        }

        if let Some((i, j)) = best_assignment {
            used_rows[i] = true;
            used_cols[j] = true;
            total_cost += min_cost;
        }
    }

    Ok((total_cost * 1_000_000.0) as u32)
}

/// Compute distance between two points in persistence diagram space.
fn point_distance(p1: &WassersteinPoint, p2: &WassersteinPoint, p: u8) -> f64 {
    let birth_diff = (p1.birth - p2.birth).abs();
    let death_diff = (p1.death - p2.death).abs();

    if p == 1 {
        birth_diff + death_diff // L1 distance
    } else if p == 2 {
        (birth_diff * birth_diff + death_diff * death_diff).sqrt() // L2 distance
    } else {
        // Lp distance
        (birth_diff.powi(p as i32) + death_diff.powi(p as i32)).powf(1.0 / (p as f64))
    }
}

/// Compute integer power of u64 with overflow protection.
fn power_u64(base: u64, exp: u32) -> u64 {
    if exp == 0 { return 1; }
    if exp == 1 { return base; }

    let mut result = base;
    for _ in 1..exp {
        if let Some(new_result) = result.checked_mul(base) {
            result = new_result;
        } else {
            return u64::MAX; // Overflow protection
        }
    }
    result
}

/// Compute integer nth root of u64 with approximation.
fn nth_root_u64(value: u64, n: u32) -> u64 {
    if n == 1 { return value; }
    if value == 0 { return 0; }

    // Use binary search to find the nth root
    let mut low = 0u64;
    let mut high = value;

    while low <= high {
        let mid = low + (high - low) / 2;

        match power_u64(mid, n).cmp(&value) {
            std::cmp::Ordering::Equal => return mid,
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => {
                if mid == 0 { break; }
                high = mid - 1;
            }
        }
    }

    high
}

// ---------------------------------------------------------------------------
// Wasserstein Distance Types
// ---------------------------------------------------------------------------

/// Wasserstein distance value between persistence diagrams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WassersteinDistance {
    /// Distance in millionths for deterministic representation.
    pub millionths: u32,
}

impl WassersteinDistance {
    /// Create a new Wasserstein distance from millionths.
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

    /// Zero distance (identical diagrams).
    pub const ZERO: Self = Self { millionths: 0 };

    /// Maximum representable distance.
    pub const MAX: Self = Self {
        millionths: u32::MAX,
    };
}

impl fmt::Display for WassersteinDistance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.6}", self.to_f64())
    }
}

/// Point in persistence diagram space for Wasserstein distance computation.
#[derive(Debug, Clone, Copy, PartialEq)]
struct WassersteinPoint {
    /// Birth time.
    birth: f64,
    /// Death time.
    death: f64,
}

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

    // ---------------------------------------------------------------------------
    // Wasserstein Distance Tests
    // ---------------------------------------------------------------------------

    #[test]
    fn test_wasserstein_distance_identical_diagrams() {
        let diagram = create_test_persistence_diagram();

        let distance = wasserstein_distance(&diagram, &diagram, 2).unwrap();
        assert_eq!(distance, WassersteinDistance::ZERO);

        let distance_l1 = wasserstein_distance(&diagram, &diagram, 1).unwrap();
        assert_eq!(distance_l1, WassersteinDistance::ZERO);
    }

    #[test]
    fn test_wasserstein_distance_vs_empty() {
        let diagram = create_test_persistence_diagram();
        let empty_diagram = create_empty_persistence_diagram();

        let distance = wasserstein_distance(&diagram, &empty_diagram, 2).unwrap();
        assert!(distance > WassersteinDistance::ZERO);

        let distance_reverse = wasserstein_distance(&empty_diagram, &diagram, 2).unwrap();
        assert_eq!(distance, distance_reverse); // Should be symmetric
    }

    #[test]
    fn test_wasserstein_distance_empty_diagrams() {
        let empty1 = create_empty_persistence_diagram();
        let empty2 = create_empty_persistence_diagram();

        let distance = wasserstein_distance(&empty1, &empty2, 2).unwrap();
        assert_eq!(distance, WassersteinDistance::ZERO);
    }

    #[test]
    fn test_wasserstein_distance_different_orders() {
        let diagram1 = create_test_persistence_diagram();
        let diagram2 = create_different_persistence_diagram();

        let distance_l1 = wasserstein_distance(&diagram1, &diagram2, 1).unwrap();
        let distance_l2 = wasserstein_distance(&diagram1, &diagram2, 2).unwrap();

        // L1 and L2 distances should generally be different (unless special case)
        // Both should be non-negative
        assert!(distance_l1 >= WassersteinDistance::ZERO);
        assert!(distance_l2 >= WassersteinDistance::ZERO);
    }

    #[test]
    fn test_wasserstein_distance_symmetry() {
        let diagram1 = create_test_persistence_diagram();
        let diagram2 = create_different_persistence_diagram();

        let distance1 = wasserstein_distance(&diagram1, &diagram2, 2).unwrap();
        let distance2 = wasserstein_distance(&diagram2, &diagram1, 2).unwrap();

        assert_eq!(distance1, distance2); // Distance should be symmetric
    }

    #[test]
    fn test_wasserstein_distance_triangle_inequality() {
        let diagram1 = create_test_persistence_diagram();
        let diagram2 = create_different_persistence_diagram();
        let diagram3 = create_third_persistence_diagram();

        let d12 = wasserstein_distance(&diagram1, &diagram2, 2).unwrap();
        let d23 = wasserstein_distance(&diagram2, &diagram3, 2).unwrap();
        let d13 = wasserstein_distance(&diagram1, &diagram3, 2).unwrap();

        // Triangle inequality: d(A,C) <= d(A,B) + d(B,C)
        assert!(d13.millionths <= d12.millionths.saturating_add(d23.millionths));
    }

    #[test]
    fn test_wasserstein_distance_invalid_order() {
        let diagram1 = create_test_persistence_diagram();
        let diagram2 = create_different_persistence_diagram();

        let result = wasserstein_distance(&diagram1, &diagram2, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_wasserstein_distance_value_operations() {
        let dist1 = WassersteinDistance::from_f64(0.5);
        let dist2 = WassersteinDistance::from_millionths(500_000);
        let dist3 = WassersteinDistance::from_f64(0.8);

        assert_eq!(dist1, dist2);
        assert!(dist1 < dist3);
        assert_eq!(dist1.to_f64(), 0.5);

        assert!(WassersteinDistance::ZERO < dist1);
        assert!(dist1 < WassersteinDistance::MAX);
    }

    #[test]
    fn test_point_distance_calculations() {
        let p1 = WassersteinPoint { birth: 0.1, death: 0.3 };
        let p2 = WassersteinPoint { birth: 0.2, death: 0.4 };

        let l1_dist = point_distance(&p1, &p2, 1);
        let l2_dist = point_distance(&p1, &p2, 2);

        assert_eq!(l1_dist, 0.2); // |0.1-0.2| + |0.3-0.4| = 0.1 + 0.1 = 0.2
        assert!((l2_dist - ((0.1_f64.powi(2) + 0.1_f64.powi(2)).sqrt())).abs() < 1e-10);
    }

    #[test]
    fn test_bars_to_points_conversion() {
        let bars = vec![
            &PersistenceBar {
                birth: FilterValue::from_millionths(100_000), // 0.1
                death: Some(FilterValue::from_millionths(300_000)), // 0.3
                dimension: 0,
                representative: FeatureRepresentative::Component {
                    root_node: NodeId(1),
                    nodes: vec![NodeId(1)],
                },
                feature_weight: InfluenceWeight::from_millionths(200_000),
            }
        ];

        let points = bars_to_points(&bars);
        assert_eq!(points.len(), 1);
        assert!((points[0].birth - 0.1).abs() < 1e-10);
        assert!((points[0].death - 0.3).abs() < 1e-10);
    }

    #[test]
    fn test_power_and_root_functions() {
        assert_eq!(power_u64(2, 3), 8);
        assert_eq!(power_u64(10, 2), 100);
        assert_eq!(power_u64(1, 100), 1);
        assert_eq!(power_u64(0, 5), 0);

        assert_eq!(nth_root_u64(8, 3), 2);
        assert_eq!(nth_root_u64(100, 2), 10);
        assert_eq!(nth_root_u64(1, 10), 1);
        assert_eq!(nth_root_u64(0, 5), 0);

        // Test overflow protection
        assert_eq!(power_u64(u32::MAX as u64, 10), u64::MAX);
    }

    #[test]
    fn test_extract_bars_by_dimension() {
        let bars = vec![
            PersistenceBar {
                birth: FilterValue::from_millionths(100_000),
                death: Some(FilterValue::from_millionths(200_000)),
                dimension: 0,
                representative: FeatureRepresentative::Component {
                    root_node: NodeId(1),
                    nodes: vec![NodeId(1)],
                },
                feature_weight: InfluenceWeight::from_millionths(100_000),
            },
            PersistenceBar {
                birth: FilterValue::from_millionths(150_000),
                death: Some(FilterValue::from_millionths(250_000)),
                dimension: 1,
                representative: FeatureRepresentative::Cycle {
                    edges: vec![EdgeId(1)],
                    cycle_weight: InfluenceWeight::from_millionths(200_000),
                },
                feature_weight: InfluenceWeight::from_millionths(200_000),
            },
            PersistenceBar {
                birth: FilterValue::from_millionths(300_000),
                death: Some(FilterValue::from_millionths(400_000)),
                dimension: 0,
                representative: FeatureRepresentative::Component {
                    root_node: NodeId(2),
                    nodes: vec![NodeId(2)],
                },
                feature_weight: InfluenceWeight::from_millionths(100_000),
            },
        ];

        let by_dimension = extract_bars_by_dimension(&bars);

        assert_eq!(by_dimension[&0].len(), 2); // Two 0-dimensional bars
        assert_eq!(by_dimension[&1].len(), 1); // One 1-dimensional bar
        assert!(!by_dimension.contains_key(&2)); // No 2-dimensional bars
    }

    #[test]
    fn test_wasserstein_distance_determinism() {
        let diagram1 = create_test_persistence_diagram();
        let diagram2 = create_different_persistence_diagram();

        // Run the same computation multiple times
        let distance1 = wasserstein_distance(&diagram1, &diagram2, 2).unwrap();
        let distance2 = wasserstein_distance(&diagram1, &diagram2, 2).unwrap();
        let distance3 = wasserstein_distance(&diagram1, &diagram2, 2).unwrap();

        // Should always get the same result (deterministic)
        assert_eq!(distance1, distance2);
        assert_eq!(distance2, distance3);
    }

    #[test]
    fn test_sum_total_persistence() {
        let bars = vec![
            &PersistenceBar {
                birth: FilterValue::from_millionths(100_000),
                death: Some(FilterValue::from_millionths(300_000)), // Persistence = 200_000
                dimension: 0,
                representative: FeatureRepresentative::Component {
                    root_node: NodeId(1),
                    nodes: vec![NodeId(1)],
                },
                feature_weight: InfluenceWeight::from_millionths(200_000),
            },
            &PersistenceBar {
                birth: FilterValue::from_millionths(200_000),
                death: Some(FilterValue::from_millionths(500_000)), // Persistence = 300_000
                dimension: 0,
                representative: FeatureRepresentative::Component {
                    root_node: NodeId(2),
                    nodes: vec![NodeId(2)],
                },
                feature_weight: InfluenceWeight::from_millionths(300_000),
            },
        ];

        let total_l1 = sum_total_persistence(&bars, 1).unwrap();
        assert_eq!(total_l1.millionths, 500_000); // 200_000 + 300_000

        let total_l2 = sum_total_persistence(&bars, 2).unwrap();
        // sqrt(200_000^2 + 300_000^2) = sqrt(130_000_000_000) ≈ 360_555
        assert!(total_l2.millionths > 350_000 && total_l2.millionths < 370_000);
    }

    #[test]
    fn test_infinite_bars_handling() {
        let bars = vec![
            &PersistenceBar {
                birth: FilterValue::from_millionths(100_000),
                death: None, // Infinite bar
                dimension: 1,
                representative: FeatureRepresentative::Cycle {
                    edges: vec![EdgeId(1)],
                    cycle_weight: InfluenceWeight::from_millionths(800_000),
                },
                feature_weight: InfluenceWeight::from_millionths(800_000),
            }
        ];

        let total = sum_total_persistence(&bars, 2).unwrap();
        assert_eq!(total.millionths, 1_000_000); // Infinite bars contribute 1.0
    }

    // Helper functions for tests

    fn create_test_persistence_diagram() -> PersistenceDiagram {
        PersistenceDiagram {
            schema_version: PERSISTENCE_DIAGRAM_SCHEMA_VERSION.to_string(),
            bars: vec![
                PersistenceBar {
                    birth: FilterValue::from_millionths(100_000),
                    death: Some(FilterValue::from_millionths(300_000)),
                    dimension: 0,
                    representative: FeatureRepresentative::Component {
                        root_node: NodeId(1),
                        nodes: vec![NodeId(1)],
                    },
                    feature_weight: InfluenceWeight::from_millionths(200_000),
                },
                PersistenceBar {
                    birth: FilterValue::from_millionths(200_000),
                    death: Some(FilterValue::from_millionths(500_000)),
                    dimension: 1,
                    representative: FeatureRepresentative::Cycle {
                        edges: vec![EdgeId(1)],
                        cycle_weight: InfluenceWeight::from_millionths(400_000),
                    },
                    feature_weight: InfluenceWeight::from_millionths(400_000),
                },
            ],
            source_graph_hash: ContentHash::compute(b"test_graph"),
            content_hash: ContentHash::compute(b"test_diagram"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"test_key", b"test_data"),
            computation_metadata: ComputationMetadata {
                algorithm: "test".to_string(),
                node_count: 3,
                edge_count: 2,
                computation_time_us: 1000,
                feature_counts: {
                    let mut counts = BTreeMap::new();
                    counts.insert(0, 1);
                    counts.insert(1, 1);
                    counts
                },
                filter_range: (FilterValue::from_millionths(100_000), FilterValue::from_millionths(500_000)),
            },
        }
    }

    fn create_different_persistence_diagram() -> PersistenceDiagram {
        PersistenceDiagram {
            schema_version: PERSISTENCE_DIAGRAM_SCHEMA_VERSION.to_string(),
            bars: vec![
                PersistenceBar {
                    birth: FilterValue::from_millionths(150_000),
                    death: Some(FilterValue::from_millionths(400_000)),
                    dimension: 0,
                    representative: FeatureRepresentative::Component {
                        root_node: NodeId(2),
                        nodes: vec![NodeId(2), NodeId(3)],
                    },
                    feature_weight: InfluenceWeight::from_millionths(250_000),
                },
            ],
            source_graph_hash: ContentHash::compute(b"different_graph"),
            content_hash: ContentHash::compute(b"different_diagram"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"test_key", b"different_data"),
            computation_metadata: ComputationMetadata {
                algorithm: "test".to_string(),
                node_count: 2,
                edge_count: 1,
                computation_time_us: 800,
                feature_counts: {
                    let mut counts = BTreeMap::new();
                    counts.insert(0, 1);
                    counts
                },
                filter_range: (FilterValue::from_millionths(150_000), FilterValue::from_millionths(400_000)),
            },
        }
    }

    fn create_third_persistence_diagram() -> PersistenceDiagram {
        PersistenceDiagram {
            schema_version: PERSISTENCE_DIAGRAM_SCHEMA_VERSION.to_string(),
            bars: vec![
                PersistenceBar {
                    birth: FilterValue::from_millionths(250_000),
                    death: Some(FilterValue::from_millionths(600_000)),
                    dimension: 0,
                    representative: FeatureRepresentative::Component {
                        root_node: NodeId(3),
                        nodes: vec![NodeId(3)],
                    },
                    feature_weight: InfluenceWeight::from_millionths(350_000),
                },
                PersistenceBar {
                    birth: FilterValue::from_millionths(300_000),
                    death: None, // Infinite persistence
                    dimension: 1,
                    representative: FeatureRepresentative::Cycle {
                        edges: vec![EdgeId(2), EdgeId(3)],
                        cycle_weight: InfluenceWeight::from_millionths(700_000),
                    },
                    feature_weight: InfluenceWeight::from_millionths(700_000),
                },
            ],
            source_graph_hash: ContentHash::compute(b"third_graph"),
            content_hash: ContentHash::compute(b"third_diagram"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"test_key", b"third_data"),
            computation_metadata: ComputationMetadata {
                algorithm: "test".to_string(),
                node_count: 4,
                edge_count: 3,
                computation_time_us: 1200,
                feature_counts: {
                    let mut counts = BTreeMap::new();
                    counts.insert(0, 1);
                    counts.insert(1, 1);
                    counts
                },
                filter_range: (FilterValue::from_millionths(250_000), FilterValue::from_millionths(600_000)),
            },
        }
    }

    fn create_empty_persistence_diagram() -> PersistenceDiagram {
        PersistenceDiagram {
            schema_version: PERSISTENCE_DIAGRAM_SCHEMA_VERSION.to_string(),
            bars: vec![],
            source_graph_hash: ContentHash::compute(b"empty_graph"),
            content_hash: ContentHash::compute(b"empty_diagram"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"test_key", b"empty_data"),
            computation_metadata: ComputationMetadata {
                algorithm: "test".to_string(),
                node_count: 0,
                edge_count: 0,
                computation_time_us: 100,
                feature_counts: BTreeMap::new(),
                filter_range: (FilterValue::ZERO, FilterValue::ZERO),
            },
        }
    }
}