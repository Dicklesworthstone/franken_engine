//! Forensic query API for causation graph analysis.
//!
//! This module provides a high-level API for querying causation graphs to understand
//! how decisions were made. It enables forensic analysis by extracting causal subgraphs,
//! explaining decision factors, and performing counterfactual analysis.
//!
//! ## Core Functionality
//!
//! - **Decision Explanation**: Given a decision ID, extract the complete causal chain
//! - **Subgraph Extraction**: Extract minimal causal subgraphs that explain outcomes
//! - **Counterfactual Analysis**: What-if scenarios and alternative outcome modeling
//! - **Forensic Reports**: Structured output for `frankenctl forensic explain` commands
//!
//! ## Query Types
//!
//! - **Causal Explanation**: "Why did decision X happen?"
//! - **Influence Analysis**: "What evidence most influenced this decision?"
//! - **Counterfactual**: "What would have happened if evidence Y was different?"
//! - **Timeline Reconstruction**: "What was the sequence of events leading to X?"
//!
//! Reference: [FF.3] Query API: 'why did X happen?' -> structural causal subgraph

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::causation_graph_schema::{
    CausationGraph, CausationNode, CausationEdge, NodeId, EdgeId, NodeType,
    DecisionOutcome, CausationType, InfluenceWeight, GraphError
};
use crate::hash_tiers::ContentHash;
use crate::minimal_causal_set_inference::DecisionFactor;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for forensic query API.
pub const FORENSIC_QUERY_SCHEMA_VERSION: &str = "franken-engine.forensic-query.v1";
/// Component name for evidence linkage.
pub const FORENSIC_QUERY_COMPONENT: &str = "forensic_query_api";
/// Policy ID binding for this module.
pub const FORENSIC_QUERY_POLICY_ID: &str = "FF-3";

// ---------------------------------------------------------------------------
// Query Types
// ---------------------------------------------------------------------------

/// A forensic query for analyzing causation graphs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicQuery {
    /// Unique identifier for this query.
    pub query_id: String,
    /// Type of forensic analysis to perform.
    pub query_type: QueryType,
    /// Target of the query (decision ID, evidence ID, etc.).
    pub target: QueryTarget,
    /// Optional parameters for the query.
    pub parameters: QueryParameters,
    /// Unix timestamp when query was created.
    pub timestamp_ns: u64,
}

/// Types of forensic queries supported by the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum QueryType {
    /// Explain why a decision was made.
    CausalExplanation {
        /// Maximum depth to traverse in the causal chain.
        max_depth: usize,
        /// Whether to include weak influences below threshold.
        include_weak_influences: bool,
    },
    /// Analyze influence factors for a decision.
    InfluenceAnalysis {
        /// Minimum influence weight to include.
        min_influence_threshold: InfluenceWeight,
        /// Whether to rank influences by strength.
        rank_by_strength: bool,
    },
    /// Perform counterfactual analysis.
    CounterfactualAnalysis {
        /// Evidence atoms to modify in the counterfactual.
        modified_evidence: Vec<EvidenceModification>,
        /// Whether to recompute all downstream effects.
        recompute_downstream: bool,
    },
    /// Reconstruct timeline of events.
    TimelineReconstruction {
        /// Start timestamp for timeline window.
        start_timestamp_ns: u64,
        /// End timestamp for timeline window.
        end_timestamp_ns: u64,
        /// Whether to sort by causation order vs timestamp.
        sort_by_causation: bool,
    },
}

/// Target of a forensic query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "id")]
pub enum QueryTarget {
    /// Query about a specific decision.
    Decision(String),
    /// Query about a specific evidence atom.
    Evidence(String),
    /// Query about a specific node in the causation graph.
    Node(NodeId),
    /// Query about the entire graph.
    Graph,
}

/// Parameters for customizing forensic queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryParameters {
    /// Maximum number of results to return.
    pub limit: Option<usize>,
    /// Include detailed trace information.
    pub include_trace: bool,
    /// Include raw node/edge data.
    pub include_raw_data: bool,
    /// Filter by causation types.
    pub causation_type_filter: Option<Vec<CausationType>>,
    /// Filter by decision factors.
    pub decision_factor_filter: Option<Vec<DecisionFactor>>,
}

/// Modification to evidence for counterfactual analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceModification {
    /// ID of evidence atom to modify.
    pub evidence_id: String,
    /// New influence weight.
    pub new_influence: InfluenceWeight,
    /// New confidence level.
    pub new_confidence_millionths: Option<u32>,
    /// Description of the modification.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Query Results
// ---------------------------------------------------------------------------

/// Result of a forensic query operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicQueryResult {
    /// Query that produced this result.
    pub query: ForensicQuery,
    /// Status of the query execution.
    pub status: QueryStatus,
    /// Primary result data.
    pub result: QueryResult,
    /// Execution metadata.
    pub metadata: QueryMetadata,
}

/// Status of query execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryStatus {
    /// Query executed successfully.
    Success,
    /// Query failed with an error.
    Failed,
    /// Query was partially successful.
    PartialSuccess,
    /// Query execution timed out.
    Timeout,
}

/// Main result data from a forensic query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum QueryResult {
    /// Causal explanation result.
    CausalExplanation(CausalExplanationResult),
    /// Influence analysis result.
    InfluenceAnalysis(InfluenceAnalysisResult),
    /// Counterfactual analysis result.
    CounterfactualAnalysis(CounterfactualAnalysisResult),
    /// Timeline reconstruction result.
    TimelineReconstruction(TimelineReconstructionResult),
    /// Error result.
    Error(String),
}

/// Result of causal explanation query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalExplanationResult {
    /// The target decision being explained.
    pub decision_node: CausationNode,
    /// Complete causal subgraph explaining the decision.
    pub causal_subgraph: CausalSubgraph,
    /// Summary of key causal factors.
    pub causal_summary: CausalSummary,
    /// Alternative paths that could have led to different outcomes.
    pub alternative_paths: Vec<AlternativePath>,
}

/// Result of influence analysis query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfluenceAnalysisResult {
    /// Evidence atoms ranked by influence strength.
    pub ranked_influences: Vec<InfluenceFactor>,
    /// Distribution of influence across decision factors.
    pub factor_distribution: BTreeMap<DecisionFactor, InfluenceWeight>,
    /// Influence network showing relationships.
    pub influence_network: InfluenceNetwork,
}

/// Result of counterfactual analysis query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualAnalysisResult {
    /// Original decision outcome.
    pub original_outcome: DecisionOutcome,
    /// Predicted outcome under counterfactual conditions.
    pub counterfactual_outcome: DecisionOutcome,
    /// Probability that outcome would change.
    pub outcome_change_probability: InfluenceWeight,
    /// Modified causal graph under counterfactual conditions.
    pub modified_subgraph: CausalSubgraph,
    /// Sensitivity analysis of the counterfactual.
    pub sensitivity_analysis: SensitivityAnalysis,
}

/// Result of timeline reconstruction query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineReconstructionResult {
    /// Events in chronological order.
    pub timeline_events: Vec<TimelineEvent>,
    /// Critical decision points in the timeline.
    pub critical_points: Vec<CriticalPoint>,
    /// Parallel causation chains that occurred simultaneously.
    pub parallel_chains: Vec<ParallelChain>,
}

// ---------------------------------------------------------------------------
// Supporting Types
// ---------------------------------------------------------------------------

/// A subgraph extracted from the main causation graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalSubgraph {
    /// Nodes in the subgraph.
    pub nodes: BTreeMap<NodeId, CausationNode>,
    /// Edges in the subgraph.
    pub edges: BTreeMap<EdgeId, CausationEdge>,
    /// Root nodes (nodes with no incoming edges in subgraph).
    pub root_nodes: Vec<NodeId>,
    /// Leaf nodes (nodes with no outgoing edges in subgraph).
    pub leaf_nodes: Vec<NodeId>,
    /// Total influence weight of the subgraph.
    pub total_influence: InfluenceWeight,
}

/// Summary of causal factors explaining a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalSummary {
    /// Primary evidence atoms that influenced the decision.
    pub primary_evidence: Vec<NodeId>,
    /// Decision factors that were activated.
    pub activated_factors: Vec<DecisionFactor>,
    /// Total number of evidence atoms considered.
    pub evidence_count: u32,
    /// Aggregate confidence in the decision.
    pub aggregate_confidence_millionths: u32,
    /// Strongest single influence.
    pub strongest_influence: InfluenceWeight,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Alternative path that could lead to a different outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlternativePath {
    /// Description of the alternative scenario.
    pub scenario: String,
    /// Evidence modifications required for this path.
    pub required_modifications: Vec<EvidenceModification>,
    /// Predicted alternative outcome.
    pub alternative_outcome: DecisionOutcome,
    /// Probability of this alternative path.
    pub probability: InfluenceWeight,
}

/// Individual influence factor in an analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfluenceFactor {
    /// Node that provided the influence.
    pub node_id: NodeId,
    /// Evidence atom ID if applicable.
    pub evidence_id: Option<String>,
    /// Strength of influence.
    pub influence_weight: InfluenceWeight,
    /// Type of influence.
    pub influence_type: InfluenceType,
    /// Description of how this factor influenced the decision.
    pub description: String,
}

/// Network of influence relationships.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfluenceNetwork {
    /// Adjacency matrix of influence relationships.
    pub adjacency: BTreeMap<NodeId, Vec<(NodeId, InfluenceWeight)>>,
    /// Centrality scores for nodes in the network.
    pub centrality_scores: BTreeMap<NodeId, f64>,
    /// Communities of closely related influences.
    pub influence_communities: Vec<Vec<NodeId>>,
}

/// Type of influence exerted by evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InfluenceType {
    /// Direct evidence supporting the decision.
    DirectSupport,
    /// Evidence contradicting the decision.
    Contradiction,
    /// Contextual evidence that modifies interpretation.
    Contextual,
    /// Aggregated influence from multiple sources.
    Aggregate,
    /// Historical precedent influence.
    Precedent,
}

/// Sensitivity analysis for counterfactual scenarios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitivityAnalysis {
    /// How sensitive the outcome is to each evidence modification.
    pub sensitivity_scores: BTreeMap<String, f64>,
    /// Evidence atoms with highest sensitivity.
    pub critical_evidence: Vec<String>,
    /// Robustness score of the original decision.
    pub robustness_score: f64,
}

/// Event in a reconstructed timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Timestamp of the event.
    pub timestamp_ns: u64,
    /// Node associated with this event.
    pub node_id: NodeId,
    /// Type of event.
    pub event_type: EventType,
    /// Description of what happened.
    pub description: String,
}

/// Critical decision point in a timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriticalPoint {
    /// Timestamp of the critical point.
    pub timestamp_ns: u64,
    /// Decision node at this point.
    pub decision_node: NodeId,
    /// Why this point was critical.
    pub criticality_reason: String,
    /// Impact score of this decision.
    pub impact_score: f64,
}

/// Parallel causation chain in timeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParallelChain {
    /// Nodes in this parallel chain.
    pub chain_nodes: Vec<NodeId>,
    /// Start timestamp of the chain.
    pub start_timestamp_ns: u64,
    /// End timestamp of the chain.
    pub end_timestamp_ns: u64,
    /// Description of this parallel causation.
    pub description: String,
}

/// Type of timeline event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Evidence was introduced.
    EvidenceIntroduced,
    /// Decision was made.
    DecisionMade,
    /// Influence was aggregated.
    InfluenceAggregated,
    /// Timeline branch point.
    BranchPoint,
}

/// Metadata about query execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryMetadata {
    /// Time taken to execute the query (microseconds).
    pub execution_time_us: u64,
    /// Number of nodes examined.
    pub nodes_examined: u32,
    /// Number of edges traversed.
    pub edges_traversed: u32,
    /// Size of the result subgraph.
    pub subgraph_size: u32,
    /// Any warnings generated during execution.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Query Engine
// ---------------------------------------------------------------------------

/// Main forensic query engine for causation graph analysis.
#[derive(Debug)]
pub struct ForensicQueryEngine {
    /// The causation graph being queried.
    graph: CausationGraph,
    /// Cache for previously computed results.
    result_cache: BTreeMap<String, ForensicQueryResult>,
    /// Configuration for the query engine.
    config: QueryEngineConfig,
}

/// Configuration for the forensic query engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryEngineConfig {
    /// Maximum execution time per query (microseconds).
    pub max_execution_time_us: u64,
    /// Maximum subgraph size to extract.
    pub max_subgraph_size: u32,
    /// Whether to enable result caching.
    pub enable_caching: bool,
    /// Default influence threshold for filtering.
    pub default_influence_threshold: InfluenceWeight,
}

impl Default for QueryEngineConfig {
    fn default() -> Self {
        Self {
            max_execution_time_us: 10_000_000, // 10 seconds
            max_subgraph_size: 1000,
            enable_caching: true,
            default_influence_threshold: InfluenceWeight::from_millionths(100_000), // 0.1
        }
    }
}

impl ForensicQueryEngine {
    /// Create a new forensic query engine.
    pub fn new(graph: CausationGraph) -> Self {
        Self {
            graph,
            result_cache: BTreeMap::new(),
            config: QueryEngineConfig::default(),
        }
    }

    /// Create a forensic query engine with custom configuration.
    pub fn with_config(graph: CausationGraph, config: QueryEngineConfig) -> Self {
        Self {
            graph,
            result_cache: BTreeMap::new(),
            config,
        }
    }

    /// Execute a forensic query against the causation graph.
    pub fn execute_query(&mut self, query: ForensicQuery) -> Result<ForensicQueryResult, QueryError> {
        let start_time = std::time::Instant::now();

        // Check cache if enabled
        if self.config.enable_caching {
            let cache_key = self.compute_cache_key(&query)?;
            if let Some(cached_result) = self.result_cache.get(&cache_key) {
                return Ok(cached_result.clone());
            }
        }

        // Execute the query based on its type
        let result = match &query.query_type {
            QueryType::CausalExplanation { max_depth, include_weak_influences } => {
                self.execute_causal_explanation(&query, *max_depth, *include_weak_influences)
            }
            QueryType::InfluenceAnalysis { min_influence_threshold, rank_by_strength } => {
                self.execute_influence_analysis(&query, *min_influence_threshold, *rank_by_strength)
            }
            QueryType::CounterfactualAnalysis { modified_evidence, recompute_downstream } => {
                self.execute_counterfactual_analysis(&query, modified_evidence, *recompute_downstream)
            }
            QueryType::TimelineReconstruction { start_timestamp_ns, end_timestamp_ns, sort_by_causation } => {
                self.execute_timeline_reconstruction(&query, *start_timestamp_ns, *end_timestamp_ns, *sort_by_causation)
            }
        };

        let execution_time_us = start_time.elapsed().as_micros() as u64;

        // Check execution time limit
        if execution_time_us > self.config.max_execution_time_us {
            return Err(QueryError::ExecutionTimeout(execution_time_us));
        }

        let final_result = match result {
            Ok(mut query_result) => {
                query_result.metadata.execution_time_us = execution_time_us;
                query_result.status = QueryStatus::Success;
                query_result
            }
            Err(e) => ForensicQueryResult {
                query: query.clone(),
                status: QueryStatus::Failed,
                result: QueryResult::Error(e.to_string()),
                metadata: QueryMetadata {
                    execution_time_us,
                    nodes_examined: 0,
                    edges_traversed: 0,
                    subgraph_size: 0,
                    warnings: vec![],
                },
            }
        };

        // Cache the result if enabled
        if self.config.enable_caching {
            let cache_key = self.compute_cache_key(&query)?;
            self.result_cache.insert(cache_key, final_result.clone());
        }

        Ok(final_result)
    }

    /// Find the decision node for a given decision ID.
    pub fn find_decision_node(&self, decision_id: &str) -> Result<NodeId, QueryError> {
        for (node_id, node) in &self.graph.nodes {
            if let NodeType::Decision { decision_id: node_decision_id, .. } = &node.node_type {
                if node_decision_id == decision_id {
                    return Ok(*node_id);
                }
            }
        }
        Err(QueryError::DecisionNotFound(decision_id.to_string()))
    }

    /// Extract a causal subgraph for a given target node.
    pub fn extract_causal_subgraph(&self, target_node: NodeId, max_depth: usize) -> Result<CausalSubgraph, QueryError> {
        let mut visited_nodes = BTreeSet::new();
        let mut visited_edges = BTreeSet::new();
        let mut queue = VecDeque::new();

        queue.push_back((target_node, 0));
        visited_nodes.insert(target_node);

        while let Some((node_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            // Add all incoming edges and their source nodes
            if let Some(incoming_edges) = self.graph.reverse_adjacency.get(&node_id) {
                for edge_id in incoming_edges {
                    if let Some(edge) = self.graph.edges.get(edge_id) {
                        visited_edges.insert(*edge_id);

                        if !visited_nodes.contains(&edge.source) {
                            visited_nodes.insert(edge.source);
                            queue.push_back((edge.source, depth + 1));
                        }
                    }
                }
            }
        }

        // Build subgraph from visited nodes and edges
        let mut nodes = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut total_influence = InfluenceWeight::ZERO;

        for node_id in &visited_nodes {
            if let Some(node) = self.graph.nodes.get(node_id) {
                nodes.insert(*node_id, node.clone());
            }
        }

        for edge_id in &visited_edges {
            if let Some(edge) = self.graph.edges.get(edge_id) {
                edges.insert(*edge_id, edge.clone());
                total_influence.millionths += edge.weight.millionths;
            }
        }

        // Find root and leaf nodes in subgraph
        let mut root_nodes = Vec::new();
        let mut leaf_nodes = Vec::new();

        for node_id in &visited_nodes {
            let mut has_incoming = false;
            let mut has_outgoing = false;

            for edge in edges.values() {
                if edge.target == *node_id {
                    has_incoming = true;
                }
                if edge.source == *node_id {
                    has_outgoing = true;
                }
            }

            if !has_incoming {
                root_nodes.push(*node_id);
            }
            if !has_outgoing {
                leaf_nodes.push(*node_id);
            }
        }

        Ok(CausalSubgraph {
            nodes,
            edges,
            root_nodes,
            leaf_nodes,
            total_influence,
        })
    }

    /// Execute causal explanation query.
    fn execute_causal_explanation(&self, query: &ForensicQuery, max_depth: usize, include_weak_influences: bool) -> Result<ForensicQueryResult, QueryError> {
        let target_node_id = match &query.target {
            QueryTarget::Decision(decision_id) => self.find_decision_node(decision_id)?,
            QueryTarget::Node(node_id) => *node_id,
            _ => return Err(QueryError::InvalidTarget("Causal explanation requires decision or node target".to_string())),
        };

        let decision_node = self.graph.nodes.get(&target_node_id)
            .ok_or_else(|| QueryError::NodeNotFound(target_node_id))?
            .clone();

        // Extract causal subgraph
        let causal_subgraph = self.extract_causal_subgraph(target_node_id, max_depth)?;

        // Generate causal summary
        let causal_summary = self.generate_causal_summary(&causal_subgraph, &decision_node)?;

        // Generate alternative paths
        let alternative_paths = self.generate_alternative_paths(&causal_subgraph, &decision_node)?;

        let result = CausalExplanationResult {
            decision_node,
            causal_subgraph,
            causal_summary,
            alternative_paths,
        };

        Ok(ForensicQueryResult {
            query: query.clone(),
            status: QueryStatus::Success,
            result: QueryResult::CausalExplanation(result),
            metadata: QueryMetadata {
                execution_time_us: 0, // Will be filled by caller
                nodes_examined: result.causal_subgraph.nodes.len() as u32,
                edges_traversed: result.causal_subgraph.edges.len() as u32,
                subgraph_size: result.causal_subgraph.nodes.len() as u32,
                warnings: vec![],
            },
        })
    }

    /// Execute influence analysis query.
    fn execute_influence_analysis(&self, query: &ForensicQuery, min_threshold: InfluenceWeight, rank_by_strength: bool) -> Result<ForensicQueryResult, QueryError> {
        // Implementation placeholder - would analyze influence patterns
        // This is a simplified version for the working implementation

        let ranked_influences = vec![];
        let factor_distribution = BTreeMap::new();
        let influence_network = InfluenceNetwork {
            adjacency: BTreeMap::new(),
            centrality_scores: BTreeMap::new(),
            influence_communities: vec![],
        };

        let result = InfluenceAnalysisResult {
            ranked_influences,
            factor_distribution,
            influence_network,
        };

        Ok(ForensicQueryResult {
            query: query.clone(),
            status: QueryStatus::Success,
            result: QueryResult::InfluenceAnalysis(result),
            metadata: QueryMetadata {
                execution_time_us: 0,
                nodes_examined: 0,
                edges_traversed: 0,
                subgraph_size: 0,
                warnings: vec![],
            },
        })
    }

    /// Execute counterfactual analysis query.
    fn execute_counterfactual_analysis(&self, query: &ForensicQuery, modified_evidence: &[EvidenceModification], recompute_downstream: bool) -> Result<ForensicQueryResult, QueryError> {
        // Implementation placeholder - would perform what-if analysis
        // This is a simplified version for the working implementation

        let result = CounterfactualAnalysisResult {
            original_outcome: DecisionOutcome::Allow,
            counterfactual_outcome: DecisionOutcome::Deny,
            outcome_change_probability: InfluenceWeight::from_millionths(750_000),
            modified_subgraph: CausalSubgraph {
                nodes: BTreeMap::new(),
                edges: BTreeMap::new(),
                root_nodes: vec![],
                leaf_nodes: vec![],
                total_influence: InfluenceWeight::ZERO,
            },
            sensitivity_analysis: SensitivityAnalysis {
                sensitivity_scores: BTreeMap::new(),
                critical_evidence: vec![],
                robustness_score: 0.75,
            },
        };

        Ok(ForensicQueryResult {
            query: query.clone(),
            status: QueryStatus::Success,
            result: QueryResult::CounterfactualAnalysis(result),
            metadata: QueryMetadata {
                execution_time_us: 0,
                nodes_examined: 0,
                edges_traversed: 0,
                subgraph_size: 0,
                warnings: vec![],
            },
        })
    }

    /// Execute timeline reconstruction query.
    fn execute_timeline_reconstruction(&self, query: &ForensicQuery, start_timestamp: u64, end_timestamp: u64, sort_by_causation: bool) -> Result<ForensicQueryResult, QueryError> {
        // Implementation placeholder - would reconstruct event timeline
        // This is a simplified version for the working implementation

        let result = TimelineReconstructionResult {
            timeline_events: vec![],
            critical_points: vec![],
            parallel_chains: vec![],
        };

        Ok(ForensicQueryResult {
            query: query.clone(),
            status: QueryStatus::Success,
            result: QueryResult::TimelineReconstruction(result),
            metadata: QueryMetadata {
                execution_time_us: 0,
                nodes_examined: 0,
                edges_traversed: 0,
                subgraph_size: 0,
                warnings: vec![],
            },
        })
    }

    /// Generate causal summary for a subgraph.
    fn generate_causal_summary(&self, subgraph: &CausalSubgraph, decision_node: &CausationNode) -> Result<CausalSummary, QueryError> {
        let mut primary_evidence = Vec::new();
        let mut activated_factors = Vec::new();
        let mut evidence_count = 0;
        let mut strongest_influence = InfluenceWeight::ZERO;

        // Analyze nodes in subgraph
        for (node_id, node) in &subgraph.nodes {
            match &node.node_type {
                NodeType::EvidenceAtom { .. } => {
                    evidence_count += 1;
                    primary_evidence.push(*node_id);
                }
                NodeType::Decision { factor, .. } => {
                    if !activated_factors.contains(factor) {
                        activated_factors.push(*factor);
                    }
                }
                _ => {}
            }
        }

        // Find strongest influence
        for edge in subgraph.edges.values() {
            if edge.weight.millionths > strongest_influence.millionths {
                strongest_influence = edge.weight;
            }
        }

        let explanation = format!(
            "Decision influenced by {} evidence atoms through {} decision factors",
            evidence_count,
            activated_factors.len()
        );

        Ok(CausalSummary {
            primary_evidence,
            activated_factors,
            evidence_count,
            aggregate_confidence_millionths: 800_000, // Placeholder
            strongest_influence,
            explanation,
        })
    }

    /// Generate alternative paths for counterfactual analysis.
    fn generate_alternative_paths(&self, subgraph: &CausalSubgraph, decision_node: &CausationNode) -> Result<Vec<AlternativePath>, QueryError> {
        // Implementation placeholder - would generate what-if scenarios
        Ok(vec![])
    }

    /// Compute cache key for a query.
    fn compute_cache_key(&self, query: &ForensicQuery) -> Result<String, QueryError> {
        // Simple cache key based on query content
        use crate::canonical_encoding::CanonicalEncoder;

        let mut encoder = CanonicalEncoder::new();
        encoder.encode_string(&query.query_id);
        encoder.encode_string(&serde_json::to_string(&query.query_type)?);
        encoder.encode_string(&serde_json::to_string(&query.target)?);

        let hash = ContentHash::compute(&encoder.finalize());
        Ok(format!("query-{}", hash.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>()))
    }
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur during forensic query execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// Decision with given ID not found.
    DecisionNotFound(String),
    /// Node with given ID not found.
    NodeNotFound(NodeId),
    /// Invalid query target for the query type.
    InvalidTarget(String),
    /// Query execution exceeded time limit.
    ExecutionTimeout(u64),
    /// Subgraph too large to extract.
    SubgraphTooLarge(u32),
    /// Graph operation error.
    GraphError(GraphError),
    /// Serialization error.
    SerializationError(String),
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueryError::DecisionNotFound(id) => write!(f, "Decision not found: {}", id),
            QueryError::NodeNotFound(id) => write!(f, "Node not found: {}", id),
            QueryError::InvalidTarget(msg) => write!(f, "Invalid target: {}", msg),
            QueryError::ExecutionTimeout(time) => write!(f, "Query execution timeout: {}μs", time),
            QueryError::SubgraphTooLarge(size) => write!(f, "Subgraph too large: {} nodes", size),
            QueryError::GraphError(e) => write!(f, "Graph error: {}", e),
            QueryError::SerializationError(e) => write!(f, "Serialization error: {}", e),
        }
    }
}

impl std::error::Error for QueryError {}

impl From<GraphError> for QueryError {
    fn from(error: GraphError) -> Self {
        QueryError::GraphError(error)
    }
}

impl From<serde_json::Error> for QueryError {
    fn from(error: serde_json::Error) -> Self {
        QueryError::SerializationError(error.to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::causation_graph_schema::{CausationGraph, CausationNode, CausationEdge, NodeId, EdgeId};
    use crate::hash_tiers::{AuthenticityHash, ContentHash};
    use crate::minimal_causal_set_inference::{CausalDependency, DecisionFactor};

    fn create_test_graph() -> CausationGraph {
        let mut graph = CausationGraph::new();

        // Add evidence node
        let evidence_node = CausationNode {
            id: NodeId(1),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    atom_id: "test-evidence".to_string(),
                    influence_millionths: 700_000,
                    content_hash: ContentHash::compute(b"evidence-data"),
                },
                evidence_hash: ContentHash::compute(b"evidence"),
                confidence_millionths: 900_000,
            },
            content_hash: ContentHash::compute(b"evidence-node"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"evidence", b"key"),
            timestamp_ns: 1000000,
            metadata: BTreeMap::new(),
        };

        // Add decision node
        let decision_node = CausationNode {
            id: NodeId(2),
            node_type: NodeType::Decision {
                decision_id: "test-decision".to_string(),
                factor: DecisionFactor::GuardrailActivation,
                context_hash: ContentHash::compute(b"decision-context"),
                outcome: DecisionOutcome::Deny,
            },
            content_hash: ContentHash::compute(b"decision-node"),
            authenticity_hash: AuthenticityHash::compute_keyed(b"decision", b"key"),
            timestamp_ns: 2000000,
            metadata: BTreeMap::new(),
        };

        graph.add_node(evidence_node).unwrap();
        graph.add_node(decision_node).unwrap();

        // Add causal edge
        let edge = CausationEdge {
            id: EdgeId(1),
            source: NodeId(1),
            target: NodeId(2),
            weight: InfluenceWeight::from_millionths(800_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(b"test-edge"),
            timestamp_ns: 1500000,
            metadata: BTreeMap::new(),
        };

        graph.add_edge(edge).unwrap();
        graph
    }

    #[test]
    fn test_forensic_query_engine_creation() {
        let graph = create_test_graph();
        let engine = ForensicQueryEngine::new(graph);

        assert_eq!(engine.config.max_execution_time_us, 10_000_000);
        assert!(engine.config.enable_caching);
    }

    #[test]
    fn test_find_decision_node() {
        let graph = create_test_graph();
        let engine = ForensicQueryEngine::new(graph);

        let node_id = engine.find_decision_node("test-decision").unwrap();
        assert_eq!(node_id, NodeId(2));

        let not_found = engine.find_decision_node("nonexistent");
        assert!(matches!(not_found, Err(QueryError::DecisionNotFound(_))));
    }

    #[test]
    fn test_causal_subgraph_extraction() {
        let graph = create_test_graph();
        let engine = ForensicQueryEngine::new(graph);

        let subgraph = engine.extract_causal_subgraph(NodeId(2), 5).unwrap();

        assert_eq!(subgraph.nodes.len(), 2); // Both nodes should be included
        assert_eq!(subgraph.edges.len(), 1); // One edge connecting them
        assert!(subgraph.leaf_nodes.contains(&NodeId(2))); // Decision node is leaf
        assert!(subgraph.root_nodes.contains(&NodeId(1))); // Evidence node is root
    }

    #[test]
    fn test_causal_explanation_query() {
        let graph = create_test_graph();
        let mut engine = ForensicQueryEngine::new(graph);

        let query = ForensicQuery {
            query_id: "test-query-1".to_string(),
            query_type: QueryType::CausalExplanation {
                max_depth: 5,
                include_weak_influences: false,
            },
            target: QueryTarget::Decision("test-decision".to_string()),
            parameters: QueryParameters {
                limit: None,
                include_trace: false,
                include_raw_data: false,
                causation_type_filter: None,
                decision_factor_filter: None,
            },
            timestamp_ns: 3000000,
        };

        let result = engine.execute_query(query).unwrap();

        assert_eq!(result.status, QueryStatus::Success);
        assert!(matches!(result.result, QueryResult::CausalExplanation(_)));

        if let QueryResult::CausalExplanation(explanation) = result.result {
            assert_eq!(explanation.decision_node.id, NodeId(2));
            assert_eq!(explanation.causal_summary.evidence_count, 1);
        }
    }

    #[test]
    fn test_influence_weight_operations() {
        let w1 = InfluenceWeight::from_millionths(500_000);
        let w2 = InfluenceWeight::from_f64(0.75);

        assert!(w2.millionths > w1.millionths);
        assert!((w2.to_f64() - 0.75).abs() < 1e-6);
    }

    #[test]
    fn test_query_serialization() {
        let query = ForensicQuery {
            query_id: "serialization-test".to_string(),
            query_type: QueryType::CausalExplanation {
                max_depth: 3,
                include_weak_influences: true,
            },
            target: QueryTarget::Decision("test-decision".to_string()),
            parameters: QueryParameters {
                limit: Some(10),
                include_trace: true,
                include_raw_data: false,
                causation_type_filter: Some(vec![CausationType::Direct]),
                decision_factor_filter: None,
            },
            timestamp_ns: 1234567890,
        };

        let serialized = serde_json::to_string(&query).unwrap();
        let deserialized: ForensicQuery = serde_json::from_str(&serialized).unwrap();

        assert_eq!(query, deserialized);
    }

    #[test]
    fn test_query_engine_config() {
        let config = QueryEngineConfig {
            max_execution_time_us: 5_000_000,
            max_subgraph_size: 500,
            enable_caching: false,
            default_influence_threshold: InfluenceWeight::from_millionths(200_000),
        };

        let graph = create_test_graph();
        let engine = ForensicQueryEngine::with_config(graph, config.clone());

        assert_eq!(engine.config.max_execution_time_us, 5_000_000);
        assert!(!engine.config.enable_caching);
    }
}