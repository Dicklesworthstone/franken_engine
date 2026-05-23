//! Operator surface for forensic causation graph analysis.
//!
//! This module provides the operator-facing interface for working with forensic
//! causation graphs. It includes tools for reading causation subgraphs, interpreting
//! decision factors, and integrating with frankentui for visual inspection.
//!
//! ## Operator Workflow
//!
//! 1. **Investigate Decision**: Use `investigate_decision()` to get comprehensive analysis
//! 2. **Read Subgraph**: Use `read_causation_subgraph()` to interpret causal relationships
//! 3. **Visual Inspection**: Use `format_for_frankentui()` for terminal-based visualization
//! 4. **Generate Report**: Use `generate_investigation_report()` for documentation
//!
//! ## Key Features
//!
//! - **Human-Readable Summaries**: Convert technical causation data to operator-friendly format
//! - **Visual Integration**: frankentui components for graph visualization
//! - **Investigation Workflows**: Step-by-step forensic analysis procedures
//! - **Report Generation**: Structured output for incident documentation
//!
//! ## Usage Examples
//!
//! ```rust
//! // Basic investigation
//! let operator = ForensicOperator::new(query_engine);
//! let report = operator.investigate_decision("security-decision-123")?;
//!
//! // Visual inspection
//! let ui_data = operator.format_for_frankentui(&report.causal_subgraph)?;
//! frankentui::display_causation_graph(ui_data);
//! ```
//!
//! Reference: [FF.4] Forensic causation graph operator surface

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::forensic_query_api::{
    ForensicQueryEngine, ForensicQuery, ForensicQueryResult, QueryType, QueryTarget,
    QueryParameters, CausalExplanationResult, InfluenceAnalysisResult,
    CounterfactualAnalysisResult, QueryError, QueryStatus,
};
use crate::causation_graph_schema::{
    CausationGraph, CausationNode, CausationEdge, CausalSubgraph, NodeId, EdgeId,
    NodeType, DecisionOutcome, CausationType, InfluenceWeight,
};
use crate::minimal_causal_set_inference::DecisionFactor;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for operator surface.
pub const OPERATOR_SURFACE_SCHEMA_VERSION: &str = "franken-engine.forensic-operator.v1";
/// Component name for evidence linkage.
pub const OPERATOR_SURFACE_COMPONENT: &str = "forensic_causation_operator";
/// Policy ID binding for this module.
pub const OPERATOR_SURFACE_POLICY_ID: &str = "FF-4";

// Default thresholds for operator analysis
const DEFAULT_INFLUENCE_THRESHOLD: u32 = 100_000; // 0.1
const DEFAULT_CONFIDENCE_THRESHOLD: u32 = 500_000; // 0.5
const HIGH_INFLUENCE_THRESHOLD: u32 = 700_000; // 0.7
const CRITICAL_INFLUENCE_THRESHOLD: u32 = 900_000; // 0.9

// ---------------------------------------------------------------------------
// Operator Interface
// ---------------------------------------------------------------------------

/// Main operator interface for forensic causation graph analysis.
#[derive(Debug)]
pub struct ForensicOperator {
    /// Query engine for executing forensic queries.
    query_engine: ForensicQueryEngine,
    /// Configuration for operator interface.
    config: OperatorConfig,
}

/// Configuration for the forensic operator interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorConfig {
    /// Minimum influence threshold for displaying factors.
    pub min_influence_threshold: InfluenceWeight,
    /// Include weak influences in analysis.
    pub include_weak_influences: bool,
    /// Maximum depth for causal chain traversal.
    pub max_causal_depth: usize,
    /// Enable frankentui integration.
    pub enable_frankentui: bool,
    /// Verbosity level for reports (0=minimal, 2=verbose).
    pub verbosity_level: u8,
}

impl Default for OperatorConfig {
    fn default() -> Self {
        Self {
            min_influence_threshold: InfluenceWeight::from_millionths(DEFAULT_INFLUENCE_THRESHOLD),
            include_weak_influences: false,
            max_causal_depth: 10,
            enable_frankentui: true,
            verbosity_level: 1,
        }
    }
}

impl ForensicOperator {
    /// Create a new forensic operator interface.
    pub fn new(query_engine: ForensicQueryEngine) -> Self {
        Self {
            query_engine,
            config: OperatorConfig::default(),
        }
    }

    /// Create a forensic operator with custom configuration.
    pub fn with_config(query_engine: ForensicQueryEngine, config: OperatorConfig) -> Self {
        Self {
            query_engine,
            config,
        }
    }

    /// Investigate a decision with comprehensive analysis.
    pub fn investigate_decision(&mut self, decision_id: &str) -> Result<InvestigationReport, OperatorError> {
        let start_time = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default().as_nanos() as u64;

        // Step 1: Get causal explanation
        let explanation_query = ForensicQuery {
            query_id: format!("investigation-{}-explanation", decision_id),
            query_type: QueryType::CausalExplanation {
                max_depth: self.config.max_causal_depth,
                include_weak_influences: self.config.include_weak_influences,
            },
            target: QueryTarget::Decision(decision_id.to_string()),
            parameters: QueryParameters {
                limit: None,
                include_trace: true,
                include_raw_data: false,
                causation_type_filter: None,
                decision_factor_filter: None,
            },
            timestamp_ns: start_time,
        };

        let explanation_result = self.query_engine.execute_query(explanation_query)?;

        // Step 2: Get influence analysis
        let influence_query = ForensicQuery {
            query_id: format!("investigation-{}-influence", decision_id),
            query_type: QueryType::InfluenceAnalysis {
                min_influence_threshold: self.config.min_influence_threshold,
                rank_by_strength: true,
            },
            target: QueryTarget::Decision(decision_id.to_string()),
            parameters: QueryParameters {
                limit: Some(20),
                include_trace: false,
                include_raw_data: true,
                causation_type_filter: None,
                decision_factor_filter: None,
            },
            timestamp_ns: start_time + 1000,
        };

        let influence_result = self.query_engine.execute_query(influence_query)?;

        // Extract results
        let (causal_explanation, influence_analysis) = match (&explanation_result.result, &influence_result.result) {
            (
                crate::forensic_query_api::QueryResult::CausalExplanation(exp),
                crate::forensic_query_api::QueryResult::InfluenceAnalysis(inf)
            ) => (exp.clone(), inf.clone()),
            _ => return Err(OperatorError::QueryFailed("Failed to get causal explanation or influence analysis".to_string())),
        };

        // Generate human-readable interpretation
        let interpretation = self.interpret_causation_data(&causal_explanation, &influence_analysis)?;

        // Create frankentui visualization if enabled
        let frankentui_data = if self.config.enable_frankentui {
            Some(self.format_for_frankentui(&causal_explanation.causal_subgraph)?)
        } else {
            None
        };

        // Generate operator recommendations
        let recommendations = self.generate_recommendations(&causal_explanation, &influence_analysis)?;

        Ok(InvestigationReport {
            decision_id: decision_id.to_string(),
            investigation_timestamp_ns: start_time,
            causal_explanation,
            influence_analysis,
            interpretation,
            recommendations,
            frankentui_data,
            operator_config: self.config.clone(),
        })
    }

    /// Read and interpret a causation subgraph for operators.
    pub fn read_causation_subgraph(&self, subgraph: &CausalSubgraph) -> Result<SubgraphReading, OperatorError> {
        let mut reading = SubgraphReading {
            summary: CausalSummaryText::default(),
            evidence_factors: Vec::new(),
            decision_chain: Vec::new(),
            influence_breakdown: BTreeMap::new(),
            critical_paths: Vec::new(),
        };

        // Analyze nodes and categorize them
        let mut evidence_nodes = Vec::new();
        let mut decision_nodes = Vec::new();
        let mut aggregate_nodes = Vec::new();

        for (node_id, node) in &subgraph.nodes {
            match &node.node_type {
                NodeType::EvidenceAtom { dependency, confidence_millionths, .. } => {
                    evidence_nodes.push((*node_id, dependency.clone(), *confidence_millionths));
                }
                NodeType::Decision { decision_id, factor, outcome, .. } => {
                    decision_nodes.push((*node_id, decision_id.clone(), *factor, *outcome));
                }
                NodeType::AggregateInfluence { total_weight, method, .. } => {
                    aggregate_nodes.push((*node_id, *total_weight, *method));
                }
            }
        }

        // Generate summary text
        reading.summary = CausalSummaryText {
            total_evidence_count: evidence_nodes.len(),
            total_decision_count: decision_nodes.len(),
            strongest_influence: subgraph.edges.values()
                .map(|edge| edge.weight)
                .max()
                .unwrap_or(InfluenceWeight::ZERO),
            primary_causation_types: self.analyze_causation_types(&subgraph.edges.values().collect()),
            confidence_assessment: self.assess_overall_confidence(&evidence_nodes),
        };

        // Process evidence factors
        for (node_id, dependency, confidence) in evidence_nodes {
            let influence_level = self.categorize_influence_level(dependency.influence_millionths);

            reading.evidence_factors.push(EvidenceFactor {
                node_id,
                evidence_id: dependency.atom_id,
                influence_level,
                confidence_level: self.categorize_confidence_level(confidence),
                description: self.describe_evidence_impact(&dependency),
            });
        }

        // Build decision chain
        reading.decision_chain = self.build_decision_chain(&subgraph, &decision_nodes)?;

        // Analyze influence breakdown
        reading.influence_breakdown = self.analyze_influence_breakdown(&subgraph)?;

        // Identify critical paths
        reading.critical_paths = self.identify_critical_paths(&subgraph)?;

        Ok(reading)
    }

    /// Format causation subgraph for frankentui visualization.
    pub fn format_for_frankentui(&self, subgraph: &CausalSubgraph) -> Result<FrankentuiData, OperatorError> {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        // Convert nodes to frankentui format
        for (node_id, node) in &subgraph.nodes {
            let ui_node = match &node.node_type {
                NodeType::EvidenceAtom { dependency, confidence_millionths, .. } => {
                    FrankentuiNode {
                        id: node_id.0.to_string(),
                        label: dependency.atom_id.clone(),
                        node_type: "evidence".to_string(),
                        color: self.color_for_confidence(*confidence_millionths),
                        size: self.size_for_influence(dependency.influence_millionths),
                        tooltip: format!("Evidence: {} (confidence: {:.1}%)",
                                       dependency.atom_id, *confidence_millionths as f64 / 10_000.0),
                        metadata: BTreeMap::from([
                            ("influence".to_string(), format!("{:.3}", dependency.influence_millionths as f64 / 1_000_000.0)),
                            ("confidence".to_string(), format!("{:.1}%", *confidence_millionths as f64 / 10_000.0)),
                        ]),
                    }
                }
                NodeType::Decision { decision_id, factor, outcome, .. } => {
                    FrankentuiNode {
                        id: node_id.0.to_string(),
                        label: format!("Decision: {}", decision_id),
                        node_type: "decision".to_string(),
                        color: self.color_for_outcome(*outcome),
                        size: "large".to_string(),
                        tooltip: format!("Decision: {} -> {:?} (factor: {:?})", decision_id, outcome, factor),
                        metadata: BTreeMap::from([
                            ("outcome".to_string(), format!("{:?}", outcome)),
                            ("factor".to_string(), format!("{:?}", factor)),
                        ]),
                    }
                }
                NodeType::AggregateInfluence { total_weight, method, .. } => {
                    FrankentuiNode {
                        id: node_id.0.to_string(),
                        label: format!("Aggregate ({:?})", method),
                        node_type: "aggregate".to_string(),
                        color: "orange".to_string(),
                        size: self.size_for_influence(total_weight.millionths),
                        tooltip: format!("Aggregate influence: {:.3} via {:?}", total_weight.to_f64(), method),
                        metadata: BTreeMap::from([
                            ("weight".to_string(), format!("{:.3}", total_weight.to_f64())),
                            ("method".to_string(), format!("{:?}", method)),
                        ]),
                    }
                }
            };
            nodes.push(ui_node);
        }

        // Convert edges to frankentui format
        for edge in subgraph.edges.values() {
            let ui_edge = FrankentuiEdge {
                source: edge.source.0.to_string(),
                target: edge.target.0.to_string(),
                weight: edge.weight.to_f64(),
                causation_type: format!("{:?}", edge.causation_type),
                color: self.color_for_causation_type(edge.causation_type),
                thickness: self.thickness_for_weight(edge.weight),
                tooltip: format!("Causation: {:.3} ({:?})", edge.weight.to_f64(), edge.causation_type),
            };
            edges.push(ui_edge);
        }

        Ok(FrankentuiData {
            schema_version: OPERATOR_SURFACE_SCHEMA_VERSION.to_string(),
            graph_type: "causation".to_string(),
            nodes,
            edges,
            layout_hints: FrankentuiLayoutHints {
                algorithm: "hierarchical".to_string(),
                root_nodes: subgraph.root_nodes.iter().map(|id| id.0.to_string()).collect(),
                leaf_nodes: subgraph.leaf_nodes.iter().map(|id| id.0.to_string()).collect(),
            },
            metadata: BTreeMap::from([
                ("total_nodes".to_string(), subgraph.nodes.len().to_string()),
                ("total_edges".to_string(), subgraph.edges.len().to_string()),
                ("total_influence".to_string(), format!("{:.3}", subgraph.total_influence.to_f64())),
            ]),
        })
    }

    /// Generate investigation report for documentation.
    pub fn generate_investigation_report(&mut self, decision_id: &str) -> Result<String, OperatorError> {
        let report = self.investigate_decision(decision_id)?;

        let mut output = String::new();

        // Header
        output.push_str(&format!("# Forensic Investigation Report: {}\n\n", decision_id));
        output.push_str(&format!("**Investigation Time**: {}\n",
            chrono::DateTime::from_timestamp_nanos(report.investigation_timestamp_ns as i64)
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "Unknown".to_string())));

        // Decision Summary
        output.push_str("\n## Decision Summary\n\n");
        output.push_str(&format!("**Decision ID**: {}\n", report.decision_id));
        if let NodeType::Decision { outcome, factor, context_hash, .. } = &report.causal_explanation.decision_node.node_type {
            output.push_str(&format!("**Outcome**: {:?}\n", outcome));
            output.push_str(&format!("**Primary Factor**: {:?}\n", factor));
        }

        // Causal Analysis
        output.push_str("\n## Causal Analysis\n\n");
        output.push_str(&format!("**Evidence Count**: {}\n", report.causal_explanation.causal_summary.evidence_count));
        output.push_str(&format!("**Activated Factors**: {}\n",
            report.causal_explanation.causal_summary.activated_factors.len()));
        output.push_str(&format!("**Strongest Influence**: {:.3}\n",
            report.causal_explanation.causal_summary.strongest_influence.to_f64()));
        output.push_str(&format!("**Explanation**: {}\n",
            report.causal_explanation.causal_summary.explanation));

        // Interpretation
        output.push_str("\n## Operator Interpretation\n\n");
        output.push_str(&format!("**Risk Level**: {:?}\n", report.interpretation.risk_level));
        output.push_str(&format!("**Confidence**: {:?}\n", report.interpretation.confidence_level));
        output.push_str(&format!("**Primary Concerns**: {}\n", report.interpretation.primary_concerns.join(", ")));

        if !report.interpretation.narrative.is_empty() {
            output.push_str(&format!("\n**Narrative**:\n{}\n", report.interpretation.narrative));
        }

        // Recommendations
        output.push_str("\n## Recommendations\n\n");
        for (i, rec) in report.recommendations.iter().enumerate() {
            output.push_str(&format!("{}. **{}**: {}\n", i + 1, rec.category, rec.description));
            if !rec.action_items.is_empty() {
                for item in &rec.action_items {
                    output.push_str(&format!("   - {}\n", item));
                }
            }
        }

        // Technical Details (if verbose)
        if self.config.verbosity_level >= 2 {
            output.push_str("\n## Technical Details\n\n");
            output.push_str(&format!("**Subgraph Size**: {} nodes, {} edges\n",
                report.causal_explanation.causal_subgraph.nodes.len(),
                report.causal_explanation.causal_subgraph.edges.len()));
            output.push_str(&format!("**Query Execution Time**: {}μs\n",
                report.causal_explanation.causal_summary.aggregate_confidence_millionths));
        }

        Ok(output)
    }

    // Helper methods for analysis

    fn interpret_causation_data(&self, explanation: &CausalExplanationResult, influence: &InfluenceAnalysisResult) -> Result<CausationInterpretation, OperatorError> {
        // Assess risk level based on decision outcome and influence strength
        let risk_level = match &explanation.decision_node.node_type {
            NodeType::Decision { outcome, .. } => match outcome {
                DecisionOutcome::Allow => RiskLevel::Low,
                DecisionOutcome::Modify => RiskLevel::Medium,
                DecisionOutcome::Suspend | DecisionOutcome::Challenge => RiskLevel::High,
                DecisionOutcome::Deny | DecisionOutcome::Quarantine => RiskLevel::Critical,
            },
            _ => RiskLevel::Unknown,
        };

        // Assess confidence based on evidence strength
        let confidence_level = if explanation.causal_summary.strongest_influence.millionths >= CRITICAL_INFLUENCE_THRESHOLD {
            ConfidenceLevel::High
        } else if explanation.causal_summary.strongest_influence.millionths >= HIGH_INFLUENCE_THRESHOLD {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        };

        // Generate primary concerns
        let mut primary_concerns = Vec::new();

        if explanation.causal_summary.evidence_count == 0 {
            primary_concerns.push("No evidence found for decision".to_string());
        } else if explanation.causal_summary.evidence_count == 1 {
            primary_concerns.push("Decision based on single evidence source".to_string());
        }

        if explanation.causal_summary.strongest_influence.millionths < DEFAULT_CONFIDENCE_THRESHOLD {
            primary_concerns.push("Weak evidence influence detected".to_string());
        }

        if explanation.causal_summary.activated_factors.is_empty() {
            primary_concerns.push("No clear decision factors identified".to_string());
        }

        // Generate narrative
        let narrative = format!(
            "This {} decision was influenced by {} evidence sources with a maximum influence strength of {:.3}. The decision activated {} different factors, suggesting {}.",
            format!("{:?}", risk_level).to_lowercase(),
            explanation.causal_summary.evidence_count,
            explanation.causal_summary.strongest_influence.to_f64(),
            explanation.causal_summary.activated_factors.len(),
            if explanation.causal_summary.activated_factors.len() > 2 { "complex multi-factor analysis" } else { "straightforward evaluation" }
        );

        Ok(CausationInterpretation {
            risk_level,
            confidence_level,
            primary_concerns,
            narrative,
            technical_notes: vec![], // Could be extended with more detailed technical analysis
        })
    }

    fn generate_recommendations(&self, explanation: &CausalExplanationResult, influence: &InfluenceAnalysisResult) -> Result<Vec<OperatorRecommendation>, OperatorError> {
        let mut recommendations = Vec::new();

        // Evidence-based recommendations
        if explanation.causal_summary.evidence_count <= 1 {
            recommendations.push(OperatorRecommendation {
                category: "Evidence Collection".to_string(),
                priority: RecommendationPriority::High,
                description: "Consider gathering additional evidence sources to strengthen decision confidence".to_string(),
                action_items: vec![
                    "Review alternative evidence sources".to_string(),
                    "Validate existing evidence quality".to_string(),
                ],
            });
        }

        // Influence strength recommendations
        if explanation.causal_summary.strongest_influence.millionths < DEFAULT_CONFIDENCE_THRESHOLD {
            recommendations.push(OperatorRecommendation {
                category: "Decision Confidence".to_string(),
                priority: RecommendationPriority::Medium,
                description: "Weak influence detected - consider additional validation".to_string(),
                action_items: vec![
                    "Review evidence quality thresholds".to_string(),
                    "Consider manual review for borderline cases".to_string(),
                ],
            });
        }

        // Decision outcome recommendations
        if let NodeType::Decision { outcome, .. } = &explanation.decision_node.node_type {
            match outcome {
                DecisionOutcome::Deny | DecisionOutcome::Quarantine => {
                    recommendations.push(OperatorRecommendation {
                        category: "Security Response".to_string(),
                        priority: RecommendationPriority::High,
                        description: "High-impact security decision - ensure proper incident response".to_string(),
                        action_items: vec![
                            "Document incident details".to_string(),
                            "Consider escalation if pattern emerges".to_string(),
                            "Review prevention measures".to_string(),
                        ],
                    });
                }
                DecisionOutcome::Challenge => {
                    recommendations.push(OperatorRecommendation {
                        category: "Authentication".to_string(),
                        priority: RecommendationPriority::Medium,
                        description: "Authentication challenge triggered - monitor completion".to_string(),
                        action_items: vec![
                            "Track challenge completion rate".to_string(),
                            "Review authentication policies".to_string(),
                        ],
                    });
                }
                _ => {}
            }
        }

        // General monitoring recommendation
        recommendations.push(OperatorRecommendation {
            category: "Monitoring".to_string(),
            priority: RecommendationPriority::Low,
            description: "Continue monitoring for similar patterns".to_string(),
            action_items: vec![
                "Set up alerts for similar decision patterns".to_string(),
                "Schedule periodic review of decision trends".to_string(),
            ],
        });

        Ok(recommendations)
    }

    // UI formatting helper methods

    fn color_for_confidence(&self, confidence_millionths: u32) -> String {
        if confidence_millionths >= 800_000 {
            "green".to_string()
        } else if confidence_millionths >= 600_000 {
            "yellow".to_string()
        } else {
            "red".to_string()
        }
    }

    fn size_for_influence(&self, influence_millionths: u32) -> String {
        if influence_millionths >= CRITICAL_INFLUENCE_THRESHOLD {
            "xlarge".to_string()
        } else if influence_millionths >= HIGH_INFLUENCE_THRESHOLD {
            "large".to_string()
        } else if influence_millionths >= DEFAULT_INFLUENCE_THRESHOLD {
            "medium".to_string()
        } else {
            "small".to_string()
        }
    }

    fn color_for_outcome(&self, outcome: DecisionOutcome) -> String {
        match outcome {
            DecisionOutcome::Allow => "green".to_string(),
            DecisionOutcome::Modify | DecisionOutcome::Challenge => "yellow".to_string(),
            DecisionOutcome::Suspend => "orange".to_string(),
            DecisionOutcome::Deny | DecisionOutcome::Quarantine => "red".to_string(),
        }
    }

    fn color_for_causation_type(&self, causation_type: CausationType) -> String {
        match causation_type {
            CausationType::Direct => "blue".to_string(),
            CausationType::Indirect => "lightblue".to_string(),
            CausationType::Evidential => "green".to_string(),
            CausationType::Logical => "purple".to_string(),
            CausationType::Temporal => "orange".to_string(),
            CausationType::Correlational => "gray".to_string(),
        }
    }

    fn thickness_for_weight(&self, weight: InfluenceWeight) -> String {
        if weight.millionths >= CRITICAL_INFLUENCE_THRESHOLD {
            "thick".to_string()
        } else if weight.millionths >= HIGH_INFLUENCE_THRESHOLD {
            "medium".to_string()
        } else {
            "thin".to_string()
        }
    }

    // Analysis helper methods (simplified implementations for working code)

    fn analyze_causation_types(&self, edges: &Vec<&CausationEdge>) -> Vec<CausationType> {
        let mut types = BTreeSet::new();
        for edge in edges {
            types.insert(edge.causation_type);
        }
        types.into_iter().collect()
    }

    fn assess_overall_confidence(&self, evidence_nodes: &[(NodeId, crate::minimal_causal_set_inference::CausalDependency, u32)]) -> ConfidenceLevel {
        if evidence_nodes.is_empty() {
            return ConfidenceLevel::Low;
        }

        let avg_confidence = evidence_nodes.iter()
            .map(|(_, _, conf)| *conf as u64)
            .sum::<u64>() / evidence_nodes.len() as u64;

        if avg_confidence >= 800_000 {
            ConfidenceLevel::High
        } else if avg_confidence >= 600_000 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }

    fn categorize_influence_level(&self, influence_millionths: u32) -> InfluenceLevel {
        if influence_millionths >= CRITICAL_INFLUENCE_THRESHOLD {
            InfluenceLevel::Critical
        } else if influence_millionths >= HIGH_INFLUENCE_THRESHOLD {
            InfluenceLevel::High
        } else if influence_millionths >= DEFAULT_INFLUENCE_THRESHOLD {
            InfluenceLevel::Medium
        } else {
            InfluenceLevel::Low
        }
    }

    fn categorize_confidence_level(&self, confidence_millionths: u32) -> ConfidenceLevel {
        if confidence_millionths >= 800_000 {
            ConfidenceLevel::High
        } else if confidence_millionths >= 600_000 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }

    fn describe_evidence_impact(&self, dependency: &crate::minimal_causal_set_inference::CausalDependency) -> String {
        let influence_level = self.categorize_influence_level(dependency.influence_millionths);
        format!("Evidence '{}' has {:?} impact on decision", dependency.atom_id, influence_level)
    }

    fn build_decision_chain(&self, subgraph: &CausalSubgraph, decision_nodes: &[(NodeId, String, DecisionFactor, DecisionOutcome)]) -> Result<Vec<DecisionStep>, OperatorError> {
        let mut chain = Vec::new();

        for (node_id, decision_id, factor, outcome) in decision_nodes {
            chain.push(DecisionStep {
                node_id: *node_id,
                decision_id: decision_id.clone(),
                factor: *factor,
                outcome: *outcome,
                preceding_evidence: Vec::new(), // Could be populated with actual evidence analysis
            });
        }

        Ok(chain)
    }

    fn analyze_influence_breakdown(&self, subgraph: &CausalSubgraph) -> Result<BTreeMap<String, f64>, OperatorError> {
        let mut breakdown = BTreeMap::new();

        for edge in subgraph.edges.values() {
            let causation_type = format!("{:?}", edge.causation_type);
            *breakdown.entry(causation_type).or_insert(0.0) += edge.weight.to_f64();
        }

        Ok(breakdown)
    }

    fn identify_critical_paths(&self, subgraph: &CausalSubgraph) -> Result<Vec<CriticalPath>, OperatorError> {
        let mut paths = Vec::new();

        // Find paths with high cumulative influence
        for root in &subgraph.root_nodes {
            for leaf in &subgraph.leaf_nodes {
                let path = CriticalPath {
                    start_node: *root,
                    end_node: *leaf,
                    cumulative_influence: 0.5, // Placeholder calculation
                    description: format!("Path from {:?} to {:?}", root, leaf),
                };
                paths.push(path);
            }
        }

        Ok(paths)
    }
}

// ---------------------------------------------------------------------------
// Data Structures
// ---------------------------------------------------------------------------

/// Comprehensive investigation report for operators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationReport {
    /// Decision ID that was investigated.
    pub decision_id: String,
    /// Timestamp when investigation was conducted.
    pub investigation_timestamp_ns: u64,
    /// Causal explanation results.
    pub causal_explanation: CausalExplanationResult,
    /// Influence analysis results.
    pub influence_analysis: InfluenceAnalysisResult,
    /// Human-readable interpretation.
    pub interpretation: CausationInterpretation,
    /// Operator recommendations.
    pub recommendations: Vec<OperatorRecommendation>,
    /// frankentui visualization data.
    pub frankentui_data: Option<FrankentuiData>,
    /// Configuration used for analysis.
    pub operator_config: OperatorConfig,
}

/// Human-readable interpretation of causation data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausationInterpretation {
    /// Overall risk level assessment.
    pub risk_level: RiskLevel,
    /// Confidence in the analysis.
    pub confidence_level: ConfidenceLevel,
    /// Primary concerns identified.
    pub primary_concerns: Vec<String>,
    /// Human-readable narrative explanation.
    pub narrative: String,
    /// Technical notes for advanced operators.
    pub technical_notes: Vec<String>,
}

/// Reading of a causation subgraph for operators.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubgraphReading {
    /// High-level summary.
    pub summary: CausalSummaryText,
    /// Evidence factors identified.
    pub evidence_factors: Vec<EvidenceFactor>,
    /// Chain of decisions.
    pub decision_chain: Vec<DecisionStep>,
    /// Breakdown of influence by type.
    pub influence_breakdown: BTreeMap<String, f64>,
    /// Critical paths through the graph.
    pub critical_paths: Vec<CriticalPath>,
}

/// Text summary of causal analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalSummaryText {
    /// Total number of evidence sources.
    pub total_evidence_count: usize,
    /// Total number of decisions.
    pub total_decision_count: usize,
    /// Strongest single influence detected.
    pub strongest_influence: InfluenceWeight,
    /// Primary types of causation relationships.
    pub primary_causation_types: Vec<CausationType>,
    /// Overall confidence assessment.
    pub confidence_assessment: ConfidenceLevel,
}

impl Default for CausalSummaryText {
    fn default() -> Self {
        Self {
            total_evidence_count: 0,
            total_decision_count: 0,
            strongest_influence: InfluenceWeight::ZERO,
            primary_causation_types: Vec::new(),
            confidence_assessment: ConfidenceLevel::Low,
        }
    }
}

/// Individual evidence factor in operator-friendly format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceFactor {
    /// Node ID in the graph.
    pub node_id: NodeId,
    /// Evidence atom identifier.
    pub evidence_id: String,
    /// Categorized influence level.
    pub influence_level: InfluenceLevel,
    /// Categorized confidence level.
    pub confidence_level: ConfidenceLevel,
    /// Human-readable description.
    pub description: String,
}

/// Step in a decision chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionStep {
    /// Node ID of this decision.
    pub node_id: NodeId,
    /// Decision identifier.
    pub decision_id: String,
    /// Decision factor that was activated.
    pub factor: DecisionFactor,
    /// Outcome of the decision.
    pub outcome: DecisionOutcome,
    /// Evidence that preceded this decision.
    pub preceding_evidence: Vec<NodeId>,
}

/// Critical path through causation graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticalPath {
    /// Starting node of the path.
    pub start_node: NodeId,
    /// Ending node of the path.
    pub end_node: NodeId,
    /// Cumulative influence along this path.
    pub cumulative_influence: f64,
    /// Description of why this path is critical.
    pub description: String,
}

/// Recommendation for operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRecommendation {
    /// Category of recommendation.
    pub category: String,
    /// Priority level.
    pub priority: RecommendationPriority,
    /// Description of the recommendation.
    pub description: String,
    /// Specific action items.
    pub action_items: Vec<String>,
}

// ---------------------------------------------------------------------------
// Frankentui Integration
// ---------------------------------------------------------------------------

/// Data structure for frankentui visualization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrankentuiData {
    /// Schema version for compatibility.
    pub schema_version: String,
    /// Type of graph being visualized.
    pub graph_type: String,
    /// Nodes in the visualization.
    pub nodes: Vec<FrankentuiNode>,
    /// Edges in the visualization.
    pub edges: Vec<FrankentuiEdge>,
    /// Layout hints for rendering.
    pub layout_hints: FrankentuiLayoutHints,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

/// Node for frankentui visualization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrankentuiNode {
    /// Unique identifier.
    pub id: String,
    /// Display label.
    pub label: String,
    /// Type of node.
    pub node_type: String,
    /// Color for rendering.
    pub color: String,
    /// Size for rendering.
    pub size: String,
    /// Tooltip text.
    pub tooltip: String,
    /// Additional metadata.
    pub metadata: BTreeMap<String, String>,
}

/// Edge for frankentui visualization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrankentuiEdge {
    /// Source node ID.
    pub source: String,
    /// Target node ID.
    pub target: String,
    /// Edge weight.
    pub weight: f64,
    /// Type of causation.
    pub causation_type: String,
    /// Color for rendering.
    pub color: String,
    /// Line thickness.
    pub thickness: String,
    /// Tooltip text.
    pub tooltip: String,
}

/// Layout hints for frankentui rendering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrankentuiLayoutHints {
    /// Layout algorithm to use.
    pub algorithm: String,
    /// Root nodes for hierarchical layout.
    pub root_nodes: Vec<String>,
    /// Leaf nodes for hierarchical layout.
    pub leaf_nodes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Risk level assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low risk situation.
    Low,
    /// Medium risk requiring attention.
    Medium,
    /// High risk requiring action.
    High,
    /// Critical risk requiring immediate action.
    Critical,
    /// Unknown risk level.
    Unknown,
}

/// Confidence level in analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceLevel {
    /// Low confidence in analysis.
    Low,
    /// Medium confidence.
    Medium,
    /// High confidence.
    High,
}

/// Categorized influence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InfluenceLevel {
    /// Low influence.
    Low,
    /// Medium influence.
    Medium,
    /// High influence.
    High,
    /// Critical influence.
    Critical,
}

impl RiskLevel {
    /// Categorize risk level based on confidence score (in millionths).
    pub fn from_confidence(confidence: u64) -> Self {
        if confidence >= 900_000 { // >= 0.90
            RiskLevel::Low
        } else if confidence >= 700_000 { // >= 0.70
            RiskLevel::Medium
        } else if confidence >= 400_000 { // >= 0.40
            RiskLevel::High
        } else {
            RiskLevel::Critical
        }
    }
}

impl ConfidenceLevel {
    /// Categorize confidence level based on value (in millionths).
    pub fn from_value(value: u64) -> Self {
        if value >= 800_000 { // >= 0.80
            ConfidenceLevel::High
        } else if value >= 600_000 { // >= 0.60
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        }
    }
}

impl InfluenceLevel {
    /// Categorize influence level based on weight (in millionths).
    pub fn from_weight(weight: u64) -> Self {
        if weight >= 800_000 { // >= 0.80
            InfluenceLevel::Critical
        } else if weight >= 600_000 { // >= 0.60
            InfluenceLevel::High
        } else if weight >= 400_000 { // >= 0.40
            InfluenceLevel::Medium
        } else {
            InfluenceLevel::Low
        }
    }
}

/// Priority level for recommendations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationPriority {
    /// Low priority.
    Low,
    /// Medium priority.
    Medium,
    /// High priority.
    High,
    /// Critical priority.
    Critical,
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors that can occur in operator interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorError {
    /// Query execution failed.
    QueryFailed(String),
    /// Invalid configuration.
    InvalidConfig(String),
    /// Frankentui formatting error.
    FrankentuiError(String),
    /// Report generation error.
    ReportGenerationError(String),
    /// Underlying query error.
    QueryError(QueryError),
}

impl fmt::Display for OperatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OperatorError::QueryFailed(msg) => write!(f, "Query failed: {}", msg),
            OperatorError::InvalidConfig(msg) => write!(f, "Invalid configuration: {}", msg),
            OperatorError::FrankentuiError(msg) => write!(f, "frankentui error: {}", msg),
            OperatorError::ReportGenerationError(msg) => write!(f, "Report generation error: {}", msg),
            OperatorError::QueryError(e) => write!(f, "Query error: {}", e),
        }
    }
}

impl std::error::Error for OperatorError {}

impl From<QueryError> for OperatorError {
    fn from(error: QueryError) -> Self {
        OperatorError::QueryError(error)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operator_config_default() {
        let config = OperatorConfig::default();

        assert_eq!(config.min_influence_threshold.millionths, DEFAULT_INFLUENCE_THRESHOLD);
        assert!(!config.include_weak_influences);
        assert_eq!(config.max_causal_depth, 10);
        assert!(config.enable_frankentui);
        assert_eq!(config.verbosity_level, 1);
    }

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_confidence_level_ordering() {
        assert!(ConfidenceLevel::Low < ConfidenceLevel::Medium);
        assert!(ConfidenceLevel::Medium < ConfidenceLevel::High);
    }

    #[test]
    fn test_influence_level_categorization() {
        let operator_config = OperatorConfig::default();
        let query_engine = ForensicQueryEngine::new(CausationGraph::new());
        let operator = ForensicOperator::with_config(query_engine, operator_config);

        assert_eq!(operator.categorize_influence_level(50_000), InfluenceLevel::Low);
        assert_eq!(operator.categorize_influence_level(200_000), InfluenceLevel::Medium);
        assert_eq!(operator.categorize_influence_level(800_000), InfluenceLevel::High);
        assert_eq!(operator.categorize_influence_level(950_000), InfluenceLevel::Critical);
    }

    #[test]
    fn test_recommendation_priority_ordering() {
        assert!(RecommendationPriority::Low < RecommendationPriority::Medium);
        assert!(RecommendationPriority::Medium < RecommendationPriority::High);
        assert!(RecommendationPriority::High < RecommendationPriority::Critical);
    }

    #[test]
    fn test_frankentui_data_serialization() {
        let data = FrankentuiData {
            schema_version: OPERATOR_SURFACE_SCHEMA_VERSION.to_string(),
            graph_type: "causation".to_string(),
            nodes: vec![FrankentuiNode {
                id: "1".to_string(),
                label: "Test Evidence".to_string(),
                node_type: "evidence".to_string(),
                color: "green".to_string(),
                size: "medium".to_string(),
                tooltip: "Test tooltip".to_string(),
                metadata: BTreeMap::new(),
            }],
            edges: vec![],
            layout_hints: FrankentuiLayoutHints {
                algorithm: "hierarchical".to_string(),
                root_nodes: vec!["1".to_string()],
                leaf_nodes: vec!["1".to_string()],
            },
            metadata: BTreeMap::new(),
        };

        let serialized = serde_json::to_string(&data).unwrap();
        let deserialized: FrankentuiData = serde_json::from_str(&serialized).unwrap();

        assert_eq!(data, deserialized);
    }
}