//! Integration tests for forensic causation operator surface.

use frankenengine_engine::causation_graph_schema::*;
use frankenengine_engine::forensic_query_api::*;
use frankenengine_engine::forensic_causation_operator::*;
use std::collections::BTreeMap;

/// Create a test causation graph with decision nodes and evidence.
fn create_test_causation_graph() -> CausationGraph {
    let mut graph = CausationGraph::new();

    // Create decision node
    let decision_node = CausationNode {
        node_id: "decision_1".to_string(),
        node_type: NodeType::Decision,
        decision_factors: vec![
            DecisionFactor {
                factor_id: "factor_1".to_string(),
                factor_type: FactorType::SecurityPolicy,
                description: "Security policy violation detected".to_string(),
                influence_weight: 750_000, // 0.75
                confidence: 900_000, // 0.90
                evidence_refs: vec!["evidence_1".to_string()],
            },
            DecisionFactor {
                factor_id: "factor_2".to_string(),
                factor_type: FactorType::UserAction,
                description: "Unauthorized access attempt".to_string(),
                influence_weight: 850_000, // 0.85
                confidence: 950_000, // 0.95
                evidence_refs: vec!["evidence_2".to_string()],
            },
        ],
        evidence_atoms: BTreeMap::new(),
        content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"decision_node_data"),
    };

    // Create evidence nodes
    let evidence_node_1 = CausationNode {
        node_id: "evidence_1".to_string(),
        node_type: NodeType::Evidence,
        decision_factors: vec![],
        evidence_atoms: {
            let mut atoms = BTreeMap::new();
            atoms.insert(
                "access_log".to_string(),
                EvidenceAtom {
                    atom_id: "access_log".to_string(),
                    atom_type: AtomType::SystemEvent,
                    timestamp: 1640995200, // 2022-01-01 00:00:00 UTC
                    data_hash: frankenengine_engine::content_hash::ContentHash::compute(b"access_log_data"),
                    integrity_proof: "proof_1".to_string(),
                    source_system: "auth_system".to_string(),
                },
            );
            atoms
        },
        content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"evidence_node_1"),
    };

    let evidence_node_2 = CausationNode {
        node_id: "evidence_2".to_string(),
        node_type: NodeType::Evidence,
        decision_factors: vec![],
        evidence_atoms: {
            let mut atoms = BTreeMap::new();
            atoms.insert(
                "user_action".to_string(),
                EvidenceAtom {
                    atom_id: "user_action".to_string(),
                    atom_type: AtomType::UserAction,
                    timestamp: 1640995260, // 2022-01-01 00:01:00 UTC
                    data_hash: frankenengine_engine::content_hash::ContentHash::compute(b"user_action_data"),
                    integrity_proof: "proof_2".to_string(),
                    source_system: "application".to_string(),
                },
            );
            atoms
        },
        content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"evidence_node_2"),
    };

    // Add nodes to graph
    graph.add_node(decision_node).unwrap();
    graph.add_node(evidence_node_1).unwrap();
    graph.add_node(evidence_node_2).unwrap();

    // Add causal edges
    let edge_1 = CausationEdge {
        edge_id: "edge_1".to_string(),
        source_node: "evidence_1".to_string(),
        target_node: "decision_1".to_string(),
        edge_type: EdgeType::Influences,
        causal_strength: 800_000, // 0.80
        temporal_ordering: TemporalOrder::Before,
        edge_metadata: EdgeMetadata {
            confidence: 900_000, // 0.90
            evidence_quality: EvidenceQuality::High,
            causal_mechanism: "policy_enforcement".to_string(),
            counterfactual_strength: 750_000, // 0.75
        },
        content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"edge_1_data"),
    };

    let edge_2 = CausationEdge {
        edge_id: "edge_2".to_string(),
        source_node: "evidence_2".to_string(),
        target_node: "decision_1".to_string(),
        edge_type: EdgeType::Influences,
        causal_strength: 900_000, // 0.90
        temporal_ordering: TemporalOrder::Before,
        edge_metadata: EdgeMetadata {
            confidence: 950_000, // 0.95
            evidence_quality: EvidenceQuality::High,
            causal_mechanism: "user_behavior_analysis".to_string(),
            counterfactual_strength: 850_000, // 0.85
        },
        content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"edge_2_data"),
    };

    graph.add_edge(edge_1).unwrap();
    graph.add_edge(edge_2).unwrap();

    graph
}

/// Create a test forensic query engine with the test graph.
fn create_test_query_engine() -> ForensicQueryEngine {
    let graph = create_test_causation_graph();
    ForensicQueryEngine::new(graph)
}

/// Create a test operator configuration.
fn create_test_operator_config() -> OperatorConfig {
    OperatorConfig {
        min_influence_threshold: InfluenceWeight::from_millionths(500_000), // 0.50
        include_weak_influences: true,
        max_causal_depth: 10,
        enable_frankentui: true,
        verbosity_level: 2, // verbose
    }
}

/// Create a test causal subgraph.
fn create_test_subgraph() -> CausalSubgraph {
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeMap::new();

    // Add decision node
    nodes.insert(
        "decision_1".to_string(),
        CausationNode {
            node_id: "decision_1".to_string(),
            node_type: NodeType::Decision,
            decision_factors: vec![
                DecisionFactor {
                    factor_id: "factor_1".to_string(),
                    factor_type: FactorType::SecurityPolicy,
                    description: "Security policy violation detected".to_string(),
                    influence_weight: 750_000,
                    confidence: 900_000,
                    evidence_refs: vec!["evidence_1".to_string()],
                },
            ],
            evidence_atoms: BTreeMap::new(),
            content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"decision_node"),
        },
    );

    // Add evidence node
    nodes.insert(
        "evidence_1".to_string(),
        CausationNode {
            node_id: "evidence_1".to_string(),
            node_type: NodeType::Evidence,
            decision_factors: vec![],
            evidence_atoms: {
                let mut atoms = BTreeMap::new();
                atoms.insert(
                    "access_log".to_string(),
                    EvidenceAtom {
                        atom_id: "access_log".to_string(),
                        atom_type: AtomType::SystemEvent,
                        timestamp: 1640995200,
                        data_hash: frankenengine_engine::content_hash::ContentHash::compute(b"access_log"),
                        integrity_proof: "proof_1".to_string(),
                        source_system: "auth_system".to_string(),
                    },
                );
                atoms
            },
            content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"evidence_node"),
        },
    );

    // Add edge
    edges.insert(
        "edge_1".to_string(),
        CausationEdge {
            edge_id: "edge_1".to_string(),
            source_node: "evidence_1".to_string(),
            target_node: "decision_1".to_string(),
            edge_type: EdgeType::Influences,
            causal_strength: 800_000,
            temporal_ordering: TemporalOrder::Before,
            edge_metadata: EdgeMetadata {
                confidence: 900_000,
                evidence_quality: EvidenceQuality::High,
                causal_mechanism: "policy_enforcement".to_string(),
                counterfactual_strength: 750_000,
            },
            content_hash: frankenengine_engine::content_hash::ContentHash::compute(b"edge_data"),
        },
    );

    CausalSubgraph {
        nodes,
        edges,
        root_nodes: vec!["decision_1".to_string()],
        leaf_nodes: vec!["evidence_1".to_string()],
        total_influence: InfluenceWeight::from_millionths(800_000),
    }
}

#[test]
fn test_forensic_operator_creation() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);

    // Verify operator is created with default config
    assert_eq!(operator.config.max_causal_depth, 10);
    assert_eq!(operator.config.min_influence_threshold.millionths, 100_000); // DEFAULT_INFLUENCE_THRESHOLD
    assert_eq!(operator.config.verbosity_level, 1);
    assert!(operator.config.enable_frankentui);
}

#[test]
fn test_forensic_operator_with_custom_config() {
    let query_engine = create_test_query_engine();
    let config = create_test_operator_config();
    let operator = ForensicOperator::with_config(query_engine, config);

    // Verify operator uses custom config
    assert_eq!(operator.config.max_causal_depth, 10);
    assert_eq!(operator.config.min_influence_threshold.millionths, 500_000);
    assert_eq!(operator.config.verbosity_level, 2);
    assert!(operator.config.include_weak_influences);
}

#[test]
fn test_investigate_decision() {
    let query_engine = create_test_query_engine();
    let config = create_test_operator_config();
    let mut operator = ForensicOperator::with_config(query_engine, config);

    let result = operator.investigate_decision("decision_1");
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.decision_id, "decision_1");
    assert!(report.investigation_timestamp > 0);
    assert!(!report.summary.is_empty());
    assert!(!report.interpretations.is_empty());
    assert!(!report.recommendations.is_empty());

    // Verify interpretations contain expected content
    let interpretation = &report.interpretations[0];
    assert!(!interpretation.key_factors.is_empty());
    assert!(!interpretation.critical_paths.is_empty());
    assert!(interpretation.overall_confidence >= 500_000);

    // Verify recommendations are provided
    assert!(!report.recommendations.is_empty());
}

#[test]
fn test_investigate_decision_missing_node() {
    let query_engine = create_test_query_engine();
    let mut operator = ForensicOperator::new(query_engine);

    let result = operator.investigate_decision("nonexistent_decision");
    assert!(result.is_err());

    if let Err(error) = result {
        assert!(matches!(error, OperatorError::QueryEngineError(_)));
    }
}

#[test]
fn test_read_causation_subgraph() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);
    let subgraph = create_test_subgraph();

    let result = operator.read_causation_subgraph(&subgraph);
    assert!(result.is_ok());

    let reading = result.unwrap();
    assert!(!reading.summary.narrative.is_empty());
    assert!(!reading.summary.key_insights.is_empty());
    assert!(!reading.decision_chain.is_empty());

    // Verify decision steps contain expected content
    let decision_step = &reading.decision_chain[0];
    assert_eq!(decision_step.step_id, "decision_1");
    assert!(decision_step.influence_score >= 0.0);
    assert!(!decision_step.evidence_summary.is_empty());

    // Verify critical paths are identified
    assert!(!reading.critical_paths.is_empty());
    let critical_path = &reading.critical_paths[0];
    assert!(!critical_path.path_nodes.is_empty());
    assert!(critical_path.overall_influence >= 0);
}

#[test]
fn test_read_empty_subgraph() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);

    let empty_subgraph = CausalSubgraph {
        nodes: BTreeMap::new(),
        edges: BTreeMap::new(),
        root_nodes: vec![],
        leaf_nodes: vec![],
        total_influence: InfluenceWeight::from_millionths(0),
    };

    let result = operator.read_causation_subgraph(&empty_subgraph);
    assert!(result.is_ok());

    let reading = result.unwrap();
    assert!(reading.decision_chain.is_empty());
    assert!(reading.critical_paths.is_empty());
    assert!(reading.summary.narrative.contains("empty") || reading.summary.narrative.contains("no"));
}

#[test]
fn test_format_for_frankentui() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);
    let subgraph = create_test_subgraph();

    let result = operator.format_for_frankentui(&subgraph);
    assert!(result.is_ok());

    let frankentui_data = result.unwrap();
    assert!(!frankentui_data.nodes.is_empty());
    assert!(!frankentui_data.edges.is_empty());

    // Verify node data
    let node = &frankentui_data.nodes[0];
    assert!(!node.id.is_empty());
    assert!(!node.label.is_empty());
    assert!(node.node_type == "decision" || node.node_type == "evidence");

    // Verify edge data
    let edge = &frankentui_data.edges[0];
    assert!(!edge.source.is_empty());
    assert!(!edge.target.is_empty());
    assert!(edge.weight >= 0.0 && edge.weight <= 1.0);

    // Verify layout hints
    assert!(frankentui_data.layout_hints.enable_clustering);
    assert!(frankentui_data.layout_hints.temporal_ordering);
    assert!(frankentui_data.layout_hints.decision_node_prominence);
}

#[test]
fn test_generate_investigation_report() {
    let query_engine = create_test_query_engine();
    let config = create_test_operator_config();
    let mut operator = ForensicOperator::with_config(query_engine, config);

    let result = operator.generate_investigation_report("decision_1");
    assert!(result.is_ok());

    let report_text = result.unwrap();
    assert!(!report_text.is_empty());
    assert!(report_text.contains("FORENSIC INVESTIGATION REPORT"));
    assert!(report_text.contains("Decision ID: decision_1"));
    assert!(report_text.contains("Investigation Summary"));
    assert!(report_text.contains("Critical Paths"));
    assert!(report_text.contains("Operator Recommendations"));
}

#[test]
fn test_report_verbosity_levels() {
    let query_engine = create_test_query_engine();

    // Test brief verbosity
    let brief_config = OperatorConfig {
        verbosity_level: 0,
        ..create_test_operator_config()
    };
    let mut brief_operator = ForensicOperator::with_config(create_test_query_engine(), brief_config);
    let brief_result = brief_operator.generate_investigation_report("decision_1").unwrap();

    // Test detailed verbosity
    let detailed_config = OperatorConfig {
        verbosity_level: 2,
        ..create_test_operator_config()
    };
    let mut detailed_operator = ForensicOperator::with_config(create_test_query_engine(), detailed_config);
    let detailed_result = detailed_operator.generate_investigation_report("decision_1").unwrap();

    // Detailed report should be longer than brief report
    assert!(detailed_result.len() > brief_result.len());
}

#[test]
fn test_operator_error_handling() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);

    // Test with malformed subgraph
    let malformed_subgraph = CausalSubgraph {
        nodes: BTreeMap::new(),
        edges: BTreeMap::new(),
        root_nodes: vec!["nonexistent".to_string()], // Reference to non-existent node
        leaf_nodes: vec![],
        total_influence: InfluenceWeight::from_millionths(0),
    };

    let result = operator.read_causation_subgraph(&malformed_subgraph);
    // Should handle gracefully even with malformed data
    assert!(result.is_ok());
}

#[test]
fn test_risk_level_assessment() {
    // Test risk level categorization
    assert!(matches!(RiskLevel::from_confidence(950_000), RiskLevel::Low));
    assert!(matches!(RiskLevel::from_confidence(750_000), RiskLevel::Medium));
    assert!(matches!(RiskLevel::from_confidence(450_000), RiskLevel::High));
    assert!(matches!(RiskLevel::from_confidence(250_000), RiskLevel::Critical));
}

#[test]
fn test_confidence_level_assessment() {
    // Test confidence level categorization
    assert!(matches!(ConfidenceLevel::from_value(950_000), ConfidenceLevel::High));
    assert!(matches!(ConfidenceLevel::from_value(750_000), ConfidenceLevel::Medium));
    assert!(matches!(ConfidenceLevel::from_value(450_000), ConfidenceLevel::Low));
}

#[test]
fn test_influence_level_assessment() {
    // Test influence level categorization
    assert!(matches!(InfluenceLevel::from_weight(900_000), InfluenceLevel::Critical));
    assert!(matches!(InfluenceLevel::from_weight(700_000), InfluenceLevel::High));
    assert!(matches!(InfluenceLevel::from_weight(500_000), InfluenceLevel::Medium));
    assert!(matches!(InfluenceLevel::from_weight(200_000), InfluenceLevel::Low));
}

#[test]
fn test_temporal_ordering_analysis() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);
    let subgraph = create_test_subgraph();

    let reading = operator.read_causation_subgraph(&subgraph).unwrap();

    // Verify temporal ordering is considered in critical paths
    for path in &reading.critical_paths {
        assert!(!path.path_nodes.is_empty());
        // Path should have valid timeline
        assert!(path.temporal_span.0 <= path.temporal_span.1);
    }
}

#[test]
fn test_evidence_quality_impact() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);
    let subgraph = create_test_subgraph();

    let reading = operator.read_causation_subgraph(&subgraph).unwrap();

    // Verify evidence quality affects confidence calculations
    for step in &reading.decision_steps {
        // High-quality evidence should result in higher confidence
        if step.evidence_summary.contains("High") {
            assert!(step.confidence_score >= 700_000);
        }
    }
}

#[test]
fn test_counterfactual_analysis_integration() {
    let query_engine = create_test_query_engine();
    let config = OperatorConfig {
        max_causal_depth: 2, // Use this field instead
        ..create_test_operator_config()
    };
    let mut operator = ForensicOperator::with_config(query_engine, config);

    let report = operator.investigate_decision("decision_1").unwrap();

    // Verify counterfactual analysis is included in recommendations
    let has_counterfactual = report.recommendations.iter().any(|r|
        r.recommendation_text.to_lowercase().contains("what if") ||
        r.recommendation_text.to_lowercase().contains("counterfactual")
    );

    // With counterfactual analysis enabled, should have related recommendations
    assert!(has_counterfactual || report.interpretations.iter().any(|i|
        i.key_factors.iter().any(|f| f.factor_description.contains("counterfactual"))
    ));
}

#[test]
fn test_frankentui_layout_optimization() {
    let query_engine = create_test_query_engine();
    let operator = ForensicOperator::new(query_engine);
    let subgraph = create_test_subgraph();

    let frankentui_data = operator.format_for_frankentui(&subgraph).unwrap();

    // Verify layout hints are optimized for operator use
    assert!(frankentui_data.layout_hints.enable_clustering);
    assert!(frankentui_data.layout_hints.temporal_ordering);
    assert!(frankentui_data.layout_hints.decision_node_prominence);

    // Verify decision nodes have special formatting
    let decision_nodes: Vec<_> = frankentui_data.nodes.iter()
        .filter(|n| matches!(n.node_type, NodeType::Decision))
        .collect();

    for decision_node in decision_nodes {
        assert!(decision_node.size == "large" || decision_node.size == "extra_large"); // Should be emphasized
    }
}

#[test]
fn test_operator_schema_constants() {
    // Verify schema constants are properly defined
    assert_eq!(OPERATOR_SURFACE_SCHEMA_VERSION, "franken-engine.forensic-operator.v1");
    assert_eq!(OPERATOR_SURFACE_COMPONENT, "forensic_causation_operator");
    assert_eq!(OPERATOR_SURFACE_POLICY_ID, "FF-4");
}

#[test]
fn test_report_serialization() {
    let query_engine = create_test_query_engine();
    let mut operator = ForensicOperator::new(query_engine);

    let report = operator.investigate_decision("decision_1").unwrap();

    // Test that report can be serialized (all fields implement serde traits)
    let serialized = serde_json::to_string(&report);
    assert!(serialized.is_ok());

    // Test deserialization
    let deserialized: Result<InvestigationReport, _> = serde_json::from_str(&serialized.unwrap());
    assert!(deserialized.is_ok());

    let restored_report = deserialized.unwrap();
    assert_eq!(restored_report.decision_id, report.decision_id);
    assert_eq!(restored_report.summary, report.summary);
}