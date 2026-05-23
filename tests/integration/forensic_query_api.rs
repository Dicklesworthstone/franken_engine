//! Integration tests for forensic query API.

use std::collections::BTreeMap;

use frankenengine_engine::forensic_query_api::*;
use frankenengine_engine::causation_graph_schema::*;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::minimal_causal_set_inference::{CausalDependency, DecisionFactor};

fn create_comprehensive_test_graph() -> CausationGraph {
    let mut graph = CausationGraph::new();

    // Create evidence atoms
    for i in 1..=3 {
        let evidence_node = CausationNode {
            id: NodeId(i),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    atom_id: format!("evidence-{}", i),
                    influence_millionths: 300_000 + i * 100_000,
                    content_hash: ContentHash::compute(format!("evidence-data-{}", i).as_bytes()),
                },
                evidence_hash: ContentHash::compute(format!("evidence-hash-{}", i).as_bytes()),
                confidence_millionths: 800_000 + i * 50_000,
            },
            content_hash: ContentHash::compute(format!("evidence-node-{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::compute_keyed(
                format!("evidence-{}", i).as_bytes(),
                b"key"
            ),
            timestamp_ns: 1640995200000000000 + i * 1000000,
            metadata: BTreeMap::new(),
        };
        graph.add_node(evidence_node).expect("Failed to add evidence node");
    }

    // Create aggregate influence node
    let aggregate_node = CausationNode {
        id: NodeId(4),
        node_type: NodeType::AggregateInfluence {
            source_nodes: vec![NodeId(1), NodeId(2), NodeId(3)],
            total_weight: InfluenceWeight::from_millionths(750_000),
            method: AggregationMethod::WeightedAverage,
        },
        content_hash: ContentHash::compute(b"aggregate-node"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"aggregate", b"key"),
        timestamp_ns: 1640995200004000000,
        metadata: BTreeMap::new(),
    };
    graph.add_node(aggregate_node).expect("Failed to add aggregate node");

    // Create decision nodes
    for i in 0..2 {
        let decision_node = CausationNode {
            id: NodeId(5 + i),
            node_type: NodeType::Decision {
                decision_id: format!("security-decision-{}", i + 1),
                factor: if i == 0 { DecisionFactor::GuardrailActivation } else { DecisionFactor::LossMatrix },
                context_hash: ContentHash::compute(format!("decision-context-{}", i).as_bytes()),
                outcome: if i == 0 { DecisionOutcome::Quarantine } else { DecisionOutcome::Deny },
            },
            content_hash: ContentHash::compute(format!("decision-node-{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::compute_keyed(
                format!("decision-{}", i).as_bytes(),
                b"key"
            ),
            timestamp_ns: 1640995200005000000 + i * 1000000,
            metadata: BTreeMap::new(),
        };
        graph.add_node(decision_node).expect("Failed to add decision node");
    }

    // Add causal edges: evidence -> aggregate -> decisions
    for i in 1..=3 {
        let edge = CausationEdge {
            id: EdgeId(i),
            source: NodeId(i),
            target: NodeId(4), // to aggregate
            weight: InfluenceWeight::from_millionths(300_000 + i * 100_000),
            causation_type: CausationType::Evidential,
            content_hash: ContentHash::compute(format!("evidence-edge-{}", i).as_bytes()),
            timestamp_ns: 1640995200000000000 + i * 500000,
            metadata: BTreeMap::new(),
        };
        graph.add_edge(edge).expect("Failed to add evidence edge");
    }

    // Add edges: aggregate -> decisions
    for i in 0..2 {
        let edge = CausationEdge {
            id: EdgeId(4 + i),
            source: NodeId(4), // from aggregate
            target: NodeId(5 + i), // to decisions
            weight: InfluenceWeight::from_millionths(850_000 - i * 100_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(format!("decision-edge-{}", i).as_bytes()),
            timestamp_ns: 1640995200004500000 + i * 500000,
            metadata: BTreeMap::new(),
        };
        graph.add_edge(edge).expect("Failed to add decision edge");
    }

    graph
}

#[test]
fn test_forensic_query_engine_initialization() {
    let graph = create_comprehensive_test_graph();
    let engine = ForensicQueryEngine::new(graph.clone());

    // Verify engine was created with default config
    assert_eq!(engine.config.max_execution_time_us, 10_000_000);
    assert!(engine.config.enable_caching);
    assert_eq!(engine.config.max_subgraph_size, 1000);

    // Test with custom config
    let custom_config = QueryEngineConfig {
        max_execution_time_us: 5_000_000,
        max_subgraph_size: 500,
        enable_caching: false,
        default_influence_threshold: InfluenceWeight::from_millionths(200_000),
    };

    let custom_engine = ForensicQueryEngine::with_config(graph, custom_config);
    assert_eq!(custom_engine.config.max_execution_time_us, 5_000_000);
    assert!(!custom_engine.config.enable_caching);
}

#[test]
fn test_decision_node_discovery() {
    let graph = create_comprehensive_test_graph();
    let engine = ForensicQueryEngine::new(graph);

    // Test finding existing decisions
    let node_id_1 = engine.find_decision_node("security-decision-1").unwrap();
    assert_eq!(node_id_1, NodeId(5));

    let node_id_2 = engine.find_decision_node("security-decision-2").unwrap();
    assert_eq!(node_id_2, NodeId(6));

    // Test finding non-existent decision
    let not_found = engine.find_decision_node("non-existent-decision");
    assert!(matches!(not_found, Err(QueryError::DecisionNotFound(_))));
}

#[test]
fn test_causal_subgraph_extraction() {
    let graph = create_comprehensive_test_graph();
    let engine = ForensicQueryEngine::new(graph);

    // Extract subgraph for first decision
    let subgraph = engine.extract_causal_subgraph(NodeId(5), 10).unwrap();

    // Should include: 3 evidence nodes + 1 aggregate + 1 decision = 5 nodes
    assert_eq!(subgraph.nodes.len(), 5);

    // Should include: 3 evidence->aggregate edges + 1 aggregate->decision edge = 4 edges
    assert_eq!(subgraph.edges.len(), 4);

    // Verify root and leaf nodes
    assert_eq!(subgraph.leaf_nodes.len(), 1); // Decision node is leaf
    assert_eq!(subgraph.root_nodes.len(), 3); // Evidence nodes are roots

    // Verify total influence is accumulated
    assert!(subgraph.total_influence.millionths > 0);

    // Test extraction with limited depth
    let shallow_subgraph = engine.extract_causal_subgraph(NodeId(5), 1).unwrap();
    assert!(shallow_subgraph.nodes.len() <= subgraph.nodes.len());
}

#[test]
fn test_causal_explanation_query() {
    let graph = create_comprehensive_test_graph();
    let mut engine = ForensicQueryEngine::new(graph);

    let query = ForensicQuery {
        query_id: "explanation-test-1".to_string(),
        query_type: QueryType::CausalExplanation {
            max_depth: 5,
            include_weak_influences: true,
        },
        target: QueryTarget::Decision("security-decision-1".to_string()),
        parameters: QueryParameters {
            limit: None,
            include_trace: false,
            include_raw_data: false,
            causation_type_filter: None,
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200010000000,
    };

    let result = engine.execute_query(query).unwrap();

    assert_eq!(result.status, QueryStatus::Success);
    assert!(matches!(result.result, QueryResult::CausalExplanation(_)));

    if let QueryResult::CausalExplanation(explanation) = result.result {
        // Verify decision node is correct
        assert_eq!(explanation.decision_node.id, NodeId(5));

        // Verify causal subgraph contains expected elements
        assert!(explanation.causal_subgraph.nodes.len() > 1);
        assert!(explanation.causal_subgraph.edges.len() > 0);

        // Verify causal summary
        assert!(explanation.causal_summary.evidence_count > 0);
        assert!(!explanation.causal_summary.activated_factors.is_empty());
        assert!(!explanation.causal_summary.explanation.is_empty());

        // Verify metadata
        assert!(result.metadata.nodes_examined > 0);
        assert!(result.metadata.edges_traversed > 0);
    }
}

#[test]
fn test_causal_explanation_with_node_target() {
    let graph = create_comprehensive_test_graph();
    let mut engine = ForensicQueryEngine::new(graph);

    let query = ForensicQuery {
        query_id: "explanation-node-target".to_string(),
        query_type: QueryType::CausalExplanation {
            max_depth: 3,
            include_weak_influences: false,
        },
        target: QueryTarget::Node(NodeId(6)), // Direct node targeting
        parameters: QueryParameters {
            limit: Some(20),
            include_trace: true,
            include_raw_data: false,
            causation_type_filter: Some(vec![CausationType::Direct, CausationType::Evidential]),
            decision_factor_filter: Some(vec![DecisionFactor::LossMatrix]),
        },
        timestamp_ns: 1640995200015000000,
    };

    let result = engine.execute_query(query).unwrap();
    assert_eq!(result.status, QueryStatus::Success);

    if let QueryResult::CausalExplanation(explanation) = result.result {
        assert_eq!(explanation.decision_node.id, NodeId(6));

        // Verify causation type filtering worked
        for edge in explanation.causal_subgraph.edges.values() {
            assert!(matches!(edge.causation_type, CausationType::Direct | CausationType::Evidential));
        }
    }
}

#[test]
fn test_influence_analysis_query() {
    let graph = create_comprehensive_test_graph();
    let mut engine = ForensicQueryEngine::new(graph);

    let query = ForensicQuery {
        query_id: "influence-analysis-1".to_string(),
        query_type: QueryType::InfluenceAnalysis {
            min_influence_threshold: InfluenceWeight::from_millionths(200_000),
            rank_by_strength: true,
        },
        target: QueryTarget::Decision("security-decision-1".to_string()),
        parameters: QueryParameters {
            limit: Some(10),
            include_trace: false,
            include_raw_data: true,
            causation_type_filter: None,
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200020000000,
    };

    let result = engine.execute_query(query).unwrap();
    assert_eq!(result.status, QueryStatus::Success);
    assert!(matches!(result.result, QueryResult::InfluenceAnalysis(_)));
}

#[test]
fn test_counterfactual_analysis_query() {
    let graph = create_comprehensive_test_graph();
    let mut engine = ForensicQueryEngine::new(graph);

    let modifications = vec![
        EvidenceModification {
            evidence_id: "evidence-1".to_string(),
            new_influence: InfluenceWeight::from_millionths(100_000), // Reduced influence
            new_confidence_millionths: Some(600_000), // Reduced confidence
            description: "Reduce first evidence influence".to_string(),
        },
        EvidenceModification {
            evidence_id: "evidence-2".to_string(),
            new_influence: InfluenceWeight::from_millionths(900_000), // Increased influence
            new_confidence_millionths: Some(950_000), // High confidence
            description: "Boost second evidence influence".to_string(),
        },
    ];

    let query = ForensicQuery {
        query_id: "counterfactual-1".to_string(),
        query_type: QueryType::CounterfactualAnalysis {
            modified_evidence: modifications,
            recompute_downstream: true,
        },
        target: QueryTarget::Decision("security-decision-1".to_string()),
        parameters: QueryParameters {
            limit: None,
            include_trace: true,
            include_raw_data: false,
            causation_type_filter: None,
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200025000000,
    };

    let result = engine.execute_query(query).unwrap();
    assert_eq!(result.status, QueryStatus::Success);
    assert!(matches!(result.result, QueryResult::CounterfactualAnalysis(_)));

    if let QueryResult::CounterfactualAnalysis(analysis) = result.result {
        assert!(matches!(analysis.original_outcome, DecisionOutcome::Allow | DecisionOutcome::Deny | DecisionOutcome::Quarantine));
        assert!(matches!(analysis.counterfactual_outcome, DecisionOutcome::Allow | DecisionOutcome::Deny | DecisionOutcome::Quarantine));
        assert!(analysis.outcome_change_probability.millionths <= 1_000_000);
        assert!(analysis.sensitivity_analysis.robustness_score >= 0.0);
        assert!(analysis.sensitivity_analysis.robustness_score <= 1.0);
    }
}

#[test]
fn test_timeline_reconstruction_query() {
    let graph = create_comprehensive_test_graph();
    let mut engine = ForensicQueryEngine::new(graph);

    let query = ForensicQuery {
        query_id: "timeline-reconstruction-1".to_string(),
        query_type: QueryType::TimelineReconstruction {
            start_timestamp_ns: 1640995200000000000,
            end_timestamp_ns: 1640995200010000000,
            sort_by_causation: true,
        },
        target: QueryTarget::Graph,
        parameters: QueryParameters {
            limit: Some(50),
            include_trace: false,
            include_raw_data: false,
            causation_type_filter: None,
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200030000000,
    };

    let result = engine.execute_query(query).unwrap();
    assert_eq!(result.status, QueryStatus::Success);
    assert!(matches!(result.result, QueryResult::TimelineReconstruction(_)));
}

#[test]
fn test_query_with_invalid_target() {
    let graph = create_comprehensive_test_graph();
    let mut engine = ForensicQueryEngine::new(graph);

    let query = ForensicQuery {
        query_id: "invalid-target".to_string(),
        query_type: QueryType::CausalExplanation {
            max_depth: 5,
            include_weak_influences: false,
        },
        target: QueryTarget::Graph, // Invalid for causal explanation
        parameters: QueryParameters {
            limit: None,
            include_trace: false,
            include_raw_data: false,
            causation_type_filter: None,
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200035000000,
    };

    let result = engine.execute_query(query).unwrap();
    assert_eq!(result.status, QueryStatus::Failed);
    assert!(matches!(result.result, QueryResult::Error(_)));
}

#[test]
fn test_query_serialization_and_deserialization() {
    let query = ForensicQuery {
        query_id: "serialization-test".to_string(),
        query_type: QueryType::InfluenceAnalysis {
            min_influence_threshold: InfluenceWeight::from_millionths(300_000),
            rank_by_strength: true,
        },
        target: QueryTarget::Decision("test-decision".to_string()),
        parameters: QueryParameters {
            limit: Some(15),
            include_trace: true,
            include_raw_data: false,
            causation_type_filter: Some(vec![CausationType::Direct, CausationType::Indirect]),
            decision_factor_filter: Some(vec![DecisionFactor::GuardrailActivation]),
        },
        timestamp_ns: 1640995200040000000,
    };

    // Test JSON serialization
    let json_serialized = serde_json::to_string(&query).expect("Failed to serialize to JSON");
    let json_deserialized: ForensicQuery = serde_json::from_str(&json_serialized)
        .expect("Failed to deserialize from JSON");
    assert_eq!(query, json_deserialized);

    // Verify specific fields
    assert_eq!(json_deserialized.query_id, "serialization-test");
    assert!(matches!(json_deserialized.query_type, QueryType::InfluenceAnalysis { .. }));
    assert!(matches!(json_deserialized.target, QueryTarget::Decision(_)));
}

#[test]
fn test_influence_weight_operations() {
    // Test creation from different sources
    let weight_from_millionths = InfluenceWeight::from_millionths(750_000);
    let weight_from_f64 = InfluenceWeight::from_f64(0.75);

    assert_eq!(weight_from_millionths.millionths, weight_from_f64.millionths);

    // Test conversion back to f64
    let converted_back = weight_from_millionths.to_f64();
    assert!((converted_back - 0.75).abs() < 1e-6);

    // Test constants
    assert_eq!(InfluenceWeight::MAX.to_f64(), 1.0);
    assert_eq!(InfluenceWeight::ZERO.to_f64(), 0.0);

    // Test ordering
    let weak = InfluenceWeight::from_millionths(100_000);
    let strong = InfluenceWeight::from_millionths(900_000);
    assert!(weak < strong);
    assert!(strong > InfluenceWeight::from_millionths(500_000));
}

#[test]
fn test_query_parameters_filtering() {
    let parameters = QueryParameters {
        limit: Some(25),
        include_trace: true,
        include_raw_data: false,
        causation_type_filter: Some(vec![
            CausationType::Direct,
            CausationType::Evidential,
            CausationType::Logical,
        ]),
        decision_factor_filter: Some(vec![
            DecisionFactor::GuardrailActivation,
            DecisionFactor::LossMatrix,
        ]),
    };

    // Test serialization preserves all filter options
    let serialized = serde_json::to_string(&parameters).unwrap();
    let deserialized: QueryParameters = serde_json::from_str(&serialized).unwrap();

    assert_eq!(parameters, deserialized);
    assert_eq!(deserialized.limit, Some(25));
    assert!(deserialized.include_trace);
    assert!(!deserialized.include_raw_data);
    assert_eq!(deserialized.causation_type_filter.as_ref().unwrap().len(), 3);
    assert_eq!(deserialized.decision_factor_filter.as_ref().unwrap().len(), 2);
}

#[test]
fn test_evidence_modification_for_counterfactuals() {
    let modification = EvidenceModification {
        evidence_id: "critical-evidence-123".to_string(),
        new_influence: InfluenceWeight::from_millionths(250_000),
        new_confidence_millionths: Some(700_000),
        description: "Simulating reduced confidence in critical evidence".to_string(),
    };

    // Test serialization
    let serialized = serde_json::to_string(&modification).unwrap();
    let deserialized: EvidenceModification = serde_json::from_str(&serialized).unwrap();

    assert_eq!(modification, deserialized);
    assert_eq!(deserialized.evidence_id, "critical-evidence-123");
    assert_eq!(deserialized.new_influence.millionths, 250_000);
    assert_eq!(deserialized.new_confidence_millionths, Some(700_000));
    assert!(deserialized.description.contains("reduced confidence"));
}

#[test]
fn test_comprehensive_query_workflow() {
    let graph = create_comprehensive_test_graph();
    let mut engine = ForensicQueryEngine::new(graph);

    // Step 1: Explain why a decision was made
    let explanation_query = ForensicQuery {
        query_id: "workflow-step-1".to_string(),
        query_type: QueryType::CausalExplanation {
            max_depth: 10,
            include_weak_influences: true,
        },
        target: QueryTarget::Decision("security-decision-1".to_string()),
        parameters: QueryParameters {
            limit: None,
            include_trace: true,
            include_raw_data: false,
            causation_type_filter: None,
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200050000000,
    };

    let explanation_result = engine.execute_query(explanation_query).unwrap();
    assert_eq!(explanation_result.status, QueryStatus::Success);

    // Step 2: Analyze influence factors
    let influence_query = ForensicQuery {
        query_id: "workflow-step-2".to_string(),
        query_type: QueryType::InfluenceAnalysis {
            min_influence_threshold: InfluenceWeight::from_millionths(100_000),
            rank_by_strength: true,
        },
        target: QueryTarget::Decision("security-decision-1".to_string()),
        parameters: QueryParameters {
            limit: Some(20),
            include_trace: false,
            include_raw_data: true,
            causation_type_filter: Some(vec![CausationType::Direct, CausationType::Evidential]),
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200055000000,
    };

    let influence_result = engine.execute_query(influence_query).unwrap();
    assert_eq!(influence_result.status, QueryStatus::Success);

    // Step 3: Perform counterfactual analysis
    let counterfactual_query = ForensicQuery {
        query_id: "workflow-step-3".to_string(),
        query_type: QueryType::CounterfactualAnalysis {
            modified_evidence: vec![EvidenceModification {
                evidence_id: "evidence-1".to_string(),
                new_influence: InfluenceWeight::from_millionths(50_000),
                new_confidence_millionths: Some(400_000),
                description: "Weakening primary evidence".to_string(),
            }],
            recompute_downstream: true,
        },
        target: QueryTarget::Decision("security-decision-1".to_string()),
        parameters: QueryParameters {
            limit: None,
            include_trace: true,
            include_raw_data: false,
            causation_type_filter: None,
            decision_factor_filter: None,
        },
        timestamp_ns: 1640995200060000000,
    };

    let counterfactual_result = engine.execute_query(counterfactual_query).unwrap();
    assert_eq!(counterfactual_result.status, QueryStatus::Success);

    // Verify all steps produced valid results
    assert!(explanation_result.metadata.execution_time_us > 0);
    assert!(influence_result.metadata.execution_time_us > 0);
    assert!(counterfactual_result.metadata.execution_time_us > 0);
}