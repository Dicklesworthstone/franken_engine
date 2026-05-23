//! Integration tests for causation graph schema.

use std::collections::BTreeMap;

use frankenengine_engine::causation_graph_schema::*;
use frankenengine_engine::hash_tiers::{AuthenticityHash, ContentHash};
use frankenengine_engine::minimal_causal_set_inference::{CausalDependency, DecisionFactor};

#[test]
fn test_full_causation_graph_workflow() {
    let mut graph = CausationGraph::new();

    // Create evidence atom node
    let evidence_node = CausationNode {
        id: NodeId(1),
        node_type: NodeType::EvidenceAtom {
            dependency: CausalDependency {
                atom_id: "security-check-failed".to_string(),
                influence_millionths: 800_000,
                content_hash: ContentHash::compute(b"suspicious-behavior"),
            },
            evidence_hash: ContentHash::compute(b"evidence-data"),
            confidence_millionths: 950_000,
        },
        content_hash: ContentHash::compute(b"evidence-node"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"evidence", b"signing-key"),
        timestamp_ns: 1640995200000000000, // 2022-01-01T00:00:00Z
        metadata: BTreeMap::new(),
    };

    // Create decision node
    let decision_node = CausationNode {
        id: NodeId(2),
        node_type: NodeType::Decision {
            decision_id: "access-control-decision".to_string(),
            factor: DecisionFactor::GuardrailActivation,
            context_hash: ContentHash::compute(b"access-request-context"),
            outcome: DecisionOutcome::Deny,
        },
        content_hash: ContentHash::compute(b"decision-node"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"decision", b"signing-key"),
        timestamp_ns: 1640995200100000000, // 100ms later
        metadata: BTreeMap::new(),
    };

    // Add nodes to graph
    graph.add_node(evidence_node).expect("Failed to add evidence node");
    graph.add_node(decision_node).expect("Failed to add decision node");

    // Create causation edge
    let causation_edge = CausationEdge {
        id: EdgeId(1),
        source: NodeId(1), // evidence influences decision
        target: NodeId(2),
        weight: InfluenceWeight::from_millionths(900_000), // strong influence
        causation_type: CausationType::Direct,
        content_hash: ContentHash::compute(b"causation-edge"),
        timestamp_ns: 1640995200050000000, // 50ms after evidence
        metadata: BTreeMap::new(),
    };

    // Add edge to graph
    graph.add_edge(causation_edge).expect("Failed to add causation edge");

    // Verify graph structure
    assert_eq!(graph.metadata.node_count, 2);
    assert_eq!(graph.metadata.edge_count, 1);
    assert_eq!(graph.topological_order.len(), 2);

    // Verify causation relationships
    let causes = graph.get_direct_causes(NodeId(2));
    assert_eq!(causes.len(), 1);
    assert_eq!(causes[0].id, NodeId(1));

    let effects = graph.get_direct_effects(NodeId(1));
    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].id, NodeId(2));

    // Test causal chain traversal
    let chain = graph.get_causal_chain(NodeId(2), 5).expect("Failed to get causal chain");
    assert!(chain.contains(&NodeId(1)));
    assert!(chain.contains(&NodeId(2)));
}

#[test]
fn test_complex_causation_graph() {
    let mut graph = CausationGraph::new();

    // Create multiple evidence atoms
    for i in 1..=3 {
        let evidence_node = CausationNode {
            id: NodeId(i),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    atom_id: format!("evidence-{}", i),
                    influence_millionths: 300_000 + i * 100_000,
                    content_hash: ContentHash::compute(format!("evidence-{}", i).as_bytes()),
                },
                evidence_hash: ContentHash::compute(format!("hash-{}", i).as_bytes()),
                confidence_millionths: 800_000 + i * 50_000,
            },
            content_hash: ContentHash::compute(format!("node-{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::compute_keyed(
                format!("node-{}", i).as_bytes(),
                b"key"
            ),
            timestamp_ns: 1640995200000000000 + i * 10000000,
            metadata: BTreeMap::new(),
        };
        graph.add_node(evidence_node).expect("Failed to add evidence node");
    }

    // Create aggregate influence node
    let aggregate_node = CausationNode {
        id: NodeId(4),
        node_type: NodeType::AggregateInfluence {
            source_nodes: vec![NodeId(1), NodeId(2), NodeId(3)],
            total_weight: InfluenceWeight::from_millionths(850_000),
            method: AggregationMethod::WeightedAverage,
        },
        content_hash: ContentHash::compute(b"aggregate-node"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"aggregate", b"key"),
        timestamp_ns: 1640995200040000000,
        metadata: BTreeMap::new(),
    };
    graph.add_node(aggregate_node).expect("Failed to add aggregate node");

    // Create final decision node
    let decision_node = CausationNode {
        id: NodeId(5),
        node_type: NodeType::Decision {
            decision_id: "final-security-decision".to_string(),
            factor: DecisionFactor::LossMatrix,
            context_hash: ContentHash::compute(b"security-context"),
            outcome: DecisionOutcome::Quarantine,
        },
        content_hash: ContentHash::compute(b"final-decision"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"final", b"key"),
        timestamp_ns: 1640995200050000000,
        metadata: BTreeMap::new(),
    };
    graph.add_node(decision_node).expect("Failed to add decision node");

    // Add edges: evidence -> aggregate -> decision
    for i in 1..=3 {
        let edge = CausationEdge {
            id: EdgeId(i),
            source: NodeId(i),
            target: NodeId(4), // all evidence feeds into aggregate
            weight: InfluenceWeight::from_millionths(300_000 + i * 100_000),
            causation_type: CausationType::Evidential,
            content_hash: ContentHash::compute(format!("edge-{}", i).as_bytes()),
            timestamp_ns: 1640995200000000000 + i * 5000000,
            metadata: BTreeMap::new(),
        };
        graph.add_edge(edge).expect("Failed to add evidence edge");
    }

    // Add edge: aggregate -> decision
    let final_edge = CausationEdge {
        id: EdgeId(4),
        source: NodeId(4),
        target: NodeId(5),
        weight: InfluenceWeight::from_millionths(950_000),
        causation_type: CausationType::Direct,
        content_hash: ContentHash::compute(b"final-edge"),
        timestamp_ns: 1640995200045000000,
        metadata: BTreeMap::new(),
    };
    graph.add_edge(final_edge).expect("Failed to add final edge");

    // Verify complex graph structure
    assert_eq!(graph.metadata.node_count, 5);
    assert_eq!(graph.metadata.edge_count, 4);

    // Test multi-level causal chain
    let decision_chain = graph.get_causal_chain(NodeId(5), 10)
        .expect("Failed to get decision causal chain");

    // Should include all nodes in the chain
    for i in 1..=5 {
        assert!(decision_chain.contains(&NodeId(i)));
    }

    // Test that aggregate has 3 direct causes
    let aggregate_causes = graph.get_direct_causes(NodeId(4));
    assert_eq!(aggregate_causes.len(), 3);

    // Test that decision has 1 direct cause (the aggregate)
    let decision_causes = graph.get_direct_causes(NodeId(5));
    assert_eq!(decision_causes.len(), 1);
    assert_eq!(decision_causes[0].id, NodeId(4));
}

#[test]
fn test_causation_types_and_weights() {
    let mut graph = CausationGraph::new();

    // Test all decision outcomes
    let outcomes = [
        DecisionOutcome::Allow,
        DecisionOutcome::Deny,
        DecisionOutcome::Modify,
        DecisionOutcome::Suspend,
        DecisionOutcome::Quarantine,
        DecisionOutcome::Challenge,
    ];

    let causation_types = [
        CausationType::Direct,
        CausationType::Indirect,
        CausationType::Correlational,
        CausationType::Temporal,
        CausationType::Logical,
        CausationType::Evidential,
    ];

    // Create nodes for each outcome type
    for (i, outcome) in outcomes.iter().enumerate() {
        let node_id = NodeId(i as u64 + 1);
        let node = CausationNode {
            id: node_id,
            node_type: NodeType::Decision {
                decision_id: format!("decision-{}", i),
                factor: DecisionFactor::PosteriorProbability,
                context_hash: ContentHash::compute(format!("context-{}", i).as_bytes()),
                outcome: *outcome,
            },
            content_hash: ContentHash::compute(format!("decision-node-{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::compute_keyed(
                format!("decision-{}", i).as_bytes(),
                b"key"
            ),
            timestamp_ns: 1640995200000000000 + i as u64 * 1000000,
            metadata: BTreeMap::new(),
        };
        graph.add_node(node).expect("Failed to add decision node");
    }

    // Test causation types with different weights
    for (i, causation_type) in causation_types.iter().enumerate() {
        if i == 0 { continue; } // Skip first iteration to avoid self-edge

        let edge_id = EdgeId(i as u64);
        let source_id = NodeId(i as u64);
        let target_id = NodeId(i as u64 + 1);

        let edge = CausationEdge {
            id: edge_id,
            source: source_id,
            target: target_id,
            weight: InfluenceWeight::from_millionths(200_000 + i as u32 * 100_000),
            causation_type: *causation_type,
            content_hash: ContentHash::compute(format!("edge-{}", i).as_bytes()),
            timestamp_ns: 1640995200000000000 + i as u64 * 2000000,
            metadata: BTreeMap::new(),
        };

        graph.add_edge(edge).expect("Failed to add typed edge");
    }

    // Verify all outcomes and types are preserved
    assert_eq!(graph.metadata.node_count, outcomes.len() as u64);
    assert_eq!(graph.metadata.edge_count, (causation_types.len() - 1) as u64);
}

#[test]
fn test_influence_weight_precision() {
    // Test precise weight conversion
    let weights = [0.0, 0.25, 0.5, 0.75, 1.0, 0.123456];

    for &weight in &weights {
        let influence_weight = InfluenceWeight::from_f64(weight);
        let converted_back = influence_weight.to_f64();

        // Should be accurate to within 1/1000000
        assert!((converted_back - weight).abs() < 1e-6);
    }

    // Test constants
    assert_eq!(InfluenceWeight::MAX.to_f64(), 1.0);
    assert_eq!(InfluenceWeight::ZERO.to_f64(), 0.0);

    // Test ordering
    let w1 = InfluenceWeight::from_millionths(500_000);
    let w2 = InfluenceWeight::from_millionths(750_000);
    assert!(w1 < w2);
    assert!(w2 > w1);
}

#[test]
fn test_graph_serialization() {
    let mut graph = CausationGraph::new();

    // Add a simple node
    let node = CausationNode {
        id: NodeId(42),
        node_type: NodeType::EvidenceAtom {
            dependency: CausalDependency {
                atom_id: "test-atom".to_string(),
                influence_millionths: 600_000,
                content_hash: ContentHash::compute(b"test-content"),
            },
            evidence_hash: ContentHash::compute(b"test-evidence"),
            confidence_millionths: 850_000,
        },
        content_hash: ContentHash::compute(b"test-node"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"test", b"key"),
        timestamp_ns: 1640995200000000000,
        metadata: {
            let mut map = BTreeMap::new();
            map.insert("source".to_string(), "integration-test".to_string());
            map
        },
    };

    graph.add_node(node).expect("Failed to add test node");

    // Test serialization to JSON
    let serialized = serde_json::to_string(&graph)
        .expect("Failed to serialize graph");

    // Test deserialization
    let deserialized: CausationGraph = serde_json::from_str(&serialized)
        .expect("Failed to deserialize graph");

    // Verify graph is preserved
    assert_eq!(deserialized.schema_version, graph.schema_version);
    assert_eq!(deserialized.metadata.node_count, 1);
    assert_eq!(deserialized.nodes.len(), 1);
    assert!(deserialized.nodes.contains_key(&NodeId(42)));
}

#[test]
fn test_aggregation_methods() {
    let mut graph = CausationGraph::new();

    // Test each aggregation method
    let methods = [
        AggregationMethod::Sum,
        AggregationMethod::WeightedAverage,
        AggregationMethod::Max,
        AggregationMethod::Bayesian,
    ];

    for (i, method) in methods.iter().enumerate() {
        let node = CausationNode {
            id: NodeId(i as u64 + 1),
            node_type: NodeType::AggregateInfluence {
                source_nodes: vec![NodeId(100), NodeId(200)], // dummy sources
                total_weight: InfluenceWeight::from_millionths(500_000 + i as u32 * 100_000),
                method: *method,
            },
            content_hash: ContentHash::compute(format!("aggregate-{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::compute_keyed(
                format!("agg-{}", i).as_bytes(),
                b"key"
            ),
            timestamp_ns: 1640995200000000000 + i as u64 * 1000000,
            metadata: BTreeMap::new(),
        };

        graph.add_node(node).expect("Failed to add aggregate node");
    }

    assert_eq!(graph.metadata.node_count, methods.len() as u64);

    // Verify each method is preserved
    for (i, method) in methods.iter().enumerate() {
        let node = graph.nodes.get(&NodeId(i as u64 + 1)).unwrap();
        if let NodeType::AggregateInfluence { method: node_method, .. } = &node.node_type {
            assert_eq!(node_method, method);
        } else {
            panic!("Expected AggregateInfluence node type");
        }
    }
}

#[test]
fn test_cycle_prevention() {
    let mut graph = CausationGraph::new();

    // Create a chain of 4 nodes
    for i in 1..=4 {
        let node = CausationNode {
            id: NodeId(i),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    atom_id: format!("evidence-{}", i),
                    influence_millionths: 500_000,
                    content_hash: ContentHash::compute(format!("test-{}", i).as_bytes()),
                },
                evidence_hash: ContentHash::compute(format!("evidence-{}", i).as_bytes()),
                confidence_millionths: 900_000,
            },
            content_hash: ContentHash::compute(format!("node-{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::compute_keyed(
                format!("node-{}", i).as_bytes(),
                b"key"
            ),
            timestamp_ns: 1640995200000000000 + i * 1000000,
            metadata: BTreeMap::new(),
        };
        graph.add_node(node).expect("Failed to add node");
    }

    // Create chain: 1 -> 2 -> 3 -> 4
    for i in 1..=3 {
        let edge = CausationEdge {
            id: EdgeId(i),
            source: NodeId(i),
            target: NodeId(i + 1),
            weight: InfluenceWeight::from_millionths(700_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(format!("edge-{}", i).as_bytes()),
            timestamp_ns: 1640995200000000000 + i * 2000000,
            metadata: BTreeMap::new(),
        };
        graph.add_edge(edge).expect("Failed to add forward edge");
    }

    // Now try to create cycles
    let cycle_attempts = [
        (NodeId(4), NodeId(1)), // 4 -> 1 (long cycle)
        (NodeId(3), NodeId(1)), // 3 -> 1 (medium cycle)
        (NodeId(2), NodeId(1)), // 2 -> 1 (short cycle)
        (NodeId(4), NodeId(3)), // 4 -> 3 (back edge)
    ];

    for (i, (source, target)) in cycle_attempts.iter().enumerate() {
        let cycle_edge = CausationEdge {
            id: EdgeId(10 + i as u64),
            source: *source,
            target: *target,
            weight: InfluenceWeight::from_millionths(400_000),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(format!("cycle-edge-{}", i).as_bytes()),
            timestamp_ns: 1640995200000000000 + (10 + i as u64) * 1000000,
            metadata: BTreeMap::new(),
        };

        // All of these should fail due to cycle detection
        let result = graph.add_edge(cycle_edge);
        assert!(matches!(result, Err(GraphError::CycleDetected(_, _))));
    }

    // Graph should still only have the original 3 edges
    assert_eq!(graph.metadata.edge_count, 3);
}

#[test]
fn test_schema_version_validation() {
    let graph = CausationGraph::new();
    assert_eq!(graph.schema_version, CAUSATION_GRAPH_SCHEMA_VERSION);

    // Ensure version string is well-formed
    assert!(graph.schema_version.starts_with("franken-engine.causation-graph."));
    assert!(graph.schema_version.ends_with(".v1"));
}

#[test]
fn test_metadata_tracking() {
    let mut graph = CausationGraph::new();
    let initial_created = graph.metadata.created_at_ns;
    let initial_modified = graph.metadata.modified_at_ns;

    // Adding a node should update modification time
    let node = CausationNode {
        id: NodeId(1),
        node_type: NodeType::EvidenceAtom {
            dependency: CausalDependency {
                atom_id: "metadata-test".to_string(),
                influence_millionths: 500_000,
                content_hash: ContentHash::compute(b"metadata"),
            },
            evidence_hash: ContentHash::compute(b"meta-evidence"),
            confidence_millionths: 800_000,
        },
        content_hash: ContentHash::compute(b"meta-node"),
        authenticity_hash: AuthenticityHash::compute_keyed(b"meta", b"key"),
        timestamp_ns: 1640995200000000000,
        metadata: BTreeMap::new(),
    };

    // Small delay to ensure timestamp difference
    std::thread::sleep(std::time::Duration::from_millis(1));
    graph.add_node(node).expect("Failed to add node");

    // Verify metadata updates
    assert_eq!(graph.metadata.created_at_ns, initial_created); // Should not change
    assert!(graph.metadata.modified_at_ns > initial_modified); // Should be updated
    assert_eq!(graph.metadata.node_count, 1);
    assert_eq!(graph.metadata.edge_count, 0);
    assert_ne!(graph.metadata.graph_hash.as_bytes(), &[0u8; 32]); // Should be non-zero
}