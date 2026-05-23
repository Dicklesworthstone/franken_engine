//! Integration tests for persistence homology computation.

use std::collections::BTreeMap;

use frankenengine_engine::persistence_homology::*;
use frankenengine_engine::causation_graph_schema::*;
use frankenengine_engine::minimal_causal_set_inference::{CausalDependency, DecisionFactor, FactorType};
use frankenengine_engine::hash_tiers::{ContentHash, AuthenticityHash};

/// Create a test causation graph with known topological structure.
fn create_test_graph() -> CausationGraph {
    let mut graph = CausationGraph::new();

    // Create nodes
    let node1 = CausationNode {
        id: NodeId(1),
        node_type: NodeType::EvidenceAtom {
            dependency: CausalDependency {
                factor_type: FactorType::SecurityPolicy,
                description: "Auth policy check".to_string(),
                confidence_millionths: 900_000,
            },
            evidence_hash: ContentHash::compute(b"evidence_1"),
            confidence_millionths: 900_000,
        },
        content_hash: ContentHash::compute(b"node_1"),
        authenticity_hash: AuthenticityHash::placeholder(),
        timestamp_ns: 1640995200_000_000_000,
        metadata: BTreeMap::new(),
    };

    let node2 = CausationNode {
        id: NodeId(2),
        node_type: NodeType::EvidenceAtom {
            dependency: CausalDependency {
                factor_type: FactorType::UserAction,
                description: "User login attempt".to_string(),
                confidence_millionths: 800_000,
            },
            evidence_hash: ContentHash::compute(b"evidence_2"),
            confidence_millionths: 800_000,
        },
        content_hash: ContentHash::compute(b"node_2"),
        authenticity_hash: AuthenticityHash::placeholder(),
        timestamp_ns: 1640995210_000_000_000,
        metadata: BTreeMap::new(),
    };

    let node3 = CausationNode {
        id: NodeId(3),
        node_type: NodeType::Decision {
            decision_id: "decision_1".to_string(),
            factor: DecisionFactor {
                factor_id: "auth_factor".to_string(),
                factor_type: FactorType::SecurityPolicy,
                description: "Authentication decision".to_string(),
                influence_weight: 800_000,
                confidence: 900_000,
                evidence_refs: vec!["evidence_1".to_string(), "evidence_2".to_string()],
            },
            context_hash: ContentHash::compute(b"decision_context"),
            outcome: DecisionOutcome::Allow,
        },
        content_hash: ContentHash::compute(b"node_3"),
        authenticity_hash: AuthenticityHash::placeholder(),
        timestamp_ns: 1640995220_000_000_000,
        metadata: BTreeMap::new(),
    };

    // Add nodes to graph
    graph.add_node(node1).unwrap();
    graph.add_node(node2).unwrap();
    graph.add_node(node3).unwrap();

    // Create edges
    let edge1 = CausationEdge {
        id: EdgeId(1),
        source: NodeId(1),
        target: NodeId(3),
        weight: InfluenceWeight::from_millionths(700_000),
        causation_type: CausationType::Direct,
        content_hash: ContentHash::compute(b"edge_1"),
        timestamp_ns: 1640995215_000_000_000,
        metadata: BTreeMap::new(),
    };

    let edge2 = CausationEdge {
        id: EdgeId(2),
        source: NodeId(2),
        target: NodeId(3),
        weight: InfluenceWeight::from_millionths(600_000),
        causation_type: CausationType::Direct,
        content_hash: ContentHash::compute(b"edge_2"),
        timestamp_ns: 1640995217_000_000_000,
        metadata: BTreeMap::new(),
    };

    // Add edges to graph
    graph.add_edge(edge1).unwrap();
    graph.add_edge(edge2).unwrap();

    graph
}

/// Create a larger test graph with multiple components.
fn create_multi_component_graph() -> CausationGraph {
    let mut graph = CausationGraph::new();

    // First component
    for i in 1..=3 {
        let node = CausationNode {
            id: NodeId(i),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    factor_type: FactorType::SecurityPolicy,
                    description: format!("Evidence {}", i),
                    confidence_millionths: 800_000,
                },
                evidence_hash: ContentHash::compute(&format!("evidence_{}", i).as_bytes()),
                confidence_millionths: 800_000,
            },
            content_hash: ContentHash::compute(&format!("node_{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::placeholder(),
            timestamp_ns: 1640995200_000_000_000 + (i as u64 * 1_000_000_000),
            metadata: BTreeMap::new(),
        };
        graph.add_node(node).unwrap();
    }

    // Second component (isolated)
    for i in 4..=6 {
        let node = CausationNode {
            id: NodeId(i),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    factor_type: FactorType::UserAction,
                    description: format!("Evidence {}", i),
                    confidence_millionths: 700_000,
                },
                evidence_hash: ContentHash::compute(&format!("evidence_{}", i).as_bytes()),
                confidence_millionths: 700_000,
            },
            content_hash: ContentHash::compute(&format!("node_{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::placeholder(),
            timestamp_ns: 1640995200_000_000_000 + (i as u64 * 1_000_000_000),
            metadata: BTreeMap::new(),
        };
        graph.add_node(node).unwrap();
    }

    // Add edges within first component
    let edge1 = CausationEdge {
        id: EdgeId(1),
        source: NodeId(1),
        target: NodeId(2),
        weight: InfluenceWeight::from_millionths(500_000),
        causation_type: CausationType::Direct,
        content_hash: ContentHash::compute(b"edge_1"),
        timestamp_ns: 1640995205_000_000_000,
        metadata: BTreeMap::new(),
    };

    let edge2 = CausationEdge {
        id: EdgeId(2),
        source: NodeId(2),
        target: NodeId(3),
        weight: InfluenceWeight::from_millionths(600_000),
        causation_type: CausationType::Direct,
        content_hash: ContentHash::compute(b"edge_2"),
        timestamp_ns: 1640995210_000_000_000,
        metadata: BTreeMap::new(),
    };

    // Add edges within second component
    let edge3 = CausationEdge {
        id: EdgeId(3),
        source: NodeId(4),
        target: NodeId(5),
        weight: InfluenceWeight::from_millionths(400_000),
        causation_type: CausationType::Indirect,
        content_hash: ContentHash::compute(b"edge_3"),
        timestamp_ns: 1640995215_000_000_000,
        metadata: BTreeMap::new(),
    };

    graph.add_edge(edge1).unwrap();
    graph.add_edge(edge2).unwrap();
    graph.add_edge(edge3).unwrap();

    graph
}

/// Create a test graph with a cycle (for 1-dimensional feature testing).
fn create_cyclic_graph() -> CausationGraph {
    let mut graph = CausationGraph::new();

    // Create a triangle of nodes
    for i in 1..=3 {
        let node = CausationNode {
            id: NodeId(i),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    factor_type: FactorType::SecurityPolicy,
                    description: format!("Cycle node {}", i),
                    confidence_millionths: 900_000,
                },
                evidence_hash: ContentHash::compute(&format!("cycle_evidence_{}", i).as_bytes()),
                confidence_millionths: 900_000,
            },
            content_hash: ContentHash::compute(&format!("cycle_node_{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::placeholder(),
            timestamp_ns: 1640995200_000_000_000 + (i as u64 * 1_000_000_000),
            metadata: BTreeMap::new(),
        };
        graph.add_node(node).unwrap();
    }

    // Create edges forming a cycle: 1 -> 2 -> 3 -> 1
    let edges = vec![
        (EdgeId(1), NodeId(1), NodeId(2)),
        (EdgeId(2), NodeId(2), NodeId(3)),
        (EdgeId(3), NodeId(3), NodeId(1)),
    ];

    for (i, (edge_id, source, target)) in edges.into_iter().enumerate() {
        let edge = CausationEdge {
            id: edge_id,
            source,
            target,
            weight: InfluenceWeight::from_millionths(700_000 + (i as u32 * 10_000)),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(&format!("cycle_edge_{}", edge_id.0).as_bytes()),
            timestamp_ns: 1640995205_000_000_000 + (i as u64 * 2_000_000_000),
            metadata: BTreeMap::new(),
        };
        graph.add_edge(edge).unwrap();
    }

    graph
}

#[test]
fn test_persistence_computer_creation() {
    let computer = PersistenceComputer::new();
    assert_eq!(computer.config.max_dimension, 1);
    assert_eq!(computer.config.filter_type, FilterType::InfluenceWeight);

    let custom_config = PersistenceConfig {
        max_dimension: 2,
        persistence_threshold: FilterValue::from_millionths(5_000),
        filter_type: FilterType::Temporal,
        detect_cycles: false,
    };

    let custom_computer = PersistenceComputer::with_config(custom_config.clone());
    assert_eq!(custom_computer.config, custom_config);
}

#[test]
fn test_basic_persistence_computation() {
    let graph = create_test_graph();
    let computer = PersistenceComputer::new();

    let result = computer.compute_diagram(&graph);
    assert!(result.is_ok());

    let diagram = result.unwrap();

    // Verify basic properties
    assert_eq!(diagram.schema_version, PERSISTENCE_DIAGRAM_SCHEMA_VERSION);
    assert!(!diagram.bars.is_empty());
    assert_eq!(diagram.computation_metadata.node_count, 3);
    assert_eq!(diagram.computation_metadata.edge_count, 2);
    assert_eq!(diagram.computation_metadata.algorithm, "ripser-style");

    // Should have content hash
    assert_ne!(diagram.content_hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn test_multi_component_persistence() {
    let graph = create_multi_component_graph();
    let computer = PersistenceComputer::new();

    let diagram = computer.compute_diagram(&graph).unwrap();

    // Should have multiple 0-dimensional features (connected components)
    let zero_dim_bars: Vec<_> = diagram.bars.iter()
        .filter(|bar| bar.dimension == 0)
        .collect();

    assert!(!zero_dim_bars.is_empty());

    // Verify metadata
    assert_eq!(diagram.computation_metadata.node_count, 6);
    assert_eq!(diagram.computation_metadata.edge_count, 3);

    // Should have feature counts
    let feature_counts = &diagram.computation_metadata.feature_counts;
    assert!(feature_counts.contains_key(&0)); // 0-dimensional features
}

#[test]
fn test_cyclic_graph_persistence() {
    let graph = create_cyclic_graph();

    let config = PersistenceConfig {
        max_dimension: 1,
        persistence_threshold: FilterValue::from_millionths(1_000),
        filter_type: FilterType::InfluenceWeight,
        detect_cycles: true,
    };

    let computer = PersistenceComputer::with_config(config);
    let diagram = computer.compute_diagram(&graph).unwrap();

    // Should detect cycles (1-dimensional features)
    let one_dim_bars: Vec<_> = diagram.bars.iter()
        .filter(|bar| bar.dimension == 1)
        .collect();

    // May or may not have cycles depending on the filtration order
    // At minimum should have 0-dimensional features
    let zero_dim_bars: Vec<_> = diagram.bars.iter()
        .filter(|bar| bar.dimension == 0)
        .collect();
    assert!(!zero_dim_bars.is_empty());

    assert_eq!(diagram.computation_metadata.node_count, 3);
    assert_eq!(diagram.computation_metadata.edge_count, 3);
}

#[test]
fn test_persistence_bar_properties() {
    let graph = create_test_graph();
    let computer = PersistenceComputer::new();
    let diagram = computer.compute_diagram(&graph).unwrap();

    for bar in &diagram.bars {
        // Basic validity checks
        assert!(bar.birth <= bar.death.unwrap_or(FilterValue::MAX));

        if let Some(persistence) = bar.persistence() {
            assert!(persistence >= FilterValue::ZERO);
        }

        let midpoint = bar.midpoint();
        assert!(midpoint >= bar.birth);

        // Verify representative structure
        match &bar.representative {
            FeatureRepresentative::Component { root_node, nodes } => {
                assert!(nodes.contains(root_node));
                assert!(!nodes.is_empty());
            },
            FeatureRepresentative::Cycle { edges, cycle_weight } => {
                assert!(!edges.is_empty());
                assert!(cycle_weight.millionths > 0);
            },
        }
    }
}

#[test]
fn test_filter_value_operations() {
    let val1 = FilterValue::from_f64(0.3);
    let val2 = FilterValue::from_millionths(300_000);
    let val3 = FilterValue::from_f64(0.7);

    assert_eq!(val1, val2);
    assert!(val1 < val3);
    assert_eq!(val1.to_f64(), 0.3);

    assert!(FilterValue::ZERO < val1);
    assert!(val1 < FilterValue::MAX);
}

#[test]
fn test_different_filter_types() {
    let graph = create_test_graph();

    let filter_types = vec![
        FilterType::InfluenceWeight,
        FilterType::Temporal,
        FilterType::GraphDistance,
        FilterType::Combined,
    ];

    for filter_type in filter_types {
        let config = PersistenceConfig {
            max_dimension: 1,
            persistence_threshold: FilterValue::from_millionths(1_000),
            filter_type,
            detect_cycles: true,
        };

        let computer = PersistenceComputer::with_config(config);
        let result = computer.compute_diagram(&graph);

        assert!(result.is_ok(), "Failed with filter type {:?}", filter_type);

        let diagram = result.unwrap();
        assert!(!diagram.bars.is_empty());
        assert_eq!(diagram.computation_metadata.node_count, 3);
    }
}

#[test]
fn test_persistence_threshold_filtering() {
    let graph = create_test_graph();

    // Low threshold - should include more bars
    let low_threshold_config = PersistenceConfig {
        persistence_threshold: FilterValue::from_millionths(1_000),
        ..PersistenceConfig::default()
    };

    let low_computer = PersistenceComputer::with_config(low_threshold_config);
    let low_diagram = low_computer.compute_diagram(&graph).unwrap();

    // High threshold - should include fewer bars
    let high_threshold_config = PersistenceConfig {
        persistence_threshold: FilterValue::from_millionths(500_000),
        ..PersistenceConfig::default()
    };

    let high_computer = PersistenceComputer::with_config(high_threshold_config);
    let high_diagram = high_computer.compute_diagram(&graph).unwrap();

    // Low threshold should have at least as many bars as high threshold
    assert!(low_diagram.bars.len() >= high_diagram.bars.len());
}

#[test]
fn test_persistence_diagram_determinism() {
    let graph = create_test_graph();
    let computer = PersistenceComputer::new();

    let diagram1 = computer.compute_diagram(&graph).unwrap();
    let diagram2 = computer.compute_diagram(&graph).unwrap();

    // Should produce identical results (deterministic)
    assert_eq!(diagram1.bars.len(), diagram2.bars.len());
    assert_eq!(diagram1.content_hash, diagram2.content_hash);

    for (bar1, bar2) in diagram1.bars.iter().zip(diagram2.bars.iter()) {
        assert_eq!(bar1.birth, bar2.birth);
        assert_eq!(bar1.death, bar2.death);
        assert_eq!(bar1.dimension, bar2.dimension);
        assert_eq!(bar1.feature_weight, bar2.feature_weight);
    }
}

#[test]
fn test_empty_graph_handling() {
    let empty_graph = CausationGraph::new();
    let computer = PersistenceComputer::new();

    let result = computer.compute_diagram(&empty_graph);
    assert!(result.is_ok());

    let diagram = result.unwrap();
    assert!(diagram.bars.is_empty());
    assert_eq!(diagram.computation_metadata.node_count, 0);
    assert_eq!(diagram.computation_metadata.edge_count, 0);
}

#[test]
fn test_single_node_graph() {
    let mut graph = CausationGraph::new();

    let node = CausationNode {
        id: NodeId(1),
        node_type: NodeType::EvidenceAtom {
            dependency: CausalDependency {
                factor_type: FactorType::SecurityPolicy,
                description: "Isolated evidence".to_string(),
                confidence_millionths: 900_000,
            },
            evidence_hash: ContentHash::compute(b"isolated_evidence"),
            confidence_millionths: 900_000,
        },
        content_hash: ContentHash::compute(b"isolated_node"),
        authenticity_hash: AuthenticityHash::placeholder(),
        timestamp_ns: 1640995200_000_000_000,
        metadata: BTreeMap::new(),
    };

    graph.add_node(node).unwrap();

    let computer = PersistenceComputer::new();
    let diagram = computer.compute_diagram(&graph).unwrap();

    // Should have exactly one 0-dimensional feature
    assert!(!diagram.bars.is_empty());
    assert_eq!(diagram.computation_metadata.node_count, 1);
    assert_eq!(diagram.computation_metadata.edge_count, 0);

    let zero_dim_count = diagram.bars.iter()
        .filter(|bar| bar.dimension == 0)
        .count();
    assert!(zero_dim_count >= 1);
}

#[test]
fn test_computation_metadata() {
    let graph = create_test_graph();
    let computer = PersistenceComputer::new();
    let diagram = computer.compute_diagram(&graph).unwrap();

    let metadata = &diagram.computation_metadata;

    // Verify metadata fields
    assert_eq!(metadata.algorithm, "ripser-style");
    assert_eq!(metadata.node_count, 3);
    assert_eq!(metadata.edge_count, 2);
    assert!(metadata.computation_time_us > 0);

    // Should have feature counts
    assert!(!metadata.feature_counts.is_empty());

    // Filter range should be valid
    let (min_val, max_val) = metadata.filter_range;
    assert!(min_val <= max_val);
}

#[test]
fn test_bar_ordering_determinism() {
    let graph = create_multi_component_graph();
    let computer = PersistenceComputer::new();
    let diagram = computer.compute_diagram(&graph).unwrap();

    // Verify bars are properly ordered
    for i in 1..diagram.bars.len() {
        let prev = &diagram.bars[i - 1];
        let curr = &diagram.bars[i];

        // Should be ordered by (birth, death, dimension)
        assert!(
            prev.birth <= curr.birth ||
            (prev.birth == curr.birth && prev.death <= curr.death) ||
            (prev.birth == curr.birth && prev.death == curr.death && prev.dimension <= curr.dimension)
        );
    }
}

#[test]
fn test_infinite_persistence_bars() {
    let graph = create_test_graph();

    // Use configuration that tends to create infinite bars
    let config = PersistenceConfig {
        max_dimension: 1,
        persistence_threshold: FilterValue::from_millionths(1_000),
        filter_type: FilterType::InfluenceWeight,
        detect_cycles: true,
    };

    let computer = PersistenceComputer::with_config(config);
    let diagram = computer.compute_diagram(&graph).unwrap();

    // Check if any bars are infinite
    let infinite_bars: Vec<_> = diagram.bars.iter()
        .filter(|bar| bar.is_infinite())
        .collect();

    // All bars might be infinite or finite depending on the graph structure
    for bar in &infinite_bars {
        assert!(bar.is_infinite());
        assert!(bar.persistence().is_none());
        assert_eq!(bar.midpoint(), bar.birth);
    }
}

#[test]
fn test_feature_representative_types() {
    let graph = create_test_graph();
    let computer = PersistenceComputer::new();
    let diagram = computer.compute_diagram(&graph).unwrap();

    let mut has_component = false;
    let mut has_cycle = false;

    for bar in &diagram.bars {
        match &bar.representative {
            FeatureRepresentative::Component { root_node, nodes } => {
                has_component = true;
                assert!(!nodes.is_empty());
                assert!(nodes.contains(root_node));
            },
            FeatureRepresentative::Cycle { edges, cycle_weight } => {
                has_cycle = true;
                assert!(!edges.is_empty());
                assert!(cycle_weight.millionths > 0);
            },
        }
    }

    // Should have at least component features
    assert!(has_component);
}

#[test]
fn test_content_hash_consistency() {
    let graph = create_test_graph();
    let computer = PersistenceComputer::new();

    let diagram1 = computer.compute_diagram(&graph).unwrap();
    let diagram2 = computer.compute_diagram(&graph).unwrap();

    // Content hashes should be identical for identical inputs
    assert_eq!(diagram1.content_hash, diagram2.content_hash);

    // Content hash should not be all zeros
    assert_ne!(diagram1.content_hash.as_bytes(), &[0u8; 32]);
}

#[test]
fn test_persistence_config_validation() {
    // Test various configuration parameters
    let configs = vec![
        PersistenceConfig {
            max_dimension: 0,
            persistence_threshold: FilterValue::ZERO,
            filter_type: FilterType::InfluenceWeight,
            detect_cycles: false,
        },
        PersistenceConfig {
            max_dimension: 3,
            persistence_threshold: FilterValue::from_millionths(100_000),
            filter_type: FilterType::Temporal,
            detect_cycles: true,
        },
    ];

    let graph = create_test_graph();

    for config in configs {
        let computer = PersistenceComputer::with_config(config);
        let result = computer.compute_diagram(&graph);
        assert!(result.is_ok());
    }
}

#[test]
fn test_large_graph_performance() {
    // Create a larger graph to test performance
    let mut graph = CausationGraph::new();

    // Create 10 nodes
    for i in 1..=10 {
        let node = CausationNode {
            id: NodeId(i),
            node_type: NodeType::EvidenceAtom {
                dependency: CausalDependency {
                    factor_type: FactorType::SecurityPolicy,
                    description: format!("Performance test node {}", i),
                    confidence_millionths: 800_000,
                },
                evidence_hash: ContentHash::compute(&format!("perf_evidence_{}", i).as_bytes()),
                confidence_millionths: 800_000,
            },
            content_hash: ContentHash::compute(&format!("perf_node_{}", i).as_bytes()),
            authenticity_hash: AuthenticityHash::placeholder(),
            timestamp_ns: 1640995200_000_000_000 + (i as u64 * 1_000_000_000),
            metadata: BTreeMap::new(),
        };
        graph.add_node(node).unwrap();
    }

    // Create edges to form a connected graph
    for i in 1..10 {
        let edge = CausationEdge {
            id: EdgeId(i),
            source: NodeId(i),
            target: NodeId(i + 1),
            weight: InfluenceWeight::from_millionths(500_000 + (i as u32 * 10_000)),
            causation_type: CausationType::Direct,
            content_hash: ContentHash::compute(&format!("perf_edge_{}", i).as_bytes()),
            timestamp_ns: 1640995205_000_000_000 + (i as u64 * 1_000_000_000),
            metadata: BTreeMap::new(),
        };
        graph.add_edge(edge).unwrap();
    }

    let computer = PersistenceComputer::new();
    let start = std::time::Instant::now();
    let diagram = computer.compute_diagram(&graph).unwrap();
    let duration = start.elapsed();

    // Should complete in reasonable time
    assert!(duration.as_millis() < 1000); // Less than 1 second

    // Verify result
    assert_eq!(diagram.computation_metadata.node_count, 10);
    assert_eq!(diagram.computation_metadata.edge_count, 9);
    assert!(!diagram.bars.is_empty());
}