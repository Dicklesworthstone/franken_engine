//! Integration tests for the spectral fleet convergence module.
//!
//! Exercises the public API of `spectral_fleet_convergence` from outside
//! the crate boundary: gossip topology construction, Laplacian computation,
//! spectral analysis, convergence certificates, and error paths.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::spectral_fleet_convergence::{
    ConvergenceCertificate, GossipTopology, LaplacianMatrix, SPECTRAL_SCHEMA_VERSION,
    SpectralAnalysis, SpectralAnalyzer, SpectralError,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn nodes(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("node-{i}")).collect()
}

/// Build a fully-connected K_n graph with unit weights.
fn complete_graph(n: usize) -> GossipTopology {
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 0..n {
        for j in (i + 1)..n {
            topo.add_edge(i, j, 1_000_000).unwrap();
        }
    }
    topo
}

/// Build a path graph 0-1-2-...(n-1) with unit weights.
fn path_graph(n: usize) -> GossipTopology {
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 0..(n - 1) {
        topo.add_edge(i, i + 1, 1_000_000).unwrap();
    }
    topo
}

/// Build a cycle graph 0-1-2-...(n-1)-0 with unit weights.
fn cycle_graph(n: usize) -> GossipTopology {
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 0..n {
        topo.add_edge(i, (i + 1) % n, 1_000_000).unwrap();
    }
    topo
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_is_stable() {
    assert_eq!(
        SPECTRAL_SCHEMA_VERSION,
        "franken-engine.spectral-fleet-convergence.v1"
    );
}

// ---------------------------------------------------------------------------
// SpectralError — Display + serde
// ---------------------------------------------------------------------------

#[test]
fn error_too_many_nodes_display() {
    let err = SpectralError::TooManyNodes {
        count: 2000,
        max: 1024,
    };
    let s = err.to_string();
    assert!(s.contains("2000"), "got: {s}");
    assert!(s.contains("1024"), "got: {s}");
}

#[test]
fn error_empty_graph_display() {
    let s = SpectralError::EmptyGraph.to_string();
    assert!(s.contains("empty"), "got: {s}");
}

#[test]
fn error_disconnected_display() {
    let err = SpectralError::Disconnected { components: 3 };
    let s = err.to_string();
    assert!(s.contains("3"), "got: {s}");
}

#[test]
fn error_node_out_of_bounds_display() {
    let err = SpectralError::NodeOutOfBounds { index: 10, size: 5 };
    let s = err.to_string();
    assert!(s.contains("10"), "got: {s}");
    assert!(s.contains("5"), "got: {s}");
}

#[test]
fn error_invalid_edge_weight_display() {
    let err = SpectralError::InvalidEdgeWeight {
        weight_millionths: -42,
    };
    let s = err.to_string();
    assert!(s.contains("-42"), "got: {s}");
}

#[test]
fn error_convergence_failure_display() {
    let err = SpectralError::ConvergenceFailure { iterations: 100 };
    let s = err.to_string();
    assert!(s.contains("100"), "got: {s}");
}

#[test]
fn error_degenerate_spectral_gap_display() {
    let s = SpectralError::DegenerateSpectralGap.to_string();
    assert!(s.contains("spectral gap"), "got: {s}");
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let variants: Vec<SpectralError> = vec![
        SpectralError::TooManyNodes {
            count: 2000,
            max: 1024,
        },
        SpectralError::EmptyGraph,
        SpectralError::Disconnected { components: 3 },
        SpectralError::NodeOutOfBounds { index: 10, size: 5 },
        SpectralError::InvalidEdgeWeight {
            weight_millionths: -1,
        },
        SpectralError::ConvergenceFailure { iterations: 100 },
        SpectralError::DegenerateSpectralGap,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SpectralError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// GossipTopology — construction
// ---------------------------------------------------------------------------

#[test]
fn topology_new_empty_fails() {
    let err = GossipTopology::new(vec![]).unwrap_err();
    assert_eq!(err, SpectralError::EmptyGraph);
}

#[test]
fn topology_new_too_many_nodes() {
    let ids: Vec<String> = (0..1025).map(|i| format!("n{i}")).collect();
    let err = GossipTopology::new(ids).unwrap_err();
    assert!(matches!(err, SpectralError::TooManyNodes { .. }));
}

#[test]
fn topology_new_valid_single_node() {
    let topo = GossipTopology::new(vec!["solo".to_string()]).unwrap();
    assert_eq!(topo.num_nodes, 1);
    assert!(topo.is_connected());
}

#[test]
fn topology_new_valid_multiple_nodes() {
    let topo = GossipTopology::new(nodes(5)).unwrap();
    assert_eq!(topo.num_nodes, 5);
    assert_eq!(topo.node_ids.len(), 5);
}

// ---------------------------------------------------------------------------
// GossipTopology — add_edge
// ---------------------------------------------------------------------------

#[test]
fn add_edge_zero_weight_fails() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let err = topo.add_edge(0, 1, 0).unwrap_err();
    assert!(matches!(err, SpectralError::InvalidEdgeWeight { .. }));
}

#[test]
fn add_edge_negative_weight_fails() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let err = topo.add_edge(0, 1, -100).unwrap_err();
    assert!(matches!(err, SpectralError::InvalidEdgeWeight { .. }));
}

#[test]
fn add_edge_node_out_of_bounds() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let err = topo.add_edge(0, 5, 1_000_000).unwrap_err();
    assert!(matches!(err, SpectralError::NodeOutOfBounds { .. }));
}

#[test]
fn add_edge_from_out_of_bounds() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let err = topo.add_edge(5, 0, 1_000_000).unwrap_err();
    assert!(matches!(err, SpectralError::NodeOutOfBounds { .. }));
}

#[test]
fn add_edge_valid() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    assert!(topo.add_edge(0, 1, 1_000_000).is_ok());
    assert!(topo.add_edge(1, 2, 500_000).is_ok());
}

// ---------------------------------------------------------------------------
// GossipTopology — degree
// ---------------------------------------------------------------------------

#[test]
fn degree_isolated_node() {
    let topo = GossipTopology::new(nodes(3)).unwrap();
    assert_eq!(topo.degree(0), 0);
}

#[test]
fn degree_connected_node() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(0, 2, 500_000).unwrap();
    assert_eq!(topo.degree(0), 1_500_000);
}

// ---------------------------------------------------------------------------
// GossipTopology — connectivity
// ---------------------------------------------------------------------------

#[test]
fn is_connected_single_node() {
    let topo = GossipTopology::new(vec!["a".into()]).unwrap();
    assert!(topo.is_connected());
    assert_eq!(topo.connected_components(), 1);
}

#[test]
fn is_connected_path() {
    let topo = path_graph(4);
    assert!(topo.is_connected());
    assert_eq!(topo.connected_components(), 1);
}

#[test]
fn is_disconnected_no_edges() {
    let topo = GossipTopology::new(nodes(3)).unwrap();
    assert!(!topo.is_connected());
    assert_eq!(topo.connected_components(), 3);
}

#[test]
fn connected_components_two_clusters() {
    let mut topo = GossipTopology::new(nodes(4)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(2, 3, 1_000_000).unwrap();
    assert!(!topo.is_connected());
    assert_eq!(topo.connected_components(), 2);
}

// ---------------------------------------------------------------------------
// GossipTopology — serde
// ---------------------------------------------------------------------------

#[test]
fn topology_serde_roundtrip() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(1, 2, 500_000).unwrap();
    let json = serde_json::to_string(&topo).unwrap();
    let back: GossipTopology = serde_json::from_str(&json).unwrap();
    assert_eq!(topo, back);
}

// ---------------------------------------------------------------------------
// LaplacianMatrix
// ---------------------------------------------------------------------------

#[test]
fn laplacian_from_empty_graph_error() {
    // GossipTopology won't allow empty, but a manually constructed one
    // would fail. We test through a 1-node graph to verify the Laplacian.
    let topo = GossipTopology::new(vec!["solo".into()]).unwrap();
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(lap.dim, 1);
    assert_eq!(lap.get(0, 0), 0); // isolated node, degree=0
}

#[test]
fn laplacian_diagonal_equals_degree() {
    let topo = path_graph(3);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(lap.dim, 3);
    // node 0: degree = 1_000_000 (one edge)
    assert_eq!(lap.get(0, 0), 1_000_000);
    // node 1: degree = 2_000_000 (two edges)
    assert_eq!(lap.get(1, 1), 2_000_000);
    // node 2: degree = 1_000_000 (one edge)
    assert_eq!(lap.get(2, 2), 1_000_000);
}

#[test]
fn laplacian_off_diagonal_negative_weight() {
    let topo = path_graph(3);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    // edge 0-1 exists with weight 1M
    assert_eq!(lap.get(0, 1), -1_000_000);
    assert_eq!(lap.get(1, 0), -1_000_000);
    // no edge 0-2
    assert_eq!(lap.get(0, 2), 0);
}

#[test]
fn laplacian_content_hash_deterministic() {
    let topo = complete_graph(3);
    let h1 = LaplacianMatrix::from_topology(&topo)
        .unwrap()
        .content_hash();
    let h2 = LaplacianMatrix::from_topology(&topo)
        .unwrap()
        .content_hash();
    assert_eq!(h1, h2);
}

#[test]
fn laplacian_content_hash_differs_for_different_graphs() {
    let topo1 = path_graph(3);
    let topo2 = complete_graph(3);
    let h1 = LaplacianMatrix::from_topology(&topo1)
        .unwrap()
        .content_hash();
    let h2 = LaplacianMatrix::from_topology(&topo2)
        .unwrap()
        .content_hash();
    assert_ne!(h1, h2);
}

#[test]
fn laplacian_serde_roundtrip() {
    let topo = path_graph(3);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    let json = serde_json::to_string(&lap).unwrap();
    let back: LaplacianMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(lap, back);
}

// ---------------------------------------------------------------------------
// SpectralAnalyzer — construction
// ---------------------------------------------------------------------------

#[test]
fn analyzer_default() {
    let analyzer = SpectralAnalyzer::default();
    assert!(analyzer.max_iterations > 0);
    assert!(analyzer.convergence_threshold_millionths > 0);
}

#[test]
fn analyzer_serde_roundtrip() {
    let analyzer = SpectralAnalyzer::default();
    let json = serde_json::to_string(&analyzer).unwrap();
    let back: SpectralAnalyzer = serde_json::from_str(&json).unwrap();
    assert_eq!(analyzer.max_iterations, back.max_iterations);
}

// ---------------------------------------------------------------------------
// SpectralAnalyzer — analyze: error paths
// ---------------------------------------------------------------------------

#[test]
fn analyze_disconnected_graph_error() {
    let topo = GossipTopology::new(nodes(3)).unwrap(); // no edges
    let analyzer = SpectralAnalyzer::default();
    let err = analyzer.analyze(&topo).unwrap_err();
    assert!(matches!(err, SpectralError::Disconnected { components: 3 }));
}

#[test]
fn analyze_two_components_error() {
    let mut topo = GossipTopology::new(nodes(4)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(2, 3, 1_000_000).unwrap();
    let analyzer = SpectralAnalyzer::default();
    let err = analyzer.analyze(&topo).unwrap_err();
    assert!(matches!(err, SpectralError::Disconnected { components: 2 }));
}

// ---------------------------------------------------------------------------
// SpectralAnalyzer — analyze: happy paths
// ---------------------------------------------------------------------------

#[test]
fn analyze_path_graph_3() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert_eq!(result.schema, SPECTRAL_SCHEMA_VERSION);
    assert_eq!(result.num_nodes, 3);
    assert!(result.algebraic_connectivity_millionths > 0);
    assert!(result.spectral_gap_millionths > 0);
    assert!(result.mixing_time_bound >= 1);
    assert!(result.lambda_max_millionths > 0);
}

#[test]
fn analyze_complete_graph_k3() {
    let topo = complete_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert_eq!(result.num_nodes, 3);
    // For K_3, all non-trivial eigenvalues should be equal (= 3M)
    // So algebraic connectivity ≈ lambda_max
    assert!(result.algebraic_connectivity_millionths > 0);
    assert!(result.lambda_max_millionths > 0);
}

#[test]
fn analyze_cycle_graph_4() {
    let topo = cycle_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert_eq!(result.num_nodes, 4);
    assert!(result.algebraic_connectivity_millionths > 0);
    assert!(result.mixing_time_bound >= 1);
}

#[test]
fn analyze_larger_path() {
    let topo = path_graph(8);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert_eq!(result.num_nodes, 8);
    // Path graphs have small spectral gap -> longer mixing time
    assert!(result.mixing_time_bound >= 1);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — field invariants
// ---------------------------------------------------------------------------

#[test]
fn analysis_partitions_cover_all_nodes() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    let total = result.partition_a.len() + result.partition_b.len();
    assert_eq!(total, 5);
}

#[test]
fn analysis_fiedler_vector_length_matches_nodes() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert_eq!(result.fiedler_vector_millionths.len(), 4);
}

#[test]
fn analysis_cheeger_lower_leq_upper() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert!(
        result.cheeger_lower_bound_millionths <= result.cheeger_upper_bound_millionths,
        "lower={} > upper={}",
        result.cheeger_lower_bound_millionths,
        result.cheeger_upper_bound_millionths
    );
}

#[test]
fn analysis_lambda_max_geq_fiedler() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert!(
        result.lambda_max_millionths >= result.algebraic_connectivity_millionths,
        "lambda_max={} < fiedler={}",
        result.lambda_max_millionths,
        result.algebraic_connectivity_millionths
    );
}

#[test]
fn analysis_laplacian_hash_populated() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    assert!(!result.laplacian_hash.as_bytes().is_empty());
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — serde
// ---------------------------------------------------------------------------

#[test]
fn analysis_serde_roundtrip() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: SpectralAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — determinism
// ---------------------------------------------------------------------------

#[test]
fn analysis_deterministic() {
    let topo = cycle_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let r1 = analyzer.analyze(&topo).unwrap();
    let r2 = analyzer.analyze(&topo).unwrap();
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate
// ---------------------------------------------------------------------------

#[test]
fn certificate_from_analysis() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let epoch = SecurityEpoch::from_raw(42);
    let cert = ConvergenceCertificate::from_analysis(&analysis, epoch);
    assert_eq!(cert.schema, SPECTRAL_SCHEMA_VERSION);
    assert_eq!(cert.num_nodes, 5);
    assert_eq!(cert.epoch, epoch);
    assert!(cert.mixing_time_rounds >= 1);
    assert!(cert.spectral_gap_millionths > 0);
}

#[test]
fn certificate_meets_sla_true() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    // Complete graph has fast mixing -> should meet a generous SLA
    assert!(cert.meets_sla(1_000_000));
}

#[test]
fn certificate_meets_sla_false() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    // Zero-round SLA should fail
    assert!(!cert.meets_sla(0));
}

#[test]
fn certificate_has_natural_partition() {
    let topo = path_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    // A path graph should detect a natural bipartition
    assert!(cert.has_natural_partition);
    let (a, b) = cert.partition_sizes;
    assert_eq!(a + b, 6);
}

#[test]
fn certificate_hash_deterministic() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let epoch = SecurityEpoch::from_raw(7);
    let c1 = ConvergenceCertificate::from_analysis(&analysis, epoch);
    let c2 = ConvergenceCertificate::from_analysis(&analysis, epoch);
    assert_eq!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn certificate_hash_differs_by_epoch() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let c1 = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    let c2 = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(2));
    assert_ne!(c1.certificate_hash, c2.certificate_hash);
}

#[test]
fn certificate_serde_roundtrip() {
    let topo = cycle_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(10));
    let json = serde_json::to_string(&cert).unwrap();
    let back: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// Full lifecycle
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_build_analyze_certify() {
    // 1. Build topology
    let mut topo = GossipTopology::new(nodes(6)).unwrap();
    // Ring + one chord for interesting structure
    for i in 0..6 {
        topo.add_edge(i, (i + 1) % 6, 1_000_000).unwrap();
    }
    topo.add_edge(0, 3, 1_000_000).unwrap(); // chord

    // 2. Verify connectivity
    assert!(topo.is_connected());
    assert_eq!(topo.connected_components(), 1);

    // 3. Build Laplacian
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(lap.dim, 6);

    // 4. Analyze
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert_eq!(analysis.num_nodes, 6);
    assert!(analysis.spectral_gap_millionths > 0);
    assert!(analysis.lambda_max_millionths >= analysis.algebraic_connectivity_millionths);

    // 5. Generate certificate
    let epoch = SecurityEpoch::from_raw(100);
    let cert = ConvergenceCertificate::from_analysis(&analysis, epoch);
    assert_eq!(cert.num_nodes, 6);
    assert_eq!(cert.epoch, epoch);
    assert!(cert.mixing_time_rounds >= 1);

    // 6. Serde roundtrip
    let json = serde_json::to_string(&cert).unwrap();
    let back: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn full_lifecycle_star_graph() {
    // Star: node 0 connected to all others
    let n = 5;
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 1..n {
        topo.add_edge(0, i, 1_000_000).unwrap();
    }
    assert!(topo.is_connected());

    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();

    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    assert!(cert.meets_sla(1_000_000));

    // Certificate should be deterministic
    let cert2 = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    assert_eq!(cert.certificate_hash, cert2.certificate_hash);
}

#[test]
fn weighted_edges_affect_spectrum() {
    // Compare analysis of same topology with different weights
    let mut topo_light = GossipTopology::new(nodes(3)).unwrap();
    topo_light.add_edge(0, 1, 100_000).unwrap();
    topo_light.add_edge(1, 2, 100_000).unwrap();

    let mut topo_heavy = GossipTopology::new(nodes(3)).unwrap();
    topo_heavy.add_edge(0, 1, 1_000_000).unwrap();
    topo_heavy.add_edge(1, 2, 1_000_000).unwrap();

    let analyzer = SpectralAnalyzer::default();
    let r_light = analyzer.analyze(&topo_light).unwrap();
    let r_heavy = analyzer.analyze(&topo_heavy).unwrap();

    // Heavier weights should give larger eigenvalues
    assert_ne!(
        r_light.algebraic_connectivity_millionths,
        r_heavy.algebraic_connectivity_millionths
    );
}

// ===========================================================================
// Enrichment tests (~90 new tests)
// ===========================================================================

// ---------------------------------------------------------------------------
// SpectralError — Display exact text for every variant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_display_too_many_nodes_exact() {
    let e = SpectralError::TooManyNodes {
        count: 5000,
        max: 1024,
    };
    assert_eq!(e.to_string(), "5000 nodes exceeds limit 1024");
}

#[test]
fn enrichment_error_display_empty_graph_exact() {
    assert_eq!(SpectralError::EmptyGraph.to_string(), "empty graph");
}

#[test]
fn enrichment_error_display_disconnected_exact() {
    let e = SpectralError::Disconnected { components: 7 };
    assert_eq!(e.to_string(), "graph is disconnected (7 components)");
}

#[test]
fn enrichment_error_display_node_oob_exact() {
    let e = SpectralError::NodeOutOfBounds {
        index: 99,
        size: 10,
    };
    assert_eq!(e.to_string(), "node 99 out of bounds (size 10)");
}

#[test]
fn enrichment_error_display_invalid_weight_exact() {
    let e = SpectralError::InvalidEdgeWeight {
        weight_millionths: -999,
    };
    assert_eq!(e.to_string(), "invalid edge weight -999; expected > 0");
}

#[test]
fn enrichment_error_display_convergence_failure_exact() {
    let e = SpectralError::ConvergenceFailure { iterations: 200 };
    assert_eq!(
        e.to_string(),
        "power iteration did not converge after 200 iterations"
    );
}

#[test]
fn enrichment_error_display_degenerate_exact() {
    assert_eq!(
        SpectralError::DegenerateSpectralGap.to_string(),
        "spectral gap is zero or negative"
    );
}

// ---------------------------------------------------------------------------
// SpectralError — Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_debug_all_variants_distinct() {
    let variants: Vec<SpectralError> = vec![
        SpectralError::TooManyNodes {
            count: 2000,
            max: 1024,
        },
        SpectralError::EmptyGraph,
        SpectralError::Disconnected { components: 2 },
        SpectralError::NodeOutOfBounds { index: 0, size: 0 },
        SpectralError::InvalidEdgeWeight {
            weight_millionths: -1,
        },
        SpectralError::ConvergenceFailure { iterations: 10 },
        SpectralError::DegenerateSpectralGap,
    ];
    let dbg_set: std::collections::BTreeSet<String> =
        variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(dbg_set.len(), 7);
}

#[test]
fn enrichment_error_debug_contains_variant_name() {
    let e = SpectralError::TooManyNodes {
        count: 1,
        max: 1024,
    };
    let d = format!("{e:?}");
    assert!(d.contains("TooManyNodes"), "got: {d}");
}

// ---------------------------------------------------------------------------
// SpectralError — Clone
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_clone_eq() {
    let e = SpectralError::Disconnected { components: 42 };
    let e2 = e.clone();
    assert_eq!(e, e2);
}

#[test]
fn enrichment_error_clone_independence() {
    let e = SpectralError::ConvergenceFailure { iterations: 50 };
    let e2 = e.clone();
    assert_eq!(e, e2);
    assert_eq!(format!("{e}"), format!("{e2}"));
}

// ---------------------------------------------------------------------------
// SpectralError — std::error::Error
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_source_is_none() {
    use std::error::Error;
    let variants: Vec<SpectralError> = vec![
        SpectralError::TooManyNodes {
            count: 1,
            max: 1024,
        },
        SpectralError::EmptyGraph,
        SpectralError::Disconnected { components: 1 },
        SpectralError::NodeOutOfBounds { index: 0, size: 0 },
        SpectralError::InvalidEdgeWeight {
            weight_millionths: -1,
        },
        SpectralError::ConvergenceFailure { iterations: 1 },
        SpectralError::DegenerateSpectralGap,
    ];
    for v in &variants {
        assert!(v.source().is_none());
    }
}

#[test]
fn enrichment_error_dyn_error_display() {
    let e: Box<dyn std::error::Error> = Box::new(SpectralError::EmptyGraph);
    assert_eq!(e.to_string(), "empty graph");
}

// ---------------------------------------------------------------------------
// SpectralError — serde JSON snake_case tags
// ---------------------------------------------------------------------------

#[test]
fn enrichment_error_serde_snake_case_too_many_nodes() {
    let e = SpectralError::TooManyNodes {
        count: 1,
        max: 1024,
    };
    let json = serde_json::to_string(&e).unwrap();
    assert!(json.contains("too_many_nodes"), "got: {json}");
}

#[test]
fn enrichment_error_serde_snake_case_empty_graph() {
    let json = serde_json::to_string(&SpectralError::EmptyGraph).unwrap();
    assert!(json.contains("empty_graph"), "got: {json}");
}

#[test]
fn enrichment_error_serde_snake_case_disconnected() {
    let json = serde_json::to_string(&SpectralError::Disconnected { components: 1 }).unwrap();
    assert!(json.contains("disconnected"), "got: {json}");
}

#[test]
fn enrichment_error_serde_snake_case_node_oob() {
    let json =
        serde_json::to_string(&SpectralError::NodeOutOfBounds { index: 0, size: 0 }).unwrap();
    assert!(json.contains("node_out_of_bounds"), "got: {json}");
}

#[test]
fn enrichment_error_serde_snake_case_invalid_weight() {
    let json = serde_json::to_string(&SpectralError::InvalidEdgeWeight {
        weight_millionths: -1,
    })
    .unwrap();
    assert!(json.contains("invalid_edge_weight"), "got: {json}");
}

#[test]
fn enrichment_error_serde_snake_case_convergence() {
    let json = serde_json::to_string(&SpectralError::ConvergenceFailure { iterations: 1 }).unwrap();
    assert!(json.contains("convergence_failure"), "got: {json}");
}

#[test]
fn enrichment_error_serde_snake_case_degenerate() {
    let json = serde_json::to_string(&SpectralError::DegenerateSpectralGap).unwrap();
    assert!(json.contains("degenerate_spectral_gap"), "got: {json}");
}

// ---------------------------------------------------------------------------
// GossipTopology — Clone, Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_topology_clone_eq() {
    let topo = complete_graph(4);
    let topo2 = topo.clone();
    assert_eq!(topo, topo2);
}

#[test]
fn enrichment_topology_debug_nonempty() {
    let topo = GossipTopology::new(vec!["x".into()]).unwrap();
    let d = format!("{topo:?}");
    assert!(!d.is_empty());
    assert!(d.contains("GossipTopology"), "got: {d}");
}

// ---------------------------------------------------------------------------
// GossipTopology — JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_topology_json_field_num_nodes() {
    let topo = GossipTopology::new(vec!["a".into()]).unwrap();
    let json = serde_json::to_string(&topo).unwrap();
    assert!(json.contains("\"num_nodes\""), "got: {json}");
}

#[test]
fn enrichment_topology_json_field_node_ids() {
    let topo = GossipTopology::new(vec!["a".into()]).unwrap();
    let json = serde_json::to_string(&topo).unwrap();
    assert!(json.contains("\"node_ids\""), "got: {json}");
}

#[test]
fn enrichment_topology_json_field_adjacency() {
    let topo = GossipTopology::new(vec!["a".into()]).unwrap();
    let json = serde_json::to_string(&topo).unwrap();
    assert!(json.contains("\"adjacency\""), "got: {json}");
}

// ---------------------------------------------------------------------------
// GossipTopology — edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_topology_self_loop_allowed() {
    let mut topo = GossipTopology::new(vec!["a".into()]).unwrap();
    assert!(topo.add_edge(0, 0, 1_000_000).is_ok());
}

#[test]
fn enrichment_topology_self_loop_degree() {
    let mut topo = GossipTopology::new(vec!["a".into(), "b".into()]).unwrap();
    topo.add_edge(0, 0, 500_000).unwrap();
    assert_eq!(topo.degree(0), 500_000);
}

#[test]
fn enrichment_topology_multi_edge_accumulates() {
    let mut topo = GossipTopology::new(nodes(2)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(0, 1, 500_000).unwrap();
    assert_eq!(topo.degree(0), 1_500_000);
}

#[test]
fn enrichment_topology_max_nodes_boundary_1024() {
    let ids: Vec<String> = (0..1024).map(|i| format!("n{i}")).collect();
    let topo = GossipTopology::new(ids).unwrap();
    assert_eq!(topo.num_nodes, 1024);
}

#[test]
fn enrichment_topology_1025_nodes_rejected() {
    let ids: Vec<String> = (0..1025).map(|i| format!("n{i}")).collect();
    let err = GossipTopology::new(ids).unwrap_err();
    match err {
        SpectralError::TooManyNodes { count, max } => {
            assert_eq!(count, 1025);
            assert_eq!(max, 1024);
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn enrichment_topology_degree_all_zero_no_edges() {
    let topo = GossipTopology::new(nodes(5)).unwrap();
    for i in 0..5 {
        assert_eq!(topo.degree(i), 0);
    }
}

#[test]
fn enrichment_topology_three_components() {
    let mut topo = GossipTopology::new(nodes(5)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(2, 3, 1_000_000).unwrap();
    // node 4 isolated
    assert_eq!(topo.connected_components(), 3);
}

// ---------------------------------------------------------------------------
// LaplacianMatrix — Clone, Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_clone_eq() {
    let topo = path_graph(3);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    let lap2 = lap.clone();
    assert_eq!(lap, lap2);
}

#[test]
fn enrichment_laplacian_debug_nonempty() {
    let topo = path_graph(2);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    let d = format!("{lap:?}");
    assert!(!d.is_empty());
    assert!(d.contains("LaplacianMatrix"), "got: {d}");
}

// ---------------------------------------------------------------------------
// LaplacianMatrix — row sums to zero
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_row_sum_zero_path() {
    let topo = path_graph(5);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    for i in 0..5 {
        let row_sum: i64 = (0..5).map(|j| lap.get(i, j)).sum();
        assert_eq!(row_sum, 0, "row {i} sum = {row_sum}");
    }
}

#[test]
fn enrichment_laplacian_row_sum_zero_cycle() {
    let topo = cycle_graph(6);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    for i in 0..6 {
        let row_sum: i64 = (0..6).map(|j| lap.get(i, j)).sum();
        assert_eq!(row_sum, 0, "row {i} sum = {row_sum}");
    }
}

// ---------------------------------------------------------------------------
// LaplacianMatrix — symmetry
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_symmetric_path() {
    let topo = path_graph(4);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    for i in 0..4 {
        for j in 0..4 {
            assert_eq!(lap.get(i, j), lap.get(j, i), "L[{i},{j}] != L[{j},{i}]");
        }
    }
}

#[test]
fn enrichment_laplacian_symmetric_complete() {
    let topo = complete_graph(5);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    for i in 0..5 {
        for j in 0..5 {
            assert_eq!(lap.get(i, j), lap.get(j, i));
        }
    }
}

// ---------------------------------------------------------------------------
// LaplacianMatrix — JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_json_field_dim() {
    let topo = path_graph(2);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    let json = serde_json::to_string(&lap).unwrap();
    assert!(json.contains("\"dim\""), "got: {json}");
}

// ---------------------------------------------------------------------------
// LaplacianMatrix — hash varies
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_hash_varies_cycle_vs_path() {
    let lap_cycle = LaplacianMatrix::from_topology(&cycle_graph(4)).unwrap();
    let lap_path = LaplacianMatrix::from_topology(&path_graph(4)).unwrap();
    assert_ne!(lap_cycle.content_hash(), lap_path.content_hash());
}

// ---------------------------------------------------------------------------
// SpectralAnalyzer — Debug, Clone
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analyzer_debug_nonempty() {
    let a = SpectralAnalyzer::default();
    let d = format!("{a:?}");
    assert!(!d.is_empty());
    assert!(d.contains("SpectralAnalyzer"), "got: {d}");
}

#[test]
fn enrichment_analyzer_clone_eq() {
    let a = SpectralAnalyzer::default();
    let b = a.clone();
    assert_eq!(a.max_iterations, b.max_iterations);
    assert_eq!(
        a.convergence_threshold_millionths,
        b.convergence_threshold_millionths
    );
}

// ---------------------------------------------------------------------------
// SpectralAnalyzer — JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analyzer_json_field_max_iterations() {
    let a = SpectralAnalyzer::default();
    let json = serde_json::to_string(&a).unwrap();
    assert!(json.contains("\"max_iterations\""), "got: {json}");
}

#[test]
fn enrichment_analyzer_json_field_threshold() {
    let a = SpectralAnalyzer::default();
    let json = serde_json::to_string(&a).unwrap();
    assert!(
        json.contains("\"convergence_threshold_millionths\""),
        "got: {json}"
    );
}

// ---------------------------------------------------------------------------
// SpectralAnalyzer — default values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analyzer_default_max_iterations_100() {
    let a = SpectralAnalyzer::default();
    assert_eq!(a.max_iterations, 100);
}

#[test]
fn enrichment_analyzer_default_threshold_100() {
    let a = SpectralAnalyzer::default();
    assert_eq!(a.convergence_threshold_millionths, 100);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — Clone, Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_clone_eq() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cloned = analysis.clone();
    assert_eq!(analysis, cloned);
}

#[test]
fn enrichment_analysis_debug_nonempty() {
    let topo = complete_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let d = format!("{analysis:?}");
    assert!(!d.is_empty());
    assert!(d.contains("SpectralAnalysis"), "got: {d}");
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — JSON field names (all 15 fields)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_json_all_fields() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let json = serde_json::to_string(&analysis).unwrap();
    for field in &[
        "schema",
        "num_nodes",
        "algebraic_connectivity_millionths",
        "spectral_gap_millionths",
        "mixing_time_bound",
        "lambda_max_millionths",
        "lambda_max_iterations",
        "fiedler_iterations",
        "fiedler_residual_millionths",
        "cheeger_lower_bound_millionths",
        "cheeger_upper_bound_millionths",
        "fiedler_vector_millionths",
        "partition_a",
        "partition_b",
        "laplacian_hash",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing field {field} in {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_deterministic_path() {
    let topo = path_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let r1 = analyzer.analyze(&topo).unwrap();
    let r2 = analyzer.analyze(&topo).unwrap();
    assert_eq!(r1, r2);
}

#[test]
fn enrichment_analysis_deterministic_complete() {
    let topo = complete_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let r1 = analyzer.analyze(&topo).unwrap();
    let r2 = analyzer.analyze(&topo).unwrap();
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — spectral gap == algebraic connectivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_spectral_gap_equals_algebraic_connectivity() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert_eq!(
        r.spectral_gap_millionths,
        r.algebraic_connectivity_millionths
    );
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — lambda_max >= spectral_gap
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lambda_max_geq_spectral_gap_cycle() {
    let topo = cycle_graph(8);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.lambda_max_millionths >= r.spectral_gap_millionths);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — iteration counts bounded
// ---------------------------------------------------------------------------

#[test]
fn enrichment_iteration_counts_within_max() {
    let topo = path_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.lambda_max_iterations >= 1);
    assert!(r.lambda_max_iterations <= analyzer.max_iterations);
    assert!(r.fiedler_iterations >= 1);
    assert!(r.fiedler_iterations <= analyzer.max_iterations);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — fiedler_residual nonnegative
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fiedler_residual_nonnegative() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.fiedler_residual_millionths >= 0);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — partition indices valid and unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_partition_indices_valid() {
    let topo = path_graph(7);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    for &idx in &r.partition_a {
        assert!(idx < 7, "partition_a index {idx} out of bounds");
    }
    for &idx in &r.partition_b {
        assert!(idx < 7, "partition_b index {idx} out of bounds");
    }
}

#[test]
fn enrichment_partition_indices_no_duplicates() {
    let topo = path_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    let all: std::collections::BTreeSet<usize> = r
        .partition_a
        .iter()
        .chain(r.partition_b.iter())
        .copied()
        .collect();
    assert_eq!(all.len(), r.partition_a.len() + r.partition_b.len());
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — mixing_time_bound >= 1
// ---------------------------------------------------------------------------

#[test]
fn enrichment_mixing_time_at_least_one() {
    let topo = complete_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.mixing_time_bound >= 1);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — Cheeger bounds nonnegative
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cheeger_bounds_nonneg() {
    let topo = cycle_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.cheeger_lower_bound_millionths >= 0);
    assert!(r.cheeger_upper_bound_millionths >= 0);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — single-node graph fails
// ---------------------------------------------------------------------------

#[test]
fn enrichment_single_node_degenerate() {
    let topo = GossipTopology::new(vec!["solo".into()]).unwrap();
    let analyzer = SpectralAnalyzer::default();
    let err = analyzer.analyze(&topo).unwrap_err();
    assert!(
        matches!(err, SpectralError::DegenerateSpectralGap)
            || matches!(err, SpectralError::ConvergenceFailure { .. })
    );
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — two-node eigenvalue
// ---------------------------------------------------------------------------

#[test]
fn enrichment_two_node_eigenvalue_near_2m() {
    let mut topo = GossipTopology::new(nodes(2)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!((r.algebraic_connectivity_millionths - 2_000_000).abs() < 200_000);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — barbell partition
// ---------------------------------------------------------------------------

#[test]
fn enrichment_barbell_detects_partition() {
    let mut topo = GossipTopology::new(nodes(6)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(1, 2, 1_000_000).unwrap();
    topo.add_edge(0, 2, 1_000_000).unwrap();
    topo.add_edge(2, 3, 1_000_000).unwrap();
    topo.add_edge(3, 4, 1_000_000).unwrap();
    topo.add_edge(4, 5, 1_000_000).unwrap();
    topo.add_edge(3, 5, 1_000_000).unwrap();

    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(!r.partition_a.is_empty());
    assert!(!r.partition_b.is_empty());
    assert_eq!(r.partition_a.len() + r.partition_b.len(), 6);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — complete graph high connectivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_complete_graph_high_connectivity_k5() {
    let topo = complete_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.algebraic_connectivity_millionths > 1_000_000);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — longer path -> lower connectivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_longer_path_lower_connectivity() {
    let analyzer = SpectralAnalyzer::default();
    let r4 = analyzer.analyze(&path_graph(4)).unwrap();
    let r8 = analyzer.analyze(&path_graph(8)).unwrap();
    assert!(
        r8.algebraic_connectivity_millionths <= r4.algebraic_connectivity_millionths,
        "8-path ({}) should have <= connectivity than 4-path ({})",
        r8.algebraic_connectivity_millionths,
        r4.algebraic_connectivity_millionths
    );
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — path slower mixing than complete
// ---------------------------------------------------------------------------

#[test]
fn enrichment_path_slower_mixing_than_complete() {
    let analyzer = SpectralAnalyzer::default();
    let rc = analyzer.analyze(&complete_graph(6)).unwrap();
    let rp = analyzer.analyze(&path_graph(6)).unwrap();
    assert!(rp.mixing_time_bound >= rc.mixing_time_bound);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — cycle < complete connectivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cycle_lower_connectivity_than_complete() {
    let analyzer = SpectralAnalyzer::default();
    let rc = analyzer.analyze(&complete_graph(6)).unwrap();
    let ry = analyzer.analyze(&cycle_graph(6)).unwrap();
    assert!(ry.algebraic_connectivity_millionths < rc.algebraic_connectivity_millionths);
}

// ---------------------------------------------------------------------------
// SpectralAnalysis — serde roundtrip for varied topologies
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_serde_roundtrip_cycle() {
    let topo = cycle_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: SpectralAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn enrichment_analysis_serde_roundtrip_complete() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    let json = serde_json::to_string(&r).unwrap();
    let back: SpectralAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — Clone, Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_clone_eq() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    let cert2 = cert.clone();
    assert_eq!(cert, cert2);
}

#[test]
fn enrichment_certificate_debug_nonempty() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    let d = format!("{cert:?}");
    assert!(!d.is_empty());
    assert!(d.contains("ConvergenceCertificate"), "got: {d}");
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — JSON field names (all 13 fields)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_json_all_fields() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    let json = serde_json::to_string(&cert).unwrap();
    for field in &[
        "schema",
        "num_nodes",
        "mixing_time_rounds",
        "spectral_gap_millionths",
        "cheeger_lower_millionths",
        "cheeger_upper_millionths",
        "lambda_max_millionths",
        "fiedler_iterations",
        "fiedler_residual_millionths",
        "has_natural_partition",
        "partition_sizes",
        "epoch",
        "certificate_hash",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing field {field} in {json}"
        );
    }
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — schema field
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_schema_field() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    assert_eq!(cert.schema, SPECTRAL_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — fields propagated from analysis
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_fields_from_analysis() {
    let topo = cycle_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let epoch = SecurityEpoch::from_raw(77);
    let cert = ConvergenceCertificate::from_analysis(&analysis, epoch);

    assert_eq!(cert.num_nodes, analysis.num_nodes);
    assert_eq!(cert.mixing_time_rounds, analysis.mixing_time_bound);
    assert_eq!(
        cert.spectral_gap_millionths,
        analysis.spectral_gap_millionths
    );
    assert_eq!(
        cert.cheeger_lower_millionths,
        analysis.cheeger_lower_bound_millionths
    );
    assert_eq!(
        cert.cheeger_upper_millionths,
        analysis.cheeger_upper_bound_millionths
    );
    assert_eq!(cert.lambda_max_millionths, analysis.lambda_max_millionths);
    assert_eq!(cert.fiedler_iterations, analysis.fiedler_iterations);
    assert_eq!(
        cert.fiedler_residual_millionths,
        analysis.fiedler_residual_millionths
    );
    assert_eq!(cert.epoch, epoch);
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — partition_sizes sum
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_partition_sizes_sum() {
    let topo = path_graph(8);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    let (a, b) = cert.partition_sizes;
    assert_eq!(a + b, 8);
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — meets_sla boundary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_meets_sla_exact_boundary() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    assert!(cert.meets_sla(cert.mixing_time_rounds));
    if cert.mixing_time_rounds > 0 {
        assert!(!cert.meets_sla(cert.mixing_time_rounds - 1));
    }
}

#[test]
fn enrichment_certificate_meets_sla_u64_max() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    assert!(cert.meets_sla(u64::MAX));
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — hash varies by epoch
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_hash_varies_by_epoch_five() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let hashes: std::collections::BTreeSet<_> = (0..5u64)
        .map(|e| {
            let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(e));
            cert.certificate_hash
        })
        .collect();
    assert_eq!(hashes.len(), 5, "each epoch should produce distinct hash");
}

// ---------------------------------------------------------------------------
// ConvergenceCertificate — serde roundtrip for multiple topologies
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_serde_roundtrip_path() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(99));
    let json = serde_json::to_string(&cert).unwrap();
    let back: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

#[test]
fn enrichment_certificate_serde_roundtrip_complete() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(10));
    let json = serde_json::to_string(&cert).unwrap();
    let back: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// Full lifecycle — weighted barbell
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_weighted_barbell() {
    let mut topo = GossipTopology::new(nodes(6)).unwrap();
    topo.add_edge(0, 1, 5_000_000).unwrap();
    topo.add_edge(1, 2, 5_000_000).unwrap();
    topo.add_edge(0, 2, 5_000_000).unwrap();
    topo.add_edge(2, 3, 100_000).unwrap(); // weak bridge
    topo.add_edge(3, 4, 5_000_000).unwrap();
    topo.add_edge(4, 5, 5_000_000).unwrap();
    topo.add_edge(3, 5, 5_000_000).unwrap();

    assert!(topo.is_connected());
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.algebraic_connectivity_millionths > 0);
    assert!(r.algebraic_connectivity_millionths < 5_000_000);

    let cert = ConvergenceCertificate::from_analysis(&r, SecurityEpoch::from_raw(1));
    assert!(cert.has_natural_partition);
    let json = serde_json::to_string(&cert).unwrap();
    let back: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// ---------------------------------------------------------------------------
// Full lifecycle — ring with chords
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lifecycle_ring_with_chords() {
    let mut topo = GossipTopology::new(nodes(8)).unwrap();
    for i in 0..8 {
        topo.add_edge(i, (i + 1) % 8, 1_000_000).unwrap();
    }
    topo.add_edge(0, 4, 1_000_000).unwrap();
    topo.add_edge(2, 6, 1_000_000).unwrap();
    assert!(topo.is_connected());

    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert_eq!(r.num_nodes, 8);

    let r_plain = analyzer.analyze(&cycle_graph(8)).unwrap();
    assert!(
        r.algebraic_connectivity_millionths >= r_plain.algebraic_connectivity_millionths,
        "chord ring ({}) should have >= connectivity of plain ring ({})",
        r.algebraic_connectivity_millionths,
        r_plain.algebraic_connectivity_millionths
    );
}

// ---------------------------------------------------------------------------
// Topology — serde preserves node_ids
// ---------------------------------------------------------------------------

#[test]
fn enrichment_topology_serde_preserves_node_ids() {
    let topo = GossipTopology::new(vec!["alpha".into(), "bravo".into(), "charlie".into()]).unwrap();
    let json = serde_json::to_string(&topo).unwrap();
    let back: GossipTopology = serde_json::from_str(&json).unwrap();
    assert_eq!(back.node_ids, vec!["alpha", "bravo", "charlie"]);
}

// ---------------------------------------------------------------------------
// Topology — degree for star center
// ---------------------------------------------------------------------------

#[test]
fn enrichment_topology_degree_full_star() {
    let n = 6;
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 1..n {
        topo.add_edge(0, i, 1_000_000).unwrap();
    }
    assert_eq!(topo.degree(0), 5_000_000);
    for i in 1..n {
        assert_eq!(topo.degree(i), 1_000_000);
    }
}

// ---------------------------------------------------------------------------
// Analysis — schema matches constant value
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_schema_matches_constant() {
    let topo = complete_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert_eq!(r.schema, "franken-engine.spectral-fleet-convergence.v1");
}

// ---------------------------------------------------------------------------
// Analysis — laplacian_hash matches independently computed
// ---------------------------------------------------------------------------

#[test]
fn enrichment_analysis_laplacian_hash_matches() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(r.laplacian_hash, lap.content_hash());
}

// ---------------------------------------------------------------------------
// Weighted edges — heavier weight -> higher connectivity
// ---------------------------------------------------------------------------

#[test]
fn enrichment_heavier_weight_higher_connectivity() {
    let analyzer = SpectralAnalyzer::default();
    let mut topo_light = GossipTopology::new(nodes(3)).unwrap();
    topo_light.add_edge(0, 1, 100_000).unwrap();
    topo_light.add_edge(1, 2, 100_000).unwrap();

    let mut topo_heavy = GossipTopology::new(nodes(3)).unwrap();
    topo_heavy.add_edge(0, 1, 10_000_000).unwrap();
    topo_heavy.add_edge(1, 2, 10_000_000).unwrap();

    let rl = analyzer.analyze(&topo_light).unwrap();
    let rh = analyzer.analyze(&topo_heavy).unwrap();
    assert!(
        rh.algebraic_connectivity_millionths > rl.algebraic_connectivity_millionths,
        "heavy ({}) should exceed light ({})",
        rh.algebraic_connectivity_millionths,
        rl.algebraic_connectivity_millionths
    );
}

// ---------------------------------------------------------------------------
// Disconnected graph — four components
// ---------------------------------------------------------------------------

#[test]
fn enrichment_disconnected_four_components() {
    let mut topo = GossipTopology::new(nodes(8)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(2, 3, 1_000_000).unwrap();
    topo.add_edge(4, 5, 1_000_000).unwrap();
    topo.add_edge(6, 7, 1_000_000).unwrap();
    assert_eq!(topo.connected_components(), 4);
    let err = SpectralAnalyzer::default().analyze(&topo).unwrap_err();
    assert!(matches!(err, SpectralError::Disconnected { components: 4 }));
}

// ---------------------------------------------------------------------------
// Large-weight overflow safety
// ---------------------------------------------------------------------------

#[test]
fn enrichment_large_weight_no_panic() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let w = i64::MAX / 16;
    topo.add_edge(0, 1, w).unwrap();
    topo.add_edge(1, 2, w).unwrap();
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(r.mixing_time_bound >= 1);
}

// ---------------------------------------------------------------------------
// Laplacian — single node
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_single_node() {
    let topo = GossipTopology::new(vec!["solo".into()]).unwrap();
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(lap.dim, 1);
    assert_eq!(lap.get(0, 0), 0);
}

// ---------------------------------------------------------------------------
// Laplacian — weighted path values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_weighted_path_values() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    topo.add_edge(0, 1, 2_000_000).unwrap();
    topo.add_edge(1, 2, 3_000_000).unwrap();
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(lap.get(0, 0), 2_000_000);
    assert_eq!(lap.get(1, 1), 5_000_000);
    assert_eq!(lap.get(2, 2), 3_000_000);
    assert_eq!(lap.get(0, 1), -2_000_000);
    assert_eq!(lap.get(1, 2), -3_000_000);
    assert_eq!(lap.get(0, 2), 0);
}

// ---------------------------------------------------------------------------
// Certificate — epoch boundary values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_epoch_zero() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(0));
    assert_eq!(cert.epoch, SecurityEpoch::from_raw(0));
}

#[test]
fn enrichment_certificate_epoch_large() {
    let topo = path_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(u64::MAX));
    assert_eq!(cert.epoch, SecurityEpoch::from_raw(u64::MAX));
}

// ---------------------------------------------------------------------------
// Certificate — partition sizes for complete graph
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_complete_graph_partition_sum() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    let (a, b) = cert.partition_sizes;
    assert_eq!(a + b, 4);
}

// ---------------------------------------------------------------------------
// Two default analyzers produce identical results
// ---------------------------------------------------------------------------

#[test]
fn enrichment_two_default_analyzers_same_result() {
    let topo = path_graph(5);
    let a1 = SpectralAnalyzer::default();
    let a2 = SpectralAnalyzer::default();
    let r1 = a1.analyze(&topo).unwrap();
    let r2 = a2.analyze(&topo).unwrap();
    assert_eq!(r1, r2);
}

// ---------------------------------------------------------------------------
// Fiedler residual small for complete graph
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fiedler_residual_small_complete() {
    let topo = complete_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let r = analyzer.analyze(&topo).unwrap();
    assert!(
        r.fiedler_residual_millionths < 200_000,
        "residual {} too large",
        r.fiedler_residual_millionths
    );
}

// ---------------------------------------------------------------------------
// Laplacian from cycle diagonal = 2M
// ---------------------------------------------------------------------------

#[test]
fn enrichment_laplacian_cycle_diagonal_2m() {
    let topo = cycle_graph(5);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    for i in 0..5 {
        assert_eq!(lap.get(i, i), 2_000_000, "node {i} diagonal");
    }
}

// ---------------------------------------------------------------------------
// Certificate deterministic for same inputs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_certificate_deterministic() {
    let topo = cycle_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let epoch = SecurityEpoch::from_raw(42);
    let c1 = ConvergenceCertificate::from_analysis(&analysis, epoch);
    let c2 = ConvergenceCertificate::from_analysis(&analysis, epoch);
    assert_eq!(c1, c2);
}
