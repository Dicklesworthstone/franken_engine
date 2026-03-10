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
    // Path graphs have small spectral gap → longer mixing time
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
    // Complete graph has fast mixing → should meet a generous SLA
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
