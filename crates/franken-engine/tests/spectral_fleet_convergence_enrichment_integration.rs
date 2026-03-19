//! Enrichment integration tests for `spectral_fleet_convergence`.
//!
//! Covers additional edge-case scenarios for GossipTopology, LaplacianMatrix,
//! SpectralAnalyzer, ConvergenceCertificate, and SpectralError beyond the
//! base integration test suite.

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
    ConvergenceCertificate, GossipTopology, LaplacianMatrix, SpectralAnalysis,
    SpectralAnalyzer, SpectralError, SPECTRAL_SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn nodes(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("node-{i}")).collect()
}

fn complete_graph(n: usize) -> GossipTopology {
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 0..n {
        for j in (i + 1)..n {
            topo.add_edge(i, j, 1_000_000).unwrap();
        }
    }
    topo
}

fn path_graph(n: usize) -> GossipTopology {
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 0..(n - 1) {
        topo.add_edge(i, i + 1, 1_000_000).unwrap();
    }
    topo
}

fn cycle_graph(n: usize) -> GossipTopology {
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 0..n {
        topo.add_edge(i, (i + 1) % n, 1_000_000).unwrap();
    }
    topo
}

fn star_graph(n: usize) -> GossipTopology {
    let mut topo = GossipTopology::new(nodes(n)).unwrap();
    for i in 1..n {
        topo.add_edge(0, i, 1_000_000).unwrap();
    }
    topo
}

// ===========================================================================
// 1. SPECTRAL_SCHEMA_VERSION constant
// ===========================================================================

#[test]
fn enrichment_schema_version_contains_spectral() {
    assert!(SPECTRAL_SCHEMA_VERSION.contains("spectral"));
}

#[test]
fn enrichment_schema_version_starts_with_franken_engine() {
    assert!(SPECTRAL_SCHEMA_VERSION.starts_with("franken-engine."));
}

// ===========================================================================
// 2. GossipTopology construction edge cases
// ===========================================================================

#[test]
fn enrichment_topology_single_node_no_edges() {
    let topo = GossipTopology::new(vec!["solo".to_string()]).unwrap();
    assert_eq!(topo.num_nodes, 1);
    assert!(topo.is_connected());
    assert_eq!(topo.connected_components(), 1);
    assert_eq!(topo.degree(0), 0);
}

#[test]
fn enrichment_topology_two_nodes_disconnected() {
    let topo = GossipTopology::new(nodes(2)).unwrap();
    assert!(!topo.is_connected());
    assert_eq!(topo.connected_components(), 2);
}

#[test]
fn enrichment_topology_self_loop_edge() {
    let mut topo = GossipTopology::new(nodes(2)).unwrap();
    topo.add_edge(0, 0, 1_000_000).unwrap();
    // Self-loop only adds once to adjacency, counts toward degree
    assert_eq!(topo.degree(0), 1_000_000);
}

#[test]
fn enrichment_topology_negative_weight_rejected() {
    let mut topo = GossipTopology::new(nodes(2)).unwrap();
    let result = topo.add_edge(0, 1, -1);
    assert!(matches!(
        result,
        Err(SpectralError::InvalidEdgeWeight { weight_millionths: -1 })
    ));
}

#[test]
fn enrichment_topology_zero_weight_rejected() {
    let mut topo = GossipTopology::new(nodes(2)).unwrap();
    let result = topo.add_edge(0, 1, 0);
    assert!(matches!(
        result,
        Err(SpectralError::InvalidEdgeWeight { weight_millionths: 0 })
    ));
}

#[test]
fn enrichment_topology_from_index_out_of_bounds() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let result = topo.add_edge(5, 0, 1_000_000);
    assert!(matches!(
        result,
        Err(SpectralError::NodeOutOfBounds { index: 5, size: 3 })
    ));
}

#[test]
fn enrichment_topology_to_index_out_of_bounds() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let result = topo.add_edge(0, 10, 1_000_000);
    assert!(matches!(
        result,
        Err(SpectralError::NodeOutOfBounds { index: 10, size: 3 })
    ));
}

#[test]
fn enrichment_topology_parallel_edges_accumulate_degree() {
    let mut topo = GossipTopology::new(nodes(2)).unwrap();
    topo.add_edge(0, 1, 500_000).unwrap();
    topo.add_edge(0, 1, 300_000).unwrap();
    // Two parallel edges: degree(0) = 500_000 + 300_000
    assert_eq!(topo.degree(0), 800_000);
    assert_eq!(topo.degree(1), 800_000);
}

#[test]
fn enrichment_topology_star_graph_connected() {
    let topo = star_graph(5);
    assert!(topo.is_connected());
    assert_eq!(topo.connected_components(), 1);
    // Center node (0) has degree = 4 * 1_000_000
    assert_eq!(topo.degree(0), 4_000_000);
    // Leaf nodes have degree = 1_000_000
    for i in 1..5 {
        assert_eq!(topo.degree(i), 1_000_000);
    }
}

#[test]
fn enrichment_topology_serde_roundtrip_with_edges() {
    let topo = path_graph(4);
    let json = serde_json::to_string(&topo).unwrap();
    let restored: GossipTopology = serde_json::from_str(&json).unwrap();
    assert_eq!(topo, restored);
}

#[test]
fn enrichment_topology_node_ids_preserved() {
    let ids = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
    let topo = GossipTopology::new(ids.clone()).unwrap();
    assert_eq!(topo.node_ids, ids);
}

// ===========================================================================
// 3. LaplacianMatrix properties
// ===========================================================================

#[test]
fn enrichment_laplacian_row_sums_zero_path_graph() {
    let topo = path_graph(5);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    for i in 0..5 {
        let row_sum: i64 = (0..5).map(|j| lap.get(i, j)).sum();
        assert_eq!(row_sum, 0, "row {i} should sum to zero");
    }
}

#[test]
fn enrichment_laplacian_symmetry_star_graph() {
    let topo = star_graph(4);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    for i in 0..4 {
        for j in 0..4 {
            assert_eq!(lap.get(i, j), lap.get(j, i), "L[{i},{j}] != L[{j},{i}]");
        }
    }
}

#[test]
fn enrichment_laplacian_diagonal_equals_degree() {
    let topo = star_graph(4);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(lap.get(0, 0), 3_000_000); // center
    for i in 1..4 {
        assert_eq!(lap.get(i, i), 1_000_000); // leaves
    }
}

#[test]
fn enrichment_laplacian_content_hash_changes_with_topology() {
    let topo1 = path_graph(3);
    let topo2 = complete_graph(3);
    let lap1 = LaplacianMatrix::from_topology(&topo1).unwrap();
    let lap2 = LaplacianMatrix::from_topology(&topo2).unwrap();
    assert_ne!(lap1.content_hash(), lap2.content_hash());
}

#[test]
fn enrichment_laplacian_dim_matches_topology() {
    let topo = complete_graph(7);
    let lap = LaplacianMatrix::from_topology(&topo).unwrap();
    assert_eq!(lap.dim, 7);
}

// ===========================================================================
// 4. SpectralAnalyzer analysis
// ===========================================================================

#[test]
fn enrichment_analyzer_default_settings() {
    let analyzer = SpectralAnalyzer::default();
    assert!(analyzer.max_iterations > 0);
    assert!(analyzer.convergence_threshold_millionths > 0);
}

#[test]
fn enrichment_analyzer_custom_settings() {
    let analyzer = SpectralAnalyzer {
        max_iterations: 200,
        convergence_threshold_millionths: 50,
    };
    assert_eq!(analyzer.max_iterations, 200);
    assert_eq!(analyzer.convergence_threshold_millionths, 50);
}

#[test]
fn enrichment_analysis_complete_graph_high_connectivity() {
    let topo = complete_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    // K_n has λ₂ = n (with unit weights), so for K_5, λ₂ = 5
    assert!(analysis.algebraic_connectivity_millionths > 0);
    assert!(analysis.spectral_gap_millionths > 0);
    assert!(analysis.lambda_max_millionths >= analysis.algebraic_connectivity_millionths);
}

#[test]
fn enrichment_analysis_path_graph_lower_connectivity() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert!(analysis.algebraic_connectivity_millionths > 0);
    // Path graph has smaller connectivity than complete graph
    let topo_k = complete_graph(5);
    let analysis_k = analyzer.analyze(&topo_k).unwrap();
    assert!(
        analysis.algebraic_connectivity_millionths < analysis_k.algebraic_connectivity_millionths,
        "path should have lower connectivity than complete"
    );
}

#[test]
fn enrichment_analysis_cycle_graph_converges() {
    let topo = cycle_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert!(analysis.algebraic_connectivity_millionths > 0);
    assert_eq!(analysis.num_nodes, 6);
}

#[test]
fn enrichment_analysis_star_graph_converges() {
    let topo = star_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert!(analysis.algebraic_connectivity_millionths > 0);
}

#[test]
fn enrichment_analysis_disconnected_graph_rejected() {
    let mut topo = GossipTopology::new(nodes(4)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    // Nodes 2,3 disconnected
    let analyzer = SpectralAnalyzer::default();
    let err = analyzer.analyze(&topo).unwrap_err();
    assert!(matches!(err, SpectralError::Disconnected { components: 3 }));
}

#[test]
fn enrichment_analysis_single_node_degenerate() {
    let topo = GossipTopology::new(vec!["solo".to_string()]).unwrap();
    let analyzer = SpectralAnalyzer::default();
    let result = analyzer.analyze(&topo);
    assert!(result.is_err());
}

#[test]
fn enrichment_analysis_two_node_graph_eigenvalues() {
    let mut topo = GossipTopology::new(nodes(2)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    // For 2-node graph with unit weight: eigenvalues are 0 and 2_000_000
    assert!((analysis.algebraic_connectivity_millionths - 2_000_000).abs() < 200_000);
}

#[test]
fn enrichment_analysis_fiedler_vector_length_matches_nodes() {
    let topo = complete_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert_eq!(analysis.fiedler_vector_millionths.len(), 6);
}

#[test]
fn enrichment_analysis_partitions_cover_all_nodes() {
    let topo = complete_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let total = analysis.partition_a.len() + analysis.partition_b.len();
    assert_eq!(total, 5, "partitions should cover all nodes");
}

#[test]
fn enrichment_analysis_cheeger_bounds_valid() {
    let topo = path_graph(6);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert!(analysis.cheeger_lower_bound_millionths >= 0);
    assert!(analysis.cheeger_upper_bound_millionths >= analysis.cheeger_lower_bound_millionths);
}

#[test]
fn enrichment_analysis_mixing_time_positive() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert!(analysis.mixing_time_bound >= 1);
}

#[test]
fn enrichment_analysis_schema_string_correct() {
    let topo = complete_graph(3);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert_eq!(analysis.schema, SPECTRAL_SCHEMA_VERSION);
}

#[test]
fn enrichment_analysis_deterministic_repeat() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let a1 = analyzer.analyze(&topo).unwrap();
    let a2 = analyzer.analyze(&topo).unwrap();
    assert_eq!(a1, a2);
}

// ===========================================================================
// 5. ConvergenceCertificate
// ===========================================================================

#[test]
fn enrichment_certificate_from_analysis_fields_correct() {
    let topo = complete_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let epoch = SecurityEpoch::from_raw(99);
    let cert = ConvergenceCertificate::from_analysis(&analysis, epoch);

    assert_eq!(cert.num_nodes, 5);
    assert_eq!(cert.schema, SPECTRAL_SCHEMA_VERSION);
    assert_eq!(cert.epoch, epoch);
    assert_eq!(cert.spectral_gap_millionths, analysis.spectral_gap_millionths);
    assert_eq!(cert.mixing_time_rounds, analysis.mixing_time_bound);
    assert_eq!(cert.lambda_max_millionths, analysis.lambda_max_millionths);
    assert_eq!(cert.fiedler_iterations, analysis.fiedler_iterations);
    assert_eq!(cert.fiedler_residual_millionths, analysis.fiedler_residual_millionths);
    assert_eq!(cert.cheeger_lower_millionths, analysis.cheeger_lower_bound_millionths);
    assert_eq!(cert.cheeger_upper_millionths, analysis.cheeger_upper_bound_millionths);
}

#[test]
fn enrichment_certificate_meets_sla_generous_bound() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    assert!(cert.meets_sla(10_000));
}

#[test]
fn enrichment_certificate_does_not_meet_impossible_sla() {
    let topo = path_graph(10);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    // SLA of 0 should never be met
    assert!(!cert.meets_sla(0));
}

#[test]
fn enrichment_certificate_hash_deterministic() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let epoch = SecurityEpoch::from_raw(42);
    let cert1 = ConvergenceCertificate::from_analysis(&analysis, epoch);
    let cert2 = ConvergenceCertificate::from_analysis(&analysis, epoch);
    assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
}

#[test]
fn enrichment_certificate_hash_differs_by_epoch() {
    let topo = complete_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert1 = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));
    let cert2 = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(2));
    assert_ne!(cert1.certificate_hash, cert2.certificate_hash);
}

#[test]
fn enrichment_certificate_partition_detection() {
    // Barbell graph: two triangles connected by a bridge
    let mut topo = GossipTopology::new(nodes(6)).unwrap();
    topo.add_edge(0, 1, 1_000_000).unwrap();
    topo.add_edge(1, 2, 1_000_000).unwrap();
    topo.add_edge(0, 2, 1_000_000).unwrap();
    topo.add_edge(2, 3, 1_000_000).unwrap();
    topo.add_edge(3, 4, 1_000_000).unwrap();
    topo.add_edge(4, 5, 1_000_000).unwrap();
    topo.add_edge(3, 5, 1_000_000).unwrap();

    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(1));

    assert!(cert.has_natural_partition);
    assert_eq!(cert.partition_sizes.0 + cert.partition_sizes.1, 6);
}

#[test]
fn enrichment_certificate_serde_roundtrip() {
    let topo = path_graph(5);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let cert = ConvergenceCertificate::from_analysis(&analysis, SecurityEpoch::from_raw(7));
    let json = serde_json::to_string(&cert).unwrap();
    let restored: ConvergenceCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, restored);
}

// ===========================================================================
// 6. SpectralError Display
// ===========================================================================

#[test]
fn enrichment_error_display_too_many_nodes() {
    let err = SpectralError::TooManyNodes { count: 2000, max: 1024 };
    let msg = format!("{err}");
    assert!(msg.contains("2000"));
    assert!(msg.contains("1024"));
}

#[test]
fn enrichment_error_display_empty_graph() {
    let err = SpectralError::EmptyGraph;
    assert_eq!(format!("{err}"), "empty graph");
}

#[test]
fn enrichment_error_display_disconnected() {
    let err = SpectralError::Disconnected { components: 3 };
    let msg = format!("{err}");
    assert!(msg.contains("disconnected"));
    assert!(msg.contains("3"));
}

#[test]
fn enrichment_error_display_node_out_of_bounds() {
    let err = SpectralError::NodeOutOfBounds { index: 5, size: 3 };
    let msg = format!("{err}");
    assert!(msg.contains("5"));
    assert!(msg.contains("3"));
}

#[test]
fn enrichment_error_display_invalid_edge_weight() {
    let err = SpectralError::InvalidEdgeWeight { weight_millionths: -42 };
    let msg = format!("{err}");
    assert!(msg.contains("-42"));
}

#[test]
fn enrichment_error_display_convergence_failure() {
    let err = SpectralError::ConvergenceFailure { iterations: 100 };
    let msg = format!("{err}");
    assert!(msg.contains("100"));
}

#[test]
fn enrichment_error_display_degenerate() {
    let err = SpectralError::DegenerateSpectralGap;
    let msg = format!("{err}");
    assert!(msg.contains("spectral gap"));
}

// ===========================================================================
// 7. SpectralError serde
// ===========================================================================

#[test]
fn enrichment_error_serde_all_variants() {
    let errors = vec![
        SpectralError::TooManyNodes { count: 2000, max: 1024 },
        SpectralError::EmptyGraph,
        SpectralError::Disconnected { components: 3 },
        SpectralError::NodeOutOfBounds { index: 5, size: 3 },
        SpectralError::InvalidEdgeWeight { weight_millionths: -1 },
        SpectralError::ConvergenceFailure { iterations: 100 },
        SpectralError::DegenerateSpectralGap,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: SpectralError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

// ===========================================================================
// 8. SpectralAnalysis serde
// ===========================================================================

#[test]
fn enrichment_spectral_analysis_serde_roundtrip() {
    let topo = path_graph(4);
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    let json = serde_json::to_string(&analysis).unwrap();
    let restored: SpectralAnalysis = serde_json::from_str(&json).unwrap();
    assert_eq!(analysis, restored);
}

// ===========================================================================
// 9. Weighted topology analysis
// ===========================================================================

#[test]
fn enrichment_weighted_edges_affect_spectral_gap() {
    // Strong edges should give higher connectivity
    let mut topo_strong = GossipTopology::new(nodes(3)).unwrap();
    topo_strong.add_edge(0, 1, 10_000_000).unwrap();
    topo_strong.add_edge(1, 2, 10_000_000).unwrap();
    topo_strong.add_edge(0, 2, 10_000_000).unwrap();

    let mut topo_weak = GossipTopology::new(nodes(3)).unwrap();
    topo_weak.add_edge(0, 1, 100_000).unwrap();
    topo_weak.add_edge(1, 2, 100_000).unwrap();
    topo_weak.add_edge(0, 2, 100_000).unwrap();

    let analyzer = SpectralAnalyzer::default();
    let a_strong = analyzer.analyze(&topo_strong).unwrap();
    let a_weak = analyzer.analyze(&topo_weak).unwrap();

    assert!(
        a_strong.spectral_gap_millionths > a_weak.spectral_gap_millionths,
        "stronger edges should give higher spectral gap"
    );
}

// ===========================================================================
// 10. Topology with large weights
// ===========================================================================

#[test]
fn enrichment_large_weight_does_not_panic() {
    let mut topo = GossipTopology::new(nodes(3)).unwrap();
    let large_w = i64::MAX / 16;
    topo.add_edge(0, 1, large_w).unwrap();
    topo.add_edge(1, 2, large_w).unwrap();
    topo.add_edge(0, 2, large_w).unwrap();
    let analyzer = SpectralAnalyzer::default();
    let analysis = analyzer.analyze(&topo).unwrap();
    assert!(analysis.mixing_time_bound >= 1);
}

// ===========================================================================
// 11. Path vs cycle mixing times
// ===========================================================================

#[test]
fn enrichment_cycle_mixes_faster_than_path() {
    // Cycle should generally have better mixing than path of same size
    let path_topo = path_graph(8);
    let cycle_topo = cycle_graph(8);
    let analyzer = SpectralAnalyzer::default();
    let a_path = analyzer.analyze(&path_topo).unwrap();
    let a_cycle = analyzer.analyze(&cycle_topo).unwrap();
    assert!(
        a_cycle.spectral_gap_millionths >= a_path.spectral_gap_millionths,
        "cycle should have at least as good connectivity as path"
    );
}
