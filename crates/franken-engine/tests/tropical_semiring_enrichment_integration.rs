//! Enrichment integration tests for the `tropical_semiring` module.
//!
//! Covers: semiring axiom edge cases, matrix algebra boundary conditions,
//! Floyd-Warshall negative cycles, scheduler determinism, dead-code elimination
//! edge cases, register pressure boundaries, Debug/Display formatting,
//! serde stability, and full-lifecycle audit artifacts.

#![forbid(unsafe_code)]
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

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::IrLevel;
use frankenengine_engine::tropical_semiring::{
    DeadCodeEliminator, DeadCodeReport, InstructionCostGraph, InstructionNode,
    OptimalityCertificate, RegisterPressureAnalyzer, RegisterPressureReport, ScheduleOptimizer,
    ScheduleQuality, TROPICAL_INFINITY, TROPICAL_SCHEMA_VERSION, TROPICAL_ZERO, TropicalError,
    TropicalMatrix, TropicalPassWitness, TropicalWeight,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_linear_chain() -> Vec<InstructionNode> {
    vec![
        InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(10),
            predecessors: vec![],
            successors: vec![1],
            register_pressure: 2,
            mnemonic: "load".into(),
        },
        InstructionNode {
            index: 1,
            cost: TropicalWeight::finite(20),
            predecessors: vec![0],
            successors: vec![2],
            register_pressure: 3,
            mnemonic: "add".into(),
        },
        InstructionNode {
            index: 2,
            cost: TropicalWeight::finite(5),
            predecessors: vec![1],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "store".into(),
        },
    ]
}

fn make_diamond() -> Vec<InstructionNode> {
    vec![
        InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(10),
            predecessors: vec![],
            successors: vec![1, 2],
            register_pressure: 2,
            mnemonic: "entry".into(),
        },
        InstructionNode {
            index: 1,
            cost: TropicalWeight::finite(30),
            predecessors: vec![0],
            successors: vec![3],
            register_pressure: 4,
            mnemonic: "branch_a".into(),
        },
        InstructionNode {
            index: 2,
            cost: TropicalWeight::finite(5),
            predecessors: vec![0],
            successors: vec![3],
            register_pressure: 1,
            mnemonic: "branch_b".into(),
        },
        InstructionNode {
            index: 3,
            cost: TropicalWeight::finite(10),
            predecessors: vec![1, 2],
            successors: vec![],
            register_pressure: 2,
            mnemonic: "merge".into(),
        },
    ]
}

fn make_wide_fan(fan_width: usize) -> Vec<InstructionNode> {
    // 0 → {1..fan_width} → fan_width+1
    let n = fan_width + 2;
    let mut nodes = Vec::with_capacity(n);
    nodes.push(InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(1),
        predecessors: vec![],
        successors: (1..=fan_width).collect(),
        register_pressure: 1,
        mnemonic: "source".into(),
    });
    for i in 1..=fan_width {
        nodes.push(InstructionNode {
            index: i,
            cost: TropicalWeight::finite(i as i64 * 10),
            predecessors: vec![0],
            successors: vec![fan_width + 1],
            register_pressure: 2,
            mnemonic: format!("fan_{i}"),
        });
    }
    nodes.push(InstructionNode {
        index: fan_width + 1,
        cost: TropicalWeight::finite(1),
        predecessors: (1..=fan_width).collect(),
        successors: vec![],
        register_pressure: 1,
        mnemonic: "sink".into(),
    });
    nodes
}

// =========================================================================
// A. TropicalWeight — semiring axiom edge cases
// =========================================================================

#[test]
fn enrichment_tropical_add_associative() {
    let a = TropicalWeight::finite(3);
    let b = TropicalWeight::finite(7);
    let c = TropicalWeight::finite(1);
    // (a ⊕ b) ⊕ c == a ⊕ (b ⊕ c)
    assert_eq!(
        a.tropical_add(b).tropical_add(c),
        a.tropical_add(b.tropical_add(c))
    );
}

#[test]
fn enrichment_tropical_mul_associative() {
    let a = TropicalWeight::finite(3);
    let b = TropicalWeight::finite(7);
    let c = TropicalWeight::finite(2);
    // (a ⊗ b) ⊗ c == a ⊗ (b ⊗ c)
    assert_eq!(
        a.tropical_mul(b).tropical_mul(c),
        a.tropical_mul(b.tropical_mul(c))
    );
}

#[test]
fn enrichment_tropical_mul_distributes_over_add() {
    let a = TropicalWeight::finite(5);
    let b = TropicalWeight::finite(3);
    let c = TropicalWeight::finite(8);
    // a ⊗ (b ⊕ c) == (a ⊗ b) ⊕ (a ⊗ c)
    let lhs = a.tropical_mul(b.tropical_add(c));
    let rhs = a.tropical_mul(b).tropical_add(a.tropical_mul(c));
    assert_eq!(lhs, rhs);
}

#[test]
fn enrichment_tropical_add_commutative_negative() {
    let a = TropicalWeight::finite(-10);
    let b = TropicalWeight::finite(5);
    assert_eq!(a.tropical_add(b), b.tropical_add(a));
    assert_eq!(a.tropical_add(b), TropicalWeight::finite(-10));
}

#[test]
fn enrichment_tropical_mul_negative_weights() {
    let a = TropicalWeight::finite(-3);
    let b = TropicalWeight::finite(7);
    // -3 + 7 = 4
    assert_eq!(a.tropical_mul(b), TropicalWeight::finite(4));
}

#[test]
fn enrichment_tropical_mul_both_negative() {
    let a = TropicalWeight::finite(-5);
    let b = TropicalWeight::finite(-3);
    assert_eq!(a.tropical_mul(b), TropicalWeight::finite(-8));
}

#[test]
fn enrichment_tropical_add_idempotent() {
    // min(x, x) = x for all x
    let w = TropicalWeight::finite(42);
    assert_eq!(w.tropical_add(w), w);
    assert_eq!(
        TropicalWeight::INFINITY.tropical_add(TropicalWeight::INFINITY),
        TropicalWeight::INFINITY
    );
}

#[test]
fn enrichment_weight_zero_is_finite() {
    assert!(TropicalWeight::ZERO.is_finite());
    assert!(!TropicalWeight::ZERO.is_infinite());
    assert_eq!(TropicalWeight::ZERO.0, 0);
}

#[test]
fn enrichment_weight_display_negative() {
    assert_eq!(TropicalWeight::finite(-42).to_string(), "-42");
}

#[test]
fn enrichment_weight_display_zero() {
    assert_eq!(TropicalWeight::ZERO.to_string(), "0");
}

#[test]
fn enrichment_weight_ord_finite_less_than_infinity() {
    assert!(TropicalWeight::finite(999_999) < TropicalWeight::INFINITY);
    assert!(TropicalWeight::finite(-1) < TropicalWeight::ZERO);
}

#[test]
fn enrichment_weight_hash_distinct_across_values() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let hash_it = |w: TropicalWeight| {
        let mut h = DefaultHasher::new();
        w.hash(&mut h);
        h.finish()
    };
    let hashes: BTreeSet<_> = [0i64, 1, -1, 42, TROPICAL_INFINITY]
        .iter()
        .map(|&v| hash_it(TropicalWeight(v)))
        .collect();
    assert_eq!(hashes.len(), 5);
}

#[test]
fn enrichment_kleene_star_zero_is_zero() {
    assert_eq!(
        TropicalWeight::ZERO.kleene_star(),
        Some(TropicalWeight::ZERO)
    );
}

#[test]
fn enrichment_kleene_star_large_positive() {
    assert_eq!(
        TropicalWeight::finite(1_000_000).kleene_star(),
        Some(TropicalWeight::ZERO)
    );
}

// =========================================================================
// B. TropicalError — Display completeness and serde
// =========================================================================

#[test]
fn enrichment_error_display_dimension_mismatch() {
    let err = TropicalError::DimensionMismatch { left: 3, right: 4 };
    let s = err.to_string();
    assert!(s.contains("3"));
    assert!(s.contains("4"));
    assert!(s.contains("mismatch"));
}

#[test]
fn enrichment_error_display_cycle_in_dag() {
    let err = TropicalError::CycleInDag {
        nodes_in_cycle: vec![2, 5, 9],
    };
    let s = err.to_string();
    assert!(s.contains("cycle"));
    assert!(s.contains("2"));
}

#[test]
fn enrichment_error_display_node_out_of_bounds() {
    let err = TropicalError::NodeOutOfBounds { index: 10, size: 5 };
    let s = err.to_string();
    assert!(s.contains("10"));
    assert!(s.contains("5"));
}

#[test]
fn enrichment_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(TropicalError::EmptyGraph);
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_error_display_all_variants_distinct() {
    let variants = vec![
        TropicalError::DimensionExceeded { dim: 1, max: 1 },
        TropicalError::DimensionMismatch { left: 1, right: 2 },
        TropicalError::NegativeCycle { node: 0 },
        TropicalError::EmptyGraph,
        TropicalError::CycleInDag {
            nodes_in_cycle: vec![0],
        },
        TropicalError::NodeOutOfBounds { index: 0, size: 0 },
    ];
    let strings: BTreeSet<_> = variants.iter().map(|e| e.to_string()).collect();
    assert_eq!(strings.len(), 6);
}

#[test]
fn enrichment_error_clone_equality() {
    let err = TropicalError::CycleInDag {
        nodes_in_cycle: vec![1, 2, 3],
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

// =========================================================================
// C. TropicalMatrix — edge cases
// =========================================================================

#[test]
fn enrichment_matrix_1x1_identity() {
    let m = TropicalMatrix::identity(1).unwrap();
    assert_eq!(m.get(0, 0), TropicalWeight::ZERO);
    assert_eq!(m.dim, 1);
}

#[test]
fn enrichment_matrix_1x1_infinity() {
    let m = TropicalMatrix::new_infinity(1).unwrap();
    assert!(m.get(0, 0).is_infinite());
}

#[test]
fn enrichment_matrix_0x0() {
    let m = TropicalMatrix::new_infinity(0).unwrap();
    assert_eq!(m.dim, 0);
}

#[test]
fn enrichment_matrix_identity_mul_is_identity() {
    let id = TropicalMatrix::identity(3).unwrap();
    let mut a = TropicalMatrix::new_infinity(3).unwrap();
    a.set(0, 1, TropicalWeight::finite(5));
    a.set(1, 2, TropicalWeight::finite(3));

    let result = id.tropical_mul(&a).unwrap();
    assert_eq!(result.get(0, 1), TropicalWeight::finite(5));
    assert_eq!(result.get(1, 2), TropicalWeight::finite(3));
    assert!(result.get(2, 0).is_infinite());
}

#[test]
fn enrichment_matrix_add_with_identity() {
    // Adding the infinity matrix to any matrix returns that matrix
    let inf = TropicalMatrix::new_infinity(2).unwrap();
    let mut a = TropicalMatrix::new_infinity(2).unwrap();
    a.set(0, 0, TropicalWeight::finite(5));
    a.set(1, 1, TropicalWeight::finite(3));

    let result = inf.tropical_add(&a).unwrap();
    assert_eq!(result.get(0, 0), TropicalWeight::finite(5));
    assert_eq!(result.get(1, 1), TropicalWeight::finite(3));
    assert!(result.get(0, 1).is_infinite());
}

#[test]
fn enrichment_matrix_add_dimension_mismatch() {
    let a = TropicalMatrix::new_infinity(2).unwrap();
    let b = TropicalMatrix::new_infinity(3).unwrap();
    assert!(matches!(
        a.tropical_add(&b),
        Err(TropicalError::DimensionMismatch { .. })
    ));
}

#[test]
fn enrichment_matrix_floyd_warshall_triangle_inequality() {
    // 3-node complete graph: verify triangle inequality after FW
    let mut m = TropicalMatrix::new_infinity(3).unwrap();
    m.set(0, 1, TropicalWeight::finite(1));
    m.set(1, 2, TropicalWeight::finite(2));
    m.set(0, 2, TropicalWeight::finite(10)); // direct path is longer

    let dist = m.floyd_warshall().unwrap();
    // dist[0][2] should be 3 (via 0→1→2), not 10
    assert_eq!(dist.get(0, 2), TropicalWeight::finite(3));
    // triangle inequality: dist[i][j] <= dist[i][k] + dist[k][j]
    for i in 0..3 {
        for j in 0..3 {
            for k in 0..3 {
                let direct = dist.get(i, j);
                let via_k = dist.get(i, k).tropical_mul(dist.get(k, j));
                assert!(direct.0 <= via_k.0);
            }
        }
    }
}

#[test]
fn enrichment_matrix_floyd_warshall_self_loops_zero() {
    let mut m = TropicalMatrix::new_infinity(3).unwrap();
    m.set(0, 1, TropicalWeight::finite(5));
    let dist = m.floyd_warshall().unwrap();
    // Diagonal must be 0 (self-distance)
    for i in 0..3 {
        assert_eq!(dist.get(i, i), TropicalWeight::ZERO);
    }
}

#[test]
fn enrichment_matrix_content_hash_empty() {
    let m = TropicalMatrix::new_infinity(0).unwrap();
    let h = m.content_hash();
    assert!(!h.as_bytes().is_empty());
}

#[test]
fn enrichment_matrix_clone_independence() {
    let mut m = TropicalMatrix::new_infinity(2).unwrap();
    m.set(0, 1, TropicalWeight::finite(42));
    let cloned = m.clone();
    m.set(0, 1, TropicalWeight::finite(99));
    assert_eq!(cloned.get(0, 1), TropicalWeight::finite(42));
    assert_eq!(m.get(0, 1), TropicalWeight::finite(99));
}

// =========================================================================
// D. InstructionCostGraph — validation and analysis
// =========================================================================

#[test]
fn enrichment_graph_out_of_bounds_predecessor() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(1),
        predecessors: vec![99],
        successors: vec![],
        register_pressure: 1,
        mnemonic: "bad_pred".into(),
    }];
    assert!(matches!(
        InstructionCostGraph::new(nodes),
        Err(TropicalError::NodeOutOfBounds { .. })
    ));
}

#[test]
fn enrichment_graph_single_node() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(42),
        predecessors: vec![],
        successors: vec![],
        register_pressure: 5,
        mnemonic: "solo".into(),
    }];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    assert_eq!(graph.len(), 1);
    let cpr = graph.critical_path_length().unwrap();
    assert_eq!(cpr.makespan, TropicalWeight::finite(42));
    assert_eq!(cpr.critical_source, 0);
    assert_eq!(cpr.critical_sink, 0);
}

#[test]
fn enrichment_graph_wide_fan_critical_path() {
    let nodes = make_wide_fan(5);
    let graph = InstructionCostGraph::new(nodes).unwrap();
    assert_eq!(graph.len(), 7); // source + 5 fan + sink
    let cpr = graph.critical_path_length().unwrap();
    // Critical path: source(1) + fan_5(50) + sink(1) = 52
    assert_eq!(cpr.makespan, TropicalWeight::finite(52));
}

#[test]
fn enrichment_graph_register_pressure_single_high() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(1),
        predecessors: vec![],
        successors: vec![],
        register_pressure: 100,
        mnemonic: "heavy".into(),
    }];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    assert_eq!(graph.peak_register_pressure(), 100);
    assert_eq!(graph.total_register_pressure(), 100);
}

#[test]
fn enrichment_graph_all_pairs_shortest_paths_diamond() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    // 0→3 via 1: 10 + 30 = 40; via 2: 10 + 5 = 15
    // Shortest is 15 (edge weights only, not destination cost)
    let dist_0_3 = apsp.shortest_distance(0, 3);
    assert!(dist_0_3.is_finite());
    assert!(dist_0_3.0 <= 40);
}

#[test]
fn enrichment_graph_serde_preserves_adjacency() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let json = serde_json::to_string(&graph).unwrap();
    let restored: InstructionCostGraph = serde_json::from_str(&json).unwrap();
    // APSP should produce same results from restored graph
    let apsp1 = graph.all_pairs_shortest_paths().unwrap();
    let apsp2 = restored.all_pairs_shortest_paths().unwrap();
    assert_eq!(apsp1.content_hash(), apsp2.content_hash());
}

// =========================================================================
// E. ScheduleOptimizer — determinism and edge cases
// =========================================================================

#[test]
fn enrichment_optimizer_schedule_deterministic() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let opt = ScheduleOptimizer::default();
    let s1 = opt.schedule(&graph).unwrap();
    let s2 = opt.schedule(&graph).unwrap();
    assert_eq!(s1.order, s2.order);
    assert_eq!(s1.total_cost, s2.total_cost);
    assert_eq!(s1.quality, s2.quality);
}

#[test]
fn enrichment_optimizer_single_node() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(7),
        predecessors: vec![],
        successors: vec![],
        register_pressure: 1,
        mnemonic: "only".into(),
    }];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();
    assert_eq!(schedule.order, vec![0]);
    assert_eq!(schedule.total_cost, TropicalWeight::finite(7));
    assert_eq!(schedule.quality, ScheduleQuality::Optimal);
}

#[test]
fn enrichment_optimizer_wide_fan_order_respects_dependencies() {
    let nodes = make_wide_fan(4);
    let graph = InstructionCostGraph::new(nodes).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();
    // Source must come first, sink must come last
    assert_eq!(*schedule.order.first().unwrap(), 0);
    assert_eq!(*schedule.order.last().unwrap(), 5);
    // All fan nodes must appear between source and sink
    let fan_positions: Vec<_> = (1..=4)
        .map(|i| schedule.order.iter().position(|&x| x == i).unwrap())
        .collect();
    for &pos in &fan_positions {
        assert!(pos > 0 && pos < 5);
    }
}

#[test]
fn enrichment_optimizer_certificate_schema_version() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();
    let cert = schedule.certificate.as_ref().unwrap();
    assert_eq!(cert.schema, TROPICAL_SCHEMA_VERSION);
}

#[test]
fn enrichment_optimizer_certificate_hashes_populated() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();
    let cert = schedule.certificate.as_ref().unwrap();
    assert!(!cert.input_graph_hash.as_bytes().is_empty());
    assert!(!cert.apsp_hash.as_bytes().is_empty());
}

// =========================================================================
// F. OptimalityCertificate — verification edges
// =========================================================================

#[test]
fn enrichment_certificate_verify_exact_boundary() {
    let cert = OptimalityCertificate {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        achieved_cost: TropicalWeight::finite(100),
        critical_path_lower_bound: TropicalWeight::finite(100),
        optimality_ratio_millionths: 1_000_000,
        input_graph_hash: ContentHash::compute(b"x"),
        apsp_hash: ContentHash::compute(b"y"),
        is_exact: true,
    };
    assert!(cert.verify(1_000_000)); // exact match
    assert!(!cert.verify(999_999)); // below
}

#[test]
fn enrichment_certificate_suboptimal_verify() {
    let cert = OptimalityCertificate {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        achieved_cost: TropicalWeight::finite(110),
        critical_path_lower_bound: TropicalWeight::finite(100),
        optimality_ratio_millionths: 1_100_000,
        input_graph_hash: ContentHash::compute(b"x"),
        apsp_hash: ContentHash::compute(b"y"),
        is_exact: false,
    };
    assert!(cert.verify(1_200_000));
    assert!(cert.verify(1_100_000));
    assert!(!cert.verify(1_099_999));
}

// =========================================================================
// G. DeadCodeEliminator — edge cases
// =========================================================================

#[test]
fn enrichment_dce_all_dead_except_output() {
    // 3 isolated nodes, only node 0 is output
    let nodes = vec![
        InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(1),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "out".into(),
        },
        InstructionNode {
            index: 1,
            cost: TropicalWeight::finite(1),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "dead_a".into(),
        },
        InstructionNode {
            index: 2,
            cost: TropicalWeight::finite(1),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "dead_b".into(),
        },
    ];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    let dce = DeadCodeEliminator {
        output_nodes: vec![0],
    };
    let report = dce.find_dead_code(&apsp, 3);
    assert_eq!(report.dead_indices.len(), 2);
    assert!(report.dead_indices.contains(&1));
    assert!(report.dead_indices.contains(&2));
    assert_eq!(report.live_indices, vec![0]);
}

#[test]
fn enrichment_dce_empty_output_nodes_all_dead() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    let dce = DeadCodeEliminator {
        output_nodes: vec![],
    };
    let report = dce.find_dead_code(&apsp, 3);
    // No output nodes → everything is dead
    assert_eq!(report.dead_indices.len(), 3);
    assert_eq!(report.elimination_ratio_millionths, 1_000_000);
}

#[test]
fn enrichment_dce_all_outputs_no_dead() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    let dce = DeadCodeEliminator {
        output_nodes: vec![0, 1, 2],
    };
    let report = dce.find_dead_code(&apsp, 3);
    assert!(report.dead_indices.is_empty());
    assert_eq!(report.live_indices.len(), 3);
}

#[test]
fn enrichment_dce_report_serde_with_zeros() {
    let report = DeadCodeReport {
        dead_indices: vec![],
        live_indices: vec![0],
        total_nodes: 1,
        elimination_ratio_millionths: 0,
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: DeadCodeReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// H. RegisterPressureAnalyzer — boundary conditions
// =========================================================================

#[test]
fn enrichment_rpa_pressure_at_exact_limit() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(1),
        predecessors: vec![],
        successors: vec![],
        register_pressure: 8,
        mnemonic: "exact".into(),
    }];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    let rpa = RegisterPressureAnalyzer { pressure_limit: 8 };
    let report = rpa.analyze(&graph);
    assert!(!report.exceeds_limit);
    assert_eq!(report.estimated_spills, 0);
}

#[test]
fn enrichment_rpa_pressure_one_over_limit() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(1),
        predecessors: vec![],
        successors: vec![],
        register_pressure: 9,
        mnemonic: "over".into(),
    }];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    let rpa = RegisterPressureAnalyzer { pressure_limit: 8 };
    let report = rpa.analyze(&graph);
    assert!(report.exceeds_limit);
    assert_eq!(report.estimated_spills, 1);
}

#[test]
fn enrichment_rpa_zero_pressure() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(1),
        predecessors: vec![],
        successors: vec![],
        register_pressure: 0,
        mnemonic: "zero_p".into(),
    }];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    let rpa = RegisterPressureAnalyzer { pressure_limit: 8 };
    let report = rpa.analyze(&graph);
    assert_eq!(report.peak_pressure, 0);
    assert_eq!(report.total_pressure, 0);
    assert!(!report.exceeds_limit);
}

#[test]
fn enrichment_rpa_report_serde_roundtrip() {
    let report = RegisterPressureReport {
        peak_pressure: 16,
        total_pressure: 128,
        pressure_limit: 32,
        exceeds_limit: false,
        estimated_spills: 0,
        node_count: 10,
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: RegisterPressureReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// I. ScheduleQuality — Debug, serde, ordering
// =========================================================================

#[test]
fn enrichment_schedule_quality_debug_distinct() {
    let variants = [
        format!("{:?}", ScheduleQuality::Optimal),
        format!("{:?}", ScheduleQuality::BoundedSuboptimal),
        format!("{:?}", ScheduleQuality::Heuristic),
    ];
    let set: BTreeSet<_> = variants.iter().collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_schedule_quality_copy() {
    let q = ScheduleQuality::Optimal;
    let q2 = q;
    assert_eq!(q, q2);
}

// =========================================================================
// J. TropicalPassWitness — populated witness roundtrip
// =========================================================================

#[test]
fn enrichment_pass_witness_fully_populated_roundtrip() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let cpr = graph.critical_path_length().unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();

    let dce = DeadCodeEliminator {
        output_nodes: vec![3],
    };
    let dead_report = dce.find_dead_code(&apsp, 4);
    let rpa = RegisterPressureAnalyzer { pressure_limit: 16 };
    let rp_report = rpa.analyze(&graph);

    let witness = TropicalPassWitness {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        ir_level: IrLevel::Ir3,
        input_hash: apsp.content_hash(),
        output_hash: ContentHash::compute(b"out"),
        critical_path: cpr,
        dead_code: Some(dead_report),
        register_pressure: Some(rp_report),
        certificate: schedule.certificate,
    };
    let json = serde_json::to_string(&witness).unwrap();
    let restored: TropicalPassWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, restored);
}

#[test]
fn enrichment_pass_witness_none_optional_fields() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let cpr = graph.critical_path_length().unwrap();
    let witness = TropicalPassWitness {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        ir_level: IrLevel::Ir1,
        input_hash: ContentHash::compute(b"in"),
        output_hash: ContentHash::compute(b"out"),
        critical_path: cpr,
        dead_code: None,
        register_pressure: None,
        certificate: None,
    };
    let json = serde_json::to_string(&witness).unwrap();
    let restored: TropicalPassWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, restored);
}

// =========================================================================
// K. CriticalPathResult — serde and hash stability
// =========================================================================

#[test]
fn enrichment_critical_path_result_hash_deterministic() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let cpr1 = graph.critical_path_length().unwrap();
    let cpr2 = graph.critical_path_length().unwrap();
    assert_eq!(cpr1.apsp_hash, cpr2.apsp_hash);
}

#[test]
fn enrichment_critical_path_result_clone() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let cpr = graph.critical_path_length().unwrap();
    let cloned = cpr.clone();
    assert_eq!(cpr, cloned);
}

// =========================================================================
// L. Schedule — serde completeness
// =========================================================================

#[test]
fn enrichment_schedule_diamond_has_certificate() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();
    assert!(schedule.certificate.is_some());
    let cert = schedule.certificate.unwrap();
    assert!(!cert.schema.is_empty());
    assert!(cert.achieved_cost.is_finite());
    assert!(cert.critical_path_lower_bound.is_finite());
}

#[test]
fn enrichment_schedule_clone_independence() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();
    let cloned = schedule.clone();
    assert_eq!(schedule, cloned);
}

// =========================================================================
// M. Constants — schema version and sentinel values
// =========================================================================

#[test]
fn enrichment_schema_version_non_empty_and_versioned() {
    assert!(!TROPICAL_SCHEMA_VERSION.is_empty());
    assert!(TROPICAL_SCHEMA_VERSION.contains("v1"));
}

#[test]
fn enrichment_infinity_is_i64_max() {
    assert_eq!(TROPICAL_INFINITY, i64::MAX);
}

#[test]
fn enrichment_zero_is_zero() {
    assert_eq!(TROPICAL_ZERO, 0);
}

// =========================================================================
// N. Debug formatting — all major types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", TropicalWeight::ZERO).is_empty());
    assert!(!format!("{:?}", TropicalWeight::INFINITY).is_empty());
    assert!(!format!("{:?}", TropicalError::EmptyGraph).is_empty());
    assert!(!format!("{:?}", ScheduleQuality::Optimal).is_empty());
    assert!(!format!("{:?}", ScheduleOptimizer::default()).is_empty());

    let m = TropicalMatrix::new_infinity(1).unwrap();
    assert!(!format!("{:?}", m).is_empty());

    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    assert!(!format!("{:?}", graph).is_empty());
}
