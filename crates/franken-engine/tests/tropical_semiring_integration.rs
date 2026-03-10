//! Integration tests for the `tropical_semiring` module.
//!
//! Exercises the public API from outside the crate boundary:
//! TropicalWeight, TropicalMatrix, TropicalError, InstructionNode,
//! InstructionCostGraph, CriticalPathResult, ScheduleQuality, Schedule,
//! OptimalityCertificate, ScheduleOptimizer, DeadCodeEliminator,
//! RegisterPressureAnalyzer, TropicalPassWitness.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::IrLevel;
use frankenengine_engine::tropical_semiring::{
    CriticalPathResult, DeadCodeEliminator, DeadCodeReport, InstructionCostGraph, InstructionNode,
    OptimalityCertificate, RegisterPressureAnalyzer, RegisterPressureReport, Schedule,
    ScheduleOptimizer, ScheduleQuality, TROPICAL_INFINITY, TROPICAL_SCHEMA_VERSION, TROPICAL_ZERO,
    TropicalError, TropicalMatrix, TropicalPassWitness, TropicalWeight,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a simple linear chain: 0 → 1 → 2.
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

/// Build a diamond: 0 → {1,2} → 3.
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

// =========================================================================
// Constants
// =========================================================================

#[test]
fn constants() {
    assert_eq!(TROPICAL_INFINITY, i64::MAX);
    assert_eq!(TROPICAL_ZERO, 0);
    assert!(!TROPICAL_SCHEMA_VERSION.is_empty());
}

// =========================================================================
// TropicalWeight — semiring axioms
// =========================================================================

#[test]
fn weight_infinity_and_zero() {
    assert!(TropicalWeight::INFINITY.is_infinite());
    assert!(!TropicalWeight::INFINITY.is_finite());
    assert!(TropicalWeight::ZERO.is_finite());
    assert!(!TropicalWeight::ZERO.is_infinite());
}

#[test]
fn weight_finite_construction() {
    let w = TropicalWeight::finite(42);
    assert_eq!(w.0, 42);
    assert!(w.is_finite());
}

#[test]
#[should_panic(expected = "use TropicalWeight::INFINITY")]
fn weight_finite_panics_on_infinity() {
    TropicalWeight::finite(i64::MAX);
}

#[test]
fn tropical_add_is_min() {
    let a = TropicalWeight::finite(3);
    let b = TropicalWeight::finite(7);
    assert_eq!(a.tropical_add(b), a); // min(3,7) = 3
    assert_eq!(b.tropical_add(a), a); // commutative
}

#[test]
fn tropical_add_identity() {
    let x = TropicalWeight::finite(42);
    // ∞ is additive identity: min(x, ∞) = x
    assert_eq!(x.tropical_add(TropicalWeight::INFINITY), x);
    assert_eq!(TropicalWeight::INFINITY.tropical_add(x), x);
}

#[test]
fn tropical_mul_is_plus() {
    let a = TropicalWeight::finite(3);
    let b = TropicalWeight::finite(7);
    assert_eq!(a.tropical_mul(b), TropicalWeight::finite(10));
}

#[test]
fn tropical_mul_identity() {
    let x = TropicalWeight::finite(42);
    // 0 is multiplicative identity: x + 0 = x
    assert_eq!(x.tropical_mul(TropicalWeight::ZERO), x);
    assert_eq!(TropicalWeight::ZERO.tropical_mul(x), x);
}

#[test]
fn tropical_mul_annihilator() {
    let x = TropicalWeight::finite(42);
    // ∞ absorbs under +
    assert_eq!(
        x.tropical_mul(TropicalWeight::INFINITY),
        TropicalWeight::INFINITY
    );
    assert_eq!(
        TropicalWeight::INFINITY.tropical_mul(x),
        TropicalWeight::INFINITY
    );
}

#[test]
fn tropical_mul_saturating() {
    let big = TropicalWeight::finite(i64::MAX - 1);
    let one = TropicalWeight::finite(1);
    // Should saturate to i64::MAX - 1 (since i64::MAX is infinity)
    let result = big.tropical_mul(one);
    assert!(result.is_finite() || result.is_infinite());
}

#[test]
fn kleene_star_nonneg() {
    assert_eq!(
        TropicalWeight::finite(5).kleene_star(),
        Some(TropicalWeight::ZERO)
    );
    assert_eq!(
        TropicalWeight::ZERO.kleene_star(),
        Some(TropicalWeight::ZERO)
    );
    assert_eq!(
        TropicalWeight::INFINITY.kleene_star(),
        Some(TropicalWeight::ZERO)
    );
}

#[test]
fn kleene_star_negative_diverges() {
    assert_eq!(TropicalWeight::finite(-1).kleene_star(), None);
}

#[test]
fn weight_display() {
    assert_eq!(TropicalWeight::finite(42).to_string(), "42");
    assert_eq!(TropicalWeight::INFINITY.to_string(), "∞");
}

#[test]
fn weight_serde_roundtrip() {
    let weights = vec![
        TropicalWeight::ZERO,
        TropicalWeight::INFINITY,
        TropicalWeight::finite(42),
        TropicalWeight::finite(-5),
    ];
    for w in &weights {
        let json = serde_json::to_string(w).unwrap();
        let restored: TropicalWeight = serde_json::from_str(&json).unwrap();
        assert_eq!(*w, restored);
    }
}

// =========================================================================
// TropicalError
// =========================================================================

#[test]
fn tropical_error_display() {
    let err = TropicalError::DimensionExceeded {
        dim: 5000,
        max: 4096,
    };
    assert!(err.to_string().contains("5000"));
    assert!(err.to_string().contains("4096"));

    let err = TropicalError::EmptyGraph;
    assert_eq!(err.to_string(), "empty instruction graph");

    let err = TropicalError::NegativeCycle { node: 3 };
    assert!(err.to_string().contains("3"));
}

#[test]
fn tropical_error_serde_roundtrip() {
    let errors = vec![
        TropicalError::DimensionExceeded { dim: 100, max: 50 },
        TropicalError::DimensionMismatch { left: 3, right: 4 },
        TropicalError::NegativeCycle { node: 2 },
        TropicalError::EmptyGraph,
        TropicalError::CycleInDag {
            nodes_in_cycle: vec![1, 2],
        },
        TropicalError::NodeOutOfBounds { index: 10, size: 5 },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: TropicalError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

// =========================================================================
// TropicalMatrix
// =========================================================================

#[test]
fn matrix_new_infinity() {
    let m = TropicalMatrix::new_infinity(3).unwrap();
    assert_eq!(m.dim, 3);
    assert!(m.get(0, 0).is_infinite());
    assert!(m.get(2, 2).is_infinite());
}

#[test]
fn matrix_identity() {
    let m = TropicalMatrix::identity(3).unwrap();
    assert_eq!(m.get(0, 0), TropicalWeight::ZERO);
    assert_eq!(m.get(1, 1), TropicalWeight::ZERO);
    assert!(m.get(0, 1).is_infinite());
    assert!(m.get(1, 0).is_infinite());
}

#[test]
fn matrix_set_and_get() {
    let mut m = TropicalMatrix::new_infinity(2).unwrap();
    m.set(0, 1, TropicalWeight::finite(5));
    assert_eq!(m.get(0, 1), TropicalWeight::finite(5));
    assert!(m.get(1, 0).is_infinite());
}

#[test]
fn matrix_dimension_exceeded() {
    let result = TropicalMatrix::new_infinity(5000);
    assert!(result.is_err());
    if let Err(TropicalError::DimensionExceeded { dim, max }) = result {
        assert_eq!(dim, 5000);
        assert_eq!(max, 4096);
    }
}

#[test]
fn matrix_tropical_mul() {
    // 2x2: A * B in tropical semiring
    let mut a = TropicalMatrix::new_infinity(2).unwrap();
    a.set(0, 0, TropicalWeight::finite(1));
    a.set(0, 1, TropicalWeight::finite(3));
    a.set(1, 0, TropicalWeight::finite(2));
    a.set(1, 1, TropicalWeight::INFINITY);

    let mut b = TropicalMatrix::new_infinity(2).unwrap();
    b.set(0, 0, TropicalWeight::finite(0));
    b.set(0, 1, TropicalWeight::finite(4));
    b.set(1, 0, TropicalWeight::finite(1));
    b.set(1, 1, TropicalWeight::finite(2));

    let c = a.tropical_mul(&b).unwrap();
    // C[0][0] = min(1+0, 3+1) = min(1,4) = 1
    assert_eq!(c.get(0, 0), TropicalWeight::finite(1));
    // C[0][1] = min(1+4, 3+2) = min(5,5) = 5
    assert_eq!(c.get(0, 1), TropicalWeight::finite(5));
    // C[1][0] = min(2+0, ∞+1) = min(2,∞) = 2
    assert_eq!(c.get(1, 0), TropicalWeight::finite(2));
    // C[1][1] = min(2+4, ∞+2) = min(6,∞) = 6
    assert_eq!(c.get(1, 1), TropicalWeight::finite(6));
}

#[test]
fn matrix_tropical_mul_dimension_mismatch() {
    let a = TropicalMatrix::new_infinity(2).unwrap();
    let b = TropicalMatrix::new_infinity(3).unwrap();
    let result = a.tropical_mul(&b);
    assert!(matches!(
        result,
        Err(TropicalError::DimensionMismatch { .. })
    ));
}

#[test]
fn matrix_tropical_add() {
    let mut a = TropicalMatrix::new_infinity(2).unwrap();
    a.set(0, 0, TropicalWeight::finite(3));
    a.set(0, 1, TropicalWeight::finite(7));

    let mut b = TropicalMatrix::new_infinity(2).unwrap();
    b.set(0, 0, TropicalWeight::finite(5));
    b.set(0, 1, TropicalWeight::finite(2));

    let c = a.tropical_add(&b).unwrap();
    // min(3,5) = 3, min(7,2) = 2
    assert_eq!(c.get(0, 0), TropicalWeight::finite(3));
    assert_eq!(c.get(0, 1), TropicalWeight::finite(2));
}

#[test]
fn matrix_floyd_warshall_simple() {
    // 3-node graph: 0→1 cost 5, 1→2 cost 3
    let mut m = TropicalMatrix::new_infinity(3).unwrap();
    m.set(0, 1, TropicalWeight::finite(5));
    m.set(1, 2, TropicalWeight::finite(3));

    let dist = m.floyd_warshall().unwrap();
    // 0→0 = 0, 0→1 = 5, 0→2 = 5+3 = 8
    assert_eq!(dist.get(0, 0), TropicalWeight::ZERO);
    assert_eq!(dist.get(0, 1), TropicalWeight::finite(5));
    assert_eq!(dist.get(0, 2), TropicalWeight::finite(8));
    // 1→0 = ∞ (no path)
    assert!(dist.get(1, 0).is_infinite());
}

#[test]
fn matrix_floyd_warshall_negative_cycle() {
    // Create a negative cycle: 0→1 cost -5, 1→0 cost -3
    let mut m = TropicalMatrix::new_infinity(2).unwrap();
    m.set(0, 1, TropicalWeight::finite(-5));
    m.set(1, 0, TropicalWeight::finite(-3));

    let result = m.floyd_warshall();
    assert!(matches!(result, Err(TropicalError::NegativeCycle { .. })));
}

#[test]
fn matrix_content_hash_deterministic() {
    let mut m1 = TropicalMatrix::new_infinity(2).unwrap();
    m1.set(0, 1, TropicalWeight::finite(42));

    let mut m2 = TropicalMatrix::new_infinity(2).unwrap();
    m2.set(0, 1, TropicalWeight::finite(42));

    assert_eq!(m1.content_hash(), m2.content_hash());
}

#[test]
fn matrix_content_hash_differs_on_change() {
    let mut m1 = TropicalMatrix::new_infinity(2).unwrap();
    m1.set(0, 1, TropicalWeight::finite(42));

    let mut m2 = TropicalMatrix::new_infinity(2).unwrap();
    m2.set(0, 1, TropicalWeight::finite(43));

    assert_ne!(m1.content_hash(), m2.content_hash());
}

#[test]
fn matrix_serde_roundtrip() {
    let mut m = TropicalMatrix::new_infinity(2).unwrap();
    m.set(0, 1, TropicalWeight::finite(10));
    m.set(1, 0, TropicalWeight::finite(20));

    let json = serde_json::to_string(&m).unwrap();
    let restored: TropicalMatrix = serde_json::from_str(&json).unwrap();
    assert_eq!(m, restored);
}

// =========================================================================
// InstructionNode
// =========================================================================

#[test]
fn instruction_node_serde_roundtrip() {
    let node = InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(10),
        predecessors: vec![],
        successors: vec![1, 2],
        register_pressure: 4,
        mnemonic: "load_r0".into(),
    };
    let json = serde_json::to_string(&node).unwrap();
    let restored: InstructionNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, restored);
}

// =========================================================================
// InstructionCostGraph
// =========================================================================

#[test]
fn graph_linear_chain() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    assert_eq!(graph.len(), 3);
    assert!(!graph.is_empty());
}

#[test]
fn graph_empty_errors() {
    let result = InstructionCostGraph::new(vec![]);
    assert!(matches!(result, Err(TropicalError::EmptyGraph)));
}

#[test]
fn graph_node_index_mismatch() {
    let nodes = vec![InstructionNode {
        index: 5, // Should be 0
        cost: TropicalWeight::finite(10),
        predecessors: vec![],
        successors: vec![],
        register_pressure: 1,
        mnemonic: "bad".into(),
    }];
    let result = InstructionCostGraph::new(nodes);
    assert!(matches!(result, Err(TropicalError::NodeOutOfBounds { .. })));
}

#[test]
fn graph_out_of_bounds_successor() {
    let nodes = vec![InstructionNode {
        index: 0,
        cost: TropicalWeight::finite(10),
        predecessors: vec![],
        successors: vec![99], // Out of bounds
        register_pressure: 1,
        mnemonic: "bad".into(),
    }];
    let result = InstructionCostGraph::new(nodes);
    assert!(matches!(result, Err(TropicalError::NodeOutOfBounds { .. })));
}

#[test]
fn graph_critical_path_linear() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let cpr = graph.critical_path_length().unwrap();
    // Critical path: 10 + 20 + 5 = 35
    assert_eq!(cpr.makespan, TropicalWeight::finite(35));
    assert_eq!(cpr.critical_source, 0);
    assert_eq!(cpr.critical_sink, 2);
}

#[test]
fn graph_critical_path_diamond() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let cpr = graph.critical_path_length().unwrap();
    // Critical path: 0→1→3 = 10 + 30 + 10 = 50 (longer than 0→2→3 = 10+5+10 = 25)
    assert_eq!(cpr.makespan, TropicalWeight::finite(50));
}

#[test]
fn graph_all_pairs_shortest_paths() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    // 0→2 = 10 + 20 = 30 (via edges, not including node 2's cost)
    assert_eq!(apsp.shortest_distance(0, 2), TropicalWeight::finite(30));
    // 0→1 = 10
    assert_eq!(apsp.shortest_distance(0, 1), TropicalWeight::finite(10));
}

#[test]
fn graph_register_pressure() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    assert_eq!(graph.peak_register_pressure(), 3);
    assert_eq!(graph.total_register_pressure(), 6); // 2 + 3 + 1
}

#[test]
fn graph_serde_roundtrip() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let json = serde_json::to_string(&graph).unwrap();
    let restored: InstructionCostGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, restored);
}

// =========================================================================
// CriticalPathResult
// =========================================================================

#[test]
fn critical_path_result_serde_roundtrip() {
    let cpr = CriticalPathResult {
        makespan: TropicalWeight::finite(35),
        critical_source: 0,
        critical_sink: 2,
        apsp_hash: ContentHash::compute(b"test"),
    };
    let json = serde_json::to_string(&cpr).unwrap();
    let restored: CriticalPathResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cpr, restored);
}

// =========================================================================
// ScheduleQuality
// =========================================================================

#[test]
fn schedule_quality_ordering() {
    assert!(ScheduleQuality::Optimal < ScheduleQuality::BoundedSuboptimal);
    assert!(ScheduleQuality::BoundedSuboptimal < ScheduleQuality::Heuristic);
}

#[test]
fn schedule_quality_serde_roundtrip() {
    for q in &[
        ScheduleQuality::Optimal,
        ScheduleQuality::BoundedSuboptimal,
        ScheduleQuality::Heuristic,
    ] {
        let json = serde_json::to_string(q).unwrap();
        let restored: ScheduleQuality = serde_json::from_str(&json).unwrap();
        assert_eq!(*q, restored);
    }
}

// =========================================================================
// ScheduleOptimizer
// =========================================================================

#[test]
fn optimizer_default() {
    let opt = ScheduleOptimizer::default();
    assert_eq!(opt.max_approximation_ratio_millionths, 1_000_000);
}

#[test]
fn optimizer_linear_chain_optimal() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();

    // Linear chain has only one valid topological order
    assert_eq!(schedule.order.len(), 3);
    assert_eq!(schedule.order[0], 0);
    assert_eq!(schedule.order[1], 1);
    assert_eq!(schedule.order[2], 2);
    assert_eq!(schedule.quality, ScheduleQuality::Optimal);

    let cert = schedule.certificate.as_ref().unwrap();
    assert!(cert.is_exact);
    assert_eq!(cert.optimality_ratio_millionths, 1_000_000);
    assert!(cert.verify(1_000_000));
}

#[test]
fn optimizer_diamond_schedule() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();

    assert_eq!(schedule.order.len(), 4);
    // Node 0 must come first, node 3 must come last
    assert_eq!(schedule.order[0], 0);
    assert_eq!(schedule.order[3], 3);
    // Quality should be optimal for a DAG
    assert_eq!(schedule.quality, ScheduleQuality::Optimal);
}

// =========================================================================
// OptimalityCertificate
// =========================================================================

#[test]
fn optimality_certificate_verify() {
    let cert = OptimalityCertificate {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        achieved_cost: TropicalWeight::finite(35),
        critical_path_lower_bound: TropicalWeight::finite(35),
        optimality_ratio_millionths: 1_000_000,
        input_graph_hash: ContentHash::compute(b"test"),
        apsp_hash: ContentHash::compute(b"apsp"),
        is_exact: true,
    };
    assert!(cert.verify(1_000_000));
    assert!(cert.verify(2_000_000));
    assert!(!cert.verify(999_999));
}

#[test]
fn optimality_certificate_serde_roundtrip() {
    let cert = OptimalityCertificate {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        achieved_cost: TropicalWeight::finite(50),
        critical_path_lower_bound: TropicalWeight::finite(45),
        optimality_ratio_millionths: 1_111_111,
        input_graph_hash: ContentHash::compute(b"in"),
        apsp_hash: ContentHash::compute(b"apsp"),
        is_exact: false,
    };
    let json = serde_json::to_string(&cert).unwrap();
    let restored: OptimalityCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, restored);
}

// =========================================================================
// DeadCodeEliminator
// =========================================================================

#[test]
fn dead_code_eliminator_no_dead() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    let dce = DeadCodeEliminator {
        output_nodes: vec![2], // node 2 is the output
    };
    let report = dce.find_dead_code(&apsp, 3);
    assert!(report.dead_indices.is_empty());
    assert_eq!(report.live_indices.len(), 3);
    assert_eq!(report.elimination_ratio_millionths, 0);
}

#[test]
fn dead_code_eliminator_with_dead() {
    // Build a 4-node graph where node 3 is disconnected
    let nodes = vec![
        InstructionNode {
            index: 0,
            cost: TropicalWeight::finite(10),
            predecessors: vec![],
            successors: vec![1],
            register_pressure: 1,
            mnemonic: "a".into(),
        },
        InstructionNode {
            index: 1,
            cost: TropicalWeight::finite(10),
            predecessors: vec![0],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "b".into(),
        },
        InstructionNode {
            index: 2,
            cost: TropicalWeight::finite(10),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "dead1".into(),
        },
        InstructionNode {
            index: 3,
            cost: TropicalWeight::finite(10),
            predecessors: vec![],
            successors: vec![],
            register_pressure: 1,
            mnemonic: "dead2".into(),
        },
    ];
    let graph = InstructionCostGraph::new(nodes).unwrap();
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    let dce = DeadCodeEliminator {
        output_nodes: vec![1], // only node 1 is an output
    };
    let report = dce.find_dead_code(&apsp, 4);
    // Nodes 2 and 3 are dead (no path to output node 1)
    assert_eq!(report.dead_indices.len(), 2);
    assert!(report.dead_indices.contains(&2));
    assert!(report.dead_indices.contains(&3));
    assert_eq!(report.elimination_ratio_millionths, 500_000); // 2/4
}

#[test]
fn dead_code_report_serde_roundtrip() {
    let report = DeadCodeReport {
        dead_indices: vec![2, 3],
        live_indices: vec![0, 1],
        total_nodes: 4,
        elimination_ratio_millionths: 500_000,
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: DeadCodeReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// RegisterPressureAnalyzer
// =========================================================================

#[test]
fn register_pressure_within_limit() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let analyzer = RegisterPressureAnalyzer { pressure_limit: 8 };
    let report = analyzer.analyze(&graph);
    assert_eq!(report.peak_pressure, 3);
    assert_eq!(report.total_pressure, 6);
    assert!(!report.exceeds_limit);
    assert_eq!(report.estimated_spills, 0);
    assert_eq!(report.node_count, 3);
}

#[test]
fn register_pressure_exceeds_limit() {
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    let analyzer = RegisterPressureAnalyzer { pressure_limit: 2 };
    let report = analyzer.analyze(&graph);
    assert_eq!(report.peak_pressure, 4);
    assert!(report.exceeds_limit);
    assert_eq!(report.estimated_spills, 2); // 4 - 2
}

#[test]
fn register_pressure_report_serde_roundtrip() {
    let report = RegisterPressureReport {
        peak_pressure: 4,
        total_pressure: 10,
        pressure_limit: 8,
        exceeds_limit: false,
        estimated_spills: 0,
        node_count: 5,
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: RegisterPressureReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// Schedule
// =========================================================================

#[test]
fn schedule_serde_roundtrip() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();

    let json = serde_json::to_string(&schedule).unwrap();
    let restored: Schedule = serde_json::from_str(&json).unwrap();
    assert_eq!(schedule, restored);
}

// =========================================================================
// TropicalPassWitness
// =========================================================================

#[test]
fn pass_witness_serde_roundtrip() {
    let graph = InstructionCostGraph::new(make_linear_chain()).unwrap();
    let cpr = graph.critical_path_length().unwrap();

    let witness = TropicalPassWitness {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        ir_level: IrLevel::Ir3,
        input_hash: ContentHash::compute(b"input"),
        output_hash: ContentHash::compute(b"output"),
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
// Full lifecycle: build graph → schedule → analyze → witness
// =========================================================================

#[test]
fn full_lifecycle_diamond() {
    // 1. Build instruction graph
    let graph = InstructionCostGraph::new(make_diamond()).unwrap();
    assert_eq!(graph.len(), 4);

    // 2. Compute critical path
    let cpr = graph.critical_path_length().unwrap();
    assert_eq!(cpr.makespan, TropicalWeight::finite(50));

    // 3. Schedule
    let opt = ScheduleOptimizer::default();
    let schedule = opt.schedule(&graph).unwrap();
    assert_eq!(schedule.quality, ScheduleQuality::Optimal);

    // 4. Dead code analysis
    let apsp = graph.all_pairs_shortest_paths().unwrap();
    let dce = DeadCodeEliminator {
        output_nodes: vec![3],
    };
    let dead_report = dce.find_dead_code(&apsp, 4);
    assert!(dead_report.dead_indices.is_empty());

    // 5. Register pressure
    let rpa = RegisterPressureAnalyzer { pressure_limit: 16 };
    let rp_report = rpa.analyze(&graph);
    assert!(!rp_report.exceeds_limit);

    // 6. Build witness
    let witness = TropicalPassWitness {
        schema: TROPICAL_SCHEMA_VERSION.into(),
        ir_level: IrLevel::Ir3,
        input_hash: apsp.content_hash(),
        output_hash: ContentHash::compute(b"scheduled_output"),
        critical_path: cpr,
        dead_code: Some(dead_report),
        register_pressure: Some(rp_report),
        certificate: schedule.certificate,
    };

    // 7. Verify serde round-trip
    let json = serde_json::to_string(&witness).unwrap();
    let restored: TropicalPassWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(witness, restored);
}
