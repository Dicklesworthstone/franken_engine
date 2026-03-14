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
    clippy::identity_op
)]

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_adjusting_resolution_graph::{
    BEAD_ID, COMPONENT, DependencyEdge, EdgeKind, InvalidationReceipt, InvalidationScope,
    MILLIONTHS, ModuleNode, POLICY_ID, ResolutionGraph, ResolutionGraphError, RollbackCheckpoint,
    SCHEMA_VERSION, add_edge, add_module, build_graph, compute_affected_set, connected_component,
    create_checkpoint, detect_cycles, franken_engine_resolution_manifest, graph_depth,
    invalidate_module, remove_module, topological_order, verify_checkpoint,
};

fn make_node(id: &str) -> ModuleNode {
    ModuleNode {
        node_id: id.to_string(),
        specifier: format!("./{id}"),
        resolved_path: format!("/src/{id}.ts"),
        version: "1.0.0".to_string(),
        content_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn make_edge(source: &str, target: &str, kind: EdgeKind) -> DependencyEdge {
    DependencyEdge {
        source: source.to_string(),
        target: target.to_string(),
        kind,
        conditions: vec![],
    }
}

// =========================================================================
// A. BTreeSet ordering/dedup for EdgeKind (Ord + Hash)
// =========================================================================

#[test]
fn enrichment_edge_kind_btreeset_ordering_dedup() {
    let mut set = BTreeSet::new();
    set.insert(EdgeKind::StaticImport);
    set.insert(EdgeKind::DynamicImport);
    set.insert(EdgeKind::Reexport);
    set.insert(EdgeKind::TypeOnly);
    set.insert(EdgeKind::SideEffect);
    set.insert(EdgeKind::Conditional);
    set.insert(EdgeKind::StaticImport); // duplicate
    set.insert(EdgeKind::Conditional); // duplicate
    assert_eq!(set.len(), 6);
    let ordered: Vec<_> = set.into_iter().collect();
    for i in 1..ordered.len() {
        assert!(ordered[i - 1] < ordered[i]);
    }
}

// =========================================================================
// B. Hash consistency for EdgeKind
// =========================================================================

#[test]
fn enrichment_edge_kind_hash_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let hash_of = |k: &EdgeKind| {
        let mut h = DefaultHasher::new();
        k.hash(&mut h);
        h.finish()
    };
    assert_eq!(
        hash_of(&EdgeKind::StaticImport),
        hash_of(&EdgeKind::StaticImport)
    );
    assert_ne!(
        hash_of(&EdgeKind::StaticImport),
        hash_of(&EdgeKind::DynamicImport)
    );
}

// =========================================================================
// C. Display values distinct for EdgeKind and InvalidationScope
// =========================================================================

#[test]
fn enrichment_edge_kind_display_values_distinct() {
    let displays: BTreeSet<String> = [
        EdgeKind::StaticImport,
        EdgeKind::DynamicImport,
        EdgeKind::Reexport,
        EdgeKind::TypeOnly,
        EdgeKind::SideEffect,
        EdgeKind::Conditional,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_invalidation_scope_display_values_distinct() {
    let displays: BTreeSet<String> = [
        InvalidationScope::SingleModule,
        InvalidationScope::SubtreeFromModule,
        InvalidationScope::ConnectedComponent,
        InvalidationScope::FullGraph,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(displays.len(), 4);
}

// =========================================================================
// D. Debug nonempty for all types
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", EdgeKind::StaticImport).is_empty());
    assert!(!format!("{:?}", EdgeKind::DynamicImport).is_empty());
    assert!(!format!("{:?}", EdgeKind::Reexport).is_empty());
    assert!(!format!("{:?}", EdgeKind::TypeOnly).is_empty());
    assert!(!format!("{:?}", EdgeKind::SideEffect).is_empty());
    assert!(!format!("{:?}", EdgeKind::Conditional).is_empty());

    assert!(!format!("{:?}", InvalidationScope::SingleModule).is_empty());
    assert!(!format!("{:?}", InvalidationScope::SubtreeFromModule).is_empty());
    assert!(!format!("{:?}", InvalidationScope::ConnectedComponent).is_empty());
    assert!(!format!("{:?}", InvalidationScope::FullGraph).is_empty());

    assert!(!format!("{:?}", ResolutionGraphError::CycleDetected).is_empty());
    assert!(!format!("{:?}", ResolutionGraphError::ModuleNotFound("m".into())).is_empty());
    assert!(!format!("{:?}", ResolutionGraphError::DuplicateEdge).is_empty());
    assert!(!format!("{:?}", ResolutionGraphError::InvalidSpecifier).is_empty());
    assert!(!format!("{:?}", ResolutionGraphError::SnapshotCorrupted).is_empty());
    assert!(!format!("{:?}", ResolutionGraphError::InternalError("err".into())).is_empty());
}

#[test]
fn enrichment_debug_nonempty_structs() {
    let node = make_node("a");
    assert!(!format!("{node:?}").is_empty());
    let edge = make_edge("a", "b", EdgeKind::StaticImport);
    assert!(!format!("{edge:?}").is_empty());
}

// =========================================================================
// E. Clone independence
// =========================================================================

#[test]
fn enrichment_clone_independence_graph() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let mut cloned = graph.clone();
    cloned.graph_id = "modified".to_string();
    assert_ne!(graph.graph_id, "modified");
}

#[test]
fn enrichment_clone_independence_receipt() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let receipt = invalidate_module(&graph, "b").unwrap();
    let mut cloned = receipt.clone();
    cloned.trigger_module = "modified".to_string();
    assert_eq!(receipt.trigger_module, "b");
}

// =========================================================================
// F. Serde roundtrips for individual types
// =========================================================================

#[test]
fn enrichment_invalidation_receipt_serde_roundtrip() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let receipt = invalidate_module(&graph, "b").unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    let back: InvalidationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_rollback_checkpoint_serde_roundtrip() {
    let graph = build_graph(vec![make_node("a")], vec![], vec!["a".to_string()]).unwrap();
    let checkpoint = create_checkpoint(&graph);
    let json = serde_json::to_string(&checkpoint).unwrap();
    let back: RollbackCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(checkpoint, back);
}

#[test]
fn enrichment_resolution_graph_error_serde_roundtrip() {
    let errors = vec![
        ResolutionGraphError::CycleDetected,
        ResolutionGraphError::ModuleNotFound("mod-x".to_string()),
        ResolutionGraphError::DuplicateEdge,
        ResolutionGraphError::InvalidSpecifier,
        ResolutionGraphError::SnapshotCorrupted,
        ResolutionGraphError::InternalError("test error".to_string()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: ResolutionGraphError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn enrichment_invalidation_scope_serde_all_variants() {
    let scopes = vec![
        InvalidationScope::SingleModule,
        InvalidationScope::SubtreeFromModule,
        InvalidationScope::ConnectedComponent,
        InvalidationScope::FullGraph,
    ];
    for scope in &scopes {
        let json = serde_json::to_string(scope).unwrap();
        let back: InvalidationScope = serde_json::from_str(&json).unwrap();
        assert_eq!(*scope, back);
    }
}

// =========================================================================
// G. Error Display all variants
// =========================================================================

#[test]
fn enrichment_error_display_all_variants_distinct() {
    let displays: BTreeSet<String> = [
        ResolutionGraphError::CycleDetected,
        ResolutionGraphError::ModuleNotFound("x".into()),
        ResolutionGraphError::DuplicateEdge,
        ResolutionGraphError::InvalidSpecifier,
        ResolutionGraphError::SnapshotCorrupted,
        ResolutionGraphError::InternalError("msg".into()),
    ]
    .iter()
    .map(|e| e.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

// =========================================================================
// H. Graph with all edge kinds
// =========================================================================

#[test]
fn enrichment_build_graph_all_edge_kinds() {
    let nodes = vec![
        make_node("a"),
        make_node("b"),
        make_node("c"),
        make_node("d"),
        make_node("e"),
        make_node("f"),
        make_node("g"),
    ];
    let edges = vec![
        make_edge("a", "b", EdgeKind::StaticImport),
        make_edge("a", "c", EdgeKind::DynamicImport),
        make_edge("a", "d", EdgeKind::Reexport),
        make_edge("a", "e", EdgeKind::TypeOnly),
        make_edge("a", "f", EdgeKind::SideEffect),
        make_edge("a", "g", EdgeKind::Conditional),
    ];
    let graph = build_graph(nodes, edges, vec!["a".into()]).unwrap();
    assert_eq!(graph.edge_count(), 6);
    assert_eq!(graph.node_count(), 7);
}

// =========================================================================
// I. Dependency edge with conditions
// =========================================================================

#[test]
fn enrichment_edge_with_conditions_serde_roundtrip() {
    let edge = DependencyEdge {
        source: "a".to_string(),
        target: "b".to_string(),
        kind: EdgeKind::Conditional,
        conditions: vec![
            "import".to_string(),
            "node".to_string(),
            "default".to_string(),
        ],
    };
    let json = serde_json::to_string(&edge).unwrap();
    let back: DependencyEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, back);
    assert_eq!(back.conditions.len(), 3);
}

// =========================================================================
// J. Invalidation scope determination
// =========================================================================

#[test]
fn enrichment_invalidate_full_graph_scope() {
    // Chain: a -> b -> c (a imports b, b imports c).
    // Reverse propagation: invalidating c affects b then a (all 3).
    // Invalidating a has no reverse dependents → only itself.
    let graph = build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();

    // Root module (no reverse dependents): only itself affected → SingleModule
    let receipt_root = invalidate_module(&graph, "a").unwrap();
    assert_eq!(receipt_root.scope, InvalidationScope::SingleModule);
    assert_eq!(receipt_root.affected_modules.len(), 1);

    // Leaf module: reverse propagation through b then a → all 3 → FullGraph
    let receipt_leaf = invalidate_module(&graph, "c").unwrap();
    assert_eq!(receipt_leaf.scope, InvalidationScope::FullGraph);
    assert_eq!(receipt_leaf.affected_modules.len(), 3);
}

// =========================================================================
// K. Detect cycles in a diamond with a back-edge
// =========================================================================

#[test]
fn enrichment_detect_cycles_with_back_edge() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
            make_edge("c", "a", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();

    let cycles = detect_cycles(&graph);
    assert!(!cycles.is_empty());
    // At least one cycle should contain all three nodes
    let has_abc_cycle = cycles.iter().any(|c| {
        c.contains(&"a".to_string()) && c.contains(&"b".to_string()) && c.contains(&"c".to_string())
    });
    assert!(has_abc_cycle);
}

// =========================================================================
// L. Constants cross-check
// =========================================================================

#[test]
fn enrichment_constants_cross_check() {
    assert!(SCHEMA_VERSION.contains("self-adjusting-resolution-graph"));
    assert!(SCHEMA_VERSION.contains("v1"));
    assert_eq!(BEAD_ID, "bd-1lsy.5.8.2");
    assert_eq!(COMPONENT, "self_adjusting_resolution_graph");
    assert_eq!(POLICY_ID, "RGC-406B");
    assert_eq!(MILLIONTHS, 1_000_000);
}

// =========================================================================
// M. Receipt hash changes when trigger module differs
// =========================================================================

#[test]
fn enrichment_receipt_hash_sensitivity() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();

    let receipt_a = invalidate_module(&graph, "a").unwrap();
    let receipt_b = invalidate_module(&graph, "b").unwrap();
    assert_ne!(receipt_a.content_hash, receipt_b.content_hash);
    assert_ne!(receipt_a.receipt_id, receipt_b.receipt_id);
}

// =========================================================================
// N. Checkpoint hash changes with different graph states
// =========================================================================

#[test]
fn enrichment_checkpoint_hash_changes_after_mutation() {
    let mut graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();

    let ckpt1 = create_checkpoint(&graph);
    add_module(&mut graph, make_node("c")).unwrap();
    let ckpt2 = create_checkpoint(&graph);

    assert_ne!(ckpt1.graph_snapshot_hash, ckpt2.graph_snapshot_hash);
    assert_ne!(ckpt1.content_hash, ckpt2.content_hash);
}

// =========================================================================
// O. Remove module removes it from roots
// =========================================================================

#[test]
fn enrichment_remove_module_cleans_roots() {
    let mut graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string(), "b".to_string()],
    )
    .unwrap();

    let _receipt = remove_module(&mut graph, "b").unwrap();
    assert!(!graph.root_modules.contains(&"b".to_string()));
    assert!(graph.root_modules.contains(&"a".to_string()));
    assert_eq!(graph.node_count(), 1);
    assert_eq!(graph.edge_count(), 0);
}

// =========================================================================
// P. Compute affected set for isolated node
// =========================================================================

#[test]
fn enrichment_affected_set_isolated_node() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![], // no edges
        vec!["a".to_string()],
    )
    .unwrap();

    let affected = compute_affected_set(&graph, "a");
    assert_eq!(affected.len(), 1);
    assert!(affected.contains("a"));
}

// =========================================================================
// Q. Build graph with multiple roots
// =========================================================================

#[test]
fn enrichment_build_graph_multiple_roots() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "c", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string(), "b".to_string()],
    )
    .unwrap();

    assert_eq!(graph.root_modules.len(), 2);
    assert_eq!(graph.node_count(), 3);
}

// =========================================================================
// R. ModuleNode hash sensitivity to content_hash
// =========================================================================

#[test]
fn enrichment_module_node_hash_sensitivity_to_content() {
    let mut node1 = make_node("a");
    let mut node2 = make_node("a");
    node2.content_hash = ContentHash::compute(b"different content");

    // Same node_id, different content → different hash
    assert_ne!(node1.compute_hash(), node2.compute_hash());

    // Same content → same hash
    node1.content_hash = ContentHash::compute(b"same");
    node2.content_hash = ContentHash::compute(b"same");
    assert_eq!(node1.compute_hash(), node2.compute_hash());
}

// =========================================================================
// S. Graph epoch starts at GENESIS
// =========================================================================

#[test]
fn enrichment_graph_epoch_starts_at_genesis() {
    let graph = build_graph(vec![make_node("a")], vec![], vec!["a".to_string()]).unwrap();
    assert_eq!(graph.epoch, SecurityEpoch::GENESIS);
}

// ===== PearlTower enrichment =====

// =========================================================================
// T. Serde roundtrip for ResolutionGraph
// =========================================================================

#[test]
fn enrichment_resolution_graph_serde_roundtrip() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::TypeOnly),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let json = serde_json::to_string(&graph).unwrap();
    let back: ResolutionGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, back);
    assert_eq!(back.node_count(), 3);
    assert_eq!(back.edge_count(), 2);
}

// =========================================================================
// U. ModuleNode serde roundtrip
// =========================================================================

#[test]
fn enrichment_module_node_serde_roundtrip() {
    let node = make_node("serde-test-node");
    let json = serde_json::to_string(&node).unwrap();
    let back: ModuleNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
    assert_eq!(back.node_id, "serde-test-node");
    assert_eq!(back.version, "1.0.0");
}

// =========================================================================
// V. Graph node uniqueness — duplicate node_id is rejected
// =========================================================================

#[test]
fn enrichment_graph_node_uniqueness_rejects_duplicate_id() {
    let node_a1 = make_node("dup");
    let node_a2 = make_node("dup"); // same id
    let result = build_graph(vec![node_a1, node_a2], vec![], vec![]);
    assert!(
        matches!(result, Err(ResolutionGraphError::InternalError(_))),
        "expected InternalError for duplicate node_id"
    );
}

// =========================================================================
// W. Edge consistency — edges referencing absent nodes are rejected
// =========================================================================

#[test]
fn enrichment_edge_consistency_rejects_missing_source() {
    let result = build_graph(
        vec![make_node("b")],
        vec![make_edge("ghost", "b", EdgeKind::StaticImport)],
        vec!["b".to_string()],
    );
    assert!(
        matches!(result, Err(ResolutionGraphError::ModuleNotFound(_))),
        "expected ModuleNotFound for absent source"
    );
}

#[test]
fn enrichment_edge_consistency_rejects_missing_target() {
    let result = build_graph(
        vec![make_node("a")],
        vec![make_edge("a", "nowhere", EdgeKind::DynamicImport)],
        vec!["a".to_string()],
    );
    assert!(
        matches!(result, Err(ResolutionGraphError::ModuleNotFound(_))),
        "expected ModuleNotFound for absent target"
    );
}

// =========================================================================
// X. Empty graph — no nodes, no edges, no roots
// =========================================================================

#[test]
fn enrichment_empty_graph_build_succeeds() {
    let graph = build_graph(vec![], vec![], vec![]).unwrap();
    assert_eq!(graph.node_count(), 0);
    assert_eq!(graph.edge_count(), 0);
    assert!(graph.root_modules.is_empty());
    // detect_cycles on empty graph returns no cycles
    let cycles = detect_cycles(&graph);
    assert!(cycles.is_empty());
    // graph_depth on empty graph returns 0
    let depth = graph_depth(&graph).unwrap();
    assert_eq!(depth, 0);
}

// =========================================================================
// Y. Single-node graph properties
// =========================================================================

#[test]
fn enrichment_single_node_graph_properties() {
    let graph = build_graph(vec![make_node("solo")], vec![], vec!["solo".to_string()]).unwrap();
    assert_eq!(graph.node_count(), 1);
    assert_eq!(graph.edge_count(), 0);
    // No cycles in a single node with no edges
    assert!(detect_cycles(&graph).is_empty());
    // Depth is 0 — no edges
    assert_eq!(graph_depth(&graph).unwrap(), 0);
    // Topological order contains the sole node
    let order = topological_order(&graph).unwrap();
    assert_eq!(order, vec!["solo".to_string()]);
    // connected_component of the single node is just itself
    let comp = connected_component(&graph, "solo").unwrap();
    assert_eq!(comp.len(), 1);
    assert!(comp.contains("solo"));
    // invalidation: only itself affected
    let receipt = invalidate_module(&graph, "solo").unwrap();
    assert_eq!(receipt.scope, InvalidationScope::SingleModule);
    assert_eq!(receipt.affected_modules.len(), 1);
}

// =========================================================================
// Z. Deterministic ordering — identical inputs yield identical graph_id and hash
// =========================================================================

#[test]
fn enrichment_deterministic_ordering_identical_inputs() {
    let build = || {
        build_graph(
            vec![make_node("x"), make_node("y"), make_node("z")],
            vec![
                make_edge("x", "y", EdgeKind::StaticImport),
                make_edge("y", "z", EdgeKind::Reexport),
            ],
            vec!["x".to_string()],
        )
        .unwrap()
    };
    let g1 = build();
    let g2 = build();
    assert_eq!(g1.graph_id, g2.graph_id);
    assert_eq!(g1.content_hash, g2.content_hash);
}

// =========================================================================
// AA. Topological order for a linear chain
// =========================================================================

#[test]
fn enrichment_topological_order_linear_chain() {
    // a -> b -> c (a imports b, b imports c)
    let graph = build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let order = topological_order(&graph).unwrap();
    // "a" must come before "b", "b" before "c"
    let pos_a = order.iter().position(|s| s == "a").unwrap();
    let pos_b = order.iter().position(|s| s == "b").unwrap();
    let pos_c = order.iter().position(|s| s == "c").unwrap();
    assert!(pos_a < pos_b);
    assert!(pos_b < pos_c);
    assert_eq!(order.len(), 3);
}

// =========================================================================
// AB. Topological order fails on cycle
// =========================================================================

#[test]
fn enrichment_topological_order_fails_on_cycle() {
    let graph = build_graph(
        vec![make_node("p"), make_node("q")],
        vec![
            make_edge("p", "q", EdgeKind::StaticImport),
            make_edge("q", "p", EdgeKind::StaticImport),
        ],
        vec!["p".to_string()],
    )
    .unwrap();
    let result = topological_order(&graph);
    assert_eq!(result, Err(ResolutionGraphError::CycleDetected));
}

// =========================================================================
// AC. connected_component returns full set for connected graph
// =========================================================================

#[test]
fn enrichment_connected_component_full_graph() {
    // a <-> b <-> c (undirected connectivity)
    let graph = build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let comp = connected_component(&graph, "a").unwrap();
    assert_eq!(comp.len(), 3);
    assert!(comp.contains("a"));
    assert!(comp.contains("b"));
    assert!(comp.contains("c"));
}

#[test]
fn enrichment_connected_component_isolated_nodes() {
    // a and b are not connected
    let graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![],
        vec!["a".to_string(), "b".to_string()],
    )
    .unwrap();
    let comp_a = connected_component(&graph, "a").unwrap();
    assert_eq!(comp_a.len(), 1);
    assert!(comp_a.contains("a"));
    assert!(!comp_a.contains("b"));
}

#[test]
fn enrichment_connected_component_missing_node_errors() {
    let graph = build_graph(vec![make_node("a")], vec![], vec!["a".to_string()]).unwrap();
    let result = connected_component(&graph, "nonexistent");
    assert!(matches!(
        result,
        Err(ResolutionGraphError::ModuleNotFound(_))
    ));
}

// =========================================================================
// AD. verify_checkpoint — matches current graph state
// =========================================================================

#[test]
fn enrichment_verify_checkpoint_matches_current_state() {
    let graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::SideEffect)],
        vec!["a".to_string()],
    )
    .unwrap();
    let checkpoint = create_checkpoint(&graph);
    let matches = verify_checkpoint(&graph, &checkpoint).unwrap();
    assert!(matches, "fresh checkpoint must match current graph");
}

#[test]
fn enrichment_verify_checkpoint_detects_stale_after_mutation() {
    let mut graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let checkpoint = create_checkpoint(&graph);
    // Mutate the graph
    add_module(&mut graph, make_node("c")).unwrap();
    let matches = verify_checkpoint(&graph, &checkpoint).unwrap();
    assert!(!matches, "checkpoint must not match after mutation");
}

// =========================================================================
// AE. add_edge increases edge count and recomputes hash
// =========================================================================

#[test]
fn enrichment_add_edge_increases_count_and_changes_hash() {
    let mut graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![],
        vec!["a".to_string()],
    )
    .unwrap();
    let hash_before = graph.content_hash;
    add_edge(&mut graph, make_edge("a", "b", EdgeKind::DynamicImport)).unwrap();
    assert_eq!(graph.edge_count(), 1);
    assert_ne!(graph.content_hash, hash_before);
}

#[test]
fn enrichment_add_edge_rejects_duplicate() {
    let mut graph = build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let result = add_edge(&mut graph, make_edge("a", "b", EdgeKind::StaticImport));
    assert_eq!(result, Err(ResolutionGraphError::DuplicateEdge));
}

// =========================================================================
// AF. graph_depth for multi-level chain
// =========================================================================

#[test]
fn enrichment_graph_depth_multi_level_chain() {
    // a -> b -> c -> d: depth should be 3
    let graph = build_graph(
        vec![
            make_node("a"),
            make_node("b"),
            make_node("c"),
            make_node("d"),
        ],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
            make_edge("c", "d", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let depth = graph_depth(&graph).unwrap();
    assert_eq!(depth, 3);
}

// =========================================================================
// AG. franken_engine_resolution_manifest produces deterministic canonical graph
// =========================================================================

#[test]
fn enrichment_franken_engine_resolution_manifest_deterministic() {
    let m1 = franken_engine_resolution_manifest();
    let m2 = franken_engine_resolution_manifest();
    assert_eq!(m1.graph_id, m2.graph_id);
    assert_eq!(m1.content_hash, m2.content_hash);
    assert_eq!(m1.node_count(), m2.node_count());
    assert_eq!(m1.edge_count(), m2.edge_count());
    // Must have at least one root
    assert!(!m1.root_modules.is_empty());
}

#[test]
fn enrichment_franken_engine_resolution_manifest_serde_roundtrip() {
    let manifest = franken_engine_resolution_manifest();
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ResolutionGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// =========================================================================
// AH. Clone/Debug derive verification for ResolutionGraph and RollbackCheckpoint
// =========================================================================

#[test]
fn enrichment_clone_debug_resolution_graph() {
    let graph = build_graph(
        vec![make_node("x"), make_node("y")],
        vec![make_edge("x", "y", EdgeKind::Conditional)],
        vec!["x".to_string()],
    )
    .unwrap();
    let cloned = graph.clone();
    assert_eq!(graph, cloned);
    assert!(!format!("{graph:?}").is_empty());
}

#[test]
fn enrichment_clone_debug_rollback_checkpoint() {
    let graph = build_graph(
        vec![make_node("u"), make_node("v")],
        vec![make_edge("u", "v", EdgeKind::Reexport)],
        vec!["u".to_string()],
    )
    .unwrap();
    let checkpoint = create_checkpoint(&graph);
    let cloned = checkpoint.clone();
    assert_eq!(checkpoint, cloned);
    assert!(!format!("{checkpoint:?}").is_empty());
}

// =========================================================================
// AI. DependencyEdge compute_hash is order-sensitive for conditions
// =========================================================================

#[test]
fn enrichment_dependency_edge_hash_condition_order_sensitive() {
    let edge1 = DependencyEdge {
        source: "a".to_string(),
        target: "b".to_string(),
        kind: EdgeKind::Conditional,
        conditions: vec!["import".to_string(), "node".to_string()],
    };
    let edge2 = DependencyEdge {
        source: "a".to_string(),
        target: "b".to_string(),
        kind: EdgeKind::Conditional,
        conditions: vec!["node".to_string(), "import".to_string()],
    };
    // Different condition order → different hash
    assert_ne!(edge1.compute_hash(), edge2.compute_hash());
}

// =========================================================================
// AJ. InvalidationReceipt recomputed + skipped counts are consistent
// =========================================================================

#[test]
fn enrichment_invalidation_receipt_counts_consistent() {
    // Chain: a -> b -> c, invalidating "b" affects b (itself) + a (dependent)
    let graph = build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let receipt = invalidate_module(&graph, "b").unwrap();
    // recomputed_count == affected_modules.len()
    assert_eq!(
        receipt.recomputed_count,
        receipt.affected_modules.len() as u64
    );
    // recomputed + skipped == total node count
    assert_eq!(
        receipt.recomputed_count + receipt.skipped_count,
        graph.node_count() as u64,
    );
}
