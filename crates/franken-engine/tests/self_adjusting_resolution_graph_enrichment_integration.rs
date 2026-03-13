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
    MILLIONTHS, ModuleNode, POLICY_ID, ResolutionGraphError, RollbackCheckpoint, SCHEMA_VERSION,
    add_module, build_graph, compute_affected_set, create_checkpoint, detect_cycles,
    invalidate_module, remove_module,
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
