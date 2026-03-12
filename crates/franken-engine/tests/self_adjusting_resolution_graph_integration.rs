//! Integration tests for the self-adjusting resolution graph (RGC-406B).

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
use frankenengine_engine::self_adjusting_resolution_graph::{
    self, BEAD_ID, COMPONENT, DependencyEdge, EdgeKind, InvalidationScope, MILLIONTHS, ModuleNode,
    POLICY_ID, ResolutionGraphError, SCHEMA_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_node(id: &str) -> ModuleNode {
    ModuleNode {
        node_id: id.to_string(),
        specifier: format!("./{id}"),
        resolved_path: format!("/src/{id}.js"),
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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn test_schema_version() {
    assert!(!SCHEMA_VERSION.is_empty());
    assert!(SCHEMA_VERSION.contains("resolution-graph"));
}

#[test]
fn test_bead_id() {
    assert!(BEAD_ID.starts_with("bd-"));
}

#[test]
fn test_component() {
    assert_eq!(COMPONENT, "self_adjusting_resolution_graph");
}

#[test]
fn test_policy_id() {
    assert_eq!(POLICY_ID, "RGC-406B");
}

#[test]
fn test_millionths() {
    assert_eq!(MILLIONTHS, 1_000_000);
}

// ---------------------------------------------------------------------------
// EdgeKind
// ---------------------------------------------------------------------------

#[test]
fn test_edge_kind_display() {
    assert_eq!(format!("{}", EdgeKind::StaticImport), "static-import");
    assert_eq!(format!("{}", EdgeKind::DynamicImport), "dynamic-import");
    assert_eq!(format!("{}", EdgeKind::Reexport), "reexport");
    assert_eq!(format!("{}", EdgeKind::TypeOnly), "type-only");
    assert_eq!(format!("{}", EdgeKind::SideEffect), "side-effect");
    assert_eq!(format!("{}", EdgeKind::Conditional), "conditional");
}

#[test]
fn test_edge_kind_serde_roundtrip() {
    let kind = EdgeKind::StaticImport;
    let json = serde_json::to_string(&kind).unwrap();
    let back: EdgeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, back);
}

// ---------------------------------------------------------------------------
// ModuleNode
// ---------------------------------------------------------------------------

#[test]
fn test_module_node_compute_hash_deterministic() {
    let a = make_node("app");
    let b = make_node("app");
    assert_eq!(a.compute_hash(), b.compute_hash());
}

#[test]
fn test_module_node_compute_hash_differs() {
    let a = make_node("app");
    let b = make_node("utils");
    assert_ne!(a.compute_hash(), b.compute_hash());
}

// ---------------------------------------------------------------------------
// DependencyEdge
// ---------------------------------------------------------------------------

#[test]
fn test_dependency_edge_compute_hash() {
    let e = make_edge("a", "b", EdgeKind::StaticImport);
    let h = e.compute_hash();
    assert_ne!(h, ContentHash::compute(b""));
}

#[test]
fn test_dependency_edge_hash_deterministic() {
    let e1 = make_edge("a", "b", EdgeKind::StaticImport);
    let e2 = make_edge("a", "b", EdgeKind::StaticImport);
    assert_eq!(e1.compute_hash(), e2.compute_hash());
}

// ---------------------------------------------------------------------------
// InvalidationScope
// ---------------------------------------------------------------------------

#[test]
fn test_invalidation_scope_display() {
    assert_eq!(
        format!("{}", InvalidationScope::SingleModule),
        "single-module"
    );
    assert_eq!(format!("{}", InvalidationScope::FullGraph), "full-graph");
}

// ---------------------------------------------------------------------------
// build_graph
// ---------------------------------------------------------------------------

#[test]
fn test_build_graph_empty() {
    let graph = self_adjusting_resolution_graph::build_graph(vec![], vec![], vec![]).unwrap();
    assert_eq!(graph.node_count(), 0);
    assert_eq!(graph.edge_count(), 0);
}

#[test]
fn test_build_graph_single_node() {
    let node = make_node("app");
    let graph =
        self_adjusting_resolution_graph::build_graph(vec![node], vec![], vec!["app".to_string()])
            .unwrap();
    assert_eq!(graph.node_count(), 1);
    assert!(graph.root_modules.contains(&"app".to_string()));
}

#[test]
fn test_build_graph_with_edges() {
    let nodes = vec![make_node("app"), make_node("utils")];
    let edges = vec![make_edge("app", "utils", EdgeKind::StaticImport)];
    let graph = self_adjusting_resolution_graph::build_graph(nodes, edges, vec!["app".to_string()])
        .unwrap();
    assert_eq!(graph.node_count(), 2);
    assert_eq!(graph.edge_count(), 1);
}

#[test]
fn test_build_graph_invalid_specifier() {
    let mut node = make_node("app");
    node.specifier = String::new();
    let result = self_adjusting_resolution_graph::build_graph(vec![node], vec![], vec![]);
    assert!(matches!(
        result,
        Err(ResolutionGraphError::InvalidSpecifier)
    ));
}

#[test]
fn test_build_graph_duplicate_edge() {
    let nodes = vec![make_node("a"), make_node("b")];
    let edges = vec![
        make_edge("a", "b", EdgeKind::StaticImport),
        make_edge("a", "b", EdgeKind::StaticImport),
    ];
    let result = self_adjusting_resolution_graph::build_graph(nodes, edges, vec![]);
    assert!(matches!(result, Err(ResolutionGraphError::DuplicateEdge)));
}

#[test]
fn test_build_graph_missing_edge_endpoint() {
    let nodes = vec![make_node("a")];
    let edges = vec![make_edge("a", "missing", EdgeKind::StaticImport)];
    let result = self_adjusting_resolution_graph::build_graph(nodes, edges, vec![]);
    assert!(matches!(
        result,
        Err(ResolutionGraphError::ModuleNotFound(_))
    ));
}

#[test]
fn test_build_graph_content_hash_deterministic() {
    let nodes = vec![make_node("a"), make_node("b")];
    let edges = vec![make_edge("a", "b", EdgeKind::StaticImport)];
    let g1 = self_adjusting_resolution_graph::build_graph(
        nodes.clone(),
        edges.clone(),
        vec!["a".to_string()],
    )
    .unwrap();
    let g2 =
        self_adjusting_resolution_graph::build_graph(nodes, edges, vec!["a".to_string()]).unwrap();
    assert_eq!(g1.content_hash, g2.content_hash);
}

// ---------------------------------------------------------------------------
// add_module / remove_module
// ---------------------------------------------------------------------------

#[test]
fn test_add_module() {
    let mut graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a")],
        vec![],
        vec!["a".to_string()],
    )
    .unwrap();
    self_adjusting_resolution_graph::add_module(&mut graph, make_node("b")).unwrap();
    assert_eq!(graph.node_count(), 2);
}

#[test]
fn test_remove_module() {
    let mut graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let receipt = self_adjusting_resolution_graph::remove_module(&mut graph, "b").unwrap();
    assert_eq!(graph.node_count(), 1);
    assert_eq!(graph.edge_count(), 0);
    assert!(!receipt.receipt_id.is_empty());
}

#[test]
fn test_remove_module_not_found() {
    let mut graph =
        self_adjusting_resolution_graph::build_graph(vec![make_node("a")], vec![], vec![]).unwrap();
    let result = self_adjusting_resolution_graph::remove_module(&mut graph, "missing");
    assert!(matches!(
        result,
        Err(ResolutionGraphError::ModuleNotFound(_))
    ));
}

// ---------------------------------------------------------------------------
// invalidate_module
// ---------------------------------------------------------------------------

#[test]
fn test_invalidate_module() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let receipt = self_adjusting_resolution_graph::invalidate_module(&graph, "a").unwrap();
    assert_eq!(receipt.trigger_module, "a");
    assert!(!receipt.affected_modules.is_empty());
}

// ---------------------------------------------------------------------------
// compute_affected_set
// ---------------------------------------------------------------------------

#[test]
fn test_compute_affected_set() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("b", "a", EdgeKind::StaticImport),
            make_edge("c", "b", EdgeKind::StaticImport),
        ],
        vec!["c".to_string()],
    )
    .unwrap();
    let affected = self_adjusting_resolution_graph::compute_affected_set(&graph, "a");
    // a -> b depends on a, c depends on b
    assert!(affected.contains("b"));
}

// ---------------------------------------------------------------------------
// create_checkpoint / verify_checkpoint
// ---------------------------------------------------------------------------

#[test]
fn test_create_and_verify_checkpoint() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a")],
        vec![],
        vec!["a".to_string()],
    )
    .unwrap();
    let checkpoint = self_adjusting_resolution_graph::create_checkpoint(&graph);
    assert!(!checkpoint.checkpoint_id.is_empty());
    let valid = self_adjusting_resolution_graph::verify_checkpoint(&graph, &checkpoint);
    assert!(valid.is_ok());
}

// ---------------------------------------------------------------------------
// detect_cycles
// ---------------------------------------------------------------------------

#[test]
fn test_detect_cycles_none() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec![],
    )
    .unwrap();
    let cycles = self_adjusting_resolution_graph::detect_cycles(&graph);
    assert!(cycles.is_empty());
}

// ---------------------------------------------------------------------------
// topological_order
// ---------------------------------------------------------------------------

#[test]
fn test_topological_order() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let order = self_adjusting_resolution_graph::topological_order(&graph).unwrap();
    assert_eq!(order.len(), 3);
}

// ---------------------------------------------------------------------------
// add_edge
// ---------------------------------------------------------------------------

#[test]
fn test_add_edge() {
    let mut graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b")],
        vec![],
        vec!["a".to_string()],
    )
    .unwrap();
    self_adjusting_resolution_graph::add_edge(
        &mut graph,
        make_edge("a", "b", EdgeKind::DynamicImport),
    )
    .unwrap();
    assert_eq!(graph.edge_count(), 1);
}

// ---------------------------------------------------------------------------
// connected_component
// ---------------------------------------------------------------------------

#[test]
fn test_connected_component() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec![],
    )
    .unwrap();
    let component = self_adjusting_resolution_graph::connected_component(&graph, "a").unwrap();
    assert!(component.contains("a"));
    assert!(component.contains("b"));
    assert!(!component.contains("c"));
}

// ---------------------------------------------------------------------------
// graph_depth
// ---------------------------------------------------------------------------

#[test]
fn test_graph_depth_linear() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let depth = self_adjusting_resolution_graph::graph_depth(&graph).unwrap();
    assert!(depth >= 2);
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

#[test]
fn test_manifest() {
    let manifest = self_adjusting_resolution_graph::franken_engine_resolution_manifest();
    assert!(!manifest.graph_id.is_empty());
    assert!(manifest.node_count() > 0);
}

#[test]
fn test_manifest_deterministic() {
    let a = self_adjusting_resolution_graph::franken_engine_resolution_manifest();
    let b = self_adjusting_resolution_graph::franken_engine_resolution_manifest();
    assert_eq!(a.graph_id, b.graph_id);
    assert_eq!(a.content_hash, b.content_hash);
}

// ---------------------------------------------------------------------------
// ResolutionGraphError Display
// ---------------------------------------------------------------------------

#[test]
fn test_error_display() {
    let e = ResolutionGraphError::CycleDetected;
    let s = format!("{e}");
    assert!(s.contains("cycle"));
}

#[test]
fn test_error_module_not_found() {
    let e = ResolutionGraphError::ModuleNotFound("foo".into());
    let s = format!("{e}");
    assert!(s.contains("foo"));
}

// ---------------------------------------------------------------------------
// Additional coverage — error Display variants
// ---------------------------------------------------------------------------

#[test]
fn test_error_display_duplicate_edge() {
    let e = ResolutionGraphError::DuplicateEdge;
    let s = format!("{e}");
    assert!(s.contains("duplicate"));
}

#[test]
fn test_error_display_invalid_specifier() {
    let e = ResolutionGraphError::InvalidSpecifier;
    let s = format!("{e}");
    assert!(s.contains("specifier"));
}

#[test]
fn test_error_display_snapshot_corrupted() {
    let e = ResolutionGraphError::SnapshotCorrupted;
    let s = format!("{e}");
    assert!(s.contains("snapshot") || s.contains("corrupt"));
}

#[test]
fn test_error_display_internal_error() {
    let e = ResolutionGraphError::InternalError("something broke".into());
    let s = format!("{e}");
    assert!(s.contains("something broke"));
}

// ---------------------------------------------------------------------------
// InvalidationScope Display — remaining variants
// ---------------------------------------------------------------------------

#[test]
fn test_invalidation_scope_display_subtree() {
    assert_eq!(
        format!("{}", InvalidationScope::SubtreeFromModule),
        "subtree"
    );
}

#[test]
fn test_invalidation_scope_display_connected_component() {
    assert_eq!(
        format!("{}", InvalidationScope::ConnectedComponent),
        "connected-component"
    );
}

// ---------------------------------------------------------------------------
// Serde roundtrips
// ---------------------------------------------------------------------------

#[test]
fn test_edge_kind_serde_all_variants() {
    let variants = [
        EdgeKind::StaticImport,
        EdgeKind::DynamicImport,
        EdgeKind::Reexport,
        EdgeKind::TypeOnly,
        EdgeKind::SideEffect,
        EdgeKind::Conditional,
    ];
    for kind in &variants {
        let json = serde_json::to_string(kind).unwrap();
        let back: EdgeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn test_module_node_serde_roundtrip() {
    let node = make_node("serde_test");
    let json = serde_json::to_string(&node).unwrap();
    let back: ModuleNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

#[test]
fn test_dependency_edge_serde_roundtrip() {
    let edge = DependencyEdge {
        source: "a".to_string(),
        target: "b".to_string(),
        kind: EdgeKind::Reexport,
        conditions: vec!["import".to_string(), "node".to_string()],
    };
    let json = serde_json::to_string(&edge).unwrap();
    let back: DependencyEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, back);
}

#[test]
fn test_resolution_graph_serde_roundtrip() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("x"), make_node("y")],
        vec![make_edge("x", "y", EdgeKind::StaticImport)],
        vec!["x".to_string()],
    )
    .unwrap();
    let json = serde_json::to_string(&graph).unwrap();
    let back: self_adjusting_resolution_graph::ResolutionGraph =
        serde_json::from_str(&json).unwrap();
    assert_eq!(graph.graph_id, back.graph_id);
    assert_eq!(graph.content_hash, back.content_hash);
    assert_eq!(graph.node_count(), back.node_count());
    assert_eq!(graph.edge_count(), back.edge_count());
}

#[test]
fn test_invalidation_scope_serde_roundtrip() {
    let scopes = [
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

// ---------------------------------------------------------------------------
// DependencyEdge — conditions affect hash
// ---------------------------------------------------------------------------

#[test]
fn test_dependency_edge_conditions_change_hash() {
    let e1 = make_edge("a", "b", EdgeKind::Conditional);
    let mut e2 = make_edge("a", "b", EdgeKind::Conditional);
    e2.conditions = vec!["import".to_string()];
    assert_ne!(e1.compute_hash(), e2.compute_hash());
}

// ---------------------------------------------------------------------------
// verify_checkpoint after mutation diverges
// ---------------------------------------------------------------------------

#[test]
fn test_verify_checkpoint_diverges_after_mutation() {
    let mut graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b")],
        vec![make_edge("a", "b", EdgeKind::StaticImport)],
        vec!["a".to_string()],
    )
    .unwrap();
    let checkpoint = self_adjusting_resolution_graph::create_checkpoint(&graph);

    // Mutate the graph by adding a new module.
    self_adjusting_resolution_graph::add_module(&mut graph, make_node("c")).unwrap();

    let result = self_adjusting_resolution_graph::verify_checkpoint(&graph, &checkpoint).unwrap();
    assert!(!result, "checkpoint should no longer match after mutation");
}

// ---------------------------------------------------------------------------
// add_module duplicate node error
// ---------------------------------------------------------------------------

#[test]
fn test_add_module_duplicate_error() {
    let mut graph =
        self_adjusting_resolution_graph::build_graph(vec![make_node("dup")], vec![], vec![])
            .unwrap();
    let result = self_adjusting_resolution_graph::add_module(&mut graph, make_node("dup"));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// connected_component — not found error
// ---------------------------------------------------------------------------

#[test]
fn test_connected_component_not_found() {
    let graph =
        self_adjusting_resolution_graph::build_graph(vec![make_node("a")], vec![], vec![]).unwrap();
    let result = self_adjusting_resolution_graph::connected_component(&graph, "missing");
    assert!(matches!(
        result,
        Err(ResolutionGraphError::ModuleNotFound(_))
    ));
}

// ---------------------------------------------------------------------------
// graph_depth — empty graph
// ---------------------------------------------------------------------------

#[test]
fn test_graph_depth_empty() {
    let graph = self_adjusting_resolution_graph::build_graph(vec![], vec![], vec![]).unwrap();
    let depth = self_adjusting_resolution_graph::graph_depth(&graph).unwrap();
    assert_eq!(depth, 0);
}

// ---------------------------------------------------------------------------
// build_graph — duplicate node_id
// ---------------------------------------------------------------------------

#[test]
fn test_build_graph_duplicate_node_id() {
    let result = self_adjusting_resolution_graph::build_graph(
        vec![make_node("dup"), make_node("dup")],
        vec![],
        vec![],
    );
    assert!(matches!(
        result,
        Err(ResolutionGraphError::InternalError(_))
    ));
}

// ---------------------------------------------------------------------------
// invalidate_module — leaf node yields SingleModule scope
// ---------------------------------------------------------------------------

#[test]
fn test_invalidate_leaf_module_single_scope() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("root"), make_node("leaf")],
        vec![make_edge("root", "leaf", EdgeKind::StaticImport)],
        vec!["root".to_string()],
    )
    .unwrap();
    // Invalidating "root" — nothing depends on root (it is the importer, not imported)
    let receipt = self_adjusting_resolution_graph::invalidate_module(&graph, "root").unwrap();
    assert_eq!(receipt.scope, InvalidationScope::SingleModule);
    assert_eq!(receipt.affected_modules.len(), 1);
    assert!(receipt.affected_modules.contains(&"root".to_string()));
}

// ---------------------------------------------------------------------------
// compute_affected_set — isolated node
// ---------------------------------------------------------------------------

#[test]
fn test_compute_affected_set_isolated() {
    let graph =
        self_adjusting_resolution_graph::build_graph(vec![make_node("alone")], vec![], vec![])
            .unwrap();
    let affected = self_adjusting_resolution_graph::compute_affected_set(&graph, "alone");
    assert_eq!(affected.len(), 1);
    assert!(affected.contains("alone"));
}

// ---------------------------------------------------------------------------
// recompute_hash — ResolutionGraph
// ---------------------------------------------------------------------------

#[test]
fn test_graph_recompute_hash_idempotent() {
    let mut graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("m1"), make_node("m2")],
        vec![make_edge("m1", "m2", EdgeKind::TypeOnly)],
        vec!["m1".to_string()],
    )
    .unwrap();
    let h1 = graph.content_hash;
    graph.recompute_hash();
    assert_eq!(h1, graph.content_hash, "recompute_hash must be idempotent");
}

// ---------------------------------------------------------------------------
// add_edge — missing source / missing target
// ---------------------------------------------------------------------------

#[test]
fn test_add_edge_missing_source() {
    let mut graph =
        self_adjusting_resolution_graph::build_graph(vec![make_node("b")], vec![], vec![]).unwrap();
    let result = self_adjusting_resolution_graph::add_edge(
        &mut graph,
        make_edge("missing", "b", EdgeKind::StaticImport),
    );
    assert!(matches!(
        result,
        Err(ResolutionGraphError::ModuleNotFound(_))
    ));
}

#[test]
fn test_add_edge_missing_target() {
    let mut graph =
        self_adjusting_resolution_graph::build_graph(vec![make_node("a")], vec![], vec![]).unwrap();
    let result = self_adjusting_resolution_graph::add_edge(
        &mut graph,
        make_edge("a", "missing", EdgeKind::StaticImport),
    );
    assert!(matches!(
        result,
        Err(ResolutionGraphError::ModuleNotFound(_))
    ));
}

// ---------------------------------------------------------------------------
// EdgeKind Clone / PartialEq
// ---------------------------------------------------------------------------

#[test]
fn test_edge_kind_clone_eq() {
    let a = EdgeKind::SideEffect;
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(EdgeKind::StaticImport, EdgeKind::DynamicImport);
}

// ---------------------------------------------------------------------------
// topological_order — deterministic across calls
// ---------------------------------------------------------------------------

#[test]
fn test_topological_order_deterministic() {
    let graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let order1 = self_adjusting_resolution_graph::topological_order(&graph).unwrap();
    let order2 = self_adjusting_resolution_graph::topological_order(&graph).unwrap();
    assert_eq!(order1, order2);
}

// ---------------------------------------------------------------------------
// invalidate_module — not found
// ---------------------------------------------------------------------------

#[test]
fn test_invalidate_module_not_found() {
    let graph =
        self_adjusting_resolution_graph::build_graph(vec![make_node("a")], vec![], vec![]).unwrap();
    let result = self_adjusting_resolution_graph::invalidate_module(&graph, "missing");
    assert!(matches!(
        result,
        Err(ResolutionGraphError::ModuleNotFound(_))
    ));
}

// ---------------------------------------------------------------------------
// remove_module — cascading edge removal + receipt fields
// ---------------------------------------------------------------------------

#[test]
fn test_remove_module_receipt_fields() {
    let mut graph = self_adjusting_resolution_graph::build_graph(
        vec![make_node("a"), make_node("b"), make_node("c")],
        vec![
            make_edge("a", "b", EdgeKind::StaticImport),
            make_edge("b", "c", EdgeKind::StaticImport),
        ],
        vec!["a".to_string()],
    )
    .unwrap();
    let old_hash = graph.content_hash;
    let receipt = self_adjusting_resolution_graph::remove_module(&mut graph, "c").unwrap();

    assert_eq!(receipt.trigger_module, "c");
    assert_eq!(receipt.old_hash, old_hash);
    assert_ne!(receipt.old_hash, receipt.new_hash);
    assert!(receipt.receipt_id.starts_with("rcpt-"));
    // c was a leaf — only b (which depended on c) and c itself affected
    assert!(receipt.affected_modules.contains(&"c".to_string()));
}

// ---------------------------------------------------------------------------
// build_graph — null byte in specifier
// ---------------------------------------------------------------------------

#[test]
fn test_build_graph_null_byte_specifier() {
    let mut node = make_node("bad");
    node.specifier = "has\0null".to_string();
    let result = self_adjusting_resolution_graph::build_graph(vec![node], vec![], vec![]);
    assert!(matches!(
        result,
        Err(ResolutionGraphError::InvalidSpecifier)
    ));
}
