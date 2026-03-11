#![forbid(unsafe_code)]

//! Integration tests for the `react_module_graph_verifier` module.

use std::collections::BTreeSet;

use frankenengine_engine::react_module_graph_verifier::*;
use frankenengine_engine::react_package_cohort::{ExportCondition, ModuleFormat, ReactPackage};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn mk_node(
    id: &str,
    pkg: ReactPackage,
    sub: &str,
    cond: ExportCondition,
    fmt: ModuleFormat,
    role: ModuleRole,
    surface: RenderSurface,
) -> ModuleGraphNode {
    build_module_node(id, pkg, sub, cond, fmt, role, surface)
}

fn mk_esm_node(id: &str, role: ModuleRole, surface: RenderSurface) -> ModuleGraphNode {
    mk_node(
        id,
        ReactPackage::React,
        ".",
        ExportCondition::Import,
        ModuleFormat::Esm,
        role,
        surface,
    )
}

/// Build a valid two-node graph for the given surface.
fn valid_graph(surface: RenderSurface) -> ModuleGraph {
    let nodes = vec![
        mk_esm_node("entry", ModuleRole::EntryPoint, surface),
        mk_esm_node("rt", ModuleRole::RuntimeProvider, surface),
    ];
    let edges = vec![build_module_edge("entry", "rt", "imports")];
    build_module_graph("valid-g", surface, nodes, edges, epoch(1))
}

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constant() {
    assert_eq!(
        REACT_MODULE_GRAPH_SCHEMA_VERSION,
        "franken-engine.react-module-graph-verifier.v1"
    );
}

#[test]
fn bead_id_constant() {
    assert_eq!(REACT_MODULE_GRAPH_BEAD_ID, "bd-1lsy.5.7.2");
}

#[test]
fn policy_id_constant() {
    assert_eq!(REACT_MODULE_GRAPH_POLICY_ID, "RGC-405B");
}

#[test]
fn component_constant() {
    assert_eq!(COMPONENT, "react_module_graph_verifier");
}

// ---------------------------------------------------------------------------
// RenderSurface enum
// ---------------------------------------------------------------------------

#[test]
fn render_surface_all_surfaces_count() {
    assert_eq!(ALL_SURFACES.len(), 5);
}

#[test]
fn render_surface_as_str_exhaustive() {
    let expected = [
        (RenderSurface::ServerSideRender, "server_side_render"),
        (RenderSurface::ClientEntry, "client_entry"),
        (RenderSurface::HydrationBridge, "hydration_bridge"),
        (RenderSurface::StaticGeneration, "static_generation"),
        (RenderSurface::StreamingSSR, "streaming_ssr"),
    ];
    for (variant, s) in &expected {
        assert_eq!(variant.as_str(), *s);
        assert_eq!(variant.to_string(), *s);
    }
}

#[test]
fn render_surface_serde_roundtrip_all() {
    for surface in ALL_SURFACES {
        let json = serde_json::to_string(surface).unwrap();
        let back: RenderSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(*surface, back);
    }
}

#[test]
fn render_surface_ordering() {
    assert!(RenderSurface::ServerSideRender < RenderSurface::ClientEntry);
    assert!(RenderSurface::ClientEntry < RenderSurface::HydrationBridge);
}

// ---------------------------------------------------------------------------
// ModuleRole enum
// ---------------------------------------------------------------------------

#[test]
fn module_role_as_str_exhaustive() {
    let expected = [
        (ModuleRole::EntryPoint, "entry_point"),
        (ModuleRole::RuntimeProvider, "runtime_provider"),
        (ModuleRole::RendererBinding, "renderer_binding"),
        (ModuleRole::SchedulerHook, "scheduler_hook"),
        (ModuleRole::InternalShared, "internal_shared"),
        (ModuleRole::UnsupportedSurface, "unsupported_surface"),
    ];
    for (variant, s) in &expected {
        assert_eq!(variant.as_str(), *s);
        assert_eq!(variant.to_string(), *s);
    }
}

#[test]
fn module_role_serde_roundtrip() {
    let roles = [
        ModuleRole::EntryPoint,
        ModuleRole::RuntimeProvider,
        ModuleRole::RendererBinding,
        ModuleRole::SchedulerHook,
        ModuleRole::InternalShared,
        ModuleRole::UnsupportedSurface,
    ];
    for role in &roles {
        let json = serde_json::to_string(role).unwrap();
        let back: ModuleRole = serde_json::from_str(&json).unwrap();
        assert_eq!(*role, back);
    }
}

// ---------------------------------------------------------------------------
// GraphNodeId
// ---------------------------------------------------------------------------

#[test]
fn graph_node_id_new_and_as_str() {
    let id = GraphNodeId::new("test-node-42");
    assert_eq!(id.as_str(), "test-node-42");
}

#[test]
fn graph_node_id_display() {
    let id = GraphNodeId::new("display-me");
    assert_eq!(id.to_string(), "display-me");
}

#[test]
fn graph_node_id_equality_same() {
    assert_eq!(GraphNodeId::new("x"), GraphNodeId::new("x"));
}

#[test]
fn graph_node_id_inequality() {
    assert_ne!(GraphNodeId::new("x"), GraphNodeId::new("y"));
}

#[test]
fn graph_node_id_ordering() {
    assert!(GraphNodeId::new("aaa") < GraphNodeId::new("bbb"));
}

#[test]
fn graph_node_id_serde_roundtrip() {
    let id = GraphNodeId::new("serde-test");
    let json = serde_json::to_string(&id).unwrap();
    let back: GraphNodeId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

// ---------------------------------------------------------------------------
// ModuleGraphNode
// ---------------------------------------------------------------------------

#[test]
fn module_graph_node_fields() {
    let node = mk_node(
        "n1",
        ReactPackage::ReactDom,
        "./client",
        ExportCondition::Browser,
        ModuleFormat::Esm,
        ModuleRole::RendererBinding,
        RenderSurface::ClientEntry,
    );
    assert_eq!(node.node_id.as_str(), "n1");
    assert_eq!(node.package, ReactPackage::ReactDom);
    assert_eq!(node.subpath, "./client");
    assert_eq!(node.condition, ExportCondition::Browser);
    assert_eq!(node.format, ModuleFormat::Esm);
    assert_eq!(node.role, ModuleRole::RendererBinding);
    assert_eq!(node.surface, RenderSurface::ClientEntry);
}

#[test]
fn module_graph_node_content_hash_deterministic() {
    let a = mk_esm_node("det", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    let b = mk_esm_node("det", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_node_content_hash_differs_by_id() {
    let a = mk_esm_node("a", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    let b = mk_esm_node("b", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_node_content_hash_differs_by_role() {
    let a = mk_esm_node("x", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    let b = mk_esm_node("x", ModuleRole::RuntimeProvider, RenderSurface::ClientEntry);
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_node_content_hash_differs_by_surface() {
    let a = mk_esm_node("x", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    let b = mk_esm_node("x", ModuleRole::EntryPoint, RenderSurface::ServerSideRender);
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_node_content_hash_differs_by_format() {
    let a = mk_node(
        "x",
        ReactPackage::React,
        ".",
        ExportCondition::Import,
        ModuleFormat::Esm,
        ModuleRole::EntryPoint,
        RenderSurface::ClientEntry,
    );
    let b = mk_node(
        "x",
        ReactPackage::React,
        ".",
        ExportCondition::Require,
        ModuleFormat::Cjs,
        ModuleRole::EntryPoint,
        RenderSurface::ClientEntry,
    );
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_node_display_contains_key_info() {
    let node = mk_node(
        "my-node",
        ReactPackage::ReactDom,
        ".",
        ExportCondition::Browser,
        ModuleFormat::Esm,
        ModuleRole::RendererBinding,
        RenderSurface::ClientEntry,
    );
    let s = node.to_string();
    assert!(s.contains("my-node"));
    assert!(s.contains("renderer_binding"));
    assert!(s.contains("client_entry"));
}

#[test]
fn module_graph_node_serde_roundtrip() {
    let node = mk_esm_node(
        "serde-n",
        ModuleRole::EntryPoint,
        RenderSurface::StreamingSSR,
    );
    let json = serde_json::to_string(&node).unwrap();
    let back: ModuleGraphNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}

// ---------------------------------------------------------------------------
// ModuleGraphEdge
// ---------------------------------------------------------------------------

#[test]
fn module_graph_edge_fields() {
    let edge = build_module_edge("src", "dst", "re-exports");
    assert_eq!(edge.from_node.as_str(), "src");
    assert_eq!(edge.to_node.as_str(), "dst");
    assert_eq!(edge.edge_kind, "re-exports");
}

#[test]
fn module_graph_edge_hash_deterministic() {
    let a = build_module_edge("a", "b", "imports");
    let b = build_module_edge("a", "b", "imports");
    assert_eq!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_edge_hash_differs_by_kind() {
    let a = build_module_edge("a", "b", "imports");
    let b = build_module_edge("a", "b", "side-effect");
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_edge_hash_differs_by_direction() {
    let a = build_module_edge("a", "b", "imports");
    let b = build_module_edge("b", "a", "imports");
    assert_ne!(a.content_hash, b.content_hash);
}

#[test]
fn module_graph_edge_display_contains_all_parts() {
    let edge = build_module_edge("from", "to", "side-effect");
    let s = edge.to_string();
    assert!(s.contains("from"));
    assert!(s.contains("to"));
    assert!(s.contains("side-effect"));
}

#[test]
fn module_graph_edge_serde_roundtrip() {
    let edge = build_module_edge("x", "y", "imports");
    let json = serde_json::to_string(&edge).unwrap();
    let back: ModuleGraphEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, back);
}

// ---------------------------------------------------------------------------
// ModuleGraph
// ---------------------------------------------------------------------------

#[test]
fn module_graph_building_basic() {
    let nodes = vec![mk_esm_node(
        "e",
        ModuleRole::EntryPoint,
        RenderSurface::ClientEntry,
    )];
    let graph = build_module_graph(
        "test-g",
        RenderSurface::ClientEntry,
        nodes,
        vec![],
        epoch(1),
    );
    assert_eq!(graph.graph_id, "test-g");
    assert_eq!(graph.surface, RenderSurface::ClientEntry);
    assert_eq!(graph.node_count(), 1);
    assert_eq!(graph.edge_count(), 0);
    assert_eq!(graph.epoch, epoch(1));
}

#[test]
fn module_graph_hash_deterministic() {
    let mk = || {
        let nodes = vec![mk_esm_node(
            "e",
            ModuleRole::EntryPoint,
            RenderSurface::ClientEntry,
        )];
        build_module_graph("det-g", RenderSurface::ClientEntry, nodes, vec![], epoch(5))
    };
    assert_eq!(mk().content_hash, mk().content_hash);
}

#[test]
fn module_graph_hash_changes_with_epoch() {
    let nodes = || {
        vec![mk_esm_node(
            "e",
            ModuleRole::EntryPoint,
            RenderSurface::ClientEntry,
        )]
    };
    let g1 = build_module_graph("g", RenderSurface::ClientEntry, nodes(), vec![], epoch(1));
    let g2 = build_module_graph("g", RenderSurface::ClientEntry, nodes(), vec![], epoch(2));
    assert_ne!(g1.content_hash, g2.content_hash);
}

#[test]
fn module_graph_display_format() {
    let graph = build_module_graph(
        "display-g",
        RenderSurface::StreamingSSR,
        vec![],
        vec![],
        epoch(1),
    );
    let s = graph.to_string();
    assert!(s.contains("display-g"));
    assert!(s.contains("streaming_ssr"));
    assert!(s.contains("0 nodes"));
    assert!(s.contains("0 edges"));
}

#[test]
fn module_graph_serde_roundtrip() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let json = serde_json::to_string(&graph).unwrap();
    let back: ModuleGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, back);
}

// ---------------------------------------------------------------------------
// GraphVerificationVerdict enum
// ---------------------------------------------------------------------------

#[test]
fn verdict_as_str_exhaustive() {
    let expected = [
        (GraphVerificationVerdict::Valid, "valid"),
        (GraphVerificationVerdict::MissingSurface, "missing_surface"),
        (
            GraphVerificationVerdict::CyclicDependency,
            "cyclic_dependency",
        ),
        (GraphVerificationVerdict::FormatMismatch, "format_mismatch"),
        (
            GraphVerificationVerdict::UnsupportedSurface,
            "unsupported_surface",
        ),
        (GraphVerificationVerdict::OrphanNode, "orphan_node"),
    ];
    for (variant, s) in &expected {
        assert_eq!(variant.as_str(), *s);
        assert_eq!(variant.to_string(), *s);
    }
}

#[test]
fn verdict_serde_roundtrip_all() {
    let verdicts = [
        GraphVerificationVerdict::Valid,
        GraphVerificationVerdict::MissingSurface,
        GraphVerificationVerdict::CyclicDependency,
        GraphVerificationVerdict::FormatMismatch,
        GraphVerificationVerdict::UnsupportedSurface,
        GraphVerificationVerdict::OrphanNode,
    ];
    for v in &verdicts {
        let json = serde_json::to_string(v).unwrap();
        let back: GraphVerificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ---------------------------------------------------------------------------
// detect_cycles
// ---------------------------------------------------------------------------

#[test]
fn detect_cycles_no_cycle_linear() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
        mk_esm_node("c", ModuleRole::SchedulerHook, s),
    ];
    let edges = vec![
        build_module_edge("a", "b", "imports"),
        build_module_edge("b", "c", "imports"),
    ];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert!(detect_cycles(&graph).is_empty());
}

#[test]
fn detect_cycles_simple_two_node() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
    ];
    let edges = vec![
        build_module_edge("a", "b", "imports"),
        build_module_edge("b", "a", "imports"),
    ];
    let graph = build_module_graph("cyc-g", s, nodes, edges, epoch(1));
    let cycles = detect_cycles(&graph);
    assert!(!cycles.is_empty());
}

#[test]
fn detect_cycles_three_node_triangle() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
        mk_esm_node("c", ModuleRole::SchedulerHook, s),
    ];
    let edges = vec![
        build_module_edge("a", "b", "imports"),
        build_module_edge("b", "c", "imports"),
        build_module_edge("c", "a", "imports"),
    ];
    let graph = build_module_graph("tri-g", s, nodes, edges, epoch(1));
    assert!(!detect_cycles(&graph).is_empty());
}

#[test]
fn detect_cycles_self_loop() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![mk_esm_node("a", ModuleRole::EntryPoint, s)];
    let edges = vec![build_module_edge("a", "a", "imports")];
    let graph = build_module_graph("self-g", s, nodes, edges, epoch(1));
    assert!(!detect_cycles(&graph).is_empty());
}

#[test]
fn detect_cycles_empty_graph() {
    let graph = build_module_graph(
        "empty-g",
        RenderSurface::ClientEntry,
        vec![],
        vec![],
        epoch(1),
    );
    assert!(detect_cycles(&graph).is_empty());
}

// ---------------------------------------------------------------------------
// detect_orphans
// ---------------------------------------------------------------------------

#[test]
fn detect_orphans_no_orphans() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert!(detect_orphans(&graph).is_empty());
}

#[test]
fn detect_orphans_single_orphan() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
        mk_esm_node("orphan", ModuleRole::InternalShared, s),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    let orphans = detect_orphans(&graph);
    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans[0].as_str(), "orphan");
}

#[test]
fn detect_orphans_multiple_orphans() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
        mk_esm_node("orphan1", ModuleRole::InternalShared, s),
        mk_esm_node("orphan2", ModuleRole::SchedulerHook, s),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    let orphans = detect_orphans(&graph);
    assert_eq!(orphans.len(), 2);
}

#[test]
fn detect_orphans_all_orphans_no_edges() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
    ];
    let graph = build_module_graph("g", s, nodes, vec![], epoch(1));
    assert_eq!(detect_orphans(&graph).len(), 2);
}

// ---------------------------------------------------------------------------
// detect_format_mismatches
// ---------------------------------------------------------------------------

#[test]
fn format_mismatch_esm_to_esm_ok() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert!(detect_format_mismatches(&graph).is_empty());
}

#[test]
fn format_mismatch_cjs_importing_esm() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_node(
            "a",
            ReactPackage::React,
            ".",
            ExportCondition::Require,
            ModuleFormat::Cjs,
            ModuleRole::EntryPoint,
            s,
        ),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    let mismatches = detect_format_mismatches(&graph);
    assert_eq!(mismatches.len(), 1);
    assert_eq!(mismatches[0].0.as_str(), "a");
    assert_eq!(mismatches[0].1.as_str(), "b");
}

#[test]
fn format_mismatch_esm_importing_cjs_ok() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_node(
            "b",
            ReactPackage::React,
            ".",
            ExportCondition::Require,
            ModuleFormat::Cjs,
            ModuleRole::RuntimeProvider,
            s,
        ),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert!(detect_format_mismatches(&graph).is_empty());
}

#[test]
fn format_mismatch_cjs_to_cjs_ok() {
    let s = RenderSurface::ClientEntry;
    let cjs = |id: &str, role| {
        mk_node(
            id,
            ReactPackage::React,
            ".",
            ExportCondition::Require,
            ModuleFormat::Cjs,
            role,
            s,
        )
    };
    let nodes = vec![
        cjs("a", ModuleRole::EntryPoint),
        cjs("b", ModuleRole::RuntimeProvider),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert!(detect_format_mismatches(&graph).is_empty());
}

// ---------------------------------------------------------------------------
// verify_module_graph
// ---------------------------------------------------------------------------

#[test]
fn verify_valid_graph() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
    assert!(receipt.diagnostics.is_empty());
    assert_eq!(receipt.node_count, 2);
    assert_eq!(receipt.edge_count, 1);
}

#[test]
fn verify_detects_unsupported_surface_first() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![mk_esm_node("bad", ModuleRole::UnsupportedSurface, s)];
    let graph = build_module_graph("g", s, nodes, vec![], epoch(1));
    let receipt = verify_module_graph(&graph);
    assert_eq!(
        receipt.verdict,
        GraphVerificationVerdict::UnsupportedSurface
    );
    assert!(!receipt.diagnostics.is_empty());
}

#[test]
fn verify_detects_cycle() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("a", ModuleRole::EntryPoint, s),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
    ];
    let edges = vec![
        build_module_edge("a", "b", "imports"),
        build_module_edge("b", "a", "imports"),
    ];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert_eq!(
        verify_module_graph(&graph).verdict,
        GraphVerificationVerdict::CyclicDependency
    );
}

#[test]
fn verify_detects_format_mismatch() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_node(
            "a",
            ReactPackage::React,
            ".",
            ExportCondition::Require,
            ModuleFormat::Cjs,
            ModuleRole::EntryPoint,
            s,
        ),
        mk_esm_node("b", ModuleRole::RuntimeProvider, s),
    ];
    let edges = vec![build_module_edge("a", "b", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert_eq!(
        verify_module_graph(&graph).verdict,
        GraphVerificationVerdict::FormatMismatch
    );
}

#[test]
fn verify_detects_orphan() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("entry", ModuleRole::EntryPoint, s),
        mk_esm_node("rt", ModuleRole::RuntimeProvider, s),
        mk_esm_node("orphan", ModuleRole::SchedulerHook, s),
    ];
    let edges = vec![build_module_edge("entry", "rt", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert_eq!(
        verify_module_graph(&graph).verdict,
        GraphVerificationVerdict::OrphanNode
    );
}

#[test]
fn verify_detects_missing_entry_point() {
    let s = RenderSurface::ClientEntry;
    let nodes = vec![
        mk_esm_node("rt", ModuleRole::RuntimeProvider, s),
        mk_esm_node("sched", ModuleRole::SchedulerHook, s),
    ];
    let edges = vec![build_module_edge("rt", "sched", "imports")];
    let graph = build_module_graph("g", s, nodes, edges, epoch(1));
    assert_eq!(
        verify_module_graph(&graph).verdict,
        GraphVerificationVerdict::MissingSurface
    );
}

#[test]
fn verify_receipt_id_format() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    assert!(receipt.receipt_id.starts_with("receipt-"));
    assert!(receipt.receipt_id.contains("client_entry"));
}

#[test]
fn verify_receipt_content_hash_deterministic() {
    let g1 = valid_graph(RenderSurface::ClientEntry);
    let g2 = valid_graph(RenderSurface::ClientEntry);
    assert_eq!(
        verify_module_graph(&g1).content_hash,
        verify_module_graph(&g2).content_hash
    );
}

#[test]
fn verify_receipt_serde_roundtrip() {
    let graph = valid_graph(RenderSurface::ServerSideRender);
    let receipt = verify_module_graph(&graph);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GraphVerificationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn verify_receipt_display() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    let s = receipt.to_string();
    assert!(s.contains("Receipt("));
    assert!(s.contains("client_entry"));
    assert!(s.contains("valid"));
}

// ---------------------------------------------------------------------------
// Canonical builders: SSR + client
// ---------------------------------------------------------------------------

#[test]
fn build_ssr_graph_structure() {
    let graph = build_ssr_graph(epoch(1));
    assert_eq!(graph.surface, RenderSurface::ServerSideRender);
    assert_eq!(graph.node_count(), 4);
    assert_eq!(graph.edge_count(), 4);
}

#[test]
fn build_ssr_graph_valid() {
    let receipt = verify_module_graph(&build_ssr_graph(epoch(1)));
    assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
}

#[test]
fn build_client_entry_graph_structure() {
    let graph = build_client_entry_graph(epoch(1));
    assert_eq!(graph.surface, RenderSurface::ClientEntry);
    assert_eq!(graph.node_count(), 4);
    assert_eq!(graph.edge_count(), 4);
}

#[test]
fn build_client_entry_graph_valid() {
    let receipt = verify_module_graph(&build_client_entry_graph(epoch(1)));
    assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
}

#[test]
fn ssr_graph_content_hash_deterministic() {
    assert_eq!(
        build_ssr_graph(epoch(3)).content_hash,
        build_ssr_graph(epoch(3)).content_hash
    );
}

#[test]
fn client_graph_content_hash_deterministic() {
    assert_eq!(
        build_client_entry_graph(epoch(3)).content_hash,
        build_client_entry_graph(epoch(3)).content_hash
    );
}

#[test]
fn ssr_and_client_graphs_different_hashes() {
    assert_ne!(
        build_ssr_graph(epoch(1)).content_hash,
        build_client_entry_graph(epoch(1)).content_hash
    );
}

// ---------------------------------------------------------------------------
// surface_coverage_millionths
// ---------------------------------------------------------------------------

#[test]
fn coverage_all_surfaces() {
    assert_eq!(surface_coverage_millionths(ALL_SURFACES), 1_000_000);
}

#[test]
fn coverage_no_surfaces() {
    assert_eq!(surface_coverage_millionths(&[]), 0);
}

#[test]
fn coverage_one_surface() {
    assert_eq!(
        surface_coverage_millionths(&[RenderSurface::ClientEntry]),
        200_000
    );
}

#[test]
fn coverage_two_surfaces() {
    assert_eq!(
        surface_coverage_millionths(
            &[RenderSurface::ServerSideRender, RenderSurface::ClientEntry,]
        ),
        400_000
    );
}

#[test]
fn coverage_deduplicates() {
    let repeated = vec![
        RenderSurface::ClientEntry,
        RenderSurface::ClientEntry,
        RenderSurface::ClientEntry,
    ];
    assert_eq!(surface_coverage_millionths(&repeated), 200_000);
}

// ---------------------------------------------------------------------------
// build_coverage_report
// ---------------------------------------------------------------------------

#[test]
fn coverage_report_two_receipts() {
    let ssr_receipt = verify_module_graph(&build_ssr_graph(epoch(1)));
    let client_receipt = verify_module_graph(&build_client_entry_graph(epoch(1)));
    let report = build_coverage_report("rpt", epoch(1), vec![ssr_receipt, client_receipt]);
    assert_eq!(report.receipts.len(), 2);
    assert_eq!(report.surfaces_covered.len(), 2);
    assert_eq!(report.coverage_millionths, 400_000);
    assert!(report.total_nodes > 0);
    assert!(report.total_edges > 0);
}

#[test]
fn coverage_report_empty() {
    let report = build_coverage_report("empty", epoch(0), vec![]);
    assert_eq!(report.receipts.len(), 0);
    assert_eq!(report.surfaces_covered.len(), 0);
    assert_eq!(report.coverage_millionths, 0);
    assert_eq!(report.total_nodes, 0);
    assert_eq!(report.total_edges, 0);
}

#[test]
fn coverage_report_content_hash_deterministic() {
    let mk = || {
        let r1 = verify_module_graph(&build_ssr_graph(epoch(1)));
        let r2 = verify_module_graph(&build_client_entry_graph(epoch(1)));
        build_coverage_report("rpt", epoch(1), vec![r1, r2])
    };
    assert_eq!(mk().content_hash, mk().content_hash);
}

#[test]
fn coverage_report_display_format() {
    let report = build_coverage_report("disp-rpt", epoch(1), vec![]);
    let s = report.to_string();
    assert!(s.contains("SurfaceCoverageReport"));
    assert!(s.contains("disp-rpt"));
}

#[test]
fn coverage_report_serde_roundtrip() {
    let ssr_receipt = verify_module_graph(&build_ssr_graph(epoch(1)));
    let report = build_coverage_report("serde-rpt", epoch(1), vec![ssr_receipt]);
    let json = serde_json::to_string(&report).unwrap();
    let back: SurfaceCoverageReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Canonical manifest
// ---------------------------------------------------------------------------

#[test]
fn canonical_manifest_structure() {
    let report = franken_engine_react_module_graph_manifest();
    assert_eq!(report.report_id, "canonical-react-module-graph-manifest");
    assert_eq!(report.epoch, epoch(1));
    assert_eq!(report.receipts.len(), 2);
    assert_eq!(report.surfaces_covered.len(), 2);
}

#[test]
fn canonical_manifest_all_valid() {
    let report = franken_engine_react_module_graph_manifest();
    for receipt in &report.receipts {
        assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
    }
}

#[test]
fn canonical_manifest_deterministic() {
    assert_eq!(
        franken_engine_react_module_graph_manifest().content_hash,
        franken_engine_react_module_graph_manifest().content_hash
    );
}

#[test]
fn canonical_manifest_has_both_surfaces() {
    let report = franken_engine_react_module_graph_manifest();
    let surfaces: BTreeSet<RenderSurface> = report.surfaces_covered.iter().copied().collect();
    assert!(surfaces.contains(&RenderSurface::ServerSideRender));
    assert!(surfaces.contains(&RenderSurface::ClientEntry));
}

// ---------------------------------------------------------------------------
// End-to-end workflow
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_graph_build_verify_and_report() {
    let e = epoch(42);
    let surface = RenderSurface::HydrationBridge;

    let entry = mk_esm_node("hb-entry", ModuleRole::EntryPoint, surface);
    let rt = mk_esm_node("hb-rt", ModuleRole::RuntimeProvider, surface);
    let sched = mk_esm_node("hb-sched", ModuleRole::SchedulerHook, surface);

    let nodes = vec![entry, rt, sched];
    let edges = vec![
        build_module_edge("hb-entry", "hb-rt", "imports"),
        build_module_edge("hb-rt", "hb-sched", "imports"),
    ];

    let graph = build_module_graph("hb-graph", surface, nodes, edges, e);
    assert_eq!(graph.node_count(), 3);
    assert_eq!(graph.edge_count(), 2);

    let receipt = verify_module_graph(&graph);
    assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
    assert!(receipt.diagnostics.is_empty());

    let report = build_coverage_report("hb-rpt", e, vec![receipt.clone()]);
    assert_eq!(report.receipts.len(), 1);
    assert_eq!(report.surfaces_covered.len(), 1);
    assert_eq!(report.surfaces_covered[0], RenderSurface::HydrationBridge);
    assert_eq!(report.coverage_millionths, 200_000);
    assert_eq!(report.total_nodes, receipt.node_count);
    assert_eq!(report.total_edges, receipt.edge_count);
}

#[test]
fn end_to_end_all_five_surfaces_full_coverage() {
    let e = epoch(99);
    let mut receipts = Vec::new();

    for surface in ALL_SURFACES {
        let entry = mk_esm_node("entry", ModuleRole::EntryPoint, *surface);
        let rt = mk_esm_node("rt", ModuleRole::RuntimeProvider, *surface);
        let nodes = vec![entry, rt];
        let edges = vec![build_module_edge("entry", "rt", "imports")];
        let graph = build_module_graph(
            &format!("g-{}", surface.as_str()),
            *surface,
            nodes,
            edges,
            e,
        );
        receipts.push(verify_module_graph(&graph));
    }

    let report = build_coverage_report("full-cov", e, receipts);
    assert_eq!(report.surfaces_covered.len(), 5);
    assert_eq!(report.coverage_millionths, 1_000_000);
}
