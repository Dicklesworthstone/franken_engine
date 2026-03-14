#![forbid(unsafe_code)]

//! Enrichment integration tests for the `react_module_graph_verifier` module.

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

use frankenengine_engine::react_module_graph_verifier::{
    ALL_SURFACES, COMPONENT, GraphNodeId, GraphVerificationReceipt, GraphVerificationVerdict,
    ModuleGraph, ModuleGraphNode, ModuleRole, REACT_MODULE_GRAPH_BEAD_ID,
    REACT_MODULE_GRAPH_POLICY_ID, REACT_MODULE_GRAPH_SCHEMA_VERSION, RenderSurface,
    SurfaceCoverageReport, build_coverage_report, build_module_edge, build_module_graph,
    build_module_node, detect_cycles, detect_format_mismatches, detect_orphans,
    franken_engine_react_module_graph_manifest, surface_coverage_millionths, verify_module_graph,
};
use frankenengine_engine::react_package_cohort::{ExportCondition, ModuleFormat, ReactPackage};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn mk_esm_node(id: &str, role: ModuleRole, surface: RenderSurface) -> ModuleGraphNode {
    build_module_node(
        id,
        ReactPackage::React,
        ".",
        ExportCondition::Import,
        ModuleFormat::Esm,
        role,
        surface,
    )
}

fn valid_graph(surface: RenderSurface) -> ModuleGraph {
    let entry = mk_esm_node("entry", ModuleRole::EntryPoint, surface);
    let rt = mk_esm_node("rt", ModuleRole::RuntimeProvider, surface);
    let edges = vec![build_module_edge("entry", "rt", "imports")];
    build_module_graph("g", surface, vec![entry, rt], edges, epoch(1))
}

// ===========================================================================
// RenderSurface enrichment
// ===========================================================================

#[test]
fn enrichment_render_surface_copy_semantics() {
    let a = RenderSurface::ServerSideRender;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_render_surface_btreeset_dedup_5() {
    let set: BTreeSet<RenderSurface> = ALL_SURFACES.iter().copied().collect();
    assert_eq!(set.len(), 5);
}

#[test]
fn enrichment_render_surface_debug_all_unique() {
    let debugs: BTreeSet<String> = ALL_SURFACES.iter().map(|s| format!("{s:?}")).collect();
    assert_eq!(debugs.len(), 5);
}

#[test]
fn enrichment_render_surface_display_all_unique() {
    let displays: BTreeSet<String> = ALL_SURFACES.iter().map(|s| s.to_string()).collect();
    assert_eq!(displays.len(), 5);
}

#[test]
fn enrichment_render_surface_as_str_matches_display() {
    for &s in ALL_SURFACES {
        assert_eq!(s.as_str(), &s.to_string());
    }
}

// ===========================================================================
// ModuleRole enrichment
// ===========================================================================

#[test]
fn enrichment_module_role_copy_semantics() {
    let a = ModuleRole::EntryPoint;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_module_role_btreeset_dedup_6() {
    let roles = [
        ModuleRole::EntryPoint,
        ModuleRole::RuntimeProvider,
        ModuleRole::RendererBinding,
        ModuleRole::SchedulerHook,
        ModuleRole::InternalShared,
        ModuleRole::UnsupportedSurface,
    ];
    let set: BTreeSet<ModuleRole> = roles.into_iter().collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_module_role_debug_all_unique() {
    let roles = [
        ModuleRole::EntryPoint,
        ModuleRole::RuntimeProvider,
        ModuleRole::RendererBinding,
        ModuleRole::SchedulerHook,
        ModuleRole::InternalShared,
        ModuleRole::UnsupportedSurface,
    ];
    let debugs: BTreeSet<String> = roles.iter().map(|r| format!("{r:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_module_role_display_all_unique() {
    let roles = [
        ModuleRole::EntryPoint,
        ModuleRole::RuntimeProvider,
        ModuleRole::RendererBinding,
        ModuleRole::SchedulerHook,
        ModuleRole::InternalShared,
        ModuleRole::UnsupportedSurface,
    ];
    let displays: BTreeSet<String> = roles.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_module_role_as_str_matches_display() {
    for role in [
        ModuleRole::EntryPoint,
        ModuleRole::RuntimeProvider,
        ModuleRole::RendererBinding,
        ModuleRole::SchedulerHook,
        ModuleRole::InternalShared,
        ModuleRole::UnsupportedSurface,
    ] {
        assert_eq!(role.as_str(), &role.to_string());
    }
}

// ===========================================================================
// GraphVerificationVerdict enrichment
// ===========================================================================

#[test]
fn enrichment_verdict_copy_semantics() {
    let a = GraphVerificationVerdict::Valid;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_verdict_btreeset_dedup_6() {
    let set: BTreeSet<GraphVerificationVerdict> = [
        GraphVerificationVerdict::Valid,
        GraphVerificationVerdict::MissingSurface,
        GraphVerificationVerdict::CyclicDependency,
        GraphVerificationVerdict::FormatMismatch,
        GraphVerificationVerdict::UnsupportedSurface,
        GraphVerificationVerdict::OrphanNode,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_verdict_debug_all_unique() {
    let verdicts = [
        GraphVerificationVerdict::Valid,
        GraphVerificationVerdict::MissingSurface,
        GraphVerificationVerdict::CyclicDependency,
        GraphVerificationVerdict::FormatMismatch,
        GraphVerificationVerdict::UnsupportedSurface,
        GraphVerificationVerdict::OrphanNode,
    ];
    let debugs: BTreeSet<String> = verdicts.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(debugs.len(), 6);
}

#[test]
fn enrichment_verdict_display_all_unique() {
    let verdicts = [
        GraphVerificationVerdict::Valid,
        GraphVerificationVerdict::MissingSurface,
        GraphVerificationVerdict::CyclicDependency,
        GraphVerificationVerdict::FormatMismatch,
        GraphVerificationVerdict::UnsupportedSurface,
        GraphVerificationVerdict::OrphanNode,
    ];
    let displays: BTreeSet<String> = verdicts.iter().map(|v| v.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_verdict_as_str_matches_display() {
    for v in [
        GraphVerificationVerdict::Valid,
        GraphVerificationVerdict::MissingSurface,
        GraphVerificationVerdict::CyclicDependency,
        GraphVerificationVerdict::FormatMismatch,
        GraphVerificationVerdict::UnsupportedSurface,
        GraphVerificationVerdict::OrphanNode,
    ] {
        assert_eq!(v.as_str(), &v.to_string());
    }
}

// ===========================================================================
// GraphNodeId enrichment
// ===========================================================================

#[test]
fn enrichment_graph_node_id_clone_independence() {
    let id = GraphNodeId::new("original");
    let cloned = id.clone();
    assert_eq!(id, cloned);
    assert_eq!(id.as_str(), "original");
}

#[test]
fn enrichment_graph_node_id_debug_nonempty() {
    let id = GraphNodeId::new("test");
    let dbg = format!("{id:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("test"));
}

#[test]
fn enrichment_graph_node_id_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(GraphNodeId::new("a"));
    set.insert(GraphNodeId::new("b"));
    set.insert(GraphNodeId::new("a")); // duplicate
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// ModuleGraphNode enrichment
// ===========================================================================

#[test]
fn enrichment_module_graph_node_clone_independence() {
    let node = mk_esm_node("n1", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    let mut cloned = node.clone();
    cloned.subpath = "changed".to_string();
    assert_eq!(node.subpath, ".");
    assert_eq!(cloned.subpath, "changed");
}

#[test]
fn enrichment_module_graph_node_debug_nonempty() {
    let node = mk_esm_node("n1", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    let dbg = format!("{node:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ModuleGraphNode"));
}

#[test]
fn enrichment_module_graph_node_display_contains_role_and_surface() {
    let node = mk_esm_node(
        "my-node",
        ModuleRole::SchedulerHook,
        RenderSurface::StreamingSSR,
    );
    let display = node.to_string();
    assert!(display.contains("scheduler_hook"), "display: {display}");
    assert!(display.contains("streaming_ssr"), "display: {display}");
}

#[test]
fn enrichment_module_graph_node_json_field_names() {
    let node = mk_esm_node("n1", ModuleRole::EntryPoint, RenderSurface::ClientEntry);
    let json = serde_json::to_string(&node).unwrap();
    for field in [
        "node_id",
        "package",
        "subpath",
        "condition",
        "format",
        "role",
        "surface",
        "content_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// ModuleGraphEdge enrichment
// ===========================================================================

#[test]
fn enrichment_module_graph_edge_clone_independence() {
    let edge = build_module_edge("a", "b", "imports");
    let mut cloned = edge.clone();
    cloned.edge_kind = "re-exports".to_string();
    assert_eq!(edge.edge_kind, "imports");
    assert_eq!(cloned.edge_kind, "re-exports");
}

#[test]
fn enrichment_module_graph_edge_debug_nonempty() {
    let edge = build_module_edge("a", "b", "imports");
    let dbg = format!("{edge:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ModuleGraphEdge"));
}

#[test]
fn enrichment_module_graph_edge_display_contains_parts() {
    let edge = build_module_edge("src", "dst", "side-effect");
    let display = edge.to_string();
    assert!(display.contains("src"), "display: {display}");
    assert!(display.contains("dst"), "display: {display}");
    assert!(display.contains("side-effect"), "display: {display}");
}

#[test]
fn enrichment_module_graph_edge_json_field_names() {
    let edge = build_module_edge("a", "b", "imports");
    let json = serde_json::to_string(&edge).unwrap();
    for field in ["from_node", "to_node", "edge_kind", "content_hash"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// ModuleGraph enrichment
// ===========================================================================

#[test]
fn enrichment_module_graph_clone_independence() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let mut cloned = graph.clone();
    cloned.graph_id = "changed".to_string();
    assert_eq!(graph.graph_id, "g");
    assert_eq!(cloned.graph_id, "changed");
}

#[test]
fn enrichment_module_graph_debug_nonempty() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let dbg = format!("{graph:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ModuleGraph"));
}

#[test]
fn enrichment_module_graph_display_contains_counts() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let display = graph.to_string();
    assert!(display.contains("2 nodes"), "display: {display}");
    assert!(display.contains("1 edges"), "display: {display}");
}

#[test]
fn enrichment_module_graph_json_field_names() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let json = serde_json::to_string(&graph).unwrap();
    for field in [
        "graph_id",
        "surface",
        "nodes",
        "edges",
        "epoch",
        "content_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// GraphVerificationReceipt enrichment
// ===========================================================================

#[test]
fn enrichment_receipt_clone_independence() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    let mut cloned = receipt.clone();
    cloned.node_count = 999;
    assert_eq!(receipt.node_count, 2);
    assert_eq!(cloned.node_count, 999);
}

#[test]
fn enrichment_receipt_debug_nonempty() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    let dbg = format!("{receipt:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("GraphVerificationReceipt"));
}

#[test]
fn enrichment_receipt_display_contains_verdict() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    let display = receipt.to_string();
    assert!(display.contains("valid"), "display: {display}");
}

#[test]
fn enrichment_receipt_json_field_names() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    let json = serde_json::to_string(&receipt).unwrap();
    for field in [
        "receipt_id",
        "graph_id",
        "surface",
        "verdict",
        "node_count",
        "edge_count",
        "diagnostics",
        "content_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// SurfaceCoverageReport enrichment
// ===========================================================================

#[test]
fn enrichment_coverage_report_clone_independence() {
    let report = build_coverage_report("rpt", epoch(1), Vec::new());
    let mut cloned = report.clone();
    cloned.total_nodes = 999;
    assert_eq!(report.total_nodes, 0);
    assert_eq!(cloned.total_nodes, 999);
}

#[test]
fn enrichment_coverage_report_debug_nonempty() {
    let report = build_coverage_report("rpt", epoch(1), Vec::new());
    let dbg = format!("{report:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SurfaceCoverageReport"));
}

#[test]
fn enrichment_coverage_report_display_contains_coverage() {
    let report = build_coverage_report("rpt", epoch(1), Vec::new());
    let display = report.to_string();
    assert!(
        display.contains("SurfaceCoverageReport"),
        "display: {display}"
    );
    assert!(display.contains("0 surfaces"), "display: {display}");
}

#[test]
fn enrichment_coverage_report_json_field_names() {
    let report = build_coverage_report("rpt", epoch(1), Vec::new());
    let json = serde_json::to_string(&report).unwrap();
    for field in [
        "report_id",
        "epoch",
        "receipts",
        "surfaces_covered",
        "coverage_millionths",
        "total_nodes",
        "total_edges",
        "content_hash",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// ===========================================================================
// Five-run determinism
// ===========================================================================

#[test]
fn enrichment_five_run_determinism_graph_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| valid_graph(RenderSurface::ClientEntry).content_hash)
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_receipt_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let graph = valid_graph(RenderSurface::ClientEntry);
            verify_module_graph(&graph).content_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_coverage_report_hash() {
    let hashes: Vec<_> = (0..5)
        .map(|_| {
            let graph = valid_graph(RenderSurface::ClientEntry);
            let receipt = verify_module_graph(&graph);
            build_coverage_report("rpt", epoch(1), vec![receipt]).content_hash
        })
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

#[test]
fn enrichment_five_run_determinism_canonical_manifest() {
    let hashes: Vec<_> = (0..5)
        .map(|_| franken_engine_react_module_graph_manifest().content_hash)
        .collect();
    for h in &hashes[1..] {
        assert_eq!(hashes[0], *h);
    }
}

// ===========================================================================
// Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_render_surface_serde_all() {
    for &s in ALL_SURFACES {
        let json = serde_json::to_string(&s).unwrap();
        let back: RenderSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}

#[test]
fn enrichment_verdict_serde_all() {
    for v in [
        GraphVerificationVerdict::Valid,
        GraphVerificationVerdict::MissingSurface,
        GraphVerificationVerdict::CyclicDependency,
        GraphVerificationVerdict::FormatMismatch,
        GraphVerificationVerdict::UnsupportedSurface,
        GraphVerificationVerdict::OrphanNode,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: GraphVerificationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_graph_node_id_serde_roundtrip() {
    let id = GraphNodeId::new("test-id");
    let json = serde_json::to_string(&id).unwrap();
    let back: GraphNodeId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn enrichment_module_graph_serde_roundtrip() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let json = serde_json::to_string(&graph).unwrap();
    let back: ModuleGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, back);
}

#[test]
fn enrichment_receipt_serde_roundtrip() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    let json = serde_json::to_string(&receipt).unwrap();
    let back: GraphVerificationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(receipt, back);
}

#[test]
fn enrichment_coverage_report_serde_roundtrip() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    let receipt = verify_module_graph(&graph);
    let report = build_coverage_report("rpt", epoch(1), vec![receipt]);
    let json = serde_json::to_string(&report).unwrap();
    let back: SurfaceCoverageReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ===========================================================================
// Cross-cutting
// ===========================================================================

#[test]
fn enrichment_detect_cycles_acyclic_graph_returns_empty() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    assert!(detect_cycles(&graph).is_empty());
}

#[test]
fn enrichment_detect_orphans_fully_connected_returns_empty() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    assert!(detect_orphans(&graph).is_empty());
}

#[test]
fn enrichment_detect_format_mismatches_all_esm_returns_empty() {
    let graph = valid_graph(RenderSurface::ClientEntry);
    assert!(detect_format_mismatches(&graph).is_empty());
}

#[test]
fn enrichment_coverage_boundary_zero() {
    assert_eq!(surface_coverage_millionths(&[]), 0);
}

#[test]
fn enrichment_coverage_boundary_one_fifth() {
    assert_eq!(
        surface_coverage_millionths(&[RenderSurface::ClientEntry]),
        200_000
    );
}

#[test]
fn enrichment_coverage_boundary_full() {
    let all: Vec<RenderSurface> = ALL_SURFACES.to_vec();
    assert_eq!(surface_coverage_millionths(&all), 1_000_000);
}

#[test]
fn enrichment_canonical_manifest_valid_verdicts() {
    let manifest = franken_engine_react_module_graph_manifest();
    for receipt in &manifest.receipts {
        assert_eq!(receipt.verdict, GraphVerificationVerdict::Valid);
    }
}

#[test]
fn enrichment_canonical_manifest_two_surfaces() {
    let manifest = franken_engine_react_module_graph_manifest();
    assert_eq!(manifest.surfaces_covered.len(), 2);
    let surfaces: BTreeSet<_> = manifest.surfaces_covered.iter().copied().collect();
    assert!(surfaces.contains(&RenderSurface::ServerSideRender));
    assert!(surfaces.contains(&RenderSurface::ClientEntry));
}

// ===========================================================================
// Constants stability
// ===========================================================================

#[test]
fn enrichment_constants_stability() {
    assert!(REACT_MODULE_GRAPH_SCHEMA_VERSION.contains("react-module-graph-verifier"));
    assert!(REACT_MODULE_GRAPH_BEAD_ID.starts_with("bd-"));
    assert!(REACT_MODULE_GRAPH_POLICY_ID.starts_with("RGC-"));
    assert_eq!(COMPONENT, "react_module_graph_verifier");
    assert_eq!(ALL_SURFACES.len(), 5);
}
