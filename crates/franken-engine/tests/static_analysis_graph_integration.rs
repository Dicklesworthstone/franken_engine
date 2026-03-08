#![forbid(unsafe_code)]
//! Integration tests for the `static_analysis_graph` module.
//!
//! Exercises the full static analysis graph API from outside the crate
//! boundary: graph construction, node/edge insertion, component registration,
//! cycle detection, transitive capability propagation, and summary generation.

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::EffectBoundary;
use frankenengine_engine::static_analysis_graph::{
    AnalysisEdge, AnalysisEdgeId, AnalysisError, AnalysisEvent, AnalysisEventKind, AnalysisNode,
    AnalysisNodeId, AnalysisSummary, CapabilityBoundary, ComponentDescriptor, ComponentId,
    CycleReport, DependencyPath, EdgeKind, EffectClassification, HookKind, HookSlot, NodeKind,
    STATIC_ANALYSIS_SCHEMA_VERSION, StaticAnalysisGraph,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn nid(name: &str) -> AnalysisNodeId {
    AnalysisNodeId::new(name)
}

fn eid(name: &str) -> AnalysisEdgeId {
    AnalysisEdgeId::new(name)
}

fn cid(name: &str) -> ComponentId {
    ComponentId::new(name)
}

fn component_node(name: &str) -> AnalysisNode {
    AnalysisNode {
        id: nid(name),
        kind: NodeKind::Component,
        label: name.to_string(),
        component_id: Some(cid(name)),
        source_offset: 0,
        content_hash: ContentHash::compute(name.as_bytes()),
        hook_slots: Vec::new(),
        effect_classification: None,
        capability_boundary: Some(CapabilityBoundary::pure_component()),
    }
}

fn data_source_node(name: &str) -> AnalysisNode {
    AnalysisNode {
        id: nid(name),
        kind: NodeKind::DataSource,
        label: name.to_string(),
        component_id: None,
        source_offset: 0,
        content_hash: ContentHash::compute(name.as_bytes()),
        hook_slots: Vec::new(),
        effect_classification: None,
        capability_boundary: None,
    }
}

fn effect_node(name: &str) -> AnalysisNode {
    AnalysisNode {
        id: nid(name),
        kind: NodeKind::EffectSite,
        label: name.to_string(),
        component_id: None,
        source_offset: 0,
        content_hash: ContentHash::compute(name.as_bytes()),
        hook_slots: Vec::new(),
        effect_classification: Some(EffectClassification::pure_effect()),
        capability_boundary: None,
    }
}

fn edge(name: &str, src: &str, tgt: &str, kind: EdgeKind) -> AnalysisEdge {
    AnalysisEdge {
        id: eid(name),
        source: nid(src),
        target: nid(tgt),
        kind,
        data_labels: Vec::new(),
        weight_millionths: 1_000_000,
    }
}

fn simple_descriptor(name: &str, children: &[&str]) -> ComponentDescriptor {
    use std::collections::BTreeMap;
    ComponentDescriptor {
        id: cid(name),
        is_function_component: true,
        module_path: format!("src/{name}.tsx"),
        export_name: Some(name.to_string()),
        hook_slots: Vec::new(),
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary::pure_component(),
        is_pure: true,
        content_hash: ContentHash::compute(name.as_bytes()),
        children: children.iter().map(|c| cid(c)).collect(),
    }
}

fn hook_slot(index: u32, kind: HookKind, label: &str) -> HookSlot {
    HookSlot {
        slot_index: index,
        kind,
        label: label.to_string(),
        dependency_count: None,
        has_cleanup: false,
        source_offset: 0,
        dependency_hash: None,
    }
}

// ===========================================================================
// 1. Schema constant
// ===========================================================================

#[test]
fn schema_version_is_stable() {
    assert_eq!(
        STATIC_ANALYSIS_SCHEMA_VERSION,
        "franken-engine.static-analysis-graph.v1"
    );
}

// ===========================================================================
// 2. ID types display and ordering
// ===========================================================================

#[test]
fn component_id_display() {
    let id = cid("App");
    assert_eq!(id.to_string(), "App");
}

#[test]
fn node_id_display() {
    let id = nid("node_1");
    assert_eq!(id.to_string(), "node_1");
}

#[test]
fn edge_id_display() {
    let id = eid("edge_1");
    assert_eq!(id.to_string(), "edge_1");
}

#[test]
fn component_id_ordering() {
    assert!(cid("A") < cid("B"));
}

#[test]
fn id_serde_round_trip() {
    let c = cid("MyComponent");
    let json = serde_json::to_string(&c).unwrap();
    let back: ComponentId = serde_json::from_str(&json).unwrap();
    assert_eq!(back, c);
}

// ===========================================================================
// 3. NodeKind display and serde
// ===========================================================================

#[test]
fn node_kind_display_all() {
    let kinds = [
        NodeKind::Component,
        NodeKind::HookSlot,
        NodeKind::EffectSite,
        NodeKind::DataSource,
        NodeKind::DataSink,
        NodeKind::ModuleBoundary,
        NodeKind::CapabilityGate,
        NodeKind::ScopeBoundary,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(
        displays.len(),
        kinds.len(),
        "all node kinds have unique display"
    );
}

#[test]
fn node_kind_serde_round_trip() {
    let k = NodeKind::HookSlot;
    let json = serde_json::to_string(&k).unwrap();
    let back: NodeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(back, k);
}

// ===========================================================================
// 4. EdgeKind display and serde
// ===========================================================================

#[test]
fn edge_kind_display_all() {
    let kinds = [
        EdgeKind::RendersChild,
        EdgeKind::PropFlow,
        EdgeKind::HookDataFlow,
        EdgeKind::EffectDependency,
        EdgeKind::ImportDependency,
        EdgeKind::ContextFlow,
        EdgeKind::CallbackFlow,
        EdgeKind::CapabilityRequirement,
        EdgeKind::ScopeContainment,
        EdgeKind::StateUpdateTrigger,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(
        displays.len(),
        kinds.len(),
        "all edge kinds have unique display"
    );
}

#[test]
fn edge_kind_serde_round_trip() {
    let k = EdgeKind::ContextFlow;
    let json = serde_json::to_string(&k).unwrap();
    let back: EdgeKind = serde_json::from_str(&json).unwrap();
    assert_eq!(back, k);
}

// ===========================================================================
// 5. HookKind display and serde
// ===========================================================================

#[test]
fn hook_kind_display_all() {
    let kinds = [
        HookKind::State,
        HookKind::Effect,
        HookKind::LayoutEffect,
        HookKind::Memo,
        HookKind::Callback,
        HookKind::Ref,
        HookKind::Context,
        HookKind::ImperativeHandle,
        HookKind::Custom,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(
        displays.len(),
        kinds.len(),
        "all hook kinds have unique display"
    );
}

#[test]
fn hook_kind_serde_round_trip() {
    let k = HookKind::Memo;
    let json = serde_json::to_string(&k).unwrap();
    let back: HookKind = serde_json::from_str(&json).unwrap();
    assert_eq!(back, k);
}

// ===========================================================================
// 6. HookSlot classification
// ===========================================================================

#[test]
fn hook_slot_state_is_stateful() {
    let h = hook_slot(0, HookKind::State, "count");
    assert!(h.is_stateful());
    assert!(!h.has_side_effects());
    assert!(!h.is_memoized());
}

#[test]
fn hook_slot_effect_has_side_effects() {
    let h = hook_slot(0, HookKind::Effect, "fetchData");
    assert!(!h.is_stateful());
    assert!(h.has_side_effects());
}

#[test]
fn hook_slot_memo_is_memoized() {
    let h = hook_slot(0, HookKind::Memo, "expensiveCalc");
    assert!(h.is_memoized());
    assert!(!h.is_stateful());
}

#[test]
fn hook_slot_callback_is_memoized() {
    let h = hook_slot(0, HookKind::Callback, "onClick");
    assert!(h.is_memoized());
}

#[test]
fn hook_slot_layout_effect_has_side_effects() {
    let h = hook_slot(0, HookKind::LayoutEffect, "measure");
    assert!(h.has_side_effects());
}

#[test]
fn hook_slot_serde_round_trip() {
    let h = HookSlot {
        slot_index: 3,
        kind: HookKind::Effect,
        label: "fetchData".to_string(),
        dependency_count: Some(2),
        has_cleanup: true,
        source_offset: 100,
        dependency_hash: Some(ContentHash::compute(b"deps")),
    };
    let json = serde_json::to_string(&h).unwrap();
    let back: HookSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(back, h);
}

// ===========================================================================
// 7. EffectClassification
// ===========================================================================

#[test]
fn pure_effect_is_pure() {
    let e = EffectClassification::pure_effect();
    assert!(e.is_pure());
    assert!(!e.requires_capabilities());
}

#[test]
fn effect_with_capabilities_requires_capabilities() {
    let mut caps = BTreeSet::new();
    caps.insert("network".to_string());
    let e = EffectClassification {
        boundary: EffectBoundary::NetworkEffect,
        required_capabilities: caps,
        idempotent: false,
        commutative: false,
        estimated_cost_millionths: 500_000,
    };
    assert!(!e.is_pure());
    assert!(e.requires_capabilities());
}

#[test]
fn effect_classification_serde_round_trip() {
    let e = EffectClassification::pure_effect();
    let json = serde_json::to_string(&e).unwrap();
    let back: EffectClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 8. CapabilityBoundary
// ===========================================================================

#[test]
fn pure_component_boundary() {
    let b = CapabilityBoundary::pure_component();
    assert!(b.is_render_pure());
    assert!(b.all_capabilities().is_empty());
}

#[test]
fn boundary_with_capabilities() {
    let mut direct = BTreeSet::new();
    direct.insert("fs".to_string());
    let mut transitive = BTreeSet::new();
    transitive.insert("network".to_string());
    let b = CapabilityBoundary {
        direct_capabilities: direct,
        transitive_capabilities: transitive,
        render_effect: EffectBoundary::Pure,
        hook_effects: Vec::new(),
        is_boundary: false,
        boundary_tags: Vec::new(),
    };
    let all = b.all_capabilities();
    assert!(all.contains("fs"));
    assert!(all.contains("network"));
    assert_eq!(all.len(), 2);
}

#[test]
fn capability_boundary_serde_round_trip() {
    let b = CapabilityBoundary::pure_component();
    let json = serde_json::to_string(&b).unwrap();
    let back: CapabilityBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, b);
}

// ===========================================================================
// 9. ComponentDescriptor
// ===========================================================================

#[test]
fn leaf_component() {
    let d = simple_descriptor("Button", &[]);
    assert!(d.is_leaf());
    assert_eq!(d.total_hook_count(), 0);
}

#[test]
fn component_with_children() {
    let d = simple_descriptor("App", &["Header", "Footer"]);
    assert!(!d.is_leaf());
    assert_eq!(d.children.len(), 2);
}

#[test]
fn component_hook_counts() {
    use std::collections::BTreeMap;
    let d = ComponentDescriptor {
        id: cid("Counter"),
        is_function_component: true,
        module_path: "src/Counter.tsx".to_string(),
        export_name: Some("Counter".to_string()),
        hook_slots: vec![
            hook_slot(0, HookKind::State, "count"),
            hook_slot(1, HookKind::Effect, "sync"),
            hook_slot(2, HookKind::Memo, "derived"),
        ],
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary::pure_component(),
        is_pure: false,
        content_hash: ContentHash::compute(b"Counter"),
        children: Vec::new(),
    };
    assert_eq!(d.total_hook_count(), 3);
    assert_eq!(d.stateful_hook_count(), 1);
    assert_eq!(d.effect_hook_count(), 1);
}

#[test]
fn component_descriptor_serde_round_trip() {
    let d = simple_descriptor("App", &["Child"]);
    let json = serde_json::to_string(&d).unwrap();
    let back: ComponentDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

// ===========================================================================
// 10. DependencyPath
// ===========================================================================

#[test]
fn dependency_path_depth() {
    let p = DependencyPath {
        components: vec![cid("A"), cid("B"), cid("C")],
        total_weight_millionths: 2_000_000,
        edge_kinds: vec![EdgeKind::RendersChild, EdgeKind::RendersChild],
    };
    assert_eq!(p.depth(), 2);
    assert!(p.contains(&cid("B")));
    assert!(!p.contains(&cid("D")));
}

#[test]
fn dependency_path_single_component() {
    let p = DependencyPath {
        components: vec![cid("Root")],
        total_weight_millionths: 0,
        edge_kinds: Vec::new(),
    };
    assert_eq!(p.depth(), 0);
}

#[test]
fn dependency_path_serde_round_trip() {
    let p = DependencyPath {
        components: vec![cid("A"), cid("B")],
        total_weight_millionths: 1_000_000,
        edge_kinds: vec![EdgeKind::PropFlow],
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: DependencyPath = serde_json::from_str(&json).unwrap();
    assert_eq!(back, p);
}

// ===========================================================================
// 11. CycleReport
// ===========================================================================

#[test]
fn cycle_report_serde_round_trip() {
    let r = CycleReport {
        cycle: vec![cid("A"), cid("B"), cid("A")],
        edge_kinds: vec![EdgeKind::RendersChild, EdgeKind::RendersChild],
        is_data_cycle: false,
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: CycleReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

// ===========================================================================
// 12. AnalysisError display
// ===========================================================================

#[test]
fn analysis_error_display_variants() {
    let errors = [
        AnalysisError::DuplicateNode(nid("x")),
        AnalysisError::DuplicateEdge(eid("e")),
        AnalysisError::UnknownNode(nid("y")),
        AnalysisError::DuplicateComponent(cid("C")),
        AnalysisError::UnknownComponent(cid("D")),
    ];
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn analysis_error_serde_round_trip() {
    let e = AnalysisError::DuplicateNode(nid("x"));
    let json = serde_json::to_string(&e).unwrap();
    let back: AnalysisError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 13. AnalysisEventKind display
// ===========================================================================

#[test]
fn event_kind_display_all() {
    let kinds = [
        AnalysisEventKind::NodeAdded,
        AnalysisEventKind::EdgeAdded,
        AnalysisEventKind::ComponentRegistered,
        AnalysisEventKind::CycleDetected,
        AnalysisEventKind::CapabilityBoundaryComputed,
        AnalysisEventKind::AnalysisFinalized,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), kinds.len());
}

// ===========================================================================
// 14. Empty graph
// ===========================================================================

#[test]
fn empty_graph_has_zero_counts() {
    let g = StaticAnalysisGraph::new();
    assert_eq!(g.node_count(), 0);
    assert_eq!(g.edge_count(), 0);
    assert_eq!(g.component_count(), 0);
    assert_eq!(g.schema_version, STATIC_ANALYSIS_SCHEMA_VERSION);
}

#[test]
fn default_graph_same_as_new() {
    let g1 = StaticAnalysisGraph::new();
    let g2 = StaticAnalysisGraph::default();
    assert_eq!(g1.node_count(), g2.node_count());
    assert_eq!(g1.schema_version, g2.schema_version);
}

// ===========================================================================
// 15. Adding nodes
// ===========================================================================

#[test]
fn add_single_node() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("App")).unwrap();
    assert_eq!(g.node_count(), 1);
    assert!(g.get_node(&nid("App")).is_some());
}

#[test]
fn add_multiple_nodes() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("App")).unwrap();
    g.add_node(component_node("Header")).unwrap();
    g.add_node(data_source_node("props")).unwrap();
    assert_eq!(g.node_count(), 3);
}

#[test]
fn duplicate_node_is_error() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("App")).unwrap();
    let result = g.add_node(component_node("App"));
    assert!(matches!(result, Err(AnalysisError::DuplicateNode(_))));
}

// ===========================================================================
// 16. Adding edges
// ===========================================================================

#[test]
fn add_edge_between_nodes() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("App")).unwrap();
    g.add_node(component_node("Header")).unwrap();
    g.add_edge(edge("e1", "App", "Header", EdgeKind::RendersChild))
        .unwrap();
    assert_eq!(g.edge_count(), 1);
    assert!(g.get_edge(&eid("e1")).is_some());
}

#[test]
fn duplicate_edge_is_error() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_edge(edge("e1", "A", "B", EdgeKind::PropFlow))
        .unwrap();
    let result = g.add_edge(edge("e1", "A", "B", EdgeKind::PropFlow));
    assert!(matches!(result, Err(AnalysisError::DuplicateEdge(_))));
}

#[test]
fn edge_to_unknown_node_fails() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    let result = g.add_edge(edge("e1", "A", "missing", EdgeKind::PropFlow));
    assert!(matches!(result, Err(AnalysisError::UnknownNode(_))));
}

// ===========================================================================
// 17. Component registration
// ===========================================================================

#[test]
fn register_component() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("App", &["Header"]))
        .unwrap();
    assert_eq!(g.component_count(), 1);
    assert!(g.get_component(&cid("App")).is_some());
}

#[test]
fn duplicate_component_is_error() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("App", &[])).unwrap();
    let result = g.register_component(simple_descriptor("App", &[]));
    assert!(matches!(result, Err(AnalysisError::DuplicateComponent(_))));
}

// ===========================================================================
// 18. Graph navigation — outgoing/incoming edges
// ===========================================================================

#[test]
fn outgoing_edges() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_node(component_node("C")).unwrap();
    g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
        .unwrap();
    g.add_edge(edge("e2", "A", "C", EdgeKind::RendersChild))
        .unwrap();
    let out = g.outgoing_edges(&nid("A"));
    assert_eq!(out.len(), 2);
}

#[test]
fn incoming_edges() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_node(component_node("C")).unwrap();
    g.add_edge(edge("e1", "A", "C", EdgeKind::PropFlow))
        .unwrap();
    g.add_edge(edge("e2", "B", "C", EdgeKind::PropFlow))
        .unwrap();
    let inc = g.incoming_edges(&nid("C"));
    assert_eq!(inc.len(), 2);
}

#[test]
fn isolated_node_has_no_edges() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("Isolated")).unwrap();
    assert!(g.outgoing_edges(&nid("Isolated")).is_empty());
    assert!(g.incoming_edges(&nid("Isolated")).is_empty());
}

// ===========================================================================
// 19. Dependencies and dependents
// ===========================================================================

#[test]
fn dependencies_and_dependents() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_node(component_node("C")).unwrap();
    g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
        .unwrap();
    g.add_edge(edge("e2", "A", "C", EdgeKind::RendersChild))
        .unwrap();
    let deps = g.dependencies(&nid("A"));
    assert_eq!(deps.len(), 2);
    let dependents = g.dependents(&nid("B"));
    assert_eq!(dependents.len(), 1);
    assert_eq!(dependents[0], nid("A"));
}

// ===========================================================================
// 20. Edges between two nodes
// ===========================================================================

#[test]
fn edges_between_nodes() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
        .unwrap();
    g.add_edge(edge("e2", "A", "B", EdgeKind::PropFlow))
        .unwrap();
    let between = g.edges_between(&nid("A"), &nid("B"));
    assert_eq!(between.len(), 2);
}

#[test]
fn edges_between_unconnected_is_empty() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    let between = g.edges_between(&nid("A"), &nid("B"));
    assert!(between.is_empty());
}

// ===========================================================================
// 21. Reachable subgraph
// ===========================================================================

#[test]
fn reachable_from_root() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_node(component_node("C")).unwrap();
    g.add_node(component_node("D")).unwrap(); // isolated
    g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
        .unwrap();
    g.add_edge(edge("e2", "B", "C", EdgeKind::RendersChild))
        .unwrap();
    let reachable = g.reachable_from(&nid("A"));
    assert!(reachable.contains(&nid("B")));
    assert!(reachable.contains(&nid("C")));
    assert!(!reachable.contains(&nid("D")));
}

#[test]
fn reachable_from_leaf_contains_only_self() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
        .unwrap();
    let reachable = g.reachable_from(&nid("B"));
    // Leaf has no forward neighbors, but reachable_from may include start node
    assert!(!reachable.contains(&nid("A")));
}

// ===========================================================================
// 22. Component tree queries
// ===========================================================================

#[test]
fn root_and_leaf_components() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("App", &["Header", "Footer"]))
        .unwrap();
    g.register_component(simple_descriptor("Header", &[]))
        .unwrap();
    g.register_component(simple_descriptor("Footer", &[]))
        .unwrap();
    let roots = g.root_components();
    let leaves = g.leaf_components();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0], cid("App"));
    assert_eq!(leaves.len(), 2);
}

#[test]
fn component_ids_returns_all() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("A", &[])).unwrap();
    g.register_component(simple_descriptor("B", &[])).unwrap();
    g.register_component(simple_descriptor("C", &[])).unwrap();
    let ids = g.component_ids();
    assert_eq!(ids.len(), 3);
}

// ===========================================================================
// 23. Node and edge filtering
// ===========================================================================

#[test]
fn nodes_of_kind_filtering() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("App")).unwrap();
    g.add_node(component_node("Header")).unwrap();
    g.add_node(data_source_node("api_data")).unwrap();
    g.add_node(effect_node("sideEffect")).unwrap();
    let components = g.nodes_of_kind(NodeKind::Component);
    assert_eq!(components.len(), 2);
    let data_sources = g.nodes_of_kind(NodeKind::DataSource);
    assert_eq!(data_sources.len(), 1);
}

#[test]
fn edges_of_kind_filtering() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_node(component_node("C")).unwrap();
    g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
        .unwrap();
    g.add_edge(edge("e2", "A", "C", EdgeKind::PropFlow))
        .unwrap();
    g.add_edge(edge("e3", "B", "C", EdgeKind::RendersChild))
        .unwrap();
    let renders = g.edges_of_kind(EdgeKind::RendersChild);
    assert_eq!(renders.len(), 2);
    let props = g.edges_of_kind(EdgeKind::PropFlow);
    assert_eq!(props.len(), 1);
}

// ===========================================================================
// 24. Hook slots for component
// ===========================================================================

#[test]
fn hook_slots_for_component() {
    use std::collections::BTreeMap;
    let mut g = StaticAnalysisGraph::new();
    let desc = ComponentDescriptor {
        id: cid("Counter"),
        is_function_component: true,
        module_path: "src/Counter.tsx".to_string(),
        export_name: Some("Counter".to_string()),
        hook_slots: vec![
            hook_slot(0, HookKind::State, "count"),
            hook_slot(1, HookKind::Effect, "sync"),
        ],
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary::pure_component(),
        is_pure: false,
        content_hash: ContentHash::compute(b"Counter"),
        children: Vec::new(),
    };
    g.register_component(desc).unwrap();
    let slots = g.hook_slots_for(&cid("Counter")).unwrap();
    assert_eq!(slots.len(), 2);
    assert_eq!(slots[0].kind, HookKind::State);
}

#[test]
fn hook_slots_for_unknown_is_none() {
    let g = StaticAnalysisGraph::new();
    assert!(g.hook_slots_for(&cid("Unknown")).is_none());
}

// ===========================================================================
// 25. Components requiring capability
// ===========================================================================

#[test]
fn components_requiring_capability() {
    use std::collections::BTreeMap;
    let mut g = StaticAnalysisGraph::new();
    let mut direct_caps = BTreeSet::new();
    direct_caps.insert("network".to_string());
    g.register_component(ComponentDescriptor {
        id: cid("Fetcher"),
        is_function_component: true,
        module_path: "src/Fetcher.tsx".to_string(),
        export_name: Some("Fetcher".to_string()),
        hook_slots: Vec::new(),
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary {
            direct_capabilities: direct_caps,
            transitive_capabilities: BTreeSet::new(),
            render_effect: EffectBoundary::Pure,
            hook_effects: Vec::new(),
            is_boundary: false,
            boundary_tags: Vec::new(),
        },
        is_pure: false,
        content_hash: ContentHash::compute(b"Fetcher"),
        children: Vec::new(),
    })
    .unwrap();
    g.register_component(simple_descriptor("Button", &[]))
        .unwrap();
    let caps = g.components_requiring_capability("network");
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0], cid("Fetcher"));
}

#[test]
fn components_requiring_nonexistent_capability() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("App", &[])).unwrap();
    let caps = g.components_requiring_capability("crypto");
    assert!(caps.is_empty());
}

// ===========================================================================
// 26. Cycle detection
// ===========================================================================

#[test]
fn no_cycles_in_tree() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("A", &["B"]))
        .unwrap();
    g.register_component(simple_descriptor("B", &["C"]))
        .unwrap();
    g.register_component(simple_descriptor("C", &[])).unwrap();
    let cycles = g.detect_cycles();
    assert!(cycles.is_empty());
}

#[test]
fn detects_simple_cycle() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("A", &["B"]))
        .unwrap();
    g.register_component(simple_descriptor("B", &["A"]))
        .unwrap();
    let cycles = g.detect_cycles();
    assert!(!cycles.is_empty());
    assert!(!g.cycles().is_empty());
}

#[test]
fn detects_three_node_cycle() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("A", &["B"]))
        .unwrap();
    g.register_component(simple_descriptor("B", &["C"]))
        .unwrap();
    g.register_component(simple_descriptor("C", &["A"]))
        .unwrap();
    let cycles = g.detect_cycles();
    assert!(!cycles.is_empty());
}

// ===========================================================================
// 27. Transitive capability propagation
// ===========================================================================

#[test]
fn transitive_capabilities_propagate_up() {
    use std::collections::BTreeMap;
    let mut g = StaticAnalysisGraph::new();
    // Child has "network" capability
    let mut child_caps = BTreeSet::new();
    child_caps.insert("network".to_string());
    g.register_component(ComponentDescriptor {
        id: cid("Fetcher"),
        is_function_component: true,
        module_path: "src/Fetcher.tsx".to_string(),
        export_name: None,
        hook_slots: Vec::new(),
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary {
            direct_capabilities: child_caps,
            transitive_capabilities: BTreeSet::new(),
            render_effect: EffectBoundary::Pure,
            hook_effects: Vec::new(),
            is_boundary: false,
            boundary_tags: Vec::new(),
        },
        is_pure: false,
        content_hash: ContentHash::compute(b"Fetcher"),
        children: Vec::new(),
    })
    .unwrap();
    // Parent renders child
    g.register_component(simple_descriptor("App", &["Fetcher"]))
        .unwrap();
    g.compute_transitive_capabilities();
    let app = g.get_component(&cid("App")).unwrap();
    assert!(
        app.capability_boundary
            .transitive_capabilities
            .contains("network")
    );
}

// ===========================================================================
// 28. Summary
// ===========================================================================

#[test]
fn empty_graph_summary() {
    let g = StaticAnalysisGraph::new();
    let s = g.summary();
    assert_eq!(s.component_count, 0);
    assert_eq!(s.edge_count, 0);
    assert_eq!(s.hook_slot_count, 0);
}

#[test]
fn summary_with_components() {
    use std::collections::BTreeMap;
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("App", &["Button"]))
        .unwrap();
    g.register_component(ComponentDescriptor {
        id: cid("Button"),
        is_function_component: true,
        module_path: "src/Button.tsx".to_string(),
        export_name: Some("Button".to_string()),
        hook_slots: vec![hook_slot(0, HookKind::State, "pressed")],
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary::pure_component(),
        is_pure: false,
        content_hash: ContentHash::compute(b"Button"),
        children: Vec::new(),
    })
    .unwrap();
    let s = g.summary();
    assert_eq!(s.component_count, 2);
    assert_eq!(s.hook_slot_count, 1);
    assert_eq!(s.stateful_component_count, 1);
    assert!(s.pure_component_count >= 1);
}

#[test]
fn summary_serde_round_trip() {
    let g = StaticAnalysisGraph::new();
    let s = g.summary();
    let json = serde_json::to_string(&s).unwrap();
    let back: AnalysisSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

// ===========================================================================
// 29. Event audit trail
// ===========================================================================

#[test]
fn events_track_mutations() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("App")).unwrap();
    g.add_node(component_node("Child")).unwrap();
    g.add_edge(edge("e1", "App", "Child", EdgeKind::RendersChild))
        .unwrap();
    let events = g.events();
    // At least node-added and edge-added events
    assert!(events.len() >= 3);
    let kinds: Vec<_> = events.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&AnalysisEventKind::NodeAdded));
    assert!(kinds.contains(&&AnalysisEventKind::EdgeAdded));
}

#[test]
fn events_have_sequential_ids() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    let events = g.events();
    if events.len() >= 2 {
        assert!(events[0].seq < events[1].seq);
    }
}

#[test]
fn event_serde_round_trip() {
    let e = AnalysisEvent {
        seq: 42,
        kind: AnalysisEventKind::NodeAdded,
        entity_id: "App".to_string(),
        detail: "added component node".to_string(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: AnalysisEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 30. Full graph serde round-trip
// ===========================================================================

#[test]
fn graph_serde_round_trip() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("App")).unwrap();
    g.add_node(component_node("Child")).unwrap();
    g.add_edge(edge("e1", "App", "Child", EdgeKind::RendersChild))
        .unwrap();
    g.register_component(simple_descriptor("App", &["Child"]))
        .unwrap();
    g.register_component(simple_descriptor("Child", &[]))
        .unwrap();
    let json = serde_json::to_string(&g).unwrap();
    let back: StaticAnalysisGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(back.node_count(), g.node_count());
    assert_eq!(back.edge_count(), g.edge_count());
    assert_eq!(back.component_count(), g.component_count());
}

// ===========================================================================
// 31. Large graph
// ===========================================================================

#[test]
fn large_flat_graph() {
    let mut g = StaticAnalysisGraph::new();
    let n = 100;
    for i in 0..n {
        g.add_node(component_node(&format!("C_{i}"))).unwrap();
    }
    // Star topology: C_0 → C_1..C_99
    for i in 1..n {
        g.add_edge(edge(
            &format!("e_{i}"),
            "C_0",
            &format!("C_{i}"),
            EdgeKind::RendersChild,
        ))
        .unwrap();
    }
    assert_eq!(g.node_count(), n);
    assert_eq!(g.edge_count(), n - 1);
    let out = g.outgoing_edges(&nid("C_0"));
    assert_eq!(out.len(), n - 1);
}

#[test]
fn deep_chain_graph() {
    let mut g = StaticAnalysisGraph::new();
    let depth = 50;
    for i in 0..depth {
        g.add_node(component_node(&format!("L_{i}"))).unwrap();
    }
    for i in 0..(depth - 1) {
        g.add_edge(edge(
            &format!("e_{i}"),
            &format!("L_{i}"),
            &format!("L_{}", i + 1),
            EdgeKind::RendersChild,
        ))
        .unwrap();
    }
    let reachable = g.reachable_from(&nid("L_0"));
    // reachable_from includes the start node itself
    assert_eq!(reachable.len(), depth);
}

// ===========================================================================
// 32. Diamond DAG
// ===========================================================================

#[test]
fn diamond_dag_no_cycles() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("A", &["B", "C"]))
        .unwrap();
    g.register_component(simple_descriptor("B", &["D"]))
        .unwrap();
    g.register_component(simple_descriptor("C", &["D"]))
        .unwrap();
    g.register_component(simple_descriptor("D", &[])).unwrap();
    let cycles = g.detect_cycles();
    assert!(cycles.is_empty());
}

#[test]
fn diamond_dag_transitive_capabilities() {
    use std::collections::BTreeMap;
    let mut g = StaticAnalysisGraph::new();
    // D requires "fs"
    let mut d_caps = BTreeSet::new();
    d_caps.insert("fs".to_string());
    g.register_component(ComponentDescriptor {
        id: cid("D"),
        is_function_component: true,
        module_path: "src/D.tsx".to_string(),
        export_name: None,
        hook_slots: Vec::new(),
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary {
            direct_capabilities: d_caps,
            transitive_capabilities: BTreeSet::new(),
            render_effect: EffectBoundary::Pure,
            hook_effects: Vec::new(),
            is_boundary: false,
            boundary_tags: Vec::new(),
        },
        is_pure: false,
        content_hash: ContentHash::compute(b"D"),
        children: Vec::new(),
    })
    .unwrap();
    g.register_component(simple_descriptor("B", &["D"]))
        .unwrap();
    g.register_component(simple_descriptor("C", &["D"]))
        .unwrap();
    g.register_component(simple_descriptor("A", &["B", "C"]))
        .unwrap();
    g.compute_transitive_capabilities();
    // All ancestors should have "fs" transitively
    let a = g.get_component(&cid("A")).unwrap();
    assert!(a.capability_boundary.transitive_capabilities.contains("fs"));
    let b = g.get_component(&cid("B")).unwrap();
    assert!(b.capability_boundary.transitive_capabilities.contains("fs"));
}

// ===========================================================================
// 33. Multiple edge kinds between same nodes
// ===========================================================================

#[test]
fn multiple_edge_kinds_between_same_pair() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
        .unwrap();
    g.add_edge(edge("e2", "A", "B", EdgeKind::PropFlow))
        .unwrap();
    g.add_edge(edge("e3", "A", "B", EdgeKind::ContextFlow))
        .unwrap();
    let between = g.edges_between(&nid("A"), &nid("B"));
    assert_eq!(between.len(), 3);
    let kinds: BTreeSet<EdgeKind> = between.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&EdgeKind::RendersChild));
    assert!(kinds.contains(&EdgeKind::PropFlow));
    assert!(kinds.contains(&EdgeKind::ContextFlow));
}

// ===========================================================================
// 34. Node accessor returns correct data
// ===========================================================================

#[test]
fn get_node_returns_correct_data() {
    let mut g = StaticAnalysisGraph::new();
    let node = AnalysisNode {
        id: nid("test_node"),
        kind: NodeKind::EffectSite,
        label: "fetchUser".to_string(),
        component_id: Some(cid("UserProfile")),
        source_offset: 42,
        content_hash: ContentHash::compute(b"fetchUser"),
        hook_slots: Vec::new(),
        effect_classification: Some(EffectClassification::pure_effect()),
        capability_boundary: None,
    };
    g.add_node(node.clone()).unwrap();
    let retrieved = g.get_node(&nid("test_node")).unwrap();
    assert_eq!(retrieved.kind, NodeKind::EffectSite);
    assert_eq!(retrieved.label, "fetchUser");
    assert_eq!(retrieved.source_offset, 42);
}

// ===========================================================================
// 35. Edge data labels
// ===========================================================================

#[test]
fn edge_with_data_labels() {
    let mut g = StaticAnalysisGraph::new();
    g.add_node(component_node("A")).unwrap();
    g.add_node(component_node("B")).unwrap();
    let e = AnalysisEdge {
        id: eid("labeled"),
        source: nid("A"),
        target: nid("B"),
        kind: EdgeKind::PropFlow,
        data_labels: vec!["userId".to_string(), "userName".to_string()],
        weight_millionths: 1_000_000,
    };
    g.add_edge(e).unwrap();
    let retrieved = g.get_edge(&eid("labeled")).unwrap();
    assert_eq!(retrieved.data_labels.len(), 2);
    assert!(retrieved.data_labels.contains(&"userId".to_string()));
}

// ===========================================================================
// 36. Purity ratio in summary
// ===========================================================================

#[test]
fn purity_ratio_all_pure() {
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("A", &[])).unwrap();
    g.register_component(simple_descriptor("B", &[])).unwrap();
    let s = g.summary();
    assert_eq!(s.pure_component_count, 2);
    assert_eq!(s.purity_ratio_millionths, 1_000_000);
}

#[test]
fn purity_ratio_half_pure() {
    use std::collections::BTreeMap;
    let mut g = StaticAnalysisGraph::new();
    g.register_component(simple_descriptor("Pure", &[]))
        .unwrap();
    g.register_component(ComponentDescriptor {
        id: cid("Impure"),
        is_function_component: true,
        module_path: "src/Impure.tsx".to_string(),
        export_name: None,
        hook_slots: vec![hook_slot(0, HookKind::State, "x")],
        props: BTreeMap::new(),
        consumed_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_boundary: CapabilityBoundary::pure_component(),
        is_pure: false,
        content_hash: ContentHash::compute(b"Impure"),
        children: Vec::new(),
    })
    .unwrap();
    let s = g.summary();
    assert_eq!(s.purity_ratio_millionths, 500_000);
}

// ===========================================================================
// 37. Snapshot hash determinism
// ===========================================================================

#[test]
fn summary_snapshot_hash_deterministic() {
    let build = || {
        let mut g = StaticAnalysisGraph::new();
        g.add_node(component_node("A")).unwrap();
        g.add_node(component_node("B")).unwrap();
        g.add_edge(edge("e1", "A", "B", EdgeKind::RendersChild))
            .unwrap();
        g.register_component(simple_descriptor("A", &["B"]))
            .unwrap();
        g.register_component(simple_descriptor("B", &[])).unwrap();
        g.summary()
    };
    let s1 = build();
    let s2 = build();
    assert_eq!(s1.snapshot_hash, s2.snapshot_hash);
}
