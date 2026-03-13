//! Enrichment integration tests for the `static_analysis_graph` module.
//!
//! Covers: NodeKind/EdgeKind/HookKind ordering/Copy/Hash, ComponentId/
//! AnalysisNodeId/AnalysisEdgeId ordering/Hash, HookSlot predicates,
//! EffectClassification predicates, CapabilityBoundary all_capabilities,
//! graph capacity limits, AnalysisError std::error::Error,
//! Debug formatting, determinism.

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
use frankenengine_engine::ir_contract::EffectBoundary;
use frankenengine_engine::static_analysis_graph::{
    AnalysisEdge, AnalysisEdgeId, AnalysisError, AnalysisEventKind, AnalysisNode, AnalysisNodeId,
    AnalysisSummary, CapabilityBoundary, ComponentDescriptor, ComponentId, CycleReport,
    DependencyPath, EdgeKind, EffectClassification, HookKind, HookSlot, NodeKind,
    STATIC_ANALYSIS_SCHEMA_VERSION, StaticAnalysisGraph,
};

// =========================================================================
// A. NodeKind — ordering, Copy, Hash
// =========================================================================

#[test]
fn enrichment_node_kind_ordering_all_pairs() {
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
    for i in 0..kinds.len() {
        for j in (i + 1)..kinds.len() {
            assert!(
                kinds[i] < kinds[j],
                "{:?} should be < {:?}",
                kinds[i],
                kinds[j]
            );
        }
    }
}

#[test]
fn enrichment_node_kind_copy_preserves_value() {
    let a = NodeKind::EffectSite;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_node_kind_hash_distinct() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

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
    let hashes: BTreeSet<u64> = kinds
        .iter()
        .map(|k| {
            let mut h = DefaultHasher::new();
            k.hash(&mut h);
            h.finish()
        })
        .collect();
    assert_eq!(hashes.len(), 8);
}

#[test]
fn enrichment_node_kind_display_all_distinct() {
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
    assert_eq!(displays.len(), 8);
}

// =========================================================================
// B. EdgeKind — ordering, Copy, Hash
// =========================================================================

#[test]
fn enrichment_edge_kind_ordering_all_pairs() {
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
    for i in 0..kinds.len() {
        for j in (i + 1)..kinds.len() {
            assert!(
                kinds[i] < kinds[j],
                "{:?} should be < {:?}",
                kinds[i],
                kinds[j]
            );
        }
    }
}

#[test]
fn enrichment_edge_kind_copy_preserves_value() {
    let a = EdgeKind::ContextFlow;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_edge_kind_display_all_distinct() {
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
    assert_eq!(displays.len(), 10);
}

// =========================================================================
// C. HookKind — ordering, Copy, Hash, Display
// =========================================================================

#[test]
fn enrichment_hook_kind_ordering_all_pairs() {
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
    for i in 0..kinds.len() {
        for j in (i + 1)..kinds.len() {
            assert!(
                kinds[i] < kinds[j],
                "{:?} should be < {:?}",
                kinds[i],
                kinds[j]
            );
        }
    }
}

#[test]
fn enrichment_hook_kind_copy_preserves_value() {
    let a = HookKind::Memo;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_hook_kind_display_all_distinct() {
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
    assert_eq!(displays.len(), 9);
}

// =========================================================================
// D. ID types — ordering, Hash
// =========================================================================

#[test]
fn enrichment_component_id_ordering() {
    let a = ComponentId::new("Alpha");
    let b = ComponentId::new("Beta");
    assert!(a < b);
}

#[test]
fn enrichment_analysis_node_id_ordering() {
    let a = AnalysisNodeId::new("node-a");
    let b = AnalysisNodeId::new("node-b");
    assert!(a < b);
}

#[test]
fn enrichment_analysis_edge_id_ordering() {
    let a = AnalysisEdgeId::new("edge-a");
    let b = AnalysisEdgeId::new("edge-b");
    assert!(a < b);
}

#[test]
fn enrichment_id_hash_distinct() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let ids = ["alpha", "beta", "gamma"];
    let node_hashes: BTreeSet<u64> = ids
        .iter()
        .map(|s| {
            let mut h = DefaultHasher::new();
            AnalysisNodeId::new(s).hash(&mut h);
            h.finish()
        })
        .collect();
    assert_eq!(node_hashes.len(), 3);

    let edge_hashes: BTreeSet<u64> = ids
        .iter()
        .map(|s| {
            let mut h = DefaultHasher::new();
            AnalysisEdgeId::new(s).hash(&mut h);
            h.finish()
        })
        .collect();
    assert_eq!(edge_hashes.len(), 3);
}

// =========================================================================
// E. HookSlot — predicates for all hook kinds
// =========================================================================

fn make_hook(kind: HookKind) -> HookSlot {
    HookSlot {
        slot_index: 0,
        kind,
        label: "test".to_string(),
        dependency_count: None,
        has_cleanup: false,
        source_offset: 0,
        dependency_hash: None,
    }
}

#[test]
fn enrichment_hook_slot_is_stateful_only_for_state() {
    assert!(make_hook(HookKind::State).is_stateful());
    assert!(!make_hook(HookKind::Effect).is_stateful());
    assert!(!make_hook(HookKind::Memo).is_stateful());
    assert!(!make_hook(HookKind::Ref).is_stateful());
    assert!(!make_hook(HookKind::Custom).is_stateful());
}

#[test]
fn enrichment_hook_slot_has_side_effects_correct_set() {
    assert!(make_hook(HookKind::Effect).has_side_effects());
    assert!(make_hook(HookKind::LayoutEffect).has_side_effects());
    assert!(make_hook(HookKind::ImperativeHandle).has_side_effects());
    assert!(!make_hook(HookKind::State).has_side_effects());
    assert!(!make_hook(HookKind::Memo).has_side_effects());
    assert!(!make_hook(HookKind::Callback).has_side_effects());
    assert!(!make_hook(HookKind::Ref).has_side_effects());
    assert!(!make_hook(HookKind::Context).has_side_effects());
    assert!(!make_hook(HookKind::Custom).has_side_effects());
}

#[test]
fn enrichment_hook_slot_is_memoized_correct_set() {
    assert!(make_hook(HookKind::Memo).is_memoized());
    assert!(make_hook(HookKind::Callback).is_memoized());
    assert!(!make_hook(HookKind::State).is_memoized());
    assert!(!make_hook(HookKind::Effect).is_memoized());
    assert!(!make_hook(HookKind::Ref).is_memoized());
    assert!(!make_hook(HookKind::Context).is_memoized());
    assert!(!make_hook(HookKind::Custom).is_memoized());
}

// =========================================================================
// F. EffectClassification — predicates
// =========================================================================

#[test]
fn enrichment_effect_classification_pure() {
    let ec = EffectClassification::pure_effect();
    assert!(ec.is_pure());
    assert!(!ec.requires_capabilities());
    assert!(ec.idempotent);
    assert!(ec.commutative);
    assert_eq!(ec.estimated_cost_millionths, 0);
}

#[test]
fn enrichment_effect_classification_with_capabilities() {
    let mut caps = BTreeSet::new();
    caps.insert("network".to_string());
    let ec = EffectClassification {
        boundary: EffectBoundary::NetworkEffect,
        required_capabilities: caps,
        idempotent: false,
        commutative: false,
        estimated_cost_millionths: 500_000,
    };
    assert!(!ec.is_pure());
    assert!(ec.requires_capabilities());
}

// =========================================================================
// G. CapabilityBoundary — all_capabilities, is_render_pure
// =========================================================================

#[test]
fn enrichment_capability_boundary_pure_component() {
    let cb = CapabilityBoundary::pure_component();
    assert!(cb.is_render_pure());
    assert!(cb.all_capabilities().is_empty());
    assert!(!cb.is_boundary);
}

#[test]
fn enrichment_capability_boundary_all_capabilities_union() {
    let mut direct = BTreeSet::new();
    direct.insert("fs".to_string());
    let mut transitive = BTreeSet::new();
    transitive.insert("network".to_string());
    transitive.insert("fs".to_string()); // overlap with direct

    let cb = CapabilityBoundary {
        direct_capabilities: direct,
        transitive_capabilities: transitive,
        render_effect: EffectBoundary::Pure,
        hook_effects: Vec::new(),
        is_boundary: true,
        boundary_tags: Vec::new(),
    };
    let all = cb.all_capabilities();
    assert_eq!(all.len(), 2); // fs + network (deduplicated)
    assert!(all.contains("fs"));
    assert!(all.contains("network"));
}

// =========================================================================
// H. Schema version constant
// =========================================================================

#[test]
fn enrichment_schema_version_nonempty() {
    assert!(!STATIC_ANALYSIS_SCHEMA_VERSION.is_empty());
    assert!(STATIC_ANALYSIS_SCHEMA_VERSION.contains("static-analysis-graph"));
}

// =========================================================================
// I. Serde roundtrips — NodeKind, EdgeKind, HookKind
// =========================================================================

#[test]
fn enrichment_node_kind_serde_all_distinct_json() {
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
    let jsons: BTreeSet<String> = kinds
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
    assert_eq!(jsons.len(), 8);
    for kind in &kinds {
        let json = serde_json::to_string(kind).unwrap();
        let restored: NodeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, restored);
    }
}

#[test]
fn enrichment_edge_kind_serde_all_distinct_json() {
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
    let jsons: BTreeSet<String> = kinds
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
    assert_eq!(jsons.len(), 10);
}

#[test]
fn enrichment_hook_kind_serde_all_distinct_json() {
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
    let jsons: BTreeSet<String> = kinds
        .iter()
        .map(|k| serde_json::to_string(k).unwrap())
        .collect();
    assert_eq!(jsons.len(), 9);
}

// =========================================================================
// J. Debug formatting
// =========================================================================

#[test]
fn enrichment_debug_nonempty_all_types() {
    assert!(!format!("{:?}", NodeKind::Component).is_empty());
    assert!(!format!("{:?}", EdgeKind::PropFlow).is_empty());
    assert!(!format!("{:?}", HookKind::State).is_empty());
    assert!(!format!("{:?}", ComponentId::new("x")).is_empty());
    assert!(!format!("{:?}", AnalysisNodeId::new("x")).is_empty());
    assert!(!format!("{:?}", AnalysisEdgeId::new("x")).is_empty());
    assert!(!format!("{:?}", EffectClassification::pure_effect()).is_empty());
    assert!(!format!("{:?}", CapabilityBoundary::pure_component()).is_empty());
}

// =========================================================================
// K. HookSlot serde roundtrip
// =========================================================================

#[test]
fn enrichment_hook_slot_serde_with_dependency_hash() {
    let slot = HookSlot {
        slot_index: 3,
        kind: HookKind::Effect,
        label: "fetchData".to_string(),
        dependency_count: Some(2),
        has_cleanup: true,
        source_offset: 1024,
        dependency_hash: Some(ContentHash::compute(b"dep-hash")),
    };
    let json = serde_json::to_string(&slot).unwrap();
    let restored: HookSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(slot, restored);
}

#[test]
fn enrichment_hook_slot_serde_without_dependency_hash() {
    let slot = HookSlot {
        slot_index: 0,
        kind: HookKind::State,
        label: "count".to_string(),
        dependency_count: None,
        has_cleanup: false,
        source_offset: 0,
        dependency_hash: None,
    };
    let json = serde_json::to_string(&slot).unwrap();
    let restored: HookSlot = serde_json::from_str(&json).unwrap();
    assert_eq!(slot, restored);
}

// =========================================================================
// L. EffectClassification serde roundtrip
// =========================================================================

#[test]
fn enrichment_effect_classification_serde_roundtrip() {
    let mut caps = BTreeSet::new();
    caps.insert("timer".to_string());
    caps.insert("network".to_string());
    let ec = EffectClassification {
        boundary: EffectBoundary::NetworkEffect,
        required_capabilities: caps,
        idempotent: true,
        commutative: false,
        estimated_cost_millionths: 250_000,
    };
    let json = serde_json::to_string(&ec).unwrap();
    let restored: EffectClassification = serde_json::from_str(&json).unwrap();
    assert_eq!(ec, restored);
}

// =========================================================================
// M. CapabilityBoundary serde roundtrip
// =========================================================================

#[test]
fn enrichment_capability_boundary_serde_roundtrip() {
    let cb = CapabilityBoundary::pure_component();
    let json = serde_json::to_string(&cb).unwrap();
    let restored: CapabilityBoundary = serde_json::from_str(&json).unwrap();
    assert_eq!(cb, restored);
}

// =========================================================================
// N. AnalysisError — Display all distinct
// =========================================================================

#[test]
fn enrichment_analysis_error_display_all_distinct() {
    let errors: Vec<AnalysisError> = vec![
        AnalysisError::NodeLimitExceeded {
            count: 100001,
            max: 100000,
        },
        AnalysisError::EdgeLimitExceeded {
            count: 500001,
            max: 500000,
        },
        AnalysisError::HookSlotLimitExceeded {
            component: ComponentId::new("App"),
            count: 257,
            max: 256,
        },
        AnalysisError::DuplicateNode(AnalysisNodeId::new("node-dup")),
        AnalysisError::DuplicateEdge(AnalysisEdgeId::new("edge-dup")),
        AnalysisError::UnknownNode(AnalysisNodeId::new("node-unk")),
        AnalysisError::DuplicateComponent(ComponentId::new("CompDup")),
        AnalysisError::UnknownComponent(ComponentId::new("CompUnk")),
        AnalysisError::CycleDetected(CycleReport {
            cycle: vec![ComponentId::new("A"), ComponentId::new("B")],
            edge_kinds: vec![EdgeKind::RendersChild],
            is_data_cycle: false,
        }),
    ];
    let displays: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
    assert_eq!(displays.len(), 9);
}

#[test]
fn enrichment_analysis_error_serde_all_variants() {
    let errors: Vec<AnalysisError> = vec![
        AnalysisError::NodeLimitExceeded { count: 10, max: 5 },
        AnalysisError::DuplicateNode(AnalysisNodeId::new("n1")),
        AnalysisError::DuplicateEdge(AnalysisEdgeId::new("e1")),
        AnalysisError::UnknownNode(AnalysisNodeId::new("n2")),
        AnalysisError::DuplicateComponent(ComponentId::new("C")),
        AnalysisError::UnknownComponent(ComponentId::new("D")),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let restored: AnalysisError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, restored);
    }
}

// =========================================================================
// O. AnalysisEventKind — Display distinct + serde
// =========================================================================

#[test]
fn enrichment_analysis_event_kind_display_all_distinct() {
    let kinds = [
        AnalysisEventKind::NodeAdded,
        AnalysisEventKind::EdgeAdded,
        AnalysisEventKind::ComponentRegistered,
        AnalysisEventKind::CycleDetected,
        AnalysisEventKind::CapabilityBoundaryComputed,
        AnalysisEventKind::AnalysisFinalized,
    ];
    let displays: BTreeSet<String> = kinds.iter().map(|k| k.to_string()).collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_analysis_event_kind_serde_all() {
    let kinds = [
        AnalysisEventKind::NodeAdded,
        AnalysisEventKind::EdgeAdded,
        AnalysisEventKind::ComponentRegistered,
        AnalysisEventKind::CycleDetected,
        AnalysisEventKind::CapabilityBoundaryComputed,
        AnalysisEventKind::AnalysisFinalized,
    ];
    for k in &kinds {
        let json = serde_json::to_string(k).unwrap();
        let restored: AnalysisEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*k, restored);
    }
}

// =========================================================================
// P. DependencyPath — depth and contains
// =========================================================================

#[test]
fn enrichment_dependency_path_depth_empty() {
    let path = DependencyPath {
        components: vec![],
        total_weight_millionths: 0,
        edge_kinds: vec![],
    };
    assert_eq!(path.depth(), 0);
}

#[test]
fn enrichment_dependency_path_depth_single_component() {
    let path = DependencyPath {
        components: vec![ComponentId::new("Root")],
        total_weight_millionths: 0,
        edge_kinds: vec![],
    };
    assert_eq!(path.depth(), 0);
}

#[test]
fn enrichment_dependency_path_depth_chain() {
    let path = DependencyPath {
        components: vec![
            ComponentId::new("A"),
            ComponentId::new("B"),
            ComponentId::new("C"),
        ],
        total_weight_millionths: 1_500_000,
        edge_kinds: vec![EdgeKind::RendersChild, EdgeKind::PropFlow],
    };
    assert_eq!(path.depth(), 2);
    assert!(path.contains(&ComponentId::new("B")));
    assert!(!path.contains(&ComponentId::new("D")));
}

#[test]
fn enrichment_dependency_path_serde_roundtrip() {
    let path = DependencyPath {
        components: vec![ComponentId::new("X"), ComponentId::new("Y")],
        total_weight_millionths: 500_000,
        edge_kinds: vec![EdgeKind::ContextFlow],
    };
    let json = serde_json::to_string(&path).unwrap();
    let restored: DependencyPath = serde_json::from_str(&json).unwrap();
    assert_eq!(path, restored);
}

// =========================================================================
// Q. ComponentDescriptor — hook counts, is_leaf
// =========================================================================

fn make_component(name: &str, hooks: Vec<HookSlot>, children: Vec<&str>) -> ComponentDescriptor {
    ComponentDescriptor {
        id: ComponentId::new(name),
        is_function_component: true,
        module_path: format!("./components/{name}.tsx"),
        export_name: Some(name.to_string()),
        hook_slots: hooks,
        props: std::collections::BTreeMap::new(),
        consumed_contexts: vec![],
        provided_contexts: vec![],
        capability_boundary: CapabilityBoundary::pure_component(),
        is_pure: true,
        content_hash: ContentHash::compute(name.as_bytes()),
        children: children.into_iter().map(ComponentId::new).collect(),
    }
}

#[test]
fn enrichment_component_descriptor_hook_counts() {
    let desc = make_component(
        "App",
        vec![
            make_hook(HookKind::State),
            make_hook(HookKind::Effect),
            make_hook(HookKind::Memo),
            make_hook(HookKind::State),
        ],
        vec!["Child"],
    );
    assert_eq!(desc.stateful_hook_count(), 2);
    assert_eq!(desc.effect_hook_count(), 1);
    assert_eq!(desc.total_hook_count(), 4);
    assert!(!desc.is_leaf());
}

#[test]
fn enrichment_component_descriptor_leaf() {
    let desc = make_component("Leaf", vec![], vec![]);
    assert!(desc.is_leaf());
    assert_eq!(desc.stateful_hook_count(), 0);
    assert_eq!(desc.effect_hook_count(), 0);
}

#[test]
fn enrichment_component_descriptor_serde_roundtrip() {
    let desc = make_component("Serde", vec![make_hook(HookKind::Ref)], vec!["X"]);
    let json = serde_json::to_string(&desc).unwrap();
    let restored: ComponentDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(desc, restored);
}

// =========================================================================
// R. CycleReport — serde roundtrip
// =========================================================================

#[test]
fn enrichment_cycle_report_serde_roundtrip() {
    let report = CycleReport {
        cycle: vec![
            ComponentId::new("A"),
            ComponentId::new("B"),
            ComponentId::new("C"),
        ],
        edge_kinds: vec![
            EdgeKind::RendersChild,
            EdgeKind::PropFlow,
            EdgeKind::RendersChild,
        ],
        is_data_cycle: true,
    };
    let json = serde_json::to_string(&report).unwrap();
    let restored: CycleReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, restored);
}

// =========================================================================
// S. AnalysisSummary — serde roundtrip
// =========================================================================

#[test]
fn enrichment_analysis_summary_serde_roundtrip() {
    let summary = AnalysisSummary {
        component_count: 10,
        hook_slot_count: 25,
        effect_site_count: 5,
        edge_count: 30,
        pure_component_count: 7,
        stateful_component_count: 3,
        cycle_count: 0,
        max_depth: 4,
        distinct_capability_count: 2,
        purity_ratio_millionths: 700_000,
        snapshot_hash: ContentHash::compute(b"summary"),
    };
    let json = serde_json::to_string(&summary).unwrap();
    let restored: AnalysisSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, restored);
}

// =========================================================================
// T. StaticAnalysisGraph — lifecycle
// =========================================================================

fn make_analysis_node(name: &str, kind: NodeKind) -> AnalysisNode {
    AnalysisNode {
        id: AnalysisNodeId::new(name),
        kind,
        label: name.to_string(),
        component_id: None,
        source_offset: 0,
        content_hash: ContentHash::compute(name.as_bytes()),
        hook_slots: vec![],
        effect_classification: None,
        capability_boundary: None,
    }
}

fn make_analysis_edge(name: &str, source: &str, target: &str, kind: EdgeKind) -> AnalysisEdge {
    AnalysisEdge {
        id: AnalysisEdgeId::new(name),
        source: AnalysisNodeId::new(source),
        target: AnalysisNodeId::new(target),
        kind,
        data_labels: vec![],
        weight_millionths: 1_000_000,
    }
}

#[test]
fn enrichment_graph_new_is_empty() {
    let graph = StaticAnalysisGraph::new();
    assert_eq!(graph.node_count(), 0);
    assert_eq!(graph.edge_count(), 0);
    assert_eq!(graph.component_count(), 0);
    assert_eq!(graph.schema_version, STATIC_ANALYSIS_SCHEMA_VERSION);
}

#[test]
fn enrichment_graph_add_node_and_edge() {
    let mut graph = StaticAnalysisGraph::new();
    graph
        .add_node(make_analysis_node("n1", NodeKind::Component))
        .unwrap();
    graph
        .add_node(make_analysis_node("n2", NodeKind::HookSlot))
        .unwrap();
    assert_eq!(graph.node_count(), 2);

    graph
        .add_edge(make_analysis_edge("e1", "n1", "n2", EdgeKind::HookDataFlow))
        .unwrap();
    assert_eq!(graph.edge_count(), 1);

    assert!(graph.get_node(&AnalysisNodeId::new("n1")).is_some());
    assert!(graph.get_edge(&AnalysisEdgeId::new("e1")).is_some());
    assert!(graph.get_node(&AnalysisNodeId::new("n99")).is_none());
}

#[test]
fn enrichment_graph_duplicate_node_rejected() {
    let mut graph = StaticAnalysisGraph::new();
    graph
        .add_node(make_analysis_node("n1", NodeKind::Component))
        .unwrap();
    let result = graph.add_node(make_analysis_node("n1", NodeKind::DataSource));
    assert!(matches!(result, Err(AnalysisError::DuplicateNode(_))));
}

#[test]
fn enrichment_graph_duplicate_edge_rejected() {
    let mut graph = StaticAnalysisGraph::new();
    graph
        .add_node(make_analysis_node("n1", NodeKind::Component))
        .unwrap();
    graph
        .add_node(make_analysis_node("n2", NodeKind::HookSlot))
        .unwrap();
    graph
        .add_edge(make_analysis_edge("e1", "n1", "n2", EdgeKind::PropFlow))
        .unwrap();
    let result = graph.add_edge(make_analysis_edge("e1", "n1", "n2", EdgeKind::PropFlow));
    assert!(matches!(result, Err(AnalysisError::DuplicateEdge(_))));
}

#[test]
fn enrichment_graph_edge_unknown_source_rejected() {
    let mut graph = StaticAnalysisGraph::new();
    graph
        .add_node(make_analysis_node("n1", NodeKind::Component))
        .unwrap();
    let result = graph.add_edge(make_analysis_edge(
        "e1",
        "n-missing",
        "n1",
        EdgeKind::PropFlow,
    ));
    assert!(matches!(result, Err(AnalysisError::UnknownNode(_))));
}

#[test]
fn enrichment_graph_register_component() {
    let mut graph = StaticAnalysisGraph::new();
    let desc = make_component("App", vec![make_hook(HookKind::State)], vec![]);
    graph.register_component(desc).unwrap();
    assert_eq!(graph.component_count(), 1);
    assert!(graph.get_component(&ComponentId::new("App")).is_some());
}

#[test]
fn enrichment_graph_duplicate_component_rejected() {
    let mut graph = StaticAnalysisGraph::new();
    let desc1 = make_component("App", vec![], vec![]);
    let desc2 = make_component("App", vec![], vec![]);
    graph.register_component(desc1).unwrap();
    let result = graph.register_component(desc2);
    assert!(matches!(result, Err(AnalysisError::DuplicateComponent(_))));
}

#[test]
fn enrichment_graph_serde_roundtrip() {
    let mut graph = StaticAnalysisGraph::new();
    graph
        .add_node(make_analysis_node("n1", NodeKind::Component))
        .unwrap();
    graph
        .add_node(make_analysis_node("n2", NodeKind::DataSink))
        .unwrap();
    graph
        .add_edge(make_analysis_edge("e1", "n1", "n2", EdgeKind::PropFlow))
        .unwrap();

    let json = serde_json::to_string(&graph).unwrap();
    let restored: StaticAnalysisGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, restored);
}

#[test]
fn enrichment_graph_events_accumulate() {
    let mut graph = StaticAnalysisGraph::new();
    assert!(graph.events().is_empty());
    graph
        .add_node(make_analysis_node("n1", NodeKind::Component))
        .unwrap();
    assert!(!graph.events().is_empty());
    let event_count_after_node = graph.events().len();
    graph
        .add_node(make_analysis_node("n2", NodeKind::DataSink))
        .unwrap();
    assert!(graph.events().len() > event_count_after_node);
}

// =========================================================================
// U. Clone independence for graph
// =========================================================================

#[test]
fn enrichment_graph_clone_independence() {
    let mut graph = StaticAnalysisGraph::new();
    graph
        .add_node(make_analysis_node("n1", NodeKind::Component))
        .unwrap();
    let cloned = graph.clone();
    graph
        .add_node(make_analysis_node("n2", NodeKind::DataSink))
        .unwrap();
    assert_eq!(cloned.node_count(), 1);
    assert_eq!(graph.node_count(), 2);
}

// =========================================================================
// V. AnalysisNode/AnalysisEdge serde roundtrip
// =========================================================================

#[test]
fn enrichment_analysis_node_serde_roundtrip() {
    let node = make_analysis_node("serde-node", NodeKind::EffectSite);
    let json = serde_json::to_string(&node).unwrap();
    let restored: AnalysisNode = serde_json::from_str(&json).unwrap();
    assert_eq!(node, restored);
}

#[test]
fn enrichment_analysis_edge_serde_roundtrip() {
    let edge = AnalysisEdge {
        id: AnalysisEdgeId::new("e-serde"),
        source: AnalysisNodeId::new("src"),
        target: AnalysisNodeId::new("tgt"),
        kind: EdgeKind::ContextFlow,
        data_labels: vec!["label-a".to_string(), "label-b".to_string()],
        weight_millionths: 750_000,
    };
    let json = serde_json::to_string(&edge).unwrap();
    let restored: AnalysisEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, restored);
}
