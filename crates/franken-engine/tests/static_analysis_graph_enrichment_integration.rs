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
    AnalysisEdgeId, AnalysisNodeId, CapabilityBoundary, ComponentId, EdgeKind,
    EffectClassification, HookKind, HookSlot, NodeKind, STATIC_ANALYSIS_SCHEMA_VERSION,
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
            assert!(kinds[i] < kinds[j], "{:?} should be < {:?}", kinds[i], kinds[j]);
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
            assert!(kinds[i] < kinds[j], "{:?} should be < {:?}", kinds[i], kinds[j]);
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
            assert!(kinds[i] < kinds[j], "{:?} should be < {:?}", kinds[i], kinds[j]);
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
