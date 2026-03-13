#![forbid(unsafe_code)]
//! Enrichment integration tests for `global_coherence_checker` (FRX-14.2).
//!
//! Covers gaps not in `global_coherence_checker_integration.rs` (117 tests):
//! - Clone independence for compound types
//! - BTreeSet ordering for enums with Ord
//! - Serde roundtrips for all public types
//! - Debug nonempty
//! - Display for all enum variants
//! - Default coverage
//! - JSON field-name stability
//! - SeverityScore boundary semantics
//! - CompositionGraph edge validation and query methods
//! - CoherenceCheckResult accessor coverage
//! - CoherenceError Display for all variants
//! - CoherenceOutcome ordering

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

use frankenengine_engine::global_coherence_checker::{
    CoherenceCheckResult, CoherenceError, CoherenceOutcome, CoherenceViolationKind,
    CompositionEdge, CompositionEdgeKind, CompositionGraph, DEBT_CAPABILITY_GAP, DEBT_EFFECT_CYCLE,
    DEBT_HOOK_CLEANUP_MISMATCH, DEBT_HYDRATION_BOUNDARY_CONFLICT, DEBT_SUSPENSE_BOUNDARY_CONFLICT,
    DEBT_UNRESOLVED_CONTEXT, GLOBAL_COHERENCE_BEAD_ID, GLOBAL_COHERENCE_SCHEMA_VERSION,
    GlobalCoherenceChecker, SeverityScore,
};
use frankenengine_engine::hash_tiers::ContentHash;

// ===========================================================================
// Section 1: CompositionEdgeKind Display
// ===========================================================================

#[test]
fn enrichment_edge_kind_display_parent_child() {
    assert_eq!(CompositionEdgeKind::ParentChild.to_string(), "parent-child");
}

#[test]
fn enrichment_edge_kind_display_context_flow() {
    assert_eq!(CompositionEdgeKind::ContextFlow.to_string(), "context-flow");
}

#[test]
fn enrichment_edge_kind_display_capability_boundary() {
    assert_eq!(
        CompositionEdgeKind::CapabilityBoundary.to_string(),
        "capability-boundary"
    );
}

#[test]
fn enrichment_edge_kind_display_suspense_boundary() {
    assert_eq!(
        CompositionEdgeKind::SuspenseBoundary.to_string(),
        "suspense-boundary"
    );
}

#[test]
fn enrichment_edge_kind_display_hydration_boundary() {
    assert_eq!(
        CompositionEdgeKind::HydrationBoundary.to_string(),
        "hydration-boundary"
    );
}

#[test]
fn enrichment_edge_kind_display_effect_dependency() {
    assert_eq!(
        CompositionEdgeKind::EffectDependency.to_string(),
        "effect-dependency"
    );
}

// ===========================================================================
// Section 2: CompositionEdgeKind serde roundtrip
// ===========================================================================

#[test]
fn enrichment_edge_kind_serde_roundtrip_all_variants() {
    let variants = [
        CompositionEdgeKind::ParentChild,
        CompositionEdgeKind::ContextFlow,
        CompositionEdgeKind::CapabilityBoundary,
        CompositionEdgeKind::SuspenseBoundary,
        CompositionEdgeKind::HydrationBoundary,
        CompositionEdgeKind::EffectDependency,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let recovered: CompositionEdgeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &recovered);
    }
}

// ===========================================================================
// Section 3: CompositionEdgeKind BTreeSet ordering
// ===========================================================================

#[test]
fn enrichment_edge_kind_btreeset_ordering_and_dedup() {
    let mut set = BTreeSet::new();
    set.insert(CompositionEdgeKind::EffectDependency);
    set.insert(CompositionEdgeKind::ParentChild);
    set.insert(CompositionEdgeKind::ParentChild); // dup
    set.insert(CompositionEdgeKind::ContextFlow);
    assert_eq!(set.len(), 3);
}

// ===========================================================================
// Section 4: CompositionEdge serde roundtrip
// ===========================================================================

#[test]
fn enrichment_composition_edge_serde_roundtrip() {
    let edge = CompositionEdge {
        from_component: "App".to_string(),
        to_component: "Header".to_string(),
        kind: CompositionEdgeKind::ParentChild,
        label: "renders".to_string(),
    };
    let json = serde_json::to_string(&edge).unwrap();
    let recovered: CompositionEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, recovered);
}

#[test]
fn enrichment_composition_edge_clone_independence() {
    let original = CompositionEdge {
        from_component: "A".to_string(),
        to_component: "B".to_string(),
        kind: CompositionEdgeKind::ContextFlow,
        label: "theme".to_string(),
    };
    let mut cloned = original.clone();
    cloned.from_component = "Z".to_string();
    cloned.label = "mutated".to_string();
    assert_eq!(original.from_component, "A");
    assert_eq!(original.label, "theme");
}

#[test]
fn enrichment_composition_edge_json_fields() {
    let edge = CompositionEdge {
        from_component: "A".to_string(),
        to_component: "B".to_string(),
        kind: CompositionEdgeKind::ParentChild,
        label: "l".to_string(),
    };
    let json = serde_json::to_string(&edge).unwrap();
    assert!(json.contains("\"from_component\""));
    assert!(json.contains("\"to_component\""));
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"label\""));
}

// ===========================================================================
// Section 5: CompositionGraph
// ===========================================================================

#[test]
fn enrichment_graph_default_is_empty() {
    let graph = CompositionGraph::default();
    assert_eq!(graph.component_count(), 0);
    assert_eq!(graph.edge_count(), 0);
}

#[test]
fn enrichment_graph_new_is_empty() {
    let graph = CompositionGraph::new();
    assert_eq!(graph.component_count(), 0);
    assert_eq!(graph.edge_count(), 0);
}

#[test]
fn enrichment_graph_add_component_and_edge() {
    let mut graph = CompositionGraph::new();
    graph.add_component("A".to_string()).unwrap();
    graph.add_component("B".to_string()).unwrap();
    assert_eq!(graph.component_count(), 2);

    graph
        .add_edge(CompositionEdge {
            from_component: "A".to_string(),
            to_component: "B".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "renders".to_string(),
        })
        .unwrap();
    assert_eq!(graph.edge_count(), 1);
}

#[test]
fn enrichment_graph_add_edge_unknown_from_component_err() {
    let mut graph = CompositionGraph::new();
    graph.add_component("B".to_string()).unwrap();
    let err = graph
        .add_edge(CompositionEdge {
            from_component: "UNKNOWN".to_string(),
            to_component: "B".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "".to_string(),
        })
        .unwrap_err();
    assert!(matches!(err, CoherenceError::UnknownComponent(_)));
}

#[test]
fn enrichment_graph_add_edge_unknown_to_component_err() {
    let mut graph = CompositionGraph::new();
    graph.add_component("A".to_string()).unwrap();
    let err = graph
        .add_edge(CompositionEdge {
            from_component: "A".to_string(),
            to_component: "UNKNOWN".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "".to_string(),
        })
        .unwrap_err();
    assert!(matches!(err, CoherenceError::UnknownComponent(_)));
}

#[test]
fn enrichment_graph_children_of() {
    let mut graph = CompositionGraph::new();
    graph.add_component("App".to_string()).unwrap();
    graph.add_component("Header".to_string()).unwrap();
    graph.add_component("Footer".to_string()).unwrap();
    graph
        .add_edge(CompositionEdge {
            from_component: "App".to_string(),
            to_component: "Header".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "".to_string(),
        })
        .unwrap();
    graph
        .add_edge(CompositionEdge {
            from_component: "App".to_string(),
            to_component: "Footer".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "".to_string(),
        })
        .unwrap();
    let children = graph.children_of("App");
    assert_eq!(children.len(), 2);
    assert!(children.contains(&"Header".to_string()));
    assert!(children.contains(&"Footer".to_string()));
}

#[test]
fn enrichment_graph_parents_of() {
    let mut graph = CompositionGraph::new();
    graph.add_component("App".to_string()).unwrap();
    graph.add_component("Child".to_string()).unwrap();
    graph
        .add_edge(CompositionEdge {
            from_component: "App".to_string(),
            to_component: "Child".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "".to_string(),
        })
        .unwrap();
    let parents = graph.parents_of("Child");
    assert_eq!(parents, vec!["App".to_string()]);
}

#[test]
fn enrichment_graph_children_of_nonexistent_empty() {
    let graph = CompositionGraph::new();
    assert!(graph.children_of("nonexistent").is_empty());
}

#[test]
fn enrichment_graph_adjacency_for_kind_filters() {
    let mut graph = CompositionGraph::new();
    graph.add_component("A".to_string()).unwrap();
    graph.add_component("B".to_string()).unwrap();
    graph.add_component("C".to_string()).unwrap();
    graph
        .add_edge(CompositionEdge {
            from_component: "A".to_string(),
            to_component: "B".to_string(),
            kind: CompositionEdgeKind::ParentChild,
            label: "".to_string(),
        })
        .unwrap();
    graph
        .add_edge(CompositionEdge {
            from_component: "A".to_string(),
            to_component: "C".to_string(),
            kind: CompositionEdgeKind::ContextFlow,
            label: "".to_string(),
        })
        .unwrap();

    let parent_adj = graph.adjacency_for_kind(&CompositionEdgeKind::ParentChild);
    assert_eq!(parent_adj.get("A").unwrap().len(), 1);
    assert_eq!(parent_adj.get("A").unwrap()[0], "B");

    let context_adj = graph.adjacency_for_kind(&CompositionEdgeKind::ContextFlow);
    assert_eq!(context_adj.get("A").unwrap().len(), 1);
    assert_eq!(context_adj.get("A").unwrap()[0], "C");
}

#[test]
fn enrichment_graph_serde_roundtrip() {
    let mut graph = CompositionGraph::new();
    graph.add_component("X".to_string()).unwrap();
    graph.add_component("Y".to_string()).unwrap();
    graph
        .add_edge(CompositionEdge {
            from_component: "X".to_string(),
            to_component: "Y".to_string(),
            kind: CompositionEdgeKind::EffectDependency,
            label: "dep".to_string(),
        })
        .unwrap();
    let json = serde_json::to_string(&graph).unwrap();
    let recovered: CompositionGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(graph, recovered);
    assert_eq!(recovered.component_count(), 2);
    assert_eq!(recovered.edge_count(), 1);
}

#[test]
fn enrichment_graph_clone_independence() {
    let mut original = CompositionGraph::new();
    original.add_component("A".to_string()).unwrap();
    let cloned = original.clone();
    original.add_component("B".to_string()).unwrap();
    assert_eq!(cloned.component_count(), 1);
    assert_eq!(original.component_count(), 2);
}

// ===========================================================================
// Section 6: SeverityScore
// ===========================================================================

#[test]
fn enrichment_severity_score_levels() {
    assert_eq!(SeverityScore::critical().0, 1_000_000);
    assert_eq!(SeverityScore::high().0, 750_000);
    assert_eq!(SeverityScore::medium().0, 500_000);
    assert_eq!(SeverityScore::low().0, 250_000);
    assert_eq!(SeverityScore::info().0, 100_000);
}

#[test]
fn enrichment_severity_score_is_blocking() {
    assert!(SeverityScore::critical().is_blocking());
    assert!(SeverityScore::high().is_blocking());
    assert!(SeverityScore::medium().is_blocking());
    assert!(!SeverityScore::low().is_blocking());
    assert!(!SeverityScore::info().is_blocking());
}

#[test]
fn enrichment_severity_score_blocking_boundary() {
    assert!(SeverityScore(500_000).is_blocking());
    assert!(!SeverityScore(499_999).is_blocking());
}

#[test]
fn enrichment_severity_score_serde_roundtrip() {
    for score in [
        SeverityScore::critical(),
        SeverityScore::high(),
        SeverityScore::medium(),
        SeverityScore::low(),
        SeverityScore::info(),
        SeverityScore(0),
        SeverityScore(999_999),
    ] {
        let json = serde_json::to_string(&score).unwrap();
        let recovered: SeverityScore = serde_json::from_str(&json).unwrap();
        assert_eq!(score, recovered);
    }
}

#[test]
fn enrichment_severity_score_clone_independence() {
    let original = SeverityScore::critical();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.0, 1_000_000);
}

#[test]
fn enrichment_severity_score_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(SeverityScore::high());
    set.insert(SeverityScore::info());
    set.insert(SeverityScore::critical());
    set.insert(SeverityScore::info()); // dup
    assert_eq!(set.len(), 3);
    let v: Vec<_> = set.into_iter().collect();
    assert_eq!(v[0], SeverityScore::info());
    assert_eq!(v[2], SeverityScore::critical());
}

// ===========================================================================
// Section 7: CoherenceViolationKind Display
// ===========================================================================

#[test]
fn enrichment_violation_kind_display_unresolved_context() {
    let kind = CoherenceViolationKind::UnresolvedContext {
        consumer: "MyComponent".to_string(),
        context_key: "ThemeContext".to_string(),
    };
    let s = kind.to_string();
    assert!(s.contains("unresolved context"));
    assert!(s.contains("MyComponent"));
    assert!(s.contains("ThemeContext"));
}

#[test]
fn enrichment_violation_kind_display_orphaned_provider() {
    let kind = CoherenceViolationKind::OrphanedProvider {
        provider: "ThemeProvider".to_string(),
        context_key: "theme".to_string(),
    };
    let s = kind.to_string();
    assert!(s.contains("orphaned provider"));
    assert!(s.contains("ThemeProvider"));
}

#[test]
fn enrichment_violation_kind_display_capability_gap() {
    let kind = CoherenceViolationKind::CapabilityGap {
        component: "Widget".to_string(),
        missing_capabilities: vec!["network".to_string(), "storage".to_string()],
    };
    let s = kind.to_string();
    assert!(s.contains("capability gap"));
    assert!(s.contains("Widget"));
    assert!(s.contains("network"));
}

#[test]
fn enrichment_violation_kind_display_effect_order_cycle() {
    let kind = CoherenceViolationKind::EffectOrderCycle {
        cycle_participants: vec!["A".to_string(), "B".to_string(), "C".to_string()],
    };
    let s = kind.to_string();
    assert!(s.contains("effect cycle"));
    assert!(s.contains("A -> B -> C"));
}

#[test]
fn enrichment_violation_kind_display_layout_after_passive() {
    let kind = CoherenceViolationKind::LayoutAfterPassive {
        layout_component: "LayoutChild".to_string(),
        passive_component: "PassiveParent".to_string(),
    };
    let s = kind.to_string();
    assert!(s.contains("layout-after-passive"));
    assert!(s.contains("LayoutChild"));
    assert!(s.contains("PassiveParent"));
}

#[test]
fn enrichment_violation_kind_display_suspense_boundary_conflict() {
    let kind = CoherenceViolationKind::SuspenseBoundaryConflict {
        boundary_component: "Suspense".to_string(),
        conflicting_children: vec!["AsyncA".to_string(), "SyncB".to_string()],
        reason: "mix of async and sync".to_string(),
    };
    let s = kind.to_string();
    assert!(s.contains("suspense conflict"));
    assert!(s.contains("Suspense"));
    assert!(s.contains("AsyncA"));
}

#[test]
fn enrichment_violation_kind_display_hydration_boundary_conflict() {
    let kind = CoherenceViolationKind::HydrationBoundaryConflict {
        boundary_component: "HydrationRoot".to_string(),
        conflicting_children: vec!["Child1".to_string()],
        reason: "non-deterministic effects".to_string(),
    };
    let s = kind.to_string();
    assert!(s.contains("hydration conflict"));
    assert!(s.contains("HydrationRoot"));
}

#[test]
fn enrichment_violation_kind_display_hook_cleanup_mismatch() {
    let kind = CoherenceViolationKind::HookCleanupMismatch {
        component_a: "CompA".to_string(),
        component_b: "CompB".to_string(),
        hook_label: "useEffect".to_string(),
    };
    let s = kind.to_string();
    assert!(s.contains("hook cleanup mismatch"));
    assert!(s.contains("CompA"));
    assert!(s.contains("useEffect"));
}

#[test]
fn enrichment_violation_kind_display_duplicate_provider() {
    let kind = CoherenceViolationKind::DuplicateProvider {
        providers: vec!["P1".to_string(), "P2".to_string()],
        context_key: "auth".to_string(),
    };
    let s = kind.to_string();
    assert!(s.contains("duplicate provider"));
    assert!(s.contains("auth"));
}

#[test]
fn enrichment_violation_kind_display_boundary_capability_leak() {
    let kind = CoherenceViolationKind::BoundaryCapabilityLeak {
        boundary: "Boundary".to_string(),
        leaked_capabilities: vec!["cap_x".to_string()],
    };
    let s = kind.to_string();
    assert!(s.contains("boundary leak"));
    assert!(s.contains("cap_x"));
}

// ===========================================================================
// Section 8: CoherenceViolationKind serde roundtrips
// ===========================================================================

#[test]
fn enrichment_violation_kind_serde_unresolved_context() {
    let kind = CoherenceViolationKind::UnresolvedContext {
        consumer: "C".to_string(),
        context_key: "K".to_string(),
    };
    let json = serde_json::to_string(&kind).unwrap();
    let recovered: CoherenceViolationKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, recovered);
}

#[test]
fn enrichment_violation_kind_serde_effect_cycle() {
    let kind = CoherenceViolationKind::EffectOrderCycle {
        cycle_participants: vec!["A".to_string(), "B".to_string()],
    };
    let json = serde_json::to_string(&kind).unwrap();
    let recovered: CoherenceViolationKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, recovered);
}

#[test]
fn enrichment_violation_kind_serde_hook_cleanup() {
    let kind = CoherenceViolationKind::HookCleanupMismatch {
        component_a: "X".to_string(),
        component_b: "Y".to_string(),
        hook_label: "useSync".to_string(),
    };
    let json = serde_json::to_string(&kind).unwrap();
    let recovered: CoherenceViolationKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, recovered);
}

// ===========================================================================
// Section 9: CoherenceOutcome
// ===========================================================================

#[test]
fn enrichment_outcome_display_all_variants() {
    assert_eq!(CoherenceOutcome::Coherent.to_string(), "coherent");
    assert_eq!(
        CoherenceOutcome::CoherentWithWarnings.to_string(),
        "coherent-with-warnings"
    );
    assert_eq!(CoherenceOutcome::Incoherent.to_string(), "incoherent");
    assert_eq!(
        CoherenceOutcome::BudgetExhausted.to_string(),
        "budget-exhausted"
    );
}

#[test]
fn enrichment_outcome_serde_roundtrip() {
    for outcome in [
        CoherenceOutcome::Coherent,
        CoherenceOutcome::CoherentWithWarnings,
        CoherenceOutcome::Incoherent,
        CoherenceOutcome::BudgetExhausted,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let recovered: CoherenceOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, recovered);
    }
}

#[test]
fn enrichment_outcome_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(CoherenceOutcome::BudgetExhausted);
    set.insert(CoherenceOutcome::Coherent);
    set.insert(CoherenceOutcome::Incoherent);
    set.insert(CoherenceOutcome::CoherentWithWarnings);
    set.insert(CoherenceOutcome::Coherent); // dup
    assert_eq!(set.len(), 4);
}

// ===========================================================================
// Section 10: CoherenceError Display
// ===========================================================================

#[test]
fn enrichment_error_display_budget_exhausted() {
    let e = CoherenceError::BudgetExhausted {
        resource: "components".to_string(),
        limit: 50000,
    };
    let s = e.to_string();
    assert!(s.contains("budget exhausted"));
    assert!(s.contains("components"));
    assert!(s.contains("50000"));
}

#[test]
fn enrichment_error_display_unknown_component() {
    let e = CoherenceError::UnknownComponent("Widget".to_string());
    assert!(e.to_string().contains("unknown component"));
    assert!(e.to_string().contains("Widget"));
}

#[test]
fn enrichment_error_display_empty_atlas() {
    assert_eq!(CoherenceError::EmptyAtlas.to_string(), "atlas is empty");
}

#[test]
fn enrichment_error_display_empty_graph() {
    assert_eq!(
        CoherenceError::EmptyGraph.to_string(),
        "composition graph is empty"
    );
}

#[test]
fn enrichment_error_display_atlas_graph_mismatch() {
    let e = CoherenceError::AtlasGraphMismatch {
        atlas_components: 10,
        graph_components: 20,
    };
    let s = e.to_string();
    assert!(s.contains("atlas/graph mismatch"));
    assert!(s.contains("10"));
    assert!(s.contains("20"));
}

#[test]
fn enrichment_error_serde_roundtrip_all_variants() {
    let errors = vec![
        CoherenceError::BudgetExhausted {
            resource: "edges".to_string(),
            limit: 200000,
        },
        CoherenceError::UnknownComponent("X".to_string()),
        CoherenceError::EmptyAtlas,
        CoherenceError::EmptyGraph,
        CoherenceError::AtlasGraphMismatch {
            atlas_components: 5,
            graph_components: 3,
        },
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let recovered: CoherenceError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, &recovered);
    }
}

#[test]
fn enrichment_error_clone_independence() {
    let original = CoherenceError::BudgetExhausted {
        resource: "violations".to_string(),
        limit: 10000,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ===========================================================================
// Section 11: Debug nonempty
// ===========================================================================

#[test]
fn enrichment_edge_kind_debug_nonempty() {
    let dbg = format!("{:?}", CompositionEdgeKind::ParentChild);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("ParentChild"));
}

#[test]
fn enrichment_composition_edge_debug_nonempty() {
    let edge = CompositionEdge {
        from_component: "A".to_string(),
        to_component: "B".to_string(),
        kind: CompositionEdgeKind::ParentChild,
        label: "l".to_string(),
    };
    let dbg = format!("{:?}", edge);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("CompositionEdge"));
}

#[test]
fn enrichment_composition_graph_debug_nonempty() {
    let dbg = format!("{:?}", CompositionGraph::new());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("CompositionGraph"));
}

#[test]
fn enrichment_severity_score_debug_nonempty() {
    let dbg = format!("{:?}", SeverityScore::critical());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("SeverityScore"));
}

#[test]
fn enrichment_coherence_outcome_debug_nonempty() {
    let dbg = format!("{:?}", CoherenceOutcome::Coherent);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("Coherent"));
}

#[test]
fn enrichment_coherence_error_debug_nonempty() {
    let dbg = format!("{:?}", CoherenceError::EmptyAtlas);
    assert!(!dbg.is_empty());
    assert!(dbg.contains("EmptyAtlas"));
}

#[test]
fn enrichment_checker_debug_nonempty() {
    let dbg = format!("{:?}", GlobalCoherenceChecker::new());
    assert!(!dbg.is_empty());
    assert!(dbg.contains("GlobalCoherenceChecker"));
}

// ===========================================================================
// Section 12: Constants
// ===========================================================================

#[test]
fn enrichment_constants_schema_version() {
    assert!(GLOBAL_COHERENCE_SCHEMA_VERSION.contains("v1"));
    assert!(GLOBAL_COHERENCE_SCHEMA_VERSION.contains("global_coherence_checker"));
}

#[test]
fn enrichment_constants_bead_id() {
    assert!(GLOBAL_COHERENCE_BEAD_ID.starts_with("bd-"));
}

#[test]
fn enrichment_debt_codes_distinct() {
    let mut set = BTreeSet::new();
    set.insert(DEBT_UNRESOLVED_CONTEXT);
    set.insert(DEBT_CAPABILITY_GAP);
    set.insert(DEBT_EFFECT_CYCLE);
    set.insert(DEBT_SUSPENSE_BOUNDARY_CONFLICT);
    set.insert(DEBT_HOOK_CLEANUP_MISMATCH);
    set.insert(DEBT_HYDRATION_BOUNDARY_CONFLICT);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_debt_codes_all_start_with_fe_prefix() {
    for code in [
        DEBT_UNRESOLVED_CONTEXT,
        DEBT_CAPABILITY_GAP,
        DEBT_EFFECT_CYCLE,
        DEBT_SUSPENSE_BOUNDARY_CONFLICT,
        DEBT_HOOK_CLEANUP_MISMATCH,
        DEBT_HYDRATION_BOUNDARY_CONFLICT,
    ] {
        assert!(code.starts_with("FE-"), "code {code} missing FE- prefix");
    }
}

// ===========================================================================
// Section 13: GlobalCoherenceChecker construction
// ===========================================================================

#[test]
fn enrichment_checker_new_default() {
    let checker = GlobalCoherenceChecker::new();
    let dbg = format!("{:?}", checker);
    assert!(dbg.contains("10000")); // default budget
}

#[test]
fn enrichment_checker_with_violation_budget() {
    let checker = GlobalCoherenceChecker::new().with_violation_budget(5);
    let dbg = format!("{:?}", checker);
    assert!(dbg.contains("5"));
}

#[test]
fn enrichment_checker_serde_roundtrip() {
    let checker = GlobalCoherenceChecker::new().with_violation_budget(100);
    let json = serde_json::to_string(&checker).unwrap();
    let recovered: GlobalCoherenceChecker = serde_json::from_str(&json).unwrap();
    let dbg = format!("{:?}", recovered);
    assert!(dbg.contains("100"));
}

#[test]
fn enrichment_checker_clone_independence() {
    let original = GlobalCoherenceChecker::new().with_violation_budget(42);
    let cloned = original.clone();
    let dbg_orig = format!("{:?}", original);
    let dbg_clone = format!("{:?}", cloned);
    assert_eq!(dbg_orig, dbg_clone);
}

// ===========================================================================
// Section 14: CoherenceCheckResult accessors
// ===========================================================================

#[test]
fn enrichment_result_is_coherent_for_coherent() {
    let result = CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
        outcome: CoherenceOutcome::Coherent,
        violations: vec![],
        component_count: 5,
        edge_count: 4,
        context_pairs_checked: 3,
        capability_boundaries_checked: 1,
        effect_orderings_checked: 2,
        suspense_boundaries_checked: 0,
        hydration_boundaries_checked: 0,
        total_severity_millionths: 0,
        blocking_violation_count: 0,
        check_epoch: 1,
        result_hash: ContentHash::compute(b"test"),
    };
    assert!(result.is_coherent());
    assert!(result.blocking_violations().is_empty());
    assert!(result.violations_by_debt_code().is_empty());
}

#[test]
fn enrichment_result_is_coherent_for_warnings() {
    let result = CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
        outcome: CoherenceOutcome::CoherentWithWarnings,
        violations: vec![],
        component_count: 1,
        edge_count: 0,
        context_pairs_checked: 0,
        capability_boundaries_checked: 0,
        effect_orderings_checked: 0,
        suspense_boundaries_checked: 0,
        hydration_boundaries_checked: 0,
        total_severity_millionths: 100_000,
        blocking_violation_count: 0,
        check_epoch: 1,
        result_hash: ContentHash::compute(b"test2"),
    };
    assert!(result.is_coherent());
}

#[test]
fn enrichment_result_not_coherent_for_incoherent() {
    let result = CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
        outcome: CoherenceOutcome::Incoherent,
        violations: vec![],
        component_count: 1,
        edge_count: 0,
        context_pairs_checked: 0,
        capability_boundaries_checked: 0,
        effect_orderings_checked: 0,
        suspense_boundaries_checked: 0,
        hydration_boundaries_checked: 0,
        total_severity_millionths: 500_000,
        blocking_violation_count: 1,
        check_epoch: 1,
        result_hash: ContentHash::compute(b"test3"),
    };
    assert!(!result.is_coherent());
}

#[test]
fn enrichment_result_not_coherent_for_budget_exhausted() {
    let result = CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
        outcome: CoherenceOutcome::BudgetExhausted,
        violations: vec![],
        component_count: 1,
        edge_count: 0,
        context_pairs_checked: 0,
        capability_boundaries_checked: 0,
        effect_orderings_checked: 0,
        suspense_boundaries_checked: 0,
        hydration_boundaries_checked: 0,
        total_severity_millionths: 0,
        blocking_violation_count: 0,
        check_epoch: 1,
        result_hash: ContentHash::compute(b"test4"),
    };
    assert!(!result.is_coherent());
}

#[test]
fn enrichment_result_summary_line_format() {
    let result = CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
        outcome: CoherenceOutcome::Coherent,
        violations: vec![],
        component_count: 10,
        edge_count: 15,
        context_pairs_checked: 0,
        capability_boundaries_checked: 0,
        effect_orderings_checked: 0,
        suspense_boundaries_checked: 0,
        hydration_boundaries_checked: 0,
        total_severity_millionths: 0,
        blocking_violation_count: 0,
        check_epoch: 1,
        result_hash: ContentHash::compute(b"summary"),
    };
    let line = result.summary_line();
    assert!(line.contains("coherent"));
    assert!(line.contains("0 violations"));
    assert!(line.contains("10 components"));
    assert!(line.contains("15 edges"));
}

#[test]
fn enrichment_result_serde_roundtrip() {
    let result = CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
        outcome: CoherenceOutcome::Coherent,
        violations: vec![],
        component_count: 2,
        edge_count: 1,
        context_pairs_checked: 0,
        capability_boundaries_checked: 0,
        effect_orderings_checked: 0,
        suspense_boundaries_checked: 0,
        hydration_boundaries_checked: 0,
        total_severity_millionths: 0,
        blocking_violation_count: 0,
        check_epoch: 42,
        result_hash: ContentHash::compute(b"roundtrip"),
    };
    let json = serde_json::to_string(&result).unwrap();
    let recovered: CoherenceCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, recovered);
}

#[test]
fn enrichment_result_json_fields() {
    let result = CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: GLOBAL_COHERENCE_BEAD_ID.to_string(),
        outcome: CoherenceOutcome::Coherent,
        violations: vec![],
        component_count: 0,
        edge_count: 0,
        context_pairs_checked: 0,
        capability_boundaries_checked: 0,
        effect_orderings_checked: 0,
        suspense_boundaries_checked: 0,
        hydration_boundaries_checked: 0,
        total_severity_millionths: 0,
        blocking_violation_count: 0,
        check_epoch: 0,
        result_hash: ContentHash::compute(b"fields"),
    };
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"bead_id\""));
    assert!(json.contains("\"outcome\""));
    assert!(json.contains("\"violations\""));
    assert!(json.contains("\"component_count\""));
    assert!(json.contains("\"edge_count\""));
    assert!(json.contains("\"total_severity_millionths\""));
    assert!(json.contains("\"blocking_violation_count\""));
    assert!(json.contains("\"check_epoch\""));
    assert!(json.contains("\"result_hash\""));
}
