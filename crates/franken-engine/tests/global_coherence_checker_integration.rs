#![forbid(unsafe_code)]
//! Integration tests for the `global_coherence_checker` module (FRX-14.2).
//!
//! Exercises every public type, enum variant, method, error path, and
//! cross-concern scenario from outside the crate boundary.  Covers:
//!
//! - CompositionGraph construction, edge validation, adjacency queries
//! - SeverityScore levels and blocking semantics
//! - CoherenceViolationKind variant display formatting
//! - CoherenceOutcome variant display and ordering
//! - CoherenceCheckResult accessors (is_coherent, blocking_violations, etc.)
//! - GlobalCoherenceChecker::check — all six coherence passes:
//!   1. Context coherence (unresolved, orphaned, duplicate providers)
//!   2. Capability boundary coherence (gaps, leaks)
//!   3. Effect ordering (cycles, layout-after-passive)
//!   4. Suspense boundary (async/sync mix, context conflicts)
//!   5. Hydration boundary (non-deterministic effects)
//!   6. Hook cleanup coherence (label mismatch)
//! - Budget exhaustion and violation limiting
//! - Serde round-tripping for all public types
//! - Deterministic result hashing
//! - Multi-pass scenarios combining multiple violation types

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
    CoherenceCheckInput, CoherenceCheckResult, CoherenceError, CoherenceOutcome,
    CoherenceViolationKind, CompositionEdge, CompositionEdgeKind, CompositionGraph,
    DEBT_CAPABILITY_GAP, DEBT_EFFECT_CYCLE, DEBT_HOOK_CLEANUP_MISMATCH,
    DEBT_HYDRATION_BOUNDARY_CONFLICT, DEBT_SUSPENSE_BOUNDARY_CONFLICT, DEBT_UNRESOLVED_CONTEXT,
    GLOBAL_COHERENCE_BEAD_ID, GLOBAL_COHERENCE_SCHEMA_VERSION, GlobalCoherenceChecker,
    SeverityScore,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::semantic_contract_baseline::{
    LocalSemanticAtlas, LocalSemanticAtlasEntry, SemanticContractVersion,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn entry(id: &str) -> LocalSemanticAtlasEntry {
    LocalSemanticAtlasEntry {
        component_id: id.to_string(),
        module_path: format!("src/components/{id}.tsx"),
        export_name: Some(id.to_string()),
        hook_signature: Vec::new(),
        effect_signature: Vec::new(),
        required_contexts: Vec::new(),
        provided_contexts: Vec::new(),
        capability_requirements: Vec::new(),
        assumption_keys: Vec::new(),
        fixture_refs: Vec::new(),
        trace_refs: Vec::new(),
        content_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn entry_ctx(id: &str, required: &[&str], provided: &[&str]) -> LocalSemanticAtlasEntry {
    let mut e = entry(id);
    e.required_contexts = required.iter().map(|s| s.to_string()).collect();
    e.provided_contexts = provided.iter().map(|s| s.to_string()).collect();
    e
}

fn entry_caps(id: &str, caps: &[&str]) -> LocalSemanticAtlasEntry {
    let mut e = entry(id);
    e.capability_requirements = caps.iter().map(|s| s.to_string()).collect();
    e
}

fn entry_effects(id: &str, effects: &[&str]) -> LocalSemanticAtlasEntry {
    let mut e = entry(id);
    e.effect_signature = effects.iter().map(|s| s.to_string()).collect();
    e
}

fn entry_hooks(id: &str, hooks: &[&str]) -> LocalSemanticAtlasEntry {
    let mut e = entry(id);
    e.hook_signature = hooks.iter().map(|s| s.to_string()).collect();
    e
}

fn entry_full(
    id: &str,
    req_ctx: &[&str],
    prov_ctx: &[&str],
    caps: &[&str],
    effects: &[&str],
    hooks: &[&str],
) -> LocalSemanticAtlasEntry {
    let mut e = entry(id);
    e.required_contexts = req_ctx.iter().map(|s| s.to_string()).collect();
    e.provided_contexts = prov_ctx.iter().map(|s| s.to_string()).collect();
    e.capability_requirements = caps.iter().map(|s| s.to_string()).collect();
    e.effect_signature = effects.iter().map(|s| s.to_string()).collect();
    e.hook_signature = hooks.iter().map(|s| s.to_string()).collect();
    e
}

fn atlas(entries: Vec<LocalSemanticAtlasEntry>) -> LocalSemanticAtlas {
    let hash = {
        let mut data = Vec::new();
        for e in &entries {
            data.extend_from_slice(e.content_hash.as_bytes());
        }
        ContentHash::compute(&data)
    };
    LocalSemanticAtlas {
        schema_version: "test.v1".to_string(),
        bead_id: "test-bead".to_string(),
        version: SemanticContractVersion::CURRENT,
        generated_epoch: 1000,
        entries,
        quality_debt: Vec::new(),
        atlas_hash: hash,
    }
}

fn graph(components: &[&str], edges: &[(&str, &str, CompositionEdgeKind)]) -> CompositionGraph {
    let mut g = CompositionGraph::new();
    for c in components {
        g.add_component(c.to_string()).unwrap();
    }
    for (from, to, kind) in edges {
        g.add_edge(CompositionEdge {
            from_component: from.to_string(),
            to_component: to.to_string(),
            kind: kind.clone(),
            label: format!("{from}->{to}"),
        })
        .unwrap();
    }
    g
}

fn input(
    entries: Vec<LocalSemanticAtlasEntry>,
    components: &[&str],
    edges: &[(&str, &str, CompositionEdgeKind)],
) -> CoherenceCheckInput {
    CoherenceCheckInput {
        atlas: atlas(entries),
        graph: graph(components, edges),
        check_epoch: 42,
        suspense_components: BTreeSet::new(),
        hydration_components: BTreeSet::new(),
        capability_boundary_components: BTreeSet::new(),
    }
}

fn checker() -> GlobalCoherenceChecker {
    GlobalCoherenceChecker::new()
}

fn has_violation_kind(
    result: &CoherenceCheckResult,
    pred: impl Fn(&CoherenceViolationKind) -> bool,
) -> bool {
    result.violations.iter().any(|v| pred(&v.kind))
}

// ===========================================================================
// 1. Constants and schema
// ===========================================================================

#[test]
fn schema_version_is_stable() {
    assert_eq!(
        GLOBAL_COHERENCE_SCHEMA_VERSION,
        "franken-engine.global_coherence_checker.v1"
    );
}

#[test]
fn bead_id_is_correct() {
    assert_eq!(GLOBAL_COHERENCE_BEAD_ID, "bd-mjh3.14.2");
}

#[test]
fn debt_codes_are_all_distinct() {
    let codes = [
        DEBT_UNRESOLVED_CONTEXT,
        DEBT_CAPABILITY_GAP,
        DEBT_EFFECT_CYCLE,
        DEBT_SUSPENSE_BOUNDARY_CONFLICT,
        DEBT_HOOK_CLEANUP_MISMATCH,
        DEBT_HYDRATION_BOUNDARY_CONFLICT,
    ];
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn debt_codes_follow_naming_convention() {
    for code in [
        DEBT_UNRESOLVED_CONTEXT,
        DEBT_CAPABILITY_GAP,
        DEBT_EFFECT_CYCLE,
        DEBT_SUSPENSE_BOUNDARY_CONFLICT,
        DEBT_HOOK_CLEANUP_MISMATCH,
        DEBT_HYDRATION_BOUNDARY_CONFLICT,
    ] {
        assert!(
            code.starts_with("FE-FRX-14-2-GLOBAL-"),
            "code {code} missing prefix"
        );
    }
}

// ===========================================================================
// 2. CompositionEdgeKind display
// ===========================================================================

#[test]
fn edge_kind_display_all_variants() {
    assert_eq!(CompositionEdgeKind::ParentChild.to_string(), "parent-child");
    assert_eq!(CompositionEdgeKind::ContextFlow.to_string(), "context-flow");
    assert_eq!(
        CompositionEdgeKind::CapabilityBoundary.to_string(),
        "capability-boundary"
    );
    assert_eq!(
        CompositionEdgeKind::SuspenseBoundary.to_string(),
        "suspense-boundary"
    );
    assert_eq!(
        CompositionEdgeKind::HydrationBoundary.to_string(),
        "hydration-boundary"
    );
    assert_eq!(
        CompositionEdgeKind::EffectDependency.to_string(),
        "effect-dependency"
    );
}

#[test]
fn edge_kind_serde_round_trip() {
    for kind in [
        CompositionEdgeKind::ParentChild,
        CompositionEdgeKind::ContextFlow,
        CompositionEdgeKind::CapabilityBoundary,
        CompositionEdgeKind::SuspenseBoundary,
        CompositionEdgeKind::HydrationBoundary,
        CompositionEdgeKind::EffectDependency,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: CompositionEdgeKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn edge_kind_ordering_is_total() {
    let kinds = vec![
        CompositionEdgeKind::ParentChild,
        CompositionEdgeKind::ContextFlow,
        CompositionEdgeKind::CapabilityBoundary,
        CompositionEdgeKind::SuspenseBoundary,
        CompositionEdgeKind::HydrationBoundary,
        CompositionEdgeKind::EffectDependency,
    ];
    // Should be sortable without panic
    let mut sorted = kinds.clone();
    sorted.sort();
    assert_eq!(sorted.len(), kinds.len());
}

// ===========================================================================
// 3. CompositionGraph
// ===========================================================================

#[test]
fn empty_graph_has_zero_counts() {
    let g = CompositionGraph::new();
    assert_eq!(g.component_count(), 0);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn default_graph_is_empty() {
    let g = CompositionGraph::default();
    assert_eq!(g.component_count(), 0);
    assert_eq!(g.edge_count(), 0);
}

#[test]
fn add_component_increments_count() {
    let mut g = CompositionGraph::new();
    g.add_component("A".to_string()).unwrap();
    assert_eq!(g.component_count(), 1);
    g.add_component("B".to_string()).unwrap();
    assert_eq!(g.component_count(), 2);
}

#[test]
fn add_duplicate_component_is_idempotent() {
    let mut g = CompositionGraph::new();
    g.add_component("A".to_string()).unwrap();
    g.add_component("A".to_string()).unwrap();
    assert_eq!(g.component_count(), 1);
}

#[test]
fn add_edge_increments_count() {
    let g = graph(&["A", "B"], &[("A", "B", CompositionEdgeKind::ParentChild)]);
    assert_eq!(g.edge_count(), 1);
}

#[test]
fn edge_to_unknown_from_component_fails() {
    let mut g = CompositionGraph::new();
    g.add_component("B".to_string()).unwrap();
    let result = g.add_edge(CompositionEdge {
        from_component: "UNKNOWN".to_string(),
        to_component: "B".to_string(),
        kind: CompositionEdgeKind::ParentChild,
        label: "bad".to_string(),
    });
    assert_eq!(
        result,
        Err(CoherenceError::UnknownComponent("UNKNOWN".to_string()))
    );
}

#[test]
fn edge_to_unknown_to_component_fails() {
    let mut g = CompositionGraph::new();
    g.add_component("A".to_string()).unwrap();
    let result = g.add_edge(CompositionEdge {
        from_component: "A".to_string(),
        to_component: "UNKNOWN".to_string(),
        kind: CompositionEdgeKind::ParentChild,
        label: "bad".to_string(),
    });
    assert_eq!(
        result,
        Err(CoherenceError::UnknownComponent("UNKNOWN".to_string()))
    );
}

#[test]
fn children_of_returns_only_direct_children() {
    let g = graph(
        &["root", "c1", "c2", "gc"],
        &[
            ("root", "c1", CompositionEdgeKind::ParentChild),
            ("root", "c2", CompositionEdgeKind::ParentChild),
            ("c1", "gc", CompositionEdgeKind::ParentChild),
        ],
    );
    let children = g.children_of("root");
    assert_eq!(children.len(), 2);
    assert!(children.contains(&"c1".to_string()));
    assert!(children.contains(&"c2".to_string()));
    // grandchild NOT returned
    assert!(!children.contains(&"gc".to_string()));
}

#[test]
fn children_of_leaf_returns_empty() {
    let g = graph(
        &["root", "leaf"],
        &[("root", "leaf", CompositionEdgeKind::ParentChild)],
    );
    assert!(g.children_of("leaf").is_empty());
}

#[test]
fn parents_of_returns_direct_parents() {
    let g = graph(
        &["p1", "p2", "child"],
        &[
            ("p1", "child", CompositionEdgeKind::ParentChild),
            ("p2", "child", CompositionEdgeKind::ParentChild),
        ],
    );
    let parents = g.parents_of("child");
    assert_eq!(parents.len(), 2);
}

#[test]
fn parents_of_root_returns_empty() {
    let g = graph(
        &["root", "child"],
        &[("root", "child", CompositionEdgeKind::ParentChild)],
    );
    assert!(g.parents_of("root").is_empty());
}

#[test]
fn adjacency_for_kind_filters_correctly() {
    let g = graph(
        &["A", "B", "C"],
        &[
            ("A", "B", CompositionEdgeKind::ParentChild),
            ("A", "C", CompositionEdgeKind::ContextFlow),
            ("B", "C", CompositionEdgeKind::EffectDependency),
        ],
    );
    let pc = g.adjacency_for_kind(&CompositionEdgeKind::ParentChild);
    assert_eq!(pc.get("A").map(|v| v.len()), Some(1));
    assert!(!pc.contains_key("B"));

    let cf = g.adjacency_for_kind(&CompositionEdgeKind::ContextFlow);
    assert_eq!(cf.get("A").unwrap(), &vec!["C".to_string()]);
}

#[test]
fn adjacency_for_nonexistent_kind_returns_empty() {
    let g = graph(&["A", "B"], &[("A", "B", CompositionEdgeKind::ParentChild)]);
    let cap = g.adjacency_for_kind(&CompositionEdgeKind::CapabilityBoundary);
    assert!(cap.is_empty());
}

#[test]
fn graph_serde_round_trip() {
    let g = graph(&["X", "Y"], &[("X", "Y", CompositionEdgeKind::ParentChild)]);
    let json = serde_json::to_string(&g).unwrap();
    let back: CompositionGraph = serde_json::from_str(&json).unwrap();
    assert_eq!(g, back);
}

// ===========================================================================
// 4. SeverityScore
// ===========================================================================

#[test]
fn severity_blocking_threshold() {
    assert!(SeverityScore::critical().is_blocking());
    assert!(SeverityScore::high().is_blocking());
    assert!(SeverityScore::medium().is_blocking());
    assert!(!SeverityScore::low().is_blocking());
    assert!(!SeverityScore::info().is_blocking());
}

#[test]
fn severity_ordering_is_decreasing() {
    assert!(SeverityScore::critical() > SeverityScore::high());
    assert!(SeverityScore::high() > SeverityScore::medium());
    assert!(SeverityScore::medium() > SeverityScore::low());
    assert!(SeverityScore::low() > SeverityScore::info());
}

#[test]
fn severity_serde_round_trip() {
    let s = SeverityScore::critical();
    let json = serde_json::to_string(&s).unwrap();
    let back: SeverityScore = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

#[test]
fn severity_exact_values() {
    assert_eq!(SeverityScore::critical().0, 1_000_000);
    assert_eq!(SeverityScore::high().0, 750_000);
    assert_eq!(SeverityScore::medium().0, 500_000);
    assert_eq!(SeverityScore::low().0, 250_000);
    assert_eq!(SeverityScore::info().0, 100_000);
}

// ===========================================================================
// 5. CoherenceOutcome
// ===========================================================================

#[test]
fn outcome_display_all_variants() {
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
fn outcome_serde_round_trip() {
    for outcome in [
        CoherenceOutcome::Coherent,
        CoherenceOutcome::CoherentWithWarnings,
        CoherenceOutcome::Incoherent,
        CoherenceOutcome::BudgetExhausted,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: CoherenceOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

// ===========================================================================
// 6. CoherenceError
// ===========================================================================

#[test]
fn error_display_empty_atlas() {
    assert_eq!(CoherenceError::EmptyAtlas.to_string(), "atlas is empty");
}

#[test]
fn error_display_empty_graph() {
    assert_eq!(
        CoherenceError::EmptyGraph.to_string(),
        "composition graph is empty"
    );
}

#[test]
fn error_display_unknown_component() {
    let e = CoherenceError::UnknownComponent("Widget".to_string());
    assert!(e.to_string().contains("Widget"));
}

#[test]
fn error_display_budget_exhausted() {
    let e = CoherenceError::BudgetExhausted {
        resource: "edges".to_string(),
        limit: 100,
    };
    assert!(e.to_string().contains("edges"));
    assert!(e.to_string().contains("100"));
}

#[test]
fn error_display_atlas_graph_mismatch() {
    let e = CoherenceError::AtlasGraphMismatch {
        atlas_components: 5,
        graph_components: 3,
    };
    assert!(e.to_string().contains("5"));
    assert!(e.to_string().contains("3"));
}

#[test]
fn error_serde_round_trip() {
    for err in [
        CoherenceError::EmptyAtlas,
        CoherenceError::EmptyGraph,
        CoherenceError::UnknownComponent("test".to_string()),
        CoherenceError::BudgetExhausted {
            resource: "x".to_string(),
            limit: 99,
        },
        CoherenceError::AtlasGraphMismatch {
            atlas_components: 2,
            graph_components: 3,
        },
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let back: CoherenceError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ===========================================================================
// 7. Checker — error paths
// ===========================================================================

#[test]
fn check_empty_atlas_returns_error() {
    let input = CoherenceCheckInput {
        atlas: atlas(vec![]),
        graph: graph(&["A"], &[]),
        check_epoch: 1,
        suspense_components: BTreeSet::new(),
        hydration_components: BTreeSet::new(),
        capability_boundary_components: BTreeSet::new(),
    };
    assert_eq!(checker().check(&input), Err(CoherenceError::EmptyAtlas));
}

#[test]
fn check_empty_graph_returns_error() {
    let input = CoherenceCheckInput {
        atlas: atlas(vec![entry("A")]),
        graph: CompositionGraph::new(),
        check_epoch: 1,
        suspense_components: BTreeSet::new(),
        hydration_components: BTreeSet::new(),
        capability_boundary_components: BTreeSet::new(),
    };
    assert_eq!(checker().check(&input), Err(CoherenceError::EmptyGraph));
}

// ===========================================================================
// 8. Checker — fully coherent
// ===========================================================================

#[test]
fn single_component_no_requirements_is_coherent() {
    let inp = input(vec![entry("Root")], &["Root"], &[]);
    let result = checker().check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::Coherent);
    assert!(result.violations.is_empty());
    assert!(result.is_coherent());
}

#[test]
fn provider_consumer_pair_is_coherent() {
    let inp = input(
        vec![
            entry_ctx("Provider", &[], &["theme"]),
            entry_ctx("Consumer", &["theme"], &[]),
        ],
        &["Provider", "Consumer"],
        &[("Provider", "Consumer", CompositionEdgeKind::ParentChild)],
    );
    let result = checker().check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::Coherent);
    assert_eq!(result.context_pairs_checked, 1);
}

#[test]
fn multiple_consumers_same_provider_is_coherent() {
    let inp = input(
        vec![
            entry_ctx("P", &[], &["auth"]),
            entry_ctx("C1", &["auth"], &[]),
            entry_ctx("C2", &["auth"], &[]),
        ],
        &["P", "C1", "C2"],
        &[
            ("P", "C1", CompositionEdgeKind::ParentChild),
            ("P", "C2", CompositionEdgeKind::ParentChild),
        ],
    );
    let result = checker().check(&inp).unwrap();
    assert!(result.is_coherent());
    assert_eq!(result.context_pairs_checked, 2);
}

#[test]
fn coherent_result_metadata_populated() {
    let inp = input(
        vec![entry("A"), entry("B")],
        &["A", "B"],
        &[("A", "B", CompositionEdgeKind::ParentChild)],
    );
    let result = checker().check(&inp).unwrap();
    assert_eq!(result.schema_version, GLOBAL_COHERENCE_SCHEMA_VERSION);
    assert_eq!(result.bead_id, GLOBAL_COHERENCE_BEAD_ID);
    assert_eq!(result.component_count, 2);
    assert_eq!(result.edge_count, 1);
    assert_eq!(result.check_epoch, 42);
    assert_eq!(result.blocking_violation_count, 0);
    assert_eq!(result.total_severity_millionths, 0);
}

#[test]
fn summary_line_for_coherent_result() {
    let inp = input(vec![entry("X")], &["X"], &[]);
    let result = checker().check(&inp).unwrap();
    let summary = result.summary_line();
    assert!(summary.contains("coherent"));
    assert!(summary.contains("0 violations"));
    assert!(summary.contains("0 blocking"));
}

// ===========================================================================
// 9. Context coherence violations
// ===========================================================================

#[test]
fn unresolved_context_detected() {
    let inp = input(
        vec![entry_ctx("Orphan", &["missing_ctx"], &[])],
        &["Orphan"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::Incoherent);
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::UnresolvedContext { context_key, .. }
            if context_key == "missing_ctx"
    )));
}

#[test]
fn multiple_unresolved_contexts() {
    let inp = input(vec![entry_ctx("C", &["ctx_a", "ctx_b"], &[])], &["C"], &[]);
    let result = checker().check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::Incoherent);
    let unresolved_count = result
        .violations
        .iter()
        .filter(|v| matches!(&v.kind, CoherenceViolationKind::UnresolvedContext { .. }))
        .count();
    assert_eq!(unresolved_count, 2);
}

#[test]
fn unresolved_context_severity_is_critical() {
    let inp = input(vec![entry_ctx("C", &["missing"], &[])], &["C"], &[]);
    let result = checker().check(&inp).unwrap();
    let violation = result
        .violations
        .iter()
        .find(|v| matches!(&v.kind, CoherenceViolationKind::UnresolvedContext { .. }))
        .unwrap();
    assert!(violation.severity.is_blocking());
    assert_eq!(violation.severity, SeverityScore::critical());
}

#[test]
fn orphaned_provider_detected() {
    let inp = input(
        vec![entry_ctx("Provider", &[], &["unused_ctx"])],
        &["Provider"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::OrphanedProvider { context_key, .. }
            if context_key == "unused_ctx"
    )));
}

#[test]
fn orphaned_provider_severity_is_low() {
    let inp = input(vec![entry_ctx("P", &[], &["orphan"])], &["P"], &[]);
    let result = checker().check(&inp).unwrap();
    let violation = result
        .violations
        .iter()
        .find(|v| matches!(&v.kind, CoherenceViolationKind::OrphanedProvider { .. }))
        .unwrap();
    assert_eq!(violation.severity, SeverityScore::low());
    assert!(!violation.severity.is_blocking());
}

#[test]
fn orphaned_provider_gives_coherent_with_warnings() {
    let inp = input(vec![entry_ctx("P", &[], &["unused"])], &["P"], &[]);
    let result = checker().check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::CoherentWithWarnings);
    assert!(result.is_coherent());
}

#[test]
fn duplicate_provider_in_ancestor_descendant_chain() {
    let inp = input(
        vec![
            entry_ctx("Parent", &[], &["theme"]),
            entry_ctx("Child", &["theme"], &["theme"]),
        ],
        &["Parent", "Child"],
        &[("Parent", "Child", CompositionEdgeKind::ParentChild)],
    );
    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::DuplicateProvider { context_key, .. }
            if context_key == "theme"
    )));
}

#[test]
fn duplicate_provider_siblings_no_violation() {
    // Two sibling providers (no ancestor-descendant relationship) should NOT trigger
    let inp = input(
        vec![
            entry("Root"),
            entry_ctx("SibA", &[], &["theme"]),
            entry_ctx("SibB", &[], &["theme"]),
        ],
        &["Root", "SibA", "SibB"],
        &[
            ("Root", "SibA", CompositionEdgeKind::ParentChild),
            ("Root", "SibB", CompositionEdgeKind::ParentChild),
        ],
    );
    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::DuplicateProvider { .. }
    )));
}

#[test]
fn context_pairs_counted_correctly() {
    let inp = input(
        vec![
            entry_ctx("P", &[], &["a", "b", "c"]),
            entry_ctx("C1", &["a", "b"], &[]),
            entry_ctx("C2", &["c"], &[]),
        ],
        &["P", "C1", "C2"],
        &[
            ("P", "C1", CompositionEdgeKind::ParentChild),
            ("P", "C2", CompositionEdgeKind::ParentChild),
        ],
    );
    let result = checker().check(&inp).unwrap();
    assert_eq!(result.context_pairs_checked, 3);
}

// ===========================================================================
// 10. Capability coherence violations
// ===========================================================================

#[test]
fn capability_gap_outside_boundary() {
    let mut inp = input(
        vec![
            entry("Boundary"),
            entry_caps("Uncovered", &["network", "storage"]),
        ],
        &["Boundary", "Uncovered"],
        &[],
    );
    inp.capability_boundary_components
        .insert("Boundary".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::CapabilityGap { component, .. }
            if component == "Uncovered"
    )));
}

#[test]
fn boundary_capability_leak_detected() {
    let mut inp = input(
        vec![
            entry_caps("Boundary", &["network"]),
            entry_caps("Child", &["network", "storage"]),
        ],
        &["Boundary", "Child"],
        &[("Boundary", "Child", CompositionEdgeKind::ParentChild)],
    );
    inp.capability_boundary_components
        .insert("Boundary".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::BoundaryCapabilityLeak { boundary, leaked_capabilities, .. }
            if boundary == "Boundary" && leaked_capabilities.contains(&"storage".to_string())
    )));
}

#[test]
fn boundary_covers_all_descendant_caps_no_violation() {
    let mut inp = input(
        vec![
            entry_caps("Boundary", &["network", "storage"]),
            entry_caps("Child", &["network"]),
            entry_caps("Grandchild", &["storage"]),
        ],
        &["Boundary", "Child", "Grandchild"],
        &[
            ("Boundary", "Child", CompositionEdgeKind::ParentChild),
            ("Child", "Grandchild", CompositionEdgeKind::ParentChild),
        ],
    );
    inp.capability_boundary_components
        .insert("Boundary".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::BoundaryCapabilityLeak { .. }
    )));
}

#[test]
fn capability_boundary_count_tracked() {
    let mut inp = input(
        vec![entry("B1"), entry("B2"), entry("C")],
        &["B1", "B2", "C"],
        &[("B1", "C", CompositionEdgeKind::ParentChild)],
    );
    inp.capability_boundary_components.insert("B1".to_string());
    inp.capability_boundary_components.insert("B2".to_string());

    let result = checker().check(&inp).unwrap();
    assert_eq!(result.capability_boundaries_checked, 2);
}

// ===========================================================================
// 11. Effect ordering violations
// ===========================================================================

#[test]
fn effect_cycle_detected() {
    let inp = input(
        vec![
            entry_effects("A", &["LayoutEffect"]),
            entry_effects("B", &["PassiveEffect"]),
            entry_effects("C", &["LayoutEffect"]),
        ],
        &["A", "B", "C"],
        &[
            ("A", "B", CompositionEdgeKind::EffectDependency),
            ("B", "C", CompositionEdgeKind::EffectDependency),
            ("C", "A", CompositionEdgeKind::EffectDependency),
        ],
    );
    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::EffectOrderCycle { .. }
    )));
    assert_eq!(result.outcome, CoherenceOutcome::Incoherent);
}

#[test]
fn no_effect_cycle_in_dag() {
    let inp = input(
        vec![
            entry_effects("A", &["LayoutEffect"]),
            entry_effects("B", &["PassiveEffect"]),
            entry_effects("C", &["LayoutEffect"]),
        ],
        &["A", "B", "C"],
        &[
            ("A", "B", CompositionEdgeKind::EffectDependency),
            ("B", "C", CompositionEdgeKind::EffectDependency),
        ],
    );
    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::EffectOrderCycle { .. }
    )));
}

#[test]
fn layout_after_passive_detected() {
    // Child has layout effect, parent has passive effect (but no layout) — bad
    let inp = input(
        vec![
            entry_effects("Parent", &["PassiveEffect"]),
            entry_effects("Child", &["LayoutEffect"]),
        ],
        &["Parent", "Child"],
        &[("Parent", "Child", CompositionEdgeKind::ParentChild)],
    );
    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::LayoutAfterPassive {
            layout_component,
            passive_component,
        } if layout_component == "Child" && passive_component == "Parent"
    )));
}

#[test]
fn layout_in_both_parent_and_child_no_violation() {
    // Parent has both layout AND passive — no violation since parent_has_layout
    let inp = input(
        vec![
            entry_effects("Parent", &["LayoutEffect", "PassiveEffect"]),
            entry_effects("Child", &["LayoutEffect"]),
        ],
        &["Parent", "Child"],
        &[("Parent", "Child", CompositionEdgeKind::ParentChild)],
    );
    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::LayoutAfterPassive { .. }
    )));
}

#[test]
fn effect_orderings_counted() {
    let inp = input(
        vec![
            entry_effects("P", &["PassiveEffect"]),
            entry_effects("C1", &[]),
            entry_effects("C2", &[]),
        ],
        &["P", "C1", "C2"],
        &[
            ("P", "C1", CompositionEdgeKind::ParentChild),
            ("P", "C2", CompositionEdgeKind::ParentChild),
        ],
    );
    let result = checker().check(&inp).unwrap();
    assert!(result.effect_orderings_checked >= 2);
}

// ===========================================================================
// 12. Suspense boundary coherence
// ===========================================================================

#[test]
fn suspense_async_sync_layout_mix_detected() {
    let mut inp = input(
        vec![
            entry("SuspBoundary"),
            entry_effects("AsyncChild", &["async-fetch; suspense"]),
            entry_effects("SyncLayoutChild", &["LayoutEffect"]),
        ],
        &["SuspBoundary", "AsyncChild", "SyncLayoutChild"],
        &[
            (
                "SuspBoundary",
                "AsyncChild",
                CompositionEdgeKind::ParentChild,
            ),
            (
                "SuspBoundary",
                "SyncLayoutChild",
                CompositionEdgeKind::ParentChild,
            ),
        ],
    );
    inp.suspense_components.insert("SuspBoundary".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::SuspenseBoundaryConflict {
            boundary_component,
            reason,
            ..
        } if boundary_component == "SuspBoundary"
            && reason.contains("async-suspended and sync layout")
    )));
}

#[test]
fn suspense_all_sync_no_violation() {
    let mut inp = input(
        vec![
            entry("Susp"),
            entry_effects("C1", &["PassiveEffect"]),
            entry_effects("C2", &["LayoutEffect"]),
        ],
        &["Susp", "C1", "C2"],
        &[
            ("Susp", "C1", CompositionEdgeKind::ParentChild),
            ("Susp", "C2", CompositionEdgeKind::ParentChild),
        ],
    );
    inp.suspense_components.insert("Susp".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::SuspenseBoundaryConflict {
            reason,
            ..
        } if reason.contains("async-suspended")
    )));
}

#[test]
fn suspense_context_mismatch_among_async_children() {
    let mut inp = input(
        vec![
            entry("Susp"),
            entry_full("Async1", &["ctx_a"], &[], &[], &["async-loader"], &[]),
            entry_full("Async2", &["ctx_b"], &[], &[], &["async-fetcher"], &[]),
        ],
        &["Susp", "Async1", "Async2"],
        &[
            ("Susp", "Async1", CompositionEdgeKind::ParentChild),
            ("Susp", "Async2", CompositionEdgeKind::ParentChild),
        ],
    );
    inp.suspense_components.insert("Susp".to_string());

    let result = checker().check(&inp).unwrap();
    // Info-level violations for context asymmetry
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::SuspenseBoundaryConflict {
            reason,
            ..
        } if reason.contains("missing contexts")
    )));
}

#[test]
fn suspense_boundaries_counted() {
    let mut inp = input(
        vec![entry("S1"), entry("S2"), entry("C")],
        &["S1", "S2", "C"],
        &[("S1", "C", CompositionEdgeKind::ParentChild)],
    );
    inp.suspense_components.insert("S1".to_string());
    inp.suspense_components.insert("S2".to_string());

    let result = checker().check(&inp).unwrap();
    assert_eq!(result.suspense_boundaries_checked, 2);
}

// ===========================================================================
// 13. Hydration boundary coherence
// ===========================================================================

#[test]
fn hydration_non_deterministic_child_detected() {
    let mut inp = input(
        vec![
            entry("HydrBoundary"),
            entry_effects("BadChild", &["idempotent=false; side-effect"]),
        ],
        &["HydrBoundary", "BadChild"],
        &[("HydrBoundary", "BadChild", CompositionEdgeKind::ParentChild)],
    );
    inp.hydration_components.insert("HydrBoundary".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HydrationBoundaryConflict {
            boundary_component,
            ..
        } if boundary_component == "HydrBoundary"
    )));
    assert_eq!(result.outcome, CoherenceOutcome::Incoherent);
}

#[test]
fn hydration_commutative_false_triggers_conflict() {
    let mut inp = input(
        vec![
            entry("Hbnd"),
            entry_effects("Child", &["commutative=false; order-sensitive"]),
        ],
        &["Hbnd", "Child"],
        &[("Hbnd", "Child", CompositionEdgeKind::ParentChild)],
    );
    inp.hydration_components.insert("Hbnd".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HydrationBoundaryConflict { .. }
    )));
}

#[test]
fn hydration_safe_children_no_violation() {
    let mut inp = input(
        vec![
            entry("Hbnd"),
            entry_effects("GoodChild", &["idempotent=true; commutative=true"]),
        ],
        &["Hbnd", "GoodChild"],
        &[("Hbnd", "GoodChild", CompositionEdgeKind::ParentChild)],
    );
    inp.hydration_components.insert("Hbnd".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HydrationBoundaryConflict { .. }
    )));
}

#[test]
fn hydration_no_children_no_violation() {
    let mut inp = input(vec![entry("Hbnd")], &["Hbnd"], &[]);
    inp.hydration_components.insert("Hbnd".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HydrationBoundaryConflict { .. }
    )));
}

#[test]
fn hydration_boundaries_counted() {
    let mut inp = input(vec![entry("H1"), entry("H2")], &["H1", "H2"], &[]);
    inp.hydration_components.insert("H1".to_string());
    inp.hydration_components.insert("H2".to_string());

    let result = checker().check(&inp).unwrap();
    assert_eq!(result.hydration_boundaries_checked, 2);
}

// ===========================================================================
// 14. Hook cleanup coherence
// ===========================================================================

#[test]
fn hook_cleanup_mismatch_detected() {
    let inp = input(
        vec![
            entry_hooks("CompA", &["label=useData; cleanup=true"]),
            entry_hooks("CompB", &["label=useData; cleanup=false"]),
        ],
        &["CompA", "CompB"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HookCleanupMismatch {
            hook_label,
            ..
        } if hook_label == "useData"
    )));
}

#[test]
fn hook_cleanup_agreement_no_violation() {
    let inp = input(
        vec![
            entry_hooks("CompA", &["label=useAuth; cleanup=true"]),
            entry_hooks("CompB", &["label=useAuth; cleanup=true"]),
        ],
        &["CompA", "CompB"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HookCleanupMismatch { .. }
    )));
}

#[test]
fn hook_different_labels_no_conflict() {
    let inp = input(
        vec![
            entry_hooks("CompA", &["label=useAuth; cleanup=true"]),
            entry_hooks("CompB", &["label=useData; cleanup=false"]),
        ],
        &["CompA", "CompB"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HookCleanupMismatch { .. }
    )));
}

#[test]
fn hook_cleanup_mismatch_severity_is_medium() {
    let inp = input(
        vec![
            entry_hooks("A", &["label=useFetch; cleanup=true"]),
            entry_hooks("B", &["label=useFetch; cleanup=false"]),
        ],
        &["A", "B"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    let violation = result
        .violations
        .iter()
        .find(|v| matches!(&v.kind, CoherenceViolationKind::HookCleanupMismatch { .. }))
        .unwrap();
    assert_eq!(violation.severity, SeverityScore::medium());
}

// ===========================================================================
// 15. Violation budget exhaustion
// ===========================================================================

#[test]
fn budget_exhaustion_limits_violations() {
    let c = GlobalCoherenceChecker::new().with_violation_budget(2);
    // Create many violations via unresolved contexts
    let inp = input(
        vec![
            entry_ctx("C1", &["missing1"], &[]),
            entry_ctx("C2", &["missing2"], &[]),
            entry_ctx("C3", &["missing3"], &[]),
            entry_ctx("C4", &["missing4"], &[]),
        ],
        &["C1", "C2", "C3", "C4"],
        &[],
    );
    let result = c.check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::BudgetExhausted);
    assert!(result.violations.len() <= 2);
}

#[test]
fn budget_of_one_stops_early() {
    let c = GlobalCoherenceChecker::new().with_violation_budget(1);
    let inp = input(
        vec![entry_ctx("C1", &["a"], &[]), entry_ctx("C2", &["b"], &[])],
        &["C1", "C2"],
        &[],
    );
    let result = c.check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::BudgetExhausted);
    assert!(result.violations.len() <= 1);
}

// ===========================================================================
// 16. Result accessors
// ===========================================================================

#[test]
fn blocking_violations_filtered() {
    let inp = input(
        vec![
            entry_ctx("C", &["missing"], &[]),
            entry_ctx("P", &[], &["orphan_ctx"]),
        ],
        &["C", "P"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    let blocking = result.blocking_violations();
    // Unresolved context is blocking (critical), orphaned provider is not (low)
    assert!(!blocking.is_empty());
    assert!(blocking.iter().all(|v| v.severity.is_blocking()));
}

#[test]
fn violations_by_debt_code_grouped() {
    let inp = input(
        vec![
            entry_ctx("C", &["missing"], &[]),
            entry_ctx("P", &[], &["orphan"]),
        ],
        &["C", "P"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    let by_code = result.violations_by_debt_code();
    assert!(by_code.contains_key(DEBT_UNRESOLVED_CONTEXT));
}

#[test]
fn is_coherent_true_for_coherent_and_warnings() {
    // Coherent
    let r1 = checker()
        .check(&input(vec![entry("A")], &["A"], &[]))
        .unwrap();
    assert!(r1.is_coherent());

    // CoherentWithWarnings (orphaned provider)
    let r2 = checker()
        .check(&input(vec![entry_ctx("P", &[], &["unused"])], &["P"], &[]))
        .unwrap();
    assert!(r2.is_coherent());
}

#[test]
fn is_coherent_false_for_incoherent() {
    let inp = input(vec![entry_ctx("C", &["missing"], &[])], &["C"], &[]);
    let result = checker().check(&inp).unwrap();
    assert!(!result.is_coherent());
}

// ===========================================================================
// 17. Deterministic result hashing
// ===========================================================================

#[test]
fn same_input_produces_same_result_hash() {
    let inp = input(
        vec![
            entry_ctx("P", &[], &["theme"]),
            entry_ctx("C", &["theme"], &[]),
        ],
        &["P", "C"],
        &[("P", "C", CompositionEdgeKind::ParentChild)],
    );
    let r1 = checker().check(&inp).unwrap();
    let r2 = checker().check(&inp).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

#[test]
fn different_violations_produce_different_hashes() {
    let inp1 = input(vec![entry("A")], &["A"], &[]);
    let inp2 = input(vec![entry_ctx("A", &["missing"], &[])], &["A"], &[]);
    let r1 = checker().check(&inp1).unwrap();
    let r2 = checker().check(&inp2).unwrap();
    assert_ne!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 18. Evidence linkage
// ===========================================================================

#[test]
fn violations_have_evidence_hashes() {
    let inp = input(vec![entry_ctx("C", &["missing"], &[])], &["C"], &[]);
    let result = checker().check(&inp).unwrap();
    for v in &result.violations {
        // Evidence hash should not be zero-length
        assert!(!v.evidence_hash.as_bytes().is_empty());
    }
}

#[test]
fn violations_have_valid_ids() {
    let inp = input(vec![entry_ctx("C", &["missing"], &[])], &["C"], &[]);
    let result = checker().check(&inp).unwrap();
    for v in &result.violations {
        // ID should be non-empty
        assert!(!format!("{:?}", v.id).is_empty());
    }
}

#[test]
fn violations_carry_epoch() {
    let mut inp = input(vec![entry_ctx("C", &["missing"], &[])], &["C"], &[]);
    inp.check_epoch = 999;
    let result = checker().check(&inp).unwrap();
    for v in &result.violations {
        assert_eq!(v.detected_epoch, 999);
    }
}

// ===========================================================================
// 19. CoherenceViolationKind display
// ===========================================================================

#[test]
fn violation_kind_display_unresolved_context() {
    let kind = CoherenceViolationKind::UnresolvedContext {
        consumer: "MyComponent".to_string(),
        context_key: "ThemeContext".to_string(),
    };
    let display = kind.to_string();
    assert!(display.contains("MyComponent"));
    assert!(display.contains("ThemeContext"));
}

#[test]
fn violation_kind_display_orphaned_provider() {
    let kind = CoherenceViolationKind::OrphanedProvider {
        provider: "ThemeProvider".to_string(),
        context_key: "Theme".to_string(),
    };
    let display = kind.to_string();
    assert!(display.contains("ThemeProvider"));
    assert!(display.contains("Theme"));
}

#[test]
fn violation_kind_display_capability_gap() {
    let kind = CoherenceViolationKind::CapabilityGap {
        component: "DangerousWidget".to_string(),
        missing_capabilities: vec!["network".to_string(), "fs".to_string()],
    };
    let display = kind.to_string();
    assert!(display.contains("DangerousWidget"));
    assert!(display.contains("network"));
    assert!(display.contains("fs"));
}

#[test]
fn violation_kind_display_effect_cycle() {
    let kind = CoherenceViolationKind::EffectOrderCycle {
        cycle_participants: vec!["A".to_string(), "B".to_string(), "C".to_string()],
    };
    let display = kind.to_string();
    assert!(display.contains("A"));
    assert!(display.contains("B"));
    assert!(display.contains("C"));
}

#[test]
fn violation_kind_display_layout_after_passive() {
    let kind = CoherenceViolationKind::LayoutAfterPassive {
        layout_component: "Child".to_string(),
        passive_component: "Parent".to_string(),
    };
    let display = kind.to_string();
    assert!(display.contains("Child"));
    assert!(display.contains("Parent"));
}

#[test]
fn violation_kind_display_suspense_conflict() {
    let kind = CoherenceViolationKind::SuspenseBoundaryConflict {
        boundary_component: "Fallback".to_string(),
        conflicting_children: vec!["X".to_string(), "Y".to_string()],
        reason: "async/sync mix".to_string(),
    };
    let display = kind.to_string();
    assert!(display.contains("Fallback"));
    assert!(display.contains("X"));
    assert!(display.contains("async/sync mix"));
}

#[test]
fn violation_kind_display_hydration_conflict() {
    let kind = CoherenceViolationKind::HydrationBoundaryConflict {
        boundary_component: "SSR".to_string(),
        conflicting_children: vec!["Widget".to_string()],
        reason: "non-deterministic".to_string(),
    };
    let display = kind.to_string();
    assert!(display.contains("SSR"));
    assert!(display.contains("Widget"));
}

#[test]
fn violation_kind_display_hook_mismatch() {
    let kind = CoherenceViolationKind::HookCleanupMismatch {
        component_a: "FormA".to_string(),
        component_b: "FormB".to_string(),
        hook_label: "useFormState".to_string(),
    };
    let display = kind.to_string();
    assert!(display.contains("FormA"));
    assert!(display.contains("FormB"));
    assert!(display.contains("useFormState"));
}

#[test]
fn violation_kind_display_duplicate_provider() {
    let kind = CoherenceViolationKind::DuplicateProvider {
        providers: vec!["P1".to_string(), "P2".to_string()],
        context_key: "Router".to_string(),
    };
    let display = kind.to_string();
    assert!(display.contains("P1"));
    assert!(display.contains("P2"));
    assert!(display.contains("Router"));
}

#[test]
fn violation_kind_display_boundary_leak() {
    let kind = CoherenceViolationKind::BoundaryCapabilityLeak {
        boundary: "SecurityBoundary".to_string(),
        leaked_capabilities: vec!["eval".to_string()],
    };
    let display = kind.to_string();
    assert!(display.contains("SecurityBoundary"));
    assert!(display.contains("eval"));
}

// ===========================================================================
// 20. Serde round-trips for full results
// ===========================================================================

#[test]
fn coherent_result_serde_round_trip() {
    let inp = input(vec![entry("A")], &["A"], &[]);
    let result = checker().check(&inp).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: CoherenceCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.outcome, back.outcome);
    assert_eq!(result.violations.len(), back.violations.len());
    assert_eq!(result.result_hash, back.result_hash);
}

#[test]
fn incoherent_result_serde_round_trip() {
    let inp = input(vec![entry_ctx("C", &["missing"], &[])], &["C"], &[]);
    let result = checker().check(&inp).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: CoherenceCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.outcome, back.outcome);
    assert_eq!(result.violations.len(), back.violations.len());
}

#[test]
fn composition_edge_serde_round_trip() {
    let edge = CompositionEdge {
        from_component: "A".to_string(),
        to_component: "B".to_string(),
        kind: CompositionEdgeKind::ContextFlow,
        label: "test".to_string(),
    };
    let json = serde_json::to_string(&edge).unwrap();
    let back: CompositionEdge = serde_json::from_str(&json).unwrap();
    assert_eq!(edge, back);
}

#[test]
fn coherence_check_input_serde_round_trip() {
    let inp = input(
        vec![
            entry_ctx("P", &[], &["theme"]),
            entry_ctx("C", &["theme"], &[]),
        ],
        &["P", "C"],
        &[("P", "C", CompositionEdgeKind::ParentChild)],
    );
    let json = serde_json::to_string(&inp).unwrap();
    let back: CoherenceCheckInput = serde_json::from_str(&json).unwrap();
    assert_eq!(inp.check_epoch, back.check_epoch);
    assert_eq!(inp.atlas.entries.len(), back.atlas.entries.len());
}

// ===========================================================================
// 21. Multi-pass combined scenarios
// ===========================================================================

#[test]
fn combined_context_and_capability_violations() {
    let mut inp = input(
        vec![
            entry_full("Root", &[], &[], &["network"], &[], &[]),
            entry_full(
                "Child",
                &["missing_ctx"],
                &[],
                &["network", "eval"],
                &[],
                &[],
            ),
        ],
        &["Root", "Child"],
        &[("Root", "Child", CompositionEdgeKind::ParentChild)],
    );
    inp.capability_boundary_components
        .insert("Root".to_string());

    let result = checker().check(&inp).unwrap();
    // Should have unresolved context + capability leak
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::UnresolvedContext { .. }
    )));
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::BoundaryCapabilityLeak { .. }
    )));
    assert_eq!(result.outcome, CoherenceOutcome::Incoherent);
}

#[test]
fn combined_effect_and_hydration_violations() {
    let mut inp = input(
        vec![
            entry_effects("Parent", &["PassiveEffect"]),
            entry_effects("Child", &["LayoutEffect; idempotent=false"]),
        ],
        &["Parent", "Child"],
        &[("Parent", "Child", CompositionEdgeKind::ParentChild)],
    );
    inp.hydration_components.insert("Parent".to_string());

    let result = checker().check(&inp).unwrap();
    // Layout-after-passive + hydration conflict
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::LayoutAfterPassive { .. }
    )));
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HydrationBoundaryConflict { .. }
    )));
}

#[test]
fn combined_hook_mismatch_and_orphaned_provider() {
    let inp = input(
        vec![
            entry_full(
                "A",
                &[],
                &["orphan_ctx"],
                &[],
                &[],
                &["label=useShared; cleanup=true"],
            ),
            entry_full("B", &[], &[], &[], &[], &["label=useShared; cleanup=false"]),
        ],
        &["A", "B"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::OrphanedProvider { .. }
    )));
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HookCleanupMismatch { .. }
    )));
    // OrphanedProvider is low (non-blocking) but HookCleanupMismatch is medium (blocking)
    assert!(!result.is_coherent());
}

// ===========================================================================
// 22. Large composition graph
// ===========================================================================

#[test]
fn large_tree_is_coherent() {
    let n = 100;
    let mut entries = vec![entry_ctx("Root", &[], &["global_ctx"])];
    let mut components = vec!["Root"];
    let mut edges = Vec::new();
    let names: Vec<String> = (0..n).map(|i| format!("Child_{i}")).collect();

    for name in &names {
        entries.push(entry_ctx(name, &["global_ctx"], &[]));
    }
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    components.extend(name_refs.iter());

    for name in &name_refs {
        edges.push(("Root", *name, CompositionEdgeKind::ParentChild));
    }

    let inp = input(entries, &components, &edges);
    let result = checker().check(&inp).unwrap();
    assert!(result.is_coherent());
    assert_eq!(result.component_count, n + 1);
    assert_eq!(result.context_pairs_checked, n);
}

#[test]
fn deep_chain_ancestor_detection() {
    // Build a chain: A -> B -> C -> D -> E
    let entries = vec![
        entry_ctx("A", &[], &["chain_ctx"]),
        entry("B"),
        entry("C"),
        entry("D"),
        entry_ctx("E", &[], &["chain_ctx"]),
    ];
    let components = vec!["A", "B", "C", "D", "E"];
    let edges = vec![
        ("A", "B", CompositionEdgeKind::ParentChild),
        ("B", "C", CompositionEdgeKind::ParentChild),
        ("C", "D", CompositionEdgeKind::ParentChild),
        ("D", "E", CompositionEdgeKind::ParentChild),
    ];

    let inp = input(entries, &components, &edges);
    let result = checker().check(&inp).unwrap();
    // A and E both provide "chain_ctx" and are in ancestor-descendant relationship
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::DuplicateProvider { context_key, .. }
            if context_key == "chain_ctx"
    )));
}

// ===========================================================================
// 23. Edge cases
// ===========================================================================

#[test]
fn self_loop_parent_child_edge() {
    let g = graph(&["A"], &[("A", "A", CompositionEdgeKind::ParentChild)]);
    assert_eq!(g.children_of("A"), vec!["A".to_string()]);
}

#[test]
fn component_with_no_atlas_entry_in_graph() {
    // Graph has components not in atlas — checker should handle gracefully
    let mut g = CompositionGraph::new();
    g.add_component("InGraph".to_string()).unwrap();
    g.add_component("AlsoInGraph".to_string()).unwrap();

    let inp = CoherenceCheckInput {
        atlas: atlas(vec![entry("InGraph")]),
        graph: g,
        check_epoch: 1,
        suspense_components: BTreeSet::new(),
        hydration_components: BTreeSet::new(),
        capability_boundary_components: BTreeSet::new(),
    };
    // Should not panic
    let result = checker().check(&inp).unwrap();
    assert!(
        result.outcome == CoherenceOutcome::Coherent
            || result.outcome == CoherenceOutcome::CoherentWithWarnings
    );
}

#[test]
fn empty_effect_signature_is_benign() {
    let inp = input(
        vec![entry_effects("A", &[]), entry_effects("B", &[])],
        &["A", "B"],
        &[("A", "B", CompositionEdgeKind::ParentChild)],
    );
    let result = checker().check(&inp).unwrap();
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::LayoutAfterPassive { .. }
    )));
}

#[test]
fn hook_without_label_is_ignored() {
    let inp = input(
        vec![
            entry_hooks("A", &["cleanup=true"]),  // no label
            entry_hooks("B", &["cleanup=false"]), // no label
        ],
        &["A", "B"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    // Should not produce HookCleanupMismatch since hooks have no label
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HookCleanupMismatch { .. }
    )));
}

#[test]
fn total_severity_sums_correctly() {
    let inp = input(
        vec![entry_ctx("C1", &["a"], &[]), entry_ctx("C2", &["b"], &[])],
        &["C1", "C2"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    let expected_sum: i64 = result.violations.iter().map(|v| v.severity.0).sum();
    assert_eq!(result.total_severity_millionths, expected_sum);
}

#[test]
fn checker_with_custom_budget_works() {
    let c = GlobalCoherenceChecker::new().with_violation_budget(100);
    let inp = input(vec![entry("X")], &["X"], &[]);
    let result = c.check(&inp).unwrap();
    assert_eq!(result.outcome, CoherenceOutcome::Coherent);
}

#[test]
fn checker_default_is_same_as_new() {
    let c1 = GlobalCoherenceChecker::new();
    let c2 = GlobalCoherenceChecker::default();
    let inp = input(vec![entry("A")], &["A"], &[]);
    let r1 = c1.check(&inp).unwrap();
    let r2 = c2.check(&inp).unwrap();
    assert_eq!(r1.outcome, r2.outcome);
    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 24. Multi-hop capability boundary
// ===========================================================================

#[test]
fn capability_leak_through_deep_descendant() {
    // Boundary -> A -> B -> C (C requires "eval", boundary doesn't have it)
    let mut inp = input(
        vec![
            entry_caps("Boundary", &["network"]),
            entry("A"),
            entry("B"),
            entry_caps("C", &["eval"]),
        ],
        &["Boundary", "A", "B", "C"],
        &[
            ("Boundary", "A", CompositionEdgeKind::ParentChild),
            ("A", "B", CompositionEdgeKind::ParentChild),
            ("B", "C", CompositionEdgeKind::ParentChild),
        ],
    );
    inp.capability_boundary_components
        .insert("Boundary".to_string());

    let result = checker().check(&inp).unwrap();
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::BoundaryCapabilityLeak {
            leaked_capabilities,
            ..
        } if leaked_capabilities.contains(&"eval".to_string())
    )));
}

// ===========================================================================
// 25. Suspense edge cases
// ===========================================================================

#[test]
fn suspense_single_async_child_no_context_conflict() {
    let mut inp = input(
        vec![
            entry("Susp"),
            entry_effects("SingleAsync", &["async-data-fetch"]),
        ],
        &["Susp", "SingleAsync"],
        &[("Susp", "SingleAsync", CompositionEdgeKind::ParentChild)],
    );
    inp.suspense_components.insert("Susp".to_string());

    let result = checker().check(&inp).unwrap();
    // Single async child should not trigger context mismatch
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::SuspenseBoundaryConflict {
            reason,
            ..
        } if reason.contains("missing contexts")
    )));
}

#[test]
fn suspense_with_lazy_child() {
    let mut inp = input(
        vec![
            entry("Susp"),
            entry_effects("LazyChild", &["lazy-load"]),
            entry_effects("SyncChild", &["LayoutEffect"]),
        ],
        &["Susp", "LazyChild", "SyncChild"],
        &[
            ("Susp", "LazyChild", CompositionEdgeKind::ParentChild),
            ("Susp", "SyncChild", CompositionEdgeKind::ParentChild),
        ],
    );
    inp.suspense_components.insert("Susp".to_string());

    let result = checker().check(&inp).unwrap();
    // lazy + sync layout should trigger suspense conflict
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::SuspenseBoundaryConflict { .. }
    )));
}

// ===========================================================================
// 26. Comprehensive violation debt code mapping
// ===========================================================================

#[test]
fn unresolved_context_has_correct_debt_code() {
    let inp = input(vec![entry_ctx("C", &["missing"], &[])], &["C"], &[]);
    let result = checker().check(&inp).unwrap();
    let v = result
        .violations
        .iter()
        .find(|v| matches!(&v.kind, CoherenceViolationKind::UnresolvedContext { .. }))
        .unwrap();
    assert_eq!(v.debt_code, DEBT_UNRESOLVED_CONTEXT);
}

#[test]
fn effect_cycle_has_correct_debt_code() {
    let inp = input(
        vec![entry("A"), entry("B")],
        &["A", "B"],
        &[
            ("A", "B", CompositionEdgeKind::EffectDependency),
            ("B", "A", CompositionEdgeKind::EffectDependency),
        ],
    );
    let result = checker().check(&inp).unwrap();
    let v = result
        .violations
        .iter()
        .find(|v| matches!(&v.kind, CoherenceViolationKind::EffectOrderCycle { .. }))
        .unwrap();
    assert_eq!(v.debt_code, DEBT_EFFECT_CYCLE);
}

#[test]
fn hook_mismatch_has_correct_debt_code() {
    let inp = input(
        vec![
            entry_hooks("A", &["label=useX; cleanup=true"]),
            entry_hooks("B", &["label=useX; cleanup=false"]),
        ],
        &["A", "B"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    let v = result
        .violations
        .iter()
        .find(|v| matches!(&v.kind, CoherenceViolationKind::HookCleanupMismatch { .. }))
        .unwrap();
    assert_eq!(v.debt_code, DEBT_HOOK_CLEANUP_MISMATCH);
}

// ===========================================================================
// 27. Checker serde round-trip
// ===========================================================================

#[test]
fn checker_serde_round_trip() {
    let c = GlobalCoherenceChecker::new().with_violation_budget(500);
    let json = serde_json::to_string(&c).unwrap();
    let back: GlobalCoherenceChecker = serde_json::from_str(&json).unwrap();
    // Both should produce same result on same input
    let inp = input(vec![entry("A")], &["A"], &[]);
    let r1 = c.check(&inp).unwrap();
    let r2 = back.check(&inp).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 28. Diamond dependency graph
// ===========================================================================

#[test]
fn diamond_graph_context_coherence() {
    //     Root
    //    /    \
    //   A      B    (both provide "theme")
    //    \    /
    //     Leaf      (requires "theme")
    let inp = input(
        vec![
            entry("Root"),
            entry_ctx("A", &[], &["theme"]),
            entry_ctx("B", &[], &["theme"]),
            entry_ctx("Leaf", &["theme"], &[]),
        ],
        &["Root", "A", "B", "Leaf"],
        &[
            ("Root", "A", CompositionEdgeKind::ParentChild),
            ("Root", "B", CompositionEdgeKind::ParentChild),
            ("A", "Leaf", CompositionEdgeKind::ParentChild),
            ("B", "Leaf", CompositionEdgeKind::ParentChild),
        ],
    );
    let result = checker().check(&inp).unwrap();
    // Leaf's context requirement is satisfied; A and B are siblings
    // so no DuplicateProvider expected (they're not ancestor-descendant)
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::DuplicateProvider { .. }
    )));
}

// ===========================================================================
// 29. Multiple hook labels
// ===========================================================================

#[test]
fn multiple_hooks_per_component() {
    let inp = input(
        vec![
            entry_hooks(
                "A",
                &[
                    "label=useAuth; cleanup=true",
                    "label=useData; cleanup=false",
                ],
            ),
            entry_hooks(
                "B",
                &["label=useAuth; cleanup=true", "label=useData; cleanup=true"],
            ),
        ],
        &["A", "B"],
        &[],
    );
    let result = checker().check(&inp).unwrap();
    // useAuth agrees (both true), useData disagrees
    assert!(has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HookCleanupMismatch { hook_label, .. }
            if hook_label == "useData"
    )));
    assert!(!has_violation_kind(&result, |k| matches!(
        k,
        CoherenceViolationKind::HookCleanupMismatch { hook_label, .. }
            if hook_label == "useAuth"
    )));
}
