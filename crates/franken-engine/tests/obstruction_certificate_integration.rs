#![forbid(unsafe_code)]
//! Integration tests for the `obstruction_certificate` module (FRX-14.3).
//!
//! Exercises the full obstruction certification pipeline from outside
//! the crate boundary: violation→certificate, certificate→fallback plan,
//! batch certification, gate helpers, and report rendering.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::global_coherence_checker::{
    CoherenceCheckInput, CoherenceCheckResult, CoherenceOutcome, CompositionEdge,
    CompositionEdgeKind, CompositionGraph, GlobalCoherenceChecker,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::obstruction_certificate::{
    CertificationOutcome, CertificationResult, DEBT_BUDGET_EXHAUSTED, DEBT_FALLBACK_INFEASIBLE,
    DEBT_OBSTRUCTION_UNRESOLVED, DEBT_PLAN_CYCLE, DEBT_WITNESS_INCOMPLETE, FallbackActionKind,
    OBSTRUCTION_CERT_BEAD_ID, OBSTRUCTION_CERT_SCHEMA_VERSION, ObstructionCertifier,
    ObstructionCertifierConfig, ObstructionError, WitnessFragment, collect_debt_codes,
    render_certification_report, should_block_gate,
};
use frankenengine_engine::semantic_contract_baseline::{
    LocalSemanticAtlas, LocalSemanticAtlasEntry, SemanticContractVersion,
};

// ===========================================================================
// Helpers — build coherence check results for certifier input
// ===========================================================================

fn entry(id: &str) -> LocalSemanticAtlasEntry {
    LocalSemanticAtlasEntry {
        component_id: id.to_string(),
        module_path: format!("src/{id}.tsx"),
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

fn make_graph(
    components: &[&str],
    edges: &[(&str, &str, CompositionEdgeKind)],
) -> CompositionGraph {
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

/// Run coherence check and return the result for certifier input.
fn run_check(
    entries: Vec<LocalSemanticAtlasEntry>,
    components: &[&str],
    edges: &[(&str, &str, CompositionEdgeKind)],
    suspense: &[&str],
    hydration: &[&str],
    cap_boundaries: &[&str],
) -> CoherenceCheckResult {
    let input = CoherenceCheckInput {
        atlas: atlas(entries),
        graph: make_graph(components, edges),
        check_epoch: 42,
        suspense_components: suspense.iter().map(|s| s.to_string()).collect(),
        hydration_components: hydration.iter().map(|s| s.to_string()).collect(),
        capability_boundary_components: cap_boundaries.iter().map(|s| s.to_string()).collect(),
    };
    GlobalCoherenceChecker::new().check(&input).unwrap()
}

fn certifier() -> ObstructionCertifier {
    ObstructionCertifier::new()
}

// ===========================================================================
// 1. Constants
// ===========================================================================

#[test]
fn schema_version_is_stable() {
    assert_eq!(
        OBSTRUCTION_CERT_SCHEMA_VERSION,
        "franken-engine.obstruction_certificate.v1"
    );
}

#[test]
fn bead_id_is_correct() {
    assert_eq!(OBSTRUCTION_CERT_BEAD_ID, "bd-mjh3.14.3");
}

#[test]
fn debt_codes_are_all_distinct() {
    let codes = [
        DEBT_OBSTRUCTION_UNRESOLVED,
        DEBT_FALLBACK_INFEASIBLE,
        DEBT_WITNESS_INCOMPLETE,
        DEBT_PLAN_CYCLE,
        DEBT_BUDGET_EXHAUSTED,
    ];
    let unique: BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn debt_codes_follow_naming_convention() {
    for code in [
        DEBT_OBSTRUCTION_UNRESOLVED,
        DEBT_FALLBACK_INFEASIBLE,
        DEBT_WITNESS_INCOMPLETE,
        DEBT_PLAN_CYCLE,
        DEBT_BUDGET_EXHAUSTED,
    ] {
        assert!(
            code.starts_with("FE-FRX-14-3-OBSTRUCTION-"),
            "code {code} missing prefix"
        );
    }
}

// ===========================================================================
// 2. FallbackActionKind display and serde
// ===========================================================================

#[test]
fn fallback_action_kind_display_all() {
    assert_eq!(FallbackActionKind::Isolate.to_string(), "isolate");
    assert_eq!(FallbackActionKind::Degrade.to_string(), "degrade");
    assert_eq!(
        FallbackActionKind::SplitBoundary.to_string(),
        "split-boundary"
    );
    assert_eq!(
        FallbackActionKind::InjectAdapter.to_string(),
        "inject-adapter"
    );
    assert_eq!(
        FallbackActionKind::RemoveAndStub.to_string(),
        "remove-and-stub"
    );
    assert_eq!(FallbackActionKind::Escalate.to_string(), "escalate");
}

#[test]
fn fallback_action_kind_serde_round_trip() {
    for kind in [
        FallbackActionKind::Isolate,
        FallbackActionKind::Degrade,
        FallbackActionKind::SplitBoundary,
        FallbackActionKind::InjectAdapter,
        FallbackActionKind::RemoveAndStub,
        FallbackActionKind::Escalate,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: FallbackActionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ===========================================================================
// 3. CertificationOutcome display and serde
// ===========================================================================

#[test]
fn certification_outcome_display_all() {
    assert_eq!(CertificationOutcome::Clear.to_string(), "clear");
    assert_eq!(
        CertificationOutcome::ObstructedWithFallbacks.to_string(),
        "obstructed-with-fallbacks"
    );
    assert_eq!(
        CertificationOutcome::ObstructedNoFallback.to_string(),
        "obstructed-no-fallback"
    );
    assert_eq!(
        CertificationOutcome::BudgetExhausted.to_string(),
        "budget-exhausted"
    );
}

#[test]
fn certification_outcome_serde_round_trip() {
    for outcome in [
        CertificationOutcome::Clear,
        CertificationOutcome::ObstructedWithFallbacks,
        CertificationOutcome::ObstructedNoFallback,
        CertificationOutcome::BudgetExhausted,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: CertificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

// ===========================================================================
// 4. WitnessFragment display and serde
// ===========================================================================

#[test]
fn witness_fragment_display() {
    let frag = WitnessFragment {
        component_id: "MyComp".to_string(),
        contract_aspect: "context.consumes".to_string(),
        contract_value: "ThemeContext".to_string(),
    };
    let display = frag.to_string();
    assert!(display.contains("MyComp"));
    assert!(display.contains("context.consumes"));
    assert!(display.contains("ThemeContext"));
}

#[test]
fn witness_fragment_serde_round_trip() {
    let frag = WitnessFragment {
        component_id: "X".to_string(),
        contract_aspect: "effect.layout".to_string(),
        contract_value: "useLayoutEffect".to_string(),
    };
    let json = serde_json::to_string(&frag).unwrap();
    let back: WitnessFragment = serde_json::from_str(&json).unwrap();
    assert_eq!(frag, back);
}

// ===========================================================================
// 5. ObstructionError display and serde
// ===========================================================================

#[test]
fn error_display_budget() {
    let err = ObstructionError::BudgetExhausted {
        resource: "certificates".to_string(),
        limit: 100,
    };
    let display = err.to_string();
    assert!(display.contains("certificates"));
    assert!(display.contains("100"));
}

#[test]
fn error_display_invalid_input() {
    let err = ObstructionError::InvalidInput("missing violations".to_string());
    assert!(err.to_string().contains("missing violations"));
}

#[test]
fn error_display_internal() {
    let err = ObstructionError::InternalInconsistency("hash mismatch".to_string());
    assert!(err.to_string().contains("hash mismatch"));
}

#[test]
fn error_serde_round_trip() {
    for err in [
        ObstructionError::BudgetExhausted {
            resource: "x".to_string(),
            limit: 1,
        },
        ObstructionError::InvalidInput("bad".to_string()),
        ObstructionError::InternalInconsistency("oops".to_string()),
    ] {
        let json = serde_json::to_string(&err).unwrap();
        let back: ObstructionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }
}

// ===========================================================================
// 6. Certifier — coherent input produces clear result
// ===========================================================================

#[test]
fn coherent_input_produces_clear() {
    let check = run_check(
        vec![
            entry_ctx("P", &[], &["theme"]),
            entry_ctx("C", &["theme"], &[]),
        ],
        &["P", "C"],
        &[("P", "C", CompositionEdgeKind::ParentChild)],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert_eq!(result.outcome, CertificationOutcome::Clear);
    assert!(result.certificates.is_empty());
    assert!(result.can_proceed());
    assert_eq!(result.total_obstructions, 0);
}

#[test]
fn clear_result_metadata() {
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let result = certifier().certify(&check).unwrap();
    assert_eq!(result.schema_version, OBSTRUCTION_CERT_SCHEMA_VERSION);
    assert_eq!(result.bead_id, OBSTRUCTION_CERT_BEAD_ID);
    assert_eq!(result.certification_epoch, 42);
}

// ===========================================================================
// 7. Certifier — unresolved context produces certificate
// ===========================================================================

#[test]
fn unresolved_context_produces_certificate() {
    let check = run_check(
        vec![entry_ctx("Orphan", &["missing"], &[])],
        &["Orphan"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(!result.certificates.is_empty());
    let cert = result
        .certificates
        .iter()
        .find(|c| c.violation_kind_tag == "unresolved-context")
        .unwrap();
    assert!(cert.witness_components.contains("Orphan"));
    assert!(cert.explanation.contains("Orphan"));
    assert!(cert.explanation.contains("missing"));
}

#[test]
fn unresolved_context_has_fallback_plan() {
    let check = run_check(
        vec![entry_ctx("Orphan", &["missing"], &[])],
        &["Orphan"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let cert = &result.certificates[0];
    let plan = cert.fallback_plan.as_ref().unwrap();
    assert!(plan.has_feasible_resolution);
    assert!(!plan.actions.is_empty());
    assert!(!plan.feasible_actions().is_empty());
}

#[test]
fn unresolved_context_fallback_includes_inject_adapter() {
    let check = run_check(
        vec![entry_ctx("C", &["ctx_a"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let cert = result
        .certificates
        .iter()
        .find(|c| c.violation_kind_tag == "unresolved-context")
        .unwrap();
    let plan = cert.fallback_plan.as_ref().unwrap();
    assert!(
        plan.actions
            .iter()
            .any(|a| a.kind == FallbackActionKind::InjectAdapter)
    );
}

// ===========================================================================
// 8. Certifier — orphaned provider produces certificate
// ===========================================================================

#[test]
fn orphaned_provider_produces_certificate() {
    let check = run_check(
        vec![entry_ctx("P", &[], &["unused"])],
        &["P"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(
        result
            .certificates
            .iter()
            .any(|c| c.violation_kind_tag == "orphaned-provider")
    );
}

#[test]
fn orphaned_provider_is_not_blocking() {
    let check = run_check(
        vec![entry_ctx("P", &[], &["unused"])],
        &["P"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert_eq!(result.blocking_obstructions, 0);
}

// ===========================================================================
// 9. Certifier — effect cycle produces certificate
// ===========================================================================

#[test]
fn effect_cycle_produces_certificate() {
    let check = run_check(
        vec![entry("A"), entry("B")],
        &["A", "B"],
        &[
            ("A", "B", CompositionEdgeKind::EffectDependency),
            ("B", "A", CompositionEdgeKind::EffectDependency),
        ],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(
        result
            .certificates
            .iter()
            .any(|c| c.violation_kind_tag == "effect-order-cycle")
    );
}

#[test]
fn effect_cycle_fallback_includes_split_boundary() {
    let check = run_check(
        vec![entry("A"), entry("B")],
        &["A", "B"],
        &[
            ("A", "B", CompositionEdgeKind::EffectDependency),
            ("B", "A", CompositionEdgeKind::EffectDependency),
        ],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let cert = result
        .certificates
        .iter()
        .find(|c| c.violation_kind_tag == "effect-order-cycle")
        .unwrap();
    let plan = cert.fallback_plan.as_ref().unwrap();
    assert!(
        plan.actions
            .iter()
            .any(|a| a.kind == FallbackActionKind::SplitBoundary)
    );
}

// ===========================================================================
// 10. Certifier — layout-after-passive
// ===========================================================================

#[test]
fn layout_after_passive_produces_certificate() {
    let check = run_check(
        vec![
            entry_effects("Parent", &["PassiveEffect"]),
            entry_effects("Child", &["LayoutEffect"]),
        ],
        &["Parent", "Child"],
        &[("Parent", "Child", CompositionEdgeKind::ParentChild)],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(
        result
            .certificates
            .iter()
            .any(|c| c.violation_kind_tag == "layout-after-passive")
    );
}

// ===========================================================================
// 11. Certifier — hook cleanup mismatch
// ===========================================================================

#[test]
fn hook_cleanup_mismatch_produces_certificate() {
    let check = run_check(
        vec![
            entry_hooks("A", &["label=useData; cleanup=true"]),
            entry_hooks("B", &["label=useData; cleanup=false"]),
        ],
        &["A", "B"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(
        result
            .certificates
            .iter()
            .any(|c| c.violation_kind_tag == "hook-cleanup-mismatch")
    );
}

// ===========================================================================
// 12. Certifier — hydration boundary conflict
// ===========================================================================

#[test]
fn hydration_conflict_produces_certificate() {
    let check = run_check(
        vec![
            entry("Hbnd"),
            entry_effects("BadChild", &["idempotent=false"]),
        ],
        &["Hbnd", "BadChild"],
        &[("Hbnd", "BadChild", CompositionEdgeKind::ParentChild)],
        &[],
        &["Hbnd"],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(
        result
            .certificates
            .iter()
            .any(|c| c.violation_kind_tag == "hydration-boundary-conflict")
    );
}

// ===========================================================================
// 13. Certifier — capability gap
// ===========================================================================

#[test]
fn capability_gap_produces_certificate() {
    let check = run_check(
        vec![
            entry("Boundary"),
            entry_caps("Uncovered", &["network", "storage"]),
        ],
        &["Boundary", "Uncovered"],
        &[],
        &[],
        &[],
        &["Boundary"],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(
        result
            .certificates
            .iter()
            .any(|c| c.violation_kind_tag == "capability-gap")
    );
}

// ===========================================================================
// 14. Certifier — boundary capability leak
// ===========================================================================

#[test]
fn boundary_leak_produces_certificate() {
    let check = run_check(
        vec![
            entry_caps("Boundary", &["network"]),
            entry_caps("Child", &["network", "eval"]),
        ],
        &["Boundary", "Child"],
        &[("Boundary", "Child", CompositionEdgeKind::ParentChild)],
        &[],
        &[],
        &["Boundary"],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(
        result
            .certificates
            .iter()
            .any(|c| c.violation_kind_tag == "boundary-capability-leak")
    );
}

// ===========================================================================
// 15. CertificationResult accessors
// ===========================================================================

#[test]
fn can_proceed_true_for_clear() {
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let result = certifier().certify(&check).unwrap();
    assert!(result.can_proceed());
}

#[test]
fn can_proceed_true_for_obstructed_with_fallbacks() {
    // Orphaned provider → non-blocking, has feasible fallback
    let check = run_check(
        vec![entry_ctx("P", &[], &["unused"])],
        &["P"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    // Should be ObstructedWithFallbacks since all have feasible plans
    assert!(result.can_proceed());
}

#[test]
fn blocking_certificates_filter() {
    let check = run_check(
        vec![
            entry_ctx("C", &["missing"], &[]), // critical → blocking
            entry_ctx("P", &[], &["unused"]),  // low → not blocking
        ],
        &["C", "P"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let blocking = result.blocking_certificates();
    assert!(!blocking.is_empty());
    // All blocking should have severity >= medium
    assert!(blocking.iter().all(|c| c.is_blocking()));
}

#[test]
fn infeasible_certificates_empty_when_all_feasible() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(result.infeasible_certificates().is_empty());
}

#[test]
fn by_debt_code_groups_correctly() {
    let check = run_check(
        vec![entry_ctx("C1", &["m1"], &[]), entry_ctx("C2", &["m2"], &[])],
        &["C1", "C2"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let by_code = result.by_debt_code();
    assert!(!by_code.is_empty());
}

#[test]
fn summary_line_contains_key_info() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let summary = result.summary_line();
    assert!(summary.contains("obstruction"));
    assert!(summary.contains("feasible"));
}

// ===========================================================================
// 16. ObstructionCertificate accessors
// ===========================================================================

#[test]
fn certificate_is_blocking_matches_severity() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    for cert in &result.certificates {
        assert_eq!(cert.is_blocking(), cert.severity.is_blocking());
    }
}

#[test]
fn certificate_summary_line_contains_debt_code() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    for cert in &result.certificates {
        let summary = cert.summary_line();
        assert!(summary.contains(&cert.debt_code));
    }
}

// ===========================================================================
// 17. FallbackPlan accessors
// ===========================================================================

#[test]
fn recommended_action_exists_when_feasible() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    for cert in &result.certificates {
        let plan = cert.fallback_plan.as_ref().unwrap();
        if plan.has_feasible_resolution {
            assert!(plan.recommended_action().is_some());
            assert!(plan.recommended_action().unwrap().feasible);
        }
    }
}

#[test]
fn feasible_actions_filtered() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    for cert in &result.certificates {
        let plan = cert.fallback_plan.as_ref().unwrap();
        let feasible = plan.feasible_actions();
        assert!(feasible.iter().all(|a| a.feasible));
    }
}

#[test]
fn plan_summary_line_contains_action_count() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    for cert in &result.certificates {
        let plan = cert.fallback_plan.as_ref().unwrap();
        let summary = plan.summary_line();
        assert!(summary.contains("actions"));
        assert!(summary.contains("feasible"));
    }
}

// ===========================================================================
// 18. Disruption cost scaling
// ===========================================================================

#[test]
fn disruption_cost_scales_with_target_count() {
    // More targets = higher disruption cost
    let check_1 = run_check(
        vec![entry_ctx("C1", &["m1"], &[])],
        &["C1"],
        &[],
        &[],
        &[],
        &[],
    );
    let check_2 = run_check(
        vec![entry_ctx("C1", &["m1"], &[]), entry_ctx("C2", &["m2"], &[])],
        &["C1", "C2"],
        &[],
        &[],
        &[],
        &[],
    );

    let r1 = certifier().certify(&check_1).unwrap();
    let r2 = certifier().certify(&check_2).unwrap();

    // The second result should have more certificates
    assert!(r2.certificates.len() >= r1.certificates.len());
}

#[test]
fn fallback_actions_sorted_by_disruption_cost() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    for cert in &result.certificates {
        let plan = cert.fallback_plan.as_ref().unwrap();
        for window in plan.actions.windows(2) {
            assert!(window[0].disruption_cost_millionths <= window[1].disruption_cost_millionths);
        }
    }
}

// ===========================================================================
// 19. Budget exhaustion
// ===========================================================================

#[test]
fn budget_limits_certificate_count() {
    let config = ObstructionCertifierConfig {
        max_certificates: 1,
        ..ObstructionCertifierConfig::default()
    };
    let c = ObstructionCertifier::with_config(config);

    let check = run_check(
        vec![
            entry_ctx("C1", &["m1"], &[]),
            entry_ctx("C2", &["m2"], &[]),
            entry_ctx("C3", &["m3"], &[]),
        ],
        &["C1", "C2", "C3"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = c.certify(&check).unwrap();
    assert_eq!(result.outcome, CertificationOutcome::BudgetExhausted);
    assert!(result.certificates.len() <= 1);
}

// ===========================================================================
// 20. Config — include_non_blocking
// ===========================================================================

#[test]
fn exclude_non_blocking_filters_low_severity() {
    let config = ObstructionCertifierConfig {
        include_non_blocking: false,
        ..ObstructionCertifierConfig::default()
    };
    let c = ObstructionCertifier::with_config(config);

    // Only orphaned provider (low severity) → should be filtered out
    let check = run_check(
        vec![entry_ctx("P", &[], &["unused"])],
        &["P"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = c.certify(&check).unwrap();
    assert_eq!(result.outcome, CertificationOutcome::Clear);
    assert!(result.certificates.is_empty());
}

#[test]
fn exclude_non_blocking_keeps_blocking() {
    let config = ObstructionCertifierConfig {
        include_non_blocking: false,
        ..ObstructionCertifierConfig::default()
    };
    let c = ObstructionCertifier::with_config(config);

    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = c.certify(&check).unwrap();
    assert!(!result.certificates.is_empty());
}

// ===========================================================================
// 21. Deterministic hashing
// ===========================================================================

#[test]
fn same_input_same_result_hash() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let r1 = certifier().certify(&check).unwrap();
    let r2 = certifier().certify(&check).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

#[test]
fn different_violations_different_result_hash() {
    let check1 = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let check2 = run_check(
        vec![entry_ctx("A", &["missing"], &[])],
        &["A"],
        &[],
        &[],
        &[],
        &[],
    );
    let r1 = certifier().certify(&check1).unwrap();
    let r2 = certifier().certify(&check2).unwrap();
    assert_ne!(r1.result_hash, r2.result_hash);
}

#[test]
fn certificate_hash_deterministic() {
    let check = run_check(
        vec![entry_ctx("C", &["ctx_x"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let r1 = certifier().certify(&check).unwrap();
    let r2 = certifier().certify(&check).unwrap();
    for (c1, c2) in r1.certificates.iter().zip(r2.certificates.iter()) {
        assert_eq!(c1.certificate_hash, c2.certificate_hash);
    }
}

// ===========================================================================
// 22. Gate integration helpers
// ===========================================================================

#[test]
fn should_block_gate_for_no_fallback() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    // All fallbacks are feasible → should not block
    assert!(!should_block_gate(&result));
}

#[test]
fn should_block_gate_for_budget_exhausted() {
    let config = ObstructionCertifierConfig {
        max_certificates: 1,
        ..ObstructionCertifierConfig::default()
    };
    let c = ObstructionCertifier::with_config(config);

    let check = run_check(
        vec![
            entry_ctx("C1", &["m1"], &[]),
            entry_ctx("C2", &["m2"], &[]),
            entry_ctx("C3", &["m3"], &[]),
        ],
        &["C1", "C2", "C3"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = c.certify(&check).unwrap();
    assert!(should_block_gate(&result));
}

#[test]
fn should_not_block_gate_for_clear() {
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let result = certifier().certify(&check).unwrap();
    assert!(!should_block_gate(&result));
}

// ===========================================================================
// 23. collect_debt_codes
// ===========================================================================

#[test]
fn collect_debt_codes_from_result() {
    let check = run_check(
        vec![
            entry_ctx("C", &["missing"], &[]),
            entry_ctx("P", &[], &["orphan"]),
        ],
        &["C", "P"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let codes = collect_debt_codes(&result);
    assert!(!codes.is_empty());
}

#[test]
fn collect_debt_codes_empty_for_clear() {
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let result = certifier().certify(&check).unwrap();
    let codes = collect_debt_codes(&result);
    assert!(codes.is_empty());
}

// ===========================================================================
// 24. render_certification_report
// ===========================================================================

#[test]
fn report_for_clear_mentions_coherent() {
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let result = certifier().certify(&check).unwrap();
    let report = render_certification_report(&result);
    assert!(report.contains("coherent"));
    assert!(report.contains("Result hash:"));
}

#[test]
fn report_for_obstructed_contains_details() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let report = render_certification_report(&result);
    assert!(report.contains("Obstruction #1"));
    assert!(report.contains("Explanation:"));
    assert!(report.contains("Witness components:"));
    assert!(report.contains("Fragment:"));
    assert!(report.contains("Fallback plan:"));
    assert!(report.contains("[RECOMMENDED]"));
    assert!(report.contains("Result hash:"));
}

#[test]
fn report_contains_epoch() {
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let result = certifier().certify(&check).unwrap();
    let report = render_certification_report(&result);
    assert!(report.contains("epoch 42"));
}

// ===========================================================================
// 25. Serde round-trips for full types
// ===========================================================================

#[test]
fn certification_result_serde_round_trip() {
    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: CertificationResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result.outcome, back.outcome);
    assert_eq!(result.certificates.len(), back.certificates.len());
    assert_eq!(result.result_hash, back.result_hash);
}

#[test]
fn certifier_config_serde_round_trip() {
    let config = ObstructionCertifierConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: ObstructionCertifierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn certifier_serde_round_trip() {
    let c = ObstructionCertifier::new();
    let json = serde_json::to_string(&c).unwrap();
    let back: ObstructionCertifier = serde_json::from_str(&json).unwrap();
    // Both should produce same result on same input
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let r1 = c.certify(&check).unwrap();
    let r2 = back.certify(&check).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 26. Combined multi-violation scenario
// ===========================================================================

#[test]
fn multiple_violation_types_produce_multiple_certificates() {
    let check = run_check(
        vec![
            entry_ctx("Consumer", &["missing_ctx"], &[]),
            entry_ctx("Provider", &[], &["orphan_ctx"]),
            entry_effects("Parent", &["PassiveEffect"]),
            entry_effects("Child", &["LayoutEffect"]),
        ],
        &["Consumer", "Provider", "Parent", "Child"],
        &[("Parent", "Child", CompositionEdgeKind::ParentChild)],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    assert!(result.certificates.len() >= 3);

    let tags: BTreeSet<String> = result
        .certificates
        .iter()
        .map(|c| c.violation_kind_tag.clone())
        .collect();
    assert!(tags.contains("unresolved-context"));
    assert!(tags.contains("orphaned-provider"));
    assert!(tags.contains("layout-after-passive"));
}

// ===========================================================================
// 27. Witness fragment correctness
// ===========================================================================

#[test]
fn unresolved_context_witness_has_consumes_fragment() {
    let check = run_check(
        vec![entry_ctx("Comp", &["ThemeCtx"], &[])],
        &["Comp"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let cert = result
        .certificates
        .iter()
        .find(|c| c.violation_kind_tag == "unresolved-context")
        .unwrap();
    assert!(
        cert.witness_fragments
            .iter()
            .any(|f| { f.contract_aspect == "context.consumes" && f.contract_value == "ThemeCtx" })
    );
}

#[test]
fn layout_after_passive_witness_has_two_components() {
    let check = run_check(
        vec![
            entry_effects("P", &["PassiveEffect"]),
            entry_effects("C", &["LayoutEffect"]),
        ],
        &["P", "C"],
        &[("P", "C", CompositionEdgeKind::ParentChild)],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let cert = result
        .certificates
        .iter()
        .find(|c| c.violation_kind_tag == "layout-after-passive")
        .unwrap();
    assert_eq!(cert.witness_components.len(), 2);
    assert!(cert.witness_components.contains("P"));
    assert!(cert.witness_components.contains("C"));
}

// ===========================================================================
// 28. Certifier default == new
// ===========================================================================

#[test]
fn certifier_default_equals_new() {
    let c1 = ObstructionCertifier::new();
    let c2 = ObstructionCertifier::default();
    let check = run_check(vec![entry("A")], &["A"], &[], &[], &[], &[]);
    let r1 = c1.certify(&check).unwrap();
    let r2 = c2.certify(&check).unwrap();
    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 29. Suspense boundary conflict certificate
// ===========================================================================

#[test]
fn suspense_conflict_produces_certificate_with_boundary_fragments() {
    let check = run_check(
        vec![
            entry("Susp"),
            entry_effects("AsyncChild", &["async-fetch; suspense"]),
            entry_effects("SyncLayoutChild", &["LayoutEffect"]),
        ],
        &["Susp", "AsyncChild", "SyncLayoutChild"],
        &[
            ("Susp", "AsyncChild", CompositionEdgeKind::ParentChild),
            ("Susp", "SyncLayoutChild", CompositionEdgeKind::ParentChild),
        ],
        &["Susp"],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    let susp_certs: Vec<_> = result
        .certificates
        .iter()
        .filter(|c| c.violation_kind_tag == "suspense-boundary-conflict")
        .collect();
    assert!(!susp_certs.is_empty());
    // Should have boundary.suspense fragment
    for cert in &susp_certs {
        assert!(
            cert.witness_fragments
                .iter()
                .any(|f| f.contract_aspect.starts_with("boundary.suspense"))
        );
    }
}

// ===========================================================================
// 30. Edge case: coherent-with-warnings still produces certificates
// ===========================================================================

#[test]
fn coherent_with_warnings_produces_certificates() {
    // Orphaned provider → CoherentWithWarnings
    let check = run_check(
        vec![entry_ctx("P", &[], &["unused"])],
        &["P"],
        &[],
        &[],
        &[],
        &[],
    );
    assert_eq!(check.outcome, CoherenceOutcome::CoherentWithWarnings);
    let result = certifier().certify(&check).unwrap();
    // Default config includes non-blocking → should have certificate
    assert!(!result.certificates.is_empty());
    assert!(result.can_proceed());
}

// ===========================================================================
// 31. Custom disruption costs
// ===========================================================================

#[test]
fn custom_disruption_costs_affect_ordering() {
    let mut costs = BTreeMap::new();
    // Make isolate very expensive, escalate cheap
    costs.insert("isolate".to_string(), 9_000_000);
    costs.insert("degrade".to_string(), 8_000_000);
    costs.insert("split-boundary".to_string(), 7_000_000);
    costs.insert("inject-adapter".to_string(), 6_000_000);
    costs.insert("remove-and-stub".to_string(), 5_000_000);
    costs.insert("escalate".to_string(), 100_000);

    let config = ObstructionCertifierConfig {
        disruption_costs: costs,
        ..ObstructionCertifierConfig::default()
    };
    let c = ObstructionCertifier::with_config(config);

    let check = run_check(
        vec![entry_ctx("C", &["missing"], &[])],
        &["C"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = c.certify(&check).unwrap();
    let cert = &result.certificates[0];
    let plan = cert.fallback_plan.as_ref().unwrap();
    // Escalate should be first (cheapest)
    assert_eq!(plan.actions[0].kind, FallbackActionKind::Escalate);
}

// ===========================================================================
// 32. Evidence hashes on certificates and actions
// ===========================================================================

#[test]
fn all_certificates_have_nonzero_hashes() {
    let check = run_check(
        vec![
            entry_ctx("C", &["missing"], &[]),
            entry_ctx("P", &[], &["orphan"]),
        ],
        &["C", "P"],
        &[],
        &[],
        &[],
        &[],
    );
    let result = certifier().certify(&check).unwrap();
    for cert in &result.certificates {
        assert!(!cert.certificate_hash.as_bytes().is_empty());
        if let Some(plan) = &cert.fallback_plan {
            assert!(!plan.plan_hash.as_bytes().is_empty());
            for action in &plan.actions {
                assert!(!action.rationale_hash.as_bytes().is_empty());
            }
        }
    }
}
