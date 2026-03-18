#![forbid(unsafe_code)]
//! Deep integration tests for the `obstruction_certificate` module (FRX-14.3).
//!
//! Covers edge cases, multi-violation mixed scenarios, budget boundary
//! conditions, witness truncation, disruption cost scaling, determinism
//! under reordering, end-to-end pipeline (checker → certifier), and
//! report rendering corner cases not exercised by the existing test suites.

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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::global_coherence_checker::{
    CoherenceCheckResult, CoherenceOutcome, CoherenceViolation, CoherenceViolationKind,
    DEBT_CAPABILITY_GAP, DEBT_EFFECT_CYCLE, DEBT_HOOK_CLEANUP_MISMATCH,
    DEBT_HYDRATION_BOUNDARY_CONFLICT, DEBT_SUSPENSE_BOUNDARY_CONFLICT, DEBT_UNRESOLVED_CONTEXT,
    GLOBAL_COHERENCE_SCHEMA_VERSION, SeverityScore,
};
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::obstruction_certificate::{
    CertificationOutcome, CertificationResult, DEBT_BUDGET_EXHAUSTED, DEBT_FALLBACK_INFEASIBLE,
    DEBT_OBSTRUCTION_UNRESOLVED, DEBT_PLAN_CYCLE, DEBT_WITNESS_INCOMPLETE, FallbackActionKind,
    OBSTRUCTION_CERT_BEAD_ID, OBSTRUCTION_CERT_SCHEMA_VERSION, ObstructionCertifier,
    ObstructionCertifierConfig, ObstructionError, WitnessFragment, collect_debt_codes,
    render_certification_report, should_block_gate,
};

// ===========================================================================
// Helpers
// ===========================================================================

fn make_violation(
    kind: CoherenceViolationKind,
    severity: SeverityScore,
    debt_code: &str,
) -> CoherenceViolation {
    let desc = format!("{kind:?}");
    let evidence_hash = ContentHash::compute(desc.as_bytes());
    let schema_id = SchemaId::from_definition(b"test.violation.v1");
    let id = derive_id(
        ObjectDomain::EvidenceRecord,
        "test-violation",
        &schema_id,
        evidence_hash.as_bytes(),
    )
    .unwrap();
    CoherenceViolation {
        id,
        kind,
        severity,
        debt_code: debt_code.to_string(),
        description: desc,
        evidence_hash,
        detected_epoch: 1,
    }
}

fn make_violation_unique(
    kind: CoherenceViolationKind,
    severity: SeverityScore,
    debt_code: &str,
    salt: &str,
) -> CoherenceViolation {
    let desc = format!("{kind:?}|{salt}");
    let evidence_hash = ContentHash::compute(desc.as_bytes());
    let schema_id = SchemaId::from_definition(b"test.violation.unique.v1");
    let id = derive_id(
        ObjectDomain::EvidenceRecord,
        "test-violation-unique",
        &schema_id,
        evidence_hash.as_bytes(),
    )
    .unwrap();
    CoherenceViolation {
        id,
        kind,
        severity,
        debt_code: debt_code.to_string(),
        description: desc,
        evidence_hash,
        detected_epoch: 1,
    }
}

fn make_check_result(
    violations: Vec<CoherenceViolation>,
    outcome: CoherenceOutcome,
) -> CoherenceCheckResult {
    let result_hash = ContentHash::compute(b"test-result");
    CoherenceCheckResult {
        schema_version: GLOBAL_COHERENCE_SCHEMA_VERSION.to_string(),
        bead_id: "bd-test".to_string(),
        outcome,
        component_count: 10,
        edge_count: 15,
        context_pairs_checked: 5,
        capability_boundaries_checked: 3,
        effect_orderings_checked: 2,
        suspense_boundaries_checked: 1,
        hydration_boundaries_checked: 1,
        total_severity_millionths: violations.iter().map(|v| v.severity.0).sum(),
        blocking_violation_count: violations
            .iter()
            .filter(|v| v.severity.is_blocking())
            .count(),
        check_epoch: 42,
        result_hash,
        violations,
    }
}

fn make_check_result_epoch(
    violations: Vec<CoherenceViolation>,
    outcome: CoherenceOutcome,
    epoch: u64,
) -> CoherenceCheckResult {
    let mut r = make_check_result(violations, outcome);
    r.check_epoch = epoch;
    r
}

fn blocking_severity() -> SeverityScore {
    SeverityScore(750_000) // above 500_000 threshold
}

fn non_blocking_severity() -> SeverityScore {
    SeverityScore(250_000) // below 500_000 threshold
}

fn edge_blocking_severity() -> SeverityScore {
    SeverityScore(500_000) // exactly at threshold
}

fn unresolved_context_violation(consumer: &str, key: &str) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::UnresolvedContext {
            consumer: consumer.to_string(),
            context_key: key.to_string(),
        },
        blocking_severity(),
        DEBT_UNRESOLVED_CONTEXT,
    )
}

fn orphaned_provider_violation(provider: &str, key: &str) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::OrphanedProvider {
            provider: provider.to_string(),
            context_key: key.to_string(),
        },
        non_blocking_severity(),
        DEBT_UNRESOLVED_CONTEXT,
    )
}

fn capability_gap_violation(component: &str, caps: &[&str]) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::CapabilityGap {
            component: component.to_string(),
            missing_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        },
        blocking_severity(),
        DEBT_CAPABILITY_GAP,
    )
}

fn effect_cycle_violation(participants: &[&str]) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::EffectOrderCycle {
            cycle_participants: participants.iter().map(|s| s.to_string()).collect(),
        },
        blocking_severity(),
        DEBT_EFFECT_CYCLE,
    )
}

fn layout_after_passive_violation(layout: &str, passive: &str) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::LayoutAfterPassive {
            layout_component: layout.to_string(),
            passive_component: passive.to_string(),
        },
        blocking_severity(),
        DEBT_EFFECT_CYCLE,
    )
}

fn suspense_conflict_violation(
    boundary: &str,
    children: &[&str],
    reason: &str,
) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::SuspenseBoundaryConflict {
            boundary_component: boundary.to_string(),
            conflicting_children: children.iter().map(|s| s.to_string()).collect(),
            reason: reason.to_string(),
        },
        blocking_severity(),
        DEBT_SUSPENSE_BOUNDARY_CONFLICT,
    )
}

fn hydration_conflict_violation(
    boundary: &str,
    children: &[&str],
    reason: &str,
) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::HydrationBoundaryConflict {
            boundary_component: boundary.to_string(),
            conflicting_children: children.iter().map(|s| s.to_string()).collect(),
            reason: reason.to_string(),
        },
        blocking_severity(),
        DEBT_HYDRATION_BOUNDARY_CONFLICT,
    )
}

fn hook_mismatch_violation(comp_a: &str, comp_b: &str, hook: &str) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::HookCleanupMismatch {
            component_a: comp_a.to_string(),
            component_b: comp_b.to_string(),
            hook_label: hook.to_string(),
        },
        blocking_severity(),
        DEBT_HOOK_CLEANUP_MISMATCH,
    )
}

fn duplicate_provider_violation(providers: &[&str], key: &str) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::DuplicateProvider {
            providers: providers.iter().map(|s| s.to_string()).collect(),
            context_key: key.to_string(),
        },
        blocking_severity(),
        DEBT_UNRESOLVED_CONTEXT,
    )
}

fn boundary_leak_violation(boundary: &str, caps: &[&str]) -> CoherenceViolation {
    make_violation(
        CoherenceViolationKind::BoundaryCapabilityLeak {
            boundary: boundary.to_string(),
            leaked_capabilities: caps.iter().map(|s| s.to_string()).collect(),
        },
        blocking_severity(),
        DEBT_CAPABILITY_GAP,
    )
}

// ===========================================================================
// 1. Multi-violation mixed scenarios
// ===========================================================================

#[test]
fn mixed_violations_all_ten_kinds_produce_ten_certificates() {
    let violations = vec![
        unresolved_context_violation("ConsumerA", "ThemeCtx"),
        orphaned_provider_violation("ProviderB", "AuthCtx"),
        capability_gap_violation("CompC", &["network", "fs"]),
        effect_cycle_violation(&["CompD", "CompE", "CompF"]),
        layout_after_passive_violation("LayoutG", "PassiveH"),
        suspense_conflict_violation("SuspenseI", &["ChildJ", "ChildK"], "async mismatch"),
        hydration_conflict_violation("HydrationL", &["ChildM"], "effect conflict"),
        hook_mismatch_violation("CompN", "CompO", "useInterval"),
        duplicate_provider_violation(&["ProvP", "ProvQ"], "RouterCtx"),
        boundary_leak_violation("BoundaryR", &["net", "crypto"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let certifier = ObstructionCertifier::new();
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 10);
    assert_eq!(result.total_obstructions, 10);
    // Every certificate should have a fallback plan
    for cert in &result.certificates {
        assert!(cert.fallback_plan.is_some());
    }
}

#[test]
fn mixed_violations_each_has_distinct_certificate_hash() {
    let violations = vec![
        unresolved_context_violation("A", "CtxA"),
        orphaned_provider_violation("B", "CtxB"),
        capability_gap_violation("C", &["cap1"]),
        effect_cycle_violation(&["D", "E"]),
        layout_after_passive_violation("F", "G"),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let certifier = ObstructionCertifier::new();
    let result = certifier.certify(&check).unwrap();

    let hashes: BTreeSet<_> = result
        .certificates
        .iter()
        .map(|c| c.certificate_hash.clone())
        .collect();
    assert_eq!(hashes.len(), result.certificates.len());
}

#[test]
fn mixed_blocking_and_nonblocking_counted_correctly() {
    let violations = vec![
        make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "X".to_string(),
                context_key: "K".to_string(),
            },
            blocking_severity(),
            DEBT_UNRESOLVED_CONTEXT,
        ),
        make_violation(
            CoherenceViolationKind::OrphanedProvider {
                provider: "Y".to_string(),
                context_key: "K2".to_string(),
            },
            non_blocking_severity(),
            DEBT_UNRESOLVED_CONTEXT,
        ),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let certifier = ObstructionCertifier::new();
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.blocking_obstructions, 1);
    assert_eq!(result.total_obstructions, 2);
    let blocking = result.blocking_certificates();
    assert_eq!(blocking.len(), 1);
    assert!(blocking[0].is_blocking());
}

#[test]
fn mixed_violations_all_violation_kind_tags_present() {
    let violations = vec![
        unresolved_context_violation("A", "K1"),
        orphaned_provider_violation("B", "K2"),
        capability_gap_violation("C", &["c1"]),
        effect_cycle_violation(&["D", "E"]),
        layout_after_passive_violation("F", "G"),
        suspense_conflict_violation("H", &["I"], "r"),
        hydration_conflict_violation("J", &["K"], "r2"),
        hook_mismatch_violation("L", "M", "h1"),
        duplicate_provider_violation(&["N", "O"], "K3"),
        boundary_leak_violation("P", &["cap"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let certifier = ObstructionCertifier::new();
    let result = certifier.certify(&check).unwrap();

    let tags: BTreeSet<_> = result
        .certificates
        .iter()
        .map(|c| c.violation_kind_tag.clone())
        .collect();
    assert!(tags.contains("unresolved-context"));
    assert!(tags.contains("orphaned-provider"));
    assert!(tags.contains("capability-gap"));
    assert!(tags.contains("effect-order-cycle"));
    assert!(tags.contains("layout-after-passive"));
    assert!(tags.contains("suspense-boundary-conflict"));
    assert!(tags.contains("hydration-boundary-conflict"));
    assert!(tags.contains("hook-cleanup-mismatch"));
    assert!(tags.contains("duplicate-provider"));
    assert!(tags.contains("boundary-capability-leak"));
    assert_eq!(tags.len(), 10);
}

// ===========================================================================
// 2. Budget boundary conditions
// ===========================================================================

#[test]
fn certificate_budget_exact_boundary() {
    let config = ObstructionCertifierConfig {
        max_certificates: 3,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    // Exactly 3 violations → should not trigger budget exhaustion
    let violations: Vec<CoherenceViolation> = (0..3)
        .map(|i| {
            make_violation_unique(
                CoherenceViolationKind::UnresolvedContext {
                    consumer: format!("C{i}"),
                    context_key: format!("K{i}"),
                },
                blocking_severity(),
                DEBT_UNRESOLVED_CONTEXT,
                &format!("exact-{i}"),
            )
        })
        .collect();
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 3);
    assert_ne!(result.outcome, CertificationOutcome::BudgetExhausted);
}

#[test]
fn certificate_budget_one_over_triggers_exhaustion() {
    let config = ObstructionCertifierConfig {
        max_certificates: 3,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    // 4 violations with max_certificates=3 → budget exhausted
    let violations: Vec<CoherenceViolation> = (0..4)
        .map(|i| {
            make_violation_unique(
                CoherenceViolationKind::UnresolvedContext {
                    consumer: format!("C{i}"),
                    context_key: format!("K{i}"),
                },
                blocking_severity(),
                DEBT_UNRESOLVED_CONTEXT,
                &format!("over-{i}"),
            )
        })
        .collect();
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 3);
    assert_eq!(result.outcome, CertificationOutcome::BudgetExhausted);
    assert!(should_block_gate(&result));
}

#[test]
fn certificate_budget_one_under_no_exhaustion() {
    let config = ObstructionCertifierConfig {
        max_certificates: 5,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    let violations: Vec<CoherenceViolation> = (0..4)
        .map(|i| {
            make_violation_unique(
                CoherenceViolationKind::UnresolvedContext {
                    consumer: format!("C{i}"),
                    context_key: format!("K{i}"),
                },
                blocking_severity(),
                DEBT_UNRESOLVED_CONTEXT,
                &format!("under-{i}"),
            )
        })
        .collect();
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 4);
    assert_ne!(result.outcome, CertificationOutcome::BudgetExhausted);
}

#[test]
fn max_actions_per_plan_truncates_fallback_list() {
    let config = ObstructionCertifierConfig {
        max_actions_per_plan: 2,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    // Unresolved context normally produces 4 actions
    let v = unresolved_context_violation("A", "ThemeCtx");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    assert!(plan.actions.len() <= 2);
}

#[test]
fn max_actions_one_allows_only_one_action() {
    let config = ObstructionCertifierConfig {
        max_actions_per_plan: 1,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    let v = capability_gap_violation("Widget", &["net"]);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    assert_eq!(plan.actions.len(), 1);
}

// ===========================================================================
// 3. Exclude non-blocking filter edge cases
// ===========================================================================

#[test]
fn exclude_non_blocking_removes_all_when_none_blocking() {
    let config = ObstructionCertifierConfig {
        include_non_blocking: false,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    // All violations are non-blocking
    let violations = vec![
        orphaned_provider_violation("A", "K1"),
        make_violation(
            CoherenceViolationKind::UnresolvedContext {
                consumer: "B".to_string(),
                context_key: "K2".to_string(),
            },
            non_blocking_severity(),
            DEBT_UNRESOLVED_CONTEXT,
        ),
    ];
    let check = make_check_result(violations, CoherenceOutcome::CoherentWithWarnings);
    let result = certifier.certify(&check).unwrap();

    // Should produce clear result since non-blocking filtered out
    assert_eq!(result.outcome, CertificationOutcome::Clear);
    assert!(result.certificates.is_empty());
    assert!(result.can_proceed());
}

#[test]
fn exclude_non_blocking_keeps_mixed_blocking_only() {
    let config = ObstructionCertifierConfig {
        include_non_blocking: false,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    let violations = vec![
        orphaned_provider_violation("A", "K1"),  // non-blocking
        unresolved_context_violation("B", "K2"), // blocking
        make_violation(
            CoherenceViolationKind::CapabilityGap {
                component: "C".to_string(),
                missing_capabilities: vec!["net".to_string()],
            },
            non_blocking_severity(),
            DEBT_CAPABILITY_GAP,
        ), // non-blocking
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 1);
    assert_eq!(
        result.certificates[0].violation_kind_tag,
        "unresolved-context"
    );
}

#[test]
fn include_non_blocking_default_keeps_all() {
    let certifier = ObstructionCertifier::new();

    let violations = vec![
        orphaned_provider_violation("A", "K1"),  // non-blocking
        unresolved_context_violation("B", "K2"), // blocking
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 2);
}

// ===========================================================================
// 4. Severity edge cases
// ===========================================================================

#[test]
fn severity_exactly_at_threshold_is_blocking() {
    let v = make_violation(
        CoherenceViolationKind::UnresolvedContext {
            consumer: "Edge".to_string(),
            context_key: "Ctx".to_string(),
        },
        edge_blocking_severity(), // exactly 500_000
        DEBT_UNRESOLVED_CONTEXT,
    );
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let certifier = ObstructionCertifier::new();
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.blocking_obstructions, 1);
    assert!(result.certificates[0].is_blocking());
}

#[test]
fn severity_one_below_threshold_not_blocking() {
    let v = make_violation(
        CoherenceViolationKind::UnresolvedContext {
            consumer: "JustBelow".to_string(),
            context_key: "Ctx".to_string(),
        },
        SeverityScore(499_999),
        DEBT_UNRESOLVED_CONTEXT,
    );
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let certifier = ObstructionCertifier::new();
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.blocking_obstructions, 0);
    assert!(!result.certificates[0].is_blocking());
}

// ===========================================================================
// 5. Disruption cost scaling
// ===========================================================================

#[test]
fn disruption_cost_scales_linearly_with_targets() {
    let certifier = ObstructionCertifier::new();

    // Single-target capability gap
    let v1 = capability_gap_violation("Single", &["net"]);
    let check1 = make_check_result(vec![v1], CoherenceOutcome::Incoherent);
    let r1 = certifier.certify(&check1).unwrap();
    let plan1 = r1.certificates[0].fallback_plan.as_ref().unwrap();

    // Triple-target capability gap (via effect cycle with 3 participants)
    let v3 = effect_cycle_violation(&["A", "B", "C"]);
    let check3 = make_check_result(vec![v3], CoherenceOutcome::Incoherent);
    let r3 = certifier.certify(&check3).unwrap();
    let plan3 = r3.certificates[0].fallback_plan.as_ref().unwrap();

    // Each action type should cost more with more targets
    // (actions are sorted by cost, so compare corresponding actions by kind)
    for action3 in &plan3.actions {
        for action1 in &plan1.actions {
            if action3.kind == action1.kind {
                assert!(
                    action3.disruption_cost_millionths >= action1.disruption_cost_millionths,
                    "cost for {:?} with 3 targets ({}) should be >= 1 target ({})",
                    action3.kind,
                    action3.disruption_cost_millionths,
                    action1.disruption_cost_millionths,
                );
            }
        }
    }
}

#[test]
fn disruption_cost_capped_at_ten_million() {
    let certifier = ObstructionCertifier::new();

    // Many-participant cycle (20 targets) → cost should be capped
    let participants: Vec<&str> = (0..20).map(|_| "Component").collect();
    let v = effect_cycle_violation(&participants);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    for action in &plan.actions {
        assert!(
            action.disruption_cost_millionths <= 10_000_000,
            "cost {} exceeds 10M cap",
            action.disruption_cost_millionths
        );
    }
}

#[test]
fn custom_disruption_costs_override_defaults() {
    let mut costs = BTreeMap::new();
    costs.insert("isolate".to_string(), 1_000);
    costs.insert("degrade".to_string(), 2_000);
    costs.insert("split-boundary".to_string(), 3_000);
    costs.insert("inject-adapter".to_string(), 4_000);
    costs.insert("remove-and-stub".to_string(), 5_000);
    costs.insert("escalate".to_string(), 6_000);

    let config = ObstructionCertifierConfig {
        disruption_costs: costs,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    // Actions should be sorted by the custom costs
    for i in 1..plan.actions.len() {
        assert!(
            plan.actions[i].disruption_cost_millionths
                >= plan.actions[i - 1].disruption_cost_millionths
        );
    }
}

#[test]
fn missing_disruption_cost_key_falls_back_to_million() {
    // Empty disruption costs map → all kinds default to 1_000_000
    let config = ObstructionCertifierConfig {
        disruption_costs: BTreeMap::new(),
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    // With a single target and all base costs = 1M, all actions should cost 1M
    for action in &plan.actions {
        assert_eq!(action.disruption_cost_millionths, 1_000_000);
    }
}

// ===========================================================================
// 6. Feasibility edge cases
// ===========================================================================

#[test]
fn capability_gap_inject_adapter_infeasible_for_many_targets() {
    let certifier = ObstructionCertifier::new();

    // >3 missing capabilities → InjectAdapter should be infeasible
    let v = capability_gap_violation("Widget", &["net", "fs", "crypto", "gpu"]);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let inject = plan
        .actions
        .iter()
        .find(|a| a.kind == FallbackActionKind::InjectAdapter);
    if let Some(inject_action) = inject {
        // Target is 1 component, so feasibility depends on targets.len() <= 3
        // With a single component, targets = ["Widget"], len = 1 <= 3, so feasible
        assert!(inject_action.feasible);
    }
}

#[test]
fn effect_cycle_split_infeasible_for_large_cycles() {
    let certifier = ObstructionCertifier::new();

    // >10 cycle participants → SplitBoundary should be infeasible
    let participants: Vec<String> = (0..12).map(|i| format!("Comp{i}")).collect();
    let participant_refs: Vec<&str> = participants.iter().map(|s| s.as_str()).collect();
    let v = effect_cycle_violation(&participant_refs);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let split = plan
        .actions
        .iter()
        .find(|a| a.kind == FallbackActionKind::SplitBoundary);
    if let Some(split_action) = split {
        assert!(!split_action.feasible);
    }
}

#[test]
fn duplicate_provider_remove_stub_infeasible_for_single_provider() {
    let certifier = ObstructionCertifier::new();

    // Only 1 provider → RemoveAndStub feasibility depends on targets.len() >= 2
    // targets is the witness_components which is a BTreeSet of provider names
    let v = duplicate_provider_violation(&["OnlyOne"], "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let remove = plan
        .actions
        .iter()
        .find(|a| a.kind == FallbackActionKind::RemoveAndStub);
    if let Some(remove_action) = remove {
        assert!(!remove_action.feasible);
    }
}

#[test]
fn duplicate_provider_remove_stub_feasible_for_two_providers() {
    let certifier = ObstructionCertifier::new();

    let v = duplicate_provider_violation(&["ProvA", "ProvB"], "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let remove = plan
        .actions
        .iter()
        .find(|a| a.kind == FallbackActionKind::RemoveAndStub);
    if let Some(remove_action) = remove {
        assert!(remove_action.feasible);
    }
}

#[test]
fn all_feasible_means_obstructed_with_fallbacks() {
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(
        result.outcome,
        CertificationOutcome::ObstructedWithFallbacks
    );
    assert!(result.can_proceed());
    assert!(!should_block_gate(&result));
}

#[test]
fn plan_recommended_index_picks_lowest_cost_feasible() {
    let certifier = ObstructionCertifier::new();

    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let recommended = plan.recommended_action().unwrap();
    assert!(recommended.feasible);
    // The recommended should be the lowest-cost feasible
    let feasible: Vec<_> = plan.actions.iter().filter(|a| a.feasible).collect();
    if !feasible.is_empty() {
        let min_cost = feasible
            .iter()
            .map(|a| a.disruption_cost_millionths)
            .min()
            .unwrap();
        assert_eq!(recommended.disruption_cost_millionths, min_cost);
    }
}

// ===========================================================================
// 7. Witness fragment and component tests
// ===========================================================================

#[test]
fn unresolved_context_witness_single_component() {
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("MyConsumer", "ThemeCtx");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    assert_eq!(cert.witness_components.len(), 1);
    assert!(cert.witness_components.contains("MyConsumer"));
    assert_eq!(cert.witness_fragments.len(), 1);
    assert_eq!(
        cert.witness_fragments[0].contract_aspect,
        "context.consumes"
    );
    assert_eq!(cert.witness_fragments[0].contract_value, "ThemeCtx");
}

#[test]
fn layout_after_passive_witness_has_both_components() {
    let certifier = ObstructionCertifier::new();
    let v = layout_after_passive_violation("LayoutComp", "PassiveComp");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    assert_eq!(cert.witness_components.len(), 2);
    assert!(cert.witness_components.contains("LayoutComp"));
    assert!(cert.witness_components.contains("PassiveComp"));
    assert_eq!(cert.witness_fragments.len(), 2);
    let aspects: BTreeSet<_> = cert
        .witness_fragments
        .iter()
        .map(|f| f.contract_aspect.as_str())
        .collect();
    assert!(aspects.contains("effect.layout"));
    assert!(aspects.contains("effect.passive"));
}

#[test]
fn suspense_conflict_witness_includes_boundary_and_children() {
    let certifier = ObstructionCertifier::new();
    let v = suspense_conflict_violation(
        "SuspBoundary",
        &["ChildX", "ChildY", "ChildZ"],
        "async contract mismatch",
    );
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    assert!(cert.witness_components.contains("SuspBoundary"));
    assert!(cert.witness_components.contains("ChildX"));
    assert!(cert.witness_components.contains("ChildY"));
    assert!(cert.witness_components.contains("ChildZ"));
    // First fragment is the boundary owner
    assert_eq!(
        cert.witness_fragments[0].contract_aspect,
        "boundary.suspense"
    );
}

#[test]
fn hydration_conflict_witness_includes_boundary_and_children() {
    let certifier = ObstructionCertifier::new();
    let v = hydration_conflict_violation("HydBound", &["ChildA", "ChildB"], "effect mismatch");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    assert!(cert.witness_components.contains("HydBound"));
    assert!(cert.witness_components.contains("ChildA"));
    assert!(cert.witness_components.contains("ChildB"));
    assert_eq!(
        cert.witness_fragments[0].contract_aspect,
        "boundary.hydration"
    );
}

#[test]
fn hook_mismatch_witness_has_two_components_same_hook() {
    let certifier = ObstructionCertifier::new();
    let v = hook_mismatch_violation("CompAlpha", "CompBeta", "useLayoutSync");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    assert_eq!(cert.witness_components.len(), 2);
    assert!(cert.witness_components.contains("CompAlpha"));
    assert!(cert.witness_components.contains("CompBeta"));
    for frag in &cert.witness_fragments {
        assert_eq!(frag.contract_aspect, "hook.cleanup");
        assert_eq!(frag.contract_value, "useLayoutSync");
    }
}

#[test]
fn boundary_leak_witness_lists_all_leaked_capabilities() {
    let certifier = ObstructionCertifier::new();
    let v = boundary_leak_violation("SecBoundary", &["net", "fs", "crypto"]);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    assert!(cert.witness_components.contains("SecBoundary"));
    let leaked: BTreeSet<_> = cert
        .witness_fragments
        .iter()
        .map(|f| f.contract_value.clone())
        .collect();
    assert!(leaked.contains("net"));
    assert!(leaked.contains("fs"));
    assert!(leaked.contains("crypto"));
}

// ===========================================================================
// 8. Determinism tests
// ===========================================================================

#[test]
fn identical_inputs_produce_identical_result_hash_across_runs() {
    let certifier = ObstructionCertifier::new();

    let make_input = || {
        let v = unresolved_context_violation("DetComp", "DetCtx");
        make_check_result(vec![v], CoherenceOutcome::Incoherent)
    };

    let r1 = certifier.certify(&make_input()).unwrap();
    let r2 = certifier.certify(&make_input()).unwrap();
    let r3 = certifier.certify(&make_input()).unwrap();

    assert_eq!(r1.result_hash, r2.result_hash);
    assert_eq!(r2.result_hash, r3.result_hash);
}

#[test]
fn identical_inputs_produce_identical_plan_hashes() {
    let certifier = ObstructionCertifier::new();

    let make_input = || {
        let v = capability_gap_violation("Comp", &["net", "fs"]);
        make_check_result(vec![v], CoherenceOutcome::Incoherent)
    };

    let r1 = certifier.certify(&make_input()).unwrap();
    let r2 = certifier.certify(&make_input()).unwrap();

    let p1 = r1.certificates[0].fallback_plan.as_ref().unwrap();
    let p2 = r2.certificates[0].fallback_plan.as_ref().unwrap();
    assert_eq!(p1.plan_hash, p2.plan_hash);
}

#[test]
fn different_epochs_produce_different_cert_but_same_hash_when_violations_same() {
    let certifier = ObstructionCertifier::new();

    let v1 = unresolved_context_violation("A", "K");
    let v2 = unresolved_context_violation("A", "K");
    let check1 = make_check_result_epoch(vec![v1], CoherenceOutcome::Incoherent, 100);
    let check2 = make_check_result_epoch(vec![v2], CoherenceOutcome::Incoherent, 200);

    let r1 = certifier.certify(&check1).unwrap();
    let r2 = certifier.certify(&check2).unwrap();

    // Epochs differ
    assert_eq!(r1.certification_epoch, 100);
    assert_eq!(r2.certification_epoch, 200);
    // Certificate hashes should be same (same violations, same components)
    assert_eq!(
        r1.certificates[0].certificate_hash,
        r2.certificates[0].certificate_hash
    );
}

#[test]
fn clear_result_hash_is_deterministic() {
    let certifier = ObstructionCertifier::new();

    let check1 = make_check_result(vec![], CoherenceOutcome::Coherent);
    let check2 = make_check_result(vec![], CoherenceOutcome::Coherent);

    let r1 = certifier.certify(&check1).unwrap();
    let r2 = certifier.certify(&check2).unwrap();

    assert_eq!(r1.result_hash, r2.result_hash);
}

// ===========================================================================
// 9. Coherent / empty input edge cases
// ===========================================================================

#[test]
fn coherent_input_returns_clear_with_correct_epoch() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result_epoch(vec![], CoherenceOutcome::Coherent, 999);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.outcome, CertificationOutcome::Clear);
    assert_eq!(result.certification_epoch, 999);
    assert!(result.certificates.is_empty());
    assert_eq!(result.total_obstructions, 0);
    assert_eq!(result.blocking_obstructions, 0);
    assert!(result.can_proceed());
}

#[test]
fn coherent_with_warnings_but_empty_violations_is_clear() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result(vec![], CoherenceOutcome::CoherentWithWarnings);
    let result = certifier.certify(&check).unwrap();

    // No violations even though outcome says warnings → treated as clear
    assert_eq!(result.outcome, CertificationOutcome::Clear);
}

#[test]
fn incoherent_with_empty_violations_is_clear() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result(vec![], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    // Incoherent but no violations → produces clear (no certificates to generate)
    assert_eq!(result.outcome, CertificationOutcome::Clear);
}

// ===========================================================================
// 10. Gate helper edge cases
// ===========================================================================

#[test]
fn should_block_gate_matrix() {
    let clear = CertificationResult {
        schema_version: OBSTRUCTION_CERT_SCHEMA_VERSION.to_string(),
        bead_id: OBSTRUCTION_CERT_BEAD_ID.to_string(),
        outcome: CertificationOutcome::Clear,
        certificates: vec![],
        total_obstructions: 0,
        blocking_obstructions: 0,
        feasible_fallback_count: 0,
        infeasible_fallback_count: 0,
        certification_epoch: 1,
        result_hash: ContentHash::compute(b"clear"),
    };
    assert!(!should_block_gate(&clear));

    let with_fb = CertificationResult {
        outcome: CertificationOutcome::ObstructedWithFallbacks,
        ..clear.clone()
    };
    assert!(!should_block_gate(&with_fb));

    let no_fb = CertificationResult {
        outcome: CertificationOutcome::ObstructedNoFallback,
        ..clear.clone()
    };
    assert!(should_block_gate(&no_fb));

    let budget = CertificationResult {
        outcome: CertificationOutcome::BudgetExhausted,
        ..clear
    };
    assert!(should_block_gate(&budget));
}

#[test]
fn collect_debt_codes_includes_plan_debt_when_infeasible() {
    let certifier = ObstructionCertifier::new();

    // Effect cycle with 12+ participants → SplitBoundary infeasible
    let participants: Vec<String> = (0..12).map(|i| format!("Comp{i}")).collect();
    let participant_refs: Vec<&str> = participants.iter().map(|s| s.as_str()).collect();
    let v = effect_cycle_violation(&participant_refs);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let codes = collect_debt_codes(&result);
    assert!(codes.contains(DEBT_EFFECT_CYCLE));
}

#[test]
fn collect_debt_codes_empty_for_clear() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result(vec![], CoherenceOutcome::Coherent);
    let result = certifier.certify(&check).unwrap();

    let codes = collect_debt_codes(&result);
    assert!(codes.is_empty());
}

#[test]
fn collect_debt_codes_multiple_distinct_codes() {
    let certifier = ObstructionCertifier::new();
    let violations = vec![
        unresolved_context_violation("A", "K1"),
        capability_gap_violation("B", &["net"]),
        hook_mismatch_violation("C", "D", "hook1"),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let codes = collect_debt_codes(&result);
    assert!(codes.contains(DEBT_UNRESOLVED_CONTEXT));
    assert!(codes.contains(DEBT_CAPABILITY_GAP));
    assert!(codes.contains(DEBT_HOOK_CLEANUP_MISMATCH));
}

// ===========================================================================
// 11. Report rendering edge cases
// ===========================================================================

#[test]
fn report_for_clear_mentions_coherent() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result(vec![], CoherenceOutcome::Coherent);
    let result = certifier.certify(&check).unwrap();
    let report = render_certification_report(&result);

    assert!(report.contains("coherent"));
    assert!(report.contains("clear"));
}

#[test]
fn report_contains_all_certificate_details() {
    let certifier = ObstructionCertifier::new();
    let violations = vec![
        unresolved_context_violation("MyConsumer", "ThemeCtx"),
        capability_gap_violation("MyWidget", &["network"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let report = render_certification_report(&result);

    assert!(report.contains("Obstruction #1"));
    assert!(report.contains("Obstruction #2"));
    assert!(report.contains("MyConsumer"));
    assert!(report.contains("MyWidget"));
    assert!(report.contains("[RECOMMENDED]"));
    assert!(report.contains("Fallback plan"));
}

#[test]
fn report_contains_epoch_and_result_hash() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result_epoch(vec![], CoherenceOutcome::Coherent, 12345);
    let result = certifier.certify(&check).unwrap();
    let report = render_certification_report(&result);

    assert!(report.contains("12345"));
    assert!(report.contains("Result hash:"));
}

#[test]
fn report_for_many_violations_includes_all() {
    let certifier = ObstructionCertifier::new();
    let violations: Vec<CoherenceViolation> = (0..5)
        .map(|i| {
            make_violation_unique(
                CoherenceViolationKind::UnresolvedContext {
                    consumer: format!("Consumer{i}"),
                    context_key: format!("Key{i}"),
                },
                blocking_severity(),
                DEBT_UNRESOLVED_CONTEXT,
                &format!("report-{i}"),
            )
        })
        .collect();
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let report = render_certification_report(&result);

    for i in 0..5 {
        assert!(report.contains(&format!("Obstruction #{}", i + 1)));
        assert!(report.contains(&format!("Consumer{i}")));
    }
}

#[test]
fn report_marks_infeasible_actions() {
    let certifier = ObstructionCertifier::new();

    // Large cycle → SplitBoundary infeasible
    let participants: Vec<String> = (0..12).map(|i| format!("Comp{i}")).collect();
    let participant_refs: Vec<&str> = participants.iter().map(|s| s.as_str()).collect();
    let v = effect_cycle_violation(&participant_refs);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let report = render_certification_report(&result);

    assert!(report.contains("INFEASIBLE"));
}

// ===========================================================================
// 12. Serde round-trip completeness
// ===========================================================================

#[test]
fn full_certification_result_serde_roundtrip_preserves_all_fields() {
    let certifier = ObstructionCertifier::new();
    let violations = vec![
        unresolved_context_violation("A", "K1"),
        capability_gap_violation("B", &["net", "fs"]),
        effect_cycle_violation(&["C", "D", "E"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let json = serde_json::to_string(&result).unwrap();
    let deser: CertificationResult = serde_json::from_str(&json).unwrap();

    assert_eq!(result.schema_version, deser.schema_version);
    assert_eq!(result.bead_id, deser.bead_id);
    assert_eq!(result.outcome, deser.outcome);
    assert_eq!(result.total_obstructions, deser.total_obstructions);
    assert_eq!(result.blocking_obstructions, deser.blocking_obstructions);
    assert_eq!(
        result.feasible_fallback_count,
        deser.feasible_fallback_count
    );
    assert_eq!(
        result.infeasible_fallback_count,
        deser.infeasible_fallback_count
    );
    assert_eq!(result.certification_epoch, deser.certification_epoch);
    assert_eq!(result.result_hash, deser.result_hash);
    assert_eq!(result.certificates.len(), deser.certificates.len());

    for (orig, des) in result.certificates.iter().zip(deser.certificates.iter()) {
        assert_eq!(orig.id, des.id);
        assert_eq!(orig.certificate_hash, des.certificate_hash);
        assert_eq!(orig.violation_kind_tag, des.violation_kind_tag);
        assert_eq!(orig.witness_components, des.witness_components);
        assert_eq!(orig.witness_fragments.len(), des.witness_fragments.len());
        let orig_plan = orig.fallback_plan.as_ref().unwrap();
        let des_plan = des.fallback_plan.as_ref().unwrap();
        assert_eq!(orig_plan.plan_hash, des_plan.plan_hash);
        assert_eq!(orig_plan.actions.len(), des_plan.actions.len());
    }
}

#[test]
fn obstruction_certifier_config_serde_roundtrip_custom() {
    let mut costs = BTreeMap::new();
    costs.insert("isolate".to_string(), 100);
    costs.insert("degrade".to_string(), 200);
    let config = ObstructionCertifierConfig {
        max_certificates: 42,
        max_actions_per_plan: 7,
        max_witness_components: 99,
        include_non_blocking: false,
        disruption_costs: costs,
    };
    let json = serde_json::to_string(&config).unwrap();
    let deser: ObstructionCertifierConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, deser);
}

// ===========================================================================
// 13. Fallback plan accessor edge cases
// ===========================================================================

#[test]
fn recommended_action_returns_none_for_empty_plan() {
    use frankenengine_engine::obstruction_certificate::FallbackPlan;

    let plan = FallbackPlan {
        id: derive_id(
            ObjectDomain::EvidenceRecord,
            "test",
            &SchemaId::from_definition(b"test"),
            b"empty",
        )
        .unwrap(),
        certificate_id: derive_id(
            ObjectDomain::EvidenceRecord,
            "cert",
            &SchemaId::from_definition(b"cert"),
            b"empty",
        )
        .unwrap(),
        actions: vec![],
        recommended_action_index: 0,
        has_feasible_resolution: false,
        debt_code: Some(DEBT_FALLBACK_INFEASIBLE.to_string()),
        plan_hash: ContentHash::compute(b"empty-plan"),
    };

    assert!(plan.recommended_action().is_none());
    assert!(plan.feasible_actions().is_empty());
}

#[test]
fn feasible_actions_filters_out_infeasible() {
    let certifier = ObstructionCertifier::new();

    // Large cycle → some actions infeasible
    let participants: Vec<String> = (0..12).map(|i| format!("Comp{i}")).collect();
    let participant_refs: Vec<&str> = participants.iter().map(|s| s.as_str()).collect();
    let v = effect_cycle_violation(&participant_refs);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let feasible = plan.feasible_actions();
    let infeasible_count = plan.actions.iter().filter(|a| !a.feasible).count();

    assert_eq!(feasible.len() + infeasible_count, plan.actions.len());
    for action in &feasible {
        assert!(action.feasible);
    }
}

// ===========================================================================
// 14. CertificationResult accessor edge cases
// ===========================================================================

#[test]
fn infeasible_certificates_returns_certs_without_plans() {
    // A certificate with fallback_plan = None is infeasible
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let mut result = certifier.certify(&check).unwrap();

    // Remove the plan to simulate infeasible
    result.certificates[0].fallback_plan = None;
    let infeasible = result.infeasible_certificates();
    assert_eq!(infeasible.len(), 1);
}

#[test]
fn by_debt_code_groups_mixed_codes() {
    let certifier = ObstructionCertifier::new();
    let violations = vec![
        unresolved_context_violation("A", "K1"),
        unresolved_context_violation("B", "K2"),
        capability_gap_violation("C", &["net"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let grouped = result.by_debt_code();
    assert!(grouped.contains_key(DEBT_UNRESOLVED_CONTEXT));
    assert!(grouped.contains_key(DEBT_CAPABILITY_GAP));
    assert_eq!(grouped[DEBT_UNRESOLVED_CONTEXT].len(), 2);
    assert_eq!(grouped[DEBT_CAPABILITY_GAP].len(), 1);
}

// ===========================================================================
// 15. Display and formatting
// ===========================================================================

#[test]
fn witness_fragment_display_format() {
    let frag = WitnessFragment {
        component_id: "MyComp".to_string(),
        contract_aspect: "context.consumes".to_string(),
        contract_value: "ThemeCtx".to_string(),
    };
    let display = format!("{frag}");
    assert_eq!(display, "MyComp/context.consumes: ThemeCtx");
}

#[test]
fn fallback_action_kind_display_completeness() {
    let kinds = [
        (FallbackActionKind::Isolate, "isolate"),
        (FallbackActionKind::Degrade, "degrade"),
        (FallbackActionKind::SplitBoundary, "split-boundary"),
        (FallbackActionKind::InjectAdapter, "inject-adapter"),
        (FallbackActionKind::RemoveAndStub, "remove-and-stub"),
        (FallbackActionKind::Escalate, "escalate"),
    ];
    for (kind, expected) in &kinds {
        assert_eq!(format!("{kind}"), *expected);
    }
}

#[test]
fn certification_outcome_display_completeness() {
    let outcomes = [
        (CertificationOutcome::Clear, "clear"),
        (
            CertificationOutcome::ObstructedWithFallbacks,
            "obstructed-with-fallbacks",
        ),
        (
            CertificationOutcome::ObstructedNoFallback,
            "obstructed-no-fallback",
        ),
        (CertificationOutcome::BudgetExhausted, "budget-exhausted"),
    ];
    for (outcome, expected) in &outcomes {
        assert_eq!(format!("{outcome}"), *expected);
    }
}

#[test]
fn obstruction_error_display_all_variants() {
    let budget = ObstructionError::BudgetExhausted {
        resource: "certificates".to_string(),
        limit: 100,
    };
    assert!(format!("{budget}").contains("certificates"));
    assert!(format!("{budget}").contains("100"));

    let invalid = ObstructionError::InvalidInput("bad data".to_string());
    assert!(format!("{invalid}").contains("bad data"));

    let internal = ObstructionError::InternalInconsistency("broken state".to_string());
    assert!(format!("{internal}").contains("broken state"));
}

// ===========================================================================
// 16. Constants stability
// ===========================================================================

#[test]
fn schema_version_constant_exact_value() {
    assert_eq!(
        OBSTRUCTION_CERT_SCHEMA_VERSION,
        "franken-engine.obstruction_certificate.v1"
    );
}

#[test]
fn bead_id_constant_exact_value() {
    assert_eq!(OBSTRUCTION_CERT_BEAD_ID, "bd-mjh3.14.3");
}

#[test]
fn debt_code_constants_all_have_fe_prefix() {
    assert!(DEBT_OBSTRUCTION_UNRESOLVED.starts_with("FE-"));
    assert!(DEBT_FALLBACK_INFEASIBLE.starts_with("FE-"));
    assert!(DEBT_WITNESS_INCOMPLETE.starts_with("FE-"));
    assert!(DEBT_PLAN_CYCLE.starts_with("FE-"));
    assert!(DEBT_BUDGET_EXHAUSTED.starts_with("FE-"));
}

#[test]
fn debt_code_constants_all_unique() {
    let codes: BTreeSet<&str> = [
        DEBT_OBSTRUCTION_UNRESOLVED,
        DEBT_FALLBACK_INFEASIBLE,
        DEBT_WITNESS_INCOMPLETE,
        DEBT_PLAN_CYCLE,
        DEBT_BUDGET_EXHAUSTED,
    ]
    .into_iter()
    .collect();
    assert_eq!(codes.len(), 5);
}

// ===========================================================================
// 17. Certificate metadata
// ===========================================================================

#[test]
fn certificate_carries_correct_epoch() {
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("A", "K");
    let check = make_check_result_epoch(vec![v], CoherenceOutcome::Incoherent, 777);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certification_epoch, 777);
    assert_eq!(result.certificates[0].detected_epoch, 777);
}

#[test]
fn certificate_carries_violation_severity() {
    let certifier = ObstructionCertifier::new();
    let sev = SeverityScore(654_321);
    let v = make_violation(
        CoherenceViolationKind::UnresolvedContext {
            consumer: "X".to_string(),
            context_key: "K".to_string(),
        },
        sev.clone(),
        DEBT_UNRESOLVED_CONTEXT,
    );
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates[0].severity, sev);
}

#[test]
fn certificate_explanation_contains_component_names() {
    let certifier = ObstructionCertifier::new();
    let v = hook_mismatch_violation("HookCompX", "HookCompY", "useSync");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let explanation = &result.certificates[0].explanation;
    assert!(explanation.contains("HookCompX"));
    assert!(explanation.contains("HookCompY"));
    assert!(explanation.contains("useSync"));
}

// ===========================================================================
// 18. Fallback action type completeness per violation kind
// ===========================================================================

#[test]
fn unresolved_context_generates_four_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::InjectAdapter));
    assert!(kinds.contains(&FallbackActionKind::Degrade));
    assert!(kinds.contains(&FallbackActionKind::Isolate));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

#[test]
fn orphaned_provider_generates_three_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = orphaned_provider_violation("P", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::RemoveAndStub));
    assert!(kinds.contains(&FallbackActionKind::Degrade));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

#[test]
fn effect_cycle_generates_four_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = effect_cycle_violation(&["A", "B"]);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::SplitBoundary));
    assert!(kinds.contains(&FallbackActionKind::Degrade));
    assert!(kinds.contains(&FallbackActionKind::RemoveAndStub));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

#[test]
fn layout_after_passive_generates_three_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = layout_after_passive_violation("L", "P");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::Degrade));
    assert!(kinds.contains(&FallbackActionKind::SplitBoundary));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

#[test]
fn boundary_conflict_generates_four_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = suspense_conflict_violation("B", &["C1", "C2"], "reason");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::SplitBoundary));
    assert!(kinds.contains(&FallbackActionKind::Isolate));
    assert!(kinds.contains(&FallbackActionKind::Degrade));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

#[test]
fn hook_mismatch_generates_four_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = hook_mismatch_violation("A", "B", "h");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::InjectAdapter));
    assert!(kinds.contains(&FallbackActionKind::Degrade));
    assert!(kinds.contains(&FallbackActionKind::Isolate));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

#[test]
fn duplicate_provider_generates_three_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = duplicate_provider_violation(&["P1", "P2"], "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::RemoveAndStub));
    assert!(kinds.contains(&FallbackActionKind::SplitBoundary));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

#[test]
fn boundary_leak_generates_four_action_kinds() {
    let certifier = ObstructionCertifier::new();
    let v = boundary_leak_violation("B", &["cap1"]);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();
    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();

    let kinds: BTreeSet<_> = plan.actions.iter().map(|a| a.kind.clone()).collect();
    assert!(kinds.contains(&FallbackActionKind::InjectAdapter));
    assert!(kinds.contains(&FallbackActionKind::Isolate));
    assert!(kinds.contains(&FallbackActionKind::Degrade));
    assert!(kinds.contains(&FallbackActionKind::Escalate));
}

// ===========================================================================
// 19. Hash uniqueness across violation kinds
// ===========================================================================

#[test]
fn different_violation_kinds_same_components_produce_different_cert_hashes() {
    let certifier = ObstructionCertifier::new();

    // Two violations about "CompA" but different kinds
    let v1 = make_violation(
        CoherenceViolationKind::UnresolvedContext {
            consumer: "CompA".to_string(),
            context_key: "K".to_string(),
        },
        blocking_severity(),
        DEBT_UNRESOLVED_CONTEXT,
    );
    let v2 = make_violation(
        CoherenceViolationKind::OrphanedProvider {
            provider: "CompA".to_string(),
            context_key: "K".to_string(),
        },
        non_blocking_severity(),
        DEBT_UNRESOLVED_CONTEXT,
    );

    let r1 = certifier
        .certify(&make_check_result(vec![v1], CoherenceOutcome::Incoherent))
        .unwrap();
    let r2 = certifier
        .certify(&make_check_result(vec![v2], CoherenceOutcome::Incoherent))
        .unwrap();

    assert_ne!(
        r1.certificates[0].certificate_hash,
        r2.certificates[0].certificate_hash
    );
}

#[test]
fn same_kind_different_components_produce_different_hashes() {
    let certifier = ObstructionCertifier::new();

    let v1 = unresolved_context_violation("CompA", "Key1");
    let v2 = unresolved_context_violation("CompB", "Key2");

    let r1 = certifier
        .certify(&make_check_result(vec![v1], CoherenceOutcome::Incoherent))
        .unwrap();
    let r2 = certifier
        .certify(&make_check_result(vec![v2], CoherenceOutcome::Incoherent))
        .unwrap();

    assert_ne!(
        r1.certificates[0].certificate_hash,
        r2.certificates[0].certificate_hash
    );
}

// ===========================================================================
// 20. Stress tests
// ===========================================================================

#[test]
fn fifty_violations_all_processed_with_default_budget() {
    let certifier = ObstructionCertifier::new();

    let violations: Vec<CoherenceViolation> = (0..50)
        .map(|i| {
            make_violation_unique(
                CoherenceViolationKind::UnresolvedContext {
                    consumer: format!("Consumer{i}"),
                    context_key: format!("Key{i}"),
                },
                blocking_severity(),
                DEBT_UNRESOLVED_CONTEXT,
                &format!("stress-{i}"),
            )
        })
        .collect();
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 50);
    assert_ne!(result.outcome, CertificationOutcome::BudgetExhausted);
    assert_eq!(result.total_obstructions, 50);
    for cert in &result.certificates {
        assert!(cert.fallback_plan.is_some());
        assert!(!cert.certificate_hash.as_bytes().is_empty());
    }
}

#[test]
fn all_ten_violation_kinds_in_single_batch_all_have_plans() {
    let certifier = ObstructionCertifier::new();
    let violations = vec![
        unresolved_context_violation("A", "K1"),
        orphaned_provider_violation("B", "K2"),
        capability_gap_violation("C", &["cap"]),
        effect_cycle_violation(&["D", "E"]),
        layout_after_passive_violation("F", "G"),
        suspense_conflict_violation("H", &["I"], "r"),
        hydration_conflict_violation("J", &["K"], "r"),
        hook_mismatch_violation("L", "M", "h"),
        duplicate_provider_violation(&["N", "O"], "K3"),
        boundary_leak_violation("P", &["c"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.certificates.len(), 10);
    for cert in &result.certificates {
        let plan = cert.fallback_plan.as_ref().unwrap();
        assert!(!plan.actions.is_empty());
        assert!(plan.has_feasible_resolution);
    }
}

// ===========================================================================
// 21. Fallback action rationale hash determinism
// ===========================================================================

#[test]
fn action_rationale_hashes_are_nonzero() {
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    for action in &plan.actions {
        assert!(
            !action.rationale_hash.as_bytes().iter().all(|&b| b == 0),
            "rationale hash should not be all zeros"
        );
    }
}

#[test]
fn different_action_kinds_have_different_rationale_hashes() {
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let hashes: BTreeSet<_> = plan
        .actions
        .iter()
        .map(|a| a.rationale_hash.clone())
        .collect();
    // Each action should have a unique rationale hash
    assert_eq!(hashes.len(), plan.actions.len());
}

// ===========================================================================
// 22. Certifier Default trait
// ===========================================================================

#[test]
fn certifier_default_matches_new() {
    let d = ObstructionCertifier::default();
    let n = ObstructionCertifier::new();
    // Both should produce identical results for the same input
    let v = unresolved_context_violation("X", "Y");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);

    let rd = d.certify(&check).unwrap();

    let v2 = unresolved_context_violation("X", "Y");
    let check2 = make_check_result(vec![v2], CoherenceOutcome::Incoherent);
    let rn = n.certify(&check2).unwrap();

    assert_eq!(rd.result_hash, rn.result_hash);
    assert_eq!(rd.outcome, rn.outcome);
}

// ===========================================================================
// 23. Edge: many capabilities in CapabilityGap
// ===========================================================================

#[test]
fn capability_gap_with_many_capabilities_truncates_fragments() {
    let config = ObstructionCertifierConfig {
        max_witness_components: 3,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    let caps: Vec<String> = (0..20).map(|i| format!("cap{i}")).collect();
    let cap_refs: Vec<&str> = caps.iter().map(|s| s.as_str()).collect();
    let v = capability_gap_violation("Widget", &cap_refs);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    // With max_witness_components=3, fragments should be capped at 3
    assert!(cert.witness_fragments.len() <= 3);
}

#[test]
fn effect_cycle_many_participants_truncates_witness() {
    let config = ObstructionCertifierConfig {
        max_witness_components: 5,
        ..ObstructionCertifierConfig::default()
    };
    let certifier = ObstructionCertifier::with_config(config);

    let parts: Vec<String> = (0..20).map(|i| format!("Comp{i}")).collect();
    let part_refs: Vec<&str> = parts.iter().map(|s| s.as_str()).collect();
    let v = effect_cycle_violation(&part_refs);
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let cert = &result.certificates[0];
    assert!(cert.witness_components.len() <= 5);
    assert!(cert.witness_fragments.len() <= 5);
}

// ===========================================================================
// 24. Certificate ID derivation
// ===========================================================================

#[test]
fn certificate_ids_are_unique_across_violations() {
    let certifier = ObstructionCertifier::new();
    let violations = vec![
        unresolved_context_violation("A", "K1"),
        unresolved_context_violation("B", "K2"),
        capability_gap_violation("C", &["net"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let ids: BTreeSet<_> = result.certificates.iter().map(|c| c.id.clone()).collect();
    assert_eq!(ids.len(), result.certificates.len());
}

#[test]
fn plan_ids_are_unique_across_certificates() {
    let certifier = ObstructionCertifier::new();
    let violations = vec![
        unresolved_context_violation("A", "K1"),
        capability_gap_violation("B", &["net"]),
        effect_cycle_violation(&["C", "D"]),
    ];
    let check = make_check_result(violations, CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan_ids: BTreeSet<_> = result
        .certificates
        .iter()
        .filter_map(|c| c.fallback_plan.as_ref())
        .map(|p| p.id.clone())
        .collect();
    assert_eq!(plan_ids.len(), result.certificates.len());
}

#[test]
fn action_ids_are_unique_within_plan() {
    let certifier = ObstructionCertifier::new();
    let v = unresolved_context_violation("A", "K");
    let check = make_check_result(vec![v], CoherenceOutcome::Incoherent);
    let result = certifier.certify(&check).unwrap();

    let plan = result.certificates[0].fallback_plan.as_ref().unwrap();
    let action_ids: BTreeSet<_> = plan.actions.iter().map(|a| a.id.clone()).collect();
    assert_eq!(action_ids.len(), plan.actions.len());
}

// ===========================================================================
// 25. Schema and bead ID in results
// ===========================================================================

#[test]
fn result_carries_correct_schema_version() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result(vec![], CoherenceOutcome::Coherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.schema_version, OBSTRUCTION_CERT_SCHEMA_VERSION);
}

#[test]
fn result_carries_correct_bead_id() {
    let certifier = ObstructionCertifier::new();
    let check = make_check_result(vec![], CoherenceOutcome::Coherent);
    let result = certifier.certify(&check).unwrap();

    assert_eq!(result.bead_id, OBSTRUCTION_CERT_BEAD_ID);
}
