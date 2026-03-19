//! Enrichment integration tests for `runtime_kernel_lane_charter`.
//!
//! Covers: CharterBuilder fluent API, canonical charter invariants,
//! footprint budget enforcement, input/output validation, failure policy
//! action lookup, compliance checks, enum Display/serde, scheduler
//! invariant coverage, and content-hash stability.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::too_many_arguments
)]

use std::collections::BTreeSet;

use frankenengine_engine::runtime_kernel_lane_charter::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn set_of(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn within_js_budget() -> ResourceUsage {
    ResourceUsage {
        heap_bytes: 1_000_000,
        stack_frames: 100,
        update_cycle_micros: 10_000,
        dom_patches: 500,
    }
}

fn exceeding_js_budget() -> ResourceUsage {
    ResourceUsage {
        heap_bytes: 100_000_000,   // exceeds 16MiB
        stack_frames: 1000,        // exceeds 256
        update_cycle_micros: 50_000, // exceeds 16_000
        dom_patches: 5000,         // exceeds 1000
    }
}

// =========================================================================
// 1. RuntimeLane enum — Display + serde
// =========================================================================

#[test]
fn enrichment_runtime_lane_display_values() {
    assert_eq!(RuntimeLane::Js.to_string(), "js");
    assert_eq!(RuntimeLane::Wasm.to_string(), "wasm");
    assert_eq!(RuntimeLane::HybridRouter.to_string(), "hybrid_router");
}

#[test]
fn enrichment_runtime_lane_serde_roundtrip_all() {
    for lane in &[RuntimeLane::Js, RuntimeLane::Wasm, RuntimeLane::HybridRouter] {
        let json = serde_json::to_string(lane).unwrap();
        let back: RuntimeLane = serde_json::from_str(&json).unwrap();
        assert_eq!(*lane, back);
    }
}

#[test]
fn enrichment_runtime_lane_ord_deterministic() {
    let mut lanes = vec![RuntimeLane::HybridRouter, RuntimeLane::Js, RuntimeLane::Wasm];
    lanes.sort();
    // Verify sort completes without panic and is stable
    let mut lanes2 = lanes.clone();
    lanes2.sort();
    assert_eq!(lanes, lanes2);
}

// =========================================================================
// 2. OwnershipDomain enum — Display + serde
// =========================================================================

#[test]
fn enrichment_ownership_domain_display_all_eight() {
    let domains = [
        (OwnershipDomain::ExecutionCorrectness, "execution_correctness"),
        (OwnershipDomain::FootprintBudget, "footprint_budget"),
        (OwnershipDomain::SchedulerDeterminism, "scheduler_determinism"),
        (OwnershipDomain::AbiStability, "abi_stability"),
        (OwnershipDomain::FailoverBehavior, "failover_behavior"),
        (OwnershipDomain::RoutingPolicy, "routing_policy"),
        (OwnershipDomain::TraceEmission, "trace_emission"),
        (OwnershipDomain::IncidentResponse, "incident_response"),
    ];
    for (domain, expected) in &domains {
        assert_eq!(domain.to_string(), *expected);
    }
}

#[test]
fn enrichment_ownership_domain_serde_roundtrip() {
    let domain = OwnershipDomain::SchedulerDeterminism;
    let json = serde_json::to_string(&domain).unwrap();
    let back: OwnershipDomain = serde_json::from_str(&json).unwrap();
    assert_eq!(domain, back);
}

// =========================================================================
// 3. FootprintBudget — defaults and check_usage
// =========================================================================

#[test]
fn enrichment_js_budget_default_values() {
    let b = FootprintBudget::js_default();
    assert_eq!(b.lane, RuntimeLane::Js);
    assert_eq!(b.max_heap_bytes, 16 * 1024 * 1024);
    assert_eq!(b.max_stack_frames, 256);
    assert_eq!(b.max_update_cycle_micros, 16_000);
    assert_eq!(b.max_dom_patches_per_cycle, 1_000);
    assert_eq!(b.max_concurrent_callbacks, 64);
}

#[test]
fn enrichment_wasm_budget_default_values() {
    let b = FootprintBudget::wasm_default();
    assert_eq!(b.lane, RuntimeLane::Wasm);
    assert_eq!(b.max_heap_bytes, 64 * 1024 * 1024);
    assert_eq!(b.max_stack_frames, 512);
}

#[test]
fn enrichment_hybrid_router_budget_no_dom_patches() {
    let b = FootprintBudget::hybrid_router_default();
    assert_eq!(b.lane, RuntimeLane::HybridRouter);
    assert_eq!(b.max_dom_patches_per_cycle, 0);
}

#[test]
fn enrichment_check_usage_within_budget() {
    let b = FootprintBudget::js_default();
    let result = b.check_usage(&within_js_budget());
    assert!(result.within_budget);
    assert!(result.violations.is_empty());
    assert_eq!(result.lane, RuntimeLane::Js);
}

#[test]
fn enrichment_check_usage_all_violations() {
    let b = FootprintBudget::js_default();
    let result = b.check_usage(&exceeding_js_budget());
    assert!(!result.within_budget);
    assert_eq!(result.violations.len(), 4); // all four resources exceeded
}

#[test]
fn enrichment_check_usage_single_violation_heap() {
    let b = FootprintBudget::js_default();
    let mut usage = within_js_budget();
    usage.heap_bytes = 100_000_000;
    let result = b.check_usage(&usage);
    assert!(!result.within_budget);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(result.violations[0].resource, "heap_bytes");
}

#[test]
fn enrichment_budget_check_result_serde_roundtrip() {
    let b = FootprintBudget::js_default();
    let result = b.check_usage(&within_js_budget());
    let json = serde_json::to_string(&result).unwrap();
    let back: BudgetCheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// =========================================================================
// 4. LaneInputContract — validation
// =========================================================================

#[test]
fn enrichment_js_input_contract_satisfied() {
    let contract = LaneInputContract::js_default();
    let provided = set_of(&["frir_plan", "component_manifest"]);
    let v = contract.validate_inputs(&provided);
    assert!(v.satisfied);
    assert!(v.missing_inputs.is_empty());
}

#[test]
fn enrichment_js_input_contract_missing_one() {
    let contract = LaneInputContract::js_default();
    let provided = set_of(&["frir_plan"]);
    let v = contract.validate_inputs(&provided);
    assert!(!v.satisfied);
    assert!(v.missing_inputs.contains("component_manifest"));
}

#[test]
fn enrichment_wasm_input_contract_needs_wasm_module() {
    let contract = LaneInputContract::wasm_default();
    let provided = set_of(&["frir_plan", "component_manifest"]);
    let v = contract.validate_inputs(&provided);
    assert!(!v.satisfied);
    assert!(v.missing_inputs.contains("wasm_module"));
}

#[test]
fn enrichment_wasm_input_requires_compiler_witness() {
    let contract = LaneInputContract::wasm_default();
    assert!(contract.requires_compiler_witness);
}

#[test]
fn enrichment_hybrid_input_needs_routing_policy() {
    let contract = LaneInputContract::hybrid_router_default();
    let provided = set_of(&["frir_plan", "component_manifest"]);
    let v = contract.validate_inputs(&provided);
    assert!(!v.satisfied);
    assert!(v.missing_inputs.contains("routing_policy"));
    assert!(v.missing_inputs.contains("calibration_data"));
}

// =========================================================================
// 5. LaneOutputContract — validation
// =========================================================================

#[test]
fn enrichment_js_output_contract_satisfied() {
    let contract = LaneOutputContract::js_default();
    let provided = set_of(&["dom_patch_log", "execution_trace", "timing_profile"]);
    let v = contract.validate_outputs(&provided);
    assert!(v.satisfied);
}

#[test]
fn enrichment_wasm_output_needs_signal_graph() {
    let contract = LaneOutputContract::wasm_default();
    let provided = set_of(&["dom_patch_log", "execution_trace", "timing_profile"]);
    let v = contract.validate_outputs(&provided);
    assert!(!v.satisfied);
    assert!(v.missing_outputs.contains("signal_graph_snapshot"));
}

#[test]
fn enrichment_hybrid_router_output_needs_lane_selection() {
    let contract = LaneOutputContract::hybrid_router_default();
    let provided = set_of(&["routing_decision_receipt", "fallback_event_log"]);
    let v = contract.validate_outputs(&provided);
    assert!(!v.satisfied);
    assert!(v.missing_outputs.contains("lane_selection_log"));
}

// =========================================================================
// 6. FailureAction + InvariantKind — Display + serde
// =========================================================================

#[test]
fn enrichment_failure_action_display() {
    assert_eq!(FailureAction::LogAndContinue.to_string(), "log_and_continue");
    assert_eq!(
        FailureAction::FallbackToLane(RuntimeLane::Js).to_string(),
        "fallback_to_js"
    );
    assert_eq!(FailureAction::ActivateSafeMode.to_string(), "activate_safe_mode");
    assert_eq!(FailureAction::ForceTerminate.to_string(), "force_terminate");
}

#[test]
fn enrichment_invariant_kind_display() {
    assert_eq!(InvariantKind::SemanticDivergence.to_string(), "semantic_divergence");
    assert_eq!(InvariantKind::BudgetExceeded.to_string(), "budget_exceeded");
    assert_eq!(InvariantKind::AbiMismatch.to_string(), "abi_mismatch");
}

#[test]
fn enrichment_failure_action_serde_all_variants() {
    let actions = [
        FailureAction::LogAndContinue,
        FailureAction::FallbackToLane(RuntimeLane::Wasm),
        FailureAction::ActivateSafeMode,
        FailureAction::ForceTerminate,
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let back: FailureAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, back);
    }
}

// =========================================================================
// 7. FailurePolicy — strict defaults + action_for
// =========================================================================

#[test]
fn enrichment_strict_policy_has_six_rules() {
    let policy = FailurePolicy::strict();
    assert_eq!(policy.rules.len(), 6);
}

#[test]
fn enrichment_strict_policy_abi_mismatch_force_terminates() {
    let policy = FailurePolicy::strict();
    assert_eq!(
        *policy.action_for(&InvariantKind::AbiMismatch),
        FailureAction::ForceTerminate
    );
}

#[test]
fn enrichment_strict_policy_semantic_divergence_fallback_to_js() {
    let policy = FailurePolicy::strict();
    assert_eq!(
        *policy.action_for(&InvariantKind::SemanticDivergence),
        FailureAction::FallbackToLane(RuntimeLane::Js)
    );
}

#[test]
fn enrichment_strict_policy_default_action_is_safe_mode() {
    let policy = FailurePolicy::strict();
    assert_eq!(policy.default_action, FailureAction::ActivateSafeMode);
}

#[test]
fn enrichment_strict_policy_always_emits_incident() {
    let policy = FailurePolicy::strict();
    assert!(policy.always_emit_incident_bundle);
}

#[test]
fn enrichment_strict_policy_max_consecutive_failures() {
    let policy = FailurePolicy::strict();
    assert_eq!(policy.max_consecutive_failures, 3);
}

// =========================================================================
// 8. CharterBuilder + canonical_charter
// =========================================================================

#[test]
fn enrichment_canonical_charter_has_all_ownership_domains() {
    let charter = canonical_charter(epoch(1));
    assert_eq!(charter.ownership_domains.len(), 8);
}

#[test]
fn enrichment_canonical_charter_has_three_budgets() {
    let charter = canonical_charter(epoch(1));
    assert_eq!(charter.footprint_budgets.len(), 3);
}

#[test]
fn enrichment_canonical_charter_has_three_input_contracts() {
    let charter = canonical_charter(epoch(1));
    assert_eq!(charter.input_contracts.len(), 3);
}

#[test]
fn enrichment_canonical_charter_has_three_output_contracts() {
    let charter = canonical_charter(epoch(1));
    assert_eq!(charter.output_contracts.len(), 3);
}

#[test]
fn enrichment_canonical_charter_has_four_invariants() {
    let charter = canonical_charter(epoch(1));
    assert_eq!(charter.scheduler_invariants.len(), 4);
}

#[test]
fn enrichment_canonical_charter_schema_version() {
    let charter = canonical_charter(epoch(1));
    assert_eq!(charter.schema_version, "0.1.0");
}

#[test]
fn enrichment_canonical_charter_content_hash_deterministic() {
    let c1 = canonical_charter(epoch(42));
    let c2 = canonical_charter(epoch(42));
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn enrichment_canonical_charter_different_epoch_different_hash() {
    let c1 = canonical_charter(epoch(1));
    let c2 = canonical_charter(epoch(2));
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn enrichment_charter_builder_empty_builds_successfully() {
    let charter = CharterBuilder::new(epoch(1)).build();
    assert!(charter.ownership_domains.is_empty());
    assert!(charter.footprint_budgets.is_empty());
}

// =========================================================================
// 9. ComplianceReport — check_compliance
// =========================================================================

#[test]
fn enrichment_compliance_report_fully_compliant() {
    let charter = canonical_charter(epoch(1));
    let inputs = set_of(&["frir_plan", "component_manifest"]);
    let outputs = set_of(&["dom_patch_log", "execution_trace", "timing_profile"]);
    let invariants = vec![
        ("sched-det-001".into(), true, "ok".into()),
        ("sched-det-002".into(), true, "ok".into()),
    ];
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &inputs,
        &outputs,
        &within_js_budget(),
        &invariants,
    );
    assert!(report.compliant);
    assert!(report.input_validation.satisfied);
    assert!(report.output_validation.satisfied);
    assert!(report.budget_check.within_budget);
}

#[test]
fn enrichment_compliance_report_missing_inputs_not_compliant() {
    let charter = canonical_charter(epoch(1));
    let inputs = BTreeSet::new();
    let outputs = set_of(&["dom_patch_log", "execution_trace", "timing_profile"]);
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &inputs,
        &outputs,
        &within_js_budget(),
        &[],
    );
    assert!(!report.compliant);
    assert!(!report.input_validation.satisfied);
}

#[test]
fn enrichment_compliance_report_budget_exceeded_not_compliant() {
    let charter = canonical_charter(epoch(1));
    let inputs = set_of(&["frir_plan", "component_manifest"]);
    let outputs = set_of(&["dom_patch_log", "execution_trace", "timing_profile"]);
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &inputs,
        &outputs,
        &exceeding_js_budget(),
        &[],
    );
    assert!(!report.compliant);
    assert!(!report.budget_check.within_budget);
}

#[test]
fn enrichment_compliance_report_serde_roundtrip() {
    let charter = canonical_charter(epoch(1));
    let inputs = set_of(&["frir_plan", "component_manifest"]);
    let outputs = set_of(&["dom_patch_log", "execution_trace", "timing_profile"]);
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &inputs,
        &outputs,
        &within_js_budget(),
        &[],
    );
    let json = serde_json::to_string(&report).unwrap();
    let back: ComplianceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// =========================================================================
// 10. SchedulerInvariant — serde
// =========================================================================

#[test]
fn enrichment_scheduler_invariant_serde_roundtrip() {
    let inv = SchedulerInvariant {
        invariant_id: "inv-001".into(),
        description: "test invariant".into(),
        hard: true,
        applies_to: [RuntimeLane::Js, RuntimeLane::Wasm].into_iter().collect(),
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: SchedulerInvariant = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// =========================================================================
// 11. Full charter serde roundtrip
// =========================================================================

#[test]
fn enrichment_full_canonical_charter_serde_roundtrip() {
    let charter = canonical_charter(epoch(42));
    let json = serde_json::to_string(&charter).unwrap();
    let back: RuntimeKernelCharter = serde_json::from_str(&json).unwrap();
    assert_eq!(charter, back);
}
