//! Integration tests for the `runtime_kernel_lane_charter` module.
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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::runtime_kernel_lane_charter::*;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn epoch(n: u64) -> SecurityEpoch {
    SecurityEpoch::from_raw(n)
}

fn js_inputs() -> BTreeSet<String> {
    ["frir_plan", "component_manifest"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn wasm_inputs() -> BTreeSet<String> {
    ["frir_plan", "component_manifest", "wasm_module"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn hybrid_inputs() -> BTreeSet<String> {
    [
        "frir_plan",
        "component_manifest",
        "routing_policy",
        "calibration_data",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn js_outputs() -> BTreeSet<String> {
    ["dom_patch_log", "execution_trace", "timing_profile"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn wasm_outputs() -> BTreeSet<String> {
    [
        "dom_patch_log",
        "execution_trace",
        "timing_profile",
        "signal_graph_snapshot",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn hybrid_outputs() -> BTreeSet<String> {
    [
        "lane_selection_log",
        "routing_decision_receipt",
        "fallback_event_log",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn low_usage() -> ResourceUsage {
    ResourceUsage {
        heap_bytes: 1_000_000,
        stack_frames: 10,
        update_cycle_micros: 5000,
        dom_patches: 50,
    }
}

fn zero_usage() -> ResourceUsage {
    ResourceUsage {
        heap_bytes: 0,
        stack_frames: 0,
        update_cycle_micros: 0,
        dom_patches: 0,
    }
}

// =========================================================================
// Section 1: RuntimeLane
// =========================================================================

#[test]
fn runtime_lane_display_values() {
    assert_eq!(RuntimeLane::Js.to_string(), "js");
    assert_eq!(RuntimeLane::Wasm.to_string(), "wasm");
    assert_eq!(RuntimeLane::HybridRouter.to_string(), "hybrid_router");
}

#[test]
fn runtime_lane_clone_eq() {
    let a = RuntimeLane::Wasm;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn runtime_lane_ord_consistent() {
    assert!(RuntimeLane::Js < RuntimeLane::Wasm);
    assert!(RuntimeLane::Wasm < RuntimeLane::HybridRouter);
    assert!(RuntimeLane::Js < RuntimeLane::HybridRouter);
}

#[test]
fn runtime_lane_serde_roundtrip_all_variants() {
    for lane in [
        RuntimeLane::Js,
        RuntimeLane::Wasm,
        RuntimeLane::HybridRouter,
    ] {
        let json = serde_json::to_string(&lane).unwrap();
        let back: RuntimeLane = serde_json::from_str(&json).unwrap();
        assert_eq!(lane, back);
    }
}

#[test]
fn runtime_lane_btreeset_dedup() {
    let set: BTreeSet<RuntimeLane> = [
        RuntimeLane::Js,
        RuntimeLane::Js,
        RuntimeLane::Wasm,
        RuntimeLane::Wasm,
        RuntimeLane::HybridRouter,
    ]
    .into_iter()
    .collect();
    assert_eq!(set.len(), 3);
}

// =========================================================================
// Section 2: OwnershipDomain
// =========================================================================

#[test]
fn ownership_domain_display_all_unique() {
    let domains = [
        OwnershipDomain::ExecutionCorrectness,
        OwnershipDomain::FootprintBudget,
        OwnershipDomain::SchedulerDeterminism,
        OwnershipDomain::AbiStability,
        OwnershipDomain::FailoverBehavior,
        OwnershipDomain::RoutingPolicy,
        OwnershipDomain::TraceEmission,
        OwnershipDomain::IncidentResponse,
    ];
    let displays: BTreeSet<String> = domains.iter().map(|d| d.to_string()).collect();
    assert_eq!(displays.len(), 8);
}

#[test]
fn ownership_domain_serde_roundtrip_all() {
    for d in [
        OwnershipDomain::ExecutionCorrectness,
        OwnershipDomain::FootprintBudget,
        OwnershipDomain::SchedulerDeterminism,
        OwnershipDomain::AbiStability,
        OwnershipDomain::FailoverBehavior,
        OwnershipDomain::RoutingPolicy,
        OwnershipDomain::TraceEmission,
        OwnershipDomain::IncidentResponse,
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: OwnershipDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}

#[test]
fn ownership_domain_ordering_chain() {
    assert!(OwnershipDomain::ExecutionCorrectness < OwnershipDomain::FootprintBudget);
    assert!(OwnershipDomain::FootprintBudget < OwnershipDomain::SchedulerDeterminism);
    assert!(OwnershipDomain::SchedulerDeterminism < OwnershipDomain::AbiStability);
}

// =========================================================================
// Section 3: FootprintBudget defaults
// =========================================================================

#[test]
fn js_default_budget_values() {
    let b = FootprintBudget::js_default();
    assert_eq!(b.lane, RuntimeLane::Js);
    assert_eq!(b.max_heap_bytes, 16 * 1024 * 1024);
    assert_eq!(b.max_stack_frames, 256);
    assert_eq!(b.max_update_cycle_micros, 16_000);
    assert_eq!(b.max_dom_patches_per_cycle, 1_000);
    assert_eq!(b.max_concurrent_callbacks, 64);
}

#[test]
fn wasm_default_budget_values() {
    let b = FootprintBudget::wasm_default();
    assert_eq!(b.lane, RuntimeLane::Wasm);
    assert_eq!(b.max_heap_bytes, 64 * 1024 * 1024);
    assert_eq!(b.max_stack_frames, 512);
    assert_eq!(b.max_update_cycle_micros, 8_000);
    assert_eq!(b.max_dom_patches_per_cycle, 5_000);
    assert_eq!(b.max_concurrent_callbacks, 128);
}

#[test]
fn hybrid_router_default_budget_values() {
    let b = FootprintBudget::hybrid_router_default();
    assert_eq!(b.lane, RuntimeLane::HybridRouter);
    assert_eq!(b.max_heap_bytes, 4 * 1024 * 1024);
    assert_eq!(b.max_stack_frames, 32);
    assert_eq!(b.max_update_cycle_micros, 500);
    assert_eq!(b.max_dom_patches_per_cycle, 0);
    assert_eq!(b.max_concurrent_callbacks, 16);
}

#[test]
fn wasm_budget_larger_than_js() {
    let js = FootprintBudget::js_default();
    let wasm = FootprintBudget::wasm_default();
    assert!(wasm.max_heap_bytes > js.max_heap_bytes);
    assert!(wasm.max_stack_frames > js.max_stack_frames);
    assert!(wasm.max_dom_patches_per_cycle > js.max_dom_patches_per_cycle);
}

// =========================================================================
// Section 4: FootprintBudget::check_usage
// =========================================================================

#[test]
fn check_usage_all_within_budget() {
    let b = FootprintBudget::js_default();
    let result = b.check_usage(&low_usage());
    assert!(result.within_budget);
    assert!(result.violations.is_empty());
    assert_eq!(result.lane, RuntimeLane::Js);
}

#[test]
fn check_usage_exact_boundary_passes() {
    let b = FootprintBudget::js_default();
    let usage = ResourceUsage {
        heap_bytes: b.max_heap_bytes,
        stack_frames: b.max_stack_frames,
        update_cycle_micros: b.max_update_cycle_micros,
        dom_patches: b.max_dom_patches_per_cycle,
    };
    let result = b.check_usage(&usage);
    assert!(result.within_budget);
    assert!(result.violations.is_empty());
}

#[test]
fn check_usage_one_byte_over_heap_fails() {
    let b = FootprintBudget::js_default();
    let usage = ResourceUsage {
        heap_bytes: b.max_heap_bytes + 1,
        stack_frames: 0,
        update_cycle_micros: 0,
        dom_patches: 0,
    };
    let result = b.check_usage(&usage);
    assert!(!result.within_budget);
    assert_eq!(result.violations.len(), 1);
    assert_eq!(result.violations[0].resource, "heap_bytes");
    assert_eq!(result.violations[0].limit, b.max_heap_bytes);
    assert_eq!(result.violations[0].observed, b.max_heap_bytes + 1);
}

#[test]
fn check_usage_stack_frames_exceeded() {
    let b = FootprintBudget::js_default();
    let usage = ResourceUsage {
        heap_bytes: 0,
        stack_frames: b.max_stack_frames + 1,
        update_cycle_micros: 0,
        dom_patches: 0,
    };
    let result = b.check_usage(&usage);
    assert!(!result.within_budget);
    assert_eq!(result.violations[0].resource, "stack_frames");
}

#[test]
fn check_usage_update_cycle_exceeded() {
    let b = FootprintBudget::wasm_default();
    let usage = ResourceUsage {
        heap_bytes: 0,
        stack_frames: 0,
        update_cycle_micros: b.max_update_cycle_micros + 1,
        dom_patches: 0,
    };
    let result = b.check_usage(&usage);
    assert!(!result.within_budget);
    assert_eq!(result.violations[0].resource, "update_cycle_micros");
}

#[test]
fn check_usage_dom_patches_exceeded() {
    let b = FootprintBudget::js_default();
    let usage = ResourceUsage {
        heap_bytes: 0,
        stack_frames: 0,
        update_cycle_micros: 0,
        dom_patches: b.max_dom_patches_per_cycle + 1,
    };
    let result = b.check_usage(&usage);
    assert!(!result.within_budget);
    assert_eq!(result.violations[0].resource, "dom_patches");
}

#[test]
fn check_usage_all_four_exceeded() {
    let b = FootprintBudget::js_default();
    let usage = ResourceUsage {
        heap_bytes: b.max_heap_bytes + 1,
        stack_frames: b.max_stack_frames + 1,
        update_cycle_micros: b.max_update_cycle_micros + 1,
        dom_patches: b.max_dom_patches_per_cycle + 1,
    };
    let result = b.check_usage(&usage);
    assert!(!result.within_budget);
    assert_eq!(result.violations.len(), 4);
}

#[test]
fn check_usage_zero_usage_always_within() {
    for budget in [
        FootprintBudget::js_default(),
        FootprintBudget::wasm_default(),
        FootprintBudget::hybrid_router_default(),
    ] {
        let result = budget.check_usage(&zero_usage());
        assert!(result.within_budget);
    }
}

// =========================================================================
// Section 5: LaneInputContract
// =========================================================================

#[test]
fn js_input_contract_required_inputs() {
    let c = LaneInputContract::js_default();
    assert!(c.required_inputs.contains("frir_plan"));
    assert!(c.required_inputs.contains("component_manifest"));
    assert!(!c.requires_compiler_witness);
    assert!(c.requires_semantics_constraints);
}

#[test]
fn wasm_input_contract_requires_wasm_module_and_witness() {
    let c = LaneInputContract::wasm_default();
    assert!(c.required_inputs.contains("wasm_module"));
    assert!(c.requires_compiler_witness);
    assert_eq!(c.accepted_frir_versions.len(), 1);
    assert!(c.accepted_frir_versions.contains("0.2.0"));
}

#[test]
fn hybrid_input_contract_has_routing_and_calibration() {
    let c = LaneInputContract::hybrid_router_default();
    assert!(c.required_inputs.contains("routing_policy"));
    assert!(c.required_inputs.contains("calibration_data"));
    assert!(!c.requires_compiler_witness);
}

#[test]
fn validate_inputs_satisfied_with_extras() {
    let c = LaneInputContract::js_default();
    let mut provided = js_inputs();
    provided.insert("bonus_artifact".into());
    let v = c.validate_inputs(&provided);
    assert!(v.satisfied);
    assert!(v.missing_inputs.is_empty());
    assert_eq!(v.lane, RuntimeLane::Js);
}

#[test]
fn validate_inputs_empty_set_fails() {
    let c = LaneInputContract::js_default();
    let v = c.validate_inputs(&BTreeSet::new());
    assert!(!v.satisfied);
    assert_eq!(v.missing_inputs.len(), 2);
}

#[test]
fn validate_inputs_partial_wasm_missing_module() {
    let c = LaneInputContract::wasm_default();
    let provided: BTreeSet<String> = ["frir_plan", "component_manifest"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let v = c.validate_inputs(&provided);
    assert!(!v.satisfied);
    assert!(v.missing_inputs.contains("wasm_module"));
}

// =========================================================================
// Section 6: LaneOutputContract
// =========================================================================

#[test]
fn js_output_contract_required_outputs() {
    let c = LaneOutputContract::js_default();
    assert!(c.required_outputs.contains("dom_patch_log"));
    assert!(c.required_outputs.contains("execution_trace"));
    assert!(c.required_outputs.contains("timing_profile"));
    assert!(c.requires_deterministic_trace);
    assert!(c.requires_evidence_ids);
    assert!(c.requires_incident_bundle_on_failure);
}

#[test]
fn wasm_output_contract_has_signal_graph() {
    let c = LaneOutputContract::wasm_default();
    assert!(c.required_outputs.contains("signal_graph_snapshot"));
    assert_eq!(c.required_outputs.len(), 4);
}

#[test]
fn hybrid_output_contract_has_routing_artifacts() {
    let c = LaneOutputContract::hybrid_router_default();
    assert!(c.required_outputs.contains("lane_selection_log"));
    assert!(c.required_outputs.contains("routing_decision_receipt"));
    assert!(c.required_outputs.contains("fallback_event_log"));
    assert!(!c.required_outputs.contains("dom_patch_log"));
}

#[test]
fn validate_outputs_satisfied() {
    let c = LaneOutputContract::js_default();
    let v = c.validate_outputs(&js_outputs());
    assert!(v.satisfied);
    assert!(v.missing_outputs.is_empty());
}

#[test]
fn validate_outputs_empty_fails() {
    let c = LaneOutputContract::wasm_default();
    let v = c.validate_outputs(&BTreeSet::new());
    assert!(!v.satisfied);
    assert_eq!(v.missing_outputs.len(), 4);
}

#[test]
fn validate_outputs_partial_missing() {
    let c = LaneOutputContract::wasm_default();
    let provided: BTreeSet<String> = ["dom_patch_log"].iter().map(|s| s.to_string()).collect();
    let v = c.validate_outputs(&provided);
    assert!(!v.satisfied);
    assert_eq!(v.missing_outputs.len(), 3);
}

// =========================================================================
// Section 7: FailureAction & InvariantKind Display/serde
// =========================================================================

#[test]
fn failure_action_display_all_variants() {
    assert_eq!(
        FailureAction::LogAndContinue.to_string(),
        "log_and_continue"
    );
    assert_eq!(
        FailureAction::FallbackToLane(RuntimeLane::Js).to_string(),
        "fallback_to_js"
    );
    assert_eq!(
        FailureAction::FallbackToLane(RuntimeLane::Wasm).to_string(),
        "fallback_to_wasm"
    );
    assert_eq!(
        FailureAction::FallbackToLane(RuntimeLane::HybridRouter).to_string(),
        "fallback_to_hybrid_router"
    );
    assert_eq!(
        FailureAction::ActivateSafeMode.to_string(),
        "activate_safe_mode"
    );
    assert_eq!(FailureAction::ForceTerminate.to_string(), "force_terminate");
}

#[test]
fn failure_action_serde_roundtrip_all() {
    for v in [
        FailureAction::LogAndContinue,
        FailureAction::FallbackToLane(RuntimeLane::Js),
        FailureAction::FallbackToLane(RuntimeLane::Wasm),
        FailureAction::FallbackToLane(RuntimeLane::HybridRouter),
        FailureAction::ActivateSafeMode,
        FailureAction::ForceTerminate,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: FailureAction = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn invariant_kind_display_all_variants() {
    assert_eq!(
        InvariantKind::SemanticDivergence.to_string(),
        "semantic_divergence"
    );
    assert_eq!(
        InvariantKind::SchedulerNondeterminism.to_string(),
        "scheduler_nondeterminism"
    );
    assert_eq!(InvariantKind::BudgetExceeded.to_string(), "budget_exceeded");
    assert_eq!(InvariantKind::AbiMismatch.to_string(), "abi_mismatch");
    assert_eq!(
        InvariantKind::TraceEmissionFailure.to_string(),
        "trace_emission_failure"
    );
    assert_eq!(
        InvariantKind::RoutingInconsistency.to_string(),
        "routing_inconsistency"
    );
}

#[test]
fn invariant_kind_serde_roundtrip_all() {
    for v in [
        InvariantKind::SemanticDivergence,
        InvariantKind::SchedulerNondeterminism,
        InvariantKind::BudgetExceeded,
        InvariantKind::AbiMismatch,
        InvariantKind::TraceEmissionFailure,
        InvariantKind::RoutingInconsistency,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: InvariantKind = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

// =========================================================================
// Section 8: FailurePolicy
// =========================================================================

#[test]
fn strict_policy_rules_all_six_invariants() {
    let p = FailurePolicy::strict();
    assert_eq!(p.rules.len(), 6);
    assert!(p.always_emit_incident_bundle);
    assert_eq!(p.max_consecutive_failures, 3);
}

#[test]
fn strict_policy_action_semantic_divergence() {
    let p = FailurePolicy::strict();
    assert_eq!(
        *p.action_for(&InvariantKind::SemanticDivergence),
        FailureAction::FallbackToLane(RuntimeLane::Js)
    );
}

#[test]
fn strict_policy_action_scheduler_nondeterminism() {
    let p = FailurePolicy::strict();
    assert_eq!(
        *p.action_for(&InvariantKind::SchedulerNondeterminism),
        FailureAction::ActivateSafeMode
    );
}

#[test]
fn strict_policy_action_budget_exceeded() {
    let p = FailurePolicy::strict();
    assert_eq!(
        *p.action_for(&InvariantKind::BudgetExceeded),
        FailureAction::FallbackToLane(RuntimeLane::Js)
    );
}

#[test]
fn strict_policy_action_abi_mismatch() {
    let p = FailurePolicy::strict();
    assert_eq!(
        *p.action_for(&InvariantKind::AbiMismatch),
        FailureAction::ForceTerminate
    );
}

#[test]
fn strict_policy_action_trace_emission_failure() {
    let p = FailurePolicy::strict();
    assert_eq!(
        *p.action_for(&InvariantKind::TraceEmissionFailure),
        FailureAction::LogAndContinue
    );
}

#[test]
fn strict_policy_action_routing_inconsistency() {
    let p = FailurePolicy::strict();
    assert_eq!(
        *p.action_for(&InvariantKind::RoutingInconsistency),
        FailureAction::FallbackToLane(RuntimeLane::Js)
    );
}

#[test]
fn strict_policy_serde_roundtrip() {
    let p = FailurePolicy::strict();
    let json = serde_json::to_string(&p).unwrap();
    let back: FailurePolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn custom_failure_policy_default_action() {
    let p = FailurePolicy {
        rules: BTreeMap::new(),
        default_action: FailureAction::ForceTerminate,
        always_emit_incident_bundle: false,
        max_consecutive_failures: 1,
    };
    // No specific rule for SemanticDivergence, so default applies
    assert_eq!(
        *p.action_for(&InvariantKind::SemanticDivergence),
        FailureAction::ForceTerminate
    );
}

// =========================================================================
// Section 9: CharterBuilder
// =========================================================================

#[test]
fn builder_minimal_charter() {
    let charter = CharterBuilder::new(epoch(1))
        .ownership(OwnershipDomain::ExecutionCorrectness)
        .build();
    assert_eq!(charter.schema_version, "0.1.0");
    assert_eq!(charter.epoch, epoch(1));
    assert_eq!(charter.ownership_domains.len(), 1);
    assert!(charter.footprint_budgets.is_empty());
    assert!(charter.input_contracts.is_empty());
    assert!(charter.output_contracts.is_empty());
    assert!(charter.scheduler_invariants.is_empty());
}

#[test]
fn builder_with_all_budgets() {
    let charter = CharterBuilder::new(epoch(5))
        .footprint_budget(FootprintBudget::js_default())
        .footprint_budget(FootprintBudget::wasm_default())
        .footprint_budget(FootprintBudget::hybrid_router_default())
        .build();
    assert_eq!(charter.footprint_budgets.len(), 3);
}

#[test]
fn builder_with_input_and_output_contracts() {
    let charter = CharterBuilder::new(epoch(10))
        .input_contract(LaneInputContract::js_default())
        .input_contract(LaneInputContract::wasm_default())
        .output_contract(LaneOutputContract::js_default())
        .output_contract(LaneOutputContract::wasm_default())
        .build();
    assert_eq!(charter.input_contracts.len(), 2);
    assert_eq!(charter.output_contracts.len(), 2);
}

#[test]
fn builder_with_scheduler_invariants() {
    let all_lanes: BTreeSet<RuntimeLane> =
        [RuntimeLane::Js, RuntimeLane::Wasm].into_iter().collect();
    let charter = CharterBuilder::new(epoch(7))
        .scheduler_invariant(SchedulerInvariant {
            invariant_id: "inv-001".into(),
            description: "test invariant".into(),
            hard: true,
            applies_to: all_lanes,
        })
        .build();
    assert_eq!(charter.scheduler_invariants.len(), 1);
    assert!(charter.scheduler_invariants[0].hard);
}

#[test]
fn builder_custom_failure_policy() {
    let custom = FailurePolicy {
        rules: BTreeMap::new(),
        default_action: FailureAction::ForceTerminate,
        always_emit_incident_bundle: false,
        max_consecutive_failures: 10,
    };
    let charter = CharterBuilder::new(epoch(2))
        .failure_policy(custom.clone())
        .build();
    assert_eq!(charter.failure_policy.max_consecutive_failures, 10);
    assert!(!charter.failure_policy.always_emit_incident_bundle);
}

#[test]
fn builder_content_hash_deterministic() {
    let c1 = CharterBuilder::new(epoch(42))
        .ownership(OwnershipDomain::ExecutionCorrectness)
        .ownership(OwnershipDomain::FootprintBudget)
        .footprint_budget(FootprintBudget::js_default())
        .build();
    let c2 = CharterBuilder::new(epoch(42))
        .ownership(OwnershipDomain::ExecutionCorrectness)
        .ownership(OwnershipDomain::FootprintBudget)
        .footprint_budget(FootprintBudget::js_default())
        .build();
    assert_eq!(c1.content_hash, c2.content_hash);
    assert_eq!(c1.charter_id, c2.charter_id);
}

#[test]
fn builder_different_epochs_different_hash() {
    let c1 = CharterBuilder::new(epoch(1)).build();
    let c2 = CharterBuilder::new(epoch(2)).build();
    assert_ne!(c1.content_hash, c2.content_hash);
    assert_ne!(c1.charter_id, c2.charter_id);
}

#[test]
fn builder_different_domains_different_hash() {
    let c1 = CharterBuilder::new(epoch(1))
        .ownership(OwnershipDomain::ExecutionCorrectness)
        .build();
    let c2 = CharterBuilder::new(epoch(1))
        .ownership(OwnershipDomain::FootprintBudget)
        .build();
    assert_ne!(c1.content_hash, c2.content_hash);
}

// =========================================================================
// Section 10: canonical_charter
// =========================================================================

#[test]
fn canonical_charter_has_all_eight_domains() {
    let charter = canonical_charter(epoch(100));
    assert_eq!(charter.ownership_domains.len(), 8);
    assert!(
        charter
            .ownership_domains
            .contains(&OwnershipDomain::ExecutionCorrectness)
    );
    assert!(
        charter
            .ownership_domains
            .contains(&OwnershipDomain::IncidentResponse)
    );
}

#[test]
fn canonical_charter_three_budgets_three_input_three_output() {
    let charter = canonical_charter(epoch(100));
    assert_eq!(charter.footprint_budgets.len(), 3);
    assert_eq!(charter.input_contracts.len(), 3);
    assert_eq!(charter.output_contracts.len(), 3);
}

#[test]
fn canonical_charter_four_scheduler_invariants() {
    let charter = canonical_charter(epoch(100));
    assert_eq!(charter.scheduler_invariants.len(), 4);
    // First three hard, last soft
    assert!(charter.scheduler_invariants[0].hard);
    assert!(charter.scheduler_invariants[1].hard);
    assert!(charter.scheduler_invariants[2].hard);
    assert!(!charter.scheduler_invariants[3].hard);
}

#[test]
fn canonical_charter_scheduler_invariants_apply_to_all_lanes() {
    let charter = canonical_charter(epoch(100));
    for inv in &charter.scheduler_invariants {
        assert!(inv.applies_to.contains(&RuntimeLane::Js));
        assert!(inv.applies_to.contains(&RuntimeLane::Wasm));
        assert!(inv.applies_to.contains(&RuntimeLane::HybridRouter));
    }
}

#[test]
fn canonical_charter_serde_roundtrip() {
    let charter = canonical_charter(epoch(42));
    let json = serde_json::to_string(&charter).unwrap();
    let back: RuntimeKernelCharter = serde_json::from_str(&json).unwrap();
    assert_eq!(charter, back);
}

// =========================================================================
// Section 11: check_compliance
// =========================================================================

#[test]
fn compliance_js_all_satisfied() {
    let charter = canonical_charter(epoch(1));
    let invariants = vec![("sched-det-001".into(), true, "ok".into())];
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &invariants,
    );
    assert!(report.compliant);
    assert!(report.input_validation.satisfied);
    assert!(report.output_validation.satisfied);
    assert!(report.budget_check.within_budget);
    assert_eq!(report.lane, RuntimeLane::Js);
}

#[test]
fn compliance_wasm_all_satisfied() {
    let charter = canonical_charter(epoch(1));
    let report = check_compliance(
        &charter,
        &RuntimeLane::Wasm,
        &wasm_inputs(),
        &wasm_outputs(),
        &low_usage(),
        &[],
    );
    assert!(report.compliant);
}

#[test]
fn compliance_hybrid_all_satisfied() {
    let charter = canonical_charter(epoch(1));
    // Hybrid router has max_dom_patches_per_cycle == 0, so use zero usage.
    let report = check_compliance(
        &charter,
        &RuntimeLane::HybridRouter,
        &hybrid_inputs(),
        &hybrid_outputs(),
        &zero_usage(),
        &[],
    );
    assert!(report.compliant);
}

#[test]
fn compliance_fails_on_missing_inputs() {
    let charter = canonical_charter(epoch(1));
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &BTreeSet::new(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    assert!(!report.compliant);
    assert!(!report.input_validation.satisfied);
    assert_eq!(report.input_validation.missing_inputs.len(), 2);
}

#[test]
fn compliance_fails_on_missing_outputs() {
    let charter = canonical_charter(epoch(1));
    let report = check_compliance(
        &charter,
        &RuntimeLane::Wasm,
        &wasm_inputs(),
        &BTreeSet::new(),
        &low_usage(),
        &[],
    );
    assert!(!report.compliant);
    assert!(!report.output_validation.satisfied);
}

#[test]
fn compliance_fails_on_budget_exceeded() {
    let charter = canonical_charter(epoch(1));
    let bad_usage = ResourceUsage {
        heap_bytes: 100 * 1024 * 1024,
        stack_frames: 10,
        update_cycle_micros: 5000,
        dom_patches: 50,
    };
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &bad_usage,
        &[],
    );
    assert!(!report.compliant);
    assert!(!report.budget_check.within_budget);
}

#[test]
fn compliance_fails_on_invariant_violation() {
    let charter = canonical_charter(epoch(1));
    let invariants = vec![(
        "sched-det-001".into(),
        false,
        "nondeterministic ordering".into(),
    )];
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &invariants,
    );
    assert!(!report.compliant);
    assert!(!report.invariant_checks[0].satisfied);
}

#[test]
fn compliance_fails_on_multiple_issues() {
    let charter = canonical_charter(epoch(1));
    let bad_usage = ResourceUsage {
        heap_bytes: 100 * 1024 * 1024,
        stack_frames: 1000,
        update_cycle_micros: 50_000,
        dom_patches: 5000,
    };
    let invariants = vec![("inv-fail".into(), false, "failed".into())];
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &bad_usage,
        &invariants,
    );
    assert!(!report.compliant);
    assert!(!report.input_validation.satisfied);
    assert!(!report.output_validation.satisfied);
    assert!(!report.budget_check.within_budget);
    assert!(!report.invariant_checks[0].satisfied);
}

#[test]
fn compliance_report_hash_deterministic() {
    let charter = canonical_charter(epoch(1));
    let r1 = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    let r2 = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    assert_eq!(r1.report_hash, r2.report_hash);
}

#[test]
fn compliance_report_hash_differs_by_lane() {
    let charter = canonical_charter(epoch(1));
    let r_js = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    let r_wasm = check_compliance(
        &charter,
        &RuntimeLane::Wasm,
        &wasm_inputs(),
        &wasm_outputs(),
        &low_usage(),
        &[],
    );
    assert_ne!(r_js.report_hash, r_wasm.report_hash);
}

#[test]
fn compliance_report_serde_roundtrip() {
    let charter = canonical_charter(epoch(1));
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[("inv1".into(), true, "ok".into())],
    );
    let json = serde_json::to_string(&report).unwrap();
    let back: ComplianceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// =========================================================================
// Section 12: CharterRegistry
// =========================================================================

#[test]
fn registry_new_has_activated_event() {
    let reg = CharterRegistry::new(epoch(1));
    assert_eq!(reg.events.len(), 1);
    assert!(matches!(
        reg.events[0].kind,
        CharterEventKind::Activated { .. }
    ));
    assert_eq!(reg.events[0].seq, 1);
    assert!(reg.compliance_history.is_empty());
}

#[test]
fn registry_record_compliance_adds_event() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    reg.record_compliance(report, 1000);
    assert_eq!(reg.compliance_history.len(), 1);
    assert_eq!(reg.events.len(), 2);
    assert!(matches!(
        reg.events[1].kind,
        CharterEventKind::ComplianceChecked {
            lane: RuntimeLane::Js,
            compliant: true,
        }
    ));
}

#[test]
fn registry_record_failing_compliance() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &BTreeSet::new(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    reg.record_compliance(report, 500);
    assert_eq!(reg.events.len(), 2);
    assert!(matches!(
        reg.events[1].kind,
        CharterEventKind::ComplianceChecked {
            lane: RuntimeLane::Js,
            compliant: false,
        }
    ));
}

#[test]
fn registry_pass_rate_no_history_returns_million() {
    let reg = CharterRegistry::new(epoch(1));
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Js), 1_000_000);
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Wasm), 1_000_000);
}

#[test]
fn registry_pass_rate_all_pass() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();
    for i in 0..5 {
        let report = check_compliance(
            &charter,
            &RuntimeLane::Js,
            &js_inputs(),
            &js_outputs(),
            &low_usage(),
            &[],
        );
        reg.record_compliance(report, i * 1000);
    }
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Js), 1_000_000);
}

#[test]
fn registry_pass_rate_all_fail() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();
    for i in 0..3 {
        let report = check_compliance(
            &charter,
            &RuntimeLane::Wasm,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &low_usage(),
            &[],
        );
        reg.record_compliance(report, i * 1000);
    }
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Wasm), 0);
}

#[test]
fn registry_pass_rate_two_thirds() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();

    // 2 passing
    for _ in 0..2 {
        let report = check_compliance(
            &charter,
            &RuntimeLane::Js,
            &js_inputs(),
            &js_outputs(),
            &low_usage(),
            &[],
        );
        reg.record_compliance(report, 0);
    }

    // 1 failing
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &BTreeSet::new(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    reg.record_compliance(report, 0);

    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Js), 666_666);
}

#[test]
fn registry_pass_rate_per_lane_independent() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();

    // JS passes
    let js_report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    reg.record_compliance(js_report, 0);

    // WASM fails
    let wasm_report = check_compliance(
        &charter,
        &RuntimeLane::Wasm,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &low_usage(),
        &[],
    );
    reg.record_compliance(wasm_report, 0);

    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Js), 1_000_000);
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Wasm), 0);
}

#[test]
fn registry_handle_violation_delegates_to_policy() {
    let reg = CharterRegistry::new(epoch(1));
    assert_eq!(
        *reg.handle_violation(&InvariantKind::AbiMismatch),
        FailureAction::ForceTerminate
    );
    assert_eq!(
        *reg.handle_violation(&InvariantKind::TraceEmissionFailure),
        FailureAction::LogAndContinue
    );
}

#[test]
fn registry_event_seq_increments() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();
    for i in 0..3 {
        let report = check_compliance(
            &charter,
            &RuntimeLane::Js,
            &js_inputs(),
            &js_outputs(),
            &low_usage(),
            &[],
        );
        reg.record_compliance(report, i * 100);
    }
    // seq starts at 1 (activated), then 2, 3, 4
    assert_eq!(reg.events[0].seq, 1);
    assert_eq!(reg.events[1].seq, 2);
    assert_eq!(reg.events[2].seq, 3);
    assert_eq!(reg.events[3].seq, 4);
}

#[test]
fn registry_event_tick_ns_preserved() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    reg.record_compliance(report, 42_000);
    assert_eq!(reg.events[1].tick_ns, 42_000);
}

#[test]
fn registry_serde_roundtrip() {
    let mut reg = CharterRegistry::new(epoch(1));
    let charter = reg.active_charter.clone();
    let report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[],
    );
    reg.record_compliance(report, 1000);
    let json = serde_json::to_string(&reg).unwrap();
    let back: CharterRegistry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.compliance_history.len(), 1);
    assert_eq!(back.events.len(), 2);
}

// =========================================================================
// Section 13: Full lifecycle integration
// =========================================================================

#[test]
fn full_lifecycle_three_lane_compliance() {
    let mut reg = CharterRegistry::new(epoch(50));
    let charter = reg.active_charter.clone();

    // JS lane: compliant
    let js_report = check_compliance(
        &charter,
        &RuntimeLane::Js,
        &js_inputs(),
        &js_outputs(),
        &low_usage(),
        &[("sched-det-001".into(), true, "ok".into())],
    );
    assert!(js_report.compliant);
    reg.record_compliance(js_report, 1000);

    // WASM lane: compliant
    let wasm_report = check_compliance(
        &charter,
        &RuntimeLane::Wasm,
        &wasm_inputs(),
        &wasm_outputs(),
        &low_usage(),
        &[("sched-det-002".into(), true, "ok".into())],
    );
    assert!(wasm_report.compliant);
    reg.record_compliance(wasm_report, 2000);

    // Hybrid lane: fails on missing output
    let hybrid_report = check_compliance(
        &charter,
        &RuntimeLane::HybridRouter,
        &hybrid_inputs(),
        &BTreeSet::new(),
        &low_usage(),
        &[],
    );
    assert!(!hybrid_report.compliant);
    reg.record_compliance(hybrid_report, 3000);

    // Pass rates
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Js), 1_000_000);
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::Wasm), 1_000_000);
    assert_eq!(reg.pass_rate_millionths(&RuntimeLane::HybridRouter), 0);

    // Events: 1 activated + 3 compliance checks
    assert_eq!(reg.events.len(), 4);
}

#[test]
fn lifecycle_failure_policy_escalation() {
    let reg = CharterRegistry::new(epoch(1));

    // Trace emission failure: least severe (log and continue)
    let a1 = reg.handle_violation(&InvariantKind::TraceEmissionFailure);
    assert_eq!(*a1, FailureAction::LogAndContinue);

    // Budget exceeded: fallback to JS
    let a2 = reg.handle_violation(&InvariantKind::BudgetExceeded);
    assert_eq!(*a2, FailureAction::FallbackToLane(RuntimeLane::Js));

    // Scheduler nondeterminism: safe mode
    let a3 = reg.handle_violation(&InvariantKind::SchedulerNondeterminism);
    assert_eq!(*a3, FailureAction::ActivateSafeMode);

    // ABI mismatch: terminate
    let a4 = reg.handle_violation(&InvariantKind::AbiMismatch);
    assert_eq!(*a4, FailureAction::ForceTerminate);
}

// =========================================================================
// Section 14: Serde roundtrips for remaining types
// =========================================================================

#[test]
fn scheduler_invariant_serde_roundtrip() {
    let inv = SchedulerInvariant {
        invariant_id: "test-inv".into(),
        description: "deterministic scheduling".into(),
        hard: true,
        applies_to: [RuntimeLane::Js, RuntimeLane::Wasm].into_iter().collect(),
    };
    let json = serde_json::to_string(&inv).unwrap();
    let back: SchedulerInvariant = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

#[test]
fn charter_event_serde_roundtrip() {
    let reg = CharterRegistry::new(epoch(1));
    let event = &reg.events[0];
    let json = serde_json::to_string(event).unwrap();
    let back: CharterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(*event, back);
}

#[test]
fn charter_event_kind_compliance_serde_roundtrip() {
    let kind = CharterEventKind::ComplianceChecked {
        lane: RuntimeLane::Wasm,
        compliant: false,
    };
    let json = serde_json::to_string(&kind).unwrap();
    let back: CharterEventKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, back);
}

#[test]
fn charter_event_kind_failure_policy_serde_roundtrip() {
    let kind = CharterEventKind::FailurePolicyTriggered {
        invariant: InvariantKind::AbiMismatch,
        action: FailureAction::ForceTerminate,
    };
    let json = serde_json::to_string(&kind).unwrap();
    let back: CharterEventKind = serde_json::from_str(&json).unwrap();
    assert_eq!(kind, back);
}

#[test]
fn resource_usage_serde_roundtrip() {
    let usage = low_usage();
    let json = serde_json::to_string(&usage).unwrap();
    let back: ResourceUsage = serde_json::from_str(&json).unwrap();
    assert_eq!(usage, back);
}

#[test]
fn invariant_check_serde_roundtrip() {
    let check = InvariantCheck {
        invariant_id: "test-inv-001".into(),
        satisfied: false,
        detail: "nondeterministic ordering detected".into(),
    };
    let json = serde_json::to_string(&check).unwrap();
    let back: InvariantCheck = serde_json::from_str(&json).unwrap();
    assert_eq!(check, back);
}
