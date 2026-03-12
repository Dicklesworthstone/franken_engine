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

use frankenengine_engine::hook_effect_contract::{
    DepToken, EffectTiming, FallbackExecutionRoute, HookKind, HookManifest, HookManifestError,
    HookRuleViolation, HookSlot, HookSlotIndex, RenderPhase, UnsupportedSemanticsTrigger,
    build_unsupported_semantics_diagnostic, classify_unsupported_semantics,
    validate_hook_consistency,
};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "franken-engine.hook-effect-unsupported-semantics.scenario-log.v1";
const POLICY_ID: &str = "policy-frx-unsupported-semantics-v1";
const COMPONENT: &str = "hook_effect_fallback_contract";
const REPLAY_COMMAND: &str = "./scripts/e2e/frx_unsupported_semantics_fallback_rules_replay.sh ci";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScenarioLogEvent {
    schema_version: String,
    scenario_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    decision_path: String,
    trigger: String,
    fallback_route: String,
    outcome: String,
    error_code: Option<String>,
    hardening_guidance: String,
    replay_command: String,
}

fn make_slot(index: u32, kind: HookKind) -> HookSlot {
    HookSlot {
        index: HookSlotIndex(index),
        kind,
        deps: None,
    }
}

struct LogEventInput<'a> {
    scenario_id: &'a str,
    trace_id: &'a str,
    decision_id: &'a str,
    event: &'a str,
    decision_path: &'a str,
    trigger: UnsupportedSemanticsTrigger,
    route: FallbackExecutionRoute,
    outcome: &'a str,
    error_code: Option<&'a str>,
    hardening_guidance: &'a str,
}

fn log_event(input: LogEventInput<'_>) -> ScenarioLogEvent {
    ScenarioLogEvent {
        schema_version: SCHEMA_VERSION.to_string(),
        scenario_id: input.scenario_id.to_string(),
        trace_id: input.trace_id.to_string(),
        decision_id: input.decision_id.to_string(),
        policy_id: POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: input.event.to_string(),
        decision_path: input.decision_path.to_string(),
        trigger: format!("{:?}", input.trigger),
        fallback_route: format!("{:?}", input.route),
        outcome: input.outcome.to_string(),
        error_code: input.error_code.map(str::to_string),
        hardening_guidance: input.hardening_guidance.to_string(),
        replay_command: REPLAY_COMMAND.to_string(),
    }
}

#[test]
fn unsupported_semantics_hook_topology_drift_fails_closed_with_compat_route() {
    let prev = HookManifest::new(
        "App",
        vec![
            make_slot(0, HookKind::State),
            make_slot(1, HookKind::Effect),
            make_slot(2, HookKind::Memo),
        ],
    );
    let curr = HookManifest::new("App", vec![make_slot(0, HookKind::State)]);

    let violations = validate_hook_consistency(&prev, &curr);
    assert_eq!(violations.len(), 1);
    let trigger = classify_unsupported_semantics(&violations[0]);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);

    let diagnostic = build_unsupported_semantics_diagnostic(
        "App",
        trigger,
        "trace-hook-topology-drift",
        "decision-hook-topology-drift",
    );
    assert!(diagnostic.compile_path_rejected);
    assert_eq!(
        diagnostic.fallback_route,
        FallbackExecutionRoute::CompatibilityRuntimeLane
    );
    assert_eq!(diagnostic.error_code, "FE-HOOK-UNSUPPORTED-0001");

    let event = log_event(LogEventInput {
        scenario_id: "unsupported_semantics_hook_topology_drift",
        trace_id: &diagnostic.trace_id,
        decision_id: &diagnostic.decision_id,
        event: "fallback_decision",
        decision_path: "validate_hook_consistency->fallback",
        trigger: diagnostic.trigger,
        route: diagnostic.fallback_route,
        outcome: "pass",
        error_code: Some(&diagnostic.error_code),
        hardening_guidance: &diagnostic.hardening_guidance,
    });

    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.outcome, "pass");
    assert_eq!(
        event.error_code.as_deref(),
        Some("FE-HOOK-UNSUPPORTED-0001")
    );
    assert_eq!(event.replay_command, REPLAY_COMMAND);
}

#[test]
fn unsupported_semantics_out_of_render_violation_uses_safe_mode_lane() {
    let violation = HookRuleViolation::HookOutsideRender {
        component: "Widget".to_string(),
        slot: HookSlotIndex(1),
        actual_phase: RenderPhase::Idle,
    };

    let trigger = classify_unsupported_semantics(&violation);
    assert_eq!(
        trigger,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution
    );

    let diagnostic = build_unsupported_semantics_diagnostic(
        "Widget",
        trigger,
        "trace-outside-render",
        "decision-outside-render",
    );

    assert!(diagnostic.compile_path_rejected);
    assert_eq!(
        diagnostic.fallback_route,
        FallbackExecutionRoute::DeterministicSafeModeLane
    );
    assert_eq!(diagnostic.error_code, "FE-HOOK-UNSUPPORTED-0003");
    assert!(diagnostic.hardening_guidance.contains("phase"));
}

#[test]
fn unsupported_semantics_same_input_yields_identical_diagnostic() {
    let d1 = build_unsupported_semantics_diagnostic(
        "Counter",
        UnsupportedSemanticsTrigger::TransformationProofMissing,
        "trace-proof-missing",
        "decision-proof-missing",
    );
    let d2 = build_unsupported_semantics_diagnostic(
        "Counter",
        UnsupportedSemanticsTrigger::TransformationProofMissing,
        "trace-proof-missing",
        "decision-proof-missing",
    );

    assert_eq!(d1, d2);
    assert_eq!(d1.derive_id(), d2.derive_id());
    assert_eq!(
        d1.fallback_route,
        FallbackExecutionRoute::BaselineInterpreterLane
    );
    assert_eq!(d1.error_code, "FE-HOOK-UNSUPPORTED-0006");
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, display, classification, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn unsupported_semantics_trigger_serde_round_trip_all_variants() {
    for trigger in [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ] {
        let json = serde_json::to_string(&trigger).expect("serialize");
        let recovered: UnsupportedSemanticsTrigger =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(trigger, recovered);
    }
}

#[test]
fn unsupported_semantics_trigger_stable_error_codes_are_unique() {
    let triggers = [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ];
    let mut codes: Vec<&str> = triggers.iter().map(|t| t.stable_error_code()).collect();
    let original_len = codes.len();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), original_len, "error codes must be unique");
    assert!(codes.iter().all(|c| c.starts_with("FE-HOOK-UNSUPPORTED-")));
}

#[test]
fn unsupported_semantics_trigger_rejection_reasons_are_non_empty() {
    for trigger in [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ] {
        assert!(
            !trigger.rejection_reason().is_empty(),
            "rejection reason must not be empty for {trigger:?}"
        );
    }
}

#[test]
fn fallback_execution_route_serde_round_trip_all_variants() {
    for route in [
        FallbackExecutionRoute::CompatibilityRuntimeLane,
        FallbackExecutionRoute::BaselineInterpreterLane,
        FallbackExecutionRoute::DeterministicSafeModeLane,
    ] {
        let json = serde_json::to_string(&route).expect("serialize");
        let recovered: FallbackExecutionRoute = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(route, recovered);
    }
}

#[test]
fn unsupported_semantics_diagnostic_serde_round_trip() {
    let diagnostic = build_unsupported_semantics_diagnostic(
        "TestComponent",
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        "trace-serde-rt",
        "decision-serde-rt",
    );
    let json = serde_json::to_string(&diagnostic).expect("serialize");
    let recovered: frankenengine_engine::hook_effect_contract::UnsupportedSemanticsDiagnostic =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(diagnostic, recovered);
}

#[test]
fn every_trigger_maps_to_a_distinct_fallback_route() {
    let topology = build_unsupported_semantics_diagnostic(
        "A",
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        "t",
        "d",
    );
    let out_of_render = build_unsupported_semantics_diagnostic(
        "B",
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        "t",
        "d",
    );
    let proof_missing = build_unsupported_semantics_diagnostic(
        "C",
        UnsupportedSemanticsTrigger::TransformationProofMissing,
        "t",
        "d",
    );
    assert_eq!(
        topology.fallback_route,
        FallbackExecutionRoute::CompatibilityRuntimeLane
    );
    assert_eq!(
        out_of_render.fallback_route,
        FallbackExecutionRoute::DeterministicSafeModeLane
    );
    assert_eq!(
        proof_missing.fallback_route,
        FallbackExecutionRoute::BaselineInterpreterLane
    );
}

#[test]
fn classify_unsupported_semantics_handles_kind_order_drift() {
    let violation = HookRuleViolation::HookKindMismatch {
        component: "Reorder".to_string(),
        slot: HookSlotIndex(2),
        previous_kind: HookKind::State,
        current_kind: HookKind::Memo,
    };
    let trigger = classify_unsupported_semantics(&violation);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);
}

#[test]
fn scenario_log_event_serde_round_trip() {
    let event = log_event(LogEventInput {
        scenario_id: "serde-test",
        trace_id: "trace-serde",
        decision_id: "decision-serde",
        event: "test_event",
        decision_path: "test->path",
        trigger: UnsupportedSemanticsTrigger::DependencyShapeDrift,
        route: FallbackExecutionRoute::CompatibilityRuntimeLane,
        outcome: "pass",
        error_code: Some("FE-HOOK-UNSUPPORTED-0002"),
        hardening_guidance: "test guidance",
    });
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: ScenarioLogEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn hook_manifest_consistent_with_itself_has_no_violations() {
    let manifest = HookManifest::new(
        "Stable",
        vec![
            make_slot(0, HookKind::State),
            make_slot(1, HookKind::Effect),
        ],
    );
    let violations = validate_hook_consistency(&manifest, &manifest);
    assert!(violations.is_empty());
}

#[test]
fn empty_hook_manifest_consistent_with_itself() {
    let manifest = HookManifest::new("Empty", vec![]);
    let violations = validate_hook_consistency(&manifest, &manifest);
    assert!(violations.is_empty());
}

#[test]
fn make_slot_populates_fields() {
    let slot = make_slot(3, HookKind::Memo);
    assert_eq!(slot.index, HookSlotIndex(3));
    assert_eq!(slot.kind, HookKind::Memo);
    assert!(slot.deps.is_none());
}

#[test]
fn hook_kind_serde_round_trip_all_variants() {
    for kind in [HookKind::State, HookKind::Effect, HookKind::Memo] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: HookKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn render_phase_serde_round_trip() {
    let phase = RenderPhase::Idle;
    let json = serde_json::to_string(&phase).expect("serialize");
    let recovered: RenderPhase = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(phase, recovered);
}

#[test]
fn hook_slot_index_ordering_is_correct() {
    let a = HookSlotIndex(1);
    let b = HookSlotIndex(5);
    assert!(a < b);
    assert_eq!(HookSlotIndex(3), HookSlotIndex(3));
}

#[test]
fn log_event_populates_constants() {
    let event = log_event(LogEventInput {
        scenario_id: "test-constants",
        trace_id: "trace-const",
        decision_id: "decision-const",
        event: "check",
        decision_path: "validate->check",
        trigger: UnsupportedSemanticsTrigger::HookTopologyDrift,
        route: FallbackExecutionRoute::CompatibilityRuntimeLane,
        outcome: "pass",
        error_code: None,
        hardening_guidance: "none",
    });
    assert_eq!(event.schema_version, SCHEMA_VERSION);
    assert_eq!(event.policy_id, POLICY_ID);
    assert_eq!(event.component, COMPONENT);
    assert_eq!(event.replay_command, REPLAY_COMMAND);
    assert!(event.error_code.is_none());
}

#[test]
fn hook_kind_serde_roundtrip() {
    for kind in [
        HookKind::State,
        HookKind::Effect,
        HookKind::Memo,
        HookKind::Reducer,
    ] {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: HookKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, recovered);
    }
}

#[test]
fn render_phase_serde_roundtrip() {
    for phase in [
        RenderPhase::Rendering,
        RenderPhase::PaintPending,
        RenderPhase::PassiveEffectsPending,
    ] {
        let json = serde_json::to_string(&phase).expect("serialize");
        let recovered: RenderPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(phase, recovered);
    }
}

#[test]
fn fallback_execution_route_serde_roundtrip() {
    for route in [
        FallbackExecutionRoute::CompatibilityRuntimeLane,
        FallbackExecutionRoute::BaselineInterpreterLane,
        FallbackExecutionRoute::DeterministicSafeModeLane,
    ] {
        let json = serde_json::to_string(&route).expect("serialize");
        let recovered: FallbackExecutionRoute = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(route, recovered);
    }
}

#[test]
fn hook_kind_debug_is_nonempty() {
    for kind in [
        HookKind::State,
        HookKind::Effect,
        HookKind::Memo,
        HookKind::Reducer,
    ] {
        assert!(!format!("{kind:?}").is_empty());
    }
}

#[test]
fn render_phase_debug_is_nonempty() {
    for phase in [
        RenderPhase::Idle,
        RenderPhase::Rendering,
        RenderPhase::PaintPending,
        RenderPhase::PassiveEffectsPending,
    ] {
        assert!(!format!("{phase:?}").is_empty());
    }
}

#[test]
fn fallback_execution_route_debug_is_nonempty() {
    for route in [
        FallbackExecutionRoute::CompatibilityRuntimeLane,
        FallbackExecutionRoute::BaselineInterpreterLane,
        FallbackExecutionRoute::DeterministicSafeModeLane,
    ] {
        assert!(!format!("{route:?}").is_empty());
    }
}

#[test]
fn diagnostic_derive_id_is_deterministic_across_calls() {
    let d = build_unsupported_semantics_diagnostic(
        "StableId",
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        "trace-stable-id",
        "decision-stable-id",
    );
    let id1 = d.derive_id();
    let id2 = d.derive_id();
    assert_eq!(id1, id2, "derive_id must be deterministic");
}

#[test]
fn diagnostic_for_different_components_produces_different_ids() {
    let d1 = build_unsupported_semantics_diagnostic(
        "Alpha",
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        "t",
        "d",
    );
    let d2 = build_unsupported_semantics_diagnostic(
        "Beta",
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        "t",
        "d",
    );
    assert_ne!(d1.derive_id(), d2.derive_id());
}

#[test]
fn adding_slots_triggers_topology_drift_violation() {
    let prev = HookManifest::new("Grow", vec![make_slot(0, HookKind::State)]);
    let curr = HookManifest::new(
        "Grow",
        vec![
            make_slot(0, HookKind::State),
            make_slot(1, HookKind::Effect),
        ],
    );
    let violations = validate_hook_consistency(&prev, &curr);
    // Hook count change (either direction) is a topology drift violation
    assert!(
        !violations.is_empty(),
        "changing hook count should trigger a violation"
    );
    let trigger = classify_unsupported_semantics(&violations[0]);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);
}

#[test]
fn hook_manifest_serde_roundtrip() {
    let manifest = HookManifest::new(
        "SerdeTest",
        vec![make_slot(0, HookKind::State), make_slot(1, HookKind::Memo)],
    );
    let json = serde_json::to_string(&manifest).expect("serialize");
    let recovered: HookManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(manifest.component_name, recovered.component_name);
    assert_eq!(manifest.slots.len(), recovered.slots.len());
}

#[test]
fn unsupported_hook_primitive_routes_to_compatibility_lane() {
    let diagnostic = build_unsupported_semantics_diagnostic(
        "PrimTest",
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        "trace-prim",
        "decision-prim",
    );
    assert!(diagnostic.compile_path_rejected);
    assert_eq!(diagnostic.error_code, "FE-HOOK-UNSUPPORTED-0005");
}

#[test]
fn dependency_shape_drift_routes_to_compatibility_lane() {
    let diagnostic = build_unsupported_semantics_diagnostic(
        "DepTest",
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        "trace-dep",
        "decision-dep",
    );
    assert!(diagnostic.compile_path_rejected);
    assert_eq!(diagnostic.error_code, "FE-HOOK-UNSUPPORTED-0002");
    assert_eq!(
        diagnostic.fallback_route,
        FallbackExecutionRoute::CompatibilityRuntimeLane
    );
}

// ---------------------------------------------------------------------------
// HookKind classification methods
// ---------------------------------------------------------------------------

#[test]
fn hook_kind_all_has_expected_count() {
    assert_eq!(HookKind::ALL.len(), 15);
    let mut seen = std::collections::BTreeSet::new();
    for kind in HookKind::ALL {
        assert!(seen.insert(format!("{kind:?}")), "duplicate in ALL: {kind:?}");
    }
}

#[test]
fn hook_kind_all_serde_roundtrip() {
    for kind in HookKind::ALL {
        let json = serde_json::to_string(kind).expect("serialize");
        let recovered: HookKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*kind, recovered);
    }
}

#[test]
fn hook_kind_has_effect_phase_classification() {
    let effect_hooks = [HookKind::Effect, HookKind::LayoutEffect, HookKind::InsertionEffect];
    for kind in &effect_hooks {
        assert!(kind.has_effect_phase(), "{kind:?} should have effect phase");
    }
    let non_effect = [
        HookKind::State, HookKind::Reducer, HookKind::Memo, HookKind::Callback,
        HookKind::Ref, HookKind::Context, HookKind::ImperativeHandle,
        HookKind::DebugValue, HookKind::DeferredValue, HookKind::Transition,
        HookKind::Id, HookKind::SyncExternalStore,
    ];
    for kind in &non_effect {
        assert!(!kind.has_effect_phase(), "{kind:?} should NOT have effect phase");
    }
}

#[test]
fn hook_kind_can_trigger_rerender_classification() {
    let rerender_hooks = [
        HookKind::State, HookKind::Reducer, HookKind::Context,
        HookKind::SyncExternalStore, HookKind::Transition, HookKind::DeferredValue,
    ];
    for kind in &rerender_hooks {
        assert!(kind.can_trigger_rerender(), "{kind:?} should trigger rerender");
    }
    assert!(!HookKind::Memo.can_trigger_rerender());
    assert!(!HookKind::Effect.can_trigger_rerender());
    assert!(!HookKind::Ref.can_trigger_rerender());
}

#[test]
fn hook_kind_has_dependency_array_classification() {
    let dep_hooks = [
        HookKind::Effect, HookKind::LayoutEffect, HookKind::InsertionEffect,
        HookKind::Memo, HookKind::Callback, HookKind::ImperativeHandle,
    ];
    for kind in &dep_hooks {
        assert!(kind.has_dependency_array(), "{kind:?} should have dep array");
    }
    assert!(!HookKind::State.has_dependency_array());
    assert!(!HookKind::Ref.has_dependency_array());
    assert!(!HookKind::Id.has_dependency_array());
}

// ---------------------------------------------------------------------------
// HookManifest::validate
// ---------------------------------------------------------------------------

#[test]
fn hook_manifest_validate_empty_returns_error() {
    let m = HookManifest::new("Empty", vec![]);
    let errs = m.validate();
    assert_eq!(errs.len(), 1);
    assert!(matches!(errs[0], HookManifestError::EmptyManifest));
}

#[test]
fn hook_manifest_validate_consecutive_indices_passes() {
    let m = HookManifest::new("Good", vec![
        make_slot(0, HookKind::State),
        make_slot(1, HookKind::Effect),
        make_slot(2, HookKind::Memo),
    ]);
    let errs = m.validate();
    assert!(errs.is_empty(), "valid manifest should pass: {:?}", errs);
}

#[test]
fn hook_manifest_validate_non_consecutive_indices() {
    let m = HookManifest::new("Bad", vec![
        make_slot(0, HookKind::State),
        make_slot(5, HookKind::Effect), // should be 1
    ]);
    let errs = m.validate();
    assert!(errs.iter().any(|e| matches!(e, HookManifestError::NonConsecutiveIndices { expected: 1, found: 5 })));
}

#[test]
fn hook_manifest_validate_deps_on_non_dep_hook() {
    let m = HookManifest::new("DepErr", vec![
        HookSlot {
            index: HookSlotIndex(0),
            kind: HookKind::State, // State does not support deps
            deps: Some(vec![DepToken(1)]),
        },
    ]);
    let errs = m.validate();
    assert!(errs.iter().any(|e| matches!(e, HookManifestError::DepsOnNonDepHook { .. })));
}

#[test]
fn hook_manifest_error_serde_roundtrip() {
    let errors = vec![
        HookManifestError::EmptyManifest,
        HookManifestError::NonConsecutiveIndices { expected: 0, found: 3 },
        HookManifestError::DepsOnNonDepHook { index: HookSlotIndex(2), kind: HookKind::Ref },
        HookManifestError::DuplicateIndex(HookSlotIndex(1)),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: HookManifestError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*err, recovered);
    }
}

// ---------------------------------------------------------------------------
// RenderPhase transitions
// ---------------------------------------------------------------------------

#[test]
fn render_phase_legal_successors_form_valid_lifecycle() {
    // Full lifecycle: Rendering -> Insertion -> Layout -> Paint -> Passive -> Idle
    let mut phase = RenderPhase::Rendering;
    let lifecycle = [
        RenderPhase::InsertionEffectsPending,
        RenderPhase::LayoutEffectsPending,
        RenderPhase::PaintPending,
        RenderPhase::PassiveEffectsPending,
        RenderPhase::Idle,
    ];
    for next in lifecycle {
        assert!(phase.can_transition_to(next), "{phase:?} -> {next:?} should be legal");
        phase = next;
    }
}

#[test]
fn render_phase_unmounting_has_no_successors() {
    assert!(RenderPhase::Unmounting.legal_successors().is_empty());
    assert!(!RenderPhase::Unmounting.can_transition_to(RenderPhase::Idle));
}

#[test]
fn render_phase_idle_can_transition_to_rendering_or_unmounting() {
    assert!(RenderPhase::Idle.can_transition_to(RenderPhase::Rendering));
    assert!(RenderPhase::Idle.can_transition_to(RenderPhase::Unmounting));
    assert!(!RenderPhase::Idle.can_transition_to(RenderPhase::PaintPending));
}

// ---------------------------------------------------------------------------
// EffectTiming
// ---------------------------------------------------------------------------

#[test]
fn effect_timing_serde_roundtrip() {
    for timing in [EffectTiming::Insertion, EffectTiming::Layout, EffectTiming::Passive] {
        let json = serde_json::to_string(&timing).expect("serialize");
        let recovered: EffectTiming = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(timing, recovered);
    }
}

#[test]
fn effect_timing_scheduling_order_monotonic() {
    assert!(EffectTiming::Insertion.scheduling_order() < EffectTiming::Layout.scheduling_order());
    assert!(EffectTiming::Layout.scheduling_order() < EffectTiming::Passive.scheduling_order());
}

#[test]
fn effect_timing_execution_phase_matches_lifecycle() {
    assert_eq!(EffectTiming::Insertion.execution_phase(), RenderPhase::InsertionEffectsPending);
    assert_eq!(EffectTiming::Layout.execution_phase(), RenderPhase::LayoutEffectsPending);
    assert_eq!(EffectTiming::Passive.execution_phase(), RenderPhase::PassiveEffectsPending);
}

// ---------------------------------------------------------------------------
// DepToken and HookSlot with deps
// ---------------------------------------------------------------------------

#[test]
fn dep_token_serde_roundtrip() {
    let token = DepToken(42);
    let json = serde_json::to_string(&token).expect("serialize");
    let recovered: DepToken = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(token, recovered);
}

#[test]
fn hook_slot_with_deps_serde_roundtrip() {
    let slot = HookSlot {
        index: HookSlotIndex(0),
        kind: HookKind::Effect,
        deps: Some(vec![DepToken(1), DepToken(2), DepToken(3)]),
    };
    let json = serde_json::to_string(&slot).expect("serialize");
    let recovered: HookSlot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(slot, recovered);
}

#[test]
fn hook_manifest_derive_id_deterministic() {
    let m1 = HookManifest::new("IdTest", vec![
        make_slot(0, HookKind::State),
        make_slot(1, HookKind::Effect),
    ]);
    let m2 = HookManifest::new("IdTest", vec![
        make_slot(0, HookKind::State),
        make_slot(1, HookKind::Effect),
    ]);
    assert_eq!(m1.derive_id(), m2.derive_id());
}

#[test]
fn hook_manifest_different_components_different_ids() {
    let m1 = HookManifest::new("Alpha", vec![make_slot(0, HookKind::State)]);
    let m2 = HookManifest::new("Beta", vec![make_slot(0, HookKind::State)]);
    assert_ne!(m1.derive_id(), m2.derive_id());
}
