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
    ComponentPhaseTracker, DepToken, DepsChange, EffectScheduler, EffectTiming,
    FallbackExecutionRoute, HookEffectContract, HookKind, HookManifest, HookManifestError,
    HookRuleViolation, HookSlot, HookSlotIndex, LegalTransformation, PendingEffect,
    PhaseTransition, PhaseTransitionError, RenderPhase, SchedulingBoundary, TransformationReceipt,
    UnsupportedSemanticsTrigger, build_unsupported_semantics_diagnostic,
    classify_unsupported_semantics, compare_deps, fallback_route_for_trigger,
    validate_hook_consistency,
};
use serde::{Deserialize, Serialize};

const SCHEMA_VERSION: &str = "franken-engine.hook-effect-contract.scenario-log.v1";
const POLICY_ID: &str = "policy-frx-hook-effect-contract-v1";
const COMPONENT: &str = "hook_effect_contract";
const REPLAY_COMMAND: &str = "./scripts/e2e/frx_hook_effect_semantics_contract_replay.sh ci";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ScenarioLogEvent {
    schema_version: String,
    scenario_id: String,
    trace_id: String,
    decision_id: String,
    policy_id: String,
    component: String,
    event: String,
    seed: u64,
    timing: String,
    decision_path: String,
    outcome: String,
    error_code: Option<String>,
    replay_command: String,
}

fn make_slot(index: u32, kind: HookKind, deps: Option<Vec<DepToken>>) -> HookSlot {
    HookSlot {
        index: HookSlotIndex(index),
        kind,
        deps,
    }
}

struct LogEventInput<'a> {
    scenario_id: &'a str,
    trace_id: &'a str,
    decision_id: &'a str,
    seed: u64,
    event: &'a str,
    timing: &'a str,
    decision_path: &'a str,
    outcome: &'a str,
    error_code: Option<&'a str>,
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
        seed: input.seed,
        timing: input.timing.to_string(),
        decision_path: input.decision_path.to_string(),
        outcome: input.outcome.to_string(),
        error_code: input.error_code.map(str::to_string),
        replay_command: REPLAY_COMMAND.to_string(),
    }
}

fn run_happy_path(seed: u64, trace_id: &str) -> Vec<ScenarioLogEvent> {
    let scenario_id = "hook_effect_happy_path";
    let decision_id = format!("decision-{scenario_id}-{seed}");
    let mut events = Vec::new();

    let manifest = HookManifest::new(
        "App",
        vec![
            make_slot(0, HookKind::State, None),
            make_slot(1, HookKind::InsertionEffect, Some(vec![])),
            make_slot(2, HookKind::LayoutEffect, Some(vec![DepToken(1)])),
            make_slot(3, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    );
    assert!(manifest.validate().is_empty());

    let mut contract = HookEffectContract::new();
    contract.register_manifest(manifest);
    assert_eq!(contract.effect_hook_count(), 3);

    let mut scheduler = EffectScheduler::new();
    scheduler.enqueue(frankenengine_engine::hook_effect_contract::PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(1),
        timing: EffectTiming::Insertion,
        tree_order: 1,
        is_cleanup: false,
    });
    scheduler.enqueue(frankenengine_engine::hook_effect_contract::PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(2),
        timing: EffectTiming::Layout,
        tree_order: 1,
        is_cleanup: false,
    });
    scheduler.enqueue(frankenengine_engine::hook_effect_contract::PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(3),
        timing: EffectTiming::Passive,
        tree_order: 1,
        is_cleanup: false,
    });

    let mut tracker = ComponentPhaseTracker::new("App");
    tracker.transition_to(RenderPhase::Rendering).unwrap();
    tracker
        .transition_to(RenderPhase::InsertionEffectsPending)
        .unwrap();
    let (insertion_cleanups, insertion_creates) =
        scheduler.drain_for_timing(EffectTiming::Insertion);
    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "drain_insertion",
        timing: "insertion",
        decision_path: "render->insertion",
        outcome: "pass",
        error_code: None,
    }));
    assert_eq!(insertion_cleanups.len() + insertion_creates.len(), 1);

    tracker
        .transition_to(RenderPhase::LayoutEffectsPending)
        .unwrap();
    let (layout_cleanups, layout_creates) = scheduler.drain_for_timing(EffectTiming::Layout);
    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "drain_layout",
        timing: "layout",
        decision_path: "insertion->layout",
        outcome: "pass",
        error_code: None,
    }));
    assert_eq!(layout_cleanups.len() + layout_creates.len(), 1);

    tracker.transition_to(RenderPhase::PaintPending).unwrap();
    tracker
        .transition_to(RenderPhase::PassiveEffectsPending)
        .unwrap();
    let (passive_cleanups, passive_creates) = scheduler.drain_for_timing(EffectTiming::Passive);
    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "drain_passive",
        timing: "passive",
        decision_path: "paint->passive",
        outcome: "pass",
        error_code: None,
    }));
    assert_eq!(passive_cleanups.len() + passive_creates.len(), 1);

    tracker.transition_to(RenderPhase::Idle).unwrap();
    assert_eq!(tracker.render_count, 1);
    assert_eq!(scheduler.pending_count(), 0);

    events.push(log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id: &decision_id,
        seed,
        event: "cycle_complete",
        timing: "none",
        decision_path: "passive->idle",
        outcome: "pass",
        error_code: None,
    }));

    events
}

#[test]
fn hook_effect_contract_happy_path_emits_structured_logs() {
    let events = run_happy_path(41, "trace-hook-effect-happy-path");
    assert_eq!(events.len(), 4);
    assert!(
        events
            .iter()
            .all(|event| event.schema_version == SCHEMA_VERSION)
    );
    assert!(
        events
            .iter()
            .all(|event| event.replay_command == REPLAY_COMMAND)
    );
    assert!(events.iter().all(|event| !event.trace_id.is_empty()));
    assert!(events.iter().all(|event| !event.scenario_id.is_empty()));
    assert!(events.iter().all(|event| !event.decision_path.is_empty()));
    assert!(events.iter().all(|event| event.outcome == "pass"));
    assert!(events.iter().all(|event| event.error_code.is_none()));

    let jsonl = events
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join("\n");

    for line in jsonl.lines() {
        let value: serde_json::Value = serde_json::from_str(line).unwrap();
        for key in [
            "schema_version",
            "scenario_id",
            "trace_id",
            "decision_id",
            "policy_id",
            "component",
            "event",
            "seed",
            "timing",
            "decision_path",
            "outcome",
            "replay_command",
        ] {
            assert!(value.get(key).is_some(), "missing structured field: {key}");
        }
    }
}

#[test]
fn hook_effect_contract_adversarial_count_drift_fails_closed_with_log() {
    let scenario_id = "hook_effect_adversarial_count_drift";
    let trace_id = "trace-hook-effect-count-drift";
    let decision_id = "decision-hook-effect-count-drift";
    let seed = 7_u64;

    let prev = HookManifest::new("App", vec![make_slot(0, HookKind::State, None)]);
    let curr = HookManifest::new(
        "App",
        vec![
            make_slot(0, HookKind::State, None),
            make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    );

    let violations = validate_hook_consistency(&prev, &curr);
    assert!(
        violations
            .iter()
            .any(|violation| matches!(violation, HookRuleViolation::HookCountMismatch { .. }))
    );

    let failure_event = log_event(LogEventInput {
        scenario_id,
        trace_id,
        decision_id,
        seed,
        event: "consistency_validation",
        timing: "rendering",
        decision_path: "validate_hook_consistency",
        outcome: "fail",
        error_code: Some("FE-HOOK-EFFECT-CONTRACT-COUNT-MISMATCH"),
    });

    assert_eq!(failure_event.outcome, "fail");
    assert_eq!(
        failure_event.error_code.as_deref(),
        Some("FE-HOOK-EFFECT-CONTRACT-COUNT-MISMATCH")
    );
}

#[test]
fn hook_effect_contract_same_seed_is_deterministic() {
    let first = run_happy_path(99, "trace-hook-effect-determinism");
    let second = run_happy_path(99, "trace-hook-effect-determinism");
    assert_eq!(first, second);
}

// ────────────────────────────────────────────────────────────
// Enrichment: serde, classification, validation, edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn hook_kind_all_serde_round_trips() {
    for kind in HookKind::ALL {
        let json = serde_json::to_string(&kind).expect("serialize");
        let recovered: HookKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(kind, &recovered);
    }
}

#[test]
fn hook_kind_has_effect_phase_classification() {
    let effect_kinds: Vec<HookKind> = HookKind::ALL
        .iter()
        .copied()
        .filter(|k| k.has_effect_phase())
        .collect();
    assert_eq!(effect_kinds.len(), 3);
    assert!(effect_kinds.contains(&HookKind::Effect));
    assert!(effect_kinds.contains(&HookKind::LayoutEffect));
    assert!(effect_kinds.contains(&HookKind::InsertionEffect));
}

#[test]
fn hook_kind_can_trigger_rerender_classification() {
    assert!(HookKind::State.can_trigger_rerender());
    assert!(HookKind::Reducer.can_trigger_rerender());
    assert!(HookKind::Context.can_trigger_rerender());
    assert!(!HookKind::Ref.can_trigger_rerender());
    assert!(!HookKind::Memo.can_trigger_rerender());
    assert!(!HookKind::DebugValue.can_trigger_rerender());
}

#[test]
fn hook_kind_has_dependency_array_classification() {
    assert!(HookKind::Effect.has_dependency_array());
    assert!(HookKind::LayoutEffect.has_dependency_array());
    assert!(HookKind::Memo.has_dependency_array());
    assert!(HookKind::Callback.has_dependency_array());
    assert!(!HookKind::State.has_dependency_array());
    assert!(!HookKind::Ref.has_dependency_array());
    assert!(!HookKind::Id.has_dependency_array());
}

#[test]
fn effect_timing_serde_round_trip() {
    for timing in [
        EffectTiming::Insertion,
        EffectTiming::Layout,
        EffectTiming::Passive,
    ] {
        let json = serde_json::to_string(&timing).expect("serialize");
        let recovered: EffectTiming = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(timing, recovered);
    }
}

#[test]
fn render_phase_legal_successors_cover_full_lifecycle() {
    let successors = RenderPhase::Rendering.legal_successors();
    assert!(successors.contains(&RenderPhase::InsertionEffectsPending));

    let idle_successors = RenderPhase::Idle.legal_successors();
    assert!(idle_successors.contains(&RenderPhase::Rendering));
}

#[test]
fn hook_manifest_validate_empty_returns_error() {
    let manifest = HookManifest::new("Empty", vec![]);
    let errors = manifest.validate();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, HookManifestError::EmptyManifest))
    );
}

#[test]
fn hook_manifest_validate_non_consecutive_indices_returns_error() {
    let manifest = HookManifest::new(
        "BadIndices",
        vec![
            make_slot(0, HookKind::State, None),
            make_slot(5, HookKind::Effect, Some(vec![])),
        ],
    );
    let errors = manifest.validate();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, HookManifestError::NonConsecutiveIndices { .. }))
    );
}

#[test]
fn hook_slot_index_ordering_is_numeric() {
    let a = HookSlotIndex(0);
    let b = HookSlotIndex(1);
    let c = HookSlotIndex(100);
    assert!(a < b);
    assert!(b < c);
}

#[test]
fn hook_rule_violation_count_mismatch_serde_round_trip() {
    let violation = HookRuleViolation::HookCountMismatch {
        component: "TestComp".to_string(),
        previous_count: 2,
        current_count: 3,
    };
    let json = serde_json::to_string(&violation).expect("serialize");
    let recovered: HookRuleViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(violation, recovered);
}

// ────────────────────────────────────────────────────────────
// compare_deps
// ────────────────────────────────────────────────────────────

#[test]
fn compare_deps_none_none_is_always_run() {
    assert_eq!(compare_deps(None, None), DepsChange::AlwaysRun);
}

#[test]
fn compare_deps_empty_is_mount_only() {
    assert_eq!(compare_deps(Some(&[]), Some(&[])), DepsChange::MountOnly);
}

#[test]
fn compare_deps_same_tokens_is_unchanged() {
    let deps = [DepToken(1), DepToken(2)];
    assert_eq!(
        compare_deps(Some(&deps), Some(&deps)),
        DepsChange::Unchanged
    );
}

#[test]
fn compare_deps_different_tokens_is_changed() {
    let prev = [DepToken(1)];
    let curr = [DepToken(2)];
    assert_eq!(compare_deps(Some(&prev), Some(&curr)), DepsChange::Changed);
}

#[test]
fn compare_deps_none_to_some_is_changed() {
    let curr = [DepToken(1)];
    assert_eq!(compare_deps(None, Some(&curr)), DepsChange::Changed);
}

// ────────────────────────────────────────────────────────────
// EffectScheduler
// ────────────────────────────────────────────────────────────

#[test]
fn effect_scheduler_empty_drain_returns_empty() {
    let mut scheduler = EffectScheduler::new();
    let (cleanups, creates) = scheduler.drain_for_timing(EffectTiming::Passive);
    assert!(cleanups.is_empty());
    assert!(creates.is_empty());
}

#[test]
fn effect_scheduler_drain_all_ordered_respects_tree_order() {
    let mut scheduler = EffectScheduler::new();
    scheduler.enqueue(PendingEffect {
        component_name: "B".to_string(),
        hook_index: HookSlotIndex(0),
        timing: EffectTiming::Passive,
        tree_order: 2,
        is_cleanup: false,
    });
    scheduler.enqueue(PendingEffect {
        component_name: "A".to_string(),
        hook_index: HookSlotIndex(0),
        timing: EffectTiming::Insertion,
        tree_order: 1,
        is_cleanup: false,
    });
    let ordered = scheduler.drain_all_ordered();
    assert_eq!(ordered.len(), 2);
    assert!(ordered[0].tree_order <= ordered[1].tree_order);
    assert_eq!(scheduler.pending_count(), 0);
}

#[test]
fn effect_scheduler_cleanups_before_creates() {
    let mut scheduler = EffectScheduler::new();
    scheduler.enqueue(PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(0),
        timing: EffectTiming::Layout,
        tree_order: 1,
        is_cleanup: false,
    });
    scheduler.enqueue(PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(0),
        timing: EffectTiming::Layout,
        tree_order: 1,
        is_cleanup: true,
    });
    let (cleanups, creates) = scheduler.drain_for_timing(EffectTiming::Layout);
    assert_eq!(cleanups.len(), 1);
    assert!(cleanups[0].is_cleanup);
    assert_eq!(creates.len(), 1);
    assert!(!creates[0].is_cleanup);
}

// ────────────────────────────────────────────────────────────
// ComponentPhaseTracker
// ────────────────────────────────────────────────────────────

#[test]
fn phase_tracker_run_full_cycle() {
    let mut tracker = ComponentPhaseTracker::new("App");
    tracker.run_full_cycle().expect("full cycle should succeed");
    assert_eq!(tracker.render_count, 1);
    assert_eq!(tracker.current_phase, RenderPhase::Idle);
    assert!(!tracker.transition_log.is_empty());
}

#[test]
fn phase_tracker_multiple_cycles_increment_render_count() {
    let mut tracker = ComponentPhaseTracker::new("App");
    tracker.run_full_cycle().unwrap();
    tracker.run_full_cycle().unwrap();
    assert_eq!(tracker.render_count, 2);
}

#[test]
fn phase_tracker_illegal_transition_returns_error() {
    let mut tracker = ComponentPhaseTracker::new("App");
    let err = tracker
        .transition_to(RenderPhase::Idle)
        .expect_err("should reject idle from initial");
    assert!(matches!(
        err,
        PhaseTransitionError::IllegalTransition { .. }
    ));
}

#[test]
fn phase_tracker_unmounting_transition() {
    let mut tracker = ComponentPhaseTracker::new("App");
    tracker.transition_to(RenderPhase::Rendering).unwrap();
    let can_unmount = RenderPhase::Rendering.can_transition_to(RenderPhase::Unmounting);
    if can_unmount {
        tracker.transition_to(RenderPhase::Unmounting).unwrap();
        assert_eq!(tracker.current_phase, RenderPhase::Unmounting);
    }
}

// ────────────────────────────────────────────────────────────
// RenderPhase
// ────────────────────────────────────────────────────────────

#[test]
fn render_phase_serde_round_trip_all_variants() {
    for phase in [
        RenderPhase::Rendering,
        RenderPhase::InsertionEffectsPending,
        RenderPhase::LayoutEffectsPending,
        RenderPhase::PaintPending,
        RenderPhase::PassiveEffectsPending,
        RenderPhase::Idle,
        RenderPhase::Unmounting,
    ] {
        let json = serde_json::to_string(&phase).expect("serialize");
        let recovered: RenderPhase = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(phase, recovered);
    }
}

#[test]
fn render_phase_can_transition_to_consistent_with_successors() {
    for phase in [
        RenderPhase::Rendering,
        RenderPhase::InsertionEffectsPending,
        RenderPhase::LayoutEffectsPending,
        RenderPhase::PaintPending,
        RenderPhase::PassiveEffectsPending,
        RenderPhase::Idle,
    ] {
        for successor in phase.legal_successors() {
            assert!(
                phase.can_transition_to(*successor),
                "{phase:?} should be able to transition to {successor:?}"
            );
        }
    }
}

// ────────────────────────────────────────────────────────────
// EffectTiming
// ────────────────────────────────────────────────────────────

#[test]
fn effect_timing_execution_phase_mapping() {
    assert_eq!(
        EffectTiming::Insertion.execution_phase(),
        RenderPhase::InsertionEffectsPending
    );
    assert_eq!(
        EffectTiming::Layout.execution_phase(),
        RenderPhase::LayoutEffectsPending
    );
    assert_eq!(
        EffectTiming::Passive.execution_phase(),
        RenderPhase::PassiveEffectsPending
    );
}

#[test]
fn effect_timing_scheduling_order_insertion_first() {
    assert!(EffectTiming::Insertion.scheduling_order() < EffectTiming::Layout.scheduling_order());
    assert!(EffectTiming::Layout.scheduling_order() < EffectTiming::Passive.scheduling_order());
}

// ────────────────────────────────────────────────────────────
// LegalTransformation
// ────────────────────────────────────────────────────────────

#[test]
fn legal_transformation_all_serde_round_trip() {
    for t in LegalTransformation::ALL {
        let json = serde_json::to_string(&t).expect("serialize");
        let recovered: LegalTransformation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(t, &recovered);
    }
}

#[test]
fn legal_transformation_applicable_hooks_non_empty() {
    for t in LegalTransformation::ALL {
        assert!(
            !t.applicable_hooks().is_empty(),
            "{t:?} should have at least one applicable hook"
        );
    }
}

#[test]
fn legal_transformation_effect_order_preservation() {
    assert!(LegalTransformation::MemoConstantFold.preserves_effect_order());
    assert!(LegalTransformation::CallbackInline.preserves_effect_order());
    assert!(LegalTransformation::EffectElision.preserves_effect_order());
}

#[test]
fn legal_transformation_unconditional_classification() {
    // Some transformations are unconditional (always safe)
    for t in LegalTransformation::ALL {
        let _ = t.is_unconditional(); // Just ensure it doesn't panic
    }
}

// ────────────────────────────────────────────────────────────
// HookManifest validation edge cases
// ────────────────────────────────────────────────────────────

#[test]
fn hook_manifest_validate_deps_on_non_dep_hook_returns_error() {
    let manifest = HookManifest::new(
        "BadDeps",
        vec![make_slot(0, HookKind::Ref, Some(vec![DepToken(1)]))],
    );
    let errors = manifest.validate();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, HookManifestError::DepsOnNonDepHook { .. })),
        "should detect deps on non-dep hook, got: {errors:?}"
    );
}

#[test]
fn hook_manifest_derive_id_is_deterministic() {
    let manifest = HookManifest::new("StableComp", vec![make_slot(0, HookKind::State, None)]);
    let id1 = manifest.derive_id();
    let id2 = manifest.derive_id();
    assert_eq!(id1, id2);
}

#[test]
fn hook_manifest_different_components_have_different_ids() {
    let m1 = HookManifest::new("A", vec![make_slot(0, HookKind::State, None)]);
    let m2 = HookManifest::new("B", vec![make_slot(0, HookKind::State, None)]);
    assert_ne!(m1.derive_id(), m2.derive_id());
}

// ────────────────────────────────────────────────────────────
// validate_hook_consistency — more violation types
// ────────────────────────────────────────────────────────────

#[test]
fn validate_hook_consistency_kind_mismatch() {
    let prev = HookManifest::new("App", vec![make_slot(0, HookKind::State, None)]);
    let curr = HookManifest::new("App", vec![make_slot(0, HookKind::Reducer, None)]);
    let violations = validate_hook_consistency(&prev, &curr);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, HookRuleViolation::HookKindMismatch { .. }))
    );
}

#[test]
fn validate_hook_consistency_no_violations_on_identical() {
    let manifest = HookManifest::new(
        "App",
        vec![
            make_slot(0, HookKind::State, None),
            make_slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    );
    let violations = validate_hook_consistency(&manifest, &manifest);
    assert!(violations.is_empty());
}

#[test]
fn validate_hook_consistency_deps_length_mismatch() {
    let prev = HookManifest::new(
        "App",
        vec![make_slot(0, HookKind::Effect, Some(vec![DepToken(1)]))],
    );
    let curr = HookManifest::new(
        "App",
        vec![make_slot(
            0,
            HookKind::Effect,
            Some(vec![DepToken(1), DepToken(2)]),
        )],
    );
    let violations = validate_hook_consistency(&prev, &curr);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, HookRuleViolation::DepsLengthMismatch { .. }))
    );
}

// ────────────────────────────────────────────────────────────
// HookEffectContract
// ────────────────────────────────────────────────────────────

#[test]
fn hook_effect_contract_register_multiple_manifests() {
    let mut contract = HookEffectContract::new();
    contract.register_manifest(HookManifest::new(
        "A",
        vec![make_slot(0, HookKind::State, None)],
    ));
    contract.register_manifest(HookManifest::new(
        "B",
        vec![
            make_slot(0, HookKind::Effect, Some(vec![])),
            make_slot(1, HookKind::LayoutEffect, Some(vec![])),
        ],
    ));
    assert_eq!(contract.total_hook_count(), 3);
    assert_eq!(contract.effect_hook_count(), 2);
}

#[test]
fn hook_effect_contract_approve_transformation() {
    let mut contract = HookEffectContract::new();
    contract.register_manifest(HookManifest::new(
        "A",
        vec![make_slot(0, HookKind::Memo, Some(vec![DepToken(1)]))],
    ));
    contract.approve_transformation(LegalTransformation::MemoConstantFold);
    let validation = contract.validate_all();
    assert!(
        validation.values().all(|errors| errors.is_empty()),
        "approved transformation should not cause validation errors"
    );
}

#[test]
fn hook_effect_contract_derive_id_is_stable() {
    let mut contract = HookEffectContract::new();
    contract.register_manifest(HookManifest::new(
        "X",
        vec![make_slot(0, HookKind::State, None)],
    ));
    let id1 = contract.derive_id();
    let id2 = contract.derive_id();
    assert_eq!(id1, id2);
}

#[test]
fn hook_effect_contract_serde_round_trip() {
    let mut contract = HookEffectContract::new();
    contract.register_manifest(HookManifest::new(
        "App",
        vec![make_slot(0, HookKind::State, None)],
    ));
    contract.approve_transformation(LegalTransformation::StateBatch);
    let json = serde_json::to_string(&contract).expect("serialize");
    let recovered: HookEffectContract = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(contract.total_hook_count(), recovered.total_hook_count());
}

// ────────────────────────────────────────────────────────────
// SchedulingBoundary
// ────────────────────────────────────────────────────────────

#[test]
fn scheduling_boundary_canonical_boundaries_non_empty() {
    let boundaries = SchedulingBoundary::canonical_boundaries();
    assert_eq!(boundaries.len(), 3, "insertion, layout, passive");
}

#[test]
fn scheduling_boundary_insertion_is_synchronous() {
    let boundaries = SchedulingBoundary::canonical_boundaries();
    let insertion = boundaries
        .iter()
        .find(|b| b.timing == EffectTiming::Insertion)
        .expect("insertion boundary");
    assert!(insertion.synchronous);
}

#[test]
fn scheduling_boundary_serde_round_trip() {
    for boundary in SchedulingBoundary::canonical_boundaries() {
        let json = serde_json::to_string(&boundary).expect("serialize");
        let recovered: SchedulingBoundary = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(boundary, recovered);
    }
}

// ────────────────────────────────────────────────────────────
// UnsupportedSemanticsTrigger + Fallback
// ────────────────────────────────────────────────────────────

#[test]
fn unsupported_semantics_trigger_serde_round_trip() {
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
        assert!(!trigger.stable_error_code().is_empty());
        assert!(!trigger.rejection_reason().is_empty());
        assert!(!trigger.hardening_guidance().is_empty());
    }
}

#[test]
fn fallback_route_for_each_trigger_is_valid() {
    for trigger in [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ] {
        let route = fallback_route_for_trigger(trigger);
        assert!(matches!(
            route,
            FallbackExecutionRoute::CompatibilityRuntimeLane
                | FallbackExecutionRoute::BaselineInterpreterLane
                | FallbackExecutionRoute::DeterministicSafeModeLane
        ));
    }
}

#[test]
fn fallback_execution_route_serde_round_trip() {
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
fn classify_unsupported_semantics_count_mismatch_is_topology_drift() {
    let violation = HookRuleViolation::HookCountMismatch {
        component: "App".to_string(),
        previous_count: 2,
        current_count: 3,
    };
    let trigger = classify_unsupported_semantics(&violation);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);
}

#[test]
fn classify_unsupported_semantics_kind_mismatch() {
    let violation = HookRuleViolation::HookKindMismatch {
        component: "App".to_string(),
        slot: HookSlotIndex(0),
        previous_kind: HookKind::State,
        current_kind: HookKind::Reducer,
    };
    let trigger = classify_unsupported_semantics(&violation);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);
}

#[test]
fn classify_unsupported_semantics_deps_length_mismatch() {
    let violation = HookRuleViolation::DepsLengthMismatch {
        component: "App".to_string(),
        slot: HookSlotIndex(0),
        previous_len: 1,
        current_len: 2,
    };
    let trigger = classify_unsupported_semantics(&violation);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::DependencyShapeDrift);
}

#[test]
fn build_unsupported_semantics_diagnostic_has_required_fields() {
    let diag = build_unsupported_semantics_diagnostic(
        "TestComp",
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        "trace-1",
        "decision-1",
    );
    assert_eq!(diag.component_name, "TestComp");
    assert_eq!(diag.trace_id, "trace-1");
    assert_eq!(diag.decision_id, "decision-1");
    assert!(!diag.error_code.is_empty());
    assert!(!diag.reason.is_empty());
    assert!(!diag.hardening_guidance.is_empty());
    assert!(!diag.schema_version.is_empty());
}

#[test]
fn build_unsupported_semantics_diagnostic_derive_id_is_deterministic() {
    let diag = build_unsupported_semantics_diagnostic(
        "App",
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        "t",
        "d",
    );
    let id1 = diag.derive_id();
    let id2 = diag.derive_id();
    assert_eq!(id1, id2);
}

// ────────────────────────────────────────────────────────────
// PendingEffect
// ────────────────────────────────────────────────────────────

#[test]
fn pending_effect_derive_id_is_deterministic() {
    let effect = PendingEffect {
        component_name: "App".to_string(),
        hook_index: HookSlotIndex(0),
        timing: EffectTiming::Passive,
        tree_order: 1,
        is_cleanup: false,
    };
    assert_eq!(effect.derive_id(), effect.derive_id());
}

#[test]
fn pending_effect_serde_round_trip() {
    let effect = PendingEffect {
        component_name: "Widget".to_string(),
        hook_index: HookSlotIndex(3),
        timing: EffectTiming::Layout,
        tree_order: 42,
        is_cleanup: true,
    };
    let json = serde_json::to_string(&effect).expect("serialize");
    let recovered: PendingEffect = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(effect, recovered);
}

// ────────────────────────────────────────────────────────────
// TransformationReceipt
// ────────────────────────────────────────────────────────────

#[test]
fn transformation_receipt_serde_round_trip() {
    let receipt = TransformationReceipt {
        transformation: LegalTransformation::MemoConstantFold,
        component_name: "App".to_string(),
        target_slots: vec![HookSlotIndex(0), HookSlotIndex(1)],
        precondition_met: true,
        reason: "constant folded memo".to_string(),
    };
    let json = serde_json::to_string(&receipt).expect("serialize");
    let recovered: TransformationReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, recovered);
}

#[test]
fn transformation_receipt_derive_id_is_deterministic() {
    let receipt = TransformationReceipt {
        transformation: LegalTransformation::CallbackInline,
        component_name: "App".to_string(),
        target_slots: vec![HookSlotIndex(2)],
        precondition_met: true,
        reason: "inlined".to_string(),
    };
    assert_eq!(receipt.derive_id(), receipt.derive_id());
}

// ────────────────────────────────────────────────────────────
// PhaseTransition
// ────────────────────────────────────────────────────────────

#[test]
fn phase_transition_validate_legal() {
    let transition = PhaseTransition {
        component_name: "App".to_string(),
        from: RenderPhase::Rendering,
        to: RenderPhase::InsertionEffectsPending,
        sequence_number: 0,
    };
    assert!(transition.validate().is_ok());
}

#[test]
fn phase_transition_validate_illegal() {
    let transition = PhaseTransition {
        component_name: "App".to_string(),
        from: RenderPhase::Idle,
        to: RenderPhase::PassiveEffectsPending,
        sequence_number: 0,
    };
    let err = transition.validate().expect_err("illegal transition");
    assert!(matches!(
        err,
        PhaseTransitionError::IllegalTransition { .. }
    ));
}

#[test]
fn phase_transition_serde_round_trip() {
    let transition = PhaseTransition {
        component_name: "App".to_string(),
        from: RenderPhase::PaintPending,
        to: RenderPhase::PassiveEffectsPending,
        sequence_number: 5,
    };
    let json = serde_json::to_string(&transition).expect("serialize");
    let recovered: PhaseTransition = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(transition, recovered);
}

// ────────────────────────────────────────────────────────────
// DepsChange serde
// ────────────────────────────────────────────────────────────

#[test]
fn deps_change_serde_round_trip() {
    for change in [
        DepsChange::AlwaysRun,
        DepsChange::MountOnly,
        DepsChange::Unchanged,
        DepsChange::Changed,
    ] {
        let json = serde_json::to_string(&change).expect("serialize");
        let recovered: DepsChange = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(change, recovered);
    }
}

// ────────────────────────────────────────────────────────────
// HookRuleViolation — all variant serde
// ────────────────────────────────────────────────────────────

#[test]
fn hook_rule_violation_kind_mismatch_serde_round_trip() {
    let violation = HookRuleViolation::HookKindMismatch {
        component: "App".to_string(),
        slot: HookSlotIndex(0),
        previous_kind: HookKind::State,
        current_kind: HookKind::Reducer,
    };
    let json = serde_json::to_string(&violation).expect("serialize");
    let recovered: HookRuleViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(violation, recovered);
}

#[test]
fn hook_rule_violation_outside_render_serde_round_trip() {
    let violation = HookRuleViolation::HookOutsideRender {
        component: "App".to_string(),
        slot: HookSlotIndex(1),
        actual_phase: RenderPhase::Idle,
    };
    let json = serde_json::to_string(&violation).expect("serialize");
    let recovered: HookRuleViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(violation, recovered);
}

#[test]
fn hook_rule_violation_conditional_hook_serde_round_trip() {
    let violation = HookRuleViolation::ConditionalHookCall {
        component: "App".to_string(),
        slot: HookSlotIndex(2),
    };
    let json = serde_json::to_string(&violation).expect("serialize");
    let recovered: HookRuleViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(violation, recovered);
}

#[test]
fn hook_rule_violation_deps_length_serde_round_trip() {
    let violation = HookRuleViolation::DepsLengthMismatch {
        component: "App".to_string(),
        slot: HookSlotIndex(0),
        previous_len: 1,
        current_len: 3,
    };
    let json = serde_json::to_string(&violation).expect("serialize");
    let recovered: HookRuleViolation = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(violation, recovered);
}

// ────────────────────────────────────────────────────────────
// PhaseTransitionError serde
// ────────────────────────────────────────────────────────────

#[test]
fn phase_transition_error_serde_round_trip() {
    let err = PhaseTransitionError::IllegalTransition {
        component: "App".to_string(),
        from: RenderPhase::Idle,
        to: RenderPhase::PaintPending,
    };
    let json = serde_json::to_string(&err).expect("serialize");
    let recovered: PhaseTransitionError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(err, recovered);
}

// ────────────────────────────────────────────────────────────
// HookManifestError serde
// ────────────────────────────────────────────────────────────

#[test]
fn hook_manifest_error_serde_round_trip_all_variants() {
    let errors = vec![
        HookManifestError::EmptyManifest,
        HookManifestError::NonConsecutiveIndices {
            expected: 1,
            found: 3,
        },
        HookManifestError::DuplicateIndex(HookSlotIndex(0)),
        HookManifestError::DepsOnNonDepHook {
            index: HookSlotIndex(0),
            kind: HookKind::Ref,
        },
    ];
    for error in errors {
        let json = serde_json::to_string(&error).expect("serialize");
        let recovered: HookManifestError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(error, recovered);
    }
}
