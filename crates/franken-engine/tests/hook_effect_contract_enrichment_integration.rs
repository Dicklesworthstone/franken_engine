//! Enrichment integration tests for `hook_effect_contract` (FRX-02.2).
//!
//! Validates the full hook/effect semantics contract: manifest validation,
//! phase-constrained lifecycle, effect scheduling, dependency tracking,
//! legal transformations, unsupported semantics fallback, and cross-cutting
//! contract-level invariants.

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

use frankenengine_engine::hook_effect_contract::{
    ComponentPhaseTracker, DepToken, DepsChange, EffectScheduler, EffectTiming,
    FallbackExecutionRoute, HookEffectContract, HookKind, HookManifest, HookManifestError,
    HookRuleViolation, HookSlot, HookSlotIndex, LegalTransformation, PendingEffect,
    PhaseTransition, PhaseTransitionError, RenderPhase, SchedulingBoundary, TransformationReceipt,
    UnsupportedSemanticsDiagnostic, UnsupportedSemanticsTrigger,
    build_unsupported_semantics_diagnostic, classify_unsupported_semantics, compare_deps,
    fallback_route_for_trigger, validate_hook_consistency,
};

// ── Helpers ─────────────────────────────────────────────────────────

fn slot(index: u32, kind: HookKind, deps: Option<Vec<DepToken>>) -> HookSlot {
    HookSlot {
        index: HookSlotIndex(index),
        kind,
        deps,
    }
}

fn effect(
    component: &str,
    hook_idx: u32,
    timing: EffectTiming,
    tree_order: u64,
    is_cleanup: bool,
) -> PendingEffect {
    PendingEffect {
        component_name: component.into(),
        hook_index: HookSlotIndex(hook_idx),
        timing,
        tree_order,
        is_cleanup,
    }
}

// ── Section 1: HookKind properties ──────────────────────────────────

#[test]
fn hook_kind_all_contains_exactly_15_variants() {
    assert_eq!(HookKind::ALL.len(), 15);
    let unique: BTreeSet<_> = HookKind::ALL.iter().collect();
    assert_eq!(unique.len(), 15);
}

#[test]
fn hook_kind_effect_phase_exactly_three_hooks() {
    let effect_hooks: Vec<_> = HookKind::ALL
        .iter()
        .filter(|k| k.has_effect_phase())
        .collect();
    assert_eq!(effect_hooks.len(), 3);
    assert!(HookKind::Effect.has_effect_phase());
    assert!(HookKind::LayoutEffect.has_effect_phase());
    assert!(HookKind::InsertionEffect.has_effect_phase());
}

#[test]
fn hook_kind_rerender_triggers() {
    let triggers: Vec<_> = HookKind::ALL
        .iter()
        .filter(|k| k.can_trigger_rerender())
        .collect();
    assert_eq!(triggers.len(), 6);
    assert!(HookKind::State.can_trigger_rerender());
    assert!(HookKind::Reducer.can_trigger_rerender());
    assert!(HookKind::Context.can_trigger_rerender());
    assert!(HookKind::SyncExternalStore.can_trigger_rerender());
    assert!(HookKind::Transition.can_trigger_rerender());
    assert!(HookKind::DeferredValue.can_trigger_rerender());
    assert!(!HookKind::Effect.can_trigger_rerender());
    assert!(!HookKind::Memo.can_trigger_rerender());
    assert!(!HookKind::Ref.can_trigger_rerender());
}

#[test]
fn hook_kind_dependency_array_hooks() {
    let dep_hooks: Vec<_> = HookKind::ALL
        .iter()
        .filter(|k| k.has_dependency_array())
        .collect();
    assert_eq!(dep_hooks.len(), 6);
    assert!(HookKind::Effect.has_dependency_array());
    assert!(HookKind::LayoutEffect.has_dependency_array());
    assert!(HookKind::InsertionEffect.has_dependency_array());
    assert!(HookKind::Memo.has_dependency_array());
    assert!(HookKind::Callback.has_dependency_array());
    assert!(HookKind::ImperativeHandle.has_dependency_array());
    assert!(!HookKind::State.has_dependency_array());
    assert!(!HookKind::Reducer.has_dependency_array());
    assert!(!HookKind::Id.has_dependency_array());
}

#[test]
fn hook_kind_serde_all_variants_roundtrip() {
    for kind in HookKind::ALL {
        let json = serde_json::to_value(kind).unwrap();
        let back: HookKind = serde_json::from_value(json).unwrap();
        assert_eq!(*kind, back);
    }
}

// ── Section 2: HookManifest validation ──────────────────────────────

#[test]
fn manifest_valid_with_mixed_hooks() {
    let m = HookManifest::new(
        "Dashboard",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Reducer, None),
            slot(2, HookKind::Effect, Some(vec![DepToken(1), DepToken(2)])),
            slot(3, HookKind::Memo, Some(vec![DepToken(1)])),
            slot(4, HookKind::Ref, None),
            slot(5, HookKind::Context, None),
        ],
    );
    assert!(m.validate().is_empty());
}

#[test]
fn manifest_empty_is_error() {
    let m = HookManifest::new("EmptyComponent", vec![]);
    let errors = m.validate();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0], HookManifestError::EmptyManifest);
}

#[test]
fn manifest_non_consecutive_indices_detected() {
    let m = HookManifest::new(
        "BadComponent",
        vec![slot(0, HookKind::State, None), slot(3, HookKind::Ref, None)],
    );
    let errors = m.validate();
    assert!(errors.iter().any(|e| matches!(
        e,
        HookManifestError::NonConsecutiveIndices {
            expected: 1,
            found: 3,
        }
    )));
}

#[test]
fn manifest_duplicate_index_detected() {
    let m = HookManifest::new(
        "DupComponent",
        vec![
            slot(0, HookKind::State, None),
            slot(0, HookKind::Reducer, None),
        ],
    );
    let errors = m.validate();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, HookManifestError::DuplicateIndex(HookSlotIndex(0))))
    );
}

#[test]
fn manifest_deps_on_state_hook_is_error() {
    let m = HookManifest::new(
        "BadDeps",
        vec![slot(0, HookKind::State, Some(vec![DepToken(1)]))],
    );
    let errors = m.validate();
    assert!(errors.iter().any(|e| matches!(
        e,
        HookManifestError::DepsOnNonDepHook {
            kind: HookKind::State,
            ..
        }
    )));
}

#[test]
fn manifest_deps_on_ref_hook_is_error() {
    let m = HookManifest::new("BadRefDeps", vec![slot(0, HookKind::Ref, Some(vec![]))]);
    let errors = m.validate();
    assert!(
        errors
            .iter()
            .any(|e| matches!(e, HookManifestError::DepsOnNonDepHook { .. }))
    );
}

#[test]
fn manifest_multiple_errors_at_once() {
    let m = HookManifest::new(
        "MultiError",
        vec![
            slot(0, HookKind::State, Some(vec![DepToken(1)])),
            slot(5, HookKind::Ref, Some(vec![])),
        ],
    );
    let errors = m.validate();
    // Should have: DepsOnNonDepHook for slot 0, NonConsecutiveIndices for slot 1, DepsOnNonDepHook for slot 1
    assert!(errors.len() >= 2);
}

#[test]
fn manifest_derive_id_stable_and_distinct() {
    let m1 = HookManifest::new("A", vec![slot(0, HookKind::State, None)]);
    let m2 = HookManifest::new("B", vec![slot(0, HookKind::State, None)]);
    assert_eq!(m1.derive_id(), m1.derive_id());
    assert_ne!(m1.derive_id(), m2.derive_id());
}

#[test]
fn manifest_serde_roundtrip_complex() {
    let m = HookManifest::new(
        "Counter",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(42), DepToken(99)])),
            slot(2, HookKind::Memo, Some(vec![])),
            slot(3, HookKind::InsertionEffect, Some(vec![DepToken(7)])),
        ],
    );
    let json = serde_json::to_string(&m).unwrap();
    let back: HookManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn manifest_version_defaults_to_one() {
    let m = HookManifest::new("V", vec![slot(0, HookKind::Id, None)]);
    assert_eq!(m.version, 1);
}

// ── Section 3: RenderPhase transitions ──────────────────────────────

#[test]
fn render_phase_full_legal_cycle() {
    let cycle = [
        RenderPhase::Idle,
        RenderPhase::Rendering,
        RenderPhase::InsertionEffectsPending,
        RenderPhase::LayoutEffectsPending,
        RenderPhase::PaintPending,
        RenderPhase::PassiveEffectsPending,
        RenderPhase::Idle,
    ];
    for window in cycle.windows(2) {
        assert!(
            window[0].can_transition_to(window[1]),
            "{:?} -> {:?} should be legal",
            window[0],
            window[1]
        );
    }
}

#[test]
fn render_phase_illegal_skip_transitions() {
    assert!(!RenderPhase::Rendering.can_transition_to(RenderPhase::PaintPending));
    assert!(!RenderPhase::Idle.can_transition_to(RenderPhase::PassiveEffectsPending));
    assert!(!RenderPhase::InsertionEffectsPending.can_transition_to(RenderPhase::PaintPending));
}

#[test]
fn render_phase_no_backwards_transitions() {
    assert!(!RenderPhase::PaintPending.can_transition_to(RenderPhase::Rendering));
    assert!(
        !RenderPhase::PassiveEffectsPending.can_transition_to(RenderPhase::LayoutEffectsPending)
    );
}

#[test]
fn render_phase_unmounting_is_terminal() {
    assert!(RenderPhase::Unmounting.legal_successors().is_empty());
    assert!(!RenderPhase::Unmounting.can_transition_to(RenderPhase::Idle));
    assert!(!RenderPhase::Unmounting.can_transition_to(RenderPhase::Rendering));
}

#[test]
fn render_phase_idle_can_unmount() {
    assert!(RenderPhase::Idle.can_transition_to(RenderPhase::Unmounting));
}

#[test]
fn render_phase_serde_all_variants() {
    let variants = [
        RenderPhase::Rendering,
        RenderPhase::InsertionEffectsPending,
        RenderPhase::LayoutEffectsPending,
        RenderPhase::PaintPending,
        RenderPhase::PassiveEffectsPending,
        RenderPhase::Idle,
        RenderPhase::Unmounting,
    ];
    for phase in &variants {
        let json = serde_json::to_value(phase).unwrap();
        let back: RenderPhase = serde_json::from_value(json).unwrap();
        assert_eq!(*phase, back);
    }
}

// ── Section 4: EffectTiming ─────────────────────────────────────────

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
fn effect_timing_scheduling_order_monotonic() {
    assert!(EffectTiming::Insertion.scheduling_order() < EffectTiming::Layout.scheduling_order());
    assert!(EffectTiming::Layout.scheduling_order() < EffectTiming::Passive.scheduling_order());
}

#[test]
fn effect_timing_serde_roundtrip() {
    for timing in [
        EffectTiming::Insertion,
        EffectTiming::Layout,
        EffectTiming::Passive,
    ] {
        let json = serde_json::to_value(timing).unwrap();
        let back: EffectTiming = serde_json::from_value(json).unwrap();
        assert_eq!(timing, back);
    }
}

// ── Section 5: EffectScheduler ──────────────────────────────────────

#[test]
fn scheduler_empty_by_default() {
    let s = EffectScheduler::new();
    assert_eq!(s.pending_count(), 0);
    let s2 = EffectScheduler::default();
    assert_eq!(s2.pending_count(), 0);
}

#[test]
fn scheduler_enqueue_and_count() {
    let mut s = EffectScheduler::new();
    s.enqueue(effect("App", 0, EffectTiming::Passive, 1, false));
    s.enqueue(effect("App", 1, EffectTiming::Layout, 2, true));
    assert_eq!(s.pending_count(), 2);
}

#[test]
fn scheduler_drain_separates_cleanup_and_create_in_tree_order() {
    let mut s = EffectScheduler::new();
    s.enqueue(effect("C", 0, EffectTiming::Passive, 3, false));
    s.enqueue(effect("A", 0, EffectTiming::Passive, 1, true));
    s.enqueue(effect("B", 0, EffectTiming::Passive, 2, false));
    s.enqueue(effect("D", 0, EffectTiming::Passive, 4, true));

    let (cleanups, creates) = s.drain_for_timing(EffectTiming::Passive);
    assert_eq!(cleanups.len(), 2);
    assert_eq!(creates.len(), 2);
    // Cleanups in tree order
    assert_eq!(cleanups[0].tree_order, 1);
    assert_eq!(cleanups[1].tree_order, 4);
    // Creates in tree order
    assert_eq!(creates[0].tree_order, 2);
    assert_eq!(creates[1].tree_order, 3);
    assert_eq!(s.pending_count(), 0);
}

#[test]
fn scheduler_drain_does_not_affect_other_timings() {
    let mut s = EffectScheduler::new();
    s.enqueue(effect("A", 0, EffectTiming::Layout, 1, false));
    s.enqueue(effect("B", 0, EffectTiming::Passive, 2, false));
    s.enqueue(effect("C", 0, EffectTiming::Insertion, 3, false));

    let (c, r) = s.drain_for_timing(EffectTiming::Layout);
    assert_eq!(c.len() + r.len(), 1);
    assert_eq!(s.pending_count(), 2);
}

#[test]
fn scheduler_drain_all_ordered_correct_global_order() {
    let mut s = EffectScheduler::new();
    // Add in reverse order
    s.enqueue(effect("P", 0, EffectTiming::Passive, 1, false));
    s.enqueue(effect("L", 0, EffectTiming::Layout, 2, true));
    s.enqueue(effect("I", 0, EffectTiming::Insertion, 3, false));
    s.enqueue(effect("I2", 0, EffectTiming::Insertion, 1, true));

    let all = s.drain_all_ordered();
    assert_eq!(all.len(), 4);
    // Insertion first: cleanup (tree_order=1), then create (tree_order=3)
    assert_eq!(all[0].timing, EffectTiming::Insertion);
    assert!(all[0].is_cleanup);
    assert_eq!(all[0].tree_order, 1);
    assert_eq!(all[1].timing, EffectTiming::Insertion);
    assert!(!all[1].is_cleanup);
    // Layout
    assert_eq!(all[2].timing, EffectTiming::Layout);
    // Passive
    assert_eq!(all[3].timing, EffectTiming::Passive);
    assert_eq!(s.pending_count(), 0);
}

#[test]
fn scheduler_drain_empty_timing_returns_empty() {
    let mut s = EffectScheduler::new();
    s.enqueue(effect("A", 0, EffectTiming::Passive, 1, false));
    let (c, r) = s.drain_for_timing(EffectTiming::Insertion);
    assert!(c.is_empty());
    assert!(r.is_empty());
    assert_eq!(s.pending_count(), 1);
}

// ── Section 6: PendingEffect ────────────────────────────────────────

#[test]
fn pending_effect_derive_id_stable() {
    let e = effect("App", 0, EffectTiming::Passive, 1, false);
    assert_eq!(e.derive_id(), e.derive_id());
}

#[test]
fn pending_effect_derive_id_differs_by_cleanup_flag() {
    let e1 = effect("App", 0, EffectTiming::Passive, 1, false);
    let e2 = effect("App", 0, EffectTiming::Passive, 1, true);
    assert_ne!(e1.derive_id(), e2.derive_id());
}

#[test]
fn pending_effect_derive_id_differs_by_timing() {
    let e1 = effect("App", 0, EffectTiming::Layout, 1, false);
    let e2 = effect("App", 0, EffectTiming::Passive, 1, false);
    assert_ne!(e1.derive_id(), e2.derive_id());
}

#[test]
fn pending_effect_serde_roundtrip() {
    let e = effect("Counter", 2, EffectTiming::Layout, 42, true);
    let json = serde_json::to_string(&e).unwrap();
    let back: PendingEffect = serde_json::from_str(&json).unwrap();
    assert_eq!(e, back);
}

// ── Section 7: Dependency change detection ──────────────────────────

#[test]
fn compare_deps_none_none_always_run() {
    assert_eq!(compare_deps(None, None), DepsChange::AlwaysRun);
}

#[test]
fn compare_deps_some_none_always_run() {
    assert_eq!(
        compare_deps(Some(&[DepToken(1)]), None),
        DepsChange::AlwaysRun
    );
}

#[test]
fn compare_deps_none_empty_mount_only() {
    assert_eq!(compare_deps(None, Some(&[])), DepsChange::MountOnly);
}

#[test]
fn compare_deps_none_some_changed() {
    assert_eq!(
        compare_deps(None, Some(&[DepToken(1)])),
        DepsChange::Changed
    );
}

#[test]
fn compare_deps_same_values_unchanged() {
    let deps = [DepToken(1), DepToken(2), DepToken(3)];
    assert_eq!(
        compare_deps(Some(&deps), Some(&deps)),
        DepsChange::Unchanged
    );
}

#[test]
fn compare_deps_different_values_changed() {
    assert_eq!(
        compare_deps(Some(&[DepToken(1)]), Some(&[DepToken(2)])),
        DepsChange::Changed
    );
}

#[test]
fn compare_deps_different_length_changed() {
    assert_eq!(
        compare_deps(Some(&[DepToken(1)]), Some(&[DepToken(1), DepToken(2)])),
        DepsChange::Changed
    );
}

#[test]
fn compare_deps_to_empty_mount_only() {
    assert_eq!(
        compare_deps(Some(&[DepToken(1)]), Some(&[])),
        DepsChange::MountOnly
    );
}

#[test]
fn deps_change_serde_all_variants() {
    for dc in [
        DepsChange::AlwaysRun,
        DepsChange::MountOnly,
        DepsChange::Unchanged,
        DepsChange::Changed,
    ] {
        let json = serde_json::to_value(dc).unwrap();
        let back: DepsChange = serde_json::from_value(json).unwrap();
        assert_eq!(dc, back);
    }
}

// ── Section 8: Hook consistency validation ──────────────────────────

#[test]
fn validate_consistency_identical_manifests_clean() {
    let m = HookManifest::new(
        "App",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    );
    assert!(validate_hook_consistency(&m, &m).is_empty());
}

#[test]
fn validate_consistency_count_mismatch() {
    let prev = HookManifest::new("App", vec![slot(0, HookKind::State, None)]);
    let curr = HookManifest::new(
        "App",
        vec![slot(0, HookKind::State, None), slot(1, HookKind::Ref, None)],
    );
    let violations = validate_hook_consistency(&prev, &curr);
    assert!(violations.iter().any(|v| matches!(
        v,
        HookRuleViolation::HookCountMismatch {
            previous_count: 1,
            current_count: 2,
            ..
        }
    )));
}

#[test]
fn validate_consistency_kind_mismatch() {
    let prev = HookManifest::new("App", vec![slot(0, HookKind::State, None)]);
    let curr = HookManifest::new("App", vec![slot(0, HookKind::Ref, None)]);
    let violations = validate_hook_consistency(&prev, &curr);
    assert!(violations.iter().any(|v| matches!(
        v,
        HookRuleViolation::HookKindMismatch {
            previous_kind: HookKind::State,
            current_kind: HookKind::Ref,
            ..
        }
    )));
}

#[test]
fn validate_consistency_deps_length_mismatch() {
    let prev = HookManifest::new(
        "App",
        vec![slot(0, HookKind::Effect, Some(vec![DepToken(1)]))],
    );
    let curr = HookManifest::new(
        "App",
        vec![slot(
            0,
            HookKind::Effect,
            Some(vec![DepToken(1), DepToken(2)]),
        )],
    );
    let violations = validate_hook_consistency(&prev, &curr);
    assert!(violations.iter().any(|v| matches!(
        v,
        HookRuleViolation::DepsLengthMismatch {
            previous_len: 1,
            current_len: 2,
            ..
        }
    )));
}

#[test]
fn validate_consistency_count_mismatch_returns_early() {
    // Count mismatch should return immediately without checking individual slots
    let prev = HookManifest::new("App", vec![slot(0, HookKind::State, None)]);
    let curr = HookManifest::new(
        "App",
        vec![
            slot(0, HookKind::Ref, None), // also kind mismatch
            slot(1, HookKind::Memo, Some(vec![])),
        ],
    );
    let violations = validate_hook_consistency(&prev, &curr);
    assert_eq!(violations.len(), 1);
    assert!(matches!(
        &violations[0],
        HookRuleViolation::HookCountMismatch { .. }
    ));
}

#[test]
fn hook_rule_violation_serde_roundtrip() {
    let violations = [
        HookRuleViolation::HookCountMismatch {
            component: "X".into(),
            previous_count: 3,
            current_count: 2,
        },
        HookRuleViolation::HookKindMismatch {
            component: "X".into(),
            slot: HookSlotIndex(1),
            previous_kind: HookKind::State,
            current_kind: HookKind::Ref,
        },
        HookRuleViolation::HookOutsideRender {
            component: "X".into(),
            slot: HookSlotIndex(0),
            actual_phase: RenderPhase::Idle,
        },
        HookRuleViolation::ConditionalHookCall {
            component: "X".into(),
            slot: HookSlotIndex(2),
        },
        HookRuleViolation::DepsLengthMismatch {
            component: "X".into(),
            slot: HookSlotIndex(0),
            previous_len: 1,
            current_len: 3,
        },
    ];
    for v in &violations {
        let json = serde_json::to_string(v).unwrap();
        let back: HookRuleViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ── Section 9: LegalTransformation ──────────────────────────────────

#[test]
fn legal_transformation_all_has_8_variants() {
    assert_eq!(LegalTransformation::ALL.len(), 8);
    let unique: BTreeSet<_> = LegalTransformation::ALL.iter().collect();
    assert_eq!(unique.len(), 8);
}

#[test]
fn legal_transformation_applicable_hooks_non_empty() {
    for t in LegalTransformation::ALL {
        assert!(
            !t.applicable_hooks().is_empty(),
            "{t:?} has no applicable hooks"
        );
    }
}

#[test]
fn effect_elision_applies_to_all_effect_kinds() {
    let hooks = LegalTransformation::EffectElision.applicable_hooks();
    assert!(hooks.contains(&HookKind::Effect));
    assert!(hooks.contains(&HookKind::LayoutEffect));
    assert!(hooks.contains(&HookKind::InsertionEffect));
}

#[test]
fn memo_reorder_does_not_preserve_effect_order() {
    assert!(!LegalTransformation::MemoReorder.preserves_effect_order());
    // All others preserve it
    for t in LegalTransformation::ALL {
        if *t != LegalTransformation::MemoReorder {
            assert!(t.preserves_effect_order(), "{t:?}");
        }
    }
}

#[test]
fn unconditional_transforms_only_context_dedup_and_state_batch() {
    assert!(LegalTransformation::ContextDedup.is_unconditional());
    assert!(LegalTransformation::StateBatch.is_unconditional());
    for t in LegalTransformation::ALL {
        if *t != LegalTransformation::ContextDedup && *t != LegalTransformation::StateBatch {
            assert!(!t.is_unconditional(), "{t:?} should be conditional");
        }
    }
}

#[test]
fn legal_transformation_serde_all_variants() {
    for t in LegalTransformation::ALL {
        let json = serde_json::to_value(t).unwrap();
        let back: LegalTransformation = serde_json::from_value(json).unwrap();
        assert_eq!(*t, back);
    }
}

// ── Section 10: TransformationReceipt ───────────────────────────────

#[test]
fn transformation_receipt_derive_id_stable() {
    let r = TransformationReceipt {
        transformation: LegalTransformation::MemoConstantFold,
        component_name: "App".into(),
        target_slots: vec![HookSlotIndex(0)],
        precondition_met: true,
        reason: "constant deps".into(),
    };
    assert_eq!(r.derive_id(), r.derive_id());
}

#[test]
fn transformation_receipt_serde_roundtrip() {
    let r = TransformationReceipt {
        transformation: LegalTransformation::StateBatch,
        component_name: "Counter".into(),
        target_slots: vec![HookSlotIndex(0), HookSlotIndex(1)],
        precondition_met: true,
        reason: "adjacent useState".into(),
    };
    let json = serde_json::to_string(&r).unwrap();
    let back: TransformationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

#[test]
fn transformation_receipt_failed_precondition() {
    let r = TransformationReceipt {
        transformation: LegalTransformation::RefHoist,
        component_name: "MultiInstance".into(),
        target_slots: vec![HookSlotIndex(2)],
        precondition_met: false,
        reason: "component is not a singleton".into(),
    };
    assert!(!r.precondition_met);
    let json = serde_json::to_string(&r).unwrap();
    let back: TransformationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(r, back);
}

// ── Section 11: PhaseTransition ─────────────────────────────────────

#[test]
fn phase_transition_valid_transitions() {
    let t = PhaseTransition {
        component_name: "App".into(),
        from: RenderPhase::Idle,
        to: RenderPhase::Rendering,
        sequence_number: 0,
    };
    assert!(t.validate().is_ok());
}

#[test]
fn phase_transition_invalid_transitions() {
    let t = PhaseTransition {
        component_name: "App".into(),
        from: RenderPhase::Idle,
        to: RenderPhase::PaintPending,
        sequence_number: 0,
    };
    assert!(matches!(
        t.validate(),
        Err(PhaseTransitionError::IllegalTransition { .. })
    ));
}

#[test]
fn phase_transition_derive_id_stable() {
    let t = PhaseTransition {
        component_name: "App".into(),
        from: RenderPhase::Idle,
        to: RenderPhase::Rendering,
        sequence_number: 0,
    };
    assert_eq!(t.derive_id(), t.derive_id());
}

#[test]
fn phase_transition_serde_roundtrip() {
    let t = PhaseTransition {
        component_name: "Counter".into(),
        from: RenderPhase::Rendering,
        to: RenderPhase::InsertionEffectsPending,
        sequence_number: 42,
    };
    let json = serde_json::to_string(&t).unwrap();
    let back: PhaseTransition = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn phase_transition_error_serde_roundtrip() {
    let err = PhaseTransitionError::IllegalTransition {
        component: "Bad".into(),
        from: RenderPhase::Idle,
        to: RenderPhase::PaintPending,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: PhaseTransitionError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ── Section 12: ComponentPhaseTracker ───────────────────────────────

#[test]
fn tracker_starts_idle_with_zero_renders() {
    let t = ComponentPhaseTracker::new("App");
    assert_eq!(t.current_phase, RenderPhase::Idle);
    assert_eq!(t.render_count, 0);
    assert!(t.transition_log.is_empty());
}

#[test]
fn tracker_full_cycle_increments_render_count() {
    let mut t = ComponentPhaseTracker::new("App");
    assert!(t.run_full_cycle().is_ok());
    assert_eq!(t.current_phase, RenderPhase::Idle);
    assert_eq!(t.render_count, 1);
    assert_eq!(t.transition_log.len(), 6);
}

#[test]
fn tracker_double_cycle() {
    let mut t = ComponentPhaseTracker::new("App");
    t.run_full_cycle().unwrap();
    t.run_full_cycle().unwrap();
    assert_eq!(t.render_count, 2);
    assert_eq!(t.transition_log.len(), 12);
}

#[test]
fn tracker_triple_cycle_increments_correctly() {
    let mut t = ComponentPhaseTracker::new("Widget");
    for i in 1..=3 {
        t.run_full_cycle().unwrap();
        assert_eq!(t.render_count, i);
    }
    assert_eq!(t.transition_log.len(), 18);
}

#[test]
fn tracker_illegal_transition_rejected_and_state_unchanged() {
    let mut t = ComponentPhaseTracker::new("App");
    let result = t.transition_to(RenderPhase::PaintPending);
    assert!(result.is_err());
    assert_eq!(t.current_phase, RenderPhase::Idle);
    assert_eq!(t.render_count, 0);
}

#[test]
fn tracker_unmount_from_idle() {
    let mut t = ComponentPhaseTracker::new("App");
    assert!(t.transition_to(RenderPhase::Unmounting).is_ok());
    assert_eq!(t.current_phase, RenderPhase::Unmounting);
}

#[test]
fn tracker_unmount_is_terminal() {
    let mut t = ComponentPhaseTracker::new("App");
    t.transition_to(RenderPhase::Unmounting).unwrap();
    assert!(t.transition_to(RenderPhase::Idle).is_err());
    assert!(t.transition_to(RenderPhase::Rendering).is_err());
}

#[test]
fn tracker_unmount_after_render_cycle() {
    let mut t = ComponentPhaseTracker::new("App");
    t.run_full_cycle().unwrap();
    assert_eq!(t.render_count, 1);
    t.transition_to(RenderPhase::Unmounting).unwrap();
    assert_eq!(t.current_phase, RenderPhase::Unmounting);
}

#[test]
fn tracker_serde_roundtrip() {
    let mut t = ComponentPhaseTracker::new("Counter");
    t.run_full_cycle().unwrap();
    let json = serde_json::to_string(&t).unwrap();
    let back: ComponentPhaseTracker = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

// ── Section 13: SchedulingBoundary ──────────────────────────────────

#[test]
fn canonical_boundaries_has_three_entries() {
    let bounds = SchedulingBoundary::canonical_boundaries();
    assert_eq!(bounds.len(), 3);
}

#[test]
fn insertion_boundary_synchronous_no_dom() {
    let bounds = SchedulingBoundary::canonical_boundaries();
    let insertion = bounds
        .iter()
        .find(|b| b.timing == EffectTiming::Insertion)
        .unwrap();
    assert!(insertion.synchronous);
    assert!(!insertion.dom_mutations_visible);
    assert!(insertion.state_updates_batched);
}

#[test]
fn layout_boundary_synchronous_with_dom() {
    let bounds = SchedulingBoundary::canonical_boundaries();
    let layout = bounds
        .iter()
        .find(|b| b.timing == EffectTiming::Layout)
        .unwrap();
    assert!(layout.synchronous);
    assert!(layout.dom_mutations_visible);
}

#[test]
fn passive_boundary_async_with_dom() {
    let bounds = SchedulingBoundary::canonical_boundaries();
    let passive = bounds
        .iter()
        .find(|b| b.timing == EffectTiming::Passive)
        .unwrap();
    assert!(!passive.synchronous);
    assert!(passive.dom_mutations_visible);
}

#[test]
fn all_boundaries_batch_state_updates() {
    for b in SchedulingBoundary::canonical_boundaries() {
        assert!(b.state_updates_batched, "{:?}", b.timing);
    }
}

#[test]
fn scheduling_boundary_serde_roundtrip() {
    let bounds = SchedulingBoundary::canonical_boundaries();
    let json = serde_json::to_string(&bounds).unwrap();
    let back: Vec<SchedulingBoundary> = serde_json::from_str(&json).unwrap();
    assert_eq!(bounds, back);
}

// ── Section 14: HookEffectContract ──────────────────────────────────

#[test]
fn contract_new_defaults() {
    let c = HookEffectContract::new();
    assert!(c.manifests.is_empty());
    assert_eq!(c.scheduling_boundaries.len(), 3);
    assert!(c.approved_transformations.is_empty());
    assert_eq!(c.version, 1);
}

#[test]
fn contract_default_equals_new() {
    assert_eq!(HookEffectContract::new(), HookEffectContract::default());
}

#[test]
fn contract_register_and_count() {
    let mut c = HookEffectContract::new();
    c.register_manifest(HookManifest::new(
        "App",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
            slot(2, HookKind::LayoutEffect, Some(vec![])),
        ],
    ));
    assert_eq!(c.manifests.len(), 1);
    assert_eq!(c.total_hook_count(), 3);
    assert_eq!(c.effect_hook_count(), 2);
}

#[test]
fn contract_multi_component_counts() {
    let mut c = HookEffectContract::new();
    c.register_manifest(HookManifest::new(
        "App",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![])),
        ],
    ));
    c.register_manifest(HookManifest::new(
        "Header",
        vec![
            slot(0, HookKind::Context, None),
            slot(1, HookKind::LayoutEffect, Some(vec![DepToken(1)])),
            slot(2, HookKind::Ref, None),
        ],
    ));
    assert_eq!(c.manifests.len(), 2);
    assert_eq!(c.total_hook_count(), 5);
    assert_eq!(c.effect_hook_count(), 2);
}

#[test]
fn contract_approve_transformation() {
    let mut c = HookEffectContract::new();
    c.approve_transformation(LegalTransformation::StateBatch);
    c.approve_transformation(LegalTransformation::MemoConstantFold);
    c.approve_transformation(LegalTransformation::StateBatch); // duplicate
    assert_eq!(c.approved_transformations.len(), 2);
}

#[test]
fn contract_validate_all_clean() {
    let mut c = HookEffectContract::new();
    c.register_manifest(HookManifest::new(
        "App",
        vec![slot(0, HookKind::State, None)],
    ));
    assert!(c.validate_all().is_empty());
}

#[test]
fn contract_validate_all_catches_errors() {
    let mut c = HookEffectContract::new();
    c.register_manifest(HookManifest::new("Bad", vec![]));
    let results = c.validate_all();
    assert!(results.contains_key("Bad"));
    assert!(
        results["Bad"]
            .iter()
            .any(|e| matches!(e, HookManifestError::EmptyManifest))
    );
}

#[test]
fn contract_derive_id_stable() {
    let mut c = HookEffectContract::new();
    c.register_manifest(HookManifest::new(
        "App",
        vec![slot(0, HookKind::State, None)],
    ));
    assert_eq!(c.derive_id(), c.derive_id());
}

#[test]
fn contract_serde_roundtrip() {
    let mut c = HookEffectContract::new();
    c.register_manifest(HookManifest::new(
        "Counter",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    ));
    c.approve_transformation(LegalTransformation::MemoConstantFold);
    let json = serde_json::to_string(&c).unwrap();
    let back: HookEffectContract = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ── Section 15: Unsupported semantics classification ────────────────

#[test]
fn classify_hook_count_mismatch_as_topology_drift() {
    let v = HookRuleViolation::HookCountMismatch {
        component: "App".into(),
        previous_count: 3,
        current_count: 2,
    };
    assert_eq!(
        classify_unsupported_semantics(&v),
        UnsupportedSemanticsTrigger::HookTopologyDrift
    );
}

#[test]
fn classify_hook_kind_mismatch_as_topology_drift() {
    let v = HookRuleViolation::HookKindMismatch {
        component: "App".into(),
        slot: HookSlotIndex(0),
        previous_kind: HookKind::State,
        current_kind: HookKind::Ref,
    };
    assert_eq!(
        classify_unsupported_semantics(&v),
        UnsupportedSemanticsTrigger::HookTopologyDrift
    );
}

#[test]
fn classify_conditional_hook_as_topology_drift() {
    let v = HookRuleViolation::ConditionalHookCall {
        component: "App".into(),
        slot: HookSlotIndex(2),
    };
    assert_eq!(
        classify_unsupported_semantics(&v),
        UnsupportedSemanticsTrigger::HookTopologyDrift
    );
}

#[test]
fn classify_deps_length_as_dependency_drift() {
    let v = HookRuleViolation::DepsLengthMismatch {
        component: "App".into(),
        slot: HookSlotIndex(1),
        previous_len: 2,
        current_len: 1,
    };
    assert_eq!(
        classify_unsupported_semantics(&v),
        UnsupportedSemanticsTrigger::DependencyShapeDrift
    );
}

#[test]
fn classify_hook_outside_render_as_out_of_render() {
    let v = HookRuleViolation::HookOutsideRender {
        component: "App".into(),
        slot: HookSlotIndex(0),
        actual_phase: RenderPhase::Idle,
    };
    assert_eq!(
        classify_unsupported_semantics(&v),
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution
    );
}

// ── Section 16: Fallback routes ─────────────────────────────────────

#[test]
fn fallback_route_compatibility_lane_triggers() {
    for trigger in [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
    ] {
        assert_eq!(
            fallback_route_for_trigger(trigger),
            FallbackExecutionRoute::CompatibilityRuntimeLane,
            "{trigger:?}"
        );
    }
}

#[test]
fn fallback_route_baseline_interpreter_lane() {
    assert_eq!(
        fallback_route_for_trigger(UnsupportedSemanticsTrigger::TransformationProofMissing),
        FallbackExecutionRoute::BaselineInterpreterLane
    );
}

#[test]
fn fallback_route_safe_mode_lane_triggers() {
    for trigger in [
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
    ] {
        assert_eq!(
            fallback_route_for_trigger(trigger),
            FallbackExecutionRoute::DeterministicSafeModeLane,
            "{trigger:?}"
        );
    }
}

#[test]
fn fallback_routes_deterministic_for_all_triggers() {
    let all_triggers = [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ];
    for trigger in all_triggers {
        assert_eq!(
            fallback_route_for_trigger(trigger),
            fallback_route_for_trigger(trigger)
        );
    }
}

// ── Section 17: UnsupportedSemanticsTrigger metadata ────────────────

#[test]
fn all_triggers_have_distinct_error_codes() {
    let all = [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ];
    let codes: BTreeSet<&str> = all.iter().map(|t| t.stable_error_code()).collect();
    assert_eq!(codes.len(), 6);
}

#[test]
fn all_triggers_have_non_empty_metadata() {
    let all = [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ];
    for trigger in all {
        assert!(!trigger.stable_error_code().is_empty(), "{trigger:?}");
        assert!(!trigger.rejection_reason().is_empty(), "{trigger:?}");
        assert!(!trigger.hardening_guidance().is_empty(), "{trigger:?}");
    }
}

#[test]
fn unsupported_semantics_trigger_serde_all_variants() {
    let all = [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ];
    for trigger in all {
        let json = serde_json::to_value(trigger).unwrap();
        let back: UnsupportedSemanticsTrigger = serde_json::from_value(json).unwrap();
        assert_eq!(trigger, back);
    }
}

// ── Section 18: Unsupported semantics diagnostics ───────────────────

#[test]
fn build_diagnostic_for_topology_drift() {
    let diag = build_unsupported_semantics_diagnostic(
        "Counter",
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        "trace-1",
        "decision-1",
    );
    assert_eq!(diag.component_name, "Counter");
    assert_eq!(diag.trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);
    assert_eq!(
        diag.fallback_route,
        FallbackExecutionRoute::CompatibilityRuntimeLane
    );
    assert!(diag.compile_path_rejected);
    assert_eq!(diag.error_code, "FE-HOOK-UNSUPPORTED-0001");
    assert!(!diag.reason.is_empty());
    assert!(!diag.hardening_guidance.is_empty());
}

#[test]
fn build_diagnostic_for_proof_missing() {
    let diag = build_unsupported_semantics_diagnostic(
        "App",
        UnsupportedSemanticsTrigger::TransformationProofMissing,
        "trace-2",
        "decision-2",
    );
    assert_eq!(
        diag.fallback_route,
        FallbackExecutionRoute::BaselineInterpreterLane
    );
    assert_eq!(diag.error_code, "FE-HOOK-UNSUPPORTED-0006");
}

#[test]
fn build_diagnostic_derive_id_stable() {
    let diag = build_unsupported_semantics_diagnostic(
        "Widget",
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        "trace-3",
        "decision-3",
    );
    assert_eq!(diag.derive_id(), diag.derive_id());
}

#[test]
fn diagnostic_serde_roundtrip() {
    let diag = build_unsupported_semantics_diagnostic(
        "Page",
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        "trace-4",
        "decision-4",
    );
    let json = serde_json::to_string(&diag).unwrap();
    let back: UnsupportedSemanticsDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(diag, back);
}

#[test]
fn all_triggers_produce_valid_diagnostics() {
    let all = [
        UnsupportedSemanticsTrigger::HookTopologyDrift,
        UnsupportedSemanticsTrigger::DependencyShapeDrift,
        UnsupportedSemanticsTrigger::OutOfRenderHookExecution,
        UnsupportedSemanticsTrigger::SchedulerOrderingAmbiguity,
        UnsupportedSemanticsTrigger::UnsupportedHookPrimitive,
        UnsupportedSemanticsTrigger::TransformationProofMissing,
    ];
    for (i, trigger) in all.iter().enumerate() {
        let diag = build_unsupported_semantics_diagnostic(
            format!("Comp{i}"),
            *trigger,
            format!("trace-{i}"),
            format!("decision-{i}"),
        );
        assert!(diag.compile_path_rejected);
        assert_eq!(diag.error_code, trigger.stable_error_code());
        assert_eq!(diag.fallback_route, fallback_route_for_trigger(*trigger));
        assert_eq!(
            diag.schema_version,
            "franken-engine.hook-effect-unsupported-semantics.v1"
        );
    }
}

// ── Section 19: End-to-end pipelines ────────────────────────────────

#[test]
fn end_to_end_render_with_effects_and_dep_check() {
    // Build manifest
    let manifest = HookManifest::new(
        "TodoList",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
            slot(
                2,
                HookKind::LayoutEffect,
                Some(vec![DepToken(1), DepToken(2)]),
            ),
            slot(3, HookKind::InsertionEffect, Some(vec![])),
            slot(4, HookKind::Memo, Some(vec![DepToken(1)])),
        ],
    );
    assert!(manifest.validate().is_empty());

    // Register in contract
    let mut contract = HookEffectContract::new();
    contract.register_manifest(manifest);
    assert_eq!(contract.total_hook_count(), 5);
    assert_eq!(contract.effect_hook_count(), 3);

    // Schedule effects
    let mut scheduler = EffectScheduler::new();
    scheduler.enqueue(effect("TodoList", 3, EffectTiming::Insertion, 1, false));
    scheduler.enqueue(effect("TodoList", 2, EffectTiming::Layout, 1, false));
    scheduler.enqueue(effect("TodoList", 1, EffectTiming::Passive, 1, false));
    assert_eq!(scheduler.pending_count(), 3);

    // Run phase tracker
    let mut tracker = ComponentPhaseTracker::new("TodoList");
    tracker.transition_to(RenderPhase::Rendering).unwrap();
    tracker
        .transition_to(RenderPhase::InsertionEffectsPending)
        .unwrap();
    let (c, r) = scheduler.drain_for_timing(EffectTiming::Insertion);
    assert_eq!(c.len() + r.len(), 1);

    tracker
        .transition_to(RenderPhase::LayoutEffectsPending)
        .unwrap();
    let (c, r) = scheduler.drain_for_timing(EffectTiming::Layout);
    assert_eq!(c.len() + r.len(), 1);

    tracker.transition_to(RenderPhase::PaintPending).unwrap();
    tracker
        .transition_to(RenderPhase::PassiveEffectsPending)
        .unwrap();
    let (c, r) = scheduler.drain_for_timing(EffectTiming::Passive);
    assert_eq!(c.len() + r.len(), 1);

    tracker.transition_to(RenderPhase::Idle).unwrap();
    assert_eq!(tracker.render_count, 1);
    assert_eq!(scheduler.pending_count(), 0);
}

#[test]
fn end_to_end_rerender_with_consistency_and_deps() {
    let prev = HookManifest::new(
        "Counter",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(42)])),
        ],
    );
    let curr = HookManifest::new(
        "Counter",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(99)])),
        ],
    );

    // Consistency check passes (same structure, different dep values)
    let violations = validate_hook_consistency(&prev, &curr);
    assert!(violations.is_empty());

    // Dep changed → effect should re-run
    assert_eq!(
        compare_deps(prev.slots[1].deps.as_deref(), curr.slots[1].deps.as_deref()),
        DepsChange::Changed
    );
}

#[test]
fn end_to_end_violation_to_fallback_diagnostic() {
    // Simulate a hook count mismatch during re-render
    let prev = HookManifest::new(
        "App",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
        ],
    );
    let curr = HookManifest::new(
        "App",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::Effect, Some(vec![DepToken(1)])),
            slot(2, HookKind::Memo, Some(vec![])),
        ],
    );

    let violations = validate_hook_consistency(&prev, &curr);
    assert!(!violations.is_empty());

    // Classify the violation
    let trigger = classify_unsupported_semantics(&violations[0]);
    assert_eq!(trigger, UnsupportedSemanticsTrigger::HookTopologyDrift);

    // Route to fallback
    let route = fallback_route_for_trigger(trigger);
    assert_eq!(route, FallbackExecutionRoute::CompatibilityRuntimeLane);

    // Build diagnostic
    let diag = build_unsupported_semantics_diagnostic("App", trigger, "trace-e2e", "dec-e2e");
    assert!(diag.compile_path_rejected);
    assert_eq!(diag.error_code, "FE-HOOK-UNSUPPORTED-0001");
    assert_eq!(
        diag.fallback_route,
        FallbackExecutionRoute::CompatibilityRuntimeLane
    );
}

#[test]
fn end_to_end_transformation_approval_and_receipt() {
    let mut contract = HookEffectContract::new();
    contract.register_manifest(HookManifest::new(
        "App",
        vec![
            slot(0, HookKind::State, None),
            slot(1, HookKind::State, None),
            slot(2, HookKind::Memo, Some(vec![DepToken(1)])),
        ],
    ));

    // Approve StateBatch
    contract.approve_transformation(LegalTransformation::StateBatch);
    assert!(
        contract
            .approved_transformations
            .contains(&LegalTransformation::StateBatch)
    );

    // Create receipt
    let receipt = TransformationReceipt {
        transformation: LegalTransformation::StateBatch,
        component_name: "App".into(),
        target_slots: vec![HookSlotIndex(0), HookSlotIndex(1)],
        precondition_met: true,
        reason: "adjacent useState calls batched".into(),
    };

    // Verify StateBatch is unconditional
    assert!(receipt.transformation.is_unconditional());
    assert!(receipt.transformation.preserves_effect_order());

    // Receipt ID is stable
    assert_eq!(receipt.derive_id(), receipt.derive_id());
}

// ── Section 20: FallbackExecutionRoute serde ────────────────────────

#[test]
fn fallback_execution_route_serde_all_variants() {
    for route in [
        FallbackExecutionRoute::CompatibilityRuntimeLane,
        FallbackExecutionRoute::BaselineInterpreterLane,
        FallbackExecutionRoute::DeterministicSafeModeLane,
    ] {
        let json = serde_json::to_value(route).unwrap();
        let back: FallbackExecutionRoute = serde_json::from_value(json).unwrap();
        assert_eq!(route, back);
    }
}

// ── Section 21: HookManifestError serde ─────────────────────────────

#[test]
fn hook_manifest_error_serde_all_variants() {
    let errors = [
        HookManifestError::EmptyManifest,
        HookManifestError::NonConsecutiveIndices {
            expected: 1,
            found: 5,
        },
        HookManifestError::DuplicateIndex(HookSlotIndex(3)),
        HookManifestError::DepsOnNonDepHook {
            index: HookSlotIndex(0),
            kind: HookKind::State,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: HookManifestError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}
