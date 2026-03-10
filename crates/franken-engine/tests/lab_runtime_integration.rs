#![forbid(unsafe_code)]

//! Comprehensive integration tests for the `lab_runtime` module.
//!
//! Covers: VirtualClock, ScheduleAction, FaultKind, ScheduleTranscript,
//! TaskState, LabEvent, Verdict, LabRunResult, LabRuntime, replay_transcript.
//! Validates construction, Display impls, serde roundtrips, state transitions,
//! error conditions, deterministic replay, and edge cases.

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

use frankenengine_engine::lab_runtime::{
    FaultKind, LabEvent, LabRunResult, LabRuntime, ScheduleAction, ScheduleTranscript, TaskState,
    Verdict, VirtualClock, replay_transcript,
};

// ---------------------------------------------------------------------------
// Section 1: VirtualClock construction and defaults
// ---------------------------------------------------------------------------

#[test]
fn virtual_clock_starts_at_zero() {
    let clock = VirtualClock::new();
    assert_eq!(clock.now(), 0);
}

#[test]
fn virtual_clock_default_is_zero() {
    let clock = VirtualClock::default();
    assert_eq!(clock.now(), 0);
}

#[test]
fn virtual_clock_new_equals_default() {
    let new_clock = VirtualClock::new();
    let default_clock = VirtualClock::default();
    assert_eq!(new_clock, default_clock);
}

// ---------------------------------------------------------------------------
// Section 2: VirtualClock advance
// ---------------------------------------------------------------------------

#[test]
fn virtual_clock_advance_single() {
    let mut clock = VirtualClock::new();
    clock.advance(100);
    assert_eq!(clock.now(), 100);
}

#[test]
fn virtual_clock_advance_cumulative() {
    let mut clock = VirtualClock::new();
    clock.advance(10);
    clock.advance(20);
    clock.advance(30);
    assert_eq!(clock.now(), 60);
}

#[test]
fn virtual_clock_advance_zero() {
    let mut clock = VirtualClock::new();
    clock.advance(0);
    assert_eq!(clock.now(), 0);
    clock.advance(50);
    clock.advance(0);
    assert_eq!(clock.now(), 50);
}

#[test]
fn virtual_clock_advance_large_values() {
    let mut clock = VirtualClock::new();
    clock.advance(u64::MAX / 2);
    assert_eq!(clock.now(), u64::MAX / 2);
}

// ---------------------------------------------------------------------------
// Section 3: VirtualClock advance_to
// ---------------------------------------------------------------------------

#[test]
fn virtual_clock_advance_to_forward() {
    let mut clock = VirtualClock::new();
    assert!(clock.advance_to(500));
    assert_eq!(clock.now(), 500);
}

#[test]
fn virtual_clock_advance_to_backward_rejected() {
    let mut clock = VirtualClock::new();
    clock.advance(500);
    assert!(!clock.advance_to(100));
    assert_eq!(clock.now(), 500, "clock must not go backward");
}

#[test]
fn virtual_clock_advance_to_same_value() {
    let mut clock = VirtualClock::new();
    clock.advance(100);
    assert!(clock.advance_to(100));
    assert_eq!(clock.now(), 100);
}

#[test]
fn virtual_clock_advance_to_zero_from_zero() {
    let mut clock = VirtualClock::new();
    assert!(clock.advance_to(0));
    assert_eq!(clock.now(), 0);
}

#[test]
fn virtual_clock_advance_to_max() {
    let mut clock = VirtualClock::new();
    assert!(clock.advance_to(u64::MAX));
    assert_eq!(clock.now(), u64::MAX);
}

// ---------------------------------------------------------------------------
// Section 4: VirtualClock serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn virtual_clock_serde_roundtrip_zero() {
    let clock = VirtualClock::new();
    let json = serde_json::to_string(&clock).expect("serialize");
    let restored: VirtualClock = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(clock, restored);
}

#[test]
fn virtual_clock_serde_roundtrip_advanced() {
    let mut clock = VirtualClock::new();
    clock.advance(1_000_000);
    let json = serde_json::to_string(&clock).expect("serialize");
    let restored: VirtualClock = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(clock, restored);
}

#[test]
fn virtual_clock_clone_equals_original() {
    let mut clock = VirtualClock::new();
    clock.advance(42);
    let cloned = clock.clone();
    assert_eq!(clock, cloned);
}

// ---------------------------------------------------------------------------
// Section 5: FaultKind Display
// ---------------------------------------------------------------------------

#[test]
fn fault_kind_display_panic() {
    assert_eq!(FaultKind::Panic.to_string(), "panic");
}

#[test]
fn fault_kind_display_channel_disconnect() {
    assert_eq!(
        FaultKind::ChannelDisconnect.to_string(),
        "channel_disconnect"
    );
}

#[test]
fn fault_kind_display_obligation_leak() {
    assert_eq!(FaultKind::ObligationLeak.to_string(), "obligation_leak");
}

#[test]
fn fault_kind_display_deadline_expired() {
    assert_eq!(FaultKind::DeadlineExpired.to_string(), "deadline_expired");
}

#[test]
fn fault_kind_display_region_close() {
    assert_eq!(FaultKind::RegionClose.to_string(), "region_close");
}

#[test]
fn fault_kind_all_variants_have_distinct_display() {
    let displays: BTreeSet<String> = [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ]
    .iter()
    .map(|f| f.to_string())
    .collect();
    assert_eq!(
        displays.len(),
        5,
        "all FaultKind variants must have distinct display strings"
    );
}

// ---------------------------------------------------------------------------
// Section 6: FaultKind serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn fault_kind_serde_roundtrip_all_variants() {
    let variants = [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize FaultKind");
        let restored: FaultKind = serde_json::from_str(&json).expect("deserialize FaultKind");
        assert_eq!(variant, &restored);
    }
}

#[test]
fn fault_kind_clone_equals() {
    let f = FaultKind::Panic;
    assert_eq!(f, f.clone());
}

// ---------------------------------------------------------------------------
// Section 7: TaskState Display
// ---------------------------------------------------------------------------

#[test]
fn task_state_display_ready() {
    assert_eq!(TaskState::Ready.to_string(), "ready");
}

#[test]
fn task_state_display_running() {
    assert_eq!(TaskState::Running.to_string(), "running");
}

#[test]
fn task_state_display_completed() {
    assert_eq!(TaskState::Completed.to_string(), "completed");
}

#[test]
fn task_state_display_faulted() {
    assert_eq!(TaskState::Faulted.to_string(), "faulted");
}

#[test]
fn task_state_display_cancelled() {
    assert_eq!(TaskState::Cancelled.to_string(), "cancelled");
}

#[test]
fn task_state_all_variants_have_distinct_display() {
    let displays: BTreeSet<String> = [
        TaskState::Ready,
        TaskState::Running,
        TaskState::Completed,
        TaskState::Faulted,
        TaskState::Cancelled,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(
        displays.len(),
        5,
        "all TaskState variants must have distinct display strings"
    );
}

// ---------------------------------------------------------------------------
// Section 8: TaskState serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn task_state_serde_roundtrip_all_variants() {
    let variants = [
        TaskState::Ready,
        TaskState::Running,
        TaskState::Completed,
        TaskState::Faulted,
        TaskState::Cancelled,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).expect("serialize TaskState");
        let restored: TaskState = serde_json::from_str(&json).expect("deserialize TaskState");
        assert_eq!(variant, &restored);
    }
}

// ---------------------------------------------------------------------------
// Section 9: Verdict Display
// ---------------------------------------------------------------------------

#[test]
fn verdict_display_pass() {
    assert_eq!(Verdict::Pass.to_string(), "PASS");
}

#[test]
fn verdict_display_fail() {
    let v = Verdict::Fail {
        reason: "task panicked".to_string(),
    };
    let display = v.to_string();
    assert!(display.contains("FAIL"));
    assert!(display.contains("task panicked"));
}

#[test]
fn verdict_display_fail_empty_reason() {
    let v = Verdict::Fail {
        reason: String::new(),
    };
    let display = v.to_string();
    assert!(display.contains("FAIL"));
}

// ---------------------------------------------------------------------------
// Section 10: Verdict serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn verdict_serde_roundtrip_pass() {
    let v = Verdict::Pass;
    let json = serde_json::to_string(&v).expect("serialize");
    let restored: Verdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, restored);
}

#[test]
fn verdict_serde_roundtrip_fail() {
    let v = Verdict::Fail {
        reason: "something went wrong".to_string(),
    };
    let json = serde_json::to_string(&v).expect("serialize");
    let restored: Verdict = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(v, restored);
}

// ---------------------------------------------------------------------------
// Section 11: ScheduleAction serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn schedule_action_serde_roundtrip_run_task() {
    let a = ScheduleAction::RunTask { task_id: 42 };
    let json = serde_json::to_string(&a).expect("serialize");
    let restored: ScheduleAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(a, restored);
}

#[test]
fn schedule_action_serde_roundtrip_advance_time() {
    let a = ScheduleAction::AdvanceTime { ticks: 1000 };
    let json = serde_json::to_string(&a).expect("serialize");
    let restored: ScheduleAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(a, restored);
}

#[test]
fn schedule_action_serde_roundtrip_inject_cancel() {
    let a = ScheduleAction::InjectCancel {
        region_id: "region-alpha".to_string(),
    };
    let json = serde_json::to_string(&a).expect("serialize");
    let restored: ScheduleAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(a, restored);
}

#[test]
fn schedule_action_serde_roundtrip_inject_fault() {
    let a = ScheduleAction::InjectFault {
        task_id: 7,
        fault: FaultKind::ObligationLeak,
    };
    let json = serde_json::to_string(&a).expect("serialize");
    let restored: ScheduleAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(a, restored);
}

#[test]
fn schedule_action_serde_roundtrip_fire_timer() {
    let a = ScheduleAction::FireTimer { timer_id: 99 };
    let json = serde_json::to_string(&a).expect("serialize");
    let restored: ScheduleAction = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(a, restored);
}

// ---------------------------------------------------------------------------
// Section 12: ScheduleTranscript construction and methods
// ---------------------------------------------------------------------------

#[test]
fn schedule_transcript_new_is_empty() {
    let t = ScheduleTranscript::new(42);
    assert_eq!(t.seed, 42);
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
}

#[test]
fn schedule_transcript_push_and_len() {
    let mut t = ScheduleTranscript::new(1);
    t.push(ScheduleAction::RunTask { task_id: 1 });
    assert_eq!(t.len(), 1);
    assert!(!t.is_empty());

    t.push(ScheduleAction::AdvanceTime { ticks: 10 });
    t.push(ScheduleAction::InjectCancel {
        region_id: "r".to_string(),
    });
    assert_eq!(t.len(), 3);
}

#[test]
fn schedule_transcript_serde_roundtrip() {
    let mut t = ScheduleTranscript::new(99);
    t.push(ScheduleAction::RunTask { task_id: 1 });
    t.push(ScheduleAction::AdvanceTime { ticks: 50 });
    t.push(ScheduleAction::InjectFault {
        task_id: 1,
        fault: FaultKind::Panic,
    });
    t.push(ScheduleAction::InjectCancel {
        region_id: "zone-a".to_string(),
    });
    t.push(ScheduleAction::FireTimer { timer_id: 7 });

    let json = serde_json::to_string(&t).expect("serialize");
    let restored: ScheduleTranscript = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(t, restored);
}

#[test]
fn schedule_transcript_clone_equals_original() {
    let mut t = ScheduleTranscript::new(42);
    t.push(ScheduleAction::RunTask { task_id: 1 });
    let cloned = t.clone();
    assert_eq!(t, cloned);
}

// ---------------------------------------------------------------------------
// Section 13: LabEvent serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn lab_event_serde_roundtrip() {
    let event = LabEvent {
        virtual_time: 100,
        step_index: 1,
        action: "run_task".to_string(),
        task_id: Some(1),
        region_id: None,
        outcome: "running".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: LabEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

#[test]
fn lab_event_serde_roundtrip_with_region() {
    let event = LabEvent {
        virtual_time: 200,
        step_index: 5,
        action: "inject_cancel".to_string(),
        task_id: None,
        region_id: Some("region-beta".to_string()),
        outcome: "cancel_injected".to_string(),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let restored: LabEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, restored);
}

// ---------------------------------------------------------------------------
// Section 14: LabRunResult serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn lab_run_result_serde_roundtrip_pass() {
    let result = LabRunResult {
        seed: 42,
        transcript: ScheduleTranscript::new(42),
        events: Vec::new(),
        final_time: 1000,
        tasks_completed: 5,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: LabRunResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

#[test]
fn lab_run_result_serde_roundtrip_fail() {
    let result = LabRunResult {
        seed: 99,
        transcript: ScheduleTranscript::new(99),
        events: vec![LabEvent {
            virtual_time: 0,
            step_index: 1,
            action: "inject_fault".to_string(),
            task_id: Some(1),
            region_id: None,
            outcome: "fault=panic".to_string(),
        }],
        final_time: 0,
        tasks_completed: 0,
        tasks_faulted: 1,
        tasks_cancelled: 0,
        verdict: Verdict::Fail {
            reason: "1 tasks faulted".to_string(),
        },
    };
    let json = serde_json::to_string(&result).expect("serialize");
    let restored: LabRunResult = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(result, restored);
}

// ---------------------------------------------------------------------------
// Section 15: LabRuntime task lifecycle
// ---------------------------------------------------------------------------

#[test]
fn runtime_spawn_task_sequential_ids() {
    let mut rt = LabRuntime::new(0);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    let t3 = rt.spawn_task();
    assert_eq!(t1, 1);
    assert_eq!(t2, 2);
    assert_eq!(t3, 3);
}

#[test]
fn runtime_task_starts_ready() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    assert_eq!(rt.task_state(id), Some(TaskState::Ready));
}

#[test]
fn runtime_run_task_transitions_to_running() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    let state = rt.run_task(id);
    assert_eq!(state, Some(TaskState::Running));
    assert_eq!(rt.task_state(id), Some(TaskState::Running));
}

#[test]
fn runtime_complete_task_transitions_to_completed() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    assert!(rt.complete_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Completed));
}

#[test]
fn runtime_complete_ready_task_fails() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    assert!(!rt.complete_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Ready));
}

#[test]
fn runtime_complete_already_completed_task_fails() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.complete_task(id);
    assert!(!rt.complete_task(id));
}

#[test]
fn runtime_cancel_running_task() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    assert!(rt.cancel_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Cancelled));
}

#[test]
fn runtime_cancel_ready_task() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    assert!(rt.cancel_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Cancelled));
}

#[test]
fn runtime_cannot_cancel_completed_task() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.complete_task(id);
    assert!(!rt.cancel_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Completed));
}

#[test]
fn runtime_cannot_cancel_faulted_task() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.inject_fault(id, FaultKind::Panic);
    assert!(!rt.cancel_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
}

#[test]
fn runtime_run_task_nonexistent_returns_none() {
    let mut rt = LabRuntime::new(0);
    assert_eq!(rt.run_task(999), None);
}

#[test]
fn runtime_task_state_nonexistent_returns_none() {
    let rt = LabRuntime::new(0);
    assert_eq!(rt.task_state(999), None);
}

#[test]
fn runtime_run_completed_task_returns_completed() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.complete_task(id);
    // Running a completed task returns its current state
    let state = rt.run_task(id);
    assert_eq!(state, Some(TaskState::Completed));
}

#[test]
fn runtime_run_faulted_task_returns_faulted() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.inject_fault(id, FaultKind::Panic);
    let state = rt.run_task(id);
    assert_eq!(state, Some(TaskState::Faulted));
}

#[test]
fn runtime_run_cancelled_task_returns_cancelled() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.cancel_task(id);
    let state = rt.run_task(id);
    assert_eq!(state, Some(TaskState::Cancelled));
}

// ---------------------------------------------------------------------------
// Section 16: LabRuntime virtual time
// ---------------------------------------------------------------------------

#[test]
fn runtime_starts_at_time_zero() {
    let rt = LabRuntime::new(0);
    assert_eq!(rt.now(), 0);
}

#[test]
fn runtime_advance_time() {
    let mut rt = LabRuntime::new(0);
    rt.advance_time(100);
    assert_eq!(rt.now(), 100);
    rt.advance_time(50);
    assert_eq!(rt.now(), 150);
}

#[test]
fn runtime_advance_time_zero() {
    let mut rt = LabRuntime::new(0);
    rt.advance_time(0);
    assert_eq!(rt.now(), 0);
}

// ---------------------------------------------------------------------------
// Section 17: LabRuntime cancellation injection
// ---------------------------------------------------------------------------

#[test]
fn runtime_region_not_cancelled_by_default() {
    let rt = LabRuntime::new(0);
    assert!(!rt.is_region_cancelled("region-x"));
}

#[test]
fn runtime_inject_cancel_marks_region() {
    let mut rt = LabRuntime::new(0);
    rt.inject_cancel("region-a");
    assert!(rt.is_region_cancelled("region-a"));
    assert!(!rt.is_region_cancelled("region-b"));
}

#[test]
fn runtime_inject_cancel_multiple_regions() {
    let mut rt = LabRuntime::new(0);
    rt.inject_cancel("r1");
    rt.inject_cancel("r2");
    rt.inject_cancel("r3");
    assert!(rt.is_region_cancelled("r1"));
    assert!(rt.is_region_cancelled("r2"));
    assert!(rt.is_region_cancelled("r3"));
    assert!(!rt.is_region_cancelled("r4"));
}

#[test]
fn runtime_inject_cancel_idempotent() {
    let mut rt = LabRuntime::new(0);
    rt.inject_cancel("region-a");
    rt.inject_cancel("region-a");
    assert!(rt.is_region_cancelled("region-a"));
}

// ---------------------------------------------------------------------------
// Section 18: LabRuntime fault injection
// ---------------------------------------------------------------------------

#[test]
fn runtime_inject_fault_marks_task_faulted() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    assert!(rt.inject_fault(id, FaultKind::Panic));
    assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
}

#[test]
fn runtime_inject_fault_on_ready_task() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    assert!(rt.inject_fault(id, FaultKind::ChannelDisconnect));
    assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
}

#[test]
fn runtime_inject_fault_nonexistent_returns_false() {
    let mut rt = LabRuntime::new(0);
    assert!(!rt.inject_fault(999, FaultKind::Panic));
}

#[test]
fn runtime_inject_fault_all_kinds() {
    let kinds = [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let mut rt = LabRuntime::new(0);
        let id = rt.spawn_task();
        rt.run_task(id);
        assert!(
            rt.inject_fault(id, kind.clone()),
            "inject_fault failed for kind {i}"
        );
        assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
    }
}

// ---------------------------------------------------------------------------
// Section 19: LabRuntime task_count
// ---------------------------------------------------------------------------

#[test]
fn runtime_task_count_zero_initially() {
    let rt = LabRuntime::new(0);
    assert_eq!(rt.task_count(), 0);
}

#[test]
fn runtime_task_count_increments_on_spawn() {
    let mut rt = LabRuntime::new(0);
    rt.spawn_task();
    assert_eq!(rt.task_count(), 1);
    rt.spawn_task();
    rt.spawn_task();
    assert_eq!(rt.task_count(), 3);
}

// ---------------------------------------------------------------------------
// Section 20: LabRuntime finalize
// ---------------------------------------------------------------------------

#[test]
fn runtime_finalize_all_pass() {
    let mut rt = LabRuntime::new(42);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    rt.run_task(t1);
    rt.complete_task(t1);
    rt.run_task(t2);
    rt.complete_task(t2);
    rt.advance_time(100);

    let result = rt.finalize();
    assert_eq!(result.seed, 42);
    assert_eq!(result.final_time, 100);
    assert_eq!(result.tasks_completed, 2);
    assert_eq!(result.tasks_faulted, 0);
    assert_eq!(result.tasks_cancelled, 0);
    assert_eq!(result.verdict, Verdict::Pass);
}

#[test]
fn runtime_finalize_with_faults() {
    let mut rt = LabRuntime::new(7);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    rt.run_task(t1);
    rt.inject_fault(t1, FaultKind::Panic);
    rt.run_task(t2);
    rt.inject_fault(t2, FaultKind::DeadlineExpired);

    let result = rt.finalize();
    assert_eq!(result.tasks_faulted, 2);
    assert!(matches!(result.verdict, Verdict::Fail { .. }));
    if let Verdict::Fail { reason } = &result.verdict {
        assert!(reason.contains("2"), "reason should mention fault count");
    }
}

#[test]
fn runtime_finalize_mixed_states() {
    let mut rt = LabRuntime::new(0);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    let t3 = rt.spawn_task();

    rt.run_task(t1);
    rt.complete_task(t1);

    rt.run_task(t2);
    rt.inject_fault(t2, FaultKind::Panic);

    rt.run_task(t3);
    rt.cancel_task(t3);

    let result = rt.finalize();
    assert_eq!(result.tasks_completed, 1);
    assert_eq!(result.tasks_faulted, 1);
    assert_eq!(result.tasks_cancelled, 1);
    assert!(matches!(result.verdict, Verdict::Fail { .. }));
}

#[test]
fn runtime_finalize_empty_runtime() {
    let rt = LabRuntime::new(0);
    let result = rt.finalize();
    assert_eq!(result.tasks_completed, 0);
    assert_eq!(result.tasks_faulted, 0);
    assert_eq!(result.tasks_cancelled, 0);
    assert_eq!(result.verdict, Verdict::Pass);
    assert_eq!(result.final_time, 0);
    assert!(result.events.is_empty());
}

#[test]
fn runtime_finalize_with_cancelled_only() {
    let mut rt = LabRuntime::new(0);
    let t1 = rt.spawn_task();
    rt.cancel_task(t1);
    let result = rt.finalize();
    assert_eq!(result.tasks_cancelled, 1);
    assert_eq!(result.tasks_faulted, 0);
    assert_eq!(result.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// Section 21: LabRuntime transcript recording
// ---------------------------------------------------------------------------

#[test]
fn runtime_transcript_records_run_task() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    let result = rt.finalize();
    assert_eq!(result.transcript.len(), 1);
    assert!(matches!(
        result.transcript.actions[0],
        ScheduleAction::RunTask { task_id: 1 }
    ));
}

#[test]
fn runtime_transcript_records_advance_time() {
    let mut rt = LabRuntime::new(0);
    rt.advance_time(50);
    let result = rt.finalize();
    assert_eq!(result.transcript.len(), 1);
    assert!(matches!(
        result.transcript.actions[0],
        ScheduleAction::AdvanceTime { ticks: 50 }
    ));
}

#[test]
fn runtime_transcript_records_inject_cancel() {
    let mut rt = LabRuntime::new(0);
    rt.inject_cancel("region-z");
    let result = rt.finalize();
    assert_eq!(result.transcript.len(), 1);
    if let ScheduleAction::InjectCancel { region_id } = &result.transcript.actions[0] {
        assert_eq!(region_id, "region-z");
    } else {
        panic!("expected InjectCancel action");
    }
}

#[test]
fn runtime_transcript_records_inject_fault() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.inject_fault(id, FaultKind::ObligationLeak);
    let result = rt.finalize();
    assert_eq!(result.transcript.len(), 1);
    if let ScheduleAction::InjectFault { task_id, fault } = &result.transcript.actions[0] {
        assert_eq!(*task_id, id);
        assert_eq!(*fault, FaultKind::ObligationLeak);
    } else {
        panic!("expected InjectFault action");
    }
}

#[test]
fn runtime_transcript_preserves_seed() {
    let rt = LabRuntime::new(12345);
    let result = rt.finalize();
    assert_eq!(result.transcript.seed, 12345);
}

// ---------------------------------------------------------------------------
// Section 22: LabRuntime event emission
// ---------------------------------------------------------------------------

#[test]
fn runtime_events_have_correct_virtual_time() {
    let mut rt = LabRuntime::new(0);
    rt.advance_time(100);
    let id = rt.spawn_task();
    rt.run_task(id);

    let result = rt.finalize();
    // The run_task event should carry virtual_time 100
    let run_event = result
        .events
        .iter()
        .find(|e| e.action == "run_task")
        .unwrap();
    assert_eq!(run_event.virtual_time, 100);
}

#[test]
fn runtime_events_have_monotone_step_index() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.advance_time(10);
    rt.complete_task(id);

    let result = rt.finalize();
    for window in result.events.windows(2) {
        assert!(
            window[0].step_index < window[1].step_index,
            "step indices must be strictly increasing"
        );
    }
}

#[test]
fn runtime_events_start_at_step_index_one() {
    let mut rt = LabRuntime::new(0);
    rt.advance_time(1);
    let result = rt.finalize();
    assert_eq!(result.events[0].step_index, 1);
}

#[test]
fn runtime_events_carry_task_id_for_task_actions() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.complete_task(id);

    let result = rt.finalize();
    let run_event = result
        .events
        .iter()
        .find(|e| e.action == "run_task")
        .unwrap();
    assert_eq!(run_event.task_id, Some(id));

    let complete_event = result
        .events
        .iter()
        .find(|e| e.action == "complete_task")
        .unwrap();
    assert_eq!(complete_event.task_id, Some(id));
}

#[test]
fn runtime_events_carry_region_id_for_cancel() {
    let mut rt = LabRuntime::new(0);
    rt.inject_cancel("my-region");

    let result = rt.finalize();
    let cancel_event = result
        .events
        .iter()
        .find(|e| e.action == "inject_cancel")
        .unwrap();
    assert_eq!(cancel_event.region_id.as_deref(), Some("my-region"));
}

// ---------------------------------------------------------------------------
// Section 23: Deterministic replay - same runtime produces same events
// ---------------------------------------------------------------------------

#[test]
fn deterministic_replay_identical_runs() {
    let run = || {
        let mut rt = LabRuntime::new(42);
        let t1 = rt.spawn_task();
        let t2 = rt.spawn_task();
        let t3 = rt.spawn_task();

        rt.run_task(t1);
        rt.advance_time(10);
        rt.run_task(t2);
        rt.inject_cancel("region-alpha");
        rt.complete_task(t1);
        rt.advance_time(5);
        rt.run_task(t3);
        rt.inject_fault(t2, FaultKind::ChannelDisconnect);
        rt.complete_task(t3);
        rt.cancel_task(t3); // already completed, should not cancel
        rt.advance_time(20);

        rt.finalize()
    };

    let r1 = run();
    let r2 = run();

    assert_eq!(r1.events, r2.events, "events must be identical");
    assert_eq!(
        r1.transcript, r2.transcript,
        "transcripts must be identical"
    );
    assert_eq!(r1.verdict, r2.verdict, "verdicts must be identical");
    assert_eq!(
        r1.final_time, r2.final_time,
        "final times must be identical"
    );
    assert_eq!(r1.tasks_completed, r2.tasks_completed);
    assert_eq!(r1.tasks_faulted, r2.tasks_faulted);
    assert_eq!(r1.tasks_cancelled, r2.tasks_cancelled);
}

#[test]
fn different_seeds_produce_same_structure() {
    // Seeds don't affect deterministic behavior of the harness itself
    // but the result should record the correct seed
    let mut rt1 = LabRuntime::new(1);
    let mut rt2 = LabRuntime::new(2);

    let t1 = rt1.spawn_task();
    let t2 = rt2.spawn_task();

    rt1.run_task(t1);
    rt2.run_task(t2);

    let r1 = rt1.finalize();
    let r2 = rt2.finalize();

    assert_eq!(r1.seed, 1);
    assert_eq!(r2.seed, 2);
    // Same operations => same event structure
    assert_eq!(r1.events.len(), r2.events.len());
}

// ---------------------------------------------------------------------------
// Section 24: replay_transcript
// ---------------------------------------------------------------------------

#[test]
fn replay_transcript_produces_same_events() {
    let mut rt = LabRuntime::new(42);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    rt.run_task(t1);
    rt.advance_time(5);
    rt.run_task(t2);
    rt.inject_cancel("r1");
    let result = rt.finalize();

    let replayed = replay_transcript(&result.transcript);
    assert_eq!(result.events, replayed);
}

#[test]
fn replay_empty_transcript() {
    let transcript = ScheduleTranscript::new(0);
    let replayed = replay_transcript(&transcript);
    assert!(replayed.is_empty());
}

#[test]
fn replay_transcript_with_faults() {
    let mut rt = LabRuntime::new(77);
    let t1 = rt.spawn_task();
    rt.run_task(t1);
    rt.inject_fault(t1, FaultKind::DeadlineExpired);
    rt.advance_time(50);
    let result = rt.finalize();

    let replayed = replay_transcript(&result.transcript);
    assert_eq!(result.events, replayed);
}

#[test]
fn replay_transcript_with_cancel() {
    let mut rt = LabRuntime::new(88);
    let t1 = rt.spawn_task();
    rt.run_task(t1);
    rt.advance_time(10);
    rt.inject_cancel("zone-beta");
    rt.advance_time(20);
    let result = rt.finalize();

    let replayed = replay_transcript(&result.transcript);
    assert_eq!(result.events, replayed);
}

#[test]
fn replay_transcript_complex_sequence() {
    let mut rt = LabRuntime::new(55);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    let t3 = rt.spawn_task();

    rt.run_task(t1);
    rt.advance_time(10);
    rt.run_task(t2);
    rt.advance_time(5);
    rt.inject_cancel("r-alpha");
    rt.inject_fault(t3, FaultKind::ObligationLeak);
    rt.advance_time(100);

    let result = rt.finalize();
    let replayed = replay_transcript(&result.transcript);
    assert_eq!(result.events, replayed);
}

#[test]
fn replay_transcript_preserves_event_order() {
    let mut rt = LabRuntime::new(0);
    for _ in 0..5 {
        let id = rt.spawn_task();
        rt.run_task(id);
    }
    rt.advance_time(50);
    let result = rt.finalize();

    let replayed = replay_transcript(&result.transcript);
    for (orig, repl) in result.events.iter().zip(replayed.iter()) {
        assert_eq!(orig.step_index, repl.step_index);
        assert_eq!(orig.action, repl.action);
        assert_eq!(orig.virtual_time, repl.virtual_time);
    }
}

// ---------------------------------------------------------------------------
// Section 25: Verdict equality and patterns
// ---------------------------------------------------------------------------

#[test]
fn verdict_pass_equals_pass() {
    assert_eq!(Verdict::Pass, Verdict::Pass);
}

#[test]
fn verdict_fail_equals_same_reason() {
    let v1 = Verdict::Fail {
        reason: "x".to_string(),
    };
    let v2 = Verdict::Fail {
        reason: "x".to_string(),
    };
    assert_eq!(v1, v2);
}

#[test]
fn verdict_fail_not_equals_different_reason() {
    let v1 = Verdict::Fail {
        reason: "a".to_string(),
    };
    let v2 = Verdict::Fail {
        reason: "b".to_string(),
    };
    assert_ne!(v1, v2);
}

#[test]
fn verdict_pass_not_equals_fail() {
    assert_ne!(
        Verdict::Pass,
        Verdict::Fail {
            reason: "x".to_string()
        }
    );
}

// ---------------------------------------------------------------------------
// Section 26: Multiple task lifecycle interleaving
// ---------------------------------------------------------------------------

#[test]
fn interleaved_task_lifecycle() {
    let mut rt = LabRuntime::new(0);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    let t3 = rt.spawn_task();

    // Interleave operations
    rt.run_task(t1);
    rt.run_task(t2);
    rt.advance_time(10);
    rt.complete_task(t1);
    rt.run_task(t3);
    rt.inject_fault(t2, FaultKind::RegionClose);
    rt.advance_time(5);
    rt.complete_task(t3);

    let result = rt.finalize();
    assert_eq!(result.tasks_completed, 2); // t1, t3
    assert_eq!(result.tasks_faulted, 1); // t2
    assert_eq!(result.tasks_cancelled, 0);
    assert_eq!(result.final_time, 15);
}

#[test]
fn many_tasks_spawn_and_finalize() {
    let mut rt = LabRuntime::new(0);
    for _ in 0..50 {
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
    }
    let result = rt.finalize();
    assert_eq!(result.tasks_completed, 50);
    assert_eq!(result.verdict, Verdict::Pass);
}

// ---------------------------------------------------------------------------
// Section 27: Edge case - FireTimer action in transcript
// ---------------------------------------------------------------------------

#[test]
fn fire_timer_in_transcript_is_noop() {
    let mut transcript = ScheduleTranscript::new(0);
    transcript.push(ScheduleAction::FireTimer { timer_id: 1 });
    transcript.push(ScheduleAction::FireTimer { timer_id: 2 });

    let events = replay_transcript(&transcript);
    // FireTimer is a no-op in the basic harness, so no events should be emitted
    assert!(events.is_empty());
}

// ---------------------------------------------------------------------------
// Section 28: Serde roundtrip of full run result with events
// ---------------------------------------------------------------------------

#[test]
fn full_run_result_serde_roundtrip() {
    let mut rt = LabRuntime::new(42);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    rt.run_task(t1);
    rt.advance_time(100);
    rt.run_task(t2);
    rt.complete_task(t1);
    rt.inject_fault(t2, FaultKind::Panic);
    rt.advance_time(50);

    let result = rt.finalize();
    let json = serde_json::to_string(&result).expect("serialize full result");
    let restored: LabRunResult = serde_json::from_str(&json).expect("deserialize full result");
    assert_eq!(result, restored);
}

// ---------------------------------------------------------------------------
// Section 29: Debug impls
// ---------------------------------------------------------------------------

#[test]
fn virtual_clock_debug_output() {
    let clock = VirtualClock::new();
    let debug = format!("{clock:?}");
    assert!(debug.contains("VirtualClock"));
}

#[test]
fn lab_runtime_debug_output() {
    let rt = LabRuntime::new(42);
    let debug = format!("{rt:?}");
    assert!(debug.contains("LabRuntime"));
}

#[test]
fn schedule_transcript_debug_output() {
    let t = ScheduleTranscript::new(0);
    let debug = format!("{t:?}");
    assert!(debug.contains("ScheduleTranscript"));
}

// ---------------------------------------------------------------------------
// Section 30: Event outcome strings
// ---------------------------------------------------------------------------

#[test]
fn runtime_run_task_event_outcome_is_running() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    let result = rt.finalize();
    let event = result
        .events
        .iter()
        .find(|e| e.action == "run_task")
        .unwrap();
    assert_eq!(event.outcome, "running");
}

#[test]
fn runtime_complete_task_event_outcome_is_completed() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.complete_task(id);
    let result = rt.finalize();
    let event = result
        .events
        .iter()
        .find(|e| e.action == "complete_task")
        .unwrap();
    assert_eq!(event.outcome, "completed");
}

#[test]
fn runtime_cancel_task_event_outcome_is_cancelled() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.cancel_task(id);
    let result = rt.finalize();
    let event = result
        .events
        .iter()
        .find(|e| e.action == "cancel_task")
        .unwrap();
    assert_eq!(event.outcome, "cancelled");
}

#[test]
fn runtime_advance_time_event_outcome_contains_ticks() {
    let mut rt = LabRuntime::new(0);
    rt.advance_time(42);
    let result = rt.finalize();
    let event = result
        .events
        .iter()
        .find(|e| e.action == "advance_time")
        .unwrap();
    assert!(event.outcome.contains("42"));
}

#[test]
fn runtime_inject_fault_event_outcome_contains_fault_kind() {
    let mut rt = LabRuntime::new(0);
    let id = rt.spawn_task();
    rt.inject_fault(id, FaultKind::ObligationLeak);
    let result = rt.finalize();
    let event = result
        .events
        .iter()
        .find(|e| e.action == "inject_fault")
        .unwrap();
    assert!(event.outcome.contains("obligation_leak"));
}

#[test]
fn runtime_inject_cancel_event_outcome_is_cancel_injected() {
    let mut rt = LabRuntime::new(0);
    rt.inject_cancel("region-x");
    let result = rt.finalize();
    let event = result
        .events
        .iter()
        .find(|e| e.action == "inject_cancel")
        .unwrap();
    assert_eq!(event.outcome, "cancel_injected");
}
