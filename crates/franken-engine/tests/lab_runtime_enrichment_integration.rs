//! Enrichment integration tests for `lab_runtime`.
//!
//! Covers: VirtualClock deterministic time, LabRuntime task lifecycle
//! (spawn/run/complete/cancel/fault), ScheduleTranscript recording,
//! deterministic replay, FaultKind all variants, TaskState transitions,
//! Verdict pass/fail, LabRunResult finalization, LabEvent virtual-time
//! correlation, ScheduleAction serde, replay_transcript equivalence,
//! boundary conditions, and full lifecycle scenarios.

#![allow(clippy::too_many_arguments)]

use frankenengine_engine::lab_runtime::{
    FaultKind, LabEvent, LabRunResult, LabRuntime, ScheduleAction, ScheduleTranscript, TaskState,
    Verdict, VirtualClock, replay_transcript,
};

// ===========================================================================
// VirtualClock tests
// ===========================================================================

#[test]
fn integ_clock_starts_at_zero() {
    let clock = VirtualClock::new();
    assert_eq!(clock.now(), 0);
}

#[test]
fn integ_clock_default_starts_at_zero() {
    let clock = VirtualClock::default();
    assert_eq!(clock.now(), 0);
}

#[test]
fn integ_clock_advance_cumulative() {
    let mut clock = VirtualClock::new();
    clock.advance(100);
    clock.advance(50);
    clock.advance(25);
    assert_eq!(clock.now(), 175);
}

#[test]
fn integ_clock_advance_zero_noop() {
    let mut clock = VirtualClock::new();
    clock.advance(100);
    clock.advance(0);
    assert_eq!(clock.now(), 100);
}

#[test]
fn integ_clock_advance_to_forward() {
    let mut clock = VirtualClock::new();
    assert!(clock.advance_to(500));
    assert_eq!(clock.now(), 500);
}

#[test]
fn integ_clock_advance_to_same() {
    let mut clock = VirtualClock::new();
    clock.advance(50);
    assert!(clock.advance_to(50));
    assert_eq!(clock.now(), 50);
}

#[test]
fn integ_clock_advance_to_backward_fails() {
    let mut clock = VirtualClock::new();
    clock.advance(500);
    assert!(!clock.advance_to(100));
    assert_eq!(clock.now(), 500);
}

#[test]
fn integ_clock_serde_roundtrip() {
    let mut clock = VirtualClock::new();
    clock.advance(42);
    let json = serde_json::to_string(&clock).unwrap();
    let back: VirtualClock = serde_json::from_str(&json).unwrap();
    assert_eq!(clock, back);
}

#[test]
fn integ_clock_clone_independence() {
    let mut a = VirtualClock::new();
    a.advance(100);
    let mut b = a.clone();
    b.advance(50);
    assert_eq!(a.now(), 100);
    assert_eq!(b.now(), 150);
}

// ===========================================================================
// Task lifecycle tests
// ===========================================================================

#[test]
fn integ_spawn_sequential_ids() {
    let mut rt = LabRuntime::new(0);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    let t3 = rt.spawn_task();
    assert_eq!(t1, 1);
    assert_eq!(t2, 2);
    assert_eq!(t3, 3);
    assert_eq!(rt.task_count(), 3);
}

#[test]
fn integ_task_spawn_to_complete() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    assert_eq!(rt.task_state(id), Some(TaskState::Ready));
    rt.run_task(id);
    assert_eq!(rt.task_state(id), Some(TaskState::Running));
    assert!(rt.complete_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Completed));
}

#[test]
fn integ_task_spawn_to_cancel() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.run_task(id);
    assert!(rt.cancel_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Cancelled));
}

#[test]
fn integ_task_spawn_to_fault() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    assert!(rt.inject_fault(id, FaultKind::Panic));
    assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
}

#[test]
fn integ_complete_non_running_fails() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    assert!(!rt.complete_task(id)); // Ready, not Running
}

#[test]
fn integ_cancel_completed_fails() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.complete_task(id);
    assert!(!rt.cancel_task(id));
}

#[test]
fn integ_cancel_faulted_fails() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.inject_fault(id, FaultKind::Panic);
    assert!(!rt.cancel_task(id));
}

#[test]
fn integ_cancel_ready_succeeds() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    assert!(rt.cancel_task(id));
    assert_eq!(rt.task_state(id), Some(TaskState::Cancelled));
}

#[test]
fn integ_run_completed_returns_completed() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.complete_task(id);
    assert_eq!(rt.run_task(id), Some(TaskState::Completed));
}

#[test]
fn integ_run_faulted_returns_faulted() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.inject_fault(id, FaultKind::Panic);
    assert_eq!(rt.run_task(id), Some(TaskState::Faulted));
}

#[test]
fn integ_run_nonexistent_returns_none() {
    let mut rt = LabRuntime::new(42);
    assert!(rt.run_task(999).is_none());
}

#[test]
fn integ_task_state_nonexistent_returns_none() {
    let rt = LabRuntime::new(42);
    assert!(rt.task_state(999).is_none());
}

#[test]
fn integ_fault_nonexistent_returns_false() {
    let mut rt = LabRuntime::new(42);
    assert!(!rt.inject_fault(999, FaultKind::Panic));
}

// ===========================================================================
// Virtual time tests
// ===========================================================================

#[test]
fn integ_runtime_time_advances() {
    let mut rt = LabRuntime::new(0);
    assert_eq!(rt.now(), 0);
    rt.advance_time(100);
    rt.advance_time(50);
    assert_eq!(rt.now(), 150);
}

// ===========================================================================
// Region cancellation tests
// ===========================================================================

#[test]
fn integ_region_cancel_independent() {
    let mut rt = LabRuntime::new(42);
    rt.inject_cancel("region-a");
    rt.inject_cancel("region-b");
    assert!(rt.is_region_cancelled("region-a"));
    assert!(rt.is_region_cancelled("region-b"));
    assert!(!rt.is_region_cancelled("region-c"));
}

#[test]
fn integ_region_cancel_persists() {
    let mut rt = LabRuntime::new(42);
    rt.inject_cancel("r1");
    assert!(rt.is_region_cancelled("r1"));
    assert!(rt.is_region_cancelled("r1")); // still true
}

// ===========================================================================
// Fault injection - all kinds
// ===========================================================================

#[test]
fn integ_fault_all_kinds() {
    for fault in [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ] {
        let mut rt = LabRuntime::new(42);
        let id = rt.spawn_task();
        assert!(rt.inject_fault(id, fault));
        assert_eq!(rt.task_state(id), Some(TaskState::Faulted));
    }
}

// ===========================================================================
// Finalization / Verdict tests
// ===========================================================================

#[test]
fn integ_finalize_no_tasks_pass() {
    let rt = LabRuntime::new(42);
    let result = rt.finalize();
    assert_eq!(result.verdict, Verdict::Pass);
    assert_eq!(result.tasks_completed, 0);
    assert_eq!(result.tasks_faulted, 0);
    assert_eq!(result.tasks_cancelled, 0);
    assert_eq!(result.seed, 42);
}

#[test]
fn integ_finalize_all_completed_pass() {
    let mut rt = LabRuntime::new(42);
    for _ in 0..3 {
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
    }
    let result = rt.finalize();
    assert_eq!(result.verdict, Verdict::Pass);
    assert_eq!(result.tasks_completed, 3);
}

#[test]
fn integ_finalize_faulted_fail() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.inject_fault(id, FaultKind::Panic);
    let result = rt.finalize();
    assert!(matches!(result.verdict, Verdict::Fail { .. }));
    assert_eq!(result.tasks_faulted, 1);
}

#[test]
fn integ_finalize_mixed_states() {
    let mut rt = LabRuntime::new(42);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    let t3 = rt.spawn_task();
    rt.run_task(t1);
    rt.complete_task(t1);
    rt.cancel_task(t2);
    rt.inject_fault(t3, FaultKind::Panic);
    let result = rt.finalize();
    assert_eq!(result.tasks_completed, 1);
    assert_eq!(result.tasks_cancelled, 1);
    assert_eq!(result.tasks_faulted, 1);
    assert!(matches!(result.verdict, Verdict::Fail { .. }));
}

#[test]
fn integ_finalize_final_time() {
    let mut rt = LabRuntime::new(42);
    rt.advance_time(100);
    rt.advance_time(200);
    let result = rt.finalize();
    assert_eq!(result.final_time, 300);
}

#[test]
fn integ_finalize_seed_preserved() {
    let rt = LabRuntime::new(12345);
    assert_eq!(rt.finalize().seed, 12345);
}

// ===========================================================================
// Event tests
// ===========================================================================

#[test]
fn integ_events_carry_virtual_time() {
    let mut rt = LabRuntime::new(42);
    rt.advance_time(100);
    let id = rt.spawn_task();
    rt.run_task(id);
    let result = rt.finalize();
    let run_event = result
        .events
        .iter()
        .find(|e| e.action == "run_task")
        .unwrap();
    assert_eq!(run_event.virtual_time, 100);
}

#[test]
fn integ_events_monotone_step_index() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.advance_time(10);
    rt.complete_task(id);
    let result = rt.finalize();
    for window in result.events.windows(2) {
        assert!(window[0].step_index < window[1].step_index);
    }
}

#[test]
fn integ_events_step_index_starts_at_one() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.run_task(id);
    let result = rt.finalize();
    assert_eq!(result.events[0].step_index, 1);
}

// ===========================================================================
// Transcript / Replay tests
// ===========================================================================

#[test]
fn integ_transcript_records_actions() {
    let mut rt = LabRuntime::new(42);
    let id = rt.spawn_task();
    rt.run_task(id);
    rt.advance_time(10);
    rt.inject_cancel("r");
    let result = rt.finalize();
    assert_eq!(result.transcript.len(), 3);
    assert_eq!(result.transcript.seed, 42);
}

#[test]
fn integ_replay_produces_identical_events() {
    let run = || {
        let mut rt = LabRuntime::new(42);
        let t1 = rt.spawn_task();
        let t2 = rt.spawn_task();
        rt.run_task(t1);
        rt.advance_time(10);
        rt.run_task(t2);
        rt.inject_cancel("region-a");
        rt.advance_time(5);
        rt.inject_fault(t2, FaultKind::ChannelDisconnect);
        rt.finalize()
    };
    let r1 = run();
    let r2 = run();
    assert_eq!(r1.events, r2.events);
    assert_eq!(r1.transcript, r2.transcript);
}

#[test]
fn integ_replay_transcript_matches_original() {
    let mut rt = LabRuntime::new(99);
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
fn integ_replay_with_faults_deterministic() {
    let mut rt = LabRuntime::new(77);
    let t1 = rt.spawn_task();
    let t2 = rt.spawn_task();
    rt.run_task(t1);
    rt.advance_time(10);
    rt.inject_fault(t2, FaultKind::ObligationLeak);
    rt.inject_cancel("region-x");
    let result = rt.finalize();
    let replayed = replay_transcript(&result.transcript);
    assert_eq!(result.events, replayed);
}

#[test]
fn integ_replay_empty_transcript() {
    let transcript = ScheduleTranscript::new(42);
    let events = replay_transcript(&transcript);
    assert!(events.is_empty());
}

#[test]
fn integ_replay_fire_timer_noop() {
    let mut transcript = ScheduleTranscript::new(42);
    transcript.push(ScheduleAction::FireTimer { timer_id: 99 });
    let events = replay_transcript(&transcript);
    assert!(events.is_empty());
}

#[test]
fn integ_replay_advance_time_only() {
    let mut transcript = ScheduleTranscript::new(55);
    transcript.push(ScheduleAction::AdvanceTime { ticks: 10 });
    transcript.push(ScheduleAction::AdvanceTime { ticks: 20 });
    transcript.push(ScheduleAction::AdvanceTime { ticks: 30 });
    let events = replay_transcript(&transcript);
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].virtual_time, 10);
    assert_eq!(events[1].virtual_time, 30);
    assert_eq!(events[2].virtual_time, 60);
}

// ===========================================================================
// Serde round-trip tests
// ===========================================================================

#[test]
fn integ_fault_kind_serde_all() {
    for kind in [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let back: FaultKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

#[test]
fn integ_task_state_serde_all() {
    for state in [
        TaskState::Ready,
        TaskState::Running,
        TaskState::Completed,
        TaskState::Faulted,
        TaskState::Cancelled,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: TaskState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }
}

#[test]
fn integ_schedule_action_serde_all() {
    let actions = vec![
        ScheduleAction::RunTask { task_id: 1 },
        ScheduleAction::AdvanceTime { ticks: 100 },
        ScheduleAction::InjectCancel {
            region_id: "r".to_string(),
        },
        ScheduleAction::InjectFault {
            task_id: 2,
            fault: FaultKind::ObligationLeak,
        },
        ScheduleAction::FireTimer { timer_id: 42 },
    ];
    for action in &actions {
        let json = serde_json::to_string(action).unwrap();
        let back: ScheduleAction = serde_json::from_str(&json).unwrap();
        assert_eq!(*action, back);
    }
}

#[test]
fn integ_schedule_transcript_serde_roundtrip() {
    let mut t = ScheduleTranscript::new(42);
    t.push(ScheduleAction::RunTask { task_id: 1 });
    t.push(ScheduleAction::AdvanceTime { ticks: 10 });
    let json = serde_json::to_string(&t).unwrap();
    let back: ScheduleTranscript = serde_json::from_str(&json).unwrap();
    assert_eq!(t, back);
}

#[test]
fn integ_verdict_serde_roundtrip() {
    for v in [
        Verdict::Pass,
        Verdict::Fail {
            reason: "test failure".into(),
        },
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn integ_lab_event_serde_roundtrip() {
    let event = LabEvent {
        virtual_time: 1000,
        step_index: 5,
        action: "run_task".to_string(),
        task_id: Some(42),
        region_id: None,
        outcome: "running".to_string(),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LabEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn integ_lab_run_result_serde_roundtrip() {
    let result = LabRunResult {
        seed: 42,
        transcript: ScheduleTranscript::new(42),
        events: Vec::new(),
        final_time: 100,
        tasks_completed: 1,
        tasks_faulted: 0,
        tasks_cancelled: 0,
        verdict: Verdict::Pass,
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: LabRunResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

// ===========================================================================
// Display tests
// ===========================================================================

#[test]
fn integ_fault_kind_display_all_unique() {
    let mut displays = std::collections::BTreeSet::new();
    for kind in [
        FaultKind::Panic,
        FaultKind::ChannelDisconnect,
        FaultKind::ObligationLeak,
        FaultKind::DeadlineExpired,
        FaultKind::RegionClose,
    ] {
        displays.insert(kind.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn integ_task_state_display_all_unique() {
    let mut displays = std::collections::BTreeSet::new();
    for state in [
        TaskState::Ready,
        TaskState::Running,
        TaskState::Completed,
        TaskState::Faulted,
        TaskState::Cancelled,
    ] {
        displays.insert(state.to_string());
    }
    assert_eq!(displays.len(), 5);
}

#[test]
fn integ_verdict_display_pass() {
    assert_eq!(Verdict::Pass.to_string(), "PASS");
}

#[test]
fn integ_verdict_display_fail_contains_reason() {
    let v = Verdict::Fail {
        reason: "2 tasks faulted".into(),
    };
    assert_eq!(v.to_string(), "FAIL: 2 tasks faulted");
}

// ===========================================================================
// Stress / boundary tests
// ===========================================================================

#[test]
fn integ_many_tasks_stress() {
    let mut rt = LabRuntime::new(42);
    for _ in 0..100 {
        let id = rt.spawn_task();
        rt.run_task(id);
        rt.complete_task(id);
    }
    let result = rt.finalize();
    assert_eq!(result.tasks_completed, 100);
    assert_eq!(result.verdict, Verdict::Pass);
}

#[test]
fn integ_many_tasks_mixed_outcomes() {
    let mut rt = LabRuntime::new(42);
    let mut ids = Vec::new();
    for _ in 0..90 {
        ids.push(rt.spawn_task());
    }
    for (i, &id) in ids.iter().enumerate() {
        rt.run_task(id);
        if i < 30 {
            rt.complete_task(id);
        } else if i < 60 {
            rt.inject_fault(id, FaultKind::ObligationLeak);
        } else {
            rt.cancel_task(id);
        }
    }
    let result = rt.finalize();
    assert_eq!(result.tasks_completed, 30);
    assert_eq!(result.tasks_faulted, 30);
    assert_eq!(result.tasks_cancelled, 30);
}

#[test]
fn integ_transcript_is_empty_on_new() {
    let t = ScheduleTranscript::new(0);
    assert!(t.is_empty());
    assert_eq!(t.len(), 0);
}

#[test]
fn integ_lab_run_result_json_fields() {
    let result = LabRunResult {
        seed: 7,
        transcript: ScheduleTranscript::new(7),
        events: Vec::new(),
        final_time: 42,
        tasks_completed: 3,
        tasks_faulted: 1,
        tasks_cancelled: 2,
        verdict: Verdict::Pass,
    };
    let val: serde_json::Value = serde_json::to_value(&result).unwrap();
    let obj = val.as_object().unwrap();
    assert!(obj.contains_key("seed"));
    assert!(obj.contains_key("transcript"));
    assert!(obj.contains_key("events"));
    assert!(obj.contains_key("final_time"));
    assert!(obj.contains_key("tasks_completed"));
    assert!(obj.contains_key("tasks_faulted"));
    assert!(obj.contains_key("tasks_cancelled"));
    assert!(obj.contains_key("verdict"));
}
