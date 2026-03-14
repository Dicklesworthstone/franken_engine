//! Enrichment integration tests for deterministic_sim_scheduler (RGC-803C).
//!
//! Covers: fast-forward scheduling, GC interval interaction, per-tick limit
//! requeue semantics, replay log construction, summary statistics,
//! Display/serde roundtrips for composite scenarios, and edge cases.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::deterministic_sim_scheduler::{
    SIM_SCHEDULER_BEAD_ID, SIM_SCHEDULER_SCHEMA_VERSION, SchedulerPolicy, SimEventKind,
    SimPriority, SimReplayEntry, SimReplayLog, SimRunSummary, SimScheduler, SimSpecimenFamily,
    TickOutcome,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_scheduler() -> SimScheduler {
    SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::from_raw(1))
}

fn small_scheduler(max_ticks: u64, max_events: u64) -> SimScheduler {
    let policy = SchedulerPolicy {
        max_ticks,
        max_events_per_tick: max_events,
        drain_microtasks_first: true,
        gc_interval_ticks: 0,
        enable_timer_coalescing: false,
        deterministic_tie_break: true,
    };
    SimScheduler::new(policy, SecurityEpoch::from_raw(1))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_contains_sim_scheduler() {
    assert!(SIM_SCHEDULER_SCHEMA_VERSION.contains("sim-scheduler"));
}

#[test]
fn bead_id_matches_expected() {
    assert_eq!(SIM_SCHEDULER_BEAD_ID, "bd-1lsy.9.3.3");
}

// ---------------------------------------------------------------------------
// SimEventKind properties
// ---------------------------------------------------------------------------

#[test]
fn sim_event_kind_all_as_str_nonempty() {
    for kind in &SimEventKind::ALL {
        assert!(!kind.as_str().is_empty(), "empty as_str for {:?}", kind);
    }
}

#[test]
fn sim_event_kind_display_matches_as_str() {
    for kind in &SimEventKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str(), "mismatch for {:?}", kind);
    }
}

#[test]
fn sim_event_kind_serde_roundtrip_preserves_all() {
    for kind in &SimEventKind::ALL {
        let json = serde_json::to_string(kind).expect("serialize");
        let deser: SimEventKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*kind, deser, "roundtrip failed for {:?}", kind);
    }
}

// ---------------------------------------------------------------------------
// SimPriority properties
// ---------------------------------------------------------------------------

#[test]
fn sim_priority_all_as_str_nonempty() {
    for p in &SimPriority::ALL {
        assert!(!p.as_str().is_empty(), "empty as_str for {:?}", p);
    }
}

#[test]
fn sim_priority_display_matches_as_str() {
    for p in &SimPriority::ALL {
        assert_eq!(p.to_string(), p.as_str(), "mismatch for {:?}", p);
    }
}

#[test]
fn sim_priority_microtask_is_highest() {
    assert!(SimPriority::Microtask < SimPriority::HighPriority);
    assert!(SimPriority::Microtask < SimPriority::Idle);
}

#[test]
fn sim_priority_idle_is_lowest() {
    assert!(SimPriority::Idle > SimPriority::LowPriority);
    assert!(SimPriority::Idle > SimPriority::Microtask);
}

// ---------------------------------------------------------------------------
// SimSpecimenFamily properties
// ---------------------------------------------------------------------------

#[test]
fn sim_specimen_family_display_matches_as_str() {
    let families = [
        SimSpecimenFamily::EventLoopDrain,
        SimSpecimenFamily::ModuleLifecycle,
        SimSpecimenFamily::CacheInteraction,
        SimSpecimenFamily::ControllerFeedback,
        SimSpecimenFamily::TimerCoalescing,
        SimSpecimenFamily::MixedPriority,
    ];
    for f in &families {
        assert_eq!(f.to_string(), f.as_str(), "mismatch for {:?}", f);
    }
}

#[test]
fn sim_specimen_family_serde_roundtrip_all() {
    let families = [
        SimSpecimenFamily::EventLoopDrain,
        SimSpecimenFamily::ModuleLifecycle,
        SimSpecimenFamily::CacheInteraction,
        SimSpecimenFamily::ControllerFeedback,
        SimSpecimenFamily::TimerCoalescing,
        SimSpecimenFamily::MixedPriority,
    ];
    for f in &families {
        let json = serde_json::to_string(f).expect("serialize");
        let deser: SimSpecimenFamily = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(*f, deser, "roundtrip failed for {:?}", f);
    }
}

// ---------------------------------------------------------------------------
// Scheduler scheduling and dispatch
// ---------------------------------------------------------------------------

#[test]
fn schedule_returns_incrementing_ids_from_zero() {
    let mut s = default_scheduler();
    let id0 = s.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "test", 0);
    let id1 = s.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "test", 0);
    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
}

#[test]
fn schedule_with_delay_targets_future_tick() {
    let mut s = default_scheduler();
    s.schedule(SimEventKind::TimerFire, SimPriority::Normal, 5, "timer", 0);
    assert_eq!(s.pending_count(), 1);

    // Advancing tick 0 should dispatch nothing (event is at tick 5)
    let outcome = s.advance_tick().expect("advance tick 0");
    assert!(outcome.events_dispatched.is_empty());
}

#[test]
fn advance_tick_dispatches_microtasks_first_when_enabled() {
    let mut s = small_scheduler(10, 100);
    // Schedule a low-priority event first, then a microtask
    s.schedule(SimEventKind::CacheHit, SimPriority::LowPriority, 0, "lo", 0);
    s.schedule(
        SimEventKind::MicrotaskDrain,
        SimPriority::Microtask,
        0,
        "hi",
        0,
    );

    let outcome = s.advance_tick().expect("advance");
    // Microtask (id=1) should be dispatched before low-priority (id=0)
    assert_eq!(outcome.events_dispatched, vec![1, 0]);
    assert_eq!(outcome.microtasks_drained, 1);
}

#[test]
fn advance_tick_requeues_excess_events() {
    let mut s = small_scheduler(10, 2); // Max 2 events per tick
    for i in 0..5 {
        s.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "ev", i);
    }
    assert_eq!(s.pending_count(), 5);

    let outcome = s.advance_tick().expect("advance");
    assert_eq!(outcome.events_dispatched.len(), 2); // Only 2 dispatched
    assert_eq!(s.pending_count(), 3); // 3 re-queued
}

#[test]
fn run_to_completion_with_sparse_ticks_fast_forwards() {
    let mut s = small_scheduler(1000, 10);
    // Schedule events at tick 0, 500, and 999
    s.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "t0", 0);
    s.schedule(
        SimEventKind::ModuleLoad,
        SimPriority::Normal,
        500,
        "t500",
        0,
    );
    s.schedule(
        SimEventKind::GcPause,
        SimPriority::LowPriority,
        999,
        "t999",
        0,
    );

    let summary = s.run_to_completion();
    assert_eq!(summary.total_events, 3);
    // Should not have iterated through all 1000 ticks
    assert!(summary.total_ticks < 1000);
}

#[test]
fn run_to_completion_empty_scheduler() {
    let mut s = default_scheduler();
    let summary = s.run_to_completion();
    assert_eq!(summary.total_ticks, 0);
    assert_eq!(summary.total_events, 0);
    assert!(summary.events_by_kind.is_empty());
}

#[test]
fn run_to_completion_summary_events_by_kind_correct() {
    let mut s = small_scheduler(10, 100);
    s.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "ch", 0);
    s.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "ch", 0);
    s.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "cm", 0);

    let summary = s.run_to_completion();
    assert_eq!(*summary.events_by_kind.get("cache_hit").unwrap_or(&0), 2);
    assert_eq!(*summary.events_by_kind.get("cache_miss").unwrap_or(&0), 1);
}

#[test]
fn run_to_completion_summary_events_by_priority_correct() {
    let mut s = small_scheduler(10, 100);
    s.schedule(SimEventKind::CacheHit, SimPriority::Microtask, 0, "mt", 0);
    s.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "n", 0);
    s.schedule(SimEventKind::CacheEvict, SimPriority::Normal, 0, "n", 0);

    let summary = s.run_to_completion();
    assert_eq!(
        *summary.events_by_priority.get("microtask").unwrap_or(&0),
        1
    );
    assert_eq!(*summary.events_by_priority.get("normal").unwrap_or(&0), 2);
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn content_hash_deterministic_across_runs() {
    let build = || {
        let mut s = small_scheduler(10, 100);
        s.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
        s.schedule(SimEventKind::CacheHit, SimPriority::HighPriority, 0, "b", 2);
        s.run_to_completion();
        s.content_hash()
    };
    assert_eq!(build(), build());
}

#[test]
fn content_hash_differs_for_different_events() {
    let build = |kind: SimEventKind| {
        let mut s = small_scheduler(10, 100);
        s.schedule(kind, SimPriority::Normal, 0, "x", 0);
        s.run_to_completion();
        s.content_hash()
    };
    assert_ne!(
        build(SimEventKind::CacheHit),
        build(SimEventKind::CacheMiss)
    );
}

// ---------------------------------------------------------------------------
// Replay log
// ---------------------------------------------------------------------------

#[test]
fn replay_log_empty_is_empty() {
    let log = SimReplayLog::default();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn replay_log_push_increments_len() {
    let mut log = SimReplayLog::default();
    log.push(SimReplayEntry {
        tick: 0,
        event_id: 0,
        kind: SimEventKind::EventLoopTick,
        priority: SimPriority::Normal,
    });
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());
}

#[test]
fn replay_log_content_hash_deterministic() {
    let build = || {
        let mut log = SimReplayLog::default();
        log.push(SimReplayEntry {
            tick: 0,
            event_id: 0,
            kind: SimEventKind::CacheHit,
            priority: SimPriority::Normal,
        });
        log.push(SimReplayEntry {
            tick: 1,
            event_id: 1,
            kind: SimEventKind::CacheMiss,
            priority: SimPriority::LowPriority,
        });
        log.content_hash()
    };
    assert_eq!(build(), build());
}

#[test]
fn replay_log_serde_roundtrip() {
    let mut log = SimReplayLog::default();
    log.push(SimReplayEntry {
        tick: 5,
        event_id: 42,
        kind: SimEventKind::HostcallInvoke,
        priority: SimPriority::HighPriority,
    });
    let json = serde_json::to_string(&log).expect("serialize");
    let deser: SimReplayLog = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(log.entries, deser.entries);
}

// ---------------------------------------------------------------------------
// TickOutcome serde
// ---------------------------------------------------------------------------

#[test]
fn tick_outcome_serde_preserves_all_fields() {
    let outcome = TickOutcome {
        tick: 7,
        events_dispatched: vec![0, 1, 2],
        microtasks_drained: 1,
        pending_count: 3,
    };
    let json = serde_json::to_string(&outcome).expect("serialize");
    let deser: TickOutcome = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(outcome, deser);
}

// ---------------------------------------------------------------------------
// SimRunSummary serde
// ---------------------------------------------------------------------------

#[test]
fn sim_run_summary_serde_roundtrip() {
    let mut s = small_scheduler(10, 100);
    s.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 0);
    s.schedule(SimEventKind::GcPause, SimPriority::LowPriority, 1, "gc", 0);
    let summary = s.run_to_completion();

    let json = serde_json::to_string(&summary).expect("serialize");
    let deser: SimRunSummary = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(summary.total_ticks, deser.total_ticks);
    assert_eq!(summary.total_events, deser.total_events);
    assert_eq!(summary.events_by_kind, deser.events_by_kind);
}

// ---------------------------------------------------------------------------
// SchedulerPolicy defaults
// ---------------------------------------------------------------------------

#[test]
fn default_policy_drains_microtasks_first() {
    let policy = SchedulerPolicy::default();
    assert!(policy.drain_microtasks_first);
}

#[test]
fn default_policy_deterministic_tie_break_enabled() {
    let policy = SchedulerPolicy::default();
    assert!(policy.deterministic_tie_break);
}

#[test]
fn default_policy_max_ticks_reasonable() {
    let policy = SchedulerPolicy::default();
    assert!(policy.max_ticks >= 100);
    assert!(policy.max_ticks <= 100_000);
}

// ---------------------------------------------------------------------------
// Scheduler state after operations
// ---------------------------------------------------------------------------

#[test]
fn total_dispatched_accumulates_across_ticks() {
    let mut s = small_scheduler(10, 100);
    s.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 0);
    s.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 1, "b", 0);

    s.advance_tick(); // tick 0: dispatches 1
    assert_eq!(s.total_dispatched(), 1);

    s.advance_tick(); // tick 1: dispatches 1
    assert_eq!(s.total_dispatched(), 2);
}

#[test]
fn scheduler_epoch_preserved() {
    let epoch = SecurityEpoch::from_raw(42);
    let s = SimScheduler::new(SchedulerPolicy::default(), epoch);
    assert_eq!(s.epoch.as_u64(), 42);
}

#[test]
fn scheduler_serde_roundtrip_preserves_state() {
    let mut s = small_scheduler(100, 50);
    s.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 0);
    s.advance_tick();

    let json = serde_json::to_string(&s).expect("serialize");
    let deser: SimScheduler = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(s.current_tick, deser.current_tick);
    assert_eq!(s.next_event_id, deser.next_event_id);
    assert_eq!(s.dispatch_log.len(), deser.dispatch_log.len());
}

// ---------------------------------------------------------------------------
// Disabled microtask drain mode
// ---------------------------------------------------------------------------

#[test]
fn microtask_drain_disabled_still_dispatches_all() {
    let policy = SchedulerPolicy {
        max_ticks: 10,
        max_events_per_tick: 100,
        drain_microtasks_first: false,
        gc_interval_ticks: 0,
        enable_timer_coalescing: false,
        deterministic_tie_break: true,
    };
    let mut s = SimScheduler::new(policy, SecurityEpoch::from_raw(1));
    s.schedule(
        SimEventKind::MicrotaskDrain,
        SimPriority::Microtask,
        0,
        "mt",
        0,
    );
    s.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "ch", 0);

    let outcome = s.advance_tick().expect("advance");
    assert_eq!(outcome.events_dispatched.len(), 2);
    assert_eq!(outcome.microtasks_drained, 1);
}
