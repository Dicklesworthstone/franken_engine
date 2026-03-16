//! Integration tests for the `deterministic_sim_scheduler` module.
//!
//! Covers all public enums (Display + serde roundtrip), struct construction,
//! key methods (schedule, advance_tick, run_to_completion), replay log,
//! content hashing determinism, and edge cases.

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

use frankenengine_engine::deterministic_sim_scheduler::*;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_scheduler() -> SimScheduler {
    SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS)
}

fn small_policy(max_ticks: u64, max_events: u64) -> SchedulerPolicy {
    SchedulerPolicy {
        max_ticks,
        max_events_per_tick: max_events,
        ..SchedulerPolicy::default()
    }
}

// ---------------------------------------------------------------------------
// SimEventKind
// ---------------------------------------------------------------------------

#[test]
fn sim_event_kind_display_all() {
    let expected = [
        "event_loop_tick",
        "module_load",
        "module_resolve",
        "cache_hit",
        "cache_miss",
        "cache_evict",
        "controller_decision",
        "timer_fire",
        "microtask_drain",
        "promise_settle",
        "gc_pause",
        "hostcall_invoke",
    ];
    for (kind, exp) in SimEventKind::ALL.iter().zip(expected.iter()) {
        assert_eq!(kind.to_string(), *exp);
    }
}

#[test]
fn sim_event_kind_serde_roundtrip_all() {
    for kind in &SimEventKind::ALL {
        let json = serde_json::to_string(kind).unwrap();
        let back: SimEventKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back);
    }
}

#[test]
fn sim_event_kind_all_count() {
    assert_eq!(SimEventKind::ALL.len(), 12);
}

#[test]
fn sim_event_kind_as_str_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for kind in &SimEventKind::ALL {
        assert!(seen.insert(kind.as_str()), "duplicate: {}", kind.as_str());
    }
}

// ---------------------------------------------------------------------------
// SimPriority
// ---------------------------------------------------------------------------

#[test]
fn sim_priority_display_all() {
    let expected = [
        "microtask",
        "high_priority",
        "normal",
        "low_priority",
        "idle",
    ];
    for (p, exp) in SimPriority::ALL.iter().zip(expected.iter()) {
        assert_eq!(p.to_string(), *exp);
    }
}

#[test]
fn sim_priority_serde_roundtrip_all() {
    for p in &SimPriority::ALL {
        let json = serde_json::to_string(p).unwrap();
        let back: SimPriority = serde_json::from_str(&json).unwrap();
        assert_eq!(*p, back);
    }
}

#[test]
fn sim_priority_ordering() {
    assert!(SimPriority::Microtask < SimPriority::HighPriority);
    assert!(SimPriority::HighPriority < SimPriority::Normal);
    assert!(SimPriority::Normal < SimPriority::LowPriority);
    assert!(SimPriority::LowPriority < SimPriority::Idle);
}

#[test]
fn sim_priority_all_count() {
    assert_eq!(SimPriority::ALL.len(), 5);
}

// ---------------------------------------------------------------------------
// SimSpecimenFamily
// ---------------------------------------------------------------------------

#[test]
fn sim_specimen_family_display_all() {
    let expected = [
        "event_loop_drain",
        "module_lifecycle",
        "cache_interaction",
        "controller_feedback",
        "timer_coalescing",
        "mixed_priority",
    ];
    let all = [
        SimSpecimenFamily::EventLoopDrain,
        SimSpecimenFamily::ModuleLifecycle,
        SimSpecimenFamily::CacheInteraction,
        SimSpecimenFamily::ControllerFeedback,
        SimSpecimenFamily::TimerCoalescing,
        SimSpecimenFamily::MixedPriority,
    ];
    for (fam, exp) in all.iter().zip(expected.iter()) {
        assert_eq!(fam.to_string(), *exp);
    }
}

#[test]
fn sim_specimen_family_serde_roundtrip() {
    let all = [
        SimSpecimenFamily::EventLoopDrain,
        SimSpecimenFamily::ModuleLifecycle,
        SimSpecimenFamily::CacheInteraction,
        SimSpecimenFamily::ControllerFeedback,
        SimSpecimenFamily::TimerCoalescing,
        SimSpecimenFamily::MixedPriority,
    ];
    for fam in &all {
        let json = serde_json::to_string(fam).unwrap();
        let back: SimSpecimenFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(*fam, back);
    }
}

// ---------------------------------------------------------------------------
// SchedulerPolicy
// ---------------------------------------------------------------------------

#[test]
fn scheduler_policy_default_values() {
    let p = SchedulerPolicy::default();
    assert_eq!(p.max_ticks, 1_000);
    assert_eq!(p.max_events_per_tick, 256);
    assert!(p.drain_microtasks_first);
    assert_eq!(p.gc_interval_ticks, 100);
    assert!(!p.enable_timer_coalescing);
    assert!(p.deterministic_tie_break);
}

#[test]
fn scheduler_policy_serde_roundtrip() {
    let p = SchedulerPolicy::default();
    let json = serde_json::to_string(&p).unwrap();
    let back: SchedulerPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

#[test]
fn scheduler_policy_custom_serde_roundtrip() {
    let p = SchedulerPolicy {
        max_ticks: 50,
        max_events_per_tick: 10,
        drain_microtasks_first: false,
        gc_interval_ticks: 0,
        enable_timer_coalescing: true,
        deterministic_tie_break: false,
    };
    let json = serde_json::to_string(&p).unwrap();
    let back: SchedulerPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(p, back);
}

// ---------------------------------------------------------------------------
// SimEvent
// ---------------------------------------------------------------------------

#[test]
fn sim_event_serde_roundtrip() {
    let event = SimEvent {
        id: 42,
        kind: SimEventKind::TimerFire,
        priority: SimPriority::HighPriority,
        scheduled_tick: 5,
        payload_hash: ContentHash::compute(b"test-payload"),
        source_label: "timer-test".to_string(),
        deterministic_seed: 12345,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SimEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// TickOutcome
// ---------------------------------------------------------------------------

#[test]
fn tick_outcome_serde_roundtrip() {
    let outcome = TickOutcome {
        tick: 3,
        events_dispatched: vec![0, 1, 2],
        microtasks_drained: 1,
        pending_count: 5,
    };
    let json = serde_json::to_string(&outcome).unwrap();
    let back: TickOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(outcome, back);
}

// ---------------------------------------------------------------------------
// SimRunSummary
// ---------------------------------------------------------------------------

#[test]
fn sim_run_summary_serde_roundtrip() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "x", 1);
    let summary = sched.run_to_completion();
    let json = serde_json::to_string(&summary).unwrap();
    let back: SimRunSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// SimReplayLog
// ---------------------------------------------------------------------------

#[test]
fn replay_log_empty() {
    let log = SimReplayLog::default();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn replay_log_push_and_len() {
    let mut log = SimReplayLog::default();
    log.push(SimReplayEntry {
        tick: 0,
        event_id: 0,
        kind: SimEventKind::EventLoopTick,
        priority: SimPriority::Normal,
    });
    log.push(SimReplayEntry {
        tick: 1,
        event_id: 1,
        kind: SimEventKind::ModuleLoad,
        priority: SimPriority::HighPriority,
    });
    assert_eq!(log.len(), 2);
    assert!(!log.is_empty());
}

#[test]
fn replay_log_content_hash_determinism() {
    let build = || {
        let mut log = SimReplayLog::default();
        log.push(SimReplayEntry {
            tick: 0,
            event_id: 42,
            kind: SimEventKind::HostcallInvoke,
            priority: SimPriority::Microtask,
        });
        log.content_hash()
    };
    assert_eq!(build(), build());
}

#[test]
fn replay_log_different_entries_different_hash() {
    let mut log1 = SimReplayLog::default();
    log1.push(SimReplayEntry {
        tick: 0,
        event_id: 1,
        kind: SimEventKind::CacheHit,
        priority: SimPriority::Normal,
    });

    let mut log2 = SimReplayLog::default();
    log2.push(SimReplayEntry {
        tick: 0,
        event_id: 2,
        kind: SimEventKind::CacheMiss,
        priority: SimPriority::Normal,
    });

    assert_ne!(log1.content_hash(), log2.content_hash());
}

#[test]
fn replay_log_serde_roundtrip() {
    let mut log = SimReplayLog::default();
    log.push(SimReplayEntry {
        tick: 7,
        event_id: 99,
        kind: SimEventKind::GcPause,
        priority: SimPriority::Idle,
    });
    let json = serde_json::to_string(&log).unwrap();
    let back: SimReplayLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

#[test]
fn replay_entry_serde_roundtrip() {
    let entry = SimReplayEntry {
        tick: 5,
        event_id: 10,
        kind: SimEventKind::PromiseSettle,
        priority: SimPriority::Microtask,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: SimReplayEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// SimScheduler — basic scheduling
// ---------------------------------------------------------------------------

#[test]
fn scheduler_new_is_empty() {
    let sched = default_scheduler();
    assert_eq!(sched.current_tick, 0);
    assert_eq!(sched.pending_count(), 0);
    assert_eq!(sched.total_dispatched(), 0);
}

#[test]
fn schedule_returns_incrementing_ids() {
    let mut sched = default_scheduler();
    let id0 = sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "src", 42);
    let id1 = sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "src", 43);
    let id2 = sched.schedule(SimEventKind::CacheEvict, SimPriority::Normal, 0, "src", 44);
    assert_eq!(id0, 0);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
}

#[test]
fn schedule_updates_pending_count() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::ModuleLoad, SimPriority::Normal, 0, "test", 1);
    sched.schedule(
        SimEventKind::ModuleResolve,
        SimPriority::Normal,
        1,
        "test",
        2,
    );
    assert_eq!(sched.pending_count(), 2);
}

// ---------------------------------------------------------------------------
// SimScheduler — dispatch ordering
// ---------------------------------------------------------------------------

#[test]
fn advance_tick_dispatches_in_priority_order() {
    let mut sched = default_scheduler();
    let idle_id = sched.schedule(SimEventKind::GcPause, SimPriority::Idle, 0, "gc", 1);
    let micro_id = sched.schedule(
        SimEventKind::MicrotaskDrain,
        SimPriority::Microtask,
        0,
        "micro",
        2,
    );
    let normal_id = sched.schedule(
        SimEventKind::ControllerDecision,
        SimPriority::Normal,
        0,
        "ctrl",
        3,
    );

    let outcome = sched.advance_tick().unwrap();
    assert_eq!(
        outcome.events_dispatched,
        vec![micro_id, normal_id, idle_id]
    );
}

#[test]
fn advance_tick_deterministic_tie_break_by_id() {
    let mut sched = default_scheduler();
    let id_a = sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 10);
    let id_b = sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "b", 20);
    let id_c = sched.schedule(SimEventKind::CacheEvict, SimPriority::Normal, 0, "c", 30);

    let outcome = sched.advance_tick().unwrap();
    assert_eq!(outcome.events_dispatched, vec![id_a, id_b, id_c]);
}

#[test]
fn advance_tick_microtask_drain_count() {
    let mut sched = default_scheduler();
    sched.schedule(
        SimEventKind::PromiseSettle,
        SimPriority::Microtask,
        0,
        "p1",
        1,
    );
    sched.schedule(
        SimEventKind::PromiseSettle,
        SimPriority::Microtask,
        0,
        "p2",
        2,
    );
    sched.schedule(SimEventKind::TimerFire, SimPriority::Normal, 0, "t1", 3);

    let outcome = sched.advance_tick().unwrap();
    assert_eq!(outcome.microtasks_drained, 2);
    assert_eq!(outcome.events_dispatched.len(), 3);
}

#[test]
fn advance_tick_returns_none_at_max_ticks() {
    let policy = small_policy(2, 256);
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 1, "a", 2);

    let _ = sched.advance_tick(); // tick 0
    let _ = sched.advance_tick(); // tick 1
    assert!(sched.advance_tick().is_none()); // tick 2 == max_ticks
}

#[test]
fn advance_tick_empty_tick() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::ModuleLoad, SimPriority::Normal, 5, "m", 1);
    let outcome = sched.advance_tick().unwrap();
    assert!(outcome.events_dispatched.is_empty());
    assert_eq!(outcome.microtasks_drained, 0);
}

// ---------------------------------------------------------------------------
// SimScheduler — multi-tick and run_to_completion
// ---------------------------------------------------------------------------

#[test]
fn multi_tick_dispatch() {
    let mut sched = default_scheduler();
    let id0 = sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "c", 1);
    let id1 = sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 2, "c", 2);

    let o0 = sched.advance_tick().unwrap();
    assert_eq!(o0.events_dispatched, vec![id0]);

    let o1 = sched.advance_tick().unwrap(); // tick 1 empty
    assert!(o1.events_dispatched.is_empty());

    let o2 = sched.advance_tick().unwrap(); // tick 2
    assert_eq!(o2.events_dispatched, vec![id1]);
}

#[test]
fn run_to_completion_empty() {
    let mut sched = default_scheduler();
    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 0);
    assert_eq!(summary.total_ticks, 0);
    assert_eq!(summary.schema_version, SIM_SCHEDULER_SCHEMA_VERSION);
}

#[test]
fn run_to_completion_dispatches_all() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
    sched.schedule(
        SimEventKind::ModuleLoad,
        SimPriority::HighPriority,
        3,
        "b",
        2,
    );
    sched.schedule(SimEventKind::CacheEvict, SimPriority::Idle, 5, "c", 3);

    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 3);
    assert_eq!(sched.pending_count(), 0);
}

#[test]
fn run_to_completion_respects_max_ticks() {
    let policy = small_policy(3, 256);
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
    sched.schedule(
        SimEventKind::EventLoopTick,
        SimPriority::Normal,
        100,
        "far",
        2,
    );

    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 1);
    assert_eq!(sched.pending_count(), 1);
}

// ---------------------------------------------------------------------------
// Content hash determinism
// ---------------------------------------------------------------------------

#[test]
fn content_hash_determinism() {
    let run = || {
        let mut sched = default_scheduler();
        sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "x", 99);
        sched.schedule(
            SimEventKind::CacheMiss,
            SimPriority::HighPriority,
            1,
            "y",
            100,
        );
        sched.run_to_completion();
        sched.content_hash()
    };
    assert_eq!(run(), run());
}

#[test]
fn content_hash_differs_for_different_schedules() {
    let mut s1 = default_scheduler();
    s1.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    s1.run_to_completion();

    let mut s2 = default_scheduler();
    s2.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    s2.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 1, "b", 2);
    s2.run_to_completion();

    assert_ne!(s1.content_hash(), s2.content_hash());
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn max_events_per_tick_limit_requeues() {
    let policy = small_policy(1000, 2);
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "b", 2);
    sched.schedule(SimEventKind::CacheEvict, SimPriority::Normal, 0, "c", 3);

    let outcome = sched.advance_tick().unwrap();
    assert_eq!(outcome.events_dispatched.len(), 2);
    assert_eq!(sched.pending_count(), 1);
}

#[test]
fn scheduler_with_custom_epoch() {
    let ep = SecurityEpoch::from_raw(42);
    let sched = SimScheduler::new(SchedulerPolicy::default(), ep);
    assert_eq!(sched.epoch.as_u64(), 42);
}

#[test]
fn total_dispatched_accumulates() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 1, "b", 2);

    sched.advance_tick();
    assert_eq!(sched.total_dispatched(), 1);
    sched.advance_tick();
    assert_eq!(sched.total_dispatched(), 2);
}

#[test]
fn scheduler_serde_roundtrip() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::ModuleLoad, SimPriority::Normal, 0, "src", 10);
    sched.advance_tick();
    let json = serde_json::to_string(&sched).unwrap();
    let back: SimScheduler = serde_json::from_str(&json).unwrap();
    assert_eq!(sched.current_tick, back.current_tick);
    assert_eq!(sched.pending_count(), back.pending_count());
    assert_eq!(sched.total_dispatched(), back.total_dispatched());
}

#[test]
fn schema_constants() {
    assert!(SIM_SCHEDULER_SCHEMA_VERSION.contains("deterministic-sim-scheduler"));
    assert_eq!(SIM_SCHEDULER_BEAD_ID, "bd-1lsy.9.3.3");
}

#[test]
fn drain_microtasks_disabled_counts_inline() {
    let policy = SchedulerPolicy {
        drain_microtasks_first: false,
        ..SchedulerPolicy::default()
    };
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
    sched.schedule(
        SimEventKind::PromiseSettle,
        SimPriority::Microtask,
        0,
        "p",
        1,
    );
    sched.schedule(SimEventKind::TimerFire, SimPriority::Normal, 0, "t", 2);

    let outcome = sched.advance_tick().unwrap();
    assert_eq!(outcome.microtasks_drained, 1);
    assert_eq!(outcome.events_dispatched.len(), 2);
}

#[test]
fn many_events_same_tick_all_dispatched() {
    let mut sched = default_scheduler();
    for i in 0..100 {
        sched.schedule(
            SimEventKind::EventLoopTick,
            SimPriority::Normal,
            0,
            "bulk",
            i,
        );
    }
    let outcome = sched.advance_tick().unwrap();
    assert_eq!(outcome.events_dispatched.len(), 100);
}

#[test]
fn saturating_add_delay_ticks() {
    let mut sched = default_scheduler();
    // This should not panic even with huge delay
    let id = sched.schedule(
        SimEventKind::TimerFire,
        SimPriority::Normal,
        u64::MAX,
        "far",
        1,
    );
    assert_eq!(id, 0);
    assert_eq!(sched.pending_count(), 1);
}

// ===========================================================================
// Enrichment tests — dispatch ordering and priority interactions
// ===========================================================================

#[test]
fn all_five_priorities_dispatch_in_order() {
    let mut sched = default_scheduler();

    // Schedule one event per priority level, same tick, reverse order.
    sched.schedule(SimEventKind::GcPause, SimPriority::Idle, 0, "idle", 1);
    sched.schedule(
        SimEventKind::TimerFire,
        SimPriority::LowPriority,
        0,
        "low",
        2,
    );
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "norm", 3);
    sched.schedule(
        SimEventKind::ControllerDecision,
        SimPriority::HighPriority,
        0,
        "high",
        4,
    );
    sched.schedule(
        SimEventKind::MicrotaskDrain,
        SimPriority::Microtask,
        0,
        "micro",
        5,
    );

    let outcome = sched.advance_tick().unwrap();
    // Should dispatch: micro (4), high (3), normal (2), low (1), idle (0).
    assert_eq!(outcome.events_dispatched.len(), 5);
    // First event must be microtask.
    assert_eq!(outcome.events_dispatched[0], 4); // microtask id
    // Last event must be idle.
    assert_eq!(outcome.events_dispatched[4], 0); // idle id
}

#[test]
fn run_to_completion_total_events_count() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "b", 2);
    sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 1, "c", 3);
    sched.schedule(SimEventKind::ModuleLoad, SimPriority::Normal, 2, "d", 4);

    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 4);
    // events_by_kind is empty by design — dispatch log only stores IDs,
    // not full event metadata. SimReplayLog is the authoritative source.
    assert!(summary.events_by_kind.is_empty());
}

#[test]
fn run_to_completion_summary_maps_are_empty_by_design() {
    // The summary cannot recover kind/priority from IDs alone.
    // This verifies the documented behavior.
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::CacheMiss, SimPriority::Microtask, 0, "b", 2);
    sched.schedule(SimEventKind::ModuleLoad, SimPriority::Normal, 1, "c", 3);
    sched.schedule(SimEventKind::GcPause, SimPriority::Idle, 1, "d", 4);

    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 4);
    assert!(summary.events_by_kind.is_empty());
    assert!(summary.events_by_priority.is_empty());
}

// ===========================================================================
// Enrichment — determinism and replay
// ===========================================================================

#[test]
fn identical_schedule_produces_identical_content_hash() {
    let run = |_: u8| {
        let mut sched = default_scheduler();
        sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "x", 99);
        sched.schedule(
            SimEventKind::MicrotaskDrain,
            SimPriority::Microtask,
            0,
            "y",
            100,
        );
        sched.schedule(
            SimEventKind::ModuleLoad,
            SimPriority::HighPriority,
            2,
            "z",
            101,
        );
        sched.run_to_completion();
        sched.content_hash()
    };
    assert_eq!(run(0), run(1));
    assert_eq!(run(0), run(2));
}

#[test]
fn dispatch_log_matches_dispatch_order() {
    let mut sched = default_scheduler();
    let micro_id = sched.schedule(
        SimEventKind::PromiseSettle,
        SimPriority::Microtask,
        0,
        "p",
        1,
    );
    let normal_id = sched.schedule(SimEventKind::TimerFire, SimPriority::Normal, 0, "t", 2);

    let outcome = sched.advance_tick().unwrap();
    // Microtask dispatched first due to drain_microtasks_first policy.
    assert_eq!(outcome.events_dispatched.len(), 2);
    assert_eq!(outcome.events_dispatched[0], micro_id);
    assert_eq!(outcome.events_dispatched[1], normal_id);
    assert_eq!(outcome.microtasks_drained, 1);
}

#[test]
fn serde_roundtrip_after_run_to_completion() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 3, "b", 2);
    sched.schedule(SimEventKind::GcPause, SimPriority::Idle, 5, "c", 3);
    let summary = sched.run_to_completion();

    let json = serde_json::to_string(&sched).unwrap();
    let restored: SimScheduler = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.current_tick, sched.current_tick);
    assert_eq!(restored.pending_count(), sched.pending_count());
    assert_eq!(restored.total_dispatched(), sched.total_dispatched());
    assert_eq!(restored.content_hash(), sched.content_hash());

    let summary_json = serde_json::to_string(&summary).unwrap();
    let summary_back: SimRunSummary = serde_json::from_str(&summary_json).unwrap();
    assert_eq!(summary_back, summary);
}

// ===========================================================================
// Enrichment — dynamic scheduling (schedule after advance_tick)
// ===========================================================================

#[test]
fn schedule_during_simulation() {
    let mut sched = default_scheduler();
    sched.schedule(
        SimEventKind::EventLoopTick,
        SimPriority::Normal,
        0,
        "init",
        1,
    );

    // Dispatch tick 0.
    let o0 = sched.advance_tick().unwrap();
    assert_eq!(o0.events_dispatched.len(), 1);

    // Schedule more events after tick 0 has been dispatched.
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "dynamic", 2);
    sched.schedule(
        SimEventKind::CacheMiss,
        SimPriority::Normal,
        1,
        "dynamic2",
        3,
    );

    // The first dynamic event targets current_tick (1), second targets tick 2.
    let o1 = sched.advance_tick().unwrap();
    assert_eq!(o1.events_dispatched.len(), 1);

    let o2 = sched.advance_tick().unwrap();
    assert_eq!(o2.events_dispatched.len(), 1);

    assert_eq!(sched.total_dispatched(), 3);
}

// ===========================================================================
// Enrichment — max_events_per_tick overflow to next tick
// ===========================================================================

#[test]
fn overflow_events_requeued_to_next_tick() {
    let policy = small_policy(100, 3);
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);

    // Schedule 5 events for tick 0 — only 3 should dispatch per tick.
    for i in 0..5 {
        sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "x", i);
    }

    let o0 = sched.advance_tick().unwrap();
    assert_eq!(o0.events_dispatched.len(), 3);
    assert_eq!(sched.pending_count(), 2); // 2 overflow to tick 1

    let o1 = sched.advance_tick().unwrap();
    assert_eq!(o1.events_dispatched.len(), 2);
    assert_eq!(sched.pending_count(), 0);
}

#[test]
fn overflow_preserves_priority_ordering_in_next_tick() {
    let policy = small_policy(100, 2);
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);

    // micro (id 0), high (id 1), normal (id 2), low (id 3)
    sched.schedule(
        SimEventKind::PromiseSettle,
        SimPriority::Microtask,
        0,
        "m",
        1,
    );
    sched.schedule(
        SimEventKind::ControllerDecision,
        SimPriority::HighPriority,
        0,
        "h",
        2,
    );
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "n", 3);
    sched.schedule(SimEventKind::GcPause, SimPriority::LowPriority, 0, "l", 4);

    // Tick 0: micro + high dispatched (limit 2).
    let o0 = sched.advance_tick().unwrap();
    assert_eq!(o0.events_dispatched, vec![0, 1]); // micro, high

    // Tick 1: normal + low dispatched.
    let o1 = sched.advance_tick().unwrap();
    assert_eq!(o1.events_dispatched, vec![2, 3]); // normal, low
}

// ===========================================================================
// Enrichment — sparse tick fast-forward
// ===========================================================================

#[test]
fn run_to_completion_fast_forwards_sparse_ticks() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 500, "b", 2);

    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 2);
    // The dispatch log should NOT have 500 empty tick entries — fast-forward.
    assert!(
        sched.dispatch_log.len() <= 3,
        "dispatch log should be sparse, got {} entries",
        sched.dispatch_log.len()
    );
}

// ===========================================================================
// Enrichment — SimRunSummary content hash from summary
// ===========================================================================

#[test]
fn run_summary_content_hash_nonempty() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
    let summary = sched.run_to_completion();
    // Content hash should be non-zero (not default).
    let zero_hash = ContentHash::compute(b"");
    assert_ne!(
        summary.content_hash, zero_hash,
        "summary hash should differ from empty hash"
    );
}

// ===========================================================================
// Enrichment — clone produces identical results
// ===========================================================================

#[test]
fn clone_scheduler_produces_same_result() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    sched.schedule(
        SimEventKind::MicrotaskDrain,
        SimPriority::Microtask,
        0,
        "b",
        2,
    );
    sched.schedule(
        SimEventKind::ModuleLoad,
        SimPriority::HighPriority,
        3,
        "c",
        3,
    );

    let mut clone = sched.clone();

    let summary1 = sched.run_to_completion();
    let summary2 = clone.run_to_completion();

    assert_eq!(summary1.total_events, summary2.total_events);
    assert_eq!(summary1.total_ticks, summary2.total_ticks);
    assert_eq!(summary1.content_hash, summary2.content_hash);
    assert_eq!(sched.content_hash(), clone.content_hash());
}

// ===========================================================================
// Enrichment — all 12 event kinds dispatch
// ===========================================================================

#[test]
fn all_event_kinds_dispatch_in_single_tick() {
    let mut sched = default_scheduler();
    for (i, kind) in SimEventKind::ALL.iter().enumerate() {
        sched.schedule(*kind, SimPriority::Normal, 0, "kind_test", i as u64);
    }

    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 12);
    assert_eq!(sched.pending_count(), 0);
    // All 12 events dispatched in a single tick.
    assert_eq!(sched.dispatch_log.len(), 1);
    assert_eq!(sched.dispatch_log[0].events_dispatched.len(), 12);
}

// ===========================================================================
// Enrichment — all 5 priority levels appear in summary
// ===========================================================================

#[test]
fn all_priority_levels_dispatch_in_order() {
    let mut sched = default_scheduler();
    for (i, prio) in SimPriority::ALL.iter().enumerate() {
        sched.schedule(SimEventKind::EventLoopTick, *prio, 0, "prio_test", i as u64);
    }

    let summary = sched.run_to_completion();
    assert_eq!(summary.total_events, 5);
    assert_eq!(sched.pending_count(), 0);

    // All 5 dispatched in one tick, in priority order.
    let outcome = &sched.dispatch_log[0];
    assert_eq!(outcome.events_dispatched.len(), 5);
    // First dispatched should be microtask (id 0), last should be idle (id 4).
    assert_eq!(outcome.events_dispatched[0], 0); // Microtask
    assert_eq!(outcome.events_dispatched[4], 4); // Idle
}

// ===========================================================================
// Enrichment — content hash changes after single additional event
// ===========================================================================

#[test]
fn content_hash_sensitive_to_additional_event() {
    let mut s1 = default_scheduler();
    s1.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    s1.run_to_completion();
    let hash1 = s1.content_hash();

    let mut s2 = default_scheduler();
    s2.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    s2.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 2);
    s2.run_to_completion();
    let hash2 = s2.content_hash();

    assert_ne!(hash1, hash2);
}

// ===========================================================================
// Enrichment — SimEvent payload_hash determinism
// ===========================================================================

#[test]
fn sim_event_payload_hash_deterministic() {
    let mut s1 = default_scheduler();
    let mut s2 = default_scheduler();

    s1.schedule(
        SimEventKind::HostcallInvoke,
        SimPriority::Normal,
        0,
        "call",
        42,
    );
    s2.schedule(
        SimEventKind::HostcallInvoke,
        SimPriority::Normal,
        0,
        "call",
        42,
    );

    let events1 = s1.event_queue.get(&0).unwrap();
    let events2 = s2.event_queue.get(&0).unwrap();
    assert_eq!(events1[0].payload_hash, events2[0].payload_hash);
}

// ===========================================================================
// Enrichment — microtask drain disabled still dispatches microtasks
// ===========================================================================

#[test]
fn drain_disabled_still_dispatches_all_priorities() {
    let policy = SchedulerPolicy {
        drain_microtasks_first: false,
        ..SchedulerPolicy::default()
    };
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);

    sched.schedule(SimEventKind::GcPause, SimPriority::Idle, 0, "idle", 1);
    sched.schedule(
        SimEventKind::PromiseSettle,
        SimPriority::Microtask,
        0,
        "micro",
        2,
    );
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "norm", 3);

    let outcome = sched.advance_tick().unwrap();
    assert_eq!(outcome.events_dispatched.len(), 3);
    // All events dispatched regardless of drain mode.
    assert_eq!(sched.pending_count(), 0);
}

// ===========================================================================
// Enrichment — zero max_events_per_tick means no dispatch
// ===========================================================================

#[test]
fn zero_max_events_per_tick_dispatches_nothing() {
    let policy = small_policy(100, 0);
    let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);

    let outcome = sched.advance_tick().unwrap();
    assert!(outcome.events_dispatched.is_empty());
    assert_eq!(sched.pending_count(), 1); // requeued to next tick
}

// ===========================================================================
// Enrichment — SimSpecimenFamily ordering
// ===========================================================================

#[test]
fn sim_specimen_family_ordering() {
    assert!(SimSpecimenFamily::EventLoopDrain < SimSpecimenFamily::ModuleLifecycle);
    assert!(SimSpecimenFamily::ModuleLifecycle < SimSpecimenFamily::CacheInteraction);
    assert!(SimSpecimenFamily::CacheInteraction < SimSpecimenFamily::ControllerFeedback);
    assert!(SimSpecimenFamily::ControllerFeedback < SimSpecimenFamily::TimerCoalescing);
    assert!(SimSpecimenFamily::TimerCoalescing < SimSpecimenFamily::MixedPriority);
}

// ===========================================================================
// Enrichment — large-scale run determinism
// ===========================================================================

#[test]
fn large_scale_run_determinism() {
    let run = |_: u8| {
        let mut sched = default_scheduler();
        for i in 0..200 {
            let kind = SimEventKind::ALL[i % 12];
            let prio = SimPriority::ALL[i % 5];
            let delay = (i as u64) % 10;
            sched.schedule(kind, prio, delay, "bulk", i as u64);
        }
        sched.run_to_completion()
    };

    let s1 = run(0);
    let s2 = run(1);
    assert_eq!(s1.total_events, s2.total_events);
    assert_eq!(s1.total_ticks, s2.total_ticks);
    assert_eq!(s1.content_hash, s2.content_hash);
    assert_eq!(s1.events_by_kind, s2.events_by_kind);
    assert_eq!(s1.events_by_priority, s2.events_by_priority);
}

// ===========================================================================
// Enrichment — dispatch_log length matches tick count
// ===========================================================================

#[test]
fn dispatch_log_covers_active_ticks() {
    let mut sched = default_scheduler();
    sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
    sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 3, "b", 2);

    let summary = sched.run_to_completion();
    // dispatch_log has entries only for ticks actually dispatched (fast-forward
    // skips empty ticks). total_ticks = current_tick which includes fast-forwards.
    assert!(sched.dispatch_log.len() >= 2, "at least 2 ticks dispatched");
    assert!(
        summary.total_ticks >= sched.dispatch_log.len() as u64,
        "total_ticks ({}) should be >= dispatch_log length ({})",
        summary.total_ticks,
        sched.dispatch_log.len()
    );
    assert_eq!(summary.total_events, 2);
}
