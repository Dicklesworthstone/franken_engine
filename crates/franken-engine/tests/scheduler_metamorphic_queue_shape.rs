#![forbid(unsafe_code)]

//! Metamorphic tests for deterministic simulation scheduler queue shape.
//!
//! MR strength matrix:
//! | Relation | Fault sensitivity | Independence | Cost | Score |
//! | --- | ---: | ---: | ---: | ---: |
//! | Empty tick insertion preserves normalized effects | 4 | 4 | 1 | 16 |
//! | Per-tick spillover preserves flattened dispatch order | 5 | 4 | 1 | 20 |
//! | Microtask drain phase toggle preserves observable order/counts | 4 | 3 | 1 | 12 |
//! | Future unreachable events do not affect within-horizon effects | 3 | 4 | 1 | 12 |
//! | Dynamic arrival after empty ticks matches equivalent delayed input | 4 | 4 | 1 | 16 |

use std::collections::BTreeMap;

use frankenengine_engine::deterministic_sim_scheduler::{
    SchedulerPolicy, SimEventKind, SimPriority, SimScheduler,
};
use frankenengine_engine::security_epoch::SecurityEpoch;

#[derive(Clone, Copy, Debug)]
struct EventSpec {
    kind: SimEventKind,
    priority: SimPriority,
    delay: u64,
    source: &'static str,
    seed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EventEffect {
    kind: SimEventKind,
    priority: SimPriority,
    source: &'static str,
    seed: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DispatchEffect {
    tick: u64,
    event: EventEffect,
}

#[derive(Debug)]
struct TraceCapture {
    dispatched: Vec<DispatchEffect>,
    total_events: u64,
    total_ticks: u64,
    pending: usize,
    microtasks_drained: u64,
}

fn policy(
    max_ticks: u64,
    max_events_per_tick: u64,
    drain_microtasks_first: bool,
) -> SchedulerPolicy {
    SchedulerPolicy {
        max_ticks,
        max_events_per_tick,
        drain_microtasks_first,
        gc_interval_ticks: 0,
        enable_timer_coalescing: false,
        deterministic_tie_break: true,
    }
}

fn effect(spec: EventSpec) -> EventEffect {
    EventEffect {
        kind: spec.kind,
        priority: spec.priority,
        source: spec.source,
        seed: spec.seed,
    }
}

fn base_specs() -> Vec<EventSpec> {
    vec![
        EventSpec {
            kind: SimEventKind::ModuleLoad,
            priority: SimPriority::HighPriority,
            delay: 0,
            source: "module-load",
            seed: 10,
        },
        EventSpec {
            kind: SimEventKind::MicrotaskDrain,
            priority: SimPriority::Microtask,
            delay: 0,
            source: "microtask-drain",
            seed: 11,
        },
        EventSpec {
            kind: SimEventKind::CacheHit,
            priority: SimPriority::Normal,
            delay: 1,
            source: "cache-hit",
            seed: 12,
        },
        EventSpec {
            kind: SimEventKind::TimerFire,
            priority: SimPriority::LowPriority,
            delay: 3,
            source: "timer-fire",
            seed: 13,
        },
        EventSpec {
            kind: SimEventKind::ControllerDecision,
            priority: SimPriority::HighPriority,
            delay: 3,
            source: "controller-decision",
            seed: 14,
        },
        EventSpec {
            kind: SimEventKind::HostcallInvoke,
            priority: SimPriority::Idle,
            delay: 5,
            source: "hostcall",
            seed: 15,
        },
    ]
}

fn same_tick_specs() -> Vec<EventSpec> {
    vec![
        EventSpec {
            kind: SimEventKind::CacheMiss,
            priority: SimPriority::Normal,
            delay: 0,
            source: "cache-miss",
            seed: 20,
        },
        EventSpec {
            kind: SimEventKind::ModuleResolve,
            priority: SimPriority::HighPriority,
            delay: 0,
            source: "module-resolve",
            seed: 21,
        },
        EventSpec {
            kind: SimEventKind::PromiseSettle,
            priority: SimPriority::Microtask,
            delay: 0,
            source: "promise-settle",
            seed: 22,
        },
        EventSpec {
            kind: SimEventKind::EventLoopTick,
            priority: SimPriority::LowPriority,
            delay: 0,
            source: "event-loop",
            seed: 23,
        },
        EventSpec {
            kind: SimEventKind::HostcallInvoke,
            priority: SimPriority::Idle,
            delay: 0,
            source: "hostcall",
            seed: 24,
        },
        EventSpec {
            kind: SimEventKind::ControllerDecision,
            priority: SimPriority::HighPriority,
            delay: 0,
            source: "controller",
            seed: 25,
        },
    ]
}

fn shifted(specs: &[EventSpec], ticks: u64) -> Vec<EventSpec> {
    specs
        .iter()
        .map(|spec| EventSpec {
            delay: spec.delay + ticks,
            ..*spec
        })
        .collect()
}

fn with_policy(policy: SchedulerPolicy, specs: &[EventSpec]) -> TraceCapture {
    let mut scheduler = SimScheduler::new(policy, SecurityEpoch::from_raw(7));
    let mut effects = BTreeMap::new();
    for &spec in specs {
        let id = scheduler.schedule(spec.kind, spec.priority, spec.delay, spec.source, spec.seed);
        effects.insert(id, effect(spec));
    }
    let summary = scheduler.run_to_completion();
    capture(
        &scheduler,
        &effects,
        summary.total_events,
        summary.total_ticks,
    )
}

fn capture(
    scheduler: &SimScheduler,
    effects: &BTreeMap<u64, EventEffect>,
    total_events: u64,
    total_ticks: u64,
) -> TraceCapture {
    let mut dispatched = Vec::new();
    let mut microtasks_drained = 0;
    for outcome in &scheduler.dispatch_log {
        microtasks_drained += outcome.microtasks_drained;
        for id in &outcome.events_dispatched {
            dispatched.push(DispatchEffect {
                tick: outcome.tick,
                event: effects
                    .get(id)
                    .copied()
                    .expect("dispatched event must have a recorded effect"),
            });
        }
    }

    TraceCapture {
        dispatched,
        total_events,
        total_ticks,
        pending: scheduler.pending_count(),
        microtasks_drained,
    }
}

fn events_only(trace: &TraceCapture) -> Vec<EventEffect> {
    trace.dispatched.iter().map(|entry| entry.event).collect()
}

fn ticks_only(trace: &TraceCapture) -> Vec<u64> {
    trace.dispatched.iter().map(|entry| entry.tick).collect()
}

fn priority_counts(trace: &TraceCapture) -> BTreeMap<SimPriority, u64> {
    let mut counts = BTreeMap::new();
    for entry in &trace.dispatched {
        *counts.entry(entry.event.priority).or_insert(0) += 1;
    }
    counts
}

fn assert_same_normalized_effects(left: &TraceCapture, right: &TraceCapture) {
    assert_eq!(events_only(left), events_only(right));
    assert_eq!(left.total_events, right.total_events);
    assert_eq!(priority_counts(left), priority_counts(right));
}

fn run_after_empty_ticks(empty_ticks: u64, spec: EventSpec) -> TraceCapture {
    let mut scheduler = SimScheduler::new(policy(20, 16, true), SecurityEpoch::from_raw(7));
    let effects = BTreeMap::from([(0, effect(spec))]);
    for _ in 0..empty_ticks {
        scheduler.advance_tick();
    }
    let id = scheduler.schedule(spec.kind, spec.priority, 0, spec.source, spec.seed);
    assert_eq!(id, 0);
    let summary = scheduler.run_to_completion();
    capture(
        &scheduler,
        &effects,
        summary.total_events,
        summary.total_ticks,
    )
}

fn run_two_wave_dynamic(first_wave: &[EventSpec], second_wave: &[EventSpec]) -> TraceCapture {
    let mut scheduler = SimScheduler::new(policy(20, 16, true), SecurityEpoch::from_raw(7));
    let mut effects = BTreeMap::new();

    for &spec in first_wave {
        let id = scheduler.schedule(spec.kind, spec.priority, 0, spec.source, spec.seed);
        effects.insert(id, effect(spec));
    }
    scheduler.advance_tick();
    for &spec in second_wave {
        let id = scheduler.schedule(spec.kind, spec.priority, 0, spec.source, spec.seed);
        effects.insert(id, effect(spec));
    }

    let summary = scheduler.run_to_completion();
    capture(
        &scheduler,
        &effects,
        summary.total_events,
        summary.total_ticks,
    )
}

#[test]
fn mr_empty_prefix_gap_preserves_dispatch_effects() {
    let baseline = with_policy(policy(20, 16, true), &base_specs());
    let transformed = with_policy(policy(20, 16, true), &shifted(&base_specs(), 2));

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![2, 2, 3, 5, 5, 7]);
}

#[test]
fn mr_empty_middle_gap_preserves_bucket_contents() {
    let baseline = with_policy(policy(20, 16, true), &base_specs());
    let mut transformed_specs = base_specs();
    for spec in &mut transformed_specs {
        if spec.delay >= 3 {
            spec.delay += 2;
        }
    }
    let transformed = with_policy(policy(20, 16, true), &transformed_specs);

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![0, 0, 1, 5, 5, 7]);
}

#[test]
fn mr_sparse_manual_ticks_match_fast_forward_trace() {
    let spec = EventSpec {
        kind: SimEventKind::TimerFire,
        priority: SimPriority::Normal,
        delay: 4,
        source: "sparse-timer",
        seed: 30,
    };
    let fast_forward = with_policy(policy(20, 16, true), &[spec]);
    let manual = run_after_empty_ticks(4, EventSpec { delay: 0, ..spec });

    assert_same_normalized_effects(&fast_forward, &manual);
    assert_eq!(ticks_only(&fast_forward), ticks_only(&manual));
}

#[test]
fn mr_future_bucket_inserted_before_present_bucket_preserves_trace() {
    let early = EventSpec {
        kind: SimEventKind::ModuleLoad,
        priority: SimPriority::Normal,
        delay: 0,
        source: "early",
        seed: 31,
    };
    let late = EventSpec {
        kind: SimEventKind::CacheEvict,
        priority: SimPriority::Normal,
        delay: 4,
        source: "late",
        seed: 32,
    };

    let baseline = with_policy(policy(20, 16, true), &[early, late]);
    let transformed = with_policy(policy(20, 16, true), &[late, early]);

    assert_same_normalized_effects(&baseline, &transformed);
}

#[test]
fn mr_three_bucket_schedule_order_permutation_preserves_tick_sorted_trace() {
    let tick0 = EventSpec {
        kind: SimEventKind::EventLoopTick,
        priority: SimPriority::Normal,
        delay: 0,
        source: "tick-0",
        seed: 33,
    };
    let tick2 = EventSpec {
        kind: SimEventKind::CacheHit,
        priority: SimPriority::Normal,
        delay: 2,
        source: "tick-2",
        seed: 34,
    };
    let tick5 = EventSpec {
        kind: SimEventKind::HostcallInvoke,
        priority: SimPriority::Normal,
        delay: 5,
        source: "tick-5",
        seed: 35,
    };

    let baseline = with_policy(policy(20, 16, true), &[tick0, tick2, tick5]);
    let transformed = with_policy(policy(20, 16, true), &[tick5, tick0, tick2]);

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![0, 2, 5]);
}

#[test]
fn mr_limit_one_spillover_preserves_flattened_sequence() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 1, true), &same_tick_specs());

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![0, 1, 2, 3, 4, 5]);
}

#[test]
fn mr_limit_two_spillover_preserves_flattened_sequence() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 2, true), &same_tick_specs());

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![0, 0, 1, 1, 2, 2]);
}

#[test]
fn mr_limit_three_spillover_preserves_flattened_sequence() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 3, true), &same_tick_specs());

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![0, 0, 0, 1, 1, 1]);
}

#[test]
fn mr_limit_four_spillover_preserves_flattened_sequence() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 4, true), &same_tick_specs());

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![0, 0, 0, 0, 1, 1]);
}

#[test]
fn mr_limit_five_spillover_preserves_flattened_sequence() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 5, true), &same_tick_specs());

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(ticks_only(&transformed), vec![0, 0, 0, 0, 0, 1]);
}

#[test]
fn mr_limit_one_mixed_delay_spillover_preserves_sequence() {
    let baseline = with_policy(policy(20, 16, true), &base_specs());
    let transformed = with_policy(policy(20, 1, true), &base_specs());

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(transformed.total_events, 6);
    assert_eq!(transformed.pending, 0);
}

#[test]
fn mr_limit_above_queue_size_is_equivalent_to_unbounded_for_fixture() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 100, true), &same_tick_specs());

    assert_eq!(baseline.dispatched, transformed.dispatched);
    assert_eq!(baseline.total_ticks, transformed.total_ticks);
}

#[test]
fn mr_microtask_drain_flag_preserves_flattened_sequence() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 16, false), &same_tick_specs());

    assert_eq!(baseline.dispatched, transformed.dispatched);
}

#[test]
fn mr_microtask_drain_flag_preserves_microtask_count() {
    let baseline = with_policy(policy(20, 16, true), &base_specs());
    let transformed = with_policy(policy(20, 16, false), &base_specs());

    assert_eq!(baseline.microtasks_drained, transformed.microtasks_drained);
    assert_eq!(baseline.microtasks_drained, 1);
}

#[test]
fn mr_microtask_drain_flag_with_only_microtasks_preserves_trace() {
    let specs = [
        EventSpec {
            kind: SimEventKind::PromiseSettle,
            priority: SimPriority::Microtask,
            delay: 0,
            source: "promise-a",
            seed: 40,
        },
        EventSpec {
            kind: SimEventKind::MicrotaskDrain,
            priority: SimPriority::Microtask,
            delay: 0,
            source: "drain-b",
            seed: 41,
        },
    ];
    let baseline = with_policy(policy(20, 16, true), &specs);
    let transformed = with_policy(policy(20, 16, false), &specs);

    assert_eq!(baseline.dispatched, transformed.dispatched);
    assert_eq!(baseline.microtasks_drained, 2);
}

#[test]
fn mr_microtask_drain_flag_with_no_microtasks_preserves_zero_count() {
    let specs: Vec<_> = base_specs()
        .into_iter()
        .filter(|spec| spec.priority != SimPriority::Microtask)
        .collect();
    let baseline = with_policy(policy(20, 16, true), &specs);
    let transformed = with_policy(policy(20, 16, false), &specs);

    assert_eq!(baseline.dispatched, transformed.dispatched);
    assert_eq!(baseline.microtasks_drained, 0);
    assert_eq!(transformed.microtasks_drained, 0);
}

#[test]
fn mr_unreachable_beyond_horizon_does_not_change_dispatched_trace() {
    let reachable = EventSpec {
        kind: SimEventKind::ModuleResolve,
        priority: SimPriority::Normal,
        delay: 1,
        source: "reachable",
        seed: 50,
    };
    let unreachable = EventSpec {
        kind: SimEventKind::GcPause,
        priority: SimPriority::HighPriority,
        delay: 50,
        source: "beyond-horizon",
        seed: 51,
    };
    let baseline = with_policy(policy(10, 16, true), &[reachable]);
    let transformed = with_policy(policy(10, 16, true), &[reachable, unreachable]);

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(baseline.pending, 0);
    assert_eq!(transformed.pending, 1);
}

#[test]
fn mr_unreachable_beyond_horizon_does_not_change_total_events() {
    let mut specs = base_specs();
    specs.push(EventSpec {
        kind: SimEventKind::GcPause,
        priority: SimPriority::HighPriority,
        delay: 99,
        source: "unreachable-gc",
        seed: 52,
    });
    let baseline = with_policy(policy(8, 16, true), &base_specs());
    let transformed = with_policy(policy(8, 16, true), &specs);

    assert_eq!(baseline.total_events, transformed.total_events);
    assert_eq!(events_only(&baseline), events_only(&transformed));
}

#[test]
fn mr_dynamic_arrival_after_one_tick_matches_delay_one_input() {
    let first_wave = [EventSpec {
        kind: SimEventKind::EventLoopTick,
        priority: SimPriority::Normal,
        delay: 0,
        source: "first-wave",
        seed: 60,
    }];
    let second_wave = [EventSpec {
        kind: SimEventKind::CacheHit,
        priority: SimPriority::HighPriority,
        delay: 0,
        source: "second-wave",
        seed: 61,
    }];
    let static_specs = [
        first_wave[0],
        EventSpec {
            delay: 1,
            ..second_wave[0]
        },
    ];
    let baseline = with_policy(policy(20, 16, true), &static_specs);
    let transformed = run_two_wave_dynamic(&first_wave, &second_wave);

    assert_eq!(baseline.dispatched, transformed.dispatched);
}

#[test]
fn mr_dynamic_arrival_after_two_empty_ticks_matches_delay_two_input() {
    let spec = EventSpec {
        kind: SimEventKind::ControllerDecision,
        priority: SimPriority::HighPriority,
        delay: 2,
        source: "late-controller",
        seed: 62,
    };
    let baseline = with_policy(policy(20, 16, true), &[spec]);
    let transformed = run_after_empty_ticks(2, EventSpec { delay: 0, ..spec });

    assert_eq!(baseline.dispatched, transformed.dispatched);
    assert_eq!(baseline.total_ticks, transformed.total_ticks);
}

#[test]
fn mr_dynamic_second_wave_preserves_priority_counts() {
    let first_wave = [EventSpec {
        kind: SimEventKind::TimerFire,
        priority: SimPriority::LowPriority,
        delay: 0,
        source: "low-first",
        seed: 63,
    }];
    let second_wave = [
        EventSpec {
            kind: SimEventKind::PromiseSettle,
            priority: SimPriority::Microtask,
            delay: 0,
            source: "micro-second",
            seed: 64,
        },
        EventSpec {
            kind: SimEventKind::ModuleLoad,
            priority: SimPriority::Normal,
            delay: 0,
            source: "normal-second",
            seed: 65,
        },
    ];
    let static_specs = [
        first_wave[0],
        EventSpec {
            delay: 1,
            ..second_wave[0]
        },
        EventSpec {
            delay: 1,
            ..second_wave[1]
        },
    ];
    let baseline = with_policy(policy(20, 16, true), &static_specs);
    let transformed = run_two_wave_dynamic(&first_wave, &second_wave);

    assert_eq!(priority_counts(&baseline), priority_counts(&transformed));
    assert_eq!(events_only(&baseline), events_only(&transformed));
}

#[test]
fn mr_batch_partitioning_preserves_summary_total_events() {
    let first_wave = [same_tick_specs()[0], same_tick_specs()[1]];
    let second_wave = [same_tick_specs()[2], same_tick_specs()[3]];
    let static_specs = [
        first_wave[0],
        first_wave[1],
        EventSpec {
            delay: 1,
            ..second_wave[0]
        },
        EventSpec {
            delay: 1,
            ..second_wave[1]
        },
    ];
    let baseline = with_policy(policy(20, 16, true), &static_specs);
    let transformed = run_two_wave_dynamic(&first_wave, &second_wave);

    assert_eq!(baseline.total_events, transformed.total_events);
    assert_eq!(baseline.pending, transformed.pending);
}

#[test]
fn mr_shifted_input_preserves_priority_histogram() {
    let baseline = with_policy(policy(20, 16, true), &base_specs());
    let transformed = with_policy(policy(20, 16, true), &shifted(&base_specs(), 4));

    assert_eq!(priority_counts(&baseline), priority_counts(&transformed));
    assert_eq!(baseline.total_events, transformed.total_events);
}

#[test]
fn mr_spillover_and_microtask_toggle_compose_without_effect_change() {
    let baseline = with_policy(policy(20, 16, true), &same_tick_specs());
    let transformed = with_policy(policy(20, 2, false), &same_tick_specs());

    assert_same_normalized_effects(&baseline, &transformed);
    assert_eq!(transformed.microtasks_drained, 1);
}
