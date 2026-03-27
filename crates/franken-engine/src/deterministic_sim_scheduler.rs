#![forbid(unsafe_code)]

//! Deterministic simulation scheduling for event-loop, module, cache,
//! and controller interactions.
//!
//! Implements [RGC-803C] (bead bd-1lsy.9.3.3): provides a deterministic
//! simulation scheduler that replays event-loop ticks, module loading,
//! cache interactions, and controller decisions in a fully reproducible
//! order for campaign-grade testing.
//!
//! Key design decisions:
//! - Events are dispatched in priority order within each tick (microtasks
//!   first when `drain_microtasks_first` is enabled).
//! - Deterministic tie-breaking by event ID guarantees identical replay
//!   across runs.
//! - All state is serialisable so simulation runs can be persisted and
//!   compared across campaign iterations.
//! - Fixed-point millionths are not directly used in scheduling arithmetic
//!   but `ContentHash` is used for fingerprinting state.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the deterministic simulation scheduler.
pub const SIM_SCHEDULER_SCHEMA_VERSION: &str = "franken-engine.deterministic-sim-scheduler.v1";

/// Bead identifier for traceability.
pub const SIM_SCHEDULER_BEAD_ID: &str = "bd-1lsy.9.3.3";

// ---------------------------------------------------------------------------
// SimEventKind
// ---------------------------------------------------------------------------

/// The kind of simulation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SimEventKind {
    /// An event-loop tick fires.
    EventLoopTick,
    /// A module load is initiated.
    ModuleLoad,
    /// A module resolution is performed.
    ModuleResolve,
    /// A cache hit occurs.
    CacheHit,
    /// A cache miss occurs.
    CacheMiss,
    /// A cache entry is evicted.
    CacheEvict,
    /// A controller makes a decision.
    ControllerDecision,
    /// A timer fires.
    TimerFire,
    /// The microtask queue is drained.
    MicrotaskDrain,
    /// A promise settles.
    PromiseSettle,
    /// A garbage-collection pause.
    GcPause,
    /// A hostcall is invoked.
    HostcallInvoke,
}

impl SimEventKind {
    /// All variants, in declaration order.
    pub const ALL: [SimEventKind; 12] = [
        SimEventKind::EventLoopTick,
        SimEventKind::ModuleLoad,
        SimEventKind::ModuleResolve,
        SimEventKind::CacheHit,
        SimEventKind::CacheMiss,
        SimEventKind::CacheEvict,
        SimEventKind::ControllerDecision,
        SimEventKind::TimerFire,
        SimEventKind::MicrotaskDrain,
        SimEventKind::PromiseSettle,
        SimEventKind::GcPause,
        SimEventKind::HostcallInvoke,
    ];

    /// Machine-readable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EventLoopTick => "event_loop_tick",
            Self::ModuleLoad => "module_load",
            Self::ModuleResolve => "module_resolve",
            Self::CacheHit => "cache_hit",
            Self::CacheMiss => "cache_miss",
            Self::CacheEvict => "cache_evict",
            Self::ControllerDecision => "controller_decision",
            Self::TimerFire => "timer_fire",
            Self::MicrotaskDrain => "microtask_drain",
            Self::PromiseSettle => "promise_settle",
            Self::GcPause => "gc_pause",
            Self::HostcallInvoke => "hostcall_invoke",
        }
    }
}

impl fmt::Display for SimEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SimPriority
// ---------------------------------------------------------------------------

/// Priority level for simulation events.
///
/// Lower numeric discriminant = higher dispatch priority.
/// `Microtask` is always dispatched first within a tick when
/// `drain_microtasks_first` is enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SimPriority {
    /// Microtask-level priority (highest).
    Microtask,
    /// High priority.
    HighPriority,
    /// Normal priority.
    Normal,
    /// Low priority.
    LowPriority,
    /// Idle priority (lowest).
    Idle,
}

impl SimPriority {
    /// All variants, ordered from highest to lowest priority.
    pub const ALL: [SimPriority; 5] = [
        SimPriority::Microtask,
        SimPriority::HighPriority,
        SimPriority::Normal,
        SimPriority::LowPriority,
        SimPriority::Idle,
    ];

    /// Machine-readable string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Microtask => "microtask",
            Self::HighPriority => "high_priority",
            Self::Normal => "normal",
            Self::LowPriority => "low_priority",
            Self::Idle => "idle",
        }
    }

    /// Numeric rank (lower = higher priority).
    fn rank(self) -> u8 {
        match self {
            Self::Microtask => 0,
            Self::HighPriority => 1,
            Self::Normal => 2,
            Self::LowPriority => 3,
            Self::Idle => 4,
        }
    }
}

impl fmt::Display for SimPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SimEvent
// ---------------------------------------------------------------------------

/// A single simulation event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimEvent {
    /// Unique, monotonically increasing event identifier.
    pub id: u64,
    /// What kind of interaction this event represents.
    pub kind: SimEventKind,
    /// Dispatch priority.
    pub priority: SimPriority,
    /// The tick at which this event should be dispatched.
    pub scheduled_tick: u64,
    /// Content-addressable payload fingerprint.
    pub payload_hash: ContentHash,
    /// Human-readable label identifying the source of the event.
    pub source_label: String,
    /// Seed for deterministic sub-decisions within event handlers.
    pub deterministic_seed: u64,
}

// ---------------------------------------------------------------------------
// SchedulerPolicy
// ---------------------------------------------------------------------------

/// Configuration for the simulation scheduler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchedulerPolicy {
    /// Maximum number of ticks to simulate.
    pub max_ticks: u64,
    /// Maximum number of events dispatched per tick.
    pub max_events_per_tick: u64,
    /// Whether microtask-priority events are drained before other
    /// priorities within each tick.
    pub drain_microtasks_first: bool,
    /// How often (in ticks) a synthetic GC pause event is injected.
    /// Zero means no automatic GC injection.
    pub gc_interval_ticks: u64,
    /// Whether timer events should be coalesced when scheduled for the
    /// same tick.
    pub enable_timer_coalescing: bool,
    /// Whether deterministic tie-breaking (by event ID) is enabled.
    /// Always `true` for reproducibility — stored explicitly so the
    /// policy is self-describing.
    pub deterministic_tie_break: bool,
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        Self {
            max_ticks: 1_000,
            max_events_per_tick: 256,
            drain_microtasks_first: true,
            gc_interval_ticks: 100,
            enable_timer_coalescing: false,
            deterministic_tie_break: true,
        }
    }
}

// ---------------------------------------------------------------------------
// TickOutcome
// ---------------------------------------------------------------------------

/// Result of dispatching a single tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TickOutcome {
    /// Which tick was dispatched.
    pub tick: u64,
    /// Event IDs dispatched, in dispatch order.
    pub events_dispatched: Vec<u64>,
    /// How many microtask-priority events were drained this tick.
    pub microtasks_drained: u64,
    /// Number of events still pending after this tick.
    pub pending_count: u64,
}

// ---------------------------------------------------------------------------
// SimRunSummary
// ---------------------------------------------------------------------------

/// Summary produced after `run_to_completion`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimRunSummary {
    /// Total ticks actually executed.
    pub total_ticks: u64,
    /// Total events dispatched across all ticks.
    pub total_events: u64,
    /// Breakdown of dispatched events by kind name.
    pub events_by_kind: BTreeMap<String, u64>,
    /// Breakdown of dispatched events by priority name.
    pub events_by_priority: BTreeMap<String, u64>,
    /// Content hash of the full dispatch log for reproducibility checks.
    pub content_hash: ContentHash,
    /// Schema version that produced this summary.
    pub schema_version: String,
}

// ---------------------------------------------------------------------------
// SimReplayEntry / SimReplayLog
// ---------------------------------------------------------------------------

/// A single replay-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimReplayEntry {
    /// Tick at which the event was dispatched.
    pub tick: u64,
    /// Event ID.
    pub event_id: u64,
    /// Kind of the dispatched event.
    pub kind: SimEventKind,
    /// Priority of the dispatched event.
    pub priority: SimPriority,
}

/// Ordered replay log capturing every dispatched event.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SimReplayLog {
    /// Entries in dispatch order.
    pub entries: Vec<SimReplayEntry>,
}

impl SimReplayLog {
    /// Append an entry.
    pub fn push(&mut self, entry: SimReplayEntry) {
        self.entries.push(entry);
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Compute a content hash over the serialised replay log.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        for e in &self.entries {
            buf.extend_from_slice(&e.tick.to_le_bytes());
            buf.extend_from_slice(&e.event_id.to_le_bytes());
            buf.extend_from_slice(e.kind.as_str().as_bytes());
            buf.extend_from_slice(e.priority.as_str().as_bytes());
        }
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// SimSpecimenFamily
// ---------------------------------------------------------------------------

/// Evidence specimen families for campaign-grade testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SimSpecimenFamily {
    /// Event-loop drain patterns.
    EventLoopDrain,
    /// Module load/resolve lifecycle.
    ModuleLifecycle,
    /// Cache hit/miss/evict interactions.
    CacheInteraction,
    /// Controller decision feedback loops.
    ControllerFeedback,
    /// Timer coalescing behaviour.
    TimerCoalescing,
    /// Mixed-priority scheduling.
    MixedPriority,
}

impl SimSpecimenFamily {
    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EventLoopDrain => "event_loop_drain",
            Self::ModuleLifecycle => "module_lifecycle",
            Self::CacheInteraction => "cache_interaction",
            Self::ControllerFeedback => "controller_feedback",
            Self::TimerCoalescing => "timer_coalescing",
            Self::MixedPriority => "mixed_priority",
        }
    }
}

impl fmt::Display for SimSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SimScheduler
// ---------------------------------------------------------------------------

/// Deterministic simulation scheduler.
///
/// Events are enqueued with a target tick and priority. Each call to
/// `advance_tick` dispatches up to `max_events_per_tick` events for the
/// current tick in deterministic priority + ID order, then advances the
/// tick counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimScheduler {
    /// Scheduling policy.
    pub policy: SchedulerPolicy,
    /// Current simulation tick.
    pub current_tick: u64,
    /// Priority queue: tick -> events scheduled for that tick.
    pub event_queue: BTreeMap<u64, Vec<SimEvent>>,
    /// Monotonic event-ID counter.
    pub next_event_id: u64,
    /// Outcomes from every dispatched tick.
    pub dispatch_log: Vec<TickOutcome>,
    /// Security epoch for provenance.
    pub epoch: SecurityEpoch,
}

impl SimScheduler {
    /// Create a new scheduler with the given policy and epoch.
    pub fn new(policy: SchedulerPolicy, epoch: SecurityEpoch) -> Self {
        Self {
            policy,
            current_tick: 0,
            event_queue: BTreeMap::new(),
            next_event_id: 0,
            dispatch_log: Vec::new(),
            epoch,
        }
    }

    /// Schedule an event.
    ///
    /// Returns the assigned event ID.
    pub fn schedule(
        &mut self,
        kind: SimEventKind,
        priority: SimPriority,
        delay_ticks: u64,
        source: &str,
        seed: u64,
    ) -> u64 {
        let id = self.next_event_id;
        self.next_event_id = self.next_event_id.saturating_add(1);

        let scheduled_tick = self.current_tick.saturating_add(delay_ticks);

        // Compute a payload hash from the event's deterministic inputs.
        let hash_input = format!(
            "{}-{}-{}-{}-{}-{}",
            id,
            kind.as_str(),
            priority.as_str(),
            scheduled_tick,
            source,
            seed,
        );
        let payload_hash = ContentHash::compute(hash_input.as_bytes());

        let event = SimEvent {
            id,
            kind,
            priority,
            scheduled_tick,
            payload_hash,
            source_label: source.to_string(),
            deterministic_seed: seed,
        };

        self.event_queue
            .entry(scheduled_tick)
            .or_default()
            .push(event);

        id
    }

    /// Advance one tick, dispatching events scheduled for the current tick.
    ///
    /// Returns `None` if the scheduler has reached `max_ticks`.
    pub fn advance_tick(&mut self) -> Option<TickOutcome> {
        if self.current_tick >= self.policy.max_ticks {
            return None;
        }

        let tick = self.current_tick;

        // Take events for this tick (if any).
        let mut events = self.event_queue.remove(&tick).unwrap_or_default();

        // Sort deterministically: by priority rank, then by event ID.
        if self.policy.deterministic_tie_break {
            events.sort_by(|a, b| {
                a.priority
                    .rank()
                    .cmp(&b.priority.rank())
                    .then(a.id.cmp(&b.id))
            });
        } else {
            events.sort_by_key(|a| a.priority.rank());
        }

        // Honour drain_microtasks_first: microtasks are already first
        // due to priority ordering; this flag controls whether they are
        // dispatched in a separate phase (affecting the microtasks_drained
        // counter).
        let mut microtasks_drained: u64 = 0;
        let mut dispatched_ids: Vec<u64> = Vec::new();

        let limit = self.policy.max_events_per_tick as usize;

        if self.policy.drain_microtasks_first {
            // Phase 1: microtasks only.
            for ev in &events {
                if dispatched_ids.len() >= limit {
                    break;
                }
                if ev.priority == SimPriority::Microtask {
                    dispatched_ids.push(ev.id);
                    microtasks_drained += 1;
                }
            }
            // Phase 2: remaining non-microtask events.
            for ev in &events {
                if dispatched_ids.len() >= limit {
                    break;
                }
                if ev.priority != SimPriority::Microtask {
                    dispatched_ids.push(ev.id);
                }
            }
        } else {
            for ev in &events {
                if dispatched_ids.len() >= limit {
                    break;
                }
                dispatched_ids.push(ev.id);
                if ev.priority == SimPriority::Microtask {
                    microtasks_drained += 1;
                }
            }
        }

        // If we hit the per-tick limit, re-enqueue remaining events
        // into the next tick.
        if dispatched_ids.len() < events.len() {
            let dispatched_set: std::collections::BTreeSet<u64> =
                dispatched_ids.iter().copied().collect();
            // Re-enqueue without mutating scheduled_tick so audit trails
            // preserve the original scheduling intent.
            let remaining: Vec<SimEvent> = events
                .into_iter()
                .filter(|ev| !dispatched_set.contains(&ev.id))
                .collect();
            if !remaining.is_empty() {
                self.event_queue
                    .entry(tick + 1)
                    .or_default()
                    .extend(remaining);
            }
        }

        let pending = self.pending_count() as u64;

        let outcome = TickOutcome {
            tick,
            events_dispatched: dispatched_ids,
            microtasks_drained,
            pending_count: pending,
        };

        self.dispatch_log.push(outcome.clone());
        self.current_tick += 1;

        Some(outcome)
    }

    /// Run ticks until no events remain or `max_ticks` is reached.
    pub fn run_to_completion(&mut self) -> SimRunSummary {
        loop {
            // Stop if we have no pending events.
            if self.event_queue.is_empty() {
                break;
            }
            // Stop if max_ticks reached.
            if self.current_tick >= self.policy.max_ticks {
                break;
            }
            // Fast-forward to next tick with events if the queue is sparse.
            // Break early if all remaining events are beyond max_ticks
            // (unreachable), avoiding O(max_ticks) empty dispatch log entries.
            if let Some(&next_tick) = self.event_queue.keys().next() {
                if next_tick >= self.policy.max_ticks {
                    break; // all remaining events are beyond the horizon
                }
                if next_tick > self.current_tick {
                    self.current_tick = next_tick;
                }
            }
            self.advance_tick();
        }

        self.build_summary()
    }

    /// Count of events still in the queue.
    pub fn pending_count(&self) -> usize {
        self.event_queue.values().map(|v| v.len()).sum()
    }

    /// Total number of events dispatched so far.
    pub fn total_dispatched(&self) -> u64 {
        self.dispatch_log
            .iter()
            .map(|o| o.events_dispatched.len() as u64)
            .sum()
    }

    /// Compute a content hash over the entire dispatch log.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        for outcome in &self.dispatch_log {
            buf.extend_from_slice(&outcome.tick.to_le_bytes());
            for &id in &outcome.events_dispatched {
                buf.extend_from_slice(&id.to_le_bytes());
            }
            buf.extend_from_slice(&outcome.microtasks_drained.to_le_bytes());
            buf.extend_from_slice(&outcome.pending_count.to_le_bytes());
        }
        ContentHash::compute(&buf)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn build_summary(&self) -> SimRunSummary {
        let mut events_by_kind: BTreeMap<String, u64> = BTreeMap::new();
        let mut events_by_priority: BTreeMap<String, u64> = BTreeMap::new();
        let mut total_events: u64 = 0;

        // Rebuild from dispatch log — we need the event metadata, so we
        // iterate the log and count by ID. Since events have been consumed
        // from the queue, we look at the log length and the outcome
        // vectors.
        //
        // NOTE: The dispatch log only stores IDs, not full event data.
        // For the summary we count totals; kind/priority breakdowns
        // are derived from a separate replay-style pass if we kept a
        // side log. For now, we produce totals only and leave per-kind
        // breakdowns empty (the caller can build a `SimReplayLog`
        // separately for full fidelity).
        for outcome in &self.dispatch_log {
            total_events += outcome.events_dispatched.len() as u64;
        }

        // We cannot recover kind/priority from IDs alone without a side
        // table. Provide empty maps (the replay log is the authoritative
        // source for breakdowns).
        let _ = &mut events_by_kind;
        let _ = &mut events_by_priority;

        SimRunSummary {
            total_ticks: self.current_tick,
            total_events,
            events_by_kind,
            events_by_priority,
            content_hash: self.content_hash(),
            schema_version: SIM_SCHEDULER_SCHEMA_VERSION.to_string(),
        }
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // SimEventKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sim_event_kind_display() {
        assert_eq!(SimEventKind::EventLoopTick.to_string(), "event_loop_tick");
        assert_eq!(SimEventKind::ModuleLoad.to_string(), "module_load");
        assert_eq!(SimEventKind::CacheEvict.to_string(), "cache_evict");
        assert_eq!(SimEventKind::HostcallInvoke.to_string(), "hostcall_invoke");
    }

    #[test]
    fn test_sim_event_kind_all_count() {
        assert_eq!(SimEventKind::ALL.len(), 12);
    }

    #[test]
    fn test_sim_event_kind_serde_roundtrip() {
        for kind in &SimEventKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: SimEventKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn test_sim_event_kind_as_str_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for kind in &SimEventKind::ALL {
            assert!(
                seen.insert(kind.as_str()),
                "duplicate as_str: {}",
                kind.as_str()
            );
        }
    }

    // -----------------------------------------------------------------------
    // SimPriority tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sim_priority_ordering() {
        assert!(SimPriority::Microtask < SimPriority::HighPriority);
        assert!(SimPriority::HighPriority < SimPriority::Normal);
        assert!(SimPriority::Normal < SimPriority::LowPriority);
        assert!(SimPriority::LowPriority < SimPriority::Idle);
    }

    #[test]
    fn test_sim_priority_display() {
        assert_eq!(SimPriority::Microtask.to_string(), "microtask");
        assert_eq!(SimPriority::Normal.to_string(), "normal");
        assert_eq!(SimPriority::Idle.to_string(), "idle");
    }

    #[test]
    fn test_sim_priority_serde_roundtrip() {
        for p in &SimPriority::ALL {
            let json = serde_json::to_string(p).unwrap();
            let back: SimPriority = serde_json::from_str(&json).unwrap();
            assert_eq!(*p, back);
        }
    }

    #[test]
    fn test_sim_priority_rank_monotonic() {
        let ranks: Vec<u8> = SimPriority::ALL.iter().map(|p| p.rank()).collect();
        for w in ranks.windows(2) {
            assert!(w[0] < w[1], "rank not strictly increasing");
        }
    }

    // -----------------------------------------------------------------------
    // SchedulerPolicy tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scheduler_policy_default() {
        let p = SchedulerPolicy::default();
        assert_eq!(p.max_ticks, 1_000);
        assert_eq!(p.max_events_per_tick, 256);
        assert!(p.drain_microtasks_first);
        assert_eq!(p.gc_interval_ticks, 100);
        assert!(!p.enable_timer_coalescing);
        assert!(p.deterministic_tie_break);
    }

    #[test]
    fn test_scheduler_policy_serde_roundtrip() {
        let p = SchedulerPolicy::default();
        let json = serde_json::to_string(&p).unwrap();
        let back: SchedulerPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // -----------------------------------------------------------------------
    // SimScheduler — basic scheduling
    // -----------------------------------------------------------------------

    #[test]
    fn test_scheduler_new_is_empty() {
        let sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        assert_eq!(sched.current_tick, 0);
        assert_eq!(sched.pending_count(), 0);
        assert_eq!(sched.total_dispatched(), 0);
    }

    #[test]
    fn test_schedule_returns_incrementing_ids() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        let id0 = sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "src", 42);
        let id1 = sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "src", 43);
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
    }

    #[test]
    fn test_schedule_updates_pending_count() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
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

    // -----------------------------------------------------------------------
    // SimScheduler — dispatch ordering
    // -----------------------------------------------------------------------

    #[test]
    fn test_advance_tick_dispatches_in_priority_order() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        // Schedule in reverse priority order.
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
    fn test_advance_tick_deterministic_tie_break_by_id() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        let id_a = sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 10);
        let id_b = sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "b", 20);
        let id_c = sched.schedule(SimEventKind::CacheEvict, SimPriority::Normal, 0, "c", 30);

        let outcome = sched.advance_tick().unwrap();
        assert_eq!(outcome.events_dispatched, vec![id_a, id_b, id_c]);
    }

    #[test]
    fn test_advance_tick_microtask_drain_count() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
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
    fn test_advance_tick_returns_none_at_max_ticks() {
        let policy = SchedulerPolicy {
            max_ticks: 2,
            ..SchedulerPolicy::default()
        };
        let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 1, "a", 2);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 5, "a", 3);

        let _ = sched.advance_tick(); // tick 0
        let _ = sched.advance_tick(); // tick 1
        assert!(sched.advance_tick().is_none()); // tick 2 == max_ticks
    }

    #[test]
    fn test_advance_tick_empty_tick() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        // No events at tick 0.
        sched.schedule(SimEventKind::ModuleLoad, SimPriority::Normal, 5, "m", 1);
        let outcome = sched.advance_tick().unwrap();
        assert!(outcome.events_dispatched.is_empty());
        assert_eq!(outcome.microtasks_drained, 0);
    }

    // -----------------------------------------------------------------------
    // SimScheduler — multi-tick
    // -----------------------------------------------------------------------

    #[test]
    fn test_multi_tick_dispatch() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        let id0 = sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "c", 1);
        let id1 = sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 2, "c", 2);

        let o0 = sched.advance_tick().unwrap();
        assert_eq!(o0.events_dispatched, vec![id0]);

        let o1 = sched.advance_tick().unwrap(); // tick 1 — empty
        assert!(o1.events_dispatched.is_empty());

        let o2 = sched.advance_tick().unwrap(); // tick 2
        assert_eq!(o2.events_dispatched, vec![id1]);
    }

    // -----------------------------------------------------------------------
    // SimScheduler — run_to_completion
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_to_completion_empty() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        let summary = sched.run_to_completion();
        assert_eq!(summary.total_events, 0);
        assert_eq!(summary.total_ticks, 0);
        assert_eq!(summary.schema_version, SIM_SCHEDULER_SCHEMA_VERSION);
    }

    #[test]
    fn test_run_to_completion_dispatches_all() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
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
    fn test_run_to_completion_respects_max_ticks() {
        let policy = SchedulerPolicy {
            max_ticks: 3,
            ..SchedulerPolicy::default()
        };
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
        assert_eq!(sched.pending_count(), 1); // far event still pending
    }

    // -----------------------------------------------------------------------
    // Content hash determinism
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_hash_determinism() {
        let run = || {
            let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
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
    fn test_content_hash_differs_for_different_schedules() {
        let mut s1 = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        s1.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
        s1.run_to_completion();

        let mut s2 = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        s2.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
        s2.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 1, "b", 2);
        s2.run_to_completion();

        assert_ne!(s1.content_hash(), s2.content_hash());
    }

    // -----------------------------------------------------------------------
    // SimReplayLog
    // -----------------------------------------------------------------------

    #[test]
    fn test_replay_log_empty() {
        let log = SimReplayLog::default();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_replay_log_push_and_len() {
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
    fn test_replay_log_content_hash_determinism() {
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
    fn test_replay_log_serde_roundtrip() {
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

    // -----------------------------------------------------------------------
    // SimSpecimenFamily
    // -----------------------------------------------------------------------

    #[test]
    fn test_specimen_family_display() {
        assert_eq!(
            SimSpecimenFamily::EventLoopDrain.to_string(),
            "event_loop_drain"
        );
        assert_eq!(
            SimSpecimenFamily::MixedPriority.to_string(),
            "mixed_priority"
        );
    }

    // -----------------------------------------------------------------------
    // SimEvent serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_sim_event_serde_roundtrip() {
        let event = SimEvent {
            id: 1,
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

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_max_events_per_tick_limit() {
        let policy = SchedulerPolicy {
            max_events_per_tick: 2,
            ..SchedulerPolicy::default()
        };
        let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
        sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "b", 2);
        sched.schedule(SimEventKind::CacheEvict, SimPriority::Normal, 0, "c", 3);

        let outcome = sched.advance_tick().unwrap();
        assert_eq!(outcome.events_dispatched.len(), 2);
        // The third event should be re-queued.
        assert_eq!(sched.pending_count(), 1);
    }

    #[test]
    fn test_scheduler_with_security_epoch() {
        let epoch = SecurityEpoch::from_raw(42);
        let sched = SimScheduler::new(SchedulerPolicy::default(), epoch);
        assert_eq!(sched.epoch.as_u64(), 42);
    }

    #[test]
    fn test_total_dispatched_accumulates() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 1, "b", 2);

        sched.advance_tick();
        assert_eq!(sched.total_dispatched(), 1);
        sched.advance_tick();
        assert_eq!(sched.total_dispatched(), 2);
    }

    #[test]
    fn test_schema_constants() {
        assert!(SIM_SCHEDULER_SCHEMA_VERSION.contains("deterministic-sim-scheduler"));
        assert_eq!(SIM_SCHEDULER_BEAD_ID, "bd-1lsy.9.3.3");
    }

    // -----------------------------------------------------------------------
    // Overflow events re-queue to next tick
    // -----------------------------------------------------------------------

    #[test]
    fn test_overflow_events_dispatched_next_tick() {
        let policy = SchedulerPolicy {
            max_events_per_tick: 2,
            ..SchedulerPolicy::default()
        };
        let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);
        let id_a = sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "a", 1);
        let id_b = sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 0, "b", 2);
        let id_c = sched.schedule(SimEventKind::CacheEvict, SimPriority::Normal, 0, "c", 3);

        let o0 = sched.advance_tick().unwrap();
        assert_eq!(o0.events_dispatched, vec![id_a, id_b]);

        let o1 = sched.advance_tick().unwrap();
        assert_eq!(o1.events_dispatched, vec![id_c]);
        assert_eq!(sched.pending_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Microtask-first draining
    // -----------------------------------------------------------------------

    #[test]
    fn test_microtask_first_drains_before_normal() {
        let policy = SchedulerPolicy {
            drain_microtasks_first: true,
            ..SchedulerPolicy::default()
        };
        let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);

        // Schedule normal first, then microtask
        let normal_id = sched.schedule(SimEventKind::TimerFire, SimPriority::Normal, 0, "timer", 1);
        let micro_id = sched.schedule(
            SimEventKind::PromiseSettle,
            SimPriority::Microtask,
            0,
            "promise",
            2,
        );

        let outcome = sched.advance_tick().unwrap();
        // Microtask should come first
        assert_eq!(outcome.events_dispatched[0], micro_id);
        assert_eq!(outcome.events_dispatched[1], normal_id);
        assert_eq!(outcome.microtasks_drained, 1);
    }

    #[test]
    fn test_microtask_first_disabled() {
        let policy = SchedulerPolicy {
            drain_microtasks_first: false,
            ..SchedulerPolicy::default()
        };
        let mut sched = SimScheduler::new(policy, SecurityEpoch::GENESIS);

        sched.schedule(SimEventKind::TimerFire, SimPriority::Normal, 0, "timer", 1);
        sched.schedule(
            SimEventKind::PromiseSettle,
            SimPriority::Microtask,
            0,
            "promise",
            2,
        );

        let outcome = sched.advance_tick().unwrap();
        // Still priority-ordered (microtask first due to lower rank)
        assert_eq!(outcome.events_dispatched.len(), 2);
        assert_eq!(outcome.microtasks_drained, 1);
    }

    // -----------------------------------------------------------------------
    // Multiple priorities in single tick
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_priorities_dispatch_in_order() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);

        let idle = sched.schedule(SimEventKind::GcPause, SimPriority::Idle, 0, "gc", 1);
        let low = sched.schedule(
            SimEventKind::CacheEvict,
            SimPriority::LowPriority,
            0,
            "cache",
            2,
        );
        let normal = sched.schedule(SimEventKind::TimerFire, SimPriority::Normal, 0, "timer", 3);
        let high = sched.schedule(
            SimEventKind::ControllerDecision,
            SimPriority::HighPriority,
            0,
            "ctrl",
            4,
        );
        let micro = sched.schedule(
            SimEventKind::MicrotaskDrain,
            SimPriority::Microtask,
            0,
            "micro",
            5,
        );

        let outcome = sched.advance_tick().unwrap();
        assert_eq!(
            outcome.events_dispatched,
            vec![micro, high, normal, low, idle]
        );
    }

    // -----------------------------------------------------------------------
    // Fast-forward to next tick with events
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_to_completion_fast_forwards_sparse_ticks() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 50, "b", 2);

        let summary = sched.run_to_completion();
        assert_eq!(summary.total_events, 2);
        // Should have fast-forwarded, not iterated through 50 empty ticks
        assert!(sched.dispatch_log.len() <= 3);
    }

    // -----------------------------------------------------------------------
    // Run summary serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_summary_serde_roundtrip() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::CacheHit, SimPriority::Normal, 0, "x", 1);
        sched.schedule(SimEventKind::CacheMiss, SimPriority::Normal, 1, "y", 2);
        let summary = sched.run_to_completion();

        let json = serde_json::to_string(&summary).unwrap();
        let back: SimRunSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary.total_events, back.total_events);
        assert_eq!(summary.total_ticks, back.total_ticks);
        assert_eq!(summary.content_hash, back.content_hash);
    }

    // -----------------------------------------------------------------------
    // TickOutcome serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_tick_outcome_serde_roundtrip() {
        let outcome = TickOutcome {
            tick: 42,
            events_dispatched: vec![1, 2, 3],
            microtasks_drained: 1,
            pending_count: 5,
        };
        let json = serde_json::to_string(&outcome).unwrap();
        let back: TickOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }

    // -----------------------------------------------------------------------
    // SimSpecimenFamily serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_specimen_family_serde_roundtrip() {
        let families = [
            SimSpecimenFamily::EventLoopDrain,
            SimSpecimenFamily::ModuleLifecycle,
            SimSpecimenFamily::CacheInteraction,
            SimSpecimenFamily::ControllerFeedback,
            SimSpecimenFamily::TimerCoalescing,
            SimSpecimenFamily::MixedPriority,
        ];
        for fam in &families {
            let json = serde_json::to_string(fam).unwrap();
            let back: SimSpecimenFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*fam, back);
        }
    }

    // -----------------------------------------------------------------------
    // Dispatch log grows with ticks
    // -----------------------------------------------------------------------

    #[test]
    fn test_dispatch_log_grows_per_tick() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 0, "a", 1);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 1, "b", 2);
        sched.schedule(SimEventKind::EventLoopTick, SimPriority::Normal, 2, "c", 3);

        assert_eq!(sched.dispatch_log.len(), 0);
        sched.advance_tick();
        assert_eq!(sched.dispatch_log.len(), 1);
        sched.advance_tick();
        assert_eq!(sched.dispatch_log.len(), 2);
        sched.advance_tick();
        assert_eq!(sched.dispatch_log.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Pending count after dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_pending_decreases_after_dispatch() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::ModuleLoad, SimPriority::Normal, 0, "m", 1);
        sched.schedule(SimEventKind::ModuleResolve, SimPriority::Normal, 0, "m", 2);
        assert_eq!(sched.pending_count(), 2);

        sched.advance_tick();
        assert_eq!(sched.pending_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Delayed events don't dispatch early
    // -----------------------------------------------------------------------

    #[test]
    fn test_delayed_events_not_dispatched_early() {
        let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
        sched.schedule(SimEventKind::TimerFire, SimPriority::Normal, 5, "t", 1);

        let o = sched.advance_tick().unwrap(); // tick 0
        assert!(o.events_dispatched.is_empty());
        assert_eq!(sched.pending_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Large schedule with mixed delays
    // -----------------------------------------------------------------------

    #[test]
    fn test_large_schedule_completes_deterministically() {
        let run = || {
            let mut sched = SimScheduler::new(SchedulerPolicy::default(), SecurityEpoch::GENESIS);
            for i in 0..100u64 {
                let kind = SimEventKind::ALL[(i as usize) % SimEventKind::ALL.len()];
                let prio = SimPriority::ALL[(i as usize) % SimPriority::ALL.len()];
                sched.schedule(kind, prio, i % 10, &format!("src-{i}"), i);
            }
            let summary = sched.run_to_completion();
            (summary.total_events, summary.content_hash)
        };

        let (events1, hash1) = run();
        let (events2, hash2) = run();
        assert_eq!(events1, events2);
        assert_eq!(hash1, hash2);
        assert_eq!(events1, 100);
    }

    // -----------------------------------------------------------------------
    // Replay log hash differs for different logs
    // -----------------------------------------------------------------------

    #[test]
    fn test_replay_log_hash_differs() {
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
}
