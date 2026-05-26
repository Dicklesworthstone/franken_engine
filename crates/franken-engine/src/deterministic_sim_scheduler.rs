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
    /// Create a new empty replay log with capacity hints.
    pub fn new() -> Self {
        // H6.1 audit: scheduler bench shows ~100+ dispatched events per completion cycle
        Self {
            entries: Vec::with_capacity(128),
        }
    }

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
    /// Ordered metadata for every dispatched event.
    pub replay_log: SimReplayLog,
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
            replay_log: SimReplayLog::new(),
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

        // Take events for this tick (if any). An empty or missing bucket is a
        // legitimate no-op tick — advance_tick must never panic on sparse schedules.
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
        let mut replay_entries: Vec<SimReplayEntry> = Vec::new();

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
                    replay_entries.push(SimReplayEntry {
                        tick,
                        event_id: ev.id,
                        kind: ev.kind,
                        priority: ev.priority,
                    });
                }
            }
            // Phase 2: remaining non-microtask events.
            for ev in &events {
                if dispatched_ids.len() >= limit {
                    break;
                }
                if ev.priority != SimPriority::Microtask {
                    dispatched_ids.push(ev.id);
                    replay_entries.push(SimReplayEntry {
                        tick,
                        event_id: ev.id,
                        kind: ev.kind,
                        priority: ev.priority,
                    });
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
                replay_entries.push(SimReplayEntry {
                    tick,
                    event_id: ev.id,
                    kind: ev.kind,
                    priority: ev.priority,
                });
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
        for entry in replay_entries {
            self.replay_log.push(entry);
        }
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

        for entry in &self.replay_log.entries {
            total_events = total_events.saturating_add(1);
            let kind = entry.kind.as_str().to_string();
            let priority = entry.priority.as_str().to_string();
            events_by_kind
                .entry(kind)
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
            events_by_priority
                .entry(priority)
                .and_modify(|count| *count = count.saturating_add(1))
                .or_insert(1);
        }

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
            let json = serde_json::to_string(kind).expect("serialize derived Serialize");
            let back: SimEventKind =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            let json = serde_json::to_string(p).expect("serialize derived Serialize");
            let back: SimPriority =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&p).expect("serialize derived Serialize");
        let back: SchedulerPolicy =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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

        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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
        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let o0 = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
        assert_eq!(o0.events_dispatched, vec![id0]);

        let o1 = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs"); // tick 1 — empty
        assert!(o1.events_dispatched.is_empty());

        let o2 = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs"); // tick 2
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
        let log = SimReplayLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn test_replay_log_push_and_len() {
        let mut log = SimReplayLog::new();
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
            let mut log = SimReplayLog::new();
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
        let mut log = SimReplayLog::new();
        log.push(SimReplayEntry {
            tick: 7,
            event_id: 99,
            kind: SimEventKind::GcPause,
            priority: SimPriority::Idle,
        });
        let json = serde_json::to_string(&log).expect("serialize derived Serialize");
        let back: SimReplayLog = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&event).expect("serialize derived Serialize");
        let back: SimEvent = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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

        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let o0 = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
        assert_eq!(o0.events_dispatched, vec![id_a, id_b]);

        let o1 = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let outcome = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs");
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

        let json = serde_json::to_string(&summary).expect("serialize derived Serialize");
        let back: SimRunSummary =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
        let json = serde_json::to_string(&outcome).expect("serialize derived Serialize");
        let back: TickOutcome = serde_json::from_str(&json).expect("deserialize known-valid JSON");
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
            let json = serde_json::to_string(fam).expect("serialize derived Serialize");
            let back: SimSpecimenFamily =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
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

        let o = sched
            .advance_tick()
            .expect("operation should succeed for valid inputs"); // tick 0
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
        let mut log1 = SimReplayLog::new();
        log1.push(SimReplayEntry {
            tick: 0,
            event_id: 1,
            kind: SimEventKind::CacheHit,
            priority: SimPriority::Normal,
        });

        let mut log2 = SimReplayLog::new();
        log2.push(SimReplayEntry {
            tick: 0,
            event_id: 2,
            kind: SimEventKind::CacheMiss,
            priority: SimPriority::Normal,
        });

        assert_ne!(log1.content_hash(), log2.content_hash());
    }

    // -- Metamorphic Task Ordering Equivalence Tests (bd-3i0z8) --

    #[test]
    fn scheduler_task_ordering_equivalence_same_priority() {
        // For equal-priority tasks scheduled at the same tick, deterministic tie-break
        // dispatches in monotonic event-ID order. Since IDs are assigned in schedule-call
        // order, the property demonstrated is FIFO-stability per scheduler instance — NOT
        // permutation-invariance across schedulers. (Cross-scheduler invariance is only
        // guaranteed when priorities differ; see preserves_priority_constraints below.)
        let mut scheduler_a = SimScheduler::new(
            SchedulerPolicy {
                max_ticks: 10,
                max_events_per_tick: 100,
                drain_microtasks_first: false,
                gc_interval_ticks: 0,
                enable_timer_coalescing: false,
                deterministic_tie_break: true,
            },
            SecurityEpoch::from_raw(42),
        );

        let mut scheduler_b =
            SimScheduler::new(scheduler_a.policy.clone(), SecurityEpoch::from_raw(42));

        // Scheduler A: order [task_a, task_b, task_c]
        let id_a1 = scheduler_a.schedule(
            SimEventKind::EventLoopTick,
            SimPriority::Normal,
            0,
            "task_a",
            100,
        );
        let id_a2 = scheduler_a.schedule(
            SimEventKind::ModuleLoad,
            SimPriority::Normal,
            0,
            "task_b",
            200,
        );
        let id_a3 = scheduler_a.schedule(
            SimEventKind::CacheHit,
            SimPriority::Normal,
            0,
            "task_c",
            300,
        );

        // Scheduler B: order [task_c, task_a, task_b] (permuted input)
        let id_b3 = scheduler_b.schedule(
            SimEventKind::CacheHit,
            SimPriority::Normal,
            0,
            "task_c",
            300,
        );
        let id_b1 = scheduler_b.schedule(
            SimEventKind::EventLoopTick,
            SimPriority::Normal,
            0,
            "task_a",
            100,
        );
        let id_b2 = scheduler_b.schedule(
            SimEventKind::ModuleLoad,
            SimPriority::Normal,
            0,
            "task_b",
            200,
        );

        let outcome_a = scheduler_a.advance_tick().expect("should dispatch events");
        let outcome_b = scheduler_b.advance_tick().expect("should dispatch events");

        // Each scheduler dispatches in its own ID-assignment (= schedule-call) order.
        assert_eq!(outcome_a.events_dispatched, vec![id_a1, id_a2, id_a3]);
        assert_eq!(outcome_b.events_dispatched, vec![id_b3, id_b1, id_b2]);
        assert_eq!(outcome_a.events_dispatched.len(), 3);
        assert_eq!(outcome_b.events_dispatched.len(), 3);
    }

    #[test]
    fn scheduler_task_ordering_preserves_priority_constraints() {
        // Test that different priorities are preserved regardless of input order
        let mut scheduler_a = SimScheduler::new(
            SchedulerPolicy {
                max_ticks: 10,
                max_events_per_tick: 100,
                drain_microtasks_first: false,
                gc_interval_ticks: 0,
                enable_timer_coalescing: false,
                deterministic_tie_break: true,
            },
            SecurityEpoch::from_raw(42),
        );

        let mut scheduler_b =
            SimScheduler::new(scheduler_a.policy.clone(), SecurityEpoch::from_raw(42));

        // Scheduler A: order [low, normal, high] (worst priority first)
        let low_a = scheduler_a.schedule(
            SimEventKind::CacheEvict,
            SimPriority::LowPriority,
            0,
            "low_priority",
            300,
        );
        let normal_a = scheduler_a.schedule(
            SimEventKind::ModuleLoad,
            SimPriority::Normal,
            0,
            "normal_priority",
            200,
        );
        let high_a = scheduler_a.schedule(
            SimEventKind::HostcallInvoke,
            SimPriority::HighPriority,
            0,
            "high_priority",
            100,
        );

        // Scheduler B: order [normal, high, low] (different input order)
        let normal_b = scheduler_b.schedule(
            SimEventKind::ModuleLoad,
            SimPriority::Normal,
            0,
            "normal_priority",
            200,
        );
        let high_b = scheduler_b.schedule(
            SimEventKind::HostcallInvoke,
            SimPriority::HighPriority,
            0,
            "high_priority",
            100,
        );
        let low_b = scheduler_b.schedule(
            SimEventKind::CacheEvict,
            SimPriority::LowPriority,
            0,
            "low_priority",
            300,
        );

        let outcome_a = scheduler_a.advance_tick().expect("should dispatch events");
        let outcome_b = scheduler_b.advance_tick().expect("should dispatch events");

        // Distinct-priority tasks dispatch in priority order regardless of input order.
        // Priority ranks (lower = earlier): HighPriority=1, Normal=2, LowPriority=3.
        assert_eq!(outcome_a.events_dispatched, vec![high_a, normal_a, low_a]);
        assert_eq!(outcome_b.events_dispatched, vec![high_b, normal_b, low_b]);

        // Both schedulers should have same number of events and priority ordering
        assert_eq!(outcome_a.events_dispatched.len(), 3);
        assert_eq!(outcome_b.events_dispatched.len(), 3);
    }

    #[test]
    fn scheduler_task_ordering_equivalence_mixed_priorities() {
        // Test with tasks having mixed priorities and IDs
        let mut scheduler_a = SimScheduler::new(
            SchedulerPolicy {
                max_ticks: 10,
                max_events_per_tick: 100,
                drain_microtasks_first: false,
                gc_interval_ticks: 0,
                enable_timer_coalescing: false,
                deterministic_tie_break: true,
            },
            SecurityEpoch::from_raw(42),
        );

        let mut scheduler_b =
            SimScheduler::new(scheduler_a.policy.clone(), SecurityEpoch::from_raw(42));

        // Scheduler A: schedule tasks in order [Normal(5), High(1), Normal(3), High(2), Low(4)]
        let task5_a = scheduler_a.schedule(
            SimEventKind::EventLoopTick,
            SimPriority::Normal,
            0,
            "task_5",
            500,
        );
        let task1_a = scheduler_a.schedule(
            SimEventKind::HostcallInvoke,
            SimPriority::HighPriority,
            0,
            "task_1",
            100,
        );
        let task3_a = scheduler_a.schedule(
            SimEventKind::CacheMiss,
            SimPriority::Normal,
            0,
            "task_3",
            300,
        );
        let task2_a = scheduler_a.schedule(
            SimEventKind::ControllerDecision,
            SimPriority::HighPriority,
            0,
            "task_2",
            200,
        );
        let task4_a = scheduler_a.schedule(
            SimEventKind::GcPause,
            SimPriority::LowPriority,
            0,
            "task_4",
            400,
        );

        // Scheduler B: schedule tasks in reverse order [Low(4), High(2), Normal(3), High(1), Normal(5)]
        let task4_b = scheduler_b.schedule(
            SimEventKind::GcPause,
            SimPriority::LowPriority,
            0,
            "task_4",
            400,
        );
        let task2_b = scheduler_b.schedule(
            SimEventKind::ControllerDecision,
            SimPriority::HighPriority,
            0,
            "task_2",
            200,
        );
        let task3_b = scheduler_b.schedule(
            SimEventKind::CacheMiss,
            SimPriority::Normal,
            0,
            "task_3",
            300,
        );
        let task1_b = scheduler_b.schedule(
            SimEventKind::HostcallInvoke,
            SimPriority::HighPriority,
            0,
            "task_1",
            100,
        );
        let task5_b = scheduler_b.schedule(
            SimEventKind::EventLoopTick,
            SimPriority::Normal,
            0,
            "task_5",
            500,
        );

        let outcome_a = scheduler_a.advance_tick().expect("should dispatch events");
        let outcome_b = scheduler_b.advance_tick().expect("should dispatch events");

        // Sort key per advance_tick: (priority.rank(), event_id), with ranks
        // HighPriority=1 < Normal=2 < LowPriority=3.
        // A's IDs by priority: High=[1,3], Normal=[0,2], Low=[4] → dispatch [1,3,0,2,4]
        let expected_a = vec![task1_a, task2_a, task5_a, task3_a, task4_a];
        // B's IDs by priority: High=[1,3], Normal=[2,4], Low=[0] → dispatch [1,3,2,4,0]
        let expected_b = vec![task2_b, task1_b, task3_b, task5_b, task4_b];

        assert_eq!(outcome_a.events_dispatched, expected_a);
        assert_eq!(outcome_b.events_dispatched, expected_b);

        // Both should have 5 events dispatched
        assert_eq!(outcome_a.events_dispatched.len(), 5);
        assert_eq!(outcome_b.events_dispatched.len(), 5);
    }

    #[test]
    fn scheduler_task_ordering_empty_and_single_task_edge_cases() {
        // Edge cases: zero tasks and one task. advance_tick must handle the
        // sparse-schedule case without panicking (see unwrap_or_default above).
        let policy = SchedulerPolicy {
            max_ticks: 10,
            max_events_per_tick: 100,
            drain_microtasks_first: false,
            gc_interval_ticks: 0,
            enable_timer_coalescing: false,
            deterministic_tie_break: true,
        };

        // Empty scheduler — no-op tick, zero dispatched, pending stays zero.
        let mut empty_scheduler = SimScheduler::new(policy.clone(), SecurityEpoch::from_raw(42));
        let outcome_empty = empty_scheduler
            .advance_tick()
            .expect("advance_tick must handle empty queues");
        assert_eq!(outcome_empty.events_dispatched.len(), 0);
        assert_eq!(outcome_empty.pending_count, 0);

        // Single task — dispatches exactly the one scheduled event.
        let mut single_scheduler = SimScheduler::new(policy, SecurityEpoch::from_raw(42));
        let task_id = single_scheduler.schedule(
            SimEventKind::EventLoopTick,
            SimPriority::Normal,
            0,
            "single_task",
            4200,
        );
        let outcome_single = single_scheduler
            .advance_tick()
            .expect("should dispatch single task");
        assert_eq!(outcome_single.events_dispatched, vec![task_id]);
    }

    #[test]
    fn scheduler_task_ordering_fifo_same_priority_same_tick() {
        // Test FIFO behavior for tasks with identical priority scheduled for same tick
        let mut scheduler_a = SimScheduler::new(
            SchedulerPolicy {
                max_ticks: 10,
                max_events_per_tick: 100,
                drain_microtasks_first: false,
                gc_interval_ticks: 0,
                enable_timer_coalescing: false,
                deterministic_tie_break: true, // Sorts by ID for determinism
            },
            SecurityEpoch::from_raw(42),
        );

        let mut scheduler_b =
            SimScheduler::new(scheduler_a.policy.clone(), SecurityEpoch::from_raw(42));

        // Scheduler A: schedule fifo_task_1..fifo_task_5 (ascending source label).
        let task_ids_a: Vec<u64> = (1..=5)
            .map(|i| {
                scheduler_a.schedule(
                    SimEventKind::ModuleResolve,
                    SimPriority::Normal,
                    0,
                    &format!("fifo_task_{}", i),
                    i * 100,
                )
            })
            .collect();

        // Scheduler B: schedule fifo_task_5..fifo_task_1 (descending source label).
        let task_ids_b: Vec<u64> = (1..=5)
            .rev()
            .map(|i| {
                scheduler_b.schedule(
                    SimEventKind::ModuleResolve,
                    SimPriority::Normal,
                    0,
                    &format!("fifo_task_{}", i),
                    i * 100,
                )
            })
            .collect();

        let outcome_a = scheduler_a.advance_tick().expect("should dispatch tasks");
        let outcome_b = scheduler_b.advance_tick().expect("should dispatch tasks");

        // Event IDs are assigned monotonically per scheduler call, so both task_ids
        // vectors are [0,1,2,3,4]; advance_tick re-sorts by ID, so dispatch == schedule
        // order in each scheduler. The semantic dispatch is opposite (A: 1..5, B: 5..1),
        // again confirming this is FIFO-stability per scheduler instance, not metamorphic
        // equivalence across permutations.
        assert_eq!(outcome_a.events_dispatched, task_ids_a);
        assert_eq!(outcome_b.events_dispatched, task_ids_b);
        assert_eq!(task_ids_a, vec![0, 1, 2, 3, 4]);
        assert_eq!(task_ids_b, vec![0, 1, 2, 3, 4]);

        // Both should have 5 tasks dispatched
        assert_eq!(outcome_a.events_dispatched.len(), 5);
        assert_eq!(outcome_b.events_dispatched.len(), 5);
    }

    #[test]
    fn metamorphic_task_ordering_equivalence_under_independent_swap() {
        // Metamorphic test: swapping two independent tasks should produce
        // equivalent scheduling outcomes modulo explicit priority constraints.
        //
        // This test implements the metamorphic property specified in bd-3i0z8:
        // schedule(X) ~ schedule(T(X)) where T(X) is X with independent tasks swapped.

        let policy = SchedulerPolicy {
            max_ticks: 10,
            max_events_per_tick: 100,
            drain_microtasks_first: true,
            gc_interval_ticks: 0,
            enable_timer_coalescing: false,
            deterministic_tie_break: true,
        };

        let mut scheduler_original =
            SimScheduler::new(policy.clone(), SecurityEpoch::from_raw(100));
        let mut scheduler_swapped = SimScheduler::new(policy, SecurityEpoch::from_raw(100));

        // Create task set X: 4 tasks with different priorities to establish independence
        // - task_1: High priority (always dispatched first)
        // - task_2: Normal priority (independent from task_3)
        // - task_3: Normal priority (independent from task_2)
        // - task_4: Low priority (always dispatched last)
        let tasks = vec![
            ("task_high", SimPriority::HighPriority, 1000),
            ("task_normal_a", SimPriority::Normal, 2000),
            ("task_normal_b", SimPriority::Normal, 3000),
            ("task_low", SimPriority::LowPriority, 4000),
        ];

        // Schedule tasks in original order: high, normal_a, normal_b, low
        let mut original_ids = Vec::new();
        for (label, priority, payload) in &tasks {
            let id = scheduler_original.schedule(
                SimEventKind::ModuleResolve,
                *priority,
                0,
                label,
                *payload,
            );
            original_ids.push(id);
        }

        // Schedule tasks in swapped order: high, normal_b, normal_a, low
        // This swaps the two independent normal-priority tasks
        let swapped_tasks = vec![
            ("task_high", SimPriority::HighPriority, 1000),
            ("task_normal_b", SimPriority::Normal, 3000), // Swapped
            ("task_normal_a", SimPriority::Normal, 2000), // Swapped
            ("task_low", SimPriority::LowPriority, 4000),
        ];

        let mut swapped_ids = Vec::new();
        for (label, priority, payload) in &swapped_tasks {
            let id = scheduler_swapped.schedule(
                SimEventKind::ModuleResolve,
                *priority,
                0,
                label,
                *payload,
            );
            swapped_ids.push(id);
        }

        let event_map_by_id = |scheduler: &SimScheduler| -> BTreeMap<u64, SimEvent> {
            scheduler
                .event_queue
                .values()
                .flat_map(|events| events.iter().cloned())
                .map(|event| (event.id, event))
                .collect()
        };

        let original_event_map = event_map_by_id(&scheduler_original);
        let swapped_event_map = event_map_by_id(&scheduler_swapped);

        // Dispatch both schedulers
        let outcome_original = scheduler_original
            .advance_tick()
            .expect("original scheduler should dispatch tasks");
        let outcome_swapped = scheduler_swapped
            .advance_tick()
            .expect("swapped scheduler should dispatch tasks");

        // Metamorphic property verification:
        // Priority-based dispatch order should be: High -> Normal tasks -> Low
        // The two normal tasks are independent, so their relative order within
        // the normal priority band doesn't affect correctness.

        // Both outcomes should have 4 tasks dispatched
        assert_eq!(outcome_original.events_dispatched.len(), 4);
        assert_eq!(outcome_swapped.events_dispatched.len(), 4);

        // Extract the dispatched events for analysis
        let original_events: Vec<_> = outcome_original
            .events_dispatched
            .iter()
            .map(|id| {
                original_event_map
                    .get(id)
                    .expect("dispatched event should exist in scheduled snapshot")
                    .clone()
            })
            .collect();
        let swapped_events: Vec<_> = outcome_swapped
            .events_dispatched
            .iter()
            .map(|id| {
                swapped_event_map
                    .get(id)
                    .expect("dispatched event should exist in scheduled snapshot")
                    .clone()
            })
            .collect();

        // Priority equivalence: both should dispatch in priority order
        assert_eq!(original_events[0].priority, SimPriority::HighPriority);
        assert_eq!(original_events[3].priority, SimPriority::LowPriority);
        assert_eq!(swapped_events[0].priority, SimPriority::HighPriority);
        assert_eq!(swapped_events[3].priority, SimPriority::LowPriority);

        // The two middle events should both be Normal priority (order may vary)
        assert_eq!(original_events[1].priority, SimPriority::Normal);
        assert_eq!(original_events[2].priority, SimPriority::Normal);
        assert_eq!(swapped_events[1].priority, SimPriority::Normal);
        assert_eq!(swapped_events[2].priority, SimPriority::Normal);

        // Metamorphic equivalence: the set of payloads should be identical
        // (regardless of order within same priority level)
        let mut original_payloads: Vec<_> = original_events
            .iter()
            .map(|e| e.deterministic_seed)
            .collect();
        let mut swapped_payloads: Vec<_> = swapped_events
            .iter()
            .map(|e| e.deterministic_seed)
            .collect();

        original_payloads.sort_unstable();
        swapped_payloads.sort_unstable();
        assert_eq!(original_payloads, swapped_payloads);

        // Priority band invariant: High priority task always first, Low always last
        assert_eq!(original_events[0].deterministic_seed, 1000); // task_high
        assert_eq!(original_events[3].deterministic_seed, 4000); // task_low
        assert_eq!(swapped_events[0].deterministic_seed, 1000); // task_high
        assert_eq!(swapped_events[3].deterministic_seed, 4000); // task_low

        // The normal-priority tasks (2000, 3000) can appear in either order
        // within their priority band, confirming independence property
        let normal_payloads_original: std::collections::BTreeSet<_> = original_events[1..3]
            .iter()
            .map(|e| e.deterministic_seed)
            .collect();
        let normal_payloads_swapped: std::collections::BTreeSet<_> = swapped_events[1..3]
            .iter()
            .map(|e| e.deterministic_seed)
            .collect();
        let expected_normal_payloads = [2000, 3000].iter().copied().collect();

        assert_eq!(normal_payloads_original, expected_normal_payloads);
        assert_eq!(normal_payloads_swapped, expected_normal_payloads);
    }
}
