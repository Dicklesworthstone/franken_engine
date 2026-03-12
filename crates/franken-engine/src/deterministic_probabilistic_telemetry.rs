//! Deterministic probabilistic telemetry and evidence-thinning for hot runtime paths.
//!
//! Bead: bd-1lsy.11.20 [RGC-066]
//!
//! Provides an engine-level observability-under-budget plane so hot runtime paths
//! can emit useful telemetry without paying full exact-counting cost. Users,
//! operators, and GA evidence consumers can always determine whether an artifact
//! or claim came from default budgeted capture, exact-shadow validation,
//! deterministic replay, or probabilistic sampling.
//!
//! # Design
//!
//! - `CaptureMode`: five-valued enum classifying how an event was captured.
//! - `TelemetryBudget`: per-window event budget with sampling rate and mode.
//! - `ThinningPolicy`: four-valued enum for evidence-thinning strategies.
//! - `ThinningConfig`: parameters for a thinning pass.
//! - `TelemetryEvent`: a single telemetry observation with provenance hashing.
//! - `EventWindow`: time-windowed event buffer with budget enforcement and
//!   automatic thinning on overflow.
//! - `ProvenanceTag`: fidelity metadata attached to every telemetry artifact.
//! - `ModeBreakdown`: per-mode counts in a report.
//! - `TelemetryReport`: aggregate report across windows with mode breakdowns,
//!   budget utilization, and content hash.
//! - `TelemetryPlane`: the top-level orchestrator that manages budgets, records
//!   events, thins windows, and generates reports.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-066]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.deterministic-probabilistic-telemetry.v1";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.11.20";

/// Component name for diagnostics.
pub const COMPONENT: &str = "deterministic_probabilistic_telemetry";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-066";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default maximum events per window.
pub const DEFAULT_MAX_EVENTS_PER_WINDOW: u64 = 10_000;

/// Default window size in nanoseconds (1 second).
pub const DEFAULT_WINDOW_NS: u64 = 1_000_000_000;

/// Default sampling rate (millionths). 100_000 = 10%.
pub const DEFAULT_SAMPLING_RATE_MILLIONTHS: u64 = 100_000;

/// Default target events after thinning.
pub const DEFAULT_THINNING_TARGET: u64 = 1_000;

/// Default minimum weight for retained events (millionths).
pub const DEFAULT_MIN_WEIGHT_MILLIONTHS: u64 = 1_000;

/// Default reservoir size for reservoir sampling.
pub const DEFAULT_RESERVOIR_SIZE: u64 = 500;

/// Maximum domains tracked per plane.
pub const MAX_DOMAINS: usize = 256;

/// Maximum windows retained per plane.
pub const MAX_WINDOWS: usize = 1_024;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// CaptureMode
// ---------------------------------------------------------------------------

/// How a telemetry event was captured.
///
/// Ordering is from highest fidelity to lowest:
/// - `ExactCounting` — every event recorded with zero loss.
/// - `ExactShadow` — exact copy validated against a sampled primary.
/// - `DeterministicReplay` — replayed from a deterministic trace.
/// - `BudgetedSampling` — sampled within a budget window.
/// - `ProbabilisticSampling` — sampled with a randomised policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Every event recorded with zero loss.
    ExactCounting,
    /// Exact-shadow validation path: full copy cross-checked against primary.
    ExactShadow,
    /// Replayed from a deterministic execution trace.
    DeterministicReplay,
    /// Sampled under a per-window budget.
    BudgetedSampling,
    /// Sampled with a randomised (probabilistic) policy.
    ProbabilisticSampling,
}

impl CaptureMode {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::ExactCounting,
        Self::ExactShadow,
        Self::DeterministicReplay,
        Self::BudgetedSampling,
        Self::ProbabilisticSampling,
    ];

    /// Stable snake_case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExactCounting => "exact_counting",
            Self::ExactShadow => "exact_shadow",
            Self::DeterministicReplay => "deterministic_replay",
            Self::BudgetedSampling => "budgeted_sampling",
            Self::ProbabilisticSampling => "probabilistic_sampling",
        }
    }

    /// Whether this mode provides exact (non-sampled) data.
    #[must_use]
    pub const fn is_exact(self) -> bool {
        matches!(self, Self::ExactCounting | Self::ExactShadow)
    }

    /// Whether this mode is a sampling mode.
    #[must_use]
    pub const fn is_sampled(self) -> bool {
        matches!(self, Self::BudgetedSampling | Self::ProbabilisticSampling)
    }

    /// Whether events captured in this mode can be deterministically replayed.
    #[must_use]
    pub const fn is_replay_safe(self) -> bool {
        matches!(self, Self::ExactCounting | Self::DeterministicReplay)
    }
}

impl fmt::Display for CaptureMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ThinningPolicy
// ---------------------------------------------------------------------------

/// Strategy for reducing event volume when a window exceeds budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinningPolicy {
    /// Keep every Nth event (uniform decimation).
    Uniform,
    /// Reservoir sampling: retain K events from N.
    Reservoir,
    /// Stratified by domain: proportional allocation per domain.
    Stratified,
    /// Priority: keep events with the highest weight.
    Priority,
}

impl ThinningPolicy {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::Uniform,
        Self::Reservoir,
        Self::Stratified,
        Self::Priority,
    ];

    /// Stable snake_case label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uniform => "uniform",
            Self::Reservoir => "reservoir",
            Self::Stratified => "stratified",
            Self::Priority => "priority",
        }
    }
}

impl fmt::Display for ThinningPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TelemetryBudget
// ---------------------------------------------------------------------------

/// Per-window event budget controlling how many events may be recorded
/// and at what sampling rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryBudget {
    /// Maximum events that may be recorded within one window.
    pub max_events_per_window: u64,
    /// Window duration in nanoseconds.
    pub window_ns: u64,
    /// Sampling rate in millionths (1_000_000 = 100%).
    pub sampling_rate_millionths: u64,
    /// Capture mode for events produced under this budget.
    pub mode: CaptureMode,
}

impl TelemetryBudget {
    /// Create a budget with the specified parameters.
    #[must_use]
    pub fn new(
        max_events_per_window: u64,
        window_ns: u64,
        sampling_rate_millionths: u64,
        mode: CaptureMode,
    ) -> Self {
        Self {
            max_events_per_window,
            window_ns,
            sampling_rate_millionths: sampling_rate_millionths.min(MILLIONTHS),
            mode,
        }
    }

    /// Create a default budget for exact counting (100% rate, 10k events/sec).
    #[must_use]
    pub fn exact() -> Self {
        Self::new(
            DEFAULT_MAX_EVENTS_PER_WINDOW,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        )
    }

    /// Create a default budgeted-sampling budget.
    #[must_use]
    pub fn budgeted_default() -> Self {
        Self::new(
            DEFAULT_MAX_EVENTS_PER_WINDOW,
            DEFAULT_WINDOW_NS,
            DEFAULT_SAMPLING_RATE_MILLIONTHS,
            CaptureMode::BudgetedSampling,
        )
    }

    /// Whether the budget allows 100% capture.
    #[must_use]
    pub fn is_full_capture(&self) -> bool {
        self.sampling_rate_millionths >= MILLIONTHS
    }

    /// Compute the effective events-per-second this budget allows.
    #[must_use]
    pub fn effective_events_per_second(&self) -> u64 {
        if self.window_ns == 0 {
            return 0;
        }
        // events_per_window * (1_000_000_000 / window_ns)
        let windows_per_second = 1_000_000_000_u64.checked_div(self.window_ns).unwrap_or(0);
        self.max_events_per_window
            .saturating_mul(windows_per_second)
    }
}

impl fmt::Display for TelemetryBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TelemetryBudget(max={} window_ns={} rate={} mode={})",
            self.max_events_per_window, self.window_ns, self.sampling_rate_millionths, self.mode,
        )
    }
}

// ---------------------------------------------------------------------------
// ThinningConfig
// ---------------------------------------------------------------------------

/// Configuration for a thinning pass applied to an overflowed window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinningConfig {
    /// Which thinning strategy to apply.
    pub policy: ThinningPolicy,
    /// Target number of events after thinning.
    pub target_events: u64,
    /// Minimum weight (millionths) for an event to survive thinning.
    pub min_weight_millionths: u64,
}

impl ThinningConfig {
    /// Create a thinning configuration.
    #[must_use]
    pub fn new(policy: ThinningPolicy, target_events: u64, min_weight_millionths: u64) -> Self {
        Self {
            policy,
            target_events: target_events.max(1),
            min_weight_millionths,
        }
    }

    /// Default uniform thinning.
    #[must_use]
    pub fn uniform_default() -> Self {
        Self::new(
            ThinningPolicy::Uniform,
            DEFAULT_THINNING_TARGET,
            DEFAULT_MIN_WEIGHT_MILLIONTHS,
        )
    }

    /// Default priority thinning.
    #[must_use]
    pub fn priority_default() -> Self {
        Self::new(
            ThinningPolicy::Priority,
            DEFAULT_THINNING_TARGET,
            DEFAULT_MIN_WEIGHT_MILLIONTHS,
        )
    }

    /// Default reservoir thinning.
    #[must_use]
    pub fn reservoir_default() -> Self {
        Self::new(
            ThinningPolicy::Reservoir,
            DEFAULT_RESERVOIR_SIZE,
            DEFAULT_MIN_WEIGHT_MILLIONTHS,
        )
    }
}

impl fmt::Display for ThinningConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ThinningConfig(policy={} target={} min_weight={})",
            self.policy, self.target_events, self.min_weight_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// TelemetryEvent
// ---------------------------------------------------------------------------

/// A single telemetry observation emitted from a hot runtime path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Unique identifier for this event.
    pub event_id: String,
    /// Domain (subsystem) that produced the event.
    pub domain: String,
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// How this event was captured.
    pub capture_mode: CaptureMode,
    /// Weight in millionths — for sampled events this is the inverse
    /// probability so downstream consumers can compute scaled-up estimates.
    /// Exact events have weight = 1_000_000.
    pub weight_millionths: u64,
    /// Content hash of the event payload.
    pub payload_hash: ContentHash,
    /// Content hash of the full event (including metadata).
    pub event_hash: ContentHash,
}

impl TelemetryEvent {
    /// Create a new event, computing hashes deterministically.
    #[must_use]
    pub fn new(
        event_id: &str,
        domain: &str,
        timestamp_ns: u64,
        capture_mode: CaptureMode,
        weight_millionths: u64,
        payload: &[u8],
    ) -> Self {
        let payload_hash = compute_digest(payload);

        let mut buf = Vec::with_capacity(256);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, event_id);
        append_str(&mut buf, domain);
        append_u64(&mut buf, timestamp_ns);
        append_str(&mut buf, capture_mode.as_str());
        append_u64(&mut buf, weight_millionths);
        buf.extend_from_slice(payload_hash.as_bytes());
        let event_hash = compute_digest(&buf);

        Self {
            event_id: event_id.to_owned(),
            domain: domain.to_owned(),
            timestamp_ns,
            capture_mode,
            weight_millionths,
            payload_hash,
            event_hash,
        }
    }

    /// Create an exact-counting event with weight = MILLIONTHS.
    #[must_use]
    pub fn exact(event_id: &str, domain: &str, timestamp_ns: u64, payload: &[u8]) -> Self {
        Self::new(
            event_id,
            domain,
            timestamp_ns,
            CaptureMode::ExactCounting,
            MILLIONTHS,
            payload,
        )
    }

    /// Create a sampled event with scaled weight.
    #[must_use]
    pub fn sampled(
        event_id: &str,
        domain: &str,
        timestamp_ns: u64,
        sampling_rate_millionths: u64,
        payload: &[u8],
    ) -> Self {
        let weight = MILLIONTHS
            .saturating_mul(MILLIONTHS)
            .checked_div(sampling_rate_millionths)
            .unwrap_or(MILLIONTHS);
        Self::new(
            event_id,
            domain,
            timestamp_ns,
            CaptureMode::ProbabilisticSampling,
            weight,
            payload,
        )
    }

    /// Whether this event represents exact (non-sampled) data.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.capture_mode.is_exact()
    }
}

impl fmt::Display for TelemetryEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TelemetryEvent({} domain={} mode={} weight={})",
            self.event_id, self.domain, self.capture_mode, self.weight_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// ProvenanceTag
// ---------------------------------------------------------------------------

/// Fidelity metadata attached to every telemetry artifact so downstream
/// consumers know how the data was obtained.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceTag {
    /// How the data was captured.
    pub capture_mode: CaptureMode,
    /// Sampling rate applied at capture time (millionths).
    pub sampling_rate_applied_millionths: u64,
    /// Whether evidence-thinning was applied post-capture.
    pub thinning_applied: bool,
    /// Whether an exact-shadow copy is available for cross-validation.
    pub exact_shadow_available: bool,
    /// Whether the data can be deterministically replayed.
    pub replay_deterministic: bool,
}

impl ProvenanceTag {
    /// Create a new provenance tag.
    #[must_use]
    pub fn new(
        capture_mode: CaptureMode,
        sampling_rate_applied_millionths: u64,
        thinning_applied: bool,
        exact_shadow_available: bool,
        replay_deterministic: bool,
    ) -> Self {
        Self {
            capture_mode,
            sampling_rate_applied_millionths,
            thinning_applied,
            exact_shadow_available,
            replay_deterministic,
        }
    }

    /// Tag for exact-counting data (100% rate, no thinning).
    #[must_use]
    pub fn exact() -> Self {
        Self::new(CaptureMode::ExactCounting, MILLIONTHS, false, false, true)
    }

    /// Tag for budgeted-sampling data.
    #[must_use]
    pub fn budgeted(sampling_rate_millionths: u64) -> Self {
        Self::new(
            CaptureMode::BudgetedSampling,
            sampling_rate_millionths,
            false,
            false,
            false,
        )
    }

    /// Tag for probabilistic sampling data.
    #[must_use]
    pub fn probabilistic(sampling_rate_millionths: u64) -> Self {
        Self::new(
            CaptureMode::ProbabilisticSampling,
            sampling_rate_millionths,
            false,
            false,
            false,
        )
    }

    /// Tag for exact-shadow validated data.
    #[must_use]
    pub fn exact_shadow() -> Self {
        Self::new(CaptureMode::ExactShadow, MILLIONTHS, false, true, false)
    }

    /// Tag for deterministic-replay data.
    #[must_use]
    pub fn replay() -> Self {
        Self::new(
            CaptureMode::DeterministicReplay,
            MILLIONTHS,
            false,
            false,
            true,
        )
    }

    /// Mark that thinning has been applied.
    #[must_use]
    pub fn with_thinning(mut self) -> Self {
        self.thinning_applied = true;
        self
    }

    /// Compute a content hash of this provenance tag.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, "provenance");
        append_str(&mut buf, self.capture_mode.as_str());
        append_u64(&mut buf, self.sampling_rate_applied_millionths);
        buf.push(u8::from(self.thinning_applied));
        buf.push(u8::from(self.exact_shadow_available));
        buf.push(u8::from(self.replay_deterministic));
        compute_digest(&buf)
    }

    /// Whether this tag represents high-fidelity (exact or shadow) data.
    #[must_use]
    pub fn is_high_fidelity(&self) -> bool {
        self.capture_mode.is_exact()
    }
}

impl fmt::Display for ProvenanceTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProvenanceTag(mode={} rate={} thinned={} shadow={} replay={})",
            self.capture_mode,
            self.sampling_rate_applied_millionths,
            self.thinning_applied,
            self.exact_shadow_available,
            self.replay_deterministic,
        )
    }
}

// ---------------------------------------------------------------------------
// EventWindow
// ---------------------------------------------------------------------------

/// A time-windowed buffer of telemetry events with budget enforcement
/// and automatic thinning on overflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventWindow {
    /// Window start time (nanoseconds).
    pub start_ns: u64,
    /// Window end time (nanoseconds). Zero means unbounded until closed.
    pub end_ns: u64,
    /// Events recorded in this window.
    pub events: Vec<TelemetryEvent>,
    /// How many events were offered but rejected due to budget exhaustion.
    pub rejected_count: u64,
    /// How many events were thinned (removed after acceptance).
    pub thinned_count: u64,
    /// Budget governing this window.
    pub budget: TelemetryBudget,
    /// Whether thinning has been applied.
    pub thinning_applied: bool,
    /// Domains seen in this window.
    pub domains_seen: BTreeSet<String>,
}

impl EventWindow {
    /// Create a new window starting at the given timestamp.
    #[must_use]
    pub fn new(start_ns: u64, budget: TelemetryBudget) -> Self {
        let end_ns = start_ns.saturating_add(budget.window_ns);
        Self {
            start_ns,
            end_ns,
            events: Vec::new(),
            rejected_count: 0,
            thinned_count: 0,
            budget,
            thinning_applied: false,
            domains_seen: BTreeSet::new(),
        }
    }

    /// Number of events currently in the window.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.events.len() as u64
    }

    /// Whether the window has reached its budget limit.
    #[must_use]
    pub fn is_at_capacity(&self) -> bool {
        self.event_count() >= self.budget.max_events_per_window
    }

    /// Remaining capacity in the window.
    #[must_use]
    pub fn remaining_capacity(&self) -> u64 {
        self.budget
            .max_events_per_window
            .saturating_sub(self.event_count())
    }

    /// Whether a timestamp falls within this window.
    #[must_use]
    pub fn contains_timestamp(&self, timestamp_ns: u64) -> bool {
        timestamp_ns >= self.start_ns && timestamp_ns < self.end_ns
    }

    /// Try to record an event in this window. Returns `true` if accepted,
    /// `false` if the budget is exhausted.
    pub fn record(&mut self, event: TelemetryEvent) -> bool {
        if self.is_at_capacity() {
            self.rejected_count += 1;
            return false;
        }
        self.domains_seen.insert(event.domain.clone());
        self.events.push(event);
        true
    }

    /// Compute the effective sampling rate for this window in millionths.
    ///
    /// If no events were rejected, the rate is 1_000_000 (100%).
    /// Otherwise, rate = accepted / (accepted + rejected), in millionths.
    #[must_use]
    pub fn effective_sampling_rate_millionths(&self) -> u64 {
        let total = self.event_count().saturating_add(self.rejected_count);
        if total == 0 {
            return MILLIONTHS;
        }
        self.event_count()
            .saturating_mul(MILLIONTHS)
            .checked_div(total)
            .unwrap_or(0)
    }

    /// Apply a thinning pass to reduce events to within the target.
    ///
    /// Returns the number of events removed.
    pub fn apply_thinning(&mut self, config: &ThinningConfig) -> u64 {
        let current = self.event_count();
        if current <= config.target_events {
            return 0;
        }

        let to_remove = current.saturating_sub(config.target_events) as usize;
        let removed = match config.policy {
            ThinningPolicy::Uniform => self.thin_uniform(to_remove),
            ThinningPolicy::Reservoir => self.thin_reservoir(config.target_events as usize),
            ThinningPolicy::Stratified => self.thin_stratified(config.target_events as usize),
            ThinningPolicy::Priority => self.thin_priority(to_remove, config.min_weight_millionths),
        };

        self.thinned_count = self.thinned_count.saturating_add(removed as u64);
        self.thinning_applied = true;

        // Rescale weights of surviving events to account for thinning.
        if !self.events.is_empty() {
            let scale_factor = current
                .saturating_mul(MILLIONTHS)
                .checked_div(self.event_count())
                .unwrap_or(MILLIONTHS);
            for ev in &mut self.events {
                ev.weight_millionths = ev
                    .weight_millionths
                    .saturating_mul(scale_factor)
                    .checked_div(MILLIONTHS)
                    .unwrap_or(ev.weight_millionths);
            }
        }

        removed as u64
    }

    /// Uniform thinning: remove every Nth event.
    fn thin_uniform(&mut self, to_remove: usize) -> usize {
        if self.events.is_empty() {
            return 0;
        }
        let total = self.events.len();
        let step = total / (to_remove + 1).max(1);
        if step == 0 {
            let kept = self
                .events
                .split_off(self.events.len().saturating_sub(to_remove));
            let removed = self.events.len();
            self.events = kept;
            return removed;
        }

        let mut remove_indices = BTreeSet::new();
        let mut idx = step.saturating_sub(1);
        while remove_indices.len() < to_remove && idx < total {
            remove_indices.insert(idx);
            idx += step;
        }
        // Fill remaining from the end if we didn't get enough.
        let mut fill_idx = total;
        while remove_indices.len() < to_remove && fill_idx > 0 {
            fill_idx -= 1;
            remove_indices.insert(fill_idx);
        }

        let removed = remove_indices.len();
        self.events = self
            .events
            .iter()
            .enumerate()
            .filter(|(i, _)| !remove_indices.contains(i))
            .map(|(_, ev)| ev.clone())
            .collect();
        removed
    }

    /// Reservoir thinning: keep exactly `reservoir_size` events
    /// using a deterministic selection based on event hashes.
    fn thin_reservoir(&mut self, reservoir_size: usize) -> usize {
        if self.events.len() <= reservoir_size {
            return 0;
        }
        // Sort by event_hash for deterministic selection, take the first K.
        self.events.sort_by_key(|a| a.event_hash);
        let removed = self.events.len() - reservoir_size;
        self.events.truncate(reservoir_size);
        removed
    }

    /// Stratified thinning: proportional allocation per domain.
    fn thin_stratified(&mut self, target: usize) -> usize {
        if self.events.len() <= target {
            return 0;
        }
        let total = self.events.len();

        // Count events per domain.
        let mut domain_counts: BTreeMap<String, usize> = BTreeMap::new();
        for ev in &self.events {
            *domain_counts.entry(ev.domain.clone()).or_insert(0) += 1;
        }

        // Allocate target proportionally.
        let mut domain_targets: BTreeMap<String, usize> = BTreeMap::new();
        let mut allocated = 0_usize;
        let domain_list: Vec<String> = domain_counts.keys().cloned().collect();
        for domain in &domain_list {
            let count = domain_counts[domain];
            let alloc = (count * target) / total;
            let alloc = alloc.max(1).min(count);
            domain_targets.insert(domain.clone(), alloc);
            allocated += alloc;
        }

        // Distribute any remaining budget to larger domains.
        let mut remaining = target.saturating_sub(allocated);
        for domain in &domain_list {
            if remaining == 0 {
                break;
            }
            let count = domain_counts[domain];
            let current_alloc = domain_targets[domain];
            if current_alloc < count {
                let extra = remaining.min(count - current_alloc);
                domain_targets.insert(domain.clone(), current_alloc + extra);
                remaining -= extra;
            }
        }

        // Keep the first N events from each domain (sorted by timestamp).
        let mut domain_taken: BTreeMap<String, usize> = BTreeMap::new();
        let old_len = self.events.len();
        self.events.retain(|ev| {
            let taken = domain_taken.entry(ev.domain.clone()).or_insert(0);
            let target_for_domain = domain_targets.get(&ev.domain).copied().unwrap_or(1);
            if *taken < target_for_domain {
                *taken += 1;
                true
            } else {
                false
            }
        });
        old_len - self.events.len()
    }

    /// Priority thinning: remove events with the lowest weight.
    fn thin_priority(&mut self, to_remove: usize, min_weight: u64) -> usize {
        if self.events.is_empty() {
            return 0;
        }
        // First remove all events below minimum weight.
        let old_len = self.events.len();
        self.events.retain(|ev| ev.weight_millionths >= min_weight);
        let removed_by_weight = old_len - self.events.len();

        let still_to_remove = to_remove.saturating_sub(removed_by_weight);
        if still_to_remove == 0 || self.events.is_empty() {
            return removed_by_weight;
        }

        // Sort by weight ascending, remove the lowest.
        self.events.sort_by_key(|ev| ev.weight_millionths);
        let remove_count = still_to_remove.min(self.events.len());
        self.events.drain(..remove_count);

        // Re-sort by timestamp for temporal ordering.
        self.events.sort_by_key(|ev| ev.timestamp_ns);
        removed_by_weight + remove_count
    }

    /// Compute a provenance tag summarising this window.
    #[must_use]
    pub fn provenance_tag(&self) -> ProvenanceTag {
        ProvenanceTag::new(
            self.budget.mode,
            self.effective_sampling_rate_millionths(),
            self.thinning_applied,
            self.budget.mode == CaptureMode::ExactShadow,
            self.budget.mode.is_replay_safe(),
        )
    }

    /// Compute a content hash of this window.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(512);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, "event_window");
        append_u64(&mut buf, self.start_ns);
        append_u64(&mut buf, self.end_ns);
        append_u64(&mut buf, self.event_count());
        append_u64(&mut buf, self.rejected_count);
        append_u64(&mut buf, self.thinned_count);
        for ev in &self.events {
            buf.extend_from_slice(ev.event_hash.as_bytes());
        }
        compute_digest(&buf)
    }
}

impl fmt::Display for EventWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EventWindow(start={} events={} rejected={} thinned={} mode={})",
            self.start_ns,
            self.event_count(),
            self.rejected_count,
            self.thinned_count,
            self.budget.mode,
        )
    }
}

// ---------------------------------------------------------------------------
// ModeBreakdown
// ---------------------------------------------------------------------------

/// Per-capture-mode event counts within a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeBreakdown {
    /// Capture mode.
    pub mode: CaptureMode,
    /// Number of events captured in this mode.
    pub event_count: u64,
    /// Fraction of total events in millionths.
    pub fraction_millionths: u64,
    /// Provenance tag for this mode.
    pub provenance: ProvenanceTag,
}

impl ModeBreakdown {
    /// Create a new mode breakdown entry.
    #[must_use]
    pub fn new(
        mode: CaptureMode,
        event_count: u64,
        total_events: u64,
        provenance: ProvenanceTag,
    ) -> Self {
        let fraction_millionths = if total_events > 0 {
            event_count
                .saturating_mul(MILLIONTHS)
                .checked_div(total_events)
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            mode,
            event_count,
            fraction_millionths,
            provenance,
        }
    }
}

impl fmt::Display for ModeBreakdown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModeBreakdown(mode={} count={} fraction={})",
            self.mode, self.event_count, self.fraction_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// TelemetryReport
// ---------------------------------------------------------------------------

/// Aggregate telemetry report across one or more windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryReport {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Security epoch at report generation.
    pub epoch: SecurityEpoch,
    /// Total events captured across all windows.
    pub total_events_captured: u64,
    /// Total events thinned across all windows.
    pub total_events_thinned: u64,
    /// Total events rejected across all windows.
    pub total_events_rejected: u64,
    /// Budget utilization in millionths (captured / budget capacity).
    pub budget_utilization_millionths: u64,
    /// Per-mode breakdowns.
    pub mode_breakdowns: Vec<ModeBreakdown>,
    /// Number of windows included.
    pub window_count: u64,
    /// Domains observed.
    pub domains: BTreeSet<String>,
    /// Content hash of the entire report.
    pub content_hash: ContentHash,
}

struct ReportHashInput<'a> {
    epoch: &'a SecurityEpoch,
    total_captured: u64,
    total_thinned: u64,
    total_rejected: u64,
    utilization: u64,
    breakdowns: &'a [ModeBreakdown],
    window_count: u64,
    domains: &'a BTreeSet<String>,
}

impl TelemetryReport {
    /// Compute the content hash for this report (excludes the hash field itself).
    #[must_use]
    fn compute_content_hash(input: &ReportHashInput<'_>) -> ContentHash {
        let mut buf = Vec::with_capacity(512);
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, COMPONENT);
        append_u64(&mut buf, input.epoch.as_u64());
        append_u64(&mut buf, input.total_captured);
        append_u64(&mut buf, input.total_thinned);
        append_u64(&mut buf, input.total_rejected);
        append_u64(&mut buf, input.utilization);
        append_u64(&mut buf, input.window_count);
        for bd in input.breakdowns {
            append_str(&mut buf, bd.mode.as_str());
            append_u64(&mut buf, bd.event_count);
        }
        for domain in input.domains {
            append_str(&mut buf, domain);
        }
        compute_digest(&buf)
    }

    /// Whether all data in this report is exact (non-sampled).
    #[must_use]
    pub fn is_all_exact(&self) -> bool {
        self.mode_breakdowns.iter().all(|b| b.mode.is_exact())
    }

    /// Whether any thinning was applied.
    #[must_use]
    pub fn has_thinning(&self) -> bool {
        self.total_events_thinned > 0
    }

    /// Fraction of events that survived thinning (millionths).
    #[must_use]
    pub fn survival_rate_millionths(&self) -> u64 {
        let total_offered = self
            .total_events_captured
            .saturating_add(self.total_events_thinned);
        if total_offered == 0 {
            return MILLIONTHS;
        }
        self.total_events_captured
            .saturating_mul(MILLIONTHS)
            .checked_div(total_offered)
            .unwrap_or(MILLIONTHS)
    }
}

impl fmt::Display for TelemetryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TelemetryReport(captured={} thinned={} rejected={} utilization={} windows={})",
            self.total_events_captured,
            self.total_events_thinned,
            self.total_events_rejected,
            self.budget_utilization_millionths,
            self.window_count,
        )
    }
}

// ---------------------------------------------------------------------------
// TelemetryPlane
// ---------------------------------------------------------------------------

/// Top-level orchestrator for deterministic probabilistic telemetry.
///
/// Manages budgets, records events into time windows, applies thinning,
/// and generates aggregate reports with full provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryPlane {
    /// Active budgets keyed by domain.
    pub budgets: BTreeMap<String, TelemetryBudget>,
    /// Default budget for domains without an explicit budget.
    pub default_budget: TelemetryBudget,
    /// Active windows keyed by domain.
    pub windows: BTreeMap<String, Vec<EventWindow>>,
    /// Default thinning configuration.
    pub default_thinning: ThinningConfig,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
    /// Total events recorded across all time.
    pub total_events_recorded: u64,
    /// Total events rejected across all time.
    pub total_events_rejected: u64,
}

impl TelemetryPlane {
    /// Create a new telemetry plane with defaults.
    #[must_use]
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            budgets: BTreeMap::new(),
            default_budget: TelemetryBudget::budgeted_default(),
            windows: BTreeMap::new(),
            default_thinning: ThinningConfig::uniform_default(),
            epoch,
            total_events_recorded: 0,
            total_events_rejected: 0,
        }
    }

    /// Create a plane with a custom default budget.
    #[must_use]
    pub fn with_default_budget(epoch: SecurityEpoch, budget: TelemetryBudget) -> Self {
        let mut plane = Self::new(epoch);
        plane.default_budget = budget;
        plane
    }

    /// Add or replace a per-domain budget.
    pub fn add_budget(&mut self, domain: &str, budget: TelemetryBudget) {
        self.budgets.insert(domain.to_owned(), budget);
    }

    /// Set the default thinning configuration.
    pub fn set_default_thinning(&mut self, config: ThinningConfig) {
        self.default_thinning = config;
    }

    /// Get the effective budget for a domain.
    #[must_use]
    pub fn effective_budget(&self, domain: &str) -> &TelemetryBudget {
        self.budgets.get(domain).unwrap_or(&self.default_budget)
    }

    /// Find or create the active window for the given domain and timestamp.
    fn active_window(&mut self, domain: &str, timestamp_ns: u64) -> &mut EventWindow {
        let budget = self.effective_budget(domain).clone();
        let windows = self.windows.entry(domain.to_owned()).or_default();

        // Check if the latest window can accept this timestamp.
        let needs_new = if let Some(last) = windows.last() {
            !last.contains_timestamp(timestamp_ns) || last.is_at_capacity()
        } else {
            true
        };

        if needs_new {
            // Enforce maximum windows per domain.
            if windows.len() >= MAX_WINDOWS {
                windows.remove(0);
            }
            let window = EventWindow::new(timestamp_ns, budget);
            windows.push(window);
        }

        windows.last_mut().expect("just pushed")
    }

    /// Record a telemetry event. Returns `true` if accepted, `false` if
    /// the window budget was exhausted.
    pub fn record_event(&mut self, event: TelemetryEvent) -> bool {
        let domain = event.domain.clone();
        let ts = event.timestamp_ns;
        let window = self.active_window(&domain, ts);
        let accepted = window.record(event);
        if accepted {
            self.total_events_recorded += 1;
        } else {
            self.total_events_rejected += 1;
        }
        accepted
    }

    /// Record an exact-counting event.
    pub fn record_exact(
        &mut self,
        event_id: &str,
        domain: &str,
        timestamp_ns: u64,
        payload: &[u8],
    ) -> bool {
        let event = TelemetryEvent::exact(event_id, domain, timestamp_ns, payload);
        self.record_event(event)
    }

    /// Record a sampled event.
    pub fn record_sampled(
        &mut self,
        event_id: &str,
        domain: &str,
        timestamp_ns: u64,
        sampling_rate_millionths: u64,
        payload: &[u8],
    ) -> bool {
        let event = TelemetryEvent::sampled(
            event_id,
            domain,
            timestamp_ns,
            sampling_rate_millionths,
            payload,
        );
        self.record_event(event)
    }

    /// Apply thinning to the most recent window for the given domain.
    /// Returns the number of events removed, or 0 if no window exists.
    pub fn thin_domain(&mut self, domain: &str, config: &ThinningConfig) -> u64 {
        if let Some(windows) = self.windows.get_mut(domain)
            && let Some(window) = windows.last_mut()
        {
            return window.apply_thinning(config);
        }
        0
    }

    /// Apply default thinning to all active (most recent) windows.
    /// Returns the total number of events removed.
    pub fn thin_all(&mut self) -> u64 {
        let config = self.default_thinning.clone();
        let domains: Vec<String> = self.windows.keys().cloned().collect();
        let mut total_removed = 0_u64;
        for domain in &domains {
            total_removed += self.thin_domain(domain, &config);
        }
        total_removed
    }

    /// Generate an aggregate telemetry report.
    #[must_use]
    pub fn generate_report(&self) -> TelemetryReport {
        let mut total_captured = 0_u64;
        let mut total_thinned = 0_u64;
        let mut total_rejected = 0_u64;
        let mut total_capacity = 0_u64;
        let mut window_count = 0_u64;
        let mut domains = BTreeSet::new();
        let mut mode_counts: BTreeMap<CaptureMode, u64> = BTreeMap::new();
        let mut mode_provenance: BTreeMap<CaptureMode, ProvenanceTag> = BTreeMap::new();

        for (domain, windows) in &self.windows {
            domains.insert(domain.clone());
            for window in windows {
                window_count += 1;
                total_captured += window.event_count();
                total_thinned += window.thinned_count;
                total_rejected += window.rejected_count;
                total_capacity += window.budget.max_events_per_window;

                for ev in &window.events {
                    *mode_counts.entry(ev.capture_mode).or_insert(0) += 1;
                }

                // Use the window's provenance for its mode.
                let tag = window.provenance_tag();
                mode_provenance.entry(window.budget.mode).or_insert(tag);

                for d in &window.domains_seen {
                    domains.insert(d.clone());
                }
            }
        }

        let budget_utilization_millionths = if total_capacity > 0 {
            total_captured
                .saturating_mul(MILLIONTHS)
                .checked_div(total_capacity)
                .unwrap_or(0)
        } else {
            0
        };

        let mut mode_breakdowns: Vec<ModeBreakdown> = Vec::new();
        for mode in CaptureMode::ALL {
            let count = mode_counts.get(mode).copied().unwrap_or(0);
            if count > 0 {
                let provenance = mode_provenance
                    .get(mode)
                    .cloned()
                    .unwrap_or_else(|| ProvenanceTag::new(*mode, MILLIONTHS, false, false, false));
                mode_breakdowns.push(ModeBreakdown::new(*mode, count, total_captured, provenance));
            }
        }

        let content_hash = TelemetryReport::compute_content_hash(&ReportHashInput {
            epoch: &self.epoch,
            total_captured,
            total_thinned,
            total_rejected,
            utilization: budget_utilization_millionths,
            breakdowns: &mode_breakdowns,
            window_count,
            domains: &domains,
        });

        TelemetryReport {
            schema_version: SCHEMA_VERSION.to_owned(),
            component: COMPONENT.to_owned(),
            epoch: self.epoch,
            total_events_captured: total_captured,
            total_events_thinned: total_thinned,
            total_events_rejected: total_rejected,
            budget_utilization_millionths,
            mode_breakdowns,
            window_count,
            domains,
            content_hash,
        }
    }

    /// Number of domains with active windows.
    #[must_use]
    pub fn active_domain_count(&self) -> usize {
        self.windows.len()
    }

    /// Total events across all windows for a domain.
    #[must_use]
    pub fn domain_event_count(&self, domain: &str) -> u64 {
        self.windows
            .get(domain)
            .map(|ws| ws.iter().map(|w| w.event_count()).sum())
            .unwrap_or(0)
    }

    /// All domains that have been observed.
    #[must_use]
    pub fn observed_domains(&self) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for (domain, windows) in &self.windows {
            out.insert(domain.clone());
            for w in windows {
                for d in &w.domains_seen {
                    out.insert(d.clone());
                }
            }
        }
        out
    }
}

impl fmt::Display for TelemetryPlane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TelemetryPlane(domains={} recorded={} rejected={} epoch={})",
            self.windows.len(),
            self.total_events_recorded,
            self.total_events_rejected,
            self.epoch.as_u64(),
        )
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_are_well_formed() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.deterministic-probabilistic-telemetry.v1"
        );
        assert_eq!(BEAD_ID, "bd-1lsy.11.20");
        assert_eq!(COMPONENT, "deterministic_probabilistic_telemetry");
        assert_eq!(POLICY_ID, "RGC-066");
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    #[test]
    fn default_constants_are_positive() {
        const {
            assert!(DEFAULT_MAX_EVENTS_PER_WINDOW > 0);
            assert!(DEFAULT_WINDOW_NS > 0);
            assert!(DEFAULT_SAMPLING_RATE_MILLIONTHS > 0);
            assert!(DEFAULT_THINNING_TARGET > 0);
            assert!(DEFAULT_MIN_WEIGHT_MILLIONTHS > 0);
            assert!(DEFAULT_RESERVOIR_SIZE > 0);
        }
    }

    // -----------------------------------------------------------------------
    // CaptureMode
    // -----------------------------------------------------------------------

    #[test]
    fn capture_mode_ordering() {
        assert!(CaptureMode::ExactCounting < CaptureMode::ExactShadow);
        assert!(CaptureMode::ExactShadow < CaptureMode::DeterministicReplay);
        assert!(CaptureMode::DeterministicReplay < CaptureMode::BudgetedSampling);
        assert!(CaptureMode::BudgetedSampling < CaptureMode::ProbabilisticSampling);
    }

    #[test]
    fn capture_mode_all_variants() {
        assert_eq!(CaptureMode::ALL.len(), 5);
        for mode in CaptureMode::ALL {
            assert!(!mode.as_str().is_empty());
        }
    }

    #[test]
    fn capture_mode_is_exact() {
        assert!(CaptureMode::ExactCounting.is_exact());
        assert!(CaptureMode::ExactShadow.is_exact());
        assert!(!CaptureMode::DeterministicReplay.is_exact());
        assert!(!CaptureMode::BudgetedSampling.is_exact());
        assert!(!CaptureMode::ProbabilisticSampling.is_exact());
    }

    #[test]
    fn capture_mode_is_sampled() {
        assert!(!CaptureMode::ExactCounting.is_sampled());
        assert!(!CaptureMode::ExactShadow.is_sampled());
        assert!(!CaptureMode::DeterministicReplay.is_sampled());
        assert!(CaptureMode::BudgetedSampling.is_sampled());
        assert!(CaptureMode::ProbabilisticSampling.is_sampled());
    }

    #[test]
    fn capture_mode_is_replay_safe() {
        assert!(CaptureMode::ExactCounting.is_replay_safe());
        assert!(CaptureMode::DeterministicReplay.is_replay_safe());
        assert!(!CaptureMode::ExactShadow.is_replay_safe());
        assert!(!CaptureMode::BudgetedSampling.is_replay_safe());
    }

    #[test]
    fn capture_mode_display() {
        assert_eq!(CaptureMode::ExactCounting.to_string(), "exact_counting");
        assert_eq!(
            CaptureMode::ProbabilisticSampling.to_string(),
            "probabilistic_sampling"
        );
    }

    // -----------------------------------------------------------------------
    // ThinningPolicy
    // -----------------------------------------------------------------------

    #[test]
    fn thinning_policy_all_variants() {
        assert_eq!(ThinningPolicy::ALL.len(), 4);
        let labels: Vec<&str> = ThinningPolicy::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(
            labels,
            vec!["uniform", "reservoir", "stratified", "priority"]
        );
    }

    #[test]
    fn thinning_policy_display() {
        assert_eq!(ThinningPolicy::Reservoir.to_string(), "reservoir");
        assert_eq!(ThinningPolicy::Stratified.to_string(), "stratified");
    }

    // -----------------------------------------------------------------------
    // TelemetryBudget
    // -----------------------------------------------------------------------

    #[test]
    fn budget_construction() {
        let b = TelemetryBudget::new(5000, 500_000_000, 500_000, CaptureMode::BudgetedSampling);
        assert_eq!(b.max_events_per_window, 5000);
        assert_eq!(b.window_ns, 500_000_000);
        assert_eq!(b.sampling_rate_millionths, 500_000);
        assert_eq!(b.mode, CaptureMode::BudgetedSampling);
    }

    #[test]
    fn budget_clamps_sampling_rate() {
        let b = TelemetryBudget::new(100, 1_000, 2_000_000, CaptureMode::ExactCounting);
        assert_eq!(b.sampling_rate_millionths, MILLIONTHS);
    }

    #[test]
    fn budget_exact_is_full_capture() {
        let b = TelemetryBudget::exact();
        assert!(b.is_full_capture());
        assert_eq!(b.mode, CaptureMode::ExactCounting);
    }

    #[test]
    fn budget_budgeted_default_not_full() {
        let b = TelemetryBudget::budgeted_default();
        assert!(!b.is_full_capture());
        assert_eq!(b.mode, CaptureMode::BudgetedSampling);
    }

    #[test]
    fn budget_effective_events_per_second() {
        let b = TelemetryBudget::new(100, 100_000_000, MILLIONTHS, CaptureMode::ExactCounting);
        // 100 events per 100ms window = 1000/s
        assert_eq!(b.effective_events_per_second(), 1000);
    }

    #[test]
    fn budget_zero_window_returns_zero_eps() {
        let b = TelemetryBudget::new(100, 0, MILLIONTHS, CaptureMode::ExactCounting);
        assert_eq!(b.effective_events_per_second(), 0);
    }

    #[test]
    fn budget_display() {
        let b = TelemetryBudget::exact();
        let s = b.to_string();
        assert!(s.contains("TelemetryBudget"));
        assert!(s.contains("exact_counting"));
    }

    // -----------------------------------------------------------------------
    // ThinningConfig
    // -----------------------------------------------------------------------

    #[test]
    fn thinning_config_construction() {
        let c = ThinningConfig::new(ThinningPolicy::Priority, 500, 2_000);
        assert_eq!(c.policy, ThinningPolicy::Priority);
        assert_eq!(c.target_events, 500);
        assert_eq!(c.min_weight_millionths, 2_000);
    }

    #[test]
    fn thinning_config_target_minimum_is_one() {
        let c = ThinningConfig::new(ThinningPolicy::Uniform, 0, 0);
        assert_eq!(c.target_events, 1);
    }

    #[test]
    fn thinning_config_defaults() {
        let u = ThinningConfig::uniform_default();
        assert_eq!(u.policy, ThinningPolicy::Uniform);
        let p = ThinningConfig::priority_default();
        assert_eq!(p.policy, ThinningPolicy::Priority);
        let r = ThinningConfig::reservoir_default();
        assert_eq!(r.policy, ThinningPolicy::Reservoir);
    }

    // -----------------------------------------------------------------------
    // TelemetryEvent
    // -----------------------------------------------------------------------

    #[test]
    fn event_hash_determinism() {
        let e1 = TelemetryEvent::new(
            "ev1",
            "domain_a",
            100,
            CaptureMode::ExactCounting,
            MILLIONTHS,
            b"payload",
        );
        let e2 = TelemetryEvent::new(
            "ev1",
            "domain_a",
            100,
            CaptureMode::ExactCounting,
            MILLIONTHS,
            b"payload",
        );
        assert_eq!(e1.event_hash, e2.event_hash);
        assert_eq!(e1.payload_hash, e2.payload_hash);
    }

    #[test]
    fn event_different_payload_different_hash() {
        let e1 = TelemetryEvent::new(
            "ev1",
            "d",
            100,
            CaptureMode::ExactCounting,
            MILLIONTHS,
            b"a",
        );
        let e2 = TelemetryEvent::new(
            "ev1",
            "d",
            100,
            CaptureMode::ExactCounting,
            MILLIONTHS,
            b"b",
        );
        assert_ne!(e1.payload_hash, e2.payload_hash);
        assert_ne!(e1.event_hash, e2.event_hash);
    }

    #[test]
    fn event_exact_constructor() {
        let ev = TelemetryEvent::exact("ev1", "dom", 42, b"data");
        assert_eq!(ev.capture_mode, CaptureMode::ExactCounting);
        assert_eq!(ev.weight_millionths, MILLIONTHS);
        assert!(ev.is_exact());
    }

    #[test]
    fn event_sampled_constructor_weight_scaling() {
        // 10% sampling rate => weight should be 10x (10_000_000 millionths).
        let ev = TelemetryEvent::sampled("ev1", "dom", 42, 100_000, b"data");
        assert_eq!(ev.capture_mode, CaptureMode::ProbabilisticSampling);
        assert_eq!(ev.weight_millionths, 10_000_000);
        assert!(!ev.is_exact());
    }

    #[test]
    fn event_sampled_zero_rate_clamps_weight() {
        let ev = TelemetryEvent::sampled("ev1", "dom", 42, 0, b"data");
        assert_eq!(ev.weight_millionths, MILLIONTHS);
    }

    #[test]
    fn event_display() {
        let ev = TelemetryEvent::exact("ev1", "dom", 42, b"data");
        let s = ev.to_string();
        assert!(s.contains("ev1"));
        assert!(s.contains("dom"));
    }

    // -----------------------------------------------------------------------
    // ProvenanceTag
    // -----------------------------------------------------------------------

    #[test]
    fn provenance_tag_exact() {
        let tag = ProvenanceTag::exact();
        assert_eq!(tag.capture_mode, CaptureMode::ExactCounting);
        assert_eq!(tag.sampling_rate_applied_millionths, MILLIONTHS);
        assert!(!tag.thinning_applied);
        assert!(tag.replay_deterministic);
        assert!(tag.is_high_fidelity());
    }

    #[test]
    fn provenance_tag_probabilistic() {
        let tag = ProvenanceTag::probabilistic(100_000);
        assert_eq!(tag.capture_mode, CaptureMode::ProbabilisticSampling);
        assert_eq!(tag.sampling_rate_applied_millionths, 100_000);
        assert!(!tag.is_high_fidelity());
    }

    #[test]
    fn provenance_tag_exact_shadow() {
        let tag = ProvenanceTag::exact_shadow();
        assert!(tag.exact_shadow_available);
        assert!(tag.is_high_fidelity());
    }

    #[test]
    fn provenance_tag_replay() {
        let tag = ProvenanceTag::replay();
        assert!(tag.replay_deterministic);
        assert_eq!(tag.capture_mode, CaptureMode::DeterministicReplay);
    }

    #[test]
    fn provenance_tag_with_thinning() {
        let tag = ProvenanceTag::exact().with_thinning();
        assert!(tag.thinning_applied);
    }

    #[test]
    fn provenance_tag_content_hash_determinism() {
        let t1 = ProvenanceTag::exact();
        let t2 = ProvenanceTag::exact();
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn provenance_tag_different_modes_different_hash() {
        let exact = ProvenanceTag::exact();
        let prob = ProvenanceTag::probabilistic(100_000);
        assert_ne!(exact.content_hash(), prob.content_hash());
    }

    #[test]
    fn provenance_tag_display() {
        let tag = ProvenanceTag::budgeted(500_000);
        let s = tag.to_string();
        assert!(s.contains("budgeted_sampling"));
        assert!(s.contains("500000"));
    }

    // -----------------------------------------------------------------------
    // EventWindow — budget enforcement
    // -----------------------------------------------------------------------

    #[test]
    fn window_accepts_events_up_to_budget() {
        let budget =
            TelemetryBudget::new(3, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting);
        let mut window = EventWindow::new(0, budget);

        for i in 0..3 {
            let ev = TelemetryEvent::exact(&format!("ev{i}"), "dom", i * 10, b"data");
            assert!(window.record(ev));
        }
        assert_eq!(window.event_count(), 3);
        assert!(window.is_at_capacity());
        assert_eq!(window.remaining_capacity(), 0);
    }

    #[test]
    fn window_rejects_events_over_budget() {
        let budget =
            TelemetryBudget::new(2, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting);
        let mut window = EventWindow::new(0, budget);

        let ev1 = TelemetryEvent::exact("ev1", "dom", 0, b"a");
        let ev2 = TelemetryEvent::exact("ev2", "dom", 1, b"b");
        let ev3 = TelemetryEvent::exact("ev3", "dom", 2, b"c");

        assert!(window.record(ev1));
        assert!(window.record(ev2));
        assert!(!window.record(ev3));
        assert_eq!(window.rejected_count, 1);
    }

    #[test]
    fn window_sampling_rate_no_rejections() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);

        let ev = TelemetryEvent::exact("ev1", "dom", 0, b"data");
        window.record(ev);
        // All accepted => 100% rate.
        assert_eq!(window.effective_sampling_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn window_sampling_rate_with_rejections() {
        let budget =
            TelemetryBudget::new(1, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting);
        let mut window = EventWindow::new(0, budget);

        let ev1 = TelemetryEvent::exact("ev1", "dom", 0, b"a");
        let ev2 = TelemetryEvent::exact("ev2", "dom", 1, b"b");
        window.record(ev1);
        window.record(ev2);
        // 1 accepted out of 2 offered => 500_000 (50%).
        assert_eq!(window.effective_sampling_rate_millionths(), 500_000);
    }

    #[test]
    fn window_empty_sampling_rate() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let window = EventWindow::new(0, budget);
        assert_eq!(window.effective_sampling_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn window_contains_timestamp() {
        let budget = TelemetryBudget::new(100, 1_000, MILLIONTHS, CaptureMode::ExactCounting);
        let window = EventWindow::new(100, budget);
        assert!(window.contains_timestamp(100));
        assert!(window.contains_timestamp(500));
        assert!(window.contains_timestamp(1099));
        assert!(!window.contains_timestamp(1100));
        assert!(!window.contains_timestamp(99));
    }

    #[test]
    fn window_tracks_domains() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);
        window.record(TelemetryEvent::exact("e1", "gc", 0, b"a"));
        window.record(TelemetryEvent::exact("e2", "jit", 1, b"b"));
        window.record(TelemetryEvent::exact("e3", "gc", 2, b"c"));

        assert_eq!(window.domains_seen.len(), 2);
        assert!(window.domains_seen.contains("gc"));
        assert!(window.domains_seen.contains("jit"));
    }

    #[test]
    fn window_content_hash_determinism() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut w1 = EventWindow::new(0, budget.clone());
        let mut w2 = EventWindow::new(0, budget);
        let ev1 = TelemetryEvent::exact("ev1", "dom", 0, b"data");
        let ev2 = TelemetryEvent::exact("ev1", "dom", 0, b"data");
        w1.record(ev1);
        w2.record(ev2);
        assert_eq!(w1.content_hash(), w2.content_hash());
    }

    // -----------------------------------------------------------------------
    // EventWindow — thinning
    // -----------------------------------------------------------------------

    #[test]
    fn thinning_uniform_reduces_event_count() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);
        for i in 0..20_u64 {
            window.record(TelemetryEvent::exact(&format!("ev{i}"), "dom", i, b"data"));
        }
        assert_eq!(window.event_count(), 20);

        let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
        let removed = window.apply_thinning(&config);
        assert_eq!(removed, 10);
        assert_eq!(window.event_count(), 10);
        assert!(window.thinning_applied);
        assert_eq!(window.thinned_count, 10);
    }

    #[test]
    fn thinning_reservoir_keeps_exact_target() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);
        for i in 0..30_u64 {
            window.record(TelemetryEvent::exact(&format!("ev{i}"), "dom", i, b"data"));
        }

        let config = ThinningConfig::new(ThinningPolicy::Reservoir, 5, 0);
        let removed = window.apply_thinning(&config);
        assert_eq!(removed, 25);
        assert_eq!(window.event_count(), 5);
    }

    #[test]
    fn thinning_stratified_distributes_across_domains() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);

        // Add 15 events from domain_a, 5 from domain_b.
        for i in 0..15_u64 {
            window.record(TelemetryEvent::exact(&format!("a{i}"), "domain_a", i, b"a"));
        }
        for i in 0..5_u64 {
            window.record(TelemetryEvent::exact(
                &format!("b{i}"),
                "domain_b",
                15 + i,
                b"b",
            ));
        }

        let config = ThinningConfig::new(ThinningPolicy::Stratified, 10, 0);
        let removed = window.apply_thinning(&config);
        assert_eq!(removed, 10);
        assert_eq!(window.event_count(), 10);

        // Both domains should be represented.
        let domain_a_count = window
            .events
            .iter()
            .filter(|e| e.domain == "domain_a")
            .count();
        let domain_b_count = window
            .events
            .iter()
            .filter(|e| e.domain == "domain_b")
            .count();
        assert!(domain_a_count > 0);
        assert!(domain_b_count > 0);
    }

    #[test]
    fn thinning_priority_keeps_high_weight_events() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);

        // Add events with increasing weight.
        for i in 0..10_u64 {
            let weight = (i + 1) * 100_000; // 100k to 1M
            let ev = TelemetryEvent::new(
                &format!("ev{i}"),
                "dom",
                i,
                CaptureMode::ExactCounting,
                weight,
                b"data",
            );
            window.record(ev);
        }

        let config = ThinningConfig::new(ThinningPolicy::Priority, 5, 0);
        let removed = window.apply_thinning(&config);
        assert_eq!(removed, 5);
        assert_eq!(window.event_count(), 5);
    }

    #[test]
    fn thinning_priority_removes_below_min_weight() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);

        // Two low-weight and two high-weight events.
        window.record(TelemetryEvent::new(
            "lo1",
            "dom",
            0,
            CaptureMode::ExactCounting,
            500,
            b"a",
        ));
        window.record(TelemetryEvent::new(
            "lo2",
            "dom",
            1,
            CaptureMode::ExactCounting,
            800,
            b"b",
        ));
        window.record(TelemetryEvent::new(
            "hi1",
            "dom",
            2,
            CaptureMode::ExactCounting,
            50_000,
            b"c",
        ));
        window.record(TelemetryEvent::new(
            "hi2",
            "dom",
            3,
            CaptureMode::ExactCounting,
            100_000,
            b"d",
        ));

        // Target=2, min_weight=1000 — the two below 1000 get removed.
        let config = ThinningConfig::new(ThinningPolicy::Priority, 2, 1_000);
        let removed = window.apply_thinning(&config);
        assert_eq!(removed, 2);
        assert_eq!(window.event_count(), 2);
    }

    #[test]
    fn thinning_no_op_when_under_target() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);

        for i in 0..3_u64 {
            window.record(TelemetryEvent::exact(&format!("ev{i}"), "dom", i, b"data"));
        }

        let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
        let removed = window.apply_thinning(&config);
        assert_eq!(removed, 0);
        assert!(!window.thinning_applied);
    }

    #[test]
    fn thinning_rescales_weights() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::ExactCounting,
        );
        let mut window = EventWindow::new(0, budget);

        for i in 0..20_u64 {
            window.record(TelemetryEvent::exact(&format!("ev{i}"), "dom", i, b"data"));
        }

        let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
        window.apply_thinning(&config);

        // After thinning 20 down to 10, surviving events should have
        // weight ~ 2x original (2_000_000 millionths).
        for ev in &window.events {
            assert_eq!(ev.weight_millionths, 2_000_000);
        }
    }

    // -----------------------------------------------------------------------
    // TelemetryPlane
    // -----------------------------------------------------------------------

    #[test]
    fn plane_record_events_across_modes() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));

        // Record in different modes by using different domain budgets.
        plane.add_budget(
            "exact_dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        plane.add_budget(
            "sampled_dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                100_000,
                CaptureMode::BudgetedSampling,
            ),
        );

        plane.record_exact("e1", "exact_dom", 0, b"a");
        plane.record_exact("e2", "exact_dom", 1, b"b");

        let ev = TelemetryEvent::new(
            "s1",
            "sampled_dom",
            0,
            CaptureMode::BudgetedSampling,
            10_000_000,
            b"c",
        );
        plane.record_event(ev);

        assert_eq!(plane.total_events_recorded, 3);
        assert_eq!(plane.active_domain_count(), 2);
        assert_eq!(plane.domain_event_count("exact_dom"), 2);
        assert_eq!(plane.domain_event_count("sampled_dom"), 1);
    }

    #[test]
    fn plane_mode_breakdown_in_report() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(5));

        plane.add_budget(
            "dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        for i in 0..5 {
            plane.record_exact(&format!("ev{i}"), "dom", i, b"data");
        }

        let report = plane.generate_report();
        assert_eq!(report.total_events_captured, 5);
        assert_eq!(report.mode_breakdowns.len(), 1);
        assert_eq!(report.mode_breakdowns[0].mode, CaptureMode::ExactCounting);
        assert_eq!(report.mode_breakdowns[0].event_count, 5);
        assert_eq!(report.mode_breakdowns[0].fraction_millionths, MILLIONTHS);
    }

    #[test]
    fn plane_report_content_hash_determinism() {
        let mk_plane = || {
            let mut p = TelemetryPlane::new(SecurityEpoch::from_raw(1));
            p.add_budget(
                "dom",
                TelemetryBudget::new(
                    100,
                    DEFAULT_WINDOW_NS,
                    MILLIONTHS,
                    CaptureMode::ExactCounting,
                ),
            );
            p.record_exact("e1", "dom", 0, b"data");
            p.record_exact("e2", "dom", 1, b"data2");
            p.generate_report()
        };
        let r1 = mk_plane();
        let r2 = mk_plane();
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn plane_report_budget_utilization() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        // Budget of 100 events.
        plane.add_budget(
            "dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        // Record 50 events = 50% utilization.
        for i in 0..50_u64 {
            plane.record_exact(&format!("ev{i}"), "dom", i, b"data");
        }
        let report = plane.generate_report();
        assert_eq!(report.budget_utilization_millionths, 500_000);
    }

    #[test]
    fn plane_empty_report() {
        let plane = TelemetryPlane::new(SecurityEpoch::from_raw(0));
        let report = plane.generate_report();
        assert_eq!(report.total_events_captured, 0);
        assert_eq!(report.total_events_thinned, 0);
        assert_eq!(report.total_events_rejected, 0);
        assert_eq!(report.budget_utilization_millionths, 0);
        assert!(report.mode_breakdowns.is_empty());
        assert_eq!(report.window_count, 0);
        assert!(report.domains.is_empty());
    }

    #[test]
    fn plane_multi_domain_recording() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.record_exact("e1", "gc", 0, b"a");
        plane.record_exact("e2", "jit", 1, b"b");
        plane.record_exact("e3", "parser", 2, b"c");
        plane.record_exact("e4", "gc", 3, b"d");

        assert_eq!(plane.active_domain_count(), 3);
        assert_eq!(plane.domain_event_count("gc"), 2);
        assert_eq!(plane.domain_event_count("jit"), 1);
        assert_eq!(plane.domain_event_count("parser"), 1);

        let domains = plane.observed_domains();
        assert!(domains.contains("gc"));
        assert!(domains.contains("jit"));
        assert!(domains.contains("parser"));
    }

    #[test]
    fn plane_window_boundary_handling() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        // Window of 100ns, budget of 1000 events.
        plane.add_budget(
            "dom",
            TelemetryBudget::new(1000, 100, MILLIONTHS, CaptureMode::ExactCounting),
        );

        // Events at t=0 and t=50 should be in the same window.
        plane.record_exact("e1", "dom", 0, b"a");
        plane.record_exact("e2", "dom", 50, b"b");
        // Event at t=200 should create a new window.
        plane.record_exact("e3", "dom", 200, b"c");

        let windows = plane.windows.get("dom").unwrap();
        assert_eq!(windows.len(), 2);
        assert_eq!(windows[0].event_count(), 2);
        assert_eq!(windows[1].event_count(), 1);
    }

    #[test]
    fn plane_thin_domain() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.add_budget(
            "dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        for i in 0..20_u64 {
            plane.record_exact(&format!("ev{i}"), "dom", i, b"data");
        }

        let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
        let removed = plane.thin_domain("dom", &config);
        assert_eq!(removed, 10);
    }

    #[test]
    fn plane_thin_all() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.default_thinning = ThinningConfig::new(ThinningPolicy::Uniform, 5, 0);

        plane.add_budget(
            "dom_a",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        plane.add_budget(
            "dom_b",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );

        for i in 0..15_u64 {
            plane.record_exact(&format!("a{i}"), "dom_a", i, b"a");
        }
        for i in 0..10_u64 {
            plane.record_exact(&format!("b{i}"), "dom_b", i, b"b");
        }

        let removed = plane.thin_all();
        // dom_a: 15 -> 5 = 10 removed, dom_b: 10 -> 5 = 5 removed.
        assert_eq!(removed, 15);
    }

    #[test]
    fn plane_thin_nonexistent_domain() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        let config = ThinningConfig::uniform_default();
        assert_eq!(plane.thin_domain("nonexistent", &config), 0);
    }

    #[test]
    fn plane_report_exact_vs_probabilistic() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));

        plane.add_budget(
            "exact",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        plane.add_budget(
            "prob",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                100_000,
                CaptureMode::ProbabilisticSampling,
            ),
        );

        for i in 0..3_u64 {
            plane.record_exact(&format!("e{i}"), "exact", i, b"data");
        }
        for i in 0..7_u64 {
            let ev = TelemetryEvent::new(
                &format!("p{i}"),
                "prob",
                i,
                CaptureMode::ProbabilisticSampling,
                10_000_000,
                b"data",
            );
            plane.record_event(ev);
        }

        let report = plane.generate_report();
        assert_eq!(report.total_events_captured, 10);
        assert_eq!(report.mode_breakdowns.len(), 2);

        let exact_bd = report
            .mode_breakdowns
            .iter()
            .find(|b| b.mode == CaptureMode::ExactCounting)
            .unwrap();
        let prob_bd = report
            .mode_breakdowns
            .iter()
            .find(|b| b.mode == CaptureMode::ProbabilisticSampling)
            .unwrap();
        assert_eq!(exact_bd.event_count, 3);
        assert_eq!(prob_bd.event_count, 7);
        assert_eq!(exact_bd.fraction_millionths, 300_000);
        assert_eq!(prob_bd.fraction_millionths, 700_000);
    }

    #[test]
    fn plane_report_thinning_recorded() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.add_budget(
            "dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        for i in 0..20_u64 {
            plane.record_exact(&format!("ev{i}"), "dom", i, b"data");
        }
        let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
        plane.thin_domain("dom", &config);

        let report = plane.generate_report();
        assert_eq!(report.total_events_captured, 10);
        assert_eq!(report.total_events_thinned, 10);
        assert!(report.has_thinning());
    }

    #[test]
    fn report_survival_rate() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.add_budget(
            "dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        for i in 0..20_u64 {
            plane.record_exact(&format!("ev{i}"), "dom", i, b"data");
        }
        let config = ThinningConfig::new(ThinningPolicy::Uniform, 10, 0);
        plane.thin_domain("dom", &config);

        let report = plane.generate_report();
        // 10 survived out of 20 total (10 captured + 10 thinned) = 50%.
        assert_eq!(report.survival_rate_millionths(), 500_000);
    }

    #[test]
    fn report_is_all_exact() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.add_budget(
            "dom",
            TelemetryBudget::new(
                100,
                DEFAULT_WINDOW_NS,
                MILLIONTHS,
                CaptureMode::ExactCounting,
            ),
        );
        plane.record_exact("e1", "dom", 0, b"data");

        let report = plane.generate_report();
        assert!(report.is_all_exact());

        // Add a sampled event.
        let ev = TelemetryEvent::new(
            "s1",
            "dom2",
            1,
            CaptureMode::BudgetedSampling,
            MILLIONTHS,
            b"data",
        );
        plane.record_event(ev);
        let report2 = plane.generate_report();
        assert!(!report2.is_all_exact());
    }

    #[test]
    fn report_empty_survival_rate() {
        let plane = TelemetryPlane::new(SecurityEpoch::from_raw(0));
        let report = plane.generate_report();
        assert_eq!(report.survival_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn report_schema_and_component() {
        let plane = TelemetryPlane::new(SecurityEpoch::from_raw(42));
        let report = plane.generate_report();
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.component, COMPONENT);
        assert_eq!(report.epoch, SecurityEpoch::from_raw(42));
    }

    #[test]
    fn plane_display() {
        let plane = TelemetryPlane::new(SecurityEpoch::from_raw(7));
        let s = plane.to_string();
        assert!(s.contains("TelemetryPlane"));
        assert!(s.contains("epoch=7"));
    }

    #[test]
    fn plane_with_default_budget() {
        let budget = TelemetryBudget::exact();
        let plane = TelemetryPlane::with_default_budget(SecurityEpoch::from_raw(1), budget.clone());
        assert_eq!(plane.default_budget.mode, CaptureMode::ExactCounting);
        assert!(plane.default_budget.is_full_capture());
    }

    #[test]
    fn plane_record_sampled_convenience() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        let accepted = plane.record_sampled("s1", "dom", 0, 100_000, b"data");
        assert!(accepted);
        assert_eq!(plane.total_events_recorded, 1);
    }

    #[test]
    fn mode_breakdown_display() {
        let bd = ModeBreakdown::new(CaptureMode::ExactCounting, 10, 20, ProvenanceTag::exact());
        let s = bd.to_string();
        assert!(s.contains("exact_counting"));
        assert!(s.contains("10"));
    }

    #[test]
    fn window_provenance_tag_matches_budget() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            200_000,
            CaptureMode::BudgetedSampling,
        );
        let window = EventWindow::new(0, budget);
        let tag = window.provenance_tag();
        assert_eq!(tag.capture_mode, CaptureMode::BudgetedSampling);
        assert!(!tag.exact_shadow_available);
        assert!(!tag.replay_deterministic);
    }

    #[test]
    fn window_provenance_exact_shadow() {
        let budget =
            TelemetryBudget::new(100, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactShadow);
        let window = EventWindow::new(0, budget);
        let tag = window.provenance_tag();
        assert!(tag.exact_shadow_available);
        assert!(!tag.replay_deterministic);
    }

    #[test]
    fn window_provenance_replay() {
        let budget = TelemetryBudget::new(
            100,
            DEFAULT_WINDOW_NS,
            MILLIONTHS,
            CaptureMode::DeterministicReplay,
        );
        let window = EventWindow::new(0, budget);
        let tag = window.provenance_tag();
        assert!(tag.replay_deterministic);
    }

    #[test]
    fn plane_budget_exhaustion_rejects() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.add_budget(
            "dom",
            TelemetryBudget::new(3, DEFAULT_WINDOW_NS, MILLIONTHS, CaptureMode::ExactCounting),
        );
        for i in 0..3_u64 {
            assert!(plane.record_exact(&format!("ev{i}"), "dom", i, b"data"));
        }
        // Fourth event should be rejected.
        assert!(!plane.record_exact("ev3", "dom", 3, b"data"));
        assert_eq!(plane.total_events_rejected, 1);

        let report = plane.generate_report();
        assert_eq!(report.total_events_rejected, 1);
    }

    #[test]
    fn report_domains_include_all_observed() {
        let mut plane = TelemetryPlane::new(SecurityEpoch::from_raw(1));
        plane.record_exact("e1", "alpha", 0, b"a");
        plane.record_exact("e2", "beta", 1, b"b");
        plane.record_exact("e3", "gamma", 2, b"c");

        let report = plane.generate_report();
        assert!(report.domains.contains("alpha"));
        assert!(report.domains.contains("beta"));
        assert!(report.domains.contains("gamma"));
        assert_eq!(report.domains.len(), 3);
    }
}
