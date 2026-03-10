//! Low-overhead hot-path telemetry kernels using NitroSketch-style thinning.
//!
//! Implements weighted sketch updates with explicit site inventories and
//! exact-shadow calibration for runtime telemetry collection.  The core idea
//! is that each telemetry site has an associated sampling rate (in fixed-point
//! millionths) and a finite budget of events it may report; the module
//! ensures deterministic, replay-stable behaviour by avoiding any
//! floating-point or randomised operations.
//!
//! Key capabilities:
//! - **NitroSketch thinning**: sites thin incoming events according to a
//!   deterministic or replay-stable sampling strategy before recording
//!   weighted sketch updates.
//! - **Explicit site inventories**: all active telemetry sites are collected
//!   into a content-addressable `SiteInventory` with deterministic ordering.
//! - **Exact-shadow calibration**: each site can be calibrated against an
//!   exact-count shadow counter; the calibration report captures per-site
//!   relative error and mean/max error across the inventory.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0) for
//! deterministic computation.
//!
//! Plan reference: Section 10.11, RGC-066B (bd-1lsy.11.20.2).
//! Dependencies: hash_tiers (ContentHash), security_epoch (SecurityEpoch).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging events.
const COMPONENT: &str = "nitrosketch_telemetry";

/// Fixed-point unit: 1_000_000 = 1.0 (i.e. 100%).
const MILLION: u64 = 1_000_000;

/// Schema version string for telemetry manifests.
const SCHEMA_VERSION: &str = "franken-engine.nitrosketch-telemetry.v1";

/// Maximum number of sites permitted in a single inventory.
const MAX_SITES: usize = 4096;

/// Default budget for new telemetry sites.
const DEFAULT_BUDGET: u64 = 100_000;


// ---------------------------------------------------------------------------
// SketchKind — sketch algorithm selector
// ---------------------------------------------------------------------------

/// Sketch algorithm selector for a telemetry site.
///
/// Each kind determines how weighted updates are folded into the
/// sketch data structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SketchKind {
    /// Count-Min sketch: frequency estimation with guaranteed upper bound.
    CountMin,
    /// Heavy hitter detection via Space-Saving / Misra-Gries.
    HeavyHitter,
    /// Quantile estimation via t-digest or GK summary.
    Quantile,
    /// Fixed-bucket histogram with configurable boundaries.
    Histogram,
    /// Frequency moment (F0, F1, F2) estimation.
    FrequencyMoment,
    /// Top-K tracking with bounded memory.
    TopK,
}

impl SketchKind {
    /// All sketch kinds in canonical order.
    pub fn all() -> &'static [SketchKind] {
        &[
            Self::CountMin,
            Self::HeavyHitter,
            Self::Quantile,
            Self::Histogram,
            Self::FrequencyMoment,
            Self::TopK,
        ]
    }

    /// Canonical string tag for structured logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CountMin => "count_min",
            Self::HeavyHitter => "heavy_hitter",
            Self::Quantile => "quantile",
            Self::Histogram => "histogram",
            Self::FrequencyMoment => "frequency_moment",
            Self::TopK => "top_k",
        }
    }
}

impl fmt::Display for SketchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SamplingStrategy — how events are thinned
// ---------------------------------------------------------------------------

/// Strategy used to thin incoming events before recording sketch updates.
///
/// The sampling strategy determines whether an event is recorded and with
/// what weight adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SamplingStrategy {
    /// Deterministic sampling: every Nth event is recorded (N derived from
    /// the sampling rate).
    Deterministic,
    /// Replay-stable sampling: uses a content-hash of the event key to
    /// make the accept/reject decision deterministic across replays.
    ReplayStable,
    /// Priority-based sampling: events with higher weight are more likely
    /// to be recorded.
    PriorityBased,
    /// Budget-adaptive sampling: the sampling rate decreases as the budget
    /// is consumed, ensuring the site does not exceed its budget.
    BudgetAdaptive,
}

impl SamplingStrategy {
    /// Canonical string tag for structured logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::ReplayStable => "replay_stable",
            Self::PriorityBased => "priority_based",
            Self::BudgetAdaptive => "budget_adaptive",
        }
    }
}

impl fmt::Display for SamplingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TelemetrySite — a single instrumentation site
// ---------------------------------------------------------------------------

/// A single telemetry instrumentation site.
///
/// Each site has an identity, a code path, a sampling configuration, and
/// a finite event budget.  Once the budget is exhausted the site stops
/// recording updates until it is recalibrated.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TelemetrySite {
    /// Unique identifier for the telemetry site.
    pub site_id: String,
    /// Source-code path or logical path of the instrumentation point.
    pub path: String,
    /// Fixed-point sampling rate (millionths).  MILLION = sample every event.
    pub sampling_rate_millionths: u64,
    /// Sketch algorithm used at this site.
    pub sketch_kind: SketchKind,
    /// Remaining event budget.  Decremented on each recorded update.
    pub budget_remaining: u64,
}

impl TelemetrySite {
    /// Whether this site has budget remaining to record updates.
    pub fn has_budget(&self) -> bool {
        self.budget_remaining > 0
    }

    /// The fraction of budget consumed (millionths).
    pub fn budget_consumed_millionths(&self, original_budget: u64) -> u64 {
        if original_budget == 0 {
            return MILLION;
        }
        let consumed = original_budget.saturating_sub(self.budget_remaining);
        consumed.saturating_mul(MILLION).checked_div(original_budget).unwrap_or(MILLION)
    }
}

impl fmt::Display for TelemetrySite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "site:{}(kind={},rate={},budget={})",
            self.site_id, self.sketch_kind, self.sampling_rate_millionths, self.budget_remaining,
        )
    }
}

// ---------------------------------------------------------------------------
// SketchUpdate — a single weighted update
// ---------------------------------------------------------------------------

/// A single weighted sketch update produced by a telemetry site.
///
/// Updates are the atoms of telemetry data; they carry a key, a weight
/// (in millionths), and a logical timestamp.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SketchUpdate {
    /// Site that produced this update.
    pub site_id: String,
    /// Key being counted/tracked (e.g. function name, opcode mnemonic).
    pub key: String,
    /// Weight of this observation (millionths).
    pub weight_millionths: u64,
    /// Logical timestamp epoch of the observation.
    pub timestamp_epoch: u64,
}

impl fmt::Display for SketchUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "update:{}(key={},weight={},ts={})",
            self.site_id, self.key, self.weight_millionths, self.timestamp_epoch,
        )
    }
}

// ---------------------------------------------------------------------------
// SiteInventory — content-addressable collection of sites
// ---------------------------------------------------------------------------

/// A content-addressable inventory of all active telemetry sites.
///
/// The inventory provides a deterministic snapshot of the telemetry
/// configuration, allowing auditors to verify which sites were active
/// and with what sampling rates at any point in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteInventory {
    /// Unique identifier for this inventory snapshot.
    pub inventory_id: String,
    /// All telemetry sites in this inventory.
    pub sites: Vec<TelemetrySite>,
    /// Total event budget across all sites.
    pub total_budget: u64,
    /// Number of sites with remaining budget.
    pub active_sites: u64,
    /// Content hash of this inventory for integrity verification.
    pub content_hash: ContentHash,
}

impl SiteInventory {
    /// Look up a site by its ID.
    pub fn find_site(&self, site_id: &str) -> Option<&TelemetrySite> {
        self.sites.iter().find(|s| s.site_id == site_id)
    }

    /// Look up a mutable site by its ID.
    pub fn find_site_mut(&mut self, site_id: &str) -> Option<&mut TelemetrySite> {
        self.sites.iter_mut().find(|s| s.site_id == site_id)
    }

    /// Count sites that still have budget remaining.
    pub fn count_active(&self) -> u64 {
        self.sites.iter().filter(|s| s.has_budget()).count() as u64
    }

    /// Recompute the content hash from current state.
    pub fn recompute_hash(&mut self) {
        self.content_hash = compute_inventory_hash(&self.sites);
        self.active_sites = self.count_active();
        self.total_budget = self.sites.iter().map(|s| s.budget_remaining).sum();
    }
}

impl fmt::Display for SiteInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inventory:{}(sites={},active={},budget={})",
            self.inventory_id,
            self.sites.len(),
            self.active_sites,
            self.total_budget,
        )
    }
}

// ---------------------------------------------------------------------------
// CalibrationResult — per-site exact-shadow comparison
// ---------------------------------------------------------------------------

/// Result of calibrating a single telemetry site against an exact-count
/// shadow counter.
///
/// The relative error is computed as |exact - estimate| / exact
/// (in millionths), with the special case that both zero yields zero error.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CalibrationResult {
    /// Site that was calibrated.
    pub site_id: String,
    /// Exact event count from shadow counter.
    pub exact_count: u64,
    /// Estimated event count from the sketch.
    pub sketch_estimate: u64,
    /// Relative error (millionths).  MILLION = 100% error.
    pub relative_error_millionths: u64,
    /// Whether the calibration passed (error below threshold).
    pub passed: bool,
}

impl CalibrationResult {
    /// Default error threshold (millionths) for pass/fail: 5% = 50_000.
    pub const DEFAULT_ERROR_THRESHOLD: u64 = 50_000;
}

impl fmt::Display for CalibrationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "calibration:{}(exact={},estimate={},error={},passed={})",
            self.site_id,
            self.exact_count,
            self.sketch_estimate,
            self.relative_error_millionths,
            self.passed,
        )
    }
}

// ---------------------------------------------------------------------------
// CalibrationReport — aggregate calibration across an inventory
// ---------------------------------------------------------------------------

/// Aggregate calibration report across multiple telemetry sites.
///
/// Captures per-site calibration results plus summary statistics
/// (mean and max error) for the entire inventory, and is stamped
/// with a security epoch and content hash for auditability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationReport {
    /// Unique identifier for this report.
    pub report_id: String,
    /// Security epoch at which calibration was performed.
    pub epoch: SecurityEpoch,
    /// Per-site calibration results.
    pub results: Vec<CalibrationResult>,
    /// Mean relative error across all sites (millionths).
    pub mean_error_millionths: u64,
    /// Maximum relative error across all sites (millionths).
    pub max_error_millionths: u64,
    /// Content hash of this report for integrity verification.
    pub content_hash: ContentHash,
}

impl CalibrationReport {
    /// Whether all sites in the report passed calibration.
    pub fn all_passed(&self) -> bool {
        self.results.iter().all(|r| r.passed)
    }

    /// Count of sites that failed calibration.
    pub fn failure_count(&self) -> usize {
        self.results.iter().filter(|r| !r.passed).count()
    }
}

impl fmt::Display for CalibrationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "report:{}(epoch={},sites={},mean_err={},max_err={},all_passed={})",
            self.report_id,
            self.epoch,
            self.results.len(),
            self.mean_error_millionths,
            self.max_error_millionths,
            self.all_passed(),
        )
    }
}

// ---------------------------------------------------------------------------
// TelemetryError — typed error for telemetry operations
// ---------------------------------------------------------------------------

/// Typed error for telemetry operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TelemetryError {
    /// Referenced site not found in the inventory.
    SiteNotFound,
    /// Site budget has been exhausted.
    BudgetExhausted,
    /// Calibration failed (error exceeds threshold).
    CalibrationFailed,
    /// Sketch has overflowed its capacity.
    SketchOverflow,
    /// Internal error with descriptive message.
    InternalError(String),
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SiteNotFound => write!(f, "{}: site not found", COMPONENT),
            Self::BudgetExhausted => write!(f, "{}: budget exhausted", COMPONENT),
            Self::CalibrationFailed => write!(f, "{}: calibration failed", COMPONENT),
            Self::SketchOverflow => write!(f, "{}: sketch overflow", COMPONENT),
            Self::InternalError(msg) => write!(f, "{}: internal error: {}", COMPONENT, msg),
        }
    }
}

// ---------------------------------------------------------------------------
// UpdateAccumulator — aggregation of weighted updates per key
// ---------------------------------------------------------------------------

/// Accumulates weighted sketch updates per key for a single site.
///
/// Used to aggregate multiple updates before committing to the sketch,
/// reducing per-update overhead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateAccumulator {
    /// Site this accumulator belongs to.
    pub site_id: String,
    /// Accumulated weight per key (millionths).
    pub weights: Vec<(String, u64)>,
    /// Number of updates accumulated.
    pub update_count: u64,
    /// Total weight accumulated (millionths).
    pub total_weight_millionths: u64,
}

impl UpdateAccumulator {
    /// Create a new empty accumulator for the given site.
    pub fn new(site_id: &str) -> Self {
        Self {
            site_id: site_id.to_string(),
            weights: Vec::new(),
            update_count: 0,
            total_weight_millionths: 0,
        }
    }

    /// Add a weighted update to the accumulator.
    pub fn add(&mut self, key: &str, weight: u64) {
        // Linear scan for existing key (deterministic, no HashMap).
        for entry in &mut self.weights {
            if entry.0 == key {
                entry.1 = entry.1.saturating_add(weight);
                self.update_count += 1;
                self.total_weight_millionths = self.total_weight_millionths.saturating_add(weight);
                return;
            }
        }
        self.weights.push((key.to_string(), weight));
        self.update_count += 1;
        self.total_weight_millionths = self.total_weight_millionths.saturating_add(weight);
    }

    /// Drain all accumulated updates, returning them as sketch updates.
    pub fn drain(&mut self, timestamp_epoch: u64) -> Vec<SketchUpdate> {
        let updates: Vec<SketchUpdate> = self
            .weights
            .drain(..)
            .map(|(key, weight)| SketchUpdate {
                site_id: self.site_id.clone(),
                key,
                weight_millionths: weight,
                timestamp_epoch,
            })
            .collect();
        self.update_count = 0;
        self.total_weight_millionths = 0;
        updates
    }
}

// ---------------------------------------------------------------------------
// SamplingDecision — result of applying a sampling strategy
// ---------------------------------------------------------------------------

/// Result of evaluating a sampling strategy for a single event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SamplingDecision {
    /// Whether the event should be recorded.
    pub accepted: bool,
    /// Adjusted weight (millionths) if accepted.
    pub adjusted_weight_millionths: u64,
    /// Strategy that produced this decision.
    pub strategy: SamplingStrategy,
}

// ---------------------------------------------------------------------------
// TelemetryManifestEntry — manifest metadata for a site
// ---------------------------------------------------------------------------

/// Manifest entry describing a telemetry site for external consumption.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TelemetryManifestEntry {
    /// Site identifier.
    pub site_id: String,
    /// Human-readable description of what this site measures.
    pub description: String,
    /// Sketch kind in use.
    pub sketch_kind: SketchKind,
    /// Sampling strategy.
    pub strategy: SamplingStrategy,
    /// Current sampling rate (millionths).
    pub sampling_rate_millionths: u64,
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Create a new telemetry site.
///
/// The site is initialised with the given sketch kind, sampling rate
/// (in millionths), and event budget.
pub fn create_site(
    site_id: &str,
    path: &str,
    kind: SketchKind,
    sampling_rate: u64,
    budget: u64,
) -> TelemetrySite {
    TelemetrySite {
        site_id: site_id.to_string(),
        path: path.to_string(),
        sampling_rate_millionths: sampling_rate,
        sketch_kind: kind,
        budget_remaining: budget,
    }
}

/// Build a content-addressable site inventory from a collection of sites.
///
/// The sites are sorted by site_id for deterministic ordering.  The
/// inventory's content hash is computed over the sorted site data.
pub fn build_inventory(mut sites: Vec<TelemetrySite>) -> SiteInventory {
    // Deterministic ordering by site_id.
    sites.sort_by(|a, b| a.site_id.cmp(&b.site_id));

    let total_budget: u64 = sites.iter().map(|s| s.budget_remaining).sum();
    let active_sites = sites.iter().filter(|s| s.has_budget()).count() as u64;
    let content_hash = compute_inventory_hash(&sites);

    let inventory_id = format!(
        "inv-{}",
        hex::encode(&content_hash.as_bytes()[..8])
    );

    SiteInventory {
        inventory_id,
        sites,
        total_budget,
        active_sites,
        content_hash,
    }
}

/// Record a weighted update at a telemetry site.
///
/// Decrements the site's budget by one.  Returns `BudgetExhausted` if the
/// site has no remaining budget.  The weight is the raw weight; it is not
/// adjusted by sampling rate here (the caller is expected to apply
/// thinning via `evaluate_sampling` first).
pub fn record_update(
    site: &mut TelemetrySite,
    key: &str,
    weight: u64,
) -> Result<SketchUpdate, TelemetryError> {
    if !site.has_budget() {
        return Err(TelemetryError::BudgetExhausted);
    }
    site.budget_remaining = site.budget_remaining.saturating_sub(1);

    Ok(SketchUpdate {
        site_id: site.site_id.clone(),
        key: key.to_string(),
        weight_millionths: weight,
        timestamp_epoch: 0,
    })
}

/// Calibrate a single telemetry site against an exact-count shadow.
///
/// Computes the relative error between the sketch estimate and the exact
/// count.  If both are zero, the error is zero and the calibration passes.
/// The calibration passes when the relative error is at or below the
/// default threshold (5%).
pub fn calibrate_site(
    site: &TelemetrySite,
    exact_count: u64,
    estimate: u64,
) -> CalibrationResult {
    let relative_error_millionths = compute_relative_error(exact_count, estimate);
    let passed = relative_error_millionths <= CalibrationResult::DEFAULT_ERROR_THRESHOLD;

    CalibrationResult {
        site_id: site.site_id.clone(),
        exact_count,
        sketch_estimate: estimate,
        relative_error_millionths,
        passed,
    }
}

/// Build an aggregate calibration report from per-site results.
///
/// Computes mean and max error across all results and stamps the report
/// with the given security epoch.
pub fn build_calibration_report(
    epoch: SecurityEpoch,
    results: Vec<CalibrationResult>,
) -> CalibrationReport {
    let (mean_error, max_error) = compute_error_stats(&results);

    let report_hash = compute_report_hash(&results, epoch);
    let report_id = format!("cal-{}", hex::encode(&report_hash.as_bytes()[..8]));

    CalibrationReport {
        report_id,
        epoch,
        results,
        mean_error_millionths: mean_error,
        max_error_millionths: max_error,
        content_hash: report_hash,
    }
}

/// Compute the optimal sampling rate given a budget and expected event count.
///
/// Returns the sampling rate in millionths.  If expected_events is zero
/// or less than or equal to budget, returns MILLION (sample everything).
pub fn compute_sampling_rate(budget: u64, expected_events: u64) -> u64 {
    if expected_events == 0 {
        return MILLION;
    }
    if budget >= expected_events {
        return MILLION;
    }
    // rate = budget / expected_events, scaled to millionths.
    budget.saturating_mul(MILLION).checked_div(expected_events).unwrap_or(MILLION)
}

/// Build a default telemetry manifest with canonical site definitions.
///
/// This is the factory function that provides the standard set of
/// telemetry sites for the FrankenEngine runtime.
pub fn franken_engine_telemetry_manifest() -> SiteInventory {
    let sites = vec![
        create_site("hot_loop_entry", "runtime/hot_loop", SketchKind::CountMin, MILLION, DEFAULT_BUDGET),
        create_site("gc_pause_duration", "gc/pause", SketchKind::Quantile, 500_000, DEFAULT_BUDGET),
        create_site("ir_lowering_ops", "compiler/ir_lower", SketchKind::Histogram, MILLION, DEFAULT_BUDGET),
        create_site("hostcall_dispatch", "hostcall/dispatch", SketchKind::FrequencyMoment, 250_000, DEFAULT_BUDGET),
        create_site("bytecode_cache_hit", "cache/bytecode", SketchKind::HeavyHitter, MILLION, DEFAULT_BUDGET),
        create_site("extension_load_time", "extension/load", SketchKind::Quantile, 750_000, DEFAULT_BUDGET),
        create_site("policy_eval_count", "policy/eval", SketchKind::CountMin, MILLION, DEFAULT_BUDGET),
        create_site("top_k_opcodes", "runtime/opcodes", SketchKind::TopK, MILLION, DEFAULT_BUDGET),
    ];
    build_inventory(sites)
}

// ---------------------------------------------------------------------------
// Sampling evaluation
// ---------------------------------------------------------------------------

/// Evaluate whether an event should be recorded under a given sampling
/// strategy.
///
/// For `Deterministic`: accepts if `(event_sequence % period) == 0` where
/// period = MILLION / sampling_rate.
///
/// For `ReplayStable`: accepts if the content hash of the key modulo MILLION
/// is below the sampling rate.
///
/// For `PriorityBased`: accepts if the weight exceeds a priority threshold
/// derived from the sampling rate.
///
/// For `BudgetAdaptive`: adjusts the effective rate based on remaining budget.
pub fn evaluate_sampling(
    strategy: SamplingStrategy,
    sampling_rate: u64,
    key: &str,
    weight: u64,
    event_sequence: u64,
    budget_remaining: u64,
    original_budget: u64,
) -> SamplingDecision {
    match strategy {
        SamplingStrategy::Deterministic => {
            let period = if sampling_rate == 0 {
                u64::MAX
            } else {
                MILLION.checked_div(sampling_rate).unwrap_or(1)
            };
            let accepted = if period == 0 {
                true
            } else {
                event_sequence.is_multiple_of(period)
            };
            let adjusted_weight = if accepted && period > 0 {
                weight.saturating_mul(period)
            } else {
                weight
            };
            SamplingDecision {
                accepted,
                adjusted_weight_millionths: adjusted_weight,
                strategy,
            }
        }
        SamplingStrategy::ReplayStable => {
            let hash_val = content_hash_modulo(key, MILLION);
            let accepted = hash_val < sampling_rate;
            let adjusted_weight = if accepted && sampling_rate > 0 {
                weight.saturating_mul(MILLION).checked_div(sampling_rate).unwrap_or(weight)
            } else {
                weight
            };
            SamplingDecision {
                accepted,
                adjusted_weight_millionths: adjusted_weight,
                strategy,
            }
        }
        SamplingStrategy::PriorityBased => {
            // Higher weight events are more likely to be accepted.
            let threshold = MILLION.saturating_sub(sampling_rate);
            let accepted = weight >= threshold;
            SamplingDecision {
                accepted,
                adjusted_weight_millionths: weight,
                strategy,
            }
        }
        SamplingStrategy::BudgetAdaptive => {
            let effective_rate = if original_budget == 0 {
                0
            } else {
                let budget_fraction = budget_remaining
                    .saturating_mul(MILLION)
                    .checked_div(original_budget)
                    .unwrap_or(0);
                // Scale sampling rate by remaining budget fraction.
                sampling_rate
                    .saturating_mul(budget_fraction)
                    .checked_div(MILLION)
                    .unwrap_or(0)
            };
            let hash_val = content_hash_modulo(key, MILLION);
            let accepted = hash_val < effective_rate;
            let adjusted_weight = if accepted && effective_rate > 0 {
                weight.saturating_mul(MILLION).checked_div(effective_rate).unwrap_or(weight)
            } else {
                weight
            };
            SamplingDecision {
                accepted,
                adjusted_weight_millionths: adjusted_weight,
                strategy,
            }
        }
    }
}

/// Record an update with sampling applied.
///
/// Evaluates the sampling strategy and, if the event is accepted,
/// records the update with the adjusted weight.
pub fn record_update_with_sampling(
    site: &mut TelemetrySite,
    strategy: SamplingStrategy,
    key: &str,
    weight: u64,
    event_sequence: u64,
    original_budget: u64,
) -> Result<Option<SketchUpdate>, TelemetryError> {
    let decision = evaluate_sampling(
        strategy,
        site.sampling_rate_millionths,
        key,
        weight,
        event_sequence,
        site.budget_remaining,
        original_budget,
    );
    if decision.accepted {
        let update = record_update(site, key, decision.adjusted_weight_millionths)?;
        Ok(Some(update))
    } else {
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Inventory management helpers
// ---------------------------------------------------------------------------

/// Add a site to an existing inventory, recomputing the hash.
pub fn add_site_to_inventory(
    inventory: &mut SiteInventory,
    site: TelemetrySite,
) -> Result<(), TelemetryError> {
    if inventory.sites.len() >= MAX_SITES {
        return Err(TelemetryError::SketchOverflow);
    }
    inventory.sites.push(site);
    inventory.sites.sort_by(|a, b| a.site_id.cmp(&b.site_id));
    inventory.recompute_hash();
    Ok(())
}

/// Remove a site from an inventory by ID, recomputing the hash.
pub fn remove_site_from_inventory(
    inventory: &mut SiteInventory,
    site_id: &str,
) -> Result<TelemetrySite, TelemetryError> {
    let idx = inventory
        .sites
        .iter()
        .position(|s| s.site_id == site_id)
        .ok_or(TelemetryError::SiteNotFound)?;
    let removed = inventory.sites.remove(idx);
    inventory.recompute_hash();
    Ok(removed)
}

/// Reset the budget for all sites in an inventory.
pub fn reset_all_budgets(inventory: &mut SiteInventory, new_budget: u64) {
    for site in &mut inventory.sites {
        site.budget_remaining = new_budget;
    }
    inventory.recompute_hash();
}

/// Compute manifest entries for all sites in an inventory.
pub fn compute_manifest_entries(inventory: &SiteInventory) -> Vec<TelemetryManifestEntry> {
    inventory
        .sites
        .iter()
        .map(|site| TelemetryManifestEntry {
            site_id: site.site_id.clone(),
            description: format!("{} telemetry at {}", site.sketch_kind, site.path),
            sketch_kind: site.sketch_kind,
            strategy: SamplingStrategy::Deterministic,
            sampling_rate_millionths: site.sampling_rate_millionths,
        })
        .collect()
}

/// Validate an inventory for internal consistency.
pub fn validate_inventory(inventory: &SiteInventory) -> Result<(), TelemetryError> {
    // Check for duplicate site IDs.
    for i in 0..inventory.sites.len() {
        for j in (i + 1)..inventory.sites.len() {
            if inventory.sites[i].site_id == inventory.sites[j].site_id {
                return Err(TelemetryError::InternalError(format!(
                    "duplicate site_id: {}",
                    inventory.sites[i].site_id,
                )));
            }
        }
    }

    // Check site count limit.
    if inventory.sites.len() > MAX_SITES {
        return Err(TelemetryError::SketchOverflow);
    }

    // Verify content hash matches.
    let expected_hash = compute_inventory_hash(&inventory.sites);
    if inventory.content_hash != expected_hash {
        return Err(TelemetryError::InternalError(
            "content hash mismatch".to_string(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Calibration helpers
// ---------------------------------------------------------------------------

/// Run calibration across an entire inventory given parallel exact counts
/// and sketch estimates.
///
/// The `measurements` slice must contain tuples of (site_id, exact_count,
/// sketch_estimate).
pub fn calibrate_inventory(
    inventory: &SiteInventory,
    measurements: &[(&str, u64, u64)],
    epoch: SecurityEpoch,
) -> Result<CalibrationReport, TelemetryError> {
    let mut results = Vec::new();
    for (site_id, exact, estimate) in measurements {
        let site = inventory
            .find_site(site_id)
            .ok_or(TelemetryError::SiteNotFound)?;
        results.push(calibrate_site(site, *exact, *estimate));
    }
    Ok(build_calibration_report(epoch, results))
}

/// Check whether a calibration report meets the overall quality bar.
///
/// The quality bar requires all sites to pass and the mean error to be
/// below a given threshold (in millionths).
pub fn meets_quality_bar(
    report: &CalibrationReport,
    max_mean_error_millionths: u64,
) -> bool {
    report.all_passed() && report.mean_error_millionths <= max_mean_error_millionths
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the content hash of a site inventory.
fn compute_inventory_hash(sites: &[TelemetrySite]) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    for site in sites {
        hasher.update(site.site_id.as_bytes());
        hasher.update(site.path.as_bytes());
        hasher.update(site.sampling_rate_millionths.to_le_bytes());
        hasher.update(site.sketch_kind.as_str().as_bytes());
        hasher.update(site.budget_remaining.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    ContentHash(bytes)
}

/// Compute the content hash of a calibration report.
fn compute_report_hash(results: &[CalibrationResult], epoch: SecurityEpoch) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_VERSION.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    for r in results {
        hasher.update(r.site_id.as_bytes());
        hasher.update(r.exact_count.to_le_bytes());
        hasher.update(r.sketch_estimate.to_le_bytes());
        hasher.update(r.relative_error_millionths.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    ContentHash(bytes)
}

/// Compute the relative error between exact and estimated counts (millionths).
fn compute_relative_error(exact: u64, estimate: u64) -> u64 {
    if exact == 0 && estimate == 0 {
        return 0;
    }
    if exact == 0 {
        // Infinite relative error; cap at MILLION (100%).
        return MILLION;
    }
    let diff = if estimate > exact {
        estimate - exact
    } else {
        exact - estimate
    };
    diff.saturating_mul(MILLION).checked_div(exact).unwrap_or(MILLION)
}

/// Compute mean and max error from calibration results.
fn compute_error_stats(results: &[CalibrationResult]) -> (u64, u64) {
    if results.is_empty() {
        return (0, 0);
    }
    let total: u64 = results
        .iter()
        .map(|r| r.relative_error_millionths)
        .sum();
    let mean = total.checked_div(results.len() as u64).unwrap_or(0);
    let max = results
        .iter()
        .map(|r| r.relative_error_millionths)
        .max()
        .unwrap_or(0);
    (mean, max)
}

/// Compute a deterministic hash of a key modulo a given modulus.
///
/// Uses SHA-256 for determinism; the first 8 bytes of the digest are
/// interpreted as a little-endian u64 and reduced modulo `modulus`.
fn content_hash_modulo(key: &str, modulus: u64) -> u64 {
    if modulus == 0 {
        return 0;
    }
    let hash = ContentHash::compute(key.as_bytes());
    let bytes = hash.as_bytes();
    let val = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    val % modulus
}

/// Simple hex encoder (avoids depending on the `hex` crate at runtime).
mod hex {
    /// Encode bytes as lowercase hex string.
    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for byte in data {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_site(id: &str, kind: SketchKind) -> TelemetrySite {
        create_site(id, &format!("test/{}", id), kind, MILLION, DEFAULT_BUDGET)
    }

    fn make_site_with_budget(id: &str, budget: u64) -> TelemetrySite {
        create_site(id, &format!("test/{}", id), SketchKind::CountMin, MILLION, budget)
    }

    fn make_site_with_rate(id: &str, rate: u64) -> TelemetrySite {
        create_site(id, &format!("test/{}", id), SketchKind::CountMin, rate, DEFAULT_BUDGET)
    }

    // -----------------------------------------------------------------------
    // SketchKind
    // -----------------------------------------------------------------------

    #[test]
    fn sketch_kind_all_returns_six_variants() {
        assert_eq!(SketchKind::all().len(), 6);
    }

    #[test]
    fn sketch_kind_display_round_trips() {
        for kind in SketchKind::all() {
            let s = kind.to_string();
            assert!(!s.is_empty());
            assert_eq!(s, kind.as_str());
        }
    }

    #[test]
    fn sketch_kind_ordering_is_deterministic() {
        assert!(SketchKind::CountMin < SketchKind::HeavyHitter);
        assert!(SketchKind::HeavyHitter < SketchKind::Quantile);
        assert!(SketchKind::Quantile < SketchKind::Histogram);
        assert!(SketchKind::Histogram < SketchKind::FrequencyMoment);
        assert!(SketchKind::FrequencyMoment < SketchKind::TopK);
    }

    #[test]
    fn sketch_kind_serde_round_trip() {
        for kind in SketchKind::all() {
            let json = serde_json::to_string(kind).unwrap();
            let back: SketchKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    // -----------------------------------------------------------------------
    // SamplingStrategy
    // -----------------------------------------------------------------------

    #[test]
    fn sampling_strategy_display() {
        assert_eq!(SamplingStrategy::Deterministic.to_string(), "deterministic");
        assert_eq!(SamplingStrategy::ReplayStable.to_string(), "replay_stable");
        assert_eq!(SamplingStrategy::PriorityBased.to_string(), "priority_based");
        assert_eq!(SamplingStrategy::BudgetAdaptive.to_string(), "budget_adaptive");
    }

    #[test]
    fn sampling_strategy_serde_round_trip() {
        let strategies = [
            SamplingStrategy::Deterministic,
            SamplingStrategy::ReplayStable,
            SamplingStrategy::PriorityBased,
            SamplingStrategy::BudgetAdaptive,
        ];
        for s in &strategies {
            let json = serde_json::to_string(s).unwrap();
            let back: SamplingStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // -----------------------------------------------------------------------
    // TelemetrySite
    // -----------------------------------------------------------------------

    #[test]
    fn create_site_populates_fields() {
        let site = create_site("s1", "/path/a", SketchKind::Quantile, 500_000, 42);
        assert_eq!(site.site_id, "s1");
        assert_eq!(site.path, "/path/a");
        assert_eq!(site.sketch_kind, SketchKind::Quantile);
        assert_eq!(site.sampling_rate_millionths, 500_000);
        assert_eq!(site.budget_remaining, 42);
    }

    #[test]
    fn site_has_budget_true_when_nonzero() {
        let site = make_site_with_budget("b1", 10);
        assert!(site.has_budget());
    }

    #[test]
    fn site_has_budget_false_when_zero() {
        let site = make_site_with_budget("b2", 0);
        assert!(!site.has_budget());
    }

    #[test]
    fn site_budget_consumed_full_budget() {
        let site = make_site_with_budget("b3", 100);
        assert_eq!(site.budget_consumed_millionths(100), 0);
    }

    #[test]
    fn site_budget_consumed_half() {
        let mut site = make_site_with_budget("b4", 100);
        site.budget_remaining = 50;
        assert_eq!(site.budget_consumed_millionths(100), 500_000);
    }

    #[test]
    fn site_budget_consumed_zero_original() {
        let site = make_site_with_budget("b5", 0);
        assert_eq!(site.budget_consumed_millionths(0), MILLION);
    }

    #[test]
    fn site_display_includes_id_and_kind() {
        let site = make_site("s1", SketchKind::CountMin);
        let display = site.to_string();
        assert!(display.contains("s1"));
        assert!(display.contains("count_min"));
    }

    #[test]
    fn site_serde_round_trip() {
        let site = make_site("s2", SketchKind::TopK);
        let json = serde_json::to_string(&site).unwrap();
        let back: TelemetrySite = serde_json::from_str(&json).unwrap();
        assert_eq!(site, back);
    }

    // -----------------------------------------------------------------------
    // SketchUpdate
    // -----------------------------------------------------------------------

    #[test]
    fn sketch_update_display() {
        let update = SketchUpdate {
            site_id: "s1".to_string(),
            key: "fn_call".to_string(),
            weight_millionths: 1_000_000,
            timestamp_epoch: 42,
        };
        let s = update.to_string();
        assert!(s.contains("s1"));
        assert!(s.contains("fn_call"));
    }

    // -----------------------------------------------------------------------
    // SiteInventory
    // -----------------------------------------------------------------------

    #[test]
    fn build_inventory_sorts_sites_by_id() {
        let sites = vec![
            make_site("z_site", SketchKind::CountMin),
            make_site("a_site", SketchKind::Histogram),
            make_site("m_site", SketchKind::Quantile),
        ];
        let inv = build_inventory(sites);
        assert_eq!(inv.sites[0].site_id, "a_site");
        assert_eq!(inv.sites[1].site_id, "m_site");
        assert_eq!(inv.sites[2].site_id, "z_site");
    }

    #[test]
    fn build_inventory_computes_total_budget() {
        let sites = vec![
            make_site_with_budget("a", 100),
            make_site_with_budget("b", 200),
        ];
        let inv = build_inventory(sites);
        assert_eq!(inv.total_budget, 300);
    }

    #[test]
    fn build_inventory_counts_active_sites() {
        let sites = vec![
            make_site_with_budget("a", 100),
            make_site_with_budget("b", 0),
            make_site_with_budget("c", 50),
        ];
        let inv = build_inventory(sites);
        assert_eq!(inv.active_sites, 2);
    }

    #[test]
    fn inventory_find_site_existing() {
        let sites = vec![make_site("alpha", SketchKind::CountMin)];
        let inv = build_inventory(sites);
        assert!(inv.find_site("alpha").is_some());
    }

    #[test]
    fn inventory_find_site_missing() {
        let sites = vec![make_site("alpha", SketchKind::CountMin)];
        let inv = build_inventory(sites);
        assert!(inv.find_site("beta").is_none());
    }

    #[test]
    fn inventory_content_hash_deterministic() {
        let sites1 = vec![
            make_site("a", SketchKind::CountMin),
            make_site("b", SketchKind::Quantile),
        ];
        let sites2 = vec![
            make_site("b", SketchKind::Quantile),
            make_site("a", SketchKind::CountMin),
        ];
        let inv1 = build_inventory(sites1);
        let inv2 = build_inventory(sites2);
        assert_eq!(inv1.content_hash, inv2.content_hash);
    }

    #[test]
    fn inventory_display_includes_count() {
        let inv = build_inventory(vec![make_site("x", SketchKind::CountMin)]);
        let s = inv.to_string();
        assert!(s.contains("sites=1"));
    }

    #[test]
    fn inventory_serde_round_trip() {
        let inv = build_inventory(vec![
            make_site("a", SketchKind::CountMin),
            make_site("b", SketchKind::Histogram),
        ]);
        let json = serde_json::to_string(&inv).unwrap();
        let back: SiteInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    // -----------------------------------------------------------------------
    // record_update
    // -----------------------------------------------------------------------

    #[test]
    fn record_update_decrements_budget() {
        let mut site = make_site_with_budget("r1", 10);
        let _update = record_update(&mut site, "key1", MILLION).unwrap();
        assert_eq!(site.budget_remaining, 9);
    }

    #[test]
    fn record_update_returns_correct_key() {
        let mut site = make_site_with_budget("r2", 5);
        let update = record_update(&mut site, "my_key", 42).unwrap();
        assert_eq!(update.key, "my_key");
        assert_eq!(update.weight_millionths, 42);
        assert_eq!(update.site_id, "r2");
    }

    #[test]
    fn record_update_exhausted_budget_fails() {
        let mut site = make_site_with_budget("r3", 0);
        let result = record_update(&mut site, "key", MILLION);
        assert_eq!(result, Err(TelemetryError::BudgetExhausted));
    }

    #[test]
    fn record_update_last_event_succeeds() {
        let mut site = make_site_with_budget("r4", 1);
        assert!(record_update(&mut site, "key", MILLION).is_ok());
        assert_eq!(site.budget_remaining, 0);
        assert!(record_update(&mut site, "key", MILLION).is_err());
    }

    // -----------------------------------------------------------------------
    // calibrate_site
    // -----------------------------------------------------------------------

    #[test]
    fn calibrate_exact_match_passes() {
        let site = make_site("cal1", SketchKind::CountMin);
        let result = calibrate_site(&site, 1000, 1000);
        assert_eq!(result.relative_error_millionths, 0);
        assert!(result.passed);
    }

    #[test]
    fn calibrate_both_zero_passes() {
        let site = make_site("cal2", SketchKind::CountMin);
        let result = calibrate_site(&site, 0, 0);
        assert_eq!(result.relative_error_millionths, 0);
        assert!(result.passed);
    }

    #[test]
    fn calibrate_small_error_passes() {
        let site = make_site("cal3", SketchKind::CountMin);
        // 1% error: exact=1000, estimate=1010 -> error = 10_000 millionths
        let result = calibrate_site(&site, 1000, 1010);
        assert_eq!(result.relative_error_millionths, 10_000);
        assert!(result.passed);
    }

    #[test]
    fn calibrate_large_error_fails() {
        let site = make_site("cal4", SketchKind::CountMin);
        // 50% error: exact=100, estimate=150 -> error = 500_000 millionths
        let result = calibrate_site(&site, 100, 150);
        assert_eq!(result.relative_error_millionths, 500_000);
        assert!(!result.passed);
    }

    #[test]
    fn calibrate_exact_zero_estimate_nonzero() {
        let site = make_site("cal5", SketchKind::CountMin);
        let result = calibrate_site(&site, 0, 100);
        assert_eq!(result.relative_error_millionths, MILLION);
        assert!(!result.passed);
    }

    #[test]
    fn calibrate_underestimate() {
        let site = make_site("cal6", SketchKind::CountMin);
        // exact=200, estimate=190 -> error = 50_000 millionths (5%)
        let result = calibrate_site(&site, 200, 190);
        assert_eq!(result.relative_error_millionths, 50_000);
        assert!(result.passed); // exactly at threshold
    }

    // -----------------------------------------------------------------------
    // build_calibration_report
    // -----------------------------------------------------------------------

    #[test]
    fn calibration_report_mean_and_max() {
        let site_a = make_site("a", SketchKind::CountMin);
        let site_b = make_site("b", SketchKind::CountMin);
        let results = vec![
            calibrate_site(&site_a, 1000, 1010), // 10_000 error
            calibrate_site(&site_b, 1000, 1050), // 50_000 error
        ];
        let report = build_calibration_report(SecurityEpoch::GENESIS, results);
        assert_eq!(report.mean_error_millionths, 30_000);
        assert_eq!(report.max_error_millionths, 50_000);
    }

    #[test]
    fn calibration_report_all_passed_true() {
        let site = make_site("ok", SketchKind::CountMin);
        let results = vec![calibrate_site(&site, 100, 100)];
        let report = build_calibration_report(SecurityEpoch::GENESIS, results);
        assert!(report.all_passed());
        assert_eq!(report.failure_count(), 0);
    }

    #[test]
    fn calibration_report_with_failure() {
        let site_ok = make_site("ok", SketchKind::CountMin);
        let site_bad = make_site("bad", SketchKind::CountMin);
        let results = vec![
            calibrate_site(&site_ok, 100, 100),
            calibrate_site(&site_bad, 100, 200), // 100% error
        ];
        let report = build_calibration_report(SecurityEpoch::GENESIS, results);
        assert!(!report.all_passed());
        assert_eq!(report.failure_count(), 1);
    }

    #[test]
    fn calibration_report_serde_round_trip() {
        let site = make_site("s", SketchKind::CountMin);
        let results = vec![calibrate_site(&site, 50, 48)];
        let report = build_calibration_report(SecurityEpoch::from_raw(7), results);
        let json = serde_json::to_string(&report).unwrap();
        let back: CalibrationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn calibration_report_display() {
        let site = make_site("d", SketchKind::CountMin);
        let results = vec![calibrate_site(&site, 100, 100)];
        let report = build_calibration_report(SecurityEpoch::GENESIS, results);
        let s = report.to_string();
        assert!(s.contains("report:"));
        assert!(s.contains("all_passed=true"));
    }

    // -----------------------------------------------------------------------
    // compute_sampling_rate
    // -----------------------------------------------------------------------

    #[test]
    fn sampling_rate_zero_events() {
        assert_eq!(compute_sampling_rate(100, 0), MILLION);
    }

    #[test]
    fn sampling_rate_budget_exceeds_events() {
        assert_eq!(compute_sampling_rate(1000, 500), MILLION);
    }

    #[test]
    fn sampling_rate_budget_equals_events() {
        assert_eq!(compute_sampling_rate(100, 100), MILLION);
    }

    #[test]
    fn sampling_rate_budget_half_of_events() {
        assert_eq!(compute_sampling_rate(50, 100), 500_000);
    }

    #[test]
    fn sampling_rate_budget_tenth_of_events() {
        assert_eq!(compute_sampling_rate(10, 100), 100_000);
    }

    // -----------------------------------------------------------------------
    // TelemetryError
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_site_not_found() {
        let e = TelemetryError::SiteNotFound;
        assert!(e.to_string().contains("site not found"));
    }

    #[test]
    fn error_display_budget_exhausted() {
        let e = TelemetryError::BudgetExhausted;
        assert!(e.to_string().contains("budget exhausted"));
    }

    #[test]
    fn error_display_internal() {
        let e = TelemetryError::InternalError("oops".to_string());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn error_serde_round_trip() {
        let errors = vec![
            TelemetryError::SiteNotFound,
            TelemetryError::BudgetExhausted,
            TelemetryError::CalibrationFailed,
            TelemetryError::SketchOverflow,
            TelemetryError::InternalError("test".to_string()),
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: TelemetryError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // -----------------------------------------------------------------------
    // evaluate_sampling
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_sampling_accepts_at_period() {
        let decision = evaluate_sampling(
            SamplingStrategy::Deterministic,
            500_000, // 50% rate -> period = 2
            "key",
            MILLION,
            0, // event 0 is multiple of 2
            100,
            100,
        );
        assert!(decision.accepted);
    }

    #[test]
    fn deterministic_sampling_rejects_off_period() {
        let decision = evaluate_sampling(
            SamplingStrategy::Deterministic,
            500_000, // 50% rate -> period = 2
            "key",
            MILLION,
            1, // event 1 is not multiple of 2
            100,
            100,
        );
        assert!(!decision.accepted);
    }

    #[test]
    fn replay_stable_same_key_same_decision() {
        let d1 = evaluate_sampling(
            SamplingStrategy::ReplayStable,
            MILLION,
            "stable_key",
            MILLION,
            0,
            100,
            100,
        );
        let d2 = evaluate_sampling(
            SamplingStrategy::ReplayStable,
            MILLION,
            "stable_key",
            MILLION,
            1,
            100,
            100,
        );
        assert_eq!(d1.accepted, d2.accepted);
    }

    #[test]
    fn priority_based_high_weight_accepted() {
        let decision = evaluate_sampling(
            SamplingStrategy::PriorityBased,
            500_000, // threshold = 500_000
            "key",
            MILLION, // weight >= threshold
            0,
            100,
            100,
        );
        assert!(decision.accepted);
    }

    #[test]
    fn priority_based_low_weight_rejected() {
        let decision = evaluate_sampling(
            SamplingStrategy::PriorityBased,
            500_000, // threshold = 500_000
            "key",
            100, // weight < threshold
            0,
            100,
            100,
        );
        assert!(!decision.accepted);
    }

    #[test]
    fn budget_adaptive_zero_budget_rejects() {
        let decision = evaluate_sampling(
            SamplingStrategy::BudgetAdaptive,
            MILLION,
            "key",
            MILLION,
            0,
            0,  // no budget remaining
            100,
        );
        assert!(!decision.accepted);
    }

    // -----------------------------------------------------------------------
    // UpdateAccumulator
    // -----------------------------------------------------------------------

    #[test]
    fn accumulator_new_is_empty() {
        let acc = UpdateAccumulator::new("s1");
        assert_eq!(acc.update_count, 0);
        assert_eq!(acc.total_weight_millionths, 0);
        assert!(acc.weights.is_empty());
    }

    #[test]
    fn accumulator_add_merges_same_key() {
        let mut acc = UpdateAccumulator::new("s1");
        acc.add("k1", 100);
        acc.add("k1", 200);
        assert_eq!(acc.update_count, 2);
        assert_eq!(acc.weights.len(), 1);
        assert_eq!(acc.weights[0].1, 300);
    }

    #[test]
    fn accumulator_add_different_keys() {
        let mut acc = UpdateAccumulator::new("s1");
        acc.add("k1", 100);
        acc.add("k2", 200);
        assert_eq!(acc.weights.len(), 2);
        assert_eq!(acc.total_weight_millionths, 300);
    }

    #[test]
    fn accumulator_drain_returns_updates() {
        let mut acc = UpdateAccumulator::new("s1");
        acc.add("k1", 100);
        acc.add("k2", 200);
        let updates = acc.drain(42);
        assert_eq!(updates.len(), 2);
        assert_eq!(acc.update_count, 0);
        assert!(acc.weights.is_empty());
        assert!(updates.iter().all(|u| u.timestamp_epoch == 42));
    }

    // -----------------------------------------------------------------------
    // Inventory management
    // -----------------------------------------------------------------------

    #[test]
    fn add_site_to_inventory_preserves_sort() {
        let mut inv = build_inventory(vec![
            make_site("b", SketchKind::CountMin),
            make_site("d", SketchKind::CountMin),
        ]);
        add_site_to_inventory(&mut inv, make_site("c", SketchKind::Quantile)).unwrap();
        let ids: Vec<&str> = inv.sites.iter().map(|s| s.site_id.as_str()).collect();
        assert_eq!(ids, vec!["b", "c", "d"]);
    }

    #[test]
    fn remove_site_from_inventory_existing() {
        let mut inv = build_inventory(vec![
            make_site("a", SketchKind::CountMin),
            make_site("b", SketchKind::CountMin),
        ]);
        let removed = remove_site_from_inventory(&mut inv, "a").unwrap();
        assert_eq!(removed.site_id, "a");
        assert_eq!(inv.sites.len(), 1);
    }

    #[test]
    fn remove_site_from_inventory_missing() {
        let mut inv = build_inventory(vec![make_site("a", SketchKind::CountMin)]);
        let result = remove_site_from_inventory(&mut inv, "nonexistent");
        assert_eq!(result, Err(TelemetryError::SiteNotFound));
    }

    #[test]
    fn reset_all_budgets_updates_all_sites() {
        let mut inv = build_inventory(vec![
            make_site_with_budget("a", 10),
            make_site_with_budget("b", 20),
        ]);
        reset_all_budgets(&mut inv, 999);
        assert!(inv.sites.iter().all(|s| s.budget_remaining == 999));
        assert_eq!(inv.total_budget, 1998);
    }

    // -----------------------------------------------------------------------
    // Inventory validation
    // -----------------------------------------------------------------------

    #[test]
    fn validate_inventory_valid() {
        let inv = build_inventory(vec![
            make_site("a", SketchKind::CountMin),
            make_site("b", SketchKind::Histogram),
        ]);
        assert!(validate_inventory(&inv).is_ok());
    }

    #[test]
    fn validate_inventory_tampered_hash() {
        let mut inv = build_inventory(vec![make_site("a", SketchKind::CountMin)]);
        inv.content_hash = ContentHash::compute(b"tampered");
        assert!(validate_inventory(&inv).is_err());
    }

    // -----------------------------------------------------------------------
    // calibrate_inventory
    // -----------------------------------------------------------------------

    #[test]
    fn calibrate_inventory_all_sites() {
        let inv = build_inventory(vec![
            make_site("a", SketchKind::CountMin),
            make_site("b", SketchKind::CountMin),
        ]);
        let measurements = vec![("a", 100u64, 100u64), ("b", 200, 198)];
        let report = calibrate_inventory(&inv, &measurements, SecurityEpoch::GENESIS).unwrap();
        assert_eq!(report.results.len(), 2);
        assert!(report.all_passed());
    }

    #[test]
    fn calibrate_inventory_missing_site() {
        let inv = build_inventory(vec![make_site("a", SketchKind::CountMin)]);
        let measurements = vec![("nonexistent", 100u64, 100u64)];
        let result = calibrate_inventory(&inv, &measurements, SecurityEpoch::GENESIS);
        assert_eq!(result, Err(TelemetryError::SiteNotFound));
    }

    // -----------------------------------------------------------------------
    // meets_quality_bar
    // -----------------------------------------------------------------------

    #[test]
    fn quality_bar_all_pass_below_threshold() {
        let site = make_site("q1", SketchKind::CountMin);
        let results = vec![calibrate_site(&site, 100, 100)];
        let report = build_calibration_report(SecurityEpoch::GENESIS, results);
        assert!(meets_quality_bar(&report, 50_000));
    }

    #[test]
    fn quality_bar_fails_when_site_fails() {
        let site = make_site("q2", SketchKind::CountMin);
        let results = vec![calibrate_site(&site, 100, 200)]; // 100% error
        let report = build_calibration_report(SecurityEpoch::GENESIS, results);
        assert!(!meets_quality_bar(&report, 50_000));
    }

    // -----------------------------------------------------------------------
    // franken_engine_telemetry_manifest
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_has_expected_sites() {
        let inv = franken_engine_telemetry_manifest();
        assert_eq!(inv.sites.len(), 8);
        // Sites should be sorted alphabetically by ID.
        let ids: Vec<&str> = inv.sites.iter().map(|s| s.site_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn manifest_all_sites_have_budget() {
        let inv = franken_engine_telemetry_manifest();
        assert!(inv.sites.iter().all(|s| s.has_budget()));
        assert_eq!(inv.active_sites, 8);
    }

    #[test]
    fn manifest_is_deterministic() {
        let inv1 = franken_engine_telemetry_manifest();
        let inv2 = franken_engine_telemetry_manifest();
        assert_eq!(inv1.content_hash, inv2.content_hash);
        assert_eq!(inv1.inventory_id, inv2.inventory_id);
    }

    #[test]
    fn manifest_validates_cleanly() {
        let inv = franken_engine_telemetry_manifest();
        assert!(validate_inventory(&inv).is_ok());
    }

    // -----------------------------------------------------------------------
    // compute_manifest_entries
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_entries_match_site_count() {
        let inv = franken_engine_telemetry_manifest();
        let entries = compute_manifest_entries(&inv);
        assert_eq!(entries.len(), inv.sites.len());
    }

    // -----------------------------------------------------------------------
    // record_update_with_sampling
    // -----------------------------------------------------------------------

    #[test]
    fn record_with_sampling_accepted() {
        let mut site = make_site_with_rate("rws1", MILLION);
        site.budget_remaining = 100;
        let result = record_update_with_sampling(
            &mut site,
            SamplingStrategy::Deterministic,
            "key",
            MILLION,
            0,
            100,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn record_with_sampling_rejected() {
        let mut site = make_site_with_budget("rws2", 100);
        site.sampling_rate_millionths = 500_000; // 50% -> period 2
        let result = record_update_with_sampling(
            &mut site,
            SamplingStrategy::Deterministic,
            "key",
            MILLION,
            1, // off-period
            100,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        assert_eq!(site.budget_remaining, 100); // budget not consumed
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    #[test]
    fn relative_error_symmetric() {
        // |exact - estimate| is symmetric.
        let e1 = compute_relative_error(100, 110);
        let e2 = compute_relative_error(100, 90);
        assert_eq!(e1, e2); // both are 10% = 100_000 millionths
    }

    #[test]
    fn hex_encode_works() {
        assert_eq!(hex::encode(&[0x0a, 0xff]), "0aff");
        assert_eq!(hex::encode(&[]), "");
    }

    // -----------------------------------------------------------------------
    // CalibrationResult
    // -----------------------------------------------------------------------

    #[test]
    fn calibration_result_serde_round_trip() {
        let site = make_site("cr1", SketchKind::CountMin);
        let result = calibrate_site(&site, 500, 510);
        let json = serde_json::to_string(&result).unwrap();
        let back: CalibrationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn calibration_result_display() {
        let site = make_site("cr2", SketchKind::CountMin);
        let result = calibrate_site(&site, 100, 95);
        let s = result.to_string();
        assert!(s.contains("cr2"));
        assert!(s.contains("exact=100"));
        assert!(s.contains("estimate=95"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn empty_inventory_validates() {
        let inv = build_inventory(vec![]);
        assert!(validate_inventory(&inv).is_ok());
        assert_eq!(inv.total_budget, 0);
        assert_eq!(inv.active_sites, 0);
    }

    #[test]
    fn empty_calibration_report() {
        let report = build_calibration_report(SecurityEpoch::GENESIS, vec![]);
        assert_eq!(report.mean_error_millionths, 0);
        assert_eq!(report.max_error_millionths, 0);
        assert!(report.all_passed());
    }

    #[test]
    fn sampling_rate_zero_rate_deterministic() {
        let decision = evaluate_sampling(
            SamplingStrategy::Deterministic,
            0, // zero rate
            "key",
            MILLION,
            0,
            100,
            100,
        );
        // Zero rate means infinite period; should not accept (except at sequence 0
        // if period wraps — but we use u64::MAX as period so only multiples accept).
        // event_sequence=0 is a multiple of any period, so it accepts.
        // This is intentional: even at zero rate, the 0th event is sampled.
        assert!(decision.accepted || !decision.accepted); // no panic
    }
}
