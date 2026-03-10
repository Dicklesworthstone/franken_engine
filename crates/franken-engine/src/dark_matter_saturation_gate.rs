#![forbid(unsafe_code)]

//! Bead: bd-1lsy.8.7.3 [RGC-707C]
//!
//! Dark-matter saturation gate: conditions board saturation, freshness, and
//! ratchet widening on the pace at which semantic dark matter is discovered
//! and retired.
//!
//! "Dark matter" is the set of program regions, behavioral paths, and
//! runtime interactions that have not yet been observed, tested, or
//! evidenced.  A board that looks green but sits atop a growing pile of
//! unaddressed dark matter is *scope-limited*, not *saturated*.
//!
//! This module provides:
//! 1. `DarkMatterEstimate` — mass estimation of unseen regions.
//! 2. `BurndownTracker` — discovery-rate vs retirement-rate tracking.
//! 3. `BoardSaturationVerdict` — conditional saturation that degrades when
//!    burndown is too slow.
//! 4. `FreshnessGate` — downgrades stale boards even when cells look green.
//! 5. `RatchetWideningControl` — only allows ratchet widening when dark
//!    matter fraction is below a configurable threshold.
//! 6. `DecisionReceipt` — content-hashed receipts for every verdict.
//! 7. `DarkMatterEvidence` — structured evidence emission.
//! 8. `BoardState` — the tri-state outcome (Saturated / ScopeLimited / Stale).
//!
//! All fractional arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the dark-matter saturation gate.
pub const DARK_MATTER_GATE_SCHEMA_VERSION: &str = "franken-engine.dark-matter-saturation-gate.v1";

/// Bead identifier originating this module.
pub const DARK_MATTER_GATE_BEAD_ID: &str = "bd-1lsy.8.7.3";

/// Component name used in evidence records.
pub const COMPONENT: &str = "dark_matter_saturation_gate";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Default maximum dark-matter fraction (in millionths) below which a board
/// may be declared saturated.  200_000 = 20%.
pub const DEFAULT_SATURATION_THRESHOLD: u64 = 200_000;

/// Default maximum staleness in hours before a board is declared stale.
pub const DEFAULT_MAX_STALENESS_HOURS: u64 = 168;

/// Default minimum burndown velocity (in millionths per observation window)
/// required for a non-stale verdict.  50_000 = 5% per window.
pub const DEFAULT_MIN_BURNDOWN_VELOCITY: u64 = 50_000;

/// Default ratchet-widening ceiling: dark matter fraction must be below this
/// value (in millionths) to permit ratchet widening.  150_000 = 15%.
pub const DEFAULT_RATCHET_WIDENING_CEILING: u64 = 150_000;

/// Default minimum observations needed to produce a statistically
/// meaningful burndown velocity estimate.
pub const DEFAULT_MIN_OBSERVATIONS: u64 = 10;

// ---------------------------------------------------------------------------
// DarkMatterRegionKind
// ---------------------------------------------------------------------------

/// Classification of a dark-matter region.
///
/// Each variant represents a category of unseen program surface area that
/// contributes to the total dark-matter mass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DarkMatterRegionKind {
    /// Untested code paths (branches, error handlers).
    UntestedCodePath,
    /// Unexercised type combinations.
    UnexercisedTypeCombination,
    /// Unobserved runtime interactions (e.g. GC + JIT interplay).
    UnobservedInteraction,
    /// Unverified concurrency interleavings.
    UnverifiedInterleaving,
    /// Untested error-recovery paths.
    UntestedErrorRecovery,
    /// Unexercised extension API surface.
    UnexercisedExtensionApi,
    /// Unobserved performance regimes (e.g. large heap, deep recursion).
    UnobservedPerformanceRegime,
    /// Unverified specification edge cases.
    UnverifiedSpecEdgeCase,
    /// Unobserved module-graph topologies.
    UnobservedModuleTopology,
    /// Uncovered security-boundary crossings.
    UncoveredSecurityBoundary,
}

impl DarkMatterRegionKind {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::UntestedCodePath,
        Self::UnexercisedTypeCombination,
        Self::UnobservedInteraction,
        Self::UnverifiedInterleaving,
        Self::UntestedErrorRecovery,
        Self::UnexercisedExtensionApi,
        Self::UnobservedPerformanceRegime,
        Self::UnverifiedSpecEdgeCase,
        Self::UnobservedModuleTopology,
        Self::UncoveredSecurityBoundary,
    ];

    /// Human-readable label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::UntestedCodePath => "untested_code_path",
            Self::UnexercisedTypeCombination => "unexercised_type_combination",
            Self::UnobservedInteraction => "unobserved_interaction",
            Self::UnverifiedInterleaving => "unverified_interleaving",
            Self::UntestedErrorRecovery => "untested_error_recovery",
            Self::UnexercisedExtensionApi => "unexercised_extension_api",
            Self::UnobservedPerformanceRegime => "unobserved_performance_regime",
            Self::UnverifiedSpecEdgeCase => "unverified_spec_edge_case",
            Self::UnobservedModuleTopology => "unobserved_module_topology",
            Self::UncoveredSecurityBoundary => "uncovered_security_boundary",
        }
    }
}

impl fmt::Display for DarkMatterRegionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DarkMatterRegion
// ---------------------------------------------------------------------------

/// A single dark-matter region: an identified area of unseen surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterRegion {
    /// Identifier for this specific region (e.g. "gc_finalizer_reentry").
    pub region_id: String,
    /// Classification of this region.
    pub kind: DarkMatterRegionKind,
    /// Estimated mass of this region in millionths of total surface area.
    pub mass_millionths: u64,
    /// Whether this region has been retired (fully tested/evidenced).
    pub retired: bool,
    /// Optional timestamp (epoch seconds) when the region was discovered.
    pub discovered_at_epoch_secs: u64,
    /// Optional timestamp when the region was retired.
    pub retired_at_epoch_secs: Option<u64>,
    /// Priority weight: higher means more important to retire.
    /// 1_000_000 = weight 1.0.
    pub priority_weight_millionths: u64,
}

impl DarkMatterRegion {
    /// Effective mass: returns 0 if retired, otherwise mass * priority weight
    /// (in millionths, clamped to prevent overflow).
    #[must_use]
    pub fn effective_mass(&self) -> u64 {
        if self.retired {
            return 0;
        }
        // mass * weight / MILLION — saturating
        self.mass_millionths
            .saturating_mul(self.priority_weight_millionths)
            .checked_div(MILLION)
            .unwrap_or(0)
    }

    /// Content hash of this region for deterministic identity.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(self.region_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.kind.as_str().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&self.mass_millionths.to_le_bytes());
        buf.push(if self.retired { 1 } else { 0 });
        buf.extend_from_slice(&self.discovered_at_epoch_secs.to_le_bytes());
        buf.extend_from_slice(&self.retired_at_epoch_secs.unwrap_or(0).to_le_bytes());
        buf.extend_from_slice(&self.priority_weight_millionths.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for DarkMatterRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.retired { "retired" } else { "active" };
        write!(
            f,
            "region[{}:{}:{}:mass={}]",
            self.region_id, self.kind, status, self.mass_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// DarkMatterEstimate
// ---------------------------------------------------------------------------

/// Aggregate estimate of dark-matter mass across all region kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterEstimate {
    /// All known dark-matter regions (keyed by region_id for deterministic ordering).
    pub regions: BTreeMap<String, DarkMatterRegion>,
    /// Total surface area in millionths (the denominator for fraction computation).
    /// Typically 1_000_000 (= 1.0 = 100% of surface).
    pub total_surface_millionths: u64,
    /// Security epoch at the time of estimation.
    pub epoch: SecurityEpoch,
    /// Timestamp (epoch seconds) when this estimate was produced.
    pub estimated_at_epoch_secs: u64,
}

impl DarkMatterEstimate {
    /// Create a new empty estimate.
    #[must_use]
    pub fn new(total_surface_millionths: u64, epoch: SecurityEpoch, timestamp: u64) -> Self {
        Self {
            regions: BTreeMap::new(),
            total_surface_millionths,
            epoch,
            estimated_at_epoch_secs: timestamp,
        }
    }

    /// Add a region to the estimate.
    pub fn add_region(&mut self, region: DarkMatterRegion) {
        self.regions.insert(region.region_id.clone(), region);
    }

    /// Total active (non-retired) dark-matter mass in millionths.
    #[must_use]
    pub fn active_mass(&self) -> u64 {
        self.regions
            .values()
            .filter(|r| !r.retired)
            .map(|r| r.mass_millionths)
            .fold(0u64, |acc, m| acc.saturating_add(m))
    }

    /// Total effective mass (mass * priority weight) in millionths.
    #[must_use]
    pub fn effective_mass(&self) -> u64 {
        self.regions
            .values()
            .map(|r| r.effective_mass())
            .fold(0u64, |acc, m| acc.saturating_add(m))
    }

    /// Total retired mass in millionths.
    #[must_use]
    pub fn retired_mass(&self) -> u64 {
        self.regions
            .values()
            .filter(|r| r.retired)
            .map(|r| r.mass_millionths)
            .fold(0u64, |acc, m| acc.saturating_add(m))
    }

    /// Dark-matter fraction: active_mass / total_surface, in millionths.
    /// Returns MILLION (100%) if total surface is 0.
    #[must_use]
    pub fn dark_matter_fraction(&self) -> u64 {
        if self.total_surface_millionths == 0 {
            return MILLION;
        }
        self.active_mass()
            .saturating_mul(MILLION)
            .checked_div(self.total_surface_millionths)
            .unwrap_or(MILLION)
    }

    /// Number of active (non-retired) regions.
    #[must_use]
    pub fn active_region_count(&self) -> usize {
        self.regions.values().filter(|r| !r.retired).count()
    }

    /// Number of retired regions.
    #[must_use]
    pub fn retired_region_count(&self) -> usize {
        self.regions.values().filter(|r| r.retired).count()
    }

    /// Total region count.
    #[must_use]
    pub fn total_region_count(&self) -> usize {
        self.regions.len()
    }

    /// Per-kind mass breakdown: kind -> (active_mass, retired_mass).
    #[must_use]
    pub fn mass_by_kind(&self) -> BTreeMap<DarkMatterRegionKind, (u64, u64)> {
        let mut map = BTreeMap::new();
        for region in self.regions.values() {
            let entry = map.entry(region.kind).or_insert((0u64, 0u64));
            if region.retired {
                entry.1 = entry.1.saturating_add(region.mass_millionths);
            } else {
                entry.0 = entry.0.saturating_add(region.mass_millionths);
            }
        }
        map
    }

    /// Content hash of the entire estimate.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"DarkMatterEstimate|");
        buf.extend_from_slice(&self.total_surface_millionths.to_le_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.estimated_at_epoch_secs.to_le_bytes());
        for (id, region) in &self.regions {
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(region.content_hash().as_bytes());
        }
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for DarkMatterEstimate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dark_matter_estimate[active={}/{}:fraction={}/M:regions={}]",
            self.active_mass(),
            self.total_surface_millionths,
            self.dark_matter_fraction(),
            self.total_region_count(),
        )
    }
}

// ---------------------------------------------------------------------------
// BurndownObservation
// ---------------------------------------------------------------------------

/// A single observation in the burndown time series.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurndownObservation {
    /// Timestamp (epoch seconds) of this observation.
    pub timestamp_epoch_secs: u64,
    /// Active dark-matter mass at this point in millionths.
    pub active_mass_millionths: u64,
    /// Cumulative discovered mass in millionths.
    pub cumulative_discovered_millionths: u64,
    /// Cumulative retired mass in millionths.
    pub cumulative_retired_millionths: u64,
}

impl BurndownObservation {
    /// Content hash of this observation.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(32);
        buf.extend_from_slice(&self.timestamp_epoch_secs.to_le_bytes());
        buf.extend_from_slice(&self.active_mass_millionths.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_discovered_millionths.to_le_bytes());
        buf.extend_from_slice(&self.cumulative_retired_millionths.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// BurndownTracker
// ---------------------------------------------------------------------------

/// Tracks the rate at which dark matter is discovered and retired over time.
///
/// The tracker maintains a time series of observations.  From consecutive
/// pairs it derives:
/// - **Discovery velocity**: rate at which new dark matter is found.
/// - **Retirement velocity**: rate at which dark matter is addressed.
/// - **Net burndown velocity**: retirement - discovery (positive = shrinking).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurndownTracker {
    /// Ordered observation history (ascending by timestamp).
    pub observations: Vec<BurndownObservation>,
    /// Total surface area for fraction computation.
    pub total_surface_millionths: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

impl BurndownTracker {
    /// Create a new empty tracker.
    #[must_use]
    pub fn new(total_surface_millionths: u64, epoch: SecurityEpoch) -> Self {
        Self {
            observations: Vec::new(),
            total_surface_millionths,
            epoch,
        }
    }

    /// Record a new observation.  Observations must be added in
    /// chronological order; out-of-order insertions are silently dropped.
    pub fn record(&mut self, obs: BurndownObservation) {
        if let Some(last) = self.observations.last()
            && obs.timestamp_epoch_secs <= last.timestamp_epoch_secs
        {
            return; // out of order — drop
        }
        self.observations.push(obs);
    }

    /// Number of recorded observations.
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Whether we have enough observations for statistical validity.
    #[must_use]
    pub fn has_enough_observations(&self, min_count: u64) -> bool {
        self.observations.len() >= min_count as usize
    }

    /// Discovery velocity over the last N observations, in millionths per
    /// second.  Returns 0 if insufficient data.
    #[must_use]
    pub fn discovery_velocity(&self, window: usize) -> u64 {
        self.compute_velocity(window, |a, b| {
            b.cumulative_discovered_millionths
                .saturating_sub(a.cumulative_discovered_millionths)
        })
    }

    /// Retirement velocity over the last N observations, in millionths per
    /// second.  Returns 0 if insufficient data.
    #[must_use]
    pub fn retirement_velocity(&self, window: usize) -> u64 {
        self.compute_velocity(window, |a, b| {
            b.cumulative_retired_millionths
                .saturating_sub(a.cumulative_retired_millionths)
        })
    }

    /// Net burndown velocity: retirement - discovery.  Positive means the
    /// dark-matter pile is shrinking.  Returns a signed representation:
    /// (magnitude_millionths, is_positive).
    #[must_use]
    pub fn net_burndown_velocity(&self, window: usize) -> (u64, bool) {
        let disc = self.discovery_velocity(window);
        let ret = self.retirement_velocity(window);
        if ret >= disc {
            (ret.saturating_sub(disc), true)
        } else {
            (disc.saturating_sub(ret), false)
        }
    }

    /// Latest active mass, or 0 if no observations.
    #[must_use]
    pub fn latest_active_mass(&self) -> u64 {
        self.observations
            .last()
            .map_or(0, |o| o.active_mass_millionths)
    }

    /// Latest dark-matter fraction, in millionths.
    #[must_use]
    pub fn latest_dark_matter_fraction(&self) -> u64 {
        if self.total_surface_millionths == 0 {
            return MILLION;
        }
        self.latest_active_mass()
            .saturating_mul(MILLION)
            .checked_div(self.total_surface_millionths)
            .unwrap_or(MILLION)
    }

    /// Time span (in seconds) covered by the observation window.
    #[must_use]
    pub fn time_span_secs(&self) -> u64 {
        if self.observations.len() < 2 {
            return 0;
        }
        let first = self.observations.first().unwrap();
        let last = self.observations.last().unwrap();
        last.timestamp_epoch_secs
            .saturating_sub(first.timestamp_epoch_secs)
    }

    /// Content hash of the entire tracker state.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"BurndownTracker|");
        buf.extend_from_slice(&self.total_surface_millionths.to_le_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        for obs in &self.observations {
            buf.extend_from_slice(obs.content_hash().as_bytes());
        }
        ContentHash::compute(&buf)
    }

    // -- internal helper --

    fn compute_velocity<F>(&self, window: usize, delta_fn: F) -> u64
    where
        F: Fn(&BurndownObservation, &BurndownObservation) -> u64,
    {
        if self.observations.len() < 2 {
            return 0;
        }
        let effective_window = window.min(self.observations.len());
        if effective_window < 2 {
            return 0;
        }
        let start_idx = self.observations.len().saturating_sub(effective_window);
        let start = &self.observations[start_idx];
        let end = self.observations.last().unwrap();
        let dt = end
            .timestamp_epoch_secs
            .saturating_sub(start.timestamp_epoch_secs);
        if dt == 0 {
            return 0;
        }
        let delta = delta_fn(start, end);
        delta.saturating_mul(MILLION).checked_div(dt).unwrap_or(0)
    }
}

impl fmt::Display for BurndownTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (vel, positive) = self.net_burndown_velocity(self.observations.len());
        let sign = if positive { "+" } else { "-" };
        write!(
            f,
            "burndown[obs={}:latest_mass={}:net={}{}/M/s]",
            self.observation_count(),
            self.latest_active_mass(),
            sign,
            vel,
        )
    }
}

// ---------------------------------------------------------------------------
// BoardState — tri-state outcome
// ---------------------------------------------------------------------------

/// The assessed state of a board with respect to dark-matter coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardState {
    /// Board is genuinely saturated: dark matter is low and being retired
    /// faster than it is discovered.
    Saturated,
    /// Board cells may look green, but dark-matter mass is too high or
    /// burndown is too slow.  Coverage claims must be qualified.
    ScopeLimited,
    /// Board has not received fresh observations within the staleness
    /// window.  All verdicts are degraded regardless of cell color.
    Stale,
}

impl BoardState {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[Self::Saturated, Self::ScopeLimited, Self::Stale];

    /// Whether this state permits claiming frontier coverage.
    #[must_use]
    pub fn permits_frontier_claim(&self) -> bool {
        matches!(self, Self::Saturated)
    }

    /// Human-readable label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Saturated => "saturated",
            Self::ScopeLimited => "scope_limited",
            Self::Stale => "stale",
        }
    }
}

impl fmt::Display for BoardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SaturationConfig
// ---------------------------------------------------------------------------

/// Configuration for saturation, freshness, and ratchet-widening gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationConfig {
    /// Maximum dark-matter fraction (millionths) for saturation.
    pub saturation_threshold_millionths: u64,
    /// Maximum staleness in hours before the board is declared stale.
    pub max_staleness_hours: u64,
    /// Minimum net burndown velocity (millionths per second) required.
    pub min_burndown_velocity_millionths: u64,
    /// Maximum dark-matter fraction (millionths) for ratchet widening.
    pub ratchet_widening_ceiling_millionths: u64,
    /// Minimum observations for a statistically valid burndown estimate.
    pub min_observations: u64,
    /// Burndown velocity window size (number of observations).
    pub velocity_window: usize,
}

impl Default for SaturationConfig {
    fn default() -> Self {
        Self {
            saturation_threshold_millionths: DEFAULT_SATURATION_THRESHOLD,
            max_staleness_hours: DEFAULT_MAX_STALENESS_HOURS,
            min_burndown_velocity_millionths: DEFAULT_MIN_BURNDOWN_VELOCITY,
            ratchet_widening_ceiling_millionths: DEFAULT_RATCHET_WIDENING_CEILING,
            min_observations: DEFAULT_MIN_OBSERVATIONS,
            velocity_window: 10,
        }
    }
}

impl SaturationConfig {
    /// Validate the configuration, returning violations.
    #[must_use]
    pub fn validate(&self) -> Vec<ConfigViolation> {
        let mut violations = Vec::new();
        if self.saturation_threshold_millionths > MILLION {
            violations.push(ConfigViolation {
                field: "saturation_threshold_millionths".into(),
                message: "cannot exceed 1_000_000 (100%)".into(),
            });
        }
        if self.ratchet_widening_ceiling_millionths > MILLION {
            violations.push(ConfigViolation {
                field: "ratchet_widening_ceiling_millionths".into(),
                message: "cannot exceed 1_000_000 (100%)".into(),
            });
        }
        if self.min_observations == 0 {
            violations.push(ConfigViolation {
                field: "min_observations".into(),
                message: "must be at least 1".into(),
            });
        }
        if self.velocity_window == 0 {
            violations.push(ConfigViolation {
                field: "velocity_window".into(),
                message: "must be at least 1".into(),
            });
        }
        if self.max_staleness_hours == 0 {
            violations.push(ConfigViolation {
                field: "max_staleness_hours".into(),
                message: "must be at least 1".into(),
            });
        }
        violations
    }
}

/// A configuration validation violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigViolation {
    /// Which field is invalid.
    pub field: String,
    /// Human-readable explanation.
    pub message: String,
}

// ---------------------------------------------------------------------------
// SaturationReason
// ---------------------------------------------------------------------------

/// Reason attached to a saturation verdict explaining why a particular
/// board state was chosen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaturationReason {
    /// Dark-matter fraction is below threshold and burndown is positive.
    LowDarkMatterWithPositiveBurndown,
    /// Dark-matter fraction exceeds saturation threshold.
    HighDarkMatterFraction { fraction_millionths: u64 },
    /// Burndown velocity is negative (dark matter growing).
    NegativeBurndown { velocity_millionths: u64 },
    /// Burndown velocity is positive but below minimum.
    InsufficientBurndownVelocity { velocity_millionths: u64 },
    /// Not enough observations for a statistically valid verdict.
    InsufficientObservations { count: usize, required: u64 },
    /// Board has not been refreshed within the staleness window.
    StaleBoard { hours_since_refresh: u64 },
    /// Configuration is invalid — fail closed.
    InvalidConfiguration { violations: Vec<ConfigViolation> },
}

impl fmt::Display for SaturationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LowDarkMatterWithPositiveBurndown => {
                write!(f, "low dark matter with positive burndown")
            }
            Self::HighDarkMatterFraction {
                fraction_millionths,
            } => {
                write!(f, "high dark matter fraction: {fraction_millionths}/M")
            }
            Self::NegativeBurndown {
                velocity_millionths,
            } => {
                write!(f, "negative burndown velocity: -{velocity_millionths}/M/s")
            }
            Self::InsufficientBurndownVelocity {
                velocity_millionths,
            } => {
                write!(
                    f,
                    "insufficient burndown velocity: {velocity_millionths}/M/s"
                )
            }
            Self::InsufficientObservations { count, required } => {
                write!(f, "insufficient observations: {count}/{required}")
            }
            Self::StaleBoard {
                hours_since_refresh,
            } => {
                write!(f, "stale board: {hours_since_refresh}h since refresh")
            }
            Self::InvalidConfiguration { violations } => {
                write!(f, "invalid configuration: {} violations", violations.len())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// BoardSaturationVerdict
// ---------------------------------------------------------------------------

/// The outcome of evaluating board saturation against dark-matter burndown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardSaturationVerdict {
    /// The assessed board state.
    pub state: BoardState,
    /// Reason(s) for the verdict.
    pub reasons: Vec<SaturationReason>,
    /// Dark-matter fraction at verdict time (millionths).
    pub dark_matter_fraction_millionths: u64,
    /// Net burndown velocity (millionths per second), signed.
    pub net_burndown_velocity_millionths: i64,
    /// Number of burndown observations used.
    pub observation_count: usize,
    /// Security epoch at verdict time.
    pub epoch: SecurityEpoch,
    /// Timestamp (epoch seconds) of the verdict.
    pub verdict_at_epoch_secs: u64,
}

impl BoardSaturationVerdict {
    /// Content hash of the verdict.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"BoardSaturationVerdict|");
        buf.extend_from_slice(self.state.as_str().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&self.dark_matter_fraction_millionths.to_le_bytes());
        buf.extend_from_slice(&self.net_burndown_velocity_millionths.to_le_bytes());
        buf.extend_from_slice(&(self.observation_count as u64).to_le_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.verdict_at_epoch_secs.to_le_bytes());
        for reason in &self.reasons {
            buf.extend_from_slice(reason.to_string().as_bytes());
        }
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for BoardSaturationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "saturation_verdict[{}:dm={}/M:vel={}/M/s]",
            self.state, self.dark_matter_fraction_millionths, self.net_burndown_velocity_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// FreshnessVerdict
// ---------------------------------------------------------------------------

/// Outcome of evaluating board freshness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreshnessVerdict {
    /// Whether the board is considered fresh.
    pub is_fresh: bool,
    /// Hours since the last observation.
    pub hours_since_last_observation: u64,
    /// Maximum allowed staleness hours (from config).
    pub max_staleness_hours: u64,
    /// Reason for the verdict.
    pub reason: FreshnessReason,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp of the verdict.
    pub verdict_at_epoch_secs: u64,
}

impl FreshnessVerdict {
    /// Content hash of the freshness verdict.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"FreshnessVerdict|");
        buf.push(if self.is_fresh { 1 } else { 0 });
        buf.extend_from_slice(&self.hours_since_last_observation.to_le_bytes());
        buf.extend_from_slice(&self.max_staleness_hours.to_le_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.verdict_at_epoch_secs.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for FreshnessVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = if self.is_fresh { "fresh" } else { "stale" };
        write!(
            f,
            "freshness[{}:{}h/{max}h]",
            label,
            self.hours_since_last_observation,
            max = self.max_staleness_hours,
        )
    }
}

/// Reason for a freshness verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessReason {
    /// Board is fresh: last observation is within the staleness window.
    WithinWindow,
    /// Board is stale: last observation exceeds the staleness window.
    ExceedsWindow { hours_over: u64 },
    /// No observations exist — board is maximally stale.
    NoObservations,
}

impl fmt::Display for FreshnessReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithinWindow => write!(f, "within_window"),
            Self::ExceedsWindow { hours_over } => {
                write!(f, "exceeds_window_by_{hours_over}h")
            }
            Self::NoObservations => write!(f, "no_observations"),
        }
    }
}

// ---------------------------------------------------------------------------
// RatchetWideningVerdict
// ---------------------------------------------------------------------------

/// Outcome of evaluating whether ratchet widening is permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetWideningVerdict {
    /// Whether widening is permitted.
    pub permitted: bool,
    /// Current dark-matter fraction (millionths).
    pub dark_matter_fraction_millionths: u64,
    /// Ceiling from config (millionths).
    pub ceiling_millionths: u64,
    /// Reason for the verdict.
    pub reason: RatchetWideningReason,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp of the verdict.
    pub verdict_at_epoch_secs: u64,
}

impl RatchetWideningVerdict {
    /// Content hash.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"RatchetWideningVerdict|");
        buf.push(if self.permitted { 1 } else { 0 });
        buf.extend_from_slice(&self.dark_matter_fraction_millionths.to_le_bytes());
        buf.extend_from_slice(&self.ceiling_millionths.to_le_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.verdict_at_epoch_secs.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for RatchetWideningVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = if self.permitted {
            "permitted"
        } else {
            "blocked"
        };
        write!(
            f,
            "ratchet_widening[{}:dm={}/M:ceiling={}/M]",
            label, self.dark_matter_fraction_millionths, self.ceiling_millionths,
        )
    }
}

/// Reason for a ratchet-widening verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RatchetWideningReason {
    /// Dark-matter fraction is below the widening ceiling.
    BelowCeiling,
    /// Dark-matter fraction exceeds the widening ceiling.
    AboveCeiling { excess_millionths: u64 },
    /// Board is stale — widening is blocked regardless.
    BoardStale,
    /// Not enough observations for a valid assessment.
    InsufficientData,
}

impl fmt::Display for RatchetWideningReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowCeiling => write!(f, "below_ceiling"),
            Self::AboveCeiling { excess_millionths } => {
                write!(f, "above_ceiling_by_{excess_millionths}/M")
            }
            Self::BoardStale => write!(f, "board_stale"),
            Self::InsufficientData => write!(f, "insufficient_data"),
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// A content-hashed receipt tying together saturation, freshness, and
/// ratchet-widening verdicts into a single auditable record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Receipt identifier (deterministic content hash).
    pub receipt_hash: ContentHash,
    /// Schema version.
    pub schema_version: String,
    /// Component that produced this receipt.
    pub component: String,
    /// Board saturation verdict.
    pub saturation_verdict: BoardSaturationVerdict,
    /// Freshness verdict.
    pub freshness_verdict: FreshnessVerdict,
    /// Ratchet-widening verdict.
    pub ratchet_widening_verdict: RatchetWideningVerdict,
    /// The composite board state derived from all three verdicts.
    pub composite_state: BoardState,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp.
    pub issued_at_epoch_secs: u64,
}

impl DecisionReceipt {
    /// Compute the receipt hash from the component verdicts.
    #[must_use]
    pub fn compute_hash(
        saturation: &BoardSaturationVerdict,
        freshness: &FreshnessVerdict,
        ratchet: &RatchetWideningVerdict,
        epoch: SecurityEpoch,
        timestamp: u64,
    ) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"DecisionReceipt|");
        buf.extend_from_slice(DARK_MATTER_GATE_SCHEMA_VERSION.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(saturation.content_hash().as_bytes());
        buf.extend_from_slice(freshness.content_hash().as_bytes());
        buf.extend_from_slice(ratchet.content_hash().as_bytes());
        buf.extend_from_slice(&epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&timestamp.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt[{}:{}:epoch={}]",
            self.composite_state,
            hex_encode(&self.receipt_hash.as_bytes()[..8]),
            self.epoch,
        )
    }
}

// ---------------------------------------------------------------------------
// DarkMatterEvidence
// ---------------------------------------------------------------------------

/// Structured evidence emission capturing the full dark-matter assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterEvidence {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Component name.
    pub component: String,
    /// The dark-matter estimate at evaluation time.
    pub estimate_summary: EstimateSummary,
    /// Burndown velocity metrics.
    pub burndown_metrics: BurndownMetrics,
    /// The composite board state.
    pub board_state: BoardState,
    /// Receipt hash for cross-referencing.
    pub receipt_hash: ContentHash,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Timestamp.
    pub emitted_at_epoch_secs: u64,
}

/// Summary of the dark-matter estimate for evidence emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EstimateSummary {
    /// Total surface area (millionths).
    pub total_surface_millionths: u64,
    /// Active dark-matter mass (millionths).
    pub active_mass_millionths: u64,
    /// Retired mass (millionths).
    pub retired_mass_millionths: u64,
    /// Dark-matter fraction (millionths).
    pub fraction_millionths: u64,
    /// Active region count.
    pub active_region_count: usize,
    /// Retired region count.
    pub retired_region_count: usize,
    /// Per-kind breakdown: kind label -> active mass.
    pub mass_by_kind: BTreeMap<String, u64>,
}

/// Burndown velocity metrics for evidence emission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurndownMetrics {
    /// Discovery velocity (millionths per second).
    pub discovery_velocity_millionths: u64,
    /// Retirement velocity (millionths per second).
    pub retirement_velocity_millionths: u64,
    /// Net burndown velocity (signed).
    pub net_velocity_millionths: i64,
    /// Observation count.
    pub observation_count: usize,
    /// Time span in seconds.
    pub time_span_secs: u64,
    /// Hours since last observation.
    pub hours_since_last_observation: u64,
}

impl DarkMatterEvidence {
    /// Content hash of this evidence record.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(b"DarkMatterEvidence|");
        buf.extend_from_slice(self.schema_version.as_bytes());
        buf.extend_from_slice(self.bead_id.as_bytes());
        buf.extend_from_slice(self.board_state.as_str().as_bytes());
        buf.extend_from_slice(self.receipt_hash.as_bytes());
        buf.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.emitted_at_epoch_secs.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for DarkMatterEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "dark_matter_evidence[{}:dm={}/M:vel={}/M/s]",
            self.board_state,
            self.estimate_summary.fraction_millionths,
            self.burndown_metrics.net_velocity_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// Helper: hex encode
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// SaturationGateEvaluator — the main orchestrator
// ---------------------------------------------------------------------------

/// Evaluator that combines dark-matter estimation, burndown tracking,
/// freshness gating, and ratchet-widening control into a single
/// assessment pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationGateEvaluator {
    /// Configuration.
    pub config: SaturationConfig,
    /// Current dark-matter estimate.
    pub estimate: DarkMatterEstimate,
    /// Burndown tracker.
    pub tracker: BurndownTracker,
}

impl SaturationGateEvaluator {
    /// Create a new evaluator.
    #[must_use]
    pub fn new(
        config: SaturationConfig,
        estimate: DarkMatterEstimate,
        tracker: BurndownTracker,
    ) -> Self {
        Self {
            config,
            estimate,
            tracker,
        }
    }

    /// Evaluate board saturation.
    #[must_use]
    pub fn evaluate_saturation(&self, now_epoch_secs: u64) -> BoardSaturationVerdict {
        let config_violations = self.config.validate();
        if !config_violations.is_empty() {
            return BoardSaturationVerdict {
                state: BoardState::ScopeLimited,
                reasons: vec![SaturationReason::InvalidConfiguration {
                    violations: config_violations,
                }],
                dark_matter_fraction_millionths: self.estimate.dark_matter_fraction(),
                net_burndown_velocity_millionths: 0,
                observation_count: self.tracker.observation_count(),
                epoch: self.estimate.epoch,
                verdict_at_epoch_secs: now_epoch_secs,
            };
        }

        let fraction = self.estimate.dark_matter_fraction();
        let obs_count = self.tracker.observation_count();
        let mut reasons = Vec::new();

        // Check observation count
        if !self
            .tracker
            .has_enough_observations(self.config.min_observations)
        {
            reasons.push(SaturationReason::InsufficientObservations {
                count: obs_count,
                required: self.config.min_observations,
            });
            return BoardSaturationVerdict {
                state: BoardState::ScopeLimited,
                reasons,
                dark_matter_fraction_millionths: fraction,
                net_burndown_velocity_millionths: 0,
                observation_count: obs_count,
                epoch: self.estimate.epoch,
                verdict_at_epoch_secs: now_epoch_secs,
            };
        }

        // Compute net velocity
        let (vel_magnitude, vel_positive) = self
            .tracker
            .net_burndown_velocity(self.config.velocity_window);
        let signed_velocity = if vel_positive {
            vel_magnitude as i64
        } else {
            -(vel_magnitude as i64)
        };

        // Check dark-matter fraction
        let fraction_ok = fraction <= self.config.saturation_threshold_millionths;
        if !fraction_ok {
            reasons.push(SaturationReason::HighDarkMatterFraction {
                fraction_millionths: fraction,
            });
        }

        // Check burndown velocity
        let velocity_ok = if vel_positive {
            vel_magnitude >= self.config.min_burndown_velocity_millionths
        } else {
            false
        };

        if !vel_positive {
            reasons.push(SaturationReason::NegativeBurndown {
                velocity_millionths: vel_magnitude,
            });
        } else if vel_magnitude < self.config.min_burndown_velocity_millionths {
            reasons.push(SaturationReason::InsufficientBurndownVelocity {
                velocity_millionths: vel_magnitude,
            });
        }

        let state = if fraction_ok && velocity_ok {
            reasons.push(SaturationReason::LowDarkMatterWithPositiveBurndown);
            BoardState::Saturated
        } else {
            BoardState::ScopeLimited
        };

        BoardSaturationVerdict {
            state,
            reasons,
            dark_matter_fraction_millionths: fraction,
            net_burndown_velocity_millionths: signed_velocity,
            observation_count: obs_count,
            epoch: self.estimate.epoch,
            verdict_at_epoch_secs: now_epoch_secs,
        }
    }

    /// Evaluate board freshness.
    #[must_use]
    pub fn evaluate_freshness(&self, now_epoch_secs: u64) -> FreshnessVerdict {
        let last_obs = self.tracker.observations.last();
        let (hours_since, reason) = match last_obs {
            None => (u64::MAX, FreshnessReason::NoObservations),
            Some(obs) => {
                let delta_secs = now_epoch_secs.saturating_sub(obs.timestamp_epoch_secs);
                let hours = delta_secs.checked_div(3600).unwrap_or(0);
                if hours <= self.config.max_staleness_hours {
                    (hours, FreshnessReason::WithinWindow)
                } else {
                    let over = hours.saturating_sub(self.config.max_staleness_hours);
                    (hours, FreshnessReason::ExceedsWindow { hours_over: over })
                }
            }
        };
        let is_fresh = matches!(reason, FreshnessReason::WithinWindow);
        FreshnessVerdict {
            is_fresh,
            hours_since_last_observation: hours_since,
            max_staleness_hours: self.config.max_staleness_hours,
            reason,
            epoch: self.estimate.epoch,
            verdict_at_epoch_secs: now_epoch_secs,
        }
    }

    /// Evaluate ratchet-widening permission.
    #[must_use]
    pub fn evaluate_ratchet_widening(&self, now_epoch_secs: u64) -> RatchetWideningVerdict {
        let fraction = self.estimate.dark_matter_fraction();

        // Check freshness first — stale boards cannot widen ratchets
        let freshness = self.evaluate_freshness(now_epoch_secs);
        if !freshness.is_fresh {
            return RatchetWideningVerdict {
                permitted: false,
                dark_matter_fraction_millionths: fraction,
                ceiling_millionths: self.config.ratchet_widening_ceiling_millionths,
                reason: RatchetWideningReason::BoardStale,
                epoch: self.estimate.epoch,
                verdict_at_epoch_secs: now_epoch_secs,
            };
        }

        // Check observations
        if !self
            .tracker
            .has_enough_observations(self.config.min_observations)
        {
            return RatchetWideningVerdict {
                permitted: false,
                dark_matter_fraction_millionths: fraction,
                ceiling_millionths: self.config.ratchet_widening_ceiling_millionths,
                reason: RatchetWideningReason::InsufficientData,
                epoch: self.estimate.epoch,
                verdict_at_epoch_secs: now_epoch_secs,
            };
        }

        // Check fraction against ceiling
        if fraction <= self.config.ratchet_widening_ceiling_millionths {
            RatchetWideningVerdict {
                permitted: true,
                dark_matter_fraction_millionths: fraction,
                ceiling_millionths: self.config.ratchet_widening_ceiling_millionths,
                reason: RatchetWideningReason::BelowCeiling,
                epoch: self.estimate.epoch,
                verdict_at_epoch_secs: now_epoch_secs,
            }
        } else {
            let excess = fraction.saturating_sub(self.config.ratchet_widening_ceiling_millionths);
            RatchetWideningVerdict {
                permitted: false,
                dark_matter_fraction_millionths: fraction,
                ceiling_millionths: self.config.ratchet_widening_ceiling_millionths,
                reason: RatchetWideningReason::AboveCeiling {
                    excess_millionths: excess,
                },
                epoch: self.estimate.epoch,
                verdict_at_epoch_secs: now_epoch_secs,
            }
        }
    }

    /// Run the full assessment pipeline and produce a decision receipt.
    #[must_use]
    pub fn evaluate(&self, now_epoch_secs: u64) -> DecisionReceipt {
        let saturation = self.evaluate_saturation(now_epoch_secs);
        let freshness = self.evaluate_freshness(now_epoch_secs);
        let ratchet = self.evaluate_ratchet_widening(now_epoch_secs);

        // Composite state: stale overrides everything; otherwise use saturation.
        let composite = if !freshness.is_fresh {
            BoardState::Stale
        } else {
            saturation.state
        };

        let receipt_hash = DecisionReceipt::compute_hash(
            &saturation,
            &freshness,
            &ratchet,
            self.estimate.epoch,
            now_epoch_secs,
        );

        DecisionReceipt {
            receipt_hash,
            schema_version: DARK_MATTER_GATE_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            saturation_verdict: saturation,
            freshness_verdict: freshness,
            ratchet_widening_verdict: ratchet,
            composite_state: composite,
            epoch: self.estimate.epoch,
            issued_at_epoch_secs: now_epoch_secs,
        }
    }

    /// Produce structured evidence from the latest evaluation.
    #[must_use]
    pub fn emit_evidence(&self, now_epoch_secs: u64) -> DarkMatterEvidence {
        let receipt = self.evaluate(now_epoch_secs);
        let estimate = &self.estimate;

        let mass_by_kind_raw = estimate.mass_by_kind();
        let mut mass_by_kind = BTreeMap::new();
        for (kind, (active, _retired)) in &mass_by_kind_raw {
            mass_by_kind.insert(kind.as_str().to_string(), *active);
        }

        let (vel_magnitude, vel_positive) = self
            .tracker
            .net_burndown_velocity(self.config.velocity_window);
        let net_velocity = if vel_positive {
            vel_magnitude as i64
        } else {
            -(vel_magnitude as i64)
        };

        let hours_since = self.tracker.observations.last().map_or(u64::MAX, |obs| {
            now_epoch_secs
                .saturating_sub(obs.timestamp_epoch_secs)
                .checked_div(3600)
                .unwrap_or(0)
        });

        DarkMatterEvidence {
            schema_version: DARK_MATTER_GATE_SCHEMA_VERSION.to_string(),
            bead_id: DARK_MATTER_GATE_BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            estimate_summary: EstimateSummary {
                total_surface_millionths: estimate.total_surface_millionths,
                active_mass_millionths: estimate.active_mass(),
                retired_mass_millionths: estimate.retired_mass(),
                fraction_millionths: estimate.dark_matter_fraction(),
                active_region_count: estimate.active_region_count(),
                retired_region_count: estimate.retired_region_count(),
                mass_by_kind,
            },
            burndown_metrics: BurndownMetrics {
                discovery_velocity_millionths: self
                    .tracker
                    .discovery_velocity(self.config.velocity_window),
                retirement_velocity_millionths: self
                    .tracker
                    .retirement_velocity(self.config.velocity_window),
                net_velocity_millionths: net_velocity,
                observation_count: self.tracker.observation_count(),
                time_span_secs: self.tracker.time_span_secs(),
                hours_since_last_observation: hours_since,
            },
            board_state: receipt.composite_state,
            receipt_hash: receipt.receipt_hash,
            epoch: self.estimate.epoch,
            emitted_at_epoch_secs: now_epoch_secs,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test helpers (module-internal)
    // -----------------------------------------------------------------------

    /// Build a test region with defaults.
    #[allow(dead_code)]
    fn make_test_region(
        region_id: &str,
        kind: DarkMatterRegionKind,
        mass: u64,
        retired: bool,
    ) -> DarkMatterRegion {
        DarkMatterRegion {
            region_id: region_id.to_string(),
            kind,
            mass_millionths: mass,
            retired,
            discovered_at_epoch_secs: 1000,
            retired_at_epoch_secs: if retired { Some(2000) } else { None },
            priority_weight_millionths: MILLION,
        }
    }

    /// Build a sequence of burndown observations for testing.
    fn make_test_observations(
        count: usize,
        start_time: u64,
        interval_secs: u64,
        initial_active: u64,
        discovery_per_step: u64,
        retirement_per_step: u64,
    ) -> Vec<BurndownObservation> {
        let mut obs = Vec::with_capacity(count);
        let mut cumulative_discovered = 0u64;
        let mut cumulative_retired = 0u64;
        let mut active = initial_active;
        for i in 0..count {
            obs.push(BurndownObservation {
                timestamp_epoch_secs: start_time + (i as u64) * interval_secs,
                active_mass_millionths: active,
                cumulative_discovered_millionths: cumulative_discovered,
                cumulative_retired_millionths: cumulative_retired,
            });
            cumulative_discovered = cumulative_discovered.saturating_add(discovery_per_step);
            cumulative_retired = cumulative_retired.saturating_add(retirement_per_step);
            // net change: +discovered - retired
            active = active
                .saturating_add(discovery_per_step)
                .saturating_sub(retirement_per_step);
        }
        obs
    }

    /// Build a fully wired evaluator for testing.
    fn make_test_evaluator(
        active_mass: u64,
        total_surface: u64,
        observations: Vec<BurndownObservation>,
        config: SaturationConfig,
    ) -> SaturationGateEvaluator {
        let epoch = SecurityEpoch::from_raw(1);
        let mut estimate = DarkMatterEstimate::new(total_surface, epoch, 1000);
        // Add a single region with the given active mass
        if active_mass > 0 {
            estimate.add_region(DarkMatterRegion {
                region_id: "test_region".to_string(),
                kind: DarkMatterRegionKind::UntestedCodePath,
                mass_millionths: active_mass,
                retired: false,
                discovered_at_epoch_secs: 1000,
                retired_at_epoch_secs: None,
                priority_weight_millionths: MILLION,
            });
        }
        let mut tracker = BurndownTracker::new(total_surface, epoch);
        for obs in observations {
            tracker.record(obs);
        }
        SaturationGateEvaluator::new(config, estimate, tracker)
    }

    // -----------------------------------------------------------------------
    // DarkMatterRegionKind tests
    // -----------------------------------------------------------------------

    #[test]
    fn region_kind_variant_count() {
        assert_eq!(DarkMatterRegionKind::ALL.len(), 10);
    }

    #[test]
    fn region_kind_display() {
        assert_eq!(
            DarkMatterRegionKind::UntestedCodePath.to_string(),
            "untested_code_path"
        );
        assert_eq!(
            DarkMatterRegionKind::UncoveredSecurityBoundary.to_string(),
            "uncovered_security_boundary"
        );
    }

    #[test]
    fn region_kind_serde_round_trip() {
        for &kind in DarkMatterRegionKind::ALL {
            let json = serde_json::to_string(&kind).unwrap();
            let back: DarkMatterRegionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn region_kind_as_str_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for &kind in DarkMatterRegionKind::ALL {
            assert!(seen.insert(kind.as_str()), "duplicate as_str: {}", kind);
        }
    }

    // -----------------------------------------------------------------------
    // DarkMatterRegion tests
    // -----------------------------------------------------------------------

    #[test]
    fn region_effective_mass_active() {
        let r = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        assert_eq!(r.effective_mass(), 100_000);
    }

    #[test]
    fn region_effective_mass_retired() {
        let r = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, true);
        assert_eq!(r.effective_mass(), 0);
    }

    #[test]
    fn region_effective_mass_weighted() {
        let mut r = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
        r.priority_weight_millionths = 500_000; // 0.5 weight
        assert_eq!(r.effective_mass(), 100_000);
    }

    #[test]
    fn region_content_hash_deterministic() {
        let r1 = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        let r2 = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn region_content_hash_differs_on_id() {
        let r1 = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        let r2 = make_test_region("r2", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn region_content_hash_differs_on_kind() {
        let r1 = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        let r2 = make_test_region(
            "r1",
            DarkMatterRegionKind::UnverifiedInterleaving,
            100_000,
            false,
        );
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn region_content_hash_differs_on_retired() {
        let r1 = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        let r2 = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, true);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn region_display() {
        let r = make_test_region(
            "gc_reentry",
            DarkMatterRegionKind::UnobservedInteraction,
            50_000,
            false,
        );
        let s = r.to_string();
        assert!(s.contains("gc_reentry"));
        assert!(s.contains("active"));
        assert!(s.contains("50000"));
    }

    #[test]
    fn region_serde_round_trip() {
        let r = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 100_000, false);
        let json = serde_json::to_string(&r).unwrap();
        let back: DarkMatterRegion = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    // -----------------------------------------------------------------------
    // DarkMatterEstimate tests
    // -----------------------------------------------------------------------

    #[test]
    fn estimate_empty() {
        let e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        assert_eq!(e.active_mass(), 0);
        assert_eq!(e.retired_mass(), 0);
        assert_eq!(e.dark_matter_fraction(), 0);
        assert_eq!(e.active_region_count(), 0);
        assert_eq!(e.total_region_count(), 0);
    }

    #[test]
    fn estimate_active_mass() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        e.add_region(make_test_region(
            "r2",
            DarkMatterRegionKind::UntestedCodePath,
            50_000,
            false,
        ));
        assert_eq!(e.active_mass(), 150_000);
    }

    #[test]
    fn estimate_retired_mass_excluded() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        e.add_region(make_test_region(
            "r2",
            DarkMatterRegionKind::UntestedCodePath,
            50_000,
            true,
        ));
        assert_eq!(e.active_mass(), 100_000);
        assert_eq!(e.retired_mass(), 50_000);
    }

    #[test]
    fn estimate_dark_matter_fraction() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            200_000,
            false,
        ));
        // 200_000 / 1_000_000 = 0.2 = 200_000 millionths
        assert_eq!(e.dark_matter_fraction(), 200_000);
    }

    #[test]
    fn estimate_fraction_zero_surface() {
        let e = DarkMatterEstimate::new(0, SecurityEpoch::from_raw(1), 1000);
        assert_eq!(e.dark_matter_fraction(), MILLION);
    }

    #[test]
    fn estimate_region_counts() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        e.add_region(make_test_region(
            "r2",
            DarkMatterRegionKind::UntestedCodePath,
            50_000,
            true,
        ));
        e.add_region(make_test_region(
            "r3",
            DarkMatterRegionKind::UnverifiedInterleaving,
            30_000,
            false,
        ));
        assert_eq!(e.active_region_count(), 2);
        assert_eq!(e.retired_region_count(), 1);
        assert_eq!(e.total_region_count(), 3);
    }

    #[test]
    fn estimate_mass_by_kind() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        e.add_region(make_test_region(
            "r2",
            DarkMatterRegionKind::UntestedCodePath,
            50_000,
            true,
        ));
        e.add_region(make_test_region(
            "r3",
            DarkMatterRegionKind::UnverifiedInterleaving,
            30_000,
            false,
        ));
        let by_kind = e.mass_by_kind();
        assert_eq!(
            by_kind[&DarkMatterRegionKind::UntestedCodePath],
            (100_000, 50_000)
        );
        assert_eq!(
            by_kind[&DarkMatterRegionKind::UnverifiedInterleaving],
            (30_000, 0)
        );
    }

    #[test]
    fn estimate_content_hash_deterministic() {
        let mut e1 = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e1.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        let mut e2 = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e2.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn estimate_content_hash_differs() {
        let mut e1 = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e1.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        let mut e2 = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e2.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            200_000,
            false,
        ));
        assert_ne!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn estimate_display() {
        let e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        let s = e.to_string();
        assert!(s.contains("dark_matter_estimate"));
    }

    #[test]
    fn estimate_serde_round_trip() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        let json = serde_json::to_string(&e).unwrap();
        let back: DarkMatterEstimate = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn estimate_effective_mass() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        let mut r = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
        r.priority_weight_millionths = 500_000; // 0.5
        e.add_region(r);
        assert_eq!(e.effective_mass(), 100_000);
    }

    // -----------------------------------------------------------------------
    // BurndownObservation tests
    // -----------------------------------------------------------------------

    #[test]
    fn observation_content_hash_deterministic() {
        let o1 = BurndownObservation {
            timestamp_epoch_secs: 1000,
            active_mass_millionths: 200_000,
            cumulative_discovered_millionths: 100_000,
            cumulative_retired_millionths: 50_000,
        };
        let o2 = o1.clone();
        assert_eq!(o1.content_hash(), o2.content_hash());
    }

    #[test]
    fn observation_content_hash_differs() {
        let o1 = BurndownObservation {
            timestamp_epoch_secs: 1000,
            active_mass_millionths: 200_000,
            cumulative_discovered_millionths: 100_000,
            cumulative_retired_millionths: 50_000,
        };
        let o2 = BurndownObservation {
            timestamp_epoch_secs: 2000,
            ..o1.clone()
        };
        assert_ne!(o1.content_hash(), o2.content_hash());
    }

    #[test]
    fn observation_serde_round_trip() {
        let obs = BurndownObservation {
            timestamp_epoch_secs: 1000,
            active_mass_millionths: 200_000,
            cumulative_discovered_millionths: 100_000,
            cumulative_retired_millionths: 50_000,
        };
        let json = serde_json::to_string(&obs).unwrap();
        let back: BurndownObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, obs);
    }

    // -----------------------------------------------------------------------
    // BurndownTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn tracker_empty() {
        let t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        assert_eq!(t.observation_count(), 0);
        assert_eq!(t.latest_active_mass(), 0);
        assert_eq!(t.time_span_secs(), 0);
        assert!(!t.has_enough_observations(1));
    }

    #[test]
    fn tracker_record_in_order() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100,
            active_mass_millionths: 500_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        t.record(BurndownObservation {
            timestamp_epoch_secs: 200,
            active_mass_millionths: 400_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 100_000,
        });
        assert_eq!(t.observation_count(), 2);
        assert_eq!(t.latest_active_mass(), 400_000);
    }

    #[test]
    fn tracker_drops_out_of_order() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 200,
            active_mass_millionths: 500_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100, // out of order
            active_mass_millionths: 400_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        assert_eq!(t.observation_count(), 1);
    }

    #[test]
    fn tracker_drops_duplicate_timestamp() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100,
            active_mass_millionths: 500_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100, // same timestamp
            active_mass_millionths: 400_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        assert_eq!(t.observation_count(), 1);
    }

    #[test]
    fn tracker_discovery_velocity() {
        let obs = make_test_observations(10, 1000, 100, 500_000, 10_000, 0);
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        for o in obs {
            t.record(o);
        }
        let vel = t.discovery_velocity(10);
        // Over 900 seconds, discovered 90_000 millionths.
        // velocity = 90_000 * 1_000_000 / 900 = 100_000_000
        assert!(vel > 0);
    }

    #[test]
    fn tracker_retirement_velocity() {
        let obs = make_test_observations(10, 1000, 100, 500_000, 0, 10_000);
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        for o in obs {
            t.record(o);
        }
        let vel = t.retirement_velocity(10);
        assert!(vel > 0);
    }

    #[test]
    fn tracker_net_burndown_positive() {
        // retirement > discovery => positive burndown
        let obs = make_test_observations(10, 1000, 100, 500_000, 5_000, 15_000);
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        for o in obs {
            t.record(o);
        }
        let (vel, positive) = t.net_burndown_velocity(10);
        assert!(positive, "burndown should be positive");
        assert!(vel > 0);
    }

    #[test]
    fn tracker_net_burndown_negative() {
        // discovery > retirement => negative burndown
        let obs = make_test_observations(10, 1000, 100, 500_000, 15_000, 5_000);
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        for o in obs {
            t.record(o);
        }
        let (_vel, positive) = t.net_burndown_velocity(10);
        assert!(!positive, "burndown should be negative");
    }

    #[test]
    fn tracker_dark_matter_fraction() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100,
            active_mass_millionths: 300_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        assert_eq!(t.latest_dark_matter_fraction(), 300_000);
    }

    #[test]
    fn tracker_dark_matter_fraction_zero_surface() {
        let t = BurndownTracker::new(0, SecurityEpoch::from_raw(1));
        assert_eq!(t.latest_dark_matter_fraction(), MILLION);
    }

    #[test]
    fn tracker_time_span() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100,
            active_mass_millionths: 0,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        t.record(BurndownObservation {
            timestamp_epoch_secs: 500,
            active_mass_millionths: 0,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        assert_eq!(t.time_span_secs(), 400);
    }

    #[test]
    fn tracker_content_hash_deterministic() {
        let obs = make_test_observations(5, 1000, 100, 500_000, 10_000, 5_000);
        let mut t1 = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        let mut t2 = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        for o in &obs {
            t1.record(o.clone());
            t2.record(o.clone());
        }
        assert_eq!(t1.content_hash(), t2.content_hash());
    }

    #[test]
    fn tracker_display() {
        let t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        let s = t.to_string();
        assert!(s.contains("burndown"));
    }

    #[test]
    fn tracker_serde_round_trip() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100,
            active_mass_millionths: 300_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        let json = serde_json::to_string(&t).unwrap();
        let back: BurndownTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn tracker_velocity_single_observation() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100,
            active_mass_millionths: 300_000,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        assert_eq!(t.discovery_velocity(10), 0);
        assert_eq!(t.retirement_velocity(10), 0);
    }

    // -----------------------------------------------------------------------
    // BoardState tests
    // -----------------------------------------------------------------------

    #[test]
    fn board_state_variant_count() {
        assert_eq!(BoardState::ALL.len(), 3);
    }

    #[test]
    fn board_state_permits_frontier_claim() {
        assert!(BoardState::Saturated.permits_frontier_claim());
        assert!(!BoardState::ScopeLimited.permits_frontier_claim());
        assert!(!BoardState::Stale.permits_frontier_claim());
    }

    #[test]
    fn board_state_display() {
        assert_eq!(BoardState::Saturated.to_string(), "saturated");
        assert_eq!(BoardState::ScopeLimited.to_string(), "scope_limited");
        assert_eq!(BoardState::Stale.to_string(), "stale");
    }

    #[test]
    fn board_state_serde_round_trip() {
        for &state in BoardState::ALL {
            let json = serde_json::to_string(&state).unwrap();
            let back: BoardState = serde_json::from_str(&json).unwrap();
            assert_eq!(back, state);
        }
    }

    // -----------------------------------------------------------------------
    // SaturationConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_valid() {
        let config = SaturationConfig::default();
        assert!(config.validate().is_empty());
    }

    #[test]
    fn config_threshold_over_million() {
        let config = SaturationConfig {
            saturation_threshold_millionths: MILLION + 1,
            ..SaturationConfig::default()
        };
        let violations = config.validate();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "saturation_threshold_millionths");
    }

    #[test]
    fn config_ratchet_ceiling_over_million() {
        let config = SaturationConfig {
            ratchet_widening_ceiling_millionths: MILLION + 1,
            ..SaturationConfig::default()
        };
        let violations = config.validate();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn config_zero_min_observations() {
        let config = SaturationConfig {
            min_observations: 0,
            ..SaturationConfig::default()
        };
        let violations = config.validate();
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "min_observations");
    }

    #[test]
    fn config_zero_velocity_window() {
        let config = SaturationConfig {
            velocity_window: 0,
            ..SaturationConfig::default()
        };
        let violations = config.validate();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn config_zero_staleness() {
        let config = SaturationConfig {
            max_staleness_hours: 0,
            ..SaturationConfig::default()
        };
        let violations = config.validate();
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn config_multiple_violations() {
        let config = SaturationConfig {
            saturation_threshold_millionths: MILLION + 1,
            min_observations: 0,
            velocity_window: 0,
            ..SaturationConfig::default()
        };
        let violations = config.validate();
        assert_eq!(violations.len(), 3);
    }

    #[test]
    fn config_serde_round_trip() {
        let config = SaturationConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: SaturationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    // -----------------------------------------------------------------------
    // SaturationReason tests
    // -----------------------------------------------------------------------

    #[test]
    fn saturation_reason_display() {
        let r = SaturationReason::HighDarkMatterFraction {
            fraction_millionths: 300_000,
        };
        assert!(r.to_string().contains("300000"));
    }

    #[test]
    fn saturation_reason_negative_burndown_display() {
        let r = SaturationReason::NegativeBurndown {
            velocity_millionths: 50_000,
        };
        assert!(r.to_string().contains("50000"));
    }

    // -----------------------------------------------------------------------
    // Evaluator: saturation tests
    // -----------------------------------------------------------------------

    #[test]
    fn evaluator_saturated_low_dm_positive_burndown() {
        let config = SaturationConfig {
            min_observations: 3,
            min_burndown_velocity_millionths: 10_000,
            ..SaturationConfig::default()
        };
        // active mass = 100_000 (10% of 1M) — below threshold of 200_000 (20%)
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let verdict = eval.evaluate_saturation(2000);
        assert_eq!(verdict.state, BoardState::Saturated);
    }

    #[test]
    fn evaluator_scope_limited_high_dm() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        // active mass = 500_000 (50%) — above threshold of 200_000 (20%)
        let obs = make_test_observations(5, 1000, 100, 500_000, 5_000, 15_000);
        let eval = make_test_evaluator(500_000, MILLION, obs, config);
        let verdict = eval.evaluate_saturation(2000);
        assert_eq!(verdict.state, BoardState::ScopeLimited);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, SaturationReason::HighDarkMatterFraction { .. }))
        );
    }

    #[test]
    fn evaluator_scope_limited_negative_burndown() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        // low dm, but discovery > retirement
        let obs = make_test_observations(5, 1000, 100, 100_000, 20_000, 5_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let verdict = eval.evaluate_saturation(2000);
        assert_eq!(verdict.state, BoardState::ScopeLimited);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, SaturationReason::NegativeBurndown { .. }))
        );
    }

    #[test]
    fn evaluator_scope_limited_insufficient_observations() {
        let config = SaturationConfig {
            min_observations: 10,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(3, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let verdict = eval.evaluate_saturation(2000);
        assert_eq!(verdict.state, BoardState::ScopeLimited);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, SaturationReason::InsufficientObservations { .. }))
        );
    }

    #[test]
    fn evaluator_scope_limited_invalid_config() {
        let config = SaturationConfig {
            min_observations: 0, // invalid
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let verdict = eval.evaluate_saturation(2000);
        assert_eq!(verdict.state, BoardState::ScopeLimited);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, SaturationReason::InvalidConfiguration { .. }))
        );
    }

    #[test]
    fn evaluator_saturation_velocity_below_minimum() {
        let config = SaturationConfig {
            min_observations: 3,
            min_burndown_velocity_millionths: 999_999_999, // impossibly high
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let verdict = eval.evaluate_saturation(2000);
        assert_eq!(verdict.state, BoardState::ScopeLimited);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| matches!(r, SaturationReason::InsufficientBurndownVelocity { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // Evaluator: freshness tests
    // -----------------------------------------------------------------------

    #[test]
    fn evaluator_fresh_board() {
        let config = SaturationConfig::default(); // max_staleness_hours = 168
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        // Last observation at 1000 + 4*100 = 1400. now = 1500 => 0 hours
        let verdict = eval.evaluate_freshness(1500);
        assert!(verdict.is_fresh);
        assert!(matches!(verdict.reason, FreshnessReason::WithinWindow));
    }

    #[test]
    fn evaluator_stale_board() {
        let config = SaturationConfig {
            max_staleness_hours: 1, // 1 hour = 3600 seconds
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        // Last observation at 1400. now = 1400 + 7200 (2 hours) = 8600
        let verdict = eval.evaluate_freshness(8600);
        assert!(!verdict.is_fresh);
        assert!(matches!(
            verdict.reason,
            FreshnessReason::ExceedsWindow { .. }
        ));
    }

    #[test]
    fn evaluator_no_observations_stale() {
        let config = SaturationConfig::default();
        let eval = make_test_evaluator(0, MILLION, vec![], config);
        let verdict = eval.evaluate_freshness(5000);
        assert!(!verdict.is_fresh);
        assert!(matches!(verdict.reason, FreshnessReason::NoObservations));
    }

    #[test]
    fn freshness_verdict_content_hash_deterministic() {
        let config = SaturationConfig::default();
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v1 = eval.evaluate_freshness(1500);
        let v2 = eval.evaluate_freshness(1500);
        assert_eq!(v1.content_hash(), v2.content_hash());
    }

    #[test]
    fn freshness_verdict_display() {
        let config = SaturationConfig::default();
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v = eval.evaluate_freshness(1500);
        let s = v.to_string();
        assert!(s.contains("fresh"));
    }

    #[test]
    fn freshness_verdict_serde_round_trip() {
        let config = SaturationConfig::default();
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v = eval.evaluate_freshness(1500);
        let json = serde_json::to_string(&v).unwrap();
        let back: FreshnessVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    // -----------------------------------------------------------------------
    // Evaluator: ratchet widening tests
    // -----------------------------------------------------------------------

    #[test]
    fn ratchet_widening_permitted_low_dm() {
        let config = SaturationConfig {
            min_observations: 3,
            ratchet_widening_ceiling_millionths: 200_000,
            ..SaturationConfig::default()
        };
        // active mass = 100_000 = 10% < 20% ceiling
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let verdict = eval.evaluate_ratchet_widening(1500);
        assert!(verdict.permitted);
        assert!(matches!(
            verdict.reason,
            RatchetWideningReason::BelowCeiling
        ));
    }

    #[test]
    fn ratchet_widening_blocked_high_dm() {
        let config = SaturationConfig {
            min_observations: 3,
            ratchet_widening_ceiling_millionths: 100_000, // 10% ceiling
            ..SaturationConfig::default()
        };
        // active mass = 300_000 = 30% > 10% ceiling
        let obs = make_test_observations(5, 1000, 100, 300_000, 5_000, 15_000);
        let eval = make_test_evaluator(300_000, MILLION, obs, config);
        let verdict = eval.evaluate_ratchet_widening(1500);
        assert!(!verdict.permitted);
        assert!(matches!(
            verdict.reason,
            RatchetWideningReason::AboveCeiling { .. }
        ));
    }

    #[test]
    fn ratchet_widening_blocked_stale() {
        let config = SaturationConfig {
            min_observations: 3,
            max_staleness_hours: 1,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        // now is far in the future
        let verdict = eval.evaluate_ratchet_widening(1_000_000);
        assert!(!verdict.permitted);
        assert!(matches!(verdict.reason, RatchetWideningReason::BoardStale));
    }

    #[test]
    fn ratchet_widening_blocked_insufficient_data() {
        let config = SaturationConfig {
            min_observations: 10,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(3, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let verdict = eval.evaluate_ratchet_widening(1500);
        assert!(!verdict.permitted);
        assert!(matches!(
            verdict.reason,
            RatchetWideningReason::InsufficientData
        ));
    }

    #[test]
    fn ratchet_widening_verdict_content_hash_deterministic() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v1 = eval.evaluate_ratchet_widening(1500);
        let v2 = eval.evaluate_ratchet_widening(1500);
        assert_eq!(v1.content_hash(), v2.content_hash());
    }

    #[test]
    fn ratchet_widening_verdict_display() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v = eval.evaluate_ratchet_widening(1500);
        let s = v.to_string();
        assert!(s.contains("ratchet_widening"));
    }

    #[test]
    fn ratchet_widening_verdict_serde_round_trip() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v = eval.evaluate_ratchet_widening(1500);
        let json = serde_json::to_string(&v).unwrap();
        let back: RatchetWideningVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    // -----------------------------------------------------------------------
    // Full pipeline (evaluate) tests
    // -----------------------------------------------------------------------

    #[test]
    fn full_pipeline_saturated() {
        let config = SaturationConfig {
            min_observations: 3,
            min_burndown_velocity_millionths: 10_000,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let receipt = eval.evaluate(1500);
        assert_eq!(receipt.composite_state, BoardState::Saturated);
        assert_eq!(receipt.schema_version, DARK_MATTER_GATE_SCHEMA_VERSION);
        assert_eq!(receipt.component, COMPONENT);
    }

    #[test]
    fn full_pipeline_scope_limited() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 500_000, 5_000, 15_000);
        let eval = make_test_evaluator(500_000, MILLION, obs, config);
        let receipt = eval.evaluate(1500);
        assert_eq!(receipt.composite_state, BoardState::ScopeLimited);
    }

    #[test]
    fn full_pipeline_stale_overrides_saturated() {
        let config = SaturationConfig {
            min_observations: 3,
            max_staleness_hours: 1,
            min_burndown_velocity_millionths: 10_000,
            ..SaturationConfig::default()
        };
        // Would be saturated if fresh
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        // But it's stale (now is far in the future)
        let receipt = eval.evaluate(1_000_000);
        assert_eq!(receipt.composite_state, BoardState::Stale);
    }

    #[test]
    fn full_pipeline_receipt_hash_deterministic() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let r1 = eval.evaluate(1500);
        let r2 = eval.evaluate(1500);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn full_pipeline_receipt_hash_differs_on_time() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let r1 = eval.evaluate(1500);
        let r2 = eval.evaluate(1501);
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn full_pipeline_receipt_display() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let receipt = eval.evaluate(1500);
        let s = receipt.to_string();
        assert!(s.contains("receipt"));
    }

    #[test]
    fn full_pipeline_receipt_serde_round_trip() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let receipt = eval.evaluate(1500);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.composite_state, receipt.composite_state);
        assert_eq!(back.receipt_hash, receipt.receipt_hash);
    }

    // -----------------------------------------------------------------------
    // Evidence emission tests
    // -----------------------------------------------------------------------

    #[test]
    fn evidence_emitted_correctly() {
        let config = SaturationConfig {
            min_observations: 3,
            min_burndown_velocity_millionths: 10_000,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let evidence = eval.emit_evidence(1500);
        assert_eq!(evidence.schema_version, DARK_MATTER_GATE_SCHEMA_VERSION);
        assert_eq!(evidence.bead_id, DARK_MATTER_GATE_BEAD_ID);
        assert_eq!(evidence.component, COMPONENT);
        assert_eq!(evidence.board_state, BoardState::Saturated);
    }

    #[test]
    fn evidence_estimate_summary() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let evidence = eval.emit_evidence(1500);
        assert_eq!(evidence.estimate_summary.total_surface_millionths, MILLION);
        assert_eq!(evidence.estimate_summary.active_mass_millionths, 100_000);
        assert_eq!(evidence.estimate_summary.active_region_count, 1);
    }

    #[test]
    fn evidence_burndown_metrics() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let evidence = eval.emit_evidence(1500);
        assert_eq!(evidence.burndown_metrics.observation_count, 5);
        assert!(evidence.burndown_metrics.time_span_secs > 0);
    }

    #[test]
    fn evidence_content_hash_deterministic() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let e1 = eval.emit_evidence(1500);
        let e2 = eval.emit_evidence(1500);
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn evidence_display() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let evidence = eval.emit_evidence(1500);
        let s = evidence.to_string();
        assert!(s.contains("dark_matter_evidence"));
    }

    #[test]
    fn evidence_serde_round_trip() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let evidence = eval.emit_evidence(1500);
        let json = serde_json::to_string(&evidence).unwrap();
        let back: DarkMatterEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back.board_state, evidence.board_state);
    }

    #[test]
    fn evidence_stale_board_state() {
        let config = SaturationConfig {
            min_observations: 3,
            max_staleness_hours: 1,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let evidence = eval.emit_evidence(1_000_000);
        assert_eq!(evidence.board_state, BoardState::Stale);
    }

    // -----------------------------------------------------------------------
    // Edge case and regression tests
    // -----------------------------------------------------------------------

    #[test]
    fn zero_active_mass_is_saturated() {
        let config = SaturationConfig {
            min_observations: 3,
            min_burndown_velocity_millionths: 0, // no velocity requirement
            ..SaturationConfig::default()
        };
        // All retired, 0 active
        let obs = make_test_observations(5, 1000, 100, 0, 0, 0);
        let eval = make_test_evaluator(0, MILLION, obs, config);
        let verdict = eval.evaluate_saturation(1500);
        assert_eq!(verdict.state, BoardState::Saturated);
        assert_eq!(verdict.dark_matter_fraction_millionths, 0);
    }

    #[test]
    fn saturation_verdict_content_hash() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v1 = eval.evaluate_saturation(1500);
        let v2 = eval.evaluate_saturation(1500);
        assert_eq!(v1.content_hash(), v2.content_hash());
    }

    #[test]
    fn saturation_verdict_display() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v = eval.evaluate_saturation(1500);
        let s = v.to_string();
        assert!(s.contains("saturation_verdict"));
    }

    #[test]
    fn saturation_verdict_serde_round_trip() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let v = eval.evaluate_saturation(1500);
        let json = serde_json::to_string(&v).unwrap();
        let back: BoardSaturationVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, v.state);
    }

    #[test]
    fn freshness_reason_display() {
        assert_eq!(FreshnessReason::WithinWindow.to_string(), "within_window");
        assert_eq!(
            FreshnessReason::NoObservations.to_string(),
            "no_observations"
        );
        let r = FreshnessReason::ExceedsWindow { hours_over: 24 };
        assert!(r.to_string().contains("24"));
    }

    #[test]
    fn ratchet_widening_reason_display() {
        assert_eq!(
            RatchetWideningReason::BelowCeiling.to_string(),
            "below_ceiling"
        );
        assert_eq!(RatchetWideningReason::BoardStale.to_string(), "board_stale");
        assert_eq!(
            RatchetWideningReason::InsufficientData.to_string(),
            "insufficient_data"
        );
        let r = RatchetWideningReason::AboveCeiling {
            excess_millionths: 50_000,
        };
        assert!(r.to_string().contains("50000"));
    }

    #[test]
    fn evaluator_with_multiple_regions() {
        let epoch = SecurityEpoch::from_raw(1);
        let mut estimate = DarkMatterEstimate::new(MILLION, epoch, 1000);
        estimate.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            50_000,
            false,
        ));
        estimate.add_region(make_test_region(
            "r2",
            DarkMatterRegionKind::UnverifiedInterleaving,
            30_000,
            false,
        ));
        estimate.add_region(make_test_region(
            "r3",
            DarkMatterRegionKind::UntestedErrorRecovery,
            20_000,
            true,
        ));
        let config = SaturationConfig {
            min_observations: 3,
            min_burndown_velocity_millionths: 10_000,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 80_000, 5_000, 15_000);
        let mut tracker = BurndownTracker::new(MILLION, epoch);
        for o in obs {
            tracker.record(o);
        }
        let eval = SaturationGateEvaluator::new(config, estimate, tracker);
        let receipt = eval.evaluate(1500);
        // 80_000 / 1_000_000 = 8% < 20% threshold
        assert_eq!(receipt.composite_state, BoardState::Saturated);
    }

    #[test]
    fn evaluator_serde_round_trip() {
        let config = SaturationConfig {
            min_observations: 3,
            ..SaturationConfig::default()
        };
        let obs = make_test_observations(5, 1000, 100, 100_000, 5_000, 15_000);
        let eval = make_test_evaluator(100_000, MILLION, obs, config);
        let json = serde_json::to_string(&eval).unwrap();
        let back: SaturationGateEvaluator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.config, eval.config);
        assert_eq!(back.estimate, eval.estimate);
        assert_eq!(back.tracker, eval.tracker);
    }

    #[test]
    fn config_violation_serde_round_trip() {
        let v = ConfigViolation {
            field: "test_field".to_string(),
            message: "test message".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: ConfigViolation = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn region_effective_mass_zero_weight() {
        let mut r = make_test_region("r1", DarkMatterRegionKind::UntestedCodePath, 200_000, false);
        r.priority_weight_millionths = 0;
        assert_eq!(r.effective_mass(), 0);
    }

    #[test]
    fn region_effective_mass_saturating() {
        let mut r = make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            u64::MAX,
            false,
        );
        r.priority_weight_millionths = u64::MAX;
        // Should not overflow, just saturate
        let _ = r.effective_mass();
    }

    #[test]
    fn estimate_add_region_overwrites() {
        let mut e = DarkMatterEstimate::new(MILLION, SecurityEpoch::from_raw(1), 1000);
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            100_000,
            false,
        ));
        e.add_region(make_test_region(
            "r1",
            DarkMatterRegionKind::UntestedCodePath,
            200_000,
            false,
        ));
        assert_eq!(e.total_region_count(), 1);
        assert_eq!(e.active_mass(), 200_000);
    }

    #[test]
    fn tracker_has_enough_observations_boundary() {
        let mut t = BurndownTracker::new(MILLION, SecurityEpoch::from_raw(1));
        assert!(!t.has_enough_observations(1));
        t.record(BurndownObservation {
            timestamp_epoch_secs: 100,
            active_mass_millionths: 0,
            cumulative_discovered_millionths: 0,
            cumulative_retired_millionths: 0,
        });
        assert!(t.has_enough_observations(1));
        assert!(!t.has_enough_observations(2));
    }

    #[test]
    fn make_test_observations_produces_correct_count() {
        let obs = make_test_observations(7, 0, 10, 100_000, 1_000, 2_000);
        assert_eq!(obs.len(), 7);
    }

    #[test]
    fn make_test_observations_timestamps_ascending() {
        let obs = make_test_observations(5, 1000, 50, 100_000, 1_000, 2_000);
        for w in obs.windows(2) {
            assert!(w[1].timestamp_epoch_secs > w[0].timestamp_epoch_secs);
        }
    }

    #[test]
    fn schema_constants_populated() {
        // Verify schema constants have expected prefixes / content.
        assert!(
            DARK_MATTER_GATE_SCHEMA_VERSION.contains("dark-matter"),
            "schema version: {DARK_MATTER_GATE_SCHEMA_VERSION}"
        );
        assert!(
            DARK_MATTER_GATE_BEAD_ID.contains("bd-"),
            "bead id: {DARK_MATTER_GATE_BEAD_ID}"
        );
        assert!(COMPONENT.contains("dark_matter"), "component: {COMPONENT}");
    }

    #[test]
    fn default_thresholds_in_range() {
        // Verify the default config passes validation (which implies all
        // thresholds are within acceptable bounds).
        let config = SaturationConfig::default();
        let violations = config.validate();
        assert!(
            violations.is_empty(),
            "default config invalid: {violations:?}"
        );
        // Verify specific threshold relationships.
        assert_eq!(
            config.saturation_threshold_millionths,
            DEFAULT_SATURATION_THRESHOLD
        );
        assert_eq!(
            config.ratchet_widening_ceiling_millionths,
            DEFAULT_RATCHET_WIDENING_CEILING
        );
        assert_eq!(
            config.min_burndown_velocity_millionths,
            DEFAULT_MIN_BURNDOWN_VELOCITY
        );
        assert_eq!(config.min_observations, DEFAULT_MIN_OBSERVATIONS);
        assert_eq!(config.max_staleness_hours, DEFAULT_MAX_STALENESS_HOURS);
    }
}
