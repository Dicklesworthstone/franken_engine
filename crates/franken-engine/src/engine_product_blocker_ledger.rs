//! Engine-product blocker ledger and cohort readiness rollups.
//!
//! Aggregates readiness signals from compatibility, parity, and module
//! system work into a blocker ledger that shows exactly what still
//! prevents engine-level closure from becoming product-level closure
//! in `franken_node`.
//!
//! ## Design
//!
//! - **Blocker taxonomy**: classify each gap by surface (parser, runtime,
//!   module, React, stdlib, etc.) and severity (blocking, degraded,
//!   cosmetic).
//! - **Cohort rollups**: aggregate per-cohort readiness from npm
//!   compatibility, React parity, module resolution, and native addon
//!   matrices.
//! - **Evidence linkage**: every blocker carries its source bead, parity
//!   evidence hash, and remediation owner.
//! - **Gate verdict**: structured pass/fail with residual-blocker catalog
//!   and handoff bundle readiness.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.5, bd-1lsy.5.10.2 (RGC-408B).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "engine_product_blocker_ledger";
pub const SCHEMA_VERSION: &str = "franken-engine.engine-product-blocker-ledger.v1";
pub const BEAD_ID: &str = "bd-1lsy.5.10.2";
pub const MAX_BLOCKERS: usize = 5000;
pub const MAX_COHORTS: usize = 100;

// ---------------------------------------------------------------------------
// Blocker surface
// ---------------------------------------------------------------------------

/// Engine surface where a blocker lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSurface {
    Parser,
    IrLowering,
    Runtime,
    ModuleSystem,
    Stdlib,
    ReactLane,
    TypeScriptLane,
    NativeAddon,
    Hostcall,
    Scheduler,
    Gc,
    SecurityPolicy,
    Replay,
    Cli,
    Observability,
}

impl BlockerSurface {
    pub const ALL: &'static [Self] = &[
        Self::Parser,
        Self::IrLowering,
        Self::Runtime,
        Self::ModuleSystem,
        Self::Stdlib,
        Self::ReactLane,
        Self::TypeScriptLane,
        Self::NativeAddon,
        Self::Hostcall,
        Self::Scheduler,
        Self::Gc,
        Self::SecurityPolicy,
        Self::Replay,
        Self::Cli,
        Self::Observability,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parser => "parser",
            Self::IrLowering => "ir_lowering",
            Self::Runtime => "runtime",
            Self::ModuleSystem => "module_system",
            Self::Stdlib => "stdlib",
            Self::ReactLane => "react_lane",
            Self::TypeScriptLane => "typescript_lane",
            Self::NativeAddon => "native_addon",
            Self::Hostcall => "hostcall",
            Self::Scheduler => "scheduler",
            Self::Gc => "gc",
            Self::SecurityPolicy => "security_policy",
            Self::Replay => "replay",
            Self::Cli => "cli",
            Self::Observability => "observability",
        }
    }
}

impl fmt::Display for BlockerSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Blocker severity
// ---------------------------------------------------------------------------

/// Severity of a blocker for product readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockerSeverity {
    /// Blocks product release entirely.
    Blocking,
    /// Causes degraded behavior but product can ship with advisory.
    Degraded,
    /// Cosmetic or non-user-visible issue.
    Cosmetic,
    /// Informational — tracked for completeness, not a real blocker.
    Informational,
}

impl BlockerSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::Degraded => "degraded",
            Self::Cosmetic => "cosmetic",
            Self::Informational => "informational",
        }
    }

    /// Weight for aggregate scoring (millionths).
    pub const fn weight_millionths(self) -> u64 {
        match self {
            Self::Blocking => 1_000_000,
            Self::Degraded => 300_000,
            Self::Cosmetic => 50_000,
            Self::Informational => 0,
        }
    }

    /// Whether this severity prevents product release.
    pub const fn is_release_blocking(self) -> bool {
        matches!(self, Self::Blocking)
    }
}

impl fmt::Display for BlockerSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Remediation status
// ---------------------------------------------------------------------------

/// Current remediation status of a blocker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    /// Blocker identified but no owner assigned.
    Unowned,
    /// Owner assigned and investigating.
    Investigating,
    /// Fix in progress.
    InProgress,
    /// Fix landed but not verified.
    FixLanded,
    /// Fix verified and closed.
    Verified,
    /// Will not fix — accepted risk with advisory.
    WontFix,
}

impl RemediationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unowned => "unowned",
            Self::Investigating => "investigating",
            Self::InProgress => "in_progress",
            Self::FixLanded => "fix_landed",
            Self::Verified => "verified",
            Self::WontFix => "wont_fix",
        }
    }

    /// Whether this status means the blocker is resolved.
    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::Verified | Self::WontFix)
    }
}

impl fmt::Display for RemediationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Blocker entry
// ---------------------------------------------------------------------------

/// A single blocker in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockerEntry {
    /// Unique blocker ID.
    pub id: String,
    /// Short description of the gap.
    pub title: String,
    /// Engine surface where the blocker lives.
    pub surface: BlockerSurface,
    /// Severity.
    pub severity: BlockerSeverity,
    /// Current remediation status.
    pub remediation: RemediationStatus,
    /// Tracking bead ID.
    pub tracking_bead: Option<String>,
    /// Evidence hash linking to parity/compatibility artifacts.
    pub evidence_hash: Option<ContentHash>,
    /// Remediation owner (agent or person).
    pub owner: Option<String>,
    /// User-visible impact description.
    pub user_impact: String,
    /// Tags for filtering.
    pub tags: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// Cohort readiness
// ---------------------------------------------------------------------------

/// Readiness status for a package or workload cohort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortReadiness {
    /// All gates pass — cohort is ready for product inclusion.
    Ready,
    /// Most gates pass but with known advisories.
    ReadyWithAdvisories,
    /// Some gates fail — cohort is partially blocked.
    PartiallyBlocked,
    /// Critical gates fail — cohort is fully blocked.
    Blocked,
    /// Not yet evaluated.
    NotEvaluated,
}

impl CohortReadiness {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ReadyWithAdvisories => "ready_with_advisories",
            Self::PartiallyBlocked => "partially_blocked",
            Self::Blocked => "blocked",
            Self::NotEvaluated => "not_evaluated",
        }
    }

    pub const fn permits_release(self) -> bool {
        matches!(self, Self::Ready | Self::ReadyWithAdvisories)
    }
}

impl fmt::Display for CohortReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Rollup for a single cohort.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CohortRollup {
    /// Cohort name (e.g., "tier_1_critical", "react_ecosystem").
    pub cohort_name: String,
    /// Overall readiness.
    pub readiness: CohortReadiness,
    /// Number of blockers in this cohort.
    pub blocker_count: usize,
    /// Number of blocking-severity entries.
    pub blocking_count: usize,
    /// Number of degraded-severity entries.
    pub degraded_count: usize,
    /// Resolved blocker count.
    pub resolved_count: usize,
    /// Readiness rate (millionths): resolved / total.
    pub readiness_rate_millionths: u64,
    /// Blocker IDs in this cohort.
    pub blocker_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Blocker ledger
// ---------------------------------------------------------------------------

/// The engine-product blocker ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockerLedger {
    pub version: String,
    pub blockers: Vec<BlockerEntry>,
    pub cohort_rollups: Vec<CohortRollup>,
}

impl BlockerLedger {
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            blockers: Vec::new(),
            cohort_rollups: Vec::new(),
        }
    }

    pub fn add_blocker(&mut self, entry: BlockerEntry) -> Result<(), LedgerError> {
        if self.blockers.len() >= MAX_BLOCKERS {
            return Err(LedgerError::LedgerOverflow {
                max: MAX_BLOCKERS,
                attempted: self.blockers.len() + 1,
            });
        }
        if self.blockers.iter().any(|b| b.id == entry.id) {
            return Err(LedgerError::DuplicateBlocker {
                id: entry.id.clone(),
            });
        }
        self.blockers.push(entry);
        Ok(())
    }

    pub fn add_cohort_rollup(&mut self, rollup: CohortRollup) -> Result<(), LedgerError> {
        if self.cohort_rollups.len() >= MAX_COHORTS {
            return Err(LedgerError::CohortOverflow {
                max: MAX_COHORTS,
                attempted: self.cohort_rollups.len() + 1,
            });
        }
        self.cohort_rollups.push(rollup);
        Ok(())
    }

    pub fn blocker_count(&self) -> usize {
        self.blockers.len()
    }

    pub fn release_blockers(&self) -> Vec<&BlockerEntry> {
        self.blockers
            .iter()
            .filter(|b| b.severity.is_release_blocking() && !b.remediation.is_resolved())
            .collect()
    }

    pub fn unresolved_blockers(&self) -> Vec<&BlockerEntry> {
        self.blockers
            .iter()
            .filter(|b| !b.remediation.is_resolved())
            .collect()
    }

    pub fn blockers_by_surface(&self) -> BTreeMap<BlockerSurface, usize> {
        let mut counts = BTreeMap::new();
        for b in &self.blockers {
            *counts.entry(b.surface).or_insert(0) += 1;
        }
        counts
    }

    pub fn blockers_by_severity(&self) -> BTreeMap<BlockerSeverity, usize> {
        let mut counts = BTreeMap::new();
        for b in &self.blockers {
            *counts.entry(b.severity).or_insert(0) += 1;
        }
        counts
    }

    pub fn content_hash(&self) -> ContentHash {
        let mut blockers: Vec<_> = self.blockers.iter().collect();
        blockers.sort_by(|left, right| left.id.cmp(&right.id));
        let blockers = blockers
            .into_iter()
            .map(|blocker| {
                let tags = blocker
                    .tags
                    .iter()
                    .map(|tag| CanonicalValue::String(tag.clone()))
                    .collect();
                CanonicalValue::Map(BTreeMap::from([
                    ("id".to_string(), CanonicalValue::String(blocker.id.clone())),
                    (
                        "title".to_string(),
                        CanonicalValue::String(blocker.title.clone()),
                    ),
                    (
                        "surface".to_string(),
                        CanonicalValue::String(blocker.surface.as_str().to_string()),
                    ),
                    (
                        "severity".to_string(),
                        CanonicalValue::String(blocker.severity.as_str().to_string()),
                    ),
                    (
                        "remediation".to_string(),
                        CanonicalValue::String(blocker.remediation.as_str().to_string()),
                    ),
                    (
                        "tracking_bead".to_string(),
                        blocker
                            .tracking_bead
                            .as_ref()
                            .map_or(CanonicalValue::Null, |bead| {
                                CanonicalValue::String(bead.clone())
                            }),
                    ),
                    (
                        "evidence_hash".to_string(),
                        blocker
                            .evidence_hash
                            .as_ref()
                            .map_or(CanonicalValue::Null, |hash| {
                                CanonicalValue::Bytes(hash.as_bytes().to_vec())
                            }),
                    ),
                    (
                        "owner".to_string(),
                        blocker
                            .owner
                            .as_ref()
                            .map_or(CanonicalValue::Null, |owner| {
                                CanonicalValue::String(owner.clone())
                            }),
                    ),
                    (
                        "user_impact".to_string(),
                        CanonicalValue::String(blocker.user_impact.clone()),
                    ),
                    ("tags".to_string(), CanonicalValue::Array(tags)),
                ]))
            })
            .collect();
        let mut cohort_rollups: Vec<_> = self.cohort_rollups.iter().collect();
        cohort_rollups.sort_by(|left, right| left.cohort_name.cmp(&right.cohort_name));
        let cohort_rollups = cohort_rollups
            .into_iter()
            .map(|rollup| {
                let mut blocker_ids: Vec<_> = rollup.blocker_ids.to_vec();
                blocker_ids.sort();
                let blocker_ids = blocker_ids
                    .into_iter()
                    .map(|id| CanonicalValue::String(id.clone()))
                    .collect();
                CanonicalValue::Map(BTreeMap::from([
                    (
                        "cohort_name".to_string(),
                        CanonicalValue::String(rollup.cohort_name.clone()),
                    ),
                    (
                        "readiness".to_string(),
                        CanonicalValue::String(rollup.readiness.as_str().to_string()),
                    ),
                    (
                        "blocker_count".to_string(),
                        CanonicalValue::U64(rollup.blocker_count as u64),
                    ),
                    (
                        "blocking_count".to_string(),
                        CanonicalValue::U64(rollup.blocking_count as u64),
                    ),
                    (
                        "degraded_count".to_string(),
                        CanonicalValue::U64(rollup.degraded_count as u64),
                    ),
                    (
                        "resolved_count".to_string(),
                        CanonicalValue::U64(rollup.resolved_count as u64),
                    ),
                    (
                        "readiness_rate_millionths".to_string(),
                        CanonicalValue::U64(rollup.readiness_rate_millionths),
                    ),
                    (
                        "blocker_ids".to_string(),
                        CanonicalValue::Array(blocker_ids),
                    ),
                ]))
            })
            .collect();
        let canonical = CanonicalValue::Map(BTreeMap::from([
            (
                "version".to_string(),
                CanonicalValue::String(self.version.clone()),
            ),
            ("blockers".to_string(), CanonicalValue::Array(blockers)),
            (
                "cohort_rollups".to_string(),
                CanonicalValue::Array(cohort_rollups),
            ),
        ]));
        let bytes = encode_value(&canonical);
        ContentHash::compute(&bytes)
    }
}

impl Default for BlockerLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Gate configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Whether any release-blocking entries cause a hard fail.
    pub fail_on_release_blockers: bool,
    /// Maximum unresolved degraded entries.
    pub max_unresolved_degraded: usize,
    /// Minimum cohort readiness rate (millionths).
    pub min_cohort_readiness_rate: u64,
    /// Required cohorts that must be Ready or ReadyWithAdvisories.
    pub required_ready_cohorts: BTreeSet<String>,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            fail_on_release_blockers: true,
            max_unresolved_degraded: 10,
            min_cohort_readiness_rate: 800_000,
            required_ready_cohorts: BTreeSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Gate verdict
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    EmptyLedger,
    ReleaseBlockersPresent {
        count: usize,
        ids: Vec<String>,
    },
    ExcessiveDegraded {
        count: usize,
        max: usize,
    },
    CohortNotReady {
        cohort: String,
        readiness: CohortReadiness,
    },
    LowCohortReadinessRate {
        rate_millionths: u64,
        threshold: u64,
    },
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLedger => write!(f, "ledger is empty"),
            Self::ReleaseBlockersPresent { count, .. } => {
                write!(f, "{count} release blockers present")
            }
            Self::ExcessiveDegraded { count, max } => {
                write!(f, "{count} unresolved degraded > max {max}")
            }
            Self::CohortNotReady { cohort, readiness } => {
                write!(f, "cohort {cohort} not ready: {readiness}")
            }
            Self::LowCohortReadinessRate {
                rate_millionths,
                threshold,
            } => {
                write!(f, "cohort readiness {rate_millionths}/1M < {threshold}/1M")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    Pass,
    Fail { reasons: Vec<RejectionReason> },
}

impl GateVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reasons } => write!(f, "FAIL ({} reasons)", reasons.len()),
        }
    }
}

// ---------------------------------------------------------------------------
// Gate report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    pub schema_version: String,
    pub bead_id: String,
    pub component: String,
    pub verdict: GateVerdict,
    pub ledger_hash: ContentHash,
    pub total_blockers: usize,
    pub release_blocker_count: usize,
    pub unresolved_count: usize,
    pub resolved_count: usize,
    pub surface_distribution: BTreeMap<BlockerSurface, usize>,
    pub severity_distribution: BTreeMap<BlockerSeverity, usize>,
    pub cohort_count: usize,
    pub ready_cohort_count: usize,
}

// ---------------------------------------------------------------------------
// Gate evaluator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BlockerLedgerGate {
    config: GateConfig,
}

impl BlockerLedgerGate {
    pub fn new(config: GateConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(GateConfig::default())
    }

    pub fn evaluate(&self, ledger: &BlockerLedger) -> GateReport {
        let mut reasons = Vec::new();

        if ledger.blockers.is_empty() && ledger.cohort_rollups.is_empty() {
            return GateReport {
                schema_version: SCHEMA_VERSION.to_string(),
                bead_id: BEAD_ID.to_string(),
                component: COMPONENT.to_string(),
                verdict: GateVerdict::Fail {
                    reasons: vec![RejectionReason::EmptyLedger],
                },
                ledger_hash: ledger.content_hash(),
                total_blockers: 0,
                release_blocker_count: 0,
                unresolved_count: 0,
                resolved_count: 0,
                surface_distribution: BTreeMap::new(),
                severity_distribution: BTreeMap::new(),
                cohort_count: 0,
                ready_cohort_count: 0,
            };
        }

        // Release blockers check
        let release_blockers = ledger.release_blockers();
        if self.config.fail_on_release_blockers && !release_blockers.is_empty() {
            reasons.push(RejectionReason::ReleaseBlockersPresent {
                count: release_blockers.len(),
                ids: release_blockers.iter().map(|b| b.id.clone()).collect(),
            });
        }

        // Degraded entries check
        let unresolved_degraded = ledger
            .blockers
            .iter()
            .filter(|b| b.severity == BlockerSeverity::Degraded && !b.remediation.is_resolved())
            .count();
        if unresolved_degraded > self.config.max_unresolved_degraded {
            reasons.push(RejectionReason::ExcessiveDegraded {
                count: unresolved_degraded,
                max: self.config.max_unresolved_degraded,
            });
        }

        // Cohort readiness checks
        for cohort_name in &self.config.required_ready_cohorts {
            if let Some(rollup) = ledger
                .cohort_rollups
                .iter()
                .find(|r| &r.cohort_name == cohort_name)
                && !rollup.readiness.permits_release()
            {
                reasons.push(RejectionReason::CohortNotReady {
                    cohort: cohort_name.clone(),
                    readiness: rollup.readiness,
                });
            }
        }

        // Aggregate cohort readiness rate
        if !ledger.cohort_rollups.is_empty() {
            let ready_count = ledger
                .cohort_rollups
                .iter()
                .filter(|r| r.readiness.permits_release())
                .count();
            let rate = (ready_count as u64)
                .saturating_mul(1_000_000)
                .checked_div(ledger.cohort_rollups.len() as u64)
                .unwrap_or(0);
            if rate < self.config.min_cohort_readiness_rate {
                reasons.push(RejectionReason::LowCohortReadinessRate {
                    rate_millionths: rate,
                    threshold: self.config.min_cohort_readiness_rate,
                });
            }
        }

        let unresolved = ledger.unresolved_blockers().len();
        let resolved = ledger.blocker_count() - unresolved;
        let ready_cohorts = ledger
            .cohort_rollups
            .iter()
            .filter(|r| r.readiness.permits_release())
            .count();

        let verdict = if reasons.is_empty() {
            GateVerdict::Pass
        } else {
            GateVerdict::Fail { reasons }
        };

        GateReport {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            component: COMPONENT.to_string(),
            verdict,
            ledger_hash: ledger.content_hash(),
            total_blockers: ledger.blocker_count(),
            release_blocker_count: ledger.release_blockers().len(),
            unresolved_count: unresolved,
            resolved_count: resolved,
            surface_distribution: ledger.blockers_by_surface(),
            severity_distribution: ledger.blockers_by_severity(),
            cohort_count: ledger.cohort_rollups.len(),
            ready_cohort_count: ready_cohorts,
        }
    }
}

// ---------------------------------------------------------------------------
// Seed ledger builder
// ---------------------------------------------------------------------------

pub fn build_seed_ledger() -> BlockerLedger {
    let mut ledger = BlockerLedger::new();

    // Sample blockers across surfaces
    let entries = [
        (
            "blk_cjs_interop",
            "CJS require() not yet wired to runtime dispatch",
            BlockerSurface::ModuleSystem,
            BlockerSeverity::Blocking,
            RemediationStatus::InProgress,
            Some("bd-1lsy.5.2"),
        ),
        (
            "blk_react_ssr",
            "SSR client-entry module graph not verified",
            BlockerSurface::ReactLane,
            BlockerSeverity::Blocking,
            RemediationStatus::Investigating,
            Some("bd-1lsy.5.7.2"),
        ),
        (
            "blk_native_addon",
            "N-API membrane not yet implemented",
            BlockerSurface::NativeAddon,
            BlockerSeverity::Degraded,
            RemediationStatus::InProgress,
            Some("bd-1lsy.5.9.2"),
        ),
        (
            "blk_regex_unicode",
            "RegExp Unicode property escapes incomplete",
            BlockerSurface::Runtime,
            BlockerSeverity::Degraded,
            RemediationStatus::Investigating,
            Some("bd-1lsy.4.12.2"),
        ),
        (
            "blk_cli_help",
            "CLI help surface minor syntax drift from README",
            BlockerSurface::Cli,
            BlockerSeverity::Cosmetic,
            RemediationStatus::Verified,
            None,
        ),
        (
            "blk_obs_mode",
            "Observability mode labels not in operator docs",
            BlockerSurface::Observability,
            BlockerSeverity::Informational,
            RemediationStatus::Unowned,
            None,
        ),
    ];

    for (id, title, surface, severity, remediation, bead) in &entries {
        let _ = ledger.add_blocker(BlockerEntry {
            id: id.to_string(),
            title: title.to_string(),
            surface: *surface,
            severity: *severity,
            remediation: *remediation,
            tracking_bead: bead.map(|s| s.to_string()),
            evidence_hash: Some(ContentHash::compute(id.as_bytes())),
            owner: None,
            user_impact: format!("Users affected by: {title}"),
            tags: BTreeSet::new(),
        });
    }

    // Sample cohort rollups
    let _ = ledger.add_cohort_rollup(CohortRollup {
        cohort_name: "tier_1_critical".to_string(),
        readiness: CohortReadiness::PartiallyBlocked,
        blocker_count: 2,
        blocking_count: 1,
        degraded_count: 1,
        resolved_count: 0,
        readiness_rate_millionths: 0,
        blocker_ids: vec![
            "blk_cjs_interop".to_string(),
            "blk_native_addon".to_string(),
        ],
    });
    let _ = ledger.add_cohort_rollup(CohortRollup {
        cohort_name: "react_ecosystem".to_string(),
        readiness: CohortReadiness::Blocked,
        blocker_count: 1,
        blocking_count: 1,
        degraded_count: 0,
        resolved_count: 0,
        readiness_rate_millionths: 0,
        blocker_ids: vec!["blk_react_ssr".to_string()],
    });
    let _ = ledger.add_cohort_rollup(CohortRollup {
        cohort_name: "cli_surface".to_string(),
        readiness: CohortReadiness::Ready,
        blocker_count: 1,
        blocking_count: 0,
        degraded_count: 0,
        resolved_count: 1,
        readiness_rate_millionths: 1_000_000,
        blocker_ids: vec!["blk_cli_help".to_string()],
    });

    ledger
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerError {
    LedgerOverflow { max: usize, attempted: usize },
    DuplicateBlocker { id: String },
    CohortOverflow { max: usize, attempted: usize },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LedgerOverflow { max, attempted } => {
                write!(f, "ledger overflow: {attempted} > {max}")
            }
            Self::DuplicateBlocker { id } => write!(f, "duplicate blocker: {id}"),
            Self::CohortOverflow { max, attempted } => {
                write!(f, "cohort overflow: {attempted} > {max}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_blocker(id: &str, surface: BlockerSurface, severity: BlockerSeverity) -> BlockerEntry {
        BlockerEntry {
            id: id.to_string(),
            title: format!("Test blocker {id}"),
            surface,
            severity,
            remediation: RemediationStatus::Unowned,
            tracking_bead: None,
            evidence_hash: Some(ContentHash::compute(id.as_bytes())),
            owner: None,
            user_impact: "test impact".to_string(),
            tags: BTreeSet::new(),
        }
    }

    // --- BlockerSurface ---
    #[test]
    fn surface_all_count() {
        assert_eq!(BlockerSurface::ALL.len(), 15);
    }

    #[test]
    fn surface_serde_roundtrip() {
        for s in BlockerSurface::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: BlockerSurface = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- BlockerSeverity ---
    #[test]
    fn severity_release_blocking() {
        assert!(BlockerSeverity::Blocking.is_release_blocking());
        assert!(!BlockerSeverity::Degraded.is_release_blocking());
        assert!(!BlockerSeverity::Cosmetic.is_release_blocking());
        assert!(!BlockerSeverity::Informational.is_release_blocking());
    }

    #[test]
    fn severity_weight_ordering() {
        assert!(
            BlockerSeverity::Degraded.weight_millionths()
                < BlockerSeverity::Blocking.weight_millionths()
        );
        assert!(
            BlockerSeverity::Cosmetic.weight_millionths()
                < BlockerSeverity::Degraded.weight_millionths()
        );
    }

    #[test]
    fn severity_serde_roundtrip() {
        let s = BlockerSeverity::Degraded;
        let json = serde_json::to_string(&s).unwrap();
        let back: BlockerSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // --- RemediationStatus ---
    #[test]
    fn remediation_resolved() {
        assert!(RemediationStatus::Verified.is_resolved());
        assert!(RemediationStatus::WontFix.is_resolved());
        assert!(!RemediationStatus::Unowned.is_resolved());
        assert!(!RemediationStatus::InProgress.is_resolved());
    }

    #[test]
    fn remediation_serde_roundtrip() {
        let r = RemediationStatus::FixLanded;
        let json = serde_json::to_string(&r).unwrap();
        let back: RemediationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- CohortReadiness ---
    #[test]
    fn readiness_permits_release() {
        assert!(CohortReadiness::Ready.permits_release());
        assert!(CohortReadiness::ReadyWithAdvisories.permits_release());
        assert!(!CohortReadiness::PartiallyBlocked.permits_release());
        assert!(!CohortReadiness::Blocked.permits_release());
        assert!(!CohortReadiness::NotEvaluated.permits_release());
    }

    // --- BlockerLedger ---
    #[test]
    fn empty_ledger() {
        let ledger = BlockerLedger::new();
        assert_eq!(ledger.blocker_count(), 0);
        assert!(ledger.release_blockers().is_empty());
    }

    #[test]
    fn add_blocker() {
        let mut ledger = BlockerLedger::new();
        ledger
            .add_blocker(make_blocker(
                "b1",
                BlockerSurface::Parser,
                BlockerSeverity::Blocking,
            ))
            .unwrap();
        assert_eq!(ledger.blocker_count(), 1);
    }

    #[test]
    fn duplicate_blocker_rejected() {
        let mut ledger = BlockerLedger::new();
        ledger
            .add_blocker(make_blocker(
                "b1",
                BlockerSurface::Parser,
                BlockerSeverity::Blocking,
            ))
            .unwrap();
        let err = ledger
            .add_blocker(make_blocker(
                "b1",
                BlockerSurface::Runtime,
                BlockerSeverity::Cosmetic,
            ))
            .unwrap_err();
        assert!(matches!(err, LedgerError::DuplicateBlocker { .. }));
    }

    #[test]
    fn release_blockers_filtered() {
        let mut ledger = BlockerLedger::new();
        ledger
            .add_blocker(make_blocker(
                "b1",
                BlockerSurface::Parser,
                BlockerSeverity::Blocking,
            ))
            .unwrap();
        ledger
            .add_blocker(make_blocker(
                "b2",
                BlockerSurface::Runtime,
                BlockerSeverity::Cosmetic,
            ))
            .unwrap();
        assert_eq!(ledger.release_blockers().len(), 1);
    }

    #[test]
    fn resolved_not_in_release_blockers() {
        let mut ledger = BlockerLedger::new();
        let mut b = make_blocker("b1", BlockerSurface::Parser, BlockerSeverity::Blocking);
        b.remediation = RemediationStatus::Verified;
        ledger.add_blocker(b).unwrap();
        assert!(ledger.release_blockers().is_empty());
    }

    #[test]
    fn blockers_by_surface() {
        let mut ledger = BlockerLedger::new();
        ledger
            .add_blocker(make_blocker(
                "b1",
                BlockerSurface::Parser,
                BlockerSeverity::Blocking,
            ))
            .unwrap();
        ledger
            .add_blocker(make_blocker(
                "b2",
                BlockerSurface::Parser,
                BlockerSeverity::Degraded,
            ))
            .unwrap();
        ledger
            .add_blocker(make_blocker(
                "b3",
                BlockerSurface::Runtime,
                BlockerSeverity::Cosmetic,
            ))
            .unwrap();
        let dist = ledger.blockers_by_surface();
        assert_eq!(*dist.get(&BlockerSurface::Parser).unwrap(), 2);
        assert_eq!(*dist.get(&BlockerSurface::Runtime).unwrap(), 1);
    }

    #[test]
    fn content_hash_deterministic() {
        let l1 = build_seed_ledger();
        let l2 = build_seed_ledger();
        assert_eq!(l1.content_hash(), l2.content_hash());
    }

    #[test]
    fn content_hash_changes() {
        let l1 = build_seed_ledger();
        let mut l2 = build_seed_ledger();
        l2.add_blocker(make_blocker(
            "extra",
            BlockerSurface::Gc,
            BlockerSeverity::Cosmetic,
        ))
        .unwrap();
        assert_ne!(l1.content_hash(), l2.content_hash());
    }

    #[test]
    fn content_hash_changes_when_blocker_payload_changes() {
        let l1 = build_seed_ledger();
        let mut l2 = build_seed_ledger();
        l2.blockers[0].title = "Different blocker title".to_string();
        assert_ne!(l1.content_hash(), l2.content_hash());
    }

    #[test]
    fn content_hash_changes_when_cohort_rollup_changes() {
        let l1 = build_seed_ledger();
        let mut l2 = build_seed_ledger();
        l2.cohort_rollups[0].readiness = CohortReadiness::ReadyWithAdvisories;
        assert_ne!(l1.content_hash(), l2.content_hash());
    }

    #[test]
    fn content_hash_is_invariant_to_blocker_and_cohort_order() {
        let l1 = build_seed_ledger();
        let mut l2 = build_seed_ledger();
        l2.blockers.reverse();
        l2.cohort_rollups.reverse();
        l2.cohort_rollups[0].blocker_ids.reverse();
        assert_eq!(l1.content_hash(), l2.content_hash());
    }

    #[test]
    fn ledger_serde_roundtrip() {
        let ledger = build_seed_ledger();
        let json = serde_json::to_string(&ledger).unwrap();
        let back: BlockerLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger.blocker_count(), back.blocker_count());
        assert_eq!(ledger.content_hash(), back.content_hash());
    }

    #[test]
    fn default_ledger_empty() {
        let ledger = BlockerLedger::default();
        assert_eq!(ledger.blocker_count(), 0);
    }

    // --- Seed ledger ---
    #[test]
    fn seed_ledger_has_entries() {
        let ledger = build_seed_ledger();
        assert_eq!(ledger.blocker_count(), 6);
        assert_eq!(ledger.cohort_rollups.len(), 3);
    }

    #[test]
    fn seed_ledger_has_release_blockers() {
        let ledger = build_seed_ledger();
        assert_eq!(ledger.release_blockers().len(), 2);
    }

    // --- Gate ---
    #[test]
    fn empty_ledger_fails() {
        let gate = BlockerLedgerGate::with_defaults();
        let ledger = BlockerLedger::new();
        let report = gate.evaluate(&ledger);
        assert!(!report.verdict.is_pass());
    }

    #[test]
    fn seed_ledger_fails_due_to_blockers() {
        let gate = BlockerLedgerGate::with_defaults();
        let ledger = build_seed_ledger();
        let report = gate.evaluate(&ledger);
        assert!(!report.verdict.is_pass()); // has release blockers
        assert!(report.release_blocker_count > 0);
    }

    #[test]
    fn all_resolved_passes() {
        let mut ledger = BlockerLedger::new();
        let mut b = make_blocker("b1", BlockerSurface::Parser, BlockerSeverity::Blocking);
        b.remediation = RemediationStatus::Verified;
        ledger.add_blocker(b).unwrap();
        let _ = ledger.add_cohort_rollup(CohortRollup {
            cohort_name: "test".to_string(),
            readiness: CohortReadiness::Ready,
            blocker_count: 0,
            blocking_count: 0,
            degraded_count: 0,
            resolved_count: 1,
            readiness_rate_millionths: 1_000_000,
            blocker_ids: Vec::new(),
        });
        let gate = BlockerLedgerGate::with_defaults();
        let report = gate.evaluate(&ledger);
        assert!(report.verdict.is_pass());
    }

    #[test]
    fn report_serde_roundtrip() {
        let gate = BlockerLedgerGate::with_defaults();
        let ledger = build_seed_ledger();
        let report = gate.evaluate(&ledger);
        let json = serde_json::to_string(&report).unwrap();
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.total_blockers, back.total_blockers);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Pass), "PASS");
    }

    #[test]
    fn error_display() {
        let e = LedgerError::DuplicateBlocker {
            id: "foo".to_string(),
        };
        assert!(format!("{e}").contains("foo"));
    }

    #[test]
    fn constants() {
        assert_eq!(COMPONENT, "engine_product_blocker_ledger");
        assert_eq!(BEAD_ID, "bd-1lsy.5.10.2");
    }
}
