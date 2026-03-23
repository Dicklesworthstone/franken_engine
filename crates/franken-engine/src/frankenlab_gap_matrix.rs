#![forbid(unsafe_code)]
//! Local-vs-upstream frankenlab surface gap matrix and migration decision.
//!
//! Bead: bd-3nr.1.1.2 \[10.13X.A2\]
//!
//! Builds the authoritative gap matrix between local deterministic
//! lab/release-gate surfaces and upstream frankenlab/LabRuntime/oracle
//! capabilities. Each cell classifies coverage and prescribes a migration
//! decision: direct upstream adoption, thin bridge, maintained wrapper,
//! no migration, or deferred.
//!
//! Plan references: Section 10.13X item A2.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the gap matrix format.
pub const GAP_MATRIX_SCHEMA_VERSION: &str = "franken-engine.frankenlab-gap-matrix.v1";

/// Bead identifier for this module.
pub const GAP_MATRIX_BEAD_ID: &str = "bd-3nr.1.1.2";

// ---------------------------------------------------------------------------
// LabSurfaceKind — local deterministic lab/release-gate surfaces
// ---------------------------------------------------------------------------

/// Enumerates the local deterministic lab and release-gate surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabSurfaceKind {
    /// Deterministic replay harness.
    DeterministicReplay,
    /// Scenario runner for lifecycle and fault paths.
    ScenarioRunner,
    /// Evidence chain integrity checker.
    EvidenceChecker,
    /// Cancellation injection at region granularity.
    CancellationInjector,
    /// Virtual time clock with tick-based advancement.
    VirtualTimeClock,
    /// Decision trace validator for audit trail.
    DecisionTraceValidator,
    /// Schedule replay with seed-based PRNG.
    ScheduleReplay,
    /// Extension/task lifecycle tester.
    LifecycleTester,
    /// Quarantine harness for isolated fault containment.
    QuarantineHarness,
    /// Fail-closed release gate runner.
    ReleaseGateRunner,
}

impl LabSurfaceKind {
    /// All variants in deterministic order.
    pub const ALL: [Self; 10] = [
        Self::DeterministicReplay,
        Self::ScenarioRunner,
        Self::EvidenceChecker,
        Self::CancellationInjector,
        Self::VirtualTimeClock,
        Self::DecisionTraceValidator,
        Self::ScheduleReplay,
        Self::LifecycleTester,
        Self::QuarantineHarness,
        Self::ReleaseGateRunner,
    ];
}

impl fmt::Display for LabSurfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeterministicReplay => write!(f, "deterministic_replay"),
            Self::ScenarioRunner => write!(f, "scenario_runner"),
            Self::EvidenceChecker => write!(f, "evidence_checker"),
            Self::CancellationInjector => write!(f, "cancellation_injector"),
            Self::VirtualTimeClock => write!(f, "virtual_time_clock"),
            Self::DecisionTraceValidator => write!(f, "decision_trace_validator"),
            Self::ScheduleReplay => write!(f, "schedule_replay"),
            Self::LifecycleTester => write!(f, "lifecycle_tester"),
            Self::QuarantineHarness => write!(f, "quarantine_harness"),
            Self::ReleaseGateRunner => write!(f, "release_gate_runner"),
        }
    }
}

// ---------------------------------------------------------------------------
// UpstreamCapability — upstream frankenlab capabilities
// ---------------------------------------------------------------------------

/// Enumerates upstream frankenlab/LabRuntime/oracle capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamCapability {
    /// Core lab runtime execution environment.
    LabRuntime,
    /// Oracle-based dispatch and verification.
    OracleDispatch,
    /// Scenario orchestration framework.
    ScenarioOrchestration,
    /// Evidence replay and validation.
    EvidenceReplay,
    /// Cancellation injection infrastructure.
    CancelInjection,
    /// Virtual time control and manipulation.
    VirtualTimeControl,
    /// Trace validation and audit.
    TraceValidation,
    /// Lifecycle orchestration for extensions/tasks.
    LifecycleOrchestration,
    /// Quarantine orchestration for fault containment.
    QuarantineOrchestration,
    /// Release gating framework.
    ReleaseGating,
}

impl UpstreamCapability {
    /// All variants in deterministic order.
    pub const ALL: [Self; 10] = [
        Self::LabRuntime,
        Self::OracleDispatch,
        Self::ScenarioOrchestration,
        Self::EvidenceReplay,
        Self::CancelInjection,
        Self::VirtualTimeControl,
        Self::TraceValidation,
        Self::LifecycleOrchestration,
        Self::QuarantineOrchestration,
        Self::ReleaseGating,
    ];
}

impl fmt::Display for UpstreamCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabRuntime => write!(f, "lab_runtime"),
            Self::OracleDispatch => write!(f, "oracle_dispatch"),
            Self::ScenarioOrchestration => write!(f, "scenario_orchestration"),
            Self::EvidenceReplay => write!(f, "evidence_replay"),
            Self::CancelInjection => write!(f, "cancel_injection"),
            Self::VirtualTimeControl => write!(f, "virtual_time_control"),
            Self::TraceValidation => write!(f, "trace_validation"),
            Self::LifecycleOrchestration => write!(f, "lifecycle_orchestration"),
            Self::QuarantineOrchestration => write!(f, "quarantine_orchestration"),
            Self::ReleaseGating => write!(f, "release_gating"),
        }
    }
}

// ---------------------------------------------------------------------------
// GapStatus — coverage classification
// ---------------------------------------------------------------------------

/// Classification of how well a local surface covers an upstream capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapStatus {
    /// Local surface fully covers the upstream capability.
    Covered,
    /// Local surface covers a subset; needs extension or bridge.
    PartialGap,
    /// No local coverage; needs adoption or wrapper.
    FullGap,
    /// Local surface duplicates upstream with no added benefit.
    Redundant,
}

impl fmt::Display for GapStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Covered => write!(f, "covered"),
            Self::PartialGap => write!(f, "partial_gap"),
            Self::FullGap => write!(f, "full_gap"),
            Self::Redundant => write!(f, "redundant"),
        }
    }
}

// ---------------------------------------------------------------------------
// MigrationDecision — what to do per surface-capability pair
// ---------------------------------------------------------------------------

/// Migration decision for a local surface relative to an upstream capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDecision {
    /// Use upstream directly, remove local implementation.
    DirectAdoption,
    /// Add a thin adapter bridging local to upstream.
    ThinBridge,
    /// Keep local, wrap upstream for specific features.
    MaintainedWrapper,
    /// Local is sufficient, upstream not needed.
    NoMigration,
    /// Decision requires more investigation.
    Deferred,
}

impl fmt::Display for MigrationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectAdoption => write!(f, "direct_adoption"),
            Self::ThinBridge => write!(f, "thin_bridge"),
            Self::MaintainedWrapper => write!(f, "maintained_wrapper"),
            Self::NoMigration => write!(f, "no_migration"),
            Self::Deferred => write!(f, "deferred"),
        }
    }
}

// ---------------------------------------------------------------------------
// GapMatrixEntry — one cell in the matrix
// ---------------------------------------------------------------------------

/// A single cell in the gap matrix mapping a local surface to an upstream
/// capability with coverage, decision, and confidence metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapMatrixEntry {
    /// Which local surface is being assessed.
    pub local_surface: LabSurfaceKind,
    /// Which upstream capability is being compared against.
    pub upstream_capability: UpstreamCapability,
    /// Coverage classification.
    pub status: GapStatus,
    /// How much of the upstream capability is covered locally,
    /// in millionths (1_000_000 = 100%).
    pub coverage_millionths: u64,
    /// Prescribed migration decision.
    pub migration_decision: MigrationDecision,
    /// Human-readable rationale for the decision.
    pub rationale: String,
    /// Confidence in the assessment, in millionths (1_000_000 = 100%).
    pub confidence_millionths: u64,
}

impl fmt::Display for GapMatrixEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{}: {} (coverage={}, decision={}, confidence={})",
            self.local_surface,
            self.upstream_capability,
            self.status,
            self.coverage_millionths,
            self.migration_decision,
            self.confidence_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// GapCoverageSummary — aggregate coverage statistics
// ---------------------------------------------------------------------------

/// Aggregate coverage statistics across the gap matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapCoverageSummary {
    /// Total number of (surface, capability) pairs assessed.
    pub total_pairs: usize,
    /// Number of pairs classified as Covered.
    pub covered_count: usize,
    /// Number of pairs classified as PartialGap.
    pub partial_gap_count: usize,
    /// Number of pairs classified as FullGap.
    pub full_gap_count: usize,
    /// Number of pairs classified as Redundant.
    pub redundant_count: usize,
    /// Overall coverage in millionths (weighted average).
    pub overall_coverage_millionths: u64,
}

// ---------------------------------------------------------------------------
// MigrationPlan — aggregate migration decisions
// ---------------------------------------------------------------------------

/// Aggregate migration plan derived from the gap matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Pairs where upstream should be adopted directly.
    pub adopt: Vec<(LabSurfaceKind, UpstreamCapability)>,
    /// Pairs where a thin bridge is needed.
    pub bridge: Vec<(LabSurfaceKind, UpstreamCapability)>,
    /// Pairs where a maintained wrapper is needed.
    pub wrap: Vec<(LabSurfaceKind, UpstreamCapability)>,
    /// Pairs where local is sufficient, no migration needed.
    pub keep: Vec<(LabSurfaceKind, UpstreamCapability)>,
    /// Pairs where the decision is deferred.
    pub defer: Vec<(LabSurfaceKind, UpstreamCapability)>,
    /// Overall recommendation text.
    pub recommendation: String,
}

// ---------------------------------------------------------------------------
// GapMatrix — the full matrix
// ---------------------------------------------------------------------------

/// Complete gap matrix comparing local surfaces against upstream capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapMatrix {
    /// All assessed entries.
    pub entries: Vec<GapMatrixEntry>,
    /// Schema version string.
    pub schema_version: String,
    /// Security epoch at which the assessment was performed.
    pub assessed_epoch: SecurityEpoch,
}

impl GapMatrix {
    /// Create a new empty gap matrix at the given epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            entries: Vec::new(),
            schema_version: GAP_MATRIX_SCHEMA_VERSION.to_string(),
            assessed_epoch: epoch,
        }
    }

    /// Add an entry to the matrix.
    pub fn add_entry(&mut self, entry: GapMatrixEntry) {
        self.entries.push(entry);
    }

    /// Look up a specific (local_surface, upstream_capability) pair.
    pub fn lookup(
        &self,
        local: LabSurfaceKind,
        upstream: UpstreamCapability,
    ) -> Option<&GapMatrixEntry> {
        self.entries
            .iter()
            .find(|e| e.local_surface == local && e.upstream_capability == upstream)
    }

    /// Compute aggregate coverage statistics.
    pub fn coverage_summary(&self) -> GapCoverageSummary {
        let total_pairs = self.entries.len();
        let covered_count = self
            .entries
            .iter()
            .filter(|e| e.status == GapStatus::Covered)
            .count();
        let partial_gap_count = self
            .entries
            .iter()
            .filter(|e| e.status == GapStatus::PartialGap)
            .count();
        let full_gap_count = self
            .entries
            .iter()
            .filter(|e| e.status == GapStatus::FullGap)
            .count();
        let redundant_count = self
            .entries
            .iter()
            .filter(|e| e.status == GapStatus::Redundant)
            .count();

        let overall_coverage_millionths = if total_pairs == 0 {
            0
        } else {
            let sum: u64 = self.entries.iter().map(|e| e.coverage_millionths).sum();
            sum / total_pairs as u64
        };

        GapCoverageSummary {
            total_pairs,
            covered_count,
            partial_gap_count,
            full_gap_count,
            redundant_count,
            overall_coverage_millionths,
        }
    }

    /// Derive a migration plan from the matrix entries.
    pub fn migration_plan(&self) -> MigrationPlan {
        let mut adopt = Vec::new();
        let mut bridge = Vec::new();
        let mut wrap = Vec::new();
        let mut keep = Vec::new();
        let mut defer = Vec::new();

        for entry in &self.entries {
            let pair = (entry.local_surface, entry.upstream_capability);
            match entry.migration_decision {
                MigrationDecision::DirectAdoption => adopt.push(pair),
                MigrationDecision::ThinBridge => bridge.push(pair),
                MigrationDecision::MaintainedWrapper => wrap.push(pair),
                MigrationDecision::NoMigration => keep.push(pair),
                MigrationDecision::Deferred => defer.push(pair),
            }
        }

        let recommendation = if !adopt.is_empty() && bridge.is_empty() && defer.is_empty() {
            "All gap pairs resolved: direct adoption recommended".to_string()
        } else if defer.is_empty() {
            format!(
                "Mixed strategy: {} adopt, {} bridge, {} wrap, {} keep",
                adopt.len(),
                bridge.len(),
                wrap.len(),
                keep.len(),
            )
        } else {
            format!(
                "Incomplete: {} pairs deferred pending investigation",
                defer.len(),
            )
        };

        MigrationPlan {
            adopt,
            bridge,
            wrap,
            keep,
            defer,
            recommendation,
        }
    }

    /// Compute a deterministic content hash of the matrix.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.schema_version.as_bytes());
        buf.extend_from_slice(&self.assessed_epoch.as_u64().to_le_bytes());
        {
            let mut sorted_entries: Vec<&GapMatrixEntry> = self.entries.iter().collect();
            sorted_entries.sort_by_key(|e| (e.local_surface, e.upstream_capability));
            for entry in &sorted_entries {
                buf.extend_from_slice(format!("{}", entry.local_surface).as_bytes());
                buf.extend_from_slice(format!("{}", entry.upstream_capability).as_bytes());
                buf.extend_from_slice(format!("{}", entry.status).as_bytes());
                buf.extend_from_slice(&entry.coverage_millionths.to_le_bytes());
                buf.extend_from_slice(format!("{}", entry.migration_decision).as_bytes());
                buf.extend_from_slice(entry.rationale.as_bytes());
                buf.extend_from_slice(&entry.confidence_millionths.to_le_bytes());
            }
        }
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for GapMatrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let summary = self.coverage_summary();
        writeln!(
            f,
            "Frankenlab Gap Matrix ({}) epoch={}",
            self.schema_version, self.assessed_epoch,
        )?;
        writeln!(f, "  Total pairs: {}", summary.total_pairs)?;
        writeln!(
            f,
            "  Covered: {}, PartialGap: {}, FullGap: {}, Redundant: {}",
            summary.covered_count,
            summary.partial_gap_count,
            summary.full_gap_count,
            summary.redundant_count,
        )?;
        write!(
            f,
            "  Overall coverage: {} millionths",
            summary.overall_coverage_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// build_canonical_gap_matrix — default 10x10 matrix
// ---------------------------------------------------------------------------

/// Build the canonical gap matrix with all 10x10 surface-capability pairs
/// using reasonable defaults for the current codebase state.
pub fn build_canonical_gap_matrix(epoch: SecurityEpoch) -> GapMatrix {
    let mut matrix = GapMatrix::new(epoch);

    // Helper to add an entry concisely.
    let mut add = |local: LabSurfaceKind,
                   upstream: UpstreamCapability,
                   status: GapStatus,
                   coverage: u64,
                   decision: MigrationDecision,
                   confidence: u64,
                   rationale: &str| {
        matrix.add_entry(GapMatrixEntry {
            local_surface: local,
            upstream_capability: upstream,
            status,
            coverage_millionths: coverage,
            migration_decision: decision,
            rationale: rationale.to_string(),
            confidence_millionths: confidence,
        });
    };

    // -- DeterministicReplay row --
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        950_000,
        MigrationDecision::MaintainedWrapper,
        900_000,
        "Local replay harness tightly coupled to engine internals",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::OracleDispatch,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Oracle verification partially overlaps with replay divergence detection",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        800_000,
        "No scenario orchestration in replay; adopt upstream",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::EvidenceReplay,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
        850_000,
        "Local nondeterminism capture fully covers evidence replay",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::CancelInjection,
        GapStatus::PartialGap,
        300_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Replay handles cancel as event but lacks injection API",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::Covered,
        850_000,
        MigrationDecision::NoMigration,
        900_000,
        "Replay uses deterministic tick clock",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::TraceValidation,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Divergence detection provides partial trace validation",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Lifecycle management not in scope for replay",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Quarantine not in scope for replay",
    );
    add(
        LabSurfaceKind::DeterministicReplay,
        UpstreamCapability::ReleaseGating,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "Replay does not gate releases; adopt upstream gating",
    );

    // -- ScenarioRunner row --
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        800_000,
        MigrationDecision::MaintainedWrapper,
        850_000,
        "Scenarios drive LabRuntime tasks directly",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "No oracle dispatch in scenario runner",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
        900_000,
        "Local scenario runner covers orchestration needs",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::EvidenceReplay,
        GapStatus::PartialGap,
        350_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Scenarios generate evidence but lack replay verification",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::CancelInjection,
        GapStatus::Covered,
        850_000,
        MigrationDecision::NoMigration,
        850_000,
        "Quarantine and ForcedCancel scenarios inject cancellation",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Scenarios use virtual time indirectly via LabRuntime",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::TraceValidation,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        750_000,
        "No trace validation in scenario runner",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::Covered,
        900_000,
        MigrationDecision::NoMigration,
        900_000,
        "Scenario runner is the lifecycle orchestrator",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::PartialGap,
        600_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Quarantine scenario exists but limited orchestration",
    );
    add(
        LabSurfaceKind::ScenarioRunner,
        UpstreamCapability::ReleaseGating,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "Scenario runner does not gate releases",
    );

    // -- EvidenceChecker row --
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Evidence checker uses LabRuntime indirectly",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::OracleDispatch,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Oracle validation partially overlaps with evidence chain checks",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        800_000,
        "No scenario orchestration in evidence checker",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::EvidenceReplay,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        950_000,
        "Evidence replay is the core function of this surface",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::CancelInjection,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Cancel injection not relevant to evidence checking",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Virtual time not directly used by evidence checker",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::TraceValidation,
        GapStatus::Covered,
        850_000,
        MigrationDecision::NoMigration,
        850_000,
        "Evidence chain validation includes trace verification",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Lifecycle orchestration outside evidence scope",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Quarantine outside evidence scope",
    );
    add(
        LabSurfaceKind::EvidenceChecker,
        UpstreamCapability::ReleaseGating,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Evidence results feed into release gating but not directly",
    );

    // -- CancellationInjector row --
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Injector uses LabRuntime inject_cancel API",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Oracle dispatch not related to cancellation",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Cancellation scenarios partially cover orchestration",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::EvidenceReplay,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Evidence replay not related to cancellation",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::CancelInjection,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        950_000,
        "Core function of this surface; full coverage",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Virtual time not directly used by injector",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::TraceValidation,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Trace validation outside injection scope",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::PartialGap,
        300_000,
        MigrationDecision::ThinBridge,
        650_000,
        "Cancel affects lifecycle but injector is narrow",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Cancellation triggers quarantine in some cases",
    );
    add(
        LabSurfaceKind::CancellationInjector,
        UpstreamCapability::ReleaseGating,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "Injector does not gate releases",
    );

    // -- VirtualTimeClock row --
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::MaintainedWrapper,
        900_000,
        "Virtual clock is core LabRuntime infrastructure",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Oracle dispatch unrelated to virtual time",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Time advances drive scenarios but clock is passive",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::EvidenceReplay,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Evidence replay unrelated to virtual time",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::CancelInjection,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Cancel injection unrelated to virtual time",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        950_000,
        "Core function; tick-based deterministic clock",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::TraceValidation,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Trace validation unrelated to virtual time",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::PartialGap,
        300_000,
        MigrationDecision::ThinBridge,
        650_000,
        "Time drives lifecycle but clock is passive",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Quarantine unrelated to virtual time",
    );
    add(
        LabSurfaceKind::VirtualTimeClock,
        UpstreamCapability::ReleaseGating,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "Clock does not gate releases",
    );

    // -- DecisionTraceValidator row --
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Trace validator consumes LabRuntime output",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::OracleDispatch,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Oracle dispatch partially overlaps with trace audit",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        750_000,
        "No scenario orchestration in trace validator",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::EvidenceReplay,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Trace validation overlaps with evidence replay audit",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::CancelInjection,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Cancel injection outside trace scope",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Virtual time outside trace scope",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::TraceValidation,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        950_000,
        "Core function of this surface",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Lifecycle outside trace scope",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Quarantine outside trace scope",
    );
    add(
        LabSurfaceKind::DecisionTraceValidator,
        UpstreamCapability::ReleaseGating,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Trace results feed into release gating indirectly",
    );

    // -- ScheduleReplay row --
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        900_000,
        MigrationDecision::MaintainedWrapper,
        900_000,
        "Schedule replay is core LabRuntime infrastructure",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Oracle dispatch unrelated to schedule replay",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Schedule replay can drive scenarios but lacks orchestration",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::EvidenceReplay,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Schedule transcript overlaps with evidence replay",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::CancelInjection,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Cancel injection unrelated to schedule replay",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::Covered,
        850_000,
        MigrationDecision::NoMigration,
        850_000,
        "Schedule replay uses deterministic tick-based time",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::TraceValidation,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Schedule transcripts provide partial trace data",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "Schedule replay does not orchestrate lifecycles",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Quarantine unrelated to schedule replay",
    );
    add(
        LabSurfaceKind::ScheduleReplay,
        UpstreamCapability::ReleaseGating,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "Schedule replay does not gate releases",
    );

    // -- LifecycleTester row --
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::LabRuntime,
        GapStatus::Covered,
        800_000,
        MigrationDecision::MaintainedWrapper,
        850_000,
        "Lifecycle tester drives LabRuntime tasks",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "No oracle dispatch in lifecycle tester",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::PartialGap,
        600_000,
        MigrationDecision::ThinBridge,
        800_000,
        "Lifecycle scenarios partially cover orchestration",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::EvidenceReplay,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Evidence replay outside lifecycle scope",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::CancelInjection,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Lifecycle includes cancel but not full injection",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Lifecycle uses time indirectly",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::TraceValidation,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        750_000,
        "No trace validation in lifecycle tester",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        950_000,
        "Core function of this surface",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Lifecycle quarantine partially covers orchestration",
    );
    add(
        LabSurfaceKind::LifecycleTester,
        UpstreamCapability::ReleaseGating,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        700_000,
        "Lifecycle tester does not gate releases",
    );

    // -- QuarantineHarness row --
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Quarantine harness uses LabRuntime for isolated execution",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::OracleDispatch,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Oracle dispatch unrelated to quarantine",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Quarantine scenarios partially cover orchestration",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::EvidenceReplay,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Evidence replay outside quarantine scope",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::CancelInjection,
        GapStatus::Covered,
        800_000,
        MigrationDecision::NoMigration,
        850_000,
        "Quarantine drives cancellation for fault containment",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Virtual time not directly used by quarantine",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::TraceValidation,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        750_000,
        "No trace validation in quarantine harness",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Quarantine affects lifecycle but is narrowly scoped",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        950_000,
        "Core function of this surface",
    );
    add(
        LabSurfaceKind::QuarantineHarness,
        UpstreamCapability::ReleaseGating,
        GapStatus::PartialGap,
        300_000,
        MigrationDecision::ThinBridge,
        650_000,
        "Quarantine results inform release gating indirectly",
    );

    // -- ReleaseGateRunner row --
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::LabRuntime,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Release gate runner delegates to LabRuntime for checks",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::OracleDispatch,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Oracle results feed into gate decisions",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::ScenarioOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::DirectAdoption,
        750_000,
        "No scenario orchestration in release gate",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::EvidenceReplay,
        GapStatus::PartialGap,
        500_000,
        MigrationDecision::ThinBridge,
        750_000,
        "Evidence results feed into gate decisions",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::CancelInjection,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Cancel injection not relevant to release gating",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::VirtualTimeControl,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Virtual time not relevant to release gating",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::TraceValidation,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Trace results feed into gate decisions",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::LifecycleOrchestration,
        GapStatus::FullGap,
        0,
        MigrationDecision::Deferred,
        500_000,
        "Lifecycle orchestration outside gate scope",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::QuarantineOrchestration,
        GapStatus::PartialGap,
        400_000,
        MigrationDecision::ThinBridge,
        700_000,
        "Quarantine results inform gate decisions",
    );
    add(
        LabSurfaceKind::ReleaseGateRunner,
        UpstreamCapability::ReleaseGating,
        GapStatus::Covered,
        950_000,
        MigrationDecision::NoMigration,
        950_000,
        "Core function of this surface; fail-closed gating",
    );

    matrix
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Constant tests --

    #[test]
    fn schema_version_is_stable() {
        assert_eq!(
            GAP_MATRIX_SCHEMA_VERSION,
            "franken-engine.frankenlab-gap-matrix.v1"
        );
    }

    #[test]
    fn bead_id_constant() {
        assert_eq!(GAP_MATRIX_BEAD_ID, "bd-3nr.1.1.2");
    }

    // -- LabSurfaceKind tests --

    #[test]
    fn lab_surface_kind_all_has_ten() {
        assert_eq!(LabSurfaceKind::ALL.len(), 10);
    }

    #[test]
    fn lab_surface_kind_display() {
        assert_eq!(
            format!("{}", LabSurfaceKind::DeterministicReplay),
            "deterministic_replay"
        );
        assert_eq!(
            format!("{}", LabSurfaceKind::ReleaseGateRunner),
            "release_gate_runner"
        );
        assert_eq!(
            format!("{}", LabSurfaceKind::VirtualTimeClock),
            "virtual_time_clock"
        );
    }

    #[test]
    fn lab_surface_kind_serde_roundtrip() {
        for s in LabSurfaceKind::ALL {
            let json = serde_json::to_string(&s).unwrap();
            let s2: LabSurfaceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(s, s2);
        }
    }

    // -- UpstreamCapability tests --

    #[test]
    fn upstream_capability_all_has_ten() {
        assert_eq!(UpstreamCapability::ALL.len(), 10);
    }

    #[test]
    fn upstream_capability_display() {
        assert_eq!(format!("{}", UpstreamCapability::LabRuntime), "lab_runtime");
        assert_eq!(
            format!("{}", UpstreamCapability::ReleaseGating),
            "release_gating"
        );
        assert_eq!(
            format!("{}", UpstreamCapability::QuarantineOrchestration),
            "quarantine_orchestration"
        );
    }

    #[test]
    fn upstream_capability_serde_roundtrip() {
        for c in UpstreamCapability::ALL {
            let json = serde_json::to_string(&c).unwrap();
            let c2: UpstreamCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(c, c2);
        }
    }

    // -- GapStatus tests --

    #[test]
    fn gap_status_display() {
        assert_eq!(format!("{}", GapStatus::Covered), "covered");
        assert_eq!(format!("{}", GapStatus::PartialGap), "partial_gap");
        assert_eq!(format!("{}", GapStatus::FullGap), "full_gap");
        assert_eq!(format!("{}", GapStatus::Redundant), "redundant");
    }

    #[test]
    fn gap_status_serde_roundtrip() {
        for s in [
            GapStatus::Covered,
            GapStatus::PartialGap,
            GapStatus::FullGap,
            GapStatus::Redundant,
        ] {
            let json = serde_json::to_string(&s).unwrap();
            let s2: GapStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn gap_status_ordering() {
        assert!(GapStatus::Covered < GapStatus::PartialGap);
        assert!(GapStatus::PartialGap < GapStatus::FullGap);
        assert!(GapStatus::FullGap < GapStatus::Redundant);
    }

    // -- MigrationDecision tests --

    #[test]
    fn migration_decision_display() {
        assert_eq!(
            format!("{}", MigrationDecision::DirectAdoption),
            "direct_adoption"
        );
        assert_eq!(format!("{}", MigrationDecision::ThinBridge), "thin_bridge");
        assert_eq!(
            format!("{}", MigrationDecision::MaintainedWrapper),
            "maintained_wrapper"
        );
        assert_eq!(
            format!("{}", MigrationDecision::NoMigration),
            "no_migration"
        );
        assert_eq!(format!("{}", MigrationDecision::Deferred), "deferred");
    }

    #[test]
    fn migration_decision_serde_roundtrip() {
        for d in [
            MigrationDecision::DirectAdoption,
            MigrationDecision::ThinBridge,
            MigrationDecision::MaintainedWrapper,
            MigrationDecision::NoMigration,
            MigrationDecision::Deferred,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let d2: MigrationDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, d2);
        }
    }

    // -- GapMatrixEntry tests --

    #[test]
    fn gap_matrix_entry_construction() {
        let entry = GapMatrixEntry {
            local_surface: LabSurfaceKind::DeterministicReplay,
            upstream_capability: UpstreamCapability::LabRuntime,
            status: GapStatus::Covered,
            coverage_millionths: 950_000,
            migration_decision: MigrationDecision::MaintainedWrapper,
            rationale: "test rationale".to_string(),
            confidence_millionths: 900_000,
        };
        assert_eq!(entry.local_surface, LabSurfaceKind::DeterministicReplay);
        assert_eq!(entry.coverage_millionths, 950_000);
    }

    #[test]
    fn gap_matrix_entry_display() {
        let entry = GapMatrixEntry {
            local_surface: LabSurfaceKind::EvidenceChecker,
            upstream_capability: UpstreamCapability::EvidenceReplay,
            status: GapStatus::Covered,
            coverage_millionths: 950_000,
            migration_decision: MigrationDecision::NoMigration,
            rationale: "fully covered".to_string(),
            confidence_millionths: 950_000,
        };
        let s = format!("{}", entry);
        assert!(s.contains("evidence_checker"));
        assert!(s.contains("evidence_replay"));
        assert!(s.contains("covered"));
    }

    #[test]
    fn gap_matrix_entry_serde_roundtrip() {
        let entry = GapMatrixEntry {
            local_surface: LabSurfaceKind::ScenarioRunner,
            upstream_capability: UpstreamCapability::ScenarioOrchestration,
            status: GapStatus::PartialGap,
            coverage_millionths: 600_000,
            migration_decision: MigrationDecision::ThinBridge,
            rationale: "partial coverage".to_string(),
            confidence_millionths: 750_000,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let entry2: GapMatrixEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, entry2);
    }

    // -- GapMatrix tests --

    #[test]
    fn gap_matrix_new_is_empty() {
        let m = GapMatrix::new(SecurityEpoch::GENESIS);
        assert!(m.entries.is_empty());
        assert_eq!(m.schema_version, GAP_MATRIX_SCHEMA_VERSION);
    }

    #[test]
    fn gap_matrix_add_entry() {
        let mut m = GapMatrix::new(SecurityEpoch::from_raw(1));
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::DeterministicReplay,
            upstream_capability: UpstreamCapability::LabRuntime,
            status: GapStatus::Covered,
            coverage_millionths: 900_000,
            migration_decision: MigrationDecision::NoMigration,
            rationale: "test".to_string(),
            confidence_millionths: 800_000,
        });
        assert_eq!(m.entries.len(), 1);
    }

    #[test]
    fn gap_matrix_lookup_found() {
        let mut m = GapMatrix::new(SecurityEpoch::from_raw(1));
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::EvidenceChecker,
            upstream_capability: UpstreamCapability::EvidenceReplay,
            status: GapStatus::Covered,
            coverage_millionths: 950_000,
            migration_decision: MigrationDecision::NoMigration,
            rationale: "covered".to_string(),
            confidence_millionths: 950_000,
        });
        let found = m.lookup(
            LabSurfaceKind::EvidenceChecker,
            UpstreamCapability::EvidenceReplay,
        );
        assert!(found.is_some());
        assert_eq!(found.unwrap().status, GapStatus::Covered);
    }

    #[test]
    fn gap_matrix_lookup_not_found() {
        let m = GapMatrix::new(SecurityEpoch::from_raw(1));
        assert!(
            m.lookup(
                LabSurfaceKind::DeterministicReplay,
                UpstreamCapability::LabRuntime
            )
            .is_none()
        );
    }

    #[test]
    fn gap_matrix_coverage_summary_empty() {
        let m = GapMatrix::new(SecurityEpoch::GENESIS);
        let s = m.coverage_summary();
        assert_eq!(s.total_pairs, 0);
        assert_eq!(s.covered_count, 0);
        assert_eq!(s.overall_coverage_millionths, 0);
    }

    #[test]
    fn gap_matrix_coverage_summary_mixed() {
        let mut m = GapMatrix::new(SecurityEpoch::from_raw(1));
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::DeterministicReplay,
            upstream_capability: UpstreamCapability::LabRuntime,
            status: GapStatus::Covered,
            coverage_millionths: 1_000_000,
            migration_decision: MigrationDecision::NoMigration,
            rationale: "full".to_string(),
            confidence_millionths: 900_000,
        });
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::ScenarioRunner,
            upstream_capability: UpstreamCapability::OracleDispatch,
            status: GapStatus::FullGap,
            coverage_millionths: 0,
            migration_decision: MigrationDecision::DirectAdoption,
            rationale: "gap".to_string(),
            confidence_millionths: 700_000,
        });
        let s = m.coverage_summary();
        assert_eq!(s.total_pairs, 2);
        assert_eq!(s.covered_count, 1);
        assert_eq!(s.full_gap_count, 1);
        assert_eq!(s.overall_coverage_millionths, 500_000);
    }

    #[test]
    fn gap_matrix_migration_plan_empty() {
        let m = GapMatrix::new(SecurityEpoch::GENESIS);
        let p = m.migration_plan();
        assert!(p.adopt.is_empty());
        assert!(p.bridge.is_empty());
        assert!(p.wrap.is_empty());
        assert!(p.keep.is_empty());
        assert!(p.defer.is_empty());
    }

    #[test]
    fn gap_matrix_migration_plan_categorizes() {
        let mut m = GapMatrix::new(SecurityEpoch::from_raw(1));
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::DeterministicReplay,
            upstream_capability: UpstreamCapability::ScenarioOrchestration,
            status: GapStatus::FullGap,
            coverage_millionths: 0,
            migration_decision: MigrationDecision::DirectAdoption,
            rationale: "adopt".to_string(),
            confidence_millionths: 800_000,
        });
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::ScenarioRunner,
            upstream_capability: UpstreamCapability::EvidenceReplay,
            status: GapStatus::PartialGap,
            coverage_millionths: 350_000,
            migration_decision: MigrationDecision::ThinBridge,
            rationale: "bridge".to_string(),
            confidence_millionths: 750_000,
        });
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::VirtualTimeClock,
            upstream_capability: UpstreamCapability::VirtualTimeControl,
            status: GapStatus::Covered,
            coverage_millionths: 950_000,
            migration_decision: MigrationDecision::NoMigration,
            rationale: "keep".to_string(),
            confidence_millionths: 950_000,
        });
        let p = m.migration_plan();
        assert_eq!(p.adopt.len(), 1);
        assert_eq!(p.bridge.len(), 1);
        assert_eq!(p.keep.len(), 1);
        assert!(p.wrap.is_empty());
        assert!(p.defer.is_empty());
    }

    #[test]
    fn gap_matrix_migration_plan_recommendation_with_defer() {
        let mut m = GapMatrix::new(SecurityEpoch::from_raw(1));
        m.add_entry(GapMatrixEntry {
            local_surface: LabSurfaceKind::CancellationInjector,
            upstream_capability: UpstreamCapability::OracleDispatch,
            status: GapStatus::FullGap,
            coverage_millionths: 0,
            migration_decision: MigrationDecision::Deferred,
            rationale: "needs investigation".to_string(),
            confidence_millionths: 500_000,
        });
        let p = m.migration_plan();
        assert!(p.recommendation.contains("deferred"));
    }

    #[test]
    fn gap_matrix_content_hash_deterministic() {
        let epoch = SecurityEpoch::from_raw(42);
        let m1 = build_canonical_gap_matrix(epoch);
        let m2 = build_canonical_gap_matrix(epoch);
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn gap_matrix_content_hash_changes_with_epoch() {
        let m1 = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        let m2 = build_canonical_gap_matrix(SecurityEpoch::from_raw(2));
        assert_ne!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn gap_matrix_display() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        let s = format!("{}", m);
        assert!(s.contains("Frankenlab Gap Matrix"));
        assert!(s.contains("Total pairs: 100"));
    }

    #[test]
    fn gap_matrix_serde_roundtrip() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        let json = serde_json::to_string(&m).unwrap();
        let m2: GapMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    // -- Canonical matrix tests --

    #[test]
    fn canonical_matrix_has_100_entries() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        assert_eq!(m.entries.len(), 100);
    }

    #[test]
    fn canonical_matrix_covers_all_surfaces() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        for surface in LabSurfaceKind::ALL {
            let count = m
                .entries
                .iter()
                .filter(|e| e.local_surface == surface)
                .count();
            assert_eq!(count, 10, "surface {surface} should have 10 entries");
        }
    }

    #[test]
    fn canonical_matrix_covers_all_capabilities() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        for cap in UpstreamCapability::ALL {
            let count = m
                .entries
                .iter()
                .filter(|e| e.upstream_capability == cap)
                .count();
            assert_eq!(count, 10, "capability {cap} should have 10 entries");
        }
    }

    #[test]
    fn canonical_matrix_diagonal_surfaces_are_covered() {
        // Each surface's "primary" upstream capability should be Covered.
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        let diagonals = [
            (
                LabSurfaceKind::EvidenceChecker,
                UpstreamCapability::EvidenceReplay,
            ),
            (
                LabSurfaceKind::CancellationInjector,
                UpstreamCapability::CancelInjection,
            ),
            (
                LabSurfaceKind::VirtualTimeClock,
                UpstreamCapability::VirtualTimeControl,
            ),
            (
                LabSurfaceKind::DecisionTraceValidator,
                UpstreamCapability::TraceValidation,
            ),
            (
                LabSurfaceKind::QuarantineHarness,
                UpstreamCapability::QuarantineOrchestration,
            ),
            (
                LabSurfaceKind::ReleaseGateRunner,
                UpstreamCapability::ReleaseGating,
            ),
            (
                LabSurfaceKind::LifecycleTester,
                UpstreamCapability::LifecycleOrchestration,
            ),
            (
                LabSurfaceKind::ScenarioRunner,
                UpstreamCapability::ScenarioOrchestration,
            ),
        ];
        for (surface, cap) in diagonals {
            let entry = m
                .lookup(surface, cap)
                .unwrap_or_else(|| panic!("missing diagonal entry for {surface}x{cap}"));
            assert_eq!(
                entry.status,
                GapStatus::Covered,
                "diagonal {surface}x{cap} should be Covered"
            );
        }
    }

    #[test]
    fn canonical_matrix_has_full_gaps() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        let summary = m.coverage_summary();
        assert!(summary.full_gap_count > 0, "should have some full gaps");
    }

    #[test]
    fn canonical_matrix_has_partial_gaps() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        let summary = m.coverage_summary();
        assert!(
            summary.partial_gap_count > 0,
            "should have some partial gaps"
        );
    }

    #[test]
    fn canonical_matrix_migration_plan_non_empty() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        let plan = m.migration_plan();
        assert!(!plan.adopt.is_empty());
        assert!(!plan.bridge.is_empty());
        assert!(!plan.keep.is_empty());
        assert!(!plan.defer.is_empty());
    }

    #[test]
    fn canonical_matrix_all_rationales_non_empty() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        for entry in &m.entries {
            assert!(
                !entry.rationale.is_empty(),
                "entry {}x{} has empty rationale",
                entry.local_surface,
                entry.upstream_capability,
            );
        }
    }

    #[test]
    fn canonical_matrix_all_confidences_positive() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        for entry in &m.entries {
            assert!(
                entry.confidence_millionths > 0,
                "entry {}x{} has zero confidence",
                entry.local_surface,
                entry.upstream_capability,
            );
        }
    }

    #[test]
    fn canonical_matrix_coverage_within_bounds() {
        let m = build_canonical_gap_matrix(SecurityEpoch::from_raw(1));
        for entry in &m.entries {
            assert!(
                entry.coverage_millionths <= 1_000_000,
                "entry {}x{} coverage exceeds 100%",
                entry.local_surface,
                entry.upstream_capability,
            );
        }
    }

    #[test]
    fn gap_coverage_summary_serde_roundtrip() {
        let summary = GapCoverageSummary {
            total_pairs: 100,
            covered_count: 20,
            partial_gap_count: 30,
            full_gap_count: 40,
            redundant_count: 10,
            overall_coverage_millionths: 450_000,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let s2: GapCoverageSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, s2);
    }

    #[test]
    fn migration_plan_serde_roundtrip() {
        let plan = MigrationPlan {
            adopt: vec![(
                LabSurfaceKind::DeterministicReplay,
                UpstreamCapability::ScenarioOrchestration,
            )],
            bridge: vec![],
            wrap: vec![],
            keep: vec![],
            defer: vec![],
            recommendation: "test".to_string(),
        };
        let json = serde_json::to_string(&plan).unwrap();
        let p2: MigrationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, p2);
    }
}
