//! Local-vs-upstream frankenlab surface gap matrix and migration decision.
//!
//! Bead: bd-3nr.1.1.2 [10.13X.A2]
//!
//! Inventories the capabilities of each local deterministic lab/release-gate
//! surface and maps them against upstream frankenlab/LabRuntime/oracle
//! equivalents. Each cell in the matrix is classified as:
//!
//! - **Covered**: local surface fully implements the upstream capability.
//! - **Partial**: local surface has a subset; upgrade path identified.
//! - **Missing**: upstream provides something local does not have.
//! - **LocalOnly**: local surface has no upstream counterpart.
//!
//! The output encodes a migration decision per surface:
//! **DirectAdoption**, **ThinBridge**, or **MaintainedWrapper**.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "frankenlab_surface_gap_matrix";
// Reuse the canonical bead/schema identity so the sibling gap-matrix modules
// cannot silently drift apart.
pub const BEAD_ID: &str = crate::frankenlab_gap_matrix::GAP_MATRIX_BEAD_ID;
pub const GAP_MATRIX_SCHEMA_VERSION: &str = crate::frankenlab_gap_matrix::GAP_MATRIX_SCHEMA_VERSION;

// ---------------------------------------------------------------------------
// SurfaceId — which local module/capability area
// ---------------------------------------------------------------------------

/// Identifier for a local deterministic lab/release-gate surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceId {
    /// `lab_runtime.rs` — deterministic harness with virtual time + tasks.
    LabRuntime,
    /// `frankenlab_extension_lifecycle.rs` — lifecycle test scenarios.
    FrankenlabScenarios,
    /// `interleaving_explorer.rs` — race-condition exploration.
    InterleavingExplorer,
    /// `evidence_replay_checker.rs` — evidence linkage validation.
    EvidenceReplayChecker,
    /// `deterministic_replay.rs` — nondeterminism capture + replay.
    DeterministicReplay,
    /// `deterministic_sim_scheduler.rs` — event/module/cache simulation.
    SimScheduler,
    /// `frankenlab_release_gate.rs` — fail-closed release gating.
    ReleaseGate,
}

impl SurfaceId {
    /// All variants in deterministic order.
    pub const ALL: [Self; 7] = [
        Self::LabRuntime,
        Self::FrankenlabScenarios,
        Self::InterleavingExplorer,
        Self::EvidenceReplayChecker,
        Self::DeterministicReplay,
        Self::SimScheduler,
        Self::ReleaseGate,
    ];

    /// Source file path (relative to crate root).
    pub fn source_file(self) -> &'static str {
        match self {
            Self::LabRuntime => "src/lab_runtime.rs",
            Self::FrankenlabScenarios => "src/frankenlab_extension_lifecycle.rs",
            Self::InterleavingExplorer => "src/interleaving_explorer.rs",
            Self::EvidenceReplayChecker => "src/evidence_replay_checker.rs",
            Self::DeterministicReplay => "src/deterministic_replay.rs",
            Self::SimScheduler => "src/deterministic_sim_scheduler.rs",
            Self::ReleaseGate => "src/frankenlab_release_gate.rs",
        }
    }
}

impl fmt::Display for SurfaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabRuntime => write!(f, "lab_runtime"),
            Self::FrankenlabScenarios => write!(f, "frankenlab_scenarios"),
            Self::InterleavingExplorer => write!(f, "interleaving_explorer"),
            Self::EvidenceReplayChecker => write!(f, "evidence_replay_checker"),
            Self::DeterministicReplay => write!(f, "deterministic_replay"),
            Self::SimScheduler => write!(f, "sim_scheduler"),
            Self::ReleaseGate => write!(f, "release_gate"),
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityId — what each surface provides
// ---------------------------------------------------------------------------

/// Named capability that a surface might provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityId {
    /// Deterministic virtual time advancing in ticks.
    VirtualTime,
    /// Schedule replay with seed-based PRNG.
    ScheduleReplay,
    /// Fault injection (panic, channel disconnect, deadline, etc.).
    FaultInjection,
    /// Cancellation injection at region granularity.
    CancellationInjection,
    /// Task lifecycle management (spawn, run, complete, fault).
    TaskLifecycle,
    /// Extension lifecycle scenarios (startup through revocation).
    ExtensionLifecycle,
    /// Race-condition / interleaving exploration.
    RaceExploration,
    /// Evidence chain validation and tamper detection.
    EvidenceChainValidation,
    /// Cross-machine determinism verification.
    CrossMachineDeterminism,
    /// Nondeterminism capture and trace recording.
    NondeterminismCapture,
    /// Divergence detection during replay.
    DivergenceDetection,
    /// Failover state machine and recovery.
    FailoverManagement,
    /// Incident artifact / postmortem generation.
    IncidentArtifacts,
    /// Event-loop / module / cache simulation.
    EventSimulation,
    /// Priority-based event dispatch.
    PriorityDispatch,
    /// Fail-closed release gating.
    FailClosedGating,
    /// Content-addressed evidence artifacts.
    ContentAddressedArtifacts,
    /// Obligation resolution checking.
    ObligationResolution,
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match serde_json::to_string(self) {
            Ok(s) => write!(f, "{}", s.trim_matches('"')),
            Err(_) => write!(f, "{:?}", self),
        }
    }
}

// ---------------------------------------------------------------------------
// CoverageLevel — how well a local surface covers a capability
// ---------------------------------------------------------------------------

/// Coverage level of a local surface for a given capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    /// Local surface fully implements the capability.
    Covered,
    /// Local surface partially covers the capability.
    Partial,
    /// The capability exists upstream but is missing locally.
    Missing,
    /// Local surface has this capability but upstream does not.
    LocalOnly,
}

impl fmt::Display for CoverageLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Covered => write!(f, "covered"),
            Self::Partial => write!(f, "partial"),
            Self::Missing => write!(f, "missing"),
            Self::LocalOnly => write!(f, "local_only"),
        }
    }
}

// ---------------------------------------------------------------------------
// MigrationDecision — what to do with each surface
// ---------------------------------------------------------------------------

/// Migration decision for a local surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MigrationDecision {
    /// Replace local implementation with upstream directly.
    DirectAdoption,
    /// Build a thin bridge between local and upstream.
    ThinBridge,
    /// Maintain local wrapper with explicit delta documentation.
    MaintainedWrapper,
}

impl fmt::Display for MigrationDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectAdoption => write!(f, "direct_adoption"),
            Self::ThinBridge => write!(f, "thin_bridge"),
            Self::MaintainedWrapper => write!(f, "maintained_wrapper"),
        }
    }
}

// ---------------------------------------------------------------------------
// GapCell — single cell in the matrix
// ---------------------------------------------------------------------------

/// One cell in the gap matrix: (surface, capability) → coverage + notes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GapCell {
    pub surface: SurfaceId,
    pub capability: CapabilityId,
    pub coverage: CoverageLevel,
    pub notes: String,
}

impl fmt::Display for GapCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}×{}: {} — {}",
            self.surface, self.capability, self.coverage, self.notes
        )
    }
}

// ---------------------------------------------------------------------------
// SurfaceAssessment — per-surface migration assessment
// ---------------------------------------------------------------------------

/// Assessment of one local surface against upstream frankenlab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceAssessment {
    pub surface: SurfaceId,
    pub decision: MigrationDecision,
    pub rationale: String,
    pub covered_count: u32,
    pub partial_count: u32,
    pub missing_count: u32,
    pub local_only_count: u32,
    pub cells: Vec<GapCell>,
}

impl SurfaceAssessment {
    /// Build from a set of gap cells for one surface.
    pub fn build(
        surface: SurfaceId,
        cells: Vec<GapCell>,
        decision: MigrationDecision,
        rationale: &str,
    ) -> Self {
        let covered = cells
            .iter()
            .filter(|c| c.coverage == CoverageLevel::Covered)
            .count() as u32;
        let partial = cells
            .iter()
            .filter(|c| c.coverage == CoverageLevel::Partial)
            .count() as u32;
        let missing = cells
            .iter()
            .filter(|c| c.coverage == CoverageLevel::Missing)
            .count() as u32;
        let local_only = cells
            .iter()
            .filter(|c| c.coverage == CoverageLevel::LocalOnly)
            .count() as u32;
        Self {
            surface,
            decision,
            rationale: rationale.to_string(),
            covered_count: covered,
            partial_count: partial,
            missing_count: missing,
            local_only_count: local_only,
            cells,
        }
    }

    /// Coverage rate in millionths (1_000_000 = 100%).
    pub fn coverage_rate_millionths(&self) -> i64 {
        let total = self.covered_count + self.partial_count + self.missing_count;
        if total == 0 {
            return 1_000_000;
        }
        let covered_equiv =
            self.covered_count as i64 * 1_000_000 + self.partial_count as i64 * 500_000;
        covered_equiv / total as i64
    }
}

impl fmt::Display for SurfaceAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (covered={}, partial={}, missing={}, local_only={})",
            self.surface,
            self.decision,
            self.covered_count,
            self.partial_count,
            self.missing_count,
            self.local_only_count,
        )
    }
}

// ---------------------------------------------------------------------------
// GapMatrix — the full matrix
// ---------------------------------------------------------------------------

/// Complete gap matrix comparing local surfaces against upstream frankenlab.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapMatrix {
    pub schema_version: String,
    pub assessments: Vec<SurfaceAssessment>,
    pub summary: GapMatrixSummary,
    pub matrix_hash: ContentHash,
}

/// Summary statistics for the gap matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GapMatrixSummary {
    pub total_surfaces: u32,
    pub direct_adoption_count: u32,
    pub thin_bridge_count: u32,
    pub maintained_wrapper_count: u32,
    pub total_cells: u32,
    pub covered_cells: u32,
    pub partial_cells: u32,
    pub missing_cells: u32,
    pub local_only_cells: u32,
    pub decisions: BTreeMap<String, u32>,
}

impl GapMatrix {
    /// Build the matrix from a list of surface assessments.
    pub fn build(assessments: Vec<SurfaceAssessment>) -> Self {
        let total_surfaces = assessments.len() as u32;
        let mut direct = 0u32;
        let mut bridge = 0u32;
        let mut wrapper = 0u32;
        let mut total_cells = 0u32;
        let mut covered = 0u32;
        let mut partial = 0u32;
        let mut missing = 0u32;
        let mut local_only = 0u32;

        for a in &assessments {
            match a.decision {
                MigrationDecision::DirectAdoption => direct += 1,
                MigrationDecision::ThinBridge => bridge += 1,
                MigrationDecision::MaintainedWrapper => wrapper += 1,
            }
            total_cells += a.cells.len() as u32;
            covered += a.covered_count;
            partial += a.partial_count;
            missing += a.missing_count;
            local_only += a.local_only_count;
        }

        let mut decisions = BTreeMap::new();
        decisions.insert("direct_adoption".to_string(), direct);
        decisions.insert("thin_bridge".to_string(), bridge);
        decisions.insert("maintained_wrapper".to_string(), wrapper);

        let summary = GapMatrixSummary {
            total_surfaces,
            direct_adoption_count: direct,
            thin_bridge_count: bridge,
            maintained_wrapper_count: wrapper,
            total_cells,
            covered_cells: covered,
            partial_cells: partial,
            missing_cells: missing,
            local_only_cells: local_only,
            decisions,
        };

        let mut hasher = Sha256::new();
        hasher.update(GAP_MATRIX_SCHEMA_VERSION.as_bytes());
        for a in &assessments {
            hasher.update(format!("{}", a.surface).as_bytes());
            hasher.update(format!("{}", a.decision).as_bytes());
            let mut sorted_cells: Vec<_> = a.cells.iter().collect();
            sorted_cells.sort_by(|x, y| {
                format!("{}", x.surface)
                    .cmp(&format!("{}", y.surface))
                    .then_with(|| format!("{}", x.capability).cmp(&format!("{}", y.capability)))
            });
            for c in &sorted_cells {
                hasher.update(format!("{}", c.surface).as_bytes());
                hasher.update(format!("{}", c.capability).as_bytes());
                hasher.update(format!("{}", c.coverage).as_bytes());
            }
        }
        let matrix_hash = ContentHash::compute(&hasher.finalize());

        Self {
            schema_version: GAP_MATRIX_SCHEMA_VERSION.to_string(),
            assessments,
            summary,
            matrix_hash,
        }
    }

    /// Get assessment for a specific surface.
    pub fn for_surface(&self, surface: SurfaceId) -> Option<&SurfaceAssessment> {
        self.assessments.iter().find(|a| a.surface == surface)
    }

    /// Check whether any surface has missing capabilities.
    pub fn has_gaps(&self) -> bool {
        self.summary.missing_cells > 0
    }

    /// Surfaces requiring a specific migration decision.
    pub fn surfaces_with_decision(&self, decision: MigrationDecision) -> Vec<SurfaceId> {
        self.assessments
            .iter()
            .filter(|a| a.decision == decision)
            .map(|a| a.surface)
            .collect()
    }
}

impl fmt::Display for GapMatrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Frankenlab Surface Gap Matrix ({})", self.schema_version)?;
        writeln!(f, "  Surfaces: {}", self.summary.total_surfaces)?;
        writeln!(
            f,
            "  Direct adoption: {}",
            self.summary.direct_adoption_count
        )?;
        writeln!(f, "  Thin bridge: {}", self.summary.thin_bridge_count)?;
        writeln!(
            f,
            "  Maintained wrapper: {}",
            self.summary.maintained_wrapper_count
        )?;
        writeln!(
            f,
            "  Total cells: {} (covered={}, partial={}, missing={}, local_only={})",
            self.summary.total_cells,
            self.summary.covered_cells,
            self.summary.partial_cells,
            self.summary.missing_cells,
            self.summary.local_only_cells
        )?;
        write!(f, "  Matrix hash: {}", self.matrix_hash)
    }
}

// ---------------------------------------------------------------------------
// build_canonical_gap_matrix — the 2026-03-09 assessment
// ---------------------------------------------------------------------------

/// Build the canonical gap matrix from the 2026-03-09 codebase assessment.
pub fn build_canonical_gap_matrix() -> GapMatrix {
    fn cell(s: SurfaceId, c: CapabilityId, cov: CoverageLevel, n: &str) -> GapCell {
        GapCell {
            surface: s,
            capability: c,
            coverage: cov,
            notes: n.to_string(),
        }
    }

    let assessments = vec![
        // --- LabRuntime ---
        SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            vec![
                cell(
                    SurfaceId::LabRuntime,
                    CapabilityId::VirtualTime,
                    CoverageLevel::Covered,
                    "VirtualClock advances in ticks; deterministic",
                ),
                cell(
                    SurfaceId::LabRuntime,
                    CapabilityId::ScheduleReplay,
                    CoverageLevel::Covered,
                    "ScheduleTranscript + replay_transcript()",
                ),
                cell(
                    SurfaceId::LabRuntime,
                    CapabilityId::FaultInjection,
                    CoverageLevel::Covered,
                    "5 FaultKind variants: Panic, ChannelDisconnect, ObligationLeak, DeadlineExpired, RegionClose",
                ),
                cell(
                    SurfaceId::LabRuntime,
                    CapabilityId::CancellationInjection,
                    CoverageLevel::Covered,
                    "inject_cancel(region_id)",
                ),
                cell(
                    SurfaceId::LabRuntime,
                    CapabilityId::TaskLifecycle,
                    CoverageLevel::Covered,
                    "spawn_task, run_task, complete_task, fault_task",
                ),
                cell(
                    SurfaceId::LabRuntime,
                    CapabilityId::ContentAddressedArtifacts,
                    CoverageLevel::Covered,
                    "LabRunResult with content hash",
                ),
            ],
            MigrationDecision::MaintainedWrapper,
            "LabRuntime is the core local harness with no upstream equivalent; maintain as-is with explicit API contract",
        ),
        // --- FrankenlabScenarios ---
        SurfaceAssessment::build(
            SurfaceId::FrankenlabScenarios,
            vec![
                cell(
                    SurfaceId::FrankenlabScenarios,
                    CapabilityId::ExtensionLifecycle,
                    CoverageLevel::Covered,
                    "7 ScenarioKind variants covering all lifecycle paths",
                ),
                cell(
                    SurfaceId::FrankenlabScenarios,
                    CapabilityId::TaskLifecycle,
                    CoverageLevel::Covered,
                    "Scenarios drive LabRuntime tasks",
                ),
                cell(
                    SurfaceId::FrankenlabScenarios,
                    CapabilityId::FaultInjection,
                    CoverageLevel::Partial,
                    "Scenarios inject faults but don't expose full FaultKind API",
                ),
                cell(
                    SurfaceId::FrankenlabScenarios,
                    CapabilityId::CancellationInjection,
                    CoverageLevel::Covered,
                    "Quarantine and ForcedCancel scenarios inject cancellation",
                ),
            ],
            MigrationDecision::ThinBridge,
            "Scenarios wrap LabRuntime; if upstream frankenlab adds richer scenarios, bridge existing ScenarioKind to upstream API",
        ),
        // --- InterleavingExplorer ---
        SurfaceAssessment::build(
            SurfaceId::InterleavingExplorer,
            vec![
                cell(
                    SurfaceId::InterleavingExplorer,
                    CapabilityId::RaceExploration,
                    CoverageLevel::Covered,
                    "Exhaustive, RandomWalk, TargetedRace strategies",
                ),
                cell(
                    SurfaceId::InterleavingExplorer,
                    CapabilityId::FaultInjection,
                    CoverageLevel::Covered,
                    "ScenarioAction includes InjectFault",
                ),
                cell(
                    SurfaceId::InterleavingExplorer,
                    CapabilityId::CancellationInjection,
                    CoverageLevel::Covered,
                    "ScenarioAction includes InjectCancel",
                ),
                cell(
                    SurfaceId::InterleavingExplorer,
                    CapabilityId::ContentAddressedArtifacts,
                    CoverageLevel::Partial,
                    "ExplorationReport has hash but not full artifact bundle",
                ),
            ],
            MigrationDecision::MaintainedWrapper,
            "No upstream interleaving explorer equivalent; maintain local implementation",
        ),
        // --- EvidenceReplayChecker ---
        SurfaceAssessment::build(
            SurfaceId::EvidenceReplayChecker,
            vec![
                cell(
                    SurfaceId::EvidenceReplayChecker,
                    CapabilityId::EvidenceChainValidation,
                    CoverageLevel::Covered,
                    "12 ReplayErrorCode variants for tamper/gap/divergence detection",
                ),
                cell(
                    SurfaceId::EvidenceReplayChecker,
                    CapabilityId::CrossMachineDeterminism,
                    CoverageLevel::Covered,
                    "verify_cross_machine_determinism()",
                ),
                cell(
                    SurfaceId::EvidenceReplayChecker,
                    CapabilityId::DivergenceDetection,
                    CoverageLevel::Covered,
                    "ReplayViolationType with outcome/calibration/expected-loss/fallback divergences",
                ),
                cell(
                    SurfaceId::EvidenceReplayChecker,
                    CapabilityId::ContentAddressedArtifacts,
                    CoverageLevel::Covered,
                    "ReplayEvidenceArtifact with content hash",
                ),
            ],
            MigrationDecision::ThinBridge,
            "Evidence replay is tightly coupled to franken-evidence/franken-decision crates; bridge to upstream if unified evidence API emerges",
        ),
        // --- DeterministicReplay ---
        SurfaceAssessment::build(
            SurfaceId::DeterministicReplay,
            vec![
                cell(
                    SurfaceId::DeterministicReplay,
                    CapabilityId::NondeterminismCapture,
                    CoverageLevel::Covered,
                    "6 NondeterminismSource variants + TraceEvent recording",
                ),
                cell(
                    SurfaceId::DeterministicReplay,
                    CapabilityId::ScheduleReplay,
                    CoverageLevel::Covered,
                    "ReplayEngine with configurable mode",
                ),
                cell(
                    SurfaceId::DeterministicReplay,
                    CapabilityId::DivergenceDetection,
                    CoverageLevel::Covered,
                    "ReplayDivergence with 4 severity levels",
                ),
                cell(
                    SurfaceId::DeterministicReplay,
                    CapabilityId::FailoverManagement,
                    CoverageLevel::Covered,
                    "FailoverController with strategy and reason tracking",
                ),
                cell(
                    SurfaceId::DeterministicReplay,
                    CapabilityId::IncidentArtifacts,
                    CoverageLevel::Covered,
                    "IncidentBundle with BinaryTrace, DivergenceLog, etc.",
                ),
                cell(
                    SurfaceId::DeterministicReplay,
                    CapabilityId::CrossMachineDeterminism,
                    CoverageLevel::Covered,
                    "verify_cross_machine_determinism()",
                ),
            ],
            MigrationDecision::MaintainedWrapper,
            "Nondeterminism capture is engine-specific; no upstream equivalent expected",
        ),
        // --- SimScheduler ---
        SurfaceAssessment::build(
            SurfaceId::SimScheduler,
            vec![
                cell(
                    SurfaceId::SimScheduler,
                    CapabilityId::EventSimulation,
                    CoverageLevel::Covered,
                    "12 SimEventKind variants for event-loop/module/cache/controller",
                ),
                cell(
                    SurfaceId::SimScheduler,
                    CapabilityId::PriorityDispatch,
                    CoverageLevel::Covered,
                    "SimPriority with microtask drain-first policy",
                ),
                cell(
                    SurfaceId::SimScheduler,
                    CapabilityId::ScheduleReplay,
                    CoverageLevel::Covered,
                    "SimReplayLog with deterministic entries",
                ),
                cell(
                    SurfaceId::SimScheduler,
                    CapabilityId::ContentAddressedArtifacts,
                    CoverageLevel::Covered,
                    "content_hash() on scheduler state",
                ),
            ],
            MigrationDecision::MaintainedWrapper,
            "Simulation scheduler is engine-specific; no upstream equivalent expected",
        ),
        // --- ReleaseGate ---
        SurfaceAssessment::build(
            SurfaceId::ReleaseGate,
            vec![
                cell(
                    SurfaceId::ReleaseGate,
                    CapabilityId::FailClosedGating,
                    CoverageLevel::Covered,
                    "4 GateKind checks with fail-closed semantics",
                ),
                cell(
                    SurfaceId::ReleaseGate,
                    CapabilityId::ObligationResolution,
                    CoverageLevel::Covered,
                    "ObligationResolution gate kind",
                ),
                cell(
                    SurfaceId::ReleaseGate,
                    CapabilityId::EvidenceChainValidation,
                    CoverageLevel::Partial,
                    "Delegates to EvidenceReplayChecker but doesn't expose full violation detail in GateReport",
                ),
                cell(
                    SurfaceId::ReleaseGate,
                    CapabilityId::ContentAddressedArtifacts,
                    CoverageLevel::Covered,
                    "GateReport with evidence hash",
                ),
            ],
            MigrationDecision::ThinBridge,
            "Release gate orchestrates other surfaces; bridge to upstream if frankenlab provides a unified gate runner",
        ),
    ];

    GapMatrix::build(assessments)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_is_stable() {
        assert_eq!(
            GAP_MATRIX_SCHEMA_VERSION,
            "franken-engine.frankenlab-gap-matrix.v1"
        );
    }

    #[test]
    fn component_constant() {
        assert_eq!(COMPONENT, "frankenlab_surface_gap_matrix");
    }

    #[test]
    fn bead_id_constant() {
        assert_eq!(BEAD_ID, "bd-3nr.1.1.2");
    }

    #[test]
    fn surface_id_display() {
        assert_eq!(format!("{}", SurfaceId::LabRuntime), "lab_runtime");
        assert_eq!(format!("{}", SurfaceId::ReleaseGate), "release_gate");
    }

    #[test]
    fn surface_id_all_has_seven() {
        assert_eq!(SurfaceId::ALL.len(), 7);
    }

    #[test]
    fn surface_id_source_files() {
        for s in SurfaceId::ALL {
            let f = s.source_file();
            assert!(f.starts_with("src/"), "bad source file for {s}");
            assert!(f.ends_with(".rs"), "bad extension for {s}");
        }
    }

    #[test]
    fn coverage_level_ordering() {
        assert!(CoverageLevel::Covered < CoverageLevel::Partial);
        assert!(CoverageLevel::Partial < CoverageLevel::Missing);
        assert!(CoverageLevel::Missing < CoverageLevel::LocalOnly);
    }

    #[test]
    fn coverage_level_display() {
        assert_eq!(format!("{}", CoverageLevel::Covered), "covered");
        assert_eq!(format!("{}", CoverageLevel::Missing), "missing");
    }

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
    }

    #[test]
    fn gap_cell_display() {
        let c = GapCell {
            surface: SurfaceId::LabRuntime,
            capability: CapabilityId::VirtualTime,
            coverage: CoverageLevel::Covered,
            notes: "good".to_string(),
        };
        let s = format!("{}", c);
        assert!(s.contains("lab_runtime"));
        assert!(s.contains("covered"));
    }

    #[test]
    fn surface_assessment_build_counts() {
        let cells = vec![
            GapCell {
                surface: SurfaceId::LabRuntime,
                capability: CapabilityId::VirtualTime,
                coverage: CoverageLevel::Covered,
                notes: String::new(),
            },
            GapCell {
                surface: SurfaceId::LabRuntime,
                capability: CapabilityId::FaultInjection,
                coverage: CoverageLevel::Partial,
                notes: String::new(),
            },
            GapCell {
                surface: SurfaceId::LabRuntime,
                capability: CapabilityId::RaceExploration,
                coverage: CoverageLevel::Missing,
                notes: String::new(),
            },
        ];
        let a = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            cells,
            MigrationDecision::ThinBridge,
            "test",
        );
        assert_eq!(a.covered_count, 1);
        assert_eq!(a.partial_count, 1);
        assert_eq!(a.missing_count, 1);
        assert_eq!(a.local_only_count, 0);
    }

    #[test]
    fn surface_assessment_coverage_rate() {
        let cells = vec![
            GapCell {
                surface: SurfaceId::LabRuntime,
                capability: CapabilityId::VirtualTime,
                coverage: CoverageLevel::Covered,
                notes: String::new(),
            },
            GapCell {
                surface: SurfaceId::LabRuntime,
                capability: CapabilityId::FaultInjection,
                coverage: CoverageLevel::Covered,
                notes: String::new(),
            },
        ];
        let a = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            cells,
            MigrationDecision::DirectAdoption,
            "full coverage",
        );
        assert_eq!(a.coverage_rate_millionths(), 1_000_000);
    }

    #[test]
    fn surface_assessment_coverage_rate_partial() {
        let cells = vec![
            GapCell {
                surface: SurfaceId::LabRuntime,
                capability: CapabilityId::VirtualTime,
                coverage: CoverageLevel::Covered,
                notes: String::new(),
            },
            GapCell {
                surface: SurfaceId::LabRuntime,
                capability: CapabilityId::FaultInjection,
                coverage: CoverageLevel::Partial,
                notes: String::new(),
            },
        ];
        let a = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            cells,
            MigrationDecision::ThinBridge,
            "partial",
        );
        assert_eq!(a.coverage_rate_millionths(), 750_000); // (1M + 500K) / 2
    }

    #[test]
    fn surface_assessment_coverage_rate_empty() {
        let a = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            vec![],
            MigrationDecision::DirectAdoption,
            "empty",
        );
        assert_eq!(a.coverage_rate_millionths(), 1_000_000);
    }

    #[test]
    fn surface_assessment_display() {
        let a = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            vec![],
            MigrationDecision::MaintainedWrapper,
            "test",
        );
        let s = format!("{}", a);
        assert!(s.contains("lab_runtime"));
        assert!(s.contains("maintained_wrapper"));
    }

    #[test]
    fn gap_matrix_empty() {
        let m = GapMatrix::build(vec![]);
        assert_eq!(m.summary.total_surfaces, 0);
        assert!(!m.has_gaps());
    }

    #[test]
    fn gap_matrix_for_surface() {
        let a = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            vec![],
            MigrationDecision::MaintainedWrapper,
            "test",
        );
        let m = GapMatrix::build(vec![a]);
        assert!(m.for_surface(SurfaceId::LabRuntime).is_some());
        assert!(m.for_surface(SurfaceId::SimScheduler).is_none());
    }

    #[test]
    fn gap_matrix_has_gaps() {
        let cells = vec![GapCell {
            surface: SurfaceId::LabRuntime,
            capability: CapabilityId::VirtualTime,
            coverage: CoverageLevel::Missing,
            notes: String::new(),
        }];
        let a = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            cells,
            MigrationDecision::ThinBridge,
            "gap",
        );
        let m = GapMatrix::build(vec![a]);
        assert!(m.has_gaps());
    }

    #[test]
    fn gap_matrix_surfaces_with_decision() {
        let a1 = SurfaceAssessment::build(
            SurfaceId::LabRuntime,
            vec![],
            MigrationDecision::MaintainedWrapper,
            "",
        );
        let a2 = SurfaceAssessment::build(
            SurfaceId::ReleaseGate,
            vec![],
            MigrationDecision::ThinBridge,
            "",
        );
        let m = GapMatrix::build(vec![a1, a2]);
        let wrappers = m.surfaces_with_decision(MigrationDecision::MaintainedWrapper);
        assert_eq!(wrappers, vec![SurfaceId::LabRuntime]);
    }

    #[test]
    fn gap_matrix_hash_deterministic() {
        let m1 = build_canonical_gap_matrix();
        let m2 = build_canonical_gap_matrix();
        assert_eq!(m1.matrix_hash, m2.matrix_hash);
    }

    #[test]
    fn gap_matrix_display() {
        let m = build_canonical_gap_matrix();
        let s = format!("{}", m);
        assert!(s.contains("Frankenlab Surface Gap Matrix"));
        assert!(s.contains("Surfaces: 7"));
    }

    #[test]
    fn canonical_matrix_has_seven_surfaces() {
        let m = build_canonical_gap_matrix();
        assert_eq!(m.summary.total_surfaces, 7);
    }

    #[test]
    fn canonical_matrix_no_direct_adoption() {
        let m = build_canonical_gap_matrix();
        assert_eq!(m.summary.direct_adoption_count, 0);
    }

    #[test]
    fn canonical_matrix_decisions_breakdown() {
        let m = build_canonical_gap_matrix();
        assert_eq!(m.summary.thin_bridge_count, 3);
        assert_eq!(m.summary.maintained_wrapper_count, 4);
    }

    #[test]
    fn canonical_matrix_coverage_cells() {
        let m = build_canonical_gap_matrix();
        assert!(m.summary.covered_cells > 0);
        assert!(m.summary.total_cells > 20);
    }

    #[test]
    fn canonical_matrix_partial_cells_exist() {
        let m = build_canonical_gap_matrix();
        assert!(m.summary.partial_cells > 0);
    }

    #[test]
    fn canonical_matrix_no_missing_cells() {
        let m = build_canonical_gap_matrix();
        // All capabilities are covered or partial; none missing
        assert_eq!(m.summary.missing_cells, 0);
    }

    #[test]
    fn canonical_matrix_lab_runtime_maintained() {
        let m = build_canonical_gap_matrix();
        let a = m.for_surface(SurfaceId::LabRuntime).unwrap();
        assert_eq!(a.decision, MigrationDecision::MaintainedWrapper);
    }

    #[test]
    fn canonical_matrix_release_gate_bridge() {
        let m = build_canonical_gap_matrix();
        let a = m.for_surface(SurfaceId::ReleaseGate).unwrap();
        assert_eq!(a.decision, MigrationDecision::ThinBridge);
    }

    #[test]
    fn canonical_matrix_serde_roundtrip() {
        let m = build_canonical_gap_matrix();
        let json = serde_json::to_string(&m).unwrap();
        let m2: GapMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn surface_id_serde_roundtrip() {
        for s in SurfaceId::ALL {
            let json = serde_json::to_string(&s).unwrap();
            let s2: SurfaceId = serde_json::from_str(&json).unwrap();
            assert_eq!(s, s2);
        }
    }

    #[test]
    fn coverage_level_serde_roundtrip() {
        for c in [
            CoverageLevel::Covered,
            CoverageLevel::Partial,
            CoverageLevel::Missing,
            CoverageLevel::LocalOnly,
        ] {
            let json = serde_json::to_string(&c).unwrap();
            let c2: CoverageLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(c, c2);
        }
    }

    #[test]
    fn migration_decision_serde_roundtrip() {
        for d in [
            MigrationDecision::DirectAdoption,
            MigrationDecision::ThinBridge,
            MigrationDecision::MaintainedWrapper,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let d2: MigrationDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, d2);
        }
    }

    #[test]
    fn capability_id_display_not_empty() {
        let c = CapabilityId::VirtualTime;
        let s = format!("{}", c);
        assert!(!s.is_empty());
    }
}
