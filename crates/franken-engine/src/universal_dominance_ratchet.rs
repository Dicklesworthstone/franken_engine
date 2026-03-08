#![forbid(unsafe_code)]

//! Universal-dominance ratchet and open-world frontier-gap ledger.
//!
//! Bead: bd-1lsy.1.6.4 [RGC-016D]
//!
//! The ratchet enforces monotonic forward progress on the supremacy board:
//! once a cell is proven, it can never regress. The frontier-gap ledger
//! tracks dimensions that are not yet claimed, providing an open-world
//! map of the unknown that drives corpus expansion and adversarial probing.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

pub const UNIVERSAL_DOMINANCE_RATCHET_SCHEMA_VERSION: &str =
    "franken-engine.universal-dominance-ratchet.v1";
pub const UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID: &str = "bd-1lsy.1.6.4";
pub const RATCHET_BOARD_SCHEMA_VERSION: &str = "franken-engine.ratchet-board.v1";
pub const FRONTIER_GAP_LEDGER_SCHEMA_VERSION: &str = "franken-engine.frontier-gap-ledger.v1";
pub const RATCHET_EVENT_LOG_SCHEMA_VERSION: &str = "franken-engine.ratchet-event-log.v1";
pub const DOMINANCE_SNAPSHOT_SCHEMA_VERSION: &str = "franken-engine.dominance-snapshot.v1";

// ---------------------------------------------------------------------------
// Cell identity and classification
// ---------------------------------------------------------------------------

/// Domain of a supremacy cell on the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellDomain {
    /// Cold-start latency measurements.
    ColdStart,
    /// Steady-state throughput measurements.
    Throughput,
    /// Tail-latency (p99/p999) measurements.
    TailLatency,
    /// Memory footprint measurements.
    Memory,
    /// React SSR/hydration measurements.
    ReactPerformance,
    /// Module resolution/loading measurements.
    ModuleLoading,
    /// TypeScript compilation measurements.
    TypeScriptCompilation,
    /// Security containment overhead measurements.
    SecurityOverhead,
    /// Deterministic replay fidelity measurements.
    ReplayFidelity,
    /// Extension isolation overhead.
    ExtensionIsolation,
}

impl fmt::Display for CellDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ColdStart => "cold_start",
            Self::Throughput => "throughput",
            Self::TailLatency => "tail_latency",
            Self::Memory => "memory",
            Self::ReactPerformance => "react_performance",
            Self::ModuleLoading => "module_loading",
            Self::TypeScriptCompilation => "typescript_compilation",
            Self::SecurityOverhead => "security_overhead",
            Self::ReplayFidelity => "replay_fidelity",
            Self::ExtensionIsolation => "extension_isolation",
        };
        write!(f, "{label}")
    }
}

/// Comparison target that a cell is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonTarget {
    /// V8 / Node.js baseline.
    V8Node,
    /// Bun runtime baseline.
    Bun,
    /// Deno runtime baseline.
    Deno,
    /// JavaScriptCore baseline.
    Jsc,
}

impl fmt::Display for ComparisonTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::V8Node => "v8_node",
            Self::Bun => "bun",
            Self::Deno => "deno",
            Self::Jsc => "jsc",
        };
        write!(f, "{label}")
    }
}

/// Unique identity of a cell on the supremacy board.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CellId {
    /// The domain this cell measures.
    pub domain: CellDomain,
    /// The comparison target.
    pub target: ComparisonTarget,
    /// Sub-dimension label (e.g., "100-module", "ssr-hydration").
    pub dimension: String,
}

impl fmt::Display for CellId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.domain, self.target, self.dimension)
    }
}

// ---------------------------------------------------------------------------
// Cell state machine
// ---------------------------------------------------------------------------

/// State of a single cell on the supremacy board.
/// Transitions are monotonic: Unproven → Claimed → Proven.
/// Regression is rejected by the ratchet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellState {
    /// No evidence has been submitted for this cell.
    Unproven,
    /// Evidence has been submitted but not yet verified to publication standard.
    Claimed,
    /// Evidence has been verified and the cell is locked.
    Proven,
}

impl CellState {
    /// Returns the ordinal rank for monotonicity checks.
    fn rank(self) -> u8 {
        match self {
            Self::Unproven => 0,
            Self::Claimed => 1,
            Self::Proven => 2,
        }
    }

    /// Returns true if transitioning from `self` to `next` is a valid
    /// forward step (or no-op equality).
    pub fn can_advance_to(self, next: Self) -> bool {
        next.rank() >= self.rank()
    }
}

impl fmt::Display for CellState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unproven => "unproven",
            Self::Claimed => "claimed",
            Self::Proven => "proven",
        };
        write!(f, "{label}")
    }
}

/// A single cell on the supremacy board with its current state and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetCell {
    /// Identity of this cell.
    pub cell_id: CellId,
    /// Current state (monotonically forward).
    pub state: CellState,
    /// Margin of victory in fixed-point millionths (1_000_000 = 100%).
    /// Positive means FrankenEngine wins. Zero if unproven.
    pub margin_millionths: i64,
    /// Evidence artifact IDs supporting the current state.
    pub evidence_ids: Vec<String>,
    /// Epoch at which the cell was last advanced.
    pub last_advanced_epoch: u64,
    /// Owning bead ID (for provenance).
    pub owning_bead: String,
}

// ---------------------------------------------------------------------------
// Ratchet board
// ---------------------------------------------------------------------------

/// The full supremacy board. Each cell can only move forward.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetBoard {
    /// Schema version for serde stability.
    pub schema_version: String,
    /// Bead ID for provenance.
    pub bead_id: String,
    /// Current epoch (monotonically increasing).
    pub current_epoch: u64,
    /// All cells on the board, keyed by serialized CellId.
    /// We use Vec instead of BTreeMap<CellId, RatchetCell> because
    /// composite keys fail JSON serde ("key must be a string").
    pub cells: Vec<RatchetCell>,
}

impl RatchetBoard {
    /// Create an empty board at epoch 0.
    pub fn new() -> Self {
        Self {
            schema_version: RATCHET_BOARD_SCHEMA_VERSION.to_string(),
            bead_id: UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID.to_string(),
            current_epoch: 0,
            cells: Vec::new(),
        }
    }

    /// Find a cell by its ID.
    pub fn find_cell(&self, cell_id: &CellId) -> Option<&RatchetCell> {
        self.cells.iter().find(|cell| cell.cell_id == *cell_id)
    }

    /// Find a mutable cell by its ID.
    fn find_cell_mut(&mut self, cell_id: &CellId) -> Option<&mut RatchetCell> {
        self.cells.iter_mut().find(|cell| cell.cell_id == *cell_id)
    }

    /// Count cells in each state.
    pub fn state_counts(&self) -> BTreeMap<CellState, usize> {
        let mut counts = BTreeMap::new();
        for cell in &self.cells {
            *counts.entry(cell.state).or_insert(0) += 1;
        }
        counts
    }

    /// Total number of cells on the board.
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Number of cells in the Proven state.
    pub fn proven_count(&self) -> usize {
        self.cells
            .iter()
            .filter(|cell| cell.state == CellState::Proven)
            .count()
    }

    /// Dominance fraction in fixed-point millionths.
    /// Returns 0 if the board is empty.
    pub fn dominance_fraction_millionths(&self) -> u64 {
        if self.cells.is_empty() {
            return 0;
        }
        let proven = self.proven_count() as u64;
        let total = self.cells.len() as u64;
        proven * 1_000_000 / total
    }
}

impl Default for RatchetBoard {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Ratchet errors
// ---------------------------------------------------------------------------

/// Errors that can occur during ratchet operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RatchetError {
    /// Attempted to regress a cell to a lower state.
    RegressionRejected {
        cell_id: CellId,
        current_state: CellState,
        attempted_state: CellState,
    },
    /// Attempted to reduce the margin of a proven cell.
    MarginRegressionRejected {
        cell_id: CellId,
        current_margin: i64,
        attempted_margin: i64,
    },
    /// Attempted to advance the epoch backwards.
    EpochRegression {
        current_epoch: u64,
        attempted_epoch: u64,
    },
    /// Cell not found on the board.
    CellNotFound { cell_id: CellId },
    /// Gap not found in the ledger.
    GapNotFound { gap_id: String },
    /// Gap already closed.
    GapAlreadyClosed { gap_id: String },
    /// Duplicate cell ID on the board.
    DuplicateCell { cell_id: CellId },
    /// Duplicate gap ID in the ledger.
    DuplicateGap { gap_id: String },
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegressionRejected {
                cell_id,
                current_state,
                attempted_state,
            } => {
                write!(
                    f,
                    "ratchet regression rejected: cell {cell_id} is {current_state}, \
                     cannot move to {attempted_state}"
                )
            }
            Self::MarginRegressionRejected {
                cell_id,
                current_margin,
                attempted_margin,
            } => {
                write!(
                    f,
                    "margin regression rejected: cell {cell_id} margin {current_margin} \
                     cannot decrease to {attempted_margin}"
                )
            }
            Self::EpochRegression {
                current_epoch,
                attempted_epoch,
            } => {
                write!(
                    f,
                    "epoch regression: current {current_epoch}, attempted {attempted_epoch}"
                )
            }
            Self::CellNotFound { cell_id } => {
                write!(f, "cell not found: {cell_id}")
            }
            Self::GapNotFound { gap_id } => {
                write!(f, "gap not found: {gap_id}")
            }
            Self::GapAlreadyClosed { gap_id } => {
                write!(f, "gap already closed: {gap_id}")
            }
            Self::DuplicateCell { cell_id } => {
                write!(f, "duplicate cell: {cell_id}")
            }
            Self::DuplicateGap { gap_id } => {
                write!(f, "duplicate gap: {gap_id}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Ratchet events (audit log)
// ---------------------------------------------------------------------------

/// Audit event for a ratchet operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetEvent {
    /// Monotonic sequence number within the event log.
    pub sequence: u64,
    /// Epoch at which this event occurred.
    pub epoch: u64,
    /// The kind of operation.
    pub kind: RatchetEventKind,
}

/// Classification of ratchet events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RatchetEventKind {
    /// A new cell was added to the board.
    CellAdded { cell_id: CellId },
    /// A cell was advanced to a higher state.
    CellAdvanced {
        cell_id: CellId,
        from_state: CellState,
        to_state: CellState,
        margin_millionths: i64,
        evidence_ids: Vec<String>,
    },
    /// A regression attempt was rejected.
    RegressionRejected {
        cell_id: CellId,
        current_state: CellState,
        attempted_state: CellState,
    },
    /// A new frontier gap was registered.
    GapRegistered { gap_id: String },
    /// A frontier gap was closed.
    GapClosed {
        gap_id: String,
        resolution: GapResolution,
    },
    /// The epoch was advanced.
    EpochAdvanced { from_epoch: u64, to_epoch: u64 },
    /// Board snapshot was taken for a dominance assessment.
    DominanceAssessed {
        proven_count: usize,
        total_count: usize,
        fraction_millionths: u64,
    },
}

// ---------------------------------------------------------------------------
// Frontier gap ledger
// ---------------------------------------------------------------------------

/// Classification of a frontier gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// Dimension is completely unexplored — no workloads or benchmarks exist.
    Unknown,
    /// Some preliminary evidence exists but is insufficient for a claim.
    PartiallyExplored,
    /// Active evidence shows FrankenEngine is currently behind the target.
    KnownDeficient,
    /// Dimension was explored but declared out of scope.
    OutOfScope,
}

impl fmt::Display for GapKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unknown => "unknown",
            Self::PartiallyExplored => "partially_explored",
            Self::KnownDeficient => "known_deficient",
            Self::OutOfScope => "out_of_scope",
        };
        write!(f, "{label}")
    }
}

/// How a gap was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapResolution {
    /// The gap was closed by proving the claim.
    ProvenOnBoard,
    /// The gap was closed by declaring it out of scope.
    DeclaredOutOfScope,
    /// The gap was subsumed by another dimension's proof.
    SubsumedByOther,
    /// The gap was closed by showing the dimension is not meaningful.
    DimensionInvalidated,
}

impl fmt::Display for GapResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ProvenOnBoard => "proven_on_board",
            Self::DeclaredOutOfScope => "declared_out_of_scope",
            Self::SubsumedByOther => "subsumed_by_other",
            Self::DimensionInvalidated => "dimension_invalidated",
        };
        write!(f, "{label}")
    }
}

/// State of a frontier gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapState {
    /// Gap is open and needs attention.
    Open,
    /// Gap has been closed with a resolution.
    Closed,
}

impl fmt::Display for GapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Open => "open",
            Self::Closed => "closed",
        };
        write!(f, "{label}")
    }
}

/// A single entry in the frontier-gap ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierGapEntry {
    /// Unique gap identifier.
    pub gap_id: String,
    /// Classification of the gap.
    pub kind: GapKind,
    /// Current state.
    pub state: GapState,
    /// The domain this gap relates to.
    pub domain: CellDomain,
    /// Optional comparison target if the gap is target-specific.
    pub target: Option<ComparisonTarget>,
    /// Human-readable description of the gap.
    pub description: String,
    /// Epoch at which this gap was registered.
    pub registered_epoch: u64,
    /// Epoch at which this gap was closed (if applicable).
    pub closed_epoch: Option<u64>,
    /// Resolution method (if closed).
    pub resolution: Option<GapResolution>,
    /// Discovery source (which bead, campaign, or user identified this gap).
    pub discovery_source: String,
    /// Priority in fixed-point millionths (1_000_000 = highest).
    pub priority_millionths: u32,
}

/// The open-world frontier-gap ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierGapLedger {
    /// Schema version for serde stability.
    pub schema_version: String,
    /// Bead ID for provenance.
    pub bead_id: String,
    /// All gap entries.
    pub entries: Vec<FrontierGapEntry>,
}

impl FrontierGapLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self {
            schema_version: FRONTIER_GAP_LEDGER_SCHEMA_VERSION.to_string(),
            bead_id: UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID.to_string(),
            entries: Vec::new(),
        }
    }

    /// Find a gap by its ID.
    pub fn find_gap(&self, gap_id: &str) -> Option<&FrontierGapEntry> {
        self.entries.iter().find(|entry| entry.gap_id == gap_id)
    }

    /// Find a mutable gap by its ID.
    fn find_gap_mut(&mut self, gap_id: &str) -> Option<&mut FrontierGapEntry> {
        self.entries.iter_mut().find(|entry| entry.gap_id == gap_id)
    }

    /// Count open gaps.
    pub fn open_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state == GapState::Open)
            .count()
    }

    /// Count closed gaps.
    pub fn closed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.state == GapState::Closed)
            .count()
    }

    /// Count gaps by kind (open only).
    pub fn open_gap_kinds(&self) -> BTreeMap<GapKind, usize> {
        let mut counts = BTreeMap::new();
        for entry in &self.entries {
            if entry.state == GapState::Open {
                *counts.entry(entry.kind).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Return open gaps sorted by priority (highest first).
    pub fn open_gaps_by_priority(&self) -> Vec<&FrontierGapEntry> {
        let mut gaps: Vec<&FrontierGapEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.state == GapState::Open)
            .collect();
        gaps.sort_by_key(|g| std::cmp::Reverse(g.priority_millionths));
        gaps
    }
}

impl Default for FrontierGapLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Dominance snapshot (point-in-time assessment)
// ---------------------------------------------------------------------------

/// Point-in-time dominance assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DominanceSnapshot {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Epoch at which this snapshot was taken.
    pub epoch: u64,
    /// Total cells on the board.
    pub total_cells: usize,
    /// Cells in Proven state.
    pub proven_cells: usize,
    /// Cells in Claimed state.
    pub claimed_cells: usize,
    /// Cells in Unproven state.
    pub unproven_cells: usize,
    /// Dominance fraction in fixed-point millionths.
    pub dominance_fraction_millionths: u64,
    /// Open frontier gaps.
    pub open_gap_count: usize,
    /// Closed frontier gaps.
    pub closed_gap_count: usize,
    /// Whether universal dominance has been achieved (all cells proven, no open gaps).
    pub universal_dominance_achieved: bool,
    /// Per-domain breakdown of proven cell counts.
    pub domain_proven_counts: Vec<DomainProvenCount>,
    /// Per-target breakdown of proven cell counts.
    pub target_proven_counts: Vec<TargetProvenCount>,
}

/// Per-domain breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainProvenCount {
    pub domain: CellDomain,
    pub proven: usize,
    pub total: usize,
}

/// Per-target breakdown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetProvenCount {
    pub target: ComparisonTarget,
    pub proven: usize,
    pub total: usize,
}

// ---------------------------------------------------------------------------
// Ratchet event log
// ---------------------------------------------------------------------------

/// Immutable event log for the ratchet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetEventLog {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// All events in sequence order.
    pub events: Vec<RatchetEvent>,
    /// Next sequence number.
    pub next_sequence: u64,
}

impl RatchetEventLog {
    /// Create an empty event log.
    pub fn new() -> Self {
        Self {
            schema_version: RATCHET_EVENT_LOG_SCHEMA_VERSION.to_string(),
            bead_id: UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID.to_string(),
            events: Vec::new(),
            next_sequence: 0,
        }
    }

    /// Append an event.
    fn push(&mut self, epoch: u64, kind: RatchetEventKind) {
        self.events.push(RatchetEvent {
            sequence: self.next_sequence,
            epoch,
            kind,
        });
        self.next_sequence += 1;
    }
}

impl Default for RatchetEventLog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Core ratchet operations
// ---------------------------------------------------------------------------

/// Add a new cell to the board. Rejects duplicate cell IDs.
pub fn add_cell(
    board: &mut RatchetBoard,
    log: &mut RatchetEventLog,
    cell: RatchetCell,
) -> Result<(), RatchetError> {
    if board.find_cell(&cell.cell_id).is_some() {
        return Err(RatchetError::DuplicateCell {
            cell_id: cell.cell_id,
        });
    }
    let cell_id = cell.cell_id.clone();
    board.cells.push(cell);
    log.push(board.current_epoch, RatchetEventKind::CellAdded { cell_id });
    Ok(())
}

/// Advance a cell to a higher state. Rejects regressions.
pub fn advance_cell(
    board: &mut RatchetBoard,
    log: &mut RatchetEventLog,
    cell_id: &CellId,
    new_state: CellState,
    margin_millionths: i64,
    evidence_ids: Vec<String>,
) -> Result<(), RatchetError> {
    // Read epoch before taking a mutable borrow on the cells vec.
    let epoch = board.current_epoch;

    let cell = board
        .find_cell_mut(cell_id)
        .ok_or_else(|| RatchetError::CellNotFound {
            cell_id: cell_id.clone(),
        })?;

    if !cell.state.can_advance_to(new_state) {
        let current = cell.state;
        log.push(
            epoch,
            RatchetEventKind::RegressionRejected {
                cell_id: cell_id.clone(),
                current_state: current,
                attempted_state: new_state,
            },
        );
        return Err(RatchetError::RegressionRejected {
            cell_id: cell_id.clone(),
            current_state: current,
            attempted_state: new_state,
        });
    }

    // For proven cells, margin cannot decrease.
    if cell.state == CellState::Proven && margin_millionths < cell.margin_millionths {
        return Err(RatchetError::MarginRegressionRejected {
            cell_id: cell_id.clone(),
            current_margin: cell.margin_millionths,
            attempted_margin: margin_millionths,
        });
    }

    let from_state = cell.state;
    cell.state = new_state;
    cell.margin_millionths = margin_millionths;
    cell.evidence_ids.extend(evidence_ids.clone());
    cell.last_advanced_epoch = epoch;

    log.push(
        epoch,
        RatchetEventKind::CellAdvanced {
            cell_id: cell_id.clone(),
            from_state,
            to_state: new_state,
            margin_millionths,
            evidence_ids,
        },
    );

    Ok(())
}

/// Advance the board epoch. Rejects epoch regression.
pub fn advance_epoch(
    board: &mut RatchetBoard,
    log: &mut RatchetEventLog,
    new_epoch: u64,
) -> Result<(), RatchetError> {
    if new_epoch <= board.current_epoch {
        return Err(RatchetError::EpochRegression {
            current_epoch: board.current_epoch,
            attempted_epoch: new_epoch,
        });
    }
    let from = board.current_epoch;
    board.current_epoch = new_epoch;
    log.push(
        new_epoch,
        RatchetEventKind::EpochAdvanced {
            from_epoch: from,
            to_epoch: new_epoch,
        },
    );
    Ok(())
}

/// Register a new frontier gap.
pub fn register_gap(
    ledger: &mut FrontierGapLedger,
    log: &mut RatchetEventLog,
    entry: FrontierGapEntry,
) -> Result<(), RatchetError> {
    if ledger.find_gap(&entry.gap_id).is_some() {
        return Err(RatchetError::DuplicateGap {
            gap_id: entry.gap_id,
        });
    }
    let gap_id = entry.gap_id.clone();
    let epoch = entry.registered_epoch;
    ledger.entries.push(entry);
    log.push(epoch, RatchetEventKind::GapRegistered { gap_id });
    Ok(())
}

/// Close a frontier gap with a resolution.
pub fn close_gap(
    ledger: &mut FrontierGapLedger,
    log: &mut RatchetEventLog,
    gap_id: &str,
    resolution: GapResolution,
    epoch: u64,
) -> Result<(), RatchetError> {
    let entry = ledger
        .find_gap_mut(gap_id)
        .ok_or_else(|| RatchetError::GapNotFound {
            gap_id: gap_id.to_string(),
        })?;

    if entry.state == GapState::Closed {
        return Err(RatchetError::GapAlreadyClosed {
            gap_id: gap_id.to_string(),
        });
    }

    entry.state = GapState::Closed;
    entry.closed_epoch = Some(epoch);
    entry.resolution = Some(resolution);

    log.push(
        epoch,
        RatchetEventKind::GapClosed {
            gap_id: gap_id.to_string(),
            resolution,
        },
    );

    Ok(())
}

/// Compute a point-in-time dominance snapshot.
pub fn compute_dominance_snapshot(
    board: &RatchetBoard,
    ledger: &FrontierGapLedger,
    log: &mut RatchetEventLog,
) -> DominanceSnapshot {
    let proven = board.proven_count();
    let total = board.cell_count();
    let fraction = board.dominance_fraction_millionths();

    // Per-domain breakdown
    let mut domain_map: BTreeMap<CellDomain, (usize, usize)> = BTreeMap::new();
    for cell in &board.cells {
        let entry = domain_map.entry(cell.cell_id.domain).or_insert((0, 0));
        entry.1 += 1;
        if cell.state == CellState::Proven {
            entry.0 += 1;
        }
    }
    let domain_proven_counts: Vec<DomainProvenCount> = domain_map
        .into_iter()
        .map(|(domain, (p, t))| DomainProvenCount {
            domain,
            proven: p,
            total: t,
        })
        .collect();

    // Per-target breakdown
    let mut target_map: BTreeMap<ComparisonTarget, (usize, usize)> = BTreeMap::new();
    for cell in &board.cells {
        let entry = target_map.entry(cell.cell_id.target).or_insert((0, 0));
        entry.1 += 1;
        if cell.state == CellState::Proven {
            entry.0 += 1;
        }
    }
    let target_proven_counts: Vec<TargetProvenCount> = target_map
        .into_iter()
        .map(|(target, (p, t))| TargetProvenCount {
            target,
            proven: p,
            total: t,
        })
        .collect();

    let open_gaps = ledger.open_count();
    let closed_gaps = ledger.closed_count();
    let claimed = board
        .cells
        .iter()
        .filter(|c| c.state == CellState::Claimed)
        .count();
    let unproven = board
        .cells
        .iter()
        .filter(|c| c.state == CellState::Unproven)
        .count();
    let universal = proven == total && total > 0 && open_gaps == 0;

    log.push(
        board.current_epoch,
        RatchetEventKind::DominanceAssessed {
            proven_count: proven,
            total_count: total,
            fraction_millionths: fraction,
        },
    );

    DominanceSnapshot {
        schema_version: DOMINANCE_SNAPSHOT_SCHEMA_VERSION.to_string(),
        bead_id: UNIVERSAL_DOMINANCE_RATCHET_BEAD_ID.to_string(),
        epoch: board.current_epoch,
        total_cells: total,
        proven_cells: proven,
        claimed_cells: claimed,
        unproven_cells: unproven,
        dominance_fraction_millionths: fraction,
        open_gap_count: open_gaps,
        closed_gap_count: closed_gaps,
        universal_dominance_achieved: universal,
        domain_proven_counts,
        target_proven_counts,
    }
}

/// Render a human-readable summary of the ratchet state.
pub fn render_ratchet_summary(board: &RatchetBoard, ledger: &FrontierGapLedger) -> String {
    let mut lines = vec![
        format!("schema_version: {}", board.schema_version),
        format!("epoch: {}", board.current_epoch),
        format!("total_cells: {}", board.cell_count()),
        format!("proven: {}", board.proven_count()),
        format!(
            "dominance: {:.4}%",
            board.dominance_fraction_millionths() as f64 / 10_000.0
        ),
        format!("open_gaps: {}", ledger.open_count()),
        format!("closed_gaps: {}", ledger.closed_count()),
    ];

    let state_counts = board.state_counts();
    for (state, count) in &state_counts {
        lines.push(format!("  {state}: {count}"));
    }

    let gap_kinds = ledger.open_gap_kinds();
    if !gap_kinds.is_empty() {
        lines.push("open_gap_kinds:".to_string());
        for (kind, count) in &gap_kinds {
            lines.push(format!("  {kind}: {count}"));
        }
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cell_id(domain: CellDomain, target: ComparisonTarget, dim: &str) -> CellId {
        CellId {
            domain,
            target,
            dimension: dim.to_string(),
        }
    }

    fn make_cell(domain: CellDomain, target: ComparisonTarget, dim: &str) -> RatchetCell {
        RatchetCell {
            cell_id: make_cell_id(domain, target, dim),
            state: CellState::Unproven,
            margin_millionths: 0,
            evidence_ids: Vec::new(),
            last_advanced_epoch: 0,
            owning_bead: "test".to_string(),
        }
    }

    fn make_gap(gap_id: &str, domain: CellDomain, kind: GapKind) -> FrontierGapEntry {
        FrontierGapEntry {
            gap_id: gap_id.to_string(),
            kind,
            state: GapState::Open,
            domain,
            target: None,
            description: format!("Test gap {gap_id}"),
            registered_epoch: 0,
            closed_epoch: None,
            resolution: None,
            discovery_source: "test".to_string(),
            priority_millionths: 500_000,
        }
    }

    // -- CellState --

    #[test]
    fn cell_state_monotonic_transitions() {
        assert!(CellState::Unproven.can_advance_to(CellState::Unproven));
        assert!(CellState::Unproven.can_advance_to(CellState::Claimed));
        assert!(CellState::Unproven.can_advance_to(CellState::Proven));
        assert!(CellState::Claimed.can_advance_to(CellState::Claimed));
        assert!(CellState::Claimed.can_advance_to(CellState::Proven));
        assert!(CellState::Proven.can_advance_to(CellState::Proven));
    }

    #[test]
    fn cell_state_rejects_regression() {
        assert!(!CellState::Proven.can_advance_to(CellState::Claimed));
        assert!(!CellState::Proven.can_advance_to(CellState::Unproven));
        assert!(!CellState::Claimed.can_advance_to(CellState::Unproven));
    }

    #[test]
    fn cell_state_display() {
        assert_eq!(CellState::Unproven.to_string(), "unproven");
        assert_eq!(CellState::Claimed.to_string(), "claimed");
        assert_eq!(CellState::Proven.to_string(), "proven");
    }

    // -- CellDomain Display --

    #[test]
    fn cell_domain_display() {
        assert_eq!(CellDomain::ColdStart.to_string(), "cold_start");
        assert_eq!(CellDomain::Throughput.to_string(), "throughput");
        assert_eq!(CellDomain::TailLatency.to_string(), "tail_latency");
        assert_eq!(CellDomain::Memory.to_string(), "memory");
        assert_eq!(
            CellDomain::ReactPerformance.to_string(),
            "react_performance"
        );
        assert_eq!(CellDomain::ModuleLoading.to_string(), "module_loading");
        assert_eq!(
            CellDomain::TypeScriptCompilation.to_string(),
            "typescript_compilation"
        );
        assert_eq!(
            CellDomain::SecurityOverhead.to_string(),
            "security_overhead"
        );
        assert_eq!(CellDomain::ReplayFidelity.to_string(), "replay_fidelity");
        assert_eq!(
            CellDomain::ExtensionIsolation.to_string(),
            "extension_isolation"
        );
    }

    // -- ComparisonTarget Display --

    #[test]
    fn comparison_target_display() {
        assert_eq!(ComparisonTarget::V8Node.to_string(), "v8_node");
        assert_eq!(ComparisonTarget::Bun.to_string(), "bun");
        assert_eq!(ComparisonTarget::Deno.to_string(), "deno");
        assert_eq!(ComparisonTarget::Jsc.to_string(), "jsc");
    }

    // -- CellId Display --

    #[test]
    fn cell_id_display() {
        let id = make_cell_id(
            CellDomain::ColdStart,
            ComparisonTarget::V8Node,
            "100-module",
        );
        assert_eq!(id.to_string(), "cold_start::v8_node::100-module");
    }

    // -- RatchetBoard --

    #[test]
    fn empty_board() {
        let board = RatchetBoard::new();
        assert_eq!(board.cell_count(), 0);
        assert_eq!(board.proven_count(), 0);
        assert_eq!(board.dominance_fraction_millionths(), 0);
    }

    #[test]
    fn add_cell_to_board() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "100-mod");
        assert!(add_cell(&mut board, &mut log, cell).is_ok());
        assert_eq!(board.cell_count(), 1);
        assert_eq!(log.events.len(), 1);
        assert!(matches!(
            log.events[0].kind,
            RatchetEventKind::CellAdded { .. }
        ));
    }

    #[test]
    fn reject_duplicate_cell() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell1 = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "dup");
        let cell2 = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "dup");
        assert!(add_cell(&mut board, &mut log, cell1).is_ok());
        let err = add_cell(&mut board, &mut log, cell2).unwrap_err();
        assert!(matches!(err, RatchetError::DuplicateCell { .. }));
    }

    // -- advance_cell --

    #[test]
    fn advance_cell_forward() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "fwd");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();

        assert!(
            advance_cell(
                &mut board,
                &mut log,
                &cell_id,
                CellState::Claimed,
                150_000,
                vec!["ev-1".to_string()],
            )
            .is_ok()
        );

        let found = board.find_cell(&cell_id).unwrap();
        assert_eq!(found.state, CellState::Claimed);
        assert_eq!(found.margin_millionths, 150_000);
        assert_eq!(found.evidence_ids, vec!["ev-1"]);
    }

    #[test]
    fn advance_cell_to_proven() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell = make_cell(CellDomain::Throughput, ComparisonTarget::Bun, "steady");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();

        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Claimed,
            100_000,
            vec!["ev-a".to_string()],
        )
        .unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Proven,
            200_000,
            vec!["ev-b".to_string()],
        )
        .unwrap();

        let found = board.find_cell(&cell_id).unwrap();
        assert_eq!(found.state, CellState::Proven);
        assert_eq!(found.margin_millionths, 200_000);
        assert_eq!(found.evidence_ids, vec!["ev-a", "ev-b"]);
        assert_eq!(board.proven_count(), 1);
    }

    #[test]
    fn reject_regression() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell = make_cell(CellDomain::Memory, ComparisonTarget::Deno, "footprint");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();

        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Proven,
            500_000,
            vec!["ev-x".to_string()],
        )
        .unwrap();

        let err = advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Claimed,
            400_000,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, RatchetError::RegressionRejected { .. }));
        // Cell should remain proven
        assert_eq!(board.find_cell(&cell_id).unwrap().state, CellState::Proven);
    }

    #[test]
    fn reject_margin_regression() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell = make_cell(CellDomain::TailLatency, ComparisonTarget::V8Node, "p99");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();

        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Proven,
            300_000,
            vec!["ev-p".to_string()],
        )
        .unwrap();

        let err = advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Proven,
            200_000,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, RatchetError::MarginRegressionRejected { .. }));
    }

    #[test]
    fn advance_cell_not_found() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell_id = make_cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "ghost");
        let err = advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Claimed,
            0,
            vec![],
        )
        .unwrap_err();
        assert!(matches!(err, RatchetError::CellNotFound { .. }));
    }

    // -- advance_epoch --

    #[test]
    fn advance_epoch_forward() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        assert!(advance_epoch(&mut board, &mut log, 1).is_ok());
        assert_eq!(board.current_epoch, 1);
        assert!(advance_epoch(&mut board, &mut log, 5).is_ok());
        assert_eq!(board.current_epoch, 5);
    }

    #[test]
    fn reject_epoch_regression() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        advance_epoch(&mut board, &mut log, 10).unwrap();
        let err = advance_epoch(&mut board, &mut log, 5).unwrap_err();
        assert!(matches!(err, RatchetError::EpochRegression { .. }));
    }

    #[test]
    fn reject_epoch_same() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        advance_epoch(&mut board, &mut log, 3).unwrap();
        let err = advance_epoch(&mut board, &mut log, 3).unwrap_err();
        assert!(matches!(err, RatchetError::EpochRegression { .. }));
    }

    // -- FrontierGapLedger --

    #[test]
    fn register_and_close_gap() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();
        let gap = make_gap("gap-1", CellDomain::ColdStart, GapKind::Unknown);
        assert!(register_gap(&mut ledger, &mut log, gap).is_ok());
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.open_count(), 1);

        assert!(
            close_gap(
                &mut ledger,
                &mut log,
                "gap-1",
                GapResolution::ProvenOnBoard,
                1,
            )
            .is_ok()
        );
        assert_eq!(ledger.open_count(), 0);
        assert_eq!(ledger.closed_count(), 1);
        let entry = ledger.find_gap("gap-1").unwrap();
        assert_eq!(entry.state, GapState::Closed);
        assert_eq!(entry.resolution, Some(GapResolution::ProvenOnBoard));
    }

    #[test]
    fn reject_duplicate_gap() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();
        let gap1 = make_gap("gap-dup", CellDomain::Memory, GapKind::PartiallyExplored);
        let gap2 = make_gap("gap-dup", CellDomain::Memory, GapKind::Unknown);
        register_gap(&mut ledger, &mut log, gap1).unwrap();
        let err = register_gap(&mut ledger, &mut log, gap2).unwrap_err();
        assert!(matches!(err, RatchetError::DuplicateGap { .. }));
    }

    #[test]
    fn close_nonexistent_gap() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();
        let err = close_gap(
            &mut ledger,
            &mut log,
            "ghost",
            GapResolution::DeclaredOutOfScope,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, RatchetError::GapNotFound { .. }));
    }

    #[test]
    fn close_already_closed_gap() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();
        let gap = make_gap("gap-2", CellDomain::Throughput, GapKind::KnownDeficient);
        register_gap(&mut ledger, &mut log, gap).unwrap();
        close_gap(
            &mut ledger,
            &mut log,
            "gap-2",
            GapResolution::SubsumedByOther,
            1,
        )
        .unwrap();
        let err = close_gap(
            &mut ledger,
            &mut log,
            "gap-2",
            GapResolution::ProvenOnBoard,
            2,
        )
        .unwrap_err();
        assert!(matches!(err, RatchetError::GapAlreadyClosed { .. }));
    }

    #[test]
    fn gap_priority_ordering() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();

        let mut gap_lo = make_gap("lo", CellDomain::ColdStart, GapKind::Unknown);
        gap_lo.priority_millionths = 100_000;
        let mut gap_hi = make_gap("hi", CellDomain::Memory, GapKind::KnownDeficient);
        gap_hi.priority_millionths = 900_000;
        let mut gap_mid = make_gap("mid", CellDomain::Throughput, GapKind::PartiallyExplored);
        gap_mid.priority_millionths = 500_000;

        register_gap(&mut ledger, &mut log, gap_lo).unwrap();
        register_gap(&mut ledger, &mut log, gap_hi).unwrap();
        register_gap(&mut ledger, &mut log, gap_mid).unwrap();

        let sorted = ledger.open_gaps_by_priority();
        assert_eq!(sorted[0].gap_id, "hi");
        assert_eq!(sorted[1].gap_id, "mid");
        assert_eq!(sorted[2].gap_id, "lo");
    }

    #[test]
    fn open_gap_kinds_count() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();

        register_gap(
            &mut ledger,
            &mut log,
            make_gap("g1", CellDomain::ColdStart, GapKind::Unknown),
        )
        .unwrap();
        register_gap(
            &mut ledger,
            &mut log,
            make_gap("g2", CellDomain::Memory, GapKind::Unknown),
        )
        .unwrap();
        register_gap(
            &mut ledger,
            &mut log,
            make_gap("g3", CellDomain::Throughput, GapKind::KnownDeficient),
        )
        .unwrap();

        let kinds = ledger.open_gap_kinds();
        assert_eq!(kinds.get(&GapKind::Unknown), Some(&2));
        assert_eq!(kinds.get(&GapKind::KnownDeficient), Some(&1));
    }

    // -- DominanceSnapshot --

    #[test]
    fn dominance_snapshot_all_proven() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let ledger = FrontierGapLedger::new();

        let cell = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "full");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Proven,
            1_000_000,
            vec!["ev-full".to_string()],
        )
        .unwrap();

        let snapshot = compute_dominance_snapshot(&board, &ledger, &mut log);
        assert!(snapshot.universal_dominance_achieved);
        assert_eq!(snapshot.dominance_fraction_millionths, 1_000_000);
        assert_eq!(snapshot.proven_cells, 1);
        assert_eq!(snapshot.total_cells, 1);
    }

    #[test]
    fn dominance_snapshot_with_gaps() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let mut ledger = FrontierGapLedger::new();

        let cell = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "partial");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Proven,
            500_000,
            vec![],
        )
        .unwrap();

        register_gap(
            &mut ledger,
            &mut log,
            make_gap("gap-block", CellDomain::Memory, GapKind::Unknown),
        )
        .unwrap();

        let snapshot = compute_dominance_snapshot(&board, &ledger, &mut log);
        assert!(!snapshot.universal_dominance_achieved);
        assert_eq!(snapshot.open_gap_count, 1);
    }

    #[test]
    fn dominance_snapshot_mixed_states() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let ledger = FrontierGapLedger::new();

        for (domain, target, dim) in [
            (CellDomain::ColdStart, ComparisonTarget::V8Node, "cs-1"),
            (CellDomain::Throughput, ComparisonTarget::Bun, "tp-1"),
            (CellDomain::Memory, ComparisonTarget::Deno, "mem-1"),
            (CellDomain::TailLatency, ComparisonTarget::Jsc, "tl-1"),
        ] {
            let cell = make_cell(domain, target, dim);
            add_cell(&mut board, &mut log, cell).unwrap();
        }

        // Prove 2 of 4
        let cs_id = make_cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "cs-1");
        let tp_id = make_cell_id(CellDomain::Throughput, ComparisonTarget::Bun, "tp-1");
        advance_cell(
            &mut board,
            &mut log,
            &cs_id,
            CellState::Proven,
            100_000,
            vec![],
        )
        .unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &tp_id,
            CellState::Claimed,
            50_000,
            vec![],
        )
        .unwrap();

        let snapshot = compute_dominance_snapshot(&board, &ledger, &mut log);
        assert_eq!(snapshot.proven_cells, 1);
        assert_eq!(snapshot.claimed_cells, 1);
        assert_eq!(snapshot.unproven_cells, 2);
        assert_eq!(snapshot.total_cells, 4);
        assert_eq!(snapshot.dominance_fraction_millionths, 250_000); // 1/4
        assert!(!snapshot.universal_dominance_achieved);
    }

    // -- render_ratchet_summary --

    #[test]
    fn summary_includes_key_fields() {
        let board = RatchetBoard::new();
        let ledger = FrontierGapLedger::new();
        let summary = render_ratchet_summary(&board, &ledger);
        assert!(summary.contains("schema_version:"));
        assert!(summary.contains("epoch: 0"));
        assert!(summary.contains("total_cells: 0"));
        assert!(summary.contains("proven: 0"));
        assert!(summary.contains("dominance:"));
    }

    // -- GapKind / GapResolution Display --

    #[test]
    fn gap_kind_display() {
        assert_eq!(GapKind::Unknown.to_string(), "unknown");
        assert_eq!(GapKind::PartiallyExplored.to_string(), "partially_explored");
        assert_eq!(GapKind::KnownDeficient.to_string(), "known_deficient");
        assert_eq!(GapKind::OutOfScope.to_string(), "out_of_scope");
    }

    #[test]
    fn gap_resolution_display() {
        assert_eq!(GapResolution::ProvenOnBoard.to_string(), "proven_on_board");
        assert_eq!(
            GapResolution::DeclaredOutOfScope.to_string(),
            "declared_out_of_scope"
        );
        assert_eq!(
            GapResolution::SubsumedByOther.to_string(),
            "subsumed_by_other"
        );
        assert_eq!(
            GapResolution::DimensionInvalidated.to_string(),
            "dimension_invalidated"
        );
    }

    #[test]
    fn gap_state_display() {
        assert_eq!(GapState::Open.to_string(), "open");
        assert_eq!(GapState::Closed.to_string(), "closed");
    }

    // -- RatchetError Display --

    #[test]
    fn ratchet_error_display() {
        let cell_id = make_cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "test");
        let err = RatchetError::RegressionRejected {
            cell_id,
            current_state: CellState::Proven,
            attempted_state: CellState::Claimed,
        };
        let display = err.to_string();
        assert!(display.contains("regression rejected"));
        assert!(display.contains("cold_start"));
    }

    // -- Serde round-trips --

    #[test]
    fn ratchet_board_serde_round_trip() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell = make_cell(CellDomain::Memory, ComparisonTarget::Bun, "serde-test");
        add_cell(&mut board, &mut log, cell).unwrap();

        let json = serde_json::to_string(&board).expect("serialize");
        let deser: RatchetBoard = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(board, deser);
    }

    #[test]
    fn frontier_gap_ledger_serde_round_trip() {
        let mut ledger = FrontierGapLedger::new();
        let mut log = RatchetEventLog::new();
        register_gap(
            &mut ledger,
            &mut log,
            make_gap("serde-gap", CellDomain::Throughput, GapKind::Unknown),
        )
        .unwrap();

        let json = serde_json::to_string(&ledger).expect("serialize");
        let deser: FrontierGapLedger = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ledger, deser);
    }

    #[test]
    fn ratchet_event_log_serde_round_trip() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let cell = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "ev-serde");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Proven,
            100_000,
            vec!["ev-1".to_string()],
        )
        .unwrap();

        let json = serde_json::to_string(&log).expect("serialize");
        let deser: RatchetEventLog = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(log, deser);
    }

    #[test]
    fn dominance_snapshot_serde_round_trip() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let ledger = FrontierGapLedger::new();
        let cell = make_cell(
            CellDomain::ColdStart,
            ComparisonTarget::V8Node,
            "snap-serde",
        );
        add_cell(&mut board, &mut log, cell).unwrap();

        let snapshot = compute_dominance_snapshot(&board, &ledger, &mut log);
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let deser: DominanceSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snapshot, deser);
    }

    #[test]
    fn cell_id_serde_round_trip() {
        let id = make_cell_id(
            CellDomain::ReactPerformance,
            ComparisonTarget::Jsc,
            "ssr-hydration",
        );
        let json = serde_json::to_string(&id).expect("serialize");
        let deser: CellId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, deser);
    }

    // -- Event log contents --

    #[test]
    fn event_log_tracks_all_operations() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();
        let mut ledger = FrontierGapLedger::new();

        let cell = make_cell(CellDomain::ColdStart, ComparisonTarget::V8Node, "track");
        let cell_id = cell.cell_id.clone();
        add_cell(&mut board, &mut log, cell).unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &cell_id,
            CellState::Claimed,
            50_000,
            vec![],
        )
        .unwrap();
        advance_epoch(&mut board, &mut log, 1).unwrap();
        register_gap(
            &mut ledger,
            &mut log,
            make_gap("tracked-gap", CellDomain::Memory, GapKind::Unknown),
        )
        .unwrap();
        close_gap(
            &mut ledger,
            &mut log,
            "tracked-gap",
            GapResolution::ProvenOnBoard,
            1,
        )
        .unwrap();
        compute_dominance_snapshot(&board, &ledger, &mut log);

        assert_eq!(log.events.len(), 6);
        assert!(matches!(
            log.events[0].kind,
            RatchetEventKind::CellAdded { .. }
        ));
        assert!(matches!(
            log.events[1].kind,
            RatchetEventKind::CellAdvanced { .. }
        ));
        assert!(matches!(
            log.events[2].kind,
            RatchetEventKind::EpochAdvanced { .. }
        ));
        assert!(matches!(
            log.events[3].kind,
            RatchetEventKind::GapRegistered { .. }
        ));
        assert!(matches!(
            log.events[4].kind,
            RatchetEventKind::GapClosed { .. }
        ));
        assert!(matches!(
            log.events[5].kind,
            RatchetEventKind::DominanceAssessed { .. }
        ));
    }

    #[test]
    fn event_sequences_are_monotonic() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();

        for i in 0..5 {
            let cell = make_cell(
                CellDomain::ColdStart,
                ComparisonTarget::V8Node,
                &format!("seq-{i}"),
            );
            add_cell(&mut board, &mut log, cell).unwrap();
        }

        for (idx, event) in log.events.iter().enumerate() {
            assert_eq!(event.sequence, idx as u64);
        }
    }

    // -- Dominance fraction edge cases --

    #[test]
    fn dominance_fraction_partial() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();

        for i in 0..3 {
            let cell = make_cell(
                CellDomain::ColdStart,
                ComparisonTarget::V8Node,
                &format!("frac-{i}"),
            );
            add_cell(&mut board, &mut log, cell).unwrap();
        }
        let id0 = make_cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "frac-0");
        advance_cell(
            &mut board,
            &mut log,
            &id0,
            CellState::Proven,
            100_000,
            vec![],
        )
        .unwrap();

        // 1 of 3 proven = 333333 millionths
        assert_eq!(board.dominance_fraction_millionths(), 333_333);
    }

    // -- Board state_counts --

    #[test]
    fn state_counts_breakdown() {
        let mut board = RatchetBoard::new();
        let mut log = RatchetEventLog::new();

        for i in 0..4 {
            let cell = make_cell(
                CellDomain::ColdStart,
                ComparisonTarget::V8Node,
                &format!("cnt-{i}"),
            );
            add_cell(&mut board, &mut log, cell).unwrap();
        }

        let id0 = make_cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "cnt-0");
        let id1 = make_cell_id(CellDomain::ColdStart, ComparisonTarget::V8Node, "cnt-1");
        advance_cell(
            &mut board,
            &mut log,
            &id0,
            CellState::Proven,
            100_000,
            vec![],
        )
        .unwrap();
        advance_cell(
            &mut board,
            &mut log,
            &id1,
            CellState::Claimed,
            50_000,
            vec![],
        )
        .unwrap();

        let counts = board.state_counts();
        assert_eq!(counts.get(&CellState::Proven), Some(&1));
        assert_eq!(counts.get(&CellState::Claimed), Some(&1));
        assert_eq!(counts.get(&CellState::Unproven), Some(&2));
    }
}
