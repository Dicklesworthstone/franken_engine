//! Synthesis search-budget contract with fail-closed conservative fallback.
//!
//! Enforces time, compute, and depth caps on PLAS synthesis.  On budget
//! exhaustion the system emits the most conservative valid result and
//! marks the witness artifact as `budget_limited`.
//!
//! Plan references: Section 10.15 item 4 (9I.5 PLAS), bd-83jh.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// SynthesisPhase — phases of the synthesis pipeline
// ---------------------------------------------------------------------------

/// Phase of the synthesis pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SynthesisPhase {
    /// Static analysis pass.
    StaticAnalysis,
    /// Dynamic ablation iterations.
    Ablation,
    /// Theorem/property checking.
    TheoremChecking,
    /// Final result assembly.
    ResultAssembly,
}

impl SynthesisPhase {
    /// All phases in pipeline order.
    pub const ALL: [Self; 4] = [
        Self::StaticAnalysis,
        Self::Ablation,
        Self::TheoremChecking,
        Self::ResultAssembly,
    ];
}

impl fmt::Display for SynthesisPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticAnalysis => f.write_str("static-analysis"),
            Self::Ablation => f.write_str("ablation"),
            Self::TheoremChecking => f.write_str("theorem-checking"),
            Self::ResultAssembly => f.write_str("result-assembly"),
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetDimension — the kind of budget being tracked
// ---------------------------------------------------------------------------

/// Kind of resource budget being tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BudgetDimension {
    /// Wall-clock time in nanoseconds.
    Time,
    /// CPU-time or resource units consumed.
    Compute,
    /// Search tree depth or ablation iteration count.
    Depth,
}

impl fmt::Display for BudgetDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Time => f.write_str("time"),
            Self::Compute => f.write_str("compute"),
            Self::Depth => f.write_str("depth"),
        }
    }
}

// ---------------------------------------------------------------------------
// PhaseBudget — per-phase resource limits
// ---------------------------------------------------------------------------

/// Resource limits for a single synthesis phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseBudget {
    /// Maximum wall-clock time for this phase (nanoseconds).
    pub time_cap_ns: u64,
    /// Maximum compute units for this phase.
    pub compute_cap: u64,
    /// Maximum depth/iterations for this phase.
    pub depth_cap: u64,
}

impl PhaseBudget {
    /// Check whether a given consumption exceeds any dimension.
    pub fn is_exceeded(&self, consumed: &PhaseConsumption) -> bool {
        consumed.time_ns > self.time_cap_ns
            || consumed.compute > self.compute_cap
            || consumed.depth > self.depth_cap
    }

    /// Which dimensions are exceeded.
    pub fn exceeded_dimensions(&self, consumed: &PhaseConsumption) -> Vec<BudgetDimension> {
        let mut dims = Vec::new();
        if consumed.time_ns > self.time_cap_ns {
            dims.push(BudgetDimension::Time);
        }
        if consumed.compute > self.compute_cap {
            dims.push(BudgetDimension::Compute);
        }
        if consumed.depth > self.depth_cap {
            dims.push(BudgetDimension::Depth);
        }
        dims
    }
}

// ---------------------------------------------------------------------------
// PhaseConsumption — resource usage for a single phase
// ---------------------------------------------------------------------------

/// Tracked resource consumption for a synthesis phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseConsumption {
    /// Wall-clock time consumed (nanoseconds).
    pub time_ns: u64,
    /// Compute units consumed.
    pub compute: u64,
    /// Depth/iterations consumed.
    pub depth: u64,
}

impl PhaseConsumption {
    /// Zero consumption.
    pub fn zero() -> Self {
        Self {
            time_ns: 0,
            compute: 0,
            depth: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SynthesisBudgetContract — the machine-readable budget specification
// ---------------------------------------------------------------------------

/// Machine-readable synthesis budget contract.
///
/// Specifies global and per-phase resource limits.  Can be overridden
/// per-extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesisBudgetContract {
    /// Contract version.
    pub version: u64,
    /// Global time cap (nanoseconds) across all phases.
    pub global_time_cap_ns: u64,
    /// Global compute cap across all phases.
    pub global_compute_cap: u64,
    /// Global depth cap across all phases.
    pub global_depth_cap: u64,
    /// Per-phase sub-budgets (phases without entries inherit from global).
    pub phase_budgets: BTreeMap<SynthesisPhase, PhaseBudget>,
    /// Security epoch when this contract was created.
    pub epoch: SecurityEpoch,
}

impl SynthesisBudgetContract {
    /// Get the budget for a specific phase.
    ///
    /// Returns the phase-specific budget if configured, otherwise
    /// derives one from the global caps.
    pub fn budget_for_phase(&self, phase: SynthesisPhase) -> PhaseBudget {
        self.phase_budgets
            .get(&phase)
            .cloned()
            .unwrap_or(PhaseBudget {
                time_cap_ns: self.global_time_cap_ns,
                compute_cap: self.global_compute_cap,
                depth_cap: self.global_depth_cap,
            })
    }

    /// Check if global caps are exceeded by total consumption.
    pub fn is_globally_exceeded(&self, total: &PhaseConsumption) -> bool {
        total.time_ns > self.global_time_cap_ns
            || total.compute > self.global_compute_cap
            || total.depth > self.global_depth_cap
    }
}

impl Default for SynthesisBudgetContract {
    fn default() -> Self {
        Self {
            version: 1,
            global_time_cap_ns: 30_000_000_000, // 30 seconds
            global_compute_cap: 100_000,
            global_depth_cap: 1000,
            phase_budgets: BTreeMap::new(),
            epoch: SecurityEpoch::from_raw(0),
        }
    }
}

// ---------------------------------------------------------------------------
// BudgetOverride — per-extension budget override
// ---------------------------------------------------------------------------

/// Per-extension override for the default budget contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetOverride {
    /// Extension ID this override applies to.
    pub extension_id: String,
    /// Override contract (replaces the default).
    pub contract: SynthesisBudgetContract,
    /// Justification for the override.
    pub justification: String,
}

// ---------------------------------------------------------------------------
// BudgetRegistry — default + per-extension override lookup
// ---------------------------------------------------------------------------

/// Registry of budget contracts with default and per-extension overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetRegistry {
    /// Default budget contract applied to all extensions.
    default_contract: SynthesisBudgetContract,
    /// Per-extension overrides (extension_id -> override).
    overrides: BTreeMap<String, BudgetOverride>,
}

impl BudgetRegistry {
    /// Create a registry with the given default contract.
    pub fn new(default_contract: SynthesisBudgetContract) -> Self {
        Self {
            default_contract,
            overrides: BTreeMap::new(),
        }
    }

    /// Add a per-extension override.
    pub fn add_override(&mut self, ovr: BudgetOverride) {
        self.overrides.insert(ovr.extension_id.clone(), ovr);
    }

    /// Remove an override.
    pub fn remove_override(&mut self, extension_id: &str) -> bool {
        self.overrides.remove(extension_id).is_some()
    }

    /// Get the effective contract for an extension.
    pub fn effective_contract(&self, extension_id: &str) -> &SynthesisBudgetContract {
        self.overrides
            .get(extension_id)
            .map(|o| &o.contract)
            .unwrap_or(&self.default_contract)
    }

    /// Number of overrides registered.
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }

    /// Get the default contract.
    pub fn default_contract(&self) -> &SynthesisBudgetContract {
        &self.default_contract
    }
}

impl Default for BudgetRegistry {
    fn default() -> Self {
        Self::new(SynthesisBudgetContract::default())
    }
}

// ---------------------------------------------------------------------------
// ExhaustionReason — why the budget was exhausted
// ---------------------------------------------------------------------------

/// Reason the budget was exhausted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExhaustionReason {
    /// Which dimension(s) were exceeded.
    pub exceeded_dimensions: Vec<BudgetDimension>,
    /// Phase during which exhaustion occurred.
    pub phase: SynthesisPhase,
    /// Whether the global cap or a phase-specific cap was hit.
    pub global_limit_hit: bool,
    /// Consumption at the time of exhaustion.
    pub consumption: PhaseConsumption,
    /// The limit that was exceeded (for the first exceeded dimension).
    pub limit_value: u64,
}

impl fmt::Display for ExhaustionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dims: Vec<String> = self
            .exceeded_dimensions
            .iter()
            .map(|d| d.to_string())
            .collect();
        write!(
            f,
            "budget exhausted during {}: {} exceeded (global={})",
            self.phase,
            dims.join(", "),
            self.global_limit_hit,
        )
    }
}

// ---------------------------------------------------------------------------
// FallbackResult — conservative result on budget exhaustion
// ---------------------------------------------------------------------------

/// Fallback quality indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FallbackQuality {
    /// Static upper bound without dynamic tightening.
    StaticBound,
    /// Partial ablation result (some tightening achieved).
    PartialAblation,
    /// Full result but without final theorem check.
    UnverifiedFull,
}

impl fmt::Display for FallbackQuality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticBound => f.write_str("static-bound"),
            Self::PartialAblation => f.write_str("partial-ablation"),
            Self::UnverifiedFull => f.write_str("unverified-full"),
        }
    }
}

/// Conservative fallback result emitted on budget exhaustion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FallbackResult {
    /// Quality level of the fallback.
    pub quality: FallbackQuality,
    /// Content hash of the best available partial result.
    pub result_digest: String,
    /// Exhaustion reason.
    pub exhaustion_reason: ExhaustionReason,
    /// Whether a budget increase would likely improve the result.
    pub increase_likely_helpful: bool,
    /// Recommended budget multiplier if increase is helpful (millionths).
    pub recommended_multiplier: Option<i64>,
}

// ---------------------------------------------------------------------------
// BudgetMonitor — real-time budget tracking during synthesis
// ---------------------------------------------------------------------------

/// Real-time budget monitor for a synthesis run.
///
/// Tracks consumption per-phase and globally, enforcing hard limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetMonitor {
    /// The effective budget contract.
    contract: SynthesisBudgetContract,
    /// Consumption per phase.
    phase_consumption: BTreeMap<SynthesisPhase, PhaseConsumption>,
    /// Total consumption across all phases.
    total_consumption: PhaseConsumption,
    /// Current phase (if synthesis is in progress).
    current_phase: Option<SynthesisPhase>,
    /// Whether budget has been exhausted.
    exhausted: bool,
    /// Exhaustion details (if exhausted).
    exhaustion_reason: Option<ExhaustionReason>,
}

impl BudgetMonitor {
    /// Create a new monitor for a budget contract.
    pub fn new(contract: SynthesisBudgetContract) -> Self {
        Self {
            contract,
            phase_consumption: BTreeMap::new(),
            total_consumption: PhaseConsumption::zero(),
            current_phase: None,
            exhausted: false,
            exhaustion_reason: None,
        }
    }

    /// Begin a new synthesis phase.
    pub fn begin_phase(&mut self, phase: SynthesisPhase) -> Result<(), BudgetError> {
        if self.exhausted {
            return Err(BudgetError::AlreadyExhausted);
        }
        self.current_phase = Some(phase);
        self.phase_consumption
            .entry(phase)
            .or_insert_with(PhaseConsumption::zero);
        Ok(())
    }

    /// Record resource consumption for the current phase.
    ///
    /// Returns `Err(BudgetExhausted)` if any limit is exceeded.
    pub fn record_consumption(
        &mut self,
        time_ns: u64,
        compute: u64,
        depth: u64,
    ) -> Result<(), BudgetError> {
        if self.exhausted {
            return Err(BudgetError::AlreadyExhausted);
        }
        let phase = self.current_phase.ok_or(BudgetError::NoActivePhase)?;

        // Update phase consumption.
        let pc = self
            .phase_consumption
            .entry(phase)
            .or_insert_with(PhaseConsumption::zero);
        pc.time_ns = pc.time_ns.saturating_add(time_ns);
        pc.compute = pc.compute.saturating_add(compute);
        pc.depth = pc.depth.saturating_add(depth);

        // Update total consumption.
        self.total_consumption.time_ns = self.total_consumption.time_ns.saturating_add(time_ns);
        self.total_consumption.compute = self.total_consumption.compute.saturating_add(compute);
        self.total_consumption.depth = self.total_consumption.depth.saturating_add(depth);

        // Check phase-level budget.
        let phase_budget = self.contract.budget_for_phase(phase);
        if phase_budget.is_exceeded(pc) {
            let exceeded = phase_budget.exceeded_dimensions(pc);
            let limit_value = match exceeded.first() {
                Some(BudgetDimension::Time) => phase_budget.time_cap_ns,
                Some(BudgetDimension::Compute) => phase_budget.compute_cap,
                Some(BudgetDimension::Depth) => phase_budget.depth_cap,
                None => 0,
            };
            self.exhausted = true;
            self.exhaustion_reason = Some(ExhaustionReason {
                exceeded_dimensions: exceeded,
                phase,
                global_limit_hit: false,
                consumption: pc.clone(),
                limit_value,
            });
            return Err(BudgetError::Exhausted(
                self.exhaustion_reason.clone().unwrap(),
            ));
        }

        // Check global budget.
        if self.contract.is_globally_exceeded(&self.total_consumption) {
            let mut exceeded = Vec::new();
            if self.total_consumption.time_ns > self.contract.global_time_cap_ns {
                exceeded.push(BudgetDimension::Time);
            }
            if self.total_consumption.compute > self.contract.global_compute_cap {
                exceeded.push(BudgetDimension::Compute);
            }
            if self.total_consumption.depth > self.contract.global_depth_cap {
                exceeded.push(BudgetDimension::Depth);
            }
            let limit_value = match exceeded.first() {
                Some(BudgetDimension::Time) => self.contract.global_time_cap_ns,
                Some(BudgetDimension::Compute) => self.contract.global_compute_cap,
                Some(BudgetDimension::Depth) => self.contract.global_depth_cap,
                None => 0,
            };
            self.exhausted = true;
            self.exhaustion_reason = Some(ExhaustionReason {
                exceeded_dimensions: exceeded,
                phase,
                global_limit_hit: true,
                consumption: self.total_consumption.clone(),
                limit_value,
            });
            return Err(BudgetError::Exhausted(
                self.exhaustion_reason.clone().unwrap(),
            ));
        }

        Ok(())
    }

    /// Whether the budget has been exhausted.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Get the exhaustion reason, if any.
    pub fn exhaustion_reason(&self) -> Option<&ExhaustionReason> {
        self.exhaustion_reason.as_ref()
    }

    /// Get total consumption across all phases.
    pub fn total_consumption(&self) -> &PhaseConsumption {
        &self.total_consumption
    }

    /// Get consumption for a specific phase.
    pub fn phase_consumption(&self, phase: SynthesisPhase) -> Option<&PhaseConsumption> {
        self.phase_consumption.get(&phase)
    }

    /// Current phase.
    pub fn current_phase(&self) -> Option<SynthesisPhase> {
        self.current_phase
    }

    /// Remaining budget for the current phase.
    pub fn remaining_for_current_phase(&self) -> Option<PhaseConsumption> {
        let phase = self.current_phase?;
        let budget = self.contract.budget_for_phase(phase);
        let consumed = self.phase_consumption.get(&phase)?;
        Some(PhaseConsumption {
            time_ns: budget.time_cap_ns.saturating_sub(consumed.time_ns),
            compute: budget.compute_cap.saturating_sub(consumed.compute),
            depth: budget.depth_cap.saturating_sub(consumed.depth),
        })
    }

    /// Remaining global budget.
    pub fn remaining_global(&self) -> PhaseConsumption {
        PhaseConsumption {
            time_ns: self
                .contract
                .global_time_cap_ns
                .saturating_sub(self.total_consumption.time_ns),
            compute: self
                .contract
                .global_compute_cap
                .saturating_sub(self.total_consumption.compute),
            depth: self
                .contract
                .global_depth_cap
                .saturating_sub(self.total_consumption.depth),
        }
    }

    /// Utilization ratio for each dimension (millionths, 0..=1_000_000).
    pub fn utilization(&self) -> BTreeMap<BudgetDimension, i64> {
        let mut map = BTreeMap::new();
        if self.contract.global_time_cap_ns > 0 {
            map.insert(
                BudgetDimension::Time,
                (self.total_consumption.time_ns as i128 * 1_000_000
                    / self.contract.global_time_cap_ns as i128) as i64,
            );
        }
        if self.contract.global_compute_cap > 0 {
            map.insert(
                BudgetDimension::Compute,
                (self.total_consumption.compute as i128 * 1_000_000
                    / self.contract.global_compute_cap as i128) as i64,
            );
        }
        if self.contract.global_depth_cap > 0 {
            map.insert(
                BudgetDimension::Depth,
                (self.total_consumption.depth as i128 * 1_000_000
                    / self.contract.global_depth_cap as i128) as i64,
            );
        }
        map
    }
}

// ---------------------------------------------------------------------------
// BudgetHistoryEntry — historical budget consumption record
// ---------------------------------------------------------------------------

/// Historical record of a synthesis run's budget consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetHistoryEntry {
    /// Extension that was synthesized.
    pub extension_id: String,
    /// Contract that was applied.
    pub contract_version: u64,
    /// Per-phase consumption.
    pub phase_consumption: BTreeMap<SynthesisPhase, PhaseConsumption>,
    /// Total consumption.
    pub total_consumption: PhaseConsumption,
    /// Whether the budget was exhausted.
    pub exhausted: bool,
    /// Timestamp of the run (nanoseconds).
    pub timestamp_ns: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

/// Budget history tracker for trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetHistory {
    /// Ordered history entries (oldest first).
    entries: Vec<BudgetHistoryEntry>,
    /// Maximum entries to retain.
    max_entries: usize,
}

impl BudgetHistory {
    /// Create a new history tracker.
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
        }
    }

    /// Record a completed synthesis run.
    pub fn record(&mut self, entry: BudgetHistoryEntry) {
        self.entries.push(entry);
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    /// Get all entries.
    pub fn entries(&self) -> &[BudgetHistoryEntry] {
        &self.entries
    }

    /// Get entries for a specific extension.
    pub fn entries_for_extension(&self, extension_id: &str) -> Vec<&BudgetHistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.extension_id == extension_id)
            .collect()
    }

    /// Compute average utilization for an extension (millionths per dimension).
    pub fn average_utilization(
        &self,
        extension_id: &str,
        contract: &SynthesisBudgetContract,
    ) -> BTreeMap<BudgetDimension, i64> {
        let ext_entries = self.entries_for_extension(extension_id);
        if ext_entries.is_empty() {
            return BTreeMap::new();
        }

        let mut totals = PhaseConsumption::zero();
        for e in &ext_entries {
            totals.time_ns = totals.time_ns.saturating_add(e.total_consumption.time_ns);
            totals.compute = totals.compute.saturating_add(e.total_consumption.compute);
            totals.depth = totals.depth.saturating_add(e.total_consumption.depth);
        }

        let count = ext_entries.len() as u64;
        let avg_time = totals.time_ns / count;
        let avg_compute = totals.compute / count;
        let avg_depth = totals.depth / count;

        let mut map = BTreeMap::new();
        if contract.global_time_cap_ns > 0 {
            map.insert(
                BudgetDimension::Time,
                (avg_time as i128 * 1_000_000 / contract.global_time_cap_ns as i128) as i64,
            );
        }
        if contract.global_compute_cap > 0 {
            map.insert(
                BudgetDimension::Compute,
                (avg_compute as i128 * 1_000_000 / contract.global_compute_cap as i128) as i64,
            );
        }
        if contract.global_depth_cap > 0 {
            map.insert(
                BudgetDimension::Depth,
                (avg_depth as i128 * 1_000_000 / contract.global_depth_cap as i128) as i64,
            );
        }
        map
    }

    /// Exhaustion rate for an extension (millionths).
    pub fn exhaustion_rate(&self, extension_id: &str) -> i64 {
        let ext_entries = self.entries_for_extension(extension_id);
        if ext_entries.is_empty() {
            return 0;
        }
        let exhausted = ext_entries.iter().filter(|e| e.exhausted).count();
        (exhausted as i64 * 1_000_000) / ext_entries.len() as i64
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for BudgetHistory {
    fn default() -> Self {
        Self::new(1000)
    }
}

// ---------------------------------------------------------------------------
// BudgetError
// ---------------------------------------------------------------------------

/// Errors from budget operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetError {
    /// Budget already exhausted; no further consumption allowed.
    AlreadyExhausted,
    /// No active phase; call `begin_phase` first.
    NoActivePhase,
    /// Budget exhausted during this consumption.
    Exhausted(ExhaustionReason),
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExhausted => f.write_str("budget already exhausted"),
            Self::NoActivePhase => f.write_str("no active synthesis phase"),
            Self::Exhausted(reason) => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for BudgetError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helpers --

    fn default_contract() -> SynthesisBudgetContract {
        SynthesisBudgetContract::default()
    }

    fn tight_contract() -> SynthesisBudgetContract {
        SynthesisBudgetContract {
            version: 1,
            global_time_cap_ns: 1000,
            global_compute_cap: 100,
            global_depth_cap: 10,
            phase_budgets: BTreeMap::new(),
            epoch: SecurityEpoch::from_raw(1),
        }
    }

    fn contract_with_phase_budgets() -> SynthesisBudgetContract {
        let mut phase_budgets = BTreeMap::new();
        phase_budgets.insert(
            SynthesisPhase::StaticAnalysis,
            PhaseBudget {
                time_cap_ns: 500,
                compute_cap: 50,
                depth_cap: 5,
            },
        );
        phase_budgets.insert(
            SynthesisPhase::Ablation,
            PhaseBudget {
                time_cap_ns: 300,
                compute_cap: 40,
                depth_cap: 8,
            },
        );
        SynthesisBudgetContract {
            version: 1,
            global_time_cap_ns: 1000,
            global_compute_cap: 100,
            global_depth_cap: 20,
            phase_budgets,
            epoch: SecurityEpoch::from_raw(1),
        }
    }

    // -- SynthesisPhase --

    #[test]
    fn phase_display() {
        assert_eq!(
            SynthesisPhase::StaticAnalysis.to_string(),
            "static-analysis"
        );
        assert_eq!(SynthesisPhase::Ablation.to_string(), "ablation");
        assert_eq!(
            SynthesisPhase::TheoremChecking.to_string(),
            "theorem-checking"
        );
        assert_eq!(
            SynthesisPhase::ResultAssembly.to_string(),
            "result-assembly"
        );
    }

    #[test]
    fn phase_serde_roundtrip() {
        for phase in SynthesisPhase::ALL {
            let json = serde_json::to_string(&phase).unwrap();
            let restored: SynthesisPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(phase, restored);
        }
    }

    // -- BudgetDimension --

    #[test]
    fn dimension_display() {
        assert_eq!(BudgetDimension::Time.to_string(), "time");
        assert_eq!(BudgetDimension::Compute.to_string(), "compute");
        assert_eq!(BudgetDimension::Depth.to_string(), "depth");
    }

    #[test]
    fn dimension_serde_roundtrip() {
        for dim in [
            BudgetDimension::Time,
            BudgetDimension::Compute,
            BudgetDimension::Depth,
        ] {
            let json = serde_json::to_string(&dim).unwrap();
            let restored: BudgetDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(dim, restored);
        }
    }

    // -- PhaseBudget --

    #[test]
    fn phase_budget_not_exceeded() {
        let budget = PhaseBudget {
            time_cap_ns: 1000,
            compute_cap: 100,
            depth_cap: 10,
        };
        let consumed = PhaseConsumption {
            time_ns: 500,
            compute: 50,
            depth: 5,
        };
        assert!(!budget.is_exceeded(&consumed));
        assert!(budget.exceeded_dimensions(&consumed).is_empty());
    }

    #[test]
    fn phase_budget_time_exceeded() {
        let budget = PhaseBudget {
            time_cap_ns: 1000,
            compute_cap: 100,
            depth_cap: 10,
        };
        let consumed = PhaseConsumption {
            time_ns: 1001,
            compute: 50,
            depth: 5,
        };
        assert!(budget.is_exceeded(&consumed));
        assert_eq!(
            budget.exceeded_dimensions(&consumed),
            vec![BudgetDimension::Time]
        );
    }

    #[test]
    fn phase_budget_multiple_exceeded() {
        let budget = PhaseBudget {
            time_cap_ns: 1000,
            compute_cap: 100,
            depth_cap: 10,
        };
        let consumed = PhaseConsumption {
            time_ns: 2000,
            compute: 200,
            depth: 5,
        };
        let dims = budget.exceeded_dimensions(&consumed);
        assert_eq!(dims.len(), 2);
        assert!(dims.contains(&BudgetDimension::Time));
        assert!(dims.contains(&BudgetDimension::Compute));
    }

    #[test]
    fn phase_budget_serde_roundtrip() {
        let budget = PhaseBudget {
            time_cap_ns: 1000,
            compute_cap: 100,
            depth_cap: 10,
        };
        let json = serde_json::to_string(&budget).unwrap();
        let restored: PhaseBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, restored);
    }

    // -- SynthesisBudgetContract --

    #[test]
    fn contract_defaults() {
        let c = SynthesisBudgetContract::default();
        assert_eq!(c.global_time_cap_ns, 30_000_000_000);
        assert_eq!(c.global_compute_cap, 100_000);
        assert_eq!(c.global_depth_cap, 1000);
        assert!(c.phase_budgets.is_empty());
    }

    #[test]
    fn contract_budget_for_phase_with_override() {
        let c = contract_with_phase_budgets();
        let sa = c.budget_for_phase(SynthesisPhase::StaticAnalysis);
        assert_eq!(sa.time_cap_ns, 500);
        assert_eq!(sa.compute_cap, 50);
    }

    #[test]
    fn contract_budget_for_phase_inherits_global() {
        let c = contract_with_phase_budgets();
        // TheoremChecking has no specific budget; inherits global.
        let tc = c.budget_for_phase(SynthesisPhase::TheoremChecking);
        assert_eq!(tc.time_cap_ns, c.global_time_cap_ns);
        assert_eq!(tc.compute_cap, c.global_compute_cap);
    }

    #[test]
    fn contract_serde_roundtrip() {
        let c = contract_with_phase_budgets();
        let json = serde_json::to_string(&c).unwrap();
        let restored: SynthesisBudgetContract = serde_json::from_str(&json).unwrap();
        assert_eq!(c, restored);
    }

    // -- BudgetRegistry --

    #[test]
    fn registry_default_contract() {
        let reg = BudgetRegistry::default();
        let effective = reg.effective_contract("any-extension");
        assert_eq!(effective, &SynthesisBudgetContract::default());
    }

    #[test]
    fn registry_override() {
        let mut reg = BudgetRegistry::default();
        reg.add_override(BudgetOverride {
            extension_id: "ext-1".to_string(),
            contract: tight_contract(),
            justification: "complex extension".to_string(),
        });
        assert_eq!(reg.override_count(), 1);

        let effective = reg.effective_contract("ext-1");
        assert_eq!(effective.global_time_cap_ns, 1000);

        // Other extensions still get default.
        let other = reg.effective_contract("ext-2");
        assert_eq!(other.global_time_cap_ns, 30_000_000_000);
    }

    #[test]
    fn registry_remove_override() {
        let mut reg = BudgetRegistry::default();
        reg.add_override(BudgetOverride {
            extension_id: "ext-1".to_string(),
            contract: tight_contract(),
            justification: "test".to_string(),
        });
        assert!(reg.remove_override("ext-1"));
        assert!(!reg.remove_override("ext-1")); // already removed
        assert_eq!(reg.override_count(), 0);
    }

    #[test]
    fn registry_serde_roundtrip() {
        let mut reg = BudgetRegistry::default();
        reg.add_override(BudgetOverride {
            extension_id: "ext-1".to_string(),
            contract: tight_contract(),
            justification: "test".to_string(),
        });
        let json = serde_json::to_string(&reg).unwrap();
        let restored: BudgetRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.override_count(), 1);
    }

    // -- BudgetMonitor --

    #[test]
    fn monitor_tracks_consumption() {
        let mut monitor = BudgetMonitor::new(default_contract());
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        monitor.record_consumption(100, 10, 1).unwrap();
        monitor.record_consumption(200, 20, 2).unwrap();

        let pc = monitor
            .phase_consumption(SynthesisPhase::StaticAnalysis)
            .unwrap();
        assert_eq!(pc.time_ns, 300);
        assert_eq!(pc.compute, 30);
        assert_eq!(pc.depth, 3);

        let total = monitor.total_consumption();
        assert_eq!(total.time_ns, 300);
    }

    #[test]
    fn monitor_halts_on_phase_budget_exceeded() {
        let c = contract_with_phase_budgets();
        let mut monitor = BudgetMonitor::new(c);
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        // Static analysis has time_cap_ns: 500.
        assert!(monitor.record_consumption(400, 10, 1).is_ok());
        let result = monitor.record_consumption(200, 10, 1); // 600 > 500
        assert!(matches!(result, Err(BudgetError::Exhausted(_))));
        assert!(monitor.is_exhausted());

        let reason = monitor.exhaustion_reason().unwrap();
        assert!(!reason.global_limit_hit);
        assert_eq!(reason.phase, SynthesisPhase::StaticAnalysis);
        assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Time));
    }

    #[test]
    fn monitor_halts_on_global_budget_exceeded() {
        let c = tight_contract(); // global_time_cap_ns: 1000
        let mut monitor = BudgetMonitor::new(c);
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        assert!(monitor.record_consumption(500, 10, 1).is_ok());

        monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
        let result = monitor.record_consumption(600, 10, 1); // total 1100 > 1000
        assert!(matches!(result, Err(BudgetError::Exhausted(_))));

        let reason = monitor.exhaustion_reason().unwrap();
        assert!(reason.global_limit_hit);
    }

    #[test]
    fn monitor_rejects_after_exhaustion() {
        let c = tight_contract();
        let mut monitor = BudgetMonitor::new(c);
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        let _ = monitor.record_consumption(2000, 0, 0); // exhaust

        assert!(matches!(
            monitor.record_consumption(1, 0, 0),
            Err(BudgetError::AlreadyExhausted)
        ));
        assert!(matches!(
            monitor.begin_phase(SynthesisPhase::Ablation),
            Err(BudgetError::AlreadyExhausted)
        ));
    }

    #[test]
    fn monitor_requires_active_phase() {
        let mut monitor = BudgetMonitor::new(default_contract());
        assert!(matches!(
            monitor.record_consumption(1, 0, 0),
            Err(BudgetError::NoActivePhase)
        ));
    }

    #[test]
    fn monitor_remaining_budget() {
        let c = tight_contract(); // 1000 / 100 / 10
        let mut monitor = BudgetMonitor::new(c);
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        monitor.record_consumption(300, 40, 3).unwrap();

        let remaining = monitor.remaining_for_current_phase().unwrap();
        assert_eq!(remaining.time_ns, 700);
        assert_eq!(remaining.compute, 60);
        assert_eq!(remaining.depth, 7);

        let global = monitor.remaining_global();
        assert_eq!(global.time_ns, 700);
    }

    #[test]
    fn monitor_utilization() {
        let c = tight_contract(); // 1000 / 100 / 10
        let mut monitor = BudgetMonitor::new(c);
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        monitor.record_consumption(500, 50, 5).unwrap();

        let util = monitor.utilization();
        assert_eq!(util[&BudgetDimension::Time], 500_000); // 50%
        assert_eq!(util[&BudgetDimension::Compute], 500_000);
        assert_eq!(util[&BudgetDimension::Depth], 500_000);
    }

    #[test]
    fn monitor_serde_roundtrip() {
        let mut monitor = BudgetMonitor::new(default_contract());
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        monitor.record_consumption(100, 10, 1).unwrap();

        let json = serde_json::to_string(&monitor).unwrap();
        let restored: BudgetMonitor = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.total_consumption().time_ns,
            monitor.total_consumption().time_ns
        );
    }

    // -- BudgetHistory --

    #[test]
    fn history_records_entries() {
        let mut history = BudgetHistory::new(10);
        assert!(history.is_empty());

        history.record(BudgetHistoryEntry {
            extension_id: "ext-1".to_string(),
            contract_version: 1,
            phase_consumption: BTreeMap::new(),
            total_consumption: PhaseConsumption {
                time_ns: 500,
                compute: 50,
                depth: 5,
            },
            exhausted: false,
            timestamp_ns: 1_000_000_000,
            epoch: SecurityEpoch::from_raw(1),
        });

        assert_eq!(history.len(), 1);
        assert!(!history.is_empty());
    }

    #[test]
    fn history_evicts_old_entries() {
        let mut history = BudgetHistory::new(3);
        for i in 0..5 {
            history.record(BudgetHistoryEntry {
                extension_id: format!("ext-{i}"),
                contract_version: 1,
                phase_consumption: BTreeMap::new(),
                total_consumption: PhaseConsumption::zero(),
                exhausted: false,
                timestamp_ns: i * 1000,
                epoch: SecurityEpoch::from_raw(1),
            });
        }
        assert_eq!(history.len(), 3);
        // Oldest entries should be evicted.
        assert_eq!(history.entries()[0].extension_id, "ext-2");
    }

    #[test]
    fn history_entries_for_extension() {
        let mut history = BudgetHistory::new(10);
        for i in 0..3 {
            history.record(BudgetHistoryEntry {
                extension_id: "ext-1".to_string(),
                contract_version: 1,
                phase_consumption: BTreeMap::new(),
                total_consumption: PhaseConsumption {
                    time_ns: 100 * (i + 1),
                    compute: 0,
                    depth: 0,
                },
                exhausted: false,
                timestamp_ns: i * 1000,
                epoch: SecurityEpoch::from_raw(1),
            });
        }
        history.record(BudgetHistoryEntry {
            extension_id: "ext-2".to_string(),
            contract_version: 1,
            phase_consumption: BTreeMap::new(),
            total_consumption: PhaseConsumption::zero(),
            exhausted: false,
            timestamp_ns: 3000,
            epoch: SecurityEpoch::from_raw(1),
        });

        let ext1 = history.entries_for_extension("ext-1");
        assert_eq!(ext1.len(), 3);
    }

    #[test]
    fn history_average_utilization() {
        let contract = tight_contract(); // 1000 / 100 / 10
        let mut history = BudgetHistory::new(10);
        history.record(BudgetHistoryEntry {
            extension_id: "ext-1".to_string(),
            contract_version: 1,
            phase_consumption: BTreeMap::new(),
            total_consumption: PhaseConsumption {
                time_ns: 500,
                compute: 50,
                depth: 5,
            },
            exhausted: false,
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
        });
        history.record(BudgetHistoryEntry {
            extension_id: "ext-1".to_string(),
            contract_version: 1,
            phase_consumption: BTreeMap::new(),
            total_consumption: PhaseConsumption {
                time_ns: 700,
                compute: 70,
                depth: 7,
            },
            exhausted: false,
            timestamp_ns: 2000,
            epoch: SecurityEpoch::from_raw(1),
        });

        let avg = history.average_utilization("ext-1", &contract);
        // Average time: (500+700)/2 = 600, cap 1000 => 600_000 millionths
        assert_eq!(avg[&BudgetDimension::Time], 600_000);
    }

    #[test]
    fn history_exhaustion_rate() {
        let mut history = BudgetHistory::new(10);
        for i in 0..4 {
            history.record(BudgetHistoryEntry {
                extension_id: "ext-1".to_string(),
                contract_version: 1,
                phase_consumption: BTreeMap::new(),
                total_consumption: PhaseConsumption::zero(),
                exhausted: i < 1, // 1 out of 4 exhausted
                timestamp_ns: i * 1000,
                epoch: SecurityEpoch::from_raw(1),
            });
        }
        let rate = history.exhaustion_rate("ext-1");
        assert_eq!(rate, 250_000); // 25%
    }

    #[test]
    fn history_serde_roundtrip() {
        let mut history = BudgetHistory::new(10);
        history.record(BudgetHistoryEntry {
            extension_id: "ext-1".to_string(),
            contract_version: 1,
            phase_consumption: BTreeMap::new(),
            total_consumption: PhaseConsumption::zero(),
            exhausted: false,
            timestamp_ns: 1000,
            epoch: SecurityEpoch::from_raw(1),
        });
        let json = serde_json::to_string(&history).unwrap();
        let restored: BudgetHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.len(), 1);
    }

    // -- FallbackResult --

    #[test]
    fn fallback_quality_display() {
        assert_eq!(FallbackQuality::StaticBound.to_string(), "static-bound");
        assert_eq!(
            FallbackQuality::PartialAblation.to_string(),
            "partial-ablation"
        );
        assert_eq!(
            FallbackQuality::UnverifiedFull.to_string(),
            "unverified-full"
        );
    }

    #[test]
    fn fallback_quality_serde_roundtrip() {
        for q in [
            FallbackQuality::StaticBound,
            FallbackQuality::PartialAblation,
            FallbackQuality::UnverifiedFull,
        ] {
            let json = serde_json::to_string(&q).unwrap();
            let restored: FallbackQuality = serde_json::from_str(&json).unwrap();
            assert_eq!(q, restored);
        }
    }

    #[test]
    fn fallback_result_serde_roundtrip() {
        let fb = FallbackResult {
            quality: FallbackQuality::PartialAblation,
            result_digest: "abc123".to_string(),
            exhaustion_reason: ExhaustionReason {
                exceeded_dimensions: vec![BudgetDimension::Time],
                phase: SynthesisPhase::Ablation,
                global_limit_hit: false,
                consumption: PhaseConsumption {
                    time_ns: 1001,
                    compute: 50,
                    depth: 5,
                },
                limit_value: 1000,
            },
            increase_likely_helpful: true,
            recommended_multiplier: Some(2_000_000),
        };
        let json = serde_json::to_string(&fb).unwrap();
        let restored: FallbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(fb, restored);
    }

    // -- ExhaustionReason --

    #[test]
    fn exhaustion_reason_display() {
        let reason = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Time, BudgetDimension::Compute],
            phase: SynthesisPhase::Ablation,
            global_limit_hit: true,
            consumption: PhaseConsumption::zero(),
            limit_value: 1000,
        };
        let s = reason.to_string();
        assert!(s.contains("ablation"));
        assert!(s.contains("time"));
        assert!(s.contains("compute"));
        assert!(s.contains("global=true"));
    }

    // -- BudgetError --

    #[test]
    fn error_display() {
        assert_eq!(
            BudgetError::AlreadyExhausted.to_string(),
            "budget already exhausted"
        );
        assert_eq!(
            BudgetError::NoActivePhase.to_string(),
            "no active synthesis phase"
        );
    }

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![BudgetError::AlreadyExhausted, BudgetError::NoActivePhase];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let restored: BudgetError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, restored);
        }
    }

    // -- Integration: full synthesis run --

    #[test]
    fn full_synthesis_run_within_budget() {
        let contract = tight_contract();
        let mut monitor = BudgetMonitor::new(contract);

        // Phase 1: Static Analysis.
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        monitor.record_consumption(200, 20, 2).unwrap();

        // Phase 2: Ablation.
        monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
        monitor.record_consumption(300, 30, 3).unwrap();

        // Phase 3: Theorem Checking.
        monitor
            .begin_phase(SynthesisPhase::TheoremChecking)
            .unwrap();
        monitor.record_consumption(200, 20, 2).unwrap();

        // Phase 4: Result Assembly.
        monitor.begin_phase(SynthesisPhase::ResultAssembly).unwrap();
        monitor.record_consumption(100, 10, 1).unwrap();

        assert!(!monitor.is_exhausted());
        let total = monitor.total_consumption();
        assert_eq!(total.time_ns, 800);
        assert_eq!(total.compute, 80);
        assert_eq!(total.depth, 8);
    }

    #[test]
    fn full_synthesis_run_budget_exhausted_mid_ablation() {
        let contract = tight_contract(); // depth_cap: 10
        let mut monitor = BudgetMonitor::new(contract);

        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        monitor.record_consumption(100, 10, 3).unwrap();

        monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
        // Each iteration adds depth.
        for _ in 0..7 {
            monitor.record_consumption(10, 1, 1).unwrap();
        }
        // Next iteration exceeds depth cap (3 + 7 + 1 = 11 > 10).
        let result = monitor.record_consumption(10, 1, 1);
        assert!(matches!(result, Err(BudgetError::Exhausted(_))));

        let reason = monitor.exhaustion_reason().unwrap();
        assert!(reason.exceeded_dimensions.contains(&BudgetDimension::Depth));
    }

    // -- Determinism --

    #[test]
    fn contract_serialization_deterministic() {
        let build = || {
            let mut c = tight_contract();
            c.phase_budgets.insert(
                SynthesisPhase::Ablation,
                PhaseBudget {
                    time_cap_ns: 500,
                    compute_cap: 50,
                    depth_cap: 5,
                },
            );
            c
        };
        let json1 = serde_json::to_string(&build()).unwrap();
        let json2 = serde_json::to_string(&build()).unwrap();
        assert_eq!(json1, json2);
    }

    // -- BudgetOverride --

    // -- Enrichment: Ord, std::error --

    #[test]
    fn synthesis_phase_ordering() {
        assert!(SynthesisPhase::StaticAnalysis < SynthesisPhase::Ablation);
        assert!(SynthesisPhase::Ablation < SynthesisPhase::TheoremChecking);
        assert!(SynthesisPhase::TheoremChecking < SynthesisPhase::ResultAssembly);
    }

    #[test]
    fn budget_dimension_ordering() {
        assert!(BudgetDimension::Time < BudgetDimension::Compute);
        assert!(BudgetDimension::Compute < BudgetDimension::Depth);
    }

    #[test]
    fn fallback_quality_ordering() {
        assert!(FallbackQuality::StaticBound < FallbackQuality::PartialAblation);
        assert!(FallbackQuality::PartialAblation < FallbackQuality::UnverifiedFull);
    }

    #[test]
    fn budget_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(BudgetError::AlreadyExhausted),
            Box::new(BudgetError::NoActivePhase),
            Box::new(BudgetError::Exhausted(ExhaustionReason {
                exceeded_dimensions: vec![BudgetDimension::Time],
                phase: SynthesisPhase::Ablation,
                global_limit_hit: false,
                consumption: PhaseConsumption::zero(),
                limit_value: 1_000_000,
            })),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            3,
            "all 3 variants produce distinct messages"
        );
    }

    #[test]
    fn budget_override_serde_roundtrip() {
        let ovr = BudgetOverride {
            extension_id: "ext-1".to_string(),
            contract: tight_contract(),
            justification: "needs more compute".to_string(),
        };
        let json = serde_json::to_string(&ovr).unwrap();
        let restored: BudgetOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(ovr, restored);
    }

    // -- Enrichment: Display uniqueness, edge cases, determinism --

    #[test]
    fn synthesis_phase_display_uniqueness_btreeset() {
        let mut displays = std::collections::BTreeSet::new();
        for phase in SynthesisPhase::ALL {
            displays.insert(phase.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all 4 phases produce distinct display strings"
        );
    }

    #[test]
    fn budget_dimension_display_uniqueness_btreeset() {
        let dims = [
            BudgetDimension::Time,
            BudgetDimension::Compute,
            BudgetDimension::Depth,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for d in &dims {
            displays.insert(d.to_string());
        }
        assert_eq!(
            displays.len(),
            3,
            "all 3 dimensions produce distinct display strings"
        );
    }

    #[test]
    fn fallback_quality_display_uniqueness_btreeset() {
        let qualities = [
            FallbackQuality::StaticBound,
            FallbackQuality::PartialAblation,
            FallbackQuality::UnverifiedFull,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for q in &qualities {
            displays.insert(q.to_string());
        }
        assert_eq!(
            displays.len(),
            3,
            "all 3 qualities produce distinct display strings"
        );
    }

    #[test]
    fn phase_consumption_zero_is_all_zeros_batch2() {
        let z = PhaseConsumption::zero();
        assert_eq!(z.time_ns, 0);
        assert_eq!(z.compute, 0);
        assert_eq!(z.depth, 0);
    }

    #[test]
    fn phase_budget_at_exact_boundary_not_exceeded() {
        let budget = PhaseBudget {
            time_cap_ns: 1000,
            compute_cap: 100,
            depth_cap: 10,
        };
        let consumed = PhaseConsumption {
            time_ns: 1000,
            compute: 100,
            depth: 10,
        };
        assert!(
            !budget.is_exceeded(&consumed),
            "exact boundary should not be exceeded"
        );
        assert!(budget.exceeded_dimensions(&consumed).is_empty());
    }

    #[test]
    fn monitor_remaining_global_after_multi_phase() {
        let c = tight_contract(); // 1000 / 100 / 10
        let mut monitor = BudgetMonitor::new(c);
        monitor.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        monitor.record_consumption(300, 20, 3).unwrap();
        monitor.begin_phase(SynthesisPhase::Ablation).unwrap();
        monitor.record_consumption(200, 30, 2).unwrap();

        let remaining = monitor.remaining_global();
        assert_eq!(remaining.time_ns, 500); // 1000 - 300 - 200
        assert_eq!(remaining.compute, 50); // 100 - 20 - 30
        assert_eq!(remaining.depth, 5); // 10 - 3 - 2
    }

    #[test]
    fn history_exhaustion_rate_no_entries_returns_zero() {
        let history = BudgetHistory::new(10);
        assert_eq!(history.exhaustion_rate("nonexistent"), 0);
    }

    #[test]
    fn budget_error_serde_exhausted_variant() {
        let err = BudgetError::Exhausted(ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Time, BudgetDimension::Depth],
            phase: SynthesisPhase::TheoremChecking,
            global_limit_hit: true,
            consumption: PhaseConsumption {
                time_ns: 5000,
                compute: 200,
                depth: 50,
            },
            limit_value: 3000,
        });
        let json = serde_json::to_string(&err).unwrap();
        let restored: BudgetError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, restored);
    }

    // -- Enrichment batch 2: PearlTower 2026-02-27 --

    #[test]
    fn registry_add_and_remove_override() {
        let mut reg = BudgetRegistry::default();
        assert_eq!(reg.override_count(), 0);

        let ovr = BudgetOverride {
            extension_id: "ext-1".into(),
            contract: SynthesisBudgetContract::default(),
            justification: "testing".into(),
        };
        reg.add_override(ovr);
        assert_eq!(reg.override_count(), 1);

        assert!(reg.remove_override("ext-1"));
        assert_eq!(reg.override_count(), 0);
        assert!(!reg.remove_override("ext-1")); // already removed
    }

    #[test]
    fn registry_override_replaces_default() {
        let mut reg = BudgetRegistry::default();
        let default_time = reg.default_contract().global_time_cap_ns;

        let custom = SynthesisBudgetContract { global_time_cap_ns: default_time + 999, ..Default::default() };
        let ovr = BudgetOverride {
            extension_id: "ext-fast".into(),
            contract: custom,
            justification: "perf".into(),
        };
        reg.add_override(ovr);

        assert_eq!(
            reg.effective_contract("ext-fast").global_time_cap_ns,
            default_time + 999
        );
        assert_eq!(
            reg.effective_contract("ext-other").global_time_cap_ns,
            default_time
        );
    }

    #[test]
    fn monitor_no_active_phase_errors() {
        let mut m = BudgetMonitor::new(SynthesisBudgetContract::default());
        assert!(m.current_phase().is_none());
        let err = m.record_consumption(1, 1, 1).unwrap_err();
        assert_eq!(err, BudgetError::NoActivePhase);
    }

    #[test]
    fn monitor_phase_switching() {
        let mut m = BudgetMonitor::new(SynthesisBudgetContract::default());
        m.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        assert_eq!(m.current_phase(), Some(SynthesisPhase::StaticAnalysis));
        m.begin_phase(SynthesisPhase::Ablation).unwrap();
        assert_eq!(m.current_phase(), Some(SynthesisPhase::Ablation));
    }

    #[test]
    fn monitor_after_exhaustion_rejects_begin_phase() {
        let mut contract = SynthesisBudgetContract { global_time_cap_ns: 10, ..Default::default() };
        for phase_budget in contract.phase_budgets.values_mut() {
            phase_budget.time_cap_ns = 10;
        }
        let mut m = BudgetMonitor::new(contract);
        m.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        let _ = m.record_consumption(100, 0, 0); // exceed
        assert!(m.is_exhausted());
        let err = m.begin_phase(SynthesisPhase::Ablation).unwrap_err();
        assert_eq!(err, BudgetError::AlreadyExhausted);
    }

    #[test]
    fn monitor_utilization_returns_correct_ratios() {
        let mut contract = SynthesisBudgetContract { global_time_cap_ns: 1_000, global_compute_cap: 100, global_depth_cap: 10, ..Default::default() };
        for phase_budget in contract.phase_budgets.values_mut() {
            phase_budget.time_cap_ns = 1_000;
            phase_budget.compute_cap = 100;
            phase_budget.depth_cap = 10;
        }
        let mut m = BudgetMonitor::new(contract);
        m.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        m.record_consumption(500, 50, 5).unwrap();

        let util = m.utilization();
        assert_eq!(*util.get(&BudgetDimension::Time).unwrap(), 500_000); // 50%
        assert_eq!(*util.get(&BudgetDimension::Compute).unwrap(), 500_000);
        assert_eq!(*util.get(&BudgetDimension::Depth).unwrap(), 500_000);
    }

    #[test]
    fn phase_consumption_zero_is_all_zeros() {
        let z = PhaseConsumption::zero();
        assert_eq!(z.time_ns, 0);
        assert_eq!(z.compute, 0);
        assert_eq!(z.depth, 0);
    }

    #[test]
    fn phase_budget_not_exceeded_at_boundary() {
        let budget = PhaseBudget {
            time_cap_ns: 100,
            compute_cap: 50,
            depth_cap: 10,
        };
        let at_limit = PhaseConsumption {
            time_ns: 100,
            compute: 50,
            depth: 10,
        };
        assert!(!budget.is_exceeded(&at_limit));
    }

    #[test]
    fn phase_budget_exceeded_one_over() {
        let budget = PhaseBudget {
            time_cap_ns: 100,
            compute_cap: 50,
            depth_cap: 10,
        };
        let over = PhaseConsumption {
            time_ns: 101,
            compute: 50,
            depth: 10,
        };
        assert!(budget.is_exceeded(&over));
        let dims = budget.exceeded_dimensions(&over);
        assert_eq!(dims, vec![BudgetDimension::Time]);
    }

    #[test]
    fn synthesis_phase_all_four_distinct_display() {
        let displays: std::collections::BTreeSet<String> =
            SynthesisPhase::ALL.iter().map(|p| p.to_string()).collect();
        assert_eq!(displays.len(), 4);
    }

    #[test]
    fn budget_dimension_display_all_distinct() {
        let dims = [
            BudgetDimension::Time,
            BudgetDimension::Compute,
            BudgetDimension::Depth,
        ];
        let displays: std::collections::BTreeSet<String> =
            dims.iter().map(|d| d.to_string()).collect();
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn fallback_quality_ordering_batch2() {
        assert!(FallbackQuality::StaticBound < FallbackQuality::PartialAblation);
        assert!(FallbackQuality::PartialAblation < FallbackQuality::UnverifiedFull);
    }

    #[test]
    fn fallback_result_serde_roundtrip_batch2() {
        let fr = FallbackResult {
            quality: FallbackQuality::PartialAblation,
            result_digest: "abc123".into(),
            exhaustion_reason: ExhaustionReason {
                exceeded_dimensions: vec![BudgetDimension::Time],
                phase: SynthesisPhase::Ablation,
                global_limit_hit: false,
                consumption: PhaseConsumption {
                    time_ns: 100,
                    compute: 50,
                    depth: 5,
                },
                limit_value: 50,
            },
            increase_likely_helpful: true,
            recommended_multiplier: Some(2_000_000),
        };
        let json = serde_json::to_string(&fr).unwrap();
        let back: FallbackResult = serde_json::from_str(&json).unwrap();
        assert_eq!(fr, back);
    }

    #[test]
    fn monitor_remaining_for_current_phase_decreases() {
        let mut contract = SynthesisBudgetContract { global_time_cap_ns: 10_000, global_compute_cap: 1_000, global_depth_cap: 100, ..Default::default() };
        contract.phase_budgets.insert(
            SynthesisPhase::StaticAnalysis,
            PhaseBudget {
                time_cap_ns: 5_000,
                compute_cap: 500,
                depth_cap: 50,
            },
        );
        let mut m = BudgetMonitor::new(contract);
        m.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        m.record_consumption(1_000, 100, 10).unwrap();

        let rem = m.remaining_for_current_phase().unwrap();
        assert_eq!(rem.time_ns, 4_000);
        assert_eq!(rem.compute, 400);
        assert_eq!(rem.depth, 40);
    }

    #[test]
    fn budget_override_serde_roundtrip_batch2() {
        let ovr = BudgetOverride {
            extension_id: "ext-test".into(),
            contract: SynthesisBudgetContract::default(),
            justification: "testing".into(),
        };
        let json = serde_json::to_string(&ovr).unwrap();
        let back: BudgetOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(ovr, back);
    }

    #[test]
    fn exhaustion_reason_display_includes_phase_and_dimension() {
        let reason = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Time, BudgetDimension::Compute],
            phase: SynthesisPhase::Ablation,
            global_limit_hit: true,
            consumption: PhaseConsumption::zero(),
            limit_value: 100,
        };
        let s = reason.to_string();
        assert!(s.contains("ablation"));
        assert!(s.contains("time"));
        assert!(s.contains("compute"));
        assert!(s.contains("global=true"));
    }

    // -- Enrichment batch 3: PearlTower 2026-02-27 --

    #[test]
    fn phase_budget_clone_equality() {
        let a = PhaseBudget {
            time_cap_ns: 5000,
            compute_cap: 250,
            depth_cap: 42,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn phase_consumption_clone_equality() {
        let a = PhaseConsumption {
            time_ns: 12345,
            compute: 678,
            depth: 9,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn exhaustion_reason_clone_equality() {
        let a = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Compute, BudgetDimension::Depth],
            phase: SynthesisPhase::TheoremChecking,
            global_limit_hit: true,
            consumption: PhaseConsumption {
                time_ns: 999,
                compute: 888,
                depth: 77,
            },
            limit_value: 500,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn fallback_result_clone_equality() {
        let a = FallbackResult {
            quality: FallbackQuality::UnverifiedFull,
            result_digest: "deadbeef".to_string(),
            exhaustion_reason: ExhaustionReason {
                exceeded_dimensions: vec![BudgetDimension::Time],
                phase: SynthesisPhase::ResultAssembly,
                global_limit_hit: false,
                consumption: PhaseConsumption {
                    time_ns: 3000,
                    compute: 200,
                    depth: 15,
                },
                limit_value: 2500,
            },
            increase_likely_helpful: false,
            recommended_multiplier: None,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn budget_history_entry_clone_equality() {
        let mut pc = BTreeMap::new();
        pc.insert(
            SynthesisPhase::StaticAnalysis,
            PhaseConsumption {
                time_ns: 100,
                compute: 10,
                depth: 1,
            },
        );
        let a = BudgetHistoryEntry {
            extension_id: "ext-clone".to_string(),
            contract_version: 3,
            phase_consumption: pc,
            total_consumption: PhaseConsumption {
                time_ns: 100,
                compute: 10,
                depth: 1,
            },
            exhausted: false,
            timestamp_ns: 42_000_000,
            epoch: SecurityEpoch::from_raw(7),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn synthesis_budget_contract_json_field_presence() {
        let c = tight_contract();
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"global_time_cap_ns\""));
        assert!(json.contains("\"global_compute_cap\""));
        assert!(json.contains("\"global_depth_cap\""));
        assert!(json.contains("\"phase_budgets\""));
        assert!(json.contains("\"epoch\""));
    }

    #[test]
    fn fallback_result_json_field_presence() {
        let fb = FallbackResult {
            quality: FallbackQuality::StaticBound,
            result_digest: "cafe".to_string(),
            exhaustion_reason: ExhaustionReason {
                exceeded_dimensions: vec![BudgetDimension::Depth],
                phase: SynthesisPhase::StaticAnalysis,
                global_limit_hit: false,
                consumption: PhaseConsumption::zero(),
                limit_value: 10,
            },
            increase_likely_helpful: true,
            recommended_multiplier: Some(3_000_000),
        };
        let json = serde_json::to_string(&fb).unwrap();
        assert!(json.contains("\"quality\""));
        assert!(json.contains("\"result_digest\""));
        assert!(json.contains("\"increase_likely_helpful\""));
        assert!(json.contains("\"recommended_multiplier\""));
    }

    #[test]
    fn budget_history_entry_json_field_presence() {
        let entry = BudgetHistoryEntry {
            extension_id: "ext-fields".to_string(),
            contract_version: 1,
            phase_consumption: BTreeMap::new(),
            total_consumption: PhaseConsumption::zero(),
            exhausted: true,
            timestamp_ns: 9999,
            epoch: SecurityEpoch::from_raw(0),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"contract_version\""));
        assert!(json.contains("\"exhausted\""));
        assert!(json.contains("\"timestamp_ns\""));
    }

    #[test]
    fn budget_error_source_is_none() {
        use std::error::Error;
        let errs: Vec<BudgetError> = vec![
            BudgetError::AlreadyExhausted,
            BudgetError::NoActivePhase,
            BudgetError::Exhausted(ExhaustionReason {
                exceeded_dimensions: vec![BudgetDimension::Compute],
                phase: SynthesisPhase::Ablation,
                global_limit_hit: false,
                consumption: PhaseConsumption::zero(),
                limit_value: 100,
            }),
        ];
        for err in &errs {
            assert!(err.source().is_none());
        }
    }

    #[test]
    fn monitor_saturating_add_does_not_overflow() {
        let contract = SynthesisBudgetContract { global_time_cap_ns: u64::MAX, global_compute_cap: u64::MAX, global_depth_cap: u64::MAX, ..Default::default() };
        let mut m = BudgetMonitor::new(contract);
        m.begin_phase(SynthesisPhase::StaticAnalysis).unwrap();
        m.record_consumption(u64::MAX - 1, 0, 0).unwrap();
        // Adding more should saturate at u64::MAX, not panic.
        m.record_consumption(10, 0, 0).unwrap();
        assert_eq!(m.total_consumption().time_ns, u64::MAX);
    }

    #[test]
    fn exhaustion_reason_display_single_dimension() {
        let reason_time = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Time],
            phase: SynthesisPhase::StaticAnalysis,
            global_limit_hit: false,
            consumption: PhaseConsumption::zero(),
            limit_value: 500,
        };
        let reason_depth = ExhaustionReason {
            exceeded_dimensions: vec![BudgetDimension::Depth],
            phase: SynthesisPhase::ResultAssembly,
            global_limit_hit: true,
            consumption: PhaseConsumption::zero(),
            limit_value: 10,
        };
        let s1 = reason_time.to_string();
        let s2 = reason_depth.to_string();
        assert_ne!(
            s1, s2,
            "different exhaustion reasons should produce different Display"
        );
        assert!(s1.contains("static-analysis"));
        assert!(s2.contains("result-assembly"));
        assert!(s1.contains("global=false"));
        assert!(s2.contains("global=true"));
    }

    #[test]
    fn history_average_utilization_empty_returns_empty_map() {
        let history = BudgetHistory::new(10);
        let contract = tight_contract();
        let avg = history.average_utilization("nonexistent-ext", &contract);
        assert!(avg.is_empty());
    }
}
