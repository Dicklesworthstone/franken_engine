#![forbid(unsafe_code)]

//! Optimized metadata substrate: explicit substrate implementations for
//! hot runtime metadata with deterministic override, rollback, and
//! generic-fallback paths.
//!
//! Bead: bd-1lsy.7.26.2 [RGC-626B]
//!
//! Consumes the inventory from `metadata_substrate_inventory` and implements
//! the actual substrate selection, instantiation, override, and rollback
//! logic. Each substrate instance carries a content-addressed receipt so
//! operators can tell which substrate is active, why it was chosen, and
//! how to force a fallback or override.
//!
//! # Design decisions
//!
//! - Every substrate instance is gated by a `SubstrateSelectionReceipt`
//!   linking the chosen substrate to the inventory contract and override
//!   reason (if any).
//! - Override and fallback paths are explicit: an operator can force a
//!   generic fallback for debugging via `OverridePolicy`, and every such
//!   override is recorded with a reason.
//! - Rollback is epoch-fenced: `SubstrateSnapshot` captures the state at
//!   a given epoch and can be restored deterministically.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::metadata_substrate_inventory::{
    FallbackMode, LocalityGoal, MetadataStructureKind, RollbackRule, SubstrateAssignment,
    SubstrateContract, SubstrateInventory, SubstrateKind,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the optimized metadata substrate module.
pub const OPTIMIZED_SUBSTRATE_SCHEMA_VERSION: &str =
    "franken-engine.optimized-metadata-substrate.v1";

/// Bead identifier for this module.
pub const OPTIMIZED_SUBSTRATE_BEAD_ID: &str = "bd-1lsy.7.26.2";

/// Component name.
pub const COMPONENT: &str = "optimized_metadata_substrate";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// SubstrateInstanceStatus
// ---------------------------------------------------------------------------

/// Lifecycle status of an instantiated substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateInstanceStatus {
    /// Active and serving lookups on the hot path.
    Active,
    /// Warming up — populated but not yet serving.
    Warming,
    /// Paused for diagnostics or override evaluation.
    Paused,
    /// Fallen back to generic substrate.
    FallenBack,
    /// Rolled back to a prior epoch snapshot.
    RolledBack,
    /// Decommissioned — no longer in use.
    Decommissioned,
}

impl SubstrateInstanceStatus {
    /// All known statuses in canonical order.
    pub const ALL: &[Self] = &[
        Self::Active,
        Self::Warming,
        Self::Paused,
        Self::FallenBack,
        Self::RolledBack,
        Self::Decommissioned,
    ];
}

impl fmt::Display for SubstrateInstanceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Active => "active",
            Self::Warming => "warming",
            Self::Paused => "paused",
            Self::FallenBack => "fallen_back",
            Self::RolledBack => "rolled_back",
            Self::Decommissioned => "decommissioned",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// OverrideReason
// ---------------------------------------------------------------------------

/// Why an operator or runtime overrode the contract-assigned substrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideReason {
    /// Operator explicitly forced a generic fallback for debugging.
    OperatorDebug,
    /// Runtime detected substrate corruption and fell back.
    CorruptionDetected,
    /// Portability triage: target lacks hardware for optimized substrate.
    PortabilityFallback,
    /// Memory pressure forced demotion to smaller substrate.
    MemoryPressure,
    /// Performance regression detected; substrate demoted.
    PerformanceRegression,
    /// Rollback to a prior epoch snapshot.
    EpochRollback,
    /// Security policy vetoed the optimized substrate.
    SecurityVeto,
    /// No override — using contract-assigned substrate.
    None,
}

impl OverrideReason {
    /// All known override reasons in canonical order.
    pub const ALL: &[Self] = &[
        Self::OperatorDebug,
        Self::CorruptionDetected,
        Self::PortabilityFallback,
        Self::MemoryPressure,
        Self::PerformanceRegression,
        Self::EpochRollback,
        Self::SecurityVeto,
        Self::None,
    ];

    /// Whether this is actually an override (vs. no-override).
    pub fn is_override(self) -> bool {
        self != Self::None
    }
}

impl fmt::Display for OverrideReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::OperatorDebug => "operator_debug",
            Self::CorruptionDetected => "corruption_detected",
            Self::PortabilityFallback => "portability_fallback",
            Self::MemoryPressure => "memory_pressure",
            Self::PerformanceRegression => "performance_regression",
            Self::EpochRollback => "epoch_rollback",
            Self::SecurityVeto => "security_veto",
            Self::None => "none",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// OverridePolicy
// ---------------------------------------------------------------------------

/// Policy governing when and how substrate overrides are permitted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct OverridePolicy {
    /// Whether operator debug overrides are allowed.
    pub allow_operator_debug: bool,
    /// Whether automatic fallback on corruption is enabled.
    pub allow_corruption_fallback: bool,
    /// Whether portability fallback is enabled.
    pub allow_portability_fallback: bool,
    /// Whether memory-pressure demotion is enabled.
    pub allow_memory_demotion: bool,
    /// Whether performance-regression demotion is enabled.
    pub allow_performance_demotion: bool,
    /// Whether security-policy vetoes are honored.
    pub honor_security_veto: bool,
    /// Content hash over policy configuration.
    pub policy_hash: ContentHash,
}

impl OverridePolicy {
    /// Create a new override policy with all overrides permitted.
    pub fn permissive() -> Self {
        let mut p = Self {
            allow_operator_debug: true,
            allow_corruption_fallback: true,
            allow_portability_fallback: true,
            allow_memory_demotion: true,
            allow_performance_demotion: true,
            honor_security_veto: true,
            policy_hash: ContentHash::compute(b"placeholder"),
        };
        p.recompute_hash();
        p
    }

    /// Create a restrictive policy where only corruption and security
    /// overrides are allowed.
    pub fn restrictive() -> Self {
        let mut p = Self {
            allow_operator_debug: false,
            allow_corruption_fallback: true,
            allow_portability_fallback: false,
            allow_memory_demotion: false,
            allow_performance_demotion: false,
            honor_security_veto: true,
            policy_hash: ContentHash::compute(b"placeholder"),
        };
        p.recompute_hash();
        p
    }

    /// Create a locked-down policy where no overrides are permitted.
    pub fn locked() -> Self {
        let mut p = Self {
            allow_operator_debug: false,
            allow_corruption_fallback: false,
            allow_portability_fallback: false,
            allow_memory_demotion: false,
            allow_performance_demotion: false,
            honor_security_veto: false,
            policy_hash: ContentHash::compute(b"placeholder"),
        };
        p.recompute_hash();
        p
    }

    /// Check whether a given override reason is permitted by this policy.
    pub fn is_permitted(&self, reason: OverrideReason) -> bool {
        match reason {
            OverrideReason::OperatorDebug => self.allow_operator_debug,
            OverrideReason::CorruptionDetected => self.allow_corruption_fallback,
            OverrideReason::PortabilityFallback => self.allow_portability_fallback,
            OverrideReason::MemoryPressure => self.allow_memory_demotion,
            OverrideReason::PerformanceRegression => self.allow_performance_demotion,
            OverrideReason::SecurityVeto => self.honor_security_veto,
            OverrideReason::EpochRollback => true, // always allowed
            OverrideReason::None => true,
        }
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let canonical = format!(
            "override_policy:{}:{}:{}:{}:{}:{}",
            self.allow_operator_debug,
            self.allow_corruption_fallback,
            self.allow_portability_fallback,
            self.allow_memory_demotion,
            self.allow_performance_demotion,
            self.honor_security_veto,
        );
        self.policy_hash = ContentHash::compute(canonical.as_bytes());
    }
}

impl fmt::Display for OverridePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let permitted: Vec<&str> = [
            (self.allow_operator_debug, "debug"),
            (self.allow_corruption_fallback, "corruption"),
            (self.allow_portability_fallback, "portability"),
            (self.allow_memory_demotion, "memory"),
            (self.allow_performance_demotion, "perf"),
            (self.honor_security_veto, "security"),
        ]
        .iter()
        .filter(|(allowed, _)| *allowed)
        .map(|(_, name)| *name)
        .collect();
        write!(f, "OverridePolicy(permits=[{}])", permitted.join(","))
    }
}

// ---------------------------------------------------------------------------
// SubstrateSelectionReceipt
// ---------------------------------------------------------------------------

/// Receipt proving which substrate was selected, why, and whether an
/// override was applied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubstrateSelectionReceipt {
    /// The metadata structure this receipt governs.
    pub structure_kind: MetadataStructureKind,
    /// The substrate selected for this structure.
    pub selected_substrate: SubstrateKind,
    /// Locality goal the selection targets.
    pub locality_goal: LocalityGoal,
    /// The original contract-assigned substrate (before override).
    pub contract_substrate: SubstrateKind,
    /// Whether an override was applied.
    pub override_applied: bool,
    /// Reason for the override (None if no override).
    pub override_reason: OverrideReason,
    /// Human-readable explanation of the selection decision.
    pub selection_rationale: String,
    /// Epoch at which the selection was made.
    pub selection_epoch: SecurityEpoch,
    /// Content hash of the inventory contract that was consulted.
    pub contract_hash: ContentHash,
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
}

impl SubstrateSelectionReceipt {
    /// Create a receipt for a contract-assigned selection (no override).
    pub fn from_contract(
        contract: &SubstrateContract,
        epoch: SecurityEpoch,
        rationale: &str,
    ) -> Self {
        let mut receipt = Self {
            structure_kind: contract.structure_kind,
            selected_substrate: contract.substrate_kind,
            locality_goal: contract.locality_goal,
            contract_substrate: contract.substrate_kind,
            override_applied: false,
            override_reason: OverrideReason::None,
            selection_rationale: rationale.to_string(),
            selection_epoch: epoch,
            contract_hash: contract.content_hash.clone(),
            receipt_hash: ContentHash::compute(b"placeholder"),
        };
        receipt.recompute_hash();
        receipt
    }

    /// Create a receipt for an overridden selection.
    pub fn from_override(
        contract: &SubstrateContract,
        override_substrate: SubstrateKind,
        override_locality: LocalityGoal,
        reason: OverrideReason,
        epoch: SecurityEpoch,
        rationale: &str,
    ) -> Self {
        let mut receipt = Self {
            structure_kind: contract.structure_kind,
            selected_substrate: override_substrate,
            locality_goal: override_locality,
            contract_substrate: contract.substrate_kind,
            override_applied: true,
            override_reason: reason,
            selection_rationale: rationale.to_string(),
            selection_epoch: epoch,
            contract_hash: contract.content_hash.clone(),
            receipt_hash: ContentHash::compute(b"placeholder"),
        };
        receipt.recompute_hash();
        receipt
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let canonical = format!(
            "receipt:{}:{}:{}:{}:{}:{}:{}:{}",
            self.structure_kind,
            self.selected_substrate,
            self.locality_goal,
            self.contract_substrate,
            self.override_applied,
            self.override_reason,
            self.selection_epoch.as_u64(),
            self.contract_hash.to_hex(),
        );
        self.receipt_hash = ContentHash::compute(canonical.as_bytes());
    }
}

impl fmt::Display for SubstrateSelectionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.override_applied {
            write!(
                f,
                "SelectionReceipt({} -> {} [overrode {} reason={}] epoch={})",
                self.structure_kind,
                self.selected_substrate,
                self.contract_substrate,
                self.override_reason,
                self.selection_epoch.as_u64(),
            )
        } else {
            write!(
                f,
                "SelectionReceipt({} -> {} epoch={})",
                self.structure_kind,
                self.selected_substrate,
                self.selection_epoch.as_u64(),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// SubstrateSnapshot
// ---------------------------------------------------------------------------

/// A snapshot of substrate state at a given epoch for rollback.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubstrateSnapshot {
    /// The metadata structure this snapshot covers.
    pub structure_kind: MetadataStructureKind,
    /// The substrate that was active at snapshot time.
    pub substrate_kind: SubstrateKind,
    /// Status at snapshot time.
    pub status: SubstrateInstanceStatus,
    /// Epoch at which the snapshot was taken.
    pub snapshot_epoch: SecurityEpoch,
    /// Number of entries in the substrate at snapshot time.
    pub entry_count: u64,
    /// Content hash of the substrate state.
    pub state_hash: ContentHash,
    /// Content hash of this snapshot record.
    pub snapshot_hash: ContentHash,
}

impl SubstrateSnapshot {
    /// Create a new snapshot.
    pub fn new(
        structure_kind: MetadataStructureKind,
        substrate_kind: SubstrateKind,
        status: SubstrateInstanceStatus,
        epoch: SecurityEpoch,
        entry_count: u64,
        state_hash: ContentHash,
    ) -> Self {
        let mut snap = Self {
            structure_kind,
            substrate_kind,
            status,
            snapshot_epoch: epoch,
            entry_count,
            state_hash,
            snapshot_hash: ContentHash::compute(b"placeholder"),
        };
        snap.recompute_hash();
        snap
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let canonical = format!(
            "snapshot:{}:{}:{}:{}:{}:{}",
            self.structure_kind,
            self.substrate_kind,
            self.status,
            self.snapshot_epoch.as_u64(),
            self.entry_count,
            self.state_hash.to_hex(),
        );
        self.snapshot_hash = ContentHash::compute(canonical.as_bytes());
    }
}

impl fmt::Display for SubstrateSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateSnapshot({} {} status={} epoch={} entries={})",
            self.structure_kind,
            self.substrate_kind,
            self.status,
            self.snapshot_epoch.as_u64(),
            self.entry_count,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateInstance
// ---------------------------------------------------------------------------

/// An instantiated substrate for a specific metadata structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateInstance {
    /// Which metadata structure this instance serves.
    pub structure_kind: MetadataStructureKind,
    /// The active substrate implementation.
    pub substrate_kind: SubstrateKind,
    /// Locality goal for this instance.
    pub locality_goal: LocalityGoal,
    /// Current lifecycle status.
    pub status: SubstrateInstanceStatus,
    /// Fallback mode if the primary substrate fails.
    pub fallback_mode: FallbackMode,
    /// Rollback rule governing epoch transitions.
    pub rollback_rule: RollbackRule,
    /// The selection receipt that authorized this instance.
    pub selection_receipt: SubstrateSelectionReceipt,
    /// Current entry count.
    pub entry_count: u64,
    /// Maximum entry count from the contract.
    pub max_entry_count: u64,
    /// Snapshots for rollback support.
    pub snapshots: Vec<SubstrateSnapshot>,
    /// Load factor in millionths (entries / max_entries * MILLION).
    pub load_factor_millionths: u64,
    /// Content hash of the current instance state.
    pub instance_hash: ContentHash,
}

impl SubstrateInstance {
    /// Instantiate from a contract and selection receipt.
    pub fn from_contract(contract: &SubstrateContract, receipt: SubstrateSelectionReceipt) -> Self {
        let mut inst = Self {
            structure_kind: contract.structure_kind,
            substrate_kind: receipt.selected_substrate,
            locality_goal: receipt.locality_goal,
            status: SubstrateInstanceStatus::Warming,
            fallback_mode: contract.fallback_mode,
            rollback_rule: contract.rollback_rule,
            selection_receipt: receipt,
            entry_count: 0,
            max_entry_count: contract.max_entry_count,
            snapshots: Vec::new(),
            load_factor_millionths: 0,
            instance_hash: ContentHash::compute(b"placeholder"),
        };
        inst.recompute_hash();
        inst
    }

    /// Activate the instance (transition from warming to active).
    pub fn activate(&mut self) {
        self.status = SubstrateInstanceStatus::Active;
        self.recompute_hash();
    }

    /// Record entries and update load factor.
    pub fn record_entries(&mut self, count: u64) {
        self.entry_count = count;
        self.load_factor_millionths = count
            .saturating_mul(MILLION)
            .checked_div(self.max_entry_count)
            .unwrap_or(0);
        self.recompute_hash();
    }

    /// Take a snapshot at the current epoch for rollback.
    pub fn take_snapshot(&mut self, epoch: SecurityEpoch) -> SubstrateSnapshot {
        let state_hash = self.instance_hash.clone();
        let snapshot = SubstrateSnapshot::new(
            self.structure_kind,
            self.substrate_kind,
            self.status,
            epoch,
            self.entry_count,
            state_hash,
        );
        self.snapshots.push(snapshot.clone());
        snapshot
    }

    /// Restore from a snapshot (rollback).
    pub fn restore_from_snapshot(&mut self, snapshot: &SubstrateSnapshot) {
        self.substrate_kind = snapshot.substrate_kind;
        self.status = SubstrateInstanceStatus::RolledBack;
        self.entry_count = snapshot.entry_count;
        self.load_factor_millionths = snapshot
            .entry_count
            .saturating_mul(MILLION)
            .checked_div(self.max_entry_count)
            .unwrap_or(0);
        self.recompute_hash();
    }

    /// Fall back to the generic substrate.
    pub fn fallback(&mut self, reason: OverrideReason) {
        self.status = SubstrateInstanceStatus::FallenBack;
        self.selection_receipt.override_applied = true;
        self.selection_receipt.override_reason = reason;
        // Demote to the most generic substrate (FlatArray) for debugging
        self.substrate_kind = SubstrateKind::FlatArray;
        self.locality_goal = LocalityGoal::DramResident;
        self.recompute_hash();
    }

    /// Decommission the instance.
    pub fn decommission(&mut self) {
        self.status = SubstrateInstanceStatus::Decommissioned;
        self.recompute_hash();
    }

    /// Whether this instance is in a serving state.
    pub fn is_serving(&self) -> bool {
        matches!(
            self.status,
            SubstrateInstanceStatus::Active | SubstrateInstanceStatus::Warming
        )
    }

    /// Whether the load factor exceeds a threshold (in millionths).
    pub fn is_overloaded(&self, threshold_millionths: u64) -> bool {
        self.load_factor_millionths > threshold_millionths
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let canonical = format!(
            "instance:{}:{}:{}:{}:{}:{}:{}",
            self.structure_kind,
            self.substrate_kind,
            self.locality_goal,
            self.status,
            self.entry_count,
            self.max_entry_count,
            self.load_factor_millionths,
        );
        self.instance_hash = ContentHash::compute(canonical.as_bytes());
    }
}

impl fmt::Display for SubstrateInstance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateInstance({} {} status={} entries={}/{} load={})",
            self.structure_kind,
            self.substrate_kind,
            self.status,
            self.entry_count,
            self.max_entry_count,
            self.load_factor_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateSelector
// ---------------------------------------------------------------------------

/// Selects and instantiates substrates from an inventory, applying override
/// policies and recording selection receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubstrateSelector {
    /// Override policy governing permitted overrides.
    pub override_policy: OverridePolicy,
    /// The epoch at which selections are being made.
    pub selection_epoch: SecurityEpoch,
    /// Selection receipts for all instantiated substrates.
    pub receipts: Vec<SubstrateSelectionReceipt>,
    /// Instantiated substrates.
    pub instances: Vec<SubstrateInstance>,
    /// Schema version.
    pub schema_version: String,
    /// Content hash of the selector state.
    pub selector_hash: ContentHash,
}

impl SubstrateSelector {
    /// Create a new selector with the given policy and epoch.
    pub fn new(override_policy: OverridePolicy, epoch: SecurityEpoch) -> Self {
        let mut sel = Self {
            override_policy,
            selection_epoch: epoch,
            receipts: Vec::new(),
            instances: Vec::new(),
            schema_version: OPTIMIZED_SUBSTRATE_SCHEMA_VERSION.to_string(),
            selector_hash: ContentHash::compute(b"placeholder"),
        };
        sel.recompute_hash();
        sel
    }

    /// Select and instantiate a substrate from a contract assignment.
    pub fn select_from_contract(&mut self, assignment: &SubstrateAssignment) -> SubstrateInstance {
        let receipt = SubstrateSelectionReceipt::from_contract(
            &assignment.contract,
            self.selection_epoch,
            &assignment.rationale,
        );
        let instance = SubstrateInstance::from_contract(&assignment.contract, receipt.clone());
        self.receipts.push(receipt);
        self.instances.push(instance.clone());
        self.recompute_hash();
        instance
    }

    /// Select with an override (e.g., operator debug fallback).
    pub fn select_with_override(
        &mut self,
        assignment: &SubstrateAssignment,
        override_substrate: SubstrateKind,
        override_locality: LocalityGoal,
        reason: OverrideReason,
        rationale: &str,
    ) -> Result<SubstrateInstance, SubstrateSelectionError> {
        if !self.override_policy.is_permitted(reason) {
            return Err(SubstrateSelectionError::OverrideDenied {
                structure_kind: assignment.contract.structure_kind,
                reason,
            });
        }
        let receipt = SubstrateSelectionReceipt::from_override(
            &assignment.contract,
            override_substrate,
            override_locality,
            reason,
            self.selection_epoch,
            rationale,
        );
        let mut instance = SubstrateInstance::from_contract(&assignment.contract, receipt.clone());
        instance.substrate_kind = override_substrate;
        instance.locality_goal = override_locality;
        instance.recompute_hash();
        self.receipts.push(receipt);
        self.instances.push(instance.clone());
        self.recompute_hash();
        Ok(instance)
    }

    /// Instantiate all substrates from an inventory using contract defaults.
    pub fn instantiate_all(&mut self, inventory: &SubstrateInventory) -> Vec<SubstrateInstance> {
        let mut result = Vec::new();
        for assignment in &inventory.assignments {
            result.push(self.select_from_contract(assignment));
        }
        result
    }

    /// Get instance for a specific structure kind.
    pub fn instance_for(&self, kind: MetadataStructureKind) -> Option<&SubstrateInstance> {
        self.instances.iter().find(|i| i.structure_kind == kind)
    }

    /// Get mutable instance for a specific structure kind.
    pub fn instance_for_mut(
        &mut self,
        kind: MetadataStructureKind,
    ) -> Option<&mut SubstrateInstance> {
        self.instances.iter_mut().find(|i| i.structure_kind == kind)
    }

    /// Count active instances.
    pub fn active_count(&self) -> usize {
        self.instances.iter().filter(|i| i.is_serving()).count()
    }

    /// Count overridden instances.
    pub fn overridden_count(&self) -> usize {
        self.receipts.iter().filter(|r| r.override_applied).count()
    }

    /// Compute a summary report.
    pub fn summary_report(&self) -> SelectorSummaryReport {
        let total = self.instances.len();
        let active = self.active_count();
        let overridden = self.overridden_count();
        let fallen_back = self
            .instances
            .iter()
            .filter(|i| i.status == SubstrateInstanceStatus::FallenBack)
            .count();
        let rolled_back = self
            .instances
            .iter()
            .filter(|i| i.status == SubstrateInstanceStatus::RolledBack)
            .count();
        let structure_kinds_covered: BTreeSet<MetadataStructureKind> =
            self.instances.iter().map(|i| i.structure_kind).collect();
        let coverage = if MetadataStructureKind::ALL.is_empty() {
            0
        } else {
            (structure_kinds_covered.len() as u64).saturating_mul(MILLION)
                / (MetadataStructureKind::ALL.len() as u64)
        };
        SelectorSummaryReport {
            total_instances: total,
            active_instances: active,
            overridden_instances: overridden,
            fallen_back_instances: fallen_back,
            rolled_back_instances: rolled_back,
            coverage_millionths: coverage,
            epoch: self.selection_epoch,
        }
    }

    /// Recompute the content hash.
    fn recompute_hash(&mut self) {
        let mut canonical = String::new();
        canonical.push_str(&self.schema_version);
        canonical.push(':');
        canonical.push_str(&self.selection_epoch.as_u64().to_string());
        canonical.push(':');
        canonical.push_str(&self.override_policy.policy_hash.to_hex());
        canonical.push(':');
        for receipt in &self.receipts {
            canonical.push_str(&receipt.receipt_hash.to_hex());
            canonical.push(';');
        }
        self.selector_hash = ContentHash::compute(canonical.as_bytes());
    }
}

impl fmt::Display for SubstrateSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SubstrateSelector(instances={} overrides={} epoch={})",
            self.instances.len(),
            self.overridden_count(),
            self.selection_epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// SelectorSummaryReport
// ---------------------------------------------------------------------------

/// Summary report of the selector's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectorSummaryReport {
    /// Total number of substrate instances.
    pub total_instances: usize,
    /// Number of instances in active/warming state.
    pub active_instances: usize,
    /// Number of instances with an override applied.
    pub overridden_instances: usize,
    /// Number of instances in fallen-back state.
    pub fallen_back_instances: usize,
    /// Number of instances in rolled-back state.
    pub rolled_back_instances: usize,
    /// Coverage of all structure kinds (millionths).
    pub coverage_millionths: u64,
    /// Epoch of the selector.
    pub epoch: SecurityEpoch,
}

impl fmt::Display for SelectorSummaryReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SelectorSummary(total={} active={} overridden={} fallback={} rollback={} coverage={})",
            self.total_instances,
            self.active_instances,
            self.overridden_instances,
            self.fallen_back_instances,
            self.rolled_back_instances,
            self.coverage_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateSelectionError
// ---------------------------------------------------------------------------

/// Errors that can occur during substrate selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateSelectionError {
    /// Override was denied by the policy.
    OverrideDenied {
        structure_kind: MetadataStructureKind,
        reason: OverrideReason,
    },
    /// No contract found for the given structure kind.
    NoContractFound {
        structure_kind: MetadataStructureKind,
    },
    /// Instance already decommissioned.
    AlreadyDecommissioned {
        structure_kind: MetadataStructureKind,
    },
}

impl fmt::Display for SubstrateSelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OverrideDenied {
                structure_kind,
                reason,
            } => write!(
                f,
                "override denied for {} (reason: {})",
                structure_kind, reason
            ),
            Self::NoContractFound { structure_kind } => {
                write!(f, "no contract found for {}", structure_kind)
            }
            Self::AlreadyDecommissioned { structure_kind } => {
                write!(f, "{} already decommissioned", structure_kind)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SubstrateHealthCheck
// ---------------------------------------------------------------------------

/// Health check result for a substrate instance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubstrateHealthCheck {
    /// The structure kind being checked.
    pub structure_kind: MetadataStructureKind,
    /// Whether the substrate passed the health check.
    pub healthy: bool,
    /// Load factor at check time (millionths).
    pub load_factor_millionths: u64,
    /// Whether the load exceeds the contract threshold.
    pub overloaded: bool,
    /// Whether the substrate is in a serving state.
    pub serving: bool,
    /// Epoch at which the check was performed.
    pub check_epoch: SecurityEpoch,
    /// Diagnostic message.
    pub diagnostic: String,
    /// Content hash of the check.
    pub check_hash: ContentHash,
}

impl SubstrateHealthCheck {
    /// Run a health check on a substrate instance.
    pub fn check(instance: &SubstrateInstance, epoch: SecurityEpoch) -> Self {
        let overloaded = instance.is_overloaded(800_000); // 80% threshold
        let serving = instance.is_serving();
        let healthy = serving && !overloaded;
        let diagnostic = if healthy {
            format!(
                "{} healthy: {} entries, {}% load",
                instance.structure_kind,
                instance.entry_count,
                instance.load_factor_millionths / 10_000,
            )
        } else if overloaded {
            format!(
                "{} overloaded: {} entries, {}% load (threshold 80%)",
                instance.structure_kind,
                instance.entry_count,
                instance.load_factor_millionths / 10_000,
            )
        } else {
            format!(
                "{} not serving: status={}",
                instance.structure_kind, instance.status,
            )
        };

        let canonical = format!(
            "healthcheck:{}:{}:{}:{}:{}",
            instance.structure_kind,
            healthy,
            instance.load_factor_millionths,
            overloaded,
            epoch.as_u64(),
        );

        Self {
            structure_kind: instance.structure_kind,
            healthy,
            load_factor_millionths: instance.load_factor_millionths,
            overloaded,
            serving,
            check_epoch: epoch,
            diagnostic,
            check_hash: ContentHash::compute(canonical.as_bytes()),
        }
    }
}

impl fmt::Display for SubstrateHealthCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HealthCheck({} healthy={} load={}% serving={})",
            self.structure_kind,
            self.healthy,
            self.load_factor_millionths / 10_000,
            self.serving,
        )
    }
}

// ---------------------------------------------------------------------------
// SubstrateTransitionEvent
// ---------------------------------------------------------------------------

/// Event recording a state transition in a substrate instance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateTransitionKind {
    /// Instance created.
    Created,
    /// Transitioned from warming to active.
    Activated,
    /// Overridden to a different substrate.
    Overridden,
    /// Fell back to generic substrate.
    FellBack,
    /// Rolled back to a snapshot.
    RolledBack,
    /// Decommissioned.
    Decommissioned,
    /// Snapshot taken.
    SnapshotTaken,
}

impl fmt::Display for SubstrateTransitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Created => "created",
            Self::Activated => "activated",
            Self::Overridden => "overridden",
            Self::FellBack => "fell_back",
            Self::RolledBack => "rolled_back",
            Self::Decommissioned => "decommissioned",
            Self::SnapshotTaken => "snapshot_taken",
        };
        write!(f, "{label}")
    }
}

/// A recorded transition event for audit trail.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubstrateTransitionEvent {
    /// The structure kind involved.
    pub structure_kind: MetadataStructureKind,
    /// What happened.
    pub transition: SubstrateTransitionKind,
    /// From substrate (if applicable).
    pub from_substrate: Option<SubstrateKind>,
    /// To substrate.
    pub to_substrate: SubstrateKind,
    /// Epoch of the transition.
    pub epoch: SecurityEpoch,
    /// Human-readable reason.
    pub reason: String,
    /// Content hash of the event.
    pub event_hash: ContentHash,
}

impl SubstrateTransitionEvent {
    /// Create a new transition event.
    pub fn new(
        structure_kind: MetadataStructureKind,
        transition: SubstrateTransitionKind,
        from_substrate: Option<SubstrateKind>,
        to_substrate: SubstrateKind,
        epoch: SecurityEpoch,
        reason: &str,
    ) -> Self {
        let canonical = format!(
            "transition:{}:{}:{}:{}:{}:{}",
            structure_kind,
            transition,
            from_substrate
                .map(|s| s.to_string())
                .unwrap_or_else(|| "none".to_string()),
            to_substrate,
            epoch.as_u64(),
            reason,
        );
        Self {
            structure_kind,
            transition,
            from_substrate,
            to_substrate,
            epoch,
            reason: reason.to_string(),
            event_hash: ContentHash::compute(canonical.as_bytes()),
        }
    }
}

impl fmt::Display for SubstrateTransitionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransitionEvent({} {} -> {} at epoch={})",
            self.structure_kind,
            self.transition,
            self.to_substrate,
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// Default substrate assignments
// ---------------------------------------------------------------------------

/// Produce the default optimized substrate assignments for all structure
/// kinds based on the inventory contracts.
pub fn default_optimized_assignments(epoch: SecurityEpoch) -> SubstrateInventory {
    let mut inventory = SubstrateInventory::new();

    #[allow(clippy::type_complexity)]
    let assignments: Vec<(
        MetadataStructureKind,
        SubstrateKind,
        LocalityGoal,
        FallbackMode,
        RollbackRule,
        u64,
        u64,
        &str,
    )> = vec![
        (
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
            LocalityGoal::L1Hot,
            FallbackMode::LinearScan,
            RollbackRule::SnapshottedCow,
            65536,
            850_000,
            "Shape tables are the hottest metadata; Swiss table with L1 locality",
        ),
        (
            MetadataStructureKind::InlineCacheTable,
            SubstrateKind::FlatArray,
            LocalityGoal::L1Hot,
            FallbackMode::Deoptimize,
            RollbackRule::EpochFenced,
            16384,
            900_000,
            "IC stubs need flat sequential access for speculative dispatch",
        ),
        (
            MetadataStructureKind::StringTable,
            SubstrateKind::ArtTree,
            LocalityGoal::L2Warm,
            FallbackMode::Rehash,
            RollbackRule::Immutable,
            262144,
            300_000,
            "String interning uses ART for prefix-friendly lookup",
        ),
        (
            MetadataStructureKind::ScopeChainTable,
            SubstrateKind::FlatArray,
            LocalityGoal::L1Hot,
            FallbackMode::LinearScan,
            RollbackRule::Rebuilds,
            4096,
            700_000,
            "Scope chains are shallow and sequential",
        ),
        (
            MetadataStructureKind::ModuleGraph,
            SubstrateKind::BTreeIndex,
            LocalityGoal::L3Cold,
            FallbackMode::Rehash,
            RollbackRule::Rebuilds,
            8192,
            200_000,
            "Module graphs are cold but need sorted iteration",
        ),
        (
            MetadataStructureKind::PrototypeChainTable,
            SubstrateKind::LinearProbe,
            LocalityGoal::L2Warm,
            FallbackMode::LinearScan,
            RollbackRule::SnapshottedCow,
            8192,
            600_000,
            "Prototype chains use linear probing for cache-friendly lookup",
        ),
        (
            MetadataStructureKind::TypeFeedbackVector,
            SubstrateKind::FlatArray,
            LocalityGoal::L1Hot,
            FallbackMode::Deoptimize,
            RollbackRule::EpochFenced,
            32768,
            800_000,
            "Type feedback needs sequential access for profiling",
        ),
        (
            MetadataStructureKind::CompilationCache,
            SubstrateKind::HashArray,
            LocalityGoal::L3Cold,
            FallbackMode::Recompile,
            RollbackRule::Rebuilds,
            131072,
            150_000,
            "Compilation artifacts use HAMT for large sparse lookup",
        ),
        (
            MetadataStructureKind::GcMetadata,
            SubstrateKind::CacheOblivious,
            LocalityGoal::L2Warm,
            FallbackMode::Abstain,
            RollbackRule::NoRollback,
            524288,
            500_000,
            "GC bitmaps use cache-oblivious layout for scan locality",
        ),
        (
            MetadataStructureKind::AllocationSiteTable,
            SubstrateKind::SwissTable,
            LocalityGoal::L2Warm,
            FallbackMode::LinearScan,
            RollbackRule::EpochFenced,
            16384,
            400_000,
            "Allocation site tracking uses Swiss table for fast insert",
        ),
    ];

    for (kind, substrate, locality, fallback, rollback, max_entries, hot_frac, rationale) in
        assignments
    {
        let contract = SubstrateContract::new(
            kind,
            substrate,
            locality,
            fallback,
            rollback,
            max_entries,
            hot_frac,
        );
        let assignment = SubstrateAssignment {
            contract,
            assigned_epoch: epoch,
            rationale: rationale.to_string(),
            confidence_millionths: 750_000,
        };
        inventory.add_assignment(assignment);
    }

    inventory
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn test_contract() -> SubstrateContract {
        SubstrateContract::new(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
            LocalityGoal::L1Hot,
            FallbackMode::LinearScan,
            RollbackRule::SnapshottedCow,
            65536,
            850_000,
        )
    }

    fn test_assignment() -> SubstrateAssignment {
        SubstrateAssignment {
            contract: test_contract(),
            assigned_epoch: test_epoch(),
            rationale: "Swiss table for L1 shape access".to_string(),
            confidence_millionths: 750_000,
        }
    }

    // --- SubstrateInstanceStatus ---

    #[test]
    fn test_instance_status_display() {
        assert_eq!(SubstrateInstanceStatus::Active.to_string(), "active");
        assert_eq!(SubstrateInstanceStatus::Warming.to_string(), "warming");
        assert_eq!(SubstrateInstanceStatus::Paused.to_string(), "paused");
        assert_eq!(
            SubstrateInstanceStatus::FallenBack.to_string(),
            "fallen_back"
        );
        assert_eq!(
            SubstrateInstanceStatus::RolledBack.to_string(),
            "rolled_back"
        );
        assert_eq!(
            SubstrateInstanceStatus::Decommissioned.to_string(),
            "decommissioned"
        );
    }

    #[test]
    fn test_instance_status_all() {
        assert_eq!(SubstrateInstanceStatus::ALL.len(), 6);
    }

    #[test]
    fn test_instance_status_serde_roundtrip() {
        for status in SubstrateInstanceStatus::ALL {
            let json = serde_json::to_string(status).unwrap();
            let back: SubstrateInstanceStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, back);
        }
    }

    // --- OverrideReason ---

    #[test]
    fn test_override_reason_display() {
        assert_eq!(OverrideReason::OperatorDebug.to_string(), "operator_debug");
        assert_eq!(
            OverrideReason::CorruptionDetected.to_string(),
            "corruption_detected"
        );
        assert_eq!(OverrideReason::None.to_string(), "none");
    }

    #[test]
    fn test_override_reason_is_override() {
        assert!(OverrideReason::OperatorDebug.is_override());
        assert!(OverrideReason::SecurityVeto.is_override());
        assert!(!OverrideReason::None.is_override());
    }

    #[test]
    fn test_override_reason_all() {
        assert_eq!(OverrideReason::ALL.len(), 8);
    }

    #[test]
    fn test_override_reason_serde_roundtrip() {
        for reason in OverrideReason::ALL {
            let json = serde_json::to_string(reason).unwrap();
            let back: OverrideReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    // --- OverridePolicy ---

    #[test]
    fn test_permissive_policy() {
        let policy = OverridePolicy::permissive();
        assert!(policy.allow_operator_debug);
        assert!(policy.allow_corruption_fallback);
        assert!(policy.allow_portability_fallback);
        assert!(policy.allow_memory_demotion);
        assert!(policy.allow_performance_demotion);
        assert!(policy.honor_security_veto);
    }

    #[test]
    fn test_restrictive_policy() {
        let policy = OverridePolicy::restrictive();
        assert!(!policy.allow_operator_debug);
        assert!(policy.allow_corruption_fallback);
        assert!(!policy.allow_portability_fallback);
        assert!(!policy.allow_memory_demotion);
        assert!(!policy.allow_performance_demotion);
        assert!(policy.honor_security_veto);
    }

    #[test]
    fn test_locked_policy() {
        let policy = OverridePolicy::locked();
        assert!(!policy.allow_operator_debug);
        assert!(!policy.allow_corruption_fallback);
    }

    #[test]
    fn test_policy_permission_check() {
        let policy = OverridePolicy::restrictive();
        assert!(!policy.is_permitted(OverrideReason::OperatorDebug));
        assert!(policy.is_permitted(OverrideReason::CorruptionDetected));
        assert!(policy.is_permitted(OverrideReason::EpochRollback));
        assert!(policy.is_permitted(OverrideReason::None));
    }

    #[test]
    fn test_policy_display() {
        let policy = OverridePolicy::permissive();
        let display = policy.to_string();
        assert!(display.contains("OverridePolicy"));
        assert!(display.contains("debug"));
    }

    #[test]
    fn test_policy_serde_roundtrip() {
        let policy = OverridePolicy::permissive();
        let json = serde_json::to_string(&policy).unwrap();
        let back: OverridePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn test_policy_hash_determinism() {
        let p1 = OverridePolicy::permissive();
        let p2 = OverridePolicy::permissive();
        assert_eq!(p1.policy_hash, p2.policy_hash);
    }

    #[test]
    fn test_policy_hash_differs_for_different_policies() {
        let p1 = OverridePolicy::permissive();
        let p2 = OverridePolicy::restrictive();
        assert_ne!(p1.policy_hash, p2.policy_hash);
    }

    // --- SubstrateSelectionReceipt ---

    #[test]
    fn test_receipt_from_contract() {
        let contract = test_contract();
        let receipt =
            SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "default selection");
        assert_eq!(receipt.structure_kind, MetadataStructureKind::ShapeTable);
        assert_eq!(receipt.selected_substrate, SubstrateKind::SwissTable);
        assert!(!receipt.override_applied);
        assert_eq!(receipt.override_reason, OverrideReason::None);
    }

    #[test]
    fn test_receipt_from_override() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_override(
            &contract,
            SubstrateKind::FlatArray,
            LocalityGoal::DramResident,
            OverrideReason::OperatorDebug,
            test_epoch(),
            "debug fallback",
        );
        assert!(receipt.override_applied);
        assert_eq!(receipt.override_reason, OverrideReason::OperatorDebug);
        assert_eq!(receipt.selected_substrate, SubstrateKind::FlatArray);
        assert_eq!(receipt.contract_substrate, SubstrateKind::SwissTable);
    }

    #[test]
    fn test_receipt_display_no_override() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "default");
        let display = receipt.to_string();
        assert!(display.contains("SelectionReceipt"));
        assert!(display.contains("shape_table"));
        assert!(!display.contains("overrode"));
    }

    #[test]
    fn test_receipt_display_with_override() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_override(
            &contract,
            SubstrateKind::FlatArray,
            LocalityGoal::DramResident,
            OverrideReason::OperatorDebug,
            test_epoch(),
            "debug",
        );
        let display = receipt.to_string();
        assert!(display.contains("overrode"));
    }

    #[test]
    fn test_receipt_hash_determinism() {
        let contract = test_contract();
        let r1 = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "x");
        let r2 = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "x");
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_receipt_serde_roundtrip() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let json = serde_json::to_string(&receipt).unwrap();
        let back: SubstrateSelectionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // --- SubstrateSnapshot ---

    #[test]
    fn test_snapshot_creation() {
        let snap = SubstrateSnapshot::new(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
            SubstrateInstanceStatus::Active,
            test_epoch(),
            1000,
            ContentHash::compute(b"test_state"),
        );
        assert_eq!(snap.structure_kind, MetadataStructureKind::ShapeTable);
        assert_eq!(snap.entry_count, 1000);
    }

    #[test]
    fn test_snapshot_hash_determinism() {
        let hash = ContentHash::compute(b"state");
        let s1 = SubstrateSnapshot::new(
            MetadataStructureKind::StringTable,
            SubstrateKind::ArtTree,
            SubstrateInstanceStatus::Active,
            test_epoch(),
            500,
            hash.clone(),
        );
        let s2 = SubstrateSnapshot::new(
            MetadataStructureKind::StringTable,
            SubstrateKind::ArtTree,
            SubstrateInstanceStatus::Active,
            test_epoch(),
            500,
            hash,
        );
        assert_eq!(s1.snapshot_hash, s2.snapshot_hash);
    }

    #[test]
    fn test_snapshot_display() {
        let snap = SubstrateSnapshot::new(
            MetadataStructureKind::GcMetadata,
            SubstrateKind::CacheOblivious,
            SubstrateInstanceStatus::Active,
            test_epoch(),
            2000,
            ContentHash::compute(b"gc"),
        );
        let display = snap.to_string();
        assert!(display.contains("gc_metadata"));
        assert!(display.contains("2000"));
    }

    #[test]
    fn test_snapshot_serde_roundtrip() {
        let snap = SubstrateSnapshot::new(
            MetadataStructureKind::ModuleGraph,
            SubstrateKind::BTreeIndex,
            SubstrateInstanceStatus::Warming,
            test_epoch(),
            100,
            ContentHash::compute(b"module"),
        );
        let json = serde_json::to_string(&snap).unwrap();
        let back: SubstrateSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // --- SubstrateInstance ---

    #[test]
    fn test_instance_from_contract() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let instance = SubstrateInstance::from_contract(&contract, receipt);
        assert_eq!(instance.structure_kind, MetadataStructureKind::ShapeTable);
        assert_eq!(instance.status, SubstrateInstanceStatus::Warming);
        assert_eq!(instance.entry_count, 0);
    }

    #[test]
    fn test_instance_activate() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        assert_eq!(instance.status, SubstrateInstanceStatus::Warming);
        instance.activate();
        assert_eq!(instance.status, SubstrateInstanceStatus::Active);
    }

    #[test]
    fn test_instance_record_entries() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.record_entries(32768);
        assert_eq!(instance.entry_count, 32768);
        assert_eq!(instance.load_factor_millionths, 500_000); // 50%
    }

    #[test]
    fn test_instance_record_entries_zero_max() {
        let contract = SubstrateContract::new(
            MetadataStructureKind::ShapeTable,
            SubstrateKind::SwissTable,
            LocalityGoal::L1Hot,
            FallbackMode::LinearScan,
            RollbackRule::SnapshottedCow,
            0,
            850_000,
        );
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.record_entries(100);
        assert_eq!(instance.load_factor_millionths, 0);
    }

    #[test]
    fn test_instance_snapshot_and_rollback() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.activate();
        instance.record_entries(1000);
        let snapshot = instance.take_snapshot(test_epoch());
        assert_eq!(instance.snapshots.len(), 1);

        instance.record_entries(5000);
        instance.restore_from_snapshot(&snapshot);
        assert_eq!(instance.entry_count, 1000);
        assert_eq!(instance.status, SubstrateInstanceStatus::RolledBack);
    }

    #[test]
    fn test_instance_fallback() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.activate();
        instance.fallback(OverrideReason::CorruptionDetected);
        assert_eq!(instance.status, SubstrateInstanceStatus::FallenBack);
        assert_eq!(instance.substrate_kind, SubstrateKind::FlatArray);
        assert_eq!(instance.locality_goal, LocalityGoal::DramResident);
    }

    #[test]
    fn test_instance_decommission() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.decommission();
        assert_eq!(instance.status, SubstrateInstanceStatus::Decommissioned);
        assert!(!instance.is_serving());
    }

    #[test]
    fn test_instance_is_serving() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        assert!(instance.is_serving()); // Warming is serving
        instance.activate();
        assert!(instance.is_serving());
        instance.decommission();
        assert!(!instance.is_serving());
    }

    #[test]
    fn test_instance_overloaded() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.record_entries(60000); // ~91% of 65536
        assert!(instance.is_overloaded(800_000));
        instance.record_entries(10000); // ~15%
        assert!(!instance.is_overloaded(800_000));
    }

    #[test]
    fn test_instance_display() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let instance = SubstrateInstance::from_contract(&contract, receipt);
        let display = instance.to_string();
        assert!(display.contains("SubstrateInstance"));
        assert!(display.contains("shape_table"));
    }

    #[test]
    fn test_instance_serde_roundtrip() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let instance = SubstrateInstance::from_contract(&contract, receipt);
        let json = serde_json::to_string(&instance).unwrap();
        let back: SubstrateInstance = serde_json::from_str(&json).unwrap();
        assert_eq!(instance, back);
    }

    // --- SubstrateSelector ---

    #[test]
    fn test_selector_creation() {
        let policy = OverridePolicy::permissive();
        let selector = SubstrateSelector::new(policy, test_epoch());
        assert_eq!(selector.instances.len(), 0);
        assert_eq!(selector.receipts.len(), 0);
    }

    #[test]
    fn test_selector_select_from_contract() {
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, test_epoch());
        let assignment = test_assignment();
        let instance = selector.select_from_contract(&assignment);
        assert_eq!(instance.structure_kind, MetadataStructureKind::ShapeTable);
        assert_eq!(selector.instances.len(), 1);
        assert_eq!(selector.receipts.len(), 1);
    }

    #[test]
    fn test_selector_select_with_override() {
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, test_epoch());
        let assignment = test_assignment();
        let result = selector.select_with_override(
            &assignment,
            SubstrateKind::FlatArray,
            LocalityGoal::DramResident,
            OverrideReason::OperatorDebug,
            "debug fallback",
        );
        assert!(result.is_ok());
        let instance = result.unwrap();
        assert_eq!(instance.substrate_kind, SubstrateKind::FlatArray);
        assert_eq!(selector.overridden_count(), 1);
    }

    #[test]
    fn test_selector_override_denied() {
        let policy = OverridePolicy::restrictive();
        let mut selector = SubstrateSelector::new(policy, test_epoch());
        let assignment = test_assignment();
        let result = selector.select_with_override(
            &assignment,
            SubstrateKind::FlatArray,
            LocalityGoal::DramResident,
            OverrideReason::OperatorDebug,
            "debug",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_selector_instantiate_all() {
        let epoch = test_epoch();
        let inventory = default_optimized_assignments(epoch);
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, epoch);
        let instances = selector.instantiate_all(&inventory);
        assert_eq!(instances.len(), 10); // All 10 structure kinds
        assert_eq!(selector.instances.len(), 10);
    }

    #[test]
    fn test_selector_instance_for() {
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, test_epoch());
        let assignment = test_assignment();
        selector.select_from_contract(&assignment);
        let instance = selector.instance_for(MetadataStructureKind::ShapeTable);
        assert!(instance.is_some());
        let instance = selector.instance_for(MetadataStructureKind::GcMetadata);
        assert!(instance.is_none());
    }

    #[test]
    fn test_selector_summary_report() {
        let epoch = test_epoch();
        let inventory = default_optimized_assignments(epoch);
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, epoch);
        selector.instantiate_all(&inventory);
        let report = selector.summary_report();
        assert_eq!(report.total_instances, 10);
        assert_eq!(report.active_instances, 10); // all warming = serving
        assert_eq!(report.coverage_millionths, MILLION);
    }

    #[test]
    fn test_selector_display() {
        let policy = OverridePolicy::permissive();
        let selector = SubstrateSelector::new(policy, test_epoch());
        let display = selector.to_string();
        assert!(display.contains("SubstrateSelector"));
    }

    #[test]
    fn test_selector_serde_roundtrip() {
        let policy = OverridePolicy::permissive();
        let selector = SubstrateSelector::new(policy, test_epoch());
        let json = serde_json::to_string(&selector).unwrap();
        let back: SubstrateSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(selector, back);
    }

    #[test]
    fn test_selector_hash_determinism() {
        let policy = OverridePolicy::permissive();
        let s1 = SubstrateSelector::new(policy.clone(), test_epoch());
        let s2 = SubstrateSelector::new(policy, test_epoch());
        assert_eq!(s1.selector_hash, s2.selector_hash);
    }

    // --- default_optimized_assignments ---

    #[test]
    fn test_default_assignments_coverage() {
        let inventory = default_optimized_assignments(test_epoch());
        let report = inventory.coverage_report();
        assert_eq!(report.coverage_millionths, MILLION);
        assert!(report.missing_kinds.is_empty());
    }

    #[test]
    fn test_default_assignments_all_kinds() {
        let inventory = default_optimized_assignments(test_epoch());
        for kind in MetadataStructureKind::ALL {
            let matches = inventory.lookup(*kind);
            assert!(!matches.is_empty(), "Missing assignment for {kind}");
        }
    }

    #[test]
    fn test_default_assignments_serde_roundtrip() {
        let inventory = default_optimized_assignments(test_epoch());
        let json = serde_json::to_string(&inventory).unwrap();
        let back: SubstrateInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inventory, back);
    }

    // --- SubstrateHealthCheck ---

    #[test]
    fn test_health_check_healthy() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.activate();
        instance.record_entries(1000);
        let check = SubstrateHealthCheck::check(&instance, test_epoch());
        assert!(check.healthy);
        assert!(check.serving);
        assert!(!check.overloaded);
    }

    #[test]
    fn test_health_check_overloaded() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.activate();
        instance.record_entries(60000); // >80% of 65536
        let check = SubstrateHealthCheck::check(&instance, test_epoch());
        assert!(!check.healthy);
        assert!(check.overloaded);
    }

    #[test]
    fn test_health_check_not_serving() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.decommission();
        let check = SubstrateHealthCheck::check(&instance, test_epoch());
        assert!(!check.healthy);
        assert!(!check.serving);
    }

    #[test]
    fn test_health_check_display() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.activate();
        instance.record_entries(1000);
        let check = SubstrateHealthCheck::check(&instance, test_epoch());
        let display = check.to_string();
        assert!(display.contains("HealthCheck"));
        assert!(display.contains("healthy=true"));
    }

    #[test]
    fn test_health_check_serde_roundtrip() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.activate();
        let check = SubstrateHealthCheck::check(&instance, test_epoch());
        let json = serde_json::to_string(&check).unwrap();
        let back: SubstrateHealthCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(check, back);
    }

    // --- SubstrateTransitionEvent ---

    #[test]
    fn test_transition_event_creation() {
        let event = SubstrateTransitionEvent::new(
            MetadataStructureKind::ShapeTable,
            SubstrateTransitionKind::Created,
            None,
            SubstrateKind::SwissTable,
            test_epoch(),
            "initial creation",
        );
        assert_eq!(event.structure_kind, MetadataStructureKind::ShapeTable);
        assert_eq!(event.transition, SubstrateTransitionKind::Created);
    }

    #[test]
    fn test_transition_event_display() {
        let event = SubstrateTransitionEvent::new(
            MetadataStructureKind::StringTable,
            SubstrateTransitionKind::Activated,
            Some(SubstrateKind::LinearProbe),
            SubstrateKind::ArtTree,
            test_epoch(),
            "upgrade to ART",
        );
        let display = event.to_string();
        assert!(display.contains("TransitionEvent"));
        assert!(display.contains("string_table"));
    }

    #[test]
    fn test_transition_event_hash_determinism() {
        let e1 = SubstrateTransitionEvent::new(
            MetadataStructureKind::GcMetadata,
            SubstrateTransitionKind::FellBack,
            Some(SubstrateKind::CacheOblivious),
            SubstrateKind::FlatArray,
            test_epoch(),
            "fallback",
        );
        let e2 = SubstrateTransitionEvent::new(
            MetadataStructureKind::GcMetadata,
            SubstrateTransitionKind::FellBack,
            Some(SubstrateKind::CacheOblivious),
            SubstrateKind::FlatArray,
            test_epoch(),
            "fallback",
        );
        assert_eq!(e1.event_hash, e2.event_hash);
    }

    #[test]
    fn test_transition_event_serde_roundtrip() {
        let event = SubstrateTransitionEvent::new(
            MetadataStructureKind::CompilationCache,
            SubstrateTransitionKind::Decommissioned,
            Some(SubstrateKind::HashArray),
            SubstrateKind::FlatArray,
            test_epoch(),
            "decommissioned",
        );
        let json = serde_json::to_string(&event).unwrap();
        let back: SubstrateTransitionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }

    #[test]
    fn test_transition_kind_display() {
        assert_eq!(SubstrateTransitionKind::Created.to_string(), "created");
        assert_eq!(SubstrateTransitionKind::Activated.to_string(), "activated");
        assert_eq!(SubstrateTransitionKind::FellBack.to_string(), "fell_back");
        assert_eq!(
            SubstrateTransitionKind::RolledBack.to_string(),
            "rolled_back"
        );
        assert_eq!(
            SubstrateTransitionKind::SnapshotTaken.to_string(),
            "snapshot_taken"
        );
    }

    // --- SubstrateSelectionError ---

    #[test]
    fn test_error_display_override_denied() {
        let err = SubstrateSelectionError::OverrideDenied {
            structure_kind: MetadataStructureKind::ShapeTable,
            reason: OverrideReason::OperatorDebug,
        };
        let display = err.to_string();
        assert!(display.contains("override denied"));
        assert!(display.contains("shape_table"));
    }

    #[test]
    fn test_error_display_no_contract() {
        let err = SubstrateSelectionError::NoContractFound {
            structure_kind: MetadataStructureKind::GcMetadata,
        };
        assert!(err.to_string().contains("no contract found"));
    }

    #[test]
    fn test_error_display_already_decommissioned() {
        let err = SubstrateSelectionError::AlreadyDecommissioned {
            structure_kind: MetadataStructureKind::StringTable,
        };
        assert!(err.to_string().contains("decommissioned"));
    }

    #[test]
    fn test_error_serde_roundtrip() {
        let err = SubstrateSelectionError::OverrideDenied {
            structure_kind: MetadataStructureKind::ShapeTable,
            reason: OverrideReason::MemoryPressure,
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: SubstrateSelectionError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // --- SelectorSummaryReport ---

    #[test]
    fn test_summary_report_display() {
        let report = SelectorSummaryReport {
            total_instances: 10,
            active_instances: 8,
            overridden_instances: 1,
            fallen_back_instances: 1,
            rolled_back_instances: 0,
            coverage_millionths: MILLION,
            epoch: test_epoch(),
        };
        let display = report.to_string();
        assert!(display.contains("SelectorSummary"));
        assert!(display.contains("total=10"));
    }

    #[test]
    fn test_summary_report_serde_roundtrip() {
        let report = SelectorSummaryReport {
            total_instances: 5,
            active_instances: 4,
            overridden_instances: 0,
            fallen_back_instances: 1,
            rolled_back_instances: 0,
            coverage_millionths: 500_000,
            epoch: test_epoch(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: SelectorSummaryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // --- Integration-style tests ---

    #[test]
    fn test_full_lifecycle_select_activate_snapshot_rollback() {
        let epoch = test_epoch();
        let inventory = default_optimized_assignments(epoch);
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, epoch);
        selector.instantiate_all(&inventory);

        // Activate shape table
        let instance = selector
            .instance_for_mut(MetadataStructureKind::ShapeTable)
            .unwrap();
        instance.activate();
        instance.record_entries(5000);
        let snapshot = instance.take_snapshot(epoch);

        // Simulate growth
        instance.record_entries(60000);
        assert!(instance.is_overloaded(800_000));

        // Rollback
        instance.restore_from_snapshot(&snapshot);
        assert_eq!(instance.entry_count, 5000);
        assert_eq!(instance.status, SubstrateInstanceStatus::RolledBack);
    }

    #[test]
    fn test_full_lifecycle_override_then_fallback() {
        let epoch = test_epoch();
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, epoch);
        let assignment = test_assignment();

        let result = selector.select_with_override(
            &assignment,
            SubstrateKind::LinearProbe,
            LocalityGoal::L2Warm,
            OverrideReason::PortabilityFallback,
            "target lacks SIMD for Swiss table",
        );
        assert!(result.is_ok());
        let mut instance = result.unwrap();
        instance.activate();
        instance.fallback(OverrideReason::CorruptionDetected);
        assert_eq!(instance.status, SubstrateInstanceStatus::FallenBack);
        assert_eq!(instance.substrate_kind, SubstrateKind::FlatArray);
    }

    #[test]
    fn test_health_checks_across_all_instances() {
        let epoch = test_epoch();
        let inventory = default_optimized_assignments(epoch);
        let policy = OverridePolicy::permissive();
        let mut selector = SubstrateSelector::new(policy, epoch);
        selector.instantiate_all(&inventory);

        for instance in &selector.instances {
            let check = SubstrateHealthCheck::check(instance, epoch);
            assert!(check.serving);
            assert!(check.healthy);
        }
    }

    #[test]
    fn test_multiple_snapshots() {
        let contract = test_contract();
        let receipt = SubstrateSelectionReceipt::from_contract(&contract, test_epoch(), "test");
        let mut instance = SubstrateInstance::from_contract(&contract, receipt);
        instance.activate();

        instance.record_entries(100);
        let snap1 = instance.take_snapshot(SecurityEpoch::from_raw(1));
        instance.record_entries(200);
        let snap2 = instance.take_snapshot(SecurityEpoch::from_raw(2));
        instance.record_entries(300);
        let _snap3 = instance.take_snapshot(SecurityEpoch::from_raw(3));

        assert_eq!(instance.snapshots.len(), 3);

        // Restore to earliest snapshot
        instance.restore_from_snapshot(&snap1);
        assert_eq!(instance.entry_count, 100);

        // Restore to middle snapshot
        instance.restore_from_snapshot(&snap2);
        assert_eq!(instance.entry_count, 200);
    }
}
