//! SIMD and morsel kernels for collection, string, and JSON builtins.
//!
//! Implements morsel-parallel execution kernels that operate on vectorized
//! lanes with explicit callback fences, small-input cliff handling, and
//! operator-visible kill switches.
//!
//! Builds on:
//! - [`vectorized_lane_contract`]: lane semantics, selection vectors, scalar oracles
//! - [`array_fast_lane`]: element-kind transitions and fast-lane tracking
//! - [`stdlib`]: builtin family identifiers

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;
use crate::vectorized_lane_contract::{BuiltinFamily, LaneWidth, SelectionVector};

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for simd-morsel-kernel artifacts.
pub const SIMD_MORSEL_KERNEL_SCHEMA_VERSION: &str = "franken-engine.simd-morsel-kernel.v1";

// ---------------------------------------------------------------------------
// Morsel size and partition
// ---------------------------------------------------------------------------

/// Size of a morsel — the unit of parallel work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MorselSize {
    /// 64 elements per morsel.
    Small,
    /// 256 elements per morsel.
    Medium,
    /// 1024 elements per morsel.
    Large,
    /// 4096 elements per morsel.
    Huge,
}

impl MorselSize {
    /// Element count for this morsel size.
    pub fn element_count(self) -> u64 {
        match self {
            Self::Small => 64,
            Self::Medium => 256,
            Self::Large => 1024,
            Self::Huge => 4096,
        }
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
            Self::Huge => "huge",
        }
    }

    /// Select morsel size based on input length.
    pub fn for_input_length(len: u64) -> Self {
        if len <= 128 {
            Self::Small
        } else if len <= 512 {
            Self::Medium
        } else if len <= 2048 {
            Self::Large
        } else {
            Self::Huge
        }
    }
}

/// A morsel partition — describes a contiguous slice of work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorselPartition {
    /// Partition index (0-based).
    pub index: u32,
    /// Start offset in the source collection.
    pub start: u64,
    /// End offset (exclusive).
    pub end: u64,
    /// Lane width to use for this partition.
    pub lane_width: LaneWidth,
    /// Whether this partition is the tail (may be smaller than morsel size).
    pub is_tail: bool,
}

impl MorselPartition {
    /// Number of elements in this partition.
    pub fn element_count(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

// ---------------------------------------------------------------------------
// Callback fence
// ---------------------------------------------------------------------------

/// Callback fence kind — determines how user callbacks interact with vectorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CallbackFenceKind {
    /// No user callback — pure data operation (e.g., TypedArray.fill).
    NoCallback,
    /// Callback is pure (no side effects detected) — safe to vectorize.
    PureCallback,
    /// Callback has observable side effects — must serialize at fence points.
    SideEffectCallback,
    /// Callback may throw — must maintain exact exception ordering.
    ThrowingCallback,
    /// Callback modifies the source collection — must abort vectorization.
    MutatingCallback,
}

impl CallbackFenceKind {
    /// Whether this fence kind allows vectorized execution.
    pub fn allows_vectorization(self) -> bool {
        matches!(self, Self::NoCallback | Self::PureCallback)
    }

    /// Whether this fence kind requires strict sequential ordering.
    pub fn requires_ordering(self) -> bool {
        matches!(
            self,
            Self::SideEffectCallback | Self::ThrowingCallback | Self::MutatingCallback
        )
    }

    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoCallback => "no_callback",
            Self::PureCallback => "pure_callback",
            Self::SideEffectCallback => "side_effect_callback",
            Self::ThrowingCallback => "throwing_callback",
            Self::MutatingCallback => "mutating_callback",
        }
    }
}

/// A callback fence inserted between morsel boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallbackFence {
    /// Fence kind.
    pub kind: CallbackFenceKind,
    /// Morsel index after which the fence is placed.
    pub after_morsel: u32,
    /// Whether the fence forced a flush of pending side effects.
    pub flushed_effects: bool,
    /// Number of callback invocations at this fence point.
    pub callback_invocations: u64,
}

// ---------------------------------------------------------------------------
// Small-input cliff
// ---------------------------------------------------------------------------

/// Cliff behavior when input is too small for vectorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CliffBehavior {
    /// Fall back to scalar loop immediately.
    ScalarFallback,
    /// Use a single narrow lane (Lane4) even for small inputs.
    NarrowLane,
    /// Pad input to fill one full lane, masking inactive elements.
    PaddedLane,
}

impl CliffBehavior {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScalarFallback => "scalar_fallback",
            Self::NarrowLane => "narrow_lane",
            Self::PaddedLane => "padded_lane",
        }
    }
}

/// Small-input cliff threshold and behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliffPolicy {
    /// Minimum input length for vectorization to engage.
    pub min_vectorize_length: u64,
    /// Behavior when input is below threshold.
    pub behavior: CliffBehavior,
    /// Minimum input length for morsel parallelism to engage.
    pub min_parallel_length: u64,
}

impl Default for CliffPolicy {
    fn default() -> Self {
        Self {
            min_vectorize_length: 8,
            behavior: CliffBehavior::ScalarFallback,
            min_parallel_length: 256,
        }
    }
}

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

/// Operator-visible kill switch for morsel kernel execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitch {
    /// Whether the kill switch is engaged (halt all morsel execution).
    pub engaged: bool,
    /// Reason for engaging the kill switch.
    pub reason: Option<String>,
    /// Epoch when the kill switch was last toggled.
    pub last_toggled_epoch: SecurityEpoch,
    /// Builtin families affected by this kill switch (empty = all).
    pub affected_families: BTreeSet<String>,
}

impl KillSwitch {
    /// Create a new disengaged kill switch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            engaged: false,
            reason: None,
            last_toggled_epoch: epoch,
            affected_families: BTreeSet::new(),
        }
    }

    /// Engage the kill switch.
    pub fn engage(&mut self, reason: &str, epoch: SecurityEpoch) {
        self.engaged = true;
        self.reason = Some(reason.to_string());
        self.last_toggled_epoch = epoch;
    }

    /// Disengage the kill switch.
    pub fn disengage(&mut self, epoch: SecurityEpoch) {
        self.engaged = false;
        self.reason = None;
        self.last_toggled_epoch = epoch;
    }

    /// Whether a specific builtin family is killed.
    pub fn is_killed(&self, family: BuiltinFamily) -> bool {
        if !self.engaged {
            return false;
        }
        if self.affected_families.is_empty() {
            return true; // all families killed
        }
        self.affected_families.contains(family.as_str())
    }

    /// Add a specific family to the kill set.
    pub fn add_family(&mut self, family: BuiltinFamily) {
        self.affected_families.insert(family.as_str().to_string());
    }
}

// ---------------------------------------------------------------------------
// Kernel descriptor
// ---------------------------------------------------------------------------

/// Describes a morsel kernel for a specific builtin family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorselKernelDescriptor {
    /// Unique kernel identifier.
    pub kernel_id: String,
    /// Which builtin family this kernel accelerates.
    pub family: BuiltinFamily,
    /// Preferred lane width.
    pub lane_width: LaneWidth,
    /// Preferred morsel size.
    pub morsel_size: MorselSize,
    /// Callback fence kind for this kernel.
    pub callback_fence: CallbackFenceKind,
    /// Cliff policy.
    pub cliff_policy: CliffPolicy,
    /// Whether this kernel requires homogeneous element kinds.
    pub requires_homogeneous: bool,
    /// Maximum supported input length (0 = unlimited).
    pub max_input_length: u64,
    /// Content hash of kernel descriptor.
    pub content_hash: ContentHash,
}

impl MorselKernelDescriptor {
    /// Create a new kernel descriptor.
    pub fn new(
        family: BuiltinFamily,
        lane_width: LaneWidth,
        morsel_size: MorselSize,
        callback_fence: CallbackFenceKind,
    ) -> Self {
        let kernel_id = format!("mk-{}-{}", family.as_str(), lane_width.width());
        let mut data = Vec::new();
        data.extend_from_slice(kernel_id.as_bytes());
        data.push(b'|');
        data.extend_from_slice(&lane_width.width().to_le_bytes());
        data.extend_from_slice(&morsel_size.element_count().to_le_bytes());
        let content_hash = ContentHash::compute(&data);

        Self {
            kernel_id,
            family,
            lane_width,
            morsel_size,
            callback_fence,
            cliff_policy: CliffPolicy::default(),
            requires_homogeneous: true,
            max_input_length: 0,
            content_hash,
        }
    }

    /// Whether this kernel can handle the given callback fence kind.
    pub fn supports_callback(&self, fence: CallbackFenceKind) -> bool {
        match self.callback_fence {
            CallbackFenceKind::NoCallback => fence == CallbackFenceKind::NoCallback,
            CallbackFenceKind::PureCallback => {
                fence == CallbackFenceKind::NoCallback || fence == CallbackFenceKind::PureCallback
            }
            _ => true, // side-effect-aware kernels handle everything
        }
    }

    /// Check whether the input length is suitable for this kernel.
    pub fn is_suitable_length(&self, input_len: u64) -> bool {
        if input_len < self.cliff_policy.min_vectorize_length {
            return false;
        }
        if self.max_input_length > 0 && input_len > self.max_input_length {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Morsel execution record
// ---------------------------------------------------------------------------

/// Outcome of executing a single morsel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MorselOutcome {
    /// Morsel completed successfully with vectorized execution.
    Vectorized,
    /// Morsel completed with scalar fallback.
    ScalarFallback,
    /// Morsel was aborted due to callback mutation.
    AbortedMutation,
    /// Morsel was aborted due to kill switch.
    AbortedKillSwitch,
    /// Morsel was skipped (empty partition).
    Skipped,
}

impl MorselOutcome {
    /// Stable string representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vectorized => "vectorized",
            Self::ScalarFallback => "scalar_fallback",
            Self::AbortedMutation => "aborted_mutation",
            Self::AbortedKillSwitch => "aborted_kill_switch",
            Self::Skipped => "skipped",
        }
    }
}

/// Record of a single morsel execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorselExecutionRecord {
    /// Partition that was executed.
    pub partition: MorselPartition,
    /// Execution outcome.
    pub outcome: MorselOutcome,
    /// Elements processed in this morsel.
    pub elements_processed: u64,
    /// Elements masked (excluded by selection vector).
    pub elements_masked: u64,
    /// Callback fences encountered during this morsel.
    pub fences: Vec<CallbackFence>,
    /// Epoch when execution occurred.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Kernel execution receipt
// ---------------------------------------------------------------------------

/// Receipt documenting a full kernel execution across all morsels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelExecutionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Kernel that was executed.
    pub kernel_id: String,
    /// Builtin family.
    pub family: BuiltinFamily,
    /// Total input length.
    pub input_length: u64,
    /// Number of morsels.
    pub morsel_count: u32,
    /// Morsels that completed with vectorized execution.
    pub vectorized_count: u32,
    /// Morsels that fell back to scalar.
    pub scalar_count: u32,
    /// Morsels that were aborted.
    pub aborted_count: u32,
    /// Total elements processed.
    pub total_elements: u64,
    /// Total callback fences.
    pub total_fences: u32,
    /// Whether kill switch was active during execution.
    pub kill_switch_active: bool,
    /// Content hash of the receipt.
    pub receipt_hash: ContentHash,
    /// Epoch.
    pub epoch: SecurityEpoch,
}

impl KernelExecutionReceipt {
    /// Vectorization rate in millionths (1_000_000 = 100%).
    pub fn vectorization_rate_millionths(&self) -> u64 {
        if self.morsel_count == 0 {
            return 0;
        }
        (self.vectorized_count as u64)
            .saturating_mul(1_000_000)
            .checked_div(self.morsel_count as u64)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Kernel catalog
// ---------------------------------------------------------------------------

/// Default kernel catalog with pre-configured kernels for all builtin families.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MorselKernelCatalog {
    /// Registered kernels, keyed by kernel_id.
    pub kernels: BTreeMap<String, MorselKernelDescriptor>,
    /// Family-to-kernel mapping (best kernel per family).
    pub family_map: BTreeMap<String, String>,
}

impl MorselKernelCatalog {
    /// Create a new empty catalog.
    pub fn new() -> Self {
        Self {
            kernels: BTreeMap::new(),
            family_map: BTreeMap::new(),
        }
    }

    /// Create a catalog with default kernels for all builtin families.
    pub fn with_defaults() -> Self {
        let mut catalog = Self::new();

        // Array collection kernels — callback-aware, Lane8
        for family in [
            BuiltinFamily::ArrayMap,
            BuiltinFamily::ArrayFilter,
            BuiltinFamily::ArrayForEach,
            BuiltinFamily::ArrayEvery,
            BuiltinFamily::ArraySome,
            BuiltinFamily::ArrayFind,
        ] {
            let kernel = MorselKernelDescriptor::new(
                family,
                LaneWidth::Lane8,
                MorselSize::Medium,
                CallbackFenceKind::PureCallback,
            );
            catalog.register(kernel);
        }

        // Array reduce — sequential accumulation, Lane4
        {
            let kernel = MorselKernelDescriptor::new(
                BuiltinFamily::ArrayReduce,
                LaneWidth::Lane4,
                MorselSize::Medium,
                CallbackFenceKind::SideEffectCallback,
            );
            catalog.register(kernel);
        }

        // String kernels — Lane4
        for family in [
            BuiltinFamily::StringReplace,
            BuiltinFamily::StringSplit,
            BuiltinFamily::StringMatch,
        ] {
            let kernel = MorselKernelDescriptor::new(
                family,
                LaneWidth::Lane4,
                MorselSize::Small,
                CallbackFenceKind::NoCallback,
            );
            catalog.register(kernel);
        }

        // JSON kernels — Lane8
        for family in [BuiltinFamily::JsonParse, BuiltinFamily::JsonStringify] {
            let kernel = MorselKernelDescriptor::new(
                family,
                LaneWidth::Lane8,
                MorselSize::Large,
                CallbackFenceKind::NoCallback,
            );
            catalog.register(kernel);
        }

        // TypedArray kernels — Lane16 (no callbacks, homogeneous)
        for family in [
            BuiltinFamily::TypedArraySort,
            BuiltinFamily::TypedArrayCopy,
            BuiltinFamily::TypedArrayFill,
        ] {
            let mut kernel = MorselKernelDescriptor::new(
                family,
                LaneWidth::Lane16,
                MorselSize::Large,
                CallbackFenceKind::NoCallback,
            );
            kernel.requires_homogeneous = true;
            catalog.register(kernel);
        }

        catalog
    }

    /// Register a kernel in the catalog.
    pub fn register(&mut self, kernel: MorselKernelDescriptor) {
        let family_key = kernel.family.as_str().to_string();
        let kernel_id = kernel.kernel_id.clone();
        self.kernels.insert(kernel_id.clone(), kernel);
        self.family_map.insert(family_key, kernel_id);
    }

    /// Look up the best kernel for a builtin family.
    pub fn lookup(&self, family: BuiltinFamily) -> Option<&MorselKernelDescriptor> {
        let kernel_id = self.family_map.get(family.as_str())?;
        self.kernels.get(kernel_id)
    }

    /// Number of registered kernels.
    pub fn kernel_count(&self) -> usize {
        self.kernels.len()
    }

    /// All registered families.
    pub fn registered_families(&self) -> Vec<BuiltinFamily> {
        let mut result = Vec::new();
        for family in BuiltinFamily::ALL {
            if self.family_map.contains_key(family.as_str()) {
                result.push(*family);
            }
        }
        result
    }
}

impl Default for MorselKernelCatalog {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ---------------------------------------------------------------------------
// Morsel kernel engine
// ---------------------------------------------------------------------------

/// Engine managing morsel kernel execution with kill switches and diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MorselKernelEngine {
    /// Kernel catalog.
    pub catalog: MorselKernelCatalog,
    /// Kill switch.
    pub kill_switch: KillSwitch,
    /// Global cliff policy override.
    pub cliff_policy: CliffPolicy,
    /// Execution receipts (audit trail).
    pub receipts: Vec<KernelExecutionReceipt>,
    /// Per-family execution counts.
    pub family_execution_counts: BTreeMap<String, u64>,
    /// Per-family vectorization rates (running average, millionths).
    pub family_vectorization_rates: BTreeMap<String, u64>,
    /// Total morsels executed.
    pub total_morsels_executed: u64,
    /// Total elements processed.
    pub total_elements_processed: u64,
    /// Total scalar fallbacks.
    pub total_scalar_fallbacks: u64,
    /// Current security epoch.
    pub epoch: SecurityEpoch,
}

impl MorselKernelEngine {
    /// Create a new engine with default catalog.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            catalog: MorselKernelCatalog::with_defaults(),
            kill_switch: KillSwitch::new(epoch),
            cliff_policy: CliffPolicy::default(),
            receipts: Vec::new(),
            family_execution_counts: BTreeMap::new(),
            family_vectorization_rates: BTreeMap::new(),
            total_morsels_executed: 0,
            total_elements_processed: 0,
            total_scalar_fallbacks: 0,
            epoch,
        }
    }

    /// Create with custom catalog.
    pub fn with_catalog(catalog: MorselKernelCatalog, epoch: SecurityEpoch) -> Self {
        Self {
            catalog,
            kill_switch: KillSwitch::new(epoch),
            cliff_policy: CliffPolicy::default(),
            receipts: Vec::new(),
            family_execution_counts: BTreeMap::new(),
            family_vectorization_rates: BTreeMap::new(),
            total_morsels_executed: 0,
            total_elements_processed: 0,
            total_scalar_fallbacks: 0,
            epoch,
        }
    }

    /// Partition an input into morsels.
    pub fn partition(&self, family: BuiltinFamily, input_length: u64) -> Vec<MorselPartition> {
        let kernel = match self.catalog.lookup(family) {
            Some(k) => k,
            None => return Vec::new(),
        };

        if input_length == 0 {
            return Vec::new();
        }

        let morsel_size = kernel.morsel_size.element_count();
        let lane_width = kernel.lane_width;
        let mut partitions = Vec::new();
        let mut offset = 0u64;
        let mut index = 0u32;

        while offset < input_length {
            let remaining = input_length - offset;
            let chunk = remaining.min(morsel_size);
            let is_tail = offset + chunk >= input_length;
            partitions.push(MorselPartition {
                index,
                start: offset,
                end: offset + chunk,
                lane_width,
                is_tail,
            });
            offset += chunk;
            index += 1;
        }

        partitions
    }

    /// Execute a kernel for a builtin family on input of given length.
    /// Returns an execution receipt.
    pub fn execute(
        &mut self,
        family: BuiltinFamily,
        input_length: u64,
        callback_fence: CallbackFenceKind,
        selection: Option<&SelectionVector>,
    ) -> Option<KernelExecutionReceipt> {
        // Check kill switch
        if self.kill_switch.is_killed(family) {
            return None;
        }

        let kernel = self.catalog.lookup(family)?.clone();

        // Check callback compatibility
        if !kernel.supports_callback(callback_fence) {
            return None;
        }

        // Partition
        let partitions = self.partition(family, input_length);
        if partitions.is_empty() {
            return None;
        }

        let mut vectorized_count = 0u32;
        let mut scalar_count = 0u32;
        let mut aborted_count = 0u32;
        let mut total_elements = 0u64;
        let mut total_fences = 0u32;

        for partition in &partitions {
            let elem_count = partition.element_count();

            // Check cliff policy
            let outcome = if elem_count < self.cliff_policy.min_vectorize_length {
                MorselOutcome::ScalarFallback
            } else if callback_fence.allows_vectorization() {
                MorselOutcome::Vectorized
            } else if callback_fence == CallbackFenceKind::MutatingCallback {
                MorselOutcome::AbortedMutation
            } else {
                MorselOutcome::ScalarFallback
            };

            // Apply selection masking
            let masked = if let Some(sel) = selection {
                let sel_len = sel.len() as u64;
                if partition.start < sel_len {
                    let end = partition.end.min(sel_len);
                    let mut count = 0u64;
                    for i in partition.start..end {
                        if !sel.is_active(i as usize) {
                            count += 1;
                        }
                    }
                    count
                } else {
                    elem_count
                }
            } else {
                0
            };

            let processed = elem_count.saturating_sub(masked);
            total_elements += processed;

            match outcome {
                MorselOutcome::Vectorized => vectorized_count += 1,
                MorselOutcome::ScalarFallback => scalar_count += 1,
                MorselOutcome::AbortedMutation | MorselOutcome::AbortedKillSwitch => {
                    aborted_count += 1;
                }
                MorselOutcome::Skipped => {}
            }

            // Count fences for side-effect callbacks
            if callback_fence.requires_ordering() {
                total_fences += 1;
            }
        }

        self.total_morsels_executed += partitions.len() as u64;
        self.total_elements_processed += total_elements;
        self.total_scalar_fallbacks += scalar_count as u64;

        // Update per-family stats
        let family_key = family.as_str().to_string();
        *self
            .family_execution_counts
            .entry(family_key.clone())
            .or_insert(0) += 1;

        let morsel_count = partitions.len() as u32;
        let vec_rate = if morsel_count > 0 {
            (vectorized_count as u64)
                .saturating_mul(1_000_000)
                .checked_div(morsel_count as u64)
                .unwrap_or(0)
        } else {
            0
        };

        // Running average: (old_rate + new_rate) / 2
        let old_rate = *self
            .family_vectorization_rates
            .get(&family_key)
            .unwrap_or(&vec_rate);
        let avg_rate = old_rate
            .saturating_add(vec_rate)
            .checked_div(2)
            .unwrap_or(0);
        self.family_vectorization_rates.insert(family_key, avg_rate);

        // Build receipt
        let mut receipt_data = Vec::new();
        receipt_data.extend_from_slice(kernel.kernel_id.as_bytes());
        receipt_data.push(b'|');
        receipt_data.extend_from_slice(&input_length.to_le_bytes());
        receipt_data.extend_from_slice(&(morsel_count as u64).to_le_bytes());
        receipt_data.extend_from_slice(&self.epoch.as_u64().to_le_bytes());
        let receipt_hash = ContentHash::compute(&receipt_data);
        let receipt_id = format!("mkr-{}", &receipt_hash.to_hex()[..16]);

        let receipt = KernelExecutionReceipt {
            receipt_id,
            kernel_id: kernel.kernel_id,
            family,
            input_length,
            morsel_count,
            vectorized_count,
            scalar_count,
            aborted_count,
            total_elements,
            total_fences,
            kill_switch_active: self.kill_switch.engaged,
            receipt_hash,
            epoch: self.epoch,
        };

        self.receipts.push(receipt.clone());
        Some(receipt)
    }

    /// Engage the kill switch for all families.
    pub fn engage_kill_switch(&mut self, reason: &str) {
        self.kill_switch.engage(reason, self.epoch);
    }

    /// Engage the kill switch for a specific family.
    pub fn engage_family_kill(&mut self, family: BuiltinFamily, reason: &str) {
        self.kill_switch.add_family(family);
        self.kill_switch.engage(reason, self.epoch);
    }

    /// Disengage the kill switch.
    pub fn disengage_kill_switch(&mut self) {
        self.kill_switch.disengage(self.epoch);
    }

    /// Get diagnostics snapshot.
    pub fn diagnostics(&self) -> MorselKernelDiagnostics {
        MorselKernelDiagnostics {
            kernel_count: self.catalog.kernel_count() as u32,
            total_morsels_executed: self.total_morsels_executed,
            total_elements_processed: self.total_elements_processed,
            total_scalar_fallbacks: self.total_scalar_fallbacks,
            total_receipts: self.receipts.len() as u32,
            kill_switch_engaged: self.kill_switch.engaged,
            family_execution_counts: self.family_execution_counts.clone(),
            family_vectorization_rates: self.family_vectorization_rates.clone(),
        }
    }

    /// Receipt count.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// Diagnostics snapshot for the morsel kernel engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MorselKernelDiagnostics {
    /// Number of registered kernels.
    pub kernel_count: u32,
    /// Total morsels executed.
    pub total_morsels_executed: u64,
    /// Total elements processed.
    pub total_elements_processed: u64,
    /// Total scalar fallbacks.
    pub total_scalar_fallbacks: u64,
    /// Total execution receipts.
    pub total_receipts: u32,
    /// Whether kill switch is engaged.
    pub kill_switch_engaged: bool,
    /// Per-family execution counts.
    pub family_execution_counts: BTreeMap<String, u64>,
    /// Per-family vectorization rates (millionths).
    pub family_vectorization_rates: BTreeMap<String, u64>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    // --- MorselSize tests ---

    #[test]
    fn test_morsel_size_element_counts() {
        assert_eq!(MorselSize::Small.element_count(), 64);
        assert_eq!(MorselSize::Medium.element_count(), 256);
        assert_eq!(MorselSize::Large.element_count(), 1024);
        assert_eq!(MorselSize::Huge.element_count(), 4096);
    }

    #[test]
    fn test_morsel_size_for_input_length() {
        assert_eq!(MorselSize::for_input_length(0), MorselSize::Small);
        assert_eq!(MorselSize::for_input_length(128), MorselSize::Small);
        assert_eq!(MorselSize::for_input_length(129), MorselSize::Medium);
        assert_eq!(MorselSize::for_input_length(512), MorselSize::Medium);
        assert_eq!(MorselSize::for_input_length(513), MorselSize::Large);
        assert_eq!(MorselSize::for_input_length(2048), MorselSize::Large);
        assert_eq!(MorselSize::for_input_length(2049), MorselSize::Huge);
    }

    #[test]
    fn test_morsel_size_as_str() {
        assert_eq!(MorselSize::Small.as_str(), "small");
        assert_eq!(MorselSize::Large.as_str(), "large");
    }

    // --- CallbackFenceKind tests ---

    #[test]
    fn test_callback_fence_allows_vectorization() {
        assert!(CallbackFenceKind::NoCallback.allows_vectorization());
        assert!(CallbackFenceKind::PureCallback.allows_vectorization());
        assert!(!CallbackFenceKind::SideEffectCallback.allows_vectorization());
        assert!(!CallbackFenceKind::ThrowingCallback.allows_vectorization());
        assert!(!CallbackFenceKind::MutatingCallback.allows_vectorization());
    }

    #[test]
    fn test_callback_fence_requires_ordering() {
        assert!(!CallbackFenceKind::NoCallback.requires_ordering());
        assert!(!CallbackFenceKind::PureCallback.requires_ordering());
        assert!(CallbackFenceKind::SideEffectCallback.requires_ordering());
        assert!(CallbackFenceKind::ThrowingCallback.requires_ordering());
        assert!(CallbackFenceKind::MutatingCallback.requires_ordering());
    }

    // --- CliffPolicy tests ---

    #[test]
    fn test_cliff_policy_defaults() {
        let p = CliffPolicy::default();
        assert_eq!(p.min_vectorize_length, 8);
        assert_eq!(p.behavior, CliffBehavior::ScalarFallback);
        assert_eq!(p.min_parallel_length, 256);
    }

    #[test]
    fn test_cliff_behavior_as_str() {
        assert_eq!(CliffBehavior::ScalarFallback.as_str(), "scalar_fallback");
        assert_eq!(CliffBehavior::NarrowLane.as_str(), "narrow_lane");
        assert_eq!(CliffBehavior::PaddedLane.as_str(), "padded_lane");
    }

    // --- KillSwitch tests ---

    #[test]
    fn test_kill_switch_lifecycle() {
        let mut ks = KillSwitch::new(epoch(1));
        assert!(!ks.engaged);
        assert!(!ks.is_killed(BuiltinFamily::ArrayMap));

        ks.engage("test", epoch(2));
        assert!(ks.engaged);
        assert!(ks.is_killed(BuiltinFamily::ArrayMap));
        assert!(ks.is_killed(BuiltinFamily::JsonParse));

        ks.disengage(epoch(3));
        assert!(!ks.engaged);
        assert!(!ks.is_killed(BuiltinFamily::ArrayMap));
    }

    #[test]
    fn test_kill_switch_targeted() {
        let mut ks = KillSwitch::new(epoch(1));
        ks.add_family(BuiltinFamily::ArrayMap);
        ks.add_family(BuiltinFamily::ArrayFilter);
        ks.engage("targeted", epoch(2));

        assert!(ks.is_killed(BuiltinFamily::ArrayMap));
        assert!(ks.is_killed(BuiltinFamily::ArrayFilter));
        assert!(!ks.is_killed(BuiltinFamily::JsonParse));
        assert!(!ks.is_killed(BuiltinFamily::TypedArraySort));
    }

    // --- MorselKernelDescriptor tests ---

    #[test]
    fn test_kernel_descriptor_creation() {
        let k = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        assert_eq!(k.family, BuiltinFamily::ArrayMap);
        assert_eq!(k.lane_width, LaneWidth::Lane8);
        assert_eq!(k.morsel_size, MorselSize::Medium);
        assert!(k.kernel_id.starts_with("mk-array_map-"));
    }

    #[test]
    fn test_kernel_supports_callback() {
        let k = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        assert!(k.supports_callback(CallbackFenceKind::NoCallback));
        assert!(k.supports_callback(CallbackFenceKind::PureCallback));
        assert!(!k.supports_callback(CallbackFenceKind::SideEffectCallback));
    }

    #[test]
    fn test_kernel_suitable_length() {
        let k = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        assert!(!k.is_suitable_length(0));
        assert!(!k.is_suitable_length(7)); // below min_vectorize_length
        assert!(k.is_suitable_length(8));
        assert!(k.is_suitable_length(1000));
    }

    #[test]
    fn test_kernel_max_input_length() {
        let mut k = MorselKernelDescriptor::new(
            BuiltinFamily::StringSplit,
            LaneWidth::Lane4,
            MorselSize::Small,
            CallbackFenceKind::NoCallback,
        );
        k.max_input_length = 100;
        assert!(k.is_suitable_length(100));
        assert!(!k.is_suitable_length(101));
    }

    // --- MorselOutcome tests ---

    #[test]
    fn test_morsel_outcome_as_str() {
        assert_eq!(MorselOutcome::Vectorized.as_str(), "vectorized");
        assert_eq!(MorselOutcome::ScalarFallback.as_str(), "scalar_fallback");
        assert_eq!(MorselOutcome::AbortedMutation.as_str(), "aborted_mutation");
    }

    // --- Catalog tests ---

    #[test]
    fn test_default_catalog_has_all_families() {
        let cat = MorselKernelCatalog::with_defaults();
        for family in BuiltinFamily::ALL {
            assert!(
                cat.lookup(*family).is_some(),
                "Missing kernel for {:?}",
                family
            );
        }
        assert_eq!(cat.kernel_count(), 15);
    }

    #[test]
    fn test_catalog_lookup() {
        let cat = MorselKernelCatalog::with_defaults();
        let k = cat.lookup(BuiltinFamily::TypedArrayFill).unwrap();
        assert_eq!(k.family, BuiltinFamily::TypedArrayFill);
        assert_eq!(k.lane_width, LaneWidth::Lane16);
        assert_eq!(k.callback_fence, CallbackFenceKind::NoCallback);
    }

    #[test]
    fn test_catalog_registered_families() {
        let cat = MorselKernelCatalog::with_defaults();
        let families = cat.registered_families();
        assert_eq!(families.len(), 15);
    }

    #[test]
    fn test_empty_catalog() {
        let cat = MorselKernelCatalog::new();
        assert_eq!(cat.kernel_count(), 0);
        assert!(cat.lookup(BuiltinFamily::ArrayMap).is_none());
    }

    // --- Engine tests ---

    #[test]
    fn test_engine_creation() {
        let engine = MorselKernelEngine::new(epoch(1));
        assert_eq!(engine.total_morsels_executed, 0);
        assert_eq!(engine.total_elements_processed, 0);
        assert!(!engine.kill_switch.engaged);
    }

    #[test]
    fn test_engine_partition() {
        let engine = MorselKernelEngine::new(epoch(1));
        let parts = engine.partition(BuiltinFamily::ArrayMap, 600);
        // Medium morsel = 256 elements, so 600 / 256 = 3 partitions (256 + 256 + 88)
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].start, 0);
        assert_eq!(parts[0].end, 256);
        assert!(!parts[0].is_tail);
        assert_eq!(parts[1].start, 256);
        assert_eq!(parts[1].end, 512);
        assert!(!parts[1].is_tail);
        assert_eq!(parts[2].start, 512);
        assert_eq!(parts[2].end, 600);
        assert!(parts[2].is_tail);
    }

    #[test]
    fn test_engine_partition_exact() {
        let engine = MorselKernelEngine::new(epoch(1));
        let parts = engine.partition(BuiltinFamily::ArrayMap, 256);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].element_count(), 256);
        assert!(parts[0].is_tail);
    }

    #[test]
    fn test_engine_partition_empty() {
        let engine = MorselKernelEngine::new(epoch(1));
        let parts = engine.partition(BuiltinFamily::ArrayMap, 0);
        assert!(parts.is_empty());
    }

    #[test]
    fn test_engine_execute_pure_callback() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine.execute(
            BuiltinFamily::ArrayMap,
            500,
            CallbackFenceKind::PureCallback,
            None,
        );
        assert!(receipt.is_some());
        let r = receipt.unwrap();
        assert_eq!(r.family, BuiltinFamily::ArrayMap);
        assert_eq!(r.input_length, 500);
        assert!(r.vectorized_count > 0);
        assert!(r.receipt_id.starts_with("mkr-"));
    }

    #[test]
    fn test_engine_execute_no_callback() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine.execute(
            BuiltinFamily::TypedArrayFill,
            2000,
            CallbackFenceKind::NoCallback,
            None,
        );
        assert!(receipt.is_some());
        let r = receipt.unwrap();
        assert!(r.vectorized_count > 0);
        assert_eq!(r.scalar_count, 0);
    }

    #[test]
    fn test_engine_execute_mutating_callback_aborts() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        // ArrayMap kernel only supports PureCallback, not MutatingCallback
        let receipt = engine.execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::MutatingCallback,
            None,
        );
        assert!(receipt.is_none());
    }

    #[test]
    fn test_engine_kill_switch_blocks_execution() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        engine.engage_kill_switch("emergency");
        let receipt = engine.execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        );
        assert!(receipt.is_none());
    }

    #[test]
    fn test_engine_targeted_kill_switch() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        engine.engage_family_kill(BuiltinFamily::ArrayMap, "map is broken");

        // ArrayMap is killed
        assert!(
            engine
                .execute(
                    BuiltinFamily::ArrayMap,
                    100,
                    CallbackFenceKind::PureCallback,
                    None,
                )
                .is_none()
        );

        // JsonParse is still alive
        assert!(
            engine
                .execute(
                    BuiltinFamily::JsonParse,
                    100,
                    CallbackFenceKind::NoCallback,
                    None,
                )
                .is_some()
        );
    }

    #[test]
    fn test_engine_disengage_kill_switch() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        engine.engage_kill_switch("test");
        engine.disengage_kill_switch();
        let receipt = engine.execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        );
        assert!(receipt.is_some());
    }

    #[test]
    fn test_engine_diagnostics() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        engine.execute(
            BuiltinFamily::ArrayMap,
            500,
            CallbackFenceKind::PureCallback,
            None,
        );
        engine.execute(
            BuiltinFamily::JsonParse,
            2000,
            CallbackFenceKind::NoCallback,
            None,
        );
        let diag = engine.diagnostics();
        assert_eq!(diag.kernel_count, 15);
        assert!(diag.total_morsels_executed > 0);
        assert!(diag.total_elements_processed > 0);
        assert_eq!(diag.total_receipts, 2);
        assert_eq!(diag.family_execution_counts.get("array_map"), Some(&1));
        assert_eq!(diag.family_execution_counts.get("json_parse"), Some(&1));
    }

    #[test]
    fn test_engine_receipt_count() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        assert_eq!(engine.receipt_count(), 0);
        engine.execute(
            BuiltinFamily::ArrayFilter,
            100,
            CallbackFenceKind::PureCallback,
            None,
        );
        assert_eq!(engine.receipt_count(), 1);
    }

    #[test]
    fn test_vectorization_rate() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine
            .execute(
                BuiltinFamily::TypedArrayFill,
                2000,
                CallbackFenceKind::NoCallback,
                None,
            )
            .unwrap();
        assert_eq!(receipt.vectorization_rate_millionths(), 1_000_000);
    }

    // --- Serde tests ---

    #[test]
    fn test_morsel_size_serde() {
        for size in [
            MorselSize::Small,
            MorselSize::Medium,
            MorselSize::Large,
            MorselSize::Huge,
        ] {
            let json = serde_json::to_string(&size).unwrap();
            let decoded: MorselSize = serde_json::from_str(&json).unwrap();
            assert_eq!(size, decoded);
        }
    }

    #[test]
    fn test_callback_fence_kind_serde() {
        for kind in [
            CallbackFenceKind::NoCallback,
            CallbackFenceKind::PureCallback,
            CallbackFenceKind::SideEffectCallback,
            CallbackFenceKind::ThrowingCallback,
            CallbackFenceKind::MutatingCallback,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let decoded: CallbackFenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    #[test]
    fn test_cliff_behavior_serde() {
        for b in [
            CliffBehavior::ScalarFallback,
            CliffBehavior::NarrowLane,
            CliffBehavior::PaddedLane,
        ] {
            let json = serde_json::to_string(&b).unwrap();
            let decoded: CliffBehavior = serde_json::from_str(&json).unwrap();
            assert_eq!(b, decoded);
        }
    }

    #[test]
    fn test_morsel_outcome_serde() {
        for o in [
            MorselOutcome::Vectorized,
            MorselOutcome::ScalarFallback,
            MorselOutcome::AbortedMutation,
            MorselOutcome::AbortedKillSwitch,
            MorselOutcome::Skipped,
        ] {
            let json = serde_json::to_string(&o).unwrap();
            let decoded: MorselOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(o, decoded);
        }
    }

    #[test]
    fn test_kernel_descriptor_serde() {
        let k = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        let json = serde_json::to_string(&k).unwrap();
        let decoded: MorselKernelDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(k, decoded);
    }

    #[test]
    fn test_diagnostics_serde() {
        let engine = MorselKernelEngine::new(epoch(1));
        let diag = engine.diagnostics();
        let json = serde_json::to_string(&diag).unwrap();
        let decoded: MorselKernelDiagnostics = serde_json::from_str(&json).unwrap();
        assert_eq!(diag, decoded);
    }

    #[test]
    fn test_schema_version() {
        assert_eq!(
            SIMD_MORSEL_KERNEL_SCHEMA_VERSION,
            "franken-engine.simd-morsel-kernel.v1"
        );
    }

    #[test]
    fn test_kernel_content_hash_deterministic() {
        let k1 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        let k2 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        assert_eq!(k1.content_hash, k2.content_hash);
    }

    #[test]
    fn test_kernel_content_hash_differs() {
        let k1 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        let k2 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayFilter,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        assert_ne!(k1.content_hash, k2.content_hash);
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut e1 = MorselKernelEngine::new(epoch(1));
        let mut e2 = MorselKernelEngine::new(epoch(1));
        let r1 = e1
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                None,
            )
            .unwrap();
        let r2 = e2
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                None,
            )
            .unwrap();
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }
}
