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

    // ---------------------------------------------------------------
    // Additional tests — morsel partition edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_partition_single_element_input() {
        let engine = MorselKernelEngine::new(epoch(1));
        // ArrayMap uses Medium morsel (256), input=1 => one tail partition
        let parts = engine.partition(BuiltinFamily::ArrayMap, 1);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].start, 0);
        assert_eq!(parts[0].end, 1);
        assert_eq!(parts[0].element_count(), 1);
        assert!(parts[0].is_tail);
        assert_eq!(parts[0].index, 0);
    }

    #[test]
    fn test_partition_large_input_many_morsels() {
        let engine = MorselKernelEngine::new(epoch(1));
        // JsonParse uses Large morsel (1024). 10000 / 1024 = 9 full + 1 tail (784)
        let parts = engine.partition(BuiltinFamily::JsonParse, 10000);
        assert_eq!(parts.len(), 10);
        for (i, p) in parts.iter().enumerate() {
            assert_eq!(p.index, i as u32);
            assert_eq!(p.lane_width, LaneWidth::Lane8);
        }
        // First 9 partitions are full-sized
        for p in &parts[..9] {
            assert_eq!(p.element_count(), 1024);
            assert!(!p.is_tail);
        }
        // Last partition is the tail
        assert_eq!(parts[9].element_count(), 10000 - 9 * 1024);
        assert!(parts[9].is_tail);
    }

    #[test]
    fn test_partition_unknown_family_in_empty_catalog() {
        let engine = MorselKernelEngine::with_catalog(MorselKernelCatalog::new(), epoch(1));
        let parts = engine.partition(BuiltinFamily::ArrayMap, 500);
        assert!(parts.is_empty());
    }

    #[test]
    fn test_partition_typed_array_uses_lane16() {
        let engine = MorselKernelEngine::new(epoch(1));
        let parts = engine.partition(BuiltinFamily::TypedArraySort, 2048);
        assert!(!parts.is_empty());
        for p in &parts {
            assert_eq!(p.lane_width, LaneWidth::Lane16);
        }
    }

    #[test]
    fn test_partition_string_uses_lane4() {
        let engine = MorselKernelEngine::new(epoch(1));
        let parts = engine.partition(BuiltinFamily::StringReplace, 100);
        // StringReplace uses Small morsel (64), Lane4
        assert_eq!(parts.len(), 2); // 64 + 36
        for p in &parts {
            assert_eq!(p.lane_width, LaneWidth::Lane4);
        }
    }

    #[test]
    fn test_partition_contiguous_no_gaps() {
        let engine = MorselKernelEngine::new(epoch(1));
        let parts = engine.partition(BuiltinFamily::ArrayFilter, 999);
        // Verify no gaps or overlaps: each partition.start == prev.end
        for i in 1..parts.len() {
            assert_eq!(parts[i].start, parts[i - 1].end);
        }
        // First starts at 0, last ends at input_length
        assert_eq!(parts[0].start, 0);
        assert_eq!(parts.last().unwrap().end, 999);
    }

    // ---------------------------------------------------------------
    // Additional tests — selection vector masking in execute
    // ---------------------------------------------------------------

    #[test]
    fn test_execute_with_selection_vector_all_active() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let sel = SelectionVector::new(100);
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                Some(&sel),
            )
            .unwrap();
        assert_eq!(receipt.total_elements, 100);
    }

    #[test]
    fn test_execute_with_selection_vector_partial_mask() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let mut sel = SelectionVector::new(100);
        // Mask out 30 elements
        for i in 0..30 {
            sel.mask(i);
        }
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                Some(&sel),
            )
            .unwrap();
        // 70 active out of 100
        assert_eq!(receipt.total_elements, 70);
    }

    #[test]
    fn test_execute_with_selection_vector_all_masked() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let mut sel = SelectionVector::new(50);
        for i in 0..50 {
            sel.mask(i);
        }
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayMap,
                50,
                CallbackFenceKind::PureCallback,
                Some(&sel),
            )
            .unwrap();
        assert_eq!(receipt.total_elements, 0);
    }

    #[test]
    fn test_execute_selection_vector_shorter_than_input() {
        // Selection vector shorter than input: masking only scans
        // [partition.start .. min(partition.end, sel_len)]. Elements
        // beyond the selection vector but within a partition whose
        // start < sel_len are NOT masked — only the covered range
        // is checked. Partitions whose start >= sel_len are fully masked.
        let mut engine = MorselKernelEngine::new(epoch(1));
        let sel = SelectionVector::new(50); // all 50 active
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayMap,
                300, // 2 partitions: [0..256] and [256..300]
                CallbackFenceKind::PureCallback,
                Some(&sel),
            )
            .unwrap();
        // Partition [0..256]: end=min(256,50)=50, scan [0..50], 0 inactive
        //   => masked=0, processed=256-0=256
        // Partition [256..300]: start=256 >= sel_len=50
        //   => masked=44, processed=44-44=0
        assert_eq!(receipt.total_elements, 256);
    }

    // ---------------------------------------------------------------
    // Additional tests — callback fence interactions
    // ---------------------------------------------------------------

    #[test]
    fn test_no_callback_kernel_rejects_side_effect() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        // StringSplit kernel uses NoCallback fence
        let receipt = engine.execute(
            BuiltinFamily::StringSplit,
            100,
            CallbackFenceKind::SideEffectCallback,
            None,
        );
        assert!(receipt.is_none());
    }

    #[test]
    fn test_side_effect_kernel_accepts_all_fences() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        // ArrayReduce uses SideEffectCallback — should accept everything
        for fence in [
            CallbackFenceKind::NoCallback,
            CallbackFenceKind::PureCallback,
            CallbackFenceKind::SideEffectCallback,
            CallbackFenceKind::ThrowingCallback,
            CallbackFenceKind::MutatingCallback,
        ] {
            let receipt = engine.execute(BuiltinFamily::ArrayReduce, 100, fence, None);
            assert!(receipt.is_some(), "ArrayReduce should accept {:?}", fence);
        }
    }

    #[test]
    fn test_throwing_callback_produces_scalar_fallback() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        // ArrayReduce accepts ThrowingCallback, but ThrowingCallback doesn't
        // allow vectorization, so all morsels should be scalar fallback.
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayReduce,
                300,
                CallbackFenceKind::ThrowingCallback,
                None,
            )
            .unwrap();
        assert_eq!(receipt.vectorized_count, 0);
        assert!(receipt.scalar_count > 0);
    }

    #[test]
    fn test_side_effect_callback_produces_fences() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayReduce,
                600,
                CallbackFenceKind::SideEffectCallback,
                None,
            )
            .unwrap();
        // SideEffectCallback requires_ordering => one fence per morsel
        assert!(receipt.total_fences > 0);
        assert_eq!(receipt.total_fences, receipt.morsel_count);
    }

    #[test]
    fn test_mutating_callback_aborts_all_morsels() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        // ArrayReduce accepts MutatingCallback but morsels get AbortedMutation
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayReduce,
                500,
                CallbackFenceKind::MutatingCallback,
                None,
            )
            .unwrap();
        assert_eq!(receipt.vectorized_count, 0);
        assert_eq!(receipt.scalar_count, 0);
        assert!(receipt.aborted_count > 0);
        assert_eq!(receipt.aborted_count, receipt.morsel_count);
    }

    // ---------------------------------------------------------------
    // Additional tests — morsel size selection boundaries
    // ---------------------------------------------------------------

    #[test]
    fn test_morsel_size_boundary_values() {
        // Exact boundary values
        assert_eq!(MorselSize::for_input_length(1), MorselSize::Small);
        assert_eq!(MorselSize::for_input_length(127), MorselSize::Small);
        assert_eq!(MorselSize::for_input_length(128), MorselSize::Small);
        assert_eq!(MorselSize::for_input_length(129), MorselSize::Medium);
        assert_eq!(MorselSize::for_input_length(511), MorselSize::Medium);
        assert_eq!(MorselSize::for_input_length(512), MorselSize::Medium);
        assert_eq!(MorselSize::for_input_length(513), MorselSize::Large);
        assert_eq!(MorselSize::for_input_length(2047), MorselSize::Large);
        assert_eq!(MorselSize::for_input_length(2048), MorselSize::Large);
        assert_eq!(MorselSize::for_input_length(2049), MorselSize::Huge);
        assert_eq!(MorselSize::for_input_length(u64::MAX), MorselSize::Huge);
    }

    #[test]
    fn test_morsel_size_ordering() {
        assert!(MorselSize::Small < MorselSize::Medium);
        assert!(MorselSize::Medium < MorselSize::Large);
        assert!(MorselSize::Large < MorselSize::Huge);
    }

    #[test]
    fn test_morsel_size_as_str_all_variants() {
        assert_eq!(MorselSize::Small.as_str(), "small");
        assert_eq!(MorselSize::Medium.as_str(), "medium");
        assert_eq!(MorselSize::Large.as_str(), "large");
        assert_eq!(MorselSize::Huge.as_str(), "huge");
    }

    // ---------------------------------------------------------------
    // Additional tests — kernel content hash uniqueness
    // ---------------------------------------------------------------

    #[test]
    fn test_kernel_hash_differs_by_lane_width() {
        let k1 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane4,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        let k2 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Medium,
            CallbackFenceKind::PureCallback,
        );
        assert_ne!(k1.content_hash, k2.content_hash);
        assert_ne!(k1.kernel_id, k2.kernel_id);
    }

    #[test]
    fn test_kernel_hash_differs_by_morsel_size() {
        let k1 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Small,
            CallbackFenceKind::PureCallback,
        );
        let k2 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Huge,
            CallbackFenceKind::PureCallback,
        );
        // Same kernel_id (based on family + lane width) but different hash
        // because morsel size element_count is hashed
        assert_eq!(k1.kernel_id, k2.kernel_id);
        assert_ne!(k1.content_hash, k2.content_hash);
    }

    // ---------------------------------------------------------------
    // Additional tests — serde round-trips for compound types
    // ---------------------------------------------------------------

    #[test]
    fn test_kill_switch_serde_roundtrip() {
        let mut ks = KillSwitch::new(epoch(5));
        ks.add_family(BuiltinFamily::ArrayMap);
        ks.add_family(BuiltinFamily::JsonParse);
        ks.engage("serde test", epoch(6));

        let json = serde_json::to_string(&ks).unwrap();
        let decoded: KillSwitch = serde_json::from_str(&json).unwrap();
        assert_eq!(ks.engaged, decoded.engaged);
        assert_eq!(ks.reason, decoded.reason);
        assert_eq!(ks.affected_families, decoded.affected_families);
        assert_eq!(ks.last_toggled_epoch, decoded.last_toggled_epoch);
    }

    #[test]
    fn test_cliff_policy_serde_roundtrip() {
        let policy = CliffPolicy {
            min_vectorize_length: 16,
            behavior: CliffBehavior::PaddedLane,
            min_parallel_length: 512,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: CliffPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, decoded);
    }

    #[test]
    fn test_morsel_partition_serde_roundtrip() {
        let part = MorselPartition {
            index: 3,
            start: 768,
            end: 1024,
            lane_width: LaneWidth::Lane16,
            is_tail: true,
        };
        let json = serde_json::to_string(&part).unwrap();
        let decoded: MorselPartition = serde_json::from_str(&json).unwrap();
        assert_eq!(part, decoded);
    }

    #[test]
    fn test_callback_fence_serde_roundtrip() {
        let fence = CallbackFence {
            kind: CallbackFenceKind::ThrowingCallback,
            after_morsel: 7,
            flushed_effects: true,
            callback_invocations: 42,
        };
        let json = serde_json::to_string(&fence).unwrap();
        let decoded: CallbackFence = serde_json::from_str(&json).unwrap();
        assert_eq!(fence, decoded);
    }

    #[test]
    fn test_execution_receipt_serde_roundtrip() {
        let mut engine = MorselKernelEngine::new(epoch(10));
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayFilter,
                500,
                CallbackFenceKind::PureCallback,
                None,
            )
            .unwrap();
        let json = serde_json::to_string(&receipt).unwrap();
        let decoded: KernelExecutionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt.receipt_id, decoded.receipt_id);
        assert_eq!(receipt.receipt_hash, decoded.receipt_hash);
        assert_eq!(receipt.family, decoded.family);
        assert_eq!(receipt.morsel_count, decoded.morsel_count);
    }

    #[test]
    fn test_catalog_serde_roundtrip() {
        let catalog = MorselKernelCatalog::with_defaults();
        let json = serde_json::to_string(&catalog).unwrap();
        let decoded: MorselKernelCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(catalog.kernel_count(), decoded.kernel_count());
        // Verify lookup still works after deserialization
        let k = decoded.lookup(BuiltinFamily::ArrayMap).unwrap();
        assert_eq!(k.family, BuiltinFamily::ArrayMap);
    }

    // ---------------------------------------------------------------
    // Additional tests — engine cumulative statistics
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_cumulative_morsels_across_executions() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        engine.execute(
            BuiltinFamily::ArrayMap,
            256,
            CallbackFenceKind::PureCallback,
            None,
        );
        let m1 = engine.total_morsels_executed;
        engine.execute(
            BuiltinFamily::ArrayFilter,
            256,
            CallbackFenceKind::PureCallback,
            None,
        );
        assert!(engine.total_morsels_executed > m1);
        assert_eq!(engine.receipt_count(), 2);
    }

    #[test]
    fn test_engine_scalar_fallback_count_below_cliff() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        // Default cliff min_vectorize_length = 8. Single morsel with 5 elements
        // should trigger scalar fallback (5 < 8).
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayMap,
                5,
                CallbackFenceKind::PureCallback,
                None,
            )
            .unwrap();
        assert_eq!(receipt.vectorized_count, 0);
        assert_eq!(receipt.scalar_count, 1);
        assert_eq!(engine.total_scalar_fallbacks, 1);
    }

    #[test]
    fn test_engine_vectorization_rate_zero_morsels() {
        let receipt = KernelExecutionReceipt {
            receipt_id: "test".to_string(),
            kernel_id: "mk-test".to_string(),
            family: BuiltinFamily::ArrayMap,
            input_length: 0,
            morsel_count: 0,
            vectorized_count: 0,
            scalar_count: 0,
            aborted_count: 0,
            total_elements: 0,
            total_fences: 0,
            kill_switch_active: false,
            receipt_hash: ContentHash::compute(b"test"),
            epoch: epoch(1),
        };
        assert_eq!(receipt.vectorization_rate_millionths(), 0);
    }

    #[test]
    fn test_engine_vectorization_rate_partial() {
        let receipt = KernelExecutionReceipt {
            receipt_id: "test".to_string(),
            kernel_id: "mk-test".to_string(),
            family: BuiltinFamily::ArrayMap,
            input_length: 100,
            morsel_count: 4,
            vectorized_count: 1,
            scalar_count: 3,
            aborted_count: 0,
            total_elements: 100,
            total_fences: 0,
            kill_switch_active: false,
            receipt_hash: ContentHash::compute(b"test"),
            epoch: epoch(1),
        };
        // 1/4 = 250_000 millionths
        assert_eq!(receipt.vectorization_rate_millionths(), 250_000);
    }

    // ---------------------------------------------------------------
    // Additional tests — kill switch edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_kill_switch_engage_disengage_epoch_tracking() {
        let mut ks = KillSwitch::new(epoch(1));
        assert_eq!(ks.last_toggled_epoch, epoch(1));

        ks.engage("reason1", epoch(5));
        assert_eq!(ks.last_toggled_epoch, epoch(5));
        assert_eq!(ks.reason, Some("reason1".to_string()));

        ks.disengage(epoch(10));
        assert_eq!(ks.last_toggled_epoch, epoch(10));
        assert!(ks.reason.is_none());
    }

    #[test]
    fn test_kill_switch_not_engaged_returns_false_for_targeted() {
        let mut ks = KillSwitch::new(epoch(1));
        ks.add_family(BuiltinFamily::ArrayMap);
        // Families added but not engaged — nothing should be killed
        assert!(!ks.is_killed(BuiltinFamily::ArrayMap));
        assert!(!ks.is_killed(BuiltinFamily::JsonParse));
    }

    #[test]
    fn test_kill_switch_engage_after_disengage_reengages() {
        let mut ks = KillSwitch::new(epoch(1));
        ks.engage("first", epoch(2));
        ks.disengage(epoch(3));
        assert!(!ks.is_killed(BuiltinFamily::ArrayMap));

        ks.engage("second", epoch(4));
        assert!(ks.is_killed(BuiltinFamily::ArrayMap));
        assert_eq!(ks.reason, Some("second".to_string()));
    }

    // ---------------------------------------------------------------
    // Additional tests — catalog register overwrites
    // ---------------------------------------------------------------

    #[test]
    fn test_catalog_register_overwrites_existing() {
        let mut catalog = MorselKernelCatalog::new();
        let k1 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane4,
            MorselSize::Small,
            CallbackFenceKind::NoCallback,
        );
        catalog.register(k1);

        let k2 = MorselKernelDescriptor::new(
            BuiltinFamily::ArrayMap,
            LaneWidth::Lane8,
            MorselSize::Large,
            CallbackFenceKind::PureCallback,
        );
        catalog.register(k2);

        // The family_map should point to the latest registered kernel
        let looked_up = catalog.lookup(BuiltinFamily::ArrayMap).unwrap();
        assert_eq!(looked_up.lane_width, LaneWidth::Lane8);
        assert_eq!(looked_up.morsel_size, MorselSize::Large);
        // Both kernel_ids remain in the kernels map since they differ
        assert_eq!(catalog.kernel_count(), 2);
    }

    #[test]
    fn test_catalog_default_impl() {
        // Default trait delegates to with_defaults
        let cat: MorselKernelCatalog = Default::default();
        assert_eq!(cat.kernel_count(), 15);
    }

    // ---------------------------------------------------------------
    // Additional tests — engine with custom catalog
    // ---------------------------------------------------------------

    #[test]
    fn test_engine_with_empty_catalog_returns_none() {
        let mut engine = MorselKernelEngine::with_catalog(MorselKernelCatalog::new(), epoch(1));
        let receipt = engine.execute(
            BuiltinFamily::ArrayMap,
            100,
            CallbackFenceKind::PureCallback,
            None,
        );
        assert!(receipt.is_none());
        assert_eq!(engine.total_morsels_executed, 0);
    }

    #[test]
    fn test_engine_execute_zero_length_returns_none() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine.execute(
            BuiltinFamily::ArrayMap,
            0,
            CallbackFenceKind::PureCallback,
            None,
        );
        assert!(receipt.is_none());
    }

    // ---------------------------------------------------------------
    // Additional tests — MorselPartition element_count edge case
    // ---------------------------------------------------------------

    #[test]
    fn test_morsel_partition_element_count_saturating() {
        // If start > end (shouldn't normally happen), saturating_sub returns 0
        let part = MorselPartition {
            index: 0,
            start: 100,
            end: 50,
            lane_width: LaneWidth::Lane8,
            is_tail: false,
        };
        assert_eq!(part.element_count(), 0);
    }

    // ---------------------------------------------------------------
    // Additional tests — receipt id format
    // ---------------------------------------------------------------

    #[test]
    fn test_receipt_id_format_prefix_and_length() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayMap,
                100,
                CallbackFenceKind::PureCallback,
                None,
            )
            .unwrap();
        assert!(receipt.receipt_id.starts_with("mkr-"));
        // "mkr-" + 16 hex chars = 20 total
        assert_eq!(receipt.receipt_id.len(), 20);
    }

    #[test]
    fn test_receipt_hash_differs_by_epoch() {
        let mut e1 = MorselKernelEngine::new(epoch(1));
        let mut e2 = MorselKernelEngine::new(epoch(99));
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
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_receipt_hash_differs_by_input_length() {
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
                200,
                CallbackFenceKind::PureCallback,
                None,
            )
            .unwrap();
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    // ---------------------------------------------------------------
    // Additional tests — callback fence kind as_str completeness
    // ---------------------------------------------------------------

    #[test]
    fn test_callback_fence_kind_as_str_all_variants() {
        assert_eq!(CallbackFenceKind::NoCallback.as_str(), "no_callback");
        assert_eq!(CallbackFenceKind::PureCallback.as_str(), "pure_callback");
        assert_eq!(
            CallbackFenceKind::SideEffectCallback.as_str(),
            "side_effect_callback"
        );
        assert_eq!(
            CallbackFenceKind::ThrowingCallback.as_str(),
            "throwing_callback"
        );
        assert_eq!(
            CallbackFenceKind::MutatingCallback.as_str(),
            "mutating_callback"
        );
    }

    // ---------------------------------------------------------------
    // Additional tests — morsel outcome ordering
    // ---------------------------------------------------------------

    #[test]
    fn test_morsel_outcome_ordering() {
        // Derive(Ord) gives declaration order
        assert!(MorselOutcome::Vectorized < MorselOutcome::ScalarFallback);
        assert!(MorselOutcome::ScalarFallback < MorselOutcome::AbortedMutation);
        assert!(MorselOutcome::AbortedMutation < MorselOutcome::AbortedKillSwitch);
        assert!(MorselOutcome::AbortedKillSwitch < MorselOutcome::Skipped);
    }

    #[test]
    fn test_morsel_outcome_as_str_all_variants() {
        assert_eq!(MorselOutcome::Vectorized.as_str(), "vectorized");
        assert_eq!(MorselOutcome::ScalarFallback.as_str(), "scalar_fallback");
        assert_eq!(MorselOutcome::AbortedMutation.as_str(), "aborted_mutation");
        assert_eq!(
            MorselOutcome::AbortedKillSwitch.as_str(),
            "aborted_kill_switch"
        );
        assert_eq!(MorselOutcome::Skipped.as_str(), "skipped");
    }

    // ---------------------------------------------------------------
    // Additional tests — MorselExecutionRecord serde
    // ---------------------------------------------------------------

    #[test]
    fn test_morsel_execution_record_serde_roundtrip() {
        let record = MorselExecutionRecord {
            partition: MorselPartition {
                index: 0,
                start: 0,
                end: 256,
                lane_width: LaneWidth::Lane8,
                is_tail: false,
            },
            outcome: MorselOutcome::Vectorized,
            elements_processed: 256,
            elements_masked: 0,
            fences: vec![CallbackFence {
                kind: CallbackFenceKind::PureCallback,
                after_morsel: 0,
                flushed_effects: false,
                callback_invocations: 10,
            }],
            epoch: epoch(1),
        };
        let json = serde_json::to_string(&record).unwrap();
        let decoded: MorselExecutionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, decoded);
    }

    // ---------------------------------------------------------------
    // Additional tests — diagnostics after kill switch
    // ---------------------------------------------------------------

    #[test]
    fn test_diagnostics_reflects_kill_switch_state() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let diag = engine.diagnostics();
        assert!(!diag.kill_switch_engaged);

        engine.engage_kill_switch("test reason");
        let diag = engine.diagnostics();
        assert!(diag.kill_switch_engaged);

        engine.disengage_kill_switch();
        let diag = engine.diagnostics();
        assert!(!diag.kill_switch_engaged);
    }

    // ---------------------------------------------------------------
    // Additional tests — pure callback fences count zero
    // ---------------------------------------------------------------

    #[test]
    fn test_pure_callback_produces_zero_fences() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine
            .execute(
                BuiltinFamily::ArrayMap,
                500,
                CallbackFenceKind::PureCallback,
                None,
            )
            .unwrap();
        // PureCallback does not require ordering => no fences
        assert_eq!(receipt.total_fences, 0);
    }

    #[test]
    fn test_no_callback_produces_zero_fences() {
        let mut engine = MorselKernelEngine::new(epoch(1));
        let receipt = engine
            .execute(
                BuiltinFamily::TypedArrayFill,
                2000,
                CallbackFenceKind::NoCallback,
                None,
            )
            .unwrap();
        assert_eq!(receipt.total_fences, 0);
    }
}
