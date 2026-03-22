//! Garbage collector with deterministic test mode.
//!
//! Provides domain-aware, per-extension garbage collection with fully
//! reproducible behavior under test/replay conditions.  Uses mark-sweep
//! as the initial collection strategy.
//!
//! Plan references: Section 10.3 item 2, 9A.3/9F.3 (deterministic replay),
//! 9A.8 (per-extension resource budgets), 9B.4 (allocator strategy).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::alloc_domain::{AllocDomainError, AllocationDomain, DomainRegistry};

// ---------------------------------------------------------------------------
// GcObjectId — unique identity for managed objects
// ---------------------------------------------------------------------------

/// Unique identifier for a GC-managed object within an extension heap.
///
/// IDs are monotonically assigned per-heap for deterministic ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GcObjectId(u64);

impl GcObjectId {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for GcObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "obj-{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// GcObject — a managed object with outgoing references
// ---------------------------------------------------------------------------

/// A garbage-collected object with a size and references to other objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcObject {
    pub id: GcObjectId,
    pub size_bytes: u64,
    /// Outgoing references.  `BTreeSet` guarantees deterministic iteration.
    pub references: BTreeSet<GcObjectId>,
    /// Root objects are always reachable (e.g., global variables, stack frames).
    pub rooted: bool,
}

// ---------------------------------------------------------------------------
// GcPhase — collection phases for event reporting
// ---------------------------------------------------------------------------

/// Phases of a mark-sweep collection cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcPhase {
    Mark,
    Sweep,
    Complete,
}

impl fmt::Display for GcPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Mark => "mark",
            Self::Sweep => "sweep",
            Self::Complete => "complete",
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// GcEvent — structured events for telemetry / evidence ledger
// ---------------------------------------------------------------------------

/// Structured event emitted during GC operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcEvent {
    /// Monotonic sequence number for deterministic ordering.
    pub sequence: u64,
    /// Which extension heap was collected.
    pub extension_id: String,
    pub phase: GcPhase,
    /// Objects found reachable during mark phase.
    pub marked_count: u64,
    /// Objects freed during sweep phase.
    pub swept_count: u64,
    /// Bytes reclaimed during this collection.
    pub bytes_reclaimed: u64,
    /// Pause duration in nanoseconds.  Deterministic mode uses a fixed
    /// sentinel (1000 ns) so replay produces identical event streams.
    pub pause_ns: u64,
}

// ---------------------------------------------------------------------------
// GcConfig — configuration for collector behavior
// ---------------------------------------------------------------------------

/// Configuration controlling GC behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcConfig {
    /// Enable deterministic mode (fixed ordering, reproducible for replay).
    pub deterministic: bool,
    /// Pressure threshold (0–100): trigger collection when heap utilization
    /// as a percentage of budget exceeds this value.
    pub pressure_threshold_percent: u8,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            deterministic: false,
            pressure_threshold_percent: 75,
        }
    }
}

impl GcConfig {
    /// Create a deterministic configuration for testing/replay.
    pub fn deterministic() -> Self {
        Self {
            deterministic: true,
            pressure_threshold_percent: 75,
        }
    }

    /// Pressure threshold as a ratio (0.0–1.0).
    pub fn pressure_ratio(&self) -> f64 {
        f64::from(self.pressure_threshold_percent) / 100.0
    }
}

// ---------------------------------------------------------------------------
// GcError — typed error contract
// ---------------------------------------------------------------------------

/// Errors from GC operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GcError {
    /// Extension heap not found.
    HeapNotFound { extension_id: String },
    /// Extension heap already registered.
    DuplicateHeap { extension_id: String },
    /// Object not found in heap.
    ObjectNotFound {
        extension_id: String,
        object_id: GcObjectId,
    },
    /// Allocation domain error propagated from budget system.
    DomainError(AllocDomainError),
}

impl fmt::Display for GcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeapNotFound { extension_id } => {
                write!(f, "gc heap not found for extension '{}'", extension_id)
            }
            Self::DuplicateHeap { extension_id } => {
                write!(
                    f,
                    "gc heap already registered for extension '{}'",
                    extension_id
                )
            }
            Self::ObjectNotFound {
                extension_id,
                object_id,
            } => write!(
                f,
                "object {} not found in extension '{}' heap",
                object_id, extension_id
            ),
            Self::DomainError(e) => write!(f, "domain error: {}", e),
        }
    }
}

impl std::error::Error for GcError {}

impl From<AllocDomainError> for GcError {
    fn from(e: AllocDomainError) -> Self {
        Self::DomainError(e)
    }
}

// ---------------------------------------------------------------------------
// CollectionStats — returned from a collection pass
// ---------------------------------------------------------------------------

/// Statistics from a single collection pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectionStats {
    pub marked_count: u64,
    pub swept_count: u64,
    pub bytes_reclaimed: u64,
}

// ---------------------------------------------------------------------------
// ExtensionHeap — per-extension managed object heap
// ---------------------------------------------------------------------------

/// Per-extension heap of GC-managed objects.
///
/// Each extension has its own heap with independent collection.  Collection
/// of one extension's heap never reads or writes another extension's objects
/// (hard isolation requirement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionHeap {
    extension_id: String,
    /// All objects in this heap.  `BTreeMap` for deterministic iteration.
    objects: BTreeMap<GcObjectId, GcObject>,
    next_id: u64,
    total_bytes: u64,
    collection_count: u64,
    total_reclaimed: u64,
}

impl ExtensionHeap {
    pub fn new(extension_id: String) -> Self {
        Self {
            extension_id,
            objects: BTreeMap::new(),
            next_id: 0,
            total_bytes: 0,
            collection_count: 0,
            total_reclaimed: 0,
        }
    }

    /// Extension this heap belongs to.
    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    /// Allocate a new rooted object, returning its ID.
    pub fn allocate(&mut self, size_bytes: u64) -> GcObjectId {
        let id = GcObjectId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.objects.insert(
            id,
            GcObject {
                id,
                size_bytes,
                references: BTreeSet::new(),
                rooted: true,
            },
        );
        self.total_bytes = self.total_bytes.saturating_add(size_bytes);
        id
    }

    /// Add a reference from one object to another within this heap.
    pub fn add_reference(&mut self, from: GcObjectId, to: GcObjectId) -> Result<(), GcError> {
        let obj = self.objects.get_mut(&from).ok_or(GcError::ObjectNotFound {
            extension_id: self.extension_id.clone(),
            object_id: from,
        })?;
        obj.references.insert(to);
        Ok(())
    }

    /// Remove root status (object becomes collectible if unreachable).
    pub fn unroot(&mut self, id: GcObjectId) -> Result<(), GcError> {
        let obj = self.objects.get_mut(&id).ok_or(GcError::ObjectNotFound {
            extension_id: self.extension_id.clone(),
            object_id: id,
        })?;
        obj.rooted = false;
        Ok(())
    }

    /// Re-root an object.
    pub fn root(&mut self, id: GcObjectId) -> Result<(), GcError> {
        let obj = self.objects.get_mut(&id).ok_or(GcError::ObjectNotFound {
            extension_id: self.extension_id.clone(),
            object_id: id,
        })?;
        obj.rooted = true;
        Ok(())
    }

    /// Number of live objects.
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Total bytes currently in this heap.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn collection_count(&self) -> u64 {
        self.collection_count
    }

    pub fn total_reclaimed(&self) -> u64 {
        self.total_reclaimed
    }

    /// Check whether an object exists.
    pub fn contains(&self, id: GcObjectId) -> bool {
        self.objects.contains_key(&id)
    }

    /// Get a reference to an object.
    pub fn get(&self, id: GcObjectId) -> Option<&GcObject> {
        self.objects.get(&id)
    }

    /// Perform a mark-sweep collection.
    ///
    /// Handles circular references safely: the mark set prevents infinite
    /// traversal.  Dangling references (to non-existent objects) are silently
    /// ignored (safe-mode requirement for untrusted extension graphs).
    fn collect_mark_sweep(&mut self) -> CollectionStats {
        // -- Phase 1: Mark --
        let mut marked: BTreeSet<GcObjectId> = BTreeSet::new();
        let mut work_stack: Vec<GcObjectId> = Vec::new();

        // Seed with all rooted objects (deterministic order from BTreeMap).
        for (id, obj) in &self.objects {
            if obj.rooted {
                work_stack.push(*id);
            }
        }

        while let Some(id) = work_stack.pop() {
            if marked.contains(&id) {
                continue;
            }
            // Only mark objects that actually exist in the heap.
            // Dangling references (to non-existent IDs) are silently
            // ignored — safe-mode requirement for untrusted code.
            if let Some(obj) = self.objects.get(&id) {
                marked.insert(id);
                for &ref_id in &obj.references {
                    if !marked.contains(&ref_id) {
                        work_stack.push(ref_id);
                    }
                }
            }
        }

        let marked_count = marked.len() as u64;

        // -- Phase 2: Sweep --
        let before_count = self.objects.len() as u64;
        let mut bytes_reclaimed: u64 = 0;

        self.objects.retain(|id, obj| {
            if marked.contains(id) {
                true
            } else {
                bytes_reclaimed += obj.size_bytes;
                false
            }
        });

        let swept_count = before_count - self.objects.len() as u64;
        self.total_bytes = self.total_bytes.saturating_sub(bytes_reclaimed);
        self.total_reclaimed = self.total_reclaimed.saturating_add(bytes_reclaimed);
        self.collection_count = self.collection_count.saturating_add(1);

        CollectionStats {
            marked_count,
            swept_count,
            bytes_reclaimed,
        }
    }
}

// ---------------------------------------------------------------------------
// GcCollector — top-level GC managing per-extension heaps
// ---------------------------------------------------------------------------

/// Top-level garbage collector managing independent per-extension heaps.
///
/// Uses `BTreeMap` for deterministic heap iteration order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcCollector {
    heaps: BTreeMap<String, ExtensionHeap>,
    config: GcConfig,
    /// Monotonic event sequence for telemetry ordering.
    event_sequence: u64,
    /// Recorded GC events for replay/evidence.
    events: Vec<GcEvent>,
}

impl GcCollector {
    pub fn new(config: GcConfig) -> Self {
        Self {
            heaps: BTreeMap::new(),
            config,
            event_sequence: 0,
            events: Vec::new(),
        }
    }

    /// Register a new extension heap.
    pub fn register_heap(&mut self, extension_id: String) -> Result<(), GcError> {
        if self.heaps.contains_key(&extension_id) {
            return Err(GcError::DuplicateHeap { extension_id });
        }
        self.heaps
            .insert(extension_id.clone(), ExtensionHeap::new(extension_id));
        Ok(())
    }

    /// Remove an extension heap entirely (on extension termination).
    pub fn remove_heap(&mut self, extension_id: &str) -> Result<ExtensionHeap, GcError> {
        self.heaps
            .remove(extension_id)
            .ok_or_else(|| GcError::HeapNotFound {
                extension_id: extension_id.to_string(),
            })
    }

    /// Get a reference to an extension's heap.
    pub fn get_heap(&self, extension_id: &str) -> Option<&ExtensionHeap> {
        self.heaps.get(extension_id)
    }

    /// Get a mutable reference to an extension's heap.
    pub fn get_heap_mut(&mut self, extension_id: &str) -> Option<&mut ExtensionHeap> {
        self.heaps.get_mut(extension_id)
    }

    /// Allocate an object in the specified extension's heap.
    pub fn allocate(&mut self, extension_id: &str, size_bytes: u64) -> Result<GcObjectId, GcError> {
        let heap = self
            .heaps
            .get_mut(extension_id)
            .ok_or_else(|| GcError::HeapNotFound {
                extension_id: extension_id.to_string(),
            })?;
        Ok(heap.allocate(size_bytes))
    }

    /// Allocate an object, charging the allocation against a `DomainRegistry`.
    ///
    /// Returns the object ID and the domain allocation sequence number.
    pub fn allocate_tracked(
        &mut self,
        extension_id: &str,
        size_bytes: u64,
        registry: &mut DomainRegistry,
    ) -> Result<(GcObjectId, u64), GcError> {
        if !self.heaps.contains_key(extension_id) {
            return Err(GcError::HeapNotFound {
                extension_id: extension_id.to_string(),
            });
        }
        let seq = registry.allocate(AllocationDomain::ExtensionHeap, size_bytes)?;
        let id = self.allocate(extension_id, size_bytes)?;
        Ok((id, seq))
    }

    /// Add a reference between objects in the same extension heap.
    pub fn add_reference(
        &mut self,
        extension_id: &str,
        from: GcObjectId,
        to: GcObjectId,
    ) -> Result<(), GcError> {
        let heap = self
            .heaps
            .get_mut(extension_id)
            .ok_or_else(|| GcError::HeapNotFound {
                extension_id: extension_id.to_string(),
            })?;
        heap.add_reference(from, to)
    }

    /// Unroot an object in the specified extension heap.
    pub fn unroot(&mut self, extension_id: &str, id: GcObjectId) -> Result<(), GcError> {
        let heap = self
            .heaps
            .get_mut(extension_id)
            .ok_or_else(|| GcError::HeapNotFound {
                extension_id: extension_id.to_string(),
            })?;
        heap.unroot(id)
    }

    /// Collect garbage from a single extension's heap.
    pub fn collect(&mut self, extension_id: &str) -> Result<GcEvent, GcError> {
        let heap = self
            .heaps
            .get_mut(extension_id)
            .ok_or_else(|| GcError::HeapNotFound {
                extension_id: extension_id.to_string(),
            })?;

        let stats = heap.collect_mark_sweep();

        self.event_sequence = self.event_sequence.saturating_add(1);
        let event = GcEvent {
            sequence: self.event_sequence,
            extension_id: extension_id.to_string(),
            phase: GcPhase::Complete,
            marked_count: stats.marked_count,
            swept_count: stats.swept_count,
            bytes_reclaimed: stats.bytes_reclaimed,
            pause_ns: if self.config.deterministic { 1000 } else { 0 },
        };
        self.events.push(event.clone());
        Ok(event)
    }

    /// Collect garbage and release reclaimed bytes back to a `DomainRegistry`.
    pub fn collect_tracked(
        &mut self,
        extension_id: &str,
        registry: &mut DomainRegistry,
    ) -> Result<GcEvent, GcError> {
        if !self.heaps.contains_key(extension_id) {
            return Err(GcError::HeapNotFound {
                extension_id: extension_id.to_string(),
            });
        }
        if registry.get(&AllocationDomain::ExtensionHeap).is_none() {
            return Err(GcError::DomainError(AllocDomainError::DomainNotFound {
                domain: AllocationDomain::ExtensionHeap,
            }));
        }
        let event = self.collect(extension_id)?;
        if event.bytes_reclaimed > 0 {
            registry.release(AllocationDomain::ExtensionHeap, event.bytes_reclaimed)?;
        }
        Ok(event)
    }

    /// Collect garbage from all extension heaps in deterministic order.
    pub fn collect_all(&mut self) -> Vec<GcEvent> {
        let ext_ids: Vec<String> = self.heaps.keys().cloned().collect();
        let mut all_events = Vec::new();
        for ext_id in ext_ids {
            if let Ok(event) = self.collect(&ext_id) {
                all_events.push(event);
            }
        }
        all_events
    }

    /// Check if a specific extension's heap exceeds the pressure threshold
    /// relative to a given budget.
    pub fn check_pressure(&self, extension_id: &str, budget_max_bytes: u64) -> Option<f64> {
        let heap = self.heaps.get(extension_id)?;
        if budget_max_bytes == 0 {
            return Some(if heap.total_bytes() > 0 {
                f64::MAX
            } else {
                0.0
            });
        }
        Some(heap.total_bytes() as f64 / budget_max_bytes as f64)
    }

    /// Should we trigger collection for this extension based on pressure?
    pub fn should_collect(&self, extension_id: &str, budget_max_bytes: u64) -> bool {
        self.check_pressure(extension_id, budget_max_bytes)
            .is_some_and(|u| u >= self.config.pressure_ratio())
    }

    /// All recorded GC events.
    pub fn events(&self) -> &[GcEvent] {
        &self.events
    }

    /// Current event sequence number.
    pub fn event_sequence(&self) -> u64 {
        self.event_sequence
    }

    /// Number of registered heaps.
    pub fn heap_count(&self) -> usize {
        self.heaps.len()
    }

    /// Iterate heaps in deterministic order.
    pub fn iter_heaps(&self) -> impl Iterator<Item = (&str, &ExtensionHeap)> {
        self.heaps.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Configuration reference.
    pub fn config(&self) -> &GcConfig {
        &self.config
    }
}

impl Default for GcCollector {
    fn default() -> Self {
        Self::new(GcConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn deterministic_collector() -> GcCollector {
        GcCollector::new(GcConfig::deterministic())
    }

    // -- Basic allocation and collection --

    #[test]
    fn allocate_and_collect_dead_objects() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let obj1 = gc.allocate("ext-a", 100).unwrap();
        let obj2 = gc.allocate("ext-a", 200).unwrap();

        // Unroot both — they become garbage.
        gc.unroot("ext-a", obj1).unwrap();
        gc.unroot("ext-a", obj2).unwrap();

        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.swept_count, 2);
        assert_eq!(event.bytes_reclaimed, 300);
        assert_eq!(event.marked_count, 0);

        let heap = gc.get_heap("ext-a").unwrap();
        assert_eq!(heap.object_count(), 0);
        assert_eq!(heap.total_bytes(), 0);
    }

    #[test]
    fn rooted_objects_survive_collection() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let obj1 = gc.allocate("ext-a", 100).unwrap();
        let _obj2 = gc.allocate("ext-a", 200).unwrap();

        // Only unroot obj1.
        gc.unroot("ext-a", obj1).unwrap();

        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.swept_count, 1); // obj1 collected
        assert_eq!(event.bytes_reclaimed, 100);
        assert_eq!(event.marked_count, 1); // obj2 still alive

        let heap = gc.get_heap("ext-a").unwrap();
        assert_eq!(heap.object_count(), 1);
    }

    #[test]
    fn referenced_objects_survive_collection() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let root = gc.allocate("ext-a", 50).unwrap();
        let child = gc.allocate("ext-a", 80).unwrap();
        let grandchild = gc.allocate("ext-a", 120).unwrap();

        // root -> child -> grandchild
        gc.add_reference("ext-a", root, child).unwrap();
        gc.add_reference("ext-a", child, grandchild).unwrap();

        // Unroot child and grandchild — they're still reachable from root.
        gc.unroot("ext-a", child).unwrap();
        gc.unroot("ext-a", grandchild).unwrap();

        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.marked_count, 3);
        assert_eq!(event.swept_count, 0);

        let heap = gc.get_heap("ext-a").unwrap();
        assert_eq!(heap.object_count(), 3);
    }

    // -- Circular references (safe-mode) --

    #[test]
    fn circular_references_collected_when_unreachable() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let a = gc.allocate("ext-a", 64).unwrap();
        let b = gc.allocate("ext-a", 64).unwrap();
        let c = gc.allocate("ext-a", 64).unwrap();

        // Create cycle: a -> b -> c -> a
        gc.add_reference("ext-a", a, b).unwrap();
        gc.add_reference("ext-a", b, c).unwrap();
        gc.add_reference("ext-a", c, a).unwrap();

        // Unroot all — cycle is unreachable.
        gc.unroot("ext-a", a).unwrap();
        gc.unroot("ext-a", b).unwrap();
        gc.unroot("ext-a", c).unwrap();

        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.swept_count, 3);
        assert_eq!(event.bytes_reclaimed, 192);

        let heap = gc.get_heap("ext-a").unwrap();
        assert_eq!(heap.object_count(), 0);
    }

    #[test]
    fn circular_references_survive_when_rooted() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let a = gc.allocate("ext-a", 64).unwrap();
        let b = gc.allocate("ext-a", 64).unwrap();

        // a -> b -> a (cycle), but a remains rooted.
        gc.add_reference("ext-a", a, b).unwrap();
        gc.add_reference("ext-a", b, a).unwrap();
        gc.unroot("ext-a", b).unwrap();

        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.marked_count, 2);
        assert_eq!(event.swept_count, 0);
    }

    // -- Dangling references (safe-mode) --

    #[test]
    fn dangling_references_do_not_crash() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let obj = gc.allocate("ext-a", 100).unwrap();
        // Add reference to a non-existent object ID.
        let phantom = GcObjectId(999);
        gc.get_heap_mut("ext-a")
            .unwrap()
            .objects
            .get_mut(&obj)
            .unwrap()
            .references
            .insert(phantom);

        // Collection should succeed without panic.
        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.marked_count, 1); // obj is rooted
        assert_eq!(event.swept_count, 0);
    }

    // -- Per-extension isolation --

    #[test]
    fn per_extension_collection_isolation() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        gc.register_heap("ext-b".into()).unwrap();

        let a1 = gc.allocate("ext-a", 100).unwrap();
        let _b1 = gc.allocate("ext-b", 200).unwrap();

        // Unroot a1 and collect ext-a only.
        gc.unroot("ext-a", a1).unwrap();
        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.swept_count, 1);
        assert_eq!(event.bytes_reclaimed, 100);
        assert_eq!(event.extension_id, "ext-a");

        // ext-b should be completely unaffected.
        let heap_b = gc.get_heap("ext-b").unwrap();
        assert_eq!(heap_b.object_count(), 1);
        assert_eq!(heap_b.total_bytes(), 200);
        assert_eq!(heap_b.collection_count(), 0);
    }

    #[test]
    fn collect_all_processes_heaps_in_deterministic_order() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-c".into()).unwrap();
        gc.register_heap("ext-a".into()).unwrap();
        gc.register_heap("ext-b".into()).unwrap();

        let events = gc.collect_all();
        assert_eq!(events.len(), 3);
        // BTreeMap orders by key — alphabetical.
        assert_eq!(events[0].extension_id, "ext-a");
        assert_eq!(events[1].extension_id, "ext-b");
        assert_eq!(events[2].extension_id, "ext-c");
        // Sequence numbers are monotonically assigned.
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[2].sequence, 3);
    }

    // -- Deterministic mode --

    #[test]
    fn deterministic_mode_produces_identical_event_sequence() {
        fn run_scenario() -> Vec<GcEvent> {
            let mut gc = GcCollector::new(GcConfig::deterministic());
            gc.register_heap("ext-a".into()).unwrap();

            let r = gc.allocate("ext-a", 50).unwrap();
            let a = gc.allocate("ext-a", 30).unwrap();
            let b = gc.allocate("ext-a", 20).unwrap();

            gc.add_reference("ext-a", r, a).unwrap();
            gc.add_reference("ext-a", a, b).unwrap();
            gc.unroot("ext-a", a).unwrap();
            gc.unroot("ext-a", b).unwrap();

            gc.collect("ext-a").unwrap();

            let c = gc.allocate("ext-a", 40).unwrap();
            gc.unroot("ext-a", c).unwrap();
            gc.unroot("ext-a", r).unwrap();

            gc.collect("ext-a").unwrap();
            gc.events().to_vec()
        }

        let run1 = run_scenario();
        let run2 = run_scenario();
        assert_eq!(run1, run2);
    }

    #[test]
    fn deterministic_mode_uses_fixed_pause_ns() {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext-a".into()).unwrap();
        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.pause_ns, 1000);
    }

    #[test]
    fn non_deterministic_mode_uses_zero_pause_ns() {
        let mut gc = GcCollector::new(GcConfig::default());
        gc.register_heap("ext-a".into()).unwrap();
        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.pause_ns, 0);
    }

    // -- Pressure / budget integration --

    #[test]
    fn pressure_check_reports_correct_utilization() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        gc.allocate("ext-a", 750).unwrap();

        let util = gc.check_pressure("ext-a", 1000).unwrap();
        assert!((util - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn should_collect_respects_threshold() {
        let mut gc = GcCollector::new(GcConfig {
            deterministic: true,
            pressure_threshold_percent: 50,
        });
        gc.register_heap("ext-a".into()).unwrap();

        gc.allocate("ext-a", 400).unwrap();
        assert!(!gc.should_collect("ext-a", 1000)); // 40% < 50%

        gc.allocate("ext-a", 200).unwrap();
        assert!(gc.should_collect("ext-a", 1000)); // 60% >= 50%
    }

    #[test]
    fn should_collect_returns_false_for_unknown_heap() {
        let gc = deterministic_collector();
        assert!(!gc.should_collect("nonexistent", 1000));
    }

    // -- Domain registry integration --

    #[test]
    fn allocate_tracked_charges_domain_registry() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            crate::alloc_domain::LifetimeClass::SessionScoped,
            1000,
        )
        .unwrap();

        let (obj_id, seq) = gc.allocate_tracked("ext-a", 400, &mut reg).unwrap();
        assert_eq!(obj_id.as_u64(), 0);
        assert_eq!(seq, 1);
        assert_eq!(
            reg.get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes,
            400
        );
    }

    #[test]
    fn collect_tracked_releases_to_domain_registry() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            crate::alloc_domain::LifetimeClass::SessionScoped,
            1000,
        )
        .unwrap();

        let (obj_id, _) = gc.allocate_tracked("ext-a", 400, &mut reg).unwrap();
        gc.unroot("ext-a", obj_id).unwrap();

        let event = gc.collect_tracked("ext-a", &mut reg).unwrap();
        assert_eq!(event.bytes_reclaimed, 400);
        assert_eq!(
            reg.get(&AllocationDomain::ExtensionHeap)
                .unwrap()
                .budget
                .used_bytes,
            0
        );
    }

    #[test]
    fn collect_tracked_missing_registry_domain_fails_without_mutation() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let obj_id = gc.allocate("ext-a", 400).unwrap();
        gc.unroot("ext-a", obj_id).unwrap();

        let mut reg = DomainRegistry::new();
        let result = gc.collect_tracked("ext-a", &mut reg);
        assert!(matches!(
            result,
            Err(GcError::DomainError(AllocDomainError::DomainNotFound {
                domain: AllocationDomain::ExtensionHeap
            }))
        ));

        let heap = gc.get_heap("ext-a").unwrap();
        assert_eq!(heap.object_count(), 1);
        assert_eq!(heap.total_bytes(), 400);
        assert_eq!(gc.events().len(), 0);
        assert_eq!(gc.event_sequence(), 0);
    }

    #[test]
    fn allocate_tracked_rejects_when_budget_exceeded() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let mut reg = DomainRegistry::new();
        reg.register(
            AllocationDomain::ExtensionHeap,
            crate::alloc_domain::LifetimeClass::SessionScoped,
            100,
        )
        .unwrap();

        let result = gc.allocate_tracked("ext-a", 200, &mut reg);
        assert!(matches!(result, Err(GcError::DomainError(_))));
    }

    // -- Heap management --

    #[test]
    fn register_duplicate_heap_rejected() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        assert!(matches!(
            gc.register_heap("ext-a".into()),
            Err(GcError::DuplicateHeap { .. })
        ));
    }

    #[test]
    fn remove_heap_returns_heap_data() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        gc.allocate("ext-a", 100).unwrap();

        let heap = gc.remove_heap("ext-a").unwrap();
        assert_eq!(heap.extension_id(), "ext-a");
        assert_eq!(heap.object_count(), 1);
        assert_eq!(gc.heap_count(), 0);
    }

    #[test]
    fn remove_nonexistent_heap_fails() {
        let mut gc = deterministic_collector();
        assert!(matches!(
            gc.remove_heap("nonexistent"),
            Err(GcError::HeapNotFound { .. })
        ));
    }

    #[test]
    fn collect_nonexistent_heap_fails() {
        let mut gc = deterministic_collector();
        assert!(matches!(
            gc.collect("nonexistent"),
            Err(GcError::HeapNotFound { .. })
        ));
    }

    // -- Event recording --

    #[test]
    fn events_accumulate_across_collections() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        gc.register_heap("ext-b".into()).unwrap();

        gc.collect("ext-a").unwrap();
        gc.collect("ext-b").unwrap();
        gc.collect("ext-a").unwrap();

        assert_eq!(gc.events().len(), 3);
        assert_eq!(gc.event_sequence(), 3);
        assert_eq!(gc.events()[0].sequence, 1);
        assert_eq!(gc.events()[1].sequence, 2);
        assert_eq!(gc.events()[2].sequence, 3);
    }

    // -- Re-root --

    #[test]
    fn reroot_prevents_collection() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let obj = gc.allocate("ext-a", 100).unwrap();
        gc.unroot("ext-a", obj).unwrap();
        gc.get_heap_mut("ext-a").unwrap().root(obj).unwrap();

        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.swept_count, 0);
        assert_eq!(event.marked_count, 1);
    }

    // -- Empty collection --

    #[test]
    fn collecting_empty_heap_is_noop() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let event = gc.collect("ext-a").unwrap();
        assert_eq!(event.marked_count, 0);
        assert_eq!(event.swept_count, 0);
        assert_eq!(event.bytes_reclaimed, 0);
    }

    // -- Collection count tracking --

    #[test]
    fn collection_count_increments() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        gc.collect("ext-a").unwrap();
        gc.collect("ext-a").unwrap();
        gc.collect("ext-a").unwrap();

        assert_eq!(gc.get_heap("ext-a").unwrap().collection_count(), 3);
    }

    // -- Total reclaimed tracking --

    #[test]
    fn total_reclaimed_accumulates() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let a = gc.allocate("ext-a", 100).unwrap();
        gc.unroot("ext-a", a).unwrap();
        gc.collect("ext-a").unwrap();

        let b = gc.allocate("ext-a", 200).unwrap();
        gc.unroot("ext-a", b).unwrap();
        gc.collect("ext-a").unwrap();

        assert_eq!(gc.get_heap("ext-a").unwrap().total_reclaimed(), 300);
    }

    // -- Serialization --

    #[test]
    fn gc_collector_serialization_round_trip() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        let obj = gc.allocate("ext-a", 100).unwrap();
        gc.unroot("ext-a", obj).unwrap();
        gc.collect("ext-a").unwrap();

        let json = serde_json::to_string(&gc).expect("serialize");
        let restored: GcCollector = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(gc.heap_count(), restored.heap_count());
        assert_eq!(gc.event_sequence(), restored.event_sequence());
        assert_eq!(gc.events().len(), restored.events().len());
        assert_eq!(
            gc.get_heap("ext-a").unwrap().object_count(),
            restored.get_heap("ext-a").unwrap().object_count()
        );
    }

    #[test]
    fn gc_config_deterministic_defaults() {
        let config = GcConfig::deterministic();
        assert!(config.deterministic);
        assert_eq!(config.pressure_threshold_percent, 75);
        assert!((config.pressure_ratio() - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn gc_object_id_display() {
        let id = GcObjectId(42);
        assert_eq!(id.to_string(), "obj-42");
        assert_eq!(id.as_u64(), 42);
    }

    // -----------------------------------------------------------------------
    // GcError Display
    // -----------------------------------------------------------------------

    #[test]
    fn gc_error_heap_not_found_display() {
        let err = GcError::HeapNotFound {
            extension_id: "missing-ext".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("missing-ext"));
        assert!(display.contains("not found"));
    }

    #[test]
    fn gc_error_duplicate_heap_display() {
        let err = GcError::DuplicateHeap {
            extension_id: "dup-ext".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("dup-ext"));
        assert!(display.contains("already registered"));
    }

    #[test]
    fn gc_error_object_not_found_display() {
        let err = GcError::ObjectNotFound {
            extension_id: "ext-a".to_string(),
            object_id: GcObjectId(99),
        };
        let display = format!("{err}");
        assert!(display.contains("obj-99"));
        assert!(display.contains("ext-a"));
    }

    // -----------------------------------------------------------------------
    // GcPhase Display
    // -----------------------------------------------------------------------

    #[test]
    fn gc_phase_display() {
        assert_eq!(GcPhase::Mark.to_string(), "mark");
        assert_eq!(GcPhase::Sweep.to_string(), "sweep");
        assert_eq!(GcPhase::Complete.to_string(), "complete");
    }

    // -----------------------------------------------------------------------
    // GcPhase and GcError serde round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn gc_phase_serde_round_trip() {
        for phase in &[GcPhase::Mark, GcPhase::Sweep, GcPhase::Complete] {
            let json = serde_json::to_string(phase).expect("serialize");
            let decoded: GcPhase = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, phase);
        }
    }

    #[test]
    fn gc_error_serde_round_trip() {
        let errors: Vec<GcError> = vec![
            GcError::HeapNotFound {
                extension_id: "ext".to_string(),
            },
            GcError::DuplicateHeap {
                extension_id: "ext".to_string(),
            },
            GcError::ObjectNotFound {
                extension_id: "ext".to_string(),
                object_id: GcObjectId(5),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).expect("serialize");
            let decoded: GcError = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(&decoded, err);
        }
    }

    // -----------------------------------------------------------------------
    // GcConfig default
    // -----------------------------------------------------------------------

    #[test]
    fn gc_config_default_is_non_deterministic() {
        let config = GcConfig::default();
        assert!(!config.deterministic);
        assert_eq!(config.pressure_threshold_percent, 75);
    }

    // -----------------------------------------------------------------------
    // Allocation IDs are monotonically assigned
    // -----------------------------------------------------------------------

    #[test]
    fn allocation_ids_are_monotonically_assigned() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();

        let id1 = gc.allocate("ext-a", 10).unwrap();
        let id2 = gc.allocate("ext-a", 20).unwrap();
        let id3 = gc.allocate("ext-a", 30).unwrap();

        assert_eq!(id1.as_u64(), 0);
        assert_eq!(id2.as_u64(), 1);
        assert_eq!(id3.as_u64(), 2);
    }

    // -----------------------------------------------------------------------
    // Allocate on nonexistent heap
    // -----------------------------------------------------------------------

    #[test]
    fn allocate_on_nonexistent_heap_returns_error() {
        let mut gc = deterministic_collector();
        let result = gc.allocate("nonexistent", 100);
        assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
    }

    // -----------------------------------------------------------------------
    // Unroot on nonexistent heap
    // -----------------------------------------------------------------------

    #[test]
    fn unroot_on_nonexistent_heap_returns_error() {
        let mut gc = deterministic_collector();
        let result = gc.unroot("nonexistent", GcObjectId(0));
        assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
    }

    // -----------------------------------------------------------------------
    // Add reference on nonexistent heap
    // -----------------------------------------------------------------------

    #[test]
    fn add_reference_on_nonexistent_heap_returns_error() {
        let mut gc = deterministic_collector();
        let result = gc.add_reference("nonexistent", GcObjectId(0), GcObjectId(1));
        assert!(matches!(result, Err(GcError::HeapNotFound { .. })));
    }

    // -----------------------------------------------------------------------
    // check_pressure with zero budget
    // -----------------------------------------------------------------------

    #[test]
    fn check_pressure_zero_budget_returns_zero() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        gc.allocate("ext-a", 100).unwrap();
        let pressure = gc.check_pressure("ext-a", 0).unwrap();
        // budget=0 with bytes>0 yields infinite pressure (f64::MAX).
        assert!((pressure - f64::MAX).abs() < f64::EPSILON);
    }

    #[test]
    fn check_pressure_nonexistent_returns_none() {
        let gc = deterministic_collector();
        assert!(gc.check_pressure("nonexistent", 1000).is_none());
    }

    // -----------------------------------------------------------------------
    // iter_heaps deterministic ordering
    // -----------------------------------------------------------------------

    #[test]
    fn iter_heaps_returns_deterministic_alphabetical_order() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-z".into()).unwrap();
        gc.register_heap("ext-a".into()).unwrap();
        gc.register_heap("ext-m".into()).unwrap();

        let ids: Vec<&str> = gc.iter_heaps().map(|(id, _)| id).collect();
        assert_eq!(ids, vec!["ext-a", "ext-m", "ext-z"]);
    }

    // -----------------------------------------------------------------------
    // GcEvent serde round-trip
    // -----------------------------------------------------------------------

    // -- Enrichment: std::error --

    #[test]
    fn gc_error_implements_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(GcError::HeapNotFound {
                extension_id: "ext-1".into(),
            }),
            Box::new(GcError::DuplicateHeap {
                extension_id: "ext-2".into(),
            }),
            Box::new(GcError::ObjectNotFound {
                extension_id: "ext-3".into(),
                object_id: GcObjectId(0),
            }),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            let msg = format!("{v}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(displays.len(), 3);
    }

    #[test]
    fn gc_event_serde_round_trip() {
        let mut gc = deterministic_collector();
        gc.register_heap("ext-a".into()).unwrap();
        gc.allocate("ext-a", 50).unwrap();
        let event = gc.collect("ext-a").unwrap();

        let json = serde_json::to_string(&event).expect("serialize");
        let decoded: GcEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, event);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GcError Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn gc_error_display_all_variants_unique() {
        let errors: Vec<GcError> = vec![
            GcError::HeapNotFound {
                extension_id: "ext-a".into(),
            },
            GcError::DuplicateHeap {
                extension_id: "ext-b".into(),
            },
            GcError::ObjectNotFound {
                extension_id: "ext-c".into(),
                object_id: GcObjectId(7),
            },
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            errors.len(),
            "all GcError variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: GcPhase Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn gc_phase_display_all_unique() {
        let mut displays = std::collections::BTreeSet::new();
        for phase in &[GcPhase::Mark, GcPhase::Sweep, GcPhase::Complete] {
            displays.insert(phase.to_string());
        }
        assert_eq!(displays.len(), 3);
    }

    // -----------------------------------------------------------------------
    // Enrichment: collect_all determinism
    // -----------------------------------------------------------------------

    #[test]
    fn collect_all_deterministic_across_runs() {
        fn run_scenario() -> Vec<GcEvent> {
            let mut gc = GcCollector::new(GcConfig::deterministic());
            gc.register_heap("ext-b".into()).unwrap();
            gc.register_heap("ext-a".into()).unwrap();
            gc.allocate("ext-a", 100).unwrap();
            gc.allocate("ext-b", 200).unwrap();
            gc.collect_all()
        }
        let r1 = run_scenario();
        let r2 = run_scenario();
        assert_eq!(r1, r2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: heap_count after register and remove
    // -----------------------------------------------------------------------

    #[test]
    fn heap_count_tracks_registrations_and_removals() {
        let mut gc = deterministic_collector();
        assert_eq!(gc.heap_count(), 0);
        gc.register_heap("ext-a".into()).unwrap();
        assert_eq!(gc.heap_count(), 1);
        gc.register_heap("ext-b".into()).unwrap();
        assert_eq!(gc.heap_count(), 2);
        gc.remove_heap("ext-a").unwrap();
        assert_eq!(gc.heap_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GcConfig serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn gc_config_serde_roundtrip() {
        let configs = [
            GcConfig::default(),
            GcConfig::deterministic(),
            GcConfig {
                deterministic: true,
                pressure_threshold_percent: 90,
            },
        ];
        for config in &configs {
            let json = serde_json::to_string(config).expect("serialize");
            let back: GcConfig = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(config.deterministic, back.deterministic);
            assert_eq!(
                config.pressure_threshold_percent,
                back.pressure_threshold_percent
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: pressure_ratio boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn gc_config_pressure_ratio_boundary() {
        let config_zero = GcConfig {
            deterministic: true,
            pressure_threshold_percent: 0,
        };
        assert!((config_zero.pressure_ratio() - 0.0).abs() < f64::EPSILON);

        let config_hundred = GcConfig {
            deterministic: true,
            pressure_threshold_percent: 100,
        };
        assert!((config_hundred.pressure_ratio() - 1.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Enrichment: GcObjectId ordering
    // -----------------------------------------------------------------------

    #[test]
    fn gc_object_id_ordering() {
        let a = GcObjectId(1);
        let b = GcObjectId(2);
        let c = GcObjectId(1);
        assert!(a < b);
        assert_eq!(a, c);
        let mut set = std::collections::BTreeSet::new();
        set.insert(b);
        set.insert(a);
        set.insert(c);
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Enrichment: DomainError variant in GcError serde
    // -----------------------------------------------------------------------

    #[test]
    fn gc_error_domain_error_serde_roundtrip() {
        let err = GcError::DomainError(AllocDomainError::BudgetExceeded {
            requested: 200,
            remaining: 100,
            domain: Some(AllocationDomain::ExtensionHeap),
        });
        let json = serde_json::to_string(&err).expect("serialize");
        let decoded: GcError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, err);
    }

    // ── Enrichment: GcObject serde ───────────────────────────────────

    #[test]
    fn gc_object_serde_roundtrip() {
        let mut refs = BTreeSet::new();
        refs.insert(GcObjectId(10));
        refs.insert(GcObjectId(20));
        let obj = GcObject {
            id: GcObjectId(5),
            size_bytes: 1024,
            references: refs,
            rooted: true,
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: GcObject = serde_json::from_str(&json).unwrap();
        assert_eq!(obj, back);
    }

    #[test]
    fn gc_object_empty_references_serde() {
        let obj = GcObject {
            id: GcObjectId(0),
            size_bytes: 0,
            references: BTreeSet::new(),
            rooted: false,
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: GcObject = serde_json::from_str(&json).unwrap();
        assert_eq!(obj, back);
    }

    // ── Enrichment: ExtensionHeap accessors ──────────────────────────

    #[test]
    fn extension_heap_contains_and_get() {
        let mut heap = ExtensionHeap::new("ext-a".into());
        let id = heap.allocate(64);
        assert!(heap.contains(id));
        assert!(heap.get(id).is_some());
        assert!(!heap.contains(GcObjectId(999)));
        assert!(heap.get(GcObjectId(999)).is_none());
    }

    #[test]
    fn extension_heap_extension_id_accessor() {
        let heap = ExtensionHeap::new("my-ext-42".into());
        assert_eq!(heap.extension_id(), "my-ext-42");
    }

    #[test]
    fn extension_heap_add_reference_idempotent() {
        let mut heap = ExtensionHeap::new("ext".into());
        let a = heap.allocate(10);
        let b = heap.allocate(20);
        heap.add_reference(a, b).unwrap();
        heap.add_reference(a, b).unwrap(); // duplicate
        let obj = heap.get(a).unwrap();
        assert_eq!(obj.references.len(), 1); // BTreeSet deduplicates
    }

    #[test]
    fn extension_heap_root_already_rooted_object() {
        let mut heap = ExtensionHeap::new("ext".into());
        let id = heap.allocate(10); // starts rooted
        heap.root(id).unwrap(); // re-root is no-op
        let obj = heap.get(id).unwrap();
        assert!(obj.rooted);
    }

    #[test]
    fn extension_heap_serde_roundtrip() {
        let mut heap = ExtensionHeap::new("serde-ext".into());
        let a = heap.allocate(100);
        let b = heap.allocate(200);
        heap.add_reference(a, b).unwrap();
        heap.unroot(b).unwrap();

        let json = serde_json::to_string(&heap).unwrap();
        let back: ExtensionHeap = serde_json::from_str(&json).unwrap();
        assert_eq!(back.extension_id(), "serde-ext");
        assert_eq!(back.object_count(), 2);
        assert_eq!(back.total_bytes(), 300);
    }

    // ── Enrichment: GcCollector accessors ────────────────────────────

    #[test]
    fn collector_get_heap_returns_none_for_missing() {
        let gc = GcCollector::new(GcConfig::deterministic());
        assert!(gc.get_heap("nonexistent").is_none());
    }

    #[test]
    fn collector_get_heap_mut_returns_none_for_missing() {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        assert!(gc.get_heap_mut("nonexistent").is_none());
    }

    #[test]
    fn collector_config_accessor() {
        let cfg = GcConfig {
            deterministic: true,
            pressure_threshold_percent: 50,
        };
        let gc = GcCollector::new(cfg.clone());
        assert_eq!(*gc.config(), cfg);
    }

    #[test]
    fn collector_event_sequence_monotonic() {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext-a".into()).unwrap();
        gc.register_heap("ext-b".into()).unwrap();
        let e1 = gc.collect("ext-a").unwrap();
        let e2 = gc.collect("ext-b").unwrap();
        assert!(e2.sequence > e1.sequence);
    }

    #[test]
    fn collect_all_events_have_complete_phase() {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("a".into()).unwrap();
        gc.register_heap("b".into()).unwrap();
        let events = gc.collect_all();
        assert_eq!(events.len(), 2);
        for ev in &events {
            assert_eq!(ev.phase, GcPhase::Complete);
        }
    }

    // ── Enrichment: CollectionStats ──────────────────────────────────

    #[test]
    fn collection_stats_equality() {
        let a = CollectionStats {
            marked_count: 5,
            swept_count: 3,
            bytes_reclaimed: 100,
        };
        let b = CollectionStats {
            marked_count: 5,
            swept_count: 3,
            bytes_reclaimed: 100,
        };
        let c = CollectionStats {
            marked_count: 5,
            swept_count: 2,
            bytes_reclaimed: 100,
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── Enrichment: GcPhase ──────────────────────────────────────────

    #[test]
    fn gc_phase_display_all_unique_alt() {
        let mut set = BTreeSet::new();
        for v in [GcPhase::Mark, GcPhase::Sweep, GcPhase::Complete] {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn gc_phase_serde_roundtrip_all_variants() {
        for v in [GcPhase::Mark, GcPhase::Sweep, GcPhase::Complete] {
            let json = serde_json::to_string(&v).unwrap();
            let back: GcPhase = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // ── Enrichment: GcError display ──────────────────────────────────

    #[test]
    fn gc_error_display_all_unique() {
        let variants: Vec<GcError> = vec![
            GcError::HeapNotFound {
                extension_id: "a".into(),
            },
            GcError::DuplicateHeap {
                extension_id: "b".into(),
            },
            GcError::ObjectNotFound {
                extension_id: "c".into(),
                object_id: GcObjectId(1),
            },
            GcError::DomainError(AllocDomainError::BudgetExceeded {
                requested: 10,
                remaining: 5,
                domain: None,
            }),
        ];
        let mut set = BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn gc_error_implements_std_error_alt() {
        let err = GcError::HeapNotFound {
            extension_id: "x".into(),
        };
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
    }

    // ── Enrichment: self-referencing object ──────────────────────────

    #[test]
    fn self_referencing_object_survives_collection() {
        let mut gc = GcCollector::new(GcConfig::deterministic());
        gc.register_heap("ext".into()).unwrap();
        let id = gc.allocate("ext", 64).unwrap();
        gc.add_reference("ext", id, id).unwrap(); // self-reference
        let ev = gc.collect("ext").unwrap();
        // rooted + self-referencing: survives collection
        assert_eq!(ev.swept_count, 0);
        assert_eq!(ev.marked_count, 1);
    }

    // ── Enrichment: GcConfig thresholds ──────────────────────────────

    #[test]
    fn gc_config_pressure_ratio_boundary_1_percent() {
        let cfg = GcConfig {
            deterministic: false,
            pressure_threshold_percent: 1,
        };
        let ratio = cfg.pressure_ratio();
        assert!((ratio - 0.01).abs() < 1e-6);
    }

    #[test]
    fn gc_config_should_collect_at_exact_threshold() {
        let mut gc = GcCollector::new(GcConfig {
            deterministic: true,
            pressure_threshold_percent: 50,
        });
        gc.register_heap("ext".into()).unwrap();
        gc.allocate("ext", 50).unwrap(); // 50 bytes out of budget 100
        assert!(gc.should_collect("ext", 100)); // 50% == threshold => true
    }

    // ── Enrichment: GcObjectId display ───────────────────────────────

    #[test]
    fn gc_object_id_display_format() {
        let id = GcObjectId(42);
        assert_eq!(id.to_string(), "obj-42");
    }
}
