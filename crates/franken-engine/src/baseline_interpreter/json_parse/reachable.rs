//! Admission-accounted scratch for reachable provenance walks.
//!
//! Stream edges into one reusable stack. Growing exactly to each fanout can
//! repeatedly copy a growing pending prefix on a comb-shaped graph; collecting
//! a fresh child vector also allocates once per non-leaf. Neither is necessary.

use super::*;

#[derive(Default)]
struct ReachablePending {
    objects: Vec<ObjectId>,
    bytes: u64,
}

impl ReachablePending {
    /// `committed` is the part of this stack already charged to core. While
    /// enumerating an object's immutable edges, every growth checks all the
    /// not-yet-published capacity, not merely the latest increment. No guest
    /// code or mutable core operation may run until that increment is charged.
    /// On failure the owning walk drops the entire stack.
    fn push(
        &mut self,
        core: &InterpreterCore,
        object: ObjectId,
        committed: u64,
    ) -> Result<(), InterpreterError> {
        if self.objects.len() == self.objects.capacity() {
            let additional = self.objects.capacity().max(1);
            let error = || core.memory_budget_error(u64::MAX, core.heap_object_count_u32());
            let growth = u64::try_from(additional)
                .ok()
                .and_then(|slots| slots.checked_mul(std::mem::size_of::<ObjectId>() as u64))
                .ok_or_else(error)?;
            let requested = self.bytes.checked_add(growth).ok_or_else(error)?;
            core.check_temporary_memory_budget(requested - committed)?;
            self.objects
                .try_reserve_exact(additional)
                .map_err(|_| error())?;
            let retained = u64::try_from(self.objects.capacity())
                .ok()
                .and_then(|slots| slots.checked_mul(std::mem::size_of::<ObjectId>() as u64))
                .ok_or_else(error)?;
            // Vec may expose more capacity than requested. It too belongs to
            // this walk, and must be admitted before any further operation.
            if retained > requested {
                core.check_temporary_memory_budget(retained - committed)?;
            }
            self.bytes = retained;
        }
        self.objects.push(object);
        Ok(())
    }
}

/// Keep short/sparse walks on the existing ordered set. Once a walk has
/// enough distinct objects to pay for a bitmap, replace covered tree nodes
/// with direct membership bits. This is scratch owned by ONE walk, not a
/// liveness/provenance cache: callbacks and subsequent walks see fresh state.
#[derive(Default)]
struct ReachableVisited {
    sparse: BTreeSet<ObjectId>,
    dense: Vec<u64>,
    first_word: usize,
    bytes: u64,
}

// Bound both optional scratch and the uninterruptible migration. Attempts
// happen only at 64, 128, 256, 512 and 1024 distinct sparse entries. A large
// heap or an allocation refusal always keeps the complete ordered-set path.
const MAX_REACHABLE_BITMAP_BYTES: usize = 64 * 1024;
const MAX_REACHABLE_BITMAP_MIGRATION: usize = 1024;

impl ReachableVisited {
    fn insert(
        &mut self,
        core: &mut InterpreterCore,
        object: ObjectId,
    ) -> Result<bool, InterpreterError> {
        let word = object.0 as usize / 64;
        if let Some(index) = word.checked_sub(self.first_word)
            && let Some(bits) = self.dense.get_mut(index)
        {
            let mask = 1_u64 << (object.0 % 64);
            let fresh = *bits & mask == 0;
            *bits |= mask;
            return Ok(fresh);
        }
        // Out-of-window (including invalid) IDs must never alias a bitmap
        // slot or disappear. Retain the original exact-key fallback for them.
        if self.sparse.contains(&object) {
            return Ok(false);
        }
        core.json_reserve_temporary(64)?;
        self.bytes += 64;
        self.sparse.insert(object);
        let count = self.sparse.len();
        if self.dense.is_empty()
            && (64..=MAX_REACHABLE_BITMAP_MIGRATION).contains(&count)
            && count.is_power_of_two()
        {
            let heap_len = core.heap.len();
            self.try_promote(core, heap_len)?;
        }
        Ok(true)
    }

    fn try_promote(
        &mut self,
        core: &mut InterpreterCore,
        heap_len: usize,
    ) -> Result<(), InterpreterError> {
        if !self.dense.is_empty() || self.sparse.len() > MAX_REACHABLE_BITMAP_MIGRATION {
            return Ok(());
        }
        let Some(first) = self.sparse.first() else {
            return Ok(());
        };
        // A recently allocated graph need not pay for unrelated older heap
        // slots. The window starts at its lowest observed word; earlier IDs
        // discovered later still use sparse membership.
        let first_word = first.0 as usize / 64;
        let end_word = heap_len.div_ceil(64);
        let Some(words) = end_word.checked_sub(first_word) else {
            return Ok(());
        };
        let Some(requested) = words.checked_mul(std::mem::size_of::<u64>()) else {
            return Ok(());
        };
        if requested == 0 || requested > MAX_REACHABLE_BITMAP_BYTES {
            return Ok(());
        }
        let covered = self
            .sparse
            .iter()
            .filter(|object| (object.0 as usize / 64) < end_word)
            .count();
        let released = covered as u64 * 64;
        if requested as u64 > released {
            return Ok(());
        }
        // Pay for BOTH representations during migration. A refused optional
        // allocation is not a refused walk; no work/cancellation error may be
        // hidden by this fallback.
        match core.json_reserve_temporary(requested as u64) {
            Ok(()) => {}
            Err(InterpreterError::MemoryBudgetExceeded { .. }) => return Ok(()),
            Err(error) => return Err(error),
        }
        let mut dense = Vec::<u64>::new();
        if dense.try_reserve_exact(words).is_err() {
            drop(dense);
            core.json_release_temporary(requested as u64);
            return Ok(());
        }
        let retained = dense.capacity().checked_mul(std::mem::size_of::<u64>());
        let Some(retained) = retained.filter(|&bytes| {
            bytes <= MAX_REACHABLE_BITMAP_BYTES && bytes as u64 <= released
        }) else {
            drop(dense);
            core.json_release_temporary(requested as u64);
            return Ok(());
        };
        if retained > requested
            && let Err(error) = core.json_reserve_temporary((retained - requested) as u64)
        {
            drop(dense);
            core.json_release_temporary(requested as u64);
            return match error {
                InterpreterError::MemoryBudgetExceeded { .. } => Ok(()),
                error => Err(error),
            };
        }
        dense.resize(words, 0);
        self.sparse.retain(|object| {
            let word = object.0 as usize / 64;
            if let Some(index) = word.checked_sub(first_word)
                && let Some(bits) = dense.get_mut(index)
            {
                *bits |= 1_u64 << (object.0 % 64);
                false
            } else {
                true
            }
        });
        // retain has dropped the covered tree entries before their charge is
        // released. Spare Vec capacity is charged too, even if never indexed.
        self.dense = dense;
        self.first_word = first_word;
        self.bytes = self.bytes + retained as u64 - released;
        core.json_release_temporary(released);
        Ok(())
    }
}

impl InterpreterCore {
    /// Enumerate the original edge sets in their original order, without a
    /// child vector or a counting pass. This reads storage only, never Get,
    /// accessors, Proxy traps, or other guest code.
    fn visit_reachable_children(
        &self,
        object: ObjectId,
        edges: ReachableEdges,
        mut visit: impl FnMut(ObjectId) -> Result<(), InterpreterError>,
    ) -> Result<(), InterpreterError> {
        let Some(heap_object) = self.heap.get(object.0 as usize) else {
            return Ok(());
        };
        match edges {
            ReachableEdges::Data => {
                for value in heap_object.properties.values_unordered() {
                    if let Value::Object(child) = value {
                        visit(*child)?;
                    }
                }
            }
            ReachableEdges::Inspect => {
                for value in heap_object.properties.all_data_values() {
                    if let Value::Object(child) = value {
                        visit(*child)?;
                    }
                }
                for (_, property) in heap_object.properties.baseline_symbol_properties() {
                    if let BaselineSymbolProperty::Data(Value::Object(child)) = property {
                        visit(*child)?;
                    }
                }
                // Console inspection also prints object-valued Map keys.
                if let Some(storage_id) = self.collection_storage_id(object, "Map", "__entries")
                    && let Some(storage) = self.heap.get(storage_id.0 as usize)
                {
                    for repr in storage.properties.keys() {
                        if let Value::Object(child) = Self::collection_key_from_repr(repr) {
                            visit(child)?;
                        }
                    }
                }
                // Error name/message can be inherited. Ordinary object
                // prototypes and accessor functions remain outside this set.
                if self.inspect_is_error(object)
                    && let Some(prototype) = heap_object.prototype
                {
                    visit(prototype)?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn observe_reachable_value(
        &mut self,
        value: &Value,
        edges: ReachableEdges,
    ) -> Result<(), InterpreterError> {
        let Value::Object(root) = value else {
            return Ok(());
        };
        let mut pending = ReachablePending::default();
        let mut visited = ReachableVisited::default();
        let mut charged = 0_u64;
        let outcome = (|| {
            pending.push(self, *root, 0)?;
            self.json_reserve_temporary(pending.bytes)?;
            charged += pending.bytes;
            while let Some(object) = pending.objects.pop() {
                // Charge every popped edge, including duplicates, exactly as
                // before. No deduplication moves work past the budget gate.
                self.json_charge_work()?;
                if !visited.insert(self, object)? {
                    continue;
                }
                let label = self
                    .object_mutation_labels
                    .get(&object)
                    .into_iter()
                    .chain(self.binary_storage_label_ref(object))
                    .max();
                if let Some(label) = label {
                    self.check_temporary_memory_budget(Self::estimate_label_bytes(label))?;
                    let label = label.clone();
                    self.json_observe_label(label)?;
                }
                let committed = pending.bytes;
                self.visit_reachable_children(object, edges, |child| {
                    pending.push(self, child, committed)
                })?;
                let growth = pending.bytes - committed;
                if growth != 0 {
                    // The immutable enumeration checked this entire growth
                    // before allocation. Publish it before the next label or
                    // work operation; spare capacity is charged exactly once.
                    self.json_reserve_temporary(growth)?;
                    charged += growth;
                }
            }
            Ok(())
        })();
        drop(pending);
        let visited_bytes = visited.bytes;
        drop(visited);
        self.json_release_temporary(visited_bytes);
        self.json_release_temporary(charged);
        outcome
    }
}

#[cfg(test)]
mod tests;
