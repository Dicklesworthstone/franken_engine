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
        let mut visited = BTreeSet::new();
        let mut charged = 0_u64;
        let outcome = (|| {
            pending.push(self, *root, 0)?;
            self.json_reserve_temporary(pending.bytes)?;
            charged += pending.bytes;
            while let Some(object) = pending.objects.pop() {
                // Charge every popped edge, including duplicates, exactly as
                // before. No deduplication moves work past the budget gate.
                self.json_charge_work()?;
                if visited.contains(&object) {
                    continue;
                }
                self.json_reserve_temporary(64)?;
                charged += 64;
                visited.insert(object);
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
        drop(visited);
        self.json_release_temporary(charged);
        outcome
    }
}

#[cfg(test)]
mod tests;
