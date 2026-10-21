//! Sparse sort scans over the canonical numeric property inventory.
//!
//! Capture may skip holes only when every possible read is ordinary data and
//! the complete prototype chain has no indexed or exotic behavior. Deletion
//! takes a NEW inventory after comparisons and prefix setters have finished;
//! it never reuses the pre-callback key list. Descriptor checks and writes
//! stay in the existing property engine. Non-public metadata stays generic.

use super::*;

const MIN_SPARSE_LENGTH: u64 = 1 << 16;

impl InterpreterCore {
    /// A metered, charged list of the indices the current phase must visit.
    /// `None` means perform every spec step; it never means an empty array.
    pub(super) fn sparse_sort_indices(
        &mut self,
        array: ObjectId,
        from: u64,
        length: u64,
        capture: bool,
        retained: &mut u64,
    ) -> Result<Option<Vec<u32>>, InterpreterError> {
        if length < MIN_SPARSE_LENGTH || length > u64::from(u32::MAX)
            || self.proxy_record(array)?.is_some()
            || !self.public_sort_index_metadata(array)
        {
            return Ok(None);
        }
        let Some(object) = self.heap.get(array.0 as usize) else {
            return Ok(None);
        };
        if !object.is_array || object.typed_array.is_some() || object.primitive_value.is_some()
            || length <= (object.properties.len() as u64).saturating_mul(8)
        {
            return Ok(None);
        }
        // Presence and data reads cannot change between this proof and capture:
        // no guest code is invoked until the captured list is complete.
        if capture && !self.sparse_sort_plain_prototypes(array)? {
            return Ok(None);
        }
        let (count, inspected, readable) = numeric_inventory(
            self.heap.get(array.0 as usize).expect("receiver was just checked"),
            from, length, capture,
        );
        // The allocation-free inventory visits only already-retained entries,
        // not the guest length. Charge it, and precharge the second pass before
        // allocating/copying the snapshot. No getter/trap runs in either pass.
        for _ in 0..inspected {
            self.charge_native_hole_read()?;
        }
        if capture && !readable {
            return Ok(None);
        }
        let requested = buffer_bytes::<u32>(count);
        let next = retained.checked_add(requested).ok_or_else(|| {
            self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
        })?;
        self.json_reserve_temporary(requested)?;
        *retained = next;
        let mut indices = Vec::new();
        indices.try_reserve_exact(count).map_err(|_| {
            self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
        })?;
        let surplus = buffer_bytes::<u32>(indices.capacity()).saturating_sub(requested);
        if surplus != 0 {
            let next = retained.checked_add(surplus).ok_or_else(|| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            self.json_reserve_temporary(surplus)?;
            *retained = next;
        }
        for _ in 0..inspected {
            self.charge_native_hole_read()?;
        }
        let object = self.heap.get(array.0 as usize).expect("no guest call changed the receiver");
        indices.extend(numeric_indices(object, from, length));
        debug_assert_eq!(indices.len(), count);
        Ok(Some(indices))
    }

    /// Conservative IFC boundary: no skipped property can carry provenance.
    /// The existing callback scope still owns the receiver/register context,
    /// and actual reads still use generic_get with their ordinary label joins.
    fn public_sort_index_metadata(&self, id: ObjectId) -> bool {
        self.object_mutation_labels.get(&id).is_none_or(|label| label == &Label::Public)
            && self.heap.get(id.0 as usize)
                .is_some_and(|object| object.property_labels.exact_is_empty())
    }

    fn sparse_sort_plain_prototypes(&mut self, array: ObjectId) -> Result<bool, InterpreterError> {
        let Some(object) = self.heap.get(array.0 as usize) else {
            return Ok(false);
        };
        let mut current = self.observable_prototype_link(object, array);
        for _ in 0..MAX_PROTOTYPE_CHAIN_DEPTH {
            let Some(id) = current else {
                return Ok(true);
            };
            self.charge_native_hole_read()?;
            if self.proxy_record(id)?.is_some() || !self.public_sort_index_metadata(id) {
                return Ok(false);
            }
            let Some(object) = self.heap.get(id.0 as usize) else {
                return Ok(false);
            };
            if object.properties.has_index_keys() || object.typed_array.is_some()
                || object.primitive_value.is_some()
            {
                return Ok(false);
            }
            current = self.observable_prototype_link(object, id);
        }
        Ok(current.is_none())
    }
}

/// Canonical array indices are the first entries in deterministic storage
/// order. Stop before named keys rather than walking an unrelated dictionary.
/// In particular, "01" and "4294967295" must never enter a delete plan.
fn numeric_indices(object: &HeapObject, from: u64, length: u64) -> impl Iterator<Item = u32> + '_ {
    object.properties.well_formed_data_entries()
        .map_while(|(key, _)| canonical_array_index(key))
        .take_while(move |index| u64::from(*index) < length)
        .filter(move |index| u64::from(*index) >= from)
}

fn numeric_inventory(
    object: &HeapObject, from: u64, length: u64, capture: bool,
) -> (usize, usize, bool) {
    let mut count = 0;
    let mut inspected = 0;
    let mut readable = true;
    for (key, value) in object.properties.well_formed_data_entries() {
        inspected += 1;
        let Some(index) = canonical_array_index(key) else { break; };
        let index = u64::from(index);
        if index >= length { break; }
        if index >= from {
            count += 1;
            if capture && matches!(value, Value::Accessor { .. }) {
                // Do not scan the rest of a dictionary before an early getter
                // can throw; a capture plan is already disproved at this point.
                readable = false;
                break;
            }
        }
    }
    (count, inspected, readable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> InterpreterConfig {
        // Direct native tests still need allocation authority. Use the real
        // deterministic profile without changing its memory or work limits.
        let mut config = InterpreterConfig::quickjs_defaults();
        config
            .granted_capabilities
            .insert(RuntimeCapability::HeapAllocate);
        config
    }

    fn sparse_array(core: &mut InterpreterCore) -> ObjectId {
        let array = core.alloc_array_from_values(&[]).expect("array");
        for (key, value) in [("7", 3), ("40000", 2), ("4294967294", 1)] {
            core.set_object_property(array, key.into(), Value::Int(value)).unwrap();
        }
        array
    }

    #[test]
    fn plans_hold_present_indices_not_the_logical_array_length() {
        let mut core = InterpreterCore::new(test_config(), "sparse-sort-plan");
        let array = sparse_array(&mut core);
        core.set_object_property(array, "01".into(), Value::Int(90)).unwrap();
        core.set_object_property(array, "4294967295".into(), Value::Int(91)).unwrap();
        let before = core.estimated_memory_bytes();
        let mut retained = 0;
        let plan = core.sparse_sort_indices(array, 0, u64::from(u32::MAX), true, &mut retained)
            .unwrap().expect("plain sparse storage");
        assert_eq!(plan, [7, 40_000, u32::MAX - 1]);
        assert_eq!(retained, buffer_bytes::<u32>(plan.capacity()));
        assert_eq!(core.estimated_memory_bytes(), before + retained);
        drop(plan);
        core.json_release_temporary(retained);
        assert_eq!(core.estimated_memory_bytes(), before);
    }

    #[test]
    fn non_public_receiver_and_prototype_metadata_keep_the_full_path() {
        let mut core = InterpreterCore::new(test_config(), "sparse-sort-labels");
        let array = sparse_array(&mut core);
        core.join_direct_object_mutation_label(array, &Label::Secret)
            .unwrap();
        let mut retained = 0;
        assert!(
            core.sparse_sort_indices(array, 0, u64::from(u32::MAX), true, &mut retained)
                .unwrap()
                .is_none()
        );
        assert_eq!(retained, 0);
        let other = sparse_array(&mut core);
        // The direct allocator deliberately creates a null-prototype Array.
        // Install the ordinary prototype this test needs explicitly.
        let prototype = core.alloc_object_with_prototype(None).unwrap();
        core.mutate_heap(|heap| heap[other.0 as usize].prototype = Some(prototype));
        let public_plan = core
            .sparse_sort_indices(other, 0, u64::from(u32::MAX), true, &mut retained)
            .unwrap()
            .expect("a Public ordinary prototype admits the sparse plan");
        assert_eq!(public_plan, [7, 40_000, u32::MAX - 1]);
        drop(public_plan);
        core.json_release_temporary(retained);
        retained = 0;
        core.join_direct_object_mutation_label(prototype, &Label::Secret)
            .unwrap();
        assert!(
            core.sparse_sort_indices(other, 0, u64::from(u32::MAX), true, &mut retained)
                .unwrap()
                .is_none()
        );
        assert_eq!(retained, 0);
    }

    #[test]
    fn delete_inventory_is_fresh_and_excludes_prefix_and_non_index_names() {
        let mut core = InterpreterCore::new(test_config(), "sparse-sort-delete");
        let array = sparse_array(&mut core);
        let mut retained = 0;
        let before = core.sparse_sort_indices(array, 0, 100_000, true, &mut retained)
            .unwrap().unwrap();
        assert_eq!(before, [7, 40_000]);
        let bytes = buffer_bytes::<u32>(before.capacity());
        drop(before); core.json_release_temporary(bytes); retained -= bytes;
        core.set_object_property(array, "90000".into(), Value::Int(8)).unwrap();
        core.set_object_property(array, "0".into(), Value::Int(1)).unwrap();
        let after = core.sparse_sort_indices(array, 2, 100_000, false, &mut retained)
            .unwrap().unwrap();
        assert_eq!(after, [7, 40_000, 90_000]);
        drop(after); core.json_release_temporary(retained);
    }

    #[test]
    fn capture_growth_and_failed_reservations_release_their_exact_charge() {
        let mut core = InterpreterCore::new(test_config(), "sort-capture-growth");
        let before = core.estimated_memory_bytes();
        let mut values = Vec::<u32>::new();
        let mut retained = 0;
        for value in 0..257 {
            core.reserve_sort_slot(&mut values, &mut retained).unwrap();
            values.push(value);
            assert_eq!(retained, buffer_bytes::<u32>(values.capacity()));
            assert_eq!(core.estimated_memory_bytes(), before + retained);
        }
        while values.len() < values.capacity() { values.push(0); }
        let capacity = values.capacity();
        let charged = retained;
        core.config.max_total_memory_bytes = core.estimated_memory_bytes();
        assert!(core.reserve_sort_slot(&mut values, &mut retained).is_err());
        assert_eq!(values.capacity(), capacity);
        assert_eq!(retained, charged);
        drop(values); core.json_release_temporary(retained);
        assert_eq!(core.estimated_memory_bytes(), before);
    }
    #[test]
    fn an_early_accessor_abandons_the_capture_inventory_immediately() {
        let mut object = HeapObject::new();
        object.properties.insert("0".into(), Value::Accessor { get: None, set: None });
        object.properties.insert("90000".into(), Value::Int(1));
        assert_eq!(numeric_inventory(&object, 0, 100_000, true), (1, 1, false));
        // Deleting an accessor never invokes it; both keys belong to that plan.
        assert_eq!(numeric_inventory(&object, 0, 100_000, false), (2, 2, true));
    }
}
