//! Conditional reachability for WeakMap entries and URL side-table links.
//!
//! Eligibility depends on object marks, but a value may first enqueue a
//! closure, promise, carrier, iterator or generator. Always drain every
//! work queue before deciding whether the object-mark fixpoint was reached.
//! The fast path indexes unresolved owner/key dependencies, so a reverse
//! chain does not rescan all entries once for every newly reachable key.

use super::*;

// Optional, collection-local scratch, never a guest-visible cache. Under
// pressure or allocation failure use the allocation-free fixpoint below.
const MAX_EPHEMERON_SCRATCH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy)]
enum EdgeTarget<'a> {
    Value(&'a Value),
    Object(ObjectId),
}

struct ConditionalEdge<'a> {
    owner: u32,
    key: Option<u32>,
    target: EdgeTarget<'a>,
    fired: bool,
}

/// Sorted dependencies avoid a hash table and one allocation per key. An
/// edge is examined once initially and at most once per unresolved gate.
/// Targets borrow interpreter state; building the index clones no Values.
struct ConditionalIndex<'a> {
    edges: Vec<ConditionalEdge<'a>>,
    watchers: Vec<(u32, usize)>,
    #[cfg(test)]
    checks: usize,
}

impl<'a> ConditionalIndex<'a> {
    fn scratch_bytes(edges: usize, watchers: usize) -> Option<usize> {
        edges
            .checked_mul(std::mem::size_of::<ConditionalEdge<'a>>())?
            .checked_add(watchers.checked_mul(std::mem::size_of::<(u32, usize)>())?)
    }

    fn try_new(count: usize, limit: usize) -> Option<Self> {
        let watchers = count.checked_mul(2)?;
        if Self::scratch_bytes(count, watchers)? > limit {
            return None;
        }
        let mut index = Self {
            edges: Vec::new(),
            watchers: Vec::new(),
            #[cfg(test)]
            checks: 0,
        };
        index.edges.try_reserve_exact(count).ok()?;
        index.watchers.try_reserve_exact(watchers).ok()?;
        // Check the actual capacities too; no marks have changed yet.
        if Self::scratch_bytes(index.edges.capacity(), index.watchers.capacity())? > limit {
            return None;
        }
        Some(index)
    }

    fn fire_if_ready(&mut self, index: usize, marker: &mut GcMarker) -> bool {
        #[cfg(test)]
        {
            self.checks += 1;
        }
        let edge = &mut self.edges[index];
        if edge.fired {
            return true;
        }
        if !marker.is_marked(edge.owner) || edge.key.is_some_and(|key| !marker.is_marked(key)) {
            return false;
        }
        edge.fired = true;
        match edge.target {
            EdgeTarget::Value(value) => marker.value(value),
            EdgeTarget::Object(id) => marker.object(id),
        }
        true
    }

    fn add(
        &mut self,
        marker: &mut GcMarker,
        owner: u32,
        key: Option<u32>,
        target: EdgeTarget<'a>,
    ) {
        let index = self.edges.len();
        self.edges.push(ConditionalEdge {
            owner,
            key,
            target,
            fired: false,
        });
        if self.fire_if_ready(index, marker) {
            return;
        }
        if !marker.is_marked(owner) {
            self.watchers.push((owner, index));
        }
        if let Some(key) = key
            && key != owner
            && !marker.is_marked(key)
        {
            self.watchers.push((key, index));
        }
    }

    fn observe(&mut self, marker: &mut GcMarker, object: u32) {
        let start = self.watchers.partition_point(|(id, _)| *id < object);
        let end = self.watchers.partition_point(|(id, _)| *id <= object);
        for position in start..end {
            self.fire_if_ready(self.watchers[position].1, marker);
        }
    }
}

impl InterpreterCore {
    pub(super) fn gc_mark_ephemerons(&mut self, marker: &mut GcMarker) {
        let headroom = self
            .config
            .max_total_memory_bytes
            .saturating_sub(self.estimated_memory_bytes);
        let limit = usize::try_from(headroom)
            .unwrap_or(usize::MAX)
            .min(MAX_EPHEMERON_SCRATCH_BYTES);
        self.gc_mark_ephemerons_with_limit(marker, limit);
        self.gc_purge_weakmap_storage(marker);
    }

    /// The reachability fixpoint is complete, so dead keys and dead owners
    /// can no longer be resurrected by another conditional edge. Dropping
    /// them here releases inline strings as well as obsolete object handles.
    fn gc_purge_weakmap_storage(&mut self, marker: &GcMarker) {
        let has_dead_entries = self.weakmap_storage.iter().any(|(owner, storage)| {
            !marker.is_marked(owner.0)
                || storage.entries.keys().any(|key| !marker.is_marked(*key))
        });
        if !has_dead_entries {
            return;
        }
        // The heap sweep also materializes outstanding execution seeds.
        // Do that before side-table mutation, not after it.
        self.before_seed_surface_write();
        let before = self.weakmap_storage_memory_bytes();
        self.weakmap_storage.retain(|owner, storage| {
            if !marker.is_marked(owner.0) {
                return false;
            }
            storage.entries.retain(|key, _| marker.is_marked(*key));
            storage
                .weak_key_objects
                .retain(|key| marker.is_marked(*key));
            // This runtime's symbols are immortal. Keep their entries while
            // the map lives, even when no object-keyed entries survive.
            true
        });
        // Reuse the canonical estimator, including the owning-map charge,
        // rather than introduce a second formula for entry/value sizes.
        let released = before.saturating_sub(self.weakmap_storage_memory_bytes());
        self.estimated_memory_bytes = self.estimated_memory_bytes.saturating_sub(released);
        self.gc.stats.reclaimed_bytes = self.gc.stats.reclaimed_bytes.saturating_add(released);
    }

    fn gc_mark_ephemerons_with_limit(&self, marker: &mut GcMarker, limit: usize) {
        match self.gc_ephemeron_index(marker, limit) {
            Some(mut index) => {
                self.gc_drain_with_objects(marker, |marker, object| index.observe(marker, object));
            }
            None => self.gc_mark_ephemerons_scanning(marker),
        }
    }

    fn gc_ephemeron_index(
        &self,
        marker: &mut GcMarker,
        limit: usize,
    ) -> Option<ConditionalIndex<'_>> {
        let mut count = self
            .url_objects
            .len()
            .checked_add(self.url_search_params.len())?;
        for storage in self.weakmap_storage.values() {
            count = count
                .checked_add(storage.entries.len())?
                .checked_add(storage.symbol_entries.len())?;
        }
        // All fallible reservations precede marking. add() never grows
        // beyond these capacities, and sort_unstable allocates no scratch.
        let mut index = ConditionalIndex::try_new(count, limit)?;
        for (owner, storage) in &self.weakmap_storage {
            for (key, value) in &storage.entries {
                index.add(marker, owner.0, Some(*key), EdgeTarget::Value(value));
            }
            for value in storage.symbol_entries.values() {
                index.add(marker, owner.0, None, EdgeTarget::Value(value));
            }
        }
        for (url, state) in &self.url_objects {
            index.add(marker, url.0, None, EdgeTarget::Object(state.search_params));
        }
        for (params, state) in &self.url_search_params {
            if let Some(owner) = state.owner_url {
                index.add(marker, params.0, None, EdgeTarget::Object(owner));
            }
        }
        index.watchers.sort_unstable();
        Some(index)
    }

    /// Allocation-free fallback and independently structured test oracle.
    fn gc_mark_ephemerons_scanning(&self, marker: &mut GcMarker) {
        loop {
            for (map_id, storage) in &self.weakmap_storage {
                if !marker.is_marked(map_id.0) {
                    continue;
                }
                for (key, value) in &storage.entries {
                    if marker.is_marked(*key) {
                        marker.value(value);
                    }
                }
                // Symbols are not reclaimed by this runtime. Their values
                // are strong only while the owning WeakMap is reachable.
                for value in storage.symbol_entries.values() {
                    marker.value(value);
                }
            }
            for (url, state) in &self.url_objects {
                if marker.is_marked(url.0) {
                    marker.object(state.search_params);
                }
            }
            for (params, state) in &self.url_search_params {
                if marker.is_marked(params.0)
                    && let Some(owner) = state.owner_url
                {
                    marker.object(owner);
                }
            }

            // A closure or settled promise can reveal the next key without
            // having added anything to the object queue above. The drain
            // visits all value kinds and reports the objects it discovers.
            let mut discovered_object = false;
            self.gc_drain_with_objects(marker, |_, _| discovered_object = true);
            if !discovered_object {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectHandle;
    use crate::promise_model::MicrotaskQueue;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [RuntimeCapability::HeapAllocate].into_iter().collect();
        InterpreterCore::new(config, "gc-ephemerons")
    }

    fn object(core: &mut InterpreterCore) -> ObjectId {
        core.alloc_object_with_prototype(None).expect("allocate")
    }

    fn store(core: &mut InterpreterCore, map: ObjectId, key: ObjectId, value: Value) {
        core.weakmap_storage.entry(map).or_default().set(key.0, value);
    }

    fn captured(core: &mut InterpreterCore, payload: ObjectId) -> u32 {
        let frame = ScopeFrame::from_bindings(BTreeMap::from([(
            "payload".to_string(),
            ScopeBinding::with_state(BindingKind::Const, Value::Object(payload), true),
        )]));
        let id = core.closures.len() as u32;
        core.closures.push(ClosureValue {
            function_index: 0,
            captured_env: vec![frame],
        });
        id
    }

    fn roots(core: &InterpreterCore, roots: &[ObjectId]) -> GcMarker {
        let mut marker = core.gc_new_marker();
        for root in roots {
            marker.object(*root);
        }
        core.gc_drain(&mut marker);
        assert!(marker.stack.is_empty());
        marker
    }

    #[test]
    fn weakmap_closure_values_trace_captured_objects_for_all_function_kinds() {
        for kind in 0..4 {
            let mut core = core();
            let map = object(&mut core);
            let key = object(&mut core);
            let payload = object(&mut core);
            let dead = object(&mut core);
            let closure = captured(&mut core, payload);
            let value = match kind {
                0 => Value::Closure(closure),
                1 => Value::GeneratorFunction(closure),
                2 => Value::AsyncFunction(closure),
                _ => Value::AsyncGeneratorFunction(closure),
            };
            store(&mut core, map, key, value);
            let mut marker = roots(&core, &[map, key]);
            assert!(!marker.is_marked(payload.0));
            core.gc_mark_ephemerons(&mut marker);
            assert!(marker.is_marked(payload.0), "function kind {kind}");
            assert!(marker.closure_stack.is_empty());
            assert!(!marker.is_marked(dead.0));
        }
    }

    #[test]
    fn weakmap_settled_promises_trace_both_objects_and_value_carriers() {
        for carrier in [false, true] {
            let mut core = core();
            let map = object(&mut core);
            let key = object(&mut core);
            let payload = object(&mut core);
            let promise = core.promise_store.create();
            let value = if carrier {
                core.promise_value_carriers
                    .insert(PROMISE_VALUE_CARRIER_BASE, Value::Object(payload));
                JsValue::Function(PROMISE_VALUE_CARRIER_BASE)
            } else {
                JsValue::Object(ObjectHandle(payload.0))
            };
            core.promise_store
                .fulfill(promise, value, Label::Public, &mut MicrotaskQueue::new())
                .expect("settle");
            store(&mut core, map, key, Value::Promise(promise.0));
            let mut marker = roots(&core, &[map, key]);
            core.gc_mark_ephemerons(&mut marker);
            assert!(marker.is_marked(payload.0), "carrier={carrier}");
            assert!(marker.promise_stack.is_empty());
            assert!(marker.carrier_stack.is_empty());
        }
    }

    #[test]
    fn weakmap_iterators_trace_their_retained_values() {
        let mut core = core();
        let map = object(&mut core);
        let key = object(&mut core);
        let payload = object(&mut core);
        let iterator = core.iterators.len() as u32;
        core.iterators
            .push(RuntimeIteratorState::ForOf(RuntimeForOfState {
                values: vec![Value::Object(payload)],
                next_index: 0,
                array: None,
                typed_array: None,
                collection: None,
                iterator_receiver: None,
                next_method: None,
                timers_interval: None,
                done: false,
                closed: false,
                return_called: false,
                trace_index: 0,
            }));
        store(&mut core, map, key, Value::Iterator(iterator));
        let mut marker = roots(&core, &[map, key]);
        core.gc_mark_ephemerons(&mut marker);
        assert!(marker.is_marked(payload.0));
        assert!(marker.iterator_stack.is_empty());
    }

    #[test]
    fn closure_discovered_keys_unlock_other_maps_and_symbol_values() {
        let mut core = core();
        let later_map = object(&mut core);
        let first_map = object(&mut core);
        let later_key = object(&mut core);
        let payload = object(&mut core);
        let closure = captured(&mut core, later_key);
        store(&mut core, later_map, later_key, Value::Object(payload));
        core.weakmap_storage
            .entry(first_map)
            .or_default()
            .set_symbol(7, Value::Closure(closure));
        let mut marker = roots(&core, &[first_map, later_map]);
        core.gc_mark_ephemerons(&mut marker);
        assert!(marker.is_marked(later_key.0));
        assert!(marker.is_marked(payload.0));
    }

    #[test]
    fn neither_unreachable_maps_nor_dead_key_cycles_keep_values_alive() {
        let mut core = core();
        let map = object(&mut core);
        let unreachable_map = object(&mut core);
        let root_key = object(&mut core);
        let a = object(&mut core);
        let b = object(&mut core);
        let dead = object(&mut core);
        store(&mut core, map, a, Value::Object(b));
        store(&mut core, map, b, Value::Object(a));
        store(&mut core, unreachable_map, root_key, Value::Object(dead));
        core.weakmap_storage
            .get_mut(&unreachable_map)
            .unwrap()
            .set_symbol(7, Value::Object(dead));
        let mut marker = roots(&core, &[map, root_key]);
        core.gc_mark_ephemerons(&mut marker);
        for id in [unreachable_map, a, b, dead] {
            assert!(
                !marker.is_marked(id.0),
                "unreachable object {} survived",
                id.0
            );
        }
    }

    fn assert_same_marks(core: &InterpreterCore, left: &GcMarker, right: &GcMarker) {
        for id in 0..core.heap.len() {
            assert_eq!(
                left.objects.is_marked(id),
                right.objects.is_marked(id),
                "object {id}"
            );
        }
        for id in 0..core.closures.len() {
            assert_eq!(
                left.closures.is_marked(id),
                right.closures.is_marked(id),
                "closure {id}"
            );
        }
    }

    #[test]
    fn reverse_chains_examine_each_dependency_a_bounded_number_of_times() {
        for length in [32, 512, 4096] {
            let mut core = core();
            let map = object(&mut core);
            let keys: Vec<_> = (0..=length).map(|_| object(&mut core)).collect();
            for index in 1..=length {
                store(&mut core, map, keys[index], Value::Object(keys[index - 1]));
            }
            let mut marker = roots(&core, &[map, keys[length]]);
            let mut index = core
                .gc_ephemeron_index(&mut marker, MAX_EPHEMERON_SCRATCH_BYTES)
                .expect("bounded fixture fits");
            core.gc_drain_with_objects(&mut marker, |marker, id| index.observe(marker, id));
            assert!(keys.iter().all(|key| marker.is_marked(key.0)));
            assert_eq!(index.edges.len(), length);
            assert!(
                index.checks <= 2 * length,
                "{} checks for {length} edges",
                index.checks
            );
            assert!(index.edges.iter().all(|edge| edge.fired));
        }
    }

    #[test]
    fn scratch_limits_fall_back_before_mutating_marks() {
        let mut core = core();
        let map = object(&mut core);
        let key = object(&mut core);
        let payload = object(&mut core);
        let closure = captured(&mut core, payload);
        store(&mut core, map, key, Value::Closure(closure));
        let mut rejected = roots(&core, &[map, key]);
        assert!(core.gc_ephemeron_index(&mut rejected, 0).is_none());
        assert!(!rejected.closures.is_marked(closure as usize));
        assert!(!rejected.is_marked(payload.0));
        assert!(ConditionalIndex::try_new(usize::MAX, usize::MAX).is_none());
        assert!(ConditionalIndex::try_new(1, 0).is_none());
        let mut indexed = roots(&core, &[map, key]);
        core.gc_mark_ephemerons_with_limit(&mut indexed, MAX_EPHEMERON_SCRATCH_BYTES);
        core.gc_mark_ephemerons_with_limit(&mut rejected, 0);
        assert_same_marks(&core, &indexed, &rejected);
        assert!(rejected.is_marked(payload.0));
        assert!(rejected.closure_stack.is_empty());
    }

    #[test]
    fn indexing_matches_full_rescans_on_generated_cyclic_graphs() {
        let mut state = 0xd3b4_9287_56ac_01efu64;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 32) as usize
        };
        for _ in 0..128 {
            let mut core = core();
            let nodes: Vec<_> = (0..48).map(|_| object(&mut core)).collect();
            for _ in 0..192 {
                let owner = nodes[next() % nodes.len()];
                let key = nodes[next() % nodes.len()];
                let payload = nodes[next() % nodes.len()];
                let value = if next().is_multiple_of(4) {
                    Value::Closure(captured(&mut core, payload))
                } else {
                    Value::Object(payload)
                };
                if next().is_multiple_of(8) {
                    core.weakmap_storage
                        .entry(owner)
                        .or_default()
                        .set_symbol((next() % 4) as u32, value);
                } else {
                    store(&mut core, owner, key, value);
                }
            }
            let mut expected = roots(&core, &nodes[..8]);
            core.gc_mark_ephemerons_scanning(&mut expected);
            let mut actual = roots(&core, &nodes[..8]);
            let mut index = core
                .gc_ephemeron_index(&mut actual, MAX_EPHEMERON_SCRATCH_BYTES)
                .expect("bounded fixture fits");
            core.gc_drain_with_objects(&mut actual, |marker, id| index.observe(marker, id));
            assert_same_marks(&core, &actual, &expected);
            assert!(index.checks <= 3 * index.edges.len());
            assert!(actual.stack.is_empty() && actual.closure_stack.is_empty());
        }
    }

    #[test]
    fn notifications_require_both_owner_and_key_and_deduplicate_self_keys() {
        for key_first in [false, true] {
            let mut marker = GcMarker::new(8, 0, 0, 0, 0, 0, 0);
            let value = Value::Object(ObjectId(3));
            let mut index =
                ConditionalIndex::try_new(2, MAX_EPHEMERON_SCRATCH_BYTES).unwrap();
            index.add(&mut marker, 1, Some(2), EdgeTarget::Value(&value));
            index.add(&mut marker, 4, Some(4), EdgeTarget::Object(ObjectId(5)));
            index.watchers.sort_unstable();
            assert_eq!(index.watchers.len(), 3, "self key has one watcher");
            let [first, second] = if key_first { [2, 1] } else { [1, 2] };
            marker.object(ObjectId(first));
            index.observe(&mut marker, first);
            assert!(!marker.is_marked(3));
            marker.object(ObjectId(second));
            index.observe(&mut marker, second);
            assert!(marker.is_marked(3));
            marker.object(ObjectId(4));
            index.observe(&mut marker, 4);
            assert!(marker.is_marked(5));
            assert!(index.edges.iter().all(|edge| edge.fired));
        }
    }

    /// Account synthetic fixture changes through the same component used
    /// by production WeakMap insertion. Heap allocations account themselves.
    fn accounted_entries(core: &mut InterpreterCore, change: impl FnOnce(&mut InterpreterCore)) {
        let before = core.weakmap_storage_memory_bytes();
        change(core);
        let after = core.weakmap_storage_memory_bytes();
        core.apply_memory_component_delta(before, after)
            .expect("fixture fits");
    }

    #[test]
    fn collection_purges_dead_weak_entries_and_releases_their_exact_charge() {
        let mut core = core();
        let map = object(&mut core);
        let dead_map = object(&mut core);
        let key = object(&mut core);
        let dead_key = object(&mut core);
        let payload = object(&mut core);
        let symbol_payload = object(&mut core);
        let unreachable = object(&mut core);
        accounted_entries(&mut core, |core| {
            store(core, map, key, Value::Object(payload));
            store(core, map, dead_key, Value::str("dead".repeat(4096)));
            store(core, dead_map, key, Value::Object(unreachable));
            core.weakmap_storage
                .get_mut(&map)
                .unwrap()
                .set_symbol(7, Value::Object(symbol_payload));
            core.weakmap_storage
                .get_mut(&dead_map)
                .unwrap()
                .set_symbol(8, Value::str("orphan".repeat(4096)));
        });
        core.seed_register(0, Value::Object(map)).expect("seed root");
        core.seed_register(1, Value::Object(key)).expect("seed root");
        let before = core.estimated_memory_bytes;
        let weak_before = core.weakmap_storage_memory_bytes();
        core.collect_garbage().expect("collect");
        let weak_after = core.weakmap_storage_memory_bytes();
        let storage = &core.weakmap_storage[&map];
        assert_eq!(storage.get(key.0), Some(&Value::Object(payload)));
        assert_eq!(storage.get_symbol(7), Some(&Value::Object(symbol_payload)));
        assert!(!storage.has(dead_key.0));
        assert_eq!(storage.get_weak_key_objects(), &BTreeSet::from([key.0]));
        assert!(!core.weakmap_storage.contains_key(&dead_map));
        for id in [map, key, payload, symbol_payload] {
            assert!(core.heap.get(id.0 as usize).is_some());
        }
        for id in [dead_map, dead_key, unreachable] {
            assert!(core.heap.is_reclaimed(id.0 as usize));
        }
        assert!(weak_after < weak_before);
        assert!(before - core.estimated_memory_bytes >= weak_before - weak_after);
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_base_estimated_memory_bytes()
        );
        assert_eq!(
            core.gc_stats().reclaimed_bytes,
            before - core.estimated_memory_bytes
        );
        let retained = core.estimated_memory_bytes;
        let reclaimed = core.gc_stats().reclaimed_bytes;
        core.collect_garbage().expect("collect again");
        assert_eq!(core.estimated_memory_bytes, retained);
        assert_eq!(core.gc_stats().reclaimed_bytes, reclaimed);
    }

    #[test]
    fn weakmap_churn_stays_bounded_across_repeated_collections() {
        let mut core = core();
        core.config.max_total_memory_bytes = 2 * 1024 * 1024;
        let map = object(&mut core);
        let key = object(&mut core);
        accounted_entries(&mut core, |core| store(core, map, key, Value::Int(42)));
        core.seed_register(0, Value::Object(map)).expect("seed root");
        core.seed_register(1, Value::Object(key)).expect("seed root");
        let retained_table_bytes = core.weakmap_storage_memory_bytes();
        // 32 MiB of historical payload under a 2 MiB budget. No register
        // roots the temporary keys; only the persistent entry may survive.
        for _ in 0..128 {
            accounted_entries(&mut core, |core| {
                for _ in 0..64 {
                    let temporary = object(core);
                    store(core, map, temporary, Value::str("x".repeat(4096)));
                }
            });
            core.collect_garbage().expect("collect churn");
            assert_eq!(core.weakmap_storage_memory_bytes(), retained_table_bytes);
            assert_eq!(core.weakmap_storage[&map].entries.len(), 1);
            assert_eq!(core.weakmap_storage[&map].weak_key_objects.len(), 1);
            assert_eq!(
                core.estimated_memory_bytes,
                core.recompute_base_estimated_memory_bytes()
            );
        }
        assert!(core.gc_stats().reclaimed_bytes >= 32 * 1024 * 1024);
    }

    #[test]
    fn pruning_waits_for_the_complete_cross_map_fixpoint() {
        let mut core = core();
        let first = object(&mut core);
        let later = object(&mut core);
        let root_key = object(&mut core);
        let later_key = object(&mut core);
        let payload = object(&mut core);
        accounted_entries(&mut core, |core| {
            store(core, later, later_key, Value::Object(payload));
            store(core, first, root_key, Value::Object(later_key));
            // The owner is initially unmarked too; a symbol value makes it
            // live only after first becomes reachable.
            core.weakmap_storage
                .get_mut(&first)
                .unwrap()
                .set_symbol(9, Value::Object(later));
        });
        core.seed_register(0, Value::Object(first))
            .expect("seed root");
        core.seed_register(1, Value::Object(root_key))
            .expect("seed root");
        core.collect_garbage().expect("collect");
        assert_eq!(
            core.weakmap_storage[&later].get(later_key.0),
            Some(&Value::Object(payload))
        );
        assert!(core.heap.get(payload.0 as usize).is_some());
        assert_eq!(
            core.estimated_memory_bytes,
            core.recompute_base_estimated_memory_bytes()
        );
    }

    #[test]
    fn javascript_weakmap_churn_completes_under_a_bounded_memory_budget() {
        use crate::ast::ParseGoal;
        use crate::ir_contract::Ir0Module;
        use crate::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
        use crate::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

        let source = "var cache = new WeakMap(); var persistent = {}; \
            cache.set(persistent, 'kept'); \
            for (let i = 0; i < 1024; i++) { \
                const key = {}; cache.set(key, 'x'.repeat(8192)); \
            } cache.get(persistent)";
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "weakmap-churn.js".into(),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .expect("parse");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "weakmap-churn.js"),
            &LoweringContext::new("gc-trace", "gc-decision", "gc-policy"),
        )
        .expect("lower")
        .ir3;
        let mut config = InterpreterConfig::quickjs_defaults();
        config.max_total_memory_bytes = 2 * 1024 * 1024;
        config.instruction_budget = 1_000_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "weakmap-churn");
        core.set_gc_stress_interval(Some(8));
        let result = core.execute(&module).expect("bounded churn completes");
        assert_eq!(result.value, Value::str("kept"));
        assert!(core.gc_stats().collections > 4);
        assert!(core.gc_stats().reclaimed_bytes > 2 * 1024 * 1024);
    }
}
