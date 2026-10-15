//! Conditional reachability for WeakMap entries and URL side-table links.
//!
//! Eligibility depends on object marks, but a value may first enqueue a
//! closure, promise, carrier, iterator or generator. Always drain every
//! work queue before deciding whether the object-mark fixpoint was reached.

use super::*;

impl InterpreterCore {
    pub(super) fn gc_mark_ephemerons(&self, marker: &mut GcMarker) {
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
}
