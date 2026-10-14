//! ArrayBuffer transfer lists for structuredClone. The list is converted before
//! serialization, while transferring its bytes happens after all graph getters.
//! No guest callback runs in the final detach phase.

use super::*;

impl InterpreterCore {
    pub(super) fn structured_clone_with_transfer(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
        options: Value,
        state: &mut CloneState,
    ) -> Result<Value, InterpreterError> {
        let sources = self.structured_clone_transfer_list(module, options, state)?;
        // Validate the complete list before allocating placeholders. A bad or
        // duplicate entry must not evaluate even the first source getter.
        for &source in &sources {
            self.json_charge_work()?;
            state.label = state.label.join(&self.structured_clone_object_label(source));
            match self.plain_buffer_receiver(&Value::Object(source), false, "structuredClone") {
                Ok(_) => {}
                Err(InterpreterError::TypeError { .. }) => {
                    return Err(self.throw_data_clone_error("Transfer list entry", &state.label));
                }
                Err(error) => return Err(error),
            }
            if self.buffer_backing(source)?.detached {
                return Err(self.throw_data_clone_error("Detached ArrayBuffer", &state.label));
            }
            state.reserve(self, CLONE_MEMO_ENTRY_BYTES)?;
            if !state.transfer_sources.insert(source) {
                return Err(self.throw_data_clone_error("Duplicate ArrayBuffer", &state.label));
            }
        }

        // Reserve identities, not a second copy of every transferred payload.
        // CloneTask::View sizes a shell before constructing a cloned view, so
        // ordinary view bounds and allocation admission remain in force.
        // Buffers with no cloned views stay empty until ownership moves after
        // all graph getters, including entries the graph never reaches.
        for &source in &sources {
            self.json_charge_work()?;
            let backing = self.buffer_backing(source)?;
            let maximum = backing.max_byte_length;
            Self::structured_clone_transfer_length(backing.bytes.len())?;
            state.reserve(self, CLONE_MEMO_ENTRY_BYTES)?;
            let target = self.alloc_array_buffer_object(0)?;
            self.mutate_heap(|heap| {
                if let Some(backing) = heap
                    .get_mut(target.0 as usize)
                    .and_then(|object| object.array_buffer.as_deref_mut())
                {
                    backing.max_byte_length = maximum;
                }
            });
            state.memory.insert(source, target);
        }
        let clone = self.structured_clone_walk(module, value, state)?;

        // A getter may have detached an entry. Validate all entries again
        // before any detach owned by this invocation. Guest side effects are
        // not rolled back, but an unrelated valid entry remains attached.
        for &source in &sources {
            self.json_charge_work()?;
            state.label = state.label.join(&self.structured_clone_object_label(source));
            if self.buffer_backing(source)?.detached {
                return Err(self.throw_data_clone_error("Detached ArrayBuffer", &state.label));
            }
        }
        for &source in &sources {
            let target = state.memory[&source];
            self.structured_clone_prepare_transfer(source, target, state)?;
        }
        // Finalize the result's IFC label before the irreversible detach.
        // This includes transfer-list getters and current backing-store labels,
        // including buffers that the graph itself never reached.
        state.label = state.label.join(
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        );
        self.replace_pending_hostcall_result_label(Some(state.label.clone()))?;
        // Existing detachment refreshes fixed-buffer views by walking the heap.
        // Charge that work in advance, so native cancellation/exhaustion cannot
        // interrupt this list between its first and last detach.
        if !sources.is_empty() {
            let work = (self.heap_size() as u64)
                .saturating_mul(sources.len() as u64)
                .saturating_add(sources.len() as u64);
            for _ in 0..work {
                self.json_charge_work()?;
            }
        }
        for source in sources {
            self.structured_clone_commit_transfer(source, state.memory[&source])?;
        }
        Ok(clone)
    }

    /// Web IDL dictionary/sequence conversion, using the engine's iterator
    /// protocol, not Array.from(arrayLike). Each getter/method is read once.
    /// Conversion finishes before checking which objects are transferable.
    fn structured_clone_transfer_list(
        &mut self,
        module: Option<&Ir3Module>,
        options: Value,
        state: &mut CloneState,
    ) -> Result<Vec<ObjectId>, InterpreterError> {
        if matches!(options, Value::Undefined | Value::Null) {
            return Ok(Vec::new());
        }
        if !options.is_object_like() {
            return Err(self.clone_transfer_type_error("Options cannot be converted to a dictionary"));
        }
        let key = RuntimePropertyKey::String(JsString::from("transfer"));
        let source = match module {
            Some(module) => self.get_v(module, &options, &key)?,
            None => {
                let Some(backing) = self.iterator_carrier_backing_id(&options, "clone options")?
                else {
                    return Err(self.clone_transfer_type_error("Options have no object backing"));
                };
                self.proxy_aware_get_runtime_property(None, backing, &key, options, 0)?
            }
        };
        self.clone_transfer_observe(state);
        if matches!(source, Value::Undefined) {
            return Ok(Vec::new());
        }
        if !source.is_object_like() {
            return Err(self.clone_transfer_type_error("transfer cannot be converted to a sequence"));
        }
        let backing = self.iterator_carrier_backing_id(&source, "clone transfer list")?;
        let method = match backing {
            Some(backing) => self.lookup_symbol_iterator_method(module, backing, source.clone())?,
            None => None,
        };
        self.clone_transfer_observe(state);
        let iterator = if let Some(method) = method {
            let module = module.ok_or_else(|| {
                self.clone_transfer_type_error("Transfer iterator requires a module context")
            })?;
            let (iterator, label) = self.invoke_inline_method_call_with_argument_label(
                Some(module),
                method,
                source.clone(),
                Vec::new(),
                Some(state.label.clone()),
            )?;
            state.label = state.label.join(&label);
            let init = self.prepare_custom_iterator_result(module, iterator)?;
            self.init_iterator_from_state(source.clone(), init, IterationKind::ForOf)?
        } else {
            // Native iterators/collections may use the interpreter's for-of
            // fallback. An explicitly nullish @@iterator is NOT that fallback.
            let native = match &source {
                Value::Iterator(_) | Value::Generator(_) => true,
                Value::Object(id) => {
                    let explicit = self.array_from_has_explicit_iterator(*id)?;
                    !explicit
                        && (self.heap.get(id.0 as usize).is_some_and(|object| {
                            object.is_array || object.typed_array.is_some()
                        }) || self.collection_storage_id(*id, "Set", "__values").is_some()
                            || self.collection_storage_id(*id, "Map", "__entries").is_some())
                }
                _ => false,
            };
            if !native {
                return Err(self.clone_transfer_type_error("transfer is not iterable"));
            }
            self.init_for_of_iterator(module, source.clone())?
        };
        // Keep yielded objects reachable across the NEXT iterator callback,
        // including a generator that no longer retains a previously yielded
        // buffer. The rooting array is engine-owned, budgeted heap storage.
        let roots = self.alloc_array_with_prototype(None)?;
        let mut entries = Vec::new();
        loop {
            self.json_charge_work()?;
            let held = vec![Value::Object(roots), source.clone(), iterator.clone()];
            let next = self.with_gc_nested_request(held, |core| {
                core.advance_for_of_iterator(module, iterator.clone())
            })?;
            self.clone_transfer_observe(state);
            let Some(entry) = next else { break };
            if !entry.is_object_like() {
                return Err(self.clone_transfer_type_error("transfer entries must be objects"));
            }
            if entries.len() == entries.capacity() {
                let capacity = entries.capacity().saturating_mul(2).max(4);
                let bytes = (capacity - entries.capacity()) as u64
                    * std::mem::size_of::<Value>() as u64;
                state.reserve(self, bytes)?;
                entries.try_reserve_exact(capacity - entries.len()).map_err(|_| {
                    self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                })?;
            }
            state.reserve(self, Self::estimate_value_bytes(&entry))?;
            self.generic_create_data_property(module, roots, entries.len() as u64, entry.clone())?;
            entries.push(entry);
        }
        state.reserve(self, (entries.len() as u64) * std::mem::size_of::<ObjectId>() as u64)?;
        let mut sources = Vec::new();
        sources.try_reserve_exact(entries.len()).map_err(|_| {
            self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
        })?;
        for entry in entries {
            self.json_charge_work()?;
            let Value::Object(id) = entry else {
                return Err(self.throw_data_clone_error("Transfer list entry", &state.label));
            };
            sources.push(id);
        }
        Ok(sources)
    }

    fn clone_transfer_type_error(&mut self, message: &str) -> InterpreterError {
        self.throw_buffer_node_error("TypeError", "ERR_INVALID_ARG_TYPE", message.to_string())
    }

    fn clone_transfer_observe(&self, state: &mut CloneState) {
        state.label = state.label.join(
            self.pending_hostcall_result_label
                .as_ref()
                .unwrap_or(&Label::Public),
        );
    }

    /// Prepare an unreachable destination without moving its source bytes.
    /// Resize and labels use the normal accounting/registered-view machinery.
    /// Every destination is prepared before the first ownership exchange, so
    /// a late admission failure cannot detach an earlier source. Materialize
    /// payload storage only for shells whose cloned views need final bounds.
    /// A viewless shell acquires its bytes directly in the commit phase.
    fn structured_clone_prepare_transfer(
        &mut self,
        source: ObjectId,
        target: ObjectId,
        state: &mut CloneState,
    ) -> Result<(), InterpreterError> {
        self.json_charge_work()?;
        let length = self.buffer_backing(source)?.bytes.len();
        Self::structured_clone_transfer_length(length)?;
        for _ in 0..(length as u64).div_ceil(64) {
            self.json_charge_work()?;
        }
        let label = self.binary_storage_label(source);
        state.label = state.label.join(&label);
        // A shell materialized by CloneTask::View still needs its final
        // size/bounds. A zero-length resizable shell can also have tracking
        // views: its registry, not a nonempty payload, detects that case.
        // Fixed zero-length buffers cannot grow. No-view shells stay empty,
        // even for large or unreferenced transfer entries.
        let backing = self.buffer_backing(target)?;
        let materialized = !backing.bytes.is_empty() || !backing.views.is_empty();
        if materialized && backing.bytes.len() != length {
            self.resize_buffer_bytes(target, length)?;
        }
        // Admit an integer byteLength slot before the irreversible phase,
        // rather than relying on a particular allocator's property layout.
        // On refusal it describes the shell, never bytes it does not own yet.
        let shell_length = self.buffer_backing(target)?.bytes.len();
        let has_length_slot = self.heap.get(target.0 as usize).is_some_and(|object| {
            matches!(object.properties.get("byteLength"), Some(Value::Int(_)))
        });
        if !has_length_slot {
            self.set_object_property(
                target,
                "byteLength".to_string(),
                Value::Int(i64::try_from(shell_length).unwrap_or(i64::MAX)),
            )?;
        }
        // All label admission still precedes every payload move.
        self.join_binary_storage_label(target, &label)
    }

    /// An empty shell must not bypass the per-buffer admission that a sized
    /// allocation enforced, including native/replay-originated source buffers.
    fn structured_clone_transfer_length(length: usize) -> Result<(), InterpreterError> {
        if length as u64 > MAX_ARRAY_BUFFER_BYTE_LENGTH {
            return Err(InterpreterError::RangeError {
                message: format!(
                    "Array buffer allocation failed: byteLength {length} exceeds the per-buffer cap of {MAX_ARRAY_BUFFER_BYTE_LENGTH} bytes"
                ),
            });
        }
        Ok(())
    }

    /// Move the source allocation into its prepared destination. Called only
    /// after all sources, destinations, labels and detachment work have been
    /// admitted. No guest code runs from preparation through the last detach.
    fn structured_clone_commit_transfer(
        &mut self,
        source: ObjectId,
        target: ObjectId,
    ) -> Result<(), InterpreterError> {
        debug_assert_ne!(source, target);
        self.mutate_heap(|heap| {
            // Temporarily own the Vec to obtain the two arena entries without
            // unsafe or simultaneous mutable borrows, as ArrayBuffer.transfer
            // does. Exchange only bytes: view registries, resizable maxima and
            // labels belong to their own objects, not to the moved allocation.
            let payload = std::mem::take(
                &mut heap
                    .get_mut(source.0 as usize)
                    .and_then(|object| object.array_buffer.as_deref_mut())
                    .expect("validated clone transfer source remains live")
                    .bytes,
            );
            let length = payload.len();
            let destination = heap
                .get_mut(target.0 as usize)
                .expect("prepared clone transfer destination remains live");
            let backing = destination
                .array_buffer
                .as_deref_mut()
                .expect("clone transfer destination is an ArrayBuffer");
            debug_assert!(
                backing.bytes.len() == length
                    || (backing.bytes.is_empty() && backing.views.is_empty())
            );
            let placeholder = std::mem::replace(&mut backing.bytes, payload);
            // Preparation admitted this Int slot before the irreversible
            // phase. Updating it neither allocates nor changes its estimate.
            *destination
                .properties
                .get_mut("byteLength")
                .expect("prepared clone transfer shell has a byteLength slot") =
                Value::Int(i64::try_from(length).unwrap_or(i64::MAX));
            heap.get_mut(source.0 as usize)
                .and_then(|object| object.array_buffer.as_deref_mut())
                .expect("validated clone transfer source remains live")
                .bytes = placeholder;
        });
        // Source N + shell M becomes source M + target N; their total charge
        // is unchanged even for an empty shell. Normal detachment refunds M,
        // not the N bytes now owned by the target. Source view invalidation
        // and resizable-view accounting retain their canonical implementation.
        self.detach_array_buffer(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "clone-transfer-resources")
    }

    fn state() -> CloneState {
        CloneState {
            memory: BTreeMap::new(),
            transfer_sources: BTreeSet::new(),
            label: Label::Public,
            charged: 0,
        }
    }

    #[test]
    fn transfer_preparation_preserves_current_bytes_until_commit_and_outer_scratch() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(1024).unwrap();
        let target = core.alloc_array_buffer_object(1024).unwrap();
        core.with_array_buffer_bytes_mut(source, |bytes| bytes.fill(37))
            .unwrap();
        let address = core.buffer_backing(source).unwrap().bytes.as_ptr();
        core.json_reserve_temporary(19).unwrap();
        let mut state = state();
        core.structured_clone_prepare_transfer(source, target, &mut state)
            .unwrap();
        assert!(!core.buffer_backing(source).unwrap().detached);
        assert_eq!(core.buffer_backing(source).unwrap().bytes, vec![37; 1024]);
        assert_eq!(core.buffer_backing(source).unwrap().bytes.as_ptr(), address);
        assert_eq!(core.buffer_backing(target).unwrap().bytes, vec![0; 1024]);
        core.structured_clone_commit_transfer(source, target).unwrap();
        assert!(core.buffer_backing(source).unwrap().detached);
        assert!(core.buffer_backing(source).unwrap().bytes.is_empty());
        assert_eq!(core.buffer_backing(target).unwrap().bytes, vec![37; 1024]);
        assert_eq!(core.buffer_backing(target).unwrap().bytes.as_ptr(), address);
        assert_eq!(state.charged, 0);
        assert_eq!(core.json_parse_temporary_bytes, 19);
        core.json_release_temporary(19);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn transfer_preparation_memory_refusal_leaves_both_buffers_unchanged() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(1024).unwrap();
        // A zero-length shell with a tracking view must still admit the real
        // 1024-byte growth before any payload moves. A viewless shell need not.
        let (target, _) = empty_tracking_target(&mut core, 1024);
        core.with_array_buffer_bytes_mut(source, |bytes| bytes.fill(37))
            .unwrap();
        let before = core.estimated_memory_bytes();
        core.config.max_total_memory_bytes = before + 1023;
        assert!(matches!(
            core.structured_clone_prepare_transfer(source, target, &mut state()),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(!core.buffer_backing(source).unwrap().detached);
        assert_eq!(core.buffer_backing(source).unwrap().bytes, vec![37; 1024]);
        assert!(core.buffer_backing(target).unwrap().bytes.is_empty());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn transfer_preparation_observes_cancellation_before_payload_movement() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(1024).unwrap();
        let target = core.alloc_array_buffer_object(1024).unwrap();
        let before = core.estimated_memory_bytes();
        let token = CancellationToken::new();
        token.cancel();
        core.config.cancellation_token = Some(token);
        assert_eq!(
            core.structured_clone_prepare_transfer(source, target, &mut state()),
            Err(InterpreterError::Cancelled)
        );
        assert!(!core.buffer_backing(source).unwrap().detached);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), before);
    }

    #[test]
    fn transfer_preparation_keeps_sensitive_storage_labels() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(8).unwrap();
        let target = core.alloc_array_buffer_object(8).unwrap();
        core.join_binary_storage_label(source, &Label::Secret).unwrap();
        let mut state = state();
        core.structured_clone_prepare_transfer(source, target, &mut state)
            .unwrap();
        assert_eq!(state.label, Label::Secret);
        assert_eq!(core.binary_storage_label(target), Label::Secret);
        assert!(!core.buffer_backing(source).unwrap().detached);
        core.structured_clone_commit_transfer(source, target).unwrap();
        assert!(core.buffer_backing(source).unwrap().detached);
        assert_eq!(core.binary_storage_label(target), Label::Secret);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn prepared_transfers_move_original_allocations_with_no_payload_scratch() {
        for (initial, current) in [(0, 0), (1, 1), (1024, 1024), (16, 32), (32, 7)] {
            for maximum in [None, Some(65_536)] {
                let mut core = runtime();
                let source = core.alloc_array_buffer_object(initial).unwrap();
                let target = core.alloc_array_buffer_object(initial).unwrap();
                core.mutate_heap(|heap| {
                    for id in [source, target] {
                        heap.get_mut(id.0 as usize)
                            .unwrap()
                            .array_buffer
                            .as_deref_mut()
                            .unwrap()
                            .max_byte_length = maximum;
                    }
                });
                core.resize_buffer_bytes(source, current).unwrap();
                core.with_array_buffer_bytes_mut(source, |bytes| {
                    for (index, byte) in bytes.iter_mut().enumerate() {
                        *byte = (index % 251) as u8;
                    }
                })
                .unwrap();
                let address = core.buffer_backing(source).unwrap().bytes.as_ptr();
                let expected = core.buffer_backing(source).unwrap().bytes.clone();
                let mut state = state();
                core.structured_clone_prepare_transfer(source, target, &mut state)
                    .unwrap();
                assert_eq!(state.charged, 0);
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(core.buffer_backing(source).unwrap().bytes, expected);
                assert_eq!(core.buffer_backing(source).unwrap().bytes.as_ptr(), address);
                let prepared_memory = core.estimated_memory_bytes();
                core.structured_clone_commit_transfer(source, target).unwrap();
                let result = core.buffer_backing(target).unwrap();
                assert_eq!(result.bytes.as_ptr(), address, "payload was copied");
                assert_eq!(result.bytes, expected);
                assert_eq!(result.max_byte_length, maximum);
                assert!(!result.detached);
                assert!(core.buffer_backing(source).unwrap().detached);
                assert_eq!(core.estimated_memory_bytes(), prepared_memory - current as u64);
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            }
        }
    }

    #[test]
    fn preparation_needs_no_third_payload_allocation() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(65_536).unwrap();
        let target = core.alloc_array_buffer_object(65_536).unwrap();
        let before = core.estimated_memory_bytes();
        // Existing source + destination payloads are already charged. The old
        // staging reservation rejected this case; no quota changes are needed.
        core.config.max_total_memory_bytes = before + 512;
        let mut state = state();
        core.structured_clone_prepare_transfer(source, target, &mut state)
            .unwrap();
        assert_eq!(state.charged, 0);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn preparation_retains_work_refusal_boundaries_before_any_bytes_move() {
        for length in [0, 1, 63, 64, 65, 129] {
            let required = 1 + (length as u64).div_ceil(64);
            for available in 0..=required {
                let mut core = runtime();
                let source = core.alloc_array_buffer_object(length).unwrap();
                let target = core.alloc_array_buffer_object(length).unwrap();
                core.with_array_buffer_bytes_mut(source, |bytes| bytes.fill(83))
                    .unwrap();
                let before = core.estimated_memory_bytes();
                let executed = core.instructions_executed;
                core.config.instruction_budget = executed + available;
                let mut state = state();
                let outcome = core.structured_clone_prepare_transfer(source, target, &mut state);
                if available < required {
                    assert!(matches!(outcome, Err(InterpreterError::BudgetExhausted { .. })));
                } else {
                    outcome.unwrap();
                }
                assert!(!core.buffer_backing(source).unwrap().detached);
                assert_eq!(core.buffer_backing(source).unwrap().bytes, vec![83; length]);
                assert_eq!(core.buffer_backing(target).unwrap().bytes, vec![0; length]);
                assert_eq!(state.charged, 0);
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(core.estimated_memory_bytes(), before);
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            }
        }
    }

    /// Make a real builtin call, including transfer-list conversion, graph
    /// traversal, final work admission, source detach and scratch cleanup.
    fn seeded_transfer_call(core: &mut InterpreterCore) -> [ObjectId; 2] {
        let a = core.alloc_array_buffer_object(8).unwrap();
        let b = core.alloc_array_buffer_object(16).unwrap();
        core.with_array_buffer_bytes_mut(a, |bytes| bytes.fill(37)).unwrap();
        core.with_array_buffer_bytes_mut(b, |bytes| bytes.fill(91)).unwrap();
        let list = core.alloc_array_with_prototype(None).unwrap();
        for (index, id) in [a, b].into_iter().enumerate() {
            core.generic_create_data_property(None, list, index as u64, Value::Object(id))
                .unwrap();
        }
        let graph = core
            .alloc_object_with_properties(&[("first", Value::Object(a)), ("again", Value::Object(a))])
            .unwrap();
        let options = core
            .alloc_object_with_properties(&[("transfer", Value::Object(list))])
            .unwrap();
        core.seed_register(0, Value::Object(graph)).unwrap();
        core.seed_register(1, Value::Object(options)).unwrap();
        [a, b]
    }

    fn call(core: &mut InterpreterCore) -> Result<Value, InterpreterError> {
        core.structured_clone_builtin(None, RegRange { start: 0, count: 2 })
    }

    #[test]
    fn builtin_moves_payload_and_preserves_graph_identity_and_unreferenced_transfers() {
        let mut core = runtime();
        let [a, b] = seeded_transfer_call(&mut core);
        let address = core.buffer_backing(a).unwrap().bytes.as_ptr();
        core.json_reserve_temporary(19).unwrap();
        let Value::Object(cloned) = call(&mut core).unwrap() else {
            panic!("cloned object expected");
        };
        let Value::Object(target) = core.heap[cloned.0 as usize].properties.get("first").unwrap()
        else {
            panic!("transferred buffer expected");
        };
        assert_eq!(core.heap[cloned.0 as usize].properties.get("again"), Some(&Value::Object(*target)));
        assert_eq!(core.buffer_backing(*target).unwrap().bytes.as_ptr(), address);
        assert_eq!(core.buffer_backing(*target).unwrap().bytes, vec![37; 8]);
        for source in [a, b] {
            assert!(core.buffer_backing(source).unwrap().detached);
            assert!(core.buffer_backing(source).unwrap().bytes.is_empty());
        }
        assert_eq!(core.json_parse_temporary_bytes, 19);
        core.json_release_temporary(19);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn builtin_work_refusal_never_transfers_only_part_of_the_list() {
        let mut probe = runtime();
        seeded_transfer_call(&mut probe);
        let before = probe.instructions_executed;
        call(&mut probe).unwrap();
        let required = probe.instructions_executed - before;
        assert!(required > 0);
        // Exhaust immediately, during traversal, and at the final pre-detach
        // work boundary. All guest buffers must retain their actual allocation.
        for available in [0, required / 2, required - 1] {
            let mut core = runtime();
            let sources = seeded_transfer_call(&mut core);
            let addresses = sources.map(|id| core.buffer_backing(id).unwrap().bytes.as_ptr());
            core.config.instruction_budget = core.instructions_executed + available;
            assert!(matches!(call(&mut core), Err(InterpreterError::BudgetExhausted { .. })));
            for (index, id) in sources.into_iter().enumerate() {
                let backing = core.buffer_backing(id).unwrap();
                assert!(!backing.detached);
                assert_eq!(backing.bytes.as_ptr(), addresses[index]);
                assert_eq!(backing.bytes, vec![if index == 0 { 37 } else { 91 }; if index == 0 { 8 } else { 16 }]);
            }
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }

    fn execute_transfer_source(source: &str, expected: &[&str]) {
        let tree = crate::parser_api_stability::parse_script(source).unwrap();
        let module = crate::lowering_pipeline::lower_ir0_to_ir3(
            &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "clone-storage-move.js"),
            &crate::lowering_pipeline::LoweringContext::new(
                "clone-storage-move", "transfer-storage", "builtin-only",
            ),
        )
        .unwrap()
        .ir3;
        for throughput in [false, true] {
            for stress in [None, Some(7)] {
                let mut config = if throughput {
                    InterpreterConfig::v8_defaults()
                } else {
                    InterpreterConfig::quickjs_defaults()
                };
                config.instruction_budget = 10_000_000;
                config.granted_capabilities = [
                    RuntimeCapability::VmDispatch,
                    RuntimeCapability::HeapAllocate,
                    RuntimeCapability::Builtin,
                    RuntimeCapability::Console,
                ]
                .into_iter()
                .collect();
                let mut core = InterpreterCore::new(config, "clone-storage-move");
                core.set_gc_stress_interval(stress);
                let result = core.execute(&module).unwrap();
                let lines: Vec<&str> = result.console_output.iter()
                    .map(|entry| entry.message.as_str()).collect();
                assert_eq!(lines, expected, "throughput={throughput}, stress={stress:?}");
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            }
        }
    }

    const LATE_TRANSFER_STORAGE: &str = r#"
const a = new ArrayBuffer(4, { maxByteLength: 16 });
const b = new ArrayBuffer(3);
const orphan = new ArrayBuffer(2);
const tracking = new Uint8Array(a, 1);
const fixed = new Uint8Array(a, 1, 2);
const data = new DataView(a, 1);
new Uint8Array(a).set([1,2,3,4]);
new Uint8Array(b).set([5,6,7]);
const log = [];
const input = { a, tracking, fixed, data, b, again: a,
  get mutate() {
    log.push('outer');
    a.resize(7);
    new Uint8Array(a)[6] = 99;
    return { get nested() {
      log.push('nested'); new Uint8Array(a)[1] = 42;
      new Uint8Array(b)[2] = 88; return 1;
    } };
  }
};
input.self = input;
const copy = structuredClone(input, { transfer: [b, orphan, a] });
console.log(log.join(','), a.byteLength, b.byteLength, orphan.byteLength, tracking.length, fixed.length);
console.log(copy.self === copy, copy.again === copy.a, copy.tracking.buffer === copy.a, copy.data.buffer === copy.a);
console.log(Array.from(new Uint8Array(copy.a)).join(','), Array.from(new Uint8Array(copy.b)).join(','));
console.log(copy.a.resizable, copy.a.maxByteLength, copy.fixed.length, copy.tracking.length, copy.data.byteLength);
copy.a.resize(10);
console.log(copy.fixed.length, copy.tracking.length, copy.data.byteLength, copy.tracking[5], copy.tracking[8]);
try { data.getUint8(0); } catch (error) { console.log(error.name); }
let held = copy.a;
for (let i = 0; i < 32; i++) {
  const old = held;
  held = structuredClone(old, { transfer: [old] });
  if (old.byteLength !== 0) throw new Error('source stayed attached');
}
console.log(held.byteLength, held.resizable, held.maxByteLength, new Uint8Array(held)[6]);
"#;

    #[test]
    fn moved_transfers_keep_late_bytes_resizable_views_and_repeated_ownership() {
        execute_transfer_source(LATE_TRANSFER_STORAGE, &[
            "outer,nested 0 0 0 0 0",
            "true true true true",
            "1,42,3,4,0,0,99 5,6,88",
            "true 16 2 6 6",
            "2 9 9 99 0",
            "TypeError",
            "10 true 16 99",
        ]);
    }

    const TRANSFER_STORAGE_FAILURES: &str = r#"
const a = new ArrayBuffer(4);
const b = new ArrayBuffer(2);
new Uint8Array(a).set([1,2,3,4]);
new Uint8Array(b).set([5,6]);
const sentinel = {};
try {
  structuredClone({ a, get late() {
    new Uint8Array(a)[3] = 77;
    throw sentinel;
  } }, { transfer: [a,b] });
} catch (error) {
  console.log(error === sentinel, a.byteLength, b.byteLength, new Uint8Array(a)[3]);
}
try { structuredClone({ a, bad: Symbol('x') }, { transfer: [a,b] }); }
catch (error) { console.log(error.name, error.code, a.byteLength, b.byteLength); }
let reads = 0;
try {
  structuredClone({ get a() { reads++; return a; } }, { transfer: [a,b,a] });
} catch (error) { console.log(error.name, error.code, reads, a.byteLength, b.byteLength); }
let inner;
const c = new ArrayBuffer(2);
new Uint8Array(c).set([8,9]);
const copy = structuredClone({ a, alias: a, get inner() {
  inner = structuredClone(c, { transfer: [c] }); return inner;
} }, { transfer: [a,b] });
console.log(c.byteLength, b.byteLength, inner.byteLength);
console.log(a.byteLength, copy.alias === copy.a, Array.from(new Uint8Array(copy.a)).join(','));
new Uint8Array(inner)[0] = 99;
console.log(Array.from(new Uint8Array(copy.inner)).join(','), inner.byteLength, copy.inner !== inner);
"#;

    #[test]
    fn failed_transfer_preparation_preserves_guest_effects_and_recoverable_sources() {
        execute_transfer_source(TRANSFER_STORAGE_FAILURES, &[
            "true 4 2 77",
            "DataCloneError 25 4 2",
            "DataCloneError 25 0 4 2",
            "0 0 2",
            "0 true 1,2,3,77",
            "8,9 2 true",
        ]);
    }

    /// A clone view reached before a later source-buffer growth: its shell
    /// still has zero bytes, but final preparation must refresh its bounds.
    fn empty_tracking_target(core: &mut InterpreterCore, maximum: usize) -> (ObjectId, ObjectId) {
        let target = core.alloc_array_buffer_object(0).unwrap();
        core.mutate_heap(|heap| {
            heap.get_mut(target.0 as usize).unwrap().array_buffer
                .as_deref_mut().unwrap().max_byte_length = Some(maximum);
        });
        let view = core.alloc_data_view_object(target, 0, 0).unwrap();
        core.register_buffer_view(view, Some(ViewBounds {
            fixed_length: None,
            out_of_bounds: false,
        })).unwrap();
        (target, view)
    }

    #[test]
    fn viewless_transfer_preparation_keeps_the_shell_empty() {
        for maximum in [None, Some(65_544)] {
            let mut core = runtime();
            let source = core.alloc_array_buffer_object(65_536).unwrap();
            let target = core.alloc_array_buffer_object(0).unwrap();
            core.mutate_heap(|heap| {
                for id in [source, target] {
                    heap.get_mut(id.0 as usize).unwrap().array_buffer
                        .as_deref_mut().unwrap().max_byte_length = maximum;
                }
            });
            core.with_array_buffer_bytes_mut(source, |bytes| bytes[65_535] = 71).unwrap();
            let address = core.buffer_backing(source).unwrap().bytes.as_ptr();
            core.json_reserve_temporary(13).unwrap();
            let before = core.estimated_memory_bytes();
            // Enough metadata headroom, but neither a payload shell nor a copy.
            core.config.max_total_memory_bytes = before + 1024;
            core.structured_clone_prepare_transfer(source, target, &mut state()).unwrap();
            assert!(core.buffer_backing(target).unwrap().bytes.is_empty());
            assert_eq!(core.heap.get(target.0 as usize).unwrap().properties.get("byteLength"),
                Some(&Value::Int(0)));
            assert_eq!(core.buffer_backing(source).unwrap().bytes.as_ptr(), address);
            core.structured_clone_commit_transfer(source, target).unwrap();
            let backing = core.buffer_backing(target).unwrap();
            assert_eq!(backing.bytes.as_ptr(), address);
            assert_eq!(backing.bytes.len(), 65_536);
            assert_eq!(backing.bytes[65_535], 71);
            assert_eq!(backing.max_byte_length, maximum);
            assert_eq!(core.heap.get(target.0 as usize).unwrap().properties.get("byteLength"),
                Some(&Value::Int(65_536)));
            assert_eq!(core.json_parse_temporary_bytes, 13);
            core.json_release_temporary(13);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }

    #[test]
    fn resizable_view_shells_follow_late_growth_and_shrink_before_movement() {
        for length in [0, 4, 16] {
            let mut core = runtime();
            let source = core.alloc_array_buffer_object(8).unwrap();
            let (target, view) = empty_tracking_target(&mut core, 32);
            core.structured_clone_prepare_transfer(source, target, &mut state()).unwrap();
            assert_eq!(core.buffer_backing(target).unwrap().bytes.len(), 8);
            core.resize_buffer_bytes(source, length).unwrap();
            let address = core.buffer_backing(source).unwrap().bytes.as_ptr();
            core.structured_clone_prepare_transfer(source, target, &mut state()).unwrap();
            assert_eq!(core.heap.get(view.0 as usize).unwrap().data_view
                .as_deref().unwrap().byte_length, length);
            core.structured_clone_commit_transfer(source, target).unwrap();
            assert_eq!(core.buffer_backing(target).unwrap().bytes.as_ptr(), address);
            assert_eq!(core.buffer_backing(target).unwrap().bytes.len(), length);
            core.resize_buffer_bytes(target, 24).unwrap();
            assert_eq!(core.heap.get(view.0 as usize).unwrap().data_view
                .as_deref().unwrap().byte_length, 24);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }

    #[test]
    fn mixed_empty_and_sized_shells_release_only_discarded_payloads() {
        let mut core = runtime();
        let first = core.alloc_array_buffer_object(4096).unwrap();
        let first_target = core.alloc_array_buffer_object(0).unwrap();
        let second = core.alloc_array_buffer_object(8).unwrap();
        let second_target = core.alloc_array_buffer_object(8).unwrap();
        let first_address = core.buffer_backing(first).unwrap().bytes.as_ptr();
        let second_address = core.buffer_backing(second).unwrap().bytes.as_ptr();
        let mut state = state();
        for (source, target) in [(first, first_target), (second, second_target)] {
            core.structured_clone_prepare_transfer(source, target, &mut state).unwrap();
        }
        for (source, target, address) in [
            (first, first_target, first_address),
            (second, second_target, second_address),
        ] {
            core.structured_clone_commit_transfer(source, target).unwrap();
            assert_eq!(core.buffer_backing(target).unwrap().bytes.as_ptr(), address);
            assert!(core.buffer_backing(source).unwrap().detached);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
        assert_eq!(core.json_parse_temporary_bytes, 0);
    }

    #[test]
    fn empty_shells_do_not_bypass_the_per_buffer_limit() {
        assert!(InterpreterCore::structured_clone_transfer_length(0).is_ok());
        let maximum = usize::try_from(MAX_ARRAY_BUFFER_BYTE_LENGTH).unwrap();
        assert!(InterpreterCore::structured_clone_transfer_length(maximum).is_ok());
        if let Some(oversized) = maximum.checked_add(1) {
            assert!(matches!(
                InterpreterCore::structured_clone_transfer_length(oversized),
                Err(InterpreterError::RangeError { .. })
            ));
        }
    }
}
