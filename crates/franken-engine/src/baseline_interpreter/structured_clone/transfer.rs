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

        // The graph's memo points at ordinary, correctly sized buffer shells.
        // Views can be constructed over them without bypassing their normal
        // bounds/heap checks. Payload preparation below deliberately happens
        // AFTER serialization: a later getter may mutate these source bytes.
        for &source in &sources {
            self.json_charge_work()?;
            let backing = self.buffer_backing(source)?;
            let (length, maximum) = (backing.bytes.len(), backing.max_byte_length);
            state.reserve(self, CLONE_MEMO_ENTRY_BYTES)?;
            let target = self.alloc_array_buffer_object(length)?;
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
            self.detach_array_buffer(source)?;
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

    /// Prepare an unreachable destination without detaching its source. Resize
    /// and labels use the same accounting/registered-view machinery as normal
    /// buffers. Even on a late budget failure no source has been detached yet.
    fn structured_clone_prepare_transfer(
        &mut self,
        source: ObjectId,
        target: ObjectId,
        state: &mut CloneState,
    ) -> Result<(), InterpreterError> {
        self.json_charge_work()?;
        let length = self.buffer_backing(source)?.bytes.len();
        for _ in 0..(length as u64).div_ceil(64) {
            self.json_charge_work()?;
        }
        let label = self.binary_storage_label(source);
        state.label = state.label.join(&label);
        state.reserve(self, length as u64)?;
        let outcome = (|| {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(length).map_err(|_| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            self.with_array_buffer_bytes(source, |input| bytes.extend_from_slice(input))?;
            if self.buffer_backing(target)?.bytes.len() != length {
                self.resize_buffer_bytes(target, length)?;
            }
            self.with_array_buffer_bytes_mut(target, |output| output.copy_from_slice(&bytes))?;
            self.join_binary_storage_label(target, &label)
        })();
        state.release(self, length as u64);
        outcome
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
    fn transfer_preparation_copies_current_bytes_and_preserves_outer_scratch() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(1024).unwrap();
        let target = core.alloc_array_buffer_object(1024).unwrap();
        core.with_array_buffer_bytes_mut(source, |bytes| bytes.fill(37))
            .unwrap();
        core.json_reserve_temporary(19).unwrap();
        let mut state = state();
        core.structured_clone_prepare_transfer(source, target, &mut state)
            .unwrap();
        assert!(!core.buffer_backing(source).unwrap().detached);
        assert_eq!(core.buffer_backing(target).unwrap().bytes, vec![37; 1024]);
        assert_eq!(state.charged, 0);
        assert_eq!(core.json_parse_temporary_bytes, 19);
        core.json_release_temporary(19);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn transfer_preparation_memory_refusal_leaves_both_buffers_unchanged() {
        let mut core = runtime();
        let source = core.alloc_array_buffer_object(1024).unwrap();
        let target = core.alloc_array_buffer_object(1024).unwrap();
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
        assert_eq!(core.buffer_backing(target).unwrap().bytes, vec![0; 1024]);
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn transfer_preparation_observes_cancellation_before_payload_allocation() {
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
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}
