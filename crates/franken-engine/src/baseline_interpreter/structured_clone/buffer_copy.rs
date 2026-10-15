//! Copy ordinary structured-clone buffers once, into their admitted result.
//! Transfer-list ownership exchange remains in transfer.rs. This path never
//! detaches a source or shares its mutable allocation with the destination.

use super::*;

impl InterpreterCore {
    pub(super) fn structured_clone_array_buffer(
        &mut self,
        source: ObjectId,
        max_byte_length: Option<usize>,
    ) -> Result<ObjectId, InterpreterError> {
        let length = self.with_array_buffer_bytes(source, <[u8]>::len)?;
        // Reject insufficient payload headroom before even creating a shell.
        // The ordinary allocator still admits the complete destination and
        // enforces its per-buffer cap. No separate length-sized scratch lives
        // across that allocation, and no guest callback runs in this path.
        self.check_temporary_memory_budget(length as u64)?;
        let label = self.binary_storage_label(source);
        let target = self.alloc_array_buffer_object(length)?;
        debug_assert_ne!(source, target);
        self.mutate_heap(|heap| {
            // The heap arena does not expose two mutable entries at once.
            // Own only the DESTINATION's already-accounted Vec while reading
            // the source. As in the transfer exchange, this no-callback region
            // cannot collect or resynchronize accounting halfway through.
            // The source remains intact, including its allocation identity.
            let mut destination = std::mem::take(
                &mut heap
                    .get_mut(target.0 as usize)
                    .and_then(|object| object.array_buffer.as_deref_mut())
                    .expect("new clone buffer has admitted backing")
                    .bytes,
            );
            let original = heap
                .get(source.0 as usize)
                .and_then(|object| object.array_buffer.as_deref())
                .expect("clone buffer source remains live without guest callbacks");
            destination.copy_from_slice(&original.bytes);
            let backing = heap
                .get_mut(target.0 as usize)
                .and_then(|object| object.array_buffer.as_deref_mut())
                .expect("new clone buffer remains live during its copy");
            backing.bytes = destination;
            backing.max_byte_length = max_byte_length;
        });
        self.join_binary_storage_label(target, &label)?;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core() -> InterpreterCore {
        let mut config = InterpreterConfig::quickjs_defaults();
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "structured-clone-single-copy")
    }

    fn source(core: &mut InterpreterCore, length: usize) -> ObjectId {
        let source = core.alloc_array_buffer_object(length).unwrap();
        core.with_array_buffer_bytes_mut(source, |bytes| {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = index.wrapping_mul(37).wrapping_add(11) as u8;
            }
        })
        .unwrap();
        core.seed_register(0, Value::Object(source)).unwrap();
        source
    }

    fn clone_buffer(core: &mut InterpreterCore) -> Result<ObjectId, InterpreterError> {
        match core.structured_clone_builtin(None, RegRange { start: 0, count: 1 })? {
            Value::Object(id) => Ok(id),
            other => panic!("buffer clone returned {other:?}"),
        }
    }

    fn accounted(core: &InterpreterCore, inherited: u64) {
        assert_eq!(core.json_parse_temporary_bytes, inherited);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        assert!(core.pending_exception.is_none());
    }

    #[test]
    fn ordinary_buffer_clones_are_independent_and_preserve_source_storage() {
        for length in [0, 1, 63, 64, 255, 1024, 65_537] {
            let mut core = core();
            let source = source(&mut core, length);
            let source_pointer = core.buffer_backing(source).unwrap().bytes.as_ptr();
            let target = clone_buffer(&mut core).unwrap();
            assert_ne!(source, target);
            let original = core.buffer_backing(source).unwrap();
            let cloned = core.buffer_backing(target).unwrap();
            assert_eq!(original.bytes, cloned.bytes);
            assert_eq!(original.bytes.as_ptr(), source_pointer);
            assert!(!original.detached && !cloned.detached);
            if length != 0 {
                assert_ne!(original.bytes.as_ptr(), cloned.bytes.as_ptr());
                core.with_array_buffer_bytes_mut(target, |bytes| bytes[0] = 222)
                    .unwrap();
                assert_eq!(core.buffer_backing(source).unwrap().bytes[0], 11);
                core.with_array_buffer_bytes_mut(source, |bytes| bytes[0] = 111)
                    .unwrap();
                assert_eq!(core.buffer_backing(target).unwrap().bytes[0], 222);
            }
            accounted(&core, 0);
        }
    }

    #[test]
    fn a_large_clone_needs_one_new_payload_not_two_simultaneous_copies() {
        let mut core = core();
        let length = 256 * 1024;
        let source = source(&mut core, length);
        core.json_reserve_temporary(71).unwrap();
        let before = core.estimated_memory_bytes();
        let headroom = length as u64 + 64 * 1024;
        core.config.max_total_memory_bytes = before + headroom;
        let target = clone_buffer(&mut core).unwrap();
        assert_eq!(
            core.buffer_backing(source).unwrap().bytes,
            core.buffer_backing(target).unwrap().bytes
        );
        // The previous implementation held a length-sized scratch allocation
        // while admitting the same result. That peak cannot fit this budget.
        assert!(2 * length as u64 > headroom);
        assert!(matches!(
            core.json_reserve_temporary(length as u64),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        accounted(&core, 71);
        core.json_release_temporary(71);
        accounted(&core, 0);
    }

    #[test]
    fn payload_refusal_and_cancellation_leave_the_source_and_outer_scratch_intact() {
        for cancelled in [false, true] {
            let mut core = core();
            let source = source(&mut core, 1024);
            let pointer = core.buffer_backing(source).unwrap().bytes.as_ptr();
            core.json_reserve_temporary(71).unwrap();
            let before = core.estimated_memory_bytes();
            let heap_before = core.heap_size();
            if cancelled {
                let token = CancellationToken::new();
                token.cancel();
                core.config.cancellation_token = Some(token);
                assert_eq!(clone_buffer(&mut core), Err(InterpreterError::Cancelled));
            } else {
                core.config.max_total_memory_bytes = before + CLONE_MEMO_ENTRY_BYTES + 1023;
                assert!(matches!(
                    clone_buffer(&mut core),
                    Err(InterpreterError::MemoryBudgetExceeded { .. })
                ));
            }
            assert_eq!(core.heap_size(), heap_before);
            assert_eq!(core.estimated_memory_bytes(), before);
            assert_eq!(core.buffer_backing(source).unwrap().bytes.as_ptr(), pointer);
            assert_eq!(core.buffer_backing(source).unwrap().bytes[0], 11);
            accounted(&core, 71);
            core.json_release_temporary(71);
        }
    }

    #[test]
    fn binary_labels_and_resizable_bounds_follow_the_copied_storage() {
        let mut core = core();
        let source = source(&mut core, 64);
        core.mutate_heap(|heap| {
            heap.get_mut(source.0 as usize)
                .unwrap()
                .array_buffer
                .as_deref_mut()
                .unwrap()
                .max_byte_length = Some(256);
        });
        let label = Label::Custom {
            name: "cloned-binary-source".repeat(8),
            level: 9,
        };
        core.join_binary_storage_label(source, &label).unwrap();
        let target = clone_buffer(&mut core).unwrap();
        assert_eq!(core.buffer_backing(target).unwrap().max_byte_length, Some(256));
        assert_eq!(core.binary_storage_label(target), label);
        assert_eq!(core.pending_hostcall_result_label, Some(label));
        core.resize_buffer_bytes(source, 128).unwrap();
        assert_eq!(core.buffer_backing(target).unwrap().bytes.len(), 64);
        core.resize_buffer_bytes(target, 96).unwrap();
        assert!(core.buffer_backing(target).unwrap().bytes[64..].iter().all(|b| *b == 0));
        assert_eq!(core.buffer_backing(source).unwrap().bytes.len(), 128);
        accounted(&core, 0);
    }

    #[test]
    fn aliases_share_one_cloned_buffer_and_each_invocation_gets_a_new_snapshot() {
        let mut core = core();
        let source = source(&mut core, 4096);
        let root = core
            .alloc_array_from_values(&[Value::Object(source), Value::Object(source)])
            .unwrap();
        let mut state = CloneState {
            memory: BTreeMap::new(),
            transfer_sources: BTreeSet::new(),
            label: Label::Public,
            charged: 0,
        };
        core.structured_clone_walk(None, Value::Object(root), &mut state)
            .unwrap();
        assert_eq!(state.memory.len(), 2);
        let first = state.memory[&source];
        assert_eq!(state.charged, 2 * CLONE_MEMO_ENTRY_BYTES);
        state.memory.clear();
        let charged = state.charged;
        state.release(&mut core, charged);
        core.with_array_buffer_bytes_mut(source, |bytes| bytes[0] = 77)
            .unwrap();
        let second = clone_buffer(&mut core).unwrap();
        assert_ne!(first, second);
        assert_eq!(core.buffer_backing(first).unwrap().bytes[0], 11);
        assert_eq!(core.buffer_backing(second).unwrap().bytes[0], 77);
        accounted(&core, 0);
    }

    #[test]
    fn guest_getter_order_views_transfer_and_detach_keep_their_native_contracts() {
        let source = include_str!("buffer_copy.js");
        let tree = crate::parser_api_stability::parse_script(source).unwrap();
        let lowered = crate::lowering_pipeline::lower_ir0_to_ir3(
            &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "clone-buffer-copy.js"),
            &crate::lowering_pipeline::LoweringContext::new("clone", "buffer-copy", "builtin-only"),
        )
        .unwrap();
        let mut core = core();
        let result = core.execute(&lowered.ir3).unwrap();
        assert_eq!(result.value, Value::str("buffer-copy-ok"));
        accounted(&core, 0);
    }
}
