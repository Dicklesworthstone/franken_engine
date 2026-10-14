//! ArrayBufferCopyAndDetach storage ownership. Equal-length transfers move the
//! existing Vec; length changes copy the surviving prefix directly into the
//! admitted destination, without an uncharged intermediate payload.

use super::*;

impl InterpreterCore {
    /// Called after observable ToIndex coercion and maximum-length validation.
    /// Every fallible allocation and label operation precedes byte movement.
    /// The existing detacher still owns source view invalidation/accounting.
    pub(super) fn array_buffer_copy_and_detach_storage(
        &mut self,
        source: ObjectId,
        new_len: usize,
        maximum: Option<usize>,
    ) -> Result<ObjectId, InterpreterError> {
        self.json_charge_work()?;
        self.plain_buffer_receiver(&Value::Object(source), false, "transfer")?;
        let backing = self.buffer_backing(source)?;
        if backing.detached {
            return Err(InterpreterError::TypeError {
                expected: "an attached ArrayBuffer for transfer".to_string(),
                got: "a detached ArrayBuffer".to_string(),
            });
        }
        if new_len as u64 > MAX_ARRAY_BUFFER_BYTE_LENGTH
            || maximum.is_some_and(|maximum| new_len > maximum)
        {
            return Err(InterpreterError::RangeError {
                message: "ArrayBuffer transfer length exceeds its maximum".to_string(),
            });
        }
        let old_len = backing.bytes.len();
        let same_length = old_len == new_len;
        let copy_len = old_len.min(new_len);
        let label = self.binary_storage_label(source);
        // Charge copy/zero-fill work and the detacher's worst-case heap walk
        // before committing. Equal-length storage movement itself is constant
        // work; it must not allocate a payload just to authorize a transfer.
        let payload_work = if same_length {
            0
        } else {
            (new_len as u64).saturating_add(copy_len as u64).div_ceil(64)
        };
        let work = payload_work
            .saturating_add(self.heap_size() as u64)
            .saturating_add(1);
        for _ in 0..work {
            self.json_charge_work()?;
        }
        let target = self.alloc_buffer_object(if same_length { 0 } else { new_len }, false)?;
        self.mutate_heap(|heap| {
            if let Some(backing) = heap
                .get_mut(target.0 as usize)
                .and_then(|object| object.array_buffer.as_deref_mut())
            {
                backing.max_byte_length = maximum;
            }
        });
        self.join_binary_storage_label(target, &label)?;
        let byte_length_key = "byteLength".to_string();
        // No callback, allocation, collection or fallible operation occurs in
        // this closure. Both distinct IDs were validated/allocated above.
        // Temporarily owning the Vec permits disjoint access through the arena
        // without unsafe pointers or a second source-sized buffer.
        self.mutate_heap(|heap| {
            let payload = std::mem::take(
                &mut heap
                    .get_mut(source.0 as usize)
                    .and_then(|object| object.array_buffer.as_deref_mut())
                    .expect("validated transfer source remains live")
                    .bytes,
            );
            if same_length {
                let object = heap
                    .get_mut(target.0 as usize)
                    .expect("new transfer destination remains live");
                object
                    .array_buffer
                    .as_deref_mut()
                    .expect("transfer destination is an ArrayBuffer")
                    .bytes = payload;
                object.properties.insert(
                    byte_length_key,
                    Value::Int(i64::try_from(new_len).unwrap_or(i64::MAX)),
                );
            } else {
                heap.get_mut(target.0 as usize)
                    .and_then(|object| object.array_buffer.as_deref_mut())
                    .expect("new transfer destination remains live")
                    .bytes[..copy_len]
                    .copy_from_slice(&payload[..copy_len]);
                heap.get_mut(source.0 as usize)
                    .and_then(|object| object.array_buffer.as_deref_mut())
                    .expect("validated transfer source remains live")
                    .bytes = payload;
            }
        });
        // Equal-length movement changes no total payload charge: source N +
        // target 0 becomes source 0 + target N. For a length change the source
        // was restored, so normal detachment releases its old payload charge.
        self.detach_array_buffer(source)?;
        Ok(target)
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
        InterpreterCore::new(config, "buffer-transfer-storage")
    }

    fn source(core: &mut InterpreterCore, length: usize) -> ObjectId {
        let source = core.alloc_array_buffer_object(length).unwrap();
        core.with_array_buffer_bytes_mut(source, |bytes| {
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte = (index % 251) as u8;
            }
        })
        .unwrap();
        source
    }

    #[test]
    fn same_length_transfer_moves_the_allocation_and_keeps_labels() {
        for length in [0, 1, 64, 4096] {
            for maximum in [None, Some(length + 8)] {
                let mut core = runtime();
                let source = source(&mut core, length);
                let address = core.buffer_backing(source).unwrap().bytes.as_ptr();
                core.join_binary_storage_label(source, &Label::Secret).unwrap();
                let target = core
                    .array_buffer_copy_and_detach_storage(source, length, maximum)
                    .unwrap();
                let backing = core.buffer_backing(target).unwrap();
                assert_eq!(backing.bytes.as_ptr(), address, "payload was copied");
                assert_eq!(backing.bytes.len(), length);
                assert_eq!(backing.max_byte_length, maximum);
                assert!(backing.bytes.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
                assert!(core.buffer_backing(source).unwrap().detached);
                assert!(core.buffer_backing(source).unwrap().bytes.is_empty());
                assert_eq!(core.binary_storage_label(target), Label::Secret);
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            }
        }
    }

    #[test]
    fn changed_lengths_copy_only_the_prefix_and_zero_fill_growth() {
        for (old, new) in [(4, 0), (4, 2), (4, 8), (4096, 17)] {
            let mut core = runtime();
            let source = source(&mut core, old);
            let target = core.array_buffer_copy_and_detach_storage(source, new, None).unwrap();
            let expected: Vec<u8> = (0..new)
                .map(|index| if index < old { (index % 251) as u8 } else { 0 })
                .collect();
            assert_eq!(core.buffer_backing(target).unwrap().bytes, expected);
            assert!(core.buffer_backing(source).unwrap().detached);
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }

    #[test]
    fn transfer_does_not_require_a_second_payloads_worth_of_headroom() {
        let mut core = runtime();
        let source = source(&mut core, 65_536);
        let address = core.buffer_backing(source).unwrap().bytes.as_ptr();
        // Enough for the new object's metadata, but not a second 64 KiB payload.
        core.config.max_total_memory_bytes = core.estimated_memory_bytes() + 32_768;
        let target = core.array_buffer_copy_and_detach_storage(source, 65_536, None).unwrap();
        assert_eq!(core.buffer_backing(target).unwrap().bytes.as_ptr(), address);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

    #[test]
    fn allocation_and_cancellation_refusals_preserve_the_source() {
        for cancel in [false, true] {
            let mut core = runtime();
            let source = source(&mut core, 4096);
            let address = core.buffer_backing(source).unwrap().bytes.as_ptr();
            let before = core.estimated_memory_bytes();
            if cancel {
                let token = CancellationToken::new();
                token.cancel();
                core.config.cancellation_token = Some(token);
            } else {
                core.config.max_total_memory_bytes = before;
            }
            let outcome = core.array_buffer_copy_and_detach_storage(source, 4096, None);
            if cancel {
                assert_eq!(outcome, Err(InterpreterError::Cancelled));
            } else {
                assert!(matches!(outcome, Err(InterpreterError::MemoryBudgetExceeded { .. })));
            }
            let backing = core.buffer_backing(source).unwrap();
            assert!(!backing.detached);
            assert_eq!(backing.bytes.as_ptr(), address);
            assert_eq!(backing.bytes.len(), 4096);
            assert!(backing.bytes.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }
}
