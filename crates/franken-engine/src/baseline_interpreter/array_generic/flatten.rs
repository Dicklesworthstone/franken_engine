//! One callback-safe FlattenIntoArray walker for Arrays and array-likes.
//!
//! Each source owns a live cursor and its captured length. Child traversal
//! never freezes the parent's unread keys. The explicit stack is fallibly
//! allocated and charged across callbacks; every exit releases that scratch.

use super::*;

struct FlattenFrame {
    source: ObjectId,
    cursor: LiveArrayCursor,
    depth: f64,
    mapped: bool,
}

impl FlattenFrame {
    fn new(source: ObjectId, length: u64, depth: f64, mapped: bool) -> Self {
        Self {
            source,
            cursor: LiveArrayCursor::new(0, length, false, false),
            depth,
            mapped,
        }
    }
}

fn frame_bytes(capacity: usize) -> u64 {
    u64::try_from(capacity)
        .unwrap_or(u64::MAX)
        .saturating_mul(std::mem::size_of::<FlattenFrame>() as u64)
}

impl InterpreterCore {
    /// ES FlattenIntoArray: top-level mapping only, depth-first nested Array
    /// expansion, and CreateDataPropertyOrThrow at consecutive output indices.
    /// The caller owns the species/provenance scope. Only the top frame is
    /// mapped: pin its source and species result while the mapper runs.
    /// Getters and traps still run without a nested collection request.
    pub(super) fn generic_flatten_into(
        &mut self,
        module: Option<&Ir3Module>,
        target: ObjectId,
        source: ObjectId,
        source_len: u64,
        depth: f64,
        mapper: Option<(&Value, &Value)>,
    ) -> Result<(), InterpreterError> {
        let mut stack = Vec::new();
        let mut reserved = 0;
        let outcome = (|| {
            self.push_flatten_frame(
                &mut stack,
                &mut reserved,
                FlattenFrame::new(source, source_len, depth, true),
            )?;
            let mut target_index = 0u64;
            while let Some(frame) = stack.last_mut() {
                // Even an empty source, a cycle, or a callback-free descent
                // must consume work. Never let flat(Infinity) grow forever.
                self.json_charge_work()?;
                let from = frame.source;
                let depth_left = frame.depth;
                let mapped = frame.mapped;
                // An empty nested Array still controls the compacted output's
                // shape. Retain its length/mutation provenance on a species
                // result that may already have a Public alias, including when
                // this frame emits no element at all.
                {
                    let prefix_label =
                        self.array_result_prefix_label(from, target, &Label::Public)?;
                    self.record_array_result_prefix_label(target, &prefix_label)?;
                }
                self.observe_scoped_callback_result()?;
                let Some(index) = frame.cursor.next(self, from)? else {
                    stack.pop();
                    continue;
                };
                let key = Self::generic_index_key(index);
                let present = self.generic_has(module, from, &key)?;
                self.observe_scoped_callback_result()?;
                if !present {
                    continue;
                }
                let mut element = self.generic_get(module, from, &key)?;
                self.observe_scoped_callback_result()?;
                if mapped && let Some((mapper, this_arg)) = mapper {
                    // Child frames are never mapped. These are the only
                    // traversal-owned objects outside interpreter state;
                    // the call itself pins mapper, thisArg and arguments.
                    element = self.with_gc_nested_request(
                        vec![Value::Object(target), Value::Object(source)],
                        |core| {
                            core.invoke_inline_method_call(
                                module,
                                mapper.clone(),
                                this_arg.clone(),
                                vec![
                                    element,
                                    Self::generic_length_value(index),
                                    core.generic_object_value(from),
                                ],
                            )
                        },
                    )?;
                    self.observe_scoped_callback_result()?;
                }
                if depth_left > 0.0
                    && let Value::Object(inner) = element
                    && self.generic_is_array(inner)?
                {
                    let inner_len = self.generic_length(module, inner)?;
                    self.observe_scoped_callback_result()?;
                    self.push_flatten_frame(
                        &mut stack,
                        &mut reserved,
                        FlattenFrame::new(inner, inner_len, depth_left - 1.0, false),
                    )?;
                    continue;
                }
                if target_index >= MAX_SAFE_LENGTH {
                    return Err(Self::generic_length_error());
                }
                self.generic_create_data_property(module, target, target_index, element)?;
                target_index += 1;
            }
            Ok(())
        })();
        drop(stack);
        self.json_release_temporary(reserved);
        outcome
    }

    /// Reserve before growing. Charge the actual capacity before another
    /// getter, mapper or result trap may run and resynchronize live memory.
    /// The caller's common cleanup owns reservations even after a failed grow.
    fn push_flatten_frame(
        &mut self,
        stack: &mut Vec<FlattenFrame>,
        reserved: &mut u64,
        frame: FlattenFrame,
    ) -> Result<(), InterpreterError> {
        if stack.len() == stack.capacity() {
            let minimum = stack.len().checked_add(1).ok_or_else(|| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            let capacity = stack
                .capacity()
                .checked_mul(2)
                .unwrap_or(minimum)
                .max(minimum)
                .max(4);
            let requested = frame_bytes(capacity).saturating_sub(*reserved);
            let next = reserved.checked_add(requested).ok_or_else(|| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            self.json_reserve_temporary(requested)?;
            *reserved = next;
            stack.try_reserve_exact(capacity - stack.len()).map_err(|_| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            let actual = frame_bytes(stack.capacity());
            if actual > *reserved {
                self.json_reserve_temporary(actual - *reserved)?;
                *reserved = actual;
            }
        }
        stack.push(frame);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
