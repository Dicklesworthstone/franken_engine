//! Callback-safe stable sorting with fixed, metered native scratch storage.
//!
//! Sort indices, not Value payloads. The top-down split and merge decisions
//! intentionally match the previous allocating merge sort, including equality
//! and the point where a comparator throws. No comparison result is cached:
//! callbacks may mutate the objects held by later comparisons.

use super::*;

impl InterpreterCore {
    /// Sort keys are JavaScript strings, not their lossy UTF-8 display. Keep
    /// lone surrogates and reuse the canonical rope-aware UTF-16 comparator.
    /// The left conversion must stay live and charged while the right one
    /// runs arbitrary guest code. Neither conversion result is cached across
    /// comparisons: a later ToString may legitimately return something else.
    pub(super) fn compare_sort_strings(
        &mut self,
        module: Option<&Ir3Module>,
        left: Value,
        right: Value,
    ) -> Result<Ordering, InterpreterError> {
        let left = self.sort_string_key(module, left)?;
        let left_bytes = Self::estimate_value_bytes(&Value::Str(left.clone()));
        self.json_reserve_temporary(left_bytes)?;
        let outcome = (|| {
            let right = self.sort_string_key(module, right)?;
            let right_bytes = Self::estimate_value_bytes(&Value::Str(right.clone()));
            self.json_reserve_temporary(right_bytes)?;
            let ordering = left.utf16_cmp(&right);
            drop(right);
            self.json_release_temporary(right_bytes);
            Ok(ordering)
        })();
        drop(left);
        self.json_release_temporary(left_bytes);
        outcome
    }

    fn sort_string_key(
        &mut self,
        module: Option<&Ir3Module>,
        value: Value,
    ) -> Result<JsString, InterpreterError> {
        let primitive = if value.is_object_like() {
            self.coerce_runtime_primitive(module, value, true)?
        } else {
            value
        };
        self.observe_scoped_callback_result()?;
        match primitive {
            Value::Symbol(_) => Err(Self::symbol_to_string_error()),
            Value::Str(text) => Ok(text),
            other => Ok(JsString::from(self.value_to_string(&other))),
        }
    }

    pub(super) fn generic_sort_properties(
        &mut self,
        module: &Ir3Module,
        kind: BuiltinFunctionKind,
        object: ObjectId,
        args: RegRange,
    ) -> Result<Value, InterpreterError> {
        let m = Some(module);
        let comparator = self.builtin_arg(args, 0)?.unwrap_or(Value::Undefined);
        if !matches!(comparator, Value::Undefined) && !comparator.is_callable() {
            return Err(InterpreterError::TypeError {
                expected: "undefined or callable comparator".to_string(),
                got: comparator.type_name().to_string(),
            });
        }
        let len = self.generic_length(m, object)?;
        // Retain a length getter's observations before an element getter can
        // replace the pending-result slot with a different callback result.
        self.observe_scoped_callback_result()?;
        let in_place = kind == BuiltinFunctionKind::ArraySort;
        if !in_place {
            Self::generic_array_create_length(len)?;
        }
        // sort skips holes: logical length is not an allocation request.
        // In particular, do not reject a huge sparse/proxy length before its
        // first HasProperty/Get can throw. toSorted materializes every index
        // and keeps its existing ArrayCreate/resource preflight.
        let mut items = if in_place { Vec::new() } else { self.generic_buffer(len)? };
        let mut retained = buffer_bytes::<Value>(items.capacity());
        self.json_reserve_temporary(retained)?;
        let outcome = (|| {
            for index in 0..len {
                self.charge_native_hole_read()?;
                let key = Self::generic_index_key(index);
                let present = !in_place || self.generic_has(m, object, &key)?;
                self.observe_scoped_callback_result()?;
                if present {
                    let value = self.generic_get(m, object, &key)?;
                    self.observe_scoped_callback_result()?;
                    // A getter can return a fresh string, then a later getter
                    // can overwrite the last heap/register reference to it.
                    // The retained snapshot must remain charged independently.
                    let bytes = Self::estimate_value_bytes(&value);
                    let next = retained.checked_add(bytes).ok_or_else(|| {
                        self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
                    })?;
                    self.json_reserve_temporary(bytes)?;
                    retained = next;
                    self.reserve_sort_slot(&mut items, &mut retained)?;
                    items.push(value);
                }
            }
            self.sort_captured_values(m, &mut items, &comparator)?;
            if in_place {
                for (index, value) in items.iter().enumerate() {
                    self.charge_native_hole_read()?;
                    let key = Self::generic_index_key(index as u64);
                    // Comparators and setters can expose public aliases. Use
                    // the existing admission/observation machinery on writes.
                    self.generic_species_output_write(object, &key, |core| {
                        core.generic_set(m, object, &key, value.clone())
                    })?;
                }
                for index in items.len() as u64..len {
                    self.charge_native_hole_read()?;
                    self.reflect_admit_mutation_label(object)?;
                    self.generic_delete(m, object, &Self::generic_index_key(index))?;
                    self.observe_scoped_callback_result()?;
                }
                Ok(self.generic_object_value(object))
            } else {
                let result = self.alloc_array_from_values(&items)?;
                self.reflect_admit_mutation_label(result)?;
                Ok(Value::Object(result))
            }
        })();
        // Cleanup performs no guest calls and runs on every Result exit,
        // including comparator throws, refused setters and resource failures.
        drop(items);
        self.json_release_temporary(retained);
        outcome
    }

    /// Grow a capture buffer from the values actually observed, never from a
    /// guest-supplied logical length. Keep both capacity and payload charges
    /// owned by the caller until its common cleanup, including failed growth.
    fn reserve_sort_slot<T>(
        &mut self,
        buffer: &mut Vec<T>,
        retained: &mut u64,
    ) -> Result<(), InterpreterError> {
        if buffer.len() < buffer.capacity() {
            return Ok(());
        }
        let minimum = buffer.len().checked_add(1).ok_or_else(|| {
            self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
        })?;
        let capacity = buffer.capacity().checked_mul(2).unwrap_or(minimum).max(minimum).max(8);
        let old_bytes = buffer_bytes::<T>(buffer.capacity());
        let requested = buffer_bytes::<T>(capacity).saturating_sub(old_bytes);
        let next = retained.checked_add(requested).ok_or_else(|| {
            self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
        })?;
        self.json_reserve_temporary(requested)?;
        *retained = next;
        buffer.try_reserve_exact(capacity - buffer.len()).map_err(|_| {
            self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
        })?;
        // The allocator may grant more capacity than requested. Admit that
        // surplus before a later getter or comparator can reenter the engine.
        let surplus = buffer_bytes::<T>(buffer.capacity())
            .saturating_sub(old_bytes.saturating_add(requested));
        if surplus != 0 {
            let next = retained.checked_add(surplus).ok_or_else(|| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            self.json_reserve_temporary(surplus)?;
            *retained = next;
        }
        Ok(())
    }

    fn sort_captured_values(
        &mut self,
        module: Option<&Ir3Module>,
        items: &mut [Value],
        comparator: &Value,
    ) -> Result<(), InterpreterError> {
        if items.len() < 2 {
            return Ok(());
        }
        let mut reserved = buffer_bytes::<usize>(items.len()).saturating_mul(2);
        self.json_reserve_temporary(reserved)?;
        let mut order = Vec::new();
        let mut scratch = Vec::new();
        let outcome = (|| {
            order.try_reserve_exact(items.len()).map_err(|_| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            scratch.try_reserve_exact(items.len()).map_err(|_| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            let actual = buffer_bytes::<usize>(order.capacity())
                .saturating_add(buffer_bytes::<usize>(scratch.capacity()));
            if actual > reserved {
                self.json_reserve_temporary(actual - reserved)?;
                reserved = actual;
            }
            for index in 0..items.len() {
                self.charge_native_hole_read()?;
                order.push(index);
                scratch.push(0);
            }
            stable_order(&mut order, &mut scratch, &mut |left, right| {
                let ordering = self.generic_sort_compare(
                    module, items[left].clone(), items[right].clone(), comparator,
                )?;
                self.observe_scoped_callback_result()?;
                Ok::<_, InterpreterError>(ordering)
            })?;
            apply_order(items, &order, &mut scratch, &mut || self.charge_native_hole_read())?;
            Ok(())
        })();
        drop(order);
        drop(scratch);
        self.json_release_temporary(reserved);
        outcome
    }
}

/// Apply destination->source order using cycle swaps, without cloning payloads.
/// On a resource failure each completed swap still preserves the permutation;
/// the caller has not published any of this captured buffer to the receiver.
fn apply_order<T, E>(
    items: &mut [T],
    order: &[usize],
    inverse: &mut [usize],
    tick: &mut impl FnMut() -> Result<(), E>,
) -> Result<(), E> {
    for (destination, &source) in order.iter().enumerate() {
        tick()?;
        inverse[source] = destination;
    }
    for start in 0..items.len() {
        while inverse[start] != start {
            tick()?;
            let target = inverse[start];
            items.swap(start, target);
            inverse.swap(start, target);
        }
    }
    Ok(())
}

fn buffer_bytes<T>(capacity: usize) -> u64 {
    u64::try_from(capacity)
        .unwrap_or(u64::MAX)
        .saturating_mul(std::mem::size_of::<T>() as u64)
}

/// No allocation or Value movement occurs in the recursion. Balanced merges
/// copy at most a constant multiple of the compared indices; each comparison
/// is metered by generic_sort_compare. Depth is bounded by usize's bit width.
fn stable_order<E>(
    order: &mut [usize],
    scratch: &mut [usize],
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(), E> {
    if order.len() < 2 {
        return Ok(());
    }
    let middle = order.len() / 2;
    let (left, right) = order.split_at_mut(middle);
    let (left_scratch, right_scratch) = scratch.split_at_mut(middle);
    stable_order(left, left_scratch, compare)?;
    stable_order(right, right_scratch, compare)?;
    scratch.copy_from_slice(order);
    let (mut left, mut right, mut output) = (0, middle, 0);
    while left < middle && right < scratch.len() {
        if compare(scratch[left], scratch[right])? == Ordering::Greater {
            order[output] = scratch[right];
            right += 1;
        } else {
            order[output] = scratch[left];
            left += 1;
        }
        output += 1;
    }
    if left < middle {
        order[output..].copy_from_slice(&scratch[left..middle]);
    } else {
        order[output..].copy_from_slice(&scratch[right..]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply_order, stable_order};
    use std::cmp::Ordering;

    // The previous allocation-heavy merge topology, independent of the new
    // scratch implementation. Values here are original element identities.
    fn allocating_reference<E>(
        mut right: Vec<usize>,
        compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
    ) -> Result<Vec<usize>, E> {
        if right.len() < 2 {
            return Ok(right);
        }
        let left = right.drain(..right.len() / 2).collect();
        let left = allocating_reference(left, compare)?;
        let right = allocating_reference(right, compare)?;
        let mut result = Vec::with_capacity(left.len() + right.len());
        let (mut left, mut right) = (left.into_iter().peekable(), right.into_iter().peekable());
        while let (Some(a), Some(b)) = (left.peek(), right.peek()) {
            if compare(*a, *b)? == Ordering::Greater {
                result.extend(right.next());
            } else {
                result.extend(left.next());
            }
        }
        result.extend(left);
        result.extend(right);
        Ok(result)
    }

    #[test]
    fn order_and_exact_comparison_trace_match_the_previous_sort() {
        let mut seed = 0x5eeda11_u64;
        for length in 0..129 {
            for _ in 0..8 {
                let values: Vec<_> = (0..length).map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (seed >> 32) % 17
                }).collect();
                let mut old_trace = Vec::new();
                let expected = allocating_reference((0..length).collect(), &mut |a, b| {
                    old_trace.push((a, b));
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap();
                let mut actual: Vec<_> = (0..length).collect();
                let mut scratch = vec![0; length];
                let mut trace = Vec::new();
                stable_order(&mut actual, &mut scratch, &mut |a, b| {
                    trace.push((a, b));
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap();
                assert_eq!(actual, expected, "length {length}");
                assert_eq!(trace, old_trace, "comparison schedule at length {length}");
                for pair in actual.windows(2) {
                    if values[pair[0]] == values[pair[1]] {
                        assert!(pair[0] < pair[1], "equal elements remain stable");
                    }
                }
            }
        }
    }

    #[test]
    fn a_throw_stops_at_the_same_comparison_without_modifying_values() {
        let values = [9, 2, 7, 3, 1, 8, 4, 0, 6, 5];
        for fail_at in 0..40 {
            let mut old_trace = Vec::new();
            let expected = allocating_reference((0..values.len()).collect(), &mut |a, b| {
                old_trace.push((a, b));
                if old_trace.len() == fail_at { Err(fail_at) }
                else { Ok(values[a].cmp(&values[b])) }
            });
            let mut order: Vec<_> = (0..values.len()).collect();
            let mut scratch = vec![0; values.len()];
            let mut trace = Vec::new();
            let result = stable_order(&mut order, &mut scratch, &mut |a, b| {
                trace.push((a, b));
                if trace.len() == fail_at { Err(fail_at) }
                else { Ok(values[a].cmp(&values[b])) }
            });
            assert_eq!(result.as_ref().err(), expected.as_ref().err());
            if let Ok(expected) = expected { assert_eq!(order, expected); }
            assert_eq!(trace, old_trace);
        }
    }

    #[test]
    fn inconsistent_comparators_keep_the_existing_call_schedule() {
        for length in 2..65 {
            for modulus in 2..9 {
                let mut old_calls = 0;
                let expected = allocating_reference((0..length).collect(), &mut |a, b| {
                    old_calls += 1;
                    Ok::<_, ()>(((a + old_calls) % modulus).cmp(&(b % modulus)))
                }).unwrap();
                let mut order: Vec<_> = (0..length).collect();
                let mut scratch = vec![0; length];
                let mut calls = 0;
                stable_order(&mut order, &mut scratch, &mut |a, b| {
                    calls += 1;
                    Ok::<_, ()>(((a + calls) % modulus).cmp(&(b % modulus)))
                }).unwrap();
                assert_eq!(order, expected);
                assert_eq!(calls, old_calls);
            }
        }
    }

    #[test]
    fn cycle_swaps_apply_destination_to_source_order_without_cloning_payloads() {
        // All permutations up to seven values, including multi-cycle orders.
        fn check(order: &mut [usize], fixed: usize) {
            if fixed != order.len() {
                for index in fixed..order.len() {
                    order.swap(fixed, index);
                    check(order, fixed + 1);
                    order.swap(fixed, index);
                }
                return;
            }
            struct Payload(usize); // Intentionally no Clone or Copy.
            let mut items: Vec<_> = (0..order.len()).map(Payload).collect();
            let mut inverse = vec![0; order.len()];
            let mut steps = 0;
            apply_order(&mut items, order, &mut inverse, &mut || {
                steps += 1;
                Ok::<_, ()>(())
            }).unwrap();
            assert_eq!(items.iter().map(|item| item.0).collect::<Vec<_>>(), order.to_vec());
            assert!(steps <= items.len() + items.len().saturating_sub(1));
        }
        for length in 0..8 { check(&mut (0..length).collect::<Vec<_>>(), 0); }
    }

    #[test]
    fn resource_failure_in_permutation_never_loses_or_duplicates_a_payload() {
        let order = [2, 4, 1, 0, 3];
        for fail_at in 1..11 {
            let mut values = [0, 1, 2, 3, 4];
            let mut inverse = [0; 5];
            let mut steps = 0;
            let result = apply_order(&mut values, &order, &mut inverse, &mut || {
                steps += 1;
                if steps == fail_at { Err(fail_at) } else { Ok(()) }
            });
            if result.is_ok() { assert_eq!(values, order); }
            else { assert_eq!(steps, fail_at); }
            values.sort_unstable();
            assert_eq!(values, [0, 1, 2, 3, 4]);
        }
    }

}
