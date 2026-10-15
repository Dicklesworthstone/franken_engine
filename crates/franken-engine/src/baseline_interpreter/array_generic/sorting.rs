//! Callback-safe stable sorting with fixed, metered native scratch storage.
//!
//! Sort indices, not Value payloads. The top-down split and merge decisions
//! intentionally match the previous allocating merge sort, including equality
//! and the point where a comparator throws. No comparison result is cached:
//! callbacks may mutate the objects held by later comparisons. Only default
//! sorting of immutable primitive keys may discover and merge natural runs.

use super::*;

mod adaptive;
mod primitive;
mod sparse;

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
        // Immutable flat primitives need no new heap-backed sort keys. Rope
        // traversal and every observable conversion retain the admitted path
        // below. CompareArrayElements still owns undefined ordering and fuel.
        if let Some(ordering) = primitive::compare(&left, &right) {
            self.observe_scoped_callback_result()?;
            return Ok(ordering);
        }
        let left = self.sort_string_key_coerced(module, left)?;
        let left_bytes = Self::estimate_value_bytes(&Value::Str(left.clone()));
        self.json_reserve_temporary(left_bytes)?;
        let outcome = (|| {
            let right = self.sort_string_key_coerced(module, right)?;
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

    fn sort_string_key_coerced(
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
            let indices = if in_place {
                self.sparse_sort_indices(object, 0, len, true, &mut retained)?
            } else {
                None
            };
            let reads = indices.as_ref().map_or(len, |indices| indices.len() as u64);
            for step in 0..reads {
                let index = indices.as_ref().map_or(step, |indices| u64::from(indices[step as usize]));
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
            if let Some(indices) = indices {
                let bytes = buffer_bytes::<u32>(indices.capacity());
                drop(indices);
                self.json_release_temporary(bytes);
                retained -= bytes;
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
                // A comparator or prefix setter may have added tail properties.
                // Enumerate AFTER every write, never from the capture snapshot.
                let from = items.len() as u64;
                let indices = self.sparse_sort_indices(object, from, len, false, &mut retained)?;
                let deletes = indices.as_ref().map_or(len.saturating_sub(from), |indices| indices.len() as u64);
                for step in 0..deletes {
                    let index = indices.as_ref().map_or(from + step, |indices| u64::from(indices[step as usize]));
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
        // Half-size scratch suffices: the callback path saves its left half,
        // and the adaptive path saves the smaller adjacent run. The
        // destination permutation needs no inverse buffer.
        let scratch_len = items.len() / 2;
        let mut reserved = buffer_bytes::<usize>(items.len())
            .saturating_add(buffer_bytes::<usize>(scratch_len));
        self.json_reserve_temporary(reserved)?;
        let mut order = Vec::new();
        let mut scratch = Vec::new();
        let outcome = (|| {
            order.try_reserve_exact(items.len()).map_err(|_| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            scratch.try_reserve_exact(scratch_len).map_err(|_| {
                self.memory_budget_error(u64::MAX, self.heap_object_count_u32())
            })?;
            let actual = buffer_bytes::<usize>(order.capacity())
                .saturating_add(buffer_bytes::<usize>(scratch.capacity()));
            if actual > reserved {
                self.json_reserve_temporary(actual - reserved)?;
                reserved = actual;
            }
            // Classify while doing the already-metered index initialization.
            // A late object/Symbol/rope must veto the entire probe: even an
            // early comparison can invoke observable conversion on fallback.
            let mut primitive_only = matches!(comparator, Value::Undefined);
            for (index, value) in items.iter().enumerate() {
                self.charge_native_hole_read()?;
                primitive_only = primitive_only && immutable_sort_primitive(value);
                order.push(index);
                if index < scratch_len {
                    scratch.push(0);
                }
            }
            {
                let mut compare = |left: usize, right: usize| {
                    let ordering = self.generic_sort_compare(
                        module, items[left].clone(), items[right].clone(), comparator,
                    )?;
                    self.observe_scoped_callback_result()?;
                    Ok::<_, InterpreterError>(ordering)
                };
                if primitive_only {
                    adaptive::sort(&mut order, &mut scratch, &mut compare)?;
                } else {
                    stable_order(&mut order, &mut scratch, &mut compare)?;
                }
            }
            apply_order(items, &mut order, &mut || self.charge_native_hole_read())?;
            Ok(())
        })();
        drop(order);
        drop(scratch);
        self.json_release_temporary(reserved);
        outcome
    }
}

/// These keys cannot execute guest code or change between comparisons. Keep
/// the same flat-string boundary as primitive::compare: ropes retain their
/// general scratch admission, and Symbols retain their observable throw point.
/// In particular, an object that usually converts to a number is not eligible.
fn immutable_sort_primitive(value: &Value) -> bool {
    match value {
        Value::Str(text) => text.concat_parts().nodes == 0,
        Value::Undefined | Value::Null | Value::Bool(_) | Value::Int(_)
        | Value::Float(_) | Value::BigInt(_) => true,
        _ => false,
    }
}

/// Prove one whole monotone run using n-1 metered comparisons. The caller
/// must first prove that comparisons have no guest-observable side effects.
/// Nondecreasing runs preserve ties as-is; descending runs must be STRICT,
/// since reversing a run containing equal keys would violate sort stability.
/// A miss or comparison error leaves every index untouched for the original
/// merge path or common cleanup. Reverse only after the complete proof.
#[cfg(test)]
fn monotone_order<E>(
    order: &mut [usize],
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<bool, E> {
    if order.len() < 2 {
        return Ok(true);
    }
    let descending = compare(order[0], order[1])? == Ordering::Greater;
    for pair in order[1..].windows(2) {
        let ordering = compare(pair[0], pair[1])?;
        let continues = if descending {
            ordering == Ordering::Greater
        } else {
            ordering != Ordering::Greater
        };
        if !continues {
            return Ok(false);
        }
    }
    if descending {
        order.reverse();
    }
    Ok(true)
}

/// Consume destination->source order by following each cycle, without an
/// inverse allocation or payload clones. Every finished cycle becomes the
/// identity permutation. Charge once per destination and once per swap, as
/// before; completed swaps conserve all payloads even if the next tick fails.
/// The caller has not published this private capture buffer to the receiver.
fn apply_order<T, E>(
    items: &mut [T],
    order: &mut [usize],
    tick: &mut impl FnMut() -> Result<(), E>,
) -> Result<(), E> {
    debug_assert_eq!(items.len(), order.len());
    for start in 0..items.len() {
        tick()?;
        let mut current = start;
        loop {
            let source = order[current];
            if source == start {
                order[current] = current;
                break;
            }
            tick()?;
            items.swap(current, source);
            order[current] = current;
            current = source;
        }
    }
    Ok(())
}

fn buffer_bytes<T>(capacity: usize) -> u64 {
    u64::try_from(capacity)
        .unwrap_or(u64::MAX)
        .saturating_mul(std::mem::size_of::<T>() as u64)
}

/// Stable top-down merges using at most floor(order.len() / 2) scratch
/// indices. Save only the left run: while it has unread entries, output is
/// strictly before the unread right cursor, so copying right entries forward
/// cannot overwrite them. Once the left run is exhausted the remaining right
/// suffix is already in place. Both recursive children reuse the same scratch.
///
/// Split points, comparison operands, equality handling and throw points are
/// unchanged, even for stateful or inconsistent guest comparators. No Value
/// moves during comparisons. Each comparison is metered by the caller, and
/// recursion depth is bounded by usize's bit width.
fn stable_order<E>(
    order: &mut [usize],
    scratch: &mut [usize],
    compare: &mut impl FnMut(usize, usize) -> Result<Ordering, E>,
) -> Result<(), E> {
    if order.len() < 2 {
        return Ok(());
    }
    let middle = order.len() / 2;
    debug_assert!(scratch.len() >= middle);
    let (left, right) = order.split_at_mut(middle);
    stable_order(left, scratch, compare)?;
    stable_order(right, scratch, compare)?;
    scratch[..middle].copy_from_slice(&order[..middle]);
    let (mut left, mut right, mut output) = (0, middle, 0);
    while left < middle && right < order.len() {
        debug_assert!(output < right);
        if compare(scratch[left], order[right])? == Ordering::Greater {
            order[output] = order[right];
            right += 1;
        } else {
            order[output] = scratch[left];
            left += 1;
        }
        output += 1;
    }
    // If left is exhausted, output == right and this copy is empty. Otherwise
    // right reached the end and only the saved left suffix needs restoring.
    order[output..right].copy_from_slice(&scratch[left..middle]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        InterpreterConfig, InterpreterCore, InterpreterError, JsString, Label,
        ObjectId, RuntimeCapability, Value, apply_order, immutable_sort_primitive,
        monotone_order, stable_order,
    };
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
                let mut scratch = vec![0; length / 2];
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
            let mut scratch = vec![0; values.len() / 2];
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
                let mut old_trace = Vec::new();
                let expected = allocating_reference((0..length).collect(), &mut |a, b| {
                    old_calls += 1;
                    old_trace.push((a, b));
                    Ok::<_, ()>(((a + old_calls) % modulus).cmp(&(b % modulus)))
                }).unwrap();
                let mut order: Vec<_> = (0..length).collect();
                let mut scratch = vec![0; length / 2];
                let mut calls = 0;
                let mut trace = Vec::new();
                stable_order(&mut order, &mut scratch, &mut |a, b| {
                    calls += 1;
                    trace.push((a, b));
                    Ok::<_, ()>(((a + calls) % modulus).cmp(&(b % modulus)))
                }).unwrap();
                assert_eq!(order, expected);
                assert_eq!(calls, old_calls);
                assert_eq!(trace, old_trace);
            }
        }
    }

    fn reference_permutation_steps(order: &[usize]) -> usize {
        let mut inverse = vec![0; order.len()];
        let mut steps = 0;
        for (destination, &source) in order.iter().enumerate() {
            steps += 1;
            inverse[source] = destination;
        }
        for start in 0..order.len() {
            while inverse[start] != start {
                steps += 1;
                let target = inverse[start];
                inverse.swap(start, target);
            }
        }
        steps
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
            let mut remaining = order.to_vec();
            let mut steps = 0;
            apply_order(&mut items, &mut remaining, &mut || {
                steps += 1;
                Ok::<_, ()>(())
            }).unwrap();
            assert_eq!(items.iter().map(|item| item.0).collect::<Vec<_>>(), order.to_vec());
            assert_eq!(remaining, (0..order.len()).collect::<Vec<_>>());
            assert_eq!(steps, reference_permutation_steps(order));
            assert!(steps <= items.len() + items.len().saturating_sub(1));
        }
        for length in 0..8 { check(&mut (0..length).collect::<Vec<_>>(), 0); }
    }

    #[test]
    fn resource_failure_in_permutation_never_loses_or_duplicates_a_payload() {
        let order = [2, 4, 1, 0, 3];
        for fail_at in 1..11 {
            let mut values = [0, 1, 2, 3, 4];
            let mut remaining = order;
            let mut steps = 0;
            let result = apply_order(&mut values, &mut remaining, &mut || {
                steps += 1;
                if steps == fail_at { Err(fail_at) } else { Ok(()) }
            });
            if result.is_ok() { assert_eq!(values, order); }
            else { assert_eq!(steps, fail_at); }
            values.sort_unstable();
            assert_eq!(values, [0, 1, 2, 3, 4]);
        }
    }

    #[test]
    fn merges_touch_only_the_left_half_scratch_at_power_of_two_boundaries() {
        for length in [2, 3, 4, 5, 15, 16, 17, 63, 64, 65, 255, 256, 257, 1023] {
            for pattern in 0..4 {
                let values: Vec<_> = (0..length).map(|index| match pattern {
                    0 => index,
                    1 => length - index,
                    2 => index % 3,
                    _ => (index * 17) % 31,
                }).collect();
                let mut order: Vec<_> = (0..length).collect();
                let mut storage = vec![usize::MAX; length / 2 + 2];
                let (canary, rest) = storage.split_at_mut(1);
                let (scratch, tail) = rest.split_at_mut(length / 2);
                stable_order(&mut order, scratch, &mut |a, b| {
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap();
                assert_eq!(canary, &[usize::MAX]);
                assert_eq!(tail, &[usize::MAX]);
                let mut expected: Vec<_> = (0..length).collect();
                expected.sort_by_key(|index| values[*index]);
                assert_eq!(order, expected);
            }
        }
    }

    #[test]
    fn permutation_refusal_preserves_nonclone_payload_ownership() {
        use std::cell::Cell;
        use std::rc::Rc;

        struct Payload(usize, Rc<Cell<usize>>);
        impl Drop for Payload {
            fn drop(&mut self) {
                self.1.set(self.1.get() + 1);
            }
        }
        let original = [3, 0, 5, 1, 2, 4];
        let total = reference_permutation_steps(&original);
        for fail_at in 1..=total + 1 {
            let drops: Vec<_> = (0..original.len()).map(|_| Rc::new(Cell::new(0))).collect();
            let mut items: Vec<_> = drops.iter().enumerate()
                .map(|(index, count)| Payload(index, Rc::clone(count))).collect();
            let mut order = original;
            let mut steps = 0;
            let result = apply_order(&mut items, &mut order, &mut || {
                steps += 1;
                if steps == fail_at { Err(()) } else { Ok(()) }
            });
            assert_eq!(result.is_ok(), fail_at > total);
            assert!(drops.iter().all(|count| count.get() == 0));
            if result.is_ok() {
                assert_eq!(items.iter().map(|item| item.0).collect::<Vec<_>>(), original);
            }
            let mut identities: Vec<_> = items.iter().map(|item| item.0).collect();
            identities.sort_unstable();
            assert_eq!(identities, (0..original.len()).collect::<Vec<_>>());
            drop(items);
            assert!(drops.iter().all(|count| count.get() == 1));
        }
    }

    #[test]
    fn monotone_runs_need_one_comparison_per_adjacent_pair() {
        for length in [0, 1, 2, 3, 16, 17, 255, 256, 257, 1024] {
            for pattern in 0..3 {
                let values: Vec<_> = (0..length).map(|index| match pattern {
                    0 => index,
                    1 => length - index,
                    _ => index / 3,
                }).collect();
                let mut order: Vec<_> = (0..length).collect();
                let mut calls = 0;
                assert!(monotone_order(&mut order, &mut |a, b| {
                    calls += 1;
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap());
                let mut expected: Vec<_> = (0..length).collect();
                expected.sort_by_key(|index| values[*index]);
                assert_eq!(order, expected);
                assert_eq!(calls, length.saturating_sub(1));
            }
        }
    }

    #[test]
    fn descending_ties_and_disordered_runs_keep_the_stable_fallback() {
        for values in [
            vec![3, 2, 2, 1], vec![4, 3, 2, 2], vec![1, 1, 0],
            vec![0, 1, 0], vec![3, 1, 2], vec![0, 1, 2, 3, 2],
        ] {
            let original: Vec<_> = (0..values.len()).collect();
            let mut order = original.clone();
            assert!(!monotone_order(&mut order, &mut |a, b| {
                Ok::<_, ()>(values[a].cmp(&values[b]))
            }).unwrap());
            assert_eq!(order, original, "failed proof must not permute indices");
            stable_order(&mut order, &mut vec![0; values.len() / 2], &mut |a, b| {
                Ok::<_, ()>(values[a].cmp(&values[b]))
            }).unwrap();
            let mut expected = original;
            expected.sort_by_key(|index| values[*index]);
            assert_eq!(order, expected);
        }
    }

    #[test]
    fn every_probe_refusal_preserves_the_original_index_order() {
        for length in 2..65 {
            for descending in [false, true] {
                for fail_at in 1..length {
                    let original: Vec<_> = (0..length).collect();
                    let mut order = original.clone();
                    let mut calls = 0;
                    let result = monotone_order(&mut order, &mut |a, b| {
                        calls += 1;
                        if calls == fail_at { return Err(fail_at); }
                        Ok(if descending { b.cmp(&a) } else { a.cmp(&b) })
                    });
                    assert_eq!(result, Err(fail_at));
                    assert_eq!(calls, fail_at);
                    assert_eq!(order, original);
                }
            }
        }
    }

    #[test]
    fn monotone_eligibility_excludes_every_observable_conversion_carrier() {
        use std::sync::Arc;

        for value in [
            Value::Object(ObjectId(0)), Value::Function(0), Value::Closure(0),
            Value::Iterator(0), Value::Generator(0), Value::Promise(0),
            Value::Accessor { get: None, set: None },
            Value::Str(JsString::from("a".repeat(2048))
                .concat(&JsString::from("b".repeat(2048)))),
        ] {
            assert!(!immutable_sort_primitive(&value));
        }
        for value in [
            Value::Undefined, Value::Null, Value::Bool(true), Value::Bool(false),
            Value::Int(i64::MIN), Value::Float(f64::NAN.into()),
            Value::Float((-0.0).into()), Value::Float(f64::INFINITY.into()),
            Value::BigInt(Arc::from("123456789012345678901234567890")),
            Value::Str(JsString::from("\u{1f600}\u{e000}")),
            Value::Str(JsString::from_code_units(&[0xd800])),
        ] {
            assert!(immutable_sort_primitive(&value));
        }
    }

    fn sort_config(mut config: InterpreterConfig) -> InterpreterConfig {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ].into_iter().collect();
        config
    }

    #[test]
    fn native_default_monotone_sort_has_linear_work_and_releases_scratch() {
        for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
            for descending in [false, true] {
                let mut core = InterpreterCore::new(sort_config(config.clone()), "monotone-sort");
                core.json_observe_label(Label::Public).unwrap();
                // Four-digit decimal spelling preserves the default lexical
                // ordering here; this is NOT a numeric-comparator fast path.
                let expected: Vec<_> = (1000..1257).map(Value::Int).collect();
                let mut items = expected.clone();
                if descending { items.reverse(); }
                let before = core.native_hole_reads.get();
                core.sort_captured_values(None, &mut items, &Value::Undefined).unwrap();
                assert_eq!(items, expected);
                let count = items.len() as u64;
                let swaps = if descending { count / 2 } else { 0 };
                // Index initialization + adjacent comparisons + permutation
                // destinations and swaps all use the real shared work meter.
                assert_eq!(core.native_hole_reads.get() - before, 3 * count - 1 + swaps);
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            }
        }
    }

    #[test]
    fn native_default_sort_preserves_equal_cross_type_keys_and_undefined_tail() {
        for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
            let mut core = InterpreterCore::new(sort_config(config), "monotone-sort-ties");
            core.json_observe_label(Label::Public).unwrap();
            let mut items = vec![
                Value::Undefined, Value::Int(3), Value::Int(2),
                Value::Str(JsString::from("2")), Value::Int(1), Value::Int(10),
            ];
            core.sort_captured_values(None, &mut items, &Value::Undefined).unwrap();
            assert_eq!(items, vec![
                Value::Int(1), Value::Int(10), Value::Int(2),
                Value::Str(JsString::from("2")), Value::Int(3), Value::Undefined,
            ]);
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }

    #[test]
    fn native_probe_budget_refusal_does_not_publish_partial_sorting() {
        for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
            for compared in [0, 1, 63, 255] {
                let mut core = InterpreterCore::new(sort_config(config.clone()), "monotone-sort-budget");
                core.json_observe_label(Label::Public).unwrap();
                let original: Vec<_> = (1000..1257).rev().map(Value::Int).collect();
                let mut items = original.clone();
                let before = core.native_hole_reads.get();
                core.config.instruction_budget = core.instructions_executed + before
                    + items.len() as u64 + compared;
                assert!(matches!(
                    core.sort_captured_values(None, &mut items, &Value::Undefined),
                    Err(InterpreterError::BudgetExhausted { .. })
                ));
                assert_eq!(items, original);
                assert_eq!(core.json_parse_temporary_bytes, 0);
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            }
        }
    }

    #[test]
    fn native_monotone_probe_keeps_pending_callback_provenance() {
        let mut core = InterpreterCore::new(
            sort_config(InterpreterConfig::quickjs_defaults()), "monotone-sort-provenance",
        );
        core.json_observe_label(Label::Public).unwrap();
        core.replace_pending_hostcall_result_label(Some(Label::Secret)).unwrap();
        let mut items = vec![Value::Int(1), Value::Int(2), Value::Int(3)];
        core.sort_captured_values(None, &mut items, &Value::Undefined).unwrap();
        assert_eq!(items, vec![Value::Int(1), Value::Int(2), Value::Int(3)]);
        assert_eq!(core.active_inline_callback_context_label, Some(Label::Secret));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }

}
