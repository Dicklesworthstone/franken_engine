use super::*;
use super::super::{InterpreterConfig, InterpreterCore, InterpreterError, Label, RuntimeCapability, Value};

fn ordered(values: &[i32]) -> (Vec<usize>, usize) {
    let mut order: Vec<_> = (0..values.len()).collect();
    let mut canaries = vec![usize::MAX; values.len() / 2 + 2];
    let mut calls = 0;
    sort(&mut order, &mut canaries[1..1 + values.len() / 2], &mut |a, b| {
        calls += 1;
        Ok::<_, ()>(values[a].cmp(&values[b]))
    }).unwrap();
    assert_eq!(canaries[0], usize::MAX);
    assert_eq!(*canaries.last().unwrap(), usize::MAX);
    let mut expected: Vec<_> = (0..values.len()).collect();
    expected.sort_by_key(|index| values[*index]);
    assert_eq!(order, expected, "values={values:?}");
    (order, calls)
}

#[test]
fn every_small_duplicate_pattern_keeps_original_equal_identities() {
    for length in 0..=8_u32 {
        for mut code in 0..3_usize.pow(length) {
            let values: Vec<_> = (0..length).map(|_| {
                let value = (code % 3) as i32;
                code /= 3;
                value
            }).collect();
            ordered(&values);
        }
    }
}

#[test]
fn unequal_adjacent_runs_use_only_the_smaller_scratch_in_both_directions() {
    for left in 1..24 {
        for right in 1..24 {
            for repeats in [1, 2, 7] {
                let values: Vec<_> = (0..left).map(|i| (i / repeats) as i32)
                    .chain((0..right).map(|i| (i / repeats) as i32 - 3)).collect();
                let mut order: Vec<_> = (0..values.len()).collect();
                let mut scratch = vec![usize::MAX; left.min(right) + 2];
                merge(&mut order, left, &mut scratch[1..1 + left.min(right)], &mut |a, b| {
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap();
                let mut expected: Vec<_> = (0..values.len()).collect();
                expected.sort_by_key(|i| values[*i]);
                assert_eq!(order, expected, "left={left} right={right} repeats={repeats}");
                assert_eq!(scratch[0], usize::MAX);
                assert_eq!(*scratch.last().unwrap(), usize::MAX);
            }
        }
    }
}

#[test]
fn generated_runs_and_skewed_length_classes_match_the_stable_oracle() {
    let mut seed = 0x0000_0005_21ad_2026_u64;
    for length in (0..128).chain([255, 256, 257, 1023, 1024, 2049]) {
        for _ in 0..8 {
            let values: Vec<_> = (0..length).map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                ((seed >> 32) % 97) as i32
            }).collect();
            ordered(&values);
        }
    }
    // Descending powers of two fill distinct stack classes; a later large
    // run collapses them all. Repeat and perturb by one around each boundary.
    for delta in [0, 1] {
        let mut values = Vec::new();
        for power in (1..16).rev().chain(1..16) {
            let length = (1 << power) + delta;
            values.extend(0..length);
        }
        ordered(&values);
    }
}

#[test]
fn partially_ordered_inputs_do_not_pay_for_full_recursive_sorting() {
    let length = 8192;
    for values in [
        (1..length).chain([0]).collect::<Vec<i32>>(),
        (2048..length).chain(0..2048).collect(),
        (0..8).rev().flat_map(|block| (block * 1024)..((block + 1) * 1024)).collect(),
    ] {
        let (_, calls) = ordered(&values);
        let mut reference: Vec<_> = (0..values.len()).collect();
        let mut reference_calls = 0;
        super::super::stable_order(&mut reference, &mut vec![0; values.len() / 2], &mut |a, b| {
            reference_calls += 1;
            Ok::<_, ()>(values[a].cmp(&values[b]))
        }).unwrap();
        assert!(calls < 3 * values.len(), "{calls} adaptive comparisons");
        assert!(2 * calls < reference_calls, "{calls} vs {reference_calls}");
    }
    for length in [0, 1, 2, 31, 4096] {
        for values in [
            (0..length).collect::<Vec<_>>(),
            (0..length).rev().collect(),
            (0..length).map(|index| index / 3).collect(),
        ] {
            assert_eq!(ordered(&values).1, values.len().saturating_sub(1));
        }
    }
}

#[test]
fn every_comparison_refusal_stops_immediately_without_touching_payloads() {
    let values = [6, 4, 4, 2, 9, 8, 3, 1, 7, 0, 5];
    let calls = ordered(&values).1;
    for fail_at in 1..=calls {
        let mut order: Vec<_> = (0..values.len()).collect();
        let mut scratch = vec![usize::MAX; values.len() / 2 + 2];
        let mut calls = 0;
        let result = sort(&mut order, &mut scratch[1..1 + values.len() / 2], &mut |a, b| {
            calls += 1;
            if calls == fail_at { Err(fail_at) } else { Ok(values[a].cmp(&values[b])) }
        });
        assert_eq!(result, Err(fail_at));
        assert_eq!(calls, fail_at);
        assert_eq!(scratch[0], usize::MAX);
        assert_eq!(*scratch.last().unwrap(), usize::MAX);
        assert_eq!(values, [6, 4, 4, 2, 9, 8, 3, 1, 7, 0, 5]);
    }
}

fn core(mut config: InterpreterConfig) -> InterpreterCore {
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate, RuntimeCapability::Builtin,
    ].into_iter().collect();
    let mut core = InterpreterCore::new(config, "adaptive-sort");
    core.json_observe_label(Label::Public).unwrap();
    core
}

#[test]
fn native_partial_runs_keep_provenance_and_release_existing_scratch_in_both_profiles() {
    for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        let mut core = core(config);
        let mut items: Vec<_> = (2000..5000).chain(1000..2000).map(Value::Int).collect();
        core.replace_pending_hostcall_result_label(Some(Label::Secret)).unwrap();
        let before = core.native_hole_reads.get();
        core.sort_captured_values(None, &mut items, &Value::Undefined).unwrap();
        assert_eq!(items, (1000..5000).map(Value::Int).collect::<Vec<_>>());
        assert!(core.native_hole_reads.get() - before < 6 * items.len() as u64);
        assert_eq!(core.active_inline_callback_context_label, Some(Label::Secret));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}

#[test]
fn native_refusal_during_a_merge_never_publishes_partial_sorting() {
    let values = [1004, 1005, 1006, 1000, 1001, 1002, 1003];
    let comparisons = ordered(&values).1;
    for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        for compared in 0..comparisons {
            let mut core = core(config.clone());
            let original: Vec<_> = values.iter().map(|value| Value::Int(i64::from(*value))).collect();
            let mut items = original.clone();
            let before = core.native_hole_reads.get();
            core.config.instruction_budget = core.instructions_executed + before
                + items.len() as u64 + compared as u64;
            assert!(matches!(core.sort_captured_values(None, &mut items, &Value::Undefined),
                Err(InterpreterError::BudgetExhausted { .. })));
            assert_eq!(items, original);
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }
}

#[test]
fn galloping_merges_preserve_ties_and_bound_scratch_on_long_runs() {
    for left in [7, 8, 9, 31, 255, 256, 257, 511, 1024] {
        for right in [7, 8, 9, 31, 255, 256, 257, 511, 1024] {
            for pattern in 0..4 {
                let values: Vec<i32> = match pattern {
                    0 => (0..left).map(|i| i as i32)
                        .chain((0..right).map(|i| i as i32 - right as i32)).collect(),
                    1 => (0..left).map(|i| (i / 8) as i32)
                        .chain((0..right).map(|i| (i / 8) as i32 - 1)).collect(),
                    2 => (0..left).map(|i| (2 * i) as i32)
                        .chain((0..right).map(|i| (2 * i + 1) as i32)).collect(),
                    _ => std::iter::repeat_n(0, left - 1).chain([2, -1])
                        .chain(std::iter::repeat_n(0, right - 1)).collect(),
                };
                let mut order: Vec<_> = (0..values.len()).collect();
                let mut scratch = vec![usize::MAX; left.min(right) + 2];
                merge(&mut order, left, &mut scratch[1..1 + left.min(right)], &mut |a, b| {
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap();
                let mut expected: Vec<_> = (0..values.len()).collect();
                expected.sort_by_key(|index| values[*index]);
                assert_eq!(order, expected, "{left}/{right}/{pattern}");
                assert_eq!(scratch[0], usize::MAX);
                assert_eq!(*scratch.last().unwrap(), usize::MAX);
            }
        }
    }
}

#[test]
fn disjoint_run_blocks_need_fewer_comparisons_than_scalar_merging() {
    for left in [1, 1024, 4096, 8191] {
        let right = 8192 - left;
        let values: Vec<i32> = (right as i32..8192).chain(0..right as i32).collect();
        let mut order: Vec<_> = (0..values.len()).collect();
        let mut calls = 0;
        merge(&mut order, left, &mut vec![0; left.min(right)], &mut |a, b| {
            calls += 1;
            Ok::<_, ()>(values[a].cmp(&values[b]))
        }).unwrap();
        assert_eq!(order, (left..8192).chain(0..left).collect::<Vec<_>>());
        // Both move directions still copy the same indices. Galloping saves
        // expensive key comparisons; it does not claim sublinear byte moves.
        assert!(calls < 1 + left.max(right) / 8, "{calls} calls for {left}/{right}");
    }
}

#[test]
fn native_budget_refusal_inside_bulk_merge_releases_all_sort_scratch() {
    let values: Vec<i32> = (1001..1513).chain([1000]).collect();
    let comparisons = ordered(&values).1;
    for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        // The first n-1 comparisons discover the runs. Exercise every
        // subsequent comparison, including exponential and binary probes.
        for compared in values.len() - 1..comparisons {
            let mut core = core(config.clone());
            let original: Vec<_> = values.iter().map(|value| Value::Int(i64::from(*value))).collect();
            let mut items = original.clone();
            core.config.instruction_budget = core.instructions_executed
                + core.native_hole_reads.get() + items.len() as u64 + compared as u64;
            assert!(matches!(core.sort_captured_values(None, &mut items, &Value::Undefined),
                Err(InterpreterError::BudgetExhausted { .. })));
            assert_eq!(items, original);
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }
}

#[test]
fn narrow_overlap_moves_only_the_active_window_in_both_merge_directions() {
    let middle = 4096;
    for backward in [false, true] {
        let mut values: Vec<i32> = (0..8192).collect();
        if backward {
            // Leave two left keys above the first right key, including a tie
            // with the settled prefix. The right scratch run has one key.
            values[middle] = middle as i32 - 3;
        } else {
            values.swap(middle - 1, middle);
        }
        let original: Vec<_> = (0..values.len()).collect();
        let (start, end) = overlap_bounds(&original, middle, &mut |a, b| {
            Ok::<_, ()>(values[a].cmp(&values[b]))
        })
        .unwrap();
        assert_eq!(middle - start, if backward { 2 } else { 1 });
        assert_eq!(end - middle, 1);
        let mut order = original.clone();
        let mut scratch = vec![usize::MAX; middle + 2];
        let mut calls = 0;
        merge(&mut order, middle, &mut scratch[1..=middle], &mut |a, b| {
            calls += 1;
            Ok::<_, ()>(values[a].cmp(&values[b]))
        })
        .unwrap();
        let mut expected = original.clone();
        expected.sort_by_key(|index| values[*index]);
        assert_eq!(order, expected);
        assert_eq!(order[..start], original[..start]);
        assert_eq!(order[end..], original[end..]);
        assert_eq!(scratch[0], usize::MAX);
        assert_ne!(scratch[1], usize::MAX);
        assert!(scratch[2..].iter().all(|slot| *slot == usize::MAX));
        assert!(calls < 128, "{calls} comparisons for a narrow overlap");
    }
}

#[test]
fn overlap_bounds_match_stable_linear_bounds_for_unequal_duplicate_runs() {
    for left in [1, 2, 7, 127, 128, 129, 255, 256, 257, 1024] {
        for right in [1, 2, 7, 127, 128, 129, 255, 256, 257, 1024] {
            for repeats in [1, 2, 8] {
                let shift = (left / (2 * repeats)) as i32 - 1;
                let values: Vec<i32> = (0..left)
                    .map(|i| (i / repeats) as i32)
                    .chain((0..right).map(|i| (i / repeats) as i32 + shift))
                    .collect();
                let mut order: Vec<_> = (0..values.len()).collect();
                let (start, end) = overlap_bounds(&order, left, &mut |a, b| {
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                })
                .unwrap();
                let prefix = values[..left]
                    .iter()
                    .take_while(|key| **key <= values[left])
                    .count();
                let suffix = values[left..]
                    .iter()
                    .rev()
                    .take_while(|key| **key >= values[left - 1])
                    .count();
                assert_eq!((start, end), (prefix, values.len() - suffix));
                assert!(start < left && left < end);
                let mut scratch = vec![usize::MAX; left.min(right) + 2];
                merge(&mut order, left, &mut scratch[1..1 + left.min(right)], &mut |a, b| {
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                })
                .unwrap();
                let mut expected: Vec<_> = (0..values.len()).collect();
                expected.sort_by_key(|index| values[*index]);
                assert_eq!(order, expected);
                assert_eq!(scratch[0], usize::MAX);
                assert_eq!(*scratch.last().unwrap(), usize::MAX);
            }
        }
    }
}

#[test]
fn refusal_at_any_overlap_probe_precedes_all_index_and_scratch_writes() {
    let middle = 512;
    let mut values: Vec<i32> = (0..1024).collect();
    values.swap(middle - 1, middle);
    let original: Vec<_> = (0..values.len()).collect();
    let mut probes = 0;
    overlap_bounds(&original, middle, &mut |a, b| {
        probes += 1;
        Ok::<_, usize>(values[a].cmp(&values[b]))
    })
    .unwrap();
    // Include the comparison proving that the two runs actually cross.
    for fail_at in 1..=probes + 1 {
        let mut order = original.clone();
        let mut scratch = vec![usize::MAX; middle];
        let mut seen = 0;
        let result = merge(&mut order, middle, &mut scratch, &mut |a, b| {
            seen += 1;
            if seen == fail_at {
                Err(seen)
            } else {
                Ok(values[a].cmp(&values[b]))
            }
        });
        assert_eq!(result, Err(fail_at));
        assert_eq!(seen, fail_at);
        assert_eq!(order, original);
        assert!(scratch.iter().all(|slot| *slot == usize::MAX));
    }
}

#[test]
fn trimmed_sort_keeps_exact_utf16_order_and_equal_key_identities() {
    use crate::js_string::JsString;

    let alphabet = [
        vec![0x0061],
        vec![0x00e9],
        vec![0xd800],
        vec![0xd83d, 0xde00],
        vec![0xdc00],
        vec![0xfffd],
    ];
    let units: Vec<_> = alphabet[..5]
        .iter()
        .chain(alphabet[2..].iter())
        .flat_map(|key| std::iter::repeat_n(key.clone(), 96))
        .collect();
    let keys: Vec<_> = units.iter().map(|key| JsString::from_code_units(key)).collect();
    let mut order: Vec<_> = (0..keys.len()).collect();
    let mut expected = order.clone();
    expected.sort_by_key(|index| &units[*index]);
    sort(&mut order, &mut vec![0; keys.len() / 2], &mut |a, b| {
        Ok::<_, ()>(keys[a].utf16_cmp(&keys[b]))
    })
    .unwrap();
    assert_eq!(order, expected);
}

#[test]
fn native_overlap_trimming_preserves_provenance_and_accounting() {
    for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        let mut core = core(config);
        let mut items: Vec<_> = (1000..1512).map(Value::Int).collect();
        items.swap(255, 256);
        core.replace_pending_hostcall_result_label(Some(Label::Secret)).unwrap();
        core.sort_captured_values(None, &mut items, &Value::Undefined).unwrap();
        assert_eq!(items, (1000..1512).map(Value::Int).collect::<Vec<_>>());
        assert_eq!(core.active_inline_callback_context_label, Some(Label::Secret));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}

#[test]
fn native_refusal_at_every_trimmed_merge_probe_never_publishes_values() {
    // Four-digit integer keys have the same numeric and default UTF-16 order.
    let mut values: Vec<i32> = (1000..1512).collect();
    values.swap(255, 256);
    let comparisons = ordered(&values).1;
    for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        for compared in values.len() - 1..comparisons {
            let mut core = core(config.clone());
            let original: Vec<_> = values.iter().map(|value| Value::Int(i64::from(*value))).collect();
            let mut items = original.clone();
            core.config.instruction_budget = core.instructions_executed
                + core.native_hole_reads.get() + items.len() as u64 + compared as u64;
            assert!(matches!(core.sort_captured_values(None, &mut items, &Value::Undefined),
                Err(InterpreterError::BudgetExhausted { .. })));
            assert_eq!(items, original);
            assert_eq!(core.json_parse_temporary_bytes, 0);
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }
}
