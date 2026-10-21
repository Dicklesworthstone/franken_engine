use super::*;
use super::super::{InterpreterConfig, InterpreterCore, InterpreterError, Label, RuntimeCapability, Value};

fn core(mut config: InterpreterConfig) -> InterpreterCore {
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch, RuntimeCapability::HeapAllocate, RuntimeCapability::Builtin,
    ].into_iter().collect();
    let mut core = InterpreterCore::new(config, "descending-groups-sort");
    core.json_observe_label(Label::Public).unwrap();
    core
}

fn comparison_count(values: &[i32]) -> usize {
    let mut order: Vec<_> = (0..values.len()).collect();
    let mut calls = 0;
    sort(&mut order, &mut vec![0; values.len() / 2], &mut |a, b| {
        calls += 1;
        Ok::<_, ()>(values[a].cmp(&values[b]))
    }).unwrap();
    calls
}

#[test]
fn whole_descending_groups_use_linear_comparisons_and_bitmap_only_scratch() {
    for length in [256_usize, 257, 319, 320, 513, 4096] {
        for repeat in [2, 3, 31, 32, 63, 64, 128, 2048] {
            let values: Vec<_> = (0..length).map(|i| (length - 1 - i) / repeat).collect();
            let mut order: Vec<_> = (0..length).collect();
            let mut scratch = vec![usize::MAX; length / 2 + 2];
            let mut calls = 0;
            sort(&mut order, &mut scratch[1..1 + length / 2], &mut |a, b| {
                calls += 1;
                Ok::<_, ()>(values[a].cmp(&values[b]))
            }).unwrap();
            let mut expected: Vec<_> = (0..length).collect();
            expected.sort_by_key(|i| values[*i]);
            assert_eq!(order, expected, "length={length}, repeat={repeat}");
            assert!(calls <= length - 1 + (2 * length).div_ceil(gallop::MAX_SPAN));
            let words = (length - 1).div_ceil(BOUNDARY_WORD_BITS);
            assert_eq!(scratch[0], usize::MAX);
            assert!(scratch[1 + words..].iter().all(|word| *word == usize::MAX));
        }
    }
}

#[test]
fn whole_descending_uniform_words_and_tail_boundaries_preserve_ties() {
    let length = MIN_WHOLE_DESCENDING_LENGTH + 2 * BOUNDARY_WORD_BITS + 17;
    for boundary in [1, 2, BOUNDARY_WORD_BITS - 1, BOUNDARY_WORD_BITS,
        BOUNDARY_WORD_BITS + 1, 2 * BOUNDARY_WORD_BITS, length - 2, length - 1]
    {
        for values in [
            (0..length).map(|i| usize::from(i < boundary)).collect::<Vec<_>>(),
            (0..length).map(|i| if i < boundary { length - i } else { length - boundary }).collect(),
            (0..length).map(|i| if i < boundary { length } else { length - i }).collect(),
        ] {
            let mut order: Vec<_> = (0..length).collect();
            let mut expected = order.clone();
            expected.sort_by_key(|i| values[*i]);
            sort(&mut order, &mut vec![0; length / 2], &mut |a, b| {
                Ok::<_, ()>(values[a].cmp(&values[b]))
            }).unwrap();
            assert_eq!(order, expected, "boundary={boundary}");
        }
    }
}

#[test]
fn failed_whole_run_proofs_keep_the_original_first_run_partition() {
    for length in [256_usize, 257, 513, 1024] {
        for repeat in [1, 2, 3, 32, 64] {
            for changed in [2, 31, 63, 64, 127, length - 2, length - 1] {
                let mut values: Vec<_> = (0..length).map(|i| (length - 1 - i) / repeat).collect();
                values[changed] = length + 7;
                let mut original: Vec<_> = (0..length).collect();
                let mut actual = original.clone();
                let expected_len = normalize_run(&mut original, &mut |a, b| {
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap();
                let actual_len = normalize_first_run(&mut actual, &mut vec![0; length / 2], &mut |a, b| {
                    Ok::<_, ()>(values[a].cmp(&values[b]))
                }).unwrap();
                assert_eq!(actual_len, expected_len);
                assert_eq!(actual, original, "{length}/{repeat}/{changed}");
            }
        }
    }
}

#[test]
fn nonidentity_orders_never_acquire_identity_materialization() {
    for length in [256_usize, 257, 513] {
        let values: Vec<_> = (0..length).map(|i| (length - 1 - i) / 3).collect();
        for changed in [0, 1, 2, 31, 63, 64, length - 2] {
            let mut actual: Vec<_> = (0..length).collect();
            actual.swap(changed, changed + 1);
            let mut expected = actual.clone();
            expected.sort_by_key(|i| values[*i]);
            sort(&mut actual, &mut vec![0; length / 2], &mut |a, b| {
                Ok::<_, ()>(values[a].cmp(&values[b]))
            }).unwrap();
            // Stability means original INPUT order, not ascending source IDs.
            assert_eq!(actual, expected, "{length}/{changed}");
        }
    }
}

#[test]
fn whole_descending_proof_and_emission_refuse_at_every_comparison() {
    for length in [256_usize, 257, 513] {
        let values: Vec<_> = (0..length).map(|i| (length - 1 - i) / 3).collect();
        let mut sorted: Vec<_> = (0..length).collect();
        let mut comparisons = 0;
        sort(&mut sorted, &mut vec![0; length / 2], &mut |a, b| {
            comparisons += 1;
            Ok::<_, usize>(values[a].cmp(&values[b]))
        }).unwrap();
        for fail_at in 1..=comparisons {
            let mut order: Vec<_> = (0..length).collect();
            let mut scratch = vec![usize::MAX; length / 2 + 2];
            let mut calls = 0;
            let result = sort(&mut order, &mut scratch[1..1 + length / 2], &mut |a, b| {
                calls += 1;
                if calls == fail_at { Err(calls) } else { Ok(values[a].cmp(&values[b])) }
            });
            assert_eq!(result, Err(fail_at));
            assert_eq!(calls, fail_at);
            if fail_at < length {
                assert_eq!(order, (0..length).collect::<Vec<_>>(), "proof must be read-only");
            }
            assert_eq!(scratch[0], usize::MAX);
            assert_eq!(*scratch.last().unwrap(), usize::MAX);
        }
    }
}

#[test]
fn whole_descending_utf16_groups_keep_exact_units_and_equal_identities() {
    use crate::js_string::JsString;

    let groups = ["a", "é", "😀", "\u{e000}", "\u{fffd}"];
    let mut keys: Vec<_> = groups.iter().map(|key| JsString::from(*key)).collect();
    keys.extend([JsString::from_code_units(&[0xd800]), JsString::from_code_units(&[0xdc00])]);
    keys.sort_by(|left, right| right.utf16_cmp(left));
    let values: Vec<_> = keys.into_iter().flat_map(|key| std::iter::repeat_n(key, 65)).collect();
    let mut order: Vec<_> = (0..values.len()).collect();
    let mut expected = order.clone();
    expected.sort_by(|left, right| values[*left].utf16_cmp(&values[*right]));
    sort(&mut order, &mut vec![0; values.len() / 2], &mut |left, right| {
        Ok::<_, ()>(values[left].utf16_cmp(&values[right]))
    }).unwrap();
    assert_eq!(order, expected);
}

#[test]
fn native_descending_groups_keep_equal_primitive_types_and_secret_context() {
    let length = 1024;
    let keys: Vec<_> = (0..length).map(|i| 1000 + ((length - 1 - i) / 4) as i64).collect();
    for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        let mut core = core(config);
        let mut items: Vec<_> = keys.iter().enumerate().map(|(i, key)| {
            if i % 2 == 0 { Value::Int(*key) } else { Value::Str(key.to_string().into()) }
        }).collect();
        let mut indices: Vec<_> = (0..length).collect();
        indices.sort_by_key(|i| keys[*i]);
        let expected: Vec<_> = indices.into_iter().map(|i| items[i].clone()).collect();
        core.replace_pending_hostcall_result_label(Some(Label::Secret)).unwrap();
        core.sort_captured_values(None, &mut items, &Value::Undefined).unwrap();
        assert_eq!(items, expected);
        assert_eq!(core.active_inline_callback_context_label, Some(Label::Secret));
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
    }
}

#[test]
fn native_bitmap_emission_budget_refusals_never_publish_partial_values() {
    let length = 513;
    let values: Vec<i32> = (0..length).map(|i| 1000 + (length - 1 - i) / 3).collect();
    let comparisons = comparison_count(&values);
    for config in [InterpreterConfig::quickjs_defaults(), InterpreterConfig::v8_defaults()] {
        for compared in [0, 1, values.len() - 2, values.len() - 1, comparisons - 2, comparisons - 1] {
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
