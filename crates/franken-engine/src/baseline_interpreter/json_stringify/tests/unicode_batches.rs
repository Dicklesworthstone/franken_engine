//! Compare the production batch writer with scalar push, including partial
//! failures. Host-side algorithm checks are not substitutes for these tests.

use super::*;

fn compare_units(
    input: &[u16],
    prefix: &[u16],
    limit: usize,
    work: u64,
    scratch: Option<u64>,
    cancel: bool,
) {
    let mut actual_core = core();
    let mut expected_core = core();
    let mut actual = StringifyState::default();
    let mut expected = StringifyState::default();
    for &unit in prefix {
        actual.push(&mut actual_core, unit).unwrap();
        expected.push(&mut expected_core, unit).unwrap();
    }
    for core in [&mut actual_core, &mut expected_core] {
        core.config.max_string_size = limit;
        core.config.instruction_budget = core.instructions_executed + work;
        if let Some(bytes) = scratch {
            core.config.max_total_memory_bytes = core.estimated_memory_bytes() + bytes;
        }
        if cancel {
            let token = CancellationToken::new();
            token.cancel();
            core.config.cancellation_token = Some(token);
        }
    }
    let got = actual.units(&mut actual_core, input.iter().copied());
    let want = input
        .iter()
        .try_for_each(|&unit| expected.push(&mut expected_core, unit));
    assert_eq!(format!("{got:?}"), format!("{want:?}"));
    assert_eq!(actual.output, expected.output);
    assert_eq!(actual.projection_bytes, expected.projection_bytes);
    assert_eq!(actual.output.capacity(), expected.output.capacity());
    assert_eq!(actual.charged, expected.charged);
    assert_eq!(
        actual_core.instructions_executed,
        expected_core.instructions_executed
    );
    assert_eq!(
        actual_core.json_parse_temporary_bytes,
        expected_core.json_parse_temporary_bytes
    );
    release_test_state(&mut actual_core, actual);
    release_test_state(&mut expected_core, expected);
}

#[test]
fn unicode_units_preserve_limits_work_and_memory_refusal_prefixes() {
    let inputs = [
        vec![0x61; 520],
        vec![0xe9; 520],
        vec![0x65e5; 520],
        [0xd83d, 0xde00, 0xd800, 0x61, 0xdc00, 0x7ff, 0x800].repeat(80),
    ];
    for prefix_len in [0, 1, 63, 64, 254, 255, 256] {
        let mut prefix = vec![0x61; prefix_len];
        if let Some(last) = prefix.last_mut() {
            *last = 0xd800;
        }
        for input in &inputs {
            for limit in [0, 1, 2, 3, 63, 64, 65, 255, 256, 257, 511, 1024, 4096] {
                compare_units(input, &prefix, limit, 100_000, None, false);
            }
            for work in [0, 1, 2, 8] {
                compare_units(input, &prefix, 4096, work, None, false);
            }
            for scratch in [0, 1, 127, 128, 129, 255, 256, 257, 1024] {
                compare_units(input, &prefix, 4096, 100_000, Some(scratch), false);
            }
            compare_units(input, &prefix, 4096, 100_000, None, true);
        }
    }
}

#[test]
fn mixed_unicode_quotes_preserve_batch_split_surrogates_and_escapes() {
    for position in [0, 1, 62, 63, 64, 126, 127, 254, 255, 256, 511] {
        let mut units = vec![0xe9; position];
        units.extend([0xd83d, 0xde00, 0xd800, 0x22, 0xdc00, 0, 0x5c, 10]);
        units.extend([0x65e5, 0x61, 0xd83d, 0xde00].repeat(150));
        let text = JsString::from_code_units(&units);
        for prefix_len in [0, 1, 255] {
            let prefix = vec![0x61; prefix_len];
            compare_quote(&text, &prefix, 4096, 100_000, None);
            for limit in [position * 2 + 1, position * 2 + 2, position * 2 + 5] {
                compare_quote(&text, &prefix, limit, 100_000, None);
            }
            for work in [0, 1, 2] {
                compare_quote(&text, &prefix, 4096, work, None);
            }
        }
    }
}

#[test]
fn long_unicode_text_uses_the_same_scalar_projection_and_limits() {
    for text in ["é".repeat(400), "日".repeat(400), "a😀é日".repeat(150)] {
        for prefix in [vec![], vec![0xd800], vec![0x61; 255]] {
            for limit in [0, 1, 2, 3, 63, 64, 65, 255, 256, 257, 1024, 4096] {
                compare_text(&text, &prefix, limit, 100_000, None);
            }
            for work in [0, 1, 2, 8] {
                compare_text(&text, &prefix, 4096, work, None);
            }
        }
    }
}

#[test]
fn unicode_batches_use_paid_capacity_without_allocating_scratch() {
    let mut core = core();
    let mut state = StringifyState::default();
    state.push(&mut core, 0xd83d).unwrap();
    let pointer = state.output.as_ptr();
    let capacity = state.output.capacity();
    let charged = state.charged;
    core.config.max_total_memory_bytes = core.estimated_memory_bytes();
    let mut input = vec![0x65e5; capacity - 1];
    input[0] = 0xde00;
    state.units(&mut core, input.into_iter()).unwrap();
    assert_eq!(state.output.len(), capacity);
    assert_eq!(state.output.capacity(), capacity);
    assert_eq!(state.output.as_ptr(), pointer);
    assert_eq!(state.charged, charged);
    assert_eq!(state.projection_bytes, 4 + (capacity - 2) * 3);
    assert!(state.units(&mut core, std::iter::once(0xe9)).is_err());
    assert_eq!(state.output.len(), capacity);
    assert_eq!(state.charged, charged);
    release_test_state(&mut core, state);
}

#[test]
fn streaming_escapes_keep_only_one_fragment_and_stop_at_first_none() {
    use std::cell::Cell;

    let reads = Cell::new(0);
    let mut source = [0xd83d, 0xde00, 0xd800, 0x22].into_iter().inspect(|_| {
        reads.set(reads.get() + 1);
    });
    let mut quoted = output::QuotedUnits::new(&mut source);
    assert_eq!(quoted.next(), Some(0xd83d));
    assert_eq!(reads.get(), 2);
    assert_eq!(quoted.next(), Some(0xde00));
    assert_eq!(reads.get(), 2);
    assert_eq!(quoted.next(), Some(u16::from(b'\\')));
    assert_eq!(reads.get(), 4);
    assert_eq!(
        quoted.by_ref().take(5).collect::<Vec<_>>(),
        "ud800".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(reads.get(), 4);
    assert_eq!(
        quoted.collect::<Vec<_>>(),
        "\\\"".encode_utf16().collect::<Vec<_>>()
    );

    let mut index = 0;
    let source = std::iter::from_fn(|| {
        index += 1;
        match index {
            1 => Some(0xd800),
            2 => None,
            _ => Some(0xdc00),
        }
    });
    let mut quoted = output::QuotedUnits::new(source);
    assert_eq!(
        quoted.by_ref().collect::<Vec<_>>(),
        "\\ud800".encode_utf16().collect::<Vec<_>>()
    );
    assert_eq!(quoted.next(), None);
    assert_eq!(quoted.next(), None);
}

#[test]
fn unit_batches_do_not_read_past_the_scalar_refusal() {
    use std::cell::Cell;

    for work in [0, 1, 2] {
        let mut core = core();
        core.config.instruction_budget = core.instructions_executed + work;
        let mut state = StringifyState::default();
        let reads = Cell::new(0);
        let source = std::iter::repeat_n(0x65e5, 1024).inspect(|_| reads.set(reads.get() + 1));
        let result = state.units(&mut core, source);
        assert!(matches!(
            result,
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert_eq!(reads.get(), state.output.len() + 1);
        release_test_state(&mut core, state);
    }
}

#[test]
fn long_unicode_builtin_keeps_exact_content_and_secret_provenance() {
    let mut core = core();
    let payload = "aé日😀".repeat(300);
    core.seed_register(0, Value::str(payload.clone())).unwrap();
    core.set_register_label(0, Label::Secret).unwrap();
    assert_eq!(
        stringify(&mut core).unwrap(),
        Value::str(format!("\"{payload}\""))
    );
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    assert_accounted(&core);
}
