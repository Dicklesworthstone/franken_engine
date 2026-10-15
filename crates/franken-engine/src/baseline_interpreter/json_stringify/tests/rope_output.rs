//! Native regressions for leaf-oriented JSON string emission. The reference
//! path is the existing scalar writer; algorithm models do not run this Rust.

use super::*;

fn rope(pieces: &[&str]) -> JsString {
    let mut text = JsString::empty();
    for piece in pieces {
        text = text.concat(&JsString::from(*piece));
    }
    assert!(text.unjoined_concat_children().is_some());
    text
}

fn assert_walk_released(core: &InterpreterCore, state: &StringifyState, inherited: u64) {
    assert_eq!(state.charged, (state.output.capacity() * 2) as u64);
    assert_eq!(core.json_parse_temporary_bytes, inherited + state.charged);
    assert!(core.pending_exception.is_none());
}

#[test]
fn rope_quotes_match_scalar_output_without_publishing_flat_text() {
    let ascii: String = (0u8..=127).map(char::from).collect();
    let inputs = [
        ("a".repeat(1024), ascii.repeat(9)),
        ("é日😀".repeat(180), "\"\\\n\tend".repeat(180)),
        ("before😀".repeat(180), "é\u{2028}\u{2029}after".repeat(180)),
    ];
    for (left, right) in inputs {
        let text = rope(&[&left, &right]);
        let mut actual_core = core();
        let mut reference_core = core();
        let mut actual = StringifyState::default();
        let mut reference = StringifyState::default();
        actual.quote(&mut actual_core, &text).unwrap();
        reference_quote(&mut reference, &mut reference_core, &text).unwrap();
        assert_eq!(actual.output, reference.output);
        assert_eq!(actual.projection_bytes, reference.projection_bytes);
        assert_eq!(actual.output.capacity(), reference.output.capacity());
        assert_eq!(actual.charged, reference.charged);
        assert_eq!(
            actual_core.instructions_executed,
            reference_core.instructions_executed + 1
        );
        assert!(text.unjoined_concat_children().is_some());
        assert_walk_released(&actual_core, &actual, 0);
        release_test_state(&mut actual_core, actual);
        release_test_state(&mut reference_core, reference);
    }
}

#[test]
fn rope_string_limits_keep_the_scalar_failure_prefix_and_output_charge() {
    let left = "x".repeat(1024);
    let right = "\"é😀\\\n日".repeat(200);
    let text = rope(&[&left, &right]);
    for prefix_length in [0, 1, 63, 255, 256] {
        for limit in [0, 1, 2, 63, 64, 65, 255, 256, 257, 1024, 1025, 1030, 4096] {
            let mut actual_core = core();
            let mut reference_core = core();
            let mut actual = StringifyState::default();
            let mut reference = StringifyState::default();
            for _ in 0..prefix_length {
                actual.push(&mut actual_core, 0x61).unwrap();
                reference.push(&mut reference_core, 0x61).unwrap();
            }
            actual_core.config.max_string_size = limit;
            reference_core.config.max_string_size = limit;
            let got = actual.quote(&mut actual_core, &text);
            let expected = reference_quote(&mut reference, &mut reference_core, &text);
            assert_eq!(format!("{got:?}"), format!("{expected:?}"));
            assert_eq!(actual.output, reference.output);
            assert_eq!(actual.projection_bytes, reference.projection_bytes);
            assert_eq!(actual.output.capacity(), reference.output.capacity());
            assert_eq!(actual.charged, reference.charged);
            assert!(text.unjoined_concat_children().is_some());
            assert_walk_released(&actual_core, &actual, 0);
            release_test_state(&mut actual_core, actual);
            release_test_state(&mut reference_core, reference);
        }
    }
}

#[test]
fn rope_work_checkpoints_bound_a_deep_spine_before_the_first_leaf() {
    let leaf = "a".repeat(1024);
    let mut text = JsString::from(leaf.clone());
    for _ in 0..512 {
        text = text.concat(&JsString::from(leaf.clone()));
    }
    let mut core = core();
    let mut state = StringifyState::default();
    core.config.instruction_budget = core.instructions_executed + 2;
    assert!(matches!(
        state.quote(&mut core, &text),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    // Opening-quote work and the first structural interval fit. The next
    // interval is refused without reading or flattening the half-megabyte input.
    assert_eq!(state.output, [u16::from(b'"')]);
    assert!(text.unjoined_concat_children().is_some());
    assert_walk_released(&core, &state, 0);
    release_test_state(&mut core, state);
}

#[test]
fn rope_memory_refusal_releases_only_its_frontier_and_preserves_input() {
    let left = "a".repeat(1024);
    let right = "é😀".repeat(300);
    let text = rope(&[&left, &right]);
    for headroom in [0, 64, 128, 255, 256, 512, 1024] {
        let mut core = core();
        let mut state = StringifyState::default();
        core.json_reserve_temporary(77).unwrap();
        core.config.max_total_memory_bytes = core.estimated_memory_bytes() + headroom;
        assert!(matches!(
            state.quote(&mut core, &text),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(text.unjoined_concat_children().is_some());
        assert_walk_released(&core, &state, 77);
        let charged = state.charged;
        drop(state);
        core.json_release_temporary(charged);
        assert_eq!(core.json_parse_temporary_bytes, 77);
        core.json_release_temporary(77);
        assert_accounted(&core);
    }
}

#[test]
fn rope_cancellation_is_observed_before_frontier_allocation() {
    let text = rope(&[&"a".repeat(1024), &"b".repeat(1024)]);
    let mut core = core();
    let mut state = StringifyState::default();
    state.push(&mut core, 0x61).unwrap();
    let charged = state.charged;
    let token = CancellationToken::new();
    token.cancel();
    core.config.cancellation_token = Some(token);
    // Output index one is not an ordinary 256-unit checkpoint. The rope's
    // structural check must still honor cancellation before allocating.
    assert_eq!(state.quote(&mut core, &text), Err(InterpreterError::Cancelled));
    assert_eq!(state.output, [0x61, u16::from(b'"')]);
    assert_eq!(state.charged, charged);
    assert!(text.unjoined_concat_children().is_some());
    assert_walk_released(&core, &state, 0);
    release_test_state(&mut core, state);
}

#[test]
fn already_published_and_exact_inputs_retain_the_flat_writer_contract() {
    let text = rope(&[&"a".repeat(1024), &"😀".repeat(300)]);
    let _ = text.as_str().unwrap();
    assert!(text.unjoined_concat_children().is_none());
    let exact = JsString::from_code_units(&[0xd800, 0x22, 0xdc00, 0xd83d, 0xde00]);
    for text in [&text, &exact] {
        for work in [0, 1, 2, 16, 100_000] {
            compare_quote(text, &[0xd800], 16_384, work, None);
        }
    }
}

#[test]
fn shared_rope_builtin_keeps_secret_provenance_and_releases_all_scratch() {
    let mut text = rope(&[&"a".repeat(1024), &"é😀".repeat(300)]);
    let mut expected = format!("{}{}", "a".repeat(1024), "é😀".repeat(300));
    for _ in 0..3 {
        text = text.concat(&text);
        expected = format!("{expected}{expected}");
    }
    let mut core = core();
    core.seed_register(0, Value::Str(text.clone())).unwrap();
    core.set_register_label(0, Label::Secret).unwrap();
    assert_eq!(
        stringify(&mut core).unwrap(),
        Value::str(format!("\"{expected}\""))
    );
    assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
    assert!(core.active_inline_callback_context_label.is_none());
    assert!(text.unjoined_concat_children().is_some());
    assert_accounted(&core);
}

#[test]
fn live_json_rope_keys_and_values_preserve_reentrant_callback_order() {
    let source = r#"
        var key = 'k'.repeat(1024) + 'é😀';
        var text = 'a'.repeat(1024) + '\\"\n😀';
        var calls = 0;
        var object = {};
        Object.defineProperty(object, key, {
            enumerable: true,
            get: function () {
                calls++;
                if (calls === 1) {
                    if (JSON.stringify({value: text}) !== '{"value":' + JSON.stringify(text) + '}')
                        throw 'nested stringify';
                }
                return text;
            }
        });
        var encoded = JSON.stringify(object, function (name, value) {
            if (name === key) calls++;
            return value;
        });
        var decoded = JSON.parse(encoded);
        var pair = String.fromCharCode(0xd83d) + String.fromCharCode(0xde00);
        var lone = String.fromCharCode(0xd800);
        [calls, decoded[key] === text, Object.keys(decoded)[0] === key,
         JSON.stringify(pair) === '"😀"', JSON.stringify(lone) === '"\\ud800"'].join('|');
    "#;
    let tree = crate::parser_api_stability::parse_script(source).unwrap();
    let lowered = crate::lowering_pipeline::lower_ir0_to_ir3(
        &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "rope-json.js"),
        &crate::lowering_pipeline::LoweringContext::new("rope-json", "callbacks", "builtin-only"),
    )
    .unwrap();
    let mut core = core();
    let result = core.execute(&lowered.ir3).unwrap();
    assert_eq!(result.value, Value::str("2|true|true|true|true"));
    assert_accounted(&core);
}

#[test]
fn raw_rope_emission_preserves_number_and_string_lexemes_without_escaping() {
    let inputs = [
        (format!("1{}", "0".repeat(1023)), ".000e+0002".to_string()),
        (
            format!("\"{}", "a".repeat(1024)),
            r#"\u0061\"\\\/é日😀""#.to_string(),
        ),
        (
            format!("\"{}", "é日😀".repeat(180)),
            r#"\uD800\u0061\uDC00""#.to_string(),
        ),
    ];
    for (left, right) in inputs {
        let text = rope(&[&left, &right]);
        let expected: Vec<u16> = format!("{left}{right}").encode_utf16().collect();
        let mut actual_core = core();
        let mut reference_core = core();
        let mut actual = StringifyState::default();
        let mut reference = StringifyState::default();
        actual.raw_text(&mut actual_core, &text).unwrap();
        for &unit in &expected {
            reference.push(&mut reference_core, unit).unwrap();
        }
        assert_eq!(actual.output, expected);
        assert_eq!(actual.projection_bytes, reference.projection_bytes);
        assert_eq!(actual.output.capacity(), reference.output.capacity());
        assert_eq!(actual.charged, reference.charged);
        assert_eq!(
            actual_core.instructions_executed,
            reference_core.instructions_executed + 1
        );
        assert!(text.unjoined_concat_children().is_some());
        assert_walk_released(&actual_core, &actual, 0);
        release_test_state(&mut actual_core, actual);
        release_test_state(&mut reference_core, reference);
    }
}

#[test]
fn raw_rope_string_limits_preserve_exact_partial_output_and_release_frontier() {
    let text = rope(&[&format!("\"{}", "a".repeat(1024)), "é😀\\u0061\""]);
    let expected = text.code_units_vec();
    for prefix in [vec![], vec![0xd800], vec![0x61; 255]] {
        for limit in [
            0, 1, 2, 63, 64, 255, 256, 1024, 1025, 1026, 1027, 1028, 1030, 4096,
        ] {
            let mut actual_core = core();
            let mut reference_core = core();
            let mut actual = StringifyState::default();
            let mut reference = StringifyState::default();
            for &unit in &prefix {
                actual.push(&mut actual_core, unit).unwrap();
                reference.push(&mut reference_core, unit).unwrap();
            }
            actual_core.config.max_string_size = limit;
            reference_core.config.max_string_size = limit;
            let got = actual.raw_text(&mut actual_core, &text);
            let want = expected
                .iter()
                .try_for_each(|&unit| reference.push(&mut reference_core, unit));
            assert_eq!(got, want);
            assert_eq!(actual.output, reference.output);
            assert_eq!(actual.projection_bytes, reference.projection_bytes);
            assert_eq!(actual.output.capacity(), reference.output.capacity());
            assert_eq!(actual.charged, reference.charged);
            assert!(text.unjoined_concat_children().is_some());
            assert_walk_released(&actual_core, &actual, 0);
            release_test_state(&mut actual_core, actual);
            release_test_state(&mut reference_core, reference);
        }
    }
}

#[test]
fn raw_flat_output_keeps_exact_units_and_original_work_refusals() {
    let published = rope(&[&"a".repeat(1024), &"😀".repeat(300)]);
    let _ = published.as_str().unwrap();
    // Test the output primitive separately from rawJSON syntax validation:
    // it must preserve exact units, not replace or re-escape lone surrogates.
    let inputs = [
        JsString::empty(),
        JsString::from("-0.000e+00"),
        JsString::from_code_units(&[0xdc00, 0xd800, 0x61, 0x22, 0x5c]),
        published,
    ];
    for text in &inputs {
        for work in [0, 1, 2, 16] {
            let mut actual_core = core();
            let mut reference_core = core();
            let mut actual = StringifyState::default();
            let mut reference = StringifyState::default();
            actual.push(&mut actual_core, 0xd800).unwrap();
            reference.push(&mut reference_core, 0xd800).unwrap();
            actual_core.config.instruction_budget = actual_core.instructions_executed + work;
            reference_core.config.instruction_budget = reference_core.instructions_executed + work;
            let got = actual.raw_text(&mut actual_core, text);
            let want = text
                .encode_utf16()
                .try_for_each(|unit| reference.push(&mut reference_core, unit));
            assert_eq!(got, want);
            assert_eq!(actual.output, reference.output);
            assert_eq!(actual.projection_bytes, reference.projection_bytes);
            assert_eq!(
                actual_core.instructions_executed,
                reference_core.instructions_executed
            );
            assert_eq!(actual.charged, reference.charged);
            release_test_state(&mut actual_core, actual);
            release_test_state(&mut reference_core, reference);
        }
    }
}

#[test]
fn raw_rope_refusals_preserve_inherited_scratch_and_unpublished_input() {
    let piece = "1".repeat(1024);
    let mut text = JsString::from(piece.clone());
    for _ in 0..512 {
        text = text.concat(&JsString::from(piece.clone()));
    }
    for headroom in [0, 64, 128, 255, 256, 512, 1024] {
        let mut core = core();
        let mut state = StringifyState::default();
        core.json_reserve_temporary(77).unwrap();
        core.config.max_total_memory_bytes = core.estimated_memory_bytes() + headroom;
        assert!(matches!(
            state.raw_text(&mut core, &text),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert!(state.output.is_empty());
        assert_walk_released(&core, &state, 77);
        core.json_release_temporary(77);
        release_test_state(&mut core, state);
    }
    let mut core = core();
    let mut state = StringifyState::default();
    core.config.instruction_budget = core.instructions_executed + 1;
    assert!(matches!(
        state.raw_text(&mut core, &text),
        Err(InterpreterError::BudgetExhausted { .. })
    ));
    assert!(state.output.is_empty());
    assert_walk_released(&core, &state, 0);
    let token = CancellationToken::new();
    token.cancel();
    core.config.cancellation_token = Some(token);
    assert_eq!(
        state.raw_text(&mut core, &text),
        Err(InterpreterError::Cancelled)
    );
    assert_eq!(state.charged, 0);
    assert!(text.unjoined_concat_children().is_some());
    release_test_state(&mut core, state);
}

#[test]
fn raw_shared_dag_refuses_small_output_without_materializing_logical_input() {
    let mut text = rope(&[&"1".repeat(1024), &"2".repeat(1024)]);
    for _ in 0..16 {
        text = text.concat(&text);
    }
    assert_eq!(text.len(), 128 * 1024 * 1024);
    let mut core = core();
    let mut state = StringifyState::default();
    core.config.max_string_size = 32;
    assert!(matches!(
        state.raw_text(&mut core, &text),
        Err(InterpreterError::StringLimitExceeded {
            length: 33,
            max: 32
        })
    ));
    assert_eq!(state.output, vec![u16::from(b'1'); 32]);
    assert!(text.unjoined_concat_children().is_some());
    assert_walk_released(&core, &state, 0);
    release_test_state(&mut core, state);
}

#[test]
fn raw_json_builtin_keeps_original_rope_lexeme_and_secret_provenance() {
    for (left, right) in [
        (format!("1{}", "0".repeat(1023)), ".000e+0002".to_string()),
        (format!("\"{}", "é😀".repeat(350)), r#"\u0061""#.to_string()),
    ] {
        let text = rope(&[&left, &right]);
        let mut core = core();
        core.seed_register(0, Value::Str(text.clone())).unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
        let raw = core
            .json_raw_json_builtin(None, RegRange { start: 0, count: 1 })
            .unwrap();
        let Value::Object(object) = raw else {
            panic!("raw JSON object expected");
        };
        assert!(core.is_raw_json_object(object));
        assert!(text.unjoined_concat_children().is_some());
        core.seed_register(0, Value::Object(object)).unwrap();
        core.set_register_label(0, Label::Public).unwrap();
        core.replace_pending_hostcall_result_label(None).unwrap();
        assert_eq!(stringify(&mut core).unwrap(), Value::Str(text.clone()));
        // A public handle must not clear the raw value's stored provenance.
        assert_eq!(core.pending_hostcall_result_label, Some(Label::Secret));
        assert!(text.unjoined_concat_children().is_some());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_accounted(&core);
    }
}

#[test]
fn live_raw_json_ropes_preserve_callbacks_validation_and_literal_spelling() {
    let source = r#"
        var number = '9'.repeat(1100) + '.000e+00';
        var text = '"' + 'é😀'.repeat(350) + '\\u0061"';
        var raw = JSON.rawJSON(number);
        var quoted = JSON.rawJSON(text);
        var calls = 0;
        var object = {
            get amount() {
                calls++;
                return {toJSON: function () { calls++; return raw; }};
            },
            text: quoted
        };
        var encoded = JSON.stringify(object, function (key, value) {
            if (key === 'amount') {
                calls++;
                if (JSON.stringify([quoted, raw]) !== '[' + text + ',' + number + ']')
                    throw 'nested raw stringify';
            }
            return value;
        });
        var invalid = 0;
        ['', ' 1', '1 ', '{}', '[]', '01', '1e+', 'true false'].forEach(function (s) {
            try { JSON.rawJSON(s); } catch (e) { if (e.name === 'SyntaxError') invalid++; }
        });
        [calls, encoded === '{"amount":' + number + ',"text":' + text + '}',
         JSON.stringify(raw) === number, JSON.stringify(quoted) === text,
         Object.isFrozen(raw), Object.getPrototypeOf(raw) === null, invalid].join('|');
    "#;
    let tree = crate::parser_api_stability::parse_script(source).unwrap();
    let lowered = crate::lowering_pipeline::lower_ir0_to_ir3(
        &crate::ir_contract::Ir0Module::from_syntax_tree(tree, "raw-rope-json.js"),
        &crate::lowering_pipeline::LoweringContext::new("raw-rope-json", "callbacks", "builtin-only"),
    )
    .unwrap();
    let mut core = core();
    let result = core.execute(&lowered.ir3).unwrap();
    assert_eq!(result.value, Value::str("3|true|true|true|true|true|8"));
    assert_accounted(&core);
}
