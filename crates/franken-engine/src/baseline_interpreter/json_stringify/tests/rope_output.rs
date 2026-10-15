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
