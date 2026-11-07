//! Lexical admission must make long scalar tokens and whitespace consume work,
//! even when the JSON syntax tree has only one value. These tests call the
//! production parser and distinguish host refusals from JavaScript errors.

use super::*;

fn initialized_core() -> InterpreterCore {
    let mut core = core();
    core.ensure_builtin_prototype("Object").unwrap();
    core.ensure_builtin_prototype("Array").unwrap();
    core.ensure_builtin_prototype("SyntaxError").unwrap();
    core
}

fn assert_scratch(core: &InterpreterCore, expected: u64) {
    assert_eq!(core.json_parse_temporary_bytes, expected);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
    assert!(core.active_inline_callback_context_label.is_none());
}

#[test]
fn short_documents_keep_their_existing_structural_work_counts() {
    for (text, expected_work) in [
        ("0", 1),
        ("true", 1),
        (r#""x""#, 1),
        ("[]", 1),
        ("{}", 1),
        (r#"{"x":0}"#, 3),
        ("[0,1]", 5),
    ] {
        let mut core = initialized_core();
        let units: Vec<u16> = text.encode_utf16().collect();
        let before = core.instructions_executed;
        core.json_parse_document(&units).unwrap();
        assert_eq!(core.instructions_executed - before, expected_work, "{text}");
        assert!(core.pending_exception.is_none());
        assert_scratch(&core, 0);
    }
}

#[test]
fn scalar_input_crosses_each_lexical_admission_interval() {
    for (length, expected_work) in [(255, 1), (256, 1), (257, 2), (512, 2), (513, 3)] {
        let mut core = initialized_core();
        let mut units = vec![0x20; length - 1];
        units.push(0x30);
        let before = core.instructions_executed;
        assert_eq!(core.json_parse_document(&units).unwrap(), Value::Int(0));
        assert_eq!(core.instructions_executed - before, expected_work);
        assert_scratch(&core, 0);
    }
}

#[test]
fn long_tokens_and_whitespace_refuse_before_publishing_heap_or_exception_state() {
    let texts = [
        format!("\"{}\"", "a".repeat(65_536)),
        "7".repeat(65_536),
        format!("{}0", " ".repeat(65_536)),
        format!("0{}", "\t\r\n ".repeat(16_384)),
        format!("{{\"{}\":0}}", "k".repeat(65_536)),
    ];
    for text in texts {
        let units: Vec<u16> = text.encode_utf16().collect();
        for outer in [0, 77] {
            let mut core = initialized_core();
            core.json_reserve_temporary(outer).unwrap();
            let heap_before = core.heap.len();
            let memory_before = core.estimated_memory_bytes();
            let budget = core.instructions_executed + 8;
            core.config.instruction_budget = budget;
            assert_eq!(
                core.json_parse_document(&units),
                Err(InterpreterError::BudgetExhausted {
                    executed: budget,
                    budget,
                })
            );
            assert_eq!(core.heap.len(), heap_before);
            assert_eq!(core.estimated_memory_bytes(), memory_before);
            assert!(core.pending_exception.is_none());
            assert_scratch(&core, outer);
            core.json_release_temporary(outer);
            assert_scratch(&core, 0);
        }
    }
}

#[test]
fn malformed_long_input_needs_work_before_its_catchable_syntax_error() {
    for text in [
        format!("\"{}\\q\"", "a".repeat(65_536)),
        format!("1{}e+", "0".repeat(65_536)),
        format!("{}x", " ".repeat(65_536)),
        format!("0{}x", " ".repeat(65_536)),
    ] {
        let mut core = initialized_core();
        let units: Vec<u16> = text.encode_utf16().collect();
        core.json_reserve_temporary(77).unwrap();
        let heap_before = core.heap.len();
        let memory_before = core.estimated_memory_bytes();
        let budget = core.instructions_executed + 8;
        core.config.instruction_budget = budget;
        assert_eq!(
            core.json_parse_document(&units),
            Err(InterpreterError::BudgetExhausted {
                executed: budget,
                budget,
            })
        );
        assert_eq!(core.heap.len(), heap_before);
        assert_eq!(core.estimated_memory_bytes(), memory_before);
        assert!(core.pending_exception.is_none());
        assert_scratch(&core, 77);

        core.config.instruction_budget = core.instructions_executed + 10_000;
        assert!(matches!(
            core.json_parse_document(&units),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert_eq!(core.heap.len(), heap_before + 1);
        let Some(Value::Object(error)) = core.pending_exception.as_ref() else {
            panic!("invalid JSON must retain a JavaScript exception");
        };
        assert_eq!(
            core.chain_data_property(*error, "name"),
            Some(&Value::str("SyntaxError"))
        );
        assert_scratch(&core, 77);
        core.replace_pending_abrupt_slots(None, None).unwrap();
        assert_eq!(core.json_parse_document(&[0x37]).unwrap(), Value::Int(7));
        assert!(core.pending_exception.is_none());
        core.json_release_temporary(77);
        assert_scratch(&core, 0);
    }
}

#[test]
fn builtin_and_module_refusals_release_their_input_buffer_but_keep_outer_scratch() {
    let text = format!("\"{}\"", "a".repeat(65_536));
    for from_module in [false, true] {
        let mut core = initialized_core();
        if !from_module {
            core.seed_register(0, Value::str(text.clone())).unwrap();
        }
        core.json_reserve_temporary(77).unwrap();
        let heap_before = core.heap.len();
        let memory_before = core.estimated_memory_bytes();
        let budget = core.instructions_executed + 8;
        core.config.instruction_budget = budget;
        let result = if from_module {
            core.json_parse_module_source(&text)
        } else {
            core.dispatch_builtin_hostcall(
                "builtin:JsonParse",
                RegRange { start: 0, count: 1 },
                None,
            )
        };
        assert_eq!(
            result,
            Err(InterpreterError::BudgetExhausted {
                executed: budget,
                budget,
            })
        );
        assert_eq!(core.heap.len(), heap_before);
        assert_eq!(core.estimated_memory_bytes(), memory_before);
        assert!(core.pending_exception.is_none());
        assert_scratch(&core, 77);
        core.json_release_temporary(77);
        assert_scratch(&core, 0);
    }
}

#[test]
fn admitted_long_scalars_preserve_exact_utf16_numeric_rounding_and_signed_zero() {
    let mut core = initialized_core();
    let payload = vec![0xD800; 4096];
    let mut units = Vec::with_capacity(payload.len() + 2);
    units.push(0x22);
    units.extend_from_slice(&payload);
    units.push(0x22);
    assert_eq!(
        core.json_parse_document(&units).unwrap(),
        Value::Str(JsString::from_code_units(&payload))
    );
    assert_scratch(&core, 0);

    for (token, expected_bits) in [
        ("-0", (-0.0_f64).to_bits()),
        ("9007199254740993.0", 9_007_199_254_740_992.0_f64.to_bits()),
        ("1e999", f64::INFINITY.to_bits()),
    ] {
        let text = format!("{}{token}{}", " ".repeat(1024), "\t".repeat(1024));
        let units: Vec<u16> = text.encode_utf16().collect();
        let Value::Float(number) = core.json_parse_document(&units).unwrap() else {
            panic!("{token} must retain its binary64 representation");
        };
        assert_eq!(number.inner().to_bits(), expected_bits);
        assert_scratch(&core, 0);
    }
    assert!(core.pending_exception.is_none());
}

#[test]
fn cancelled_lexical_admission_keeps_outer_scratch_and_never_creates_an_exception() {
    let mut core = initialized_core();
    let token = CancellationToken::new();
    token.cancel();
    core.config.cancellation_token = Some(token);
    core.json_reserve_temporary(77).unwrap();
    let heap_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();
    let mut units = vec![0x20; 65_536];
    units.push(0x30);
    assert_eq!(
        core.json_parse_document(&units),
        Err(InterpreterError::Cancelled)
    );
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert!(core.pending_exception.is_none());
    assert_scratch(&core, 77);
    core.json_release_temporary(77);
    assert_scratch(&core, 0);
}
