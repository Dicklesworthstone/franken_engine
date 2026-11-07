//! Deep JSON exercises the production parser and its transactional boundary.
//! Resource refusals must unwind only their own scratch, including failures
//! while returning through a long run of closing delimiters.

use super::*;

fn nested_document(depth: usize, objects: bool, mixed: bool, leaf: &str) -> String {
    let is_object = |level: usize| objects || (mixed && level % 2 != 0);
    let mut text = String::new();
    for level in 0..depth {
        text.push_str(if is_object(level) { r#"{"x":"# } else { "[" });
    }
    text.push_str(leaf);
    for level in (0..depth).rev() {
        text.push(if is_object(level) { '}' } else { ']' });
    }
    text
}

fn descend(
    core: &InterpreterCore,
    mut value: Value,
    depth: usize,
    objects: bool,
    mixed: bool,
) -> Value {
    for level in 0..depth {
        let key = if objects || (mixed && level % 2 != 0) {
            "x"
        } else {
            "0"
        };
        value = core.json_parsed_child(&value, &JsString::from(key));
    }
    value
}

fn initialized_core() -> InterpreterCore {
    let mut core = core();
    core.ensure_builtin_prototype("Object").unwrap();
    core.ensure_builtin_prototype("Array").unwrap();
    core.ensure_builtin_prototype("SyntaxError").unwrap();
    core
}

#[test]
fn five_thousand_arrays_objects_and_mixed_containers_parse_without_native_recursion() {
    let depth = 5000;
    for (objects, mixed) in [(false, false), (true, false), (false, true)] {
        let mut core = core();
        let text = nested_document(depth, objects, mixed, "42");
        let value = parse(&mut core, Value::str(text)).unwrap();
        assert_eq!(descend(&core, value, depth, objects, mixed), Value::Int(42));
        assert!(core.pending_exception.is_none());
        assert!(core.active_inline_callback_context_label.is_none());
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn deep_json_module_preserves_exact_keys_signed_zero_and_proto_data() {
    let mut core = core();
    let depth = 5000;
    let text = nested_document(
        depth,
        false,
        true,
        r#"{"\ud800":"\ud801","n":-0,"__proto__":1}"#,
    );
    let root = core
        .json_parse_module_source(&format!("\u{feff}{text}"))
        .unwrap();
    let Value::Object(leaf) = descend(&core, root, depth, false, true) else {
        panic!("deep module leaf must be an ordinary object");
    };
    let object = &core.heap[leaf.0 as usize];
    assert_eq!(
        object
            .properties
            .get_exact(&JsString::from_code_units(&[0xD800])),
        Some(&Value::Str(JsString::from_code_units(&[0xD801])))
    );
    assert_eq!(object.properties.get("__proto__"), Some(&Value::Int(1)));
    let Some(Value::Float(zero)) = object.properties.get("n") else {
        panic!("JSON -0 must keep its binary64 sign");
    };
    assert_eq!(zero.inner().to_bits(), (-0.0_f64).to_bits());
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn malformed_deep_suffixes_roll_back_the_unpublished_heap() {
    let depth = 5000;
    for text in [
        format!("{}0{}}}", "[".repeat(depth), "]".repeat(depth - 1)),
        format!("{}0,]{}", "[".repeat(depth), "]".repeat(depth - 1)),
        format!("{}0{} trailing", "[".repeat(depth), "]".repeat(depth)),
        nested_document(depth, true, false, r#"{"bad":1,}"#),
    ] {
        let mut core = initialized_core();
        let heap_before = core.heap.len();
        let units: Vec<u16> = text.encode_utf16().collect();
        assert!(matches!(
            core.json_parse_document(&units),
            Err(InterpreterError::UncaughtException { .. })
        ));
        assert_eq!(core.heap.len(), heap_before + 1, "only the error may escape");
        let Some(Value::Object(error)) = core.pending_exception.as_ref() else {
            panic!("invalid JSON must retain its language exception");
        };
        assert_eq!(
            core.chain_data_property(*error, "name"),
            Some(&Value::str("SyntaxError"))
        );
        assert_eq!(core.json_parse_temporary_bytes, 0);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn closing_a_deep_document_is_metered_and_rolls_back_on_budget_exhaustion() {
    let mut core = initialized_core();
    let depth = 1024;
    let units: Vec<u16> = nested_document(depth, false, false, "0")
        .encode_utf16()
        .collect();
    let heap_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();
    // Admit every opening token and the innermost primitive. The first
    // parent attachment must still charge work instead of freely unwinding.
    let budget = core.instructions_executed + depth as u64 + 1;
    core.config.instruction_budget = budget;
    assert_eq!(
        core.json_parse_document(&units),
        Err(InterpreterError::BudgetExhausted {
            executed: budget,
            budget,
        })
    );
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert!(core.pending_exception.is_none());
}

#[test]
fn parse_frame_memory_refusal_keeps_outer_reservations_and_allows_reuse() {
    let mut core = initialized_core();
    core.json_reserve_temporary(77).unwrap();
    let heap_before = core.heap.len();
    let memory_before = core.estimated_memory_bytes();
    let limit = core.config.max_total_memory_bytes;
    core.config.max_total_memory_bytes = memory_before + 2048;
    let units: Vec<u16> = nested_document(5000, true, false, "0")
        .encode_utf16()
        .collect();
    assert!(matches!(
        core.json_parse_document(&units),
        Err(InterpreterError::MemoryBudgetExceeded { .. })
    ));
    assert_eq!(core.heap.len(), heap_before);
    assert_eq!(core.json_parse_temporary_bytes, 77);
    assert_eq!(core.estimated_memory_bytes(), memory_before);
    assert!(core.pending_exception.is_none());
    core.config.max_total_memory_bytes = limit;
    assert_eq!(core.json_parse_document(&[0x37]).unwrap(), Value::Int(7));
    core.json_release_temporary(77);
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn recursive_reviver_records_are_refused_before_allocating_a_deep_tree() {
    let mut core = core();
    let units: Vec<u16> = nested_document(5000, false, true, "0")
        .encode_utf16()
        .collect();
    let value = core.json_parse_document(&units).unwrap();
    let mut charged = 0;
    let result = core.json_parse_record(&units, &mut 0, value, &mut charged);
    assert!(matches!(
        result,
        Err(InterpreterError::StackOverflow {
            depth: 201,
            max: 200,
        })
    ));
    assert_eq!(charged, 0, "refuse before constructing recursive records");
    assert_eq!(core.json_parse_temporary_bytes, 0);
    assert!(core.pending_exception.is_none());
}

#[test]
fn reviver_record_depth_scan_ignores_string_delimiters_and_preserves_boundary() {
    for text in [
        nested_document(200, false, false, r#""[{\"}]\\""#),
        format!("{}{}", "[".repeat(201), "]".repeat(201)),
    ] {
        let mut core = core();
        let (record, charged, _) = parse_record(&mut core, &text);
        drop(record);
        core.json_release_temporary(charged);
        assert_eq!(core.json_parse_temporary_bytes, 0);
    }
}
