//! Integration tests for the ES2020 standard library baseline (bd-1lsy.4.6 / RGC-306).
//!
//! Validates: install_stdlib initialization, prototype chain wiring, builtin
//! registry completeness, math/string/number/JSON method execution, determinism,
//! serde round-trips, and error taxonomy coverage.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use frankenengine_engine::object_model::{
    JsValue, ObjectHeap, PropertyDescriptor, PropertyKey, SymbolId,
};
use frankenengine_engine::rgc_test_harness::{
    DeterministicTestContext, EventInput, HarnessLane, HarnessRunManifest, write_artifact_triad,
};
use frankenengine_engine::stdlib::{
    ArrayMethodResult, BuiltinId, GlobalEnvironment, StdlibError, alloc_array_instance,
    alloc_map_instance, alloc_set_instance, exec_array_method, exec_boolean_method,
    exec_date_method, exec_error_constructor, exec_global_function, exec_heap_collection_method,
    exec_math, exec_number_method, exec_object_static, exec_string_method,
    exec_string_method_with_receipt, exec_string_static, exec_symbol_static, install_stdlib,
    json_parse, json_stringify, read_array_elements, read_map_entries, read_set_values,
};

const FP_SCALE: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// install_stdlib smoke tests
// ---------------------------------------------------------------------------

#[test]
fn install_stdlib_returns_valid_global_environment() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    // Global object should exist on the heap with constructor properties.
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Array"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Object"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("String"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Number"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Boolean"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("Math"))
            .is_ok()
    );
    assert!(
        heap.get_property(env.global_object, &PropertyKey::from("JSON"))
            .is_ok()
    );
}

#[test]
fn install_stdlib_registers_builtins_in_registry() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    assert!(!env.registry.is_empty(), "registry should not be empty");
}

#[test]
fn install_stdlib_prototype_chain_object_proto_is_root() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    // Object.prototype has null [[Prototype]] (it's the root).
    let proto = env.prototypes.object_prototype;
    let parent = heap.get_prototype_of(proto).unwrap();
    assert!(
        parent.is_none(),
        "Object.prototype should have null [[Prototype]]"
    );
}

#[test]
fn install_stdlib_prototype_chain_array_inherits_object() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    // Array.prototype.[[Prototype]] should be Object.prototype.
    let array_proto_parent = heap
        .get_prototype_of(env.prototypes.array_prototype)
        .unwrap();
    assert_eq!(
        array_proto_parent,
        Some(env.prototypes.object_prototype),
        "Array.prototype should inherit from Object.prototype"
    );
}

#[test]
fn install_stdlib_determinism_across_invocations() {
    let env1 = {
        let mut heap = ObjectHeap::new();
        install_stdlib(&mut heap)
    };
    let env2 = {
        let mut heap = ObjectHeap::new();
        install_stdlib(&mut heap)
    };
    assert_eq!(env1.registry.len(), env2.registry.len());
}

// ---------------------------------------------------------------------------
// Math method tests
// ---------------------------------------------------------------------------

#[test]
fn math_abs_positive() {
    let result = exec_math(BuiltinId::MathAbs, &[JsValue::Int(-5 * FP_SCALE)]).unwrap();
    assert_eq!(result, JsValue::Int(5 * FP_SCALE));
}

#[test]
fn math_abs_zero() {
    let result = exec_math(BuiltinId::MathAbs, &[JsValue::Int(0)]).unwrap();
    assert_eq!(result, JsValue::Int(0));
}

#[test]
fn math_ceil() {
    let result = exec_math(BuiltinId::MathCeil, &[JsValue::Int(2_300_000)]).unwrap();
    assert_eq!(result, JsValue::Int(3 * FP_SCALE));
}

#[test]
fn math_floor() {
    let result = exec_math(BuiltinId::MathFloor, &[JsValue::Int(2_700_000)]).unwrap();
    assert_eq!(result, JsValue::Int(2 * FP_SCALE));
}

#[test]
fn math_round() {
    assert_eq!(
        exec_math(BuiltinId::MathRound, &[JsValue::Int(2_500_000)]).unwrap(),
        JsValue::Int(3 * FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathRound, &[JsValue::Int(2_499_999)]).unwrap(),
        JsValue::Int(2 * FP_SCALE)
    );
}

#[test]
fn math_trunc() {
    assert_eq!(
        exec_math(BuiltinId::MathTrunc, &[JsValue::Int(3_700_000)]).unwrap(),
        JsValue::Int(3 * FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathTrunc, &[JsValue::Int(-3_700_000)]).unwrap(),
        JsValue::Int(-3 * FP_SCALE)
    );
}

#[test]
fn math_sign() {
    assert_eq!(
        exec_math(BuiltinId::MathSign, &[JsValue::Int(42 * FP_SCALE)]).unwrap(),
        JsValue::Int(FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathSign, &[JsValue::Int(-FP_SCALE)]).unwrap(),
        JsValue::Int(-FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathSign, &[JsValue::Int(0)]).unwrap(),
        JsValue::Int(0)
    );
}

#[test]
fn math_max_min() {
    let args = vec![
        JsValue::Int(3 * FP_SCALE),
        JsValue::Int(FP_SCALE),
        JsValue::Int(5 * FP_SCALE),
    ];
    assert_eq!(
        exec_math(BuiltinId::MathMax, &args).unwrap(),
        JsValue::Int(5 * FP_SCALE)
    );
    assert_eq!(
        exec_math(BuiltinId::MathMin, &args).unwrap(),
        JsValue::Int(FP_SCALE)
    );
}

#[test]
fn math_pow() {
    let result = exec_math(
        BuiltinId::MathPow,
        &[JsValue::Int(2 * FP_SCALE), JsValue::Int(3 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(8 * FP_SCALE));
}

#[test]
fn math_clz32() {
    let result = exec_math(BuiltinId::MathClz32, &[JsValue::Int(FP_SCALE)]).unwrap();
    assert_eq!(result, JsValue::Int(31 * FP_SCALE));
}

#[test]
fn math_imul() {
    let result = exec_math(
        BuiltinId::MathImul,
        &[JsValue::Int(3 * FP_SCALE), JsValue::Int(4 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(12 * FP_SCALE));
}

// ---------------------------------------------------------------------------
// String method tests
// ---------------------------------------------------------------------------

#[test]
fn string_char_at() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeCharAt,
        "hello",
        &[JsValue::Int(0)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("h".into()));
}

#[test]
fn string_char_at_end() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeCharAt,
        "hello",
        &[JsValue::Int(4 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("o".into()));
}

#[test]
fn string_char_at_out_of_bounds() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeCharAt,
        "hi",
        &[JsValue::Int(10 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str(String::new()));
}

#[test]
fn string_includes() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeIncludes,
        "hello world",
        &[JsValue::Str("world".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Bool(true));

    let result2 = exec_string_method(
        BuiltinId::StringPrototypeIncludes,
        "hello",
        &[JsValue::Str("xyz".into())],
    )
    .unwrap();
    assert_eq!(result2, JsValue::Bool(false));
}

#[test]
fn string_starts_with() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeStartsWith,
            "hello",
            &[JsValue::Str("hel".into())]
        )
        .unwrap(),
        JsValue::Bool(true)
    );
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeStartsWith,
            "hello",
            &[JsValue::Str("llo".into())]
        )
        .unwrap(),
        JsValue::Bool(false)
    );
}

#[test]
fn string_ends_with() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeEndsWith,
            "hello",
            &[JsValue::Str("llo".into())]
        )
        .unwrap(),
        JsValue::Bool(true)
    );
}

#[test]
fn string_to_upper_lower() {
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeToUpperCase, "hello", &[]).unwrap(),
        JsValue::Str("HELLO".into())
    );
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeToLowerCase, "HELLO", &[]).unwrap(),
        JsValue::Str("hello".into())
    );
}

#[test]
fn string_trim() {
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeTrim, "  hello  ", &[]).unwrap(),
        JsValue::Str("hello".into())
    );
}

#[test]
fn string_trim_start_end() {
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeTrimStart, "  hello  ", &[]).unwrap(),
        JsValue::Str("hello  ".into())
    );
    assert_eq!(
        exec_string_method(BuiltinId::StringPrototypeTrimEnd, "  hello  ", &[]).unwrap(),
        JsValue::Str("  hello".into())
    );
}

#[test]
fn string_repeat() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeRepeat,
            "ab",
            &[JsValue::Int(3 * FP_SCALE)]
        )
        .unwrap(),
        JsValue::Str("ababab".into())
    );
}

#[test]
fn string_pad_start_end() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypePadStart,
            "5",
            &[JsValue::Int(3 * FP_SCALE), JsValue::Str("0".into())]
        )
        .unwrap(),
        JsValue::Str("005".into())
    );
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypePadEnd,
            "5",
            &[JsValue::Int(3 * FP_SCALE), JsValue::Str("0".into())]
        )
        .unwrap(),
        JsValue::Str("500".into())
    );
}

#[test]
fn string_index_of() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeIndexOf,
            "hello world",
            &[JsValue::Str("world".into())]
        )
        .unwrap(),
        JsValue::Int(6 * FP_SCALE)
    );
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeIndexOf,
            "hello",
            &[JsValue::Str("xyz".into())]
        )
        .unwrap(),
        JsValue::Int(-FP_SCALE)
    );
}

#[test]
fn string_slice() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeSlice,
            "hello world",
            &[JsValue::Int(6 * FP_SCALE)]
        )
        .unwrap(),
        JsValue::Str("world".into())
    );
}

#[test]
fn string_substring() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeSubstring,
            "hello",
            &[JsValue::Int(FP_SCALE), JsValue::Int(3 * FP_SCALE)]
        )
        .unwrap(),
        JsValue::Str("el".into())
    );
}

#[test]
fn string_split() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeSplit,
        "a,b,c",
        &[JsValue::Str(",".into())],
    )
    .unwrap();
    assert!(matches!(result, JsValue::Str(_)));
}

#[test]
fn string_concat() {
    assert_eq!(
        exec_string_method(
            BuiltinId::StringPrototypeConcat,
            "hello",
            &[JsValue::Str(" world".into())]
        )
        .unwrap(),
        JsValue::Str("hello world".into())
    );
}

#[test]
fn string_receipt_tracks_unicode_observability_for_slice() {
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeSlice,
        "a😀b",
        &[JsValue::Int(FP_SCALE), JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    let receipt = traced.receipt.expect("string receipt");

    assert_eq!(traced.value, JsValue::Str("😀".into()));
    assert_eq!(receipt.source_utf16_units, 4);
    assert_eq!(receipt.result_utf16_units, 2);
    assert!(receipt.result_has_non_bmp);
    assert!(!receipt.flatten_required);
}

#[test]
fn string_receipt_marks_flatten_budget_pressure_for_concat() {
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeConcat,
        &"x".repeat(220),
        &[JsValue::Str("y".repeat(80))],
    )
    .unwrap();
    let receipt = traced.receipt.expect("string receipt");

    assert!(receipt.flatten_required);
    assert!(receipt.flatten_budget_exhausted);
    assert_eq!(receipt.segment_count, 2);
    assert!(receipt.trace_id.starts_with("trace-string-"));
}

// ---------------------------------------------------------------------------
// Number method tests
// ---------------------------------------------------------------------------

#[test]
fn number_is_finite() {
    // Static method — this_val is conventional 0.
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsFinite, 42 * FP_SCALE, &[]).unwrap(),
        JsValue::Bool(true)
    );
}

#[test]
fn number_is_integer() {
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsInteger, 5 * FP_SCALE, &[]).unwrap(),
        JsValue::Bool(true)
    );
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsInteger, 5_500_000, &[]).unwrap(),
        JsValue::Bool(false)
    );
}

#[test]
fn number_is_nan() {
    assert_eq!(
        exec_number_method(BuiltinId::NumberIsNaN, 0, &[]).unwrap(),
        JsValue::Bool(false)
    );
}

/// `Number.parseInt` is a static constructor method installed via `install_builtin_fn`,
/// not dispatched through `exec_number_method`. Verify it is installed on the constructor.
#[test]
fn number_parse_int_installed_on_constructor() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let prop = heap
        .get_property(number_ctor, &PropertyKey::from("parseInt"))
        .unwrap();
    assert!(
        matches!(prop, JsValue::Function(_)),
        "Number.parseInt should be installed as a Function on the constructor"
    );
}

/// `Number.parseFloat` is a static constructor method installed via `install_builtin_fn`,
/// not dispatched through `exec_number_method`. Verify it is installed on the constructor.
#[test]
fn number_parse_float_installed_on_constructor() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let prop = heap
        .get_property(number_ctor, &PropertyKey::from("parseFloat"))
        .unwrap();
    assert!(
        matches!(prop, JsValue::Function(_)),
        "Number.parseFloat should be installed as a Function on the constructor"
    );
}

// ---------------------------------------------------------------------------
// JSON tests
// ---------------------------------------------------------------------------

#[test]
fn json_stringify_null() {
    assert_eq!(
        json_stringify(&JsValue::Null).unwrap(),
        JsValue::Str("null".into())
    );
}

#[test]
fn json_stringify_bool() {
    assert_eq!(
        json_stringify(&JsValue::Bool(true)).unwrap(),
        JsValue::Str("true".into())
    );
    assert_eq!(
        json_stringify(&JsValue::Bool(false)).unwrap(),
        JsValue::Str("false".into())
    );
}

#[test]
fn json_stringify_int() {
    assert_eq!(
        json_stringify(&JsValue::Int(42 * FP_SCALE)).unwrap(),
        JsValue::Str("42".into())
    );
    assert_eq!(
        json_stringify(&JsValue::Int(3_141_593)).unwrap(),
        JsValue::Str("3.141593".into())
    );
}

#[test]
fn json_stringify_string_with_escapes() {
    assert_eq!(
        json_stringify(&JsValue::Str("hello \"world\"".into())).unwrap(),
        JsValue::Str("\"hello \\\"world\\\"\"".into())
    );
    assert_eq!(
        json_stringify(&JsValue::Str("line\nnewline".into())).unwrap(),
        JsValue::Str("\"line\\nnewline\"".into())
    );
}

#[test]
fn json_stringify_undefined_returns_undefined() {
    assert_eq!(
        json_stringify(&JsValue::Undefined).unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn json_parse_primitives() {
    assert_eq!(json_parse("null").unwrap(), JsValue::Null);
    assert_eq!(json_parse("true").unwrap(), JsValue::Bool(true));
    assert_eq!(json_parse("false").unwrap(), JsValue::Bool(false));
    assert_eq!(json_parse("42").unwrap(), JsValue::Int(42 * FP_SCALE));
}

#[test]
fn json_parse_string() {
    assert_eq!(
        json_parse("\"hello\"").unwrap(),
        JsValue::Str("hello".into())
    );
}

#[test]
fn json_parse_compound_returns_placeholder() {
    let result = json_parse("[1,2,3]").unwrap();
    assert!(matches!(result, JsValue::Str(s) if s.starts_with("[json-compound:")));
}

#[test]
fn json_parse_invalid_returns_error() {
    let result = json_parse("not_valid_json");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// StdlibError taxonomy
// ---------------------------------------------------------------------------

#[test]
fn stdlib_error_type_error_display() {
    let err = StdlibError::TypeError("bad argument".into());
    let msg = format!("{err}");
    assert!(msg.contains("TypeError"), "should contain TypeError");
    assert!(msg.contains("bad argument"), "should contain message");
}

#[test]
fn stdlib_error_arity_display() {
    let err = StdlibError::ArityError {
        builtin: "Array.from".into(),
        expected_min: 1,
        expected_max: 3,
        got: 0,
    };
    let msg = format!("{err}");
    assert!(msg.contains("Array.from"));
}

#[test]
fn stdlib_error_range_error_display() {
    let err = StdlibError::RangeError("out of range".into());
    let msg = format!("{err}");
    assert!(msg.contains("RangeError"));
}

// ---------------------------------------------------------------------------
// BuiltinId completeness and Display
// ---------------------------------------------------------------------------

#[test]
fn builtin_id_display_distinguishes_methods() {
    let cases = [
        (BuiltinId::MathAbs, "Math.abs"),
        (BuiltinId::ArrayPrototypePush, "Array.prototype.push"),
        (BuiltinId::ObjectKeys, "Object.keys"),
        (BuiltinId::StringPrototypeSlice, "String.prototype.slice"),
        (BuiltinId::JsonParse, "JSON.parse"),
        (BuiltinId::JsonStringify, "JSON.stringify"),
    ];
    for (id, expected) in cases {
        assert_eq!(
            format!("{id}"),
            expected,
            "BuiltinId::{id:?} should display as {expected}"
        );
    }
}

// ---------------------------------------------------------------------------
// Serde round-trip tests
// ---------------------------------------------------------------------------

#[test]
fn builtin_id_serde_roundtrip() {
    let ids = [
        BuiltinId::MathAbs,
        BuiltinId::ArrayPrototypePush,
        BuiltinId::ObjectKeys,
        BuiltinId::JsonParse,
        BuiltinId::StringPrototypeCharAt,
        BuiltinId::NumberIsFinite,
    ];
    for id in ids {
        let json = serde_json::to_string(&id).unwrap();
        let back: BuiltinId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back, "serde roundtrip failed for {id:?}");
    }
}

#[test]
fn stdlib_error_serde_roundtrip() {
    let err = StdlibError::TypeError("test".into());
    let json = serde_json::to_string(&err).unwrap();
    let back: StdlibError = serde_json::from_str(&json).unwrap();
    assert_eq!(format!("{err}"), format!("{back}"));
}

#[test]
fn global_environment_serde_roundtrip() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let json = serde_json::to_string(&env).unwrap();
    let back: GlobalEnvironment = serde_json::from_str(&json).unwrap();
    assert_eq!(env.registry.len(), back.registry.len());
}

// ---------------------------------------------------------------------------
// Determinism verification
// ---------------------------------------------------------------------------

#[test]
fn math_operations_deterministic_across_runs() {
    let ops: Vec<(BuiltinId, Vec<JsValue>)> = vec![
        (BuiltinId::MathAbs, vec![JsValue::Int(-42 * FP_SCALE)]),
        (
            BuiltinId::MathPow,
            vec![JsValue::Int(2 * FP_SCALE), JsValue::Int(10 * FP_SCALE)],
        ),
        (BuiltinId::MathCeil, vec![JsValue::Int(1_100_000)]),
        (BuiltinId::MathFloor, vec![JsValue::Int(1_900_000)]),
    ];

    for _ in 0..5 {
        for (op, args) in &ops {
            let r1 = exec_math(*op, args).unwrap();
            let r2 = exec_math(*op, args).unwrap();
            assert_eq!(r1, r2, "math op {op:?} not deterministic");
        }
    }
}

#[test]
fn string_operations_deterministic_across_runs() {
    for _ in 0..5 {
        let r1 =
            exec_string_method(BuiltinId::StringPrototypeToUpperCase, "determinism", &[]).unwrap();
        let r2 =
            exec_string_method(BuiltinId::StringPrototypeToUpperCase, "determinism", &[]).unwrap();
        assert_eq!(r1, r2);
    }
}

// ---------------------------------------------------------------------------
// Number constants via heap
// ---------------------------------------------------------------------------

#[test]
fn number_max_safe_integer_is_accessible() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let max_safe = heap
        .get_property(number_ctor, &PropertyKey::from("MAX_SAFE_INTEGER"))
        .unwrap();
    if let JsValue::Int(v) = max_safe {
        assert!(v > 0, "MAX_SAFE_INTEGER should be positive");
        assert_eq!(v % FP_SCALE, 0, "should be an exact integer in fixed-point");
    } else {
        panic!("MAX_SAFE_INTEGER should be a JsValue::Int");
    }
}

#[test]
fn number_epsilon_is_one() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let number_ctor = env.constructors.number_constructor;
    let epsilon = heap
        .get_property(number_ctor, &PropertyKey::from("EPSILON"))
        .unwrap();
    assert_eq!(epsilon, JsValue::Int(1));
}

// ---------------------------------------------------------------------------
// exec_global_function tests
// ---------------------------------------------------------------------------

#[test]
fn global_is_nan_undefined_returns_true() {
    let result = exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Undefined]).unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn global_is_nan_number_returns_false() {
    let result =
        exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Int(42 * FP_SCALE)]).unwrap();
    assert_eq!(result, JsValue::Bool(false));
}

#[test]
fn global_is_nan_numeric_string_returns_false() {
    let result =
        exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Str("123".into())]).unwrap();
    assert_eq!(result, JsValue::Bool(false));
}

#[test]
fn global_is_nan_non_numeric_string_returns_true() {
    let result =
        exec_global_function(BuiltinId::GlobalIsNaN, &[JsValue::Str("abc".into())]).unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn global_is_finite_number_returns_true() {
    let result =
        exec_global_function(BuiltinId::GlobalIsFinite, &[JsValue::Int(99 * FP_SCALE)]).unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn global_is_finite_undefined_returns_false() {
    let result = exec_global_function(BuiltinId::GlobalIsFinite, &[JsValue::Undefined]).unwrap();
    assert_eq!(result, JsValue::Bool(false));
}

#[test]
fn global_parse_int_decimal() {
    let result =
        exec_global_function(BuiltinId::GlobalParseInt, &[JsValue::Str("42".into())]).unwrap();
    assert_eq!(result, JsValue::Int(42 * FP_SCALE));
}

#[test]
fn global_parse_int_with_radix() {
    let result = exec_global_function(
        BuiltinId::GlobalParseInt,
        &[JsValue::Str("ff".into()), JsValue::Int(16 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(255 * FP_SCALE));
}

#[test]
fn global_parse_int_negative() {
    let result =
        exec_global_function(BuiltinId::GlobalParseInt, &[JsValue::Str("-10".into())]).unwrap();
    assert_eq!(result, JsValue::Int(-10 * FP_SCALE));
}

#[test]
fn global_parse_int_invalid_returns_zero() {
    let result = exec_global_function(
        BuiltinId::GlobalParseInt,
        &[JsValue::Str("not_a_number".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(0));
}

#[test]
fn global_parse_float_integer() {
    let result =
        exec_global_function(BuiltinId::GlobalParseFloat, &[JsValue::Str("99".into())]).unwrap();
    assert_eq!(result, JsValue::Int(99 * FP_SCALE));
}

#[test]
fn global_encode_uri_preserves_safe_chars() {
    let result = exec_global_function(
        BuiltinId::GlobalEncodeURI,
        &[JsValue::Str("http://example.com/path?q=1".into())],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.contains("http"));
        assert!(s.contains("example.com"));
    } else {
        panic!("expected string result");
    }
}

#[test]
fn global_encode_uri_component_encodes_special_chars() {
    let result = exec_global_function(
        BuiltinId::GlobalEncodeURIComponent,
        &[JsValue::Str("hello world".into())],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(
            s.contains("%20") || s.contains("+"),
            "space should be encoded: {s}"
        );
    } else {
        panic!("expected string result");
    }
}

#[test]
fn global_decode_uri_round_trips() {
    let encoded = exec_global_function(
        BuiltinId::GlobalEncodeURIComponent,
        &[JsValue::Str("hello world!".into())],
    )
    .unwrap();
    if let JsValue::Str(encoded_str) = &encoded {
        let decoded = exec_global_function(
            BuiltinId::GlobalDecodeURIComponent,
            &[JsValue::Str(encoded_str.clone())],
        )
        .unwrap();
        assert_eq!(decoded, JsValue::Str("hello world!".into()));
    }
}

// ---------------------------------------------------------------------------
// exec_boolean_method tests
// ---------------------------------------------------------------------------

#[test]
fn boolean_to_string_true() {
    let result = exec_boolean_method(BuiltinId::BooleanPrototypeToString, true).unwrap();
    assert_eq!(result, JsValue::Str("true".into()));
}

#[test]
fn boolean_to_string_false() {
    let result = exec_boolean_method(BuiltinId::BooleanPrototypeToString, false).unwrap();
    assert_eq!(result, JsValue::Str("false".into()));
}

#[test]
fn boolean_value_of_true() {
    let result = exec_boolean_method(BuiltinId::BooleanPrototypeValueOf, true).unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn boolean_value_of_false() {
    let result = exec_boolean_method(BuiltinId::BooleanPrototypeValueOf, false).unwrap();
    assert_eq!(result, JsValue::Bool(false));
}

#[test]
fn boolean_method_wrong_builtin_returns_error() {
    let result = exec_boolean_method(BuiltinId::MathAbs, true);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// exec_object_static tests
// ---------------------------------------------------------------------------

#[test]
fn object_is_same_value_ints() {
    let result =
        exec_object_static(BuiltinId::ObjectIs, &[JsValue::Int(42), JsValue::Int(42)]).unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn object_is_different_values() {
    let result =
        exec_object_static(BuiltinId::ObjectIs, &[JsValue::Int(1), JsValue::Int(2)]).unwrap();
    assert_eq!(result, JsValue::Bool(false));
}

#[test]
fn object_is_null_null() {
    let result = exec_object_static(BuiltinId::ObjectIs, &[JsValue::Null, JsValue::Null]).unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn object_is_undefined_undefined() {
    let result = exec_object_static(
        BuiltinId::ObjectIs,
        &[JsValue::Undefined, JsValue::Undefined],
    )
    .unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn object_is_null_vs_undefined() {
    let result =
        exec_object_static(BuiltinId::ObjectIs, &[JsValue::Null, JsValue::Undefined]).unwrap();
    assert_eq!(result, JsValue::Bool(false));
}

#[test]
fn object_is_no_args_defaults_to_undefined() {
    let result = exec_object_static(BuiltinId::ObjectIs, &[]).unwrap();
    assert_eq!(result, JsValue::Bool(true), "both default to undefined");
}

// ---------------------------------------------------------------------------
// exec_string_static tests
// ---------------------------------------------------------------------------

#[test]
fn string_from_char_code_single() {
    let result = exec_string_static(
        BuiltinId::StringFromCharCode,
        &[JsValue::Int(65 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("A".into()));
}

#[test]
fn string_from_char_code_multiple() {
    let result = exec_string_static(
        BuiltinId::StringFromCharCode,
        &[JsValue::Int(72 * FP_SCALE), JsValue::Int(105 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("Hi".into()));
}

#[test]
fn string_from_code_point_single() {
    let result = exec_string_static(
        BuiltinId::StringFromCodePoint,
        &[JsValue::Int(9731 * FP_SCALE)],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert_eq!(s.chars().count(), 1);
    } else {
        panic!("expected string");
    }
}

#[test]
fn string_from_code_point_invalid_returns_error() {
    let result = exec_string_static(
        BuiltinId::StringFromCodePoint,
        &[JsValue::Int(0x11_0000_i64 * FP_SCALE)],
    );
    assert!(result.is_err(), "code point above U+10FFFF should fail");
}

// ---------------------------------------------------------------------------
// exec_array_method tests
// ---------------------------------------------------------------------------

#[test]
fn array_index_of_found() {
    let elements = vec![
        JsValue::Int(FP_SCALE),
        JsValue::Int(2 * FP_SCALE),
        JsValue::Int(3 * FP_SCALE),
    ];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeIndexOf,
        &elements,
        &[JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    assert!(matches!(result, ArrayMethodResult::Value(JsValue::Int(v)) if v == FP_SCALE));
}

#[test]
fn array_index_of_not_found() {
    let elements = vec![JsValue::Int(FP_SCALE)];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeIndexOf,
        &elements,
        &[JsValue::Int(99 * FP_SCALE)],
    )
    .unwrap();
    assert!(matches!(result, ArrayMethodResult::Value(JsValue::Int(v)) if v == -FP_SCALE));
}

#[test]
fn array_last_index_of_found() {
    let elements = vec![
        JsValue::Int(FP_SCALE),
        JsValue::Int(2 * FP_SCALE),
        JsValue::Int(FP_SCALE),
    ];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeLastIndexOf,
        &elements,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();
    assert!(matches!(result, ArrayMethodResult::Value(JsValue::Int(v)) if v == 2 * FP_SCALE));
}

#[test]
fn array_includes_true() {
    let elements = vec![JsValue::Int(10 * FP_SCALE), JsValue::Int(20 * FP_SCALE)];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeIncludes,
        &elements,
        &[JsValue::Int(20 * FP_SCALE)],
    )
    .unwrap();
    assert!(matches!(
        result,
        ArrayMethodResult::Value(JsValue::Bool(true))
    ));
}

#[test]
fn array_includes_false() {
    let elements = vec![JsValue::Int(10 * FP_SCALE)];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeIncludes,
        &elements,
        &[JsValue::Int(99 * FP_SCALE)],
    )
    .unwrap();
    assert!(matches!(
        result,
        ArrayMethodResult::Value(JsValue::Bool(false))
    ));
}

#[test]
fn array_join_default_separator() {
    let elements = vec![
        JsValue::Int(FP_SCALE),
        JsValue::Int(2 * FP_SCALE),
        JsValue::Int(3 * FP_SCALE),
    ];
    let result = exec_array_method(BuiltinId::ArrayPrototypeJoin, &elements, &[]).unwrap();
    if let ArrayMethodResult::Value(JsValue::Str(s)) = &result {
        assert!(s.contains(','), "default separator should be comma: {s}");
    } else {
        panic!("expected string value result");
    }
}

#[test]
fn array_join_custom_separator() {
    let elements = vec![JsValue::Str("a".into()), JsValue::Str("b".into())];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeJoin,
        &elements,
        &[JsValue::Str("-".into())],
    )
    .unwrap();
    assert!(matches!(result, ArrayMethodResult::Value(JsValue::Str(s)) if s == "a-b"));
}

#[test]
fn array_reverse() {
    let elements = vec![
        JsValue::Int(FP_SCALE),
        JsValue::Int(2 * FP_SCALE),
        JsValue::Int(3 * FP_SCALE),
    ];
    let result = exec_array_method(BuiltinId::ArrayPrototypeReverse, &elements, &[]).unwrap();
    if let ArrayMethodResult::NewArray(arr) = result {
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], JsValue::Int(3 * FP_SCALE));
        assert_eq!(arr[2], JsValue::Int(FP_SCALE));
    } else {
        panic!("expected NewArray result");
    }
}

#[test]
fn array_slice_basic() {
    let elements = vec![
        JsValue::Int(10 * FP_SCALE),
        JsValue::Int(20 * FP_SCALE),
        JsValue::Int(30 * FP_SCALE),
        JsValue::Int(40 * FP_SCALE),
    ];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeSlice,
        &elements,
        &[JsValue::Int(FP_SCALE), JsValue::Int(3 * FP_SCALE)],
    )
    .unwrap();
    if let ArrayMethodResult::NewArray(arr) = result {
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], JsValue::Int(20 * FP_SCALE));
        assert_eq!(arr[1], JsValue::Int(30 * FP_SCALE));
    } else {
        panic!("expected NewArray result");
    }
}

#[test]
fn array_concat() {
    let elements = vec![JsValue::Int(FP_SCALE)];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeConcat,
        &elements,
        &[JsValue::Int(2 * FP_SCALE), JsValue::Int(3 * FP_SCALE)],
    )
    .unwrap();
    if let ArrayMethodResult::NewArray(arr) = result {
        assert_eq!(arr.len(), 3);
    } else {
        panic!("expected NewArray result");
    }
}

#[test]
fn array_fill() {
    let elements = vec![JsValue::Int(0), JsValue::Int(0), JsValue::Int(0)];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeFill,
        &elements,
        &[JsValue::Int(7 * FP_SCALE)],
    )
    .unwrap();
    if let ArrayMethodResult::NewArray(arr) = result {
        assert!(arr.iter().all(|v| *v == JsValue::Int(7 * FP_SCALE)));
    } else {
        panic!("expected NewArray result");
    }
}

#[test]
fn array_empty_index_of() {
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeIndexOf,
        &[],
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();
    assert!(matches!(result, ArrayMethodResult::Value(JsValue::Int(v)) if v == -FP_SCALE));
}

// ---------------------------------------------------------------------------
// exec_date_method tests
// ---------------------------------------------------------------------------

#[test]
fn date_now_returns_deterministic_value() {
    let r1 = exec_date_method(BuiltinId::DateNow, None).unwrap();
    let r2 = exec_date_method(BuiltinId::DateNow, None).unwrap();
    assert_eq!(r1, r2, "Date.now() should be deterministic");
    if let JsValue::Int(v) = r1 {
        assert!(v > 0, "Date.now() should return positive value");
    }
}

#[test]
fn date_get_time_returns_timestamp() {
    let ts = 1_000_000_i64 * FP_SCALE;
    let result = exec_date_method(BuiltinId::DatePrototypeGetTime, Some(ts)).unwrap();
    assert_eq!(result, JsValue::Int(ts));
}

#[test]
fn date_value_of_returns_timestamp() {
    let ts = 500_000_i64 * FP_SCALE;
    let result = exec_date_method(BuiltinId::DatePrototypeValueOf, Some(ts)).unwrap();
    assert_eq!(result, JsValue::Int(ts));
}

#[test]
fn date_to_string_contains_date_prefix() {
    let result = exec_date_method(BuiltinId::DatePrototypeToString, Some(1000 * FP_SCALE)).unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.starts_with("Date("), "should start with Date(: {s}");
    } else {
        panic!("expected string");
    }
}

#[test]
fn date_to_iso_string_contains_t_and_z() {
    let result = exec_date_method(
        BuiltinId::DatePrototypeToISOString,
        Some(86400000 * FP_SCALE),
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.contains('T'), "ISO string should contain T: {s}");
        assert!(s.ends_with('Z'), "ISO string should end with Z: {s}");
    } else {
        panic!("expected string");
    }
}

#[test]
fn date_method_none_timestamp_uses_zero() {
    let result = exec_date_method(BuiltinId::DatePrototypeGetTime, None).unwrap();
    assert_eq!(result, JsValue::Int(0));
}

// ---------------------------------------------------------------------------
// exec_error_constructor tests
// ---------------------------------------------------------------------------

#[test]
fn error_constructor_with_message() {
    let result = exec_error_constructor(
        BuiltinId::ErrorConstructor,
        &[JsValue::Str("something went wrong".into())],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.contains("Error"), "should contain Error: {s}");
        assert!(
            s.contains("something went wrong"),
            "should contain message: {s}"
        );
    } else {
        panic!("expected string");
    }
}

#[test]
fn type_error_constructor() {
    let result = exec_error_constructor(
        BuiltinId::TypeErrorConstructor,
        &[JsValue::Str("bad type".into())],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(
            s.starts_with("TypeError:"),
            "should start with TypeError: {s}"
        );
    } else {
        panic!("expected string");
    }
}

#[test]
fn range_error_constructor() {
    let result = exec_error_constructor(
        BuiltinId::RangeErrorConstructor,
        &[JsValue::Str("out of range".into())],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.starts_with("RangeError:"));
    } else {
        panic!("expected string");
    }
}

#[test]
fn reference_error_constructor() {
    let result = exec_error_constructor(
        BuiltinId::ReferenceErrorConstructor,
        &[JsValue::Str("not defined".into())],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.starts_with("ReferenceError:"));
    } else {
        panic!("expected string");
    }
}

#[test]
fn syntax_error_constructor() {
    let result = exec_error_constructor(
        BuiltinId::SyntaxErrorConstructor,
        &[JsValue::Str("unexpected token".into())],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.starts_with("SyntaxError:"));
    } else {
        panic!("expected string");
    }
}

#[test]
fn error_constructor_no_args_empty_message() {
    let result = exec_error_constructor(BuiltinId::ErrorConstructor, &[]).unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.starts_with("Error:"), "should start with Error: {s}");
    } else {
        panic!("expected string");
    }
}

#[test]
fn error_constructor_wrong_builtin_returns_error() {
    let result = exec_error_constructor(BuiltinId::MathAbs, &[]);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// exec_symbol_static tests
// ---------------------------------------------------------------------------

#[test]
fn symbol_for_returns_symbol() {
    let result = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("myKey".into())]).unwrap();
    assert!(matches!(result, JsValue::Symbol(_)));
}

#[test]
fn symbol_for_deterministic_same_key() {
    let r1 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("key".into())]).unwrap();
    let r2 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("key".into())]).unwrap();
    assert_eq!(r1, r2, "same key should produce same symbol");
}

#[test]
fn symbol_for_different_keys_produce_different_symbols() {
    let r1 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("key1".into())]).unwrap();
    let r2 = exec_symbol_static(BuiltinId::SymbolFor, &[JsValue::Str("key2".into())]).unwrap();
    assert_ne!(r1, r2, "different keys should produce different symbols");
}

#[test]
fn symbol_key_for_returns_undefined() {
    let result =
        exec_symbol_static(BuiltinId::SymbolKeyFor, &[JsValue::Symbol(SymbolId(42))]).unwrap();
    assert_eq!(result, JsValue::Undefined);
}

// ---------------------------------------------------------------------------
// Additional number method tests
// ---------------------------------------------------------------------------

#[test]
fn number_is_safe_integer_true() {
    let result = exec_number_method(BuiltinId::NumberIsSafeInteger, 100 * FP_SCALE, &[]).unwrap();
    assert_eq!(result, JsValue::Bool(true));
}

#[test]
fn number_is_safe_integer_false_for_fractional() {
    let result = exec_number_method(BuiltinId::NumberIsSafeInteger, 500_000, &[]).unwrap();
    assert_eq!(result, JsValue::Bool(false));
}

#[test]
fn number_to_fixed_zero_digits() {
    let result = exec_number_method(
        BuiltinId::NumberPrototypeToFixed,
        3_141_593,
        &[JsValue::Int(0)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("3".into()));
}

#[test]
fn number_to_fixed_two_digits() {
    let result = exec_number_method(
        BuiltinId::NumberPrototypeToFixed,
        3_141_593,
        &[JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.starts_with("3.14"), "expected 3.14..., got {s}");
    }
}

#[test]
fn number_to_fixed_out_of_range_returns_error() {
    let result = exec_number_method(
        BuiltinId::NumberPrototypeToFixed,
        FP_SCALE,
        &[JsValue::Int(21 * FP_SCALE)],
    );
    assert!(result.is_err());
}

#[test]
fn number_to_string_integer() {
    let result =
        exec_number_method(BuiltinId::NumberPrototypeToString, 42 * FP_SCALE, &[]).unwrap();
    assert_eq!(result, JsValue::Str("42".into()));
}

#[test]
fn number_to_string_fractional() {
    let result = exec_number_method(BuiltinId::NumberPrototypeToString, 3_500_000, &[]).unwrap();
    if let JsValue::Str(s) = &result {
        assert!(s.contains('.'), "should contain decimal point: {s}");
    }
}

#[test]
fn number_value_of() {
    let result = exec_number_method(BuiltinId::NumberPrototypeValueOf, 42 * FP_SCALE, &[]).unwrap();
    assert_eq!(result, JsValue::Int(42 * FP_SCALE));
}

// ---------------------------------------------------------------------------
// Additional math edge cases
// ---------------------------------------------------------------------------

#[test]
fn math_sqrt_four() {
    let result = exec_math(BuiltinId::MathSqrt, &[JsValue::Int(4 * FP_SCALE)]).unwrap();
    assert_eq!(result, JsValue::Int(2 * FP_SCALE));
}

#[test]
fn math_pow_zero_exponent() {
    let result = exec_math(
        BuiltinId::MathPow,
        &[JsValue::Int(5 * FP_SCALE), JsValue::Int(0)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(FP_SCALE));
}

#[test]
fn math_max_no_args() {
    let result = exec_math(BuiltinId::MathMax, &[]).unwrap();
    if let JsValue::Int(v) = result {
        assert!(
            v < 0,
            "Math.max() with no args should return -Infinity equivalent"
        );
    }
}

#[test]
fn math_min_no_args() {
    let result = exec_math(BuiltinId::MathMin, &[]).unwrap();
    if let JsValue::Int(v) = result {
        assert!(
            v > 0,
            "Math.min() with no args should return +Infinity equivalent"
        );
    }
}

#[test]
fn math_hypot_3_4() {
    let result = exec_math(
        BuiltinId::MathHypot,
        &[JsValue::Int(3 * FP_SCALE), JsValue::Int(4 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(5 * FP_SCALE));
}

// ---------------------------------------------------------------------------
// Additional string method tests
// ---------------------------------------------------------------------------

#[test]
fn string_replace_basic() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeReplace,
        "hello world",
        &[JsValue::Str("world".into()), JsValue::Str("rust".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("hello rust".into()));
}

#[test]
fn string_search_found() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeSearch,
        "hello world",
        &[JsValue::Str("world".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(6 * FP_SCALE));
}

#[test]
fn string_search_not_found() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeSearch,
        "hello",
        &[JsValue::Str("xyz".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(-FP_SCALE));
}

#[test]
fn string_last_index_of() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeLastIndexOf,
        "abcabc",
        &[JsValue::Str("abc".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(3 * FP_SCALE));
}

#[test]
fn string_char_code_at() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeCharCodeAt,
        "A",
        &[JsValue::Int(0)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(65 * FP_SCALE));
}

#[test]
fn string_repeat_zero() {
    let result =
        exec_string_method(BuiltinId::StringPrototypeRepeat, "x", &[JsValue::Int(0)]).unwrap();
    assert_eq!(result, JsValue::Str(String::new()));
}

#[test]
fn string_normalize_ascii() {
    let result = exec_string_method(BuiltinId::StringPrototypeNormalize, "hello", &[]).unwrap();
    assert_eq!(result, JsValue::Str("hello".into()));
}

#[test]
fn string_representation_scenario_emits_artifact_triad_and_reports() {
    let slice = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeSlice,
        "prefix-😀-suffix",
        &[JsValue::Int(7 * FP_SCALE), JsValue::Int(8 * FP_SCALE)],
    )
    .unwrap();
    let concat = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeConcat,
        &"x".repeat(220),
        &[JsValue::Str("y".repeat(80))],
    )
    .unwrap();
    let normalize =
        exec_string_method_with_receipt(BuiltinId::StringPrototypeNormalize, "Cafe\u{301}", &[])
            .unwrap();

    let receipts = [
        slice.receipt.clone().expect("slice receipt"),
        concat.receipt.clone().expect("concat receipt"),
        normalize.receipt.clone().expect("normalize receipt"),
    ];
    let trace_ids: Vec<String> = receipts
        .iter()
        .map(|receipt| receipt.trace_id.clone())
        .collect();

    let context = DeterministicTestContext::new(
        "bd-1lsy.4.12.1-string-representation",
        "string-representation-fixture",
        HarnessLane::E2e,
        4_121,
    );
    let events = vec![
        context.event(EventInput {
            sequence: 1,
            component: "stdlib",
            event: "string_slice_receipt",
            outcome: "pass",
            error_code: None,
            timing_us: 11,
            timestamp_unix_ms: 1_700_000_004_121,
        }),
        context.event(EventInput {
            sequence: 2,
            component: "stdlib",
            event: "string_concat_receipt",
            outcome: "pass",
            error_code: None,
            timing_us: 17,
            timestamp_unix_ms: 1_700_000_004_122,
        }),
        context.event(EventInput {
            sequence: 3,
            component: "stdlib",
            event: "string_normalize_receipt",
            outcome: "pass",
            error_code: None,
            timing_us: 9,
            timestamp_unix_ms: 1_700_000_004_123,
        }),
    ];
    let commands = vec![
        format!(
            "exec_string_method_with_receipt {} trace_id={}",
            receipts[0].builtin, receipts[0].trace_id
        ),
        format!(
            "exec_string_method_with_receipt {} trace_id={}",
            receipts[1].builtin, receipts[1].trace_id
        ),
        format!(
            "exec_string_method_with_receipt {} trace_id={}",
            receipts[2].builtin, receipts[2].trace_id
        ),
    ];
    let run_id = context.default_run_id();
    let manifest = HarnessRunManifest::from_context(
        &context,
        &run_id,
        events.len(),
        commands.len(),
        "cargo test --test stdlib_integration string_representation_scenario_emits_artifact_triad_and_reports",
        1_700_000_004_199,
    );

    let root = artifact_root("string_representation");
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let trace_ids_path = triad.run_dir.join("trace_ids.json");
    let contract_path = triad
        .run_dir
        .join("bd-1lsy.4.12.1_string_representation_contract.json");
    let budget_path = triad
        .run_dir
        .join("bd-1lsy.4.12.1_string_flatten_budget_report.json");

    let report = StringRepresentationScenarioReport {
        bead_id: "bd-1lsy.4.12.1",
        trace_ids: trace_ids.clone(),
        receipts: receipts
            .iter()
            .map(|receipt| serde_json::to_value(receipt).expect("receipt json"))
            .collect(),
    };
    let budget_report = serde_json::json!({
        "bead_id": "bd-1lsy.4.12.1",
        "flatten_budget_code_units": receipts[1].flatten_budget_code_units,
        "flatten_cost_code_units": receipts[1].flatten_cost_code_units,
        "flatten_budget_exhausted": receipts[1].flatten_budget_exhausted,
        "trace_id": receipts[1].trace_id,
    });

    fs::write(
        &trace_ids_path,
        serde_json::to_vec_pretty(&trace_ids).expect("trace ids json"),
    )
    .expect("write trace ids");
    fs::write(
        &contract_path,
        serde_json::to_vec_pretty(&report).expect("string contract json"),
    )
    .expect("write string contract");
    fs::write(
        &budget_path,
        serde_json::to_vec_pretty(&budget_report).expect("budget json"),
    )
    .expect("write budget report");

    assert!(triad.manifest_path.exists());
    assert!(triad.events_path.exists());
    assert!(triad.commands_path.exists());
    assert!(trace_ids_path.exists());
    assert!(contract_path.exists());
    assert!(budget_path.exists());

    let report_text = fs::read_to_string(&contract_path).expect("read string contract");
    assert!(report_text.contains("bd-1lsy.4.12.1"));
    assert!(report_text.contains("trace-string-"));
}

#[test]
fn string_ascii_fast_path_hotloop_emits_artifact_report() {
    const ITERATIONS: usize = 4_096;

    let prefix = "prefix-".repeat(32);
    let haystack = format!("{prefix}target{}", "-suffix".repeat(32));
    let expected_index_units = prefix.len();
    let slice_args = [
        JsValue::Int(expected_index_units as i64 * FP_SCALE),
        JsValue::Int((expected_index_units + "target".len()) as i64 * FP_SCALE),
    ];
    let search_arg = [JsValue::Str("target".into())];

    for _ in 0..ITERATIONS {
        assert_eq!(
            exec_string_method(
                BuiltinId::StringPrototypeCharCodeAt,
                &haystack,
                &[JsValue::Int(0)],
            )
            .unwrap(),
            JsValue::Int(i64::from(b'p') * FP_SCALE)
        );
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeIndexOf, &haystack, &search_arg).unwrap(),
            JsValue::Int(expected_index_units as i64 * FP_SCALE)
        );
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeSearch, &haystack, &search_arg).unwrap(),
            JsValue::Int(expected_index_units as i64 * FP_SCALE)
        );
        assert_eq!(
            exec_string_method(BuiltinId::StringPrototypeSlice, &haystack, &slice_args).unwrap(),
            JsValue::Str("target".into())
        );
    }

    let traced =
        exec_string_method_with_receipt(BuiltinId::StringPrototypeSlice, &haystack, &slice_args)
            .unwrap();
    let receipt = traced.receipt.expect("slice receipt");
    assert_eq!(traced.value, JsValue::Str("target".into()));
    assert!(receipt.source_is_ascii);
    assert!(receipt.result_is_ascii);

    let context = DeterministicTestContext::new(
        "bd-1lsy.4.12.1-string-ascii-fast-path",
        "string-ascii-fast-path-fixture",
        HarnessLane::E2e,
        4_122,
    );
    let events = vec![
        context.event(EventInput {
            sequence: 1,
            component: "stdlib",
            event: "string_ascii_hotloop_char_code_at",
            outcome: "pass",
            error_code: None,
            timing_us: 8,
            timestamp_unix_ms: 1_700_000_004_221,
        }),
        context.event(EventInput {
            sequence: 2,
            component: "stdlib",
            event: "string_ascii_hotloop_index_of",
            outcome: "pass",
            error_code: None,
            timing_us: 12,
            timestamp_unix_ms: 1_700_000_004_222,
        }),
        context.event(EventInput {
            sequence: 3,
            component: "stdlib",
            event: "string_ascii_hotloop_search",
            outcome: "pass",
            error_code: None,
            timing_us: 12,
            timestamp_unix_ms: 1_700_000_004_223,
        }),
        context.event(EventInput {
            sequence: 4,
            component: "stdlib",
            event: "string_ascii_hotloop_slice",
            outcome: "pass",
            error_code: None,
            timing_us: 14,
            timestamp_unix_ms: 1_700_000_004_224,
        }),
    ];
    let benchmark_command = "cargo test -p frankenengine-engine --test stdlib_integration string_ascii_fast_path_hotloop_emits_artifact_report -- --exact --nocapture".to_string();
    let commands = vec![
        benchmark_command.clone(),
        format!(
            "exec_string_method {} iterations={} ascii_only=true",
            BuiltinId::StringPrototypeCharCodeAt.name(),
            ITERATIONS
        ),
        format!(
            "exec_string_method {} iterations={} ascii_only=true",
            BuiltinId::StringPrototypeIndexOf.name(),
            ITERATIONS
        ),
        format!(
            "exec_string_method {} iterations={} ascii_only=true",
            BuiltinId::StringPrototypeSearch.name(),
            ITERATIONS
        ),
        format!(
            "exec_string_method {} iterations={} trace_id={}",
            BuiltinId::StringPrototypeSlice.name(),
            ITERATIONS,
            receipt.trace_id
        ),
    ];
    let run_id = context.default_run_id();
    let manifest = HarnessRunManifest::from_context(
        &context,
        &run_id,
        events.len(),
        commands.len(),
        &benchmark_command,
        1_700_000_004_299,
    );

    let root = artifact_root("string_ascii_fast_path");
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let trace_ids = vec![receipt.trace_id.clone()];
    let trace_ids_path = triad.run_dir.join("trace_ids.json");
    let report_path = triad
        .run_dir
        .join("bd-1lsy.4.12.1_string_ascii_fast_path_report.json");
    let report = StringAsciiFastPathScenarioReport {
        bead_id: "bd-1lsy.4.12.1",
        iterations: ITERATIONS,
        ascii_only: haystack.is_ascii(),
        haystack_bytes: haystack.len(),
        expected_utf16_index: expected_index_units,
        hotloop_operations: vec![
            BuiltinId::StringPrototypeCharCodeAt.name(),
            BuiltinId::StringPrototypeIndexOf.name(),
            BuiltinId::StringPrototypeSearch.name(),
            BuiltinId::StringPrototypeSlice.name(),
        ],
        trace_id: receipt.trace_id.clone(),
        slice_receipt: serde_json::to_value(&receipt).expect("slice receipt json"),
    };

    fs::write(
        &trace_ids_path,
        serde_json::to_vec_pretty(&trace_ids).expect("trace ids json"),
    )
    .expect("write trace ids");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("ascii fast path report json"),
    )
    .expect("write ascii fast path report");

    assert!(triad.manifest_path.exists());
    assert!(triad.events_path.exists());
    assert!(triad.commands_path.exists());
    assert!(trace_ids_path.exists());
    assert!(report_path.exists());

    let report_text = fs::read_to_string(&report_path).expect("read ascii fast path report");
    assert!(report_text.contains("\"ascii_only\": true"));
    assert!(report_text.contains("\"iterations\": 4096"));
    assert!(report_text.contains("trace-string-"));
}

// ---------------------------------------------------------------------------
// Additional JSON tests
// ---------------------------------------------------------------------------

#[test]
fn json_parse_negative_number() {
    let result = json_parse("-42").unwrap();
    assert_eq!(result, JsValue::Int(-42 * FP_SCALE));
}

#[test]
fn json_stringify_negative_number() {
    let result = json_stringify(&JsValue::Int(-10 * FP_SCALE)).unwrap();
    assert_eq!(result, JsValue::Str("-10".into()));
}

#[test]
fn json_stringify_negative_fractional_number() {
    let result = json_stringify(&JsValue::Int(-(FP_SCALE / 2))).unwrap();
    assert_eq!(result, JsValue::Str("-0.5".into()));
}

#[test]
fn json_stringify_string() {
    let result = json_stringify(&JsValue::Str("hello".into())).unwrap();
    assert_eq!(result, JsValue::Str("\"hello\"".into()));
}

#[test]
fn json_roundtrip_string() {
    let original = JsValue::Str("test value".into());
    let stringified = json_stringify(&original).unwrap();
    if let JsValue::Str(s) = &stringified {
        let parsed = json_parse(s).unwrap();
        assert_eq!(parsed, original);
    }
}

#[test]
fn json_roundtrip_number() {
    let original = JsValue::Int(42 * FP_SCALE);
    let stringified = json_stringify(&original).unwrap();
    if let JsValue::Str(s) = &stringified {
        let parsed = json_parse(s).unwrap();
        assert_eq!(parsed, original);
    }
}

// ---------------------------------------------------------------------------
// Prototype chain verification
// ---------------------------------------------------------------------------

#[test]
fn string_prototype_inherits_from_object_prototype() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let parent = heap
        .get_prototype_of(env.prototypes.string_prototype)
        .unwrap();
    assert_eq!(parent, Some(env.prototypes.object_prototype));
}

#[test]
fn error_prototype_inherits_from_object_prototype() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let parent = heap
        .get_prototype_of(env.prototypes.error_prototype)
        .unwrap();
    assert_eq!(parent, Some(env.prototypes.object_prototype));
}

#[test]
fn type_error_prototype_inherits_from_error_prototype() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let parent = heap
        .get_prototype_of(env.prototypes.type_error_prototype)
        .unwrap();
    assert_eq!(parent, Some(env.prototypes.error_prototype));
}

#[test]
fn map_prototype_inherits_from_object_prototype() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let parent = heap.get_prototype_of(env.prototypes.map_prototype).unwrap();
    assert_eq!(parent, Some(env.prototypes.object_prototype));
}

#[test]
fn set_prototype_inherits_from_object_prototype() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let parent = heap.get_prototype_of(env.prototypes.set_prototype).unwrap();
    assert_eq!(parent, Some(env.prototypes.object_prototype));
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

#[test]
fn registry_lookup_returns_none_for_invalid_slot() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    assert!(env.registry.lookup(u32::MAX).is_none());
}

#[test]
fn registry_entries_all_have_valid_names() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    for (_slot, id) in env.registry.entries() {
        assert!(
            !id.name().is_empty(),
            "builtin {id:?} should have a non-empty name"
        );
    }
}

#[derive(Debug, Serialize)]
struct CollectionMutationScenarioReport {
    bead_id: &'static str,
    trace_ids: Vec<String>,
    final_array: Vec<JsValue>,
    final_map: Vec<(JsValue, JsValue)>,
    final_set: Vec<JsValue>,
}

#[derive(Debug, Serialize)]
struct StringRepresentationScenarioReport {
    bead_id: &'static str,
    trace_ids: Vec<String>,
    receipts: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct StringAsciiFastPathScenarioReport {
    bead_id: &'static str,
    iterations: usize,
    ascii_only: bool,
    haystack_bytes: usize,
    expected_utf16_index: usize,
    hotloop_operations: Vec<&'static str>,
    trace_id: String,
    slice_receipt: serde_json::Value,
}

fn artifact_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should advance")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken_engine_{label}_{nanos}_{}",
        std::process::id()
    ))
}

// ---------------------------------------------------------------------------
// Heap-backed collection mutation semantics
// ---------------------------------------------------------------------------

#[test]
fn heap_array_push_updates_alias_visible_state_and_trace() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let array = alloc_array_instance(
        &mut heap,
        env.prototypes.array_prototype,
        &[JsValue::Int(FP_SCALE), JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    let alias = array;

    let result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::ArrayPrototypePush,
        array,
        &[JsValue::Int(3 * FP_SCALE), JsValue::Int(4 * FP_SCALE)],
    )
    .unwrap();

    assert_eq!(result.value, JsValue::Int(4 * FP_SCALE));
    assert_eq!(
        read_array_elements(&heap, alias).unwrap(),
        vec![
            JsValue::Int(FP_SCALE),
            JsValue::Int(2 * FP_SCALE),
            JsValue::Int(3 * FP_SCALE),
            JsValue::Int(4 * FP_SCALE),
        ]
    );
    assert_eq!(
        heap.get_property(alias, &PropertyKey::from("length"))
            .unwrap(),
        JsValue::Int(4 * FP_SCALE)
    );
    assert_eq!(result.trace.before_size, 2);
    assert_eq!(result.trace.after_size, 4);
    assert!(result.trace.trace_id.starts_with("trace-collection-"));
    assert!(result.trace.mutated_keys.contains(&"2".to_string()));
    assert!(result.trace.mutated_keys.contains(&"3".to_string()));
    assert!(result.trace.mutated_keys.contains(&"length".to_string()));
}

#[test]
fn heap_array_splice_returns_removed_array_and_preserves_order() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let array = alloc_array_instance(
        &mut heap,
        env.prototypes.array_prototype,
        &[
            JsValue::Int(10 * FP_SCALE),
            JsValue::Int(20 * FP_SCALE),
            JsValue::Int(30 * FP_SCALE),
            JsValue::Int(40 * FP_SCALE),
        ],
    )
    .unwrap();

    let result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::ArrayPrototypeSplice,
        array,
        &[
            JsValue::Int(FP_SCALE),
            JsValue::Int(2 * FP_SCALE),
            JsValue::Int(99 * FP_SCALE),
            JsValue::Int(100 * FP_SCALE),
        ],
    )
    .unwrap();

    let removed = match result.value {
        JsValue::Object(handle) => handle,
        other => panic!("expected removed array handle, got {other:?}"),
    };
    assert_eq!(
        read_array_elements(&heap, array).unwrap(),
        vec![
            JsValue::Int(10 * FP_SCALE),
            JsValue::Int(99 * FP_SCALE),
            JsValue::Int(100 * FP_SCALE),
            JsValue::Int(40 * FP_SCALE),
        ]
    );
    assert_eq!(
        read_array_elements(&heap, removed).unwrap(),
        vec![JsValue::Int(20 * FP_SCALE), JsValue::Int(30 * FP_SCALE)]
    );
    assert_eq!(result.trace.before_size, 4);
    assert_eq!(result.trace.after_size, 4);
    assert!(result.trace.mutated_keys.contains(&"1".to_string()));
    assert!(result.trace.mutated_keys.contains(&"2".to_string()));
}

#[test]
fn heap_map_mutation_updates_observable_state_and_keeps_reads_pure() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let map = alloc_map_instance(
        &mut heap,
        env.prototypes.map_prototype,
        &[(JsValue::Str("alpha".into()), JsValue::Int(FP_SCALE))],
    )
    .unwrap();

    let set_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::MapPrototypeSet,
        map,
        &[JsValue::Str("beta".into()), JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(set_result.value, JsValue::Object(map));
    assert_eq!(
        read_map_entries(&heap, map).unwrap(),
        vec![
            (JsValue::Str("alpha".into()), JsValue::Int(FP_SCALE)),
            (JsValue::Str("beta".into()), JsValue::Int(2 * FP_SCALE)),
        ]
    );
    assert_eq!(
        heap.get_property(map, &PropertyKey::from("size")).unwrap(),
        JsValue::Int(2 * FP_SCALE)
    );

    let get_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::MapPrototypeGet,
        map,
        &[JsValue::Str("beta".into())],
    )
    .unwrap();
    assert_eq!(get_result.value, JsValue::Int(2 * FP_SCALE));
    assert!(get_result.trace.mutated_keys.is_empty());

    let delete_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::MapPrototypeDelete,
        map,
        &[JsValue::Str("alpha".into())],
    )
    .unwrap();
    assert_eq!(delete_result.value, JsValue::Bool(true));
    assert_eq!(
        read_map_entries(&heap, map).unwrap(),
        vec![(JsValue::Str("beta".into()), JsValue::Int(2 * FP_SCALE))]
    );

    exec_heap_collection_method(&mut heap, BuiltinId::MapPrototypeClear, map, &[]).unwrap();
    assert!(read_map_entries(&heap, map).unwrap().is_empty());
    assert_eq!(
        heap.get_property(map, &PropertyKey::from("size")).unwrap(),
        JsValue::Int(0)
    );
}

#[test]
fn heap_set_mutation_preserves_uniqueness_and_alias_visibility() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let set = alloc_set_instance(
        &mut heap,
        env.prototypes.set_prototype,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();

    let duplicate = exec_heap_collection_method(
        &mut heap,
        BuiltinId::SetPrototypeAdd,
        set,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();
    assert_eq!(duplicate.value, JsValue::Object(set));
    assert!(duplicate.trace.mutated_keys.is_empty());

    let add_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::SetPrototypeAdd,
        set,
        &[JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(add_result.value, JsValue::Object(set));
    assert_eq!(
        read_set_values(&heap, set).unwrap(),
        vec![JsValue::Int(FP_SCALE), JsValue::Int(2 * FP_SCALE)]
    );

    let has_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::SetPrototypeHas,
        set,
        &[JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    assert_eq!(has_result.value, JsValue::Bool(true));
    assert!(has_result.trace.mutated_keys.is_empty());

    let delete_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::SetPrototypeDelete,
        set,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();
    assert_eq!(delete_result.value, JsValue::Bool(true));
    assert_eq!(
        read_set_values(&heap, set).unwrap(),
        vec![JsValue::Int(2 * FP_SCALE)]
    );
    assert_eq!(
        heap.get_property(set, &PropertyKey::from("size")).unwrap(),
        JsValue::Int(FP_SCALE)
    );
}

#[test]
fn heap_collection_methods_reject_wrong_receiver_kind() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let plain = heap.alloc(Some(env.prototypes.object_prototype));
    let err = exec_heap_collection_method(
        &mut heap,
        BuiltinId::ArrayPrototypePush,
        plain,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap_err();
    assert!(matches!(err, StdlibError::TypeError(msg) if msg.contains("Array")));
}

#[test]
fn heap_array_internal_reads_fail_closed_on_inherited_slots() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let array = alloc_array_instance(
        &mut heap,
        env.prototypes.array_prototype,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();

    heap.delete_property(array, &PropertyKey::from("length"))
        .unwrap();
    heap.define_property(
        env.prototypes.array_prototype,
        PropertyKey::from("length"),
        PropertyDescriptor::data(JsValue::Int(FP_SCALE)),
    )
    .unwrap();
    heap.define_property(
        env.prototypes.array_prototype,
        PropertyKey::from("0"),
        PropertyDescriptor::data(JsValue::Int(99 * FP_SCALE)),
    )
    .unwrap();

    let err = read_array_elements(&heap, array).unwrap_err();
    assert!(matches!(err, StdlibError::TypeError(msg) if msg.contains("own data property")));
}

#[test]
fn heap_map_internal_reads_fail_closed_on_inherited_hidden_slots() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let map = alloc_map_instance(
        &mut heap,
        env.prototypes.map_prototype,
        &[(JsValue::Str("alpha".into()), JsValue::Int(FP_SCALE))],
    )
    .unwrap();

    heap.delete_property(map, &PropertyKey::from("[[MapNextIndex]]"))
        .unwrap();
    heap.define_property(
        env.prototypes.map_prototype,
        PropertyKey::from("[[MapNextIndex]]"),
        PropertyDescriptor::data(JsValue::Int(FP_SCALE)),
    )
    .unwrap();
    heap.define_property(
        env.prototypes.map_prototype,
        PropertyKey::from("[[MapKey]]:0"),
        PropertyDescriptor::data(JsValue::Str("spoofed".into())),
    )
    .unwrap();
    heap.define_property(
        env.prototypes.map_prototype,
        PropertyKey::from("[[MapValue]]:0"),
        PropertyDescriptor::data(JsValue::Int(99 * FP_SCALE)),
    )
    .unwrap();

    let err = read_map_entries(&heap, map).unwrap_err();
    assert!(matches!(err, StdlibError::TypeError(msg) if msg.contains("own data property")));
}

#[test]
fn heap_array_internal_reads_fail_closed_on_inherited_element_slots() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let array = alloc_array_instance(
        &mut heap,
        env.prototypes.array_prototype,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();

    heap.delete_property(array, &PropertyKey::from("0"))
        .unwrap();
    heap.define_property(
        env.prototypes.array_prototype,
        PropertyKey::from("0"),
        PropertyDescriptor::data(JsValue::Int(99 * FP_SCALE)),
    )
    .unwrap();

    let err = read_array_elements(&heap, array).unwrap_err();
    assert!(matches!(err, StdlibError::TypeError(msg) if msg.contains("own data property")));
}

#[test]
fn heap_map_internal_reads_fail_closed_on_inherited_entry_slots() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let map = alloc_map_instance(
        &mut heap,
        env.prototypes.map_prototype,
        &[(JsValue::Str("alpha".into()), JsValue::Int(FP_SCALE))],
    )
    .unwrap();

    heap.delete_property(map, &PropertyKey::from("[[MapValue]]:0"))
        .unwrap();
    heap.define_property(
        env.prototypes.map_prototype,
        PropertyKey::from("[[MapValue]]:0"),
        PropertyDescriptor::data(JsValue::Int(99 * FP_SCALE)),
    )
    .unwrap();

    let err = read_map_entries(&heap, map).unwrap_err();
    assert!(matches!(err, StdlibError::TypeError(msg) if msg.contains("own data property")));
}

#[test]
fn heap_set_internal_reads_fail_closed_on_inherited_hidden_slots() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let set = alloc_set_instance(
        &mut heap,
        env.prototypes.set_prototype,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();

    heap.delete_property(set, &PropertyKey::from("[[SetNextIndex]]"))
        .unwrap();
    heap.define_property(
        env.prototypes.set_prototype,
        PropertyKey::from("[[SetNextIndex]]"),
        PropertyDescriptor::data(JsValue::Int(FP_SCALE)),
    )
    .unwrap();
    heap.define_property(
        env.prototypes.set_prototype,
        PropertyKey::from("[[SetValue]]:0"),
        PropertyDescriptor::data(JsValue::Int(99 * FP_SCALE)),
    )
    .unwrap();

    let err = read_set_values(&heap, set).unwrap_err();
    assert!(matches!(err, StdlibError::TypeError(msg) if msg.contains("own data property")));
}

#[test]
fn heap_set_internal_reads_fail_closed_on_inherited_value_slots() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let set = alloc_set_instance(
        &mut heap,
        env.prototypes.set_prototype,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();

    heap.delete_property(set, &PropertyKey::from("[[SetValue]]:0"))
        .unwrap();
    heap.define_property(
        env.prototypes.set_prototype,
        PropertyKey::from("[[SetValue]]:0"),
        PropertyDescriptor::data(JsValue::Int(99 * FP_SCALE)),
    )
    .unwrap();

    let err = read_set_values(&heap, set).unwrap_err();
    assert!(matches!(err, StdlibError::TypeError(msg) if msg.contains("own data property")));
}

#[test]
fn collection_mutation_scenario_emits_artifact_triad_and_reports() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);

    let array = alloc_array_instance(
        &mut heap,
        env.prototypes.array_prototype,
        &[JsValue::Int(FP_SCALE), JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    let map = alloc_map_instance(
        &mut heap,
        env.prototypes.map_prototype,
        &[(JsValue::Str("alpha".into()), JsValue::Int(FP_SCALE))],
    )
    .unwrap();
    let set = alloc_set_instance(
        &mut heap,
        env.prototypes.set_prototype,
        &[JsValue::Int(FP_SCALE)],
    )
    .unwrap();

    let array_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::ArrayPrototypePush,
        array,
        &[JsValue::Int(3 * FP_SCALE)],
    )
    .unwrap();
    let map_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::MapPrototypeSet,
        map,
        &[JsValue::Str("beta".into()), JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    let set_result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::SetPrototypeAdd,
        set,
        &[JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();

    let trace_ids = vec![
        array_result.trace.trace_id.clone(),
        map_result.trace.trace_id.clone(),
        set_result.trace.trace_id.clone(),
    ];

    let context = DeterministicTestContext::new(
        "bd-1lsy.4.9.2-collection-mutation",
        "heap-backed-collection-fixture",
        HarnessLane::E2e,
        4_902,
    );
    let events = vec![
        context.event(EventInput {
            sequence: 1,
            component: "stdlib",
            event: "array_push",
            outcome: "pass",
            error_code: None,
            timing_us: 19,
            timestamp_unix_ms: 1_700_000_004_902,
        }),
        context.event(EventInput {
            sequence: 2,
            component: "stdlib",
            event: "map_set",
            outcome: "pass",
            error_code: None,
            timing_us: 23,
            timestamp_unix_ms: 1_700_000_004_903,
        }),
        context.event(EventInput {
            sequence: 3,
            component: "stdlib",
            event: "set_add",
            outcome: "pass",
            error_code: None,
            timing_us: 17,
            timestamp_unix_ms: 1_700_000_004_904,
        }),
    ];
    let commands = vec![
        format!(
            "exec_heap_collection_method {} trace_id={}",
            array_result.trace.builtin, array_result.trace.trace_id
        ),
        format!(
            "exec_heap_collection_method {} trace_id={}",
            map_result.trace.builtin, map_result.trace.trace_id
        ),
        format!(
            "exec_heap_collection_method {} trace_id={}",
            set_result.trace.builtin, set_result.trace.trace_id
        ),
    ];
    let run_id = context.default_run_id();
    let manifest = HarnessRunManifest::from_context(
        &context,
        &run_id,
        events.len(),
        commands.len(),
        "cargo test --test stdlib_integration collection_mutation_scenario_emits_artifact_triad_and_reports",
        1_700_000_004_999,
    );

    let root = artifact_root("collection_mutation_semantics");
    let triad = write_artifact_triad(&root, &manifest, &events, &commands).unwrap();
    let trace_ids_path = triad.run_dir.join("trace_ids.json");
    let report_path = triad
        .run_dir
        .join("bd-1lsy.4.9.2_collection_mutation_report.json");
    let report = CollectionMutationScenarioReport {
        bead_id: "bd-1lsy.4.9.2",
        trace_ids: trace_ids.clone(),
        final_array: read_array_elements(&heap, array).unwrap(),
        final_map: read_map_entries(&heap, map).unwrap(),
        final_set: read_set_values(&heap, set).unwrap(),
    };

    fs::write(
        &trace_ids_path,
        serde_json::to_vec_pretty(&trace_ids).expect("trace ids json"),
    )
    .expect("write trace ids");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&report).expect("report json"),
    )
    .expect("write report");

    assert!(triad.manifest_path.exists());
    assert!(triad.events_path.exists());
    assert!(triad.commands_path.exists());
    assert!(trace_ids_path.exists());
    assert!(report_path.exists());

    let report_text = fs::read_to_string(&report_path).expect("read report");
    assert!(report_text.contains("bd-1lsy.4.9.2"));
    assert!(report_text.contains("trace-collection-"));
}
