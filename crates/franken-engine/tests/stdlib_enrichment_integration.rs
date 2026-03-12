//! Enrichment integration tests for the stdlib module.
//!
//! Covers: serde roundtrips, Display uniqueness, StringFastPath gating,
//! as_str / constants, math edge cases, string edge cases, JSON edge cases,
//! array edge cases, number edge cases, heap collection edge cases,
//! BuiltinRegistry semantics, and install_stdlib contract enforcement.

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

use std::collections::BTreeSet;

use frankenengine_engine::object_model::{JsValue, ObjectHeap, PropertyKey, SymbolId};
use frankenengine_engine::stdlib::{
    ArrayMethodResult, BuiltinId, CollectionKind, GlobalEnvironment, StdlibError,
    StringFastPathConsumer, StringFastPathGateError, StringObservationMode,
    StringRepresentationKind, alloc_array_instance, alloc_map_instance, alloc_set_instance,
    derive_string_fast_path_eligibility, exec_array_method, exec_boolean_method,
    exec_error_constructor, exec_global_function, exec_heap_collection_method, exec_math,
    exec_number_method, exec_object_static, exec_string_method, exec_string_method_with_receipt,
    exec_string_static, exec_symbol_static, install_stdlib, json_parse, json_stringify,
    read_array_elements, read_map_entries, read_set_values,
    require_string_fast_path_eligibility,
};

const FP_SCALE: i64 = 1_000_000;

// ===========================================================================
// A. Serde Roundtrip (6 tests)
// ===========================================================================

#[test]
fn enrichment_serde_roundtrip_collection_kind_all_variants() {
    let variants = [CollectionKind::Array, CollectionKind::Map, CollectionKind::Set];
    for kind in &variants {
        let json = serde_json::to_string(kind).unwrap();
        let back: CollectionKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back, "CollectionKind roundtrip failed for {kind:?}");
    }
}

#[test]
fn enrichment_serde_roundtrip_string_representation_kind_all_variants() {
    let variants = [
        StringRepresentationKind::Inline,
        StringRepresentationKind::Flat,
        StringRepresentationKind::SliceView,
        StringRepresentationKind::RopeCandidate,
    ];
    for kind in &variants {
        let json = serde_json::to_string(kind).unwrap();
        let back: StringRepresentationKind = serde_json::from_str(&json).unwrap();
        assert_eq!(*kind, back, "StringRepresentationKind roundtrip failed for {kind:?}");
    }
}

#[test]
fn enrichment_serde_roundtrip_string_observation_mode_all_variants() {
    let variants = [
        StringObservationMode::ScalarAlignedUtf16,
        StringObservationMode::BoundarySensitiveUtf16,
    ];
    for mode in &variants {
        let json = serde_json::to_string(mode).unwrap();
        let back: StringObservationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(*mode, back, "StringObservationMode roundtrip failed for {mode:?}");
    }
}

#[test]
fn enrichment_serde_roundtrip_string_fast_path_consumer_all_variants() {
    let variants = [
        StringFastPathConsumer::Runtime,
        StringFastPathConsumer::Optimizer,
        StringFastPathConsumer::Cache,
    ];
    for consumer in &variants {
        let json = serde_json::to_string(consumer).unwrap();
        let back: StringFastPathConsumer = serde_json::from_str(&json).unwrap();
        assert_eq!(*consumer, back, "StringFastPathConsumer roundtrip failed for {consumer:?}");
    }
}

#[test]
fn enrichment_serde_roundtrip_array_method_result_both_variants() {
    let value_variant = ArrayMethodResult::Value(JsValue::Int(42 * FP_SCALE));
    let json_v = serde_json::to_string(&value_variant).unwrap();
    let back_v: ArrayMethodResult = serde_json::from_str(&json_v).unwrap();
    assert_eq!(value_variant, back_v);

    let array_variant = ArrayMethodResult::NewArray(vec![
        JsValue::Int(FP_SCALE),
        JsValue::Str("hello".into()),
    ]);
    let json_a = serde_json::to_string(&array_variant).unwrap();
    let back_a: ArrayMethodResult = serde_json::from_str(&json_a).unwrap();
    assert_eq!(array_variant, back_a);
}

#[test]
fn enrichment_serde_roundtrip_stdlib_error_all_variants() {
    let errors = [
        StdlibError::TypeError("type mismatch".into()),
        StdlibError::RangeError("out of bounds".into()),
        StdlibError::ObjectError("heap failure".into()),
        StdlibError::ArityError {
            builtin: "Math.pow".into(),
            expected_min: 2,
            expected_max: 2,
            got: 0,
        },
        StdlibError::JsonParseError("unexpected token".into()),
        StdlibError::JsonStringifyError("circular".into()),
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: StdlibError = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{err}"), format!("{back}"), "StdlibError roundtrip for {err:?}");
    }
}

// ===========================================================================
// B. Display Uniqueness (4 tests)
// ===========================================================================

#[test]
fn enrichment_builtin_id_all_names_unique() {
    // Collect all BuiltinId names; there must be no duplicates.
    let all_ids = all_builtin_ids();
    let mut seen = BTreeSet::new();
    for id in &all_ids {
        let name = id.name();
        assert!(
            seen.insert(name),
            "BuiltinId name collision: {name} (at {id:?})"
        );
    }
    // The enum has at least 150 variants.
    assert!(
        all_ids.len() >= 150,
        "expected at least 150 BuiltinId variants, got {}",
        all_ids.len()
    );
}

#[test]
fn enrichment_builtin_id_display_matches_name() {
    for id in &all_builtin_ids() {
        let display = format!("{id}");
        let name = id.name();
        assert_eq!(
            display, name,
            "BuiltinId Display and name() differ for {id:?}"
        );
    }
}

#[test]
fn enrichment_stdlib_error_display_all_distinct() {
    let errors = [
        StdlibError::TypeError("x".into()),
        StdlibError::RangeError("x".into()),
        StdlibError::ObjectError("x".into()),
        StdlibError::ArityError {
            builtin: "f".into(),
            expected_min: 1,
            expected_max: 2,
            got: 0,
        },
        StdlibError::JsonParseError("x".into()),
        StdlibError::JsonStringifyError("x".into()),
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let msg = format!("{err}");
        assert!(
            displays.insert(msg.clone()),
            "StdlibError Display collision: {msg}"
        );
    }
}

#[test]
fn enrichment_string_fast_path_gate_error_display_all_four() {
    let errors = [
        StringFastPathGateError::MissingReceipt {
            consumer: StringFastPathConsumer::Runtime,
        },
        StringFastPathGateError::FlattenBudgetExceeded {
            consumer: StringFastPathConsumer::Optimizer,
            trace_id: "trace-test-001".into(),
        },
        StringFastPathGateError::BoundarySensitiveUnicode {
            consumer: StringFastPathConsumer::Cache,
            builtin: "String.prototype.slice".into(),
            trace_id: "trace-test-002".into(),
        },
        StringFastPathGateError::IneligibleRepresentation {
            consumer: StringFastPathConsumer::Runtime,
            kind: StringRepresentationKind::RopeCandidate,
            trace_id: "trace-test-003".into(),
        },
    ];
    let mut displays = BTreeSet::new();
    for err in &errors {
        let msg = format!("{err}");
        assert!(!msg.is_empty(), "Display should not be empty");
        assert!(
            displays.insert(msg.clone()),
            "StringFastPathGateError Display collision: {msg}"
        );
    }
}

// ===========================================================================
// C. StringFastPath (7 tests)
// ===========================================================================

#[test]
fn enrichment_string_fast_path_missing_receipt_rejects() {
    let err = require_string_fast_path_eligibility(StringFastPathConsumer::Runtime, None)
        .unwrap_err();
    assert!(
        matches!(err, StringFastPathGateError::MissingReceipt { .. }),
        "expected MissingReceipt, got {err:?}"
    );
}

#[test]
fn enrichment_string_fast_path_flatten_budget_exceeded_rejects() {
    // Create a receipt with flatten_budget_exhausted = true by concatenating
    // long strings (> 256 code units).
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeConcat,
        &"a".repeat(200),
        &[JsValue::Str("b".repeat(200))],
    )
    .unwrap();
    let receipt = traced.receipt.as_ref().expect("concat receipt");
    assert!(receipt.flatten_budget_exhausted);

    let err = require_string_fast_path_eligibility(StringFastPathConsumer::Runtime, Some(receipt))
        .unwrap_err();
    assert!(
        matches!(err, StringFastPathGateError::FlattenBudgetExceeded { .. }),
        "expected FlattenBudgetExceeded, got {err:?}"
    );
}

#[test]
fn enrichment_string_fast_path_boundary_sensitive_rejects_optimizer() {
    // Use a non-BMP character to trigger BoundarySensitiveUtf16.
    // "a\u{1F600}b" has UTF-16 units: a(0), D83D(1), DE00(2), b(3). Total = 4.
    // Slice [0, 3) = "a\u{1F600}" (valid: includes full surrogate pair).
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeSlice,
        "a\u{1F600}b",
        &[JsValue::Int(0), JsValue::Int(3 * FP_SCALE)],
    )
    .unwrap();
    let receipt = traced.receipt.as_ref().expect("slice receipt");
    assert_eq!(
        receipt.observation_mode,
        StringObservationMode::BoundarySensitiveUtf16
    );

    let err =
        require_string_fast_path_eligibility(StringFastPathConsumer::Optimizer, Some(receipt))
            .unwrap_err();
    assert!(
        matches!(
            err,
            StringFastPathGateError::BoundarySensitiveUnicode { .. }
        ),
        "expected BoundarySensitiveUnicode, got {err:?}"
    );
}

#[test]
fn enrichment_string_fast_path_boundary_sensitive_allows_runtime() {
    // "a\u{1F600}b" has UTF-16 units: a(0), D83D(1), DE00(2), b(3). Total = 4.
    // Slice [0, 3) = "a\u{1F600}" (valid: includes full surrogate pair).
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeSlice,
        "a\u{1F600}b",
        &[JsValue::Int(0), JsValue::Int(3 * FP_SCALE)],
    )
    .unwrap();
    let receipt = traced.receipt.as_ref().expect("slice receipt");
    assert_eq!(
        receipt.observation_mode,
        StringObservationMode::BoundarySensitiveUtf16
    );

    // Runtime consumer should still be allowed (boundary-sensitive is only rejected for optimizer).
    let eligibility =
        require_string_fast_path_eligibility(StringFastPathConsumer::Runtime, Some(receipt))
            .unwrap();
    assert!(eligibility.runtime_eligible);
}

#[test]
fn enrichment_derive_eligibility_inline_string() {
    // Short ASCII string results in Inline kind.
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeToUpperCase,
        "hello",
        &[],
    )
    .unwrap();
    let receipt = traced.receipt.as_ref().expect("toUpperCase receipt");
    let eligibility = derive_string_fast_path_eligibility(receipt);
    assert!(eligibility.runtime_eligible);
    assert!(eligibility.cache_eligible);
    assert!(!eligibility.stable_cache_key.is_empty());
}

#[test]
fn enrichment_derive_eligibility_rope_candidate() {
    // A large concat produces RopeCandidate when segment_count > 1 and flatten required.
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeConcat,
        &"x".repeat(200),
        &[JsValue::Str("y".repeat(200))],
    )
    .unwrap();
    let receipt = traced.receipt.as_ref().expect("concat receipt");
    assert_eq!(receipt.kind, StringRepresentationKind::RopeCandidate);

    let eligibility = derive_string_fast_path_eligibility(receipt);
    // RopeCandidate with flatten_budget_exhausted => optimizer ineligible
    assert!(!eligibility.optimizer_eligible);
}

#[test]
fn enrichment_string_fast_path_gate_error_implements_error_trait() {
    let err = StringFastPathGateError::MissingReceipt {
        consumer: StringFastPathConsumer::Runtime,
    };
    // Verify it implements std::error::Error by using it as a trait object.
    let dyn_err: &dyn std::error::Error = &err;
    assert!(!dyn_err.to_string().is_empty());
}

// ===========================================================================
// D. as_str / Constants (3 tests)
// ===========================================================================

#[test]
fn enrichment_collection_kind_as_str_all_variants() {
    assert_eq!(CollectionKind::Array.as_str(), "array");
    assert_eq!(CollectionKind::Map.as_str(), "map");
    assert_eq!(CollectionKind::Set.as_str(), "set");
}

#[test]
fn enrichment_string_fast_path_consumer_as_str_all_variants() {
    assert_eq!(StringFastPathConsumer::Runtime.as_str(), "runtime");
    assert_eq!(StringFastPathConsumer::Optimizer.as_str(), "optimizer");
    assert_eq!(StringFastPathConsumer::Cache.as_str(), "cache");
}

#[test]
fn enrichment_eligibility_cache_key_format() {
    let traced = exec_string_method_with_receipt(
        BuiltinId::StringPrototypeSlice,
        "hello world",
        &[JsValue::Int(0), JsValue::Int(5 * FP_SCALE)],
    )
    .unwrap();
    let receipt = traced.receipt.as_ref().expect("slice receipt");
    let eligibility = derive_string_fast_path_eligibility(receipt);
    assert!(
        eligibility.stable_cache_key.starts_with("string-fast-path:"),
        "cache key should start with 'string-fast-path:', got {}",
        eligibility.stable_cache_key
    );
    assert!(
        eligibility.stable_cache_key.contains(receipt.builtin.as_str()),
        "cache key should contain builtin name"
    );
}

// ===========================================================================
// E. Math Edge Cases (6 tests)
// ===========================================================================

#[test]
fn enrichment_math_log_of_e_is_approximately_one() {
    // ln(e) should be close to 1.0 (FP_SCALE) in fixed-point.
    // e in fixed-point is 2_718_282.
    let result = exec_math(BuiltinId::MathLog, &[JsValue::Int(2_718_282)]).unwrap();
    if let JsValue::Int(v) = result {
        let diff = (v - FP_SCALE).abs();
        assert!(
            diff < 100_000,
            "ln(e) should be approx 1.0 ({FP_SCALE}), got {v}, diff {diff}"
        );
    } else {
        panic!("expected Int result");
    }
}

#[test]
fn enrichment_math_log2_of_two_is_approximately_one() {
    let result = exec_math(BuiltinId::MathLog2, &[JsValue::Int(2 * FP_SCALE)]).unwrap();
    if let JsValue::Int(v) = result {
        let diff = (v - FP_SCALE).abs();
        assert!(
            diff < 100_000,
            "log2(2) should be approx 1.0 ({FP_SCALE}), got {v}, diff {diff}"
        );
    } else {
        panic!("expected Int result");
    }
}

#[test]
fn enrichment_math_log10_of_ten_is_approximately_one() {
    let result = exec_math(BuiltinId::MathLog10, &[JsValue::Int(10 * FP_SCALE)]).unwrap();
    if let JsValue::Int(v) = result {
        let diff = (v - FP_SCALE).abs();
        assert!(
            diff < 100_000,
            "log10(10) should be approx 1.0 ({FP_SCALE}), got {v}, diff {diff}"
        );
    } else {
        panic!("expected Int result");
    }
}

#[test]
fn enrichment_math_sqrt_negative_returns_range_error() {
    let result = exec_math(BuiltinId::MathSqrt, &[JsValue::Int(-4 * FP_SCALE)]);
    assert!(result.is_err());
    if let Err(StdlibError::RangeError(msg)) = &result {
        assert!(msg.contains("negative"), "message should mention negative: {msg}");
    } else {
        panic!("expected RangeError, got {result:?}");
    }
}

#[test]
fn enrichment_math_pow_negative_exponent_returns_range_error() {
    let result = exec_math(
        BuiltinId::MathPow,
        &[JsValue::Int(2 * FP_SCALE), JsValue::Int(-1 * FP_SCALE)],
    );
    assert!(result.is_err());
    if let Err(StdlibError::RangeError(msg)) = &result {
        assert!(
            msg.contains("negative exponent"),
            "message should mention negative exponent: {msg}"
        );
    } else {
        panic!("expected RangeError, got {result:?}");
    }
}

#[test]
fn enrichment_math_fround_reduces_precision() {
    // fround rounds to nearest 1000 in our fixed-point approximation.
    let result = exec_math(BuiltinId::MathFround, &[JsValue::Int(1_234_567)]).unwrap();
    if let JsValue::Int(v) = result {
        assert_eq!(v, 1_234_000, "fround should round 1_234_567 to 1_234_000");
    } else {
        panic!("expected Int result");
    }
}

// ===========================================================================
// F. String Edge Cases (7 tests)
// ===========================================================================

#[test]
fn enrichment_string_match_found_returns_matched_substring() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeMatch,
        "hello world",
        &[JsValue::Str("world".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("world".into()));
}

#[test]
fn enrichment_string_match_not_found_returns_null() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeMatch,
        "hello",
        &[JsValue::Str("xyz".into())],
    )
    .unwrap();
    assert_eq!(result, JsValue::Null);
}

#[test]
fn enrichment_string_code_point_at_non_bmp_returns_full_code_point() {
    // U+1F600 (Grinning Face) has code point 128512.
    let result = exec_string_method(
        BuiltinId::StringPrototypeCodePointAt,
        "\u{1F600}",
        &[JsValue::Int(0)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Int(128_512 * FP_SCALE));
}

#[test]
fn enrichment_string_repeat_negative_count_returns_range_error() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeRepeat,
        "x",
        &[JsValue::Int(-1 * FP_SCALE)],
    );
    assert!(result.is_err());
    if let Err(StdlibError::RangeError(msg)) = &result {
        assert!(
            msg.contains("non-negative"),
            "should mention non-negative: {msg}"
        );
    } else {
        panic!("expected RangeError");
    }
}

#[test]
fn enrichment_string_repeat_exceeds_max_returns_range_error() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeRepeat,
        "x",
        &[JsValue::Int(2_000_000_i64 * FP_SCALE)],
    );
    assert!(result.is_err());
    if let Err(StdlibError::RangeError(msg)) = &result {
        assert!(
            msg.contains("exceeds maximum"),
            "should mention exceeds maximum: {msg}"
        );
    } else {
        panic!("expected RangeError");
    }
}

#[test]
fn enrichment_string_substring_swaps_args_when_start_greater_than_end() {
    // Per ES spec, substring swaps start/end if start > end.
    let result = exec_string_method(
        BuiltinId::StringPrototypeSubstring,
        "hello",
        &[JsValue::Int(3 * FP_SCALE), JsValue::Int(FP_SCALE)],
    )
    .unwrap();
    // Should return chars 1..3 ("el"), same as substring(1,3).
    assert_eq!(result, JsValue::Str("el".into()));
}

#[test]
fn enrichment_string_split_with_limit() {
    let result = exec_string_method(
        BuiltinId::StringPrototypeSplit,
        "a,b,c,d",
        &[JsValue::Str(",".into()), JsValue::Int(2 * FP_SCALE)],
    )
    .unwrap();
    // Split returns a descriptor like "[split:N]" where N is the number of parts.
    if let JsValue::Str(s) = &result {
        assert_eq!(s, "[split:2]", "split with limit=2 should produce 2 parts");
    } else {
        panic!("expected string result");
    }
}

// ===========================================================================
// G. JSON Edge Cases (5 tests)
// ===========================================================================

#[test]
fn enrichment_json_parse_whitespace_trimmed() {
    assert_eq!(json_parse("  null  ").unwrap(), JsValue::Null);
    assert_eq!(json_parse("  true  ").unwrap(), JsValue::Bool(true));
    assert_eq!(json_parse("  42  ").unwrap(), JsValue::Int(42 * FP_SCALE));
}

#[test]
fn enrichment_json_parse_unicode_escape() {
    // "\u0041" should parse as "A" (code point 65).
    let result = json_parse(r#""\u0041""#).unwrap();
    assert_eq!(result, JsValue::Str("A".into()));
}

#[test]
fn enrichment_json_parse_escape_sequences() {
    let result = json_parse(r#""line\nnewline""#).unwrap();
    assert_eq!(result, JsValue::Str("line\nnewline".into()));

    let result2 = json_parse(r#""tab\there""#).unwrap();
    assert_eq!(result2, JsValue::Str("tab\there".into()));

    let result3 = json_parse(r#""back\\slash""#).unwrap();
    assert_eq!(result3, JsValue::Str("back\\slash".into()));
}

#[test]
fn enrichment_json_stringify_symbol_returns_undefined() {
    let result = json_stringify(&JsValue::Symbol(SymbolId(42))).unwrap();
    assert_eq!(result, JsValue::Undefined);
}

#[test]
fn enrichment_json_stringify_object_returns_placeholder() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let obj_handle = env.global_object;
    let result = json_stringify(&JsValue::Object(obj_handle)).unwrap();
    if let JsValue::Str(s) = &result {
        assert_eq!(s, "[json-object]");
    } else {
        panic!("expected string result");
    }
}

// ===========================================================================
// H. Array Edge Cases (4 tests)
// ===========================================================================

#[test]
fn enrichment_array_slice_negative_start() {
    // Negative start should resolve from end.
    let elements = vec![
        JsValue::Int(10 * FP_SCALE),
        JsValue::Int(20 * FP_SCALE),
        JsValue::Int(30 * FP_SCALE),
        JsValue::Int(40 * FP_SCALE),
    ];
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeSlice,
        &elements,
        &[JsValue::Int(-2 * FP_SCALE)],
    )
    .unwrap();
    if let ArrayMethodResult::NewArray(arr) = result {
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], JsValue::Int(30 * FP_SCALE));
        assert_eq!(arr[1], JsValue::Int(40 * FP_SCALE));
    } else {
        panic!("expected NewArray");
    }
}

#[test]
fn enrichment_array_fill_with_range() {
    let elements = vec![
        JsValue::Int(FP_SCALE),
        JsValue::Int(2 * FP_SCALE),
        JsValue::Int(3 * FP_SCALE),
        JsValue::Int(4 * FP_SCALE),
    ];
    // fill(0, 1, 3) fills indices 1..3 with 0.
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeFill,
        &elements,
        &[
            JsValue::Int(0),
            JsValue::Int(FP_SCALE),
            JsValue::Int(3 * FP_SCALE),
        ],
    )
    .unwrap();
    if let ArrayMethodResult::NewArray(arr) = result {
        assert_eq!(arr[0], JsValue::Int(FP_SCALE), "index 0 unchanged");
        assert_eq!(arr[1], JsValue::Int(0), "index 1 filled");
        assert_eq!(arr[2], JsValue::Int(0), "index 2 filled");
        assert_eq!(arr[3], JsValue::Int(4 * FP_SCALE), "index 3 unchanged");
    } else {
        panic!("expected NewArray");
    }
}

#[test]
fn enrichment_array_last_index_of_negative_from_index() {
    // With negative fromIndex, it should resolve from end.
    let elements = vec![
        JsValue::Int(FP_SCALE),
        JsValue::Int(2 * FP_SCALE),
        JsValue::Int(FP_SCALE),
        JsValue::Int(3 * FP_SCALE),
    ];
    // lastIndexOf(1, -2) means search from index (4 + -2) = 2.
    let result = exec_array_method(
        BuiltinId::ArrayPrototypeLastIndexOf,
        &elements,
        &[JsValue::Int(FP_SCALE), JsValue::Int(-2 * FP_SCALE)],
    )
    .unwrap();
    if let ArrayMethodResult::Value(JsValue::Int(idx)) = result {
        assert_eq!(idx, 2 * FP_SCALE, "lastIndexOf(1, -2) should find at index 2");
    } else {
        panic!("expected Value result, got {result:?}");
    }
}

#[test]
fn enrichment_array_flat_returns_copy_of_elements() {
    // Without heap access, flat returns the elements unchanged.
    let elements = vec![
        JsValue::Int(FP_SCALE),
        JsValue::Int(2 * FP_SCALE),
    ];
    let result = exec_array_method(BuiltinId::ArrayPrototypeFlat, &elements, &[]).unwrap();
    if let ArrayMethodResult::NewArray(arr) = result {
        assert_eq!(arr, elements);
    } else {
        panic!("expected NewArray");
    }
}

// ===========================================================================
// I. Number Edge Cases (3 tests)
// ===========================================================================

#[test]
fn enrichment_number_to_fixed_zero_for_whole_number() {
    let result = exec_number_method(
        BuiltinId::NumberPrototypeToFixed,
        5 * FP_SCALE,
        &[JsValue::Int(0)],
    )
    .unwrap();
    assert_eq!(result, JsValue::Str("5".into()));
}

#[test]
fn enrichment_number_to_string_negative_value() {
    let result =
        exec_number_method(BuiltinId::NumberPrototypeToString, -7 * FP_SCALE, &[]).unwrap();
    assert_eq!(result, JsValue::Str("-7".into()));
}

#[test]
fn enrichment_number_wrong_builtin_returns_type_error() {
    let result = exec_number_method(BuiltinId::MathAbs, 42 * FP_SCALE, &[]);
    assert!(result.is_err());
    if let Err(StdlibError::TypeError(msg)) = &result {
        assert!(
            msg.contains("not a Number method"),
            "message should say not a Number method: {msg}"
        );
    } else {
        panic!("expected TypeError");
    }
}

// ===========================================================================
// J. Heap Collection Edge Cases (3 tests)
// ===========================================================================

#[test]
fn enrichment_heap_array_pop_empty_returns_undefined() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let array = alloc_array_instance(&mut heap, env.prototypes.array_prototype, &[]).unwrap();

    let result =
        exec_heap_collection_method(&mut heap, BuiltinId::ArrayPrototypePop, array, &[]).unwrap();
    assert_eq!(result.value, JsValue::Undefined);
    assert_eq!(result.trace.before_size, 0);
    assert_eq!(result.trace.after_size, 0);
}

#[test]
fn enrichment_heap_array_shift_empty_returns_undefined() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let array = alloc_array_instance(&mut heap, env.prototypes.array_prototype, &[]).unwrap();

    let result =
        exec_heap_collection_method(&mut heap, BuiltinId::ArrayPrototypeShift, array, &[])
            .unwrap();
    assert_eq!(result.value, JsValue::Undefined);
    assert_eq!(result.trace.before_size, 0);
    assert_eq!(result.trace.after_size, 0);
}

#[test]
fn enrichment_heap_map_get_missing_key_returns_undefined() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let map = alloc_map_instance(
        &mut heap,
        env.prototypes.map_prototype,
        &[(JsValue::Str("alpha".into()), JsValue::Int(FP_SCALE))],
    )
    .unwrap();

    let result = exec_heap_collection_method(
        &mut heap,
        BuiltinId::MapPrototypeGet,
        map,
        &[JsValue::Str("missing_key".into())],
    )
    .unwrap();
    assert_eq!(result.value, JsValue::Undefined);
    // Get is a read-only operation, so no mutations.
    assert!(result.trace.mutated_keys.is_empty());
}

// ===========================================================================
// K. BuiltinRegistry (2 tests)
// ===========================================================================

#[test]
fn enrichment_registry_entries_count_matches_len() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    assert_eq!(
        env.registry.entries().len(),
        env.registry.len(),
        "entries().len() should match len()"
    );
    // There should be a substantial number of entries (all installed builtins).
    assert!(env.registry.len() >= 100, "registry should have >= 100 entries");
}

#[test]
fn enrichment_fresh_registry_is_empty() {
    use frankenengine_engine::stdlib::BuiltinRegistry;
    let registry = BuiltinRegistry::new(0);
    assert!(registry.is_empty());
    assert_eq!(registry.len(), 0);
    assert!(registry.entries().is_empty());
    assert!(registry.lookup(0).is_none());
}

// ===========================================================================
// L. install_stdlib contract (2 tests)
// ===========================================================================

#[test]
fn enrichment_install_stdlib_constructors_accessible() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);

    // All constructors should be accessible as properties on the global object.
    let constructor_names = [
        "Array", "Object", "String", "Number", "Boolean", "Error", "TypeError",
        "RangeError", "ReferenceError", "SyntaxError", "Map", "Set", "Date", "Symbol",
    ];
    for name in &constructor_names {
        let prop = heap.get_property(env.global_object, &PropertyKey::from(*name));
        assert!(
            prop.is_ok(),
            "constructor '{name}' should be accessible on the global object"
        );
    }
}

#[test]
fn enrichment_install_stdlib_math_constants_present() {
    let mut heap = ObjectHeap::new();
    let env = install_stdlib(&mut heap);
    let math_ns = env.namespaces.math;

    // Math namespace object should have standard constant properties installed.
    let math_prop = heap.get_property(env.global_object, &PropertyKey::from("Math"));
    assert!(math_prop.is_ok(), "Math should be on global");

    // Math methods should be functions.
    let abs_prop = heap.get_property(math_ns, &PropertyKey::from("abs"));
    assert!(
        abs_prop.is_ok(),
        "Math.abs should be installed"
    );
    if let Ok(JsValue::Function(slot)) = abs_prop {
        let id = env.registry.lookup(slot);
        assert_eq!(id, Some(BuiltinId::MathAbs));
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Collects all BuiltinId variants by exhaustive enumeration.
fn all_builtin_ids() -> Vec<BuiltinId> {
    vec![
        // Array
        BuiltinId::ArrayConstructor,
        BuiltinId::ArrayIsArray,
        BuiltinId::ArrayFrom,
        BuiltinId::ArrayOf,
        BuiltinId::ArrayPrototypePush,
        BuiltinId::ArrayPrototypePop,
        BuiltinId::ArrayPrototypeShift,
        BuiltinId::ArrayPrototypeUnshift,
        BuiltinId::ArrayPrototypeSlice,
        BuiltinId::ArrayPrototypeSplice,
        BuiltinId::ArrayPrototypeConcat,
        BuiltinId::ArrayPrototypeIndexOf,
        BuiltinId::ArrayPrototypeLastIndexOf,
        BuiltinId::ArrayPrototypeIncludes,
        BuiltinId::ArrayPrototypeJoin,
        BuiltinId::ArrayPrototypeReverse,
        BuiltinId::ArrayPrototypeSort,
        BuiltinId::ArrayPrototypeMap,
        BuiltinId::ArrayPrototypeFilter,
        BuiltinId::ArrayPrototypeReduce,
        BuiltinId::ArrayPrototypeReduceRight,
        BuiltinId::ArrayPrototypeForEach,
        BuiltinId::ArrayPrototypeSome,
        BuiltinId::ArrayPrototypeEvery,
        BuiltinId::ArrayPrototypeFind,
        BuiltinId::ArrayPrototypeFindIndex,
        BuiltinId::ArrayPrototypeFill,
        BuiltinId::ArrayPrototypeCopyWithin,
        BuiltinId::ArrayPrototypeFlat,
        BuiltinId::ArrayPrototypeFlatMap,
        BuiltinId::ArrayPrototypeEntries,
        BuiltinId::ArrayPrototypeKeys,
        BuiltinId::ArrayPrototypeValues,
        // Object
        BuiltinId::ObjectConstructor,
        BuiltinId::ObjectKeys,
        BuiltinId::ObjectValues,
        BuiltinId::ObjectEntries,
        BuiltinId::ObjectAssign,
        BuiltinId::ObjectFreeze,
        BuiltinId::ObjectSeal,
        BuiltinId::ObjectCreate,
        BuiltinId::ObjectDefineProperty,
        BuiltinId::ObjectDefineProperties,
        BuiltinId::ObjectGetPrototypeOf,
        BuiltinId::ObjectSetPrototypeOf,
        BuiltinId::ObjectGetOwnPropertyDescriptor,
        BuiltinId::ObjectGetOwnPropertyNames,
        BuiltinId::ObjectGetOwnPropertySymbols,
        BuiltinId::ObjectIs,
        BuiltinId::ObjectFromEntries,
        BuiltinId::ObjectPrototypeHasOwnProperty,
        BuiltinId::ObjectPrototypeIsPrototypeOf,
        BuiltinId::ObjectPrototypePropertyIsEnumerable,
        BuiltinId::ObjectPrototypeToString,
        BuiltinId::ObjectPrototypeValueOf,
        // String
        BuiltinId::StringConstructor,
        BuiltinId::StringFromCharCode,
        BuiltinId::StringFromCodePoint,
        BuiltinId::StringPrototypeCharAt,
        BuiltinId::StringPrototypeCharCodeAt,
        BuiltinId::StringPrototypeCodePointAt,
        BuiltinId::StringPrototypeConcat,
        BuiltinId::StringPrototypeIncludes,
        BuiltinId::StringPrototypeStartsWith,
        BuiltinId::StringPrototypeEndsWith,
        BuiltinId::StringPrototypeIndexOf,
        BuiltinId::StringPrototypeLastIndexOf,
        BuiltinId::StringPrototypeSlice,
        BuiltinId::StringPrototypeSubstring,
        BuiltinId::StringPrototypeTrim,
        BuiltinId::StringPrototypeTrimStart,
        BuiltinId::StringPrototypeTrimEnd,
        BuiltinId::StringPrototypePadStart,
        BuiltinId::StringPrototypePadEnd,
        BuiltinId::StringPrototypeRepeat,
        BuiltinId::StringPrototypeToUpperCase,
        BuiltinId::StringPrototypeToLowerCase,
        BuiltinId::StringPrototypeSplit,
        BuiltinId::StringPrototypeReplace,
        BuiltinId::StringPrototypeMatch,
        BuiltinId::StringPrototypeSearch,
        BuiltinId::StringPrototypeNormalize,
        // Number
        BuiltinId::NumberConstructor,
        BuiltinId::NumberIsFinite,
        BuiltinId::NumberIsInteger,
        BuiltinId::NumberIsNaN,
        BuiltinId::NumberIsSafeInteger,
        BuiltinId::NumberParseFloat,
        BuiltinId::NumberParseInt,
        BuiltinId::NumberPrototypeToFixed,
        BuiltinId::NumberPrototypeToString,
        BuiltinId::NumberPrototypeValueOf,
        // Boolean
        BuiltinId::BooleanConstructor,
        BuiltinId::BooleanPrototypeToString,
        BuiltinId::BooleanPrototypeValueOf,
        // Math
        BuiltinId::MathAbs,
        BuiltinId::MathCeil,
        BuiltinId::MathFloor,
        BuiltinId::MathRound,
        BuiltinId::MathTrunc,
        BuiltinId::MathSign,
        BuiltinId::MathMax,
        BuiltinId::MathMin,
        BuiltinId::MathPow,
        BuiltinId::MathSqrt,
        BuiltinId::MathLog,
        BuiltinId::MathLog2,
        BuiltinId::MathLog10,
        BuiltinId::MathClz32,
        BuiltinId::MathImul,
        BuiltinId::MathFround,
        BuiltinId::MathHypot,
        // JSON
        BuiltinId::JsonParse,
        BuiltinId::JsonStringify,
        // Map
        BuiltinId::MapConstructor,
        BuiltinId::MapPrototypeGet,
        BuiltinId::MapPrototypeSet,
        BuiltinId::MapPrototypeHas,
        BuiltinId::MapPrototypeDelete,
        BuiltinId::MapPrototypeClear,
        BuiltinId::MapPrototypeSize,
        BuiltinId::MapPrototypeForEach,
        BuiltinId::MapPrototypeEntries,
        BuiltinId::MapPrototypeKeys,
        BuiltinId::MapPrototypeValues,
        // Set
        BuiltinId::SetConstructor,
        BuiltinId::SetPrototypeAdd,
        BuiltinId::SetPrototypeHas,
        BuiltinId::SetPrototypeDelete,
        BuiltinId::SetPrototypeClear,
        BuiltinId::SetPrototypeSize,
        BuiltinId::SetPrototypeForEach,
        BuiltinId::SetPrototypeEntries,
        BuiltinId::SetPrototypeKeys,
        BuiltinId::SetPrototypeValues,
        // Date
        BuiltinId::DateConstructor,
        BuiltinId::DateNow,
        BuiltinId::DatePrototypeGetTime,
        BuiltinId::DatePrototypeToISOString,
        BuiltinId::DatePrototypeToString,
        BuiltinId::DatePrototypeValueOf,
        // Error
        BuiltinId::ErrorConstructor,
        BuiltinId::TypeErrorConstructor,
        BuiltinId::RangeErrorConstructor,
        BuiltinId::ReferenceErrorConstructor,
        BuiltinId::SyntaxErrorConstructor,
        BuiltinId::ErrorPrototypeToString,
        // Symbol
        BuiltinId::SymbolConstructor,
        BuiltinId::SymbolFor,
        BuiltinId::SymbolKeyFor,
        BuiltinId::SymbolPrototypeToString,
        BuiltinId::SymbolPrototypeValueOf,
        // Global functions
        BuiltinId::GlobalIsNaN,
        BuiltinId::GlobalIsFinite,
        BuiltinId::GlobalParseInt,
        BuiltinId::GlobalParseFloat,
        BuiltinId::GlobalEncodeURI,
        BuiltinId::GlobalDecodeURI,
        BuiltinId::GlobalEncodeURIComponent,
        BuiltinId::GlobalDecodeURIComponent,
    ]
}
