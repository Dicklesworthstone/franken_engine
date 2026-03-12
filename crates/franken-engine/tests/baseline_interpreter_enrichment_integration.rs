#![forbid(unsafe_code)]
//! Enrichment integration tests for `baseline_interpreter` module.
//!
//! Covers: Value::Iterator variant behavior, LaneChoice/LaneReason Display+label+serde,
//! profile label constants, ForIn/ForOf iterator edge cases, IteratorClose,
//! NewArray allocation, TemplateLiteral coercion, HeapObject fields,
//! Construct edge cases, abstract equality, bitwise edge cases,
//! InterpreterError Display/serde, and cross-cutting scenarios.

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

use frankenengine_engine::baseline_interpreter::{
    HeapObject, InterpreterConfig, InterpreterError, LaneChoice, LaneReason, LaneRouter, ObjectId,
    QuickJsLane, V8Lane, Value, DETERMINISTIC_PROFILE_LABEL, LEGACY_QUICKJS_PROFILE_LABEL,
    LEGACY_V8_PROFILE_LABEL, THROUGHPUT_PROFILE_LABEL,
};
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion,
    IteratorCloseReason, RegRange,
};

// ============================================================================
// Helpers
// ============================================================================

fn make_header() -> IrHeader {
    IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir3,
        source_hash: None,
        source_label: "enrichment-test".to_string(),
    }
}

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: make_header(),
        instructions,
        constant_pool: Vec::new(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn test_module_with_pool(instructions: Vec<Ir3Instruction>, pool: Vec<String>) -> Ir3Module {
    let mut m = test_module(instructions);
    m.constant_pool = pool;
    m
}

fn qjs_run(
    module: &Ir3Module,
) -> Result<frankenengine_engine::baseline_interpreter::ExecutionResult, InterpreterError> {
    QuickJsLane::new().execute(module, "enrichment-trace")
}

fn v8_run(
    module: &Ir3Module,
) -> Result<frankenengine_engine::baseline_interpreter::ExecutionResult, InterpreterError> {
    V8Lane::new().execute(module, "enrichment-trace")
}

// ============================================================================
// 1. Value::Iterator variant (7 tests)
// ============================================================================

#[test]
fn enrichment_value_iterator_display() {
    let v = Value::Iterator(42);
    assert_eq!(v.to_string(), "[iterator#42]");
}

#[test]
fn enrichment_value_iterator_is_truthy() {
    // Iterator values are always truthy (like objects).
    assert!(Value::Iterator(0).is_truthy());
    assert!(Value::Iterator(u32::MAX).is_truthy());
}

#[test]
fn enrichment_value_iterator_type_name() {
    assert_eq!(Value::Iterator(0).type_name(), "iterator");
}

#[test]
fn enrichment_value_iterator_typeof_name() {
    // typeof on an iterator returns "object", not "iterator".
    assert_eq!(Value::Iterator(0).typeof_name(), "object");
}

#[test]
fn enrichment_value_iterator_is_nullish() {
    assert!(!Value::Iterator(0).is_nullish());
}

#[test]
fn enrichment_value_iterator_serde_roundtrip() {
    let v = Value::Iterator(99);
    let json = serde_json::to_string(&v).unwrap();
    let back: Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn enrichment_value_iterator_ord() {
    // Iterator variant should be after Function in the enum ordering.
    assert!(Value::Function(0) < Value::Iterator(0));
    // Same variant, different handles: order by handle.
    assert!(Value::Iterator(0) < Value::Iterator(1));
}

// ============================================================================
// 2. LaneChoice/LaneReason Display + label (6 tests)
// ============================================================================

#[test]
fn enrichment_lane_choice_display_deterministic() {
    let choice = LaneChoice::QuickJs;
    assert_eq!(choice.to_string(), "baseline_deterministic_profile");
}

#[test]
fn enrichment_lane_choice_display_throughput() {
    let choice = LaneChoice::V8;
    assert_eq!(choice.to_string(), "baseline_throughput_profile");
}

#[test]
fn enrichment_lane_choice_stable_label() {
    assert_eq!(
        LaneChoice::QuickJs.stable_label(),
        DETERMINISTIC_PROFILE_LABEL
    );
    assert_eq!(LaneChoice::V8.stable_label(), THROUGHPUT_PROFILE_LABEL);
}

#[test]
fn enrichment_lane_choice_legacy_lineage_label() {
    assert_eq!(
        LaneChoice::QuickJs.legacy_lineage_label(),
        LEGACY_QUICKJS_PROFILE_LABEL
    );
    assert_eq!(
        LaneChoice::V8.legacy_lineage_label(),
        LEGACY_V8_PROFILE_LABEL
    );
}

#[test]
fn enrichment_lane_reason_display_all() {
    assert_eq!(
        LaneReason::SecuritySensitive.to_string(),
        "security_sensitive"
    );
    assert_eq!(
        LaneReason::ThroughputOptimized.to_string(),
        "throughput_optimized"
    );
    assert_eq!(LaneReason::PolicyDirective.to_string(), "policy_directive");
    assert_eq!(
        LaneReason::DefaultFallback.to_string(),
        "default_deterministic_profile"
    );
}

#[test]
fn enrichment_lane_reason_stable_label_all() {
    assert_eq!(
        LaneReason::SecuritySensitive.stable_label(),
        "security_sensitive"
    );
    assert_eq!(
        LaneReason::ThroughputOptimized.stable_label(),
        "throughput_optimized"
    );
    assert_eq!(
        LaneReason::PolicyDirective.stable_label(),
        "policy_directive"
    );
    assert_eq!(
        LaneReason::DefaultFallback.stable_label(),
        "default_deterministic_profile"
    );
}

// ============================================================================
// 3. LaneChoice/LaneReason serde (6 tests)
// ============================================================================

#[test]
fn enrichment_lane_choice_serde_legacy_quickjs_label() {
    // Deserialize using legacy label "quickjs_inspired_native".
    let json = format!("\"{}\"", LEGACY_QUICKJS_PROFILE_LABEL);
    let choice: LaneChoice = serde_json::from_str(&json).unwrap();
    assert_eq!(choice, LaneChoice::QuickJs);
}

#[test]
fn enrichment_lane_choice_serde_legacy_v8_label() {
    // Deserialize using legacy label "v8_inspired_native".
    let json = format!("\"{}\"", LEGACY_V8_PROFILE_LABEL);
    let choice: LaneChoice = serde_json::from_str(&json).unwrap();
    assert_eq!(choice, LaneChoice::V8);
}

#[test]
fn enrichment_lane_choice_serde_short_labels() {
    // Short form labels should deserialize.
    let qjs: LaneChoice = serde_json::from_str("\"quickjs\"").unwrap();
    assert_eq!(qjs, LaneChoice::QuickJs);
    let v8: LaneChoice = serde_json::from_str("\"v8\"").unwrap();
    assert_eq!(v8, LaneChoice::V8);
}

#[test]
fn enrichment_lane_choice_serde_unknown_fails() {
    let result = serde_json::from_str::<LaneChoice>("\"unknown_lane\"");
    assert!(result.is_err());
}

#[test]
fn enrichment_lane_reason_serde_alternate_labels() {
    // Alternate casing forms.
    let ss: LaneReason = serde_json::from_str("\"SecuritySensitive\"").unwrap();
    assert_eq!(ss, LaneReason::SecuritySensitive);
    let to: LaneReason = serde_json::from_str("\"ThroughputOptimized\"").unwrap();
    assert_eq!(to, LaneReason::ThroughputOptimized);
    let pd: LaneReason = serde_json::from_str("\"PolicyDirective\"").unwrap();
    assert_eq!(pd, LaneReason::PolicyDirective);
    let df: LaneReason = serde_json::from_str("\"DefaultFallback\"").unwrap();
    assert_eq!(df, LaneReason::DefaultFallback);
}

#[test]
fn enrichment_lane_reason_serde_unknown_fails() {
    let result = serde_json::from_str::<LaneReason>("\"bogus_reason\"");
    assert!(result.is_err());
}

// ============================================================================
// 4. Profile label constants (1 test)
// ============================================================================

#[test]
fn enrichment_profile_labels_non_empty_and_unique() {
    let labels = [
        DETERMINISTIC_PROFILE_LABEL,
        THROUGHPUT_PROFILE_LABEL,
        LEGACY_QUICKJS_PROFILE_LABEL,
        LEGACY_V8_PROFILE_LABEL,
    ];
    for label in &labels {
        assert!(!label.is_empty(), "profile label must be non-empty");
    }
    // All unique.
    let mut seen = std::collections::BTreeSet::new();
    for label in &labels {
        assert!(seen.insert(*label), "duplicate profile label: {label}");
    }
}

// ============================================================================
// 5. ForIn iterator (4 tests)
// ============================================================================

#[test]
fn enrichment_for_in_empty_object() {
    // for..in on an empty object yields no keys and halts.
    // r1 = new object (empty), r2 = ForInInit(r1), then ForInNext immediately done -> jump to halt.
    let m = test_module(vec![
        Ir3Instruction::NewObject { dst: 1 },         // 0: r1 = {}
        Ir3Instruction::ForInInit { src: 1, dst: 2 }, // 1: r2 = iterator
        Ir3Instruction::ForInNext {
            // 2: next -> done_target=4
            iterator: 2,
            value_dst: 3,
            done_target: 4,
        },
        Ir3Instruction::Jump { target: 2 }, // 3: keep iterating (shouldn't reach)
        Ir3Instruction::LoadInt { dst: 0, value: 42 }, // 4: done path
        Ir3Instruction::Halt,               // 5
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn enrichment_for_in_enumerates_keys_in_order() {
    // Create an object with properties "a", "b", "c" (BTreeMap order).
    // Collect first key into r0.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::NewObject { dst: 1 }, // 0: r1 = {}
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            }, // 1: r4 = "a"
            Ir3Instruction::LoadInt { dst: 5, value: 10 }, // 2: r5 = 10
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 4,
                val: 5,
            }, // 3: r1["a"] = 10
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 1,
            }, // 4: r4 = "b"
            Ir3Instruction::LoadInt { dst: 5, value: 20 }, // 5: r5 = 20
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 4,
                val: 5,
            }, // 6: r1["b"] = 20
            Ir3Instruction::ForInInit { src: 1, dst: 2 }, // 7: r2 = iterator
            Ir3Instruction::ForInNext {
                // 8: next
                iterator: 2,
                value_dst: 0,
                done_target: 10,
            },
            Ir3Instruction::Halt, // 9: stop after first key
            Ir3Instruction::Halt, // 10: done (shouldn't reach)
        ],
        vec!["a".to_string(), "b".to_string()],
    );
    let result = qjs_run(&m).unwrap();
    // BTreeMap order: "a" comes first.
    assert_eq!(result.value, Value::Str("a".to_string()));
}

#[test]
fn enrichment_for_in_type_error_on_non_object() {
    // for..in on an integer should yield a TypeError.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 5 }, // 0
        Ir3Instruction::ForInInit { src: 1, dst: 2 }, // 1
    ]);
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::TypeError { expected, got } => {
            assert_eq!(expected, "object");
            assert_eq!(got, "number");
        }
        other => panic!("expected TypeError, got: {other:?}"),
    }
}

#[test]
fn enrichment_for_in_both_lanes_same() {
    // Both QuickJs and V8 lanes produce same keys.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::NewObject { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 5, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 4,
                val: 5,
            },
            Ir3Instruction::ForInInit { src: 1, dst: 2 },
            Ir3Instruction::ForInNext {
                iterator: 2,
                value_dst: 0,
                done_target: 7,
            },
            Ir3Instruction::Halt,
            Ir3Instruction::Halt,
        ],
        vec!["x".to_string()],
    );
    let qjs = qjs_run(&m).unwrap();
    let v8 = v8_run(&m).unwrap();
    assert_eq!(qjs.value, v8.value);
}

// ============================================================================
// 6. ForOf iterator (4 tests)
// ============================================================================

#[test]
fn enrichment_for_of_string_yields_chars() {
    // for..of on "ab" yields "a" then "b".
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            }, // 0: r1 = "ab"
            Ir3Instruction::ForOfInit { src: 1, dst: 2 }, // 1: r2 = iterator
            Ir3Instruction::ForOfNext {
                // 2: next
                iterator: 2,
                value_dst: 0,
                done_target: 4,
            },
            Ir3Instruction::Halt, // 3: stop after first char
            Ir3Instruction::Halt, // 4: done
        ],
        vec!["ab".to_string()],
    );
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Str("a".to_string()));
}

#[test]
fn enrichment_for_of_indexed_properties() {
    // for..of on an object with numeric keys "0", "1" yields values in index order.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::NewObject { dst: 1 }, // 0
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            }, // 1: r4 = "0"
            Ir3Instruction::LoadInt { dst: 5, value: 100 }, // 2: r5 = 100
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 4,
                val: 5,
            }, // 3: r1["0"] = 100
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 1,
            }, // 4: r4 = "1"
            Ir3Instruction::LoadInt { dst: 5, value: 200 }, // 5: r5 = 200
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 4,
                val: 5,
            }, // 6: r1["1"] = 200
            Ir3Instruction::ForOfInit { src: 1, dst: 2 }, // 7
            Ir3Instruction::ForOfNext {
                // 8
                iterator: 2,
                value_dst: 0,
                done_target: 10,
            },
            Ir3Instruction::Halt, // 9: first value
            Ir3Instruction::Halt, // 10: done
        ],
        vec!["0".to_string(), "1".to_string()],
    );
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Int(100));
}

#[test]
fn enrichment_for_of_type_error_on_non_iterable() {
    // for..of on a boolean should yield TypeError.
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::ForOfInit { src: 1, dst: 2 },
    ]);
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::TypeError { expected, got } => {
            assert_eq!(expected, "iterable");
            assert_eq!(got, "boolean");
        }
        other => panic!("expected TypeError, got: {other:?}"),
    }
}

#[test]
fn enrichment_for_of_no_indices_type_error() {
    // Object with non-numeric keys is not iterable for..of.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::NewObject { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 5, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 4,
                val: 5,
            },
            Ir3Instruction::ForOfInit { src: 1, dst: 2 },
        ],
        vec!["not_a_number".to_string()],
    );
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::TypeError { expected, .. } => {
            assert_eq!(expected, "iterable");
        }
        other => panic!("expected TypeError, got: {other:?}"),
    }
}

// ============================================================================
// 7. IteratorClose (2 tests)
// ============================================================================

#[test]
fn enrichment_iterator_close_stops_for_in() {
    // After IteratorClose, ForInNext should jump to done_target.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::NewObject { dst: 1 }, // 0
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 0,
            }, // 1
            Ir3Instruction::LoadInt { dst: 5, value: 1 }, // 2
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 4,
                val: 5,
            }, // 3
            Ir3Instruction::ForInInit { src: 1, dst: 2 }, // 4
            Ir3Instruction::IteratorClose {
                // 5: close immediately
                iterator: 2,
                reason: IteratorCloseReason::Break,
            },
            Ir3Instruction::ForInNext {
                // 6: should jump to done
                iterator: 2,
                value_dst: 3,
                done_target: 8,
            },
            Ir3Instruction::LoadInt { dst: 0, value: 99 }, // 7: should NOT be reached
            Ir3Instruction::LoadInt { dst: 0, value: 42 }, // 8: done path
            Ir3Instruction::Halt,                          // 9
        ],
        vec!["key".to_string()],
    );
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn enrichment_iterator_close_stops_for_of() {
    // After IteratorClose, ForOfNext should jump to done_target.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            }, // 0: r1 = "abc"
            Ir3Instruction::ForOfInit { src: 1, dst: 2 }, // 1
            Ir3Instruction::IteratorClose {
                // 2: close with Return reason
                iterator: 2,
                reason: IteratorCloseReason::Return,
            },
            Ir3Instruction::ForOfNext {
                // 3: should jump to done
                iterator: 2,
                value_dst: 3,
                done_target: 5,
            },
            Ir3Instruction::LoadInt { dst: 0, value: 99 }, // 4: NOT reached
            Ir3Instruction::LoadInt { dst: 0, value: 77 }, // 5: done path
            Ir3Instruction::Halt,                          // 6
        ],
        vec!["abc".to_string()],
    );
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Int(77));
}

// ============================================================================
// 8. NewArray (2 tests)
// ============================================================================

#[test]
fn enrichment_new_array_allocates_object() {
    // NewArray allocates an object on the heap (same as NewObject).
    let m = test_module(vec![
        Ir3Instruction::NewArray { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    match result.value {
        Value::Object(id) => {
            // Object was allocated; id should be valid.
            assert_eq!(id.0, 0);
        }
        other => panic!("expected Object, got: {other:?}"),
    }
}

#[test]
fn enrichment_new_array_distinct_ids() {
    // Two NewArray calls yield distinct object IDs stored in different registers.
    // We verify they are not equal via StrictNotEq.
    let m = test_module(vec![
        Ir3Instruction::NewArray { dst: 1 }, // 0: r1 = Object(0)
        Ir3Instruction::NewArray { dst: 2 }, // 1: r2 = Object(1)
        Ir3Instruction::StrictNotEq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        }, // 2: r0 = r1 !== r2
        Ir3Instruction::Halt,                // 3
    ]);
    let result = qjs_run(&m).unwrap();
    // Two distinct allocations should not be equal.
    assert_eq!(result.value, Value::Bool(true));
}

// ============================================================================
// 9. TemplateLiteral edge cases (4 tests)
// ============================================================================

#[test]
fn enrichment_template_literal_object_coercion() {
    // Object parts in a template literal become "[object Object]".
    let m = test_module(vec![
        Ir3Instruction::NewObject { dst: 1 }, // 0: r1 = {}
        Ir3Instruction::TemplateLiteral {
            // 1
            parts: RegRange { start: 1, count: 1 },
            dst: 0,
        },
        Ir3Instruction::Halt, // 2
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Str("[object Object]".to_string()));
}

#[test]
fn enrichment_template_literal_null_and_undefined_coercion() {
    // Null and Undefined parts coerce to "null" and "undefined".
    let m = test_module(vec![
        Ir3Instruction::LoadNull { dst: 1 },      // 0: r1 = null
        Ir3Instruction::LoadUndefined { dst: 2 }, // 1: r2 = undefined
        Ir3Instruction::TemplateLiteral {
            // 2
            parts: RegRange { start: 1, count: 2 },
            dst: 0,
        },
        Ir3Instruction::Halt, // 3
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Str("nullundefined".to_string()));
}

#[test]
fn enrichment_template_literal_empty_parts() {
    // Zero parts yields an empty string.
    let m = test_module(vec![
        Ir3Instruction::TemplateLiteral {
            parts: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Str(String::new()));
}

#[test]
fn enrichment_template_literal_false_and_negative() {
    // false and negative integers coerce correctly.
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: false,
        }, // 0
        Ir3Instruction::LoadInt { dst: 2, value: -7 }, // 1
        Ir3Instruction::TemplateLiteral {
            // 2
            parts: RegRange { start: 1, count: 2 },
            dst: 0,
        },
        Ir3Instruction::Halt, // 3
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Str("false-7".to_string()));
}

// ============================================================================
// 10. HeapObject fields (3 tests)
// ============================================================================

#[test]
fn enrichment_heap_object_prototype_default() {
    let obj = HeapObject::new();
    assert_eq!(obj.prototype, None);
}

#[test]
fn enrichment_heap_object_constructor_function_default() {
    let obj = HeapObject::new();
    assert_eq!(obj.constructor_function, None);
}

#[test]
fn enrichment_heap_object_serde_with_both_fields() {
    let mut obj = HeapObject::new();
    obj.properties.insert("x".to_string(), Value::Int(1));
    obj.prototype = Some(ObjectId(5));
    obj.constructor_function = Some(3);
    let json = serde_json::to_string(&obj).unwrap();
    let back: HeapObject = serde_json::from_str(&json).unwrap();
    assert_eq!(obj, back);
    assert_eq!(back.prototype, Some(ObjectId(5)));
    assert_eq!(back.constructor_function, Some(3));
}

// ============================================================================
// 11. Construct edge cases (3 tests)
// ============================================================================

#[test]
fn enrichment_construct_non_function_error() {
    // Construct on an integer callee should yield TypeError.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 42 },
        Ir3Instruction::Construct {
            callee: 1,
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
    ]);
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::TypeError { expected, got } => {
            assert_eq!(expected, "function");
            assert_eq!(got, "number");
        }
        other => panic!("expected TypeError, got: {other:?}"),
    }
}

#[test]
fn enrichment_construct_on_undefined_type_error() {
    // Construct on undefined register (default Undefined) is a TypeError.
    let m = test_module(vec![Ir3Instruction::Construct {
        callee: 5, // r5 is Undefined by default
        args: RegRange { start: 0, count: 0 },
        dst: 0,
    }]);
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::TypeError { expected, got } => {
            assert_eq!(expected, "function");
            assert_eq!(got, "undefined");
        }
        other => panic!("expected TypeError, got: {other:?}"),
    }
}

#[test]
fn enrichment_construct_on_string_type_error() {
    // Construct on a string callee should yield TypeError.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::Construct {
                callee: 1,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
        ],
        vec!["NotAFunction".to_string()],
    );
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::TypeError { expected, got } => {
            assert_eq!(expected, "function");
            assert_eq!(got, "string");
        }
        other => panic!("expected TypeError, got: {other:?}"),
    }
}

// ============================================================================
// 12. Abstract equality (5 tests)
// ============================================================================

#[test]
fn enrichment_abstract_eq_null_undefined() {
    // null == undefined should be true.
    let m = test_module(vec![
        Ir3Instruction::LoadNull { dst: 1 },
        Ir3Instruction::LoadUndefined { dst: 2 },
        Ir3Instruction::Eq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn enrichment_abstract_eq_bool_coercion() {
    // true == 1 via numeric coercion.
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 1 },
        Ir3Instruction::Eq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn enrichment_abstract_eq_string_coercion() {
    // "42" == 42 via numeric coercion.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::Eq {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["42".to_string()],
    );
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn enrichment_strict_eq_no_coerce() {
    // true === 1 should be false (strict equality, no coercion).
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 1 },
        Ir3Instruction::StrictEq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn enrichment_not_eq_operator() {
    // 1 != 2 should be true.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 2 },
        Ir3Instruction::NotEq {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Bool(true));
}

// ============================================================================
// 13. Bitwise (2 tests)
// ============================================================================

#[test]
fn enrichment_bitwise_shift_modulo_32() {
    // Shift amount is masked to lower 5 bits (modulo 32).
    // 1 << 33 should be same as 1 << 1 = 2.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 33 },
        Ir3Instruction::Shl {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Int(2));
}

#[test]
fn enrichment_bitwise_bool_coercion() {
    // Booleans coerce to numbers for bitwise ops: true & true = 1.
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadBool {
            dst: 2,
            value: true,
        },
        Ir3Instruction::BitAnd {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = qjs_run(&m).unwrap();
    assert_eq!(result.value, Value::Int(1));
}

// ============================================================================
// 14. InterpreterError Display (2 tests)
// ============================================================================

#[test]
fn enrichment_interpreter_error_display_exact_formats() {
    // Verify exact format strings for specific errors.
    let err1 = InterpreterError::BudgetExhausted {
        executed: 500,
        budget: 100,
    };
    assert_eq!(err1.to_string(), "instruction budget exhausted: 500/100");

    let err2 = InterpreterError::RegisterOutOfBounds {
        register: 300,
        max: 256,
    };
    assert_eq!(err2.to_string(), "register 300 out of bounds (max 256)");

    let err3 = InterpreterError::InstructionOutOfBounds { ip: 10, count: 5 };
    assert_eq!(
        err3.to_string(),
        "instruction pointer 10 out of bounds (5 instructions)"
    );

    let err4 = InterpreterError::StackOverflow {
        depth: 300,
        max: 256,
    };
    assert_eq!(
        err4.to_string(),
        "call stack overflow: depth 300 exceeds max 256"
    );

    let err5 = InterpreterError::TypeError {
        expected: "number".to_string(),
        got: "string".to_string(),
    };
    assert_eq!(err5.to_string(), "type error: expected number, got string");

    let err6 = InterpreterError::DivisionByZero;
    assert_eq!(err6.to_string(), "division by zero");

    let err7 = InterpreterError::UndefinedRegister { register: 7 };
    assert_eq!(err7.to_string(), "undefined register r7");

    let err8 = InterpreterError::ObjectNotFound { id: 42 };
    assert_eq!(err8.to_string(), "object#42 not found");

    let err9 = InterpreterError::PropertyNotFound {
        object_id: 3,
        key: "foo".to_string(),
    };
    assert_eq!(err9.to_string(), "property 'foo' not found on object#3");

    let err10 = InterpreterError::FunctionNotFound {
        index: 5,
        table_size: 2,
    };
    assert_eq!(err10.to_string(), "function#5 not found (table size 2)");

    let err11 = InterpreterError::StringPoolOutOfBounds {
        index: 10,
        pool_size: 3,
    };
    assert_eq!(
        err11.to_string(),
        "string pool index 10 out of bounds (pool size 3)"
    );

    let err12 = InterpreterError::CapabilityDenied {
        capability: "net".to_string(),
    };
    assert_eq!(err12.to_string(), "capability denied: net");

    let err13 = InterpreterError::IteratorNotFound { handle: 7 };
    assert_eq!(err13.to_string(), "iterator#7 not found");

    let err14 = InterpreterError::Halted;
    assert_eq!(err14.to_string(), "execution halted");

    let err15 = InterpreterError::UnsupportedMembershipSemantics {
        operator: "in".to_string(),
    };
    assert_eq!(
        err15.to_string(),
        "unsupported in semantics: baseline interpreter heap is not prototype-aware"
    );
}

#[test]
fn enrichment_iterator_not_found_serde() {
    let err = InterpreterError::IteratorNotFound { handle: 42 };
    let json = serde_json::to_string(&err).unwrap();
    let back: InterpreterError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ============================================================================
// 15. Cross-cutting (3 tests)
// ============================================================================

#[test]
fn enrichment_witness_instruction_index_tracks() {
    // Hostcall decision records the instruction_index where the hostcall occurred.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 }, // 0
        Ir3Instruction::LoadInt { dst: 1, value: 2 }, // 1
        Ir3Instruction::HostCall {
            // 2: hostcall at ip=2
            capability: CapabilityTag("fs".to_string()),
            args: RegRange { start: 0, count: 0 },
            dst: 3,
        },
        Ir3Instruction::Halt, // 3
    ]);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = vec!["fs".to_string()];
    let lane = QuickJsLane::with_config(config);
    let result = lane.execute(&m, "enrichment-trace").unwrap();
    assert!(!result.hostcall_decisions.is_empty());
    let decision = &result.hostcall_decisions[0];
    assert_eq!(decision.instruction_index, 2);
    assert!(decision.allowed);
}

#[test]
fn enrichment_routed_result_clone() {
    // RoutedResult is Clone-able; verify we can clone the result.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::Halt,
    ]);
    let router = LaneRouter::new();
    let result = router.execute(&m, "enrichment-trace", None).unwrap();
    let cloned = result.clone();
    assert_eq!(cloned.lane, result.lane);
    assert_eq!(cloned.reason, result.reason);
    assert_eq!(cloned.result.value, result.result.value);
}

#[test]
fn enrichment_core_re_execute_resets_state() {
    // Creating a fresh InterpreterCore and executing the same module twice yields same results.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        Ir3Instruction::LoadInt { dst: 2, value: 20 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let r1 = qjs_run(&m).unwrap();
    let r2 = qjs_run(&m).unwrap();
    assert_eq!(r1.value, r2.value);
    assert_eq!(r1.instructions_executed, r2.instructions_executed);
    assert_eq!(r1.value, Value::Int(30));
}
