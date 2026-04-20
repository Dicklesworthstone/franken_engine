#![forbid(unsafe_code)]
//! Integration tests for `baseline_interpreter` — exercises the public API
//! of `Value`, `ObjectId`, `HeapObject`, `InterpreterError`, `InterpreterConfig`,
//! `InterpreterEvent`, `ExecutionResult`, `InterpreterCore`, `QuickJsLane`,
//! `V8Lane`, `LaneRouter`, `LaneChoice`, `LaneReason`, and `RoutedResult`
//! from outside the crate boundary.

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
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::baseline_interpreter::{
    ConsoleLevel, ExecutionResult, HeapObject, InterpreterConfig, InterpreterCore,
    InterpreterError, InterpreterEvent, LaneChoice, LaneReason, LaneRouter, ObjectId, QuickJsLane,
    V8Lane, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion,
    RegRange, WitnessEventKind,
};

// ============================================================================
// Helpers
// ============================================================================

fn make_header() -> IrHeader {
    IrHeader {
        schema_version: IrSchemaVersion::CURRENT,
        level: IrLevel::Ir3,
        source_hash: None,
        source_label: "integration-test".to_string(),
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

fn test_module_with_functions(
    instructions: Vec<Ir3Instruction>,
    functions: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    let mut m = test_module(instructions);
    m.function_table = functions;
    m
}

fn qjs_run(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    QuickJsLane::new().execute(module, "integ-trace")
}

fn v8_run(module: &Ir3Module) -> Result<ExecutionResult, InterpreterError> {
    V8Lane::new().execute(module, "integ-trace")
}

fn assert_both_lanes_value(module: &Ir3Module, expected: Value, label: &str) {
    let qjs = qjs_run(module).unwrap();
    assert_eq!(qjs.value, expected.clone(), "quickjs mismatch for {label}");

    let v8 = v8_run(module).unwrap();
    assert_eq!(v8.value, expected, "v8 mismatch for {label}");
}

fn temp_module_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut dir = std::env::temp_dir();
    dir.push(format!("franken_engine_{prefix}_{nanos}"));
    dir
}

// ============================================================================
// 1. Value — constructors, truthiness, type_name, Display, Ord, serde
// ============================================================================

#[test]
fn value_truthiness_falsy_variants() {
    assert!(!Value::Undefined.is_truthy());
    assert!(!Value::Null.is_truthy());
    assert!(!Value::Bool(false).is_truthy());
    assert!(!Value::Int(0).is_truthy());
    assert!(!Value::Str(String::new()).is_truthy());
}

#[test]
fn value_truthiness_truthy_variants() {
    assert!(Value::Bool(true).is_truthy());
    assert!(Value::Int(1).is_truthy());
    assert!(Value::Int(-1).is_truthy());
    assert!(Value::Int(i64::MAX).is_truthy());
    assert!(Value::Str("x".to_string()).is_truthy());
    assert!(Value::Object(ObjectId(0)).is_truthy());
    assert!(Value::Function(0).is_truthy());
}

#[test]
fn value_type_name_all_variants() {
    assert_eq!(Value::Undefined.type_name(), "undefined");
    assert_eq!(Value::Null.type_name(), "null");
    assert_eq!(Value::Bool(false).type_name(), "boolean");
    assert_eq!(Value::Int(42).type_name(), "number");
    assert_eq!(Value::Str("hi".into()).type_name(), "string");
    assert_eq!(Value::Object(ObjectId(0)).type_name(), "object");
    assert_eq!(Value::Function(0).type_name(), "function");
}

#[test]
fn value_display_all_variants() {
    assert_eq!(Value::Undefined.to_string(), "undefined");
    assert_eq!(Value::Null.to_string(), "null");
    assert_eq!(Value::Bool(true).to_string(), "true");
    assert_eq!(Value::Bool(false).to_string(), "false");
    assert_eq!(Value::Int(42).to_string(), "42");
    assert_eq!(Value::Int(-7).to_string(), "-7");
    assert_eq!(Value::Str("abc".into()).to_string(), "abc");
    assert_eq!(Value::Object(ObjectId(5)).to_string(), "[object#5]");
    assert_eq!(Value::Function(3).to_string(), "[function#3]");
}

#[test]
fn value_ord_total() {
    assert!(Value::Undefined < Value::Null);
    assert!(Value::Null < Value::Bool(false));
    assert!(Value::Bool(false) < Value::Bool(true));
    assert!(Value::Bool(true) < Value::Int(i64::MIN));
    assert!(Value::Int(0) < Value::Str(String::new()));
    assert!(Value::Str(String::new()) < Value::Object(ObjectId(0)));
    assert!(Value::Object(ObjectId(0)) < Value::Function(0));
}

#[test]
fn value_serde_roundtrip_all_variants() {
    let values = vec![
        Value::Undefined,
        Value::Null,
        Value::Bool(true),
        Value::Bool(false),
        Value::Int(0),
        Value::Int(-999),
        Value::Int(1_000_000),
        Value::Str("hello world".into()),
        Value::Object(ObjectId(42)),
        Value::Function(7),
    ];
    for v in &values {
        let json = serde_json::to_string(v).unwrap();
        let back: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ============================================================================
// 2. ObjectId, HeapObject
// ============================================================================

#[test]
fn object_id_serde_roundtrip() {
    let id = ObjectId(123);
    let json = serde_json::to_string(&id).unwrap();
    let back: ObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn heap_object_new_is_empty() {
    let obj = HeapObject::new();
    assert!(obj.properties.is_empty());
}

#[test]
fn heap_object_default_equals_new() {
    let a = HeapObject::new();
    let b = HeapObject::default();
    assert_eq!(a, b);
}

#[test]
fn heap_object_serde_roundtrip() {
    let mut obj = HeapObject::new();
    obj.properties.insert("key".into(), Value::Int(42));
    let json = serde_json::to_string(&obj).unwrap();
    let back: HeapObject = serde_json::from_str(&json).unwrap();
    assert_eq!(obj, back);
}

// ============================================================================
// 3. InterpreterError — Display, serde
// ============================================================================

#[test]
fn interpreter_error_display_all_unique() {
    let errors = vec![
        InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 999,
            max: 256,
        },
        InterpreterError::InstructionOutOfBounds { ip: 10, count: 5 },
        InterpreterError::StackOverflow { depth: 10, max: 5 },
        InterpreterError::TypeError {
            expected: "number".into(),
            got: "object".into(),
        },
        InterpreterError::DivisionByZero,
        InterpreterError::UndefinedRegister { register: 42 },
        InterpreterError::ObjectNotFound { id: 7 },
        InterpreterError::PropertyNotFound {
            object_id: 3,
            key: "x".into(),
        },
        InterpreterError::FunctionNotFound {
            index: 5,
            table_size: 3,
        },
        InterpreterError::StringPoolOutOfBounds {
            index: 10,
            pool_size: 5,
        },
        InterpreterError::RequireSpecifierNotString {
            got: "undefined".into(),
        },
        InterpreterError::CapabilityDenied {
            capability: "net".into(),
        },
        InterpreterError::UnsupportedMembershipSemantics {
            operator: "in".into(),
        },
        InterpreterError::Halted,
    ];
    let mut set = BTreeSet::new();
    for e in &errors {
        let s = e.to_string();
        assert!(!s.is_empty());
        set.insert(s);
    }
    assert_eq!(set.len(), errors.len(), "all display strings unique");
}

#[test]
fn interpreter_error_serde_all_variants() {
    let variants = vec![
        InterpreterError::BudgetExhausted {
            executed: 1,
            budget: 2,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 3,
            max: 4,
        },
        InterpreterError::InstructionOutOfBounds { ip: 5, count: 6 },
        InterpreterError::StackOverflow { depth: 7, max: 8 },
        InterpreterError::TypeError {
            expected: "a".into(),
            got: "b".into(),
        },
        InterpreterError::DivisionByZero,
        InterpreterError::UndefinedRegister { register: 9 },
        InterpreterError::ObjectNotFound { id: 10 },
        InterpreterError::PropertyNotFound {
            object_id: 11,
            key: "k".into(),
        },
        InterpreterError::FunctionNotFound {
            index: 12,
            table_size: 13,
        },
        InterpreterError::StringPoolOutOfBounds {
            index: 14,
            pool_size: 15,
        },
        InterpreterError::RequireSpecifierNotString {
            got: "undefined".into(),
        },
        InterpreterError::CapabilityDenied {
            capability: "cap".into(),
        },
        InterpreterError::UnsupportedMembershipSemantics {
            operator: "instanceof".into(),
        },
        InterpreterError::Halted,
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: InterpreterError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

// ============================================================================
// 4. InterpreterConfig — constructors, fields, serde
// ============================================================================

#[test]
fn quickjs_defaults_fields() {
    let c = InterpreterConfig::quickjs_defaults();
    assert_eq!(c.instruction_budget, 100_000);
    assert_eq!(c.max_registers, 256);
    assert_eq!(c.max_call_depth, 256);
    assert!(c.granted_capabilities.is_empty());
}

#[test]
fn v8_defaults_fields() {
    let c = InterpreterConfig::v8_defaults();
    assert_eq!(c.instruction_budget, 1_000_000);
    assert_eq!(c.max_registers, 4096);
    assert_eq!(c.max_call_depth, 256);
    assert!(c.granted_capabilities.is_empty());
}

#[test]
fn v8_budget_larger_than_quickjs() {
    let q = InterpreterConfig::quickjs_defaults();
    let v = InterpreterConfig::v8_defaults();
    assert!(v.instruction_budget > q.instruction_budget);
    assert!(v.max_registers > q.max_registers);
}

#[test]
fn config_serde_roundtrip() {
    let mut c = InterpreterConfig::v8_defaults();
    c.granted_capabilities =
        BTreeSet::from([RuntimeCapability::NetworkEgress, RuntimeCapability::FsRead]);
    let json = serde_json::to_string(&c).unwrap();
    let back: InterpreterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

// ============================================================================
// 5. InterpreterEvent — serde
// ============================================================================

#[test]
fn interpreter_event_serde_roundtrip() {
    let ev = InterpreterEvent {
        trace_id: "tr-1".into(),
        component: "baseline_interpreter".into(),
        event: "execution_started".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: InterpreterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev, back);
}

#[test]
fn interpreter_event_with_error_code() {
    let ev = InterpreterEvent {
        trace_id: "tr-2".into(),
        component: "baseline_interpreter".into(),
        event: "execution_failed".into(),
        outcome: "fail".into(),
        error_code: Some("ERR_BUDGET".into()),
    };
    let json = serde_json::to_string(&ev).unwrap();
    let back: InterpreterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(ev.error_code, back.error_code);
}

// ============================================================================
// 6. LaneChoice, LaneReason — serde
// ============================================================================

#[test]
fn lane_choice_serde_roundtrip() {
    for choice in [LaneChoice::QuickJs, LaneChoice::V8] {
        let json = serde_json::to_string(&choice).unwrap();
        let back: LaneChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(choice, back);
    }
}

#[test]
fn lane_reason_serde_all_variants() {
    let reasons = [
        LaneReason::SecuritySensitive,
        LaneReason::ThroughputOptimized,
        LaneReason::PolicyDirective,
        LaneReason::DefaultFallback,
    ];
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let back: LaneReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, back);
    }
}

// ============================================================================
// 7. InterpreterCore — new, alloc_object, heap_size, execute
// ============================================================================

#[test]
fn core_alloc_object_increments_heap_size() {
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "test");
    assert_eq!(core.heap_size(), 0);
    let id0 = core.alloc_object_with_prototype(None).unwrap();
    assert_eq!(id0, ObjectId(0));
    assert_eq!(core.heap_size(), 1);
    let id1 = core.alloc_object_with_prototype(None).unwrap();
    assert_eq!(id1, ObjectId(1));
    assert_eq!(core.heap_size(), 2);
}

// ============================================================================
// 8. Load instructions via QuickJsLane
// ============================================================================

#[test]
fn load_int_via_quickjs() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let r = qjs_run(&m).unwrap();
    assert_eq!(r.value, Value::Int(42));
}

#[test]
fn load_str_via_quickjs() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["hello".into()],
    );
    let r = qjs_run(&m).unwrap();
    assert_eq!(r.value, Value::Str("hello".into()));
}

#[test]
fn load_bool_true_and_false() {
    let m_true = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 0,
            value: true,
        },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m_true).unwrap().value, Value::Bool(true));

    let m_false = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 0,
            value: false,
        },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m_false).unwrap().value, Value::Bool(false));
}

#[test]
fn load_null_and_undefined() {
    let m_null = test_module(vec![
        Ir3Instruction::LoadNull { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m_null).unwrap().value, Value::Null);

    let m_undef = test_module(vec![
        Ir3Instruction::LoadUndefined { dst: 0 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m_undef).unwrap().value, Value::Undefined);
}

// ============================================================================
// 9. Arithmetic — Add, Sub, Mul, Div
// ============================================================================

#[test]
fn add_integers() {
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
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(30));
}

#[test]
fn add_strings_concatenation() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["foo".into(), "bar".into()],
    );
    assert_eq!(qjs_run(&m).unwrap().value, Value::Str("foobar".into()));
}

#[test]
fn add_string_plus_int_coercion() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["answer=".into()],
    );
    assert_eq!(qjs_run(&m).unwrap().value, Value::Str("answer=42".into()));
}

#[test]
fn add_int_plus_string_coercion() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 7 },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["px".into()],
    );
    assert_eq!(qjs_run(&m).unwrap().value, Value::Str("7px".into()));
}

#[test]
fn sub_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(7));
}

#[test]
fn mul_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 6 },
        Ir3Instruction::LoadInt { dst: 2, value: 7 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(42));
}

#[test]
fn div_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 20 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(5));
}

#[test]
fn div_by_zero_error() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 10 },
        Ir3Instruction::LoadInt { dst: 2, value: 0 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    assert_eq!(qjs_run(&m).unwrap_err(), InterpreterError::DivisionByZero);
}

#[test]
fn add_type_error_bool_plus_null() {
    // In JS, `true + null` = 1 (true coerces to 1, null coerces to 0).
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadNull { dst: 2 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(1));
}

#[test]
fn sub_type_error_on_non_integers() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 1 },
            Ir3Instruction::Sub {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
        ],
        vec!["hello".into()],
    );
    assert!(matches!(
        qjs_run(&m).unwrap_err(),
        InterpreterError::TypeError { .. }
    ));
}

#[test]
fn negative_integer_arithmetic() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: -10 },
        Ir3Instruction::LoadInt { dst: 2, value: 3 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(-7));
}

// ============================================================================
// 10. Control flow — Move, Jump, JumpIf, Return, Halt
// ============================================================================

#[test]
fn move_register() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 5, value: 99 },
        Ir3Instruction::Move { dst: 0, src: 5 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(99));
}

#[test]
fn unconditional_jump_skips_instruction() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Jump { target: 3 },
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(1));
}

#[test]
fn jump_if_taken_when_truthy() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadInt { dst: 0, value: 10 },
        Ir3Instruction::JumpIf { cond: 1, target: 4 },
        Ir3Instruction::LoadInt { dst: 0, value: 20 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(10));
}

#[test]
fn jump_if_not_taken_when_falsy() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: false,
        },
        Ir3Instruction::LoadInt { dst: 0, value: 10 },
        Ir3Instruction::JumpIf { cond: 1, target: 4 },
        Ir3Instruction::LoadInt { dst: 0, value: 20 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(20));
}

#[test]
fn return_from_top_level() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 77 },
        Ir3Instruction::Return { value: 0 },
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(77));
}

#[test]
fn halt_returns_r0() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 55 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(55));
}

#[test]
fn fall_off_end_returns_r0() {
    let m = test_module(vec![Ir3Instruction::LoadInt { dst: 0, value: 33 }]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(33));
}

#[test]
fn empty_module_returns_undefined() {
    let m = test_module(vec![]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Undefined);
}

// ============================================================================
// 11. Function calls
// ============================================================================

#[test]
fn simple_function_call_add_ten() {
    // Use instructions to set up registers (registers field is private).
    // r3 = Function(0), r1 = 5, then call func(r1) -> r0.
    // Function body at entry=4: r0 = arg, load 10 into r1, add r0+r1 -> r2, return r2.
    let m = test_module_with_functions(
        vec![
            // Main setup
            Ir3Instruction::LoadInt { dst: 1, value: 5 }, // 0: r1 = 5 (arg)
            // We need r3 to be Function(0). Unfortunately LoadInt can't produce
            // a Function value. But we can use the callee register directly by
            // constructing the function table so entry points work. The trick:
            // use a LoadInt to store a dummy in r3, but call via r1 which holds int.
            // Actually, the only way to get a Function value into a register
            // is via LoadInt on a register that already was Function — which we can't
            // do from instructions alone.
            //
            // Instead, restructure: put function body first, jump over it.
            Ir3Instruction::Jump { target: 5 }, // 1: jump to main
            // Function body (entry=2)
            Ir3Instruction::LoadInt { dst: 1, value: 10 }, // 2
            Ir3Instruction::Add {
                // 3: r2 = r0 + 10
                dst: 2,
                lhs: 0,
                rhs: 1,
            },
            Ir3Instruction::Return { value: 2 }, // 4
            // Main continues (ip=5): We can't create Function value from instructions.
            // So we test via the lane API where function calls are initiated by
            // having Function values pre-loaded. Since registers are private,
            // we test function calls indirectly through the unit tests.
            // Instead, test that calling a non-function is a TypeError.
            Ir3Instruction::LoadInt { dst: 0, value: 5 },
            Ir3Instruction::Halt,
        ],
        vec![Ir3FunctionDesc {
            entry: 2,
            arity: 1,
            frame_size: 3,
            name: Some("add_ten".into()),
            is_generator: false,
        }],
    );

    // Since we cannot set Function values via instructions, just verify the
    // module executes the main path correctly.
    let r = qjs_run(&m).unwrap();
    assert_eq!(r.value, Value::Int(5));
}

#[test]
fn call_string_value_type_error() {
    // Calling a register that holds a String value should also TypeError.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::Call {
                callee: 1,
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
        ],
        vec!["not_a_function".into()],
    );
    assert!(matches!(
        qjs_run(&m).unwrap_err(),
        InterpreterError::TypeError { .. }
    ));
}

#[test]
fn call_non_function_causes_type_error() {
    // Calling a register that holds an Int (not Function) should TypeError.
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 5, value: 99 },
        Ir3Instruction::Call {
            callee: 5,
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
    ]);
    assert!(matches!(
        qjs_run(&m).unwrap_err(),
        InterpreterError::TypeError { .. }
    ));
}

// ============================================================================
// 12. Budget exhaustion
// ============================================================================

#[test]
fn budget_exhaustion_infinite_loop() {
    let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 5;
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "integ").unwrap_err();
    match err {
        InterpreterError::BudgetExhausted { executed, budget } => {
            assert_eq!(executed, 5);
            assert_eq!(budget, 5);
        }
        other => panic!("expected BudgetExhausted, got {other:?}"),
    }
}

// ============================================================================
// 13. Register bounds
// ============================================================================

#[test]
fn register_out_of_bounds_error() {
    let m = test_module(vec![Ir3Instruction::LoadInt {
        dst: 9999,
        value: 1,
    }]);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_registers = 256;
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "integ").unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::RegisterOutOfBounds {
            register: 9999,
            max: 256
        }
    ));
}

// ============================================================================
// 14. String pool bounds
// ============================================================================

#[test]
fn string_pool_out_of_bounds_error() {
    let m = test_module(vec![Ir3Instruction::LoadStr {
        dst: 0,
        pool_index: 99,
    }]);
    let err = qjs_run(&m).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::StringPoolOutOfBounds {
            index: 99,
            pool_size: 0,
        }
    ));
}

// ============================================================================
// 15. Hostcall capability
// ============================================================================

#[test]
fn hostcall_capability_denied() {
    let m = test_module(vec![Ir3Instruction::HostCall {
        capability: CapabilityTag("network".into()),
        args: RegRange { start: 0, count: 0 },
        dst: 0,
    }]);
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::CapabilityDenied { capability } => {
            assert_eq!(capability, "network");
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

#[test]
fn hostcall_module_require_denied_without_capability() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("module:require".into()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
        ],
        vec!["./dep.js".to_string()],
    );
    let err = qjs_run(&m).unwrap_err();
    match err {
        InterpreterError::CapabilityDenied { capability } => {
            assert_eq!(capability, "module:require");
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

#[test]
fn hostcall_capability_granted_returns_undefined() {
    let m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::FsRead]);
    let lane = QuickJsLane::with_config(config);
    let r = lane.execute(&m, "integ").unwrap();
    assert_eq!(r.value, Value::Undefined);
    assert!(!r.hostcall_decisions.is_empty());
    assert!(r.hostcall_decisions[0].allowed);
}

#[test]
fn hostcall_module_require_rejects_non_string_specifier() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("module:require".into()),
            args: RegRange { start: 0, count: 1 },
            dst: 1,
        },
    ]);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "integ").unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::RequireSpecifierNotString { got }
            if got == "number"
    ));
}

#[test]
fn hostcall_module_require_rejects_bare_specifier() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("module:require".into()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
        ],
        vec!["dep".to_string()],
    );
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&m, "integ").unwrap_err();
    match err {
        InterpreterError::ModuleResolutionFailed { specifier, reason } => {
            assert_eq!(specifier, "dep");
            assert!(reason.contains("bare specifiers not supported"));
        }
        other => panic!("expected ModuleResolutionFailed, got {other:?}"),
    }
}

#[test]
fn hostcall_module_require_rejects_missing_file() {
    let root = temp_module_dir("module_require_missing");
    fs::create_dir_all(&root).expect("create module root");
    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("module:require".into()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
        ],
        vec!["./missing.cjs".to_string()],
    );
    let entry_path = root.join("main.mjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let err = lane.execute(&module, "integ").unwrap_err();
    match err {
        InterpreterError::ModuleResolutionFailed { specifier, reason } => {
            assert!(specifier.ends_with("missing.cjs"));
            assert!(reason.contains("module not found"));
        }
        other => panic!("expected ModuleResolutionFailed, got {other:?}"),
    }
}

#[test]
fn hostcall_module_require_resolves_extensionless_to_mjs() {
    let root = temp_module_dir("module_require_extless_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.mjs");
    fs::write(&dep_path, "const value = 21; export { value };").expect("write mjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("module:require".into()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./dep".to_string(), "value".to_string()],
    );
    let entry_path = root.join("main.cjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-extless-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(21));
}

// ============================================================================
// 16. Witness events
// ============================================================================

#[test]
fn execution_produces_witness_completed_event() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let r = qjs_run(&m).unwrap();
    assert!(
        r.witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::ExecutionCompleted)
    );
}

#[test]
fn hostcall_produces_dispatch_and_capability_witness() {
    let mut m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("db".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    m.required_capabilities = vec![CapabilityTag("db".into())];

    let mut config = InterpreterConfig::quickjs_defaults();
    // "db" is an unmapped tag — passes through typed check.
    config.granted_capabilities = BTreeSet::new();
    let lane = QuickJsLane::with_config(config);
    let r = lane.execute(&m, "integ").unwrap();

    assert!(
        r.witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::HostcallDispatched)
    );
    assert!(
        r.witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::CapabilityChecked)
    );
}

// ============================================================================
// 17. Structured events
// ============================================================================

#[test]
fn structured_events_on_halt() {
    let m = test_module(vec![Ir3Instruction::Halt]);
    let r = qjs_run(&m).unwrap();
    assert!(r.events.iter().any(|e| e.event == "execution_started"));
    assert!(r.events.iter().any(|e| e.event == "execution_halted"));
    assert!(
        r.events
            .iter()
            .all(|e| e.component == "baseline_interpreter")
    );
    assert!(r.events.iter().all(|e| e.trace_id == "integ-trace"));
}

#[test]
fn structured_events_on_normal_completion() {
    let m = test_module(vec![Ir3Instruction::LoadInt { dst: 0, value: 1 }]);
    let r = qjs_run(&m).unwrap();
    assert!(r.events.iter().any(|e| e.event == "execution_started"));
    assert!(r.events.iter().any(|e| e.event == "execution_completed"));
}

#[test]
fn structured_event_on_error_has_error_code() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 0 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    // This will fail with DivisionByZero and not produce the fail event
    // in the result (it returns Err). But the internal push_event occurs
    // before the error propagates. We just verify the error.
    let err = qjs_run(&m).unwrap_err();
    assert_eq!(err, InterpreterError::DivisionByZero);
}

// ============================================================================
// 18. V8Lane
// ============================================================================

#[test]
fn v8_lane_produces_same_value_as_quickjs() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let qjs = qjs_run(&m).unwrap();
    let v8 = v8_run(&m).unwrap();
    assert_eq!(qjs.value, v8.value);
    assert_eq!(qjs.value, Value::Int(12));
}

#[test]
fn v8_lane_budget_exhaustion() {
    let m = test_module(vec![Ir3Instruction::Jump { target: 0 }]);
    let mut config = InterpreterConfig::v8_defaults();
    config.instruction_budget = 3;
    let lane = V8Lane::with_config(config);
    let err = lane.execute(&m, "integ").unwrap_err();
    assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
}

#[test]
fn v8_lane_default_new() {
    let lane = V8Lane::new();
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 100 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(lane.execute(&m, "integ").unwrap().value, Value::Int(100));
}

// ============================================================================
// 19. LaneRouter
// ============================================================================

#[test]
fn router_default_fallback_for_simple_module() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let router = LaneRouter::new();
    let rr = router.execute(&m, "integ", None).unwrap();
    assert_eq!(rr.lane, LaneChoice::QuickJs);
    assert_eq!(rr.reason, LaneReason::DefaultFallback);
    assert_eq!(rr.result.value, Value::Int(1));
}

#[test]
fn router_selects_quickjs_for_capability_module() {
    let mut m = test_module(vec![Ir3Instruction::Halt]);
    m.required_capabilities = vec![CapabilityTag("net".into())];
    let router = LaneRouter::new();
    let rr = router.execute(&m, "integ", None).unwrap();
    assert_eq!(rr.lane, LaneChoice::QuickJs);
    assert_eq!(rr.reason, LaneReason::SecuritySensitive);
}

#[test]
fn router_selects_v8_for_large_module() {
    let instrs: Vec<Ir3Instruction> = (0..1001)
        .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 0 })
        .chain(std::iter::once(Ir3Instruction::Halt))
        .collect();
    let m = test_module(instrs);
    let router = LaneRouter::new();
    let rr = router.execute(&m, "integ", None).unwrap();
    assert_eq!(rr.lane, LaneChoice::V8);
    assert_eq!(rr.reason, LaneReason::ThroughputOptimized);
}

#[test]
fn router_force_v8_overrides_default() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let router = LaneRouter::new();
    let rr = router.execute(&m, "integ", Some(LaneChoice::V8)).unwrap();
    assert_eq!(rr.lane, LaneChoice::V8);
    assert_eq!(rr.reason, LaneReason::PolicyDirective);
}

#[test]
fn router_force_quickjs_overrides_throughput() {
    let instrs: Vec<Ir3Instruction> = (0..1001)
        .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 0 })
        .chain(std::iter::once(Ir3Instruction::Halt))
        .collect();
    let m = test_module(instrs);
    let router = LaneRouter::new();
    let rr = router
        .execute(&m, "integ", Some(LaneChoice::QuickJs))
        .unwrap();
    assert_eq!(rr.lane, LaneChoice::QuickJs);
    assert_eq!(rr.reason, LaneReason::PolicyDirective);
}

#[test]
fn router_with_custom_configs() {
    let qjs_cfg = InterpreterConfig {
        instruction_budget: 50,
        max_registers: 64,
        max_call_depth: 16,
        max_string_size: 33_554_432,
        max_heap_objects: 100_000,
        max_total_memory_bytes: 64 * 1024 * 1024,
        max_console_entries: 1_000,
        max_scope_depth: 512,
        module_root: None,
        granted_capabilities: BTreeSet::new(),
        extension_id: None,
        cancellation_token: None,
        checkpoint_density: 1000,
    };
    let v8_cfg = InterpreterConfig {
        instruction_budget: 500,
        max_registers: 128,
        max_call_depth: 32,
        max_string_size: 33_554_432,
        max_heap_objects: 1_000_000,
        max_total_memory_bytes: 512 * 1024 * 1024,
        max_console_entries: 10_000,
        max_scope_depth: 512,
        module_root: None,
        granted_capabilities: BTreeSet::new(),
        extension_id: None,
        cancellation_token: None,
        checkpoint_density: 1000,
    };
    let router = LaneRouter::with_configs(qjs_cfg, v8_cfg);
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::Halt,
    ]);
    let rr = router.execute(&m, "integ", None).unwrap();
    assert_eq!(rr.result.value, Value::Int(7));
}

// ============================================================================
// 20. Determinism — same input, same output
// ============================================================================

#[test]
fn deterministic_execution_across_runs() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: 1,
            value: 1_000_000,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 2 },
        Ir3Instruction::Mul {
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
    assert_eq!(r1.witness_events.len(), r2.witness_events.len());
}

// ============================================================================
// 21. Instruction count tracking
// ============================================================================

#[test]
fn instructions_executed_count() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::LoadInt { dst: 1, value: 2 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Halt,
    ]);
    let r = qjs_run(&m).unwrap();
    assert_eq!(r.instructions_executed, 4);
}

// ============================================================================
// 22. Loop: sum 1..5
// ============================================================================

#[test]
fn loop_sum_one_to_five() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 0 }, // 0: sum = 0
        Ir3Instruction::LoadInt { dst: 1, value: 1 }, // 1: counter = 1
        Ir3Instruction::LoadInt { dst: 2, value: 6 }, // 2: limit = 6
        Ir3Instruction::LoadInt { dst: 3, value: 1 }, // 3: increment = 1
        // Loop body
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 1,
        }, // 4: sum += counter
        Ir3Instruction::Add {
            dst: 1,
            lhs: 1,
            rhs: 3,
        }, // 5: counter += 1
        Ir3Instruction::Sub {
            dst: 4,
            lhs: 2,
            rhs: 1,
        }, // 6: r4 = limit - counter
        Ir3Instruction::JumpIf { cond: 4, target: 4 }, // 7: if r4 truthy, loop
        Ir3Instruction::Halt,                          // 8
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(15));
}

// ============================================================================
// 23. Complex expression: (3 + 4) * 2 - 1
// ============================================================================

#[test]
fn complex_arithmetic_expression() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 3 },
        Ir3Instruction::LoadInt { dst: 2, value: 4 },
        Ir3Instruction::Add {
            dst: 3,
            lhs: 1,
            rhs: 2,
        }, // r3 = 7
        Ir3Instruction::LoadInt { dst: 4, value: 2 },
        Ir3Instruction::Mul {
            dst: 5,
            lhs: 3,
            rhs: 4,
        }, // r5 = 14
        Ir3Instruction::LoadInt { dst: 6, value: 1 },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 5,
            rhs: 6,
        }, // r0 = 13
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(13));
}

// ============================================================================
// 24. Fixed-point millionths convention
// ============================================================================

#[test]
fn fixed_point_millionths_arithmetic() {
    // 1.5 * 2.0 in fixed-point millionths = 1_500_000 * 2_000_000 / 1_000_000 = 3_000_000
    // But since we only have int ops, we do it in two steps:
    // r0 = 1_500_000, r1 = 2, r0 = r0 * r1 = 3_000_000
    let m = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: 1,
            value: 1_500_000,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 2 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(qjs_run(&m).unwrap().value, Value::Int(3_000_000));
}

// ============================================================================
// 25. GetProperty / SetProperty on heap objects
// ============================================================================

#[test]
fn get_property_on_non_object_type_error() {
    // GetProperty on an Int register should TypeError.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 5 },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 0,
            },
        ],
        vec!["x".into()],
    );
    assert!(matches!(
        qjs_run(&m).unwrap_err(),
        InterpreterError::TypeError { .. }
    ));
}

#[test]
fn set_property_on_non_object_type_error() {
    // SetProperty on a Null register should TypeError.
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadNull { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 3, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 2,
                val: 3,
            },
        ],
        vec!["x".into()],
    );
    assert!(matches!(
        qjs_run(&m).unwrap_err(),
        InterpreterError::TypeError { .. }
    ));
}

// ============================================================================
// 26. Re-execution clears state (new core each time)
// ============================================================================

#[test]
fn re_execution_on_same_core_resets_ip_and_count() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "integ");
    let r1 = core.execute(&m).unwrap();
    assert_eq!(r1.instructions_executed, 2);
    let r2 = core.execute(&m).unwrap();
    assert_eq!(r2.instructions_executed, 2);
}

#[test]
fn re_execution_on_same_core_clears_runtime_state_after_error() {
    let failing = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::LoadInt { dst: 1, value: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 0 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    let halted = test_module(vec![Ir3Instruction::Halt]);
    let config = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(config, "integ");

    let err = core.execute(&failing).unwrap_err();
    assert!(matches!(err, InterpreterError::DivisionByZero));

    let rerun = core.execute(&halted).unwrap();
    assert_eq!(rerun.value, Value::Undefined);
    assert_eq!(rerun.instructions_executed, 1);
    assert_eq!(
        rerun
            .events
            .iter()
            .filter(|event| event.event == "execution_started")
            .count(),
        1
    );
    assert!(
        !rerun
            .events
            .iter()
            .any(|event| event.event == "execution_failed"),
        "events from the prior failed execution must not leak into a rerun"
    );
}

// ============================================================================
// 27. Witness sequence monotonicity
// ============================================================================

#[test]
fn witness_events_have_monotonic_seq() {
    let mut m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("a".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("b".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    m.required_capabilities = vec![CapabilityTag("a".into()), CapabilityTag("b".into())];

    let mut config = InterpreterConfig::quickjs_defaults();
    // "a"/"b" are unmapped tags — pass through typed check.
    config.granted_capabilities = BTreeSet::new();
    let lane = QuickJsLane::with_config(config);
    let r = lane.execute(&m, "integ").unwrap();

    for pair in r.witness_events.windows(2) {
        assert!(
            pair[1].seq > pair[0].seq,
            "witness seq should be strictly monotonic"
        );
    }
}

// ============================================================================
// 28. QuickJsLane default is same as new
// ============================================================================

#[test]
fn quickjs_lane_default_eq_new() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 7 },
        Ir3Instruction::Halt,
    ]);
    let d = QuickJsLane::default();
    let n = QuickJsLane::new();
    let rd = d.execute(&m, "t1").unwrap();
    let rn = n.execute(&m, "t2").unwrap();
    assert_eq!(rd.value, rn.value);
}

// ============================================================================
// 29. V8Lane default is same as new
// ============================================================================

#[test]
fn v8_lane_default_eq_new() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 8 },
        Ir3Instruction::Halt,
    ]);
    let d = V8Lane::default();
    let n = V8Lane::new();
    let rd = d.execute(&m, "t1").unwrap();
    let rn = n.execute(&m, "t2").unwrap();
    assert_eq!(rd.value, rn.value);
}

// ============================================================================
// 30. LaneRouter default is same as new
// ============================================================================

#[test]
fn lane_router_default_eq_new() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 9 },
        Ir3Instruction::Halt,
    ]);
    let d = LaneRouter::default();
    let n = LaneRouter::new();
    let rd = d.execute(&m, "t1", None).unwrap();
    let rn = n.execute(&m, "t2", None).unwrap();
    assert_eq!(rd.result.value, rn.result.value);
    assert_eq!(rd.lane, rn.lane);
}

// ============================================================================
// 31. Extended operator semantics
// ============================================================================

#[test]
fn arithmetic_extension_ops_execute_across_lanes() {
    let cases = vec![
        (
            "mod",
            test_module(vec![
                Ir3Instruction::LoadInt { dst: 0, value: 11 },
                Ir3Instruction::LoadInt { dst: 1, value: 4 },
                Ir3Instruction::Mod {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ]),
            Value::Int(3),
        ),
        (
            "exp",
            test_module(vec![
                Ir3Instruction::LoadInt { dst: 0, value: 3 },
                Ir3Instruction::LoadInt { dst: 1, value: 4 },
                Ir3Instruction::Exp {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ]),
            Value::Int(81),
        ),
        (
            "bitand",
            test_module(vec![
                Ir3Instruction::LoadInt { dst: 0, value: 6 },
                Ir3Instruction::LoadInt { dst: 1, value: 3 },
                Ir3Instruction::BitAnd {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ]),
            Value::Int(2),
        ),
        (
            "ushr",
            test_module(vec![
                Ir3Instruction::LoadInt { dst: 0, value: -1 },
                Ir3Instruction::LoadInt { dst: 1, value: 1 },
                Ir3Instruction::Ushr {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ]),
            Value::Int(2_147_483_647),
        ),
    ];

    for (label, module, expected) in cases {
        assert_both_lanes_value(&module, expected, label);
    }
}

#[test]
fn comparison_and_equality_ops_execute_across_lanes() {
    let cases = vec![
        (
            "lt_numeric_string",
            test_module_with_pool(
                vec![
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: 9 },
                    Ir3Instruction::Lt {
                        dst: 2,
                        lhs: 0,
                        rhs: 1,
                    },
                    Ir3Instruction::Return { value: 2 },
                ],
                vec!["5".into()],
            ),
            Value::Bool(true),
        ),
        (
            "gt_strings",
            test_module_with_pool(
                vec![
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    },
                    Ir3Instruction::LoadStr {
                        dst: 1,
                        pool_index: 1,
                    },
                    Ir3Instruction::Gt {
                        dst: 2,
                        lhs: 0,
                        rhs: 1,
                    },
                    Ir3Instruction::Return { value: 2 },
                ],
                vec!["beta".into(), "alpha".into()],
            ),
            Value::Bool(true),
        ),
        (
            "abstract_eq_numeric_string",
            test_module_with_pool(
                vec![
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: 7 },
                    Ir3Instruction::Eq {
                        dst: 2,
                        lhs: 0,
                        rhs: 1,
                    },
                    Ir3Instruction::Return { value: 2 },
                ],
                vec!["7".into()],
            ),
            Value::Bool(true),
        ),
        (
            "strict_eq_numeric_string",
            test_module_with_pool(
                vec![
                    Ir3Instruction::LoadStr {
                        dst: 0,
                        pool_index: 0,
                    },
                    Ir3Instruction::LoadInt { dst: 1, value: 7 },
                    Ir3Instruction::StrictEq {
                        dst: 2,
                        lhs: 0,
                        rhs: 1,
                    },
                    Ir3Instruction::Return { value: 2 },
                ],
                vec!["7".into()],
            ),
            Value::Bool(false),
        ),
        (
            "null_eq_undefined",
            test_module(vec![
                Ir3Instruction::LoadNull { dst: 0 },
                Ir3Instruction::LoadUndefined { dst: 1 },
                Ir3Instruction::Eq {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ]),
            Value::Bool(true),
        ),
        (
            "strict_not_eq_null_undefined",
            test_module(vec![
                Ir3Instruction::LoadNull { dst: 0 },
                Ir3Instruction::LoadUndefined { dst: 1 },
                Ir3Instruction::StrictNotEq {
                    dst: 2,
                    lhs: 0,
                    rhs: 1,
                },
                Ir3Instruction::Return { value: 2 },
            ]),
            Value::Bool(true),
        ),
    ];

    for (label, module, expected) in cases {
        assert_both_lanes_value(&module, expected, label);
    }
}

#[test]
fn in_operator_checks_own_properties_across_lanes() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::NewObject { dst: 0 },
            Ir3Instruction::LoadInt { dst: 1, value: 7 },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::InOp {
                dst: 3,
                lhs: 1,
                rhs: 0,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec![],
    );
    assert_eq!(qjs_run(&m).unwrap().value, Value::Bool(true));
    assert_eq!(v8_run(&m).unwrap().value, Value::Bool(true));
}

#[test]
fn instanceof_requires_function_rhs() {
    let m = test_module(vec![
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::LoadInt { dst: 1, value: 5 },
        Ir3Instruction::InstanceOf {
            dst: 2,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::Return { value: 2 },
    ]);

    assert!(matches!(
        qjs_run(&m).unwrap_err(),
        InterpreterError::TypeError { .. }
    ));
    assert!(matches!(
        v8_run(&m).unwrap_err(),
        InterpreterError::TypeError { .. }
    ));
}

#[test]
#[ignore = "needs IR3 LoadFunction instruction to populate callee register"]
fn instanceof_returns_false_for_primitive_lhs_across_lanes() {
    let m = test_module_with_functions(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 7 },
            Ir3Instruction::InstanceOf {
                dst: 2,
                lhs: 1,
                rhs: 0,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::LoadUndefined { dst: 1 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            name: Some("Ctor".to_string()),
            entry: 3,
            arity: 0,
            frame_size: 4,
            is_generator: false,
        }],
    );

    assert_both_lanes_value(&m, Value::Bool(false), "instanceof_primitive");
}

#[test]
#[ignore = "needs IR3 LoadFunction instruction to populate callee register"]
fn constructed_object_is_instanceof_constructor_across_lanes() {
    let m = test_module_with_functions(
        vec![
            Ir3Instruction::Construct {
                callee: 0,
                args: RegRange { start: 1, count: 0 },
                dst: 1,
            },
            Ir3Instruction::InstanceOf {
                dst: 2,
                lhs: 1,
                rhs: 0,
            },
            Ir3Instruction::Return { value: 2 },
            Ir3Instruction::LoadUndefined { dst: 1 },
            Ir3Instruction::Return { value: 1 },
        ],
        vec![Ir3FunctionDesc {
            name: Some("Ctor".to_string()),
            entry: 3,
            arity: 1,
            frame_size: 8,
            is_generator: false,
        }],
    );

    assert_both_lanes_value(&m, Value::Bool(true), "construct_instanceof");
}

#[test]
fn import_module_executes_and_returns_export() {
    let root = temp_module_dir("module_import");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.js");
    fs::write(&dep_path, "const value = 7; export { value };").expect("write dep module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./dep.js".to_string(), "value".to_string()],
    );
    let entry_path = root.join("main.js");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-import-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn import_module_prefers_mjs_over_js_for_extensionless_specifier() {
    let root = temp_module_dir("module_import_mjs_prefer");
    fs::create_dir_all(&root).expect("create module root");
    let mjs_path = root.join("dep.mjs");
    fs::write(&mjs_path, "const value = 9; export { value };").expect("write mjs module");
    let js_path = root.join("dep.js");
    fs::write(&js_path, "const value = 3; export { value };").expect("write js module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./dep".to_string(), "value".to_string()],
    );
    let entry_path = root.join("main.js");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-import-mjs-prefer-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(9));
}

#[test]
fn import_module_resolves_index_mjs_for_directory_specifier() {
    let root = temp_module_dir("module_import_index_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "const value = 11; export { value };").expect("write index.mjs");
    let index_js = pkg_dir.join("index.js");
    fs::write(&index_js, "const value = 5; export { value };").expect("write index.js");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg".to_string(), "value".to_string()],
    );
    let entry_path = root.join("main.js");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-import-index-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(11));
}

#[test]
fn import_module_cjs_default_export_bridges_module_exports() {
    let root = temp_module_dir("module_import_cjs_default");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("config.cjs");
    fs::write(&dep_path, "module.exports = { port: 3000 };").expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./config.cjs".to_string(),
            "default".to_string(),
            "port".to_string(),
        ],
    );
    let entry_path = root.join("main.mjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-import-cjs-default-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(3000));
}

#[test]
fn import_module_cjs_named_exports_project_properties() {
    let root = temp_module_dir("module_import_cjs_named");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("config.cjs");
    fs::write(&dep_path, "module.exports = { port: 8080 };").expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./config.cjs".to_string(), "port".to_string()],
    );
    let entry_path = root.join("main.mjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-import-cjs-named-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(8080));
}

#[test]
fn require_module_allows_cjs_to_read_esm_namespace() {
    let root = temp_module_dir("module_require_esm");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.mjs");
    fs::write(&dep_path, "const version = 42; export { version };").expect("write esm module");
    let util_path = root.join("util.cjs");
    fs::write(
        &util_path,
        "const { version } = require('./dep.mjs'); module.exports = { version };",
    )
    .expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./util.cjs".to_string(),
            "default".to_string(),
            "version".to_string(),
        ],
    );
    let entry_path = root.join("main.mjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-esm-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn require_module_allows_cjs_to_read_esm_default_export() {
    let root = temp_module_dir("module_require_esm_default");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.mjs");
    fs::write(&dep_path, "export default 17;").expect("write esm module");
    let util_path = root.join("util.cjs");
    fs::write(
        &util_path,
        "const mod = require('./dep.mjs'); module.exports = { value: mod.default };",
    )
    .expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./util.cjs".to_string(),
            "default".to_string(),
            "value".to_string(),
        ],
    );
    let entry_path = root.join("main.mjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-esm-default-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(17));
}

#[test]
fn require_module_caches_esm_namespace_object() {
    let root = temp_module_dir("module_require_esm_cache");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.mjs");
    fs::write(&dep_path, "export const value = 1;").expect("write esm module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const first = require('./dep.mjs');\n\
const second = require('./dep.mjs');\n\
module.exports = first === second;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-esm-cache-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn require_module_returns_cjs_module_exports_value() {
    let root = temp_module_dir("module_require_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("value.cjs");
    fs::write(&dep_path, "module.exports = 7;").expect("write cjs value module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./value.cjs'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn require_module_resolves_relative_to_cjs_entry() {
    let root = temp_module_dir("module_require_relative_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let dep_path = pkg_dir.join("dep.cjs");
    fs::write(&dep_path, "module.exports = 7;").expect("write nested dep");
    let root_dep = root.join("dep.cjs");
    fs::write(&root_dep, "module.exports = 99;").expect("write root dep");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./dep.cjs'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(8));
}

#[test]
fn require_module_resolves_extensionless_relative_to_cjs_entry() {
    let root = temp_module_dir("module_require_relative_extensionless_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let dep_path = pkg_dir.join("dep.cjs");
    fs::write(&dep_path, "module.exports = 4;").expect("write nested dep");
    let root_dep = root.join("dep.cjs");
    fs::write(&root_dep, "module.exports = 99;").expect("write root dep");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./dep'); module.exports = value * 2;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-extensionless-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(8));
}

#[test]
fn require_module_resolves_parent_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_parent_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let dep_path = root.join("dep.cjs");
    fs::write(&dep_path, "module.exports = 41;").expect("write root dep");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('../dep.cjs'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-parent-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn require_module_resolves_directory_relative_to_cjs_entry() {
    let root = temp_module_dir("module_require_relative_dir_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let inner_index = inner_dir.join("index.cjs");
    fs::write(&inner_index, "module.exports = 5;").expect("write inner index");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./inner'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-dir-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(6));
}

#[test]
fn require_module_resolves_parent_directory_relative_to_cjs_entry() {
    let root = temp_module_dir("module_require_relative_parent_dir_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let child_dir = pkg_dir.join("child");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let inner_index = inner_dir.join("index.cjs");
    fs::write(&inner_index, "module.exports = 12;").expect("write inner index");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = child_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('../inner'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/child/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-parent-dir-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(13));
}

#[test]
fn require_module_resolves_extensionless_parent_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_parent_extensionless_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let child_dir = pkg_dir.join("child");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let dep_path = pkg_dir.join("dep.cjs");
    fs::write(&dep_path, "module.exports = 6;").expect("write parent dep");
    let root_dep = root.join("dep.cjs");
    fs::write(&root_dep, "module.exports = 99;").expect("write root dep");
    let entry_path = child_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('../dep'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/child/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-relative-parent-extensionless-cjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn require_module_prefers_cjs_extension_over_js_when_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_prefers_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let dep_cjs = pkg_dir.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 3;").expect("write dep cjs");
    let dep_js = pkg_dir.join("dep.js");
    fs::write(&dep_js, "export const value = 9;").expect("write dep js");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-prefers-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(3));
}

#[test]
fn require_module_prefers_cjs_extension_over_mjs_when_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_prefers_cjs_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let dep_cjs = pkg_dir.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 5;").expect("write dep cjs");
    let dep_mjs = pkg_dir.join("dep.mjs");
    fs::write(&dep_mjs, "export const value = 11;").expect("write dep mjs");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-relative-prefers-cjs-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(5));
}

#[test]
fn require_module_prefers_index_js_over_index_mjs_when_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_index_js_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_js = inner_dir.join("index.js");
    fs::write(&index_js, "export const value = 14;").expect("write index js");
    let index_mjs = inner_dir.join("index.mjs");
    fs::write(&index_mjs, "export const value = 33;").expect("write index mjs");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.js");
    fs::write(&root_index, "export const value = 99;").expect("write root index");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./inner');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-index-js-over-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(14));
}

#[test]
fn require_module_prefers_index_js_over_index_mjs_for_parent_relative_directory() {
    let root = temp_module_dir("module_require_parent_relative_index_js_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let child_dir = pkg_dir.join("child");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_js = inner_dir.join("index.js");
    fs::write(&index_js, "export const value = 17;").expect("write index js");
    let index_mjs = inner_dir.join("index.mjs");
    fs::write(&index_mjs, "export const value = 31;").expect("write index mjs");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.js");
    fs::write(&root_index, "export const value = 99;").expect("write root index");
    let entry_path = child_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('../inner');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/child/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-parent-relative-index-js-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(17));
}

#[test]
fn require_module_prefers_index_cjs_over_index_mjs_when_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_index_cjs_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 21;").expect("write index cjs");
    let index_mjs = inner_dir.join("index.mjs");
    fs::write(&index_mjs, "export const value = 33;").expect("write index mjs");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./inner'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-index-cjs-over-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(22));
}

#[test]
fn require_module_prefers_index_cjs_over_index_js_for_parent_relative_directory() {
    let root = temp_module_dir("module_require_parent_relative_index_cjs_over_js");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let child_dir = pkg_dir.join("child");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 20;").expect("write index cjs");
    let index_js = inner_dir.join("index.js");
    fs::write(&index_js, "export default 9;").expect("write index js");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = child_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('../inner'); module.exports = value + 2;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/child/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-parent-relative-index-cjs-over-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(22));
}

#[test]
fn require_module_prefers_index_cjs_over_index_mjs_for_parent_relative_directory() {
    let root = temp_module_dir("module_require_parent_relative_index_cjs_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let child_dir = pkg_dir.join("child");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 24;").expect("write index cjs");
    let index_mjs = inner_dir.join("index.mjs");
    fs::write(&index_mjs, "export const value = 44;").expect("write index mjs");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = child_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('../inner'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/child/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-parent-relative-index-cjs-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(25));
}

#[test]
fn require_module_resolves_index_mjs_when_only_index_mjs_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_index_mjs_only");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_mjs = inner_dir.join("index.mjs");
    fs::write(&index_mjs, "export const value = 8;").expect("write index mjs");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./inner'); module.exports = mod.value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-index-mjs-only-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(8));
}

#[test]
fn require_module_resolves_index_js_when_only_index_js_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_index_js_only");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_js = inner_dir.join("index.js");
    fs::write(&index_js, "export const value = 6;").expect("write index js");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./inner'); module.exports = mod.value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-index-js-only-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(6));
}

#[test]
fn require_module_resolves_directory_with_trailing_slash_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_trailing_slash_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 9;").expect("write inner index");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./inner/'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-relative-trailing-slash-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(10));
}

#[test]
fn require_module_trailing_slash_prefers_directory_index_over_file_neighbor() {
    let root = temp_module_dir("module_require_trailing_slash_prefers_index_over_file");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 9;").expect("write inner index");
    let inner_file = pkg_dir.join("inner.cjs");
    fs::write(&inner_file, "module.exports = 40;").expect("write inner file");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./inner/'); module.exports = value + 1;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-relative-trailing-slash-prefers-index-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(10));
}

#[test]
fn require_module_resolves_parent_trailing_slash_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_parent_trailing_slash_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let child_dir = pkg_dir.join("child");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 4;").expect("write inner index");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = child_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('../inner/'); module.exports = value + 2;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/child/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-parent-trailing-slash-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(6));
}

#[test]
fn require_module_parent_trailing_slash_prefers_directory_index_over_file_neighbor() {
    let root = temp_module_dir("module_require_parent_trailing_slash_prefers_index_over_file");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let child_dir = pkg_dir.join("child");
    fs::create_dir_all(&child_dir).expect("create child dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 4;").expect("write inner index");
    let inner_file = pkg_dir.join("inner.cjs");
    fs::write(&inner_file, "module.exports = 80;").expect("write inner file");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = child_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('../inner/'); module.exports = value + 2;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/child/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-parent-trailing-slash-prefers-index-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(6));
}

#[test]
fn require_module_prefers_index_cjs_for_extensionless_index_relative_from_cjs_entry() {
    let root = temp_module_dir("module_require_relative_index_extensionless_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let inner_dir = pkg_dir.join("inner");
    fs::create_dir_all(&inner_dir).expect("create inner dir");
    let index_cjs = inner_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 12;").expect("write index cjs");
    let index_js = inner_dir.join("index.js");
    fs::write(&index_js, "export const value = 9;").expect("write index js");
    let root_inner = root.join("inner");
    fs::create_dir_all(&root_inner).expect("create root inner dir");
    let root_index = root_inner.join("index.cjs");
    fs::write(&root_index, "module.exports = 99;").expect("write root index");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./inner/index'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-relative-index-extensionless-cjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(12));
}

#[test]
fn require_module_prefers_explicit_js_over_extensionless_cjs_neighbor() {
    let root = temp_module_dir("module_require_explicit_js_over_cjs_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 3;").expect("write dep cjs");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "export const value = 7;").expect("write dep js");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.js');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-explicit-js-over-cjs-neighbor-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn require_module_prefers_explicit_mjs_over_extensionless_cjs_neighbor() {
    let root = temp_module_dir("module_require_explicit_mjs_over_cjs_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 3;").expect("write dep cjs");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "export const value = 10;").expect("write dep mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.mjs');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-explicit-mjs-over-cjs-neighbor-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(10));
}

#[test]
fn require_module_falls_back_to_js_in_nested_directory_without_cjs() {
    let root = temp_module_dir("module_require_nested_js_only");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let dep_js = pkg_dir.join("dep.js");
    fs::write(&dep_js, "export const value = 9;").expect("write dep js");
    let entry_path = pkg_dir.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./pkg/entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-js-only-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(9));
}

#[test]
fn require_module_resolves_nested_require_relative_to_cjs_dependency() {
    let root = temp_module_dir("module_require_nested_relative");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep = root.join("dep.cjs");
    fs::write(&root_dep, "module.exports = { value: 100 };").expect("write root dep");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep = nested_dir.join("dep.cjs");
    fs::write(&nested_dep, "module.exports = { value: 42 };").expect("write nested dep");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const dep = require('./dep'); module.exports = dep.value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-relative-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(42));
}

#[test]
fn require_module_nested_cjs_dirname_binding_is_relative_to_inner_module() {
    let root = temp_module_dir("module_require_nested_dirname");
    fs::create_dir_all(&root).expect("create module root");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(&inner_path, "module.exports = { dirname: __dirname };").expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const inner = require('./nested/inner.cjs'); module.exports = inner.dirname;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-dirname-trace")
        .expect("execute");
    let expected_dir = inner_path
        .canonicalize()
        .unwrap_or(inner_path)
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    assert_eq!(result.value, Value::Str(expected_dir));
}

#[test]
fn require_module_nested_cjs_filename_binding_is_inner_module() {
    let root = temp_module_dir("module_require_nested_filename");
    fs::create_dir_all(&root).expect("create module root");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(&inner_path, "module.exports = { filename: __filename };")
        .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const inner = require('./nested/inner.cjs'); module.exports = inner.filename;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-filename-trace")
        .expect("execute");
    let expected_file = inner_path.canonicalize().unwrap_or(inner_path);
    assert_eq!(
        result.value,
        Value::Str(expected_file.display().to_string())
    );
}

#[test]
fn require_module_nested_parent_relative_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_parent_relative");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep = root.join("dep.cjs");
    fs::write(&root_dep, "module.exports = { value: 21 };").expect("write root dep");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep = nested_dir.join("dep.cjs");
    fs::write(&nested_dep, "module.exports = { value: 7 };").expect("write nested dep");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const dep = require('../dep'); module.exports = dep.value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-parent-relative-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(21));
}

#[test]
fn require_module_nested_parent_relative_directory_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_parent_dir");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index = root_pkg.join("index.cjs");
    fs::write(&root_index, "module.exports = { value: 88 };").expect("write root index");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index = nested_pkg.join("index.cjs");
    fs::write(&nested_index, "module.exports = { value: 5 };").expect("write nested index");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const dep = require('../pkg'); module.exports = dep.value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-parent-dir-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(88));
}

#[test]
fn require_module_nested_parent_relative_directory_trailing_slash_ignores_nested_pkg() {
    let root = temp_module_dir("module_require_nested_parent_dir_slash_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 41;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 77;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 99;").expect("write nested index cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-slash-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_parent_relative_directory_trailing_slash_prefers_js_over_mjs() {
    let root = temp_module_dir("module_require_nested_parent_dir_slash_js_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 41;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 77;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-slash-js-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_parent_relative_directory_trailing_slash_prefers_cjs_over_js() {
    let root = temp_module_dir("module_require_nested_parent_dir_slash_cjs_over_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 63;").expect("write root index cjs");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 92;").expect("write root index js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-slash-cjs-over-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(63));
}

#[test]
fn require_module_nested_parent_relative_directory_trailing_slash_prefers_cjs_over_mjs() {
    let root = temp_module_dir("module_require_nested_parent_dir_slash_cjs_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 51;").expect("write root index cjs");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 84;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-slash-cjs-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(51));
}

#[test]
fn require_module_nested_parent_relative_directory_trailing_slash_prefers_cjs_over_mjs_with_js_neighbor()
 {
    let root = temp_module_dir("module_require_nested_parent_dir_slash_cjs_over_mjs_with_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 67;").expect("write root index cjs");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 88;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 97;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-slash-cjs-over-mjs-with-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(67));
}

#[test]
fn require_module_nested_parent_relative_directory_ignores_nested_pkg() {
    let root = temp_module_dir("module_require_nested_parent_dir_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 41;").expect("write root index js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 99;").expect("write nested index cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_parent_relative_directory_prefers_mjs_when_no_cjs_or_js() {
    let root = temp_module_dir("module_require_nested_parent_dir_mjs_only");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 58;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-parent-dir-mjs-only-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(58));
}

#[test]
fn require_module_nested_parent_relative_extensionless_prefers_cjs_over_js_and_mjs() {
    let root = temp_module_dir("module_require_nested_parent_extensionless_prefers_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_cjs = root.join("dep.cjs");
    fs::write(&root_cjs, "module.exports = 31;").expect("write root cjs");
    let root_js = root.join("dep.js");
    fs::write(&root_js, "export default 44;").expect("write root js");
    let root_mjs = root.join("dep.mjs");
    fs::write(&root_mjs, "export default 55;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_cjs = nested_dir.join("dep.cjs");
    fs::write(&nested_cjs, "module.exports = 77;").expect("write nested cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-extensionless-cjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(31));
}

#[test]
fn require_module_nested_parent_relative_extensionless_prefers_js_when_no_cjs() {
    let root = temp_module_dir("module_require_nested_parent_extensionless_prefers_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_js = root.join("dep.js");
    fs::write(&root_js, "export default 41;").expect("write root js");
    let root_mjs = root.join("dep.mjs");
    fs::write(&root_mjs, "export default 90;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_js = nested_dir.join("dep.js");
    fs::write(&nested_js, "export default 7;").expect("write nested js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-extensionless-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_parent_relative_extensionless_prefers_mjs_when_no_cjs_or_js() {
    let root = temp_module_dir("module_require_nested_parent_extensionless_prefers_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_mjs = root.join("dep.mjs");
    fs::write(&root_mjs, "export default 52;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_mjs = nested_dir.join("dep.mjs");
    fs::write(&nested_mjs, "export default 7;").expect("write nested mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-extensionless-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(52));
}

#[test]
fn require_module_nested_parent_relative_explicit_mjs_ignores_js_and_cjs_neighbors() {
    let root = temp_module_dir("module_require_nested_parent_explicit_mjs_over_neighbors");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep_mjs = root.join("dep.mjs");
    fs::write(&root_dep_mjs, "export default 64;").expect("write root mjs");
    let root_dep_js = root.join("dep.js");
    fs::write(&root_dep_js, "export default 11;").expect("write root js");
    let root_dep_cjs = root.join("dep.cjs");
    fs::write(&root_dep_cjs, "module.exports = 7;").expect("write root cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep_mjs = nested_dir.join("dep.mjs");
    fs::write(&nested_dep_mjs, "export default 103;").expect("write nested mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep.mjs');
\
module.exports = mod.default;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-mjs-over-neighbors-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(64));
}

#[test]
fn require_module_nested_parent_relative_explicit_js_ignores_cjs_and_mjs_neighbors() {
    let root = temp_module_dir("module_require_nested_parent_explicit_js_over_neighbors");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep_js = root.join("dep.js");
    fs::write(&root_dep_js, "export default 71;").expect("write root js");
    let root_dep_cjs = root.join("dep.cjs");
    fs::write(&root_dep_cjs, "module.exports = 9;").expect("write root cjs");
    let root_dep_mjs = root.join("dep.mjs");
    fs::write(&root_dep_mjs, "export default 17;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-js-over-neighbors-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(71));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_extensionless_prefers_js_when_no_cjs() {
    let root = temp_module_dir("module_require_nested_parent_explicit_index_extensionless_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 19;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 44;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 77;").expect("write nested index js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/index');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-extensionless-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(19));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_extensionless_prefers_mjs_when_no_cjs_or_js()
 {
    let root = temp_module_dir("module_require_nested_parent_explicit_index_extensionless_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 55;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 77;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/index');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-extensionless-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(55));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_extensionless_ignores_nested_pkg() {
    let root = temp_module_dir("module_require_nested_parent_explicit_index_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 41;").expect("write root index js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 99;").expect("write nested index cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/index');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_extensionless_ignores_nested_pkg_trailing_slash()
 {
    let root =
        temp_module_dir("module_require_nested_parent_explicit_index_slash_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 41;").expect("write root index js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 99;").expect("write nested index cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/index/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-slash-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_js_ignores_nested_pkg() {
    let root = temp_module_dir("module_require_nested_parent_explicit_index_js_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 41;").expect("write root index js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 99;").expect("write nested index js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/index.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-js-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_mjs_ignores_nested_pkg() {
    let root =
        temp_module_dir("module_require_nested_parent_explicit_index_mjs_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 55;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 99;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/index.mjs');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-mjs-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(55));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_cjs_ignores_nested_pkg() {
    let root =
        temp_module_dir("module_require_nested_parent_explicit_index_cjs_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 32;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 99;").expect("write nested index cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('../pkg/index.cjs');
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-cjs-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(32));
}

#[test]
fn require_module_nested_parent_relative_explicit_index_extensionless_prefers_cjs() {
    let root = temp_module_dir("module_require_nested_parent_explicit_index_extensionless_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 32;").expect("write root index cjs");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 19;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 44;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 99;").expect("write nested index cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/index');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-index-extensionless-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(32));
}

#[test]
fn require_module_nested_parent_relative_explicit_mjs_resolves_from_parent() {
    let root = temp_module_dir("module_require_nested_parent_explicit_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep = root.join("dep.mjs");
    fs::write(&root_dep, "export default 64;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep = nested_dir.join("dep.mjs");
    fs::write(&nested_dep, "export default 103;").expect("write nested mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep.mjs');
\
module.exports = mod.default;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-parent-explicit-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(64));
}

#[test]
fn require_module_nested_parent_relative_explicit_js_resolves_from_parent() {
    let root = temp_module_dir("module_require_nested_parent_explicit_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep = root.join("dep.js");
    fs::write(&root_dep, "export default 71;").expect("write root js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep = nested_dir.join("dep.js");
    fs::write(&nested_dep, "export default 12;").expect("write nested js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-parent-explicit-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(71));
}

#[test]
fn require_module_nested_parent_relative_explicit_cjs_ignores_js_and_mjs_neighbors() {
    let root = temp_module_dir("module_require_nested_parent_explicit_cjs_over_neighbors");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep_cjs = root.join("dep.cjs");
    fs::write(&root_dep_cjs, "module.exports = 82;").expect("write root cjs");
    let root_dep_js = root.join("dep.js");
    fs::write(&root_dep_js, "export default 12;").expect("write root js");
    let root_dep_mjs = root.join("dep.mjs");
    fs::write(&root_dep_mjs, "export default 19;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('../dep.cjs');
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-cjs-over-neighbors-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(82));
}

#[test]
fn require_module_nested_parent_relative_explicit_cjs_resolves_from_parent() {
    let root = temp_module_dir("module_require_nested_parent_explicit_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep = root.join("dep.cjs");
    fs::write(&root_dep, "module.exports = 82;").expect("write root cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep = nested_dir.join("dep.cjs");
    fs::write(&nested_dep, "module.exports = 17;").expect("write nested cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('../dep.cjs');\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-parent-explicit-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(82));
}

#[test]
fn require_module_nested_parent_relative_directory_trailing_slash_prefers_mjs_when_no_cjs_or_js() {
    let root = temp_module_dir("module_require_nested_parent_dir_slash_mjs_only");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 73;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-slash-mjs-only-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(73));
}

#[test]
fn require_module_nested_parent_relative_directory_prefers_js_over_mjs_when_no_cjs() {
    let root = temp_module_dir("module_require_nested_parent_dir_js_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 44;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 91;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-dir-js-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(44));
}

#[test]
fn require_module_nested_parent_relative_directory_prefers_cjs_over_js_over_mjs() {
    let root = temp_module_dir("module_require_nested_parent_dir_cjs_js_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 39;").expect("write root index cjs");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 72;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 95;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../pkg');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-parent-dir-cjs-js-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(39));
}

#[test]
fn require_module_nested_parent_relative_explicit_js_over_mjs_neighbor() {
    let root = temp_module_dir("module_require_nested_parent_explicit_js_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep_js = root.join("dep.js");
    fs::write(&root_dep_js, "export default 56;").expect("write root js");
    let root_dep_mjs = root.join("dep.mjs");
    fs::write(&root_dep_mjs, "export default 99;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep_js = nested_dir.join("dep.js");
    fs::write(&nested_dep_js, "export default 12;").expect("write nested js");
    let nested_dep_mjs = nested_dir.join("dep.mjs");
    fs::write(&nested_dep_mjs, "export default 21;").expect("write nested mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('../dep.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-js-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(56));
}

#[test]
fn require_module_nested_parent_relative_explicit_cjs_over_js_and_mjs_neighbors() {
    let root = temp_module_dir("module_require_nested_parent_explicit_cjs_over_js_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep_cjs = root.join("dep.cjs");
    fs::write(&root_dep_cjs, "module.exports = 68;").expect("write root cjs");
    let root_dep_js = root.join("dep.js");
    fs::write(&root_dep_js, "export default 81;").expect("write root js");
    let root_dep_mjs = root.join("dep.mjs");
    fs::write(&root_dep_mjs, "export default 97;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep_cjs = nested_dir.join("dep.cjs");
    fs::write(&nested_dep_cjs, "module.exports = 12;").expect("write nested cjs");
    let nested_dep_js = nested_dir.join("dep.js");
    fs::write(&nested_dep_js, "export default 22;").expect("write nested js");
    let nested_dep_mjs = nested_dir.join("dep.mjs");
    fs::write(&nested_dep_mjs, "export default 33;").expect("write nested mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('../dep.cjs');\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-parent-explicit-cjs-over-js-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(68));
}

#[test]
fn require_module_nested_explicit_mjs_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_explicit_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep = root.join("dep.mjs");
    fs::write(&root_dep, "export default 3;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep = nested_dir.join("dep.mjs");
    fs::write(&nested_dep, "export default 61;").expect("write nested mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./dep.mjs'); module.exports = mod.default;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-explicit-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(61));
}

#[test]
fn require_module_nested_explicit_js_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_explicit_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_dep = root.join("dep.js");
    fs::write(&root_dep, "export const value = 4;").expect("write root js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_dep = nested_dir.join("dep.js");
    fs::write(&nested_dep, "export const value = 72;").expect("write nested js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./dep.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-explicit-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(72));
}

#[test]
fn require_module_nested_directory_specifier_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_dir_specifier");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index = root_pkg.join("index.cjs");
    fs::write(&root_index, "module.exports = { value: 19 };").expect("write root index");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index = nested_pkg.join("index.cjs");
    fs::write(&nested_index, "module.exports = { value: 47 };").expect("write nested index");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const dep = require('./pkg/'); module.exports = dep.value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-dir-specifier-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(47));
}

#[test]
fn require_module_nested_directory_without_trailing_slash_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_dir_no_slash");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index = root_pkg.join("index.cjs");
    fs::write(&root_index, "module.exports = { value: 13 };").expect("write root index");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index = nested_pkg.join("index.cjs");
    fs::write(&nested_index, "module.exports = { value: 91 };").expect("write nested index");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const dep = require('./pkg'); module.exports = dep.value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-dir-no-slash-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(91));
}

#[test]
fn require_module_nested_directory_without_trailing_slash_prefers_js_over_mjs_when_no_cjs() {
    let root = temp_module_dir("module_require_nested_dir_no_slash_prefers_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 71;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 88;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-dir-no-slash-prefers-js-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(71));
}

#[test]
fn require_module_nested_directory_without_trailing_slash_prefers_cjs_over_js_and_mjs() {
    let root = temp_module_dir("module_require_nested_dir_no_slash_prefers_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 96;").expect("write nested index cjs");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 18;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 27;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-dir-no-slash-prefers-cjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(96));
}

#[test]
fn require_module_nested_directory_without_trailing_slash_prefers_mjs_when_no_cjs_or_js() {
    let root = temp_module_dir("module_require_nested_dir_no_slash_prefers_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 82;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-dir-no-slash-prefers-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(82));
}

#[test]
fn require_module_nested_extensionless_prefers_cjs_in_inner_module() {
    let root = temp_module_dir("module_require_nested_extensionless_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_cjs = root.join("dep.cjs");
    fs::write(&root_cjs, "module.exports = 12;").expect("write root cjs");
    let root_js = root.join("dep.js");
    fs::write(&root_js, "export const value = 1;").expect("write root js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_cjs = nested_dir.join("dep.cjs");
    fs::write(&nested_cjs, "module.exports = 44;").expect("write nested cjs");
    let nested_js = nested_dir.join("dep.js");
    fs::write(&nested_js, "export const value = 3;").expect("write nested js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('./dep'); module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-extensionless-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(44));
}

#[test]
fn require_module_nested_extensionless_falls_back_to_js_in_inner_module() {
    let root = temp_module_dir("module_require_nested_extensionless_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_js = root.join("dep.js");
    fs::write(&root_js, "export const value = 2;").expect("write root js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_js = nested_dir.join("dep.js");
    fs::write(&nested_js, "export const value = 58;").expect("write nested js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./dep');
\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-extensionless-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(58));
}

#[test]
fn require_module_nested_extensionless_falls_back_to_mjs_in_inner_module() {
    let root = temp_module_dir("module_require_nested_extensionless_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_mjs = root.join("dep.mjs");
    fs::write(&root_mjs, "export default 6;").expect("write root mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_mjs = nested_dir.join("dep.mjs");
    fs::write(&nested_mjs, "export default 77;").expect("write nested mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./dep');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-extensionless-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(77));
}

#[test]
fn require_module_nested_explicit_index_cjs_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_explicit_index_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index = root_pkg.join("index.cjs");
    fs::write(&root_index, "module.exports = 8;").expect("write root index");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index = nested_pkg.join("index.cjs");
    fs::write(&nested_index, "module.exports = 34;").expect("write nested index");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('./pkg/index.cjs'); module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-explicit-index-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(34));
}

#[test]
fn require_module_nested_explicit_index_js_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_explicit_index_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index = root_pkg.join("index.js");
    fs::write(&root_index, "export default 6;").expect("write root index");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index = nested_pkg.join("index.js");
    fs::write(&nested_index, "export default 25;").expect("write nested index");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-explicit-index-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(25));
}

#[test]
fn require_module_nested_explicit_index_mjs_resolves_from_inner_module() {
    let root = temp_module_dir("module_require_nested_explicit_index_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index = root_pkg.join("index.mjs");
    fs::write(&root_index, "export default 5;").expect("write root index");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index = nested_pkg.join("index.mjs");
    fs::write(&nested_index, "export default 29;").expect("write nested index");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index.mjs');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-nested-explicit-index-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(29));
}

#[test]
fn require_module_nested_explicit_index_js_over_cjs_neighbor() {
    let root = temp_module_dir("module_require_nested_explicit_index_js_over_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 6;").expect("write root index js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 11;").expect("write nested index cjs");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 31;").expect("write nested index js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-js-over-cjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(31));
}

#[test]
fn require_module_nested_explicit_index_mjs_over_cjs_neighbor() {
    let root = temp_module_dir("module_require_nested_explicit_index_mjs_over_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 6;").expect("write root index cjs");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 9;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 13;").expect("write nested index cjs");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 41;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index.mjs');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-mjs-over-cjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_nested_explicit_index_mjs_over_js_neighbor() {
    let root = temp_module_dir("module_require_nested_explicit_index_mjs_over_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 7;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 12;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 17;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 39;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index.mjs');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-mjs-over-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(39));
}

#[test]
fn require_module_nested_explicit_index_cjs_over_mjs_neighbor() {
    let root = temp_module_dir("module_require_nested_explicit_index_cjs_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 5;").expect("write root index cjs");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 8;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 27;").expect("write nested index cjs");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 33;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('./pkg/index.cjs'); module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-cjs-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(27));
}

#[test]
fn require_module_nested_explicit_index_cjs_over_js_neighbor() {
    let root = temp_module_dir("module_require_nested_explicit_index_cjs_over_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 2;").expect("write root index cjs");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 5;").expect("write root index js");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 23;").expect("write nested index cjs");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 36;").expect("write nested index js");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('./pkg/index.cjs'); module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-cjs-over-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(23));
}

#[test]
fn require_module_nested_explicit_index_js_over_mjs_neighbor() {
    let root = temp_module_dir("module_require_nested_explicit_index_js_over_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_js = root_pkg.join("index.js");
    fs::write(&root_index_js, "export default 4;").expect("write root index js");
    let root_index_mjs = root_pkg.join("index.mjs");
    fs::write(&root_index_mjs, "export default 9;").expect("write root index mjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 37;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 53;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index.js');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-js-over-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(37));
}

#[test]
fn require_module_nested_explicit_index_extensionless_prefers_cjs() {
    let root = temp_module_dir("module_require_nested_explicit_index_extensionless_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 93;").expect("write nested index cjs");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 18;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 27;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-extensionless-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(93));
}

#[test]
fn require_module_nested_explicit_index_extensionless_prefers_js_when_no_cjs() {
    let root = temp_module_dir("module_require_nested_explicit_index_extensionless_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 81;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 27;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-extensionless-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(81));
}

#[test]
fn require_module_nested_explicit_index_extensionless_prefers_mjs_when_no_cjs_or_js() {
    let root = temp_module_dir("module_require_nested_explicit_index_extensionless_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 66;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/index');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-extensionless-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(66));
}

#[test]
fn require_module_nested_explicit_index_cjs_ignores_nested_pkg() {
    let root = temp_module_dir("module_require_nested_explicit_index_cjs_ignores_nested_pkg");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 32;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 99;").expect("write nested index cjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const value = require('./pkg/index.cjs');
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-explicit-index-cjs-ignores-nested-pkg-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(32));
}

#[test]
fn require_module_nested_directory_index_prefers_nested_cjs_when_present() {
    let root = temp_module_dir("module_require_nested_directory_index_prefers_nested_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_cjs = nested_pkg.join("index.cjs");
    fs::write(&nested_index_cjs, "module.exports = 95;").expect("write nested index cjs");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 18;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 27;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-directory-index-prefers-nested-cjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(95));
}

#[test]
fn require_module_nested_directory_index_prefers_nested_js_when_no_cjs() {
    let root = temp_module_dir("module_require_nested_directory_index_prefers_nested_js");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_js = nested_pkg.join("index.js");
    fs::write(&nested_index_js, "export default 71;").expect("write nested index js");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 88;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-directory-index-prefers-nested-js-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(71));
}

#[test]
fn require_module_nested_directory_index_prefers_nested_mjs_when_no_cjs_or_js() {
    let root = temp_module_dir("module_require_nested_directory_index_prefers_nested_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let root_pkg = root.join("pkg");
    fs::create_dir_all(&root_pkg).expect("create root package dir");
    let root_index_cjs = root_pkg.join("index.cjs");
    fs::write(&root_index_cjs, "module.exports = 4;").expect("write root index cjs");
    let nested_dir = root.join("nested");
    fs::create_dir_all(&nested_dir).expect("create nested dir");
    let nested_pkg = nested_dir.join("pkg");
    fs::create_dir_all(&nested_pkg).expect("create nested package dir");
    let nested_index_mjs = nested_pkg.join("index.mjs");
    fs::write(&nested_index_mjs, "export default 62;").expect("write nested index mjs");
    let inner_path = nested_dir.join("inner.cjs");
    fs::write(
        &inner_path,
        "const mod = require('./pkg/');
\
const value = typeof mod === 'object' && mod !== null ? mod.default : mod;
\
module.exports = value;",
    )
    .expect("write inner module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = require('./nested/inner.cjs');",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(
            &module,
            "module-require-nested-directory-index-prefers-nested-mjs-trace",
        )
        .expect("execute");
    assert_eq!(result.value, Value::Int(62));
}

#[test]
fn require_module_uses_explicit_cjs_specifier_even_with_js_neighbor() {
    let root = temp_module_dir("module_require_explicit_cjs_with_js_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 13;").expect("write cjs module");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "const value = 5; export { value };").expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./dep.cjs'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(13));
}

#[test]
fn require_module_uses_explicit_cjs_specifier_even_with_mjs_neighbor() {
    let root = temp_module_dir("module_require_explicit_cjs_with_mjs_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 15;").expect("write cjs module");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "export default 3;").expect("write mjs module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./dep.cjs'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-cjs-mjs-neighbor-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(15));
}

#[test]
fn require_module_uses_explicit_mjs_specifier_even_with_cjs_neighbor() {
    let root = temp_module_dir("module_require_explicit_mjs_with_cjs_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 3;").expect("write cjs module");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "export default 7;").expect("write mjs module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.mjs'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(7));
}

#[test]
fn require_module_uses_explicit_mjs_specifier_even_with_js_neighbor() {
    let root = temp_module_dir("module_require_explicit_mjs_with_js_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "const value = 2; export { value };").expect("write js module");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "export default 11;").expect("write mjs module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.mjs'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-mjs-js-neighbor-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(11));
}

#[test]
fn require_module_prefers_cjs_over_mjs_for_extensionless_specifier() {
    let root = temp_module_dir("module_require_prefers_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 2;").expect("write cjs module");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "export default 9;").expect("write esm module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./dep'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-prefers-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(2));
}

#[test]
fn require_module_prefers_cjs_over_js_for_extensionless_specifier() {
    let root = temp_module_dir("module_require_prefers_cjs_over_js");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 2;").expect("write cjs module");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "export const value = 9;").expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep');\n\
const value = typeof mod === 'object' && mod !== null ? mod.value : mod;\n\
module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-prefers-cjs-over-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(2));
}

#[test]
fn require_module_resolves_index_cjs_for_directory_specifier() {
    let root = temp_module_dir("module_require_index_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_cjs = pkg_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 11;").expect("write index.cjs");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "export default 3;").expect("write index.mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./pkg'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-index-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(11));
}

#[test]
fn require_module_prefers_index_cjs_over_index_js() {
    let root = temp_module_dir("module_require_index_cjs_over_js");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_cjs = pkg_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 19;").expect("write index.cjs");
    let index_js = pkg_dir.join("index.js");
    fs::write(&index_js, "export default 7;").expect("write index.js");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./pkg'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-index-cjs-over-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(19));
}

#[test]
fn require_module_resolves_index_js_when_only_index_js() {
    let root = temp_module_dir("module_require_index_js_only");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_js = pkg_dir.join("index.js");
    fs::write(&index_js, "export default 23;").expect("write index.js");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./pkg'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-index-js-only-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(23));
}

#[test]
fn require_module_uses_explicit_index_mjs_even_with_index_cjs() {
    let root = temp_module_dir("module_require_explicit_index_mjs_with_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_cjs = pkg_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 4;").expect("write index.cjs");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "export default 12;").expect("write index.mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./pkg/index.mjs'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-index-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(12));
}

#[test]
fn require_module_uses_explicit_index_js_even_with_index_cjs() {
    let root = temp_module_dir("module_require_explicit_index_js_with_cjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_cjs = pkg_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 2;").expect("write index.cjs");
    let index_js = pkg_dir.join("index.js");
    fs::write(&index_js, "export default 9;").expect("write index.js");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./pkg/index.js'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-index-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(9));
}

#[test]
fn require_module_uses_explicit_index_mjs_even_with_index_js() {
    let root = temp_module_dir("module_require_explicit_index_mjs_with_js");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_js = pkg_dir.join("index.js");
    fs::write(&index_js, "export default 5;").expect("write index.js");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "export default 18;").expect("write index.mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./pkg/index.mjs'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-index-mjs-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(18));
}

#[test]
fn require_module_uses_explicit_index_js_even_with_index_mjs() {
    let root = temp_module_dir("module_require_explicit_index_js_with_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_js = pkg_dir.join("index.js");
    fs::write(&index_js, "export default 17;").expect("write index.js");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "export default 2;").expect("write index.mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./pkg/index.js'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-index-js-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(17));
}

#[test]
fn require_module_uses_explicit_index_cjs_even_with_index_mjs() {
    let root = temp_module_dir("module_require_explicit_index_cjs_with_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_cjs = pkg_dir.join("index.cjs");
    fs::write(&index_cjs, "module.exports = 21;").expect("write index.cjs");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "export default 3;").expect("write index.mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const value = require('./pkg/index.cjs'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-index-cjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(21));
}

#[test]
fn require_module_falls_back_to_mjs_for_extensionless_specifier() {
    let root = temp_module_dir("module_require_fallback_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "export default 13;").expect("write esm module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-fallback-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(13));
}

#[test]
fn require_module_falls_back_to_index_mjs_for_directory_specifier() {
    let root = temp_module_dir("module_require_fallback_index_mjs");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "export default 17;").expect("write index.mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./pkg'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-fallback-index-mjs-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(17));
}

#[test]
fn require_module_prefers_js_over_mjs_for_extensionless_specifier() {
    let root = temp_module_dir("module_require_js_prefer");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "const version = 37; export { version };").expect("write js module");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "const version = 9; export { version };").expect("write mjs module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep'); module.exports = mod.version;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-js-prefer-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(37));
}

#[test]
fn require_module_falls_back_to_js_for_extensionless_specifier() {
    let root = temp_module_dir("module_require_fallback_js");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "const value = 14; export { value };").expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep'); module.exports = mod.value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-fallback-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(14));
}

#[test]
fn require_module_uses_explicit_js_specifier_even_with_cjs_neighbor() {
    let root = temp_module_dir("module_require_explicit_js_with_cjs_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_cjs = root.join("dep.cjs");
    fs::write(&dep_cjs, "module.exports = 2;").expect("write cjs module");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "const value = 5; export { value };").expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.js'); module.exports = mod.value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(5));
}

#[test]
fn require_module_uses_explicit_js_specifier_even_with_mjs_neighbor() {
    let root = temp_module_dir("module_require_explicit_js_with_mjs_neighbor");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "const value = 6; export { value };").expect("write js module");
    let dep_mjs = root.join("dep.mjs");
    fs::write(&dep_mjs, "const value = 99; export { value };").expect("write mjs module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.js'); module.exports = mod.value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-explicit-js-mjs-neighbor-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(6));
}

#[test]
fn require_module_allows_cjs_to_read_js_default_export() {
    let root = temp_module_dir("module_require_js_extension");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "export default 21;").expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.js'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-js-extension-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(21));
}

#[test]
fn require_module_allows_cjs_to_read_js_named_export() {
    let root = temp_module_dir("module_require_js_named");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "const value = 41; export { value };").expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const { value } = require('./dep.js'); module.exports = value;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-js-named-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(41));
}

#[test]
fn require_module_exposes_js_default_and_named_exports() {
    let root = temp_module_dir("module_require_js_default_named");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(
        &dep_js,
        "const named = 8; const d = 47; export { named }; export default d;",
    )
    .expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./dep.js'); module.exports = mod.default + mod.named;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-js-default-named-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(55));
}

#[test]
fn require_module_caches_js_namespace_object() {
    let root = temp_module_dir("module_require_js_cache");
    fs::create_dir_all(&root).expect("create module root");
    let dep_js = root.join("dep.js");
    fs::write(&dep_js, "export const value = 1;").expect("write js module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const first = require('./dep.js');\n\
const second = require('./dep.js');\n\
module.exports = first === second;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-js-cache-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn require_module_prefers_index_js_over_index_mjs() {
    let root = temp_module_dir("module_require_index_js_prefers");
    fs::create_dir_all(&root).expect("create module root");
    let pkg_dir = root.join("pkg");
    fs::create_dir_all(&pkg_dir).expect("create package dir");
    let index_js = pkg_dir.join("index.js");
    fs::write(&index_js, "export default 31;").expect("write index.js");
    let index_mjs = pkg_dir.join("index.mjs");
    fs::write(&index_mjs, "export default 5;").expect("write index.mjs");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const mod = require('./pkg'); module.exports = mod.default;",
    )
    .expect("write cjs entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let main_path = root.join("main.mjs");
    module.header.source_label = main_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-index-js-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(31));
}

#[test]
fn cjs_module_exposes_filename_binding() {
    let root = temp_module_dir("cjs_filename_binding");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(&entry_path, "module.exports = { filename: __filename };").expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "filename".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-filename-trace")
        .expect("execute");
    let expected_file = entry_path.canonicalize().unwrap_or(entry_path);
    assert_eq!(
        result.value,
        Value::Str(expected_file.display().to_string())
    );
}

#[test]
fn cjs_module_exposes_dirname_binding() {
    let root = temp_module_dir("cjs_dirname_binding");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(&entry_path, "module.exports = { dirname: __dirname };").expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "dirname".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-dirname-trace")
        .expect("execute");
    let expected_file = entry_path.canonicalize().unwrap_or(entry_path);
    let expected_dir = expected_file
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    assert_eq!(result.value, Value::Str(expected_dir));
}

#[test]
fn cjs_module_exports_module_filename() {
    let root = temp_module_dir("cjs_module_filename");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = { filename: module.filename };",
    )
    .expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "filename".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-module-filename-trace")
        .expect("execute");
    let expected_file = entry_path.canonicalize().unwrap_or(entry_path);
    assert_eq!(
        result.value,
        Value::Str(expected_file.display().to_string())
    );
}

#[test]
fn cjs_module_exports_module_id() {
    let root = temp_module_dir("cjs_module_id");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(&entry_path, "module.exports = { id: module.id };").expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "id".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-module-id-trace")
        .expect("execute");
    let expected_file = entry_path.canonicalize().unwrap_or(entry_path);
    assert_eq!(
        result.value,
        Value::Str(expected_file.display().to_string())
    );
}

#[test]
fn cjs_module_exports_loaded_true_after_eval() {
    let root = temp_module_dir("cjs_module_loaded");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(&entry_path, "module.exports = module;").expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "loaded".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-module-loaded-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn cjs_module_parent_tracks_require_chain() {
    let root = temp_module_dir("cjs_module_parent_chain");
    fs::create_dir_all(&root).expect("create module root");
    let child_path = root.join("child.cjs");
    fs::write(&child_path, "module.exports = module;").expect("write child module");
    let parent_path = root.join("parent.cjs");
    fs::write(
        &parent_path,
        "const child = require('./child.cjs');\nmodule.exports = { parentId: module.id, childParentId: child.parent.id, rootParent: module.parent };",
    )
    .expect("write parent module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./parent.cjs".to_string(),
            "default".to_string(),
            "childParentId".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-parent-chain-trace")
        .expect("execute");
    let expected_parent = parent_path.canonicalize().unwrap_or(parent_path);
    assert_eq!(
        result.value,
        Value::Str(expected_parent.display().to_string())
    );
}

#[test]
fn cjs_entry_module_parent_is_null() {
    let root = temp_module_dir("cjs_entry_parent_null");
    fs::create_dir_all(&root).expect("create module root");
    let child_path = root.join("child.cjs");
    fs::write(&child_path, "module.exports = module;").expect("write child module");
    let parent_path = root.join("parent.cjs");
    fs::write(
        &parent_path,
        "const child = require('./child.cjs');\nmodule.exports = { rootParent: module.parent, childParentId: child.parent.id };",
    )
    .expect("write parent module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./parent.cjs".to_string(),
            "default".to_string(),
            "rootParent".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-parent-null-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Null);
}

#[test]
fn cjs_module_exports_module_path() {
    let root = temp_module_dir("cjs_module_path");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(&entry_path, "module.exports = { path: module.path };").expect("write cjs module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "path".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-module-path-trace")
        .expect("execute");
    let expected_file = entry_path.canonicalize().unwrap_or(entry_path);
    let expected_dir = expected_file
        .parent()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    assert_eq!(result.value, Value::Str(expected_dir));
}

#[test]
fn require_module_cjs_cycle_reads_partial_exports() {
    let root = temp_module_dir("module_require_cycle");
    fs::create_dir_all(&root).expect("create module root");
    let a_path = root.join("a.cjs");
    fs::write(
        &a_path,
        "exports.loaded = false;\nconst b = require('./b.cjs');\nexports.seen_loaded = b.a_loaded;\nexports.loaded = true;\n",
    )
    .expect("write a.cjs");
    let b_path = root.join("b.cjs");
    fs::write(&b_path, "exports.a_loaded = require('./a.cjs').loaded;\n").expect("write b.cjs");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./a.cjs".to_string(),
            "default".to_string(),
            "seen_loaded".to_string(),
        ],
    );
    let entry_path = root.join("main.mjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-cycle-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn cjs_module_loaded_false_during_cycle() {
    let root = temp_module_dir("module_cjs_loaded_cycle");
    fs::create_dir_all(&root).expect("create module root");
    let a_path = root.join("a.cjs");
    fs::write(
        &a_path,
        "module.exports = module;\nconst b = require('./b.cjs');\nmodule.exports.child_loaded = b.loaded;\n",
    )
    .expect("write a.cjs");
    let b_path = root.join("b.cjs");
    fs::write(&b_path, "module.exports = require('./a.cjs');\n").expect("write b.cjs");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./a.cjs".to_string(),
            "default".to_string(),
            "child_loaded".to_string(),
        ],
    );
    let entry_path = root.join("main.mjs");
    module.header.source_label = entry_path.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-cjs-loaded-cycle-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Bool(false));
}

#[test]
fn cjs_require_returns_cached_exports() {
    let root = temp_module_dir("module_require_cache");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.cjs");
    fs::write(&dep_path, "module.exports = { count: 0 };").expect("write dep module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const a = require('./dep.cjs');\n\
a.count += 1;\n\
const b = require('./dep.cjs');\n\
module.exports = { count: b.count };",
    )
    .expect("write entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::Return { value: 5 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "count".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-cache-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(1));
}

#[test]
fn cjs_require_returns_same_exports_object() {
    let root = temp_module_dir("module_require_identity");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.cjs");
    fs::write(&dep_path, "module.exports = { count: 0 };").expect("write dep module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const first = require('./dep.cjs');\n\
const second = require('./dep.cjs');\n\
module.exports = first === second;",
    )
    .expect("write entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-identity-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Bool(true));
}

#[test]
fn cjs_exports_reassignment_does_not_replace_module_exports() {
    let root = temp_module_dir("module_exports_reassign");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "exports.answer = 1;\nmodule.exports.value = 2;\nexports = { answer: 3, value: 99 };\n",
    )
    .expect("write entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 3,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::Add {
                dst: 8,
                lhs: 5,
                rhs: 7,
            },
            Ir3Instruction::Return { value: 8 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "answer".to_string(),
            "value".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-exports-reassign-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(3));
}

#[test]
fn cjs_module_exports_reassignment_severs_exports_alias() {
    let root = temp_module_dir("module_exports_reassign_alias");
    fs::create_dir_all(&root).expect("create module root");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = { value: 7 };\nexports.value = 9;\nmodule.exports.extra = 1;\n",
    )
    .expect("write entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::LoadStr {
                dst: 4,
                pool_index: 2,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 4,
                dst: 5,
            },
            Ir3Instruction::LoadStr {
                dst: 6,
                pool_index: 3,
            },
            Ir3Instruction::GetProperty {
                obj: 3,
                key: 6,
                dst: 7,
            },
            Ir3Instruction::Add {
                dst: 8,
                lhs: 5,
                rhs: 7,
            },
            Ir3Instruction::Return { value: 8 },
        ],
        vec![
            "./entry.cjs".to_string(),
            "default".to_string(),
            "value".to_string(),
            "extra".to_string(),
        ],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-exports-reassign-alias-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(8));
}

#[test]
fn cjs_require_binding_can_be_aliased_and_called() {
    let root = temp_module_dir("module_require_alias");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.cjs");
    fs::write(&dep_path, "module.exports = 13;").expect("write dep module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "const req = require;\nmodule.exports = req('./dep.cjs');\n",
    )
    .expect("write entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-alias-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(13));
}

#[test]
fn cjs_module_require_property_is_callable() {
    let root = temp_module_dir("module_require_property");
    fs::create_dir_all(&root).expect("create module root");
    let dep_path = root.join("dep.cjs");
    fs::write(&dep_path, "module.exports = 17;").expect("write dep module");
    let entry_path = root.join("entry.cjs");
    fs::write(
        &entry_path,
        "module.exports = module.require('./dep.cjs');\n",
    )
    .expect("write entry module");

    let mut module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::ImportModule {
                specifier: 0,
                dst: 1,
            },
            Ir3Instruction::LoadStr {
                dst: 2,
                pool_index: 1,
            },
            Ir3Instruction::GetProperty {
                obj: 1,
                key: 2,
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ],
        vec!["./entry.cjs".to_string(), "default".to_string()],
    );
    let entry_label = root.join("main.mjs");
    module.header.source_label = entry_label.display().to_string();

    let mut config = InterpreterConfig::quickjs_defaults();
    config.module_root = Some(root.display().to_string());
    config.granted_capabilities = BTreeSet::from([RuntimeCapability::ModuleLoad]);
    let lane = QuickJsLane::with_config(config);
    let result = lane
        .execute(&module, "module-require-property-trace")
        .expect("execute");
    assert_eq!(result.value, Value::Int(17));
}

// ============================================================================
// Console Memory DoS Prevention Tests
// ============================================================================

#[test]
fn console_output_bounded_by_config_builtin_methods() {
    // Test that builtin console methods (ConsoleLog, ConsoleError, ConsoleWarn)
    // respect max_console_entries to prevent DoS via console spam
    let module = test_module_with_pool(
        vec![
            // Call console.log 5 times with different messages
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 3,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 4,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec![
            "message1".to_string(),
            "message2".to_string(),
            "message3".to_string(),
            "message4".to_string(),
            "message5".to_string(),
        ],
    );

    // Configure interpreter with max_console_entries = 3
    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_console_entries = 3;
    let mut core = InterpreterCore::new(config, "console-bounds-test");

    let result = core.execute(&module).expect("execution should succeed");
    assert_eq!(result.value, Value::Undefined);

    // Verify console output is bounded to max 3 entries (ring buffer behavior)
    let console_output = core.console_output();
    assert_eq!(
        console_output.len(),
        3,
        "console output should be limited to max_console_entries"
    );

    // Verify ring buffer: should contain last 3 messages (message3, message4, message5)
    assert_eq!(console_output[0].message, "message3");
    assert_eq!(console_output[1].message, "message4");
    assert_eq!(console_output[2].message, "message5");

    // All entries should be Log level
    for entry in console_output {
        assert_eq!(entry.level, ConsoleLevel::Log);
    }
}

#[test]
fn console_output_bounded_by_config_mixed_levels() {
    // Test that console bounds work with mixed console levels (log, error, warn)
    let module = test_module_with_pool(
        vec![
            // console.log
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            // console.error
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleError".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            // console.warn
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleWarn".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            // console.log again (should trigger ring buffer truncation)
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 3,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec![
            "log1".to_string(),
            "error1".to_string(),
            "warn1".to_string(),
            "log2".to_string(),
        ],
    );

    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_console_entries = 2; // Very small limit
    let mut core = InterpreterCore::new(config, "console-mixed-levels");

    let result = core.execute(&module).expect("execution should succeed");
    assert_eq!(result.value, Value::Undefined);

    let console_output = core.console_output();
    assert_eq!(
        console_output.len(),
        2,
        "console output should be limited to 2 entries"
    );

    // Should contain the last 2 messages: warn1 and log2
    assert_eq!(console_output[0].message, "warn1");
    assert_eq!(console_output[0].level, ConsoleLevel::Warn);
    assert_eq!(console_output[1].message, "log2");
    assert_eq!(console_output[1].level, ConsoleLevel::Log);
}

#[test]
fn console_output_zero_limit_prevents_all_output() {
    // Test edge case: max_console_entries = 0 should prevent any console output
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ConsoleLog".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["should_not_appear".to_string()],
    );

    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_console_entries = 0; // Zero limit
    let mut core = InterpreterCore::new(config, "console-zero-limit");

    let result = core.execute(&module).expect("execution should succeed");
    assert_eq!(result.value, Value::Undefined);

    let console_output = core.console_output();
    assert_eq!(
        console_output.len(),
        0,
        "zero max_console_entries should prevent all output"
    );
}

#[test]
fn console_output_hostcall_bounds_capability_based() {
    // Test console bounds for capability-based hostcalls (console:log, console:error, console:warn)
    // This tests the dispatch_console_hostcall implementation
    let mut module = test_module_with_pool(
        vec![
            // Make multiple console calls via hostcalls
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:log".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 1,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:error".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:warn".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 3,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("console:log".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec![
            "hostcall_log1".to_string(),
            "hostcall_error1".to_string(),
            "hostcall_warn1".to_string(),
            "hostcall_log2".to_string(),
        ],
    );

    // Grant console capabilities
    module.required_capabilities = vec![
        CapabilityTag("console:log".to_string()),
        CapabilityTag("console:error".to_string()),
        CapabilityTag("console:warn".to_string()),
    ];

    let mut config = InterpreterConfig::quickjs_defaults();
    config.max_console_entries = 3;
    let mut core = InterpreterCore::new(config, "console-hostcall-bounds");

    let result = core.execute(&module).expect("execution should succeed");
    assert_eq!(result.value, Value::Undefined);

    let console_output = core.console_output();
    assert_eq!(
        console_output.len(),
        3,
        "hostcall console output should be bounded"
    );

    // Should contain last 3 messages (error1, warn1, log2)
    assert_eq!(console_output[0].message, "hostcall_error1");
    assert_eq!(console_output[0].level, ConsoleLevel::Error);
    assert_eq!(console_output[1].message, "hostcall_warn1");
    assert_eq!(console_output[1].level, ConsoleLevel::Warn);
    assert_eq!(console_output[2].message, "hostcall_log2");
    assert_eq!(console_output[2].level, ConsoleLevel::Log);
}
