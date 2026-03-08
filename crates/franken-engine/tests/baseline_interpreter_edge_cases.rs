//! Integration edge-case tests for `baseline_interpreter` module.
//!
//! Covers: Value (serde, display, truthiness, type_name, ordering),
//! ObjectId, HeapObject, InterpreterError (serde, display, std::error),
//! InterpreterConfig (defaults, serde), InterpreterEvent (serde),
//! InterpreterCore (arithmetic edge cases, control flow, register bounds,
//! object heap, hostcall, capability, witness events, budget precision),
//! QuickJsLane, V8Lane, LaneRouter (routing, forced lanes),
//! LaneChoice/LaneReason (serde), and cross-cutting scenarios.

use frankenengine_engine::baseline_interpreter::{
    HeapObject, InterpreterConfig, InterpreterCore, InterpreterError, InterpreterEvent, LaneChoice,
    LaneReason, LaneRouter, ObjectId, QuickJsLane, V8Lane, Value,
};
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
    WitnessEventKind,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "test".to_string(),
        },
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

fn quickjs_execute(
    module: &Ir3Module,
) -> Result<frankenengine_engine::baseline_interpreter::ExecutionResult, InterpreterError> {
    QuickJsLane::new().execute(module, "test-trace")
}

// ===========================================================================
// Value
// ===========================================================================

#[test]
fn value_serde_all_variants() {
    let values = [
        Value::Undefined,
        Value::Null,
        Value::Bool(false),
        Value::Bool(true),
        Value::Int(0),
        Value::Int(-1),
        Value::Int(i64::MAX),
        Value::Int(i64::MIN),
        Value::Str(String::new()),
        Value::Str("hello world".into()),
        Value::Object(ObjectId(0)),
        Value::Object(ObjectId(u32::MAX)),
        Value::Function(0),
        Value::Function(u32::MAX),
    ];
    for val in &values {
        let json = serde_json::to_string(val).unwrap();
        let back: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(*val, back);
    }
}

#[test]
fn value_display_all_variants() {
    assert_eq!(Value::Undefined.to_string(), "undefined");
    assert_eq!(Value::Null.to_string(), "null");
    assert_eq!(Value::Bool(true).to_string(), "true");
    assert_eq!(Value::Bool(false).to_string(), "false");
    assert_eq!(Value::Int(42).to_string(), "42");
    assert_eq!(Value::Int(-1).to_string(), "-1");
    assert_eq!(Value::Str("hi".into()).to_string(), "hi");
    assert_eq!(Value::Object(ObjectId(7)).to_string(), "[object#7]");
    assert_eq!(Value::Function(3).to_string(), "[function#3]");
}

#[test]
fn value_type_name_all_variants() {
    assert_eq!(Value::Undefined.type_name(), "undefined");
    assert_eq!(Value::Null.type_name(), "null");
    assert_eq!(Value::Bool(true).type_name(), "boolean");
    assert_eq!(Value::Int(0).type_name(), "number");
    assert_eq!(Value::Str("x".into()).type_name(), "string");
    assert_eq!(Value::Object(ObjectId(0)).type_name(), "object");
    assert_eq!(Value::Function(0).type_name(), "function");
}

#[test]
fn value_truthiness_all_falsy() {
    assert!(!Value::Undefined.is_truthy());
    assert!(!Value::Null.is_truthy());
    assert!(!Value::Bool(false).is_truthy());
    assert!(!Value::Int(0).is_truthy());
    assert!(!Value::Str(String::new()).is_truthy());
}

#[test]
fn value_truthiness_all_truthy() {
    assert!(Value::Bool(true).is_truthy());
    assert!(Value::Int(1).is_truthy());
    assert!(Value::Int(-1).is_truthy());
    assert!(Value::Int(i64::MAX).is_truthy());
    assert!(Value::Str("x".into()).is_truthy());
    assert!(Value::Object(ObjectId(0)).is_truthy());
    assert!(Value::Function(0).is_truthy());
}

#[test]
fn value_ordering() {
    assert!(Value::Undefined < Value::Null);
    assert!(Value::Null < Value::Bool(false));
    assert!(Value::Bool(false) < Value::Bool(true));
    assert!(Value::Bool(true) < Value::Int(0));
    assert!(Value::Int(0) < Value::Str(String::new()));
}

// ===========================================================================
// ObjectId
// ===========================================================================

#[test]
fn object_id_serde() {
    let id = ObjectId(42);
    let json = serde_json::to_string(&id).unwrap();
    let back: ObjectId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}

#[test]
fn object_id_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(ObjectId(0));
    set.insert(ObjectId(0));
    assert_eq!(set.len(), 1);
    set.insert(ObjectId(1));
    assert_eq!(set.len(), 2);
}

// ===========================================================================
// HeapObject
// ===========================================================================

#[test]
fn heap_object_default_empty() {
    let obj = HeapObject::new();
    assert!(obj.properties.is_empty());
}

#[test]
fn heap_object_serde() {
    let mut obj = HeapObject::new();
    obj.properties.insert("key".into(), Value::Int(42));
    let json = serde_json::to_string(&obj).unwrap();
    let back: HeapObject = serde_json::from_str(&json).unwrap();
    assert_eq!(obj, back);
}

// ===========================================================================
// InterpreterError
// ===========================================================================

#[test]
fn interpreter_error_serde_all_variants() {
    let errors = [
        InterpreterError::BudgetExhausted {
            executed: 100,
            budget: 50,
        },
        InterpreterError::RegisterOutOfBounds {
            register: 999,
            max: 256,
        },
        InterpreterError::InstructionOutOfBounds { ip: 10, count: 5 },
        InterpreterError::StackOverflow {
            depth: 300,
            max: 256,
        },
        InterpreterError::TypeError {
            expected: "number".into(),
            got: "string".into(),
        },
        InterpreterError::DivisionByZero,
        InterpreterError::UndefinedRegister { register: 7 },
        InterpreterError::ObjectNotFound { id: 99 },
        InterpreterError::PropertyNotFound {
            object_id: 1,
            key: "foo".into(),
        },
        InterpreterError::FunctionNotFound {
            index: 5,
            table_size: 3,
        },
        InterpreterError::StringPoolOutOfBounds {
            index: 10,
            pool_size: 3,
        },
        InterpreterError::CapabilityDenied {
            capability: "net".into(),
        },
        InterpreterError::Halted,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: InterpreterError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn interpreter_error_display_all_variants() {
    let cases: Vec<(InterpreterError, &str)> = vec![
        (
            InterpreterError::BudgetExhausted {
                executed: 100,
                budget: 50,
            },
            "budget",
        ),
        (
            InterpreterError::RegisterOutOfBounds {
                register: 999,
                max: 256,
            },
            "register",
        ),
        (
            InterpreterError::InstructionOutOfBounds { ip: 10, count: 5 },
            "instruction pointer",
        ),
        (
            InterpreterError::StackOverflow {
                depth: 300,
                max: 256,
            },
            "stack overflow",
        ),
        (
            InterpreterError::TypeError {
                expected: "number".into(),
                got: "string".into(),
            },
            "type error",
        ),
        (InterpreterError::DivisionByZero, "division by zero"),
        (
            InterpreterError::UndefinedRegister { register: 7 },
            "undefined register",
        ),
        (InterpreterError::ObjectNotFound { id: 99 }, "object#99"),
        (
            InterpreterError::PropertyNotFound {
                object_id: 1,
                key: "foo".into(),
            },
            "foo",
        ),
        (
            InterpreterError::FunctionNotFound {
                index: 5,
                table_size: 3,
            },
            "function#5",
        ),
        (
            InterpreterError::StringPoolOutOfBounds {
                index: 10,
                pool_size: 3,
            },
            "string pool",
        ),
        (
            InterpreterError::CapabilityDenied {
                capability: "net".into(),
            },
            "net",
        ),
        (InterpreterError::Halted, "halted"),
    ];
    for (err, expected_substr) in &cases {
        let s = err.to_string();
        assert!(
            s.contains(expected_substr),
            "'{s}' should contain '{expected_substr}'"
        );
    }
}

// ===========================================================================
// InterpreterConfig
// ===========================================================================

#[test]
fn config_quickjs_defaults() {
    let cfg = InterpreterConfig::quickjs_defaults();
    assert_eq!(cfg.instruction_budget, 100_000);
    assert_eq!(cfg.max_registers, 256);
    assert_eq!(cfg.max_call_depth, 256);
    assert!(cfg.granted_capabilities.is_empty());
}

#[test]
fn config_v8_defaults() {
    let cfg = InterpreterConfig::v8_defaults();
    assert_eq!(cfg.instruction_budget, 1_000_000);
    assert_eq!(cfg.max_registers, 4096);
    assert_eq!(cfg.max_call_depth, 256);
    assert!(cfg.granted_capabilities.is_empty());
}

#[test]
fn config_v8_more_generous_than_quickjs() {
    let qjs = InterpreterConfig::quickjs_defaults();
    let v8 = InterpreterConfig::v8_defaults();
    assert!(v8.instruction_budget > qjs.instruction_budget);
    assert!(v8.max_registers > qjs.max_registers);
}

#[test]
fn config_serde_roundtrip() {
    let cfg = InterpreterConfig::quickjs_defaults();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: InterpreterConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

// ===========================================================================
// InterpreterEvent serde
// ===========================================================================

#[test]
fn interpreter_event_serde() {
    let evt = InterpreterEvent {
        trace_id: "t".into(),
        component: "baseline_interpreter".into(),
        event: "execution_started".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&evt).unwrap();
    let back: InterpreterEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(evt, back);
}

// ===========================================================================
// LaneChoice / LaneReason serde
// ===========================================================================

#[test]
fn lane_choice_serde() {
    for lc in [LaneChoice::QuickJs, LaneChoice::V8] {
        let json = serde_json::to_string(&lc).unwrap();
        let back: LaneChoice = serde_json::from_str(&json).unwrap();
        assert_eq!(lc, back);
    }
}

#[test]
fn lane_reason_serde() {
    for lr in [
        LaneReason::SecuritySensitive,
        LaneReason::ThroughputOptimized,
        LaneReason::PolicyDirective,
        LaneReason::DefaultFallback,
    ] {
        let json = serde_json::to_string(&lr).unwrap();
        let back: LaneReason = serde_json::from_str(&json).unwrap();
        assert_eq!(lr, back);
    }
}

// ===========================================================================
// Arithmetic edge cases
// ===========================================================================

#[test]
fn add_wrapping_overflow() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: 1,
            value: i64::MAX,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 1 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(i64::MIN)); // wrapping
}

#[test]
fn sub_wrapping_underflow() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: 1,
            value: i64::MIN,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 1 },
        Ir3Instruction::Sub {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(i64::MAX)); // wrapping
}

#[test]
fn mul_wrapping_overflow() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt {
            dst: 1,
            value: i64::MAX,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 2 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(i64::MAX.wrapping_mul(2)));
}

#[test]
fn add_negative_integers() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: -10 },
        Ir3Instruction::LoadInt { dst: 2, value: -20 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(-30));
}

#[test]
fn div_integer_truncation() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 7 },
        Ir3Instruction::LoadInt { dst: 2, value: 2 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(3)); // truncated
}

#[test]
fn sub_type_error() {
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
    let err = quickjs_execute(&m).unwrap_err();
    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

#[test]
fn mul_type_error() {
    let m = test_module(vec![
        Ir3Instruction::LoadBool {
            dst: 1,
            value: true,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 2 },
        Ir3Instruction::Mul {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    let err = quickjs_execute(&m).unwrap_err();
    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

#[test]
fn div_type_error() {
    let m = test_module(vec![
        Ir3Instruction::LoadNull { dst: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 1 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    let err = quickjs_execute(&m).unwrap_err();
    assert!(matches!(err, InterpreterError::TypeError { .. }));
}

// ===========================================================================
// String concatenation variants
// ===========================================================================

#[test]
fn string_plus_int() {
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
        vec!["val=".into()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Str("val=42".into()));
}

#[test]
fn int_plus_string() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadInt { dst: 1, value: 42 },
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
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Str("42px".into()));
}

#[test]
fn string_plus_bool() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadBool {
                dst: 2,
                value: true,
            },
            Ir3Instruction::Add {
                dst: 0,
                lhs: 1,
                rhs: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["is: ".into()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Str("is: true".into()));
}

// ===========================================================================
// Control flow edge cases
// ===========================================================================

#[test]
fn jump_to_halt() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        Ir3Instruction::Jump { target: 2 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(99));
}

#[test]
fn jumpif_with_int_truthy() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 42 }, // truthy
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::JumpIf { cond: 1, target: 4 },
        Ir3Instruction::LoadInt { dst: 0, value: 2 }, // skipped
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(1));
}

#[test]
fn jumpif_with_zero_falsy() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 0 }, // falsy
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::JumpIf { cond: 1, target: 4 },
        Ir3Instruction::LoadInt { dst: 0, value: 2 }, // executed
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(2));
}

#[test]
fn jumpif_with_empty_string_falsy() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::JumpIf { cond: 1, target: 4 },
            Ir3Instruction::LoadInt { dst: 0, value: 2 },
            Ir3Instruction::Halt,
        ],
        vec![String::new()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(2));
}

#[test]
fn jumpif_with_null_falsy() {
    let m = test_module(vec![
        Ir3Instruction::LoadNull { dst: 1 },
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::JumpIf { cond: 1, target: 4 },
        Ir3Instruction::LoadInt { dst: 0, value: 2 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(2));
}

// ===========================================================================
// Budget precision
// ===========================================================================

#[test]
fn budget_exactly_sufficient() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.instruction_budget = 2;
    let lane = QuickJsLane::with_config(cfg);
    let result = lane.execute(&m, "test").unwrap();
    assert_eq!(result.value, Value::Int(42));
    assert_eq!(result.instructions_executed, 2);
}

#[test]
fn budget_one_short() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.instruction_budget = 1;
    let lane = QuickJsLane::with_config(cfg);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
}

#[test]
fn zero_budget() {
    let m = test_module(vec![Ir3Instruction::Halt]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.instruction_budget = 0;
    let lane = QuickJsLane::with_config(cfg);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::BudgetExhausted { .. }));
}

// ===========================================================================
// Register edge cases
// ===========================================================================

#[test]
fn register_out_of_bounds_on_read() {
    let m = test_module(vec![Ir3Instruction::Move { dst: 0, src: 9999 }]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.max_registers = 256;
    let lane = QuickJsLane::with_config(cfg);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::RegisterOutOfBounds { .. }));
}

#[test]
fn register_out_of_bounds_on_write() {
    let m = test_module(vec![Ir3Instruction::LoadInt {
        dst: 9999,
        value: 1,
    }]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.max_registers = 256;
    let lane = QuickJsLane::with_config(cfg);
    let err = lane.execute(&m, "test").unwrap_err();
    assert!(matches!(err, InterpreterError::RegisterOutOfBounds { .. }));
}

#[test]
fn move_to_same_register() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Move { dst: 0, src: 0 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(42));
}

// ===========================================================================
// String pool edge cases
// ===========================================================================

#[test]
fn string_pool_out_of_bounds() {
    let m = test_module(vec![Ir3Instruction::LoadStr {
        dst: 0,
        pool_index: 0,
    }]);
    let err = quickjs_execute(&m).unwrap_err();
    assert!(matches!(
        err,
        InterpreterError::StringPoolOutOfBounds { .. }
    ));
}

#[test]
fn string_pool_max_index() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 2,
            },
            Ir3Instruction::Halt,
        ],
        vec!["a".into(), "b".into(), "c".into()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Str("c".into()));
}

// ===========================================================================
// Hostcall / Capability
// ===========================================================================

#[test]
fn hostcall_capability_denied() {
    let m = test_module(vec![Ir3Instruction::HostCall {
        capability: CapabilityTag("network".into()),
        args: RegRange { start: 0, count: 0 },
        dst: 0,
    }]);
    let err = quickjs_execute(&m).unwrap_err();
    match &err {
        InterpreterError::CapabilityDenied { capability } => {
            assert_eq!(capability, "network");
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
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.granted_capabilities = vec!["fs".into()];
    let lane = QuickJsLane::with_config(cfg);
    let result = lane.execute(&m, "test").unwrap();
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn hostcall_records_decision() {
    let m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.granted_capabilities = vec!["fs".into()];
    let lane = QuickJsLane::with_config(cfg);
    let result = lane.execute(&m, "test").unwrap();
    assert_eq!(result.hostcall_decisions.len(), 1);
    assert!(result.hostcall_decisions[0].allowed);
    assert_eq!(result.hostcall_decisions[0].capability.0, "fs");
    assert_eq!(result.hostcall_decisions[0].seq, 0);
}

#[test]
fn multiple_hostcalls_sequential_decisions() {
    let m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::HostCall {
            capability: CapabilityTag("net".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 1,
        },
        Ir3Instruction::Halt,
    ]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.granted_capabilities = vec!["fs".into(), "net".into()];
    let lane = QuickJsLane::with_config(cfg);
    let result = lane.execute(&m, "test").unwrap();
    assert_eq!(result.hostcall_decisions.len(), 2);
    assert_eq!(result.hostcall_decisions[0].seq, 0);
    assert_eq!(result.hostcall_decisions[1].seq, 1);
}

// ===========================================================================
// Witness events
// ===========================================================================

#[test]
fn witness_events_include_execution_completed() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::ExecutionCompleted)
    );
}

#[test]
fn witness_events_from_hostcall() {
    let m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.granted_capabilities = vec!["fs".into()];
    let lane = QuickJsLane::with_config(cfg);
    let result = lane.execute(&m, "test").unwrap();
    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::HostcallDispatched)
    );
    assert!(
        result
            .witness_events
            .iter()
            .any(|e| e.kind == WitnessEventKind::CapabilityChecked)
    );
}

#[test]
fn witness_events_seq_numbers_increment() {
    let m = test_module(vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag("fs".into()),
            args: RegRange { start: 0, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ]);
    let mut cfg = InterpreterConfig::quickjs_defaults();
    cfg.granted_capabilities = vec!["fs".into()];
    let lane = QuickJsLane::with_config(cfg);
    let result = lane.execute(&m, "test").unwrap();
    for (i, evt) in result.witness_events.iter().enumerate() {
        assert_eq!(evt.seq, i as u64);
    }
}

// ===========================================================================
// Structured events
// ===========================================================================

#[test]
fn structured_events_on_success() {
    let m = test_module(vec![Ir3Instruction::Halt]);
    let result = quickjs_execute(&m).unwrap();
    assert!(result.events.iter().any(|e| e.event == "execution_started"));
    assert!(result.events.iter().any(|e| e.event == "execution_halted"));
    assert!(result.events.iter().all(|e| e.outcome == "ok"));
}

#[test]
fn structured_events_on_error() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 1 },
        Ir3Instruction::LoadInt { dst: 2, value: 0 },
        Ir3Instruction::Div {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
    ]);
    // DivisionByZero should produce execution_started but no execution_completed
    let _ = quickjs_execute(&m);
    // (We can't inspect events on error — they're consumed by the error path)
}

#[test]
fn structured_events_trace_id_propagated() {
    let m = test_module(vec![Ir3Instruction::Halt]);
    let lane = QuickJsLane::new();
    let result = lane.execute(&m, "my-trace-id").unwrap();
    for evt in &result.events {
        assert_eq!(evt.trace_id, "my-trace-id");
        assert_eq!(evt.component, "baseline_interpreter");
    }
}

// ===========================================================================
// Empty module
// ===========================================================================

#[test]
fn empty_module_returns_undefined() {
    let m = test_module(vec![]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Undefined);
    assert_eq!(result.instructions_executed, 0);
}

// ===========================================================================
// Lane routing
// ===========================================================================

#[test]
fn router_default_selects_quickjs() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let router = LaneRouter::new();
    let result = router.execute(&m, "t", None).unwrap();
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.reason, LaneReason::DefaultFallback);
}

#[test]
fn router_capability_selects_quickjs_security() {
    let mut m = test_module(vec![Ir3Instruction::Halt]);
    m.required_capabilities = vec![CapabilityTag("net".into())];
    let router = LaneRouter::new();
    let result = router.execute(&m, "t", None).unwrap();
    assert_eq!(result.lane, LaneChoice::QuickJs);
    assert_eq!(result.reason, LaneReason::SecuritySensitive);
}

#[test]
fn router_large_module_selects_v8() {
    let instrs: Vec<Ir3Instruction> = (0..1001)
        .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 1 })
        .chain(std::iter::once(Ir3Instruction::Halt))
        .collect();
    let m = test_module(instrs);
    let router = LaneRouter::new();
    let result = router.execute(&m, "t", None).unwrap();
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::ThroughputOptimized);
}

#[test]
fn router_forced_lane_overrides() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 1 },
        Ir3Instruction::Halt,
    ]);
    let router = LaneRouter::new();
    let result = router.execute(&m, "t", Some(LaneChoice::V8)).unwrap();
    assert_eq!(result.lane, LaneChoice::V8);
    assert_eq!(result.reason, LaneReason::PolicyDirective);
}

#[test]
fn router_1000_instructions_still_quickjs() {
    // Exactly 1000 instructions (boundary: > 1000 needed for V8)
    let instrs: Vec<Ir3Instruction> = (0..999)
        .map(|_| Ir3Instruction::LoadInt { dst: 0, value: 1 })
        .chain(std::iter::once(Ir3Instruction::Halt))
        .collect();
    assert_eq!(instrs.len(), 1000);
    let m = test_module(instrs);
    let router = LaneRouter::new();
    let result = router.execute(&m, "t", None).unwrap();
    assert_eq!(result.lane, LaneChoice::QuickJs);
}

// ===========================================================================
// V8 and QuickJs produce same results
// ===========================================================================

#[test]
fn both_lanes_produce_same_value() {
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
    let qjs = QuickJsLane::new().execute(&m, "t").unwrap();
    let v8 = V8Lane::new().execute(&m, "t").unwrap();
    assert_eq!(qjs.value, v8.value);
    assert_eq!(qjs.instructions_executed, v8.instructions_executed);
}

// ===========================================================================
// Determinism
// ===========================================================================

#[test]
fn deterministic_execution_same_witness() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 100 },
        Ir3Instruction::LoadInt { dst: 2, value: 200 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 1,
            rhs: 2,
        },
        Ir3Instruction::Halt,
    ]);
    let r1 = quickjs_execute(&m).unwrap();
    let r2 = quickjs_execute(&m).unwrap();
    assert_eq!(r1.value, r2.value);
    assert_eq!(r1.instructions_executed, r2.instructions_executed);
    assert_eq!(r1.witness_events.len(), r2.witness_events.len());
}

// ===========================================================================
// InterpreterCore heap operations
// ===========================================================================

#[test]
fn alloc_object_returns_sequential_ids() {
    let cfg = InterpreterConfig::quickjs_defaults();
    let mut core = InterpreterCore::new(cfg, "test");
    let id0 = core.alloc_object();
    let id1 = core.alloc_object();
    let id2 = core.alloc_object();
    assert_eq!(id0, ObjectId(0));
    assert_eq!(id1, ObjectId(1));
    assert_eq!(id2, ObjectId(2));
    assert_eq!(core.heap_size(), 3);
}

#[test]
fn heap_size_starts_at_zero() {
    let cfg = InterpreterConfig::quickjs_defaults();
    let core = InterpreterCore::new(cfg, "test");
    assert_eq!(core.heap_size(), 0);
}

// ===========================================================================
// Complex programs
// ===========================================================================

#[test]
fn fibonacci_iterative_10() {
    // Compute fib(10) = 55 iteratively
    // r0=a, r1=b, r2=counter, r3=limit, r4=temp, r5=1
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 0 }, // 0: a = 0
        Ir3Instruction::LoadInt { dst: 1, value: 1 }, // 1: b = 1
        Ir3Instruction::LoadInt { dst: 2, value: 0 }, // 2: counter = 0
        Ir3Instruction::LoadInt { dst: 3, value: 10 }, // 3: limit = 10
        Ir3Instruction::LoadInt { dst: 5, value: 1 }, // 4: const 1
        // Loop body (5):
        Ir3Instruction::Add {
            dst: 4,
            lhs: 0,
            rhs: 1,
        }, // 5: temp = a + b
        Ir3Instruction::Move { dst: 0, src: 1 }, // 6: a = b
        Ir3Instruction::Move { dst: 1, src: 4 }, // 7: b = temp
        Ir3Instruction::Add {
            dst: 2,
            lhs: 2,
            rhs: 5,
        }, // 8: counter++
        Ir3Instruction::Sub {
            dst: 4,
            lhs: 3,
            rhs: 2,
        }, // 9: r4 = limit - counter
        Ir3Instruction::JumpIf { cond: 4, target: 5 }, // 10: loop
        Ir3Instruction::Halt,                    // 11
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(55));
}

#[test]
fn many_sequential_loads() {
    let mut instrs: Vec<Ir3Instruction> = (0..100u32)
        .map(|i| Ir3Instruction::LoadInt {
            dst: i.min(255),
            value: i as i64,
        })
        .collect();
    instrs.push(Ir3Instruction::Halt);
    let m = test_module(instrs);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.instructions_executed, 101);
}

// ===========================================================================
// Return from top level
// ===========================================================================

#[test]
fn return_from_top_level_yields_value() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 99 },
        Ir3Instruction::Return { value: 0 },
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(99));
}

#[test]
fn fall_off_end_returns_r0() {
    let m = test_module(vec![Ir3Instruction::LoadInt { dst: 0, value: 77 }]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Int(77));
}

// ===========================================================================
// Router with custom configs
// ===========================================================================

#[test]
fn router_with_custom_configs() {
    let qjs_cfg = InterpreterConfig {
        instruction_budget: 10,
        ..InterpreterConfig::quickjs_defaults()
    };
    let v8_cfg = InterpreterConfig {
        instruction_budget: 20,
        ..InterpreterConfig::v8_defaults()
    };
    let router = LaneRouter::with_configs(qjs_cfg, v8_cfg);

    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 0, value: 42 },
        Ir3Instruction::Halt,
    ]);
    let result = router.execute(&m, "t", None).unwrap();
    assert_eq!(result.result.value, Value::Int(42));
}

// ===========================================================================
// New unary / nullish / delete instruction coverage
// ===========================================================================

#[test]
fn value_nullish_and_typeof_helpers_cover_runtime_contract() {
    assert!(Value::Undefined.is_nullish());
    assert!(Value::Null.is_nullish());
    assert!(!Value::Int(0).is_nullish());

    assert_eq!(Value::Undefined.typeof_name(), "undefined");
    assert_eq!(Value::Null.typeof_name(), "object");
    assert_eq!(Value::Bool(true).typeof_name(), "boolean");
    assert_eq!(Value::Int(1).typeof_name(), "number");
    assert_eq!(Value::Str("x".into()).typeof_name(), "string");
    assert_eq!(Value::Object(ObjectId(0)).typeof_name(), "object");
    assert_eq!(Value::Function(0).typeof_name(), "function");
}

#[test]
fn jump_if_nullish_branches_only_for_nullish_values() {
    let taken = test_module(vec![
        Ir3Instruction::LoadNull { dst: 1 },
        Ir3Instruction::LoadInt { dst: 0, value: 10 },
        Ir3Instruction::JumpIfNullish { cond: 1, target: 4 },
        Ir3Instruction::LoadInt { dst: 0, value: 20 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(quickjs_execute(&taken).unwrap().value, Value::Int(10));

    let not_taken = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 1 },
        Ir3Instruction::LoadInt { dst: 0, value: 10 },
        Ir3Instruction::JumpIfNullish { cond: 1, target: 4 },
        Ir3Instruction::LoadInt { dst: 0, value: 20 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(quickjs_execute(&not_taken).unwrap().value, Value::Int(20));
}

#[test]
fn unary_instruction_variants_execute_with_deterministic_coercions() {
    let m = test_module_with_pool(
        vec![
            Ir3Instruction::LoadStr {
                dst: 1,
                pool_index: 0,
            },
            Ir3Instruction::UnaryPlus { dst: 2, src: 1 },
            Ir3Instruction::UnaryNeg { dst: 3, src: 1 },
            Ir3Instruction::BitNot { dst: 4, src: 1 },
            Ir3Instruction::LogicalNot { dst: 5, src: 4 },
            Ir3Instruction::TemplateLiteral {
                parts: RegRange { start: 2, count: 4 },
                dst: 0,
            },
            Ir3Instruction::Halt,
        ],
        vec!["7".into()],
    );
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Str("7-7-8false".into()));
}

#[test]
fn void_instruction_returns_undefined_after_evaluating_input() {
    let m = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 99 },
        Ir3Instruction::Void { dst: 0, src: 1 },
        Ir3Instruction::Halt,
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Undefined);
}

#[test]
fn typeof_instruction_matches_js_null_and_number_labels() {
    let number_case = test_module(vec![
        Ir3Instruction::LoadInt { dst: 1, value: 5 },
        Ir3Instruction::TypeOf { dst: 0, src: 1 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(
        quickjs_execute(&number_case).unwrap().value,
        Value::Str("number".into())
    );

    let null_case = test_module(vec![
        Ir3Instruction::LoadNull { dst: 1 },
        Ir3Instruction::TypeOf { dst: 0, src: 1 },
        Ir3Instruction::Halt,
    ]);
    assert_eq!(
        quickjs_execute(&null_case).unwrap().value,
        Value::Str("object".into())
    );
}

#[test]
fn delete_property_returns_true_and_removes_key() {
    let delete_result = test_module(vec![
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::LoadInt { dst: 1, value: 7 },
        Ir3Instruction::LoadInt { dst: 2, value: 42 },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::DeleteProperty {
            obj: 0,
            key: 1,
            dst: 3,
        },
        Ir3Instruction::Return { value: 3 },
    ]);
    assert_eq!(
        quickjs_execute(&delete_result).unwrap().value,
        Value::Bool(true)
    );

    let m = test_module(vec![
        Ir3Instruction::NewObject { dst: 0 },
        Ir3Instruction::LoadInt { dst: 1, value: 7 },
        Ir3Instruction::LoadInt { dst: 2, value: 42 },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::DeleteProperty {
            obj: 0,
            key: 1,
            dst: 3,
        },
        Ir3Instruction::InOp {
            dst: 4,
            lhs: 1,
            rhs: 0,
        },
        Ir3Instruction::Return { value: 4 },
    ]);
    let result = quickjs_execute(&m).unwrap();
    assert_eq!(result.value, Value::Bool(false));
}
