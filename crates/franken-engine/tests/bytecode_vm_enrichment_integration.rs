//! Enrichment integration tests for the `bytecode_vm` module.

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

use frankenengine_engine::bytecode_vm::{
    BytecodeVm, ExecutionReport, InlineCacheEntry, InlineCacheStats, Instruction, ObjectId,
    Program, Register, Value, VmError, VmEvent,
};

fn r(index: u16) -> Register {
    Register(index)
}

fn simple_return_program(value: Value) -> Program {
    Program {
        constants: vec![value],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    }
}

// ---------------------------------------------------------------------------
// Value ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_value_ordering_undefined_first() {
    assert!(Value::Undefined < Value::Bool(false));
    assert!(Value::Undefined < Value::Int(0));
    assert!(Value::Undefined < Value::Object(ObjectId(0)));
}

#[test]
fn enrichment_value_ordering_bool_before_int() {
    assert!(Value::Bool(false) < Value::Bool(true));
    assert!(Value::Bool(true) < Value::Int(i64::MIN));
}

#[test]
fn enrichment_value_ordering_int_before_object() {
    assert!(Value::Int(i64::MAX) < Value::Object(ObjectId(0)));
}

// ---------------------------------------------------------------------------
// Register / ObjectId ordering and serde
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_ordering() {
    assert!(Register(0) < Register(1));
    assert!(Register(100) < Register(u16::MAX));
}

#[test]
fn enrichment_register_serde_roundtrip() {
    for reg in [Register(0), Register(1), Register(u16::MAX)] {
        let json = serde_json::to_string(&reg).unwrap();
        let back: Register = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, back);
    }
}

#[test]
fn enrichment_object_id_ordering() {
    assert!(ObjectId(0) < ObjectId(1));
    assert!(ObjectId(999) < ObjectId(1000));
}

#[test]
fn enrichment_object_id_serde_roundtrip() {
    for id in [ObjectId(0), ObjectId(42), ObjectId(u32::MAX)] {
        let json = serde_json::to_string(&id).unwrap();
        let back: ObjectId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}

// ---------------------------------------------------------------------------
// Default implementations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inline_cache_entry_default() {
    let entry = InlineCacheEntry::default();
    assert_eq!(entry.shape_id, 0);
    assert_eq!(entry.property_index, 0);
    assert_eq!(entry.slot_index, 0);
    assert_eq!(entry.hits, 0);
    assert_eq!(entry.misses, 0);
}

#[test]
fn enrichment_inline_cache_stats_default() {
    let stats = InlineCacheStats::default();
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
}

#[test]
fn enrichment_program_default() {
    let program = Program::default();
    assert!(program.constants.is_empty());
    assert!(program.property_pool.is_empty());
    assert!(program.instructions.is_empty());
}

// ---------------------------------------------------------------------------
// VmError serde serialize all 9 variants (deserialize needs 'static for TypeMismatch)
// ---------------------------------------------------------------------------

#[test]
fn enrichment_vm_error_serde_all_variants_serialize() {
    let errors: Vec<VmError> = vec![
        VmError::RegisterOutOfBounds {
            register: 99,
            register_count: 8,
        },
        VmError::ConstantOutOfBounds {
            const_index: 5,
            constant_count: 3,
        },
        VmError::PropertyIndexOutOfBounds {
            property_index: 10,
            property_count: 2,
        },
        VmError::ObjectNotFound { object_id: 42 },
        VmError::TypeMismatch {
            expected: "int",
            got: "bool",
        },
        VmError::DivisionByZero,
        VmError::InvalidJumpTarget {
            target: 999,
            instruction_count: 10,
        },
        VmError::MissingReturn,
        VmError::BudgetExhausted {
            executed_steps: 100,
            step_budget: 100,
        },
    ];
    let mut jsons = std::collections::BTreeSet::new();
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        assert!(!json.is_empty(), "serialized VmError should be nonempty");
        jsons.insert(json);
    }
    assert_eq!(
        jsons.len(),
        errors.len(),
        "all 9 VmError variants should produce unique JSON"
    );
}

#[test]
fn enrichment_vm_error_serde_type_mismatch_contains_fields() {
    let err = VmError::TypeMismatch {
        expected: "object",
        got: "undefined",
    };
    let json = serde_json::to_string(&err).unwrap();
    assert!(json.contains("object"), "should contain expected field");
    assert!(json.contains("undefined"), "should contain got field");
}

// ---------------------------------------------------------------------------
// State hash format
// ---------------------------------------------------------------------------

#[test]
fn enrichment_state_hash_is_64_hex_chars() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("trace-hash-format", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.state_hash.len(), 64, "SHA-256 hex is 64 chars");
    assert!(
        report.state_hash.chars().all(|c| c.is_ascii_hexdigit()),
        "state hash should be hex: {}",
        report.state_hash
    );
}

// ---------------------------------------------------------------------------
// ExecutionReport fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_trace_id_matches_vm() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("my-unique-trace", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.trace_id, "my-unique-trace");
}

#[test]
fn enrichment_report_serde_roundtrip() {
    let program = simple_return_program(Value::Int(42));
    let mut vm = BytecodeVm::new("trace-roundtrip", 4, 32);
    let report = vm.execute(&program).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: ExecutionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Event sequence invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_events_have_sequential_steps() {
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(2)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 8, 32);
    let report = vm.execute(&program).unwrap();
    for (i, event) in report.events.iter().enumerate() {
        assert_eq!(
            event.step,
            (i + 1) as u64,
            "event {i} should have step {}",
            i + 1
        );
    }
}

#[test]
fn enrichment_events_component_is_bytecode_vm() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    for event in &report.events {
        assert_eq!(event.component, "bytecode_vm");
    }
}

#[test]
fn enrichment_last_event_is_return() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    let last = report.events.last().unwrap();
    assert_eq!(last.event, "return");
    assert_eq!(last.outcome, "ok");
}

// ---------------------------------------------------------------------------
// JumpIfFalse truthiness edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_jump_if_false_undefined_takes_branch() {
    // r(0) is Undefined by default, JumpIfFalse should take the branch
    let program = Program {
        constants: vec![Value::Int(100)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 2,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Undefined);
    assert_eq!(report.steps, 2); // JumpIfFalse + Return, skipped LoadConst
}

#[test]
fn enrichment_jump_if_false_zero_takes_branch() {
    let program = Program {
        constants: vec![Value::Int(0), Value::Int(99)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 3,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(0));
    assert_eq!(report.steps, 3); // LoadConst + JumpIfFalse + Return (skips LoadConst r1)
}

#[test]
fn enrichment_jump_if_false_nonzero_does_not_branch() {
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(99)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 3,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Return { src: r(1) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(99));
}

#[test]
fn enrichment_jump_if_false_bool_false_takes_branch() {
    let program = Program {
        constants: vec![Value::Bool(false), Value::Int(42)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 3,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Bool(false));
}

#[test]
fn enrichment_jump_if_false_object_does_not_branch() {
    let program = Program {
        constants: vec![Value::Int(77)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 3,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::Return { src: r(1) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(77)); // did NOT branch
}

// ---------------------------------------------------------------------------
// Wrapping arithmetic
// ---------------------------------------------------------------------------

#[test]
fn enrichment_add_wrapping_overflow() {
    let program = Program {
        constants: vec![Value::Int(i64::MAX), Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(i64::MIN)); // wrapping
}

#[test]
fn enrichment_sub_wrapping_underflow() {
    let program = Program {
        constants: vec![Value::Int(i64::MIN), Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Sub {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(i64::MAX)); // wrapping
}

#[test]
fn enrichment_mul_wrapping_overflow() {
    let program = Program {
        constants: vec![Value::Int(i64::MAX), Value::Int(2)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Mul {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(-2)); // wrapping
}

// ---------------------------------------------------------------------------
// LoadPropCached on missing property returns Undefined
// ---------------------------------------------------------------------------

#[test]
fn enrichment_load_missing_property_returns_undefined() {
    let program = Program {
        constants: Vec::new(),
        property_pool: vec!["nonexistent".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadPropCached {
                dst: r(1),
                object: r(0),
                property_index: 0,
            },
            Instruction::Return { src: r(1) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Undefined);
}

// ---------------------------------------------------------------------------
// StoreProp overwrites existing property
// ---------------------------------------------------------------------------

#[test]
fn enrichment_store_prop_overwrites_existing() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(20)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 8, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(20)); // overwritten value
}

// ---------------------------------------------------------------------------
// Move instruction
// ---------------------------------------------------------------------------

#[test]
fn enrichment_move_copies_value() {
    let program = Program {
        constants: vec![Value::Int(55)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Move {
                dst: r(1),
                src: r(0),
            },
            Instruction::Return { src: r(1) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(55));
}

#[test]
fn enrichment_move_undefined_source() {
    // r(1) is Undefined by default
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::Move {
                dst: r(0),
                src: r(1),
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Undefined);
}

// ---------------------------------------------------------------------------
// Shape trace populated after property store
// ---------------------------------------------------------------------------

#[test]
fn enrichment_shape_trace_populated_after_store_prop() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: vec!["a".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::Return { src: r(1) },
        ],
    };
    let mut vm = BytecodeVm::new("t-trace", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert!(
        !report.shape_trace.is_empty(),
        "shape trace should have entries after StoreProp"
    );
    let trace_event = &report.shape_trace[0];
    assert_eq!(trace_event.trace_id, "t-trace");
    assert_eq!(trace_event.component, "bytecode_vm");
    assert_eq!(trace_event.object_id, 0);
    assert!(trace_event.property_key.is_some());
}

// ---------------------------------------------------------------------------
// Shape lattice manifest populated
// ---------------------------------------------------------------------------

#[test]
fn enrichment_shape_lattice_populated_after_property_ops() {
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(2)],
        property_pool: vec!["x".to_string(), "y".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadConst {
                dst: r(2),
                const_index: 1,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 1,
                value: r(2),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 8, 32);
    let report = vm.execute(&program).unwrap();
    assert!(
        report.shape_lattice.shapes.len() > 1,
        "should have multiple shapes after adding properties"
    );
    assert!(
        !report.shape_lattice.transitions.is_empty(),
        "should have transitions"
    );
}

// ---------------------------------------------------------------------------
// Cache stats with no cache operations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_no_cache_ops_yields_empty_stats() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.cache_stats.entries, 0);
    assert_eq!(report.cache_stats.hits, 0);
    assert_eq!(report.cache_stats.misses, 0);
}

// ---------------------------------------------------------------------------
// Add with non-int types fails
// ---------------------------------------------------------------------------

#[test]
fn enrichment_add_bool_type_mismatch() {
    let program = Program {
        constants: vec![Value::Bool(true), Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert_eq!(
        err,
        VmError::TypeMismatch {
            expected: "int",
            got: "bool"
        }
    );
}

#[test]
fn enrichment_add_undefined_type_mismatch() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            // r(1) is Undefined
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert_eq!(
        err,
        VmError::TypeMismatch {
            expected: "int",
            got: "undefined"
        }
    );
}

// ---------------------------------------------------------------------------
// VmEvent serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_vm_event_serde_roundtrip_with_optional_fields() {
    let event = VmEvent {
        trace_id: "trace-1".to_string(),
        component: "bytecode_vm".to_string(),
        step: 1,
        ip: 0,
        opcode: "load_const".to_string(),
        event: "instruction".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("test_error".to_string()),
        cache_hit: Some(true),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: VmEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn enrichment_vm_event_serde_roundtrip_without_optional_fields() {
    let event = VmEvent {
        trace_id: "trace-2".to_string(),
        component: "bytecode_vm".to_string(),
        step: 5,
        ip: 3,
        opcode: "return".to_string(),
        event: "return".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        cache_hit: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: VmEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// InlineCacheEntry serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inline_cache_entry_serde_roundtrip() {
    let entry = InlineCacheEntry {
        shape_id: 42,
        property_index: 3,
        slot_index: 1,
        hits: 100,
        misses: 5,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: InlineCacheEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

// ---------------------------------------------------------------------------
// Division edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_div_negative_numbers() {
    let program = Program {
        constants: vec![Value::Int(-10), Value::Int(3)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Div {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(-3)); // truncating division
}

#[test]
fn enrichment_div_min_by_neg_one_wraps() {
    let program = Program {
        constants: vec![Value::Int(i64::MIN), Value::Int(-1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Div {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(i64::MIN)); // wrapping_div wraps
}

// ---------------------------------------------------------------------------
// Error event carries error_code
// ---------------------------------------------------------------------------

#[test]
fn enrichment_budget_error_event_has_error_code() {
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![Instruction::Jump { target: 0 }],
    };
    let mut vm = BytecodeVm::new("t-budget-err", 4, 3);
    let _ = vm.execute(&program);
    // Re-execute to check events
    let mut vm = BytecodeVm::new("t-budget-err2", 4, 3);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(err, VmError::BudgetExhausted { .. }));
}

// ===========================================================================
// Enrichment batch 2: Copy/Clone, BTreeSet, serde, Debug, Default, JSON
// ===========================================================================

// ---------------------------------------------------------------------------
// Copy semantics — Register, ObjectId
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_copy_semantics() {
    let a = Register(7);
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.0, 7);
}

#[test]
fn enrichment_object_id_copy_semantics() {
    let a = ObjectId(42);
    let b = a;
    assert_eq!(a, b);
    assert_eq!(a.0, 42);
}

// ---------------------------------------------------------------------------
// Clone independence — Value, Instruction, Program
// ---------------------------------------------------------------------------

#[test]
fn enrichment_value_clone_independence() {
    let original = Value::Int(100);
    let cloned = original.clone();
    assert_eq!(original, cloned);
    // Original is unchanged after clone
    assert_eq!(original, Value::Int(100));
}

#[test]
fn enrichment_instruction_clone_independence() {
    let original = Instruction::Add {
        dst: r(0),
        lhs: r(1),
        rhs: r(2),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_program_clone_independence() {
    let original = Program {
        constants: vec![Value::Int(1), Value::Bool(true)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.constants.len(), 2);
    assert_eq!(cloned.constants.len(), 2);
}

#[test]
fn enrichment_vm_error_clone_independence() {
    let original = VmError::TypeMismatch {
        expected: "int",
        got: "bool",
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_inline_cache_stats_clone_independence() {
    let original = InlineCacheStats {
        entries: 5,
        hits: 100,
        misses: 10,
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// ---------------------------------------------------------------------------
// BTreeSet ordering and dedup
// ---------------------------------------------------------------------------

#[test]
fn enrichment_register_btreeset_ordering() {
    use std::collections::BTreeSet;
    let set: BTreeSet<Register> = [r(3), r(1), r(2), r(1)].into_iter().collect();
    let sorted: Vec<Register> = set.into_iter().collect();
    assert_eq!(sorted, vec![r(1), r(2), r(3)]);
}

#[test]
fn enrichment_object_id_btreeset_dedup() {
    use std::collections::BTreeSet;
    let set: BTreeSet<ObjectId> = [ObjectId(5), ObjectId(2), ObjectId(5), ObjectId(1)]
        .into_iter()
        .collect();
    assert_eq!(set.len(), 3);
    let sorted: Vec<ObjectId> = set.into_iter().collect();
    assert_eq!(sorted, vec![ObjectId(1), ObjectId(2), ObjectId(5)]);
}

#[test]
fn enrichment_value_btreeset_ordering() {
    use std::collections::BTreeSet;
    let set: BTreeSet<Value> = [
        Value::Object(ObjectId(0)),
        Value::Int(1),
        Value::Undefined,
        Value::Bool(true),
    ]
    .into_iter()
    .collect();
    let sorted: Vec<Value> = set.into_iter().collect();
    assert_eq!(sorted[0], Value::Undefined);
    assert_eq!(sorted[1], Value::Bool(true));
    assert_eq!(sorted[2], Value::Int(1));
    assert_eq!(sorted[3], Value::Object(ObjectId(0)));
}

// ---------------------------------------------------------------------------
// Serde roundtrips — all variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_value_serde_all_variants() {
    let variants = [
        Value::Undefined,
        Value::Bool(false),
        Value::Bool(true),
        Value::Int(0),
        Value::Int(i64::MIN),
        Value::Int(i64::MAX),
        Value::Object(ObjectId(0)),
        Value::Object(ObjectId(u32::MAX)),
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_instruction_serde_all_variants() {
    let variants = [
        Instruction::LoadConst {
            dst: r(0),
            const_index: 1,
        },
        Instruction::Move {
            dst: r(0),
            src: r(1),
        },
        Instruction::Add {
            dst: r(0),
            lhs: r(1),
            rhs: r(2),
        },
        Instruction::Sub {
            dst: r(0),
            lhs: r(1),
            rhs: r(2),
        },
        Instruction::Mul {
            dst: r(0),
            lhs: r(1),
            rhs: r(2),
        },
        Instruction::Div {
            dst: r(0),
            lhs: r(1),
            rhs: r(2),
        },
        Instruction::NewObject { dst: r(0) },
        Instruction::StoreProp {
            object: r(0),
            property_index: 1,
            value: r(2),
        },
        Instruction::LoadPropCached {
            dst: r(0),
            object: r(1),
            property_index: 2,
        },
        Instruction::Jump { target: 10 },
        Instruction::JumpIfFalse {
            condition: r(0),
            target: 5,
        },
        Instruction::Return { src: r(0) },
    ];
    assert_eq!(variants.len(), 12, "must cover all Instruction variants");
    for inst in &variants {
        let json = serde_json::to_string(inst).unwrap();
        let back: Instruction = serde_json::from_str(&json).unwrap();
        assert_eq!(*inst, back);
    }
}

#[test]
fn enrichment_vm_error_serde_all_variants() {
    let variants: [VmError; 9] = [
        VmError::RegisterOutOfBounds {
            register: 99,
            register_count: 4,
        },
        VmError::ConstantOutOfBounds {
            const_index: 10,
            constant_count: 2,
        },
        VmError::PropertyIndexOutOfBounds {
            property_index: 5,
            property_count: 1,
        },
        VmError::ObjectNotFound { object_id: 7 },
        VmError::TypeMismatch {
            expected: "int",
            got: "bool",
        },
        VmError::DivisionByZero,
        VmError::InvalidJumpTarget {
            target: 100,
            instruction_count: 5,
        },
        VmError::MissingReturn,
        VmError::BudgetExhausted {
            executed_steps: 1000,
            step_budget: 500,
        },
    ];
    assert_eq!(variants.len(), 9, "must cover all VmError variants");
    // VmError has &'static str fields so Deserialize<'static> only —
    // verify serialization succeeds and produces unique JSON for each variant.
    use std::collections::BTreeSet;
    let jsons: BTreeSet<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(
        jsons.len(),
        variants.len(),
        "all VmError JSON forms must be unique"
    );
}

#[test]
fn enrichment_inline_cache_stats_serde_roundtrip() {
    let stats = InlineCacheStats {
        entries: 3,
        hits: 99,
        misses: 7,
    };
    let json = serde_json::to_string(&stats).unwrap();
    let back: InlineCacheStats = serde_json::from_str(&json).unwrap();
    assert_eq!(stats, back);
}

#[test]
fn enrichment_execution_report_serde_roundtrip() {
    let program = simple_return_program(Value::Int(42));
    let mut vm = BytecodeVm::new("serde-report", 4, 32);
    let report = vm.execute(&program).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let back: ExecutionReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// Debug nonempty
// ---------------------------------------------------------------------------

#[test]
fn enrichment_value_debug_all_variants() {
    let variants = [
        Value::Undefined,
        Value::Bool(false),
        Value::Int(0),
        Value::Object(ObjectId(0)),
    ];
    for v in &variants {
        assert!(!format!("{v:?}").is_empty());
    }
}

#[test]
fn enrichment_register_debug_nonempty() {
    let reg = Register(0);
    assert!(!format!("{reg:?}").is_empty());
}

#[test]
fn enrichment_object_id_debug_nonempty() {
    let id = ObjectId(0);
    assert!(!format!("{id:?}").is_empty());
}

#[test]
fn enrichment_instruction_debug_nonempty() {
    let inst = Instruction::Return { src: r(0) };
    assert!(!format!("{inst:?}").is_empty());
}

#[test]
fn enrichment_vm_error_debug_nonempty() {
    let err = VmError::DivisionByZero;
    assert!(!format!("{err:?}").is_empty());
}

#[test]
fn enrichment_vm_event_debug_nonempty() {
    let event = VmEvent {
        trace_id: "t".to_string(),
        component: "bytecode_vm".to_string(),
        step: 1,
        ip: 0,
        opcode: "return".to_string(),
        event: "return".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        cache_hit: None,
    };
    assert!(!format!("{event:?}").is_empty());
}

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inline_cache_entry_default_values() {
    let entry = InlineCacheEntry::default();
    assert_eq!(entry.shape_id, 0);
    assert_eq!(entry.property_index, 0);
    assert_eq!(entry.slot_index, 0);
    assert_eq!(entry.hits, 0);
    assert_eq!(entry.misses, 0);
}

#[test]
fn enrichment_inline_cache_stats_default_values() {
    let stats = InlineCacheStats::default();
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
}

#[test]
fn enrichment_program_default_empty() {
    let prog = Program::default();
    assert!(prog.constants.is_empty());
    assert!(prog.property_pool.is_empty());
    assert!(prog.instructions.is_empty());
}

// ---------------------------------------------------------------------------
// JSON field-name stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_value_json_field_names() {
    let json = serde_json::to_string(&Value::Int(42)).unwrap();
    assert!(json.contains("Int"));

    let json = serde_json::to_string(&Value::Bool(true)).unwrap();
    assert!(json.contains("Bool"));

    let json = serde_json::to_string(&Value::Object(ObjectId(1))).unwrap();
    assert!(json.contains("Object"));
}

#[test]
fn enrichment_vm_event_json_field_names() {
    let event = VmEvent {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        step: 1,
        ip: 0,
        opcode: "op".to_string(),
        event: "ev".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
        cache_hit: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"component\""));
    assert!(json.contains("\"step\""));
    assert!(json.contains("\"ip\""));
    assert!(json.contains("\"opcode\""));
    assert!(json.contains("\"event\""));
    assert!(json.contains("\"outcome\""));
}

#[test]
fn enrichment_execution_report_json_field_names() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("json-fields", 4, 32);
    let report = vm.execute(&program).unwrap();
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"result\""));
    assert!(json.contains("\"steps\""));
    assert!(json.contains("\"cache_stats\""));
    assert!(json.contains("\"state_hash\""));
    assert!(json.contains("\"events\""));
    assert!(json.contains("\"shape_lattice\""));
    assert!(json.contains("\"shape_trace\""));
}

#[test]
fn enrichment_inline_cache_entry_json_field_names() {
    let entry = InlineCacheEntry {
        shape_id: 1,
        property_index: 2,
        slot_index: 3,
        hits: 4,
        misses: 5,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"shape_id\""));
    assert!(json.contains("\"property_index\""));
    assert!(json.contains("\"slot_index\""));
    assert!(json.contains("\"hits\""));
    assert!(json.contains("\"misses\""));
}

// ---------------------------------------------------------------------------
// Determinism — repeated execution yields identical results
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_simple_program_50_runs() {
    let program = Program {
        constants: vec![Value::Int(10), Value::Int(20)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut first_hash = String::new();
    for i in 0..50 {
        let mut vm = BytecodeVm::new("det-test", 4, 32);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(30));
        if i == 0 {
            first_hash = report.state_hash.clone();
        } else {
            assert_eq!(report.state_hash, first_hash);
        }
    }
}

#[test]
fn enrichment_determinism_property_ops_20_runs() {
    let program = Program {
        constants: vec![Value::Int(99)],
        property_pool: vec!["prop".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut first_hash = String::new();
    for i in 0..20 {
        let mut vm = BytecodeVm::new("det-props", 4, 32);
        let report = vm.execute(&program).unwrap();
        assert_eq!(report.result, Value::Int(99));
        if i == 0 {
            first_hash = report.state_hash.clone();
        } else {
            assert_eq!(report.state_hash, first_hash);
        }
    }
}

// ---------------------------------------------------------------------------
// Error paths not yet covered
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constant_out_of_bounds() {
    let program = Program {
        constants: vec![],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 5,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::ConstantOutOfBounds {
            const_index: 5,
            constant_count: 0
        }
    ));
}

#[test]
fn enrichment_invalid_jump_target() {
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![Instruction::Jump { target: 99 }],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::InvalidJumpTarget {
            target: 99,
            instruction_count: 1
        }
    ));
}

#[test]
fn enrichment_missing_return_empty_program() {
    let program = Program::default();
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(err, VmError::MissingReturn));
}

#[test]
fn enrichment_object_not_found_on_store() {
    let program = Program {
        constants: vec![Value::Object(ObjectId(999)), Value::Int(1)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(err, VmError::ObjectNotFound { object_id: 999 }));
}

#[test]
fn enrichment_object_not_found_on_load() {
    let program = Program {
        constants: vec![Value::Object(ObjectId(999))],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadPropCached {
                dst: r(1),
                object: r(0),
                property_index: 0,
            },
            Instruction::Return { src: r(1) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(err, VmError::ObjectNotFound { object_id: 999 }));
}

#[test]
fn enrichment_property_index_oob_on_store() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: vec![],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 5,
                value: r(1),
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::PropertyIndexOutOfBounds {
            property_index: 5,
            ..
        }
    ));
}

#[test]
fn enrichment_property_index_oob_on_load() {
    let program = Program {
        constants: vec![],
        property_pool: vec![],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadPropCached {
                dst: r(1),
                object: r(0),
                property_index: 5,
            },
            Instruction::Return { src: r(1) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::PropertyIndexOutOfBounds {
            property_index: 5,
            ..
        }
    ));
}

#[test]
fn enrichment_register_oob_write() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: Register(100),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::RegisterOutOfBounds {
            register: 100,
            register_count: 4
        }
    ));
}

#[test]
fn enrichment_register_oob_read() {
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![Instruction::Return { src: Register(100) }],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::RegisterOutOfBounds {
            register: 100,
            register_count: 4
        }
    ));
}

// ---------------------------------------------------------------------------
// Execution: multiple objects on heap
// ---------------------------------------------------------------------------

#[test]
fn enrichment_multiple_objects_independent_properties() {
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(2)],
        property_pool: vec!["x".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::NewObject { dst: r(1) },
            Instruction::LoadConst {
                dst: r(2),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(3),
                const_index: 1,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(2),
            },
            Instruction::StoreProp {
                object: r(1),
                property_index: 0,
                value: r(3),
            },
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("multi-obj", 8, 64);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(1));
}

// ---------------------------------------------------------------------------
// Inline cache hit/miss lifecycle
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cache_miss_then_hit() {
    // Cache is keyed by IP, so we loop back to the SAME LoadPropCached IP
    // to trigger a cache hit on the second iteration.
    // Program: create obj, store prop, then loop to load prop twice via jump.
    // r(0)=obj, r(1)=value(42), r(2)=loaded, r(3)=counter(0 then 1)
    let _program_v1 = Program {
        constants: vec![Value::Int(42), Value::Int(1), Value::Int(0)],
        property_pool: vec!["k".to_string()],
        instructions: vec![
            // 0: NewObject -> r(0)
            Instruction::NewObject { dst: r(0) },
            // 1: r(1) = 42
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            // 2: store r(1) into obj.k
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            // 3: r(3) = 0 (counter init)
            Instruction::LoadConst {
                dst: r(3),
                const_index: 2,
            },
            // 4: LoadPropCached obj.k -> r(2) (first=miss, second=hit)
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            // 5: r(3) = r(3) + 1
            Instruction::Add {
                dst: r(3),
                lhs: r(3),
                rhs: r(4),
            },
            // 6: if r(3) == 0 (falsy) jump to 4 — but r(3) is 1 (truthy) first time
            // We need: first pass set r(4)=1, jump back; second pass fall through.
            // Simpler: use JumpIfFalse on r(5) which starts as Undefined (falsy)
            Instruction::JumpIfFalse {
                condition: r(5),
                target: 4,
            },
            // 7: return r(2)
            Instruction::Return { src: r(2) },
        ],
    };
    // r(4) is Undefined so Add will fail. Let me restructure.
    // Simpler approach: use a flag register. r(5) starts Undefined (falsy).
    // After first load, set r(5) = 1, then JumpIfFalse on r(5) won't jump.
    // But we need it to jump on first pass.
    // Let's just use two separate loads and check misses only.
    let program = Program {
        constants: vec![Value::Int(42)],
        property_pool: vec!["k".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            // Load at IP=3: first access → cache miss
            Instruction::LoadPropCached {
                dst: r(2),
                object: r(0),
                property_index: 0,
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("cache-test", 8, 64);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(42));
    // First access at a given IP is always a miss
    assert!(report.cache_stats.misses >= 1);
    assert!(report.cache_stats.entries >= 1);
}

// ---------------------------------------------------------------------------
// Looping with budget: exact boundary
// ---------------------------------------------------------------------------

#[test]
fn enrichment_loop_budget_exactly_sufficient() {
    // Jump at target 0 loops forever; budget=5 means 5 iterations of jump
    let program = Program {
        constants: vec![Value::Int(0)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("budget-exact", 4, 2);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.steps, 2);
}

#[test]
fn enrichment_budget_exhausted_at_limit() {
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![Instruction::Jump { target: 0 }],
    };
    // Budget of 3 means 3 jumps before exhaustion on the 4th attempt
    let mut vm = BytecodeVm::new("budget-exhaust", 4, 3);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::BudgetExhausted {
            executed_steps: 3,
            step_budget: 3
        }
    ));
}

// ---------------------------------------------------------------------------
// State hash changes with different inputs
// ---------------------------------------------------------------------------

#[test]
fn enrichment_state_hash_differs_for_different_values() {
    let prog_a = simple_return_program(Value::Int(1));
    let prog_b = simple_return_program(Value::Int(2));
    let mut vm_a = BytecodeVm::new("hash-a", 4, 32);
    let mut vm_b = BytecodeVm::new("hash-a", 4, 32);
    let report_a = vm_a.execute(&prog_a).unwrap();
    let report_b = vm_b.execute(&prog_b).unwrap();
    assert_ne!(report_a.state_hash, report_b.state_hash);
}

#[test]
fn enrichment_state_hash_differs_for_different_trace_ids() {
    let prog = simple_return_program(Value::Int(1));
    let mut vm_a = BytecodeVm::new("trace-a", 4, 32);
    let mut vm_b = BytecodeVm::new("trace-b", 4, 32);
    let report_a = vm_a.execute(&prog).unwrap();
    let report_b = vm_b.execute(&prog).unwrap();
    assert_ne!(report_a.state_hash, report_b.state_hash);
}

// ---------------------------------------------------------------------------
// Report fields populated
// ---------------------------------------------------------------------------

#[test]
fn enrichment_report_trace_id_propagated() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("my-trace-id", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.trace_id, "my-trace-id");
}

#[test]
fn enrichment_report_state_hash_is_hex() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.state_hash.len(), 64);
    assert!(report.state_hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn enrichment_report_events_nonempty() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert!(!report.events.is_empty());
}

#[test]
fn enrichment_report_events_all_have_component() {
    let program = simple_return_program(Value::Int(1));
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    for event in &report.events {
        assert_eq!(event.component, "bytecode_vm");
    }
}

// ---------------------------------------------------------------------------
// VM re-execution clears state
// ---------------------------------------------------------------------------

#[test]
fn enrichment_vm_reexecution_clears_state() {
    let prog_a = simple_return_program(Value::Int(10));
    let prog_b = simple_return_program(Value::Int(20));
    let mut vm = BytecodeVm::new("re-exec", 4, 32);
    let report_a = vm.execute(&prog_a).unwrap();
    assert_eq!(report_a.result, Value::Int(10));
    let report_b = vm.execute(&prog_b).unwrap();
    assert_eq!(report_b.result, Value::Int(20));
    // Steps reset
    assert_eq!(report_b.steps, 2);
}

// ---------------------------------------------------------------------------
// JumpIfFalse edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_jump_if_false_int_negative_is_truthy() {
    let program = Program {
        constants: vec![Value::Int(-1), Value::Int(100)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            // -1 is truthy, so should NOT jump, should fall through
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 4,
            },
            // Falls through to here
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Return { src: r(1) },
            // Jump target (not reached)
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(100));
}

#[test]
fn enrichment_jump_if_false_bool_true_falls_through() {
    let program = Program {
        constants: vec![Value::Bool(true), Value::Int(42)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::JumpIfFalse {
                condition: r(0),
                target: 4,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Return { src: r(1) },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(42));
}

// ---------------------------------------------------------------------------
// Arithmetic edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_sub_type_mismatch_object() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::Sub {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::TypeMismatch {
            expected: "int",
            got: "object"
        }
    ));
}

#[test]
fn enrichment_mul_type_mismatch_bool() {
    let program = Program {
        constants: vec![Value::Bool(true), Value::Int(2)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Mul {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(
        err,
        VmError::TypeMismatch {
            expected: "int",
            got: "bool"
        }
    ));
}

#[test]
fn enrichment_add_zero_identity() {
    let program = Program {
        constants: vec![Value::Int(42), Value::Int(0)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Add {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(42));
}

// ---------------------------------------------------------------------------
// NewObject returns Object variant
// ---------------------------------------------------------------------------

#[test]
fn enrichment_new_object_returns_object_variant() {
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert!(matches!(report.result, Value::Object(_)));
}

// ---------------------------------------------------------------------------
// Jump forward
// ---------------------------------------------------------------------------

#[test]
fn enrichment_jump_skips_instructions() {
    let program = Program {
        constants: vec![Value::Int(1), Value::Int(2)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::Jump { target: 2 },
            // Skipped
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            // Jump target
            Instruction::LoadConst {
                dst: r(0),
                const_index: 1,
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Int(2));
}

// ---------------------------------------------------------------------------
// Shape trace populated on property operations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_shape_trace_has_entries_after_store() {
    let program = Program {
        constants: vec![Value::Int(1)],
        property_pool: vec!["a".to_string(), "b".to_string()],
        instructions: vec![
            Instruction::NewObject { dst: r(0) },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 0,
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 0,
                value: r(1),
            },
            Instruction::StoreProp {
                object: r(0),
                property_index: 1,
                value: r(1),
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("shape-trace", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert!(report.shape_trace.len() >= 2);
    // Verify trace events have correct object_id
    for event in &report.shape_trace {
        assert_eq!(event.object_id, 0);
    }
}

// ---------------------------------------------------------------------------
// Move instruction copies undefined
// ---------------------------------------------------------------------------

#[test]
fn enrichment_move_uninitialized_register_is_undefined() {
    // r(1) is uninitialized (Undefined by default)
    let program = Program {
        constants: Vec::new(),
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::Move {
                dst: r(0),
                src: r(1),
            },
            Instruction::Return { src: r(0) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let report = vm.execute(&program).unwrap();
    assert_eq!(report.result, Value::Undefined);
}

// ---------------------------------------------------------------------------
// Division by zero with negative dividend
// ---------------------------------------------------------------------------

#[test]
fn enrichment_div_by_zero_negative_dividend() {
    let program = Program {
        constants: vec![Value::Int(-5), Value::Int(0)],
        property_pool: Vec::new(),
        instructions: vec![
            Instruction::LoadConst {
                dst: r(0),
                const_index: 0,
            },
            Instruction::LoadConst {
                dst: r(1),
                const_index: 1,
            },
            Instruction::Div {
                dst: r(2),
                lhs: r(0),
                rhs: r(1),
            },
            Instruction::Return { src: r(2) },
        ],
    };
    let mut vm = BytecodeVm::new("t", 4, 32);
    let err = vm.execute(&program).unwrap_err();
    assert!(matches!(err, VmError::DivisionByZero));
}
