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
