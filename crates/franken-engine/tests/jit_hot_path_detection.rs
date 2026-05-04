//! Integration tests for the JIT hot-path counters.
//!
//! These tests intentionally exercise the current `Ir3Module` and
//! `InterpreterCore::execute` APIs instead of the removed pre-IR3 `Module`
//! harness. The assertions cover function-call counting, loop backedge
//! counting, threshold semantics, deterministic statistics, eviction counters,
//! and counter reset behavior.

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{
    Ir3FunctionDesc, Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};

const LOOP_BACKEDGE_IP: usize = 5;

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn test_interpreter(trace_id: &str) -> InterpreterCore {
    InterpreterCore::new(test_config(), trace_id)
}

fn test_module(
    source_label: &str,
    instructions: Vec<Ir3Instruction>,
    function_table: Vec<Ir3FunctionDesc>,
) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: Some(ContentHash::compute(source_label.as_bytes())),
            source_label: source_label.to_string(),
        },
        instructions,
        constant_pool: Vec::new(),
        function_table,
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn function_desc(entry: u32, name: &str) -> Ir3FunctionDesc {
    Ir3FunctionDesc {
        entry,
        arity: 0,
        frame_size: 2,
        name: Some(name.to_string()),
        is_generator: false,
    }
}

fn one_call_module() -> Ir3Module {
    test_module(
        "jit-one-call",
        vec![
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 4, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 0, value: 42 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![function_desc(4, "callee")],
    )
}

fn multi_call_module() -> Ir3Module {
    test_module(
        "jit-multi-call",
        vec![
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 4, count: 0 },
                dst: 1,
            },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 1,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 4, count: 0 },
                dst: 1,
            },
            Ir3Instruction::CreateClosure {
                dst: 0,
                function_index: 0,
                capture_count: 0,
            },
            Ir3Instruction::Call {
                callee: 0,
                args: RegRange { start: 4, count: 0 },
                dst: 1,
            },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
            Ir3Instruction::LoadInt { dst: 0, value: 1 },
            Ir3Instruction::Return { value: 0 },
            Ir3Instruction::LoadInt { dst: 0, value: 2 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec![function_desc(8, "func1"), function_desc(10, "func2")],
    )
}

fn loop_module(loop_bound: i64) -> Ir3Module {
    loop_module_with_padding("jit-loop", 0, loop_bound).0
}

fn loop_module_with_padding(
    source_label: &str,
    padding_instructions: usize,
    loop_bound: i64,
) -> (Ir3Module, usize) {
    let mut instructions = Vec::new();
    for index in 0..padding_instructions {
        instructions.push(Ir3Instruction::LoadInt {
            dst: 7,
            value: index as i64,
        });
    }

    let loop_start = instructions.len() + 3;
    instructions.extend([
        Ir3Instruction::LoadInt { dst: 0, value: 0 },
        Ir3Instruction::LoadInt {
            dst: 1,
            value: loop_bound,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 1 },
        Ir3Instruction::Add {
            dst: 0,
            lhs: 0,
            rhs: 2,
        },
        Ir3Instruction::Lt {
            dst: 3,
            lhs: 0,
            rhs: 1,
        },
        Ir3Instruction::JumpIf {
            cond: 3,
            target: loop_start as u32,
        },
        Ir3Instruction::Halt,
    ]);

    let backedge_ip = loop_start + 2;
    (
        test_module(source_label, instructions, Vec::new()),
        backedge_ip,
    )
}

#[test]
fn jit_function_call_counter_increments_through_ir3_calls() {
    let mut interpreter = test_interpreter("jit-function-counter");
    let module = one_call_module();

    assert_eq!(interpreter.jit_get_function_call_count(0), 0);

    let result = interpreter
        .execute(&module)
        .expect("first call should execute");
    assert_eq!(result.value, Value::Int(42));
    assert_eq!(interpreter.jit_get_function_call_count(0), 1);

    interpreter
        .execute(&module)
        .expect("second call should execute");
    assert_eq!(interpreter.jit_get_function_call_count(0), 2);
}

#[test]
fn jit_loop_iteration_counter_records_taken_backedges() {
    let mut interpreter = test_interpreter("jit-loop-counter");
    let module = loop_module(6);

    assert_eq!(
        interpreter.jit_get_loop_iteration_count(LOOP_BACKEDGE_IP),
        0
    );

    let result = interpreter.execute(&module).expect("loop should execute");
    assert_eq!(result.value, Value::Int(6));
    assert_eq!(
        interpreter.jit_get_loop_iteration_count(LOOP_BACKEDGE_IP),
        5
    );
}

#[test]
fn jit_threshold_marks_functions_hot_at_threshold() {
    let mut interpreter = test_interpreter("jit-threshold-function");
    interpreter.jit_set_hot_threshold(3);
    let module = one_call_module();

    for expected_count in 1..=3 {
        interpreter
            .execute(&module)
            .expect("function call should execute");
        assert_eq!(interpreter.jit_get_function_call_count(0), expected_count);
    }

    assert!(interpreter.jit_is_function_hot(0));
    assert_eq!(interpreter.jit_get_hot_threshold(), 3);
}

#[test]
fn jit_threshold_marks_loops_hot_at_threshold() {
    let mut interpreter = test_interpreter("jit-threshold-loop");
    interpreter.jit_set_hot_threshold(3);
    let module = loop_module(4);

    interpreter.execute(&module).expect("loop should execute");

    assert_eq!(
        interpreter.jit_get_loop_iteration_count(LOOP_BACKEDGE_IP),
        3
    );
    assert!(interpreter.jit_is_loop_hot(LOOP_BACKEDGE_IP));
}

#[test]
fn jit_multi_function_counters_remain_disjoint() {
    let mut interpreter = test_interpreter("jit-multi-function");
    let module = multi_call_module();

    interpreter
        .execute(&module)
        .expect("multi-function module should execute");

    assert_eq!(interpreter.jit_get_function_call_count(0), 2);
    assert_eq!(interpreter.jit_get_function_call_count(1), 1);
}

#[test]
fn jit_statistics_are_deterministic_for_identical_execution_sequences() {
    let mut interpreter1 = test_interpreter("jit-determinism-a");
    let mut interpreter2 = test_interpreter("jit-determinism-b");
    let module = one_call_module();

    for _ in 0..5 {
        let result1 = interpreter1
            .execute(&module)
            .expect("first interpreter should execute");
        let result2 = interpreter2
            .execute(&module)
            .expect("second interpreter should execute");
        assert_eq!(result1.value, result2.value);
    }

    assert_eq!(
        interpreter1.jit_get_statistics(),
        interpreter2.jit_get_statistics()
    );
}

#[test]
fn jit_threshold_config_clamps_and_is_respected() {
    let mut interpreter = test_interpreter("jit-threshold-config");
    assert_eq!(interpreter.jit_get_hot_threshold(), 10_000);

    interpreter.jit_set_hot_threshold(0);
    assert_eq!(interpreter.jit_get_hot_threshold(), 1);

    interpreter.jit_set_hot_threshold(4);
    assert_eq!(interpreter.jit_get_hot_threshold(), 4);
}

#[test]
fn jit_eviction_counter_advances_and_eventually_evicts_cold_counts() {
    let mut interpreter = test_interpreter("jit-eviction");
    let module = one_call_module();

    for _ in 0..5 {
        interpreter
            .execute(&module)
            .expect("function call should execute");
    }
    assert_eq!(interpreter.jit_get_function_call_count(0), 5);

    for _ in 0..50_000 {
        interpreter.jit_evict_cold_functions();
    }

    let stats = interpreter.jit_get_statistics();
    assert_eq!(stats.eviction_counter(), 50_000);
    assert_eq!(stats.function_counts_len(), 0);
    assert_eq!(interpreter.jit_get_function_call_count(0), 0);
}

#[test]
fn jit_statistics_track_function_and_loop_surfaces() {
    let mut interpreter = test_interpreter("jit-statistics");
    let call_module = one_call_module();
    let loop_module = loop_module(4);

    for _ in 0..5 {
        interpreter
            .execute(&call_module)
            .expect("function call should execute");
    }
    interpreter
        .execute(&loop_module)
        .expect("loop should execute");

    let stats = interpreter.jit_get_statistics();
    assert_eq!(stats.function_counts_len(), 1);
    assert_eq!(stats.loop_counts_len(), 1);
    assert_eq!(stats.total_function_calls(), 5);
    assert_eq!(
        interpreter.jit_get_loop_iteration_count(LOOP_BACKEDGE_IP),
        3
    );
}

#[test]
fn jit_loop_iteration_counters_track_many_distinct_backedges() {
    let mut interpreter = test_interpreter("jit-many-loop-sites");

    for padding in 0..=12 {
        let (module, backedge_ip) =
            loop_module_with_padding(&format!("jit-loop-site-{padding}"), padding, 3);
        let result = interpreter
            .execute(&module)
            .expect("padded loop should execute");
        assert_eq!(result.value, Value::Int(3));
        assert_eq!(interpreter.jit_get_loop_iteration_count(backedge_ip), 2);
    }

    assert_eq!(interpreter.jit_get_statistics().loop_counts_len(), 13);
}

#[test]
fn jit_eviction_removes_cold_loop_counts_after_many_loop_sites() {
    let mut interpreter = test_interpreter("jit-loop-eviction-many-sites");

    for padding in 0..=12 {
        let (module, backedge_ip) =
            loop_module_with_padding(&format!("jit-loop-evict-{padding}"), padding, 4);
        interpreter
            .execute(&module)
            .expect("padded loop should execute before eviction");
        assert_eq!(interpreter.jit_get_loop_iteration_count(backedge_ip), 3);
    }
    assert_eq!(interpreter.jit_get_statistics().loop_counts_len(), 13);

    for _ in 0..50_000 {
        interpreter.jit_evict_cold_functions();
    }

    assert_eq!(interpreter.jit_get_statistics().loop_counts_len(), 0);
    for padding in 0..=12 {
        let (_, backedge_ip) = loop_module_with_padding("jit-loop-evict-check", padding, 4);
        assert_eq!(interpreter.jit_get_loop_iteration_count(backedge_ip), 0);
    }
}

#[test]
fn jit_clear_counters_resets_observable_statistics() {
    let mut interpreter = test_interpreter("jit-clear");
    let module = one_call_module();

    for _ in 0..3 {
        interpreter
            .execute(&module)
            .expect("function call should execute");
    }
    assert!(interpreter.jit_get_statistics().total_function_calls() > 0);

    interpreter.jit_clear_counters();

    let stats = interpreter.jit_get_statistics();
    assert_eq!(interpreter.jit_get_function_call_count(0), 0);
    assert_eq!(stats.function_counts_len(), 0);
    assert_eq!(stats.loop_counts_len(), 0);
    assert_eq!(stats.eviction_counter(), 0);
}

#[test]
fn jit_missing_counters_read_as_zero() {
    let interpreter = test_interpreter("jit-edge-cases");

    assert_eq!(interpreter.jit_get_function_call_count(999), 0);
    assert_eq!(interpreter.jit_get_loop_iteration_count(999), 0);

    let stats = interpreter.jit_get_statistics();
    assert_eq!(stats.function_counts_len(), 0);
    assert_eq!(stats.loop_counts_len(), 0);
    assert_eq!(stats.eviction_counter(), 0);
}
