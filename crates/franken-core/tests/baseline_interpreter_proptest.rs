//! Property tests for baseline interpreter execution seed consistency.
//!
//! Validates that lazy-seed implementation and eager baseline implementation
//! produce byte-identical interpreter state at every reset point.

use proptest::prelude::*;
use proptest::collection::vec;

use frankenengine_core::baseline_interpreter::{InterpreterCore, ExecutionSeed, EagerExecutionSeed, Value};

#[derive(Debug, Clone)]
enum Op {
    WriteRegister(u8, Value),
    WriteHeapSlot(u32, Value),
    Capture,
    Reset(usize),   // index into the live seed list
}

fn arbitrary_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Undefined),
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|n| Value::Int(n as i64)),
        ".*".prop_map(Value::Str),
    ]
}

fn arbitrary_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0..32u8, arbitrary_value()).prop_map(|(r, v)| Op::WriteRegister(r, v)),
        (0..16u32, arbitrary_value()).prop_map(|(s, v)| Op::WriteHeapSlot(s, v)),
        Just(Op::Capture),
        (0..4usize).prop_map(Op::Reset),
    ]
}


proptest! {
    #[test]
    fn lazy_seed_observation_equivalent_to_eager(
        ops in vec(arbitrary_op(), 0..256)
    ) {
        // Build two interpreters with identical initial state.
        let mut lazy = InterpreterCore::new_for_proptest();
        let mut eager = InterpreterCore::new_for_proptest_eager_seeds();
        let mut lazy_seeds: Vec<ExecutionSeed> = Vec::new();
        let mut eager_seeds: Vec<EagerExecutionSeed> = Vec::new();

        for op in &ops {
            match op {
                Op::WriteRegister(r, v) => {
                    lazy.write_register(*r as usize, v.clone());
                    eager.write_register(*r as usize, v.clone());
                }
                Op::WriteHeapSlot(s, v) => {
                    lazy.write_heap_slot(*s, v.clone());
                    eager.write_heap_slot(*s, v.clone());
                }
                Op::Capture => {
                    lazy_seeds.push(lazy.capture_execution_seed());
                    eager_seeds.push(eager.capture_execution_seed_eager_for_test());
                }
                Op::Reset(i) => {
                    if !lazy_seeds.is_empty() {
                        let idx = i % lazy_seeds.len();
                        lazy.reset_execution_state_from_seed(&lazy_seeds[idx]);
                        eager.reset_execution_state_from_seed_eager_for_test(&eager_seeds[idx]);
                    }
                }
            }

            // After every op, both interpreters must have byte-equal state.
            prop_assert_eq!(lazy.get_registers(), eager.get_registers());
            prop_assert_eq!(lazy.get_heap(), eager.get_heap());
        }
    }
}