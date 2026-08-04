//! bd-qsz8t regression — u32 overflow in the array sparse-length folds.
//!
//! The property key `"4294967295"` parses to `u32::MAX`. Two sparse-length scan
//! folds in `baseline_interpreter.rs` (the `Ir3Instruction::ArrayPush` sparse
//! fallback and the `SpreadIntoArray` next-index computation) computed the next
//! dense index with an unguarded `n + 1` on the parsed `u32`. For the key
//! `"4294967295"` that is `u32::MAX + 1`, which **panics in debug builds**
//! (a reachable DoS on adversarial input — `cargo test` is a debug build) and
//! **wraps to 0 in release** (silent array corruption / wrong push index).
//!
//! The fix mirrors the engine's `canonical_array_index_property` convention by
//! excluding `u32::MAX` from the fold (`.filter(|&n| n != u32::MAX)`), so `n + 1`
//! can never overflow; the spread loop's `next_idx` increment is also saturated.
//!
//! This mirrors the verified franken-core regression
//! (`array_push_does_not_overflow_on_u32_max_index_key`, commit 54db7797): it
//! drives the interpreter at the IR3 level so the array stays in the sparse
//! representation that takes the fold, rather than the dense fast path a
//! source-level `a[k]=v` assignment uses.

use std::collections::BTreeSet;

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    Ir3Instruction, Ir3Module, IrHeader, IrLevel, IrSchemaVersion,
};

fn test_module_with_pool(instructions: Vec<Ir3Instruction>, pool: Vec<String>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "bd-qsz8t".to_string(),
        },
        instructions,
        constant_pool: pool.into_iter().map(Into::into).collect(),
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
    }
}

fn baseline_test_interpreter() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    InterpreterCore::new(config, "bd-qsz8t-trace")
}

#[test]
fn array_push_does_not_overflow_on_u32_max_index_key() {
    // Build: a = []; a["4294967295"] = 1; a.push(42); return a;
    // The `SetProperty` keeps the array sparse, so `ArrayPush` takes the
    // sparse-length fold. The fold parses "4294967295" to u32::MAX and, before
    // the fix, evaluated `u32::MAX + 1` — a debug-build overflow panic. The
    // load-bearing assertion is simply that `execute` returns instead of
    // panicking.
    let module = test_module_with_pool(
        vec![
            Ir3Instruction::NewArray { dst: 1 },
            Ir3Instruction::LoadStr {
                dst: 3,
                pool_index: 0,
            },
            Ir3Instruction::LoadInt { dst: 4, value: 1 },
            Ir3Instruction::SetProperty {
                obj: 1,
                key: 3,
                val: 4,
            },
            Ir3Instruction::LoadInt { dst: 2, value: 42 },
            Ir3Instruction::ArrayPush {
                array: 1,
                element: 2,
            },
            Ir3Instruction::Move { dst: 0, src: 1 },
            Ir3Instruction::Halt,
        ],
        vec!["4294967295".to_string()],
    );

    let mut core = baseline_test_interpreter();
    let result = core
        .execute(&module)
        .expect("array push must not overflow on a u32::MAX index key");

    // The push completed and yielded the array back (the heap field is private,
    // so the no-panic return plus an object result is the observable contract).
    assert!(
        matches!(result.value, Value::Object(_)),
        "expected the array object as the result, got {:?}",
        result.value
    );
}
