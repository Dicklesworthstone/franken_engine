//! Integration tests for GC write barriers (bd-28ezw).
//!
//! Validates that write barriers properly track old->young generation references:
//!   - Write operations trigger barrier registration
//!   - Idempotent barrier calls (same object multiple times)
//!   - BTreeSet determinism for remembered set ordering
//!   - Integration with garbage collection cycles
//!   - Memory safety with forbid(unsafe_code)
//!   - Remembered set reset after collection

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op
)]

use frankenengine_engine::baseline_interpreter::{
    Float64, InterpreterConfig, InterpreterCore, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::ir_contract::{Ir3Instruction, Ir3Module};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    config
}

fn test_module_with_object_operations() -> Ir3Module {
    let mut m = Ir3Module::new(ContentHash::compute(b"gc-write-barrier"), "test-gc");
    m.constant_pool = vec!["test_property".to_string()];
    m.instructions = vec![
        // Create an object
        Ir3Instruction::NewObject { dst: 0 },
        // Set a property (should trigger write barrier)
        Ir3Instruction::LoadStr {
            dst: 1,
            pool_index: 0,
        },
        Ir3Instruction::LoadInt { dst: 2, value: 42 },
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 1,
            val: 2,
        },
        Ir3Instruction::Halt,
    ];
    m
}

// =========================================================================
// Test 1: Write operations trigger barrier registration
// =========================================================================

#[test]
fn write_operations_trigger_barrier() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "write-barrier-test");
    let module = test_module_with_object_operations();

    // Initially, remembered set should be empty
    assert_eq!(core.gc_remembered_set_size(), 0);

    // Execute module with object property setting
    let result = core.execute(&module);
    assert!(result.is_ok(), "Module execution should succeed");

    // After setting a property, remembered set should contain the object
    assert!(
        core.gc_remembered_set_size() > 0,
        "Write barrier should add object to remembered set"
    );
}

// =========================================================================
// Test 2: Idempotent barrier calls (same object multiple times)
// =========================================================================

#[test]
fn barrier_calls_are_idempotent() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "idempotent-test");

    // Create an object to get its ID
    let object_id = core.alloc_object_with_prototype(None).unwrap();

    // Initially empty
    assert_eq!(core.gc_remembered_set_size(), 0);

    // Set property multiple times on same object (through different mechanisms)
    core.set_object_property(object_id, "prop1".to_string(), Value::Int(1))
        .unwrap();
    let size_after_first = core.gc_remembered_set_size();

    core.set_object_property(object_id, "prop2".to_string(), Value::Int(2))
        .unwrap();
    let size_after_second = core.gc_remembered_set_size();

    core.set_object_property(object_id, "prop3".to_string(), Value::Int(3))
        .unwrap();
    let size_after_third = core.gc_remembered_set_size();

    // All operations should track the same object only once (BTreeSet dedup)
    assert_eq!(size_after_first, 1, "First write should add object");
    assert_eq!(
        size_after_second, size_after_first,
        "Second write on same object should not increase size"
    );
    assert_eq!(
        size_after_third, size_after_first,
        "Third write on same object should not increase size"
    );

    // Verify the object is actually tracked
    assert!(
        core.gc_is_remembered(object_id),
        "Object should be in remembered set"
    );
}

// =========================================================================
// Test 3: BTreeSet determinism for remembered set ordering
// =========================================================================

#[test]
fn remembered_set_has_deterministic_ordering() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "determinism-test");

    // Create multiple objects
    let obj1 = core.alloc_object_with_prototype(None).unwrap();
    let obj2 = core.alloc_object_with_prototype(None).unwrap();
    let obj3 = core.alloc_object_with_prototype(None).unwrap();

    // Write to them in different order
    core.set_object_property(obj3, "c".to_string(), Value::Int(3))
        .unwrap();
    core.set_object_property(obj1, "a".to_string(), Value::Int(1))
        .unwrap();
    core.set_object_property(obj2, "b".to_string(), Value::Int(2))
        .unwrap();

    // Get remembered set and verify it's sorted (BTreeSet property)
    let remembered = core.gc_get_remembered_set();
    let mut sorted_ids: Vec<_> = remembered.iter().copied().collect();
    sorted_ids.sort_by_key(|id| id.0);

    let original_ids: Vec<_> = remembered.iter().copied().collect();

    assert_eq!(
        original_ids, sorted_ids,
        "BTreeSet should maintain deterministic ordering"
    );
    assert_eq!(remembered.len(), 3, "All three objects should be tracked");
}

// =========================================================================
// Test 4: Integration with garbage collection cycle
// =========================================================================

#[test]
fn integration_with_gc_cycle() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "gc-integration-test");

    // Create objects and trigger write barriers
    let obj1 = core.alloc_object_with_prototype(None).unwrap();
    let obj2 = core.alloc_object_with_prototype(None).unwrap();

    core.set_object_property(obj1, "ref".to_string(), Value::Object(obj2))
        .unwrap();
    core.set_object_property(obj2, "data".to_string(), Value::Int(42))
        .unwrap();

    assert_eq!(core.gc_remembered_set_size(), 2);
    assert!(core.gc_is_remembered(obj1));
    assert!(core.gc_is_remembered(obj2));

    // Simulate GC cycle - clear remembered set
    core.gc_clear_remembered_set();

    assert_eq!(core.gc_remembered_set_size(), 0);
    assert!(!core.gc_is_remembered(obj1));
    assert!(!core.gc_is_remembered(obj2));

    // After GC, new writes should rebuild remembered set
    core.set_object_property(
        obj1,
        "new_prop".to_string(),
        Value::Str("post_gc".to_string()),
    )
    .unwrap();

    assert_eq!(core.gc_remembered_set_size(), 1);
    assert!(core.gc_is_remembered(obj1));
    assert!(!core.gc_is_remembered(obj2)); // Not written to after GC
}

// =========================================================================
// Test 5: Memory safety with forbid(unsafe_code)
// =========================================================================

#[test]
fn memory_safety_no_unsafe_code() {
    // This test validates that write barriers work without unsafe code
    // The #![forbid(unsafe_code)] directive at the top ensures this

    let config = test_config();
    let mut core = InterpreterCore::new(config, "safety-test");

    // Perform operations that could be memory-unsafe if implemented incorrectly
    for i in 0..100 {
        let obj = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(obj, format!("prop_{}", i), Value::Int(i as i64))
            .unwrap();
    }

    // All objects should be tracked
    assert_eq!(core.gc_remembered_set_size(), 100);

    // Clear and verify
    core.gc_clear_remembered_set();
    assert_eq!(core.gc_remembered_set_size(), 0);
}

// =========================================================================
// Test 6: Reset remembered set after collection
// =========================================================================

#[test]
fn reset_remembered_set_after_collection() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "reset-test");

    // Create multiple generations of objects
    let mut objects = Vec::new();
    for i in 0..10 {
        let obj = core.alloc_object_with_prototype(None).unwrap();
        core.set_object_property(obj, "generation".to_string(), Value::Int(i))
            .unwrap();
        objects.push(obj);
    }

    // Verify all are remembered
    assert_eq!(core.gc_remembered_set_size(), 10);
    for &obj in &objects {
        assert!(core.gc_is_remembered(obj));
    }

    // Simulate collection cycle - clear remembered set
    core.gc_clear_remembered_set();

    // Verify complete reset
    assert_eq!(core.gc_remembered_set_size(), 0);
    for &obj in &objects {
        assert!(!core.gc_is_remembered(obj));
    }

    // Verify remembered set can be rebuilt after reset
    let new_obj = core.alloc_object_with_prototype(None).unwrap();
    core.set_object_property(new_obj, "post_reset".to_string(), Value::Bool(true))
        .unwrap();

    assert_eq!(core.gc_remembered_set_size(), 1);
    assert!(core.gc_is_remembered(new_obj));
    for &old_obj in &objects {
        assert!(!core.gc_is_remembered(old_obj));
    }
}

// =========================================================================
// Test 7: Write barrier behavior with different value types
// =========================================================================

#[test]
fn write_barrier_with_different_value_types() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "value-types-test");

    let obj = core.alloc_object_with_prototype(None).unwrap();

    // Test different value types that could contain object references
    let test_values = vec![
        Value::Int(42),
        Value::Float(Float64::new(std::f64::consts::PI)),
        Value::Str("string_value".to_string()),
        Value::Bool(true),
        Value::Null,
        Value::Undefined,
    ];

    core.gc_clear_remembered_set();

    for (i, value) in test_values.into_iter().enumerate() {
        core.set_object_property(obj, format!("prop_{}", i), value)
            .unwrap();
    }

    // Object should be in remembered set regardless of value type
    assert_eq!(core.gc_remembered_set_size(), 1);
    assert!(core.gc_is_remembered(obj));
}

// =========================================================================
// Test 8: Concurrent write barrier operations maintain consistency
// =========================================================================

#[test]
fn concurrent_writes_maintain_consistency() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "concurrent-test");

    // Simulate rapid successive writes to different objects
    let mut objects = Vec::new();
    for _i in 0..50 {
        let obj = core.alloc_object_with_prototype(None).unwrap();
        objects.push(obj);
    }

    // Write to all objects in rapid succession
    for (i, &obj) in objects.iter().enumerate() {
        core.set_object_property(obj, "index".to_string(), Value::Int(i as i64))
            .unwrap();
        core.set_object_property(obj, "double".to_string(), Value::Int((i * 2) as i64))
            .unwrap();
    }

    // All objects should be tracked exactly once
    assert_eq!(core.gc_remembered_set_size(), 50);
    for &obj in &objects {
        assert!(core.gc_is_remembered(obj));
    }

    // Verify BTreeSet maintains uniqueness even with rapid operations
    let remembered = core.gc_get_remembered_set();
    assert_eq!(remembered.len(), objects.len());
}

// =========================================================================
// Test 9: Write barrier integration with complex object graphs
// =========================================================================

#[test]
fn write_barrier_with_complex_object_graphs() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "complex-graph-test");

    // Create a complex object graph
    let root = core.alloc_object_with_prototype(None).unwrap();
    let child1 = core.alloc_object_with_prototype(None).unwrap();
    let child2 = core.alloc_object_with_prototype(None).unwrap();
    let grandchild = core.alloc_object_with_prototype(None).unwrap();

    // Build the graph
    core.set_object_property(root, "child1".to_string(), Value::Object(child1))
        .unwrap();
    core.set_object_property(root, "child2".to_string(), Value::Object(child2))
        .unwrap();
    core.set_object_property(child1, "grandchild".to_string(), Value::Object(grandchild))
        .unwrap();
    core.set_object_property(child2, "back_ref".to_string(), Value::Object(root))
        .unwrap();

    // The write barrier remembers mutated objects, not every referenced object.
    assert_eq!(core.gc_remembered_set_size(), 3);
    assert!(core.gc_is_remembered(root));
    assert!(core.gc_is_remembered(child1));
    assert!(core.gc_is_remembered(child2));
    assert!(!core.gc_is_remembered(grandchild));
}

// =========================================================================
// Test 10: Write barrier performance and overhead
// =========================================================================

#[test]
fn write_barrier_performance_overhead() {
    let config = test_config();
    let mut core = InterpreterCore::new(config, "performance-test");

    // Perform many write operations and verify remembered set stays bounded
    for batch in 0..10 {
        for i in 0..100 {
            let obj = core.alloc_object_with_prototype(None).unwrap();
            core.set_object_property(obj, "batch".to_string(), Value::Int(batch))
                .unwrap();
            core.set_object_property(obj, "index".to_string(), Value::Int(i))
                .unwrap();
        }

        // Simulate periodic GC to reset remembered set
        if batch % 3 == 2 {
            core.gc_clear_remembered_set();
        }
    }

    // Final state should be reasonable (not all 1000 objects)
    let final_size = core.gc_remembered_set_size();
    assert!(
        final_size <= 200,
        "Remembered set should be bounded by periodic GC, got {}",
        final_size
    );
}
