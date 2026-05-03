//! Tests for Information Flow Control (IFC) label propagation.
//!
//! This test module verifies that IFC labels properly propagate through
//! arithmetic, comparison, and logical operations according to the security lattice:
//! Public < Internal < Confidential < Secret < TopSecret
//!
//! Key security properties tested:
//! 1. Binary operations join labels (take the higher confidentiality level)
//! 2. Unary operations preserve source label
//! 3. Move operations preserve source label
//! 4. High-confidentiality values correctly taint low-confidentiality computations

use frankenengine::baseline_interpreter::{CoreInterpreter, InterpreterConfig, InterpreterError};
use frankenengine::ir_contract::Ir3Instruction;
use frankenengine::ifc_artifacts::Label;

/// Create a test interpreter with default configuration.
fn test_interpreter() -> CoreInterpreter {
    let config = InterpreterConfig::test_default();
    CoreInterpreter::new(config)
}

/// Helper to set a register's IFC label directly (for testing).
fn set_label(core: &mut CoreInterpreter, reg: u32, label: Label) {
    core.set_register_label(reg, label).unwrap();
}

/// Helper to get a register's IFC label directly (for testing).
fn get_label(core: &CoreInterpreter, reg: u32) -> Label {
    core.get_register_label(reg).unwrap().clone()
}

#[test]
fn test_binary_arithmetic_label_propagation() {
    let mut core = test_interpreter();

    // Setup: put different values with different labels
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(10)).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Int(20)).unwrap();
    set_label(&mut core, 0, Label::Public);
    set_label(&mut core, 1, Label::Confidential);

    // Test Add operation - should join labels (Public ∨ Confidential = Confidential)
    let result = core.eval_add(0, 1).unwrap();
    core.write_reg(2, result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();

    assert_eq!(get_label(&core, 2), Label::Confidential);
}

#[test]
fn test_arithmetic_operations_label_join() {
    let mut core = test_interpreter();

    // Test all arithmetic operations with Secret ⊔ Internal = Secret
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(15)).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Int(3)).unwrap();
    set_label(&mut core, 0, Label::Secret);
    set_label(&mut core, 1, Label::Internal);

    // Addition
    let add_result = core.eval_add(0, 1).unwrap();
    core.write_reg(2, add_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();
    assert_eq!(get_label(&core, 2), Label::Secret);

    // Subtraction
    let sub_result = core.eval_arith(0, 1, "sub").unwrap();
    core.write_reg(3, sub_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 3).unwrap();
    assert_eq!(get_label(&core, 3), Label::Secret);

    // Multiplication
    let mul_result = core.eval_arith(0, 1, "mul").unwrap();
    core.write_reg(4, mul_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 4).unwrap();
    assert_eq!(get_label(&core, 4), Label::Secret);

    // Division
    let div_result = core.eval_div(0, 1).unwrap();
    core.write_reg(5, div_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 5).unwrap();
    assert_eq!(get_label(&core, 5), Label::Secret);
}

#[test]
fn test_comparison_operations_label_propagation() {
    let mut core = test_interpreter();

    // Setup values with TopSecret and Public labels
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(42)).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Int(42)).unwrap();
    set_label(&mut core, 0, Label::TopSecret);
    set_label(&mut core, 1, Label::Public);

    // Test equality comparison - should result in TopSecret label
    let eq_result = core.eval_equality(0, 1, false, false).unwrap();
    core.write_reg(2, eq_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();
    assert_eq!(get_label(&core, 2), Label::TopSecret);

    // Test relational comparison
    let lt_result = core.eval_relational(0, 1, "<").unwrap();
    core.write_reg(3, lt_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 3).unwrap();
    assert_eq!(get_label(&core, 3), Label::TopSecret);
}

#[test]
fn test_unary_operations_label_preservation() {
    let mut core = test_interpreter();

    // Setup a value with Internal label
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(-10)).unwrap();
    set_label(&mut core, 0, Label::Internal);

    // Test unary negation - should preserve label
    let neg_result = core.eval_unary_neg(0).unwrap();
    core.write_reg(1, neg_result).unwrap();
    core.propagate_unary_operation_label(0, 1).unwrap();
    assert_eq!(get_label(&core, 1), Label::Internal);

    // Test unary plus - should preserve label
    let plus_result = core.eval_unary_plus(0).unwrap();
    core.write_reg(2, plus_result).unwrap();
    core.propagate_unary_operation_label(0, 2).unwrap();
    assert_eq!(get_label(&core, 2), Label::Internal);
}

#[test]
fn test_logical_operations_label_propagation() {
    let mut core = test_interpreter();

    // Setup boolean values with different labels
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Bool(true)).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Bool(false)).unwrap();
    set_label(&mut core, 0, Label::Confidential);
    set_label(&mut core, 1, Label::Secret);

    // Test bitwise AND - should join to Secret
    let and_result = core.eval_bitwise(0, 1, "&").unwrap();
    core.write_reg(2, and_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();
    assert_eq!(get_label(&core, 2), Label::Secret);

    // Test bitwise OR - should join to Secret
    let or_result = core.eval_bitwise(0, 1, "|").unwrap();
    core.write_reg(3, or_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 3).unwrap();
    assert_eq!(get_label(&core, 3), Label::Secret);

    // Test logical NOT on first value - should preserve Confidential
    core.write_reg(4, frankenengine::baseline_interpreter::Value::Bool(!core.read_reg(0).unwrap().is_truthy())).unwrap();
    core.propagate_unary_operation_label(0, 4).unwrap();
    assert_eq!(get_label(&core, 4), Label::Confidential);
}

#[test]
fn test_move_operation_label_propagation() {
    let mut core = test_interpreter();

    // Setup a value with Secret label
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Str("sensitive".to_string())).unwrap();
    set_label(&mut core, 0, Label::Secret);

    // Move value to another register - should preserve label
    let val = core.read_reg(0).unwrap();
    core.write_reg(1, val).unwrap();
    core.propagate_unary_operation_label(0, 1).unwrap();

    assert_eq!(get_label(&core, 1), Label::Secret);
}

#[test]
fn test_typeof_and_void_operations_label_propagation() {
    let mut core = test_interpreter();

    // Setup a value with Internal label
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(123)).unwrap();
    set_label(&mut core, 0, Label::Internal);

    // Test typeof operation - should preserve label
    let val = core.read_reg(0).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Str(val.typeof_name().to_string())).unwrap();
    core.propagate_unary_operation_label(0, 1).unwrap();
    assert_eq!(get_label(&core, 1), Label::Internal);

    // Test void operation - should preserve label
    core.write_reg(2, frankenengine::baseline_interpreter::Value::Undefined).unwrap();
    core.propagate_unary_operation_label(0, 2).unwrap();
    assert_eq!(get_label(&core, 2), Label::Internal);
}

#[test]
fn test_bitwise_operations_label_propagation() {
    let mut core = test_interpreter();

    // Setup integer values with different labels
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(0b1010)).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Int(0b1100)).unwrap();
    set_label(&mut core, 0, Label::Public);
    set_label(&mut core, 1, Label::TopSecret);

    // Test XOR - should join to TopSecret
    let xor_result = core.eval_bitwise(0, 1, "^").unwrap();
    core.write_reg(2, xor_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();
    assert_eq!(get_label(&core, 2), Label::TopSecret);

    // Test left shift - should join to TopSecret
    core.write_reg(3, frankenengine::baseline_interpreter::Value::Int(2)).unwrap();
    set_label(&mut core, 3, Label::Public);
    let shl_result = core.eval_bitwise(1, 3, "<<").unwrap();
    core.write_reg(4, shl_result).unwrap();
    core.propagate_binary_operation_label(1, 3, 4).unwrap();
    assert_eq!(get_label(&core, 4), Label::TopSecret);

    // Test right shift
    let shr_result = core.eval_bitwise(1, 3, ">>").unwrap();
    core.write_reg(5, shr_result).unwrap();
    core.propagate_binary_operation_label(1, 3, 5).unwrap();
    assert_eq!(get_label(&core, 5), Label::TopSecret);
}

#[test]
fn test_label_lattice_ordering() {
    let mut core = test_interpreter();

    // Test that label joins respect the ordering: Public < Internal < Confidential < Secret < TopSecret
    let test_cases = vec![
        (Label::Public, Label::Internal, Label::Internal),
        (Label::Internal, Label::Confidential, Label::Confidential),
        (Label::Confidential, Label::Secret, Label::Secret),
        (Label::Secret, Label::TopSecret, Label::TopSecret),
        (Label::TopSecret, Label::Public, Label::TopSecret),
        (Label::Public, Label::TopSecret, Label::TopSecret),
    ];

    for (i, (label1, label2, expected)) in test_cases.into_iter().enumerate() {
        core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(i as i64)).unwrap();
        core.write_reg(1, frankenengine::baseline_interpreter::Value::Int((i + 100) as i64)).unwrap();
        set_label(&mut core, 0, label1.clone());
        set_label(&mut core, 1, label2.clone());

        let result = core.eval_add(0, 1).unwrap();
        core.write_reg(2, result).unwrap();
        core.propagate_binary_operation_label(0, 1, 2).unwrap();

        assert_eq!(
            get_label(&core, 2),
            expected,
            "Test case {}: {:?} ⊔ {:?} should equal {:?}",
            i,
            label1,
            label2,
            expected
        );
    }
}

#[test]
fn test_modulo_and_exponentiation_label_propagation() {
    let mut core = test_interpreter();

    // Setup values for modulo and exponentiation
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(17)).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Int(5)).unwrap();
    core.write_reg(2, frankenengine::baseline_interpreter::Value::Int(2)).unwrap();
    set_label(&mut core, 0, Label::Confidential);
    set_label(&mut core, 1, Label::Internal);
    set_label(&mut core, 2, Label::Secret);

    // Test modulo operation - Confidential ⊔ Internal = Confidential
    let mod_result = core.eval_mod(0, 1).unwrap();
    core.write_reg(3, mod_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 3).unwrap();
    assert_eq!(get_label(&core, 3), Label::Confidential);

    // Test exponentiation - Confidential ⊔ Secret = Secret
    let exp_result = core.eval_exp(0, 2).unwrap();
    core.write_reg(4, exp_result).unwrap();
    core.propagate_binary_operation_label(0, 2, 4).unwrap();
    assert_eq!(get_label(&core, 4), Label::Secret);
}

#[test]
fn test_taint_propagation_attack_scenario() {
    let mut core = test_interpreter();

    // Attack scenario: Low-privilege computation accesses high-privilege data
    // and the result should be properly re-labeled to prevent information leakage

    // Setup: Public computation context
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(1)).unwrap();
    set_label(&mut core, 0, Label::Public);

    // Attacker attempts to read secret data
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Int(42)).unwrap(); // Secret data
    set_label(&mut core, 1, Label::Secret);

    // Any operation involving secret data should taint the result
    let result = core.eval_add(0, 1).unwrap(); // Public + Secret
    core.write_reg(2, result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();

    // Result should be labeled Secret, preventing information leakage
    assert_eq!(get_label(&core, 2), Label::Secret);

    // Even comparison operations should propagate the taint
    let comparison = core.eval_relational(0, 1, "<").unwrap(); // Public < Secret
    core.write_reg(3, comparison).unwrap();
    core.propagate_binary_operation_label(0, 1, 3).unwrap();

    // Comparison result is also tainted
    assert_eq!(get_label(&core, 3), Label::Secret);
}

#[test]
fn test_label_initialization() {
    let core = test_interpreter();

    // All registers should start with Public label
    for i in 0..10 {
        assert_eq!(get_label(&core, i), Label::Public);
    }
}

#[test]
fn test_string_concatenation_label_propagation() {
    let mut core = test_interpreter();

    // Test string concatenation with different labels
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Str("public".to_string())).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Str("confidential".to_string())).unwrap();
    set_label(&mut core, 0, Label::Public);
    set_label(&mut core, 1, Label::Confidential);

    // String concatenation should join labels
    let concat_result = core.eval_add(0, 1).unwrap(); // String concatenation uses Add
    core.write_reg(2, concat_result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();

    assert_eq!(get_label(&core, 2), Label::Confidential);
}

#[test]
fn test_mixed_type_operations_label_propagation() {
    let mut core = test_interpreter();

    // Test operations between different value types
    core.write_reg(0, frankenengine::baseline_interpreter::Value::Int(42)).unwrap();
    core.write_reg(1, frankenengine::baseline_interpreter::Value::Str("42".to_string())).unwrap();
    set_label(&mut core, 0, Label::Internal);
    set_label(&mut core, 1, Label::Secret);

    // Mixed type operations should still propagate labels correctly
    let result = core.eval_add(0, 1).unwrap(); // Int + String -> String concatenation
    core.write_reg(2, result).unwrap();
    core.propagate_binary_operation_label(0, 1, 2).unwrap();

    assert_eq!(get_label(&core, 2), Label::Secret);
}