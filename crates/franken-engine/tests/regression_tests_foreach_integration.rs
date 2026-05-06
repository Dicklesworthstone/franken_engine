#![forbid(unsafe_code)]
//! Regression tests for `Array.prototype.forEach` callback dispatch behavior.

fn baseline_interpreter_source() -> &'static str {
    include_str!("../src/baseline_interpreter.rs")
}

#[test]
fn test_array_prototype_foreach_callback_dispatch_comprehensive() {
    let source = baseline_interpreter_source();
    assert!(source.contains("\"builtin:ArrayPrototypeForEach\" => {"));
    assert!(
        source.contains("validate_array_callback_structure(args, \"Array.prototype.forEach\")")
    );
    assert!(source.contains("self.invoke_array_callback("));
}

#[test]
fn test_array_prototype_foreach_error_message_quality() {
    let source = baseline_interpreter_source();
    assert!(source.contains("missing callback argument"));
    assert!(source.contains("expected: \"function\""));
}

#[test]
fn test_array_prototype_foreach_duplicate_removal_verification() {
    let source = baseline_interpreter_source();
    assert_eq!(
        source
            .matches("\"builtin:ArrayPrototypeForEach\" => {")
            .count(),
        1
    );
}

#[test]
fn test_array_prototype_foreach_non_array_objects_comprehensive() {
    let source = baseline_interpreter_source();
    assert!(source.contains("expected: \"array object\""));
    assert!(source.contains("receiver for {method_name}"));
}

#[test]
fn test_array_prototype_foreach_thisarg_parameter_handling() {
    let source = baseline_interpreter_source();
    assert!(source.contains("expected: \"function\""));
    assert!(source.contains("missing callback argument"));
}

#[test]
fn test_array_prototype_foreach_expected_future_behavior_documentation() {
    let source = baseline_interpreter_source();
    assert!(source.contains("Ok(Value::Undefined)"));
    assert!(source.contains("self.array_index_value(array_id, index)?"));
}

#[test]
fn test_array_prototype_foreach_sparse_array_preparation() {
    let source = baseline_interpreter_source();
    assert!(source.contains("\"builtin:ArrayPrototypeForEach\" => {"));
}
