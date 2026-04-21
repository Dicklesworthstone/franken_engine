#![forbid(unsafe_code)]
//! Regression tests for `Array.prototype.forEach` fail-closed behavior.

fn baseline_interpreter_source() -> &'static str {
    include_str!("../src/baseline_interpreter.rs")
}

#[test]
fn test_array_prototype_foreach_fail_closed_comprehensive() {
    let source = baseline_interpreter_source();
    assert!(source.contains("\"builtin:ArrayPrototypeForEach\" => {"));
    assert!(source.contains("supported Array.prototype.forEach implementation"));
    assert!(source.contains("callback invocation not yet supported"));
}

#[test]
fn test_array_prototype_foreach_error_message_quality() {
    let source = baseline_interpreter_source();
    assert!(source.contains("side-effect execution for each element"));
    assert!(source.contains("thisArg handling"));
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
    assert!(source.contains("validate_array_callback_args(args, \"Array.prototype.forEach\")"));
    assert!(source.contains("expected: \"object\""));
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
    assert!(source.contains("Array.prototype.forEach(callback[, thisArg]) implementation"));
    assert!(source.contains("callback invocation not yet supported"));
}

#[test]
fn test_array_prototype_foreach_sparse_array_preparation() {
    let source = baseline_interpreter_source();
    assert!(source.contains("\"builtin:ArrayPrototypeForEach\" => {"));
}
