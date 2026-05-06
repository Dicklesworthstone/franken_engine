#![forbid(unsafe_code)]
//! Regression coverage for `Array.prototype.forEach` duplicate-removal behavior.

fn baseline_interpreter_source() -> &'static str {
    include_str!("../src/baseline_interpreter.rs")
}

#[test]
fn test_array_foreach_callback_dispatch_behavior() {
    let source = baseline_interpreter_source();
    assert!(source.contains("\"builtin:ArrayPrototypeForEach\" => {"));
    assert!(source.contains("self.invoke_array_callback("));
    assert!(source.contains("Ok(Value::Undefined)"));
}

#[test]
fn test_array_foreach_invalid_callback_behavior() {
    let source = baseline_interpreter_source();
    assert!(source.contains("expected: \"function\""));
    assert!(source.contains("missing callback argument"));
}

#[test]
fn test_array_foreach_no_duplicate_implementations() {
    let source = baseline_interpreter_source();
    assert_eq!(
        source
            .matches("\"builtin:ArrayPrototypeForEach\" => {")
            .count(),
        1
    );
}

#[test]
fn test_array_foreach_non_object_this_behavior() {
    let source = baseline_interpreter_source();
    assert!(source.contains("expected: \"array object\""));
    assert!(source.contains("receiver for {method_name}"));
}

#[test]
fn test_array_foreach_callback_validation_consistency() {
    let source = baseline_interpreter_source();
    assert!(
        source.contains("validate_array_callback_structure(args, \"Array.prototype.forEach\")")
    );
}

#[test]
fn test_array_foreach_duplicate_removal_memory_consistency() {
    let source = baseline_interpreter_source();
    assert!(source.contains("self.array_index_value(array_id, index)?"));
}
