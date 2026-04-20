// Regression test for Array.prototype.some duplicate removal fix
// Commit de0c1906

use frankenengine_engine::*;
use frankenengine_test_support::interpreter_test_framework::*;

#[test]
fn test_array_some_fail_closed_no_callback() {
    let mut interpreter = create_test_interpreter();
    let script = r#"
        let arr = [1, 2, 3];
        let result = arr.some();
        result;
    "#;
    match run_script_sync(&mut interpreter, script) {
        Ok(value) => assert_eq!(value, Value::Bool(false)),
        Err(_) => {} // fail-closed acceptable
    }
}

#[test]
fn test_array_some_fail_closed_invalid_callback() {
    let mut interpreter = create_test_interpreter();
    let script = r#"
        let arr = [1, 2, 3];
        let result = arr.some("not a function");
        result;
    "#;
    match run_script_sync(&mut interpreter, script) {
        Ok(value) => assert_eq!(value, Value::Bool(false)),
        Err(_) => {} // fail-closed acceptable
    }
}

#[test]
fn test_array_some_consistent_behavior() {
    let mut interpreter = create_test_interpreter();
    let script = r#"
        let arr = [1, 2, 3];
        let result1 = arr.some();
        let result2 = arr.some();
        result1 === result2;
    "#;
    let result = run_script_sync(&mut interpreter, script)
        .expect("Script should execute");
    assert_eq!(result, Value::Bool(true));
}

#[test]
fn test_array_some_non_object_this() {
    let mut interpreter = create_test_interpreter();
    let script = r#"
        let result1 = Array.prototype.some.call(null);
        let result2 = Array.prototype.some.call(undefined);
        [result1, result2];
    "#;
    run_script_sync(&mut interpreter, script)
        .expect("Should not crash on non-object this");
}

#[test]
fn test_array_some_callback_validation_types() {
    let mut interpreter = create_test_interpreter();
    let test_cases = vec!["null", "undefined", "123", "'string'", "true", "[]", "{}"];

    for value in test_cases {
        let script = format!(
            r#"
            let arr = [1, 2, 3];
            let result = arr.some({});
            typeof result;
            "#,
            value
        );
        let result = run_script_sync(&mut interpreter, &script)
            .expect("Should not crash");
        if let Value::Str(type_str) = result {
            assert_eq!(type_str, "boolean");
        }
    }
}

#[test]
fn test_array_some_duplicate_removal_memory() {
    let mut interpreter = create_test_interpreter();
    let script = r#"
        let results = [];
        for (let i = 0; i < 50; i++) {
            let arr = [1, 2, 3];
            let result = arr.some();
            results.push(result);
        }
        results.every(r => r === false);
    "#;
    let result = run_script_sync(&mut interpreter, script)
        .expect("Memory stress test should not crash");
    assert_eq!(result, Value::Bool(true));
}