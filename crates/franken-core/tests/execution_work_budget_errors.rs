#![forbid(unsafe_code)]

use frankenengine_core::baseline_interpreter::InterpreterError;
use frankenengine_core::execution_work_budget::WorkBudgetError;

#[test]
fn interpreter_cause_remains_downcastable_in_standard_error_chain() {
    let native = InterpreterError::Cancelled;
    let wrapped = WorkBudgetError::Interpreter(native.clone());
    let source = std::error::Error::source(&wrapped).expect("typed native cause");
    assert_eq!(source.downcast_ref::<InterpreterError>(), Some(&native));
    assert_eq!(wrapped.to_string(), native.to_string());
    assert!(source.source().is_none());
    let boxed: Box<dyn std::error::Error> = Box::new(native);
    assert!(boxed.is::<InterpreterError>());
}

#[test]
fn admission_failures_do_not_fabricate_interpreter_causes() {
    for error in [
        WorkBudgetError::ZeroInstructionBudget,
        WorkBudgetError::Exhausted {
            requested: 128,
            remaining: 0,
        },
        WorkBudgetError::Interrupted,
    ] {
        assert!(std::error::Error::source(&error).is_none());
    }
}
