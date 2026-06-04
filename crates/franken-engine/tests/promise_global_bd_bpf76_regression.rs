//! Regression: the `Promise` global must expose static methods that return
//! real promise handles with callable instance methods.
//!
//! Bead: bd-bpf76. Original eval probes faulted on
//! `typeof Promise.resolve(5).then` and `typeof Promise.all`.

use frankenengine_engine::{EvalOutcome, HybridRouter};

fn eval_outcome(source: &str) -> EvalOutcome {
    let mut engine = HybridRouter::default();
    engine
        .eval(source)
        .unwrap_or_else(|err| panic!("eval failed for {source:?}: {err}"))
}

fn eval_value(source: &str) -> String {
    eval_outcome(source).value
}

#[test]
fn promise_resolve_result_exposes_then_method() {
    assert_eq!(eval_value("typeof Promise.resolve(5).then"), "function");
}

#[test]
fn promise_static_all_is_callable() {
    assert_eq!(eval_value("typeof Promise.all"), "function");
}

#[test]
fn promise_then_callback_runs_from_source_eval() {
    let outcome = eval_outcome("Promise.resolve(5).then(v => console.log(v));");
    let messages: Vec<_> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(messages, ["5"]);
}
