//! Regression tests for bd-es2ra — for-of iterator init/step must accept
//! every object-like carrier, not only `Value::Object`, while primitives
//! still reject with TypeError.
//!
//! Before the fix, core's `init_for_of_iterator` and
//! `advance_for_of_iterator` required the concrete `Value::Object` carrier:
//! a function returned as an iterator (or as an iterator *result*) hit the
//! "object returned by Symbol.iterator" / "iterator result object"
//! TypeErrors even though functions are objects in ECMAScript. Now:
//!
//! - an object-like iterator carrier without ordinary-property backing reads
//!   `next` as `undefined` and fails the *callable iterator.next* check;
//! - an object-like iterator *result* without ordinary-property backing reads
//!   `done`/`value` as `undefined`, so the step is not done and yields
//!   `undefined`;
//! - primitives keep the historical TypeErrors.
//!
//! Twin: `crates/franken-engine/tests/for_of_object_like_carriers_bd_es2ra.rs`.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, QuickJsLane, Value};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

/// Parse -> IR0 -> IR3 -> execute on the QuickJS lane with the minimal
/// execution capabilities, returning the completion value.
fn completion(source: &str) -> Value {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_es2ra");
    let context = LoweringContext::new("bd-es2ra-trace", "bd-es2ra-decision", "bd-es2ra-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-es2ra-trace")
        .expect("execution should succeed")
        .value
}

fn completion_str(source: &str) -> String {
    match completion(source) {
        Value::Str(s) => s.as_str().expect("completion should be UTF-8").to_string(),
        other => panic!("expected string completion, got {other:?}"),
    }
}

/// A function-like iterator *result* is object-like: `done`/`value` read as
/// undefined, so each such step yields `undefined` instead of throwing.
/// On pre-fix core this run failed with a TypeError ("iterator result
/// object, got function").
#[test]
fn function_like_iterator_result_steps_yield_undefined() {
    let src = r#"
        let c = 0;
        let iterator = {
            next: function () {
                c = c + 1;
                if (c > 2) { return { done: true }; }
                return function () {};
            }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let seen = 0;
        let allUndefined = 1;
        for (const value of iterable) {
            seen = seen + 1;
            if (value !== undefined) { allUndefined = 0; }
        }
        seen * 10 + allUndefined;
    "#;
    assert_eq!(completion(src), Value::Int(21));
}

/// A bare function returned by Symbol.iterator is object-like, so it passes
/// the carrier check — and then fails on `next` not being callable (it reads
/// as undefined off a carrier with no ordinary-property backing). Pre-fix
/// core instead rejected the carrier itself ("object returned by
/// Symbol.iterator, got function").
#[test]
fn bare_function_iterator_rejects_on_missing_next() {
    let src = r#"
        let iterable = { [Symbol.iterator]: function () { return function () {}; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error.name + "|" + error.message; }
        caught;
    "#;
    let caught = completion_str(src);
    assert!(
        caught.starts_with("TypeError|"),
        "bare-function iterator must throw TypeError, got: {caught}"
    );
    assert!(
        caught.contains("callable iterator.next"),
        "rejection must be the missing-next check, not the carrier check: {caught}"
    );
}

/// Primitives returned by Symbol.iterator keep the historical carrier
/// TypeError.
#[test]
fn primitive_iterator_still_rejects_as_non_object() {
    let src = r#"
        let iterable = { [Symbol.iterator]: function () { return 5; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error.name + "|" + error.message; }
        caught;
    "#;
    let caught = completion_str(src);
    assert!(
        caught.starts_with("TypeError|"),
        "primitive iterator must throw TypeError, got: {caught}"
    );
    assert!(
        caught.contains("object returned by Symbol.iterator"),
        "primitive iterator must fail the carrier check: {caught}"
    );
}

/// Primitive iterator *results* keep the historical result TypeError.
#[test]
fn primitive_iterator_result_still_rejects() {
    let src = r#"
        let iterator = { next: function () { return 1; } };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error.name + "|" + error.message; }
        caught;
    "#;
    let caught = completion_str(src);
    assert!(
        caught.starts_with("TypeError|"),
        "primitive iterator result must throw TypeError, got: {caught}"
    );
    assert!(
        caught.contains("iterator result object"),
        "primitive result must fail the result-carrier check: {caught}"
    );
}
