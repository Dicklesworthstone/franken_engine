//! bd-9vouw.75: `AggregateError` is a real constructor (ES2021 20.5.7), and
//! `Promise.any` rejects with an instance of it.
//!
//! Before: `typeof AggregateError` was "undefined", and `Promise.any`
//! rejected with a plain object whose `constructor.name` was "Object".
//! Expected strings are Node v22.2.0's output for the same programs.
//!
//! No mocks: real source through the parser, lowering and `InterpreterCore`
//! for both native profiles.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "aggregate-error.js".into(),
                text: format!("const log = console.log;\n{source}"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("AggregateError source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "aggregate-error.js"),
        &LoweringContext::new("aggregate-trace", "aggregate-decision", "aggregate-policy"),
    )
    .expect("AggregateError source must lower")
    .ir3
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "aggregate-error");
        let result = core
            .execute(&module)
            .unwrap_or_else(|error| panic!("`{source}` failed: {error}"));
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected, "{source}");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes(),
            "{source}"
        );
    }
}

/// The acceptance shape: `errors`, `message`, the prototype chain to
/// Error.prototype, `name` on the prototype, `errors` own and non-enumerable.
#[test]
fn constructor_builds_an_error_with_an_errors_list() {
    assert_output(
        "const e = new AggregateError([1, 2], 'm');
         log([typeof AggregateError, e.errors.length, e.message, e instanceof AggregateError,
              e instanceof Error, e.name, e.constructor === AggregateError, Object.keys(e).length,
              Object.prototype.hasOwnProperty.call(e, 'errors'), AggregateError.prototype.name,
              AggregateError.length,
              Object.getPrototypeOf(AggregateError.prototype) === Error.prototype].join(' '));",
        &["function 2 m true true AggregateError true 0 true AggregateError 2 true"],
    );
}

/// `errors` is IterableToList: a Set, a generator and a string all iterate.
#[test]
fn errors_come_from_any_iterable() {
    assert_output(
        "log(new AggregateError(new Set(['a', 'b'])).errors.join(),
             new AggregateError((function* () { yield 1; yield 2; })()).errors.length,
             new AggregateError('xy').errors.join('|'));",
        &["a,b 2 x|y"],
    );
}

/// `cause` from the options argument, a plain call constructs too, the
/// string form, and no own `message` when none was given.
#[test]
fn cause_plain_call_string_form_and_absent_message() {
    assert_output(
        "log(new AggregateError([], 'm', { cause: 'c' }).cause, AggregateError([3]).errors[0],
             String(new AggregateError([], 'boom')), 'message' in new AggregateError([]),
             Object.prototype.hasOwnProperty.call(new AggregateError([]), 'message'));",
        &["c 3 AggregateError: boom true false"],
    );
}

#[test]
fn subclasses_initialize_errors_and_message() {
    assert_output(
        "class MyAgg extends AggregateError {}
         const m = new MyAgg([1], 'x');
         log(m instanceof MyAgg, m instanceof AggregateError, m.errors.length, m.message, m.name);",
        &["true true 1 x AggregateError"],
    );
}

/// A non-iterable `errors` is a TypeError, including an array-like object
/// that `Array.from` would accept.
#[test]
fn non_iterable_errors_throw_type_error() {
    assert_output(
        "for (const bad of [5, undefined, {}, { length: 1, 0: 'x' }]) {
           try { new AggregateError(bad); log('no error'); } catch (err) { log(err instanceof TypeError); }
         }",
        &["true", "true", "true", "true"],
    );
}

#[test]
fn promise_any_rejects_with_an_aggregate_error() {
    assert_output(
        "Promise.any([Promise.reject(1), Promise.reject(2)]).catch((err) =>
           log(err.constructor.name, err instanceof AggregateError, err.errors.join(), err.message,
               Object.keys(err).length));",
        &["AggregateError true 1,2 All promises were rejected 0"],
    );
    assert_output(
        "Promise.any([]).catch((err) => log('empty', err instanceof AggregateError, err.errors.length));",
        &["empty true 0"],
    );
}
