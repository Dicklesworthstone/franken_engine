//! Array rest destructuring (bd-wxce8): `const [a, ...rest] = ...` binds
//! the remaining elements to a real array.
//!
//! These tests asserted an `ArraySlice` instruction in the lowered program.
//! Since 99827e3fc (2026-09-14) array destructuring runs the iterator
//! protocol and collects the rest element by element, which works for any
//! iterable, so no slice is emitted. They now execute each program and check
//! the bound values; expected strings are Node v22.2.0's output for the same
//! programs. The lowering-determinism check is kept.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "rest.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "rest.js"),
        &LoweringContext::new("rest-trace", "rest-decision", "rest-policy"),
    )
    .expect("source lowers")
    .ir3
}

/// The completion value of `source` on the deterministic configuration.
fn eval(source: &str) -> String {
    let module = lower(source);
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "rest");
    match core.execute(&module).expect("program runs").value {
        Value::Str(text) => text.to_string(),
        other => format!("{other:?}"),
    }
}

/// `const [a, b, ...rest]` collects the remaining elements.
#[test]
fn rest_destructuring_simple_rest() {
    assert_eq!(
        eval("const [a, b, ...rest] = [1, 2, 3, 4, 5]; JSON.stringify([a, b, rest]);"),
        "[1,2,[3,4,5]]"
    );
}

/// A rest with nothing left is an empty array.
#[test]
fn rest_destructuring_empty_rest() {
    assert_eq!(
        eval("const [a, b, ...rest] = [1, 2]; JSON.stringify([a, b, rest, Array.isArray(rest)]);"),
        "[1,2,[],true]"
    );
}

/// Missing elements are undefined and the rest is empty.
#[test]
fn rest_destructuring_source_shorter_than_pattern() {
    assert_eq!(
        eval(
            "const [a, b, c, ...rest] = [1]; JSON.stringify([a, b === undefined, c === undefined, rest]);"
        ),
        "[1,true,true,[]]"
    );
}

/// A rest-only pattern copies every element.
#[test]
fn rest_destructuring_rest_only() {
    assert_eq!(
        eval("const [...rest] = [7, 8, 9]; JSON.stringify(rest);"),
        "[7,8,9]"
    );
}

/// Rest elements in a nested pattern and in the outer pattern.
#[test]
fn rest_destructuring_nested_rest() {
    assert_eq!(
        eval(
            "const [a, [b, ...inner], ...outer] = [1, [2, 3, 4], 5, 6]; JSON.stringify([a, b, inner, outer]);"
        ),
        "[1,2,[3,4],[5,6]]"
    );
}

/// The rest is collected through the iterator protocol, so any iterable works (a Set, a string).
#[test]
fn rest_destructuring_rest_from_any_iterable() {
    assert_eq!(
        eval(
            "const [first, ...others] = new Set(['x', 'y', 'z']); const [c, ...chars] = 'hey'; JSON.stringify([first, others, c, chars]);"
        ),
        "[\"x\",[\"y\",\"z\"],\"h\",[\"e\",\"y\"]]"
    );
}

/// Lowering the same program twice gives the same instructions.
#[test]
fn rest_destructuring_lowering_is_deterministic() {
    let source = "const [a, b, ...rest] = [1, 2, 3, 4, 5]; rest.length;";
    assert_eq!(lower(source).instructions, lower(source).instructions);
}
