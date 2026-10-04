#![forbid(unsafe_code)]

//! A function's `length` is ES2020 ExpectedArgumentCount: the parameters
//! before the first one with an initializer or the rest parameter
//! (bd-9vouw.66 / bd-9vouw.105 / bd-9vouw.134). Expected lines are Node
//! v22.2.0's output for the same programs.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn console_output(source: &str) -> Vec<String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "length.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "length.js"),
        &LoweringContext::new("length-trace", "length-decision", "length-policy"),
    )
    .expect("source lowers")
    .ir3;
    let mut outputs = Vec::new();
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
        let mut core = InterpreterCore::new(config, "length");
        let result = core.execute(&module).expect("program runs");
        outputs.push(
            result
                .console_output
                .into_iter()
                .map(|entry| entry.message)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(outputs[0], outputs[1], "both profiles agree");
    outputs.swap_remove(0)
}

/// Function declarations: the count stops at the first parameter with an initializer.
#[test]
fn declarations_stop_at_the_first_default() {
    assert_eq!(
        console_output(
            "function f1(a, b = 1) {}\nfunction f2(a = 1) {}\nfunction f3(a, b = 1, c) {}\nfunction f4({ a } = {}, b) {}\nfunction f5([a] = [], b) {}\nconsole.log(f1.length, f2.length, f3.length, f4.length, f5.length);\n"
        ),
        ["1 0 1 0 0"]
    );
}

/// Arrow functions and function expressions.
#[test]
fn arrows_and_function_expressions() {
    assert_eq!(
        console_output(
            "const a1 = (a = 1) => 0;\nconst a2 = (a, b = 1) => 0;\nconst e1 = function (x, y = 2, z) {};\nconsole.log(a1.length, a2.length, e1.length);\n"
        ),
        ["0 1 1"]
    );
}

/// Object methods, generator methods, async functions and async arrows.
#[test]
fn methods_generators_and_async() {
    assert_eq!(
        console_output(
            "const o = { *g(a, b = 1) {}, async n(a = 0, b) {}, m(a, b, c = 3) {} };\nasync function af(a, b = 1) {}\nconst aa = async (a = 1) => 0;\nconsole.log(o.g.length, o.n.length, o.m.length, af.length, aa.length);\n"
        ),
        ["1 0 2 1 0"]
    );
}

/// Class constructors, instance methods and static methods.
#[test]
fn class_methods_and_constructors() {
    assert_eq!(
        console_output(
            "class C { constructor(a, b = 1) {} m(x, y = 2) {} static s(p = 0) {} }\nconsole.log(C.length, new C().m.length, C.s.length);\n"
        ),
        ["1 1 0"]
    );
}

/// A rest parameter ends the count too; whichever comes first wins.
#[test]
fn rest_and_defaults_together() {
    assert_eq!(
        console_output(
            "function r1(a, ...rest) {}\nfunction r2(a, b = 1, ...rest) {}\nfunction r3(...rest) {}\nconsole.log(r1.length, r2.length, r3.length);\n"
        ),
        ["1 1 0"]
    );
}

/// Plain and destructuring parameters without initializers all count.
#[test]
fn parameters_without_initializers_still_count() {
    assert_eq!(
        console_output(
            "function p(a, b) {}\nfunction q({ a }, [b], c) {}\nconsole.log(p.length, q.length);\n"
        ),
        ["2 3"]
    );
}

/// A bound function's length starts from its target's length.
#[test]
fn bound_functions_use_the_target_length() {
    assert_eq!(
        console_output(
            "function f(a, b = 1, c) {}\nconsole.log(f.bind(null).length, f.bind(null, 1).length, f.bind(null, 1, 2).length);\n"
        ),
        ["1 0 0"]
    );
}
