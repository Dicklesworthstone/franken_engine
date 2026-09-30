//! A generator's parameters are bound when it is called (bd-9vouw.49).
//!
//! ES2020 14.4.10 runs FunctionDeclarationInstantiation (parameter
//! initializers and destructuring) before GeneratorStart, so a throwing
//! default or a pattern over null throws from the call and the parameters'
//! side effects happen before the call returns. The engine created the
//! generator suspended at its first instruction, so all of this waited for
//! the first next(): `try { g(); } catch {}` caught nothing, and the error
//! surfaced later from next(). About 40 of the 81 generator parameter tests
//! in the Test262 sample failed this way.
//!
//! Async generators follow the same rule (ES2020 14.5: their body evaluation
//! also runs FunctionDeclarationInstantiation first, so a parameter error
//! throws from the call; an async function rejects its promise instead).
//!
//! Expected lines are Node v22.2.0's (`node -e`). Eight programs are controls
//! that already matched (first next() argument, throw() before next(),
//! simple parameters, this/arguments, a nested generator, object shape,
//! for-await over an async generator, a static async generator default).

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

/// (name, program, Node v22.2.0 output)
const CASES: &[(&str, &str, &str)] = &[
    (
        "throwing_default_throws_from_the_call",
        r#"function* g(a = (() => { throw new Error('p'); })()) { yield a; } let r; try { g(); r = 'no throw'; } catch (e) { r = 'caught ' + e.message; } console.log(r);"#,
        "caught p",
    ),
    (
        "destructuring_null_throws_from_the_call",
        r#"function* g({ a }) { yield a; } let r; try { g(null); r = 'no throw'; } catch (e) { r = e instanceof TypeError; } console.log(r);"#,
        "true",
    ),
    (
        "parameters_run_before_the_call_returns",
        r#"var log = []; function* g(a = log.push('param')) { log.push('body'); yield 1; } var it = g(); log.push('created'); it.next(); console.log(log.join());"#,
        "param,created,body",
    ),
    (
        "first_next_argument_is_ignored",
        r#"function* g(a = 1) { const x = yield a; yield x; } const it = g(); console.log([it.next('ignored').value, it.next('b').value].join());"#,
        "1,b",
    ),
    (
        "return_before_next_skips_the_body",
        r#"var log = []; function* g(a = log.push('p')) { try { yield 1; } finally { log.push('f'); } } const it = g(); const r = it.return(5); console.log([r.value, r.done, log.join(), it.next().done].join());"#,
        "5,true,p,true",
    ),
    (
        "throw_before_next_completes",
        r#"function* g(a = 1) { try { yield 1; } catch (e) { return 'caught'; } } const it = g(); let r; try { it.throw(new Error('x')); r = 'no'; } catch (e) { r = e.message + ' ' + it.next().done; } console.log(r);"#,
        "x true",
    ),
    (
        "object_method_pattern_default",
        r#"const o = { *m({ x } = {}) { yield x; } }; let r; try { o.m(null); r = 'no'; } catch (e) { r = e.constructor.name; } console.log(r, o.m({ x: 4 }).next().value, o.m().next().value);"#,
        "TypeError 4 undefined",
    ),
    (
        "class_method_and_static_default_reference_error",
        r#"class C { *m([a] = []) { yield a; } static *s(a = b) { yield a; } } let r; try { C.s(); r = 'no'; } catch (e) { r = e.constructor.name; } console.log(r, new C().m([9]).next().value);"#,
        "ReferenceError 9",
    ),
    (
        "generator_expression_default_reference_error",
        r#"const g = function* (a = x) { yield a; }; let r; try { g(); r = 'no'; } catch (e) { r = e.constructor.name; } console.log(r, g(3).next().value);"#,
        "ReferenceError 3",
    ),
    (
        "simple_parameters",
        r#"function* g(a, b) { yield a + b; } console.log([...g(1, 2)].join());"#,
        "3",
    ),
    (
        "this_and_arguments_in_defaults",
        r#"function* g(a = this.v) { yield a; yield arguments.length; } const it = g.call({ v: 7 }); console.log([it.next().value, it.next().value].join());"#,
        "7,0",
    ),
    (
        "nested_generator_in_a_default",
        r#"function* inner() { yield 1; } function* g(a = inner().next().value) { yield a; } console.log([...g()].join());"#,
        "1",
    ),
    (
        "each_call_evaluates_its_own_defaults",
        r#"var calls = 0; function* g([x, y] = [calls++, 2]) { yield x + y; } const a = g(); const b = g(); console.log(calls, a.next().value, b.next().value);"#,
        "2 2 3",
    ),
    (
        "generator_object_shape",
        r#"function* g(a = 1) { yield a; } const it = g(); console.log(Object.prototype.toString.call(it), typeof it.next, it[Symbol.iterator]() === it);"#,
        "[object Generator] function true",
    ),
];

/// (name, program, Node v22.2.0 output) for async generators.
const ASYNC_CASES: &[(&str, &str, &str)] = &[
    (
        "async_throwing_default_throws_from_the_call",
        r#"async function* g(a = (() => { throw new Error('x'); })()) { yield a; } let r; try { g(); r = 'no throw'; } catch (e) { r = 'sync ' + e.message; } console.log(r);"#,
        "sync x",
    ),
    (
        "async_parameters_run_before_the_call_returns",
        r#"var log = []; async function* h(a = log.push('p')) { log.push('b'); yield 1; } const it = h(); log.push('c'); it.next().then(() => console.log(log.join()));"#,
        "p,c,b",
    ),
    (
        "async_for_await",
        r#"async function* g(a = 2) { yield a; yield a * 2; } (async () => { const r = []; for await (const v of g()) r.push(v); console.log(r.join()); })();"#,
        "2,4",
    ),
    (
        "async_return_before_next",
        r#"var log = []; async function* g(a = log.push('p')) { try { yield 1; } finally { log.push('f'); } } const it = g(); it.return(5).then((r) => console.log(r.value, r.done, log.join()));"#,
        "5 true p",
    ),
    (
        "async_object_method_null_pattern",
        r#"const o = { async *m({ x }) { yield x; } }; let r; try { o.m(null); r = 'no'; } catch (e) { r = e.constructor.name; } o.m({ x: 3 }).next().then((v) => console.log(r, v.value));"#,
        "TypeError 3",
    ),
    (
        "async_static_method_default",
        r#"class C { static async *s([a] = [5]) { yield a; } } C.s().next().then((v) => console.log(v.value, v.done));"#,
        "5 false",
    ),
];

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "genparams.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "genparams.js"),
        &LoweringContext::new("genparams-trace", "genparams-decision", "genparams-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "genparams");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift: {source}"
    );
    let result = result.map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

fn check_cases(cases: &[(&str, &str, &str)]) {
    let mut mismatches = Vec::new();
    for (name, source, node) in cases {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n")
    );
}

#[test]
fn generator_parameters_bind_at_the_call() {
    check_cases(CASES);
}

#[test]
fn async_generator_parameters_bind_at_the_call() {
    check_cases(ASYNC_CASES);
}
