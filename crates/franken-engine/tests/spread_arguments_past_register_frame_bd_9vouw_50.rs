//! Spread and `apply` argument lists longer than the register frame
//! (bd-9vouw.50).
//!
//! Every spread call (`f(...a)`, `new C(...a)`, `super(...a)`) and every
//! `apply`/`Reflect.apply`/`Reflect.construct` staged receiver, callee and
//! arguments in one 256-register frame, so a list of 255 or more elements
//! failed with "register 4294967295 out of bounds (max 256)" (only
//! `Math.max`/`Math.min`/`String.fromCharCode`/`String.fromCodePoint` had a
//! vector path). Arguments past the frame are now staged out of band and read
//! through the ordinary register accessors, so formals, rest parameters,
//! `arguments` and native builtins see the whole list.
//!
//! Each program runs through the parser, the lowering and the interpreter;
//! the expected line is what Node v22.2.0 prints for the same program
//! (`node -e`). Every run also checks the memory-accounting invariant
//! (estimated == recomputed).

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
        "push_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); const b = [7]; b.push(...a); console.log(b.length, b[1000]);"#,
        "1001 999",
    ),
    (
        "rest_param",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); function f(...r) { return r.length + r[999]; } console.log(f(...a));"#,
        "1999",
    ),
    (
        "arguments_object",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); function g() { return arguments.length + arguments[999]; } console.log(g(...a));"#,
        "1999",
    ),
    (
        "formals_and_arguments",
        r#"const a = Array.from({ length: 300 }, (_, i) => i + 1); function h(x, y) { return x + y + arguments.length; } console.log(h(...a));"#,
        "303",
    ),
    (
        "apply",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); function h(x, y) { return x + y + arguments.length; } console.log(h.apply(null, a));"#,
        "1001",
    ),
    (
        "concat_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => [i]); console.log([].concat(...a).length);"#,
        "1000",
    ),
    (
        "unshift_spread",
        r#"const a = Array.from({ length: 500 }, (_, i) => i); const b = [1, 2]; b.unshift(...a); console.log(b.length, b[499], b[500]);"#,
        "502 499 1",
    ),
    (
        "array_of",
        r#"const a = Array.from({ length: 700 }, (_, i) => i); const o = Array.of(...a); console.log(o.length, o[699]);"#,
        "700 699",
    ),
    (
        "new_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); class C { constructor(...r) { this.n = r.length + r[998]; } } console.log(new C(...a).n);"#,
        "1998",
    ),
    (
        "super_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); class B { constructor(...r) { this.n = r.length; } } class D extends B { constructor(...r) { super(...r); this.m = r[500]; } } const d = new D(...a); console.log(d.n, d.m);"#,
        "1000 500",
    ),
    (
        "bound_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); const f = function (...r) { return r.length + r[0] + r[1001]; }.bind(null, 5, 6); console.log(f(...a));"#,
        "2006",
    ),
    (
        "call_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); function k() { return arguments.length + arguments[999]; } console.log(k.call(null, ...a));"#,
        "1999",
    ),
    (
        "method_this",
        r#"const a = Array.from({ length: 400 }, (_, i) => i); const o = { base: 10, sum(...r) { return this.base + r.length; } }; console.log(o.sum(...a));"#,
        "410",
    ),
    (
        "reflect_apply",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); console.log(Reflect.apply(function (...r) { return r.length; }, null, a));"#,
        "1000",
    ),
    (
        "reflect_construct",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); function P(...r) { this.n = r.length; } console.log(Reflect.construct(P, a).n);"#,
        "1000",
    ),
    (
        "async_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); async function af(...r) { await null; return r.length + r[999]; } af(...a).then(v => console.log(v));"#,
        "1999",
    ),
    (
        "generator_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); function* gen(...r) { yield r.length; yield r[999]; } const it = gen(...a); console.log(it.next().value, it.next().value);"#,
        "1000 999",
    ),
    (
        "nested_spread",
        r#"const a = Array.from({ length: 600 }, (_, i) => i); function inner(...r) { return r.length; } function outer(...r) { return inner(...r, ...r) + r.length; } console.log(outer(...a));"#,
        "1800",
    ),
    (
        "arrow_spread",
        r#"const a = Array.from({ length: 1000 }, (_, i) => i); const f = (...r) => r.reduce((s, x) => s + x, 0); console.log(f(...a));"#,
        "499500",
    ),
    (
        "string_concat_apply",
        r#"const parts = Array.from({ length: 300 }, (_, i) => String(i % 10)); console.log(''.concat(...parts).length);"#,
        "300",
    ),
];

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "spread.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "spread.js"),
        &LoweringContext::new("spread-trace", "spread-decision", "spread-policy"),
    )
    .map_err(|error| format!("lower: {error:?}"))?
    .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.instruction_budget = 100_000_000;
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
        RuntimeCapability::Timer,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "spread");
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

#[test]
fn spread_and_apply_lists_past_the_register_frame_match_node() {
    let mut mismatches = Vec::new();
    for (name, source, node) in CASES {
        match console_output(source) {
            Ok(output) if output == *node => {}
            other => mismatches.push(format!("{name}: node {node:?}, got {other:?}")),
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} programs differ from Node:\n{}",
        mismatches.len(),
        CASES.len(),
        mismatches.join("\n")
    );
}

/// The out-of-band list is not a way around the budget: a list is refused
/// before it is materialized once it is longer than the engine accepts, and
/// a guest catch does not see the refusal.
#[test]
fn oversized_spread_list_is_still_refused() {
    let error = console_output(
        "try { Reflect.apply(function () {}, null, { length: 200000 }); } catch (e) { console.log('caught'); }",
    )
    .expect_err("a 200,000-element list exceeds MAX_CALL_ARGUMENTS");
    assert!(error.contains("RegisterOutOfBounds"), "{error}");
}

/// `count` numeric literals `0, 1, ...` as an argument list.
fn numbers(count: usize) -> String {
    (0..count)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// bd-9vouw.254: a call with 120 to 128 positional arguments took about
/// 2N + 2 registers (each argument and its contiguous copy) and overflowed
/// the frame. 128 arguments needed 258 registers, and from about 120 a
/// function with live locals failed. Babel standalone's regenerate tables
/// (`regenerateExports(...125 code points)`) failed at load with "register
/// 256 out of bounds". Calls, method calls, `new` and a builtin with 120-128
/// arguments now match Node v22.2.0 ("131,255,126 128 127 120").
#[test]
fn calls_with_up_to_128_positional_arguments_fit_the_frame_bd_9vouw_254() {
    let source = format!(
        "function count() {{ return arguments.length; }}\nvar o = {{ m: function () {{ return arguments.length + arguments[arguments.length - 1]; }} }};\nfunction C() {{ this.n = arguments.length; }}\nfunction g() {{ var a = 1, b = 2, c = 3; var r = count({}); var s = o.m({}); var t = new C({}).n; return [r + a + b + c, s, t].join(); }}\nconsole.log(g(), count({}), Math.max({}), [].concat({}).length);\n",
        numbers(125),
        numbers(128),
        numbers(126),
        numbers(128),
        numbers(128),
        numbers(120)
    );
    assert_eq!(
        console_output(&source).expect("the program runs"),
        "131,255,126 128 127 120"
    );
}
