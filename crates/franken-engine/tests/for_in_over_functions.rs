//! for-in over a function enumerates its enumerable own properties.
//!
//! It failed with an internal "expected object, got function". Test262's
//! harness/propertyHelper.js runs `for (var x in obj)` in its enumerability
//! check (verifyProperty), which `name.js`/`length.js` tests of functions
//! use. A function's own properties live on its backing object, where
//! `name` and `length` are non-enumerable. Expected lines are Node
//! v22.2.0's (`node -e`).

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
        "for_in_over_functions",
        r#"function f() {} f.a = 1; f.b = 2; Object.defineProperty(f, 'hidden', { value: 3, enumerable: false }); const k = []; for (const x in f) k.push(x); class C { static s = 1; static m() {} } const c = []; for (const x in C) c.push(x); const g = []; for (const x in Math.max) g.push(x); console.log(k.join(), c.join(), g.length);"#,
        "a,b s 0",
    ),
    (
        "property_helper_is_enumerable",
        r#"function isEnumerable(obj, name) { var s = false; for (var x in obj) { if (x === name) { s = true; break; } } return s && Object.prototype.hasOwnProperty.call(obj, name) && Object.prototype.propertyIsEnumerable.call(obj, name); } function f(a, b) {} f.extra = 1; console.log(isEnumerable(f, 'name'), isEnumerable(f, 'length'), isEnumerable(Math.max, 'name'), isEnumerable(f, 'extra'));"#,
        "false false false true",
    ),
    // ES2020 13.7.5.12 step 7.a: for-in over undefined or null runs no
    // iteration; it threw "expected object, got null", which stopped
    // preact's `h(type, null)` (`for (f in t)` over null props) and every
    // `for (k in opts)` with `opts` omitted.
    (
        "for_in_over_undefined_and_null",
        r#"var n = 0; for (var k in null) n++; for (var k2 in undefined) n++; function g(o) { var ks = []; for (const k in o) ks.push(k); return ks.length; } var t = null, f, c = 0; for (f in t) c++; var c2 = 0; for (let k3 in void 0) { c2++; } console.log(n, g(null), g(undefined), g({ a: 1 }), c, f, c2);"#,
        "0 0 0 1 0 undefined 0",
    ),
    // bd-9vouw.278: `Date` and `Promise` keep their own properties on a
    // property object; for-in over them failed ("expected function with an
    // own-property object"), so verifyProperty of Promise.all / Date.now
    // could not run.
    (
        "for_in_over_date_and_promise",
        r#"var k = []; for (var x in Date) k.push(x); var p = []; for (var y in Promise) p.push(y); Promise.extra = 1; var q = []; for (var z in Promise) q.push(z); console.log(k.length, p.length, q.join(), Object.keys(Date).length, Object.keys(Promise).join(), Object.prototype.propertyIsEnumerable.call(Promise, 'all'));"#,
        "0 0 extra 0 extra false",
    ),
];
fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "forin.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "forin.js"),
        &LoweringContext::new("forin-trace", "forin-decision", "forin-policy"),
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
    let mut core = InterpreterCore::new(config, "forin");
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
fn for_in_over_functions_matches_node() {
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
