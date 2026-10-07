//! bd-9vouw.242: ES2020 B.3.3 block-level function declarations in
//! non-strict code.
//!
//! A function declared in a block (or a switch case, or as an if clause,
//! B.3.4) stayed visible only inside that block: `if (x) { function f() {} }
//! f();` threw "f is not defined", where Node calls `f`. Non-strict code
//! also gives the name a var binding in the enclosing function or script.
//! It starts as undefined and takes the function when the declaration is
//! evaluated, unless a `var f` there would be an early error (an enclosing
//! let/const/class, block function or loop binding of `f`) or `f` is a
//! parameter.
//!
//! Block function declarations are also now created when their block is
//! entered (ES2020 13.2.14), so a call before the declaration inside the
//! block works.
//!
//! PROGRAM checks:
//! - duplicate declarations in one block;
//! - an enclosing `let` (skipped);
//! - a catch parameter of the same name (B.3.5, hoisted);
//! - a parameter (skipped);
//! - async and generator declarations (stay block-scoped);
//! - typeof before and after, and a call inside the block before the
//!   declaration;
//! - a for-of `let` head (skipped);
//! - an assignment after the declaration (changes only the block binding);
//! - switch cases, if clauses taken and not taken, labeled blocks;
//! - arrow and method bodies;
//! - a strict function (block-scoped);
//! - the block binding and the var binding being distinct (Test262's
//!   block-scoping case);
//! - initialization to undefined;
//! - an outer `let`, an existing var, an existing top-level function, an
//!   if clause next to a `let` of the same name;
//! - a loop body, a try block, and a script-level block.
//!
//! NODE_OUTPUT is Node v22.2.0's output, captured programmatically.
//!
//! No-claim: a script-level block function becomes a script var binding,
//! not a property of the global object.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = r#"var r = [];
r.push((function () { { function f() { return 1; } function f() { return 2; } } return typeof f + f(); })());
r.push((function () { { let g = 1; { function g() {} } } return typeof g; })());
r.push((function () { try { throw 0; } catch (k) { { function k() {} } } return typeof k; })());
r.push((function (a) { { function a() {} } return typeof a; })(5));
r.push((function () { { async function m() {} function* n() {} } return typeof m + typeof n; })());
r.push((function () { var before = typeof p; { p(); function p() {} } return before + typeof p; })());
r.push((function () { for (let q of [1]) { function q() {} } return typeof q; })());
r.push((function () { { function s() { return 'x'; } s = 5; } return typeof s; })());
r.push((function () { switch (1) { case 1: function t() { return 't'; } } return t(); })());
r.push((function () { if (true) function u() { return 'u'; } return u(); })());
r.push((function () { if (false) function u2() {} return typeof u2; })());
r.push((function () { l: { function v() {} } return typeof v; })());
r.push((() => { { function w() {} } return typeof w; })());
r.push(({ m() { { function x() {} } return typeof x; } }).m());
r.push((function () { 'use strict'; { function y() {} } return typeof y; })());
r.push((function () {
  var initial, current, outer;
  { function z() { initial = z; z = 123; current = z; return 'decl'; } }
  outer = z;
  z();
  return [typeof initial, current, outer(), typeof z].join('/');
})());
r.push((function () { var log = [typeof aa]; aa = 7; log.push(aa); { function aa() {} } log.push(typeof aa); return log.join('/'); })());
r.push((function () { let bb = 1; { function bb() {} } return bb; })());
r.push((function () { var cc = 'var'; { function cc() {} } return typeof cc; })());
r.push((function () { function dd() { return 'top'; } { function dd() { return 'block'; } } return dd(); })());
r.push((function () { { let ee = 1; if (true) function ee() {} } return typeof ee; })());
r.push((function () { var log = [typeof ff]; while (log.length < 2) { log.push(typeof ff); function ff() {} } return log.join('/') + '/' + typeof ff; })());
r.push((function () { try { function gg() { return 'g'; } } finally {} return gg(); })());
r.push((function () { var o = { wf: 1 }; with (o) { { function wf() { return 'w'; } } } return typeof wf + typeof o.wf; })());
{ function scriptLevel() { return 'script'; } }
r.push(scriptLevel());
console.log(r.join(' | '));"#;

/// Node v22.2.0's output for `PROGRAM`.
const NODE_OUTPUT: &str = r#"function2 | undefined | function | number | undefinedundefined | undefinedfunction | undefined | function | t | u | undefined | function | function | function | undefined | function/123/decl/function | undefined/7/function | 1 | function | block | undefined | undefined/function/function | g | functionnumber | script"#;

fn console_output(source: &str) -> Result<String, String> {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "annex-b.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .map_err(|error| format!("parse: {error:?}"))?;
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "annex-b.js"),
        &LoweringContext::new("annex-b-trace", "annex-b-decision", "annex-b-policy"),
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
    let mut core = InterpreterCore::new(config, "annex-b");
    let result = core.execute(&module);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "memory accounting drift"
    );
    let result = result.map_err(|error| format!("execute: {error:?}"))?;
    Ok(result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n"))
}

#[test]
fn block_function_declarations_match_node_bd_9vouw_242() {
    assert_eq!(
        console_output(PROGRAM).expect("the program runs"),
        NODE_OUTPUT
    );
}

/// Test262 annexB/language/function-code/block-decl-nested-blocks-with-fun-decl.js:
/// the inner `f` is not hoisted, because a `var f` in its place would
/// conflict with the outer block's `f`. The spec keeps the outer one, and
/// Node v22.2.0 (which returns 2) does not.
#[test]
fn a_block_function_inside_a_block_declaring_the_same_name_stays_block_scoped_bd_9vouw_242() {
    let source = "function g() { { function f() { return 1; } { function f() { return 2; } } } return f(); }\nconsole.log(g());";
    assert_eq!(console_output(source).expect("the program runs"), "1");
}

/// Strict code keeps block functions block-scoped (B.3.3 applies only to
/// non-strict code), at the script level as in functions.
#[test]
fn strict_scripts_keep_block_functions_block_scoped_bd_9vouw_242() {
    let source = "'use strict';\n{ function f() {} }\nconsole.log(typeof f);";
    assert_eq!(
        console_output(source).expect("the program runs"),
        "undefined"
    );
}
