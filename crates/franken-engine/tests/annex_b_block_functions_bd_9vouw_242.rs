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
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
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
    console_output_with_config(source, InterpreterConfig::quickjs_defaults())
}

fn console_output_with_config(source: &str, config: InterpreterConfig) -> Result<String, String> {
    evaluate_script_with_config(source, config).map(|(_, output)| output)
}

fn evaluate_script_with_config(
    source: &str,
    mut config: InterpreterConfig,
) -> Result<(Value, String), String> {
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
    let output = result
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    Ok((result.value, output))
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

/// bd-9vouw.253: ES2020 B.3.5. A `var` may redeclare a simple catch
/// parameter in its catch block, including a for-in head's `var`. Its
/// initializer assigns the parameter, and the hoisted var outside stays
/// undefined. This was refused at lowering with
/// FE-SEM-LEXICAL-VAR-CONFLICT. Node v22.2.0 prints the expected line.
#[test]
fn a_var_may_redeclare_a_simple_catch_parameter_bd_9vouw_253() {
    let source = r#"var out = [];
try { throw 1; } catch (e) { var e = 2; out.push(e); }
out.push(typeof e, e);
try { throw 1; } catch (f) { for (var f in { k: 1 }) { out.push(f); } }
out.push(f);
try { throw 1; } catch (g) { for (var g = 5; false;) {} out.push(g); }
console.log(out.join(' '));"#;
    assert_eq!(
        console_output(source).expect("the program runs"),
        r#"2 undefined  k  5"#
    );
}

fn assert_native_console_output(source: &str, expected: &str) {
    for (lane, config) in [
        ("quickjs", InterpreterConfig::quickjs_defaults()),
        ("v8", InterpreterConfig::v8_defaults()),
    ] {
        assert_eq!(
            console_output_with_config(source, config)
                .unwrap_or_else(|error| panic!("{lane}: {error}")),
            expected,
            "{lane}"
        );
    }
}

#[test]
fn labelled_script_and_body_functions_are_hoisted() {
    let source = r#"
var out = [];
out.push(typeof labelledGlobal, labelledGlobal());
first: second: function labelledGlobal() { return "global"; }
out.push(globalThis.labelledGlobal === labelledGlobal);
out.push(Object.getOwnPropertyDescriptor(globalThis, "labelledGlobal").configurable);
function beforeReturn() {
  return inner();
  first: second: function inner() { return "body"; }
}
function duplicate() {
  first: function inner() { return 1; }
  function inner() { return 2; }
  return inner();
}
out.push(beforeReturn(), duplicate());
console.log(out.join("|"));
"#;
    assert_native_console_output(source, "function|global|true|false|body|2");
}

#[test]
fn labelled_block_functions_keep_declaration_time_var_copies() {
    let source = r#"
function run() {
  var readOuter = function () { return f; };
  var out = [typeof f];
  {
    out.push(f(), typeof readOuter());
    first: second: function f() { return 7; }
    out.push(typeof readOuter());
    f = 19;
  }
  out.push(readOuter()(), typeof f);
  return out.join("|");
}
console.log(run());
"#;
    assert_native_console_output(source, "undefined|7|undefined|function|7|function");
}

#[test]
fn labelled_block_functions_respect_shadowing_and_branch_entry() {
    let source = r#"
function run(parameter) {
  var out = [];
  if (false) { label: function absent() {} }
  out.push(typeof absent);
  if (true) { label: function present() { return "taken"; } }
  out.push(present());
  {
    let blocked = 3;
    { label: function blocked() {} }
    out.push(blocked);
  }
  out.push(typeof blocked);
  { label: function parameter() {} }
  out.push(parameter);
  { label: function arguments() {} }
  out.push(typeof arguments);
  return out.join("|");
}
console.log(run(8));
"#;
    assert_native_console_output(source, "undefined|taken|3|undefined|8|function");
}

#[test]
fn hoisted_labelled_functions_preserve_label_control() {
    let source = r#"
var out = [];
outer: {
  out.push(f());
  inner: function f() {
    outer: { break outer; }
    return "block";
  }
  break outer;
  out.push("unreachable");
}
inner: function g() { return "script"; }
out.push(g());
console.log(out.join("|"));
"#;
    assert_native_console_output(source, "block|script");
}

#[test]
fn try_catch_and_finally_instantiate_block_functions_on_entry() {
    let source = r#"
var out = [];
try {
  out.push(t());
  label: function t() { return "try"; }
  throw 5;
} catch (error) {
  out.push(c());
  label: function c() { return error + 1; }
} finally {
  out.push(f());
  label: function f() { return "finally"; }
}
function beforeReturn() {
  "use strict";
  try {
    return inside();
    function inside() { return "returned"; }
  } finally {
    out.push(after());
    function after() { return "strict-finally"; }
  }
}
function replaceReturn() {
  try { return "old"; }
  finally {
    return replacement();
    function replacement() { return "replacement"; }
  }
}
out.push(beforeReturn(), replaceReturn());
for (var i = 0; i < 3; i++) {
  try {
    if (i === 0) continue;
    break;
  } finally {
    out.push(cleanup());
    function cleanup() { return i; }
  }
}
try {
  out.push(typeof asyncFn, generatorFn().next().value);
  async function asyncFn() {}
  function* generatorFn() { yield 17; }
} finally {}
console.log(out.join("|"));
"#;
    assert_native_console_output(
        source,
        "try|6|finally|strict-finally|returned|replacement|0|1|function|17",
    );
}

#[test]
fn switch_functions_exist_before_selectors_without_early_var_copies() {
    let source = r#"
function select() {
  var out = [];
  var f = 13;
  var readOuter = function () { return f; };
  switch ((out.push(f), 1)) {
    case (out.push(typeof f, typeof readOuter()), 1):
      out.push(f());
      break;
    default:
      label: function f() { return 7; }
  }
  out.push(typeof f, f);
  return out.join("|");
}
function duplicate() {
  var out = [];
  switch (1) {
    case 1:
      out.push(f());
      function f() { return 1; }
      break;
    case 2:
      label: function f() { return 2; }
  }
  out.push(f());
  return out.join("|");
}
console.log(select());
console.log(duplicate());
"#;
    assert_native_console_output(source, "13|function|number|7|number|13\n2|2");
}

#[test]
fn strict_switch_functions_are_initialized_without_annex_b_leakage() {
    let source = r#"
function run() {
  "use strict";
  var out = [];
  switch (1) {
    case (out.push(typeof f), 1):
      out.push(f());
      break;
    default:
      function f() { return "unreached"; }
  }
  out.push(typeof f);
  return out.join("|");
}
console.log(run());
"#;
    assert_native_console_output(source, "function|unreached|undefined");
}

#[test]
fn labelled_declaration_early_errors_stay_early_errors() {
    for source in [
        "'use strict'; label: function f() {}",
        "function outer() { 'use strict'; label: function f() {} }",
        "label: async function f() {}",
        "label: function* f() {}",
        "if (true) label: function f() {}",
        "while (false) label: function f() {}",
        "first: first: function f() {}",
        "first: { first: function f() {} }",
        "{ let f; label: function f() {} }",
        "label: function f() { break label; }",
    ] {
        let error = console_output(source).expect_err(source);
        assert!(
            error.starts_with("parse:") || error.starts_with("lower:"),
            "declaration error must precede execution: {source}: {error}"
        );
    }
    assert!(
        CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "labelled-module.mjs".into(),
                    text: "label: function f() {}".into(),
                },
                ParseGoal::Module,
                &ParserOptions::default(),
            )
            .is_err(),
        "module code cannot admit a labelled function declaration"
    );
}

#[test]
fn annex_b_arguments_copy_reuses_the_existing_binding() {
    let source = r#"
function run(value) {
  var original = arguments;
  var out = [arguments[0], typeof arguments];
  {
    out.push(arguments());
    label: function arguments() { return "block"; }
  }
  out.push(typeof arguments, arguments === original, arguments());
  return out.join("|");
}
function parameter(arguments) {
  { label: function arguments() { return "block"; } }
  return arguments;
}
console.log(run(11));
console.log(parameter("parameter"));
function arrowScope(value) {
  var original = arguments;
  var skipped = () => {
    if (false) { label: function arguments() {} }
    return typeof arguments;
  };
  var entered = () => {
    { label: function arguments() { return "arrow"; } }
    return arguments();
  };
  return [skipped(), entered(), arguments === original, arguments[0]].join("|");
}
console.log(arrowScope(23));
"#;
    assert_native_console_output(
        source,
        "11|object|block|function|false|block\nparameter\nundefined|arrow|true|23",
    );
}

#[test]
fn labelled_block_functions_shadow_with_properties() {
    let source = r#"
function run() {
  var out = [];
  var object = { f: function () { return "object"; } };
  with (object) {
    {
      out.push(f());
      label: function f() { return "lexical"; }
    }
  }
  out.push(f(), object.f());
  return out.join("|");
}
console.log(run());
"#;
    assert_native_console_output(source, "lexical|lexical|object");
}

#[test]
fn function_declarations_have_empty_completion_values() {
    for (source, expected) in [
        ("function declared() {}", Value::Undefined),
        ("label: function declared() {}", Value::Undefined),
        ("42; { label: function declared() {} }", Value::Int(42)),
        ("42; { function declared() {} }", Value::Int(42)),
        ("42; label: function declared() {}", Value::Int(42)),
        (
            "42; { function* iterator() {} async function task() {} }",
            Value::Int(42),
        ),
    ] {
        for (lane, config) in [
            ("quickjs", InterpreterConfig::quickjs_defaults()),
            ("v8", InterpreterConfig::v8_defaults()),
        ] {
            let (value, _) = evaluate_script_with_config(source, config)
                .unwrap_or_else(|error| panic!("{lane}: {source}: {error}"));
            assert_eq!(value, expected, "{lane}: {source}");
        }
    }
}
