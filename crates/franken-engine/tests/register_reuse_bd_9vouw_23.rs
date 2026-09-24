//! bd-9vouw.23: program size no longer runs a frame out of registers.
//!
//! IR2->IR3 lowering gave every temporary a fresh register and never reused
//! one, and every binding held a register for the whole body, so 300
//! expression statements or ~200 top-level `let`s failed at runtime with
//! "register 256 out of bounds (max 256)". Temporaries are now reused at
//! statement boundaries and root-scope lexical bindings beyond a budget live in
//! the runtime scope. Expected strings are what Node v22.2.0 prints for the
//! same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path, plus
//! the real lowering pipeline for the register high-water assertion.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::QuickJsLane;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(name: &str, source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "{name} must match Node v22.2.0"
    );
}

/// The fixed-width lane (256 registers, as `frankenctl run` executes):
/// `HybridRouter::eval` sizes its frame to the program, so only this path
/// proves register reuse and binding spill actually keep programs in bounds.
fn fixed_lane_value(source: &str) -> String {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "register_reuse_bd_9vouw_23.js");
    let context = LoweringContext::new("rr-trace", "rr-decision", "rr-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    match QuickJsLane::new().execute(&module, "rr-trace") {
        Ok(result) => result.value.to_string(),
        Err(err) => format!("ERROR: {err}"),
    }
}

fn main_frame_size(source: &str) -> u32 {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "register_reuse_bd_9vouw_23.js");
    let context = LoweringContext::new("rr-trace", "rr-decision", "rr-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    module.function_table[0].frame_size
}

#[test]
fn many_expression_statements_run() {
    let source = format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(300));
    check("300 top-level statements", &source, "300");
    let source = format!(
        "function f() {{ let t = 0;\n{}return t; }} f();",
        "t = t + 1;\n".repeat(400)
    );
    check("400 statements in a function body", &source, "400");
}

#[test]
fn many_top_level_lets_run() {
    let lets: String = (0..5000).map(|i| format!("let v{i} = {i};\n")).collect();
    check("5000 top-level lets", &format!("{lets}v0 + v4999;"), "4999");
}

#[test]
fn many_top_level_vars_run_and_stay_hoisted() {
    let vars: String = (0..300).map(|i| format!("var w{i} = {i};\n")).collect();
    check("300 top-level vars", &format!("{vars}w0 + w299;"), "299");
    // A `var` past the register budget is still hoisted: read before its
    // declaration it is undefined, not a ReferenceError.
    let vars: String = (0..200).map(|i| format!("var w{i} = {i};\n")).collect();
    check(
        "hoisted spilled var",
        &format!("{vars}var r = typeof late; var late = 5; r + ':' + late;"),
        "undefined:5",
    );
}

#[test]
fn many_try_catch_statements_run() {
    let source = format!(
        "let r;\n{}r;",
        "try { r = typeof X; } catch (e) { r = 'THROW'; }\n".repeat(1000)
    );
    check("1000 try/catch statements", &source, "undefined");
}

#[test]
fn spilled_lexical_bindings_keep_their_semantics() {
    let lets: String = (0..200).map(|i| format!("let v{i} = {i};\n")).collect();
    // A closure over a binding past the register budget sees later writes.
    check(
        "closure over spilled let",
        &format!("{lets}let cap = 5; const g = () => cap; cap = 6; g() + ':' + v199;"),
        "6:199",
    );
    // A spilled binding read before its declaration is still in its TDZ.
    check(
        "TDZ of spilled let",
        &format!(
            "{lets}let r = 'none'; try {{ late; }} catch (e) {{ r = e.name; }} let late = 1; r + ':' + late;"
        ),
        "ReferenceError:1",
    );
}

#[test]
fn register_high_water_does_not_grow_with_statement_count() {
    let small = main_frame_size(&format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(10)));
    let large = main_frame_size(&format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(1000)));
    assert_eq!(
        small, large,
        "independent statements must reuse temporaries (frame {small} vs {large})"
    );
}

#[test]
fn large_programs_fit_the_fixed_256_register_lane() {
    let statements = format!("let x = 0;\n{}x;", "x = x + 1;\n".repeat(300));
    assert_eq!(fixed_lane_value(&statements), "300");
    let lets: String = (0..300).map(|i| format!("let v{i} = {i};\n")).collect();
    assert_eq!(fixed_lane_value(&format!("{lets}v0 + v299;")), "299");
    let vars: String = (0..300).map(|i| format!("var w{i} = {i};\n")).collect();
    assert_eq!(fixed_lane_value(&format!("{vars}w0 + w299;")), "299");
}

#[test]
fn bindings_read_before_their_first_write_never_see_stale_temporaries() {
    // A binding register must not have held an earlier statement's rewound
    // temporary: a hoisted `var` read before assignment is undefined.
    check(
        "hoisted var after rewound temporaries",
        "function f() { var a = [1, 2, 3].map(x => x * 2).join(); \
         var r = typeof late; var late = 5; return r + ':' + a; } f();",
        "undefined:2,4,6",
    );
    check(
        "hoisted var after a block temporary",
        "function g() { var s = 'x' + 'y'; { let inner = s + 'z'; } \
         var r = typeof later; var later = 1; return r; } g();",
        "undefined",
    );
}
