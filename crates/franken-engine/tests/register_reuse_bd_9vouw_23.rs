//! bd-9vouw.23: program size no longer runs a frame out of registers.
//!
//! IR2->IR3 lowering gave every temporary a fresh register and never reused
//! one, and every binding held a register for the whole body, so 300
//! expression statements or ~200 top-level `let`s failed at runtime with
//! "register 256 out of bounds (max 256)". Temporaries are now reused at
//! statement boundaries. Root-scope bindings (functions included) and
//! function-body locals beyond a budget live in the runtime scope. Name-status
//! slots are released by their put. Expected strings are what Node v22.2.0
//! prints for the same programs.
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

fn top_level_vars(count: usize) -> String {
    (0..count).map(|i| format!("var w{i} = {i};\n")).collect()
}

#[test]
fn function_declarations_past_the_root_budget_are_callable() {
    // A function declared after the register-resident root budget used to
    // pin a register and never reach its runtime-scope binding, so `typeof
    // add` was "undefined" and every call threw.
    let source = format!(
        "{}function add(a, b) {{ return a + b; }}\n\
         typeof add + ':' + add(2, 3) + ':' + w0 + ':' + w199;",
        top_level_vars(200)
    );
    assert_eq!(fixed_lane_value(&source), "function:5:0:199");
    // Each such declaration also cost a whole register: 300 top-level
    // functions overflowed the 256-register frame.
    let functions: String = (0..300)
        .map(|i| format!("function f{i}() {{ return {i}; }}\n"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!("{functions}f0() + f299();")),
        "299"
    );
}

#[test]
fn large_function_bodies_fit_the_fixed_256_register_lane() {
    // Bundler output wraps a whole program in one function. Its locals used
    // to pin one register each for the whole body.
    let vars = top_level_vars(300);
    assert_eq!(
        fixed_lane_value(&format!("(function () {{\n{vars}return w0 + w299; }})();")),
        "299"
    );
    // Each function captures its predecessor, so all 300 declarations are
    // scope-routed; each used to pin a register too. (No deep recursion: the
    // lane's call depth is capped at 256.)
    let chain: String = (1..300)
        .map(|i| {
            format!(
                "function f{i}() {{ return typeof f{} === 'function' ? {i} : -1; }}\n",
                i - 1
            )
        })
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\nfunction f0() {{ return 0; }}\n{chain}return f1() + f299(); }})();"
        )),
        "300"
    );
}

#[test]
fn spilled_function_locals_keep_their_semantics() {
    let vars = top_level_vars(200);
    // Still hoisted: read before its declaration a spilled `var` is undefined.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var r = typeof late;\n{vars}var late = 5; return r + ':' + late; }})();"
        )),
        "undefined:5"
    );
    // Loop counters and compound assignment past the budget.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{vars}var acc = 0; for (var i = 0; i < 10; i++) acc += i; return acc; }})();"
        )),
        "45"
    );
    // A closure over a local past the budget sees later writes.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{vars}var cap = 1; var g = function () {{ return cap; }}; cap = 2; return g(); }})();"
        )),
        "2"
    );
    // A spilled function declaration is hoisted above its first call.
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{vars}return late(); function late() {{ return 'hoisted'; }} }})();"
        )),
        "hoisted"
    );
}

#[test]
fn assignments_to_undeclared_names_release_their_status_registers() {
    // The pre-RHS resolution status of `name = value` for an undeclared name
    // used to hold a register for the rest of the body.
    let globals: String = (0..300).map(|i| format!("ig{i} = {i};\n")).collect();
    assert_eq!(fixed_lane_value(&format!("{globals}ig0 + ig299;")), "299");
    let globals: String = (0..300).map(|i| format!("jg{i} = {i};\n")).collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{\n{globals}return jg0 + jg299; }})();"
        )),
        "299"
    );
    // A statement boundary inside the RHS (a comma expression) must not
    // reclaim the live status register.
    assert_eq!(
        fixed_lane_value("var side = 0; zz = (side++, side++, side + 40); zz + side;"),
        "44"
    );
}

fn array_literal(count: usize) -> String {
    let elements: Vec<String> = (0..count).map(|i| i.to_string()).collect();
    format!("[{}]", elements.join(", "))
}

fn object_literal(count: usize) -> String {
    let entries: Vec<String> = (0..count).map(|i| format!("k{i}: {i}")).collect();
    format!("{{{}}}", entries.join(", "))
}

#[test]
fn large_literals_fit_the_fixed_256_register_lane() {
    // A literal held one register per element (two per object entry) until
    // it was built, so data tables with hundreds of entries overflowed the
    // frame. Test262's generated RegExp property-escape tests hit this too.
    // Past 64 entries, literals build one entry at a time and reuse each
    // entry's registers.
    assert_eq!(
        fixed_lane_value(&format!(
            "var a = {}; a.length + a[299];",
            array_literal(300)
        )),
        "599"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "var o = {}; var n = 0, first, last; \
             for (var k in o) {{ if (n === 0) first = k; last = k; n++; }} \
             n + o.k299 + ':' + first + ':' + last;",
            object_literal(300)
        )),
        "599:k0:k299"
    );
    let rows: Vec<String> = (0..100)
        .map(|i| format!("{{a: {i}, b: [{i}, {i}], c: 'x'}}"))
        .collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "var rows = [{}]; var t = 0; for (var i = 0; i < rows.length; i++) \
             t += rows[i].a + rows[i].b[1]; t + ':' + rows.length;",
            rows.join(", ")
        )),
        "9900:100"
    );
    let calls: Vec<String> = (0..300).map(|i| format!("f({i})")).collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "function f(x) {{ return x * 2; }} var a = [{}]; a[299] + a[0] + a.length;",
            calls.join(", ")
        )),
        "898"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "function sum(xs) {{ var t = 0; for (var i = 0; i < xs.length; i++) t += xs[i]; \
             return t; }} sum({});",
            array_literal(300)
        )),
        "44850"
    );
    assert_eq!(
        fixed_lane_value(&format!(
            "(function () {{ var a = {}; var o = {}; return a[150] + o.k150; }})();",
            array_literal(300),
            object_literal(300)
        )),
        "300"
    );
    // A literal `__proto__:` entry sets the prototype; such literals stay on
    // the batch path, which implements that.
    let entries: Vec<String> = (0..100).map(|i| format!("k{i}: {i}")).collect();
    assert_eq!(
        fixed_lane_value(&format!(
            "var p = {{ z: 1 }}; var o = {{__proto__: p, {}}}; \
             var n = 0; for (var k in o) n++; o.z + ':' + n + ':' + o.k99;",
            entries.join(", ")
        )),
        "1:101:99"
    );
}
