//! bd-9vouw.331: a named function expression's own name is an immutable
//! binding created with strict = false (ES2020 14.1.22 step 4): sloppy
//! code's assignment to it (plain, compound, `++`, in a generator) is
//! ignored and yields the assigned value; strict code's throws; a
//! declaration's name and a shadowing var or parameter stay writable. The
//! sloppy forms threw a TypeError (the run-once idiom `var init = function
//! init() { init = null; ... }` crashed). Assignments from a nested arrow
//! are not covered here. The line is Node v22.2.0's output for the same
//! program.

use frankenengine_engine::HybridRouter;

#[test]
fn sloppy_assignment_to_a_function_expression_name_is_ignored() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + "=" + f()); } catch (e) { out.push(name + "!" + e.constructor.name); } }
t("sloppy", function () { return (function f() { f = 1; return typeof f; })(); });
t("result", function () { return (function f() { return (f = 7); })(); });
t("run-once", function () { var calls = 0; var init = function init() { init = null; calls++; return calls; }; init(); return init === null ? "replaced" : typeof init; });
t("compound", function () { return (function f() { f += 1; f++; return typeof f; })(); });
t("generator", function () { var g = function* gen() { gen = 0; yield typeof gen; }; return g().next().value; });
t("strict-throws", function () { return (function f() { "use strict"; f = 1; return "no"; })(); });
t("declaration", function () { function d() { d = 2; return typeof d; } return d() + ":" + typeof d; });
t("shadow-var", function () { return (function f() { var f = 4; f = 5; return f; })(); });
t("shadow-param", function () { return (function f(f) { f = 6; return f; })(0); });
console.log(out.join(" | "));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "sloppy=function | result=7 | run-once=function | compound=function | generator=function | strict-throws!TypeError | declaration=number:number | shadow-var=5 | shadow-param=6",
        ]
    );
}
