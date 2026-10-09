//! bd-9vouw.408: in non-strict code a call is an assignment target for
//! `=`, the arithmetic and bitwise compound operators and `++` / `--`
//! (Annex B, function calls as assignment targets): the program parses,
//! and evaluating the assignment calls the function and then throws a
//! ReferenceError before the value is evaluated. Logical assignment, a
//! destructuring pattern and a tagged template call stay SyntaxErrors. The
//! engine refused every such program at parse time. Strict code keeps the
//! early SyntaxError the specification requires; V8 accepts it there, so it
//! is not part of these Node-derived lines (Test262's strict
//! direct-callexpression negatives cover it). The lines are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

#[test]
fn non_strict_call_targets_throw_reference_errors_when_evaluated() {
    let source = r#"
var log = [];
function f() { log.push("f"); return { valueOf: function () { log.push("valueOf"); return 1; } }; }
function g() { log.push("g"); return 1; }
function async() { log.push("async"); }
function t(name, fn) {
  try { fn(); log.push(name + ":no-throw"); } catch (e) { log.push(name + ":" + e.name); }
}
t("assign", function () { f() = g(); });
t("compound", function () { f() += g(); });
t("shift", function () { f() <<= g(); });
t("postfix", function () { f()++; });
t("prefix", function () { --f(); });
t("cover", function () { async() = 1; });
console.log(log.join(" "));
log = [];
try { f() = g(); } catch (e) { log.push("top:" + e.name); }
log.push(0 ? (f() = g()) : "skipped");
console.log(log.join(" "));
var r = [];
["f() &&= 1;", "f() ||= 1;", "f() ??= 1;", "[f()] = [1];", "({ a: f() } = {});",
 "f()`` = 1;", "(f``) = 1;", "f``++;", "f() = 1;", "f()--;", "(f()) = 1;"].forEach(function (s) {
  try { Function(s); r.push("ok"); } catch (e) { r.push(e.name); }
});
console.log(r.join(" "));
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
            "f assign:ReferenceError f compound:ReferenceError f shift:ReferenceError f postfix:ReferenceError f prefix:ReferenceError async cover:ReferenceError",
            "f top:ReferenceError skipped",
            "SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError SyntaxError ok ok ok",
        ]
    );
}
