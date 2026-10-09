//! bd-9vouw.402: no ASI before a same-line `else`, a line break after
//! `throw`, an unterminated `/*`, `#!` starting a nested body, strict
//! `eval`/`arguments` destructuring targets, a parenthesized literal target
//! and `[...x,]` are catchable SyntaxErrors through Function(); valid
//! look-alikes run. Expected lines are Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn statement_and_target_early_errors_are_syntax_errors() {
    let source = r#"
var out = [];
function t(name, src) {
  try { Function(src); out.push(name + ":ok"); } catch (e) { out.push(name + "!" + e.name); }
}
t("throw-newline", "throw\n1;");
t("throw-empty", "throw;");
t("unterminated-comment", "/*CHECK#1/");
t("hashbang-in-body", "function fn() {#!\n}");
t("hashbang-in-block", "{\n#!\n}");
t("strict-array-arguments", "'use strict'; [arguments] = [];");
t("strict-object-eval", "'use strict'; ({ eval } = {});");
t("parenthesized-object-target", "({}) = 1;");
t("arrow-target", "() => ({}) = 1;");
t("parenthesized-array-target", "var a; ([a]) = [1];");
t("for-in-rest-comma", "var x; for ([...x,] in [[]]) ;");
t("var-rest-comma", "var [...x,] = [];");
t("lone-increment", "++;");
t("lone-decrement", "--;");
t("postfix-after-newline", "var x = 0;\nx\n++;");
console.log(out.join(" | "));
var ok = [];
function v(name, src) {
  try { ok.push(name + "=" + Function(src)()); } catch (e) { ok.push(name + "!" + e.name); }
}
v("else-next-line", "var x; if (false) x = 1\nelse x = 2; return x;");
v("else-after-semicolon", "var x; if (false) x = 1; else x = 3; return x;");
v("do-while-before-else", "var r = 'a'; if (true) do r += 'b'; while (false) else r = 'c'; return r;");
v("throw-same-line", "try { throw 4; } catch (e) { return e; }");
v("closed-comment", "/* ok */ return 5;");
v("parenthesized-name-target", "var a; (a) = 6; return a;");
v("member-of-literal-target", "({}).x = 1; return 7;");
v("strict-default-reads-arguments", "'use strict'; var x; [x = arguments.length] = []; return x;");
v("rest-last", "for (var [a, ...b] of [[1, 2, 3]]) return a + ':' + b;");
v("trailing-comma-no-rest", "var [p, q,] = [8, 9]; return p + q;");
console.log(ok.join(" | "));
var out3 = [];
function v3(name, src) {
  try { out3.push(name + "=" + Function(src)()); } catch (e) { out3.push(name + "!" + e.name); }
}
v3("template-then-newline-else", "var x; if (false) x = `a`\nelse x = 'b'; return x;");
v3("regex-then-newline-else", "var x; if (false) x = /a/\nelse x = 'r'; return x;");
v3("call-semicolon-else", "var x; function f(){ return 1; } if (true) x = f(); else x = 2; return x;");
v3("nested-if-else", "var x = 0; if (true) if (false) x = 1; else x = 2; return x;");
v3("block-else", "var x; if (false) { x = 1 } else x = 3; return x;");
v3("empty-consequent-else", "var x = 0; if (false) ; else x = 4; return x;");
v3("comment-newline-else", "var x; if (false) x = 1 // c\nelse x = 5; return x;");
v3("block-comment-newline-else", "var x; if (false) x = 1 /*\n*/ else x = 6; return x;");
v3("arrow-block-semicolon-else", "var x; if (false) x = () => {}; else x = 7; return x;");
console.log(out3.join(" | "));
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
            "throw-newline!SyntaxError | throw-empty!SyntaxError | unterminated-comment!SyntaxError | hashbang-in-body!SyntaxError | hashbang-in-block!SyntaxError | strict-array-arguments!SyntaxError | strict-object-eval!SyntaxError | parenthesized-object-target!SyntaxError | arrow-target!SyntaxError | parenthesized-array-target!SyntaxError | for-in-rest-comma!SyntaxError | var-rest-comma!SyntaxError | lone-increment!SyntaxError | lone-decrement!SyntaxError | postfix-after-newline!SyntaxError",
            "else-next-line=2 | else-after-semicolon=3 | do-while-before-else=ab | throw-same-line=4 | closed-comment=5 | parenthesized-name-target=6 | member-of-literal-target=7 | strict-default-reads-arguments=0 | rest-last=1:2,3 | trailing-comma-no-rest=17",
            "template-then-newline-else=b | regex-then-newline-else=r | call-semicolon-else=1 | nested-if-else=2 | block-else=3 | empty-consequent-else=4 | comment-newline-else=5 | block-comment-newline-else=6 | arrow-block-semicolon-else=7",
        ]
    );
}
