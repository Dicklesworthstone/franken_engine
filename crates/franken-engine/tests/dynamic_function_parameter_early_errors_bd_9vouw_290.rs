//! bd-9vouw.290 follow-up: `await` or `yield` in a parameter list and a
//! private name no enclosing class declares are early errors (ES2020
//! "It is a Syntax Error if FormalParameters Contains AwaitExpression /
//! YieldExpression"; ES2022 AllPrivateIdentifiersValid). The parser reported
//! them under UnsupportedSyntax, which dynamic compilation keeps as an
//! uncatchable refusal, so GeneratorFunction('a = yield', ''),
//! AsyncFunction('a = await 1', ''), AsyncGeneratorFunction('x = await 42',
//! '') and Function('this.#x') aborted the program after InvalidSyntax made
//! the other early errors catchable. They are InvalidSyntax now; the
//! controls (await and yield in the body, a declared private name) still
//! construct. The line is Node v22.2.0's (Bun 1.4.2 agrees).

use frankenengine_engine::HybridRouter;

#[test]
fn parameter_await_yield_and_undeclared_private_names_are_syntax_errors() {
    let source = r#"
var GeneratorFunction = Object.getPrototypeOf(function* () {}).constructor;
var AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
var AsyncGeneratorFunction = Object.getPrototypeOf(async function* () {}).constructor;
var cases = [
  [Function, '', 'this.#x;'],
  [GeneratorFunction, 'a = yield', ''],
  [AsyncFunction, 'a = await 1', ''],
  [AsyncGeneratorFunction, 'x = await 42', ''],
  [AsyncGeneratorFunction, 'x = yield', ''],
  [AsyncGeneratorFunction, 'x = 42', 'yield x; await x;'],
  [GeneratorFunction, 'a', 'yield a;'],
  [Function, '', 'class C { #x = 1; m() { return this.#x; } } return new C().m();'],
];
var out = [];
for (var i = 0; i < cases.length; i++) {
  try { var f = cases[i][0](cases[i][1], cases[i][2]); out.push(i + ':' + typeof f); }
  catch (e) { out.push(i + ':' + e.constructor.name); }
}
console.log(out.join(' '));
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
            "0:SyntaxError 1:SyntaxError 2:SyntaxError 3:SyntaxError 4:SyntaxError 5:function 6:function 7:function"
        ]
    );
}
