//! bd-9vouw.135: the Function constructor's syntax and early errors are
//! SyntaxErrors the caller can catch (ES2020 19.2.1.1.1 CreateDynamicFunction
//! steps 18-20).
//!
//! `try { new Function('break') } catch (e) {}` aborted the whole program
//! ("failed to lower module '<function-constructor>'"). PROGRAM builds
//! functions whose bodies are early errors (`break` and `continue` outside a
//! loop, an undefined label, a duplicate `let`, a strict `with`) and two
//! valid ones, and the program keeps running after them. NODE_OUTPUT is Node
//! v22.2.0's output.
//!
//! No-claim: syntax the parser files under UnsupportedSyntax still aborts,
//! because that code also covers syntax the engine does not support.
//! Examples are duplicate strict parameters and `new Function('{')`.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

const PROGRAM: &str = r#"for (const source of ['break', 'continue', 'L: { break M; }', 'let a; let a;', '"use strict"; with ({}) {}', 'return 1', 'var b = 2; return b;']) {
  try { const f = new Function(source); console.log(JSON.stringify(source), 'ok', f()); } catch (e) { console.log(JSON.stringify(source), e.constructor.name, e instanceof SyntaxError); }
}
console.log('after');"#;

const NODE_OUTPUT: &str = r#""break" SyntaxError true
"continue" SyntaxError true
"L: { break M; }" SyntaxError true
"let a; let a;" SyntaxError true
"\"use strict\"; with ({}) {}" SyntaxError true
"return 1" ok 1
"var b = 2; return b;" ok 2
after"#;

#[test]
fn function_constructor_early_errors_are_catchable_syntax_errors() {
    let mut engine = HybridRouter::default();
    let outcome = engine.eval(PROGRAM).expect("the program runs to the end");
    let output = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n");
    for (index, (actual, expected)) in output.lines().zip(NODE_OUTPUT.lines()).enumerate() {
        assert_eq!(actual, expected, "line {}", index + 1);
    }
    assert_eq!(output.lines().count(), NODE_OUTPUT.lines().count());
}
