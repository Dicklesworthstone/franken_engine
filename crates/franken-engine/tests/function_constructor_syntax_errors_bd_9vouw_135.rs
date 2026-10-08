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
//! bd-9vouw.290: recognized grammar and early errors have an InvalidSyntax
//! diagnostic, so generated code can reject invalid bindings, parameters and
//! incomplete expressions without aborting its caller. Unsupported parser
//! features and resource refusals remain distinct from proven-invalid source.

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

#[test]
fn generated_function_invalid_bindings_and_expressions_are_catchable() {
    let source = r#"
        const invalid = [
            'let let = 1',
            '"use strict"; var eval = 1',
            '"use strict"; var arguments = 1',
            '"use strict"; var implements = 1',
            'var null = 1',
            'return 1 +* 2',
            'x = ',
            'x += ',
            'return )',
            'a => a +',
            'class { }',
            'const missing',
            'var x =',
            '"use strict"; eval = 1',
            '"use strict"; arguments++',
            'if (true) let x = 1',
            'return { get x(a) {} }',
            'return { set x() {} }'
        ];
        const results = [];
        for (const body of invalid) {
            try {
                new Function(body);
                results.push('accepted');
            } catch (error) {
                results.push(error.name + ':' + (error instanceof SyntaxError));
            }
        }
        results.push(new Function('return 6 * 7')());
        results.join('|');
    "#;
    let expected = std::iter::repeat_n("SyntaxError:true", 18)
        .chain(std::iter::once("42"))
        .collect::<Vec<_>>()
        .join("|");
    assert_eq!(
        HybridRouter::default().eval(source).unwrap().value,
        expected
    );
}

#[test]
fn generated_function_parameter_early_errors_preserve_valid_sloppy_forms() {
    let source = r#"
        function attempt(parts) {
            try {
                Function.apply(null, parts);
                return 'accepted';
            } catch (error) {
                return error.name + ':' + (error instanceof SyntaxError);
            }
        }
        [
            attempt(['a,a', '"use strict"; return a']),
            attempt(['a=1', '"use strict"; return a']),
            attempt(['...args', '"use strict"; return args']),
            attempt(['a,,b', 'return a']),
            attempt(['...args,b', 'return b']),
            attempt(['...args,', 'return args']),
            attempt(['...args=[]', 'return args']),
            attempt(['eval', '"use strict"; return eval']),
            attempt(['arguments', '"use strict"; return arguments']),
            attempt(['a=1,a', 'return a']),
            Function('a,a', 'return a')(1,2),
            Function('a=3', 'return a')(),
            Function('return typeof class {}')(),
            Function('return /[(){}=+]/.test("=")')(),
            Function('return 1e-3 + 2e+3')(),
            Function('return ({in: 42}). in')(),
            Function('return ({instanceof: 43}). instanceof')(),
            Function('return ({in: 44}).\u00a0in')(),
            Function('var αin=45; return αin')(),
            Function('var αinstanceof=46; return αinstanceof')(),
            Function('for (class {}; false;) {} return 47')(),
            Function('for (class extends Object {}; false;) {} return 48')(),
            Function('for (function () {}; false;) {} return 49')()
        ].join('|');
    "#;
    let expected = std::iter::repeat_n("SyntaxError:true", 10)
        .chain([
            "2", "3", "function", "true", "2000.001", "42", "43", "44", "45", "46", "47", "48",
            "49",
        ])
        .collect::<Vec<_>>()
        .join("|");
    assert_eq!(
        HybridRouter::default().eval(source).unwrap().value,
        expected
    );
}
