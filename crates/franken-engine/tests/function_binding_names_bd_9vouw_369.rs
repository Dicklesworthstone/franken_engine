//! bd-9vouw.369: a function's name is a BindingIdentifier (ES2020 14.1.2,
//! 14.4.1, 14.7.1). It was taken as raw source text: a name spelled with a
//! unicode escape bound the escape text, so a later escaped declaration did
//! not replace an earlier one (Test262 statements/function/S14_A5_T1,
//! S14_A5_T2), could not be called by its decoded name, and a function
//! expression's own name was unbound inside its body. Names that are not
//! identifiers, reserved words (escaped or not), strict-mode reserved
//! words, and yield/await where the grammar reserves them were accepted;
//! Function() now throws a SyntaxError for each, as Node does. The line is
//! Node v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn escaped_and_reserved_function_names_follow_the_binding_identifier_rules() {
    let source = r#"
var out = [];
out.push("pre " + ab());
function ab() { return "ascii"; }
function a\u0062() { return "escaped"; }
out.push("post " + ab());
function \u0063d() { return "cd"; }
out.push(typeof cd + ":" + cd());
var f = function g\u0068() { return typeof gh; };
out.push(f() + ":" + f.name);
function attempt(src) { try { Function(src); return "accepted"; } catch (e) { return e.constructor.name; } }
var rejected = ["function if(){}", "function \\u0069f(){}", "function a b(){}", "function 1a(){}", "\"use strict\"; function yield(){}", "function static(){ \"use strict\"; }", "function* g(){ function yield(){} }", "(function* yield(){})", "(async function await(){})"];
out.push(rejected.map(attempt).join(","));
var accepted = ["function let(){}", "(function yield(){})", "async function await(){}", "function* g(){ (function yield(){}); }", "function \\u0061b(){}"];
out.push(accepted.map(attempt).join(","));
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
            "pre escaped | post escaped | function:cd | function:gh | SyntaxError,SyntaxError,SyntaxError,SyntaxError,SyntaxError,SyntaxError,SyntaxError,SyntaxError,SyntaxError | accepted,accepted,accepted,accepted,accepted",
        ]
    );
}

/// The same rules in a whole program (the parser's early errors), with the
/// engine's message for each. Escaped spellings are built from char 92 so
/// the source really holds the escape: u0069 is `i`, u0065 is `e`, u0062
/// is `b`. Every verdict is Node v22.2.0's (`node --check`).
#[test]
fn function_names_are_binding_identifiers_in_whole_programs() {
    use frankenengine_engine::parser_api_stability::parse_script;

    let backslash = char::from(92);
    let rejected = [
        ("function if(){}".to_string(), "reserved word"),
        ("function 1a(){}".to_string(), "invalid function name"),
        ("function a b(){}".to_string(), "invalid function name"),
        ("(function if(){});".to_string(), "reserved word"),
        (
            format!("function {backslash}u0069f(){{}}"),
            "must not contain escaped characters",
        ),
        (
            format!("function a{backslash}x62(){{}}"),
            "invalid function name",
        ),
        (
            "'use strict'; function yield(){}".to_string(),
            "reserved word here",
        ),
        (
            "function static(){ 'use strict'; }".to_string(),
            "reserved word here",
        ),
        (
            format!("'use strict'; function {backslash}u0065val(){{}}"),
            "cannot be a binding name in strict mode",
        ),
        (
            "function* g(){ function yield(){} }".to_string(),
            "reserved word here",
        ),
        (
            "async function f(){ function await(){} }".to_string(),
            "reserved word here",
        ),
        ("(function* yield(){});".to_string(), "reserved word here"),
        (
            "(async function await(){});".to_string(),
            "reserved word here",
        ),
    ];
    for (program, fragment) in &rejected {
        let error = parse_script(program).expect_err("Node rejects this program");
        assert!(error.to_string().contains(fragment), "{program}: {error}");
    }
    for program in [
        "function let(){}".to_string(),
        "async function await(){}".to_string(),
        "(function yield(){});".to_string(),
        "function* g(){ (function yield(){}); }".to_string(),
        format!("function a{backslash}u0062(){{}}"),
    ] {
        parse_script(&program).unwrap_or_else(|error| panic!("{program} must parse: {error}"));
    }
}
