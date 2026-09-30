//! Early errors (ES2020 static semantics) the parser accepted, so the
//! programs ran: parameter lists (duplicates where names must be unique,
//! getter/setter arity, elisions, a rest parameter's position and trailing
//! comma), class names and `let` as lexically bound names, for-in/of
//! declarations with an initializer, strict-mode assignment to `eval` and
//! `arguments`, BigInt literals with a fraction or exponent, escaped
//! keywords, reserved words as shorthand references, `await` in an async
//! arrow's parameters, and text after an arrow function's block body.
//! Test262 sample (2026-09-30) negative tests: statements/class/
//! class-name-ident-let, statements/for-of/head-let-init, statements/for-in/
//! head-let-bound-names-let, statements/function/dflt-params-duplicates,
//! statements/class/getter-param-dflt, expressions/class/method/
//! rest-params-trailing-comma-early-error, expressions/object/
//! identifier-shorthand-implements-invalid-strict-mode, expressions/
//! compound-assignment/lshift-arguments-strict, literals/bigint/
//! exponent-part, identifiers/val-case-via-escape-hex4, expressions/
//! async-arrow-function/early-errors-arrow-await-in-formals(-default),
//! expressions/assignmenttargettype/direct-arrowfunction-1.
//! Every verdict is Node v22.2.0's (`node --check`) for the same text.

use frankenengine_engine::parser_api_stability::parse_script;

/// (program, a fragment of the engine's error for it)
const REJECTED: &[(&str, &str)] = &[
    ("class let {}", "reserved word here"),
    (
        "var C = class eval {};",
        "cannot be a binding name in strict mode",
    ),
    ("function* g() { class yield {} }", "reserved word here"),
    ("for (let x = 1 of []) {}", "may not have an initializer"),
    ("for (var x = 1 of []) {}", "may not have an initializer"),
    ("for (let x = 1 in {}) {}", "may not have an initializer"),
    (
        "'use strict'; for (var x = 1 in {}) {}",
        "may not have an initializer",
    ),
    ("for (var [a] = 1 in {}) {}", "may not have an initializer"),
    ("for (let let in {}) {}", "`let` is disallowed"),
    ("let let = 1;", "`let` is disallowed"),
    ("const [let] = [];", "`let` is disallowed"),
    ("function f(x = 0, x) {}", "duplicate parameter name"),
    (
        "'use strict'; function f(a, a) {}",
        "duplicate parameter name",
    ),
    (
        "function f(a, a) { 'use strict'; }",
        "duplicate parameter name",
    ),
    ("var g = (a, a) => 1;", "duplicate parameter name"),
    ("var o = { m(a, a) {} };", "duplicate parameter name"),
    ("class C { m(a, a) {} }", "duplicate parameter name"),
    ("function f([a], a) {}", "duplicate parameter name"),
    ("class C { get a(p) {} }", "getter must not have parameters"),
    (
        "class C { get a(param = null) {} }",
        "getter must not have parameters",
    ),
    (
        "var o = { get a(x) { return 1; } };",
        "getter must not have parameters",
    ),
    (
        "var o = { set a(...p) {} };",
        "setter must have exactly one",
    ),
    ("var o = { set a() {} };", "setter must have exactly one"),
    ("class C { set a(p, q) {} }", "setter must have exactly one"),
    ("function f(...a,) {}", "may not have a trailing comma"),
    (
        "0, class { method(...a,) {} };",
        "may not have a trailing comma",
    ),
    ("var f = (a,,b) => 1;", "empty parameter"),
    ("function f(,a) {}", "empty parameter"),
    ("function f(...a, b) {}", "rest parameter must be last"),
    (
        "'use strict'; arguments <<= 20;",
        "cannot be assigned in strict mode",
    ),
    (
        "'use strict'; eval = 1;",
        "cannot be assigned in strict mode",
    ),
    (
        "'use strict'; arguments++;",
        "cannot be assigned in strict mode",
    ),
    ("'use strict'; --eval;", "cannot be assigned in strict mode"),
    ("0e0n;", "invalid BigInt literal"),
    ("1.5n;", "invalid BigInt literal"),
    (".5n;", "invalid BigInt literal"),
    ("'use strict'; ({ implements });", "cannot be referenced"),
    ("({ if });", "cannot be referenced"),
    (
        "async function f() { ({ await }); }",
        "cannot be referenced",
    ),
    ("var af = async (await) => {};", "reserved word here"),
    ("var af = async await => 1;", "reserved word here"),
    ("'use strict'; var af = yield => 1;", "reserved word here"),
    ("() => {} = 1;", "after an arrow function body"),
    ("async () => {} = 1;", "after an arrow function body"),
    ("var x = (() => {}.x);", "after an arrow function body"),
];

const ACCEPTED: &[&str] = &[
    "function f(a, a) { return a; }",
    "for (var x = 1 in {}) {}",
    "var f = (a, b,) => a;",
    "function f(a, b,) {}",
    "class C { get a() { return 1; } set a(v) {} }",
    "var o = { get a() { return 1; }, set a([v]) {} };",
    "var implements = 1; ({ implements });",
    "var let = 1; var o = { let };",
    "var yield = 1; ({ yield });",
    "var x = 1n, y = 0x1Fn, z = 1_000n;",
    "var e = 1e3, g = .5;",
    "let a = 1; const b = 2;",
    "class await {}",
    "var f = async x => x, g = async (a, b) => a;",
    "var h = (x) => { return x; };",
    "var i = [() => {}, 1];",
    "var c, j = c ? () => {} : 0;",
    "(() => {})();",
    "'use strict'; var o = {}; o.eval = 2; o.arguments = 3;",
    "for (const x of [1]) {}",
    "function g2(a, b = a, ...rest) {}",
    "var asyncFn = async function (a, b) {};",
];

#[test]
fn early_errors_reject_the_programs_node_rejects() {
    let mut accepted = Vec::new();
    for (source, fragment) in REJECTED {
        match parse_script(source) {
            Ok(_) => accepted.push(format!("{source}: parsed")),
            Err(error) if !error.to_string().contains(fragment) => {
                accepted.push(format!("{source}: rejected for another reason: {error}"));
            }
            Err(_) => {}
        }
    }
    assert!(
        accepted.is_empty(),
        "Node rejects each of these with an early error:\n{}",
        accepted.join("\n")
    );
}

#[test]
fn nearby_valid_programs_still_parse() {
    let failures: Vec<String> = ACCEPTED
        .iter()
        .filter_map(|source| {
            parse_script(source)
                .err()
                .map(|error| format!("{source}: {error}"))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "Node parses each of these:\n{}",
        failures.join("\n")
    );
}

/// `await` with no operand in an async arrow's parameter default is a
/// SyntaxError (the parameters reserve `await`).
#[test]
fn await_in_async_arrow_parameters_is_rejected() {
    assert!(parse_script("var af = async (x = await) => {};").is_err());
}

/// Escaped spellings are built from char 92 so the source text really holds
/// the escape (u0063 for `c`, u0065 for `e`): an escaped `case` is still the
/// keyword, an escaped `let` is still reserved as a class name, and an
/// escaped ordinary name stays valid.
#[test]
fn escaped_keywords_are_still_keywords() {
    let backslash = char::from(92);
    let case_keyword = format!("var {backslash}u0063ase = 123;");
    let error = parse_script(&case_keyword).expect_err("Node rejects an escaped `case`");
    assert!(
        error
            .to_string()
            .contains("must not contain escaped characters"),
        "{case_keyword}: {error}"
    );
    let class_let = format!("class l{backslash}u0065t {{}}");
    let error = parse_script(&class_let).expect_err("Node rejects an escaped `let`");
    assert!(
        error.to_string().contains("reserved word here"),
        "{class_let}: {error}"
    );
    for valid in [
        format!("var {backslash}u0061b = 1;"),
        format!("class {backslash}u0061 {{}}"),
    ] {
        parse_script(&valid).unwrap_or_else(|error| panic!("{valid} must parse: {error}"));
    }
}
