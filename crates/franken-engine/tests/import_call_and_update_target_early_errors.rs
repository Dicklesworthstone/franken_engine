//! ES2020 12.3.10 (ImportCall) and 12.4.1 / 12.5.1 (update-expression
//! targets) early errors. The parser accepted `import` as an ordinary
//! identifier: `new import('')`, `typeof import`, `import()`,
//! `import(...args)`, three-argument calls, `import('')++`, and increments
//! of any call or optional chain. Test262 has 313 files under
//! language/expressions/dynamic-import/syntax/invalid (9 in the 2026-09-27
//! Node-calibrated sample failed).
//!
//! Verdicts are Node v22.2.0's, which throws SyntaxError for all of these
//! except increments of an ordinary call (`f()++`, `++g()`): V8 defers
//! those to a runtime ReferenceError for web compatibility. In non-strict
//! code Annex B does too (Test262 annexB/language/expressions/
//! assignmenttargettype/callexpression-in-{postfix,prefix}-update.js,
//! bd-9vouw.408); in strict code they are early SyntaxErrors (Test262
//! language/expressions/assignmenttargettype/direct-callexpression-in-*),
//! which is what these cases assert. They used to be sloppy here, asserting
//! the pre-Annex-B rule that .408 replaced. Before this change the engine
//! threw a SyntaxError only when the expression ran, after calling `f`.

use frankenengine_engine::parser_api_stability::parse_script;

#[test]
fn invalid_import_calls_are_syntax_errors() {
    for source in [
        "let f = () => import('./x.js', {}, '');",
        "new import('');",
        "typeof import;",
        "import(...['']);",
        "import();",
    ] {
        let error = parse_script(source).expect_err("Node rejects this program");
        assert!(error.to_string().contains("import"), "{source}: {error}");
    }
}

#[test]
fn calls_and_optional_chains_are_not_update_targets() {
    for source in [
        "import('')++",
        "++import('');",
        "'use strict'; function f() {} f()++;",
        "'use strict'; function g() {} ++g();",
        "var a = {}; a?.b++;",
    ] {
        let error = parse_script(source).expect_err("early SyntaxError");
        assert!(
            error.to_string().contains("invalid update target"),
            "{source}: {error}"
        );
    }
}

#[test]
fn valid_import_calls_and_updates_still_parse() {
    for source in [
        "var p = import('./nope.js'); p.catch(() => {});",
        "var q = import('./nope.js', {}); q.catch(() => {});",
        "var r = import('./nope.js',); r.catch(() => {});",
        "var x = 1; x++; ++x;",
        "var o = { b: 1 }; o.b++; o['b']--;",
        "var n = 1; var k = n + n++;",
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("{source} must parse: {error}"));
    }
}

#[test]
fn other_non_assignable_update_targets_are_syntax_errors() {
    for source in [
        "function f() { new.target++; }",
        "function g() { ++new.target; }",
        "this++;",
        "1++;",
        "--'x';",
        "(() => {})++;",
        "`x`++;",
        "null++;",
        "(function () {})++;",
    ] {
        let error = parse_script(source).expect_err("Node rejects this program");
        assert!(
            error.to_string().contains("invalid update target"),
            "{source}: {error}"
        );
    }
    // Operands that other paths split first stay valid.
    for source in [
        "var x = 1; var y = -x++;",
        "async function f() { var x = 1; return await x++; }",
        "undefined++;",
        "var z = 1; var w = !z++;",
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("{source} must parse: {error}"));
    }
}
