//! ES2020 13.6 / 13.7 / 13.11 / 13.13 with Annex B.3.2 and B.3.4: an if,
//! loop, `with` or labelled body is a Statement, not a Declaration. The
//! parser accepted class, lexical, generator and async-function declarations
//! there, strict-mode function declarations in if bodies, and labelled
//! functions as loop bodies. The 2026-09-27 Node-calibrated Test262 sample
//! has 6 negative tests of this shape (for-of/labelled-fn-stmt-*,
//! for-in/decl-gen, if/if-gen-else-gen, if/if-fun-no-else-strict,
//! labeled/decl-let). Accept/reject verdicts are Node v22.2.0's.

use frankenengine_engine::parser_api_stability::parse_script;

#[test]
fn declarations_in_statement_position_are_syntax_errors() {
    for source in [
        "for (var x of []) label1: label2: function f() {}",
        "for (var x in null) function* g() {}",
        "if (true) function* g() {} else function* _g() {}",
        r#""use strict"; if (true) function f() {}"#,
        "label: let x;",
        "while (false) function f() {}",
        "if (true) class C {}",
        "do const x = 1; while (false)",
        "if (true) async function f() {}",
        "if (true) L: function f() {}",
    ] {
        let error = parse_script(source).expect_err("Node rejects this program");
        assert!(
            error
                .to_string()
                .contains("is not allowed in statement position"),
            "{source}: {error}"
        );
    }
}

#[test]
fn statements_and_annex_b_functions_still_parse() {
    for source in [
        "if (true) function f() {}",
        "label: function f() {}",
        "var letter; if (true) letter = 1;",
        "var let_ = 1; if (true) let_ = 2;",
        "var constant; if (true) constant = 1;",
        "var async = 1; if (true) async = 2;",
        "var x; if (true) x = function () {};",
        "for (;;) break;",
        "L: for (;;) break L;",
        "if (true) { let y = 1; }",
        "var a; label: a = 1;",
        "if (true) label: a2 = 1; var a2;",
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("{source} must parse: {error}"));
    }
}
