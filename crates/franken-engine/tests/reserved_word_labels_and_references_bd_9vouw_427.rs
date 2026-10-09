//! bd-9vouw.427: a reserved word is neither a label (`true: ;`, an escaped
//! `null:`) nor an identifier reference (`case = 1`, `else = 1`), a
//! SyntaxError at parse time. The parser sent `true:` to the runtime as an
//! unsupported expression and accepted the rest. Contextual keywords stay
//! valid labels in sloppy script code, `debugger;` stays a statement, and
//! keywords stay property names and switch clauses. Verdicts are Node
//! v22.2.0's (`new vm.Script` of each source).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

const SYNTAX_ERRORS: [&str; 8] = [
    "true: ;",
    "nul\\u006c: ;",
    "fals\\u0065: x;",
    "case = 1;",
    "else = 1;",
    "finally = 1;",
    "catch = 1;",
    "default = 1;",
];

const VALID: [&str; 9] = [
    "foo: ;",
    "yield: ;",
    "await: ;",
    "let: ;",
    "async: x;",
    "debugger;",
    "if (x) debugger;",
    "x.default = 1; ({ default: 1, case: 2 }).case;",
    "switch (x) { case 1: default: y; }",
];

#[test]
fn reserved_words_are_no_labels_or_references() {
    let parser = CanonicalEs2020Parser;
    for source in SYNTAX_ERRORS {
        let error = parser.parse(source, ParseGoal::Script).expect_err(source);
        assert_eq!(error.code, ParseErrorCode::InvalidSyntax, "{source}");
    }
    for source in VALID {
        parser
            .parse(source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{source}: {error:?}"));
    }
}
