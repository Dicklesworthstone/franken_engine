//! bd-9vouw.421: an object literal defines `__proto__` by a plain data
//! property at most once (ES2020 12.2.6.1); computed, shorthand, method and
//! accessor forms do not count, and an assignment pattern or arrow
//! parameter list is not an object literal. The parser accepted the
//! duplicate. An invalid shorthand (`({ a = 1 })` outside a pattern,
//! `({ 0 })`) is a SyntaxError, which the parser reported as unsupported
//! syntax. Verdicts are Node v22.2.0's (`new vm.Script` of each source).

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser, ParseErrorCode};

const SYNTAX_ERRORS: [&str; 5] = [
    "({ __proto__: 1, __proto__: 2 });",
    "({ __proto__: 1, '__proto__': 2 });",
    "({ '__proto__': 1, \"__proto__\": 2 });",
    "({ a = 1 });",
    "({ 0 });",
];

const VALID: [&str; 7] = [
    "({ __proto__: 1, ['__proto__']: 2 });",
    "var __proto__ = 1; ({ __proto__, __proto__: 2 });",
    "({ __proto__() {}, __proto__: 1 });",
    "({ get __proto__() {}, __proto__: 1 });",
    "var a, b; ({ __proto__: a, __proto__: b } = {});",
    "({ __proto__: a, __proto__: b }) => 1;",
    "var o = { __proto__: null }; o;",
];

#[test]
fn duplicate_proto_and_invalid_shorthands_are_syntax_errors() {
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
