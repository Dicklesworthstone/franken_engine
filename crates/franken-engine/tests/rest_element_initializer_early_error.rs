//! ES2020 13.3.3 / 14.1 early error: a rest element or rest parameter has no
//! initializer. The parser accepted `[...x = 1]` in every binding context, so
//! 14 negative Test262 syntax tests in the 2026-09-27 Node-calibrated sample
//! (for-of / for-await-of heads, arrow / method / class / async-generator
//! parameters) ran their `$DONOTEVALUATE()` body instead of failing to parse.
//! Accept/reject verdicts are Node v22.2.0's for the same text.

use frankenengine_engine::parser_api_stability::parse_script;

#[test]
fn rest_element_with_initializer_is_a_syntax_error() {
    for source in [
        "var [...x = 1] = [];",
        "for (var [...x = 1] of []) {}",
        "(function (...args = []) {});",
        "var f = ([...[a] = []]) => 0;",
        "class C { m([...{a} = {}]) {} }",
    ] {
        let error = parse_script(source).expect_err("Node rejects this program");
        assert!(
            error
                .to_string()
                .contains("rest element cannot have an initializer"),
            "{source}: {error}"
        );
    }
}

#[test]
fn defaults_beside_or_inside_a_rest_target_still_parse() {
    for source in [
        "var [a = 1, ...rest] = [];",
        "function g(a = 1, ...r) {}",
        "var [...[b = 1]] = [];",
        "var {...o} = {};",
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("{source} must parse: {error}"));
    }
}
