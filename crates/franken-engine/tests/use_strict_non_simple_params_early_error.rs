//! ES2020 14.1.2 / 14.2.1 / 14.3.1 early error: a function whose own body
//! has a "use strict" directive must have simple parameters. The parser
//! accepted defaults, patterns and rest parameters there (5 negative Test262
//! syntax tests in the 2026-09-27 Node-calibrated sample, e.g.
//! statements/function/rest-param-strict-body.js and the
//! *-destructuring-param-strict-body.js class/method variants).
//! Accept/reject verdicts are Node v22.2.0's for the same text.

use frankenengine_engine::parser_api_stability::parse_script;

#[test]
fn use_strict_body_with_non_simple_parameters_is_a_syntax_error() {
    for source in [
        r#"function f(a = 1) { "use strict"; }"#,
        "function g({a}) { 'use strict'; }",
        r#"var h = (...r) => { "use strict"; };"#,
        r#"class C { m([a]) { "use strict"; } }"#,
        r#"var o = { m(a = 1) { "use strict"; } };"#,
    ] {
        let error = parse_script(source).expect_err("Node rejects this program");
        assert!(
            error
                .to_string()
                .contains("not allowed in a function with non-simple parameters"),
            "{source}: {error}"
        );
    }
}

#[test]
fn strictness_without_the_conflict_still_parses() {
    for source in [
        r#"function ok1(a, b) { "use strict"; }"#,
        r#""use strict"; function ok2(a = 1) {}"#,
        r#"function ok3(a = 1) { "not strict"; }"#,
        r#"var ok4 = (a = 1) => { return "use strict"; };"#,
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("{source} must parse: {error}"));
    }
}
