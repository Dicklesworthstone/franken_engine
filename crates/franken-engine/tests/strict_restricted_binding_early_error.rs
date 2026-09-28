//! ES2020 12.1.1 / 13.3.1.1 / 14.1.2 early error: strict mode code cannot
//! bind `eval` or `arguments` (variable, parameter, catch parameter or
//! function name). The parser accepted these; the 2026-09-27 Node-calibrated
//! Test262 sample has 4 negative tests of this shape
//! (statements/variable/eval-strict-single.js, 12.2.1-4gs.js,
//! statements/function/name-arguments-strict.js,
//! statements/for-in/var-arguments-fn-strict.js). Assignment to them in
//! strict code (`arguments <<= 1`) is not covered here.
//! Accept/reject verdicts are Node v22.2.0's for the same text.

use frankenengine_engine::parser_api_stability::parse_script;

#[test]
fn strict_code_cannot_bind_eval_or_arguments() {
    for source in [
        r#""use strict"; var eval;"#,
        r#""use strict"; function arguments() {}"#,
        r#""use strict"; for (var arguments in {}) {}"#,
        r#"function f(eval) { "use strict"; }"#,
        r#""use strict"; try {} catch (arguments) {}"#,
        r#"function arguments() { "use strict"; }"#,
        r#""use strict"; let [eval] = [];"#,
    ] {
        let error = parse_script(source).expect_err("Node rejects this program");
        assert!(
            error
                .to_string()
                .contains("cannot be a binding name in strict mode code"),
            "{source}: {error}"
        );
    }
}

#[test]
fn sloppy_bindings_and_strict_references_still_parse() {
    for source in [
        "var eval2 = 1; var arguments2;",
        "function g() { var arguments; return 1; }",
        "var eval = 1;",
        r#""use strict"; function h() { return arguments.length; }"#,
        r#""use strict"; var o = { eval: 1, arguments: 2 };"#,
    ] {
        parse_script(source).unwrap_or_else(|error| panic!("{source} must parse: {error}"));
    }
}
