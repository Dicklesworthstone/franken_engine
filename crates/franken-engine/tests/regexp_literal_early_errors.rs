//! Early errors of regular expression literals (ES2020 12.2.8.1).
//!
//! An invalid literal is a SyntaxError of the whole script, even in a
//! function that never runs. The engine compiled a literal only when it was
//! evaluated, so `function never() { return /(?<a>x)(?<a>y)/; }` ran and an
//! invalid literal elsewhere failed only when reached. Literals are now
//! checked at parse time: invalid or duplicate flags, and patterns that both
//! the backtracking parser and the `regex` crate reject. Verdicts are Node
//! v22.2.0's (`new Function(src)` throws SyntaxError / values below).
//!
//! No-claim: the backtracking parser is lenient in some `u`-mode corners
//! (identity escapes such as `\-` or `\a`), so those invalid literals still
//! parse; a literal either engine accepts is left to the runtime.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> Result<String, String> {
    HybridRouter::default()
        .eval(source)
        .map(|outcome| outcome.value)
        .map_err(|error| error.to_string())
}

#[test]
fn invalid_literals_are_early_syntax_errors() {
    for source in [
        "/a/gg",
        "/(?<a>x)(?<a>y)/",
        "/(?<1a>x)/",
        "/(?<a>x/",
        "/x{2,1}/",
        "/[z-a]/",
        "/\\p{Nope}/u",
        "/(/",
        "/a**/",
        "/a/uv",
        // Never evaluated, still refused.
        "function never() { return /(?<a>x)(?<a>y)/; } 1",
    ] {
        let error = eval(source).expect_err(source);
        assert!(
            error.contains("parse") && error.contains("Invalid"),
            "`{source}` must be an early SyntaxError, got {error}"
        );
    }
}

#[test]
fn valid_literals_still_run() {
    assert_eq!(
        eval(
            "[/a{/.test('a{'), /\\8/.test('8'), /]/.test(']'), /{/.test('{'), \
             /\\p{L}/u.test('é'), /(?<a>x)\\k<a>/.test('xx'), /[\\b]/.test('\\b'), \
             /x/v.test('x')].join()"
        ),
        Ok("true,true,true,true,true,true,true,true".to_string())
    );
}
