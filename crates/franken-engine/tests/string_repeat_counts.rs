#![forbid(unsafe_code)]

//! String.prototype.repeat with a count of +Infinity throws a RangeError for
//! every receiver (ES2020 21.1.3.16 step 4): "".repeat(Infinity) returned ""
//! because the saturated count passed the result-length guard (Test262
//! String/prototype/repeat/count-is-infinity-throws.js). Negative, fractional
//! and NaN counts keep their behavior.

use frankenengine_engine::HybridRouter;

/// Expected line is Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn repeat_counts_match_node() {
    let source = r#"function k(f) { try { return JSON.stringify(f()); } catch (e) { return e.constructor.name; } }
console.log(k(function () { return "x".repeat(Infinity); }), k(function () { return "".repeat(Infinity); }), k(function () { return "ab".repeat(-1); }), k(function () { return "ab".repeat(2.9); }), k(function () { return "ab".repeat(NaN); }), k(function () { return "".repeat(1e10); }));
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        ["RangeError RangeError RangeError \"abab\" \"\" \"\"",]
    );
}
