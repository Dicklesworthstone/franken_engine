#![forbid(unsafe_code)]
//! A comma sequence is an Expression, so it may appear wherever the grammar
//! has one: `if`/`while`/`do-while`/`switch` heads, `case` tests, the right
//! side of `for-in`, template substitutions and computed member keys.
//! Earlier fixes covered expression statements (bd-j4l7k), `for` clauses
//! (bd-qxkli) and `return`/`throw` (bd-h5m8u); the heads below still parsed
//! with `parse_expression`, and the sequence became an `Expression::Raw` that
//! threw "SyntaxError: unsupported expression syntax" when it ran. Minifiers
//! emit `if (a = f(), a)` constantly: lru-cache's bundled constructor has
//! `if (this.#w = v ?? N.defaultPerf, e !== 0 && !T(e))`.
//!
//! A for-in/of head may also be a member target (`for (o.a of xs)`,
//! `for (this.#k in o)`); it was refused as "unsupported binding pattern".
//!
//! Expected values are Node v22.2.0's.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn if_head_sequence_runs_every_operand() {
    assert_eq!(
        eval_value(r#"var n = 0, r = ""; if (n++, n > 0) r = "then"; r + n"#),
        "then1"
    );
}

#[test]
fn if_head_assignment_with_logical_right_side_then_comma() {
    // `x = v ?? 5, true` is `(x = (v ?? 5)), true`; the logical operator's
    // right operand used to swallow `5, true`.
    assert_eq!(
        eval_value("var x, v, r; if (x = v ?? 5, true) r = x; else r = -1; r"),
        "5"
    );
    assert_eq!(
        eval_value("var x, v, r; if (x = v || 7, x > 6) r = x; else r = -1; r"),
        "7"
    );
}

#[test]
fn while_and_do_while_heads_take_sequences() {
    assert_eq!(eval_value("var n = 0; while (n++, n < 3) ; n"), "3");
    assert_eq!(eval_value("var n = 0; do ; while (n++, n < 4); n"), "4");
}

#[test]
fn switch_discriminant_and_case_test_take_sequences() {
    assert_eq!(
        eval_value(
            r#"var n = 0, r; switch (n++, n) { case 1: r = "one"; break; default: r = "other"; } r"#
        ),
        "one"
    );
    assert_eq!(
        eval_value(r#"var n = 1, r; switch (1) { case 0, n: r = "bare"; } r"#),
        "bare"
    );
}

#[test]
fn for_in_right_side_takes_a_sequence() {
    assert_eq!(
        eval_value(r#"var o = {k: 1}, r = ""; for (var k in 0, o) r += k; r"#),
        "k"
    );
}

#[test]
fn template_substitution_and_computed_key_take_sequences() {
    assert_eq!(eval_value("var a = 1, b = 2; `t ${a, b}`"), "t 2");
    assert_eq!(eval_value(r#"var o = {b: 7}; o[0, "b"]"#), "7");
}

#[test]
fn for_of_and_for_in_assign_member_targets() {
    assert_eq!(
        eval_value(
            r#"var log = []; var o = {a: 0}; for (o.a of [4, 5]) log.push(o.a); log.join() + "|" + o.a"#
        ),
        "4,5|5"
    );
    assert_eq!(
        eval_value("var o = {}, r = []; for (o.k in {x: 1, y: 2}) r.push(o.k); r.join()"),
        "x,y"
    );
}

#[test]
fn member_target_is_evaluated_once_per_iteration() {
    assert_eq!(
        eval_value(
            r#"var o = {}, n = 0; function get() { n++; return o; } for (get().v of [1, 2, 3]) ; n + ":" + o.v"#
        ),
        "3:3"
    );
}

#[test]
fn private_member_target_and_labeled_continue() {
    assert_eq!(
        eval_value(
            r#"class A { #a = 0; run(xs) { var s = 0; for (this.#a of xs) s += this.#a; return s + ":" + this.#a; } } new A().run([1, 2, 3])"#
        ),
        "6:3"
    );
    assert_eq!(
        eval_value(
            "var o = {a: 0}; outer: for (o.a of [1, 2, 3]) { for (;;) { if (o.a < 3) continue outer; break outer; } } o.a"
        ),
        "3"
    );
}

#[test]
fn a_call_is_not_a_for_of_target() {
    let result = eval_value("function f() { return {}; } for (f() of [1]) ;");
    assert!(result.starts_with("ERR:"), "{result}");
}
