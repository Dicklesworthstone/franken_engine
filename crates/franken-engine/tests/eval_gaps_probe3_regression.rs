//! Regressions for eval gaps surfaced by an OliveLake eval-probe (round 3) at
//! HEAD df67b045. Each case `#[ignore]`d until its bead lands; un-ignore per-test.
//!
//! - bd-bpf76: Promise global unimplemented (Promise.resolve/all).
//! - bd-7w22r: object destructuring rest `{a, ...rest}` leaves rest empty.
//! - bd-1trl5: Number() coercion function unimplemented.
//!
//! All assert VALUES (not just `eval == Ok`).

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-bpf76: Promise global unimplemented; un-ignore when it lands"]
fn promise_resolve_then_is_function() {
    assert_eq!(eval_value("typeof Promise.resolve(5).then"), "function");
}

#[test]
#[ignore = "bd-bpf76: Promise global unimplemented; un-ignore when it lands"]
fn promise_all_is_function() {
    assert_eq!(eval_value("typeof Promise.all"), "function");
}

#[test]
#[ignore = "bd-7w22r: object destructuring rest unsupported; un-ignore when it lands"]
fn object_rest_captures_remaining() {
    assert_eq!(
        eval_value("let {a, ...rest} = {a:1, b:2, c:3}; Object.keys(rest).length"),
        "2"
    );
}

#[test]
#[ignore = "bd-7w22r: object destructuring rest unsupported; un-ignore when it lands"]
fn object_rest_value() {
    assert_eq!(eval_value("let {a, ...rest} = {a:1, b:2, c:3}; rest.b"), "2");
}

#[test]
#[ignore = "bd-1trl5: Number() coercion unimplemented; un-ignore when it lands"]
fn number_coerces_string() {
    assert_eq!(eval_value(r#"Number("42") + 1"#), "43");
}

#[test]
#[ignore = "bd-1trl5: Number() coercion unimplemented; un-ignore when it lands"]
fn number_coerces_bool() {
    assert_eq!(eval_value("Number(true)"), "1");
}
