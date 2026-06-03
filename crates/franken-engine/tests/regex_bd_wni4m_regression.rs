//! Regression: regular-expression literals must work in eval — `/re/.test`,
//! `String.prototype.match`, and regex-based `replace`.
//!
//! Bead: bd-wni4m (found by OliveLake eval-probe). REPRO (`HybridRouter::eval`):
//! `/ab/.test("xabz")` faults "capability denied: regexp:create". A
//! `regexp:create` capability gates RegExp construction and the default eval
//! profile does not grant it (or no real regex engine is wired). DISTINCT from
//! "unimplemented" — it is a capability-gate denial.
//!
//! These cases are `#[ignore]`d until regex is usable in the default eval lane
//! (grant + wire a sandboxed, ReDoS-bounded engine, or relabel honestly).
//! Un-ignore them then.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-wni4m: regex capability-denied in eval; un-ignore when usable"]
fn regex_test_matches() {
    assert_eq!(eval_value(r#"/ab/.test("xabz")"#), "true");
}

#[test]
#[ignore = "bd-wni4m: regex capability-denied in eval; un-ignore when usable"]
fn regex_replace_global() {
    assert_eq!(eval_value(r#""a1b2".replace(/[0-9]/g, "X")"#), "aXbX");
}

#[test]
#[ignore = "bd-wni4m: regex capability-denied in eval; un-ignore when usable"]
fn string_match_returns_first() {
    assert_eq!(eval_value(r#"let m = "a1b2".match(/[0-9]/); m[0]"#), "1");
}
