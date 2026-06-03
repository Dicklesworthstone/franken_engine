//! Regression for bd-v6cv1: generator `.next()` faulted with the misleading
//! "expected object, got object". The generator engine (generator_next) and the
//! Call-handler that steps a generator-as-callee already existed; the gap was
//! the GetProperty member-access handler having no Value::Generator arm, so
//! `it.next` faulted before the call. Fix exposes `.next` as the generator
//! itself so `it.next()` resumes it via the existing path, yielding {value,done}.
use frankenengine_engine::HybridRouter;

fn eval(src: &str) -> String {
    let mut e = HybridRouter::default();
    match e.eval(src) {
        Ok(o) => format!("{}", o.value),
        Err(err) => format!("ERR={}", err.to_string().lines().next().unwrap_or("")),
    }
}

#[test]
fn generator_next_value() {
    assert_eq!(
        eval("function* g(){ yield 1; yield 2; } let it = g(); it.next().value;"),
        "1"
    );
}

#[test]
fn generator_sequential_next() {
    assert_eq!(
        eval("function* g(){ yield 1; yield 2; } let it = g(); it.next(); it.next().value;"),
        "2"
    );
}

#[test]
fn generator_done_flag_before_exhaustion() {
    // Not yet exhausted → done is false. (The post-exhaustion `done:true`
    // transition is a deeper generator-engine bug — see bd-hoplz.)
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next().done;"),
        "false"
    );
}

// bd-hoplz bug #1 (completion-via-return) — FIXED: `generator_next` now reads a
// `generator_yielded` marker set by the `Yield` handler, so a `run_loop` exit
// that was a function `Return` (not a yield) is wrapped as
// `{value:<ret>, done:true}` and marks the generator Completed.
#[test]
fn generator_done_after_exhaustion() {
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next(); it.next().done;"),
        "true"
    );
}

#[test]
fn generator_value_undefined_after_exhaustion() {
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next(); it.next().value;"),
        "undefined"
    );
}

// bd-hoplz bug #2 — FIXED: the symptom looked like a bad resume, but the IR3
// dump showed `yield 1+1` was mis-parsed as `(yield 1) + 1` (binary scanning ran
// before the yield arm). `parse_expression` now routes yield/await-prefixed
// expressions to the yield/await arm before binary scanning, so the operand is a
// full AssignmentExpression and the body yields 2 then 10.
#[test]
fn generator_yields_computed_values() {
    assert_eq!(
        eval("function* g(){ yield 1+1; yield 2*5; } let it = g(); it.next(); it.next().value;"),
        "10"
    );
}
