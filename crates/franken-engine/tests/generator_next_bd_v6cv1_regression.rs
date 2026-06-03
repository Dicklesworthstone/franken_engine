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

// The following cases exercise deeper generator-ENGINE bugs that are OUT OF
// SCOPE for bd-v6cv1 (which fixed member-access reachability) and tracked under
// bd-hoplz: (1) completion-via-return isn't detected so next() past the end
// returns a raw value instead of {value:undefined, done:true}; (2) resuming
// after a yield whose operand is a computed expression re-yields the first
// value. Un-ignore when bd-hoplz lands.
#[test]
#[ignore = "bd-hoplz: generator completion-via-return not detected (returns raw undefined)"]
fn generator_done_after_exhaustion() {
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next(); it.next().done;"),
        "true"
    );
}

#[test]
#[ignore = "bd-hoplz: generator completion-via-return not detected"]
fn generator_value_undefined_after_exhaustion() {
    assert_eq!(
        eval("function* g(){ yield 1; } let it = g(); it.next(); it.next().value;"),
        "undefined"
    );
}

#[test]
#[ignore = "bd-hoplz: yield-of-expression resume re-yields the first value"]
fn generator_yields_computed_values() {
    assert_eq!(
        eval("function* g(){ yield 1+1; yield 2*5; } let it = g(); it.next(); it.next().value;"),
        "10"
    );
}
