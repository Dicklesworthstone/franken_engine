//! Regression: the `Date` global must be a callable/object with `Date.now()`
//! and `new Date(ms)` instances.
//!
//! Bead: bd-cseei (found by OliveLake eval-probe). REPRO (`HybridRouter::eval`):
//! `typeof Date` yields `"undefined"` (expect `"function"`); `Date.now()` faults
//! "expected object, got undefined". Same bare-global-resolution family as
//! Symbol (bd-bn1z7) / Map/Set / Object/JSON.
//!
//! NOTE: in a deterministic-replay engine, `Date.now()` must route through the
//! engine's clock seam (not wall time). These cases are `#[ignore]`d until a
//! Date builtin lands; un-ignore them then.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-cseei: Date global unimplemented; un-ignore when it lands"]
fn date_is_a_function() {
    assert_eq!(eval_value("typeof Date"), "function");
}

#[test]
#[ignore = "bd-cseei: Date global unimplemented; un-ignore when it lands"]
fn date_now_is_a_number() {
    assert_eq!(eval_value("typeof Date.now()"), "number");
}

#[test]
#[ignore = "bd-cseei: Date global unimplemented; un-ignore when it lands"]
fn new_date_from_millis_get_time() {
    assert_eq!(eval_value("new Date(0).getTime()"), "0");
}
