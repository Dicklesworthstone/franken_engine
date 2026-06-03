//! Regressions for advanced-feature eval gaps surfaced by an OliveLake
//! eval-probe at HEAD 68f8f4a7. Each case is `#[ignore]`d until its bead lands;
//! un-ignore per-test as each feature is implemented.
//!
//! - bd-v93ds: Reflect / Proxy meta-globals unimplemented.
//! - bd-9j3zw: BigInt literals unsupported (`typeof 1n` => "string").
//! - bd-phzab: class accessor getters/setters not invoked (returns the closure).
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
#[ignore = "bd-v93ds: Reflect unimplemented; un-ignore when it lands"]
fn reflect_has() {
    assert_eq!(eval_value(r#"Reflect.has({a:1}, "a")"#), "true");
}

#[test]
#[ignore = "bd-v93ds: Reflect unimplemented; un-ignore when it lands"]
fn reflect_own_keys_count() {
    assert_eq!(eval_value("Reflect.ownKeys({a:1, b:2}).length"), "2");
}

#[test]
#[ignore = "bd-v93ds: Proxy unimplemented; un-ignore when it lands"]
fn proxy_empty_handler_passthrough() {
    assert_eq!(eval_value("let p = new Proxy({x:5}, {}); p.x"), "5");
}

#[test]
#[ignore = "bd-9j3zw: BigInt literals unsupported; un-ignore when they land"]
fn bigint_typeof() {
    assert_eq!(eval_value("typeof 1n"), "bigint");
}

#[test]
#[ignore = "bd-phzab: class accessor getter not invoked; un-ignore when it lands"]
fn class_getter_returns_value() {
    assert_eq!(eval_value("class C { get v() { return 7; } } new C().v"), "7");
}

#[test]
#[ignore = "bd-phzab: class accessor setter not invoked; un-ignore when it lands"]
fn class_setter_side_effect() {
    assert_eq!(
        eval_value("class C { set v(x){ this._x = x; } get v(){ return this._x; } } let c = new C(); c.v = 5; c.v"),
        "5"
    );
}
