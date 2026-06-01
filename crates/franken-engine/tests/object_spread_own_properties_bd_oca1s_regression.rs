//! Regression: object-literal spread `{ ...o }` must copy the source object's
//! own enumerable properties onto the new object, in ES2018 evaluation order.
//!
//! Bead: bd-oca1s. REPRO (`HybridRouter::eval`):
//! `let o = {a:1}; let p = {...o, b:2}; p.a + p.b;` yields `"NaN"` (WRONG;
//! expect `3` — `p.a` is `undefined` because `...o` copies nothing).
//!
//! ROOT CAUSE + FIX (lowering_pipeline.rs, ObjectLiteral incremental/spread arm):
//! the incremental path emitted `Ir1Op::SetProperty` for each data property, but
//! `SetProperty`'s Ir1->Ir3 lowering pushes the assigned *value* back on the
//! stack (correct for an `obj.x = v` assignment expression, which evaluates to
//! `v`) — which CONSUMES the target object. So `{...o, b:2}` left the value `2`,
//! not the object, on the stack, and `p.a` then faulted "expected object, got
//! number". (The `SpreadIntoObject` handler and its Ir1->Ir3 register binding
//! are both correct — a lone `{...o}` always worked.) Fixed by emitting each data
//! property as a single-property temp object spread into the target
//! (`NewObject{count:1}` + `SpreadIntoObject`), which preserves the target like
//! the spread arm and keeps ES2018 override ordering (temp objects merge in
//! source order). Interpreter unchanged.
//!
//! These assert VALUES (not just `eval == Ok`), covering the ES2018 override
//! ordering (spread before/after an explicit key) the conformance harness
//! cannot see.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn object_spread_copies_own_properties() {
    assert_eq!(
        eval_value("let o = {a:1, b:2}; let p = {...o}; p.a + p.b"),
        "3"
    );
}

#[test]
fn object_spread_mixed_with_explicit_property() {
    // The original repro: spread then an explicit extra property.
    assert_eq!(
        eval_value("let o = {a:1}; let p = {...o, b:2}; p.a + p.b"),
        "3"
    );
}

#[test]
fn later_explicit_property_overrides_spread() {
    // `{ ...{a:1}, a:9 }` — the explicit `a:9` comes AFTER the spread, so it wins.
    assert_eq!(eval_value("({ ...{a:1}, a:9 }).a"), "9");
}

#[test]
fn spread_overrides_earlier_explicit_property() {
    // `{ a:9, ...{a:1} }` — the spread comes AFTER `a:9`, so the spread's `a:1` wins.
    assert_eq!(eval_value("({ a:9, ...{a:1} }).a"), "1");
}
