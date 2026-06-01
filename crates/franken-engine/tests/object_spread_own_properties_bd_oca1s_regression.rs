//! Regression: object-literal spread `{ ...o }` must copy the source object's
//! own enumerable properties onto the new object, in ES2018 evaluation order.
//!
//! Bead: bd-oca1s. REPRO (`HybridRouter::eval`):
//! `let o = {a:1}; let p = {...o, b:2}; p.a + p.b;` yields `"NaN"` (WRONG;
//! expect `3` — `p.a` is `undefined` because `...o` copies nothing).
//!
//! DIAGNOSIS (OliveLake, read-only): the lowering DOES emit
//! `Ir1Op::SpreadIntoObject` for spread props (lowering_pipeline.rs ObjectLiteral
//! arm ~:7948) and the interpreter HAS a handler
//! (baseline_interpreter.rs:8080 `Ir3Instruction::SpreadIntoObject{target,source}`)
//! that copies the source's own properties to the target — which looks correct
//! for the basic case. So the gap is most likely the Ir1->Ir3 register
//! assignment for `SpreadIntoObject` (lowering_pipeline.rs ~:4162 / ~:5209) —
//! e.g. `source`/`target` mis-bound, or the spread source not resolving to a
//! `Value::Object` (the handler's `if let (Object, Object)` guard then silently
//! no-ops). baseline_interpreter.rs is leased by another agent at staging time;
//! these cases are `#[ignore]`d until the fix lands — un-ignore them in that
//! commit.
//!
//! They assert VALUES (not just `eval == Ok`), covering the ES2018 override
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
#[ignore = "bd-oca1s: blocked on SpreadIntoObject fix (baseline_interpreter.rs:8080 / lowering register binding); un-ignore when landed"]
fn object_spread_copies_own_properties() {
    assert_eq!(
        eval_value("let o = {a:1, b:2}; let p = {...o}; p.a + p.b"),
        "3"
    );
}

#[test]
#[ignore = "bd-oca1s: blocked on SpreadIntoObject fix; un-ignore when landed"]
fn object_spread_mixed_with_explicit_property() {
    // The original repro: spread then an explicit extra property.
    assert_eq!(
        eval_value("let o = {a:1}; let p = {...o, b:2}; p.a + p.b"),
        "3"
    );
}

#[test]
#[ignore = "bd-oca1s: blocked on SpreadIntoObject fix; un-ignore when landed"]
fn later_explicit_property_overrides_spread() {
    // `{ ...{a:1}, a:9 }` — the explicit `a:9` comes AFTER the spread, so it wins.
    assert_eq!(eval_value("({ ...{a:1}, a:9 }).a"), "9");
}

#[test]
#[ignore = "bd-oca1s: blocked on SpreadIntoObject fix; un-ignore when landed"]
fn spread_overrides_earlier_explicit_property() {
    // `{ a:9, ...{a:1} }` — the spread comes AFTER `a:9`, so the spread's `a:1` wins.
    assert_eq!(eval_value("({ a:9, ...{a:1} }).a"), "1");
}
