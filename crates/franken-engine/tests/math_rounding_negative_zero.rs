//! ES2020 20.2.2.10 / .16 / .28: Math.ceil, Math.floor and Math.round return
//! -0 for a zero result from a negative argument (`Math.round(-0.4)`,
//! `Math.ceil(-0.5)`, `Math.floor(-0)`). FrankenEngine stored every in-range
//! result as an integer, which has no -0, so `Object.is(Math.round(-0.5), -0)`
//! was false and `1 / Math.ceil(-0.5)` was Infinity. Expected string is Node
//! v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn rounding_to_zero_from_below_is_negative_zero() {
    let source = "[Math.round(-0.5), Math.round(-0.4), Math.round(-0), Math.round(-0.6), \
                  Math.round(0.4), Math.round(2.5), Math.ceil(-0.5), Math.ceil(-0), \
                  Math.floor(-0), Math.ceil(0.2), Math.floor(-0.2)]\
                  .map(v => Object.is(v, -0) ? '-0' : String(v)).join() + '|' + \
                  (1 / Math.ceil(-0.5));";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(value, "-0,-0,-0,-1,0,3,-0,-0,-0,1,-1|-Infinity");
}
