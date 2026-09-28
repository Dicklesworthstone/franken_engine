//! ES2020 20.1.3.6 Number.prototype.toString with radix 10 (or none) is
//! Number::toString (7.1.12.1), the same form as `String(x)`: exponent
//! notation outside [1e-6, 1e21). FrankenEngine formatted radix 10 with Rust's
//! f64 Display, so `(1e21).toString()` printed all 22 digits while
//! `String(1e21)` printed "1e+21". Expected string is Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

#[test]
fn number_to_string_uses_the_js_number_form() {
    let source = "[(1e21).toString(), (-1e21).toString(), (1.5e300).toString(), (2**70).toString(), \
                  (1e20).toString(), (123.456).toString(), (1e-7).toString(), (0.000001).toString(), \
                  (-0).toString(), (5).toString(), (NaN).toString(), (-Infinity).toString(), \
                  (1e21).toString(10), (255).toString(16)].join(' ');";
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "1e+21 -1e+21 1.5e+300 1.1805916207174113e+21 100000000000000000000 123.456 1e-7 \
         0.000001 0 5 NaN -Infinity 1e+21 ff"
    );
}
