//! bd-9vouw.54: BigInt operators, comparisons and methods (ES2020 6.1.6.2,
//! 7.2.13-14, 20.2).
//!
//! Before this only `5n + 3n` worked: every other operator coerced its
//! operands to f64 and threw, and `(1n).toString()` was undefined. Expected
//! strings are what Node v22.2.0 prints for `String(eval(source))`.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn arithmetic_operators() {
    check(
        "[5n + 3n, 5n - 8n, 6n * -7n, 7n / 2n, -7n / 2n, 7n % 3n, -7n % 3n, 2n ** 64n, \
         (-2n) ** 3n].join()",
        "8,-3,-42,3,-3,1,-1,18446744073709551616,-8",
    );
}

#[test]
fn bitwise_and_shift_operators() {
    check(
        "[5n & 3n, 5n | 3n, 5n ^ 3n, ~5n, -(5n), 1n << 70n, -5n >> 1n, 1024n >> 3n, \
         5n << -1n].join()",
        "1,7,6,-6,-5,1180591620717411303424,-3,128,2",
    );
}

#[test]
fn comparisons_with_bigints_numbers_and_strings() {
    check(
        "[10n > 3n, 3n >= 3n, 2n < 3, 2n < 2.5, 3n > 2.5, 2n == 2, 2n == '2', 2n === 2, \
         1n < '2', 0n == false, 1n == true, 9007199254740993n > 9007199254740992].join()",
        "true,true,true,true,true,true,true,false,true,true,true,true",
    );
}

#[test]
fn string_conversions_and_methods() {
    check(
        "[(255n).toString(16), (-255n).toString(2), (123n).toString(), String(10n ** 30n), \
         typeof 1n, `${7n}`, 'x' + 1n].join()",
        "ff,-11111111,123,1000000000000000000000000000000,bigint,7,x1",
    );
    check(
        "[Number(2n ** 64n), Number(-5n), parseInt('12n'), 0n ? 'y' : 'n', !!1n, \
         [3n, 1n, 2n].sort().join('|'), (5n).valueOf() === 5n].join()",
        "18446744073709552000,-5,12,n,true,1|2|3,true",
    );
}

#[test]
fn bigint_constructor_and_statics() {
    check(
        "[BigInt(42), BigInt('0x1f'), BigInt('  12  '), BigInt(true), BigInt.asUintN(8, 257n), \
         BigInt.asUintN(8, -1n), BigInt.asIntN(8, 255n), BigInt.asIntN(64, 2n ** 63n)].join()",
        "42,31,12,1,1,255,-1,-9223372036854775808",
    );
}

#[test]
fn errors_match_the_spec() {
    // Mixing types is a TypeError; division by zero, a negative exponent and
    // a non-integral Number are RangeErrors; a malformed string is a
    // SyntaxError; `>>>` and unary `+` have no BigInt form.
    check(
        "var e = []; function t(f) { try { f(); e.push('ok'); } \
         catch (x) { e.push(x.constructor.name); } } \
         t(() => 1n + 1); t(() => 1n / 0n); t(() => 2n ** -1n); t(() => 1n >>> 0n); \
         t(() => BigInt(1.5)); t(() => BigInt('1e3')); t(() => +1n); t(() => Math.max(1n)); \
         e.join()",
        "TypeError,RangeError,RangeError,TypeError,RangeError,SyntaxError,TypeError,TypeError",
    );
}

#[test]
fn oversized_results_are_refused_not_materialized() {
    // An engine bound, not Node parity: results are capped at 2^20 bits
    // (Node allows 2^30 and would compute these slowly). An untrusted
    // `2n ** 10n ** 9n` must be refused before it can exhaust memory or time.
    let source = "var r; try { 2n ** 100000000n; r = 'computed'; } \
                  catch (x) { r = x instanceof RangeError; } \
                  var s; try { 1n << 100000000n; s = 'computed'; } \
                  catch (x) { s = x instanceof RangeError; } r + ',' + s";
    assert_eq!(
        eval_to_string(source),
        "true,true",
        "oversized BigInt results must throw a catchable RangeError"
    );
}
