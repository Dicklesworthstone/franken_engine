//! BigInt arithmetic (ES2020 6.1.6.2, 7.1.13-14, 20.2) over the canonical
//! decimal text that [`Value::BigInt`](super::Value) carries (bd-9vouw.54).
//!
//! Checked machine-integer arithmetic handles small values; `num-bigint` is
//! the exact overflow fallback. The representation stays decimal text, so
//! hashing, serialization and `===` are unchanged. String conversion
//! bounds significant input before allocating a magnitude, and arithmetic
//! results above [`MAX_BIGINT_BITS`] are refused before decimal formatting.

use std::cmp::Ordering;

use num_bigint::{BigInt, Sign};

/// Largest BigInt magnitude this engine materializes, in bits (about 315,000
/// decimal digits). Node allows 2^30 bits; this bound keeps every single
/// operation, including the decimal conversion, within a bounded time.
pub(super) const MAX_BIGINT_BITS: u64 = 1 << 20;

/// Binary BigInt operators (ES2020 6.1.6.2). `>>>` has no BigInt form; `+`
/// keeps its preflighted decimal path (`add_bigint_decimal`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BigIntBinaryOp {
    Sub,
    Mul,
    Div,
    Rem,
    Exp,
    Shl,
    Shr,
    And,
    Or,
    Xor,
}

/// Why a BigInt operation produced no value; each maps to a JS RangeError.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BigIntError {
    DivisionByZero,
    NegativeExponent,
    TooLarge,
}

impl BigIntError {
    /// Node's message for the same failure.
    pub(super) fn message(self) -> &'static str {
        match self {
            Self::DivisionByZero => "Division by zero",
            Self::NegativeExponent => "Exponent must be non-negative",
            Self::TooLarge => "Maximum BigInt size exceeded",
        }
    }
}

/// Parse canonical decimal text (what `Value::BigInt` always holds).
pub(super) fn parse(text: &str) -> BigInt {
    text.parse().unwrap_or_default()
}

fn bounded(value: BigInt) -> Result<String, BigIntError> {
    if value.bits() > MAX_BIGINT_BITS {
        return Err(BigIntError::TooLarge);
    }
    Ok(value.to_string())
}

fn is_zero(value: &BigInt) -> bool {
    value.sign() == Sign::NoSign
}

/// `left op right` for two BigInts.
pub(super) fn binary(op: BigIntBinaryOp, left: &str, right: &str) -> Result<String, BigIntError> {
    if let Some(result) = small_binary(op, left, right) {
        return result;
    }
    binary_arbitrary_precision(op, left, right)
}

/// Avoid allocating two BigInts and their result for common counter, mask,
/// and integer-arithmetic operations. Checked overflow is a tier miss, not a
/// JS error: the arbitrary-precision path must still compute the exact value.
/// Every admitted result fits in 128 bits, well below MAX_BIGINT_BITS.
fn small_binary(
    op: BigIntBinaryOp,
    left: &str,
    right: &str,
) -> Option<Result<String, BigIntError>> {
    if left.len() > 40 || right.len() > 40 {
        return None;
    }
    let x = left.parse::<i128>().ok()?;
    let y = right.parse::<i128>().ok()?;
    let value = match op {
        BigIntBinaryOp::Sub => x.checked_sub(y)?,
        BigIntBinaryOp::Mul => x.checked_mul(y)?,
        BigIntBinaryOp::Div | BigIntBinaryOp::Rem if y == 0 => {
            return Some(Err(BigIntError::DivisionByZero));
        }
        // MIN / -1 (and MIN % -1) must fall back, never panic or wrap.
        BigIntBinaryOp::Div => x.checked_div(y)?,
        BigIntBinaryOp::Rem => x.checked_rem(y)?,
        // Sign extension makes these identical to unbounded two's complement.
        BigIntBinaryOp::And => x & y,
        BigIntBinaryOp::Or => x | y,
        BigIntBinaryOp::Xor => x ^ y,
        BigIntBinaryOp::Exp if y < 0 => return Some(Err(BigIntError::NegativeExponent)),
        BigIntBinaryOp::Exp if y == 0 => 1,
        BigIntBinaryOp::Exp if x == 0 || x == 1 => x,
        BigIntBinaryOp::Exp if x == -1 => {
            if y & 1 == 0 {
                1
            } else {
                -1
            }
        }
        BigIntBinaryOp::Exp => x.checked_pow(u32::try_from(y).ok()?)?,
        BigIntBinaryOp::Shl => small_shift(x, y, true)?,
        BigIntBinaryOp::Shr => small_shift(x, y, false)?,
    };
    Some(Ok(value.to_string()))
}

/// A negative BigInt shift count reverses the direction. Rust's checked_shl
/// only checks the count, not lost value bits, so a left shift also requires
/// the arithmetic right-shift round trip to preserve the original operand.
fn small_shift(value: i128, amount: i128, mut left: bool) -> Option<i128> {
    if value == 0 {
        return Some(0);
    }
    if amount < 0 {
        left = !left;
    }
    let amount = amount.unsigned_abs();
    if amount >= 128 {
        return if left {
            None
        } else {
            Some(if value < 0 { -1 } else { 0 })
        };
    }
    let amount = amount as u32; // Proven below the native width above.
    if !left {
        return Some(value >> amount);
    }
    let shifted = value << amount;
    ((shifted >> amount) == value).then_some(shifted)
}

fn binary_arbitrary_precision(
    op: BigIntBinaryOp,
    left: &str,
    right: &str,
) -> Result<String, BigIntError> {
    let x = parse(left);
    let y = parse(right);
    let result = match op {
        BigIntBinaryOp::Sub => x - y,
        BigIntBinaryOp::Mul => multiply_bounded(&x, &y)?,
        BigIntBinaryOp::Div | BigIntBinaryOp::Rem if is_zero(&y) => {
            return Err(BigIntError::DivisionByZero);
        }
        // Truncating division and a remainder with the dividend's sign, as
        // BigInt::divide / BigInt::remainder specify.
        BigIntBinaryOp::Div => x / y,
        BigIntBinaryOp::Rem => x % y,
        BigIntBinaryOp::Exp => return exponentiate(&x, &y),
        BigIntBinaryOp::Shl => return shift_left(&x, &y),
        BigIntBinaryOp::Shr => return shift_left(&x, &-y),
        BigIntBinaryOp::And => x & y,
        BigIntBinaryOp::Or => x | y,
        BigIntBinaryOp::Xor => x ^ y,
    };
    bounded(result)
}

fn exponentiate(base: &BigInt, exponent: &BigInt) -> Result<String, BigIntError> {
    if exponent.sign() == Sign::Minus {
        return Err(BigIntError::NegativeExponent);
    }
    if is_zero(exponent) {
        return Ok("1".to_string());
    }
    // 0, 1 and -1 stay small for any exponent.
    if base.bits() <= 1 {
        let odd = exponent.bit(0);
        return Ok(match (base.sign(), odd) {
            (Sign::NoSign, _) => "0",
            (Sign::Minus, true) => "-1",
            _ => "1",
        }
        .to_string());
    }
    let Ok(exponent) = u32::try_from(exponent) else {
        return Err(BigIntError::TooLarge);
    };
    // |base| >= 2^(bits-1), so the result has at least
    // (bits-1) * exponent + 1 bits.
    if (base.bits() - 1).saturating_mul(u64::from(exponent)) >= MAX_BIGINT_BITS {
        return Err(BigIntError::TooLarge);
    }
    // A lower bound alone is insufficient: e.g. 3^n can pass the estimate
    // above while its actual magnitude is over budget. Check every product,
    // rather than allocating that oversized power and rejecting it afterward.
    let mut remaining = exponent;
    let mut factor = base.clone();
    let mut result = BigInt::from(1u8);
    while remaining != 0 {
        if remaining & 1 != 0 {
            result = multiply_bounded(&result, &factor)?;
        }
        remaining >>= 1;
        // Do not square after the last used exponent bit: an unused factor
        // can exceed the limit even though the requested result fits.
        if remaining != 0 {
            factor = multiply_bounded(&factor, &factor)?;
        }
    }
    bounded(result)
}

/// A nonzero product has either x.bits() + y.bits() or one fewer bits.
/// Reject a provably oversized multiplication before num-bigint allocates it.
/// Only the one-bit boundary case needs multiplication followed by an exact
/// check. Squaring in exponentiation uses this same admission boundary.
fn multiply_bounded(x: &BigInt, y: &BigInt) -> Result<BigInt, BigIntError> {
    if is_zero(x) || is_zero(y) {
        return Ok(BigInt::from(0u8));
    }
    if x.bits().saturating_add(y.bits()) > MAX_BIGINT_BITS.saturating_add(1) {
        return Err(BigIntError::TooLarge);
    }
    let product = x * y;
    if product.bits() > MAX_BIGINT_BITS {
        Err(BigIntError::TooLarge)
    } else {
        Ok(product)
    }
}

/// `value << amount`; a negative amount shifts right, rounding toward
/// negative infinity (BigInt::leftShift / signedRightShift).
fn shift_left(value: &BigInt, amount: &BigInt) -> Result<String, BigIntError> {
    if is_zero(value) {
        return Ok("0".to_string());
    }
    if amount.sign() == Sign::Minus {
        let Ok(right) = u64::try_from(amount.magnitude()) else {
            return Ok(if value.sign() == Sign::Minus {
                "-1"
            } else {
                "0"
            }
            .to_string());
        };
        if right >= value.bits() {
            return Ok(if value.sign() == Sign::Minus {
                "-1"
            } else {
                "0"
            }
            .to_string());
        }
        return bounded(value >> right);
    }
    let Ok(left) = u64::try_from(amount) else {
        return Err(BigIntError::TooLarge);
    };
    if value.bits().saturating_add(left) > MAX_BIGINT_BITS {
        return Err(BigIntError::TooLarge);
    }
    bounded(value << left)
}

/// `-value` (BigInt::unaryMinus).
pub(super) fn negate(text: &str) -> String {
    match text.strip_prefix('-') {
        Some(magnitude) => magnitude.to_string(),
        None if text == "0" => "0".to_string(),
        None => format!("-{text}"),
    }
}

/// `~value` (BigInt::bitwiseNOT): `-value - 1`.
pub(super) fn bitwise_not(text: &str) -> String {
    (-parse(text) - BigInt::from(1u8)).to_string()
}

/// Borrow the sign and significant decimal digits without allocating limbs.
/// Validation preserves the old parser fallback for non-decimal internal
/// values; leading zeroes and signed zero do not affect numeric ordering.
fn decimal_parts(text: &str) -> Option<(bool, &str)> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(digits) => (true, digits),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let digits = digits.trim_start_matches('0');
    Some((negative && !digits.is_empty(), digits))
}

/// Order of two BigInts, with no heap allocation for decimal operands.
pub(super) fn compare(left: &str, right: &str) -> Ordering {
    if left == right {
        return Ordering::Equal;
    }
    let (Some((left_negative, left_digits)), Some((right_negative, right_digits))) =
        (decimal_parts(left), decimal_parts(right))
    else {
        return parse(left).cmp(&parse(right));
    };
    if left_negative != right_negative {
        return if left_negative {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let magnitude = left_digits
        .len()
        .cmp(&right_digits.len())
        .then_with(|| left_digits.cmp(right_digits));
    if left_negative {
        magnitude.reverse()
    } else {
        magnitude
    }
}

/// Order of a BigInt against a Number, exactly (ES2020 7.2.13 steps 3-4 and
/// 7.2.14); `None` when the Number is NaN.
pub(super) fn compare_with_number(bigint: &str, number: f64) -> Option<Ordering> {
    if number.is_nan() {
        return None;
    }
    if number.is_infinite() {
        return Some(if number > 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let floor = number.floor();
    // `{:.0}` prints an integral f64's exact decimal expansion.
    let floor_value = format!("{floor:.0}");
    match compare(bigint, &floor_value) {
        // Equal to floor(n): less than n when n has a fraction.
        Ordering::Equal if number > floor => Some(Ordering::Less),
        ordering => Some(ordering),
    }
}

/// StringToBigInt (ES2020 7.1.14): an optionally signed decimal integer, or a
/// `0x`/`0o`/`0b` literal, surrounded by whitespace; the empty string is 0n.
/// `None` when the text is not such a literal.
pub(super) fn from_string(text: &str) -> Option<String> {
    let text = text.trim_matches(is_string_integer_whitespace);
    if text.is_empty() {
        return Some("0".to_string());
    }
    let prefixed = [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ]
    .into_iter()
    .find_map(|(prefix, radix)| text.strip_prefix(prefix).map(|digits| (digits, radix)));
    let (digits, radix, negative) = match prefixed {
        Some((digits, radix)) => (digits, radix, false),
        None => match text.strip_prefix('-') {
            Some(digits) => (digits, 10, true),
            None => (text.strip_prefix('+').unwrap_or(text), 10, false),
        },
    };
    if digits.is_empty() {
        return None;
    }
    // Leading zeroes do not increase the magnitude. Keep this a borrowed
    // slice: even a very long zero prefix must not allocate a second string
    // or force the bigint parser to process an unbounded number of limbs.
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some("0".to_string());
    }
    let bits_per_digit = match radix {
        2 => 1,
        8 => 3,
        16 => 4,
        // 10 > 2^3: ceil(MAX_BIGINT_BITS / 3) is a conservative upper
        // bound on the decimal digit count of any admissible magnitude.
        // The exact bit check below still rejects the small excess range.
        10 => 3,
        _ => unreachable!("StringToBigInt admits only binary, octal, decimal and hex"),
    };
    if digits.len() as u64 > MAX_BIGINT_BITS.div_ceil(bits_per_digit)
        || !digits.chars().all(|c| c.is_digit(radix))
    {
        return None;
    }
    if radix != 10 {
        let leading = (digits.as_bytes()[0] as char).to_digit(radix)?;
        let bits = (digits.len() as u64 - 1)
            .saturating_mul(bits_per_digit)
            .saturating_add(u64::from(u32::BITS - leading.leading_zeros()));
        if bits > MAX_BIGINT_BITS {
            return None;
        }
    }
    // Only bounded significant input reaches the allocating parser. In
    // particular, checking magnitude.bits() after parsing alone is too late
    // to defend this boundary against an oversized untrusted literal.
    let magnitude = BigInt::parse_bytes(digits.as_bytes(), radix)?;
    if magnitude.bits() > MAX_BIGINT_BITS {
        return None;
    }
    Some(if negative { -magnitude } else { magnitude }.to_string())
}

// StringIntegerLiteral uses ECMAScript WhiteSpace and LineTerminator, not
// Unicode White_Space. In particular U+0085 is not accepted; U+FEFF is.
fn is_string_integer_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000d}'
            | '\u{0020}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
            | '\u{feff}'
    )
}

/// BigInt::toString(x, radix) with lowercase digits.
pub(super) fn to_string_radix(text: &str, radix: u32) -> String {
    parse(text).to_str_radix(radix)
}

/// Width conversion without allocating a magnitude for machine-sized input.
/// The shifts here deliberately discard bits: unlike BigInt <<, asIntN and
/// asUintN are specified as modular truncations, not unbounded arithmetic.
fn small_width(bits: u64, text: &str, signed: bool) -> Option<String> {
    if text.len() > 40 {
        return None;
    }
    let value = text.parse::<i128>().ok()?;
    if bits == 0 {
        return Some("0".to_string());
    }
    if signed {
        if bits >= 128 {
            return Some(value.to_string());
        }
        let shift = (128 - bits) as u32;
        return Some(((value << shift) >> shift).to_string());
    }
    if bits > 128 {
        return (value >= 0).then(|| value.to_string());
    }
    // Casting to u128 supplies exactly the modulo-2^128 representation.
    let unsigned = value as u128;
    let narrowed = if bits == 128 {
        unsigned
    } else {
        unsigned & ((1u128 << bits) - 1)
    };
    Some(narrowed.to_string())
}

/// BigInt.asUintN(bits, value): `value` modulo 2^bits.
pub(super) fn as_uint_n(bits: u64, text: &str) -> Result<String, BigIntError> {
    if bits == 0 {
        return Ok("0".to_string());
    }
    if let Some(value) = small_width(bits, text, false) {
        return Ok(value);
    }
    let value = parse(text);
    if bits > MAX_BIGINT_BITS {
        // Non-negative values already fit; a negative one would need 2^bits.
        return if value.sign() == Sign::Minus {
            Err(BigIntError::TooLarge)
        } else {
            Ok(value.to_string())
        };
    }
    // Most typed-width conversions already fit. Do not materialize 2^bits
    // (up to a million-bit allocation) just to return a small positive value.
    if value.sign() != Sign::Minus && value.bits() <= bits {
        return Ok(value.to_string());
    }
    let modulus = BigInt::from(1u8) << bits;
    let remainder = value % &modulus;
    bounded(if remainder.sign() == Sign::Minus {
        remainder + modulus
    } else {
        remainder
    })
}

/// BigInt.asIntN(bits, value): `value` modulo 2^bits in two's complement.
pub(super) fn as_int_n(bits: u64, text: &str) -> Result<String, BigIntError> {
    if bits == 0 {
        return Ok("0".to_string());
    }
    if let Some(value) = small_width(bits, text, true) {
        return Ok(value);
    }
    let value = parse(text);
    if bits > MAX_BIGINT_BITS || value.bits() < bits {
        // |value| < 2^(bits-1): neither sign needs truncation. The exact
        // negative endpoint -2^(bits-1) is handled by the general path below.
        // Oversized widths retain the existing already-in-range behavior.
        return Ok(value.to_string());
    }
    // Keep the computation in binary form. The former asUintN -> decimal
    // String -> parse round-trip formatted and reparsed a potentially huge
    // intermediate, and could construct the same modulus twice.
    let modulus = BigInt::from(1u8) << bits;
    let half = BigInt::from(1u8) << (bits - 1);
    let remainder = value % &modulus;
    bounded(match remainder.sign() {
        Sign::Minus if remainder.magnitude() > half.magnitude() => remainder + modulus,
        Sign::Plus if remainder >= half => remainder - modulus,
        _ => remainder,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_binary_matches_arbitrary_precision_at_machine_boundaries() {
        let values = [
            i128::MIN,
            i128::MIN + 1,
            -(1i128 << 64),
            -65536,
            -129,
            -128,
            -1,
            0,
            1,
            127,
            128,
            65536,
            1i128 << 64,
            i128::MAX - 1,
            i128::MAX,
        ];
        for op in [
            BigIntBinaryOp::Sub,
            BigIntBinaryOp::Mul,
            BigIntBinaryOp::Div,
            BigIntBinaryOp::Rem,
            BigIntBinaryOp::And,
            BigIntBinaryOp::Or,
            BigIntBinaryOp::Xor,
        ] {
            for x in values {
                for y in values {
                    let left = x.to_string();
                    let right = y.to_string();
                    assert_eq!(
                        binary(op, &left, &right),
                        binary_arbitrary_precision(op, &left, &right),
                        "{left} {op:?} {right}"
                    );
                }
            }
        }
    }

    #[test]
    fn machine_overflow_is_a_fallback_not_a_javascript_error() {
        let min = i128::MIN.to_string();
        let max = i128::MAX.to_string();
        for (op, left, right) in [
            (BigIntBinaryOp::Div, min.as_str(), "-1"),
            (BigIntBinaryOp::Rem, min.as_str(), "-1"),
            (BigIntBinaryOp::Sub, min.as_str(), "1"),
            (BigIntBinaryOp::Mul, max.as_str(), "2"),
        ] {
            assert_eq!(small_binary(op, left, right), None);
            assert_eq!(
                binary(op, left, right),
                binary_arbitrary_precision(op, left, right)
            );
        }
        assert_eq!(
            small_binary(BigIntBinaryOp::Mul, "6", "7"),
            Some(Ok("42".to_string()))
        );
        for op in [BigIntBinaryOp::Div, BigIntBinaryOp::Rem] {
            assert_eq!(
                small_binary(op, "1", "0"),
                Some(Err(BigIntError::DivisionByZero))
            );
        }
        for (op, expected) in [
            (BigIntBinaryOp::Exp, "8"),
            (BigIntBinaryOp::Shl, "16"),
            (BigIntBinaryOp::Shr, "0"),
        ] {
            assert_eq!(small_binary(op, "2", "3"), Some(Ok(expected.to_string())));
        }
        let huge = "9".repeat(100);
        assert_eq!(small_binary(BigIntBinaryOp::Sub, &huge, "1"), None);
        assert_eq!(
            binary(BigIntBinaryOp::Sub, &huge, "1"),
            binary_arbitrary_precision(BigIntBinaryOp::Sub, &huge, "1")
        );
    }

    #[test]
    fn borrowed_decimal_comparison_matches_the_parser() {
        let mut values: Vec<String> = [
            "", "+", "-", "-0", "+000", "000", "0", "+001", "1", "-1", "9", "10", "-9", "-10",
            "1_0", "invalid", "１２", "1.5",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        values.extend((-128i32..=128).map(|value| value.to_string()));
        let long = "9".repeat(8192);
        values.extend([
            i128::MIN.to_string(),
            i128::MAX.to_string(),
            format!("-{long}"),
            format!("1{long}"),
            long,
        ]);
        // Parse once per operand in the oracle rather than once per pair.
        let parsed: Vec<BigInt> = values.iter().map(|value| parse(value)).collect();
        for (i, left) in values.iter().enumerate() {
            for (j, right) in values.iter().enumerate() {
                assert_eq!(compare(left, right), parsed[i].cmp(&parsed[j]));
            }
        }
    }

    #[test]
    fn mixed_number_comparison_keeps_exact_rounding_and_special_values() {
        let integers = [
            "-9007199254740993",
            "-2",
            "-1",
            "0",
            "1",
            "2",
            "9007199254740993",
        ];
        let numbers = [
            f64::NEG_INFINITY,
            -9007199254740992.0,
            -1.5,
            -1.0,
            -f64::from_bits(1),
            -0.0,
            0.0,
            f64::from_bits(1),
            1.0,
            1.5,
            9007199254740992.0,
            f64::MAX,
            f64::INFINITY,
            f64::NAN,
        ];
        for integer in integers {
            for number in numbers {
                let expected = if number.is_nan() {
                    None
                } else if number.is_infinite() {
                    Some(if number.is_sign_negative() {
                        Ordering::Greater
                    } else {
                        Ordering::Less
                    })
                } else {
                    let floor = number.floor();
                    let ordering = parse(integer).cmp(&parse(&format!("{floor:.0}")));
                    Some(if ordering == Ordering::Equal && number > floor {
                        Ordering::Less
                    } else {
                        ordering
                    })
                };
                assert_eq!(compare_with_number(integer, number), expected);
            }
        }
    }

    #[test]
    fn native_shifts_preserve_direction_sign_and_overflow_fallbacks() {
        for value in [i128::MIN, i128::MIN + 1, -129, -1, 0, 1, 127, i128::MAX] {
            for amount in [
                i128::MIN,
                -129,
                -128,
                -127,
                -64,
                -1,
                0,
                1,
                63,
                64,
                126,
                127,
                128,
                129,
                i128::MAX,
            ] {
                for op in [BigIntBinaryOp::Shl, BigIntBinaryOp::Shr] {
                    let left = value.to_string();
                    let right = amount.to_string();
                    assert_eq!(
                        binary(op, &left, &right),
                        binary_arbitrary_precision(op, &left, &right),
                        "{left} {op:?} {right}"
                    );
                }
            }
        }
        assert_eq!(small_shift(1, 127, true), None);
        assert_eq!(small_shift(-1, 127, true), Some(i128::MIN));
        assert_eq!(small_shift(i128::MIN, 1, true), None);
        assert_eq!(small_shift(-3, 1, false), Some(-2));
    }

    #[test]
    fn native_powers_fall_back_without_losing_the_high_sign_bit() {
        for (base, exponent) in [("2", "127"), ("2", "128"), ("-2", "127"), ("2", "-1")] {
            assert_eq!(
                binary(BigIntBinaryOp::Exp, base, exponent),
                binary_arbitrary_precision(BigIntBinaryOp::Exp, base, exponent)
            );
        }
        assert_eq!(small_binary(BigIntBinaryOp::Exp, "2", "127"), None);
        assert_eq!(
            small_binary(BigIntBinaryOp::Exp, "-2", "127"),
            Some(Ok(i128::MIN.to_string()))
        );
    }

    #[test]
    fn native_width_lane_handles_full_width_and_unsigned_high_bit() {
        assert_eq!(small_width(8, "255", true).as_deref(), Some("-1"));
        assert_eq!(small_width(8, "-129", true).as_deref(), Some("127"));
        assert_eq!(small_width(8, "-1", false).as_deref(), Some("255"));
        assert_eq!(small_width(128, "-1", false), Some(u128::MAX.to_string()));
        assert_eq!(
            small_width(128, &i128::MIN.to_string(), true),
            Some(i128::MIN.to_string())
        );
        assert_eq!(small_width(129, "-1", false), None);
        assert_eq!(small_width(u64::MAX, "-1", false), None);
    }

    #[test]
    fn width_conversions_match_modular_reference_at_signed_boundaries() {
        for bits in [1u64, 2, 7, 8, 31, 32, 63, 64, 127, 128, 129, 256] {
            let modulus = BigInt::from(1u8) << bits;
            let half = BigInt::from(1u8) << (bits - 1);
            for delta in -1i32..=1 {
                for value in [
                    &modulus + delta,
                    -&modulus + delta,
                    &half + delta,
                    -&half + delta,
                    BigInt::from(delta),
                ] {
                    let text = value.to_string();
                    let mut unsigned = &value % &modulus;
                    if unsigned.sign() == Sign::Minus {
                        unsigned += &modulus;
                    }
                    let signed = if unsigned >= half {
                        &unsigned - &modulus
                    } else {
                        unsigned.clone()
                    };
                    assert_eq!(as_uint_n(bits, &text), Ok(unsigned.to_string()));
                    assert_eq!(as_int_n(bits, &text), Ok(signed.to_string()));
                }
            }
        }
    }

    #[test]
    fn already_fitting_values_do_not_need_a_width_sized_modulus() {
        for bits in [64, 128, MAX_BIGINT_BITS, MAX_BIGINT_BITS + 1, u64::MAX] {
            for text in ["0", "1", "42", "9223372036854775807"] {
                assert_eq!(as_uint_n(bits, text).as_deref(), Ok(text));
                assert_eq!(as_int_n(bits, text).as_deref(), Ok(text));
            }
            for text in ["-1", "-42", "-9223372036854775807"] {
                assert_eq!(as_int_n(bits, text).as_deref(), Ok(text));
            }
        }
        // Retain the negative unsigned width cap rather than constructing an
        // unbounded two's-complement magnitude on the fast path.
        assert_eq!(
            as_uint_n(MAX_BIGINT_BITS + 1, "-1"),
            Err(BigIntError::TooLarge)
        );
        let huge = "9".repeat(8192);
        assert_eq!(as_uint_n(0, &huge).as_deref(), Ok("0"));
        assert_eq!(as_int_n(0, &huge).as_deref(), Ok("0"));
    }

    /// Runs the real production helpers, not the independent JS/Python models.
    /// This is a primitive-level A/B measurement, not an end-to-end V8 claim.
    #[test]
    #[ignore = "manual timing: run with --release --ignored --nocapture"]
    fn benchmark_bigint_hot_paths() {
        use std::hint::black_box;
        use std::time::Instant;

        assert!(!cfg!(debug_assertions), "benchmark requires --release");

        fn measure<T>(iterations: u32, operation: &mut impl FnMut() -> T) -> u128 {
            for _ in 0..100 {
                let _ = black_box(operation());
            }
            let start = Instant::now();
            for _ in 0..iterations {
                let _ = black_box(operation());
            }
            start.elapsed().as_nanos() / u128::from(iterations)
        }

        fn report<T: PartialEq + std::fmt::Debug>(
            label: &str,
            iterations: u32,
            mut baseline: impl FnMut() -> T,
            mut optimized: impl FnMut() -> T,
        ) {
            assert_eq!(baseline(), optimized(), "{label} semantic mismatch");
            let mut before = [0; 7];
            let mut after = [0; 7];
            for sample in 0..7 {
                // Alternate ordering to reduce systematic warmup/clock bias.
                if sample % 2 == 0 {
                    before[sample] = measure(iterations, &mut baseline);
                    after[sample] = measure(iterations, &mut optimized);
                } else {
                    after[sample] = measure(iterations, &mut optimized);
                    before[sample] = measure(iterations, &mut baseline);
                }
            }
            before.sort_unstable();
            after.sort_unstable();
            eprintln!(
                "{label}: baseline={} ns/op optimized={} ns/op (7-sample medians)",
                before[3], after[3]
            );
        }

        for (label, op, left, right) in [
            ("multiply", BigIntBinaryOp::Mul, "1234567", "7654321"),
            ("bitmask", BigIntBinaryOp::And, "123456789012345", "65535"),
            ("shift", BigIntBinaryOp::Shl, "1234567", "17"),
            ("power", BigIntBinaryOp::Exp, "7", "20"),
        ] {
            report(
                label,
                10_000,
                || binary_arbitrary_precision(black_box(op), black_box(left), black_box(right)),
                || binary(black_box(op), black_box(left), black_box(right)),
            );
        }
        let left = "9".repeat(4096);
        let right = format!("1{left}");
        report(
            "compare-4096-digits",
            100,
            || parse(black_box(&left)).cmp(&parse(black_box(&right))),
            || compare(black_box(&left), black_box(&right)),
        );

        // Reproduce the old 64-bit conversion paths as the timing baseline.
        fn old_uint64(text: &str) -> String {
            let modulus = BigInt::from(1u8) << 64u32;
            let remainder = parse(text) % &modulus;
            if remainder.sign() == Sign::Minus {
                (remainder + modulus).to_string()
            } else {
                remainder.to_string()
            }
        }
        fn old_int64(text: &str) -> String {
            let unsigned = parse(&old_uint64(text));
            if unsigned >= BigInt::from(1u8) << 63u32 {
                (unsigned - (BigInt::from(1u8) << 64u32)).to_string()
            } else {
                unsigned.to_string()
            }
        }
        report(
            "asUintN-64",
            10_000,
            || old_uint64(black_box("-123456789")),
            || as_uint_n(black_box(64), black_box("-123456789")).unwrap(),
        );
        report(
            "asIntN-64",
            10_000,
            || old_int64(black_box("-123456789")),
            || as_int_n(black_box(64), black_box("-123456789")).unwrap(),
        );
    }

    #[test]
    fn string_integer_grammar_and_canonical_signs() {
        for (source, expected) in [
            ("", "0"),
            ("-000", "0"),
            ("+00042", "42"),
            ("-00042", "-42"),
            ("0b00101", "5"),
            ("0O077", "63"),
            ("0x00fF", "255"),
        ] {
            assert_eq!(from_string(source).as_deref(), Some(expected), "{source:?}");
        }
        for source in [
            "+", "-", "0x", "0b2", "0o8", "-0x1", "+0b1", "1_0", "1n", "1.0", "1e2", "1 2",
            "Infinity", "１２", "٠١",
        ] {
            assert_eq!(from_string(source), None, "{source:?}");
        }
    }

    #[test]
    fn string_integer_uses_ecmascript_not_unicode_whitespace() {
        for whitespace in [
            '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{00a0}',
            '\u{1680}', '\u{2000}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}',
            '\u{3000}', '\u{feff}',
        ] {
            let source = format!("{whitespace}-42{whitespace}");
            assert_eq!(from_string(&source).as_deref(), Some("-42"));
            assert_eq!(from_string(&whitespace.to_string()).as_deref(), Some("0"));
        }
        for whitespace in ['\u{0085}', '\u{180e}', '\u{200b}', '\u{2060}'] {
            for source in [format!("{whitespace}1"), format!("1{whitespace}")] {
                assert_eq!(from_string(&source), None, "{source:?}");
            }
        }
    }

    #[test]
    fn large_zero_prefixes_do_not_consume_the_magnitude_budget() {
        let zeroes = "0".repeat(MAX_BIGINT_BITS as usize + 1);
        for prefix in ["", "+", "-", "0b", "0o", "0x"] {
            assert_eq!(
                from_string(&format!("{prefix}{zeroes}")).as_deref(),
                Some("0")
            );
            let expected = if prefix == "-" { "-1" } else { "1" };
            assert_eq!(
                from_string(&format!("{prefix}{zeroes}1")).as_deref(),
                Some(expected)
            );
            assert_eq!(from_string(&format!("{prefix}{zeroes}z")), None);
        }
    }

    #[test]
    fn oversized_radix_inputs_are_rejected_before_magnitude_allocation() {
        for (prefix, leading, zeroes) in [
            ("0b", "1", MAX_BIGINT_BITS),
            ("0o", "2", MAX_BIGINT_BITS / 3),
            ("0x", "1", MAX_BIGINT_BITS / 4),
            ("", "1", MAX_BIGINT_BITS.div_ceil(3)),
        ] {
            let source = format!("{prefix}{leading}{}", "0".repeat(zeroes as usize));
            assert_eq!(from_string(&source), None, "radix prefix {prefix:?}");
        }
    }

    #[test]
    fn exact_bit_limit_remains_accepted_in_every_radix() {
        let magnitude = (BigInt::from(1u8) << MAX_BIGINT_BITS) - BigInt::from(1u8);
        let decimal = magnitude.to_string();
        for (prefix, radix) in [("0b", 2), ("0o", 8), ("", 10), ("0x", 16)] {
            let source = format!("{prefix}{}", magnitude.to_str_radix(radix));
            assert_eq!(from_string(&source).as_deref(), Some(decimal.as_str()));
        }
        let negative = format!("-{decimal}");
        assert_eq!(from_string(&negative).as_deref(), Some(negative.as_str()));
    }

    #[test]
    fn decimal_exact_limit_is_checked_after_conservative_admission() {
        let too_large = (BigInt::from(1u8) << MAX_BIGINT_BITS).to_string();
        assert!(too_large.len() as u64 <= MAX_BIGINT_BITS.div_ceil(3));
        assert_eq!(from_string(&too_large), None);
        assert_eq!(from_string(&format!("-{too_large}")), None);
    }

    #[test]
    fn bounded_exponentiation_matches_integer_powers_and_signs() {
        for base in -16..=16 {
            for exponent in 0..=20u32 {
                let expected = BigInt::from(base).pow(exponent).to_string();
                assert_eq!(
                    binary(
                        BigIntBinaryOp::Exp,
                        &base.to_string(),
                        &exponent.to_string()
                    ),
                    Ok(expected),
                    "base={base}, exponent={exponent}"
                );
            }
        }
    }

    #[test]
    fn tiny_bases_keep_huge_exponents_and_negative_exponents_still_throw() {
        let even = "10000000000000000000000000000000000000000";
        let odd = "10000000000000000000000000000000000000001";
        for (base, exponent, expected) in [
            ("0", even, "0"),
            ("1", odd, "1"),
            ("-1", even, "1"),
            ("-1", odd, "-1"),
            ("0", "0", "1"),
        ] {
            assert_eq!(
                binary(BigIntBinaryOp::Exp, base, exponent).as_deref(),
                Ok(expected)
            );
        }
        for base in ["0", "1", "-1", "2"] {
            assert_eq!(
                binary(BigIntBinaryOp::Exp, base, "-1"),
                Err(BigIntError::NegativeExponent)
            );
        }
    }

    #[test]
    fn powers_that_pass_the_lower_bound_still_obey_the_intermediate_limit() {
        let exponent = (MAX_BIGINT_BITS - 1).to_string();
        // The old admission test sees only (bits(3)-1)*exponent < limit.
        // The actual result has many more bits, so product admission must
        // reject it during exponentiation, before constructing the power.
        assert_eq!(
            binary(BigIntBinaryOp::Exp, "3", &exponent),
            Err(BigIntError::TooLarge)
        );
        assert_eq!(
            binary(BigIntBinaryOp::Exp, "-3", &exponent),
            Err(BigIntError::TooLarge)
        );
    }

    #[test]
    fn multiplication_checks_the_boundary_without_rejecting_exact_fit() {
        let edge = BigInt::from(1u8) << (MAX_BIGINT_BITS - 1);
        assert_eq!(
            multiply_bounded(&edge, &BigInt::from(1u8)),
            Ok(edge.clone())
        );
        assert_eq!(
            multiply_bounded(&edge, &BigInt::from(-1)),
            Ok(-edge.clone())
        );
        assert_eq!(
            multiply_bounded(&edge, &BigInt::from(2u8)),
            Err(BigIntError::TooLarge)
        );
        assert_eq!(
            multiply_bounded(&edge, &BigInt::from(0u8)),
            Ok(BigInt::from(0u8))
        );
    }

    #[test]
    fn final_unused_square_cannot_reject_a_valid_power() {
        let edge = BigInt::from(1u8) << (MAX_BIGINT_BITS - 1);
        assert_eq!(
            exponentiate(&edge, &BigInt::from(1u8)),
            Ok(edge.to_string())
        );
        assert_eq!(
            exponentiate(&BigInt::from(2u8), &BigInt::from(MAX_BIGINT_BITS - 1)),
            Ok(edge.to_string())
        );
    }
}
