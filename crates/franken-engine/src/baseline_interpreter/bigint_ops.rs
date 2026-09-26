//! BigInt arithmetic (ES2020 6.1.6.2, 7.1.13-14, 20.2) over the canonical
//! decimal text that [`Value::BigInt`](super::Value) carries (bd-9vouw.54).
//!
//! `num-bigint` does the arithmetic; the value representation stays decimal
//! text, so hashing, serialization and `===` are unchanged. String conversion
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

/// Order of two BigInts.
pub(super) fn compare(left: &str, right: &str) -> Ordering {
    parse(left).cmp(&parse(right))
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
    let floor_value = parse(&format!("{floor:.0}"));
    match parse(bigint).cmp(&floor_value) {
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

/// BigInt.asUintN(bits, value): `value` modulo 2^bits.
pub(super) fn as_uint_n(bits: u64, text: &str) -> Result<String, BigIntError> {
    let value = parse(text);
    if bits == 0 {
        return Ok("0".to_string());
    }
    if bits > MAX_BIGINT_BITS {
        // Non-negative values already fit; a negative one would need 2^bits.
        return if value.sign() == Sign::Minus {
            Err(BigIntError::TooLarge)
        } else {
            Ok(value.to_string())
        };
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
    if bits > MAX_BIGINT_BITS {
        // |value| < 2^MAX_BIGINT_BITS <= 2^(bits-1): already in range.
        return Ok(parse(text).to_string());
    }
    let unsigned = parse(&as_uint_n(bits, text)?);
    let half = BigInt::from(1u8) << (bits - 1);
    bounded(if unsigned >= half {
        unsigned - (BigInt::from(1u8) << bits)
    } else {
        unsigned
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
