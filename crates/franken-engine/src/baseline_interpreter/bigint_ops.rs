//! BigInt arithmetic (ES2020 6.1.6.2, 7.1.13-14, 20.2) over the canonical
//! decimal text that [`Value::BigInt`](super::Value) carries (bd-9vouw.54).
//!
//! `num-bigint` does the arithmetic; the value representation stays decimal
//! text, so hashing, serialization and `===` are unchanged. A result larger
//! than [`MAX_BIGINT_BITS`] is refused with a RangeError before it is
//! materialized, so an untrusted `2n ** 10n ** 9n` cannot exhaust memory or
//! time.

use std::cmp::Ordering;

use num_bigint::{BigInt, Sign};

/// Largest BigInt magnitude this engine materializes, in bits (about 315,000
/// decimal digits). Node allows 2^30 bits; this bound keeps every single
/// operation, including the decimal conversion, within a bounded time.
pub(super) const MAX_BIGINT_BITS: u64 = 1 << 20;

/// Binary BigInt operators (ES2020 6.1.6.2). `>>>` has no BigInt form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BigIntBinaryOp {
    Add,
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
        BigIntBinaryOp::Add => x + y,
        BigIntBinaryOp::Sub => x - y,
        BigIntBinaryOp::Mul => {
            if x.bits().saturating_add(y.bits()) > MAX_BIGINT_BITS.saturating_add(1) {
                return Err(BigIntError::TooLarge);
            }
            x * y
        }
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
    bounded(base.pow(exponent))
}

/// `value << amount`; a negative amount shifts right, rounding toward
/// negative infinity (BigInt::leftShift / signedRightShift).
fn shift_left(value: &BigInt, amount: &BigInt) -> Result<String, BigIntError> {
    if is_zero(value) {
        return Ok("0".to_string());
    }
    if amount.sign() == Sign::Minus {
        let Ok(right) = u64::try_from(amount.magnitude()) else {
            return Ok(if value.sign() == Sign::Minus { "-1" } else { "0" }.to_string());
        };
        if right >= value.bits() {
            return Ok(if value.sign() == Sign::Minus { "-1" } else { "0" }.to_string());
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
    (-parse(text) - 1).to_string()
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

/// Number(bigint): the nearest double, ties to even.
pub(super) fn to_f64(text: &str) -> f64 {
    text.parse::<f64>().unwrap_or(f64::NAN)
}

/// NumberToBigInt (ES2020 20.2.1.1.1): `None` for a non-integral Number.
pub(super) fn from_integral_f64(number: f64) -> Option<String> {
    (number.is_finite() && number.fract() == 0.0).then(|| {
        let text = format!("{number:.0}");
        if text == "-0" { "0".to_string() } else { text }
    })
}

/// StringToBigInt (ES2020 7.1.14): an optionally signed decimal integer, or a
/// `0x`/`0o`/`0b` literal, surrounded by whitespace; the empty string is 0n.
/// `None` when the text is not such a literal.
pub(super) fn from_string(text: &str) -> Option<String> {
    let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if text.is_empty() {
        return Some("0".to_string());
    }
    let prefixed = [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)]
        .into_iter()
        .find_map(|(prefix, radix)| text.strip_prefix(prefix).map(|digits| (digits, radix)));
    let (digits, radix, negative) = match prefixed {
        Some((digits, radix)) => (digits, radix, false),
        None => match text.strip_prefix('-') {
            Some(digits) => (digits, 10, true),
            None => (text.strip_prefix('+').unwrap_or(text), 10, false),
        },
    };
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    let magnitude = BigInt::parse_bytes(digits.as_bytes(), radix)?;
    if magnitude.bits() > MAX_BIGINT_BITS {
        return None;
    }
    Some(if negative { -magnitude } else { magnitude }.to_string())
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
