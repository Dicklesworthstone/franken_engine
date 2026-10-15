//! Exact mixed BigInt/Number ordering without a heap-allocated Number key.
//!
//! Never round the BigInt to binary64: adjacent integers above 2^53 would
//! compare equal. Compare with floor(Number), then resolve a fractional tie.
//! Machine-sized BigInts compare directly; other values use the same exact
//! fixed-decimal formatter as the original path, through bounded stack space.

use std::cmp::Ordering;
use std::fmt::{self, Write};

// This power of two is represented exactly. i128::MAX as f64 rounds UP to
// this boundary, so it is not a valid inclusive upper-bound check.
const I128_BOUNDARY: f64 = (1u128 << 127) as f64;
// A finite binary64 integer has at most 309 decimal digits, plus its sign.
const FLOOR_TEXT_CAPACITY: usize = 320;

pub(super) fn compare(bigint: &str, number: f64) -> Option<Ordering> {
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
    let ordering = machine_floor_order(bigint, floor)
        .unwrap_or_else(|| formatted_floor_order::<FLOOR_TEXT_CAPACITY>(bigint, floor));
    Some(if ordering == Ordering::Equal && number > floor {
        Ordering::Less
    } else {
        ordering
    })
}

/// An exact comparison, not a floating-point approximation of the integer.
/// Range checks precede the float-to-i128 cast; its saturation must never
/// turn Number == 2^127 into equality with i128::MAX.
fn machine_floor_order(bigint: &str, floor: f64) -> Option<Ordering> {
    if bigint.len() > 40 {
        return None;
    }
    let integer = bigint.parse::<i128>().ok()?;
    Some(if floor < -I128_BOUNDARY {
        Ordering::Greater
    } else if floor >= I128_BOUNDARY {
        Ordering::Less
    } else {
        integer.cmp(&(floor as i128))
    })
}

fn formatted_floor_order<const N: usize>(bigint: &str, floor: f64) -> Ordering {
    let mut buffer = DecimalBuffer::<N>::new();
    if write!(&mut buffer, "{floor:.0}").is_ok()
        && let Some(text) = buffer.text()
    {
        return super::compare(bigint, text);
    }
    // A failed optimization is not an ordering or a new runtime error. The
    // original formatter remains a deterministic fallback. Capacity tests
    // establish that finite binary64 floors fit the production stack buffer.
    super::compare(bigint, &format!("{floor:.0}"))
}

struct DecimalBuffer<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> DecimalBuffer<N> {
    fn new() -> Self {
        Self { bytes: [0; N], len: 0 }
    }

    fn text(&self) -> Option<&str> {
        std::str::from_utf8(&self.bytes[..self.len]).ok()
    }
}

impl<const N: usize> Write for DecimalBuffer<N> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{compare_with_number, parse};
    use num_bigint::BigInt;

    // The former implementation, retained independently of both fast paths.
    fn original(bigint: &str, number: f64) -> Option<Ordering> {
        if number.is_nan() {
            return None;
        }
        if number.is_infinite() {
            return Some(if number > 0.0 { Ordering::Less } else { Ordering::Greater });
        }
        let floor = number.floor();
        let ordering = super::super::compare(bigint, &format!("{floor:.0}"));
        Some(if ordering == Ordering::Equal && number > floor {
            Ordering::Less
        } else {
            ordering
        })
    }

    // A separate binary-rational oracle. No decimal formatting of Number,
    // floor operation, narrowing cast, or call to the optimized comparison.
    fn rational(bigint: &str, number: f64) -> Option<Ordering> {
        if number.is_nan() {
            return None;
        }
        if number.is_infinite() {
            return Some(if number.is_sign_negative() { Ordering::Greater } else { Ordering::Less });
        }
        let raw = number.to_bits();
        let exponent = ((raw >> 52) & 0x7ff) as i32;
        let fraction = raw & ((1u64 << 52) - 1);
        let (significand, power) = if exponent == 0 {
            (fraction, -1074)
        } else {
            (fraction | (1u64 << 52), exponent - 1023 - 52)
        };
        let mut numerator = BigInt::from(significand);
        if number.is_sign_negative() {
            numerator = -numerator;
        }
        let integer = parse(bigint);
        Some(if power >= 0 {
            integer.cmp(&(numerator << power as u32))
        } else {
            (integer << (-power) as u32).cmp(&numerator)
        })
    }

    #[test]
    fn machine_boundaries_preserve_adjacent_bigints_fractions_and_subnormals() {
        let numbers = [
            f64::NEG_INFINITY, -f64::MAX,
            -f64::from_bits(I128_BOUNDARY.to_bits() + 1), -I128_BOUNDARY,
            -f64::from_bits(I128_BOUNDARY.to_bits() - 1), -9007199254740992.0,
            -1.5, -1.0, -f64::from_bits(1), -0.0, 0.0, f64::from_bits(1),
            1.0, 1.5, 9007199254740992.0,
            f64::from_bits(I128_BOUNDARY.to_bits() - 1), I128_BOUNDARY,
            f64::from_bits(I128_BOUNDARY.to_bits() + 1), f64::MAX,
            f64::INFINITY, f64::NAN,
        ];
        for integer in [
            i128::MIN, i128::MIN + 1, -9007199254740993, -9007199254740992,
            -1, 0, 1, 9007199254740992, 9007199254740993, i128::MAX - 1, i128::MAX,
        ] {
            let text = integer.to_string();
            for number in numbers {
                let expected = rational(&text, number);
                assert_eq!(compare_with_number(&text, number), expected, "{text} vs {number:?}");
                assert_eq!(compare_with_number(&text, number), original(&text, number));
                if number.is_finite() {
                    assert!(machine_floor_order(&text, number.floor()).is_some());
                }
            }
        }
        assert_eq!(machine_floor_order(&i128::MAX.to_string(), I128_BOUNDARY), Some(Ordering::Less));
        assert_eq!(machine_floor_order(&i128::MIN.to_string(), -I128_BOUNDARY), Some(Ordering::Equal));
    }

    #[test]
    fn stack_formatter_matches_original_across_all_finite_binary_exponents() {
        for exponent in 0..2047u64 {
            for fraction in [0, 1, (1u64 << 51) - 1, 1u64 << 51, (1u64 << 52) - 2, (1u64 << 52) - 1] {
                for sign in [0, 1u64 << 63] {
                    let number = f64::from_bits(sign | (exponent << 52) | fraction);
                    let floor = number.floor();
                    let mut buffer = DecimalBuffer::<FLOOR_TEXT_CAPACITY>::new();
                    write!(&mut buffer, "{floor:.0}").expect("finite floor fits");
                    let expected = format!("{floor:.0}");
                    assert_eq!(buffer.text(), Some(expected.as_str()));
                    assert!(buffer.len <= 310, "binary64 decimal bound");
                }
            }
        }
    }

    #[test]
    fn generated_values_match_binary_rationals_and_the_previous_algorithm() {
        let mut seed = 0x763f_e219_03ac_849du64;
        for _ in 0..4096 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let number = f64::from_bits(seed);
            let near = if number.is_finite() {
                parse(&format!("{:.0}", number.floor()))
            } else {
                BigInt::from(0u8)
            };
            for integer in [
                &near - 1, near.clone(), &near + 1,
                BigInt::from(seed as i64),
                BigInt::from(seed) << ((seed >> 32) % 2048) as u32,
            ] {
                let text = integer.to_string();
                let expected = rational(&text, number);
                assert_eq!(compare_with_number(&text, number), expected, "{text} vs {number:?}");
                assert_eq!(compare_with_number(&text, number), original(&text, number));
            }
        }
    }

    #[test]
    fn non_machine_and_non_decimal_inputs_retain_the_original_fallback() {
        let huge = "9".repeat(8192);
        let zero_prefixed = format!("{}1", "0".repeat(8192));
        let values = [
            "", "+", "-", "--1", "1_0", "0x10", "１２", "1.5", "-0", "+001",
            huge.as_str(), zero_prefixed.as_str(),
        ];
        for text in values {
            for number in [-f64::MAX, -1.5, -0.0, 0.0, 0.5, 1.0, 10.0, f64::MAX] {
                assert_eq!(compare_with_number(text, number), original(text, number));
                assert_eq!(compare_with_number(text, number), rational(text, number));
            }
        }
        assert_eq!(machine_floor_order(&huge, 0.0), None);
        assert_eq!(machine_floor_order(&zero_prefixed, 0.0), None);
    }

    #[test]
    fn stack_capacity_failure_preserves_data_and_uses_original_formatting() {
        let mut buffer = DecimalBuffer::<4>::new();
        buffer.write_str("1234").unwrap();
        assert!(buffer.write_str("5").is_err());
        assert_eq!(buffer.text(), Some("1234"));
        let mut unicode = DecimalBuffer::<4>::new();
        unicode.write_str("é").unwrap();
        assert!(unicode.write_str("€").is_err());
        assert_eq!(unicode.text(), Some("é"));
        for number in [-f64::MAX, -12345.0, -0.0, 0.0, 12345.0, f64::MAX] {
            for text in ["-99999", "-1", "0", "1", "99999"] {
                assert_eq!(
                    formatted_floor_order::<0>(text, number),
                    super::super::compare(text, &format!("{number:.0}"))
                );
            }
        }
    }
}
