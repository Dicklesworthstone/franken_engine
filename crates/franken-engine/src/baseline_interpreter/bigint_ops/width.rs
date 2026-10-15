//! Decimal-to-machine-width reduction without constructing the full magnitude.
//!
//! For a b-bit result, 10^b is divisible by 2^b. The prefix before the last
//! b decimal digits cannot affect the residue. Validate that prefix, but do
//! arithmetic on at most 128 suffix digits with one wrapping accumulator.
//! The only allocation is the final, at-most-40-byte decimal result.

/// A machine-width result, or None for unsupported widths/non-decimal text.
/// Callers retain the existing arbitrary-precision fallback on None. Do not
/// turn an invalid internal spelling into a valid suffix: the whole input is
/// validated, including ignored digits and signs. Public argument coercions
/// and their side effects have already happened before entering this helper.
pub(super) fn narrow(bits: u64, text: &str, signed: bool) -> Option<String> {
    if bits > 128 {
        return None;
    }
    let (negative, digits) = match text.as_bytes() {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        digits => (false, digits),
    };
    if digits.is_empty() {
        return None;
    }
    let residue = decimal_residue(bits as usize, digits)?;
    let residue = if negative {
        residue.wrapping_neg()
    } else {
        residue
    };
    if bits == 0 {
        return Some("0".to_string());
    }
    // These are modular shifts, not BigInt's unbounded shift operation.
    // The zero-width return above prevents a Rust shift by 128.
    let shift = (128 - bits) as u32;
    if signed {
        Some((((residue << shift) as i128) >> shift).to_string())
    } else {
        Some(((residue << shift) >> shift).to_string())
    }
}

fn decimal_residue(bits: usize, digits: &[u8]) -> Option<u128> {
    let suffix = digits.len().saturating_sub(bits);
    if !digits[..suffix].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut residue = 0u128;
    for &byte in &digits[suffix..] {
        if !byte.is_ascii_digit() {
            return None;
        }
        residue = residue.wrapping_mul(10).wrapping_add(u128::from(byte - b'0'));
    }
    Some(residue)
}

#[cfg(test)]
mod tests {
    use super::super::{BigIntError, MAX_BIGINT_BITS, as_int_n, as_uint_n, parse, small_width};
    use super::*;
    use num_bigint::{BigInt, Sign};

    // Independent full-magnitude oracle: never call the optimized width API.
    fn reference(bits: u64, text: &str, signed: bool) -> String {
        if bits == 0 {
            return "0".to_string();
        }
        let modulus = BigInt::from(1u8) << bits;
        let mut residue = parse(text) % &modulus;
        if residue.sign() == Sign::Minus {
            residue += &modulus;
        }
        if signed && residue >= (BigInt::from(1u8) << (bits - 1)) {
            residue -= modulus;
        }
        residue.to_string()
    }

    #[test]
    fn every_machine_width_matches_full_magnitude_at_power_of_two_boundaries() {
        for exponent in [0u64, 1, 7, 8, 31, 32, 63, 64, 127, 128, 129, 255, 512] {
            let power = BigInt::from(1u8) << exponent;
            for delta in -2i32..=2 {
                for value in [&power + delta, -&power + delta] {
                    let text = value.to_string();
                    for bits in 0..=128 {
                        for signed in [false, true] {
                            let expected = reference(bits, &text, signed);
                            assert_eq!(narrow(bits, &text, signed), Some(expected.clone()));
                            let actual = if signed {
                                as_int_n(bits, &text)
                            } else {
                                as_uint_n(bits, &text)
                            };
                            assert_eq!(actual, Ok(expected), "bits={bits}, signed={signed}, {text}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn long_operands_and_leading_zeroes_use_the_same_exact_reduction() {
        let mut seed = 0x54ab_739c_d824_150fu64;
        for length in [1usize, 39, 40, 41, 127, 128, 129, 1024, 8192] {
            let digits: String = (0..length)
                .map(|_| {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    char::from(b'0' + ((seed >> 32) % 10) as u8)
                })
                .collect();
            for prefix in ["", "+", "-", "000", "+000", "-000"] {
                let text = format!("{prefix}{digits}");
                for bits in [0, 1, 7, 8, 31, 32, 63, 64, 65, 127, 128] {
                    for signed in [false, true] {
                        assert_eq!(
                            narrow(bits, &text, signed),
                            Some(reference(bits, &text, signed))
                        );
                    }
                }
            }
        }
        // Near the runtime magnitude cap, only validation scales with input
        // size. The arithmetic suffix stays <=128 decimal digits.
        let nines = "9".repeat(300_000);
        for bits in [8, 64, 128] {
            assert_eq!(narrow(bits, &nines, true).as_deref(), Some("-1"));
            assert_eq!(
                narrow(bits, &format!("-{nines}"), true).as_deref(),
                Some("1")
            );
            assert!(small_width(bits, &nines, false).is_some());
        }
    }

    #[test]
    fn ignored_prefixes_are_validated_and_non_decimal_spellings_keep_fallback() {
        for invalid in [
            "", "+", "-", "--1", "+-1", " 1", "1 ", "0x10", "1_0", "１２", "1.5",
        ] {
            for bits in [0, 1, 64, 128] {
                assert_eq!(narrow(bits, invalid, false), None, "{invalid:?}");
                // The public zero-width shortcut intentionally never parses.
                if bits != 0 {
                    assert_eq!(
                        as_uint_n(bits, invalid),
                        Ok(reference(bits, invalid, false))
                    );
                    assert_eq!(as_int_n(bits, invalid), Ok(reference(bits, invalid, true)));
                }
            }
        }
        for position in [0usize, 1, 2047, 3967, 3999] {
            let mut bytes = vec![b'9'; 4000];
            bytes[position] = b'x';
            let text = String::from_utf8(bytes).unwrap();
            assert_eq!(narrow(32, &text, true), None, "position={position}");
        }
        for zero in ["0", "-0", "+0", "000", "-000"] {
            assert_eq!(narrow(128, zero, true).as_deref(), Some("0"));
        }
    }

    #[test]
    fn width_refusals_and_large_width_paths_are_unchanged() {
        let value = "9".repeat(300);
        for bits in [129, 256, 1024] {
            assert_eq!(narrow(bits, &value, false), None);
            assert_eq!(as_uint_n(bits, &value), Ok(reference(bits, &value, false)));
            assert_eq!(as_int_n(bits, &value), Ok(reference(bits, &value, true)));
        }
        for bits in [MAX_BIGINT_BITS + 1, u64::MAX] {
            assert_eq!(narrow(bits, "-1", false), None);
            assert_eq!(as_uint_n(bits, "-1"), Err(BigIntError::TooLarge));
            assert_eq!(as_int_n(bits, "-1").as_deref(), Ok("-1"));
        }
    }

    #[test]
    fn full_unsigned_width_and_signed_minimum_do_not_overflow() {
        let two128 = (BigInt::from(1u8) << 128u64).to_string();
        let maximum = u128::MAX.to_string();
        assert_eq!(narrow(128, &maximum, false), Some(maximum.clone()));
        assert_eq!(narrow(128, &maximum, true).as_deref(), Some("-1"));
        assert_eq!(narrow(128, &two128, false).as_deref(), Some("0"));
        assert_eq!(
            narrow(128, &format!("-{maximum}"), false).as_deref(),
            Some("1")
        );
        assert_eq!(
            narrow(128, &i128::MIN.to_string(), true),
            Some(i128::MIN.to_string())
        );
        assert_eq!(narrow(1, "-1", true).as_deref(), Some("-1"));
    }
}
