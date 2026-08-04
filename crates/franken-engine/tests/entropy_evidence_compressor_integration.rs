//! Integration tests for the `entropy_evidence_compressor` module.
//!
//! Exercises the full public API from outside the crate boundary:
//! constants, error types (Display, serde, std::error), EntropyEstimator
//! (construction, observe, entropy, probability, redundancy, Shannon bound),
//! ArithmeticCoder (from_estimator, encode, Kraft inequality, expected code
//! length), SufficientStatistic (construction, consistency, Fisher info),
//! CompressedEvidence, CompressionCertificate, and multi-step lifecycle
//! combining estimation, coding, compression, and certification.

#![forbid(unsafe_code)]
#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_core::entropy_evidence_compressor as core_entropy;
use frankenengine_engine::entropy_evidence_compressor::*;
use frankenengine_engine::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;

fn test_hash(label: &[u8]) -> ContentHash {
    ContentHash::compute(label)
}

/// Build an estimator with `n` observations of each symbol in `0..k`.
fn uniform_estimator(k: u32, n: usize) -> EntropyEstimator {
    let mut est = EntropyEstimator::new();
    for _ in 0..n {
        for sym in 0..k {
            est.observe(sym);
        }
    }
    est
}

/// Build an estimator from a frequency map.
fn freq_estimator(freq: &[(u32, usize)]) -> EntropyEstimator {
    let mut est = EntropyEstimator::new();
    for &(sym, count) in freq {
        for _ in 0..count {
            est.observe(sym);
        }
    }
    est
}

// ===========================================================================
// Section 1: Constants
// ===========================================================================

#[test]
fn constant_schema_version_non_empty() {
    assert!(!ENTROPY_SCHEMA_VERSION.is_empty());
}

#[test]
fn constant_schema_version_value() {
    assert_eq!(
        ENTROPY_SCHEMA_VERSION,
        "franken-engine.entropy-evidence-compressor.v2"
    );
}

#[test]
fn certificate_schema_version_value() {
    assert_eq!(
        COMPRESSION_CERTIFICATE_SCHEMA_VERSION,
        "franken-engine.entropy-compression-certificate.v1"
    );
}

// ===========================================================================
// Section 2: EntropyError — Display, serde, std::error
// ===========================================================================

#[test]
fn error_display_alphabet_too_large() {
    let e = EntropyError::AlphabetTooLarge {
        size: 512,
        max: 256,
    };
    let s = e.to_string();
    assert!(s.contains("512"), "should mention size");
    assert!(s.contains("256"), "should mention max");
}

#[test]
fn error_display_empty_input() {
    let e = EntropyError::EmptyInput;
    assert!(e.to_string().contains("empty"));
}

#[test]
fn error_display_unknown_symbol() {
    let e = EntropyError::UnknownSymbol { symbol: 77 };
    assert!(e.to_string().contains("77"));
}

#[test]
fn error_display_decode_error() {
    let e = EntropyError::DecodeError {
        message: "bad offset".into(),
    };
    let s = e.to_string();
    assert!(s.contains("bad offset"));
}

#[test]
fn error_display_insufficient_samples() {
    let e = EntropyError::InsufficientSamples { count: 3, min: 10 };
    let s = e.to_string();
    assert!(s.contains("3"));
    assert!(s.contains("10"));
}

#[test]
fn error_display_kraft_violation() {
    let e = EntropyError::KraftViolation {
        kraft_sum_millionths: 1_200_000,
    };
    let s = e.to_string();
    assert!(s.contains("frequency mass"));
    assert!(s.contains("1200000"));
}

#[test]
fn error_all_displays_distinct() {
    let variants = [
        EntropyError::AlphabetTooLarge {
            size: 300,
            max: 256,
        },
        EntropyError::EmptyInput,
        EntropyError::UnknownSymbol { symbol: 1 },
        EntropyError::DecodeError {
            message: "err".into(),
        },
        EntropyError::InsufficientSamples { count: 1, min: 2 },
        EntropyError::KraftViolation {
            kraft_sum_millionths: 2_000_000,
        },
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), 6);
}

#[test]
fn error_implements_std_error() {
    fn assert_error(_: &dyn std::error::Error) {}
    let errs: Vec<EntropyError> = vec![
        EntropyError::EmptyInput,
        EntropyError::AlphabetTooLarge { size: 1, max: 0 },
    ];
    for e in &errs {
        assert_error(e);
    }
}

#[test]
fn error_source_is_none() {
    use std::error::Error;
    let e = EntropyError::EmptyInput;
    assert!(e.source().is_none());
}

#[test]
fn error_serde_roundtrip_all_variants() {
    let variants = vec![
        EntropyError::AlphabetTooLarge {
            size: 300,
            max: 256,
        },
        EntropyError::EmptyInput,
        EntropyError::UnknownSymbol { symbol: 99 },
        EntropyError::DecodeError {
            message: "corrupt data at byte 42".into(),
        },
        EntropyError::InsufficientSamples { count: 5, min: 10 },
        EntropyError::KraftViolation {
            kraft_sum_millionths: 1_100_000,
        },
    ];
    for err in &variants {
        let json = serde_json::to_string(err).unwrap();
        let back: EntropyError = serde_json::from_str(&json).unwrap();
        assert_eq!(*err, back);
    }
}

#[test]
fn error_clone_and_eq() {
    let e1 = EntropyError::UnknownSymbol { symbol: 10 };
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

// ===========================================================================
// Section 3: EntropyEstimator — construction, observe, entropy math
// ===========================================================================

#[test]
fn estimator_new_is_empty() {
    let est = EntropyEstimator::new();
    assert_eq!(est.total_count, 0);
    assert_eq!(est.alphabet_size, 0);
    assert!(est.frequencies.is_empty());
}

#[test]
fn estimator_default_equals_new() {
    assert_eq!(EntropyEstimator::new(), EntropyEstimator::default());
}

#[test]
fn estimator_observe_single_symbol() {
    let mut est = EntropyEstimator::new();
    est.observe(42);
    assert_eq!(est.total_count, 1);
    assert_eq!(est.alphabet_size, 1);
    assert_eq!(est.frequencies.get(&42), Some(&1));
}

#[test]
fn estimator_observe_repeated_symbol() {
    let mut est = EntropyEstimator::new();
    for _ in 0..50 {
        est.observe(7);
    }
    assert_eq!(est.total_count, 50);
    assert_eq!(est.alphabet_size, 1);
    assert_eq!(est.frequencies.get(&7), Some(&50));
}

#[test]
fn estimator_observe_multiple_symbols() {
    let mut est = EntropyEstimator::new();
    est.observe(0);
    est.observe(1);
    est.observe(2);
    est.observe(0);
    assert_eq!(est.total_count, 4);
    assert_eq!(est.alphabet_size, 3);
    assert_eq!(est.frequencies.get(&0), Some(&2));
}

#[test]
fn estimator_entropy_empty_is_zero() {
    let est = EntropyEstimator::new();
    assert_eq!(est.entropy_millibits(), 0);
}

#[test]
fn estimator_entropy_below_min_samples_is_zero() {
    // Observe 9 distinct symbols (below the 10-sample threshold).
    let mut est = EntropyEstimator::new();
    for i in 0..9u32 {
        est.observe(i);
    }
    assert_eq!(est.entropy_millibits(), 0);
}

#[test]
fn estimator_entropy_at_min_samples_is_nonzero() {
    let mut est = EntropyEstimator::new();
    for i in 0..10u32 {
        est.observe(i % 2);
    }
    assert!(est.entropy_millibits() > 0);
}

#[test]
fn estimator_entropy_single_symbol_is_zero() {
    let est = freq_estimator(&[(0, 100)]);
    assert_eq!(est.entropy_millibits(), 0);
}

#[test]
fn estimator_entropy_uniform_binary_approx_one_bit() {
    let est = uniform_estimator(2, 1000);
    let h = est.entropy_millibits();
    // H(uniform over 2) = log2(2) = 1.0 bit = 1_000_000 millionths.
    assert!((h - MILLION).abs() < 100_000, "expected ~1M, got {h}");
}

#[test]
fn estimator_entropy_uniform_four_approx_two_bits() {
    let est = uniform_estimator(4, 1000);
    let h = est.entropy_millibits();
    assert!((h - 2 * MILLION).abs() < 200_000, "expected ~2M, got {h}");
}

#[test]
fn estimator_entropy_uniform_eight_approx_three_bits() {
    let est = uniform_estimator(8, 500);
    let h = est.entropy_millibits();
    assert!((h - 3 * MILLION).abs() < 300_000, "expected ~3M, got {h}");
}

#[test]
fn estimator_entropy_skewed_below_uniform() {
    let est = freq_estimator(&[(0, 900), (1, 100)]);
    let h = est.entropy_millibits();
    assert!(h > 0);
    assert!(h < MILLION, "skewed should be below 1 bit");
}

#[test]
fn estimator_probability_millionths_basic() {
    let est = freq_estimator(&[(0, 75), (1, 25)]);
    assert_eq!(est.probability_millionths(0), 750_000);
    assert_eq!(est.probability_millionths(1), 250_000);
}

#[test]
fn estimator_probability_unknown_symbol() {
    let est = freq_estimator(&[(0, 10)]);
    assert_eq!(est.probability_millionths(99), 0);
}

#[test]
fn estimator_probability_empty() {
    let est = EntropyEstimator::new();
    assert_eq!(est.probability_millionths(0), 0);
}

#[test]
fn estimator_max_entropy_single_symbol_zero() {
    let est = freq_estimator(&[(0, 50)]);
    assert_eq!(est.max_entropy_millibits(), 0);
}

#[test]
fn estimator_max_entropy_100_symbols() {
    let est = uniform_estimator(100, 1);
    let h_max = est.max_entropy_millibits();
    // log2(100) ~ 6.64 bits.
    assert!(h_max > 6 * MILLION);
    assert!(h_max < 7 * MILLION);
}

#[test]
fn estimator_redundancy_uniform_near_zero() {
    let est = uniform_estimator(2, 1000);
    let r = est.redundancy_millibits();
    assert!(
        r < 100_000,
        "redundancy for uniform should be near 0, got {r}"
    );
}

#[test]
fn estimator_redundancy_skewed_positive() {
    let est = freq_estimator(&[(0, 990), (1, 10)]);
    let r = est.redundancy_millibits();
    assert!(r > 0, "skewed distribution should have positive redundancy");
}

#[test]
fn estimator_shannon_lower_bound_empty_is_zero() {
    let est = EntropyEstimator::new();
    assert_eq!(est.shannon_lower_bound_bits(), 0);
}

#[test]
fn estimator_shannon_lower_bound_positive_for_uniform() {
    let est = uniform_estimator(2, 1000);
    let lb = est.shannon_lower_bound_bits();
    assert!(lb > 0, "lower bound should be positive, got {lb}");
}

#[test]
fn estimator_serde_roundtrip() {
    let est = freq_estimator(&[(0, 20), (1, 30), (2, 50)]);
    let json = serde_json::to_string(&est).unwrap();
    let restored: EntropyEstimator = serde_json::from_str(&json).unwrap();
    assert_eq!(est, restored);
}

#[test]
fn estimator_clone_eq() {
    let est = uniform_estimator(3, 100);
    let cloned = est.clone();
    assert_eq!(est, cloned);
}

// ===========================================================================
// Section 4: ArithmeticCoder — construction, encode, Kraft, code length
// ===========================================================================

#[test]
fn coder_from_empty_estimator_rejected() {
    let est = EntropyEstimator::new();
    let result = ArithmeticCoder::from_estimator(&est);
    assert!(matches!(result, Err(EntropyError::EmptyInput)));
}

#[test]
fn coder_from_oversize_alphabet_rejected() {
    let est = uniform_estimator(257, 1);
    let result = ArithmeticCoder::from_estimator(&est);
    assert!(matches!(
        result,
        Err(EntropyError::AlphabetTooLarge {
            size: 257,
            max: 256
        })
    ));
}

#[test]
fn coder_from_max_alphabet_accepted() {
    let est = uniform_estimator(256, 1);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    assert_eq!(coder.alphabet_size, 256);
}

#[test]
fn coder_from_estimator_basic() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    assert_eq!(coder.alphabet_size, 2);
    assert_eq!(coder.frequency_table.len(), 2);
    assert!(coder.total_frequency > 0);
}

#[test]
fn coder_encode_empty_rejected() {
    let est = freq_estimator(&[(0, 10)]);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    assert!(matches!(coder.encode(&[]), Err(EntropyError::EmptyInput)));
}

#[test]
fn coder_encode_unknown_symbol_rejected() {
    let est = freq_estimator(&[(0, 10)]);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    assert!(matches!(
        coder.encode(&[99]),
        Err(EntropyError::UnknownSymbol { symbol: 99 })
    ));
}

#[test]
fn coder_encode_single_symbol_stream() {
    let est = freq_estimator(&[(0, 100)]);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 0, 0]).unwrap();
    assert!(!compressed.compressed_data.is_empty());
    assert_eq!(compressed.original_symbol_count, 3);
    assert_eq!(compressed.schema, ENTROPY_SCHEMA_VERSION);
}

#[test]
fn coder_encode_two_symbol_stream() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..20).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    assert_eq!(compressed.original_symbol_count, 20);
    assert_eq!(
        compressed.compressed_bytes,
        compressed.compressed_data.len()
    );
    assert!(compressed.compressed_bits > 0);
    assert!(compressed.compressed_bits <= compressed.compressed_bytes as i64 * 8);
    assert!(compressed.compressed_bits > (compressed.compressed_bytes as i64 - 1) * 8);
}

#[test]
fn coder_encode_large_stream() {
    let est = uniform_estimator(4, 200);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..500).map(|i| i % 4).collect();
    let compressed = coder.encode(&symbols).unwrap();
    assert_eq!(compressed.original_symbol_count, 500);
    assert!(!compressed.compressed_data.is_empty());
}

#[test]
fn coder_kraft_inequality_satisfied() {
    let est = uniform_estimator(10, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    assert!(kraft <= MILLION + 1000);
}

#[test]
fn coder_kraft_equals_one_million() {
    // The legacy Kraft-named model mass should be exactly MILLION.
    let est = uniform_estimator(5, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    assert_eq!(kraft, MILLION);
}

#[test]
fn coder_expected_code_length_binary() {
    let est = uniform_estimator(2, 1000);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let ecl = coder.expected_code_length_millibits();
    // Should be close to 1 bit per symbol.
    assert!(ecl > 500_000);
    assert!(ecl < 1_500_000);
}

#[test]
fn coder_expected_code_length_skewed() {
    let est = freq_estimator(&[(0, 990), (1, 10)]);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let ecl = coder.expected_code_length_millibits();
    assert!(
        ecl < 500_000,
        "skewed distribution should have low expected code length, got {ecl}"
    );
}

#[test]
fn coder_serde_roundtrip() {
    let est = uniform_estimator(3, 50);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let json = serde_json::to_string(&coder).unwrap();
    let restored: ArithmeticCoder = serde_json::from_str(&json).unwrap();
    assert_eq!(coder, restored);
}

#[test]
fn coder_clone_eq() {
    let est = uniform_estimator(4, 50);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let cloned = coder.clone();
    assert_eq!(coder, cloned);
}

#[test]
fn coder_roundtrips_carry_underflow_and_boundary_streams() {
    let cases = [
        vec![7],
        (0..7).map(|index| index % 2).collect(),
        (0..8).map(|index| index % 2).collect(),
        vec![0, 0, 0, 0, 0, 0, 0, 1, 1],
        vec![1, 0],
        (0..31).map(|index| index % 3).collect(),
        (0..32).map(|index| index % 3).collect(),
        (0..33).map(|index| index % 2).collect(),
        (0..2_048).map(|index| index % 5).collect(),
    ];

    for symbols in cases {
        let mut estimator = EntropyEstimator::new();
        for &symbol in &symbols {
            estimator.observe(symbol);
        }
        let coder = ArithmeticCoder::from_estimator(&estimator).unwrap();
        let compressed = coder.encode(&symbols).unwrap();
        assert_eq!(coder.decode(&compressed).unwrap(), symbols);
        assert!(CompressionCertificate::build_verified(&estimator, &coder, &compressed).is_ok());
    }
}

#[test]
fn serialized_model_and_artifact_restore_together() {
    let symbols: Vec<u32> = (0..257).map(|index| (index * 17) % 11).collect();
    let mut estimator = EntropyEstimator::new();
    for &symbol in &symbols {
        estimator.observe(symbol);
    }
    let coder = ArithmeticCoder::from_estimator(&estimator).unwrap();
    let artifact = coder.encode(&symbols).unwrap();

    let coder_json = serde_json::to_string(&coder).unwrap();
    let artifact_json = serde_json::to_string(&artifact).unwrap();
    let restored_coder: ArithmeticCoder = serde_json::from_str(&coder_json).unwrap();
    let restored_artifact: CompressedEvidence = serde_json::from_str(&artifact_json).unwrap();

    assert_eq!(restored_coder.decode(&restored_artifact).unwrap(), symbols);
}

#[test]
fn coder_roundtrips_deterministic_generated_streams() {
    let mut state = 0x4d59_5df4_d0f3_3173u64;
    for case_index in 0..64u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1 + case_index);
        let alphabet = u32::try_from(state % 64 + 1).unwrap();
        let length = usize::try_from((state >> 8) % 512 + 1).unwrap();
        let mut symbols = Vec::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(2_862_933_555_777_941_757)
                .wrapping_add(3_037_000_493);
            symbols.push(u32::try_from(state % u64::from(alphabet)).unwrap());
        }

        let mut estimator = EntropyEstimator::new();
        for &symbol in &symbols {
            estimator.observe(symbol);
        }
        let coder = ArithmeticCoder::from_estimator(&estimator).unwrap();
        let artifact = coder.encode(&symbols).unwrap();
        assert_eq!(coder.decode(&artifact).unwrap(), symbols);
    }
}

#[test]
fn coder_has_stable_carry_and_e3_golden_vectors() {
    let carry_estimator = freq_estimator(&[(0, 1), (1, 1)]);
    let carry_coder = ArithmeticCoder::from_estimator(&carry_estimator).unwrap();
    let carry_symbols = [0, 0, 0, 0, 0, 0, 0, 1, 1];
    let carry = carry_coder.encode(&carry_symbols).unwrap();
    assert_eq!(carry.compressed_data, vec![0x01, 0xa0]);
    assert_eq!(carry.compressed_bits, 11);
    assert_eq!(carry_coder.decode(&carry).unwrap(), carry_symbols);

    let e3_estimator = freq_estimator(&[(0, 1), (1, 2)]);
    let e3_coder = ArithmeticCoder::from_estimator(&e3_estimator).unwrap();
    let e3 = e3_coder.encode(&[1, 0]).unwrap();
    assert_eq!(e3.compressed_data, vec![0x60]);
    assert_eq!(e3.compressed_bits, 3);
    assert_eq!(e3_coder.decode(&e3).unwrap(), vec![1, 0]);
}

#[test]
fn coder_roundtrips_skew_max_alphabet_and_scaled_counts() {
    let skew_estimator = freq_estimator(&[(17, 990), (u32::MAX, 10)]);
    let skew_coder = ArithmeticCoder::from_estimator(&skew_estimator).unwrap();
    let mut skew_symbols = vec![17; 990];
    skew_symbols.extend([u32::MAX; 10]);
    let skew = skew_coder.encode(&skew_symbols).unwrap();
    assert_eq!(skew_coder.decode(&skew).unwrap(), skew_symbols);

    let mut max_symbols: Vec<u32> = (0..255).collect();
    max_symbols.push(u32::MAX);
    let mut max_estimator = EntropyEstimator::new();
    for &symbol in &max_symbols {
        max_estimator.observe(symbol);
    }
    let max_coder = ArithmeticCoder::from_estimator(&max_estimator).unwrap();
    let max_artifact = max_coder.encode(&max_symbols).unwrap();
    assert_eq!(max_coder.decode(&max_artifact).unwrap(), max_symbols);

    let scaled_estimator = EntropyEstimator {
        frequencies: BTreeMap::from([(7, u64::MAX - 3), (u32::MAX, 3)]),
        total_count: u64::MAX,
        alphabet_size: 2,
    };
    let scaled_coder = ArithmeticCoder::from_estimator(&scaled_estimator).unwrap();
    assert!(scaled_coder.total_frequency < u64::MAX);
    let scaled_symbols = [7, 7, u32::MAX, 7, 7, 7, u32::MAX];
    let scaled_artifact = scaled_coder.encode(&scaled_symbols).unwrap();
    assert_eq!(
        scaled_coder.decode(&scaled_artifact).unwrap(),
        scaled_symbols
    );
}

#[test]
fn coder_rejects_corruption_noncanonical_framing_and_wrong_model() {
    let estimator = uniform_estimator(3, 64);
    let coder = ArithmeticCoder::from_estimator(&estimator).unwrap();
    let symbols: Vec<u32> = (0..96).map(|index| index % 3).collect();
    let artifact = coder.encode(&symbols).unwrap();

    for bit_index in 0..artifact.compressed_data.len() * 8 {
        let mut tampered = artifact.clone();
        tampered.compressed_data[bit_index / 8] ^= 1 << (7 - bit_index % 8);
        assert!(
            coder.decode(&tampered).is_err(),
            "accepted flipped bit {bit_index}"
        );
    }

    for retained_bytes in 0..artifact.compressed_data.len() {
        let mut truncated = artifact.clone();
        truncated.compressed_data.truncate(retained_bytes);
        truncated.compressed_bytes = retained_bytes;
        truncated.compressed_bits = (retained_bytes * 8) as i64;
        assert!(coder.decode(&truncated).is_err());
    }

    let mut appended = artifact.clone();
    appended.compressed_data.push(0);
    appended.compressed_bytes += 1;
    appended.compressed_bits += 8;
    assert!(coder.decode(&appended).is_err());

    let mut wrong_schema = artifact.clone();
    wrong_schema.schema = "franken-engine.entropy-evidence-compressor.v1".to_string();
    assert!(coder.decode(&wrong_schema).is_err());

    let mut wrong_count = artifact.clone();
    wrong_count.original_symbol_count += 1;
    assert!(coder.decode(&wrong_count).is_err());

    let mut excessive_count = artifact.clone();
    excessive_count.original_symbol_count = usize::MAX;
    assert!(coder.decode(&excessive_count).is_err());

    let mut wrong_size = artifact.clone();
    wrong_size.compressed_bytes += 1;
    assert!(coder.decode(&wrong_size).is_err());

    let mut wrong_estimate = artifact.clone();
    wrong_estimate.original_bits_estimate += 1;
    assert!(coder.decode(&wrong_estimate).is_err());

    let mut wrong_ratio = artifact.clone();
    wrong_ratio.compression_ratio_millionths += 1;
    assert!(coder.decode(&wrong_ratio).is_err());

    let mut wrong_content_hash = artifact.clone();
    wrong_content_hash.content_hash = test_hash(b"wrong-content");
    assert!(coder.decode(&wrong_content_hash).is_err());

    let mut wrong_model_hash = artifact.clone();
    wrong_model_hash.model_hash = test_hash(b"wrong-model");
    assert!(coder.decode(&wrong_model_hash).is_err());

    let other_estimator = uniform_estimator(4, 64);
    let other_coder = ArithmeticCoder::from_estimator(&other_estimator).unwrap();
    assert!(other_coder.decode(&artifact).is_err());
}

#[test]
fn coder_rejects_malformed_serialized_models_and_unknown_fields() {
    let zero_frequency = ArithmeticCoder {
        frequency_table: BTreeMap::from([(0, (0, 0))]),
        total_frequency: 1,
        alphabet_size: 1,
    };
    assert!(zero_frequency.encode(&[0]).is_err());

    let cumulative_gap = ArithmeticCoder {
        frequency_table: BTreeMap::from([(0, (1, 1))]),
        total_frequency: 2,
        alphabet_size: 1,
    };
    assert!(cumulative_gap.encode(&[0]).is_err());

    let overlapping_intervals = ArithmeticCoder {
        frequency_table: BTreeMap::from([(0, (0, 1)), (1, (0, 1))]),
        total_frequency: 2,
        alphabet_size: 2,
    };
    assert!(overlapping_intervals.encode(&[0]).is_err());

    let total_mismatch = ArithmeticCoder {
        frequency_table: BTreeMap::from([(0, (0, 1))]),
        total_frequency: 2,
        alphabet_size: 1,
    };
    assert!(total_mismatch.encode(&[0]).is_err());

    let estimator = uniform_estimator(2, 8);
    let coder = ArithmeticCoder::from_estimator(&estimator).unwrap();
    let artifact = coder.encode(&[0, 1, 0, 1]).unwrap();

    let mut coder_json = serde_json::to_value(&coder).unwrap();
    coder_json
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<ArithmeticCoder>(coder_json).is_err());

    let mut missing_coder_field = serde_json::to_value(&coder).unwrap();
    missing_coder_field
        .as_object_mut()
        .unwrap()
        .remove("total_frequency");
    assert!(serde_json::from_value::<ArithmeticCoder>(missing_coder_field).is_err());

    let mut artifact_json = serde_json::to_value(&artifact).unwrap();
    artifact_json
        .as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<CompressedEvidence>(artifact_json).is_err());

    let mut missing_artifact_field = serde_json::to_value(&artifact).unwrap();
    missing_artifact_field
        .as_object_mut()
        .unwrap()
        .remove("model_hash");
    assert!(serde_json::from_value::<CompressedEvidence>(missing_artifact_field).is_err());
}

#[test]
fn coder_and_artifact_are_exactly_cross_crate_canonical() {
    let mut max_alphabet: Vec<u32> = (0..255).collect();
    max_alphabet.push(u32::MAX);
    let cases = [
        vec![0, 0, 0, 0, 0, 0, 0, 1, 1],
        (0..1_000)
            .map(|index| if index % 100 == 0 { u32::MAX } else { 17 })
            .collect(),
        max_alphabet,
    ];

    for symbols in cases {
        let mut engine_estimator = EntropyEstimator::new();
        let mut core_estimator = core_entropy::EntropyEstimator::new();
        for &symbol in &symbols {
            engine_estimator.observe(symbol);
            core_estimator.observe(symbol);
        }

        let engine_coder = ArithmeticCoder::from_estimator(&engine_estimator).unwrap();
        let core_coder = core_entropy::ArithmeticCoder::from_estimator(&core_estimator).unwrap();
        assert_eq!(
            serde_json::to_value(&engine_coder).unwrap(),
            serde_json::to_value(&core_coder).unwrap()
        );

        let engine_artifact = engine_coder.encode(&symbols).unwrap();
        let core_artifact = core_coder.encode(&symbols).unwrap();
        assert_eq!(
            serde_json::to_value(&engine_artifact).unwrap(),
            serde_json::to_value(&core_artifact).unwrap()
        );
        assert_eq!(engine_coder.decode(&engine_artifact).unwrap(), symbols);
        assert_eq!(core_coder.decode(&core_artifact).unwrap(), symbols);

        let engine_certificate = CompressionCertificate::build_verified(
            &engine_estimator,
            &engine_coder,
            &engine_artifact,
        )
        .unwrap();
        let core_certificate = core_entropy::CompressionCertificate::build_verified(
            &core_estimator,
            &core_coder,
            &core_artifact,
        )
        .unwrap();
        assert_eq!(
            serde_json::to_value(&engine_certificate).unwrap(),
            serde_json::to_value(&core_certificate).unwrap()
        );
        engine_certificate
            .verify(&engine_coder, &engine_artifact)
            .unwrap();
        core_certificate
            .verify(&core_coder, &core_artifact)
            .unwrap();
    }

    let engine_scaled_estimator = EntropyEstimator {
        frequencies: BTreeMap::from([(7, u64::MAX - 3), (u32::MAX, 3)]),
        total_count: u64::MAX,
        alphabet_size: 2,
    };
    let core_scaled_estimator = core_entropy::EntropyEstimator {
        frequencies: BTreeMap::from([(7, u64::MAX - 3), (u32::MAX, 3)]),
        total_count: u64::MAX,
        alphabet_size: 2,
    };
    let engine_scaled = ArithmeticCoder::from_estimator(&engine_scaled_estimator).unwrap();
    let core_scaled =
        core_entropy::ArithmeticCoder::from_estimator(&core_scaled_estimator).unwrap();
    assert_eq!(
        serde_json::to_value(&engine_scaled).unwrap(),
        serde_json::to_value(&core_scaled).unwrap()
    );

    let engine_malformed = ArithmeticCoder {
        frequency_table: BTreeMap::from([(0, (0, 0))]),
        total_frequency: 1,
        alphabet_size: 1,
    };
    let core_malformed = core_entropy::ArithmeticCoder {
        frequency_table: BTreeMap::from([(0, (0, 0))]),
        total_frequency: 1,
        alphabet_size: 1,
    };
    assert_eq!(
        serde_json::to_value(engine_malformed.encode(&[0]).unwrap_err()).unwrap(),
        serde_json::to_value(core_malformed.encode(&[0]).unwrap_err()).unwrap()
    );
}

#[test]
fn verified_certificate_rejects_estimator_artifact_mismatch() {
    let estimator = freq_estimator(&[(0, 8), (1, 8)]);
    let coder = ArithmeticCoder::from_estimator(&estimator).unwrap();
    let artifact = coder.encode(&[0, 1, 0, 1]).unwrap();
    assert!(CompressionCertificate::build_verified(&estimator, &coder, &artifact).is_err());
}

// ===========================================================================
// Section 5: SufficientStatistic
// ===========================================================================

#[test]
fn sufficient_stat_from_estimator_basic() {
    let est = freq_estimator(&[(0, 20), (1, 20), (2, 20), (3, 20), (4, 20)]);
    let ss = SufficientStatistic::from_estimator(&est, 500_000, 1_000_000, test_hash(b"ss-test"));
    assert!(ss.is_consistent());
    assert!(ss.is_fisher_sufficient);
    assert_eq!(ss.total_count, 100);
    assert_eq!(ss.symbol_counts.len(), 5);
    assert_eq!(ss.cumulative_llr_millionths, 500_000);
    assert_eq!(ss.sum_squared_millionths, 1_000_000);
}

#[test]
fn sufficient_stat_from_empty_estimator() {
    let est = EntropyEstimator::new();
    let ss = SufficientStatistic::from_estimator(&est, 0, 0, test_hash(b"empty"));
    assert!(ss.is_consistent());
    assert_eq!(ss.total_count, 0);
    assert_eq!(ss.mean_millionths, 0);
}

#[test]
fn sufficient_stat_mean_computation() {
    let est = freq_estimator(&[(0, 10)]);
    let ss = SufficientStatistic::from_estimator(&est, 500, 1000, test_hash(b"mean"));
    // mean = cumulative_llr / total = 500 / 10 = 50
    assert_eq!(ss.mean_millionths, 50);
}

#[test]
fn sufficient_stat_consistency_true() {
    let est = freq_estimator(&[(0, 3), (1, 7)]);
    let ss = SufficientStatistic::from_estimator(&est, 0, 0, test_hash(b"c"));
    assert!(ss.is_consistent());
}

#[test]
fn sufficient_stat_consistency_false_when_tampered() {
    let est = freq_estimator(&[(0, 3), (1, 7)]);
    let mut ss = SufficientStatistic::from_estimator(&est, 0, 0, test_hash(b"t"));
    ss.total_count = 999;
    assert!(!ss.is_consistent());
}

#[test]
fn sufficient_stat_fisher_info_zero_for_single_sample() {
    let est = freq_estimator(&[(0, 1)]);
    let ss = SufficientStatistic::from_estimator(&est, 0, 0, test_hash(b"single"));
    assert_eq!(ss.fisher_information_millionths(), 0);
}

#[test]
fn sufficient_stat_fisher_info_positive_for_many_samples() {
    let est = freq_estimator(&[(0, 100)]);
    let ss =
        SufficientStatistic::from_estimator(&est, 100_000_000, 200_000_000, test_hash(b"fisher"));
    let fi = ss.fisher_information_millionths();
    assert!(fi > 0, "Fisher info should be positive, got {fi}");
}

#[test]
fn sufficient_stat_serde_roundtrip() {
    let est = freq_estimator(&[(0, 5), (1, 5)]);
    let ss = SufficientStatistic::from_estimator(&est, 100, 200, test_hash(b"serde"));
    let json = serde_json::to_string(&ss).unwrap();
    let restored: SufficientStatistic = serde_json::from_str(&json).unwrap();
    assert_eq!(ss, restored);
}

#[test]
fn sufficient_stat_clone_eq() {
    let est = freq_estimator(&[(0, 10), (1, 10)]);
    let ss = SufficientStatistic::from_estimator(&est, 50, 100, test_hash(b"cl"));
    let cloned = ss.clone();
    assert_eq!(ss, cloned);
}

// ===========================================================================
// Section 6: CompressedEvidence
// ===========================================================================

#[test]
fn compressed_evidence_fields() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1, 0, 1, 0]).unwrap();
    assert_eq!(compressed.schema, ENTROPY_SCHEMA_VERSION);
    assert_eq!(compressed.original_symbol_count, 5);
    assert_eq!(
        compressed.compressed_bytes,
        compressed.compressed_data.len()
    );
    assert!(compressed.compressed_bits > 0);
    assert!(compressed.compressed_bits <= compressed.compressed_bytes as i64 * 8);
    assert!(compressed.compressed_bits > (compressed.compressed_bytes as i64 - 1) * 8);
}

#[test]
fn compressed_evidence_content_hash_deterministic() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let c1 = coder.encode(&[0, 1, 0]).unwrap();
    let c2 = coder.encode(&[0, 1, 0]).unwrap();
    assert_eq!(c1.content_hash, c2.content_hash);
}

#[test]
fn compressed_evidence_content_hash_differs_for_different_input() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let c1 = coder.encode(&[0, 0, 0]).unwrap();
    let c2 = coder.encode(&[1, 1, 1]).unwrap();
    assert_ne!(c1.content_hash, c2.content_hash);
}

#[test]
fn compressed_evidence_serde_roundtrip() {
    let ce = CompressedEvidence {
        schema: ENTROPY_SCHEMA_VERSION.to_string(),
        compressed_data: vec![1, 2, 3, 4, 5],
        original_symbol_count: 200,
        compressed_bytes: 5,
        original_bits_estimate: 400,
        compressed_bits: 40,
        compression_ratio_millionths: 100_000,
        content_hash: test_hash(b"ce-serde"),
        model_hash: test_hash(b"ce-serde-model"),
    };
    let json = serde_json::to_string(&ce).unwrap();
    let restored: CompressedEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(ce, restored);
}

#[test]
fn compressed_evidence_clone_eq() {
    let ce = CompressedEvidence {
        schema: ENTROPY_SCHEMA_VERSION.to_string(),
        compressed_data: vec![10, 20],
        original_symbol_count: 50,
        compressed_bytes: 2,
        original_bits_estimate: 100,
        compressed_bits: 16,
        compression_ratio_millionths: 160_000,
        content_hash: test_hash(b"ce-clone"),
        model_hash: test_hash(b"ce-clone-model"),
    };
    let cloned = ce.clone();
    assert_eq!(ce, cloned);
}

// ===========================================================================
// Section 7: CompressionCertificate
// ===========================================================================

#[test]
fn certificate_build_basic() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..50).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);

    assert_eq!(cert.schema, COMPRESSION_CERTIFICATE_SCHEMA_VERSION);
    assert!(cert.kraft_satisfied);
    assert!(cert.entropy_millibits_per_symbol > 0);
    assert!(cert.shannon_lower_bound_bits > 0);
    assert!(cert.achieved_bits > 0);
    assert_eq!(cert.symbol_count, est.total_count);
}

#[test]
fn certificate_zero_lower_bound_fails_closed() {
    // Single symbol => Shannon lower bound = 0, achieved > 0.
    let est = freq_estimator(&[(7, 1)]);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[7]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);

    assert_eq!(cert.shannon_lower_bound_bits, 0);
    assert!(cert.achieved_bits > 0);
    assert_eq!(cert.overhead_ratio_millionths, i64::MAX);
    assert!(!cert.is_within_factor(&coder, &compressed, 10_000_000));
    assert!(!cert.is_within_factor(&coder, &compressed, i64::MAX));
}

#[test]
fn certificate_is_within_factor_passing() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..200).map(|index| index % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let cert = CompressionCertificate::build_verified(&est, &coder, &compressed).unwrap();

    assert!(cert.is_within_factor(&coder, &compressed, cert.overhead_ratio_millionths));
    assert!(!cert.is_within_factor(
        &coder,
        &compressed,
        cert.overhead_ratio_millionths.saturating_sub(1)
    ));
    assert!(!cert.is_within_factor(&coder, &compressed, -1));
}

#[test]
fn certificate_verification_rejects_every_tampered_field_and_artifact_substitution() {
    let symbols: Vec<u32> = (0..256).map(|index| index % 4).collect();
    let estimator = freq_estimator(&[(0, 64), (1, 64), (2, 64), (3, 64)]);
    let coder = ArithmeticCoder::from_estimator(&estimator).unwrap();
    let artifact = coder.encode(&symbols).unwrap();
    let certificate =
        CompressionCertificate::build_verified(&estimator, &coder, &artifact).unwrap();
    certificate.verify(&coder, &artifact).unwrap();

    macro_rules! reject_tamper {
        ($field:ident, $value:expr) => {{
            let mut tampered = certificate.clone();
            tampered.$field = $value;
            assert!(
                tampered.verify(&coder, &artifact).is_err(),
                "tampered {} must fail contextual verification",
                stringify!($field)
            );
            assert!(
                !tampered.is_within_factor(&coder, &artifact, i64::MAX),
                "tampered {} must not authorize factor gating",
                stringify!($field)
            );
        }};
    }

    reject_tamper!(schema, "unknown-certificate-schema".to_string());
    reject_tamper!(
        entropy_millibits_per_symbol,
        certificate.entropy_millibits_per_symbol.saturating_add(1)
    );
    reject_tamper!(
        shannon_lower_bound_bits,
        certificate.shannon_lower_bound_bits.saturating_add(1)
    );
    reject_tamper!(achieved_bits, certificate.achieved_bits.saturating_add(1));
    reject_tamper!(
        overhead_bits_millionths,
        certificate.overhead_bits_millionths.saturating_add(1)
    );
    reject_tamper!(
        overhead_ratio_millionths,
        certificate.overhead_ratio_millionths.saturating_add(1)
    );
    reject_tamper!(
        kraft_sum_millionths,
        certificate.kraft_sum_millionths.saturating_add(1)
    );
    reject_tamper!(kraft_satisfied, !certificate.kraft_satisfied);
    reject_tamper!(
        redundancy_millibits,
        certificate.redundancy_millibits.saturating_add(1)
    );
    reject_tamper!(symbol_count, certificate.symbol_count.saturating_add(1));
    reject_tamper!(compressed_artifact_hash, test_hash(b"forged-artifact-hash"));
    reject_tamper!(content_hash, test_hash(b"forged-content-hash"));
    reject_tamper!(model_hash, test_hash(b"forged-model-hash"));
    reject_tamper!(certificate_hash, test_hash(b"forged-certificate-hash"));

    let mut alternate_symbols = symbols.clone();
    alternate_symbols.rotate_left(1);
    let alternate_artifact = coder.encode(&alternate_symbols).unwrap();
    let alternate_certificate =
        CompressionCertificate::build_verified(&estimator, &coder, &alternate_artifact).unwrap();
    alternate_certificate
        .verify(&coder, &alternate_artifact)
        .unwrap();
    assert!(alternate_certificate.verify(&coder, &artifact).is_err());
    assert!(!alternate_certificate.is_within_factor(&coder, &artifact, i64::MAX));

    for accepted_but_noncanonical_kraft in [999_000, 1_001_000] {
        let forged =
            CompressionCertificate::build(&estimator, &artifact, accepted_but_noncanonical_kraft);
        forged.verify_integrity().unwrap();
        assert!(forged.verify(&coder, &artifact).is_err());
        assert!(!forged.is_within_factor(&coder, &artifact, i64::MAX));
    }
    for rejected_kraft in [i64::MIN, -1, 0, 998_999, 1_001_001, i64::MAX] {
        let forged = CompressionCertificate::build(&estimator, &artifact, rejected_kraft);
        assert!(forged.verify_integrity().is_err());
        assert!(!forged.is_within_factor(&coder, &artifact, i64::MAX));
    }

    let mut json = serde_json::to_value(&certificate).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("unexpected".to_string(), serde_json::json!(true));
    assert!(serde_json::from_value::<CompressionCertificate>(json).is_err());

    let mut missing_link = serde_json::to_value(&certificate).unwrap();
    missing_link
        .as_object_mut()
        .unwrap()
        .remove("compressed_artifact_hash");
    assert!(serde_json::from_value::<CompressionCertificate>(missing_link).is_err());
}

#[test]
fn certificate_overhead_ratio_consistency() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..200).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);

    if cert.shannon_lower_bound_bits > 0 {
        let expected_ratio = cert.achieved_bits * MILLION / cert.shannon_lower_bound_bits;
        assert_eq!(cert.overhead_ratio_millionths, expected_ratio);
    }
}

#[test]
fn certificate_serde_roundtrip() {
    let cert = CompressionCertificate {
        schema: COMPRESSION_CERTIFICATE_SCHEMA_VERSION.to_string(),
        entropy_millibits_per_symbol: 500_000,
        shannon_lower_bound_bits: 50,
        achieved_bits: 60,
        overhead_bits_millionths: 10 * MILLION,
        overhead_ratio_millionths: 1_200_000,
        kraft_sum_millionths: MILLION,
        kraft_satisfied: true,
        redundancy_millibits: 500_000,
        symbol_count: 200,
        compressed_artifact_hash: test_hash(b"cert-serde-artifact"),
        content_hash: test_hash(b"cert-serde-content"),
        model_hash: test_hash(b"cert-serde-model"),
        certificate_hash: test_hash(b"cert-serde"),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let restored: CompressionCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, restored);
}

#[test]
fn certificate_clone_eq() {
    let cert = CompressionCertificate {
        schema: COMPRESSION_CERTIFICATE_SCHEMA_VERSION.to_string(),
        entropy_millibits_per_symbol: MILLION,
        shannon_lower_bound_bits: 100,
        achieved_bits: 110,
        overhead_bits_millionths: 10 * MILLION,
        overhead_ratio_millionths: 1_100_000,
        kraft_sum_millionths: MILLION,
        kraft_satisfied: true,
        redundancy_millibits: 0,
        symbol_count: 500,
        compressed_artifact_hash: test_hash(b"cert-clone-artifact"),
        content_hash: test_hash(b"cert-clone-content"),
        model_hash: test_hash(b"cert-clone-model"),
        certificate_hash: test_hash(b"cert-clone"),
    };
    let cloned = cert.clone();
    assert_eq!(cert, cloned);
}

// ===========================================================================
// Section 8: Full lifecycle — estimate -> code -> compress -> certify
// ===========================================================================

#[test]
fn lifecycle_uniform_binary() {
    // 1. Build estimator.
    let est = uniform_estimator(2, 500);
    assert_eq!(est.total_count, 1000);
    assert_eq!(est.alphabet_size, 2);

    // 2. Check entropy.
    let h = est.entropy_millibits();
    assert!((h - MILLION).abs() < 100_000);

    // 3. Build coder.
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    assert_eq!(coder.alphabet_size, 2);

    // 4. Encode a stream.
    let symbols: Vec<u32> = (0..200).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    assert_eq!(compressed.original_symbol_count, 200);

    // 5. Verify Kraft.
    let kraft = coder.verify_kraft_inequality().unwrap();
    assert!(kraft <= MILLION + 1000);

    // 6. Build certificate.
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert!(cert.kraft_satisfied);
    assert!(cert.entropy_millibits_per_symbol > 0);

    // 7. Build sufficient statistic.
    let ss = SufficientStatistic::from_estimator(
        &est,
        est.total_count as i64 * 1000,
        est.total_count as i64 * 2000,
        compressed.content_hash,
    );
    assert!(ss.is_consistent());
    assert!(ss.is_fisher_sufficient);
}

#[test]
fn lifecycle_skewed_distribution() {
    // Very skewed: 99% symbol 0, 1% symbol 1.
    let est = freq_estimator(&[(0, 990), (1, 10)]);
    let h = est.entropy_millibits();
    assert!(h > 0);
    assert!(h < 200_000, "skewed H should be < 0.2 bits, got {h}");

    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let ecl = coder.expected_code_length_millibits();
    assert!(ecl < 500_000);

    let kraft = coder.verify_kraft_inequality().unwrap();
    assert_eq!(kraft, MILLION);

    let symbols: Vec<u32> = (0..100).map(|i| if i < 99 { 0 } else { 1 }).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert!(cert.kraft_satisfied);
}

#[test]
fn lifecycle_large_alphabet() {
    let est = uniform_estimator(50, 20);
    assert_eq!(est.total_count, 1000);
    assert_eq!(est.alphabet_size, 50);

    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    assert_eq!(kraft, MILLION);

    let symbols: Vec<u32> = (0..100).map(|i| i % 50).collect();
    let compressed = coder.encode(&symbols).unwrap();
    assert_eq!(compressed.original_symbol_count, 100);

    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert!(cert.kraft_satisfied);
    assert!(cert.entropy_millibits_per_symbol > 0);
}

#[test]
fn lifecycle_sufficient_statistic_preserves_counts() {
    let est = freq_estimator(&[(0, 30), (1, 20), (2, 50)]);
    let ss = SufficientStatistic::from_estimator(&est, 1_000_000, 2_000_000, test_hash(b"life"));
    assert!(ss.is_consistent());
    assert_eq!(ss.symbol_counts.get(&0), Some(&30));
    assert_eq!(ss.symbol_counts.get(&1), Some(&20));
    assert_eq!(ss.symbol_counts.get(&2), Some(&50));
}

#[test]
fn lifecycle_json_fields_present_in_certificate() {
    let est = uniform_estimator(2, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1, 0]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    let json = serde_json::to_string(&cert).unwrap();

    assert!(json.contains("\"entropy_millibits_per_symbol\""));
    assert!(json.contains("\"shannon_lower_bound_bits\""));
    assert!(json.contains("\"kraft_satisfied\""));
    assert!(json.contains("\"certificate_hash\""));
    assert!(json.contains("\"redundancy_millibits\""));
    assert!(json.contains("\"overhead_ratio_millionths\""));
}

#[test]
fn lifecycle_compression_ratio_for_single_symbol_alphabet() {
    // Single symbol: compression_ratio = MILLION (no gain possible).
    let est = freq_estimator(&[(5, 100)]);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[5, 5, 5, 5, 5]).unwrap();
    // original_bits_estimate will be 0 (since log2(1) = 0), so ratio = MILLION.
    assert_eq!(compressed.compression_ratio_millionths, MILLION);
}

#[test]
fn lifecycle_multiple_encodings_same_coder() {
    let est = uniform_estimator(3, 100);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();

    let c1 = coder.encode(&[0, 1, 2]).unwrap();
    let c2 = coder.encode(&[2, 1, 0]).unwrap();
    let c3 = coder.encode(&[0, 0, 0]).unwrap();

    // All should succeed with same schema.
    assert_eq!(c1.schema, ENTROPY_SCHEMA_VERSION);
    assert_eq!(c2.schema, ENTROPY_SCHEMA_VERSION);
    assert_eq!(c3.schema, ENTROPY_SCHEMA_VERSION);

    // Same symbols in same order produce same hash.
    let c1_dup = coder.encode(&[0, 1, 2]).unwrap();
    assert_eq!(c1.content_hash, c1_dup.content_hash);

    // Different order produces different hash.
    assert_ne!(c1.content_hash, c2.content_hash);
}
