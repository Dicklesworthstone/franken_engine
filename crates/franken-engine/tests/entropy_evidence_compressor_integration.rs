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

use std::collections::BTreeSet;

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
        "franken-engine.entropy-evidence-compressor.v1"
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
    assert!(s.contains("Kraft"));
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
    assert_eq!(
        compressed.compressed_bits,
        compressed.compressed_bytes as i64 * 8
    );
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
    // For arithmetic coding, Kraft sum should be exactly MILLION (frequencies sum to total).
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
    assert_eq!(
        compressed.compressed_bits,
        compressed.compressed_bytes as i64 * 8
    );
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

    assert_eq!(cert.schema, ENTROPY_SCHEMA_VERSION);
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
    assert!(!cert.is_within_factor(10_000_000));
}

#[test]
fn certificate_is_within_factor_passing() {
    let cert = CompressionCertificate {
        schema: ENTROPY_SCHEMA_VERSION.to_string(),
        entropy_millibits_per_symbol: MILLION,
        shannon_lower_bound_bits: 100,
        achieved_bits: 120,
        overhead_bits_millionths: 20 * MILLION,
        overhead_ratio_millionths: 1_200_000,
        kraft_sum_millionths: MILLION,
        kraft_satisfied: true,
        redundancy_millibits: 0,
        symbol_count: 100,
        certificate_hash: test_hash(b"factor"),
    };
    // 1.2x overhead is within 2.0x factor.
    assert!(cert.is_within_factor(2_000_000));
    // But not within 1.1x factor.
    assert!(!cert.is_within_factor(1_100_000));
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
        schema: ENTROPY_SCHEMA_VERSION.to_string(),
        entropy_millibits_per_symbol: 500_000,
        shannon_lower_bound_bits: 50,
        achieved_bits: 60,
        overhead_bits_millionths: 10 * MILLION,
        overhead_ratio_millionths: 1_200_000,
        kraft_sum_millionths: MILLION,
        kraft_satisfied: true,
        redundancy_millibits: 500_000,
        symbol_count: 200,
        certificate_hash: test_hash(b"cert-serde"),
    };
    let json = serde_json::to_string(&cert).unwrap();
    let restored: CompressionCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, restored);
}

#[test]
fn certificate_clone_eq() {
    let cert = CompressionCertificate {
        schema: ENTROPY_SCHEMA_VERSION.to_string(),
        entropy_millibits_per_symbol: MILLION,
        shannon_lower_bound_bits: 100,
        achieved_bits: 110,
        overhead_bits_millionths: 10 * MILLION,
        overhead_ratio_millionths: 1_100_000,
        kraft_sum_millionths: MILLION,
        kraft_satisfied: true,
        redundancy_millibits: 0,
        symbol_count: 500,
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
        compressed.content_hash.clone(),
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
