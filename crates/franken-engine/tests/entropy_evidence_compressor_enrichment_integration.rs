//! Enrichment integration tests for the `entropy_evidence_compressor` module.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering/dedup, serde roundtrips,
//! Display coverage, Debug nonempty, Default, std::error::Error, JSON
//! field-name stability, determinism, and edge cases.

use std::collections::BTreeSet;

use frankenengine_engine::entropy_evidence_compressor::{
    ArithmeticCoder, CompressedEvidence, CompressionCertificate, ENTROPY_SCHEMA_VERSION,
    EntropyError, EntropyEstimator, SufficientStatistic,
};
use frankenengine_engine::hash_tiers::ContentHash;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn uniform_two_estimator() -> EntropyEstimator {
    let mut est = EntropyEstimator::new();
    for _ in 0..1000 {
        est.observe(0);
        est.observe(1);
    }
    est
}

fn uniform_four_estimator() -> EntropyEstimator {
    let mut est = EntropyEstimator::new();
    for _ in 0..1000 {
        for sym in 0..4u32 {
            est.observe(sym);
        }
    }
    est
}

fn make_sufficient_stat(est: &EntropyEstimator) -> SufficientStatistic {
    SufficientStatistic::from_estimator(est, 500_000, 1_000_000, ContentHash::compute(b"test"))
}

// -----------------------------------------------------------------------
// Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_estimator_clone_independence() {
    let original = uniform_two_estimator();
    let mut cloned = original.clone();
    cloned.observe(99);
    assert_eq!(original.total_count, 2000);
    assert_eq!(cloned.total_count, 2001);
}

#[test]
fn enrichment_sufficient_statistic_clone_independence() {
    let est = uniform_two_estimator();
    let original = make_sufficient_stat(&est);
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.total_count, cloned.total_count);
}

#[test]
fn enrichment_arithmetic_coder_clone_independence() {
    let est = uniform_two_estimator();
    let original = ArithmeticCoder::from_estimator(&est).unwrap();
    let cloned = original.clone();
    assert_eq!(original, cloned);
    assert_eq!(original.alphabet_size, cloned.alphabet_size);
}

#[test]
fn enrichment_compressed_evidence_clone_independence() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..100).map(|i| i % 2).collect();
    let original = coder.encode(&symbols).unwrap();
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_entropy_error_clone_independence() {
    let original = EntropyError::EmptyInput;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

// -----------------------------------------------------------------------
// Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_estimator_serde_roundtrip() {
    let est = uniform_four_estimator();
    let json = serde_json::to_string(&est).unwrap();
    let back: EntropyEstimator = serde_json::from_str(&json).unwrap();
    assert_eq!(est, back);
}

#[test]
fn enrichment_entropy_estimator_empty_serde() {
    let est = EntropyEstimator::new();
    let json = serde_json::to_string(&est).unwrap();
    let back: EntropyEstimator = serde_json::from_str(&json).unwrap();
    assert_eq!(est, back);
}

#[test]
fn enrichment_entropy_error_serde_all_variants() {
    let variants = [
        EntropyError::AlphabetTooLarge {
            size: 300,
            max: 256,
        },
        EntropyError::EmptyInput,
        EntropyError::UnknownSymbol { symbol: 42 },
        EntropyError::DecodeError {
            message: "bad data".to_string(),
        },
        EntropyError::InsufficientSamples { count: 5, min: 10 },
        EntropyError::KraftViolation {
            kraft_sum_millionths: 1_500_000,
        },
    ];
    assert_eq!(variants.len(), 6, "must cover all EntropyError variants");
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: EntropyError = serde_json::from_str(&json).unwrap();
        assert_eq!(*v, back);
    }
}

#[test]
fn enrichment_sufficient_statistic_serde_roundtrip() {
    let est = uniform_two_estimator();
    let ss = make_sufficient_stat(&est);
    let json = serde_json::to_string(&ss).unwrap();
    let back: SufficientStatistic = serde_json::from_str(&json).unwrap();
    assert_eq!(ss, back);
}

#[test]
fn enrichment_arithmetic_coder_serde_roundtrip() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let json = serde_json::to_string(&coder).unwrap();
    let back: ArithmeticCoder = serde_json::from_str(&json).unwrap();
    assert_eq!(coder, back);
}

#[test]
fn enrichment_compressed_evidence_serde_roundtrip() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..50).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let json = serde_json::to_string(&compressed).unwrap();
    let back: CompressedEvidence = serde_json::from_str(&json).unwrap();
    assert_eq!(compressed, back);
}

#[test]
fn enrichment_compression_certificate_serde_roundtrip() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..100).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    let json = serde_json::to_string(&cert).unwrap();
    let back: CompressionCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, back);
}

// -----------------------------------------------------------------------
// Display coverage — EntropyError all variants
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_error_display_all_variants() {
    let variants = [
        EntropyError::AlphabetTooLarge {
            size: 300,
            max: 256,
        },
        EntropyError::EmptyInput,
        EntropyError::UnknownSymbol { symbol: 42 },
        EntropyError::DecodeError {
            message: "corrupt".to_string(),
        },
        EntropyError::InsufficientSamples { count: 3, min: 10 },
        EntropyError::KraftViolation {
            kraft_sum_millionths: 2_000_000,
        },
    ];
    for v in &variants {
        let s = v.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn enrichment_entropy_error_display_uniqueness() {
    let variants = [
        EntropyError::AlphabetTooLarge {
            size: 300,
            max: 256,
        },
        EntropyError::EmptyInput,
        EntropyError::UnknownSymbol { symbol: 42 },
        EntropyError::DecodeError {
            message: "corrupt".to_string(),
        },
        EntropyError::InsufficientSamples { count: 3, min: 10 },
        EntropyError::KraftViolation {
            kraft_sum_millionths: 2_000_000,
        },
    ];
    let set: BTreeSet<String> = variants.iter().map(|v| v.to_string()).collect();
    assert_eq!(set.len(), variants.len());
}

#[test]
fn enrichment_entropy_error_display_contains_values() {
    let err = EntropyError::AlphabetTooLarge {
        size: 300,
        max: 256,
    };
    assert!(err.to_string().contains("300"));
    assert!(err.to_string().contains("256"));

    let err = EntropyError::UnknownSymbol { symbol: 42 };
    assert!(err.to_string().contains("42"));

    let err = EntropyError::InsufficientSamples { count: 5, min: 10 };
    assert!(err.to_string().contains("5"));
    assert!(err.to_string().contains("10"));
}

// -----------------------------------------------------------------------
// Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_estimator_debug_nonempty() {
    let est = EntropyEstimator::new();
    assert!(!format!("{est:?}").is_empty());
}

#[test]
fn enrichment_sufficient_statistic_debug_nonempty() {
    let est = uniform_two_estimator();
    let ss = make_sufficient_stat(&est);
    assert!(!format!("{ss:?}").is_empty());
}

#[test]
fn enrichment_arithmetic_coder_debug_nonempty() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    assert!(!format!("{coder:?}").is_empty());
}

#[test]
fn enrichment_compressed_evidence_debug_nonempty() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1, 0, 1]).unwrap();
    assert!(!format!("{compressed:?}").is_empty());
}

#[test]
fn enrichment_compression_certificate_debug_nonempty() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert!(!format!("{cert:?}").is_empty());
}

#[test]
fn enrichment_entropy_error_debug_nonempty() {
    let err = EntropyError::EmptyInput;
    assert!(!format!("{err:?}").is_empty());
}

// -----------------------------------------------------------------------
// Default
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_estimator_default() {
    let est = EntropyEstimator::default();
    assert_eq!(est.total_count, 0);
    assert_eq!(est.alphabet_size, 0);
    assert!(est.frequencies.is_empty());
}

// -----------------------------------------------------------------------
// std::error::Error
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(EntropyError::EmptyInput);
    assert!(!err.to_string().is_empty());
}

#[test]
fn enrichment_entropy_error_source_is_none() {
    use std::error::Error;
    let err = EntropyError::EmptyInput;
    assert!(err.source().is_none());
}

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

#[test]
fn enrichment_schema_version_nonempty() {
    assert!(!ENTROPY_SCHEMA_VERSION.is_empty());
    assert!(ENTROPY_SCHEMA_VERSION.contains("entropy"));
}

// -----------------------------------------------------------------------
// EntropyEstimator methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_estimator_observe_increments() {
    let mut est = EntropyEstimator::new();
    assert_eq!(est.total_count, 0);
    assert_eq!(est.alphabet_size, 0);

    est.observe(0);
    assert_eq!(est.total_count, 1);
    assert_eq!(est.alphabet_size, 1);

    est.observe(0);
    assert_eq!(est.total_count, 2);
    assert_eq!(est.alphabet_size, 1);

    est.observe(1);
    assert_eq!(est.total_count, 3);
    assert_eq!(est.alphabet_size, 2);
}

#[test]
fn enrichment_estimator_probability_zero_total() {
    let est = EntropyEstimator::new();
    assert_eq!(est.probability_millionths(0), 0);
}

#[test]
fn enrichment_estimator_probability_unseen_symbol() {
    let mut est = EntropyEstimator::new();
    est.observe(0);
    assert_eq!(est.probability_millionths(99), 0);
}

#[test]
fn enrichment_estimator_max_entropy_single_symbol() {
    let mut est = EntropyEstimator::new();
    for _ in 0..100 {
        est.observe(0);
    }
    assert_eq!(est.max_entropy_millibits(), 0);
}

#[test]
fn enrichment_estimator_max_entropy_empty() {
    let est = EntropyEstimator::new();
    assert_eq!(est.max_entropy_millibits(), 0);
}

#[test]
fn enrichment_estimator_entropy_below_min_samples() {
    let mut est = EntropyEstimator::new();
    for i in 0..5u32 {
        est.observe(i);
    }
    // Only 5 samples, below MIN_SAMPLES_FOR_ENTROPY=10
    assert_eq!(est.entropy_millibits(), 0);
}

#[test]
fn enrichment_estimator_redundancy_skewed() {
    let mut est = EntropyEstimator::new();
    for _ in 0..950 {
        est.observe(0);
    }
    for _ in 0..50 {
        est.observe(1);
    }
    let r = est.redundancy_millibits();
    // Skewed distribution has positive redundancy
    assert!(r > 0);
}

#[test]
fn enrichment_estimator_shannon_lower_bound_positive() {
    let est = uniform_two_estimator();
    let lb = est.shannon_lower_bound_bits();
    assert!(lb > 0);
}

// -----------------------------------------------------------------------
// SufficientStatistic methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_sufficient_stat_consistency() {
    let est = uniform_four_estimator();
    let ss = make_sufficient_stat(&est);
    assert!(ss.is_consistent());
}

#[test]
fn enrichment_sufficient_stat_fisher_sufficient_flag() {
    let est = uniform_two_estimator();
    let ss = make_sufficient_stat(&est);
    assert!(ss.is_fisher_sufficient);
}

#[test]
fn enrichment_sufficient_stat_fisher_information_positive() {
    let est = uniform_two_estimator();
    let ss = SufficientStatistic::from_estimator(
        &est,
        500_000,
        2_000_000,
        ContentHash::compute(b"fisher"),
    );
    let fi = ss.fisher_information_millionths();
    assert!(fi > 0);
}

#[test]
fn enrichment_sufficient_stat_fisher_information_low_count() {
    let mut est = EntropyEstimator::new();
    est.observe(0);
    let ss = make_sufficient_stat(&est);
    assert_eq!(ss.fisher_information_millionths(), 0);
}

#[test]
fn enrichment_sufficient_stat_mean_computed() {
    let mut est = EntropyEstimator::new();
    for _ in 0..100 {
        est.observe(0);
    }
    let ss = SufficientStatistic::from_estimator(
        &est,
        1_000_000,
        2_000_000,
        ContentHash::compute(b"mean"),
    );
    // mean = cumulative_llr / total = 1_000_000 / 100 = 10_000
    assert_eq!(ss.mean_millionths, 10_000);
}

// -----------------------------------------------------------------------
// ArithmeticCoder
// -----------------------------------------------------------------------

#[test]
fn enrichment_coder_from_empty_estimator_fails() {
    let est = EntropyEstimator::new();
    let err = ArithmeticCoder::from_estimator(&est).unwrap_err();
    assert!(matches!(err, EntropyError::EmptyInput));
}

#[test]
fn enrichment_coder_from_large_alphabet_fails() {
    let mut est = EntropyEstimator::new();
    for i in 0..257u32 {
        est.observe(i);
    }
    let err = ArithmeticCoder::from_estimator(&est).unwrap_err();
    assert!(matches!(err, EntropyError::AlphabetTooLarge { .. }));
}

#[test]
fn enrichment_coder_encode_empty_fails() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let err = coder.encode(&[]).unwrap_err();
    assert!(matches!(err, EntropyError::EmptyInput));
}

#[test]
fn enrichment_coder_encode_unknown_symbol_fails() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let err = coder.encode(&[0, 1, 99]).unwrap_err();
    assert!(matches!(err, EntropyError::UnknownSymbol { symbol: 99 }));
}

#[test]
fn enrichment_coder_kraft_inequality_satisfied() {
    let est = uniform_four_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    // Should be approximately 1_000_000 (= 1.0)
    assert!(kraft <= 1_001_000);
    assert!(kraft > 0);
}

#[test]
fn enrichment_coder_expected_code_length_positive() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let ecl = coder.expected_code_length_millibits();
    assert!(ecl > 0);
}

#[test]
fn enrichment_coder_total_frequency_matches_observations() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    assert_eq!(coder.alphabet_size, 2);
    assert_eq!(coder.total_frequency, 2000);
}

// -----------------------------------------------------------------------
// CompressedEvidence
// -----------------------------------------------------------------------

#[test]
fn enrichment_compressed_evidence_schema_version() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1, 0]).unwrap();
    assert_eq!(compressed.schema, ENTROPY_SCHEMA_VERSION);
}

#[test]
fn enrichment_compressed_evidence_symbol_count() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols = vec![0, 1, 0, 1, 0];
    let compressed = coder.encode(&symbols).unwrap();
    assert_eq!(compressed.original_symbol_count, 5);
}

#[test]
fn enrichment_compressed_evidence_bytes_positive() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    assert!(compressed.compressed_bytes > 0);
    assert_eq!(
        compressed.compressed_bytes,
        compressed.compressed_data.len()
    );
    assert_eq!(
        compressed.compressed_bits,
        compressed.compressed_bytes as i64 * 8
    );
}

// -----------------------------------------------------------------------
// CompressionCertificate
// -----------------------------------------------------------------------

#[test]
fn enrichment_certificate_schema_version() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert_eq!(cert.schema, ENTROPY_SCHEMA_VERSION);
}

#[test]
fn enrichment_certificate_kraft_satisfied() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert!(cert.kraft_satisfied);
}

#[test]
fn enrichment_certificate_entropy_positive() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert!(cert.entropy_millibits_per_symbol > 0);
}

#[test]
fn enrichment_certificate_is_within_factor() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..200).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    // Within 10x of Shannon optimal (very generous)
    assert!(cert.is_within_factor(10_000_000));
}

#[test]
fn enrichment_certificate_hash_nonempty() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    assert_ne!(cert.certificate_hash, ContentHash::compute(b""));
}

// -----------------------------------------------------------------------
// JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_estimator_json_field_names() {
    let est = uniform_two_estimator();
    let json = serde_json::to_string(&est).unwrap();
    assert!(json.contains("\"frequencies\""));
    assert!(json.contains("\"total_count\""));
    assert!(json.contains("\"alphabet_size\""));
}

#[test]
fn enrichment_compressed_evidence_json_field_names() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    let json = serde_json::to_string(&compressed).unwrap();
    assert!(json.contains("\"schema\""));
    assert!(json.contains("\"compressed_data\""));
    assert!(json.contains("\"original_symbol_count\""));
    assert!(json.contains("\"compressed_bytes\""));
    assert!(json.contains("\"compression_ratio_millionths\""));
    assert!(json.contains("\"content_hash\""));
}

#[test]
fn enrichment_compression_certificate_json_field_names() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 1]).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let cert = CompressionCertificate::build(&est, &compressed, kraft);
    let json = serde_json::to_string(&cert).unwrap();
    assert!(json.contains("\"entropy_millibits_per_symbol\""));
    assert!(json.contains("\"shannon_lower_bound_bits\""));
    assert!(json.contains("\"overhead_ratio_millionths\""));
    assert!(json.contains("\"kraft_satisfied\""));
    assert!(json.contains("\"redundancy_millibits\""));
    assert!(json.contains("\"symbol_count\""));
}

#[test]
fn enrichment_sufficient_statistic_json_field_names() {
    let est = uniform_two_estimator();
    let ss = make_sufficient_stat(&est);
    let json = serde_json::to_string(&ss).unwrap();
    assert!(json.contains("\"symbol_counts\""));
    assert!(json.contains("\"total_count\""));
    assert!(json.contains("\"cumulative_llr_millionths\""));
    assert!(json.contains("\"mean_millionths\""));
    assert!(json.contains("\"is_fisher_sufficient\""));
}

// -----------------------------------------------------------------------
// Determinism
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_determinism_50_runs() {
    let mut first_entropy = 0i64;
    for i in 0..50 {
        let est = uniform_two_estimator();
        let h = est.entropy_millibits();
        if i == 0 {
            first_entropy = h;
        } else {
            assert_eq!(h, first_entropy);
        }
    }
}

#[test]
fn enrichment_compression_determinism_20_runs() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..100).map(|i| i % 2).collect();
    let first = coder.encode(&symbols).unwrap();
    for _ in 1..20 {
        let result = coder.encode(&symbols).unwrap();
        assert_eq!(result.compressed_data, first.compressed_data);
        assert_eq!(result.content_hash, first.content_hash);
    }
}

#[test]
fn enrichment_certificate_determinism_20_runs() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..100).map(|i| i % 2).collect();
    let compressed = coder.encode(&symbols).unwrap();
    let kraft = coder.verify_kraft_inequality().unwrap();
    let first = CompressionCertificate::build(&est, &compressed, kraft);
    for _ in 1..20 {
        let cert = CompressionCertificate::build(&est, &compressed, kraft);
        assert_eq!(cert.certificate_hash, first.certificate_hash);
        assert_eq!(
            cert.overhead_ratio_millionths,
            first.overhead_ratio_millionths
        );
    }
}

// -----------------------------------------------------------------------
// Edge cases
// -----------------------------------------------------------------------

#[test]
fn enrichment_single_symbol_entropy_zero() {
    let mut est = EntropyEstimator::new();
    for _ in 0..100 {
        est.observe(0);
    }
    assert_eq!(est.entropy_millibits(), 0);
    assert_eq!(est.redundancy_millibits(), 0);
}

#[test]
fn enrichment_single_symbol_encodes_successfully() {
    let mut est = EntropyEstimator::new();
    for _ in 0..100 {
        est.observe(0);
    }
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let compressed = coder.encode(&[0, 0, 0]).unwrap();
    assert_eq!(compressed.original_symbol_count, 3);
}

#[test]
fn enrichment_max_alphabet_size_encodes() {
    let mut est = EntropyEstimator::new();
    for i in 0..256u32 {
        est.observe(i);
    }
    assert_eq!(est.alphabet_size, 256);
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let symbols: Vec<u32> = (0..256).collect();
    let compressed = coder.encode(&symbols).unwrap();
    assert_eq!(compressed.original_symbol_count, 256);
}

#[test]
fn enrichment_content_hash_changes_with_different_symbols() {
    let est = uniform_two_estimator();
    let coder = ArithmeticCoder::from_estimator(&est).unwrap();
    let c1 = coder.encode(&[0, 0, 0]).unwrap();
    let c2 = coder.encode(&[1, 1, 1]).unwrap();
    assert_ne!(c1.content_hash, c2.content_hash);
}

// -----------------------------------------------------------------------
// Sufficient statistic edge cases
// -----------------------------------------------------------------------

#[test]
fn enrichment_sufficient_stat_empty_estimator() {
    let est = EntropyEstimator::new();
    let ss = SufficientStatistic::from_estimator(&est, 0, 0, ContentHash::compute(b"empty"));
    assert!(ss.is_consistent());
    assert_eq!(ss.total_count, 0);
    assert_eq!(ss.mean_millionths, 0);
}

#[test]
fn enrichment_sufficient_stat_inconsistent_detection() {
    let est = uniform_two_estimator();
    let mut ss = make_sufficient_stat(&est);
    ss.total_count = 9999; // Deliberately mismatched
    assert!(!ss.is_consistent());
}

// -----------------------------------------------------------------------
// BTreeSet ordering
// -----------------------------------------------------------------------

#[test]
fn enrichment_entropy_error_serde_unique_json() {
    let variants = [
        EntropyError::AlphabetTooLarge {
            size: 300,
            max: 256,
        },
        EntropyError::EmptyInput,
        EntropyError::UnknownSymbol { symbol: 42 },
        EntropyError::DecodeError {
            message: "bad".to_string(),
        },
        EntropyError::InsufficientSamples { count: 3, min: 10 },
        EntropyError::KraftViolation {
            kraft_sum_millionths: 2_000_000,
        },
    ];
    let set: BTreeSet<String> = variants
        .iter()
        .map(|v| serde_json::to_string(v).unwrap())
        .collect();
    assert_eq!(set.len(), variants.len());
}
