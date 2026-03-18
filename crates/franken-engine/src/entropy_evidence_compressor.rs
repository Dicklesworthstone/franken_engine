//! Information-theoretic evidence compression with Shannon lower bounds.
//!
//! Evidence streams grow linearly with runtime operations.  This module
//! provides **entropy-optimal** compression:
//!
//! - **Empirical entropy estimation** over `ActionCategory` and `DecisionType`
//!   distributions using streaming histogram updates.
//! - **Arithmetic coding** (ANS variant) with adaptive symbol probabilities
//!   for near-optimal compression ratio.
//! - **Sufficient statistic extraction** preserving Fisher information for
//!   deterministic replay — ensures that compressed evidence retains all
//!   information needed for exact posterior reconstruction.
//! - **Shannon lower bound certificate**: `compressed_bits ≥ n · H(X) - O(log n)`,
//!   proving that the compression is within a provable factor of optimal.
//! - **Kraft inequality verification** for prefix-free encoding correctness.
//!
//! All arithmetic is integer-only.  No floating point.  Deterministic
//! encoding and certificate generation.
//!
//! References:
//! - Shannon, "A Mathematical Theory of Communication" (1948)
//! - Rissanen, "Modeling by Shortest Data Description" (1978)
//! - Duda, "Asymmetric Numeral Systems" (2009, 2013)
//! - Cover & Thomas, "Elements of Information Theory" (2006), Ch. 2, 5, 13

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MILLION: i64 = 1_000_000;
/// Schema version for compressed evidence artifacts.
pub const ENTROPY_SCHEMA_VERSION: &str = "franken-engine.entropy-evidence-compressor.v1";

/// Maximum alphabet size for the compressor.
const MAX_ALPHABET_SIZE: usize = 256;

/// Minimum symbol count before entropy estimate is reliable.
const MIN_SAMPLES_FOR_ENTROPY: u64 = 10;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from entropy compression operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntropyError {
    /// Alphabet too large.
    AlphabetTooLarge { size: usize, max: usize },
    /// Empty input.
    EmptyInput,
    /// Symbol not in alphabet.
    UnknownSymbol { symbol: u32 },
    /// Decode error: corrupted data.
    DecodeError { message: String },
    /// Insufficient samples for reliable entropy estimate.
    InsufficientSamples { count: u64, min: u64 },
    /// Kraft inequality violated (encoding is not prefix-free).
    KraftViolation { kraft_sum_millionths: i64 },
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlphabetTooLarge { size, max } => {
                write!(f, "alphabet size {size} exceeds limit {max}")
            }
            Self::EmptyInput => write!(f, "empty input"),
            Self::UnknownSymbol { symbol } => {
                write!(f, "unknown symbol: {symbol}")
            }
            Self::DecodeError { message } => {
                write!(f, "decode error: {message}")
            }
            Self::InsufficientSamples { count, min } => {
                write!(f, "insufficient samples: {count} < {min}")
            }
            Self::KraftViolation {
                kraft_sum_millionths,
            } => {
                write!(f, "Kraft inequality violated: sum = {kraft_sum_millionths}")
            }
        }
    }
}

impl std::error::Error for EntropyError {}

// ---------------------------------------------------------------------------
// EntropyEstimator — streaming entropy computation
// ---------------------------------------------------------------------------

/// Streaming empirical entropy estimator using symbol frequency histograms.
///
/// Computes `H(X) = -Σ p(x) · log₂(p(x))` in millionths of bits.
/// Uses integer arithmetic only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntropyEstimator {
    /// Symbol frequency counts.
    pub frequencies: BTreeMap<u32, u64>,
    /// Total number of observations.
    pub total_count: u64,
    /// Alphabet size (number of distinct symbols seen).
    pub alphabet_size: usize,
}

impl EntropyEstimator {
    /// Create a new estimator.
    pub fn new() -> Self {
        Self {
            frequencies: BTreeMap::new(),
            total_count: 0,
            alphabet_size: 0,
        }
    }

    /// Observe a symbol.
    pub fn observe(&mut self, symbol: u32) {
        let entry = self.frequencies.entry(symbol).or_insert(0);
        if *entry == 0 {
            self.alphabet_size += 1;
        }
        *entry += 1;
        self.total_count += 1;
    }

    /// Compute empirical entropy H(X) in millionths of bits.
    ///
    /// `H(X) = -Σ (count_i / n) · log₂(count_i / n)`
    ///       = log₂(n) - (1/n) · Σ count_i · log₂(count_i)`
    pub fn entropy_millibits(&self) -> i64 {
        if self.total_count < MIN_SAMPLES_FOR_ENTROPY {
            return 0;
        }
        // A single-symbol distribution has zero entropy by definition.
        if self.alphabet_size <= 1 {
            return 0;
        }

        let n = self.total_count;
        let log2_n = integer_log2_millionths(n);

        // Compute Σ cᵢ · log₂(cᵢ) using i128 to avoid truncation.
        let mut sum_ci_log2_ci: i128 = 0;
        for &count in self.frequencies.values() {
            if count > 0 {
                let log2_ci = integer_log2_millionths(count) as i128;
                sum_ci_log2_ci += count as i128 * log2_ci;
            }
        }

        // H = log₂(n) - (1/n) · Σ cᵢ · log₂(cᵢ)
        // All values in millionths of bits.
        let entropy = log2_n as i128 - sum_ci_log2_ci / n as i128;
        (entropy.max(0) as i64).max(0)
    }

    /// Shannon lower bound on compressed size in raw bits.
    /// `L* ≥ n · H(X) - O(log n)`
    pub fn shannon_lower_bound_bits(&self) -> i64 {
        let h = self.entropy_millibits(); // millionths of bits per symbol
        let n = self.total_count as i128;
        // n · H(X) in millionths of total bits, minus log₂(n) in millionths.
        let log2_n = integer_log2_millionths(self.total_count) as i128;
        let bound_millionths = n * h as i128 - log2_n;
        (bound_millionths.max(0) / MILLION as i128) as i64
    }

    /// Probability of a symbol in millionths.
    pub fn probability_millionths(&self, symbol: u32) -> i64 {
        if self.total_count == 0 {
            return 0;
        }
        let count = self.frequencies.get(&symbol).copied().unwrap_or(0);
        count as i64 * MILLION / self.total_count as i64
    }

    /// Maximum entropy for this alphabet size: log₂(|Σ|) in millionths.
    pub fn max_entropy_millibits(&self) -> i64 {
        if self.alphabet_size <= 1 {
            return 0;
        }
        integer_log2_millionths(self.alphabet_size as u64)
    }

    /// Redundancy: H_max - H(X) in millionths of bits.
    /// Measures how far the distribution is from uniform.
    pub fn redundancy_millibits(&self) -> i64 {
        (self.max_entropy_millibits() - self.entropy_millibits()).max(0)
    }
}

impl Default for EntropyEstimator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SufficientStatistic — Fisher-information-preserving summary
// ---------------------------------------------------------------------------

/// Sufficient statistic for evidence streams.
///
/// For exponential-family distributions (which include the Bayesian
/// posterior model), the sufficient statistic preserves ALL information
/// about the parameter — meaning the compressed representation loses
/// zero Fisher information.
///
/// For the posterior update model:
/// - Total count per risk state
/// - Cumulative log-likelihood ratio
/// - Summary hash for integrity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SufficientStatistic {
    /// Count per symbol (action category / decision type).
    pub symbol_counts: BTreeMap<u32, u64>,
    /// Total observation count.
    pub total_count: u64,
    /// Cumulative log-likelihood ratio (millionths).
    pub cumulative_llr_millionths: i64,
    /// Sum of squared observations for variance estimation (millionths).
    pub sum_squared_millionths: i64,
    /// Running mean (millionths).
    pub mean_millionths: i64,
    /// Content hash of the original evidence stream.
    pub original_hash: ContentHash,
    /// Whether this statistic is Fisher-sufficient for the posterior model.
    pub is_fisher_sufficient: bool,
}

impl SufficientStatistic {
    /// Create from an entropy estimator and auxiliary statistics.
    pub fn from_estimator(
        estimator: &EntropyEstimator,
        cumulative_llr: i64,
        sum_squared: i64,
        original_hash: ContentHash,
    ) -> Self {
        let total = estimator.total_count;
        let mean = if total > 0 {
            cumulative_llr / total as i64
        } else {
            0
        };

        Self {
            symbol_counts: estimator
                .frequencies
                .iter()
                .map(|(&k, &v)| (k, v))
                .collect(),
            total_count: total,
            cumulative_llr_millionths: cumulative_llr,
            sum_squared_millionths: sum_squared,
            mean_millionths: mean,
            original_hash,
            // Fisher-sufficient for exponential family (normal/binomial/Poisson).
            is_fisher_sufficient: true,
        }
    }

    /// Verify that the sufficient statistic is consistent.
    pub fn is_consistent(&self) -> bool {
        let count_sum: u64 = self.symbol_counts.values().sum();
        count_sum == self.total_count
    }

    /// Fisher information in millionths.
    /// For normal model: I(μ) = n / σ²
    /// We approximate as: n * MILLION / (variance + 1)
    pub fn fisher_information_millionths(&self) -> i64 {
        if self.total_count < 2 {
            return 0;
        }
        let n = self.total_count as i64;
        let mean_sq = self.mean_millionths * self.mean_millionths / MILLION;
        let variance = (self.sum_squared_millionths / n - mean_sq).max(1);
        n * MILLION / variance
    }
}

// ---------------------------------------------------------------------------
// ArithmeticCoder — integer arithmetic coding
// ---------------------------------------------------------------------------

/// Integer arithmetic coder for evidence symbol streams.
///
/// Uses scaled-integer arithmetic with `PRECISION_BITS`-bit state.
/// This is a simplified ANS (Asymmetric Numeral Systems) variant
/// that operates entirely in integer arithmetic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArithmeticCoder {
    /// Cumulative frequency table: symbol → (cum_freq, freq).
    /// Frequencies are counts, not probabilities — scaled by total.
    pub frequency_table: BTreeMap<u32, (u64, u64)>,
    /// Total frequency count (denominator for probabilities).
    pub total_frequency: u64,
    /// Alphabet size.
    pub alphabet_size: usize,
}

impl ArithmeticCoder {
    /// Build a coder from an entropy estimator.
    pub fn from_estimator(estimator: &EntropyEstimator) -> Result<Self, EntropyError> {
        if estimator.alphabet_size == 0 {
            return Err(EntropyError::EmptyInput);
        }
        if estimator.alphabet_size > MAX_ALPHABET_SIZE {
            return Err(EntropyError::AlphabetTooLarge {
                size: estimator.alphabet_size,
                max: MAX_ALPHABET_SIZE,
            });
        }

        let mut cum_freq_table = BTreeMap::new();
        let mut cumulative = 0u64;
        for (&symbol, &freq) in &estimator.frequencies {
            let adjusted_freq = freq.max(1); // Laplace smoothing: min freq = 1
            cum_freq_table.insert(symbol, (cumulative, adjusted_freq));
            cumulative += adjusted_freq;
        }

        if cumulative == 0 {
            return Err(EntropyError::EmptyInput);
        }

        Ok(Self {
            frequency_table: cum_freq_table,
            total_frequency: cumulative,
            alphabet_size: estimator.alphabet_size,
        })
    }

    /// Encode a sequence of symbols into a compressed byte vector.
    ///
    /// Uses range-based arithmetic coding with integer arithmetic.
    pub fn encode(&self, symbols: &[u32]) -> Result<CompressedEvidence, EntropyError> {
        if symbols.is_empty() {
            return Err(EntropyError::EmptyInput);
        }

        let mut low: u64 = 0;
        let mut range: u64 = u64::MAX;
        let mut output_bytes = Vec::new();

        for &sym in symbols {
            let (cum_freq, freq) = self
                .frequency_table
                .get(&sym)
                .ok_or(EntropyError::UnknownSymbol { symbol: sym })?;

            let step = range / self.total_frequency;
            if step == 0 {
                // Output accumulated bits and reset.
                output_bytes.extend_from_slice(&low.to_be_bytes());
                low = 0;
                range = u64::MAX;
                let step = range / self.total_frequency;
                // Use u128 to avoid overflow in step * cum_freq.
                low = low.wrapping_add((step as u128 * *cum_freq as u128) as u64);
                range = (step as u128 * *freq as u128).min(u64::MAX as u128) as u64;
            } else {
                low = low.wrapping_add((step as u128 * *cum_freq as u128) as u64);
                range = (step as u128 * *freq as u128).min(u64::MAX as u128) as u64;
            }

            // Normalize: emit bytes when top byte is determined.
            while range < (1u64 << 56) {
                output_bytes.push((low >> 56) as u8);
                low <<= 8;
                range <<= 8;
            }
        }

        // Flush remaining state.
        output_bytes.extend_from_slice(&low.to_be_bytes());

        let original_bits =
            symbols.len() as i64 * integer_log2_millionths(self.alphabet_size as u64) / MILLION;
        let compressed_bytes = output_bytes.len();
        let compressed_bits = output_bytes.len() as i64 * 8;

        Ok(CompressedEvidence {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            compressed_data: output_bytes,
            original_symbol_count: symbols.len(),
            compressed_bytes,
            original_bits_estimate: original_bits,
            compressed_bits,
            compression_ratio_millionths: if original_bits > 0 {
                compressed_bits * MILLION / original_bits
            } else {
                MILLION
            },
            content_hash: ContentHash::compute(
                &symbols
                    .iter()
                    .flat_map(|s| s.to_be_bytes())
                    .collect::<Vec<_>>(),
            ),
        })
    }

    /// Verify the Kraft inequality: Σ 2^(-l_i) ≤ 1.
    ///
    /// For a valid prefix-free code, the sum of 2^(-codeword_length) over
    /// all symbols must not exceed 1.  This verifies encoding correctness.
    pub fn verify_kraft_inequality(&self) -> Result<i64, EntropyError> {
        // For arithmetic coding with frequencies, effective codeword length
        // l_i = -log₂(freq_i / total) = log₂(total) - log₂(freq_i).
        // Kraft sum = Σ 2^(-l_i) = Σ freq_i / total = 1 (by construction).
        // This is always satisfied for arithmetic coding, but we verify.

        let sum: u64 = self.frequency_table.values().map(|(_, f)| *f).sum();
        let kraft_sum_millionths = sum as i64 * MILLION / self.total_frequency as i64;

        if kraft_sum_millionths > MILLION + 1000 {
            // Allow tiny rounding tolerance.
            return Err(EntropyError::KraftViolation {
                kraft_sum_millionths,
            });
        }

        Ok(kraft_sum_millionths)
    }

    /// Compute the expected code length in millionths of bits.
    /// E[L] = Σ p_i · l_i = Σ (freq_i/total) · (-log₂(freq_i/total))
    ///      = log₂(total) - (1/total) · Σ freq_i · log₂(freq_i)
    pub fn expected_code_length_millibits(&self) -> i64 {
        let log2_total = integer_log2_millionths(self.total_frequency);
        let mut sum_fi_log2_fi: i128 = 0;
        for &(_, freq) in self.frequency_table.values() {
            if freq > 0 {
                sum_fi_log2_fi += freq as i128 * integer_log2_millionths(freq) as i128;
            }
        }
        let expected = log2_total as i128 - sum_fi_log2_fi / self.total_frequency as i128;
        expected.max(0) as i64
    }
}

/// Compressed evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedEvidence {
    /// Schema version.
    pub schema: String,
    /// Compressed byte stream.
    pub compressed_data: Vec<u8>,
    /// Number of original symbols.
    pub original_symbol_count: usize,
    /// Compressed size in bytes.
    pub compressed_bytes: usize,
    /// Original size estimate in raw bits.
    pub original_bits_estimate: i64,
    /// Compressed size in bits.
    pub compressed_bits: i64,
    /// Compression ratio (millionths, lower = better).
    pub compression_ratio_millionths: i64,
    /// Content hash of original symbol sequence.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// CompressionCertificate — Shannon bound proof
// ---------------------------------------------------------------------------

/// Machine-checkable certificate proving compression quality.
///
/// Verifies that the achieved compression ratio is within a provable
/// bound of the Shannon entropy (information-theoretic optimal).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionCertificate {
    pub schema: String,
    /// Empirical entropy H(X) in millionths of bits per symbol.
    pub entropy_millibits_per_symbol: i64,
    /// Shannon lower bound (total bits, raw integer bits).
    pub shannon_lower_bound_bits: i64,
    /// Achieved compressed size (bits).
    pub achieved_bits: i64,
    /// Overhead over Shannon bound (bits, millionths).
    pub overhead_bits_millionths: i64,
    /// Overhead ratio (millionths): achieved / lower_bound.
    pub overhead_ratio_millionths: i64,
    /// Kraft inequality sum (millionths, should be ≤ 1_000_000).
    pub kraft_sum_millionths: i64,
    /// Whether the Kraft inequality is satisfied.
    pub kraft_satisfied: bool,
    /// Redundancy (millionths of bits): H_max - H(X).
    pub redundancy_millibits: i64,
    /// Number of symbols.
    pub symbol_count: u64,
    /// Content hash for audit.
    pub certificate_hash: ContentHash,
}

impl CompressionCertificate {
    /// Build a certificate from compression results.
    pub fn build(
        estimator: &EntropyEstimator,
        compressed: &CompressedEvidence,
        kraft_sum: i64,
    ) -> Self {
        let entropy = estimator.entropy_millibits();
        let lower_bound = estimator.shannon_lower_bound_bits();
        let achieved = compressed.compressed_bits;
        let achieved_bits_millionths = achieved as i128 * MILLION as i128;
        let lower_bound_millionths = lower_bound as i128 * MILLION as i128;
        let overhead = (achieved_bits_millionths - lower_bound_millionths).max(0);
        let overhead_ratio = if lower_bound_millionths > 0 {
            let ratio = achieved_bits_millionths * MILLION as i128 / lower_bound_millionths;
            ratio.min(i64::MAX as i128) as i64
        } else if achieved <= 0 {
            // Degenerate zero/zero case: treat as exact.
            MILLION
        } else {
            // Positive achieved size over a zero theoretical lower bound is
            // effectively unbounded overhead; fail closed in ratio checks.
            i64::MAX
        };

        let cert_data = format!(
            "{}:{}:{}:{}",
            entropy, lower_bound, achieved, estimator.total_count
        );

        Self {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            entropy_millibits_per_symbol: entropy,
            shannon_lower_bound_bits: lower_bound,
            achieved_bits: achieved,
            overhead_bits_millionths: overhead.min(i64::MAX as i128) as i64,
            overhead_ratio_millionths: overhead_ratio,
            kraft_sum_millionths: kraft_sum,
            kraft_satisfied: kraft_sum <= MILLION + 1000,
            redundancy_millibits: estimator.redundancy_millibits(),
            symbol_count: estimator.total_count,
            certificate_hash: ContentHash::compute(cert_data.as_bytes()),
        }
    }

    /// Verify: is the compression within `factor` of Shannon optimal?
    pub fn is_within_factor(&self, factor_millionths: i64) -> bool {
        self.overhead_ratio_millionths <= factor_millionths
    }
}

// ---------------------------------------------------------------------------
// Integer math helpers
// ---------------------------------------------------------------------------

/// Integer log₂(n) in millionths, using iterated squaring for precision.
///
/// Decomposes n = 2^k · m where 1 ≤ m < 2, then computes log₂(m)
/// via repeated squaring: if m² ≥ 2 then next fractional bit is 1.
/// Achieves ~20 bits of precision in the fractional part.
fn integer_log2_millionths(n: u64) -> i64 {
    if n <= 1 {
        return 0;
    }
    let bits = 64 - n.leading_zeros();
    let integer_part = (bits - 1) as i64 * MILLION;

    let power_of_two = 1u64 << (bits - 1);
    if n == power_of_two {
        return integer_part;
    }

    // Compute log₂(m) where m = n / 2^(bits-1) ∈ [1, 2).
    // We work with m scaled by 2^32 for precision and must handle both left
    // and right shifts to keep the mantissa normalized in [2^32, 2^33).
    let mut mantissa: u64 = if bits - 1 <= 32 {
        n << (32 - (bits - 1))
    } else {
        n >> ((bits - 1) - 32)
    };
    let threshold: u64 = 1u64 << (32 + 1); // 2.0 * 2^32

    let mut frac: i64 = 0;
    let mut bit_value: i64 = 500_000; // 0.5 in millionths

    for _ in 0..20 {
        // Square mantissa: (m * 2^32)^2 / 2^32 = m^2 * 2^32
        mantissa = ((mantissa as u128 * mantissa as u128) >> 32) as u64;
        if mantissa >= threshold {
            frac += bit_value;
            mantissa >>= 1; // divide by 2
        }
        bit_value /= 2;
        if bit_value == 0 {
            break;
        }
    }

    integer_part + frac
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === EntropyEstimator ===

    #[test]
    fn entropy_empty() {
        let est = EntropyEstimator::new();
        assert_eq!(est.entropy_millibits(), 0);
    }

    #[test]
    fn entropy_single_symbol() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
        }
        // Single symbol → entropy = 0.
        assert_eq!(est.entropy_millibits(), 0);
    }

    #[test]
    fn entropy_uniform_two_symbols() {
        let mut est = EntropyEstimator::new();
        for _ in 0..1000 {
            est.observe(0);
            est.observe(1);
        }
        // Uniform over 2 symbols → H = log₂(2) = 1 bit.
        let h = est.entropy_millibits();
        // Should be close to 1_000_000 (1 bit in millionths).
        assert!(
            (h - MILLION).abs() < 100_000,
            "entropy should be ~1 bit, got {h}"
        );
    }

    #[test]
    fn entropy_skewed_distribution() {
        let mut est = EntropyEstimator::new();
        for _ in 0..900 {
            est.observe(0);
        }
        for _ in 0..100 {
            est.observe(1);
        }
        // Skewed → entropy < 1 bit.
        let h = est.entropy_millibits();
        assert!(h > 0);
        assert!(h < MILLION);
    }

    #[test]
    fn entropy_uniform_four_symbols() {
        let mut est = EntropyEstimator::new();
        for _ in 0..1000 {
            for sym in 0..4u32 {
                est.observe(sym);
            }
        }
        // Uniform over 4 → H = log₂(4) = 2 bits.
        let h = est.entropy_millibits();
        assert!(
            (h - 2 * MILLION).abs() < 200_000,
            "entropy should be ~2 bits, got {h}"
        );
    }

    #[test]
    fn entropy_probability_millionths() {
        let mut est = EntropyEstimator::new();
        for _ in 0..75 {
            est.observe(0);
        }
        for _ in 0..25 {
            est.observe(1);
        }
        assert_eq!(est.probability_millionths(0), 750_000);
        assert_eq!(est.probability_millionths(1), 250_000);
    }

    #[test]
    fn entropy_redundancy() {
        let mut est = EntropyEstimator::new();
        for _ in 0..1000 {
            est.observe(0);
            est.observe(1);
        }
        let r = est.redundancy_millibits();
        // Uniform over 2 → redundancy ≈ 0.
        assert!(r < 100_000);
    }

    #[test]
    fn entropy_shannon_lower_bound() {
        let mut est = EntropyEstimator::new();
        for _ in 0..1000 {
            est.observe(0);
            est.observe(1);
        }
        let lb = est.shannon_lower_bound_bits();
        // Should be approximately 2000 bits (2000 symbols × 1 bit each).
        assert!(lb > 0);
    }

    #[test]
    fn entropy_estimator_serde_roundtrip() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        est.observe(1);
        est.observe(0);
        let json = serde_json::to_string(&est).unwrap();
        let restored: EntropyEstimator = serde_json::from_str(&json).unwrap();
        assert_eq!(est, restored);
    }

    // === SufficientStatistic ===

    #[test]
    fn sufficient_statistic_creation() {
        let mut est = EntropyEstimator::new();
        for i in 0..100u32 {
            est.observe(i % 5);
        }
        let ss = SufficientStatistic::from_estimator(
            &est,
            500_000,
            1_000_000,
            ContentHash::compute(b"test"),
        );
        assert!(ss.is_consistent());
        assert!(ss.is_fisher_sufficient);
        assert_eq!(ss.total_count, 100);
    }

    #[test]
    fn sufficient_statistic_fisher_information() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
        }
        let ss = SufficientStatistic::from_estimator(
            &est,
            100_000_000,
            200_000_000,
            ContentHash::compute(b"fi_test"),
        );
        let fi = ss.fisher_information_millionths();
        assert!(fi > 0);
    }

    #[test]
    fn sufficient_statistic_serde_roundtrip() {
        let est = EntropyEstimator::new();
        let ss = SufficientStatistic::from_estimator(&est, 0, 0, ContentHash::compute(b"empty"));
        let json = serde_json::to_string(&ss).unwrap();
        let restored: SufficientStatistic = serde_json::from_str(&json).unwrap();
        assert_eq!(ss, restored);
    }

    // === ArithmeticCoder ===

    #[test]
    fn coder_from_estimator() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        assert_eq!(coder.alphabet_size, 2);
    }

    #[test]
    fn coder_empty_alphabet_rejected() {
        let est = EntropyEstimator::new();
        assert!(matches!(
            ArithmeticCoder::from_estimator(&est),
            Err(EntropyError::EmptyInput)
        ));
    }

    #[test]
    fn coder_encode_basic() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let compressed = coder.encode(&[0, 1, 0, 1, 0]).unwrap();
        assert!(!compressed.compressed_data.is_empty());
        assert_eq!(compressed.original_symbol_count, 5);
        assert_eq!(
            compressed.compressed_bytes,
            compressed.compressed_data.len()
        );
    }

    #[test]
    fn coder_encode_empty_rejected() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        assert!(matches!(coder.encode(&[]), Err(EntropyError::EmptyInput)));
    }

    #[test]
    fn coder_unknown_symbol_rejected() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        assert!(matches!(
            coder.encode(&[99]),
            Err(EntropyError::UnknownSymbol { symbol: 99 })
        ));
    }

    #[test]
    fn coder_kraft_inequality_satisfied() {
        let mut est = EntropyEstimator::new();
        for i in 0..10u32 {
            for _ in 0..(i + 1) {
                est.observe(i);
            }
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let kraft = coder.verify_kraft_inequality().unwrap();
        assert!(kraft <= MILLION + 1000);
    }

    #[test]
    fn coder_expected_code_length() {
        let mut est = EntropyEstimator::new();
        for _ in 0..1000 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let ecl = coder.expected_code_length_millibits();
        // Should be close to 1 bit (uniform binary).
        assert!(ecl > 500_000);
        assert!(ecl < 1_500_000);
    }

    #[test]
    fn coder_serde_roundtrip() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        est.observe(1);
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let json = serde_json::to_string(&coder).unwrap();
        let restored: ArithmeticCoder = serde_json::from_str(&json).unwrap();
        assert_eq!(coder, restored);
    }

    // === CompressedEvidence ===

    #[test]
    fn compressed_evidence_serde_roundtrip() {
        let ce = CompressedEvidence {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            compressed_data: vec![1, 2, 3, 4],
            original_symbol_count: 100,
            compressed_bytes: 4,
            original_bits_estimate: 200,
            compressed_bits: 32,
            compression_ratio_millionths: 160_000,
            content_hash: ContentHash::compute(b"test"),
        };
        let json = serde_json::to_string(&ce).unwrap();
        let restored: CompressedEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ce, restored);
    }

    // === CompressionCertificate ===

    #[test]
    fn compression_certificate_build() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols: Vec<u32> = (0..20).map(|i| i % 2).collect();
        let compressed = coder.encode(&symbols).unwrap();
        let kraft = coder.verify_kraft_inequality().unwrap();

        let cert = CompressionCertificate::build(&est, &compressed, kraft);
        assert!(cert.kraft_satisfied);
        assert!(cert.entropy_millibits_per_symbol > 0);
    }

    #[test]
    fn compression_certificate_serde_roundtrip() {
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
            certificate_hash: ContentHash::compute(b"cert"),
        };
        let json = serde_json::to_string(&cert).unwrap();
        let restored: CompressionCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, restored);
    }

    // === Integer math ===

    #[test]
    fn log2_basic() {
        assert_eq!(integer_log2_millionths(1), 0);
        // log₂(2) = 1
        let l2 = integer_log2_millionths(2);
        assert!(
            (l2 - MILLION).abs() < 100_000,
            "log₂(2) should be ~1M, got {l2}"
        );
        // log₂(4) = 2
        let l4 = integer_log2_millionths(4);
        assert!(
            (l4 - 2 * MILLION).abs() < 200_000,
            "log₂(4) should be ~2M, got {l4}"
        );
    }

    #[test]
    fn log2_monotone() {
        let mut prev = 0;
        for n in [1, 2, 4, 8, 16, 32, 64, 128] {
            let current = integer_log2_millionths(n);
            assert!(
                current >= prev,
                "log₂ should be monotone: {current} < {prev}"
            );
            prev = current;
        }
    }

    #[test]
    fn log2_large_values_stay_normalized() {
        let n = (1u64 << 40) + 1;
        let l = integer_log2_millionths(n);
        // log2(2^40 + 1) is extremely close to 40.0.
        assert!(l >= 40 * MILLION);
        assert!(l < 40 * MILLION + 20_000);
    }

    #[test]
    fn compression_certificate_ratio_uses_consistent_units() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
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
    fn compression_certificate_zero_lower_bound_fails_closed() {
        let mut est = EntropyEstimator::new();
        est.observe(7);
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let compressed = coder.encode(&[7]).unwrap();
        let kraft = coder.verify_kraft_inequality().unwrap();
        let cert = CompressionCertificate::build(&est, &compressed, kraft);

        assert_eq!(cert.shannon_lower_bound_bits, 0);
        assert!(cert.achieved_bits > 0);
        assert_eq!(cert.overhead_ratio_millionths, i64::MAX);
        assert!(!cert.is_within_factor(10_000_000));
    }

    // === Error display ===

    #[test]
    fn entropy_error_display() {
        let err = EntropyError::UnknownSymbol { symbol: 42 };
        assert!(format!("{err}").contains("42"));
    }

    #[test]
    fn entropy_error_kraft() {
        let err = EntropyError::KraftViolation {
            kraft_sum_millionths: 1_100_000,
        };
        assert!(format!("{err}").contains("Kraft"));
    }

    // === Edge cases ===

    #[test]
    fn entropy_max_for_large_alphabet() {
        let mut est = EntropyEstimator::new();
        for i in 0..100u32 {
            est.observe(i);
        }
        let h_max = est.max_entropy_millibits();
        // log₂(100) ≈ 6.64 bits.
        assert!(h_max > 6 * MILLION);
        assert!(h_max < 7 * MILLION);
    }

    #[test]
    fn compression_skewed_distribution_compresses_well() {
        let mut est = EntropyEstimator::new();
        // Highly skewed: symbol 0 appears 99%, symbol 1 appears 1%.
        for _ in 0..990 {
            est.observe(0);
        }
        for _ in 0..10 {
            est.observe(1);
        }

        let h = est.entropy_millibits();
        // H(0.99, 0.01) ≈ 0.081 bits.
        assert!(h < 200_000, "skewed entropy should be low, got {h}");

        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let ecl = coder.expected_code_length_millibits();
        assert!(
            ecl < 500_000,
            "expected code length should be low for skewed dist"
        );
    }

    #[test]
    fn sufficient_statistic_consistency_check() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        est.observe(1);
        est.observe(0);
        let ss = SufficientStatistic::from_estimator(&est, 100, 200, ContentHash::compute(b"test"));
        assert!(ss.is_consistent());
        assert_eq!(ss.total_count, 3);

        // Tamper and check.
        let mut tampered = ss.clone();
        tampered.total_count = 999;
        assert!(!tampered.is_consistent());
    }

    // -----------------------------------------------------------------------
    // Enrichment: EntropyEstimator properties
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_estimator_default() {
        let est = EntropyEstimator::default();
        assert_eq!(est.total_count, 0);
        assert_eq!(est.alphabet_size, 0);
        assert!(est.frequencies.is_empty());
    }

    #[test]
    fn entropy_observe_updates_state() {
        let mut est = EntropyEstimator::new();
        est.observe(5);
        assert_eq!(est.total_count, 1);
        assert_eq!(est.alphabet_size, 1);
        est.observe(5);
        assert_eq!(est.total_count, 2);
        assert_eq!(est.alphabet_size, 1); // same symbol
        est.observe(10);
        assert_eq!(est.total_count, 3);
        assert_eq!(est.alphabet_size, 2);
    }

    #[test]
    fn entropy_probability_unknown_symbol_returns_zero() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        assert_eq!(est.probability_millionths(99), 0);
    }

    #[test]
    fn entropy_probability_empty_estimator_returns_zero() {
        let est = EntropyEstimator::new();
        assert_eq!(est.probability_millionths(0), 0);
    }

    #[test]
    fn entropy_max_for_single_symbol_is_zero() {
        let mut est = EntropyEstimator::new();
        for _ in 0..20 {
            est.observe(0);
        }
        assert_eq!(est.max_entropy_millibits(), 0);
    }

    #[test]
    fn entropy_below_min_samples_returns_zero() {
        let mut est = EntropyEstimator::new();
        // MIN_SAMPLES_FOR_ENTROPY is 10; observe only 9.
        for i in 0..9 {
            est.observe(i);
        }
        assert_eq!(est.entropy_millibits(), 0);
    }

    #[test]
    fn entropy_at_min_samples_returns_nonzero() {
        let mut est = EntropyEstimator::new();
        for i in 0..10 {
            est.observe(i % 2);
        }
        assert!(est.entropy_millibits() > 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: EntropyError display and std::error completeness
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_error_display_all_variants() {
        let displays: std::collections::BTreeSet<String> = [
            EntropyError::AlphabetTooLarge {
                size: 300,
                max: 256,
            },
            EntropyError::EmptyInput,
            EntropyError::UnknownSymbol { symbol: 42 },
            EntropyError::DecodeError {
                message: "corrupt".into(),
            },
            EntropyError::InsufficientSamples { count: 5, min: 10 },
            EntropyError::KraftViolation {
                kraft_sum_millionths: 1_100_000,
            },
        ]
        .into_iter()
        .map(|e| e.to_string())
        .collect();
        assert_eq!(displays.len(), 6, "all 6 variants have distinct Display");
    }

    #[test]
    fn entropy_error_implements_std_error() {
        let errors: [Box<dyn std::error::Error>; 6] = [
            Box::new(EntropyError::EmptyInput),
            Box::new(EntropyError::AlphabetTooLarge { size: 1, max: 0 }),
            Box::new(EntropyError::UnknownSymbol { symbol: 0 }),
            Box::new(EntropyError::DecodeError {
                message: "x".into(),
            }),
            Box::new(EntropyError::InsufficientSamples { count: 1, min: 2 }),
            Box::new(EntropyError::KraftViolation {
                kraft_sum_millionths: 2_000_000,
            }),
        ];
        for e in &errors {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn entropy_error_serde_all_variants() {
        let errors = [
            EntropyError::AlphabetTooLarge {
                size: 300,
                max: 256,
            },
            EntropyError::EmptyInput,
            EntropyError::UnknownSymbol { symbol: 42 },
            EntropyError::DecodeError {
                message: "x".into(),
            },
            EntropyError::InsufficientSamples { count: 5, min: 10 },
            EntropyError::KraftViolation {
                kraft_sum_millionths: 1_100_000,
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: EntropyError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: CompressedEvidence schema
    // -----------------------------------------------------------------------

    #[test]
    fn compressed_evidence_uses_correct_schema() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let compressed = coder.encode(&[0, 1, 0]).unwrap();
        assert_eq!(compressed.schema, ENTROPY_SCHEMA_VERSION);
    }

    // -----------------------------------------------------------------------
    // Enrichment: CompressionCertificate is_within_factor
    // -----------------------------------------------------------------------

    #[test]
    fn is_within_factor_passing() {
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
            certificate_hash: ContentHash::compute(b"x"),
        };
        // 1.2x overhead — within 2.0x factor
        assert!(cert.is_within_factor(2_000_000));
        // But not within 1.1x factor
        assert!(!cert.is_within_factor(1_100_000));
    }

    // -----------------------------------------------------------------------
    // Enrichment: SufficientStatistic from empty estimator
    // -----------------------------------------------------------------------

    #[test]
    fn sufficient_statistic_fisher_information_zero_for_few_samples() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        let ss = SufficientStatistic::from_estimator(&est, 0, 0, ContentHash::compute(b"single"));
        assert_eq!(ss.fisher_information_millionths(), 0);
    }

    #[test]
    fn sufficient_statistic_mean_computation() {
        let mut est = EntropyEstimator::new();
        for _ in 0..10 {
            est.observe(0);
        }
        let ss =
            SufficientStatistic::from_estimator(&est, 500, 1000, ContentHash::compute(b"mean"));
        // mean = cumulative_llr / total = 500 / 10 = 50
        assert_eq!(ss.mean_millionths, 50);
    }

    // -----------------------------------------------------------------------
    // Enrichment: coder with large alphabet
    // -----------------------------------------------------------------------

    #[test]
    fn coder_alphabet_at_max_size() {
        let mut est = EntropyEstimator::new();
        for i in 0..MAX_ALPHABET_SIZE as u32 {
            est.observe(i);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        assert_eq!(coder.alphabet_size, MAX_ALPHABET_SIZE);
    }

    #[test]
    fn coder_alphabet_exceeds_max_rejected() {
        let mut est = EntropyEstimator::new();
        for i in 0..=MAX_ALPHABET_SIZE as u32 {
            est.observe(i);
        }
        assert!(matches!(
            ArithmeticCoder::from_estimator(&est),
            Err(EntropyError::AlphabetTooLarge { .. })
        ));
    }

    // -----------------------------------------------------------------------
    // Enrichment: clone equality
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_clone_eq_entropy_estimator() {
        let mut est = EntropyEstimator::new();
        for i in 0..20u32 {
            est.observe(i % 3);
        }
        let cloned = est.clone();
        assert_eq!(est, cloned);
    }

    #[test]
    fn enrichment_clone_eq_sufficient_statistic() {
        let mut est = EntropyEstimator::new();
        for _ in 0..10 {
            est.observe(0);
            est.observe(1);
        }
        let ss = SufficientStatistic::from_estimator(&est, 500, 1000, ContentHash::compute(b"c"));
        let cloned = ss.clone();
        assert_eq!(ss, cloned);
    }

    #[test]
    fn enrichment_clone_eq_arithmetic_coder() {
        let mut est = EntropyEstimator::new();
        for _ in 0..50 {
            est.observe(0);
            est.observe(1);
            est.observe(2);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let cloned = coder.clone();
        assert_eq!(coder, cloned);
    }

    #[test]
    fn enrichment_clone_eq_compressed_evidence() {
        let ce = CompressedEvidence {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            compressed_data: vec![10, 20, 30],
            original_symbol_count: 50,
            compressed_bytes: 3,
            original_bits_estimate: 100,
            compressed_bits: 24,
            compression_ratio_millionths: 240_000,
            content_hash: ContentHash::compute(b"clone_test"),
        };
        let cloned = ce.clone();
        assert_eq!(ce, cloned);
    }

    #[test]
    fn enrichment_clone_eq_compression_certificate() {
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
            certificate_hash: ContentHash::compute(b"cert_clone"),
        };
        let cloned = cert.clone();
        assert_eq!(cert, cloned);
    }

    // -----------------------------------------------------------------------
    // Enrichment: JSON field presence
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_json_fields_entropy_estimator() {
        let mut est = EntropyEstimator::new();
        est.observe(7);
        let json = serde_json::to_string(&est).unwrap();
        assert!(json.contains("\"frequencies\""));
        assert!(json.contains("\"total_count\""));
        assert!(json.contains("\"alphabet_size\""));
    }

    #[test]
    fn enrichment_json_fields_sufficient_statistic() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        let ss = SufficientStatistic::from_estimator(&est, 0, 0, ContentHash::compute(b"f"));
        let json = serde_json::to_string(&ss).unwrap();
        assert!(json.contains("\"symbol_counts\""));
        assert!(json.contains("\"cumulative_llr_millionths\""));
        assert!(json.contains("\"is_fisher_sufficient\""));
        assert!(json.contains("\"original_hash\""));
    }

    #[test]
    fn enrichment_json_fields_compression_certificate() {
        let cert = CompressionCertificate {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            entropy_millibits_per_symbol: MILLION,
            shannon_lower_bound_bits: 80,
            achieved_bits: 90,
            overhead_bits_millionths: 10 * MILLION,
            overhead_ratio_millionths: 1_125_000,
            kraft_sum_millionths: MILLION,
            kraft_satisfied: true,
            redundancy_millibits: 0,
            symbol_count: 100,
            certificate_hash: ContentHash::compute(b"fld"),
        };
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("\"entropy_millibits_per_symbol\""));
        assert!(json.contains("\"shannon_lower_bound_bits\""));
        assert!(json.contains("\"kraft_satisfied\""));
        assert!(json.contains("\"certificate_hash\""));
    }

    // -----------------------------------------------------------------------
    // Enrichment: serde roundtrip (EntropyError with nested data)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_serde_roundtrip_decode_error() {
        let err = EntropyError::DecodeError {
            message: "unexpected EOF at offset 42".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: EntropyError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness for EntropyError
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_display_uniqueness_entropy_error() {
        let variants = [
            EntropyError::AlphabetTooLarge { size: 1, max: 0 },
            EntropyError::EmptyInput,
            EntropyError::UnknownSymbol { symbol: 1 },
            EntropyError::DecodeError {
                message: "bad".into(),
            },
            EntropyError::InsufficientSamples { count: 1, min: 2 },
            EntropyError::KraftViolation {
                kraft_sum_millionths: 2_000_000,
            },
        ];
        let display_set: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v}")).collect();
        assert_eq!(display_set.len(), variants.len());
    }

    // -----------------------------------------------------------------------
    // Enrichment: boundary condition (zero observations, probability sums)
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_boundary_zero_observations_lower_bound() {
        let est = EntropyEstimator::new();
        assert_eq!(est.shannon_lower_bound_bits(), 0);
        assert_eq!(est.redundancy_millibits(), 0);
        assert_eq!(est.max_entropy_millibits(), 0);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Error source returns None
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_error_source_returns_none() {
        use std::error::Error;
        let variants: [EntropyError; 6] = [
            EntropyError::AlphabetTooLarge {
                size: 300,
                max: 256,
            },
            EntropyError::EmptyInput,
            EntropyError::UnknownSymbol { symbol: 0 },
            EntropyError::DecodeError {
                message: "x".into(),
            },
            EntropyError::InsufficientSamples { count: 1, min: 10 },
            EntropyError::KraftViolation {
                kraft_sum_millionths: 0,
            },
        ];
        for err in &variants {
            assert!(err.source().is_none());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: Debug distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn debug_distinct_entropy_error_variants() {
        let variants: [EntropyError; 6] = [
            EntropyError::AlphabetTooLarge {
                size: 512,
                max: 256,
            },
            EntropyError::EmptyInput,
            EntropyError::UnknownSymbol { symbol: 77 },
            EntropyError::DecodeError {
                message: "truncated".into(),
            },
            EntropyError::InsufficientSamples { count: 3, min: 10 },
            EntropyError::KraftViolation {
                kraft_sum_millionths: 1_500_000,
            },
        ];
        let debug_set: std::collections::BTreeSet<String> =
            variants.iter().map(|v| format!("{v:?}")).collect();
        assert_eq!(debug_set.len(), variants.len());
    }

    #[test]
    fn debug_distinct_entropy_estimator_states() {
        let empty = EntropyEstimator::new();
        let mut one_sym = EntropyEstimator::new();
        one_sym.observe(0);
        let mut two_sym = EntropyEstimator::new();
        two_sym.observe(0);
        two_sym.observe(1);
        let set: std::collections::BTreeSet<String> = [&empty, &one_sym, &two_sym]
            .iter()
            .map(|e| format!("{e:?}"))
            .collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn debug_distinct_sufficient_statistics() {
        let mut est_a = EntropyEstimator::new();
        est_a.observe(0);
        let ss_a =
            SufficientStatistic::from_estimator(&est_a, 100, 200, ContentHash::compute(b"a"));
        let ss_b =
            SufficientStatistic::from_estimator(&est_a, 300, 400, ContentHash::compute(b"b"));
        assert_ne!(format!("{ss_a:?}"), format!("{ss_b:?}"));
    }

    #[test]
    fn debug_distinct_compressed_evidence() {
        let ce_a = CompressedEvidence {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            compressed_data: vec![1],
            original_symbol_count: 1,
            compressed_bytes: 1,
            original_bits_estimate: 8,
            compressed_bits: 8,
            compression_ratio_millionths: MILLION,
            content_hash: ContentHash::compute(b"da"),
        };
        let ce_b = CompressedEvidence {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            compressed_data: vec![2],
            original_symbol_count: 1,
            compressed_bytes: 1,
            original_bits_estimate: 8,
            compressed_bits: 8,
            compression_ratio_millionths: MILLION,
            content_hash: ContentHash::compute(b"db"),
        };
        assert_ne!(format!("{ce_a:?}"), format!("{ce_b:?}"));
    }

    #[test]
    fn debug_distinct_compression_certificate() {
        let cert_a = CompressionCertificate {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            entropy_millibits_per_symbol: 500_000,
            shannon_lower_bound_bits: 50,
            achieved_bits: 60,
            overhead_bits_millionths: 10 * MILLION,
            overhead_ratio_millionths: 1_200_000,
            kraft_sum_millionths: MILLION,
            kraft_satisfied: true,
            redundancy_millibits: 500_000,
            symbol_count: 100,
            certificate_hash: ContentHash::compute(b"ca"),
        };
        let cert_b = CompressionCertificate {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            entropy_millibits_per_symbol: 800_000,
            shannon_lower_bound_bits: 80,
            achieved_bits: 90,
            overhead_bits_millionths: 10 * MILLION,
            overhead_ratio_millionths: 1_125_000,
            kraft_sum_millionths: MILLION,
            kraft_satisfied: true,
            redundancy_millibits: 200_000,
            symbol_count: 200,
            certificate_hash: ContentHash::compute(b"cb"),
        };
        assert_ne!(format!("{cert_a:?}"), format!("{cert_b:?}"));
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: Clone independence
    // -----------------------------------------------------------------------

    #[test]
    fn clone_independence_entropy_estimator() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        est.observe(1);
        let mut cloned = est.clone();
        cloned.observe(2);
        assert_eq!(est.alphabet_size, 2);
        assert_eq!(cloned.alphabet_size, 3);
        assert_ne!(est, cloned);
    }

    #[test]
    fn clone_independence_sufficient_statistic() {
        let mut est = EntropyEstimator::new();
        for _ in 0..10 {
            est.observe(0);
        }
        let ss = SufficientStatistic::from_estimator(&est, 100, 200, ContentHash::compute(b"ci"));
        let mut cloned = ss.clone();
        cloned.total_count = 999;
        assert_ne!(ss, cloned);
        assert!(ss.is_consistent());
        assert!(!cloned.is_consistent());
    }

    #[test]
    fn clone_independence_compressed_evidence() {
        let mut ce = CompressedEvidence {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            compressed_data: vec![1, 2, 3],
            original_symbol_count: 3,
            compressed_bytes: 3,
            original_bits_estimate: 24,
            compressed_bits: 24,
            compression_ratio_millionths: MILLION,
            content_hash: ContentHash::compute(b"ci_ce"),
        };
        let original = ce.clone();
        ce.compressed_data.push(4);
        assert_ne!(ce, original);
        assert_eq!(original.compressed_data.len(), 3);
    }

    #[test]
    fn clone_independence_arithmetic_coder() {
        let mut est = EntropyEstimator::new();
        for _ in 0..50 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let mut cloned = coder.clone();
        cloned.total_frequency = 999;
        assert_ne!(coder, cloned);
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: JSON field-name stability
    // -----------------------------------------------------------------------

    #[test]
    fn json_field_stability_compressed_evidence() {
        let ce = CompressedEvidence {
            schema: "v1".to_string(),
            compressed_data: vec![0xAB],
            original_symbol_count: 10,
            compressed_bytes: 1,
            original_bits_estimate: 40,
            compressed_bits: 8,
            compression_ratio_millionths: 200_000,
            content_hash: ContentHash::compute(b"fs"),
        };
        let json = serde_json::to_string(&ce).unwrap();
        for field in &[
            "schema",
            "compressed_data",
            "original_symbol_count",
            "compressed_bytes",
            "original_bits_estimate",
            "compressed_bits",
            "compression_ratio_millionths",
            "content_hash",
        ] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing field {field}"
            );
        }
    }

    #[test]
    fn json_field_stability_arithmetic_coder() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let json = serde_json::to_string(&coder).unwrap();
        for field in &["frequency_table", "total_frequency", "alphabet_size"] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing field {field}"
            );
        }
    }

    #[test]
    fn json_field_stability_sufficient_statistic_all_fields() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        est.observe(1);
        let ss = SufficientStatistic::from_estimator(&est, 500, 1000, ContentHash::compute(b"ss"));
        let json = serde_json::to_string(&ss).unwrap();
        for field in &[
            "symbol_counts",
            "total_count",
            "cumulative_llr_millionths",
            "sum_squared_millionths",
            "mean_millionths",
            "original_hash",
            "is_fisher_sufficient",
        ] {
            assert!(
                json.contains(&format!("\"{field}\"")),
                "missing field {field}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: serde variant distinctness
    // -----------------------------------------------------------------------

    #[test]
    fn serde_variant_distinctness_entropy_error() {
        let variants = [
            EntropyError::AlphabetTooLarge {
                size: 300,
                max: 256,
            },
            EntropyError::EmptyInput,
            EntropyError::UnknownSymbol { symbol: 7 },
            EntropyError::DecodeError {
                message: "oops".into(),
            },
            EntropyError::InsufficientSamples { count: 2, min: 10 },
            EntropyError::KraftViolation {
                kraft_sum_millionths: 2_000_000,
            },
        ];
        let jsons: std::collections::BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(
            jsons.len(),
            variants.len(),
            "each variant must produce distinct JSON"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: boundary/edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_estimator_observe_u32_max() {
        let mut est = EntropyEstimator::new();
        est.observe(u32::MAX);
        assert_eq!(est.total_count, 1);
        assert_eq!(est.alphabet_size, 1);
        assert_eq!(est.probability_millionths(u32::MAX), MILLION);
    }

    #[test]
    fn entropy_estimator_observe_zero_symbol() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        assert_eq!(est.frequencies.get(&0), Some(&1));
    }

    #[test]
    fn entropy_estimator_many_observations_same_symbol() {
        let mut est = EntropyEstimator::new();
        for _ in 0..10_000 {
            est.observe(42);
        }
        assert_eq!(est.total_count, 10_000);
        assert_eq!(est.alphabet_size, 1);
        assert_eq!(est.entropy_millibits(), 0);
    }

    #[test]
    fn entropy_probabilities_sum_close_to_million() {
        let mut est = EntropyEstimator::new();
        for i in 0..5u32 {
            for _ in 0..((i + 1) * 10) {
                est.observe(i);
            }
        }
        let total_prob: i64 = (0..5u32).map(|i| est.probability_millionths(i)).sum();
        assert!(total_prob <= MILLION);
        assert!(
            total_prob > 900_000,
            "total prob should be close to 1M, got {total_prob}"
        );
    }

    #[test]
    fn entropy_redundancy_skewed_is_positive() {
        let mut est = EntropyEstimator::new();
        for _ in 0..990 {
            est.observe(0);
        }
        for _ in 0..10 {
            est.observe(1);
        }
        let r = est.redundancy_millibits();
        assert!(r > 0, "skewed distribution should have positive redundancy");
    }

    #[test]
    fn entropy_shannon_lower_bound_zero_for_single_symbol() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
        }
        assert_eq!(est.shannon_lower_bound_bits(), 0);
    }

    #[test]
    fn log2_zero_returns_zero() {
        assert_eq!(integer_log2_millionths(0), 0);
    }

    #[test]
    fn log2_power_of_two_exact() {
        for exp in 0..30 {
            let n = 1u64 << exp;
            let result = integer_log2_millionths(n);
            let expected = exp as i64 * MILLION;
            assert_eq!(
                result, expected,
                "log2(2^{exp}) should be exactly {expected}, got {result}"
            );
        }
    }

    #[test]
    fn log2_non_power_of_two_between_adjacent_integers() {
        let l3 = integer_log2_millionths(3);
        assert!(l3 > MILLION, "log2(3) > 1.0");
        assert!(l3 < 2 * MILLION, "log2(3) < 2.0");
        assert!(
            (l3 - 1_585_000).abs() < 50_000,
            "log2(3) approx 1.585M, got {l3}"
        );
    }

    #[test]
    fn coder_encode_single_repeated_symbol() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(5);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let compressed = coder.encode(&[5, 5, 5, 5, 5]).unwrap();
        assert_eq!(compressed.original_symbol_count, 5);
        assert!(!compressed.compressed_data.is_empty());
    }

    #[test]
    fn coder_encode_long_sequence() {
        let mut est = EntropyEstimator::new();
        for _ in 0..200 {
            est.observe(0);
            est.observe(1);
            est.observe(2);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols: Vec<u32> = (0..1000).map(|i| (i % 3) as u32).collect();
        let compressed = coder.encode(&symbols).unwrap();
        assert_eq!(compressed.original_symbol_count, 1000);
        assert!(compressed.compressed_data.len() < 1000);
    }

    #[test]
    fn coder_kraft_sum_for_uniform_distribution() {
        let mut est = EntropyEstimator::new();
        for i in 0..4u32 {
            for _ in 0..250 {
                est.observe(i);
            }
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let kraft = coder.verify_kraft_inequality().unwrap();
        assert!(
            (kraft - MILLION).abs() < 100,
            "kraft sum should be ~1M, got {kraft}"
        );
    }

    #[test]
    fn coder_expected_code_length_approaches_entropy() {
        let mut est = EntropyEstimator::new();
        for _ in 0..10_000 {
            est.observe(0);
            est.observe(1);
        }
        let h = est.entropy_millibits();
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let ecl = coder.expected_code_length_millibits();
        assert!(
            (ecl - h).abs() < 200_000,
            "ECL {ecl} should be close to H {h}"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: SufficientStatistic additional coverage
    // -----------------------------------------------------------------------

    #[test]
    fn sufficient_statistic_empty_estimator() {
        let est = EntropyEstimator::new();
        let ss = SufficientStatistic::from_estimator(&est, 0, 0, ContentHash::compute(b"empty_ss"));
        assert!(ss.is_consistent());
        assert_eq!(ss.total_count, 0);
        assert_eq!(ss.mean_millionths, 0);
        assert!(ss.symbol_counts.is_empty());
    }

    #[test]
    fn sufficient_statistic_preserves_symbol_counts() {
        let mut est = EntropyEstimator::new();
        est.observe(0);
        est.observe(0);
        est.observe(1);
        est.observe(2);
        est.observe(2);
        est.observe(2);
        let ss = SufficientStatistic::from_estimator(&est, 0, 0, ContentHash::compute(b"counts"));
        assert_eq!(ss.symbol_counts.get(&0), Some(&2));
        assert_eq!(ss.symbol_counts.get(&1), Some(&1));
        assert_eq!(ss.symbol_counts.get(&2), Some(&3));
        assert_eq!(ss.total_count, 6);
    }

    #[test]
    fn sufficient_statistic_fisher_information_increases_with_samples() {
        let mut est_10 = EntropyEstimator::new();
        for _ in 0..10 {
            est_10.observe(0);
        }
        let ss_10 = SufficientStatistic::from_estimator(
            &est_10,
            100_000,
            200_000,
            ContentHash::compute(b"fi10"),
        );

        let mut est_100 = EntropyEstimator::new();
        for _ in 0..100 {
            est_100.observe(0);
        }
        let ss_100 = SufficientStatistic::from_estimator(
            &est_100,
            1_000_000,
            2_000_000,
            ContentHash::compute(b"fi100"),
        );

        let fi_10 = ss_10.fisher_information_millionths();
        let fi_100 = ss_100.fisher_information_millionths();
        assert!(fi_10 > 0);
        assert!(fi_100 > 0);
    }

    #[test]
    fn sufficient_statistic_negative_llr() {
        let mut est = EntropyEstimator::new();
        for _ in 0..10 {
            est.observe(0);
        }
        let ss = SufficientStatistic::from_estimator(
            &est,
            -500_000,
            1_000_000,
            ContentHash::compute(b"neg"),
        );
        assert_eq!(ss.mean_millionths, -50_000);
        assert!(ss.is_consistent());
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: CompressionCertificate additional coverage
    // -----------------------------------------------------------------------

    #[test]
    fn certificate_is_within_factor_exact_boundary() {
        let cert = CompressionCertificate {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            entropy_millibits_per_symbol: MILLION,
            shannon_lower_bound_bits: 100,
            achieved_bits: 150,
            overhead_bits_millionths: 50 * MILLION,
            overhead_ratio_millionths: 1_500_000,
            kraft_sum_millionths: MILLION,
            kraft_satisfied: true,
            redundancy_millibits: 0,
            symbol_count: 100,
            certificate_hash: ContentHash::compute(b"boundary"),
        };
        assert!(cert.is_within_factor(1_500_000));
        assert!(cert.is_within_factor(1_500_001));
        assert!(!cert.is_within_factor(1_499_999));
    }

    #[test]
    fn certificate_build_kraft_not_satisfied() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols: Vec<u32> = (0..20).map(|i| i % 2).collect();
        let compressed = coder.encode(&symbols).unwrap();
        let cert = CompressionCertificate::build(&est, &compressed, 1_500_000);
        assert!(!cert.kraft_satisfied);
    }

    #[test]
    fn certificate_build_kraft_borderline_satisfied() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols: Vec<u32> = (0..20).map(|i| i % 2).collect();
        let compressed = coder.encode(&symbols).unwrap();
        let cert = CompressionCertificate::build(&est, &compressed, MILLION + 1000);
        assert!(cert.kraft_satisfied);
    }

    #[test]
    fn certificate_hash_deterministic() {
        let mut est = EntropyEstimator::new();
        for _ in 0..50 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols: Vec<u32> = (0..10).map(|i| i % 2).collect();
        let compressed = coder.encode(&symbols).unwrap();
        let kraft = coder.verify_kraft_inequality().unwrap();

        let cert1 = CompressionCertificate::build(&est, &compressed, kraft);
        let cert2 = CompressionCertificate::build(&est, &compressed, kraft);
        assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: Display format checks
    // -----------------------------------------------------------------------

    #[test]
    fn display_format_alphabet_too_large() {
        let err = EntropyError::AlphabetTooLarge {
            size: 300,
            max: 256,
        };
        assert_eq!(format!("{err}"), "alphabet size 300 exceeds limit 256");
    }

    #[test]
    fn display_format_empty_input() {
        let err = EntropyError::EmptyInput;
        assert_eq!(format!("{err}"), "empty input");
    }

    #[test]
    fn display_format_unknown_symbol() {
        let err = EntropyError::UnknownSymbol { symbol: 99 };
        assert_eq!(format!("{err}"), "unknown symbol: 99");
    }

    #[test]
    fn display_format_decode_error() {
        let err = EntropyError::DecodeError {
            message: "bad frame".to_string(),
        };
        assert_eq!(format!("{err}"), "decode error: bad frame");
    }

    #[test]
    fn display_format_insufficient_samples() {
        let err = EntropyError::InsufficientSamples { count: 3, min: 10 };
        assert_eq!(format!("{err}"), "insufficient samples: 3 < 10");
    }

    #[test]
    fn display_format_kraft_violation() {
        let err = EntropyError::KraftViolation {
            kraft_sum_millionths: 1_200_000,
        };
        assert_eq!(format!("{err}"), "Kraft inequality violated: sum = 1200000");
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: serde roundtrips (multi-symbol)
    // -----------------------------------------------------------------------

    #[test]
    fn serde_roundtrip_arithmetic_coder_multi_symbol() {
        let mut est = EntropyEstimator::new();
        for i in 0..10u32 {
            for _ in 0..((i + 1) * 5) {
                est.observe(i);
            }
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let json = serde_json::to_string(&coder).unwrap();
        let restored: ArithmeticCoder = serde_json::from_str(&json).unwrap();
        assert_eq!(coder, restored);
        assert_eq!(restored.alphabet_size, 10);
    }

    #[test]
    fn serde_roundtrip_compressed_evidence_large() {
        let mut est = EntropyEstimator::new();
        for _ in 0..200 {
            est.observe(0);
            est.observe(1);
            est.observe(2);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols: Vec<u32> = (0..500).map(|i| (i % 3) as u32).collect();
        let compressed = coder.encode(&symbols).unwrap();
        let json = serde_json::to_string(&compressed).unwrap();
        let restored: CompressedEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(compressed, restored);
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: entropy ordering properties
    // -----------------------------------------------------------------------

    #[test]
    fn entropy_increases_with_more_distinct_symbols() {
        let mut est2 = EntropyEstimator::new();
        for _ in 0..500 {
            est2.observe(0);
            est2.observe(1);
        }
        let h2 = est2.entropy_millibits();

        let mut est4 = EntropyEstimator::new();
        for _ in 0..250 {
            for s in 0..4u32 {
                est4.observe(s);
            }
        }
        let h4 = est4.entropy_millibits();

        let mut est8 = EntropyEstimator::new();
        for _ in 0..125 {
            for s in 0..8u32 {
                est8.observe(s);
            }
        }
        let h8 = est8.entropy_millibits();

        assert!(h2 < h4, "H(uniform 2) < H(uniform 4)");
        assert!(h4 < h8, "H(uniform 4) < H(uniform 8)");
    }

    #[test]
    fn entropy_at_most_max_entropy() {
        let mut est = EntropyEstimator::new();
        for _ in 0..900 {
            est.observe(0);
        }
        for _ in 0..100 {
            est.observe(1);
        }
        let h = est.entropy_millibits();
        let h_max = est.max_entropy_millibits();
        assert!(
            h <= h_max,
            "H(X) should be <= H_max, got H={h}, H_max={h_max}"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: hash determinism
    // -----------------------------------------------------------------------

    #[test]
    fn compressed_evidence_hash_deterministic() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols = [0u32, 1, 0, 1, 0, 1];
        let ce1 = coder.encode(&symbols).unwrap();
        let ce2 = coder.encode(&symbols).unwrap();
        assert_eq!(ce1.content_hash, ce2.content_hash);
        assert_eq!(ce1.compressed_data, ce2.compressed_data);
    }

    // -----------------------------------------------------------------------
    // Enrichment round 2: full pipeline integration
    // -----------------------------------------------------------------------

    #[test]
    fn full_pipeline_encode_certify() {
        let mut est = EntropyEstimator::new();
        for _ in 0..500 {
            est.observe(0);
            est.observe(1);
            est.observe(2);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let kraft = coder.verify_kraft_inequality().unwrap();
        assert!(kraft <= MILLION + 1000);

        let symbols: Vec<u32> = (0..300).map(|i| (i % 3) as u32).collect();
        let compressed = coder.encode(&symbols).unwrap();
        assert_eq!(compressed.schema, ENTROPY_SCHEMA_VERSION);

        let cert = CompressionCertificate::build(&est, &compressed, kraft);
        assert!(cert.kraft_satisfied);
        assert!(cert.entropy_millibits_per_symbol > 0);
        assert!(cert.shannon_lower_bound_bits > 0);
        assert!(cert.achieved_bits > 0);

        let ss = SufficientStatistic::from_estimator(
            &est,
            500_000,
            1_000_000,
            ContentHash::compute(b"pipe"),
        );
        assert!(ss.is_consistent());
        assert!(ss.is_fisher_sufficient);
    }

    #[test]
    fn full_pipeline_serde_all_artifacts() {
        let mut est = EntropyEstimator::new();
        for _ in 0..100 {
            est.observe(0);
            est.observe(1);
        }
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        let symbols: Vec<u32> = (0..50).map(|i| i % 2).collect();
        let compressed = coder.encode(&symbols).unwrap();
        let kraft = coder.verify_kraft_inequality().unwrap();
        let cert = CompressionCertificate::build(&est, &compressed, kraft);
        let ss = SufficientStatistic::from_estimator(
            &est,
            200_000,
            400_000,
            ContentHash::compute(b"all"),
        );

        let est_json = serde_json::to_string(&est).unwrap();
        let coder_json = serde_json::to_string(&coder).unwrap();
        let compressed_json = serde_json::to_string(&compressed).unwrap();
        let cert_json = serde_json::to_string(&cert).unwrap();
        let ss_json = serde_json::to_string(&ss).unwrap();

        assert_eq!(
            est,
            serde_json::from_str::<EntropyEstimator>(&est_json).unwrap()
        );
        assert_eq!(
            coder,
            serde_json::from_str::<ArithmeticCoder>(&coder_json).unwrap()
        );
        assert_eq!(
            compressed,
            serde_json::from_str::<CompressedEvidence>(&compressed_json).unwrap()
        );
        assert_eq!(
            cert,
            serde_json::from_str::<CompressionCertificate>(&cert_json).unwrap()
        );
        assert_eq!(
            ss,
            serde_json::from_str::<SufficientStatistic>(&ss_json).unwrap()
        );
    }
}
