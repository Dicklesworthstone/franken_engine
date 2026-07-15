//! Information-theoretic evidence compression with Shannon lower bounds.
//!
//! Evidence streams grow linearly with runtime operations.  This module
//! provides deterministic empirical-entropy diagnostics and compression:
//!
//! - **Empirical entropy estimation** over `ActionCategory` and `DecisionType`
//!   distributions using streaming histogram updates.
//! - **Arithmetic coding** with a deterministic static frequency model for
//!   near-optimal compression ratio and exact symbol-stream restoration.
//! - **Sufficient statistic extraction** for deterministic empirical
//!   diagnostics. This summary is separate from the codec's exact restoration
//!   of its derived symbol stream and is not a full-evidence replay claim.
//! - **Empirical Shannon comparison certificate** for tracking achieved size
//!   against the module's deterministic entropy estimate.
//! - **Frequency-mass normalization checks** retained under the legacy Kraft
//!   field name.
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
pub const ENTROPY_SCHEMA_VERSION: &str = "franken-engine.entropy-evidence-compressor.v2";

/// Maximum alphabet size for the compressor.
const MAX_ALPHABET_SIZE: usize = 256;

/// Arithmetic-coder state width. A 32-bit interval leaves ample headroom for
/// deterministic `u128` scaling while keeping the decoder portable.
const CODE_VALUE_BITS: usize = 32;
const CODE_MAX: u64 = (1u64 << CODE_VALUE_BITS) - 1;
const HALF: u64 = 1u64 << (CODE_VALUE_BITS - 1);
const FIRST_QUARTER: u64 = HALF >> 1;
const THIRD_QUARTER: u64 = FIRST_QUARTER * 3;

/// Cumulative frequencies must remain well below the coding interval so every
/// admitted symbol retains a non-empty sub-interval after renormalization.
const MAX_TOTAL_FREQUENCY: u64 = (1u64 << 24) - 1;

/// Bound allocation and CPU work before trusting serialized symbol counts.
const MAX_DECODED_SYMBOLS: usize = 1 << 20;

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
    /// Canonical model frequency mass is not normalized (legacy Kraft name).
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
                write!(
                    f,
                    "model frequency mass is not normalized: sum = {kraft_sum_millionths}"
                )
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
        // Use i128 to prevent overflow when count * MILLION exceeds i64::MAX.
        (count as i128 * MILLION as i128 / self.total_count.max(1) as i128) as i64
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
        let mut count_sum: u64 = 0;
        for &x in self.symbol_counts.values() {
            if let Some(sum) = count_sum.checked_add(x) {
                count_sum = sum;
            } else {
                return false;
            }
        }
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
        // Use i128 intermediary to avoid overflow in mean_sq computation:
        // mean_millionths can be large, so (mean * mean) can exceed i64 range.
        let mean_wide = self.mean_millionths as i128;
        let mean_sq = (mean_wide * mean_wide / MILLION as i128) as i64;
        let variance = (self.sum_squared_millionths / n - mean_sq).max(1);

        let n_wide = self.total_count as i128;
        let variance_wide = variance as i128;
        let fisher_wide = (n_wide * MILLION as i128) / variance_wide;

        fisher_wide.min(i64::MAX as i128) as i64
    }
}

// ---------------------------------------------------------------------------
// ArithmeticCoder — integer arithmetic coding
// ---------------------------------------------------------------------------

/// Integer arithmetic coder for evidence symbol streams.
///
/// Uses a canonical static model and a 32-bit E1/E2/E3 interval. The matching
/// decoder verifies framing, model identity, content identity, and canonical
/// re-encoding before returning symbols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
        let observed_frequencies: Vec<(u32, u64)> = estimator
            .frequencies
            .iter()
            .filter(|(_, frequency)| **frequency > 0)
            .map(|(&symbol, &frequency)| (symbol, frequency))
            .collect();
        let alphabet_size = observed_frequencies.len();
        if alphabet_size == 0 {
            return Err(EntropyError::EmptyInput);
        }
        if alphabet_size > MAX_ALPHABET_SIZE {
            return Err(EntropyError::AlphabetTooLarge {
                size: alphabet_size,
                max: MAX_ALPHABET_SIZE,
            });
        }

        let raw_total = observed_frequencies
            .iter()
            .try_fold(0u64, |total, (_, frequency)| {
                total
                    .checked_add(*frequency)
                    .ok_or_else(|| decode_error("frequency table overflow"))
            })?;
        if raw_total == 0 {
            return Err(EntropyError::EmptyInput);
        }

        let alphabet_reserve = u64::try_from(alphabet_size).map_err(|_| {
            decode_error("alphabet size cannot be represented by the frequency model")
        })?;
        let proportional_budget = MAX_TOTAL_FREQUENCY
            .checked_sub(alphabet_reserve)
            .ok_or_else(|| decode_error("alphabet exceeds the arithmetic coding budget"))?;

        let mut cum_freq_table = BTreeMap::new();
        let mut cumulative = 0u64;
        for (symbol, frequency) in observed_frequencies {
            let adjusted_freq = if raw_total <= MAX_TOTAL_FREQUENCY {
                frequency
            } else {
                // Preserve every observed symbol while scaling the table into
                // the arithmetic interval. The sorted BTreeMap traversal makes
                // this model canonical across platforms and crate mirrors.
                1u64.saturating_add(u64_from_u128_saturating(
                    u128::from(frequency).saturating_mul(u128::from(proportional_budget))
                        / u128::from(raw_total),
                ))
            };
            cum_freq_table.insert(symbol, (cumulative, adjusted_freq));
            cumulative = cumulative
                .checked_add(adjusted_freq)
                .ok_or_else(|| decode_error("frequency table overflow"))?;
        }

        if cumulative == 0 {
            return Err(EntropyError::EmptyInput);
        }

        let coder = Self {
            frequency_table: cum_freq_table,
            total_frequency: cumulative,
            alphabet_size,
        };
        coder.validate_model()?;
        Ok(coder)
    }

    /// Encode a sequence of symbols into a compressed byte vector.
    ///
    /// Uses range-based arithmetic coding with integer arithmetic.
    pub fn encode(&self, symbols: &[u32]) -> Result<CompressedEvidence, EntropyError> {
        self.validate_model()?;
        if symbols.is_empty() {
            return Err(EntropyError::EmptyInput);
        }
        if symbols.len() > MAX_DECODED_SYMBOLS {
            return Err(decode_error(format!(
                "symbol count {} exceeds decode limit {MAX_DECODED_SYMBOLS}",
                symbols.len()
            )));
        }

        let mut low: u64 = 0;
        let mut high: u64 = CODE_MAX;
        let mut pending_underflow_bits = 0usize;
        let mut writer = BitWriter::new();

        for &sym in symbols {
            let (cum_freq, freq) = self
                .frequency_table
                .get(&sym)
                .ok_or(EntropyError::UnknownSymbol { symbol: sym })?;

            update_interval(&mut low, &mut high, *cum_freq, *freq, self.total_frequency)?;

            loop {
                if high < HALF {
                    emit_bit_with_follow(&mut writer, false, &mut pending_underflow_bits);
                } else if low >= HALF {
                    emit_bit_with_follow(&mut writer, true, &mut pending_underflow_bits);
                    low -= HALF;
                    high -= HALF;
                } else if low >= FIRST_QUARTER && high < THIRD_QUARTER {
                    pending_underflow_bits =
                        pending_underflow_bits.checked_add(1).ok_or_else(|| {
                            decode_error("arithmetic coder underflow counter overflow")
                        })?;
                    low -= FIRST_QUARTER;
                    high -= FIRST_QUARTER;
                } else {
                    break;
                }

                low <<= 1;
                high = (high << 1) | 1;
            }
        }

        pending_underflow_bits = pending_underflow_bits
            .checked_add(1)
            .ok_or_else(|| decode_error("arithmetic coder finalization overflow"))?;
        emit_bit_with_follow(
            &mut writer,
            low >= FIRST_QUARTER,
            &mut pending_underflow_bits,
        );
        let (output_bytes, valid_bits) = writer.finish();

        let original_bits = original_bits_estimate(symbols.len(), self.alphabet_size);
        let compressed_bytes = output_bytes.len();
        let compressed_bits = i64_from_i128_saturating(i128_from_usize_saturating(valid_bits));

        Ok(CompressedEvidence {
            schema: ENTROPY_SCHEMA_VERSION.to_string(),
            compressed_data: output_bytes,
            original_symbol_count: symbols.len(),
            compressed_bytes,
            original_bits_estimate: original_bits,
            compressed_bits,
            compression_ratio_millionths: compression_ratio(compressed_bits, original_bits),
            content_hash: content_hash_for_symbols(symbols),
            model_hash: content_hash_for_model(self),
        })
    }

    /// Decode and verify a compressed evidence artifact.
    ///
    /// Verification is deliberately stronger than merely producing symbols:
    /// the decoded count and original content hash must match, and re-encoding
    /// must reproduce the complete artifact byte-for-byte. This rejects
    /// corrupted, truncated, overlong, and otherwise non-canonical streams.
    pub fn decode(&self, compressed: &CompressedEvidence) -> Result<Vec<u32>, EntropyError> {
        self.validate_model()?;
        compressed.validate_metadata(self)?;

        let valid_bits = usize::try_from(compressed.compressed_bits)
            .map_err(|_| decode_error("compressed bit length cannot be represented"))?;
        let mut reader = BitReader::new(&compressed.compressed_data, valid_bits);
        let mut low = 0u64;
        let mut high = CODE_MAX;
        let mut code = 0u64;
        for _ in 0..CODE_VALUE_BITS {
            code = (code << 1) | u64::from(reader.read_bit_or_zero());
        }

        let model_intervals: Vec<(u32, u64, u64)> = self
            .frequency_table
            .iter()
            .map(|(&symbol, &(cumulative, frequency))| (symbol, cumulative, frequency))
            .collect();
        let mut symbols = Vec::with_capacity(compressed.original_symbol_count);
        for _ in 0..compressed.original_symbol_count {
            let interval = high
                .checked_sub(low)
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| decode_error("invalid arithmetic decoder interval"))?;
            let code_offset = code
                .checked_sub(low)
                .ok_or_else(|| decode_error("arithmetic code fell below its interval"))?;
            if code > high {
                return Err(decode_error("arithmetic code exceeded its interval"));
            }
            let scaled = u64_from_u128_saturating(
                (u128::from(code_offset).saturating_add(1))
                    .saturating_mul(u128::from(self.total_frequency))
                    .saturating_sub(1)
                    / u128::from(interval),
            );

            let selected_index = model_intervals
                .partition_point(|&(_, cumulative, frequency)| cumulative + frequency <= scaled);
            let &(symbol, cum_freq, frequency) = model_intervals
                .get(selected_index)
                .filter(|&&(_, cumulative, frequency)| {
                    (cumulative..cumulative + frequency).contains(&scaled)
                })
                .ok_or_else(|| decode_error("arithmetic code selects no model symbol"))?;
            symbols.push(symbol);

            update_interval(
                &mut low,
                &mut high,
                cum_freq,
                frequency,
                self.total_frequency,
            )?;

            loop {
                if high < HALF {
                    // Interval already lies in the lower half.
                } else if low >= HALF {
                    low -= HALF;
                    high -= HALF;
                    code = code
                        .checked_sub(HALF)
                        .ok_or_else(|| decode_error("decoder half-range underflow"))?;
                } else if low >= FIRST_QUARTER && high < THIRD_QUARTER {
                    low -= FIRST_QUARTER;
                    high -= FIRST_QUARTER;
                    code = code
                        .checked_sub(FIRST_QUARTER)
                        .ok_or_else(|| decode_error("decoder quarter-range underflow"))?;
                } else {
                    break;
                }

                low <<= 1;
                high = (high << 1) | 1;
                code = ((code << 1) & CODE_MAX) | u64::from(reader.read_bit_or_zero());
            }
        }

        if content_hash_for_symbols(&symbols) != compressed.content_hash {
            return Err(decode_error("decoded content hash mismatch"));
        }

        let canonical = self.encode(&symbols)?;
        if canonical != *compressed {
            return Err(decode_error("non-canonical compressed evidence artifact"));
        }

        Ok(symbols)
    }

    fn validate_model(&self) -> Result<(), EntropyError> {
        let actual_alphabet_size = self.frequency_table.len();
        if actual_alphabet_size == 0 || self.total_frequency == 0 {
            return Err(EntropyError::EmptyInput);
        }
        if actual_alphabet_size > MAX_ALPHABET_SIZE {
            return Err(EntropyError::AlphabetTooLarge {
                size: actual_alphabet_size,
                max: MAX_ALPHABET_SIZE,
            });
        }
        if self.alphabet_size != actual_alphabet_size {
            return Err(decode_error("arithmetic coder alphabet metadata mismatch"));
        }
        if self.total_frequency > MAX_TOTAL_FREQUENCY {
            return Err(decode_error(
                "arithmetic coder frequency total exceeds limit",
            ));
        }

        let mut expected_cumulative = 0u64;
        for &(cumulative, frequency) in self.frequency_table.values() {
            if frequency == 0 {
                return Err(decode_error("arithmetic coder contains a zero frequency"));
            }
            if cumulative != expected_cumulative {
                return Err(decode_error(
                    "arithmetic coder cumulative table is not canonical",
                ));
            }
            expected_cumulative = expected_cumulative
                .checked_add(frequency)
                .ok_or_else(|| decode_error("arithmetic coder frequency table overflow"))?;
        }
        if expected_cumulative != self.total_frequency {
            return Err(decode_error("arithmetic coder frequency total mismatch"));
        }
        Ok(())
    }

    /// Verify that the canonical model frequencies normalize to unit mass.
    ///
    /// The method retains its legacy public name, but it does not prove that a
    /// framed block stream is prefix-free and is not a substitute for decode
    /// plus canonical re-encode verification.
    pub fn verify_kraft_inequality(&self) -> Result<i64, EntropyError> {
        // For arithmetic coding with frequencies, effective codeword length
        // l_i = -log₂(freq_i / total) = log₂(total) - log₂(freq_i).
        // The legacy Kraft-named value is Σ freq_i / total = 1 for a valid
        // canonical model.

        self.validate_model()?;

        let mut sum: u64 = 0;
        for &(_, freq) in self.frequency_table.values() {
            sum = sum.checked_add(freq).ok_or(EntropyError::KraftViolation {
                kraft_sum_millionths: i64::MAX,
            })?;
        }
        // Use i128 to prevent overflow when sum * MILLION exceeds i64::MAX.
        let kraft_sum_millionths = i64_from_i128_saturating(
            i128::from(sum).saturating_mul(i128::from(MILLION))
                / i128::from(self.total_frequency.max(1)),
        );

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
                sum_fi_log2_fi += i128::from(freq) * i128::from(integer_log2_millionths(freq));
            }
        }
        let expected =
            i128::from(log2_total) - sum_fi_log2_fi / i128::from(self.total_frequency.max(1));
        i64_from_i128_saturating(expected.max(0))
    }
}

/// Compressed evidence artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Hash of the exact canonical arithmetic model used for this artifact.
    pub model_hash: ContentHash,
}

impl CompressedEvidence {
    fn validate_metadata(&self, coder: &ArithmeticCoder) -> Result<(), EntropyError> {
        if self.schema != ENTROPY_SCHEMA_VERSION {
            return Err(decode_error(format!(
                "unsupported compressed evidence schema: {}",
                self.schema
            )));
        }
        if self.original_symbol_count == 0 {
            return Err(EntropyError::EmptyInput);
        }
        if self.original_symbol_count > MAX_DECODED_SYMBOLS {
            return Err(decode_error(format!(
                "declared symbol count {} exceeds decode limit {MAX_DECODED_SYMBOLS}",
                self.original_symbol_count
            )));
        }
        if self.compressed_bytes != self.compressed_data.len() {
            return Err(decode_error("compressed byte-length metadata mismatch"));
        }
        if self.model_hash != content_hash_for_model(coder) {
            return Err(decode_error("arithmetic model hash mismatch"));
        }

        let valid_bits = usize::try_from(self.compressed_bits)
            .map_err(|_| decode_error("compressed bit length must be positive"))?;
        let maximum_canonical_bits = self
            .original_symbol_count
            .checked_mul(CODE_VALUE_BITS)
            .and_then(|bits| bits.checked_add(2))
            .ok_or_else(|| decode_error("declared symbol count exceeds codec framing limit"))?;
        if valid_bits > maximum_canonical_bits {
            return Err(decode_error(
                "compressed payload exceeds codec framing limit",
            ));
        }
        let maximum_bits = self
            .compressed_data
            .len()
            .checked_mul(8)
            .ok_or_else(|| decode_error("compressed byte length overflow"))?;
        let minimum_bits = self
            .compressed_data
            .len()
            .saturating_sub(1)
            .saturating_mul(8)
            .saturating_add(1);
        if valid_bits == 0 || valid_bits < minimum_bits || valid_bits > maximum_bits {
            return Err(decode_error("compressed bit-length metadata mismatch"));
        }

        let remainder = valid_bits % 8;
        if remainder != 0 {
            let padding_mask = (1u8 << (8 - remainder)) - 1;
            let final_byte = self
                .compressed_data
                .last()
                .copied()
                .ok_or_else(|| decode_error("compressed payload is empty"))?;
            if final_byte & padding_mask != 0 {
                return Err(decode_error("compressed payload has non-zero padding bits"));
            }
        }

        let expected_original_bits =
            original_bits_estimate(self.original_symbol_count, coder.alphabet_size);
        if self.original_bits_estimate != expected_original_bits {
            return Err(decode_error("original bit-estimate metadata mismatch"));
        }
        let expected_ratio = compression_ratio(self.compressed_bits, expected_original_bits);
        if self.compression_ratio_millionths != expected_ratio {
            return Err(decode_error("compression-ratio metadata mismatch"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CompressionCertificate — Shannon bound proof
// ---------------------------------------------------------------------------

/// Deterministic certificate recording empirical compression diagnostics.
///
/// `build_verified` establishes codec restoration and estimator association.
/// The Shannon- and Kraft-named fields are empirical comparison and model-mass
/// diagnostics, not a source-distribution or prefix-freeness proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionCertificate {
    pub schema: String,
    /// Empirical entropy H(X) in millionths of bits per symbol.
    pub entropy_millibits_per_symbol: i64,
    /// Module-specific empirical Shannon comparison (raw integer bits).
    pub shannon_lower_bound_bits: i64,
    /// Achieved compressed size (bits).
    pub achieved_bits: i64,
    /// Overhead over Shannon bound (bits, millionths).
    pub overhead_bits_millionths: i64,
    /// Overhead ratio (millionths): achieved / lower_bound.
    pub overhead_ratio_millionths: i64,
    /// Canonical model frequency-mass sum (legacy Kraft name, millionths).
    pub kraft_sum_millionths: i64,
    /// Whether the canonical model mass is normalized within tolerance.
    pub kraft_satisfied: bool,
    /// Redundancy (millionths of bits): H_max - H(X).
    pub redundancy_millibits: i64,
    /// Number of symbols.
    pub symbol_count: u64,
    /// Content hash for audit.
    pub certificate_hash: ContentHash,
}

impl CompressionCertificate {
    /// Build a certificate only after the artifact has been decoded and shown
    /// to reproduce the exact estimator histogram.
    pub fn build_verified(
        estimator: &EntropyEstimator,
        coder: &ArithmeticCoder,
        compressed: &CompressedEvidence,
    ) -> Result<Self, EntropyError> {
        let restored = coder.decode(compressed)?;
        let mut restored_estimator = EntropyEstimator::new();
        for symbol in restored {
            restored_estimator.observe(symbol);
        }
        if restored_estimator != *estimator {
            return Err(decode_error(
                "decoded symbol histogram does not match certificate estimator",
            ));
        }
        let kraft_sum = coder.verify_kraft_inequality()?;
        Ok(Self::build(estimator, compressed, kraft_sum))
    }

    /// Build a certificate from compression results.
    pub fn build(
        estimator: &EntropyEstimator,
        compressed: &CompressedEvidence,
        kraft_sum: i64,
    ) -> Self {
        let entropy = estimator.entropy_millibits();
        let lower_bound = estimator.shannon_lower_bound_bits();
        let achieved = compressed.compressed_bits;
        let achieved_bits_millionths = i128::from(achieved).saturating_mul(i128::from(MILLION));
        let lower_bound_millionths = i128::from(lower_bound).saturating_mul(i128::from(MILLION));
        let overhead = (achieved_bits_millionths - lower_bound_millionths).max(0);
        let overhead_ratio = if lower_bound_millionths > 0 {
            let ratio = achieved_bits_millionths.saturating_mul(i128::from(MILLION))
                / lower_bound_millionths;
            i64_from_i128_saturating(ratio)
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
            overhead_bits_millionths: i64_from_i128_saturating(overhead),
            overhead_ratio_millionths: overhead_ratio,
            kraft_sum_millionths: kraft_sum,
            kraft_satisfied: kraft_sum <= MILLION + 1000,
            redundancy_millibits: estimator.redundancy_millibits(),
            symbol_count: estimator.total_count,
            certificate_hash: ContentHash::compute(cert_data.as_bytes()),
        }
    }

    /// Compare the stored empirical overhead ratio with `factor`.
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
    let integer_part = i64::from(bits - 1) * MILLION;

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
        mantissa = u64_from_u128_saturating(
            (u128::from(mantissa).saturating_mul(u128::from(mantissa))) >> 32,
        );
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

fn i128_from_usize_saturating(value: usize) -> i128 {
    u64::try_from(value).map(i128::from).unwrap_or(i128::MAX)
}

fn decode_error(message: impl Into<String>) -> EntropyError {
    EntropyError::DecodeError {
        message: message.into(),
    }
}

fn update_interval(
    low: &mut u64,
    high: &mut u64,
    cumulative: u64,
    frequency: u64,
    total: u64,
) -> Result<(), EntropyError> {
    let upper = cumulative
        .checked_add(frequency)
        .ok_or_else(|| decode_error("arithmetic model upper bound overflow"))?;
    if frequency == 0 || upper > total || total == 0 {
        return Err(decode_error("invalid arithmetic model interval"));
    }

    let interval = high
        .checked_sub(*low)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| decode_error("invalid arithmetic coding interval"))?;
    let scaled_low = u64_from_u128_saturating(
        u128::from(interval).saturating_mul(u128::from(cumulative)) / u128::from(total),
    );
    let scaled_high = u64_from_u128_saturating(
        u128::from(interval).saturating_mul(u128::from(upper)) / u128::from(total),
    );
    if scaled_high == 0 {
        return Err(decode_error("arithmetic model interval collapsed"));
    }

    let next_low = (*low)
        .checked_add(scaled_low)
        .ok_or_else(|| decode_error("arithmetic coding low bound overflow"))?;
    let next_high = (*low)
        .checked_add(scaled_high - 1)
        .ok_or_else(|| decode_error("arithmetic coding high bound overflow"))?;
    if next_low > next_high {
        return Err(decode_error("arithmetic model interval collapsed"));
    }
    *low = next_low;
    *high = next_high;
    Ok(())
}

#[derive(Debug, Default)]
struct BitWriter {
    bytes: Vec<u8>,
    current_byte: u8,
    used_bits: u8,
    bit_len: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self::default()
    }

    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current_byte |= 1u8 << (7 - self.used_bits);
        }
        self.used_bits += 1;
        self.bit_len = self.bit_len.saturating_add(1);
        if self.used_bits == 8 {
            self.bytes.push(self.current_byte);
            self.current_byte = 0;
            self.used_bits = 0;
        }
    }

    fn finish(mut self) -> (Vec<u8>, usize) {
        if self.used_bits > 0 {
            self.bytes.push(self.current_byte);
        }
        (self.bytes, self.bit_len)
    }
}

fn emit_bit_with_follow(writer: &mut BitWriter, bit: bool, pending: &mut usize) {
    writer.write_bit(bit);
    for _ in 0..*pending {
        writer.write_bit(!bit);
    }
    *pending = 0;
}

#[derive(Debug)]
struct BitReader<'a> {
    bytes: &'a [u8],
    valid_bits: usize,
    position: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8], valid_bits: usize) -> Self {
        Self {
            bytes,
            valid_bits,
            position: 0,
        }
    }

    fn read_bit_or_zero(&mut self) -> u8 {
        if self.position >= self.valid_bits {
            return 0;
        }
        let byte = self.bytes[self.position / 8];
        let bit = (byte >> (7 - (self.position % 8))) & 1;
        self.position += 1;
        bit
    }
}

fn original_bits_estimate(symbol_count: usize, alphabet_size: usize) -> i64 {
    i64_from_i128_saturating(
        i128_from_usize_saturating(symbol_count).saturating_mul(i128::from(
            integer_log2_millionths(u64_from_usize_saturating(alphabet_size)),
        )) / i128::from(MILLION),
    )
}

fn compression_ratio(compressed_bits: i64, original_bits: i64) -> i64 {
    if original_bits > 0 {
        i64_from_i128_saturating(
            i128::from(compressed_bits).saturating_mul(i128::from(MILLION))
                / i128::from(original_bits),
        )
    } else {
        MILLION
    }
}

fn content_hash_for_symbols(symbols: &[u32]) -> ContentHash {
    const DOMAIN: &[u8] = b"franken-engine.entropy-symbol-stream.v2\0";
    let mut bytes = Vec::with_capacity(
        DOMAIN
            .len()
            .saturating_add(symbols.len().saturating_mul(std::mem::size_of::<u32>())),
    );
    bytes.extend_from_slice(DOMAIN);
    for symbol in symbols {
        bytes.extend_from_slice(&symbol.to_be_bytes());
    }
    ContentHash::compute(&bytes)
}

fn content_hash_for_model(coder: &ArithmeticCoder) -> ContentHash {
    const DOMAIN: &[u8] = b"franken-engine.arithmetic-model.v2\0";
    let entry_bytes = std::mem::size_of::<u32>() + 2 * std::mem::size_of::<u64>();
    let mut bytes = Vec::with_capacity(
        DOMAIN.len()
            + 2 * std::mem::size_of::<u64>()
            + coder.frequency_table.len().saturating_mul(entry_bytes),
    );
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&u64_from_usize_saturating(coder.alphabet_size).to_be_bytes());
    bytes.extend_from_slice(&coder.total_frequency.to_be_bytes());
    for (&symbol, &(cumulative, frequency)) in &coder.frequency_table {
        bytes.extend_from_slice(&symbol.to_be_bytes());
        bytes.extend_from_slice(&cumulative.to_be_bytes());
        bytes.extend_from_slice(&frequency.to_be_bytes());
    }
    ContentHash::compute(&bytes)
}

fn i64_from_i128_saturating(value: i128) -> i64 {
    i64::try_from(value).unwrap_or(if value.is_negative() {
        i64::MIN
    } else {
        i64::MAX
    })
}

fn u64_from_u128_saturating(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn u64_from_usize_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
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
        // SAFETY: EntropyEstimator derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&est).unwrap();
        // SAFETY: JSON was just produced by to_string of a valid EntropyEstimator,
        // so from_str back to EntropyEstimator cannot fail (valid format + matching schema).
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
        // SAFETY: SufficientStatistic derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&ss).unwrap();
        // SAFETY: JSON was just produced by to_string of a valid SufficientStatistic,
        // so from_str back to SufficientStatistic cannot fail (valid format + matching schema).
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
        // SAFETY: EntropyEstimator contains valid observed data (0,1 symbols, 200 total observations),
        // so from_estimator has non-empty frequency table and cannot fail with InvalidInput.
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
        // SAFETY: EntropyEstimator contains valid observed data (0,1 symbols, 200 total observations),
        // so from_estimator has non-empty frequency table and cannot fail with InvalidInput.
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        // SAFETY: Input symbols [0,1,0,1,0] are all present in coder's frequency table
        // (observed during estimator construction), so encode cannot fail with UnknownSymbol.
        let compressed = coder.encode(&[0, 1, 0, 1, 0]).unwrap();
        assert!(!compressed.compressed_data.is_empty());
        assert_eq!(compressed.original_symbol_count, 5);
        assert_eq!(
            compressed.compressed_bytes,
            compressed.compressed_data.len()
        );
    }

    #[test]
    fn coder_decode_roundtrip_carry_e3_and_corruption() {
        let mut uniform = EntropyEstimator::new();
        uniform.observe(0);
        uniform.observe(1);
        let uniform_coder = ArithmeticCoder::from_estimator(&uniform).unwrap();
        let carry_symbols = [0, 0, 0, 0, 0, 0, 0, 1, 1];
        let carry = uniform_coder.encode(&carry_symbols).unwrap();
        assert_eq!(carry.compressed_data, vec![0x01, 0xa0]);
        assert_eq!(carry.compressed_bits, 11);
        assert_eq!(uniform_coder.decode(&carry).unwrap(), carry_symbols);

        let mut e3_estimator = EntropyEstimator::new();
        e3_estimator.observe(0);
        e3_estimator.observe(1);
        e3_estimator.observe(1);
        let e3_coder = ArithmeticCoder::from_estimator(&e3_estimator).unwrap();
        let e3 = e3_coder.encode(&[1, 0]).unwrap();
        assert_eq!(e3.compressed_data, vec![0x60]);
        assert_eq!(e3.compressed_bits, 3);
        assert_eq!(e3_coder.decode(&e3).unwrap(), vec![1, 0]);

        for bit_index in 0..carry.compressed_data.len() * 8 {
            let mut tampered = carry.clone();
            tampered.compressed_data[bit_index / 8] ^= 1 << (7 - bit_index % 8);
            assert!(uniform_coder.decode(&tampered).is_err());
        }
    }

    #[test]
    fn coder_decode_rejects_malformed_model() {
        let coder = ArithmeticCoder {
            frequency_table: BTreeMap::from([(0, (0, 0))]),
            total_frequency: 1,
            alphabet_size: 1,
        };
        assert!(coder.encode(&[0]).is_err());
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
        // SAFETY: EntropyEstimator contains valid observed data (0,1), so from_estimator
        // has non-empty frequency table and cannot fail with InvalidInput.
        let coder = ArithmeticCoder::from_estimator(&est).unwrap();
        // SAFETY: ArithmeticCoder derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&coder).unwrap();
        // SAFETY: JSON was just produced by to_string of a valid ArithmeticCoder,
        // so from_str back to ArithmeticCoder cannot fail (valid format + matching schema).
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
            model_hash: ContentHash::compute(b"test-model"),
        };
        // SAFETY: CompressedEvidence derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&ce).unwrap();
        // SAFETY: JSON was just produced by to_string of a valid CompressedEvidence,
        // so from_str back to CompressedEvidence cannot fail (valid format + matching schema).
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
        // SAFETY: CompressionCertificate derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&cert).unwrap();
        // SAFETY: JSON was just produced by to_string of a valid CompressionCertificate,
        // so from_str back to CompressionCertificate cannot fail (valid format + matching schema).
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
        assert!(format!("{err}").contains("frequency mass"));
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
            // SAFETY: EntropyError derives Serialize and has no non-serializable fields.
            // to_string on derived Serialize types only fails on writer errors (impossible with String).
            let json = serde_json::to_string(err).unwrap();
            // SAFETY: JSON was just produced by to_string of a valid EntropyError,
            // so from_str back to EntropyError cannot fail (valid format + matching schema).
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
            model_hash: ContentHash::compute(b"clone-model"),
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
        // SAFETY: EntropyError derives Serialize and has no non-serializable fields.
        // to_string on derived Serialize types only fails on writer errors (impossible with String).
        let json = serde_json::to_string(&err).unwrap();
        // SAFETY: JSON was just produced by to_string of a valid EntropyError,
        // so from_str back to EntropyError cannot fail (valid format + matching schema).
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
            model_hash: ContentHash::compute(b"model-a"),
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
            model_hash: ContentHash::compute(b"model-b"),
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
            model_hash: ContentHash::compute(b"ci-model"),
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
            model_hash: ContentHash::compute(b"fs-model"),
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
            "model_hash",
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
        let total_prob: i64 = (0..5u32)
            .map(|i| est.probability_millionths(i))
            .fold(0i64, |acc, x| acc.saturating_add(x));
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
        assert_eq!(
            format!("{err}"),
            "model frequency mass is not normalized: sum = 1200000"
        );
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
