//! SIMD/SWAR-accelerated lexical analysis for the FrankenEngine parser front-end.
//!
//! Uses SWAR (SIMD Within A Register) techniques to classify bytes in parallel
//! using ordinary 64-bit arithmetic — no `unsafe` code or platform intrinsics
//! required. Maintains strict semantic parity with the scalar reference lexer
//! (`parser::count_lexical_tokens`), with built-in differential parity checking
//! and deterministic fallback.
//!
//! ## Architecture
//!
//! The module provides three levels of lexing:
//! 1. **SWAR-accelerated** (`SwarLexer`): Processes 8 bytes at a time for whitespace
//!    skipping, identifier-boundary detection, and string delimiter scanning.
//! 2. **Scalar reference** (`ScalarLexer`): Byte-by-byte lexer that exactly mirrors
//!    `parser::count_lexical_tokens` semantics.
//! 3. **Differential harness** (`DifferentialLexer`): Runs both in parallel and
//!    asserts token-stream parity, emitting diagnostics on mismatch.
//!
//! ## Related beads
//!
//! - bd-19ba (this module)
//! - bd-2mds.1.3.2 (SoA token/span storage with cache-local layout)
//! - bd-drjd (arena-allocated AST / token definitions — upstream dependency)
//! - bd-1vfi (parallel parsing — downstream consumer)
//! - bd-1b70 (parser oracle — parity gate)

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ast::SourceSpan;
use crate::engine_object_id::EngineObjectId;

/// Schema version for serde stability of simd_lexer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LexerSchemaVersion {
    /// Initial version.
    V1,
}

impl fmt::Display for LexerSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => f.write_str("v1"),
        }
    }
}

// ---------------------------------------------------------------------------
// Token kinds — deterministic, exhaustive classification
// ---------------------------------------------------------------------------

/// Deterministic token classification for lexical analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TokenKind {
    /// Identifier: `[a-zA-Z_$][a-zA-Z0-9_$]*`
    Identifier,
    /// Numeric literal: `[0-9]+`
    NumericLiteral,
    /// String literal: single or double quoted, with escape support.
    StringLiteral,
    /// Unterminated string literal (hit newline or EOF before closing quote).
    UnterminatedString,
    /// Two-character operator: `==`, `!=`, `<=`, `>=`, `&&`, `||`, `??`, `=>`.
    TwoCharOperator,
    /// Single-character punctuation or operator (anything not otherwise classified).
    Punctuation,
}

impl fmt::Display for TokenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identifier => write!(f, "Identifier"),
            Self::NumericLiteral => write!(f, "NumericLiteral"),
            Self::StringLiteral => write!(f, "StringLiteral"),
            Self::UnterminatedString => write!(f, "UnterminatedString"),
            Self::TwoCharOperator => write!(f, "TwoCharOperator"),
            Self::Punctuation => write!(f, "Punctuation"),
        }
    }
}

/// A single lexical token with kind, byte span, and source text slice reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub kind: TokenKind,
    pub start: u64,
    pub end: u64,
}

impl Token {
    pub fn span_len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn source_span(&self, line: u64, column_start: u64) -> SourceSpan {
        SourceSpan::new(
            self.start,
            self.end,
            line,
            column_start,
            line,
            column_start.saturating_add(self.span_len()),
        )
    }
}

/// Cache-local token/span storage using a Structure-of-Arrays (SoA) layout.
///
/// Keeps token kinds and span columns contiguous to improve scan/merge locality
/// in parser-adjacent lanes while still materializing canonical `Token` vectors
/// for compatibility at API boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenSpanStorage {
    kinds: Vec<TokenKind>,
    starts: Vec<u64>,
    ends: Vec<u64>,
}

impl TokenSpanStorage {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            kinds: Vec::with_capacity(capacity),
            starts: Vec::with_capacity(capacity),
            ends: Vec::with_capacity(capacity),
        }
    }

    pub fn from_tokens(tokens: &[Token]) -> Self {
        let mut storage = Self::with_capacity(tokens.len());
        for token in tokens {
            storage.push(token.kind, token.start, token.end);
        }
        storage
    }

    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    pub fn token_kinds(&self) -> &[TokenKind] {
        &self.kinds
    }

    pub fn starts(&self) -> &[u64] {
        &self.starts
    }

    pub fn ends(&self) -> &[u64] {
        &self.ends
    }

    pub fn push(&mut self, kind: TokenKind, start: u64, end: u64) {
        self.kinds.push(kind);
        self.starts.push(start);
        self.ends.push(end);
        debug_assert_eq!(self.kinds.len(), self.starts.len());
        debug_assert_eq!(self.starts.len(), self.ends.len());
    }

    pub fn to_tokens(&self) -> Vec<Token> {
        debug_assert_eq!(self.kinds.len(), self.starts.len());
        debug_assert_eq!(self.starts.len(), self.ends.len());

        let mut tokens = Vec::with_capacity(self.kinds.len());
        for index in 0..self.kinds.len() {
            tokens.push(Token {
                kind: self.kinds[index],
                start: self.starts[index],
                end: self.ends[index],
            });
        }
        tokens
    }

    pub fn into_tokens(self) -> Vec<Token> {
        let len = self.kinds.len();
        debug_assert_eq!(len, self.starts.len());
        debug_assert_eq!(len, self.ends.len());

        let mut tokens = Vec::with_capacity(len);
        for index in 0..len {
            tokens.push(Token {
                kind: self.kinds[index],
                start: self.starts[index],
                end: self.ends[index],
            });
        }
        tokens
    }
}

// ---------------------------------------------------------------------------
// Lexer mode and configuration
// ---------------------------------------------------------------------------

/// Which lexer engine to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LexerMode {
    /// SWAR-accelerated path (default on all targets since it uses no intrinsics).
    Swar,
    /// Scalar reference path (guaranteed baseline).
    Scalar,
    /// Run both and assert parity; emit diagnostics on mismatch.
    Differential,
}

impl fmt::Display for LexerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Swar => write!(f, "SWAR"),
            Self::Scalar => write!(f, "Scalar"),
            Self::Differential => write!(f, "Differential"),
        }
    }
}

/// Required architecture feature gate for enabling SWAR mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SwarFeatureGate {
    /// Portable SWAR-only gate (no SIMD intrinsics required).
    Portable,
    /// Require x86_64 AVX2 capability.
    RequireAvx2,
    /// Require x86_64 AVX512F capability.
    RequireAvx512F,
    /// Require ARM/AArch64 NEON capability.
    RequireNeon,
}

impl fmt::Display for SwarFeatureGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Portable => write!(f, "portable"),
            Self::RequireAvx2 => write!(f, "require_avx2"),
            Self::RequireAvx512F => write!(f, "require_avx512f"),
            Self::RequireNeon => write!(f, "require_neon"),
        }
    }
}

/// Architecture family used for deterministic fallback decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ArchFamily {
    X86_64,
    Aarch64,
    Arm,
    Other,
}

impl fmt::Display for ArchFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::Aarch64 => write!(f, "aarch64"),
            Self::Arm => write!(f, "arm"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// Reason the SWAR path was disabled in favor of scalar fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwarDisableReason {
    /// Operator explicitly chose scalar mode.
    OperatorOverride,
    /// Differential parity check detected a mismatch — automatic fallback.
    ParityMismatch { mismatch_index: u64 },
    /// Input too small to benefit from SWAR (below width threshold).
    InputBelowThreshold { input_len: u64, threshold: u64 },
    /// SWAR path not supported on the active architecture profile.
    ArchitectureUnsupported {
        pointer_width: u32,
        little_endian: bool,
    },
    /// Policy requires an architecture feature gate that is unavailable.
    FeatureGateUnavailable {
        required: SwarFeatureGate,
        arch_family: ArchFamily,
    },
    /// Token budget would be exceeded before SWAR scan completes.
    TokenBudgetExceeded,
}

impl fmt::Display for SwarDisableReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperatorOverride => write!(f, "operator_override"),
            Self::ParityMismatch { mismatch_index } => {
                write!(f, "parity_mismatch(index={})", mismatch_index)
            }
            Self::InputBelowThreshold {
                input_len,
                threshold,
            } => write!(
                f,
                "input_below_threshold(len={}, threshold={})",
                input_len, threshold
            ),
            Self::ArchitectureUnsupported {
                pointer_width,
                little_endian,
            } => write!(
                f,
                "architecture_unsupported(pointer_width={}, little_endian={})",
                pointer_width, little_endian
            ),
            Self::FeatureGateUnavailable {
                required,
                arch_family,
            } => write!(
                f,
                "feature_gate_unavailable(required={}, arch={})",
                required, arch_family
            ),
            Self::TokenBudgetExceeded => write!(f, "token_budget_exceeded"),
        }
    }
}

/// Configuration for the lexer pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexerConfig {
    /// Which engine to use.
    pub mode: LexerMode,
    /// Maximum number of tokens before budget is exceeded.
    pub max_tokens: u64,
    /// Maximum number of source bytes to scan.
    pub max_source_bytes: u64,
    /// Minimum input size (bytes) to engage SWAR path. Below this, scalar is used.
    pub swar_min_input_bytes: u64,
    /// Architecture feature gate policy for enabling SWAR.
    pub feature_gate: SwarFeatureGate,
    /// If true, emit full token stream. If false, only count tokens (fast path).
    pub emit_tokens: bool,
}

impl Default for LexerConfig {
    fn default() -> Self {
        Self {
            mode: LexerMode::Swar,
            max_tokens: 65_536,
            max_source_bytes: 1_048_576,
            swar_min_input_bytes: 64,
            feature_gate: SwarFeatureGate::Portable,
            emit_tokens: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Lexer output
// ---------------------------------------------------------------------------

/// Result of a lexing pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexerOutput {
    /// The mode that was actually used (may differ from config if fallback occurred).
    pub actual_mode: LexerMode,
    /// If SWAR was disabled, why.
    pub swar_disable_reason: Option<SwarDisableReason>,
    /// Total number of tokens found.
    pub token_count: u64,
    /// Emitted tokens (empty if `emit_tokens` was false).
    pub tokens: Vec<Token>,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Whether the token budget was exceeded.
    pub budget_exceeded: bool,
    /// Schema version for serde stability.
    pub schema_version: LexerSchemaVersion,
}

/// Mismatch detail when differential mode detects divergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityMismatch {
    /// Index of the first divergent token (0-based).
    pub token_index: u64,
    /// SWAR token at the divergence point (if available).
    pub swar_token: Option<Token>,
    /// Scalar token at the divergence point (if available).
    pub scalar_token: Option<Token>,
    /// Overall SWAR token count.
    pub swar_count: u64,
    /// Overall scalar token count.
    pub scalar_count: u64,
}

impl fmt::Display for ParityMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "parity mismatch at token {}: swar_count={}, scalar_count={}",
            self.token_index, self.swar_count, self.scalar_count
        )
    }
}

/// Full differential result including both outputs and any mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialResult {
    pub swar_output: LexerOutput,
    pub scalar_output: LexerOutput,
    pub parity_ok: bool,
    pub mismatch: Option<ParityMismatch>,
}

// ---------------------------------------------------------------------------
// Lexer error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LexerError {
    /// Source exceeds maximum allowed byte count.
    SourceTooLarge { size: u64, max: u64 },
    /// Token budget was exceeded during scanning.
    TokenBudgetExceeded { count: u64, max: u64 },
    /// Internal consistency error.
    InternalError(String),
}

impl fmt::Display for LexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceTooLarge { size, max } => {
                write!(f, "source too large: {} bytes (max {})", size, max)
            }
            Self::TokenBudgetExceeded { count, max } => {
                write!(f, "token budget exceeded: {} tokens (max {})", count, max)
            }
            Self::InternalError(msg) => write!(f, "internal lexer error: {}", msg),
        }
    }
}

// ---------------------------------------------------------------------------
// SWAR bit-parallel primitives (safe Rust, no intrinsics)
// ---------------------------------------------------------------------------

/// SWAR word size: we process 8 bytes at a time using u64 arithmetic.
const SWAR_WIDTH: usize = 8;

/// Broadcast a single byte to all 8 positions of a u64.
#[inline]
const fn broadcast(byte: u8) -> u64 {
    0x0101_0101_0101_0101_u64.wrapping_mul(byte as u64)
}

#[inline]
fn new_token_storage(input_len: usize, emit_tokens: bool) -> Option<TokenSpanStorage> {
    if emit_tokens {
        // Most inputs have far fewer tokens than bytes, but keeping a bounded
        // headroom avoids repeated growth on common short/medium snippets.
        Some(TokenSpanStorage::with_capacity(input_len.min(256)))
    } else {
        None
    }
}

#[inline]
fn push_emitted_token(
    storage: &mut Option<TokenSpanStorage>,
    kind: TokenKind,
    start: u64,
    end: u64,
) {
    if let Some(storage) = storage.as_mut() {
        storage.push(kind, start, end);
    }
}

#[inline]
fn finalize_tokens(storage: Option<TokenSpanStorage>) -> Vec<Token> {
    storage
        .map(TokenSpanStorage::into_tokens)
        .unwrap()
}

const SWAR_HIGH_BITS: u64 = 0x8080_8080_8080_8080_u64;

#[inline]
fn match_prefix_len(mask: u64) -> usize {
    let mut count = 0usize;
    while count < SWAR_WIDTH {
        if (mask & (0x80_u64 << (count * 8))) == 0 {
            break;
        }
        count += 1;
    }
    count
}

/// Produce a mask where each byte position that equals `target` has its high bit set.
/// Other bytes have their high bit clear.
///
/// Uses a carry-safe SWAR formulation: isolates the lower 7 bits of each XOR'd byte,
/// adds 0x7F per lane (which never overflows a byte boundary since max input is 0x7F),
/// and checks whether both the lower-7-bit and high-bit portions are zero. This avoids
/// the borrow-propagation false positive in the classic `(v - 0x01…) & ~v & 0x80…`
/// pattern (which misdetects byte value target+1 after a match).
#[inline]
const fn byte_eq_mask(word: u64, target: u8) -> u64 {
    let broadcast_target = broadcast(target);
    let xor = word ^ broadcast_target;
    let high_bits = 0x8080_8080_8080_8080_u64;
    let low_mask = !high_bits;
    // 0x7F7F_7F7F_7F7F_7F7F
    // Check lower 7 bits of each byte are zero.
    // Carry-free guarantee: max 0x7F + 0x7F = 0xFE < 0x100.
    let lower7 = xor & low_mask;
    let lower_nonzero = lower7.wrapping_add(low_mask) & high_bits;
    let lower_zero = !lower_nonzero & high_bits;
    // Check high bit of each byte is also zero
    let high_zero = !xor & high_bits;
    lower_zero & high_zero
}

// SWAR mask helpers used by lexer hot loops and parity tests.
fn whitespace_mask(word: u64) -> u64 {
    byte_eq_mask(word, b' ')
        | byte_eq_mask(word, b'\t')
        | byte_eq_mask(word, b'\n')
        | byte_eq_mask(word, b'\r')
        | byte_eq_mask(word, 0x0B)
        | byte_eq_mask(word, 0x0C)
}

fn digit_mask(word: u64) -> u64 {
    let high_bits = 0x8080_8080_8080_8080_u64;
    let low_bound = 0x3030_3030_3030_3030_u64;
    let high_bound = 0x3939_3939_3939_3939_u64;
    let ge_low = !word.wrapping_sub(low_bound) & high_bits;
    let le_high = !high_bound.wrapping_sub(word) & high_bits;
    ge_low & le_high
}

fn identifier_continue_mask(word: u64) -> u64 {
    alpha_mask(word) | digit_mask(word) | byte_eq_mask(word, b'_') | byte_eq_mask(word, b'$')
}

fn alpha_mask(word: u64) -> u64 {
    let upper = word & !broadcast(0x20);
    let high_bits = 0x8080_8080_8080_8080_u64;
    let a_broadcast = broadcast(b'A');
    let z_broadcast = broadcast(b'Z');
    let ge_a = !upper.wrapping_sub(a_broadcast) & high_bits;
    let le_z = !z_broadcast.wrapping_sub(upper) & high_bits;
    ge_a & le_z
}

#[cfg(test)]
const fn mask_popcount(mask: u64) -> u32 {
    (mask >> 7).count_ones()
}

const fn mask_first_set(mask: u64) -> u32 {
    if mask == 0 {
        8
    } else {
        mask.trailing_zeros() / 8
    }
}

// ---------------------------------------------------------------------------
// Scalar reference lexer
// ---------------------------------------------------------------------------

/// Scalar reference lexer — byte-by-byte, mirrors `parser::count_lexical_tokens` exactly.
pub struct ScalarLexer;

impl ScalarLexer {
    pub fn lex(input: &[u8], config: &LexerConfig) -> Result<LexerOutput, LexerError> {
        let input_len = input.len() as u64;
        if input_len > config.max_source_bytes {
            return Err(LexerError::SourceTooLarge {
                size: input_len,
                max: config.max_source_bytes,
            });
        }

        let mut index = 0usize;
        let mut token_storage = new_token_storage(input.len(), config.emit_tokens);
        let mut token_count = 0u64;

        while index < input.len() {
            if token_count >= config.max_tokens {
                return Ok(LexerOutput {
                    actual_mode: LexerMode::Scalar,
                    swar_disable_reason: None,
                    token_count,
                    tokens: finalize_tokens(token_storage),
                    bytes_scanned: index as u64,
                    budget_exceeded: true,
                    schema_version: LexerSchemaVersion::V1,
                });
            }

            let byte = input[index];

            // Whitespace
            if byte.is_ascii_whitespace() {
                index = index.saturating_add(1);
                continue;
            }

            // Identifier
            if is_ident_start(byte) {
                let start = index as u64;
                index = index.saturating_add(1);
                while index < input.len() && is_ident_continue(input[index]) {
                    index = index.saturating_add(1);
                }
                token_count = token_count.saturating_add(1);
                push_emitted_token(
                    &mut token_storage,
                    TokenKind::Identifier,
                    start,
                    index as u64,
                );
                continue;
            }

            // Numeric literal
            if byte.is_ascii_digit() {
                let start = index as u64;
                index = index.saturating_add(1);
                while index < input.len() && input[index].is_ascii_digit() {
                    index = index.saturating_add(1);
                }
                token_count = token_count.saturating_add(1);
                push_emitted_token(
                    &mut token_storage,
                    TokenKind::NumericLiteral,
                    start,
                    index as u64,
                );
                continue;
            }

            // String literal
            if byte == b'\'' || byte == b'"' {
                let quote = byte;
                let start = index as u64;
                index = index.saturating_add(1);
                let mut terminated = false;

                while index < input.len() {
                    let current = input[index];
                    if current == b'\\' {
                        index = index.saturating_add(2).min(input.len());
                        continue;
                    }
                    if current == quote {
                        index = index.saturating_add(1);
                        terminated = true;
                        break;
                    }
                    if current == b'\n' || current == b'\r' {
                        break;
                    }
                    index = index.saturating_add(1);
                }

                token_count = token_count.saturating_add(1);
                let kind = if terminated {
                    TokenKind::StringLiteral
                } else {
                    TokenKind::UnterminatedString
                };
                push_emitted_token(&mut token_storage, kind, start, index as u64);
                continue;
            }

            // Two-character operators
            if index + 1 < input.len() && is_two_char_operator(input[index], input[index + 1]) {
                let start = index as u64;
                index = index.saturating_add(2);
                token_count = token_count.saturating_add(1);
                push_emitted_token(
                    &mut token_storage,
                    TokenKind::TwoCharOperator,
                    start,
                    index as u64,
                );
                continue;
            }

            // Single punctuation / operator
            let start = index as u64;
            index = index.saturating_add(1);
            token_count = token_count.saturating_add(1);
            push_emitted_token(
                &mut token_storage,
                TokenKind::Punctuation,
                start,
                index as u64,
            );
        }

        Ok(LexerOutput {
            actual_mode: LexerMode::Scalar,
            swar_disable_reason: None,
            token_count,
            tokens: finalize_tokens(token_storage),
            bytes_scanned: input.len() as u64,
            budget_exceeded: false,
            schema_version: LexerSchemaVersion::V1,
        })
    }
}

// ---------------------------------------------------------------------------
// SWAR-accelerated lexer
// ---------------------------------------------------------------------------

/// SWAR-accelerated lexer — processes 8 bytes at a time for fast whitespace
/// skipping and identifier/digit boundary detection.
pub struct SwarLexer;

impl SwarLexer {
    pub fn lex(input: &[u8], config: &LexerConfig) -> Result<LexerOutput, LexerError> {
        let input_len = input.len() as u64;
        if input_len > config.max_source_bytes {
            return Err(LexerError::SourceTooLarge {
                size: input_len,
                max: config.max_source_bytes,
            });
        }

        let profile = ArchCapabilityProfile::detect();
        if let Some(reason) = evaluate_swar_fallback_matrix(input_len, config, &profile) {
            let mut result = ScalarLexer::lex(input, config)?;
            result.swar_disable_reason = Some(reason);
            return Ok(result);
        }

        let mut index = 0usize;
        let mut token_storage = new_token_storage(input.len(), config.emit_tokens);
        let mut token_count = 0u64;
        let len = input.len();

        while index < len {
            if token_count >= config.max_tokens {
                return Ok(LexerOutput {
                    actual_mode: LexerMode::Swar,
                    swar_disable_reason: Some(SwarDisableReason::TokenBudgetExceeded),
                    token_count,
                    tokens: finalize_tokens(token_storage),
                    bytes_scanned: index as u64,
                    budget_exceeded: true,
                    schema_version: LexerSchemaVersion::V1,
                });
            }

            // SWAR fast-path: skip whitespace in 8-byte chunks.
            while index + SWAR_WIDTH <= len {
                let word = read_u64_le(input, index);
                let mask = whitespace_mask(word);
                if mask == SWAR_HIGH_BITS {
                    index = index.saturating_add(SWAR_WIDTH);
                    continue;
                }
                index = index.saturating_add(match_prefix_len(mask));
                break;
            }

            // Scalar whitespace skip for remainder
            while index < len && input[index].is_ascii_whitespace() {
                index = index.saturating_add(1);
            }

            if index >= len {
                break;
            }

            let byte = input[index];

            // Identifier with SWAR continuation scanning
            if is_ident_start(byte) {
                let start = index as u64;
                index = index.saturating_add(1);

                // SWAR scan for identifier continuation bytes with partial-prefix skipping.
                while index + SWAR_WIDTH <= len {
                    let word = read_u64_le(input, index);
                    let mask = identifier_continue_mask(word);
                    if mask == SWAR_HIGH_BITS {
                        index = index.saturating_add(SWAR_WIDTH);
                        continue;
                    }
                    index = index.saturating_add(match_prefix_len(mask));
                    break;
                }

                // Scalar remainder
                while index < len && is_ident_continue(input[index]) {
                    index = index.saturating_add(1);
                }

                token_count = token_count.saturating_add(1);
                push_emitted_token(
                    &mut token_storage,
                    TokenKind::Identifier,
                    start,
                    index as u64,
                );
                continue;
            }

            // Numeric literal with SWAR digit scanning
            if byte.is_ascii_digit() {
                let start = index as u64;
                index = index.saturating_add(1);

                // SWAR scan for digit bytes with partial-prefix skipping.
                while index + SWAR_WIDTH <= len {
                    let word = read_u64_le(input, index);
                    let mask = digit_mask(word);
                    if mask == SWAR_HIGH_BITS {
                        index = index.saturating_add(SWAR_WIDTH);
                        continue;
                    }
                    index = index.saturating_add(match_prefix_len(mask));
                    break;
                }

                while index < len && input[index].is_ascii_digit() {
                    index = index.saturating_add(1);
                }

                token_count = token_count.saturating_add(1);
                push_emitted_token(
                    &mut token_storage,
                    TokenKind::NumericLiteral,
                    start,
                    index as u64,
                );
                continue;
            }

            // String literal with SWAR quote/escape scanning
            if byte == b'\'' || byte == b'"' {
                let quote = byte;
                let start = index as u64;
                index = index.saturating_add(1);
                let mut terminated = false;

                // SWAR scan for string termination
                while index + SWAR_WIDTH <= len {
                    let word = read_u64_le(input, index);
                    let quote_mask = byte_eq_mask(word, quote);
                    let escape_mask = byte_eq_mask(word, b'\\');
                    let nl_mask = byte_eq_mask(word, b'\n') | byte_eq_mask(word, b'\r');

                    let interesting = quote_mask | escape_mask | nl_mask;
                    if interesting == 0 {
                        // No interesting bytes in this chunk — skip all 8
                        index = index.saturating_add(SWAR_WIDTH);
                        continue;
                    }

                    // Jump directly to the first interesting byte and continue
                    // with scalar logic for exact semantics.
                    index = index.saturating_add(mask_first_set(interesting) as usize);
                    break;
                }

                // Scalar string scanning for remainder / complex cases
                while index < len {
                    let current = input[index];
                    if current == b'\\' {
                        index = index.saturating_add(2).min(input.len());
                        continue;
                    }
                    if current == quote {
                        index = index.saturating_add(1);
                        terminated = true;
                        break;
                    }
                    if current == b'\n' || current == b'\r' {
                        break;
                    }
                    index = index.saturating_add(1);
                }

                token_count = token_count.saturating_add(1);
                let kind = if terminated {
                    TokenKind::StringLiteral
                } else {
                    TokenKind::UnterminatedString
                };
                push_emitted_token(&mut token_storage, kind, start, index as u64);
                continue;
            }

            // Two-character operators
            if index + 1 < len && is_two_char_operator(input[index], input[index + 1]) {
                let start = index as u64;
                index = index.saturating_add(2);
                token_count = token_count.saturating_add(1);
                push_emitted_token(
                    &mut token_storage,
                    TokenKind::TwoCharOperator,
                    start,
                    index as u64,
                );
                continue;
            }

            // Single punctuation
            let start = index as u64;
            index = index.saturating_add(1);
            token_count = token_count.saturating_add(1);
            push_emitted_token(
                &mut token_storage,
                TokenKind::Punctuation,
                start,
                index as u64,
            );
        }

        Ok(LexerOutput {
            actual_mode: LexerMode::Swar,
            swar_disable_reason: None,
            token_count,
            tokens: finalize_tokens(token_storage),
            bytes_scanned: input.len() as u64,
            budget_exceeded: false,
            schema_version: LexerSchemaVersion::V1,
        })
    }
}

// ---------------------------------------------------------------------------
// Differential lexer
// ---------------------------------------------------------------------------

/// Runs both SWAR and scalar lexers and compares results for parity.
pub struct DifferentialLexer;

impl DifferentialLexer {
    pub fn lex(input: &[u8], config: &LexerConfig) -> Result<DifferentialResult, LexerError> {
        // Force emit_tokens for comparison
        let mut emit_config = config.clone();
        emit_config.emit_tokens = true;

        let mut swar_config = emit_config.clone();
        swar_config.mode = LexerMode::Swar;
        let swar_output = SwarLexer::lex(input, &swar_config)?;

        let mut scalar_config = emit_config;
        scalar_config.mode = LexerMode::Scalar;
        let scalar_output = ScalarLexer::lex(input, &scalar_config)?;

        let mismatch = find_mismatch(&swar_output, &scalar_output);
        let parity_ok = mismatch.is_none();

        Ok(DifferentialResult {
            swar_output,
            scalar_output,
            parity_ok,
            mismatch,
        })
    }
}

fn find_mismatch(swar: &LexerOutput, scalar: &LexerOutput) -> Option<ParityMismatch> {
    // First check token counts
    if swar.token_count != scalar.token_count {
        let min_len = swar.tokens.len().min(scalar.tokens.len());
        // Find first divergence point
        for i in 0..min_len {
            if swar.tokens[i] != scalar.tokens[i] {
                return Some(ParityMismatch {
                    token_index: i as u64,
                    swar_token: Some(swar.tokens[i].clone()),
                    scalar_token: Some(scalar.tokens[i].clone()),
                    swar_count: swar.token_count,
                    scalar_count: scalar.token_count,
                });
            }
        }
        // Counts differ but tokens agree up to min_len — divergence at min_len
        return Some(ParityMismatch {
            token_index: min_len as u64,
            swar_token: swar.tokens.get(min_len).cloned(),
            scalar_token: scalar.tokens.get(min_len).cloned(),
            swar_count: swar.token_count,
            scalar_count: scalar.token_count,
        });
    }

    // Check individual tokens
    for (i, (s, r)) in swar.tokens.iter().zip(scalar.tokens.iter()).enumerate() {
        if s != r {
            return Some(ParityMismatch {
                token_index: i as u64,
                swar_token: Some(s.clone()),
                scalar_token: Some(r.clone()),
                swar_count: swar.token_count,
                scalar_count: scalar.token_count,
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Lex the input using the configured mode. Returns the lexer output or an error.
pub fn lex(input: &str, config: &LexerConfig) -> Result<LexerOutput, LexerError> {
    let bytes = input.as_bytes();
    match config.mode {
        LexerMode::Scalar => {
            let mut output = ScalarLexer::lex(bytes, config)?;
            output.swar_disable_reason = Some(SwarDisableReason::OperatorOverride);
            Ok(output)
        }
        LexerMode::Swar => SwarLexer::lex(bytes, config),
        LexerMode::Differential => {
            let diff = DifferentialLexer::lex(bytes, config)?;
            if diff.parity_ok {
                // Return SWAR result (it's the fast one)
                Ok(diff.swar_output)
            } else {
                // Parity failure — return scalar result with diagnostic
                let mismatch_index = diff.mismatch.as_ref().map(|m| m.token_index).unwrap_or(0);
                let mut output = diff.scalar_output;
                output.swar_disable_reason =
                    Some(SwarDisableReason::ParityMismatch { mismatch_index });
                Ok(output)
            }
        }
    }
}

/// Quick token count — does not emit individual tokens.
pub fn count_tokens(input: &str, config: &LexerConfig) -> Result<u64, LexerError> {
    let mut count_config = config.clone();
    count_config.emit_tokens = false;
    let output = lex(input, &count_config)?;
    Ok(output.token_count)
}

// ---------------------------------------------------------------------------
// Lexer artifact for reproducibility
// ---------------------------------------------------------------------------

/// Artifact bundle produced by the lexer for reproducibility and audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexerArtifact {
    /// Unique identifier for this artifact.
    pub artifact_id: EngineObjectId,
    /// Configuration used for the run.
    pub config: LexerConfig,
    /// Output from the lexer.
    pub output: LexerOutput,
    /// SHA-256 of the input source (for reproducibility without storing the source).
    pub input_hash: String,
    /// Input length in bytes.
    pub input_len: u64,
    /// Schema version.
    pub schema_version: LexerSchemaVersion,
}

/// Structured witness log for lexer fallback and token determinism auditing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexerTokenWitnessLog {
    /// Schema version.
    pub schema_version: LexerSchemaVersion,
    /// Stable trace identifier for correlation.
    pub trace_id: String,
    /// Stable decision identifier for policy decisions.
    pub decision_id: String,
    /// Policy identifier for the feature-gate policy applied.
    pub policy_id: String,
    /// Requested mode from the input config.
    pub requested_mode: LexerMode,
    /// Actual mode selected by fallback matrix.
    pub actual_mode: LexerMode,
    /// Feature-gate policy requested by the config.
    pub feature_gate: SwarFeatureGate,
    /// SWAR disable reason when fallback occurred.
    pub swar_disable_reason: Option<SwarDisableReason>,
    /// Architecture profile used for fallback decisions.
    pub arch_profile: ArchCapabilityProfile,
    /// SHA-256 hash of input bytes.
    pub input_hash: String,
    /// Total tokens produced.
    pub token_count: u64,
    /// Deterministic hash of token witness rows.
    pub token_witness_hash: String,
    /// One-command replay instruction.
    pub replay_command: String,
}

/// Build a structured token witness log from a lexer result.
pub fn build_token_witness_log(
    input: &str,
    config: &LexerConfig,
    output: &LexerOutput,
    trace_id: &str,
    decision_id: &str,
    policy_id: &str,
    replay_command: &str,
) -> LexerTokenWitnessLog {
    LexerTokenWitnessLog {
        schema_version: LexerSchemaVersion::V1,
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: policy_id.to_string(),
        requested_mode: config.mode,
        actual_mode: output.actual_mode,
        feature_gate: config.feature_gate,
        swar_disable_reason: output.swar_disable_reason.clone(),
        arch_profile: ArchCapabilityProfile::detect(),
        input_hash: sha256_prefixed(input.as_bytes()),
        token_count: output.token_count,
        token_witness_hash: compute_token_witness_hash(&output.tokens, output.token_count),
        replay_command: replay_command.to_string(),
    }
}

/// Architecture capability profile for SWAR support decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchCapabilityProfile {
    /// Architecture family.
    pub arch_family: ArchFamily,
    /// SWAR width in bytes (always 8 for u64-based SWAR).
    pub swar_width: u32,
    /// Target pointer width in bits (32 or 64).
    pub pointer_width: u32,
    /// Whether the target is little-endian (required for our SWAR read).
    pub little_endian: bool,
    /// Whether SWAR path is available (true on all targets with 64-bit u64).
    pub swar_available: bool,
    /// Whether AVX2 is available on the current machine (x86_64 only).
    pub avx2_available: bool,
    /// Whether AVX512F is available on the current machine (x86_64 only).
    pub avx512f_available: bool,
    /// Whether NEON is available on the current machine (ARM/AArch64 only).
    pub neon_available: bool,
}

impl ArchCapabilityProfile {
    /// Detect the current architecture's SWAR capability.
    pub fn detect() -> Self {
        let arch_family = if cfg!(target_arch = "x86_64") {
            ArchFamily::X86_64
        } else if cfg!(target_arch = "aarch64") {
            ArchFamily::Aarch64
        } else if cfg!(target_arch = "arm") {
            ArchFamily::Arm
        } else {
            ArchFamily::Other
        };
        let avx2_available = {
            #[cfg(target_arch = "x86_64")]
            {
                std::arch::is_x86_feature_detected!("avx2")
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                false
            }
        };
        let avx512f_available = {
            #[cfg(target_arch = "x86_64")]
            {
                std::arch::is_x86_feature_detected!("avx512f")
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                false
            }
        };
        let neon_available = {
            #[cfg(target_arch = "aarch64")]
            {
                std::arch::is_aarch64_feature_detected!("neon")
            }
            #[cfg(target_arch = "arm")]
            {
                cfg!(target_feature = "neon")
            }
            #[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
            {
                false
            }
        };
        Self {
            arch_family,
            swar_width: 8,
            pointer_width: if cfg!(target_pointer_width = "64") {
                64
            } else {
                32
            },
            little_endian: cfg!(target_endian = "little"),
            swar_available: true, // u64 SWAR works on all targets
            avx2_available,
            avx512f_available,
            neon_available,
        }
    }

    /// Whether the architecture supports the SWAR fast path.
    pub fn supports_swar(&self) -> bool {
        self.swar_available && self.little_endian
    }

    /// Whether this profile satisfies a feature-gate requirement.
    pub fn supports_feature_gate(&self, gate: SwarFeatureGate) -> bool {
        if !self.supports_swar() {
            return false;
        }
        match gate {
            SwarFeatureGate::Portable => true,
            SwarFeatureGate::RequireAvx2 => {
                self.arch_family == ArchFamily::X86_64 && self.avx2_available
            }
            SwarFeatureGate::RequireAvx512F => {
                self.arch_family == ArchFamily::X86_64 && self.avx512f_available
            }
            SwarFeatureGate::RequireNeon => {
                matches!(self.arch_family, ArchFamily::Aarch64 | ArchFamily::Arm)
                    && self.neon_available
            }
        }
    }
}

/// Deterministic scalar-fallback matrix for SWAR mode.
pub fn evaluate_swar_fallback_matrix(
    input_len: u64,
    config: &LexerConfig,
    profile: &ArchCapabilityProfile,
) -> Option<SwarDisableReason> {
    if !profile.supports_swar() {
        return Some(SwarDisableReason::ArchitectureUnsupported {
            pointer_width: profile.pointer_width,
            little_endian: profile.little_endian,
        });
    }
    if !profile.supports_feature_gate(config.feature_gate) {
        return Some(SwarDisableReason::FeatureGateUnavailable {
            required: config.feature_gate,
            arch_family: profile.arch_family,
        });
    }
    if input_len < config.swar_min_input_bytes {
        return Some(SwarDisableReason::InputBelowThreshold {
            input_len,
            threshold: config.swar_min_input_bytes,
        });
    }
    None
}

// ---------------------------------------------------------------------------
// Throughput measurement
// ---------------------------------------------------------------------------

/// Throughput measurement for a lexer run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputSample {
    /// Lexer mode used.
    pub mode: LexerMode,
    /// Input size in bytes.
    pub input_bytes: u64,
    /// Tokens produced.
    pub token_count: u64,
    /// Wall time in nanoseconds.
    pub wall_time_ns: u64,
    /// Bytes per second (millionths for fixed-point).
    pub bytes_per_second_millionths: u64,
    /// Tokens per second (millionths for fixed-point).
    pub tokens_per_second_millionths: u64,
}

impl ThroughputSample {
    /// Compute throughput from raw measurements.
    pub fn compute(mode: LexerMode, input_bytes: u64, token_count: u64, wall_time_ns: u64) -> Self {
        let bytes_per_sec = if wall_time_ns > 0 {
            input_bytes
                .saturating_mul(1_000_000_000)
                .saturating_mul(1_000_000)
                .checked_div(wall_time_ns)
                .unwrap_or(0)
        } else {
            0
        };
        let tokens_per_sec = if wall_time_ns > 0 {
            token_count
                .saturating_mul(1_000_000_000)
                .saturating_mul(1_000_000)
                .checked_div(wall_time_ns)
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            mode,
            input_bytes,
            token_count,
            wall_time_ns,
            bytes_per_second_millionths: bytes_per_sec,
            tokens_per_second_millionths: tokens_per_sec,
        }
    }
}

/// Comparison between SWAR and scalar throughput.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputComparison {
    pub swar: ThroughputSample,
    pub scalar: ThroughputSample,
    /// Speedup ratio in millionths (e.g. 3_000_000 = 3x faster).
    /// Values > 1_000_000 mean SWAR is faster.
    pub speedup_millionths: u64,
}

impl ThroughputComparison {
    pub fn compute(swar: ThroughputSample, scalar: ThroughputSample) -> Self {
        let speedup = if scalar.bytes_per_second_millionths > 0 {
            swar.bytes_per_second_millionths
                .saturating_mul(1_000_000)
                .checked_div(scalar.bytes_per_second_millionths)
                .unwrap_or(0)
        } else {
            0
        };
        Self {
            swar,
            scalar,
            speedup_millionths: speedup,
        }
    }
}

// ---------------------------------------------------------------------------
// Rollback gate
// ---------------------------------------------------------------------------

/// Configuration for the SWAR rollback gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackGateConfig {
    /// Maximum allowed parity mismatches before SWAR is disabled.
    pub max_parity_mismatches: u64,
    /// Minimum speedup (millionths) required to keep SWAR enabled.
    pub min_speedup_millionths: u64,
    /// Maximum p99 tail latency regression (millionths) allowed.
    pub max_p99_regression_millionths: u64,
}

impl Default for RollbackGateConfig {
    fn default() -> Self {
        Self {
            max_parity_mismatches: 0,
            min_speedup_millionths: 1_000_000, // At least 1x (no regression)
            max_p99_regression_millionths: 500_000, // 50% max regression on p99
        }
    }
}

/// Result of the rollback gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackGateResult {
    /// Whether SWAR should remain enabled.
    pub swar_approved: bool,
    /// Parity mismatches observed.
    pub parity_mismatches: u64,
    /// Speedup ratio observed (millionths).
    pub observed_speedup_millionths: u64,
    /// Reasons for disabling SWAR (empty if approved).
    pub disable_reasons: Vec<String>,
}

/// Evaluate whether SWAR should remain enabled based on observed behavior.
pub fn evaluate_rollback_gate(
    parity_mismatches: u64,
    speedup_millionths: u64,
    p99_regression_millionths: u64,
    config: &RollbackGateConfig,
) -> RollbackGateResult {
    let mut reasons = Vec::new();

    if parity_mismatches > config.max_parity_mismatches {
        reasons.push(format!(
            "parity mismatches {} > max {}",
            parity_mismatches, config.max_parity_mismatches
        ));
    }

    if speedup_millionths < config.min_speedup_millionths {
        reasons.push(format!(
            "speedup {} < min {}",
            speedup_millionths, config.min_speedup_millionths
        ));
    }

    if p99_regression_millionths > config.max_p99_regression_millionths {
        reasons.push(format!(
            "p99 regression {} > max {}",
            p99_regression_millionths, config.max_p99_regression_millionths
        ));
    }

    RollbackGateResult {
        swar_approved: reasons.is_empty(),
        parity_mismatches,
        observed_speedup_millionths: speedup_millionths,
        disable_reasons: reasons,
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn token_kind_tag(kind: TokenKind) -> u8 {
    match kind {
        TokenKind::Identifier => 0,
        TokenKind::NumericLiteral => 1,
        TokenKind::StringLiteral => 2,
        TokenKind::UnterminatedString => 3,
        TokenKind::TwoCharOperator => 4,
        TokenKind::Punctuation => 5,
    }
}

fn compute_token_witness_hash(tokens: &[Token], token_count: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"franken-engine.simd-lexer.token-witness.v1");
    hasher.update(token_count.to_le_bytes());
    for token in tokens {
        hasher.update([token_kind_tag(token.kind)]);
        hasher.update(token.start.to_le_bytes());
        hasher.update(token.end.to_le_bytes());
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[inline]
fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_' || byte == b'$'
}

#[inline]
fn is_ident_continue(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'$'
}

#[inline]
fn is_two_char_operator(a: u8, b: u8) -> bool {
    matches!(
        (a, b),
        (b'=', b'=')
            | (b'!', b'=')
            | (b'<', b'=')
            | (b'>', b'=')
            | (b'&', b'&')
            | (b'|', b'|')
            | (b'?', b'?')
            | (b'=', b'>')
    )
}

/// Check if all 8 bytes in a word are ASCII whitespace.
#[cfg(test)]
#[inline]
#[cfg(test)]
fn is_all_whitespace_word(word: u64) -> bool {
    whitespace_mask(word) == SWAR_HIGH_BITS
}

/// Check if all 8 bytes in a word are identifier continuation characters.
#[cfg(test)]
#[inline]
#[cfg(test)]
fn is_all_ident_continue_word(word: u64) -> bool {
    identifier_continue_mask(word) == SWAR_HIGH_BITS
}

/// Check if all 8 bytes in a word are ASCII digits.
#[cfg(test)]
#[inline]
#[cfg(test)]
fn is_all_digit_word(word: u64) -> bool {
    digit_mask(word) == SWAR_HIGH_BITS
}

/// Read 8 bytes from `input[offset..]` as a little-endian u64.
/// If fewer than 8 bytes remain, pad with zeros.
#[inline]
fn read_u64_le(input: &[u8], offset: usize) -> u64 {
    let remaining = input.len().saturating_sub(offset);
    if remaining >= 8 {
        let slice = &input[offset..offset + 8];
        u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    } else {
        let mut buf = [0u8; 8];
        let copy_len = remaining.min(8);
        buf[..copy_len].copy_from_slice(&input[offset..offset + copy_len]);
        u64::from_le_bytes(buf)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> LexerConfig {
        LexerConfig::default()
    }

    fn scalar_config() -> LexerConfig {
        LexerConfig {
            mode: LexerMode::Scalar,
            ..Default::default()
        }
    }

    #[allow(dead_code)]
    fn diff_config() -> LexerConfig {
        LexerConfig {
            mode: LexerMode::Differential,
            ..Default::default()
        }
    }

    fn profile_for_tests(
        arch_family: ArchFamily,
        little_endian: bool,
        avx2_available: bool,
        avx512f_available: bool,
        neon_available: bool,
    ) -> ArchCapabilityProfile {
        ArchCapabilityProfile {
            arch_family,
            swar_width: 8,
            pointer_width: 64,
            little_endian,
            swar_available: true,
            avx2_available,
            avx512f_available,
            neon_available,
        }
    }

    #[test]
    fn token_span_storage_preserves_column_alignment() {
        let mut storage = TokenSpanStorage::with_capacity(3);
        storage.push(TokenKind::Identifier, 0, 3);
        storage.push(TokenKind::Punctuation, 4, 5);
        storage.push(TokenKind::NumericLiteral, 6, 9);

        assert_eq!(storage.len(), 3);
        assert_eq!(
            storage.token_kinds(),
            &[
                TokenKind::Identifier,
                TokenKind::Punctuation,
                TokenKind::NumericLiteral
            ]
        );
        assert_eq!(storage.starts(), &[0, 4, 6]);
        assert_eq!(storage.ends(), &[3, 5, 9]);
    }

    #[test]
    fn token_span_storage_roundtrips_tokens() {
        let tokens = vec![
            Token {
                kind: TokenKind::Identifier,
                start: 0,
                end: 4,
            },
            Token {
                kind: TokenKind::TwoCharOperator,
                start: 5,
                end: 7,
            },
            Token {
                kind: TokenKind::Identifier,
                start: 8,
                end: 9,
            },
        ];

        let storage = TokenSpanStorage::from_tokens(&tokens);
        assert_eq!(storage.to_tokens(), tokens);
        assert_eq!(storage.clone().into_tokens(), tokens);
    }

    // --- SWAR primitives ---

    #[test]
    fn broadcast_fills_all_bytes() {
        let val = broadcast(0x42);
        assert_eq!(val, 0x4242_4242_4242_4242);
    }

    #[test]
    fn byte_eq_mask_matches_target() {
        let word = u64::from_le_bytes([b'a', b'b', b'a', b'c', b'a', b'd', b'a', b'e']);
        let mask = byte_eq_mask(word, b'a');
        // Bytes 0, 2, 4, 6 should match (high bit set)
        assert_eq!(mask_popcount(mask), 4);
        assert_eq!(mask_first_set(mask), 0);
    }

    #[test]
    fn byte_eq_mask_no_match() {
        let word = u64::from_le_bytes([b'x', b'y', b'z', b'w', b'v', b'u', b't', b's']);
        let mask = byte_eq_mask(word, b'a');
        assert_eq!(mask_popcount(mask), 0);
        assert_eq!(mask_first_set(mask), 8);
    }

    #[test]
    fn whitespace_mask_detects_all_ws_types() {
        let word = u64::from_le_bytes([b' ', b'\t', b'\n', b'\r', 0x0B, 0x0C, b' ', b'\t']);
        let mask = whitespace_mask(word);
        assert_eq!(mask_popcount(mask), 8);
    }

    #[test]
    fn whitespace_mask_rejects_non_ws() {
        let word = u64::from_le_bytes([b'a', b'b', b'c', b'd', b'1', b'2', b'3', b'4']);
        let mask = whitespace_mask(word);
        assert_eq!(mask_popcount(mask), 0);
    }

    #[test]
    fn digit_mask_detects_digits() {
        let word = u64::from_le_bytes([b'0', b'5', b'9', b'a', b'z', b' ', b'1', b'8']);
        let mask = digit_mask(word);
        // Positions 0,1,2,6,7 are digits
        assert_eq!(mask_popcount(mask), 5);
    }

    #[test]
    fn alpha_mask_detects_letters() {
        let word = u64::from_le_bytes([b'a', b'Z', b'0', b'_', b'M', b'q', b' ', b'\n']);
        let mask = alpha_mask(word);
        // a, Z, M, q are alpha
        assert_eq!(mask_popcount(mask), 4);
    }

    #[test]
    fn identifier_continue_mask_includes_dollar_underscore() {
        let word = u64::from_le_bytes([b'$', b'_', b'a', b'Z', b'0', b' ', b'!', b'@']);
        let mask = identifier_continue_mask(word);
        // $, _, a, Z, 0 are ident continues; ' ', '!', '@' are not
        assert_eq!(mask_popcount(mask), 5);
    }

    #[test]
    fn identifier_continue_mask_includes_digits() {
        let word = u64::from_le_bytes([b'$', b'_', b'a', b'Z', b'0', b'9', b' ', b'!']);
        let mask = identifier_continue_mask(word);
        // $, _, a, Z, 0, 9 are ident continues
        assert_eq!(mask_popcount(mask), 6);
    }

    #[test]
    fn mask_first_set_finds_correct_byte() {
        // High bit set in byte 2 (0-indexed)
        let mask = 0x0000_0000_0080_0000_u64;
        assert_eq!(mask_first_set(mask), 2);
    }

    #[test]
    fn match_prefix_len_counts_leading_matches() {
        for expected in 0..=8 {
            let mut mask = 0u64;
            for byte_index in 0..expected {
                mask |= 0x80_u64 << (byte_index * 8);
            }
            assert_eq!(match_prefix_len(mask), expected);
        }

        // Non-prefix match bits should not increase the prefix length.
        let sparse = 0x80_u64 | (0x80_u64 << 16) | (0x80_u64 << 56);
        assert_eq!(match_prefix_len(sparse), 1);
    }

    #[test]
    fn swar_all_word_predicates_match_scalar_reference() {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        for _ in 0..20_000 {
            // Deterministic xorshift64* stream.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D_u64);
            let bytes = word.to_le_bytes();

            let scalar_ws = bytes.iter().all(|b| b.is_ascii_whitespace());
            let scalar_ident = bytes.iter().all(|b| is_ident_continue(*b));
            let scalar_digit = bytes.iter().all(|b| b.is_ascii_digit());

            assert_eq!(is_all_whitespace_word(word), scalar_ws);
            assert_eq!(is_all_ident_continue_word(word), scalar_ident);
            assert_eq!(is_all_digit_word(word), scalar_digit);
        }
    }

    // --- Scalar lexer ---

    #[test]
    fn scalar_empty_input() {
        let result = ScalarLexer::lex(b"", &default_config()).unwrap();
        assert_eq!(result.token_count, 0);
        assert!(result.tokens.is_empty());
    }

    #[test]
    fn scalar_whitespace_only() {
        let result = ScalarLexer::lex(b"   \t\n\r  ", &default_config()).unwrap();
        assert_eq!(result.token_count, 0);
    }

    #[test]
    fn scalar_single_identifier() {
        let result = ScalarLexer::lex(b"hello", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[0].start, 0);
        assert_eq!(result.tokens[0].end, 5);
    }

    #[test]
    fn scalar_dollar_identifier() {
        let result = ScalarLexer::lex(b"$foo_bar123", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
    }

    #[test]
    fn scalar_numeric_literal() {
        let result = ScalarLexer::lex(b"42", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::NumericLiteral);
    }

    #[test]
    fn scalar_string_literal_double_quote() {
        let result = ScalarLexer::lex(b"\"hello world\"", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn scalar_string_literal_single_quote() {
        let result = ScalarLexer::lex(b"'hello'", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn scalar_string_with_escape() {
        let result = ScalarLexer::lex(b"\"he\\\"llo\"", &default_config()).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn scalar_unterminated_string() {
        let result = ScalarLexer::lex(b"\"hello\nworld\"", &default_config()).unwrap();
        // The first string is unterminated at newline, then 'world' is ident, then '"' is punct
        assert_eq!(result.tokens[0].kind, TokenKind::UnterminatedString);
    }

    #[test]
    fn scalar_two_char_operators() {
        let input = b"== != <= >= && || ?? =>";
        let result = ScalarLexer::lex(input, &default_config()).unwrap();
        assert_eq!(result.token_count, 8);
        for tok in &result.tokens {
            assert_eq!(tok.kind, TokenKind::TwoCharOperator);
        }
    }

    #[test]
    fn scalar_punctuation() {
        let result = ScalarLexer::lex(b"+ - * / ( )", &default_config()).unwrap();
        assert_eq!(result.token_count, 6);
        for tok in &result.tokens {
            assert_eq!(tok.kind, TokenKind::Punctuation);
        }
    }

    #[test]
    fn scalar_mixed_expression() {
        let input = b"foo + bar * 123";
        let result = ScalarLexer::lex(input, &default_config()).unwrap();
        assert_eq!(result.token_count, 5);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[1].kind, TokenKind::Punctuation); // +
        assert_eq!(result.tokens[2].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[3].kind, TokenKind::Punctuation); // *
        assert_eq!(result.tokens[4].kind, TokenKind::NumericLiteral);
    }

    #[test]
    fn scalar_token_budget_exceeded() {
        let config = LexerConfig {
            max_tokens: 3,
            ..default_config()
        };
        let result = ScalarLexer::lex(b"a b c d e", &config).unwrap();
        assert!(result.budget_exceeded);
        assert_eq!(result.token_count, 3);
    }

    #[test]
    fn scalar_source_too_large() {
        let config = LexerConfig {
            max_source_bytes: 5,
            ..default_config()
        };
        let err = ScalarLexer::lex(b"hello world", &config).unwrap_err();
        assert!(matches!(err, LexerError::SourceTooLarge { .. }));
    }

    // --- SWAR lexer ---

    #[test]
    fn swar_falls_back_on_small_input() {
        let config = LexerConfig {
            swar_min_input_bytes: 64,
            ..default_config()
        };
        let result = SwarLexer::lex(b"hello", &config).unwrap();
        assert!(result.swar_disable_reason.is_some());
        assert!(matches!(
            result.swar_disable_reason,
            Some(SwarDisableReason::InputBelowThreshold { .. })
        ));
    }

    #[test]
    fn swar_processes_large_whitespace_block() {
        let input = " ".repeat(256) + "hello";
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.actual_mode, LexerMode::Swar);
    }

    #[test]
    fn swar_long_identifier() {
        let input = "a".repeat(200);
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::Identifier);
        assert_eq!(result.tokens[0].start, 0);
        assert_eq!(result.tokens[0].end, 200);
    }

    #[test]
    fn swar_long_number() {
        let input = "1".repeat(200);
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::NumericLiteral);
    }

    #[test]
    fn swar_long_string() {
        let input = format!("\"{}\"", "x".repeat(200));
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 1);
        assert_eq!(result.tokens[0].kind, TokenKind::StringLiteral);
    }

    #[test]
    fn swar_mixed_tokens_large_input() {
        // Build an input > 64 bytes with mixed token types
        let input = "function foo(x, y) { return x + y * 123; } var bar = \"hello world\"; if (a == b && c != d) { console.log(42); }";
        let config = LexerConfig {
            swar_min_input_bytes: 8,
            ..default_config()
        };
        let swar_result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        let scalar_result = ScalarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(swar_result.token_count, scalar_result.token_count);
    }

    // --- Differential lexer ---

    #[test]
    fn differential_parity_on_simple_input() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = "var x = 42; function foo() { return x + 1; }";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert!(result.mismatch.is_none());
    }

    #[test]
    fn differential_parity_on_operators() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = "a == b && c != d || e <= f >= g ?? h => i";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(
            result.swar_output.token_count,
            result.scalar_output.token_count
        );
    }

    #[test]
    fn differential_parity_on_strings_with_escapes() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = r#"var s = "hello \"world\""; var t = 'it\'s';"#;
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    #[test]
    fn differential_parity_on_large_whitespace() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = format!(
            "{}a{}b{}c",
            " ".repeat(100),
            "\t".repeat(50),
            "\n".repeat(30)
        );
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(result.swar_output.token_count, 3);
    }

    #[test]
    fn differential_parity_on_unterminated_strings() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = "\"hello\nworld\"";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    #[test]
    fn differential_parity_on_empty() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let result = DifferentialLexer::lex(b"", &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(result.swar_output.token_count, 0);
    }

    #[test]
    fn differential_parity_on_long_identifiers() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = format!(
            "{} + {} + {}",
            "a".repeat(100),
            "b".repeat(100),
            "c".repeat(100)
        );
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
        assert_eq!(result.swar_output.token_count, 5); // 3 idents + 2 punctuation
    }

    #[test]
    fn differential_parity_on_adversarial_unicode() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        // Multi-byte UTF-8 treated as individual non-ASCII bytes
        let input = "var x = \u{00e9}\u{00f1}\u{00fc};";
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    // --- Public API ---

    #[test]
    fn lex_with_scalar_mode() {
        let output = lex("hello world", &scalar_config()).unwrap();
        assert_eq!(output.token_count, 2);
        assert_eq!(output.actual_mode, LexerMode::Scalar);
        assert_eq!(
            output.swar_disable_reason,
            Some(SwarDisableReason::OperatorOverride)
        );
    }

    #[test]
    fn lex_with_swar_mode() {
        let config = LexerConfig {
            mode: LexerMode::Swar,
            swar_min_input_bytes: 0,
            ..Default::default()
        };
        let output = lex("hello world", &config).unwrap();
        assert_eq!(output.token_count, 2);
        assert_eq!(output.actual_mode, LexerMode::Swar);
    }

    #[test]
    fn lex_differential_returns_swar_on_parity() {
        let output = lex(
            "var x = 42;",
            &LexerConfig {
                mode: LexerMode::Differential,
                swar_min_input_bytes: 0,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(output.actual_mode, LexerMode::Swar);
    }

    #[test]
    fn count_tokens_matches_scalar() {
        let input = "var x = foo(1, 2, 3); if (a == b) { return; }";
        let count = count_tokens(input, &scalar_config()).unwrap();
        let output = lex(input, &scalar_config()).unwrap();
        assert_eq!(count, output.token_count);
    }

    // --- Architecture ---

    #[test]
    fn arch_profile_detects_swar_support() {
        let profile = ArchCapabilityProfile::detect();
        assert_eq!(profile.swar_width, 8);
        assert!(profile.swar_available);
        assert_eq!(
            profile.supports_feature_gate(SwarFeatureGate::Portable),
            profile.supports_swar()
        );
    }

    #[test]
    fn fallback_matrix_rejects_unsupported_architecture() {
        let profile = profile_for_tests(ArchFamily::Other, false, false, false, false);
        let config = LexerConfig::default();
        let reason = evaluate_swar_fallback_matrix(4096, &config, &profile).unwrap();
        assert_eq!(
            reason,
            SwarDisableReason::ArchitectureUnsupported {
                pointer_width: 64,
                little_endian: false
            }
        );
    }

    #[test]
    fn fallback_matrix_rejects_missing_feature_gate() {
        let profile = profile_for_tests(ArchFamily::X86_64, true, false, false, false);
        let config = LexerConfig {
            feature_gate: SwarFeatureGate::RequireAvx2,
            ..LexerConfig::default()
        };
        let reason = evaluate_swar_fallback_matrix(4096, &config, &profile).unwrap();
        assert_eq!(
            reason,
            SwarDisableReason::FeatureGateUnavailable {
                required: SwarFeatureGate::RequireAvx2,
                arch_family: ArchFamily::X86_64
            }
        );
    }

    #[test]
    fn fallback_matrix_accepts_matching_feature_gate() {
        let profile = profile_for_tests(ArchFamily::Aarch64, true, false, false, true);
        let config = LexerConfig {
            feature_gate: SwarFeatureGate::RequireNeon,
            swar_min_input_bytes: 64,
            ..LexerConfig::default()
        };
        let reason = evaluate_swar_fallback_matrix(4096, &config, &profile);
        assert!(reason.is_none());
    }

    // --- Throughput ---

    #[test]
    fn throughput_sample_computes_correctly() {
        let sample = ThroughputSample::compute(LexerMode::Swar, 1000, 50, 1_000_000);
        // 1000 bytes in 1ms = 1_000_000_000 bytes/sec → * 1_000_000 for fixed-point
        assert!(sample.bytes_per_second_millionths > 0);
        assert!(sample.tokens_per_second_millionths > 0);
    }

    #[test]
    fn throughput_sample_zero_time() {
        let sample = ThroughputSample::compute(LexerMode::Scalar, 1000, 50, 0);
        assert_eq!(sample.bytes_per_second_millionths, 0);
        assert_eq!(sample.tokens_per_second_millionths, 0);
    }

    #[test]
    fn throughput_comparison_speedup() {
        let swar = ThroughputSample {
            mode: LexerMode::Swar,
            input_bytes: 1000,
            token_count: 50,
            wall_time_ns: 100_000,
            bytes_per_second_millionths: 10_000_000_000,
            tokens_per_second_millionths: 500_000_000,
        };
        let scalar = ThroughputSample {
            mode: LexerMode::Scalar,
            input_bytes: 1000,
            token_count: 50,
            wall_time_ns: 300_000,
            bytes_per_second_millionths: 3_333_333_333,
            tokens_per_second_millionths: 166_666_666,
        };
        let comparison = ThroughputComparison::compute(swar, scalar);
        // 10B / 3.33B ≈ 3x
        assert!(comparison.speedup_millionths > 2_000_000);
    }

    // --- Rollback gate ---

    #[test]
    fn rollback_gate_approves_clean_run() {
        let result = evaluate_rollback_gate(0, 2_000_000, 0, &RollbackGateConfig::default());
        assert!(result.swar_approved);
        assert!(result.disable_reasons.is_empty());
    }

    #[test]
    fn rollback_gate_rejects_parity_mismatch() {
        let result = evaluate_rollback_gate(1, 2_000_000, 0, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
        assert_eq!(result.disable_reasons.len(), 1);
    }

    #[test]
    fn rollback_gate_rejects_low_speedup() {
        let result = evaluate_rollback_gate(0, 500_000, 0, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
    }

    #[test]
    fn rollback_gate_rejects_p99_regression() {
        let result = evaluate_rollback_gate(0, 2_000_000, 600_000, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
    }

    #[test]
    fn rollback_gate_multiple_failures() {
        let result = evaluate_rollback_gate(5, 100_000, 900_000, &RollbackGateConfig::default());
        assert!(!result.swar_approved);
        assert_eq!(result.disable_reasons.len(), 3);
    }

    // --- Serde ---

    #[test]
    fn token_kind_serde_round_trip() {
        let kinds = vec![
            TokenKind::Identifier,
            TokenKind::NumericLiteral,
            TokenKind::StringLiteral,
            TokenKind::UnterminatedString,
            TokenKind::TwoCharOperator,
            TokenKind::Punctuation,
        ];
        let json = serde_json::to_string(&kinds).unwrap();
        let back: Vec<TokenKind> = serde_json::from_str(&json).unwrap();
        assert_eq!(kinds, back);
    }

    #[test]
    fn lexer_output_serde_round_trip() {
        let output = lex("var x = 42;", &scalar_config()).unwrap();
        let json = serde_json::to_string(&output).unwrap();
        let back: LexerOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(output, back);
    }

    #[test]
    fn lexer_config_serde_round_trip() {
        let config = LexerConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: LexerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn differential_result_serde_round_trip() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let result = DifferentialLexer::lex(b"a + b", &config).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: DifferentialResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    // --- Display ---

    #[test]
    fn token_kind_display() {
        assert_eq!(TokenKind::Identifier.to_string(), "Identifier");
        assert_eq!(TokenKind::NumericLiteral.to_string(), "NumericLiteral");
        assert_eq!(TokenKind::StringLiteral.to_string(), "StringLiteral");
        assert_eq!(
            TokenKind::UnterminatedString.to_string(),
            "UnterminatedString"
        );
        assert_eq!(TokenKind::TwoCharOperator.to_string(), "TwoCharOperator");
        assert_eq!(TokenKind::Punctuation.to_string(), "Punctuation");
    }

    #[test]
    fn lexer_mode_display() {
        assert_eq!(LexerMode::Swar.to_string(), "SWAR");
        assert_eq!(LexerMode::Scalar.to_string(), "Scalar");
        assert_eq!(LexerMode::Differential.to_string(), "Differential");
    }

    #[test]
    fn swar_feature_gate_display() {
        assert_eq!(SwarFeatureGate::Portable.to_string(), "portable");
        assert_eq!(SwarFeatureGate::RequireAvx2.to_string(), "require_avx2");
        assert_eq!(
            SwarFeatureGate::RequireAvx512F.to_string(),
            "require_avx512f"
        );
        assert_eq!(SwarFeatureGate::RequireNeon.to_string(), "require_neon");
    }

    #[test]
    fn swar_disable_reason_display() {
        assert_eq!(
            SwarDisableReason::OperatorOverride.to_string(),
            "operator_override"
        );
        assert_eq!(
            SwarDisableReason::ParityMismatch { mismatch_index: 42 }.to_string(),
            "parity_mismatch(index=42)"
        );
        assert_eq!(
            SwarDisableReason::InputBelowThreshold {
                input_len: 10,
                threshold: 64
            }
            .to_string(),
            "input_below_threshold(len=10, threshold=64)"
        );
        assert_eq!(
            SwarDisableReason::ArchitectureUnsupported {
                pointer_width: 64,
                little_endian: true
            }
            .to_string(),
            "architecture_unsupported(pointer_width=64, little_endian=true)"
        );
        assert_eq!(
            SwarDisableReason::FeatureGateUnavailable {
                required: SwarFeatureGate::RequireAvx2,
                arch_family: ArchFamily::X86_64
            }
            .to_string(),
            "feature_gate_unavailable(required=require_avx2, arch=x86_64)"
        );
        assert_eq!(
            SwarDisableReason::TokenBudgetExceeded.to_string(),
            "token_budget_exceeded"
        );
    }

    #[test]
    fn lexer_error_display() {
        assert_eq!(
            LexerError::SourceTooLarge {
                size: 200,
                max: 100
            }
            .to_string(),
            "source too large: 200 bytes (max 100)"
        );
        assert_eq!(
            LexerError::TokenBudgetExceeded {
                count: 500,
                max: 100
            }
            .to_string(),
            "token budget exceeded: 500 tokens (max 100)"
        );
    }

    // --- Determinism ---

    #[test]
    fn scalar_output_is_deterministic() {
        let input = "var x = foo(1, 2, 3); if (a == b) { return 'hello'; }";
        let out1 = lex(input, &scalar_config()).unwrap();
        let out2 = lex(input, &scalar_config()).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn swar_output_is_deterministic() {
        let config = LexerConfig {
            mode: LexerMode::Swar,
            swar_min_input_bytes: 0,
            ..Default::default()
        };
        let input = "var x = foo(1, 2, 3); if (a == b) { return 'hello'; }";
        let out1 = lex(input, &config).unwrap();
        let out2 = lex(input, &config).unwrap();
        assert_eq!(out1, out2);
    }

    #[test]
    fn token_witness_log_is_deterministic() {
        let input = "let total = value + 42;";
        let config = LexerConfig {
            mode: LexerMode::Swar,
            swar_min_input_bytes: 0,
            ..Default::default()
        };
        let output = lex(input, &config).unwrap();
        let replay = "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact token_witness_log_contains_replay_command";
        let log1 = build_token_witness_log(
            input,
            &config,
            &output,
            "trace-simd-lexer-feature-gate",
            "decision-simd-lexer-feature-gate",
            "policy-simd-lexer-feature-gate-v1",
            replay,
        );
        let log2 = build_token_witness_log(
            input,
            &config,
            &output,
            "trace-simd-lexer-feature-gate",
            "decision-simd-lexer-feature-gate",
            "policy-simd-lexer-feature-gate-v1",
            replay,
        );
        assert_eq!(log1, log2);
        assert!(log1.input_hash.starts_with("sha256:"));
        assert!(log1.token_witness_hash.starts_with("sha256:"));
        assert_eq!(log1.actual_mode, output.actual_mode);
        assert_eq!(log1.token_count, output.token_count);
    }

    // --- Token span properties ---

    #[test]
    fn token_span_len() {
        let token = Token {
            kind: TokenKind::Identifier,
            start: 5,
            end: 10,
        };
        assert_eq!(token.span_len(), 5);
    }

    #[test]
    fn token_source_span() {
        let token = Token {
            kind: TokenKind::Identifier,
            start: 5,
            end: 10,
        };
        let span = token.source_span(1, 5);
        assert_eq!(span.start_offset, 5);
        assert_eq!(span.end_offset, 10);
        assert_eq!(span.start_line, 1);
        assert_eq!(span.end_line, 1);
    }

    // --- Parity mismatch display ---

    #[test]
    fn parity_mismatch_display() {
        let m = ParityMismatch {
            token_index: 3,
            swar_token: None,
            scalar_token: None,
            swar_count: 10,
            scalar_count: 11,
        };
        assert_eq!(
            m.to_string(),
            "parity mismatch at token 3: swar_count=10, scalar_count=11"
        );
    }

    // --- Stress: long mixed input ---

    #[test]
    fn differential_parity_stress_long_mixed() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            max_tokens: 100_000,
            ..default_config()
        };
        // Build a long input with diverse tokens
        let mut input = String::new();
        for i in 0u64..200 {
            input.push_str(&format!("var x{} = {}; ", i, i));
            if i % 5 == 0 {
                input.push_str(&format!("\"string{}\" ", i));
            }
            if i % 7 == 0 {
                input.push_str("== != && || ");
            }
        }
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok, "parity mismatch: {:?}", result.mismatch);
    }

    // --- Stress: only whitespace ---

    #[test]
    fn swar_all_whitespace_large() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            ..default_config()
        };
        let input = " ".repeat(1024);
        let result = SwarLexer::lex(input.as_bytes(), &config).unwrap();
        assert_eq!(result.token_count, 0);
        assert_eq!(result.bytes_scanned, 1024);
    }

    // --- Stress: dense punctuation ---

    #[test]
    fn differential_parity_dense_punctuation() {
        let config = LexerConfig {
            swar_min_input_bytes: 0,
            max_tokens: 100_000,
            ..default_config()
        };
        let input = "+-*/(){}[];,.:<>!@#%^~".repeat(20);
        let result = DifferentialLexer::lex(input.as_bytes(), &config).unwrap();
        assert!(result.parity_ok);
    }

    // --- Artifact ---

    #[test]
    fn lexer_artifact_serde_round_trip() {
        let output = lex("x + y", &scalar_config()).unwrap();
        let artifact = LexerArtifact {
            artifact_id: crate::engine_object_id::derive_id(
                crate::engine_object_id::ObjectDomain::EvidenceRecord,
                "simd-lexer-test",
                &crate::engine_object_id::SchemaId::from_definition(b"test-artifact"),
                b"test-artifact",
            )
            .unwrap(),
            config: scalar_config(),
            output,
            input_hash: "abc123".to_string(),
            input_len: 5,
            schema_version: LexerSchemaVersion::V1,
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let back: LexerArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, back);
    }

    #[test]
    fn token_kind_ord() {
        assert!(TokenKind::Identifier < TokenKind::NumericLiteral);
        assert!(TokenKind::NumericLiteral < TokenKind::StringLiteral);
        assert!(TokenKind::StringLiteral < TokenKind::UnterminatedString);
        assert!(TokenKind::TwoCharOperator < TokenKind::Punctuation);
    }

    #[test]
    fn lexer_mode_ord() {
        assert!(LexerMode::Swar < LexerMode::Scalar);
        assert!(LexerMode::Scalar < LexerMode::Differential);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn lexer_schema_version_serde_roundtrip() {
        let v = LexerSchemaVersion::V1;
        let json = serde_json::to_string(&v).unwrap();
        let back: LexerSchemaVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn lexer_mode_serde_all_variants() {
        let variants = [LexerMode::Swar, LexerMode::Scalar, LexerMode::Differential];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LexerMode = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn swar_feature_gate_serde_all_variants() {
        let variants = [
            SwarFeatureGate::Portable,
            SwarFeatureGate::RequireAvx2,
            SwarFeatureGate::RequireAvx512F,
            SwarFeatureGate::RequireNeon,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SwarFeatureGate = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn arch_family_serde_all_variants() {
        let variants = [
            ArchFamily::X86_64,
            ArchFamily::Aarch64,
            ArchFamily::Arm,
            ArchFamily::Other,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: ArchFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn arch_family_display_all_distinct() {
        let variants = [
            ArchFamily::X86_64,
            ArchFamily::Aarch64,
            ArchFamily::Arm,
            ArchFamily::Other,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for v in &variants {
            assert!(seen.insert(v.to_string()), "duplicate display: {v}");
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn swar_disable_reason_serde_all_variants() {
        let variants: Vec<SwarDisableReason> = vec![
            SwarDisableReason::OperatorOverride,
            SwarDisableReason::ParityMismatch { mismatch_index: 42 },
            SwarDisableReason::InputBelowThreshold {
                input_len: 4,
                threshold: 8,
            },
            SwarDisableReason::ArchitectureUnsupported {
                pointer_width: 32,
                little_endian: false,
            },
            SwarDisableReason::FeatureGateUnavailable {
                required: SwarFeatureGate::RequireAvx2,
                arch_family: ArchFamily::Aarch64,
            },
            SwarDisableReason::TokenBudgetExceeded,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: SwarDisableReason = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
        assert_eq!(variants.len(), 6);
    }

    #[test]
    fn lexer_error_serde_all_variants() {
        let variants: Vec<LexerError> = vec![
            LexerError::SourceTooLarge {
                size: 1024,
                max: 512,
            },
            LexerError::TokenBudgetExceeded {
                count: 100,
                max: 50,
            },
            LexerError::InternalError("test error".into()),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: LexerError = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, v);
        }
    }

    #[test]
    fn lexer_schema_version_display() {
        assert_eq!(LexerSchemaVersion::V1.to_string(), "v1");
    }
}
