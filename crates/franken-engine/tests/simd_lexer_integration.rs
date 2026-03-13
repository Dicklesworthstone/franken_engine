//! Integration tests for the `simd_lexer` module.
//!
//! Covers: LexerConfig defaults, LexerMode variants, token classification for
//! JS-like expressions (identifiers, numbers, strings, operators, punctuation),
//! whitespace handling, span correctness, empty/large input, Unicode bytes,
//! Scalar/SWAR parity via differential mode, SwarStats / rollback gate,
//! serde roundtrips, determinism, and diagnostic generation.

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

use frankenengine_engine::engine_object_id::{ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::simd_lexer::{
    ArchCapabilityProfile, ArchFamily, DifferentialLexer, DifferentialResult, LexerArtifact,
    LexerConfig, LexerError, LexerMode, LexerOutput, LexerSchemaVersion, LexerTokenWitnessLog,
    ParityMismatch, RollbackGateConfig, RollbackGateResult, SwarDisableReason, SwarFeatureGate,
    ThroughputComparison, ThroughputSample, Token, TokenKind, build_token_witness_log,
    count_tokens, evaluate_rollback_gate, evaluate_swar_fallback_matrix, lex,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn scalar_config() -> LexerConfig {
    LexerConfig {
        mode: LexerMode::Scalar,
        ..LexerConfig::default()
    }
}

fn swar_config_no_threshold() -> LexerConfig {
    LexerConfig {
        mode: LexerMode::Swar,
        swar_min_input_bytes: 0,
        ..LexerConfig::default()
    }
}

fn diff_config() -> LexerConfig {
    LexerConfig {
        mode: LexerMode::Differential,
        swar_min_input_bytes: 0,
        ..LexerConfig::default()
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

// ===========================================================================
// 1. LexerConfig defaults and modes
// ===========================================================================

#[test]
fn config_default_values() {
    let cfg = LexerConfig::default();
    assert_eq!(cfg.mode, LexerMode::Swar);
    assert_eq!(cfg.max_tokens, 65_536);
    assert_eq!(cfg.max_source_bytes, 1_048_576);
    assert_eq!(cfg.swar_min_input_bytes, 64);
    assert_eq!(cfg.feature_gate, SwarFeatureGate::Portable);
    assert!(cfg.emit_tokens);
}

#[test]
fn config_mode_override() {
    let cfg = LexerConfig {
        mode: LexerMode::Scalar,
        ..LexerConfig::default()
    };
    assert_eq!(cfg.mode, LexerMode::Scalar);
    // Other fields stay at defaults.
    assert_eq!(cfg.max_tokens, 65_536);
}

// ===========================================================================
// 2. LexerMode enum variants
// ===========================================================================

#[test]
fn lexer_mode_display_variants() {
    assert_eq!(LexerMode::Swar.to_string(), "SWAR");
    assert_eq!(LexerMode::Scalar.to_string(), "Scalar");
    assert_eq!(LexerMode::Differential.to_string(), "Differential");
}

#[test]
fn lexer_mode_ordering() {
    // Swar < Scalar < Differential (derive order)
    assert!(LexerMode::Swar < LexerMode::Scalar);
    assert!(LexerMode::Scalar < LexerMode::Differential);
}

// ===========================================================================
// 3. Lexing simple JS expressions
// ===========================================================================

#[test]
fn lex_simple_assignment() {
    let out = lex("var x = 42", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 4);
    assert_eq!(out.tokens[0].kind, TokenKind::Identifier); // var
    assert_eq!(out.tokens[1].kind, TokenKind::Identifier); // x
    assert_eq!(out.tokens[2].kind, TokenKind::Punctuation); // =
    assert_eq!(out.tokens[3].kind, TokenKind::NumericLiteral); // 42
}

#[test]
fn lex_function_call() {
    let out = lex("foo(1, 2)", &scalar_config()).unwrap();
    // foo ( 1 , 2 ) => 6 tokens
    assert_eq!(out.token_count, 6);
    assert_eq!(out.tokens[0].kind, TokenKind::Identifier);
    assert_eq!(out.tokens[1].kind, TokenKind::Punctuation); // (
    assert_eq!(out.tokens[2].kind, TokenKind::NumericLiteral); // 1
    assert_eq!(out.tokens[3].kind, TokenKind::Punctuation); // ,
    assert_eq!(out.tokens[4].kind, TokenKind::NumericLiteral); // 2
    assert_eq!(out.tokens[5].kind, TokenKind::Punctuation); // )
}

// ===========================================================================
// 4. Lexing operators
// ===========================================================================

#[test]
fn lex_two_char_operators_all() {
    let input = "== != <= >= && || ?? =>";
    let out = lex(input, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 8);
    for tok in &out.tokens {
        assert_eq!(tok.kind, TokenKind::TwoCharOperator);
    }
}

#[test]
fn lex_single_char_operators() {
    let input = "+ - * / = < > ! ?";
    let out = lex(input, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 9);
    for tok in &out.tokens {
        assert_eq!(tok.kind, TokenKind::Punctuation);
    }
}

#[test]
fn lex_operator_mixed_with_identifiers() {
    let out = lex("a == b", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 3);
    assert_eq!(out.tokens[0].kind, TokenKind::Identifier);
    assert_eq!(out.tokens[1].kind, TokenKind::TwoCharOperator);
    assert_eq!(out.tokens[2].kind, TokenKind::Identifier);
}

// ===========================================================================
// 5. Lexing keywords (treated as identifiers by this lexer)
// ===========================================================================

#[test]
fn lex_js_keywords_as_identifiers() {
    let keywords = "var let const function if else return while for switch case break continue";
    let out = lex(keywords, &scalar_config()).unwrap();
    // 13 keywords, all classified as Identifier (keyword distinction is a parser concern)
    assert_eq!(out.token_count, 13);
    for tok in &out.tokens {
        assert_eq!(tok.kind, TokenKind::Identifier);
    }
}

// ===========================================================================
// 6. Lexing string literals
// ===========================================================================

#[test]
fn lex_double_quoted_string() {
    let out = lex(r#""hello world""#, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::StringLiteral);
}

#[test]
fn lex_single_quoted_string() {
    let out = lex("'hello'", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::StringLiteral);
}

#[test]
fn lex_string_with_escape_sequences() {
    let out = lex(r#""he\"llo""#, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::StringLiteral);
}

#[test]
fn lex_unterminated_string_at_newline() {
    let out = lex("\"hello\nworld", &scalar_config()).unwrap();
    assert_eq!(out.tokens[0].kind, TokenKind::UnterminatedString);
    // After the newline, "world" is lexed as a separate identifier.
    assert_eq!(out.tokens[1].kind, TokenKind::Identifier);
}

#[test]
fn lex_unterminated_string_at_eof() {
    let out = lex("\"hello", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::UnterminatedString);
}

#[test]
fn lex_empty_string() {
    let out = lex(r#""""#, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::StringLiteral);
    assert_eq!(out.tokens[0].span_len(), 2); // Just the two quote chars.
}

// ===========================================================================
// 7. Lexing numeric literals
// ===========================================================================

#[test]
fn lex_integer() {
    let out = lex("42", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::NumericLiteral);
    assert_eq!(out.tokens[0].start, 0);
    assert_eq!(out.tokens[0].end, 2);
}

#[test]
fn lex_multi_digit_number() {
    let out = lex("123456789", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].span_len(), 9);
}

#[test]
fn lex_zero() {
    let out = lex("0", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::NumericLiteral);
}

#[test]
fn lex_hex_prefix_split() {
    // The lexer is simple: "0x1A" lexes "0" as NumericLiteral, "x1A" as Identifier
    // because the scalar lexer only scans ASCII digits.
    let out = lex("0x1A", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
    assert_eq!(out.tokens[0].kind, TokenKind::NumericLiteral);
    assert_eq!(out.tokens[1].kind, TokenKind::Identifier);
}

// ===========================================================================
// 8. Whitespace handling
// ===========================================================================

#[test]
fn lex_tabs_and_spaces() {
    let out = lex("a\t\tb", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
}

#[test]
fn lex_newlines_separate_tokens() {
    let out = lex("a\nb\nc", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 3);
}

#[test]
fn lex_carriage_return_line_feed() {
    let out = lex("a\r\nb", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
}

#[test]
fn lex_only_whitespace() {
    let out = lex("   \t\n\r   ", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 0);
    assert!(out.tokens.is_empty());
    assert!(!out.budget_exceeded);
}

// ===========================================================================
// 9. Empty input handling
// ===========================================================================

#[test]
fn lex_empty_input_scalar() {
    let out = lex("", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 0);
    assert!(out.tokens.is_empty());
    assert_eq!(out.bytes_scanned, 0);
}

#[test]
fn lex_empty_input_swar() {
    let out = lex("", &swar_config_no_threshold()).unwrap();
    assert_eq!(out.token_count, 0);
}

// ===========================================================================
// 10. Token position/span correctness
// ===========================================================================

#[test]
fn token_spans_are_contiguous_and_correct() {
    let input = "abc + 123";
    let out = lex(input, &scalar_config()).unwrap();
    assert_eq!(out.tokens.len(), 3);

    // "abc" at [0..3]
    assert_eq!(out.tokens[0].start, 0);
    assert_eq!(out.tokens[0].end, 3);
    assert_eq!(out.tokens[0].span_len(), 3);

    // "+" at [4..5]
    assert_eq!(out.tokens[1].start, 4);
    assert_eq!(out.tokens[1].end, 5);
    assert_eq!(out.tokens[1].span_len(), 1);

    // "123" at [6..9]
    assert_eq!(out.tokens[2].start, 6);
    assert_eq!(out.tokens[2].end, 9);
    assert_eq!(out.tokens[2].span_len(), 3);
}

#[test]
fn token_source_span_conversion() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 10,
        end: 15,
    };
    let span = token.source_span(3, 10);
    assert_eq!(span.start_offset, 10);
    assert_eq!(span.end_offset, 15);
    assert_eq!(span.start_line, 3);
    assert_eq!(span.end_line, 3);
    assert_eq!(span.start_column, 10);
    assert_eq!(span.end_column, 15);
}

#[test]
fn bytes_scanned_equals_input_length() {
    let input = "hello world";
    let out = lex(input, &scalar_config()).unwrap();
    assert_eq!(out.bytes_scanned, input.len() as u64);
}

// ===========================================================================
// 11. Unicode handling (multi-byte UTF-8 treated as non-ASCII bytes)
// ===========================================================================

#[test]
fn unicode_chars_become_punctuation() {
    // Multi-byte UTF-8 characters are not ASCII, so each byte that is not
    // whitespace / ident-start / digit / quote / operator is Punctuation.
    let input = "\u{00e9}"; // e-acute, 2 bytes: 0xC3 0xA9
    let out = lex(input, &scalar_config()).unwrap();
    // Both bytes are non-ASCII, non-ident, non-digit => 2 punctuation tokens.
    assert_eq!(out.token_count, 2);
    for tok in &out.tokens {
        assert_eq!(tok.kind, TokenKind::Punctuation);
    }
}

#[test]
fn unicode_between_identifiers_differential_parity() {
    let input = format!("abc {} def", "\u{00f1}");
    let result = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert!(result.parity_ok, "parity mismatch: {:?}", result.mismatch);
}

// ===========================================================================
// 12. Scalar mode vs SWAR mode parity
// ===========================================================================

#[test]
fn scalar_swar_parity_simple() {
    let input = "var x = foo(1, 2, 3); if (a == b) { return 'hello'; }";
    let scalar_out = lex(input, &scalar_config()).unwrap();
    let swar_out = lex(input, &swar_config_no_threshold()).unwrap();
    assert_eq!(scalar_out.token_count, swar_out.token_count);
    assert_eq!(scalar_out.tokens.len(), swar_out.tokens.len());
    for (s, w) in scalar_out.tokens.iter().zip(swar_out.tokens.iter()) {
        assert_eq!(s.kind, w.kind);
        assert_eq!(s.start, w.start);
        assert_eq!(s.end, w.end);
    }
}

#[test]
fn scalar_swar_parity_long_whitespace_prefix() {
    let input = format!("{}hello", " ".repeat(256));
    let scalar_out = lex(&input, &scalar_config()).unwrap();
    let swar_out = lex(&input, &swar_config_no_threshold()).unwrap();
    assert_eq!(scalar_out.token_count, swar_out.token_count);
    assert_eq!(scalar_out.tokens, swar_out.tokens);
}

#[test]
fn scalar_swar_parity_long_identifier() {
    let input = "a".repeat(300);
    let scalar_out = lex(&input, &scalar_config()).unwrap();
    let swar_out = lex(&input, &swar_config_no_threshold()).unwrap();
    assert_eq!(scalar_out.tokens, swar_out.tokens);
}

// ===========================================================================
// 13. Differential mode catches mismatches (or proves parity)
// ===========================================================================

#[test]
fn differential_parity_ok_on_diverse_input() {
    let input =
        "function test(a, b) { if (a == b && a != 0) { return 'yes'; } else { return 42; } }";
    let result = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert!(result.parity_ok);
    assert!(result.mismatch.is_none());
    assert_eq!(
        result.swar_output.token_count,
        result.scalar_output.token_count
    );
}

#[test]
fn differential_via_public_lex_returns_swar_output_on_parity() {
    let out = lex("var x = 42;", &diff_config()).unwrap();
    // When parity holds, the public lex() returns the SWAR result.
    assert_eq!(out.actual_mode, LexerMode::Swar);
}

#[test]
fn differential_parity_on_all_two_char_operators() {
    let input = "== != <= >= && || ?? =>";
    let result = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert!(result.parity_ok);
}

// ===========================================================================
// 14. SWAR fallback for small input
// ===========================================================================

#[test]
fn swar_falls_back_below_threshold() {
    let cfg = LexerConfig {
        mode: LexerMode::Swar,
        swar_min_input_bytes: 64,
        ..LexerConfig::default()
    };
    let out = lex("hi", &cfg).unwrap();
    assert!(out.swar_disable_reason.is_some());
    match out.swar_disable_reason.as_ref().unwrap() {
        SwarDisableReason::InputBelowThreshold {
            input_len,
            threshold,
        } => {
            assert_eq!(*input_len, 2);
            assert_eq!(*threshold, 64);
        }
        other => panic!("unexpected disable reason: {:?}", other),
    }
}

#[test]
fn swar_token_budget_exceeded() {
    let cfg = LexerConfig {
        mode: LexerMode::Swar,
        swar_min_input_bytes: 0,
        max_tokens: 2,
        ..LexerConfig::default()
    };
    let out = lex("a b c d e", &cfg).unwrap();
    assert!(out.budget_exceeded);
    assert_eq!(out.token_count, 2);
}

// ===========================================================================
// 15. SwarDisableReason and RollbackGate
// ===========================================================================

#[test]
fn swar_disable_reason_display_all_variants() {
    assert_eq!(
        SwarDisableReason::OperatorOverride.to_string(),
        "operator_override"
    );
    assert_eq!(
        SwarDisableReason::ParityMismatch { mismatch_index: 7 }.to_string(),
        "parity_mismatch(index=7)"
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
fn rollback_gate_default_approves_good_metrics() {
    let result = evaluate_rollback_gate(0, 2_000_000, 0, &RollbackGateConfig::default());
    assert!(result.swar_approved);
    assert!(result.disable_reasons.is_empty());
    assert_eq!(result.parity_mismatches, 0);
    assert_eq!(result.observed_speedup_millionths, 2_000_000);
}

#[test]
fn rollback_gate_rejects_on_parity_failures() {
    let result = evaluate_rollback_gate(1, 2_000_000, 0, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
    assert_eq!(result.disable_reasons.len(), 1);
}

#[test]
fn rollback_gate_rejects_on_low_speedup() {
    let result = evaluate_rollback_gate(0, 500_000, 0, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
}

#[test]
fn rollback_gate_rejects_on_p99_regression() {
    let result = evaluate_rollback_gate(0, 2_000_000, 600_000, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
}

#[test]
fn rollback_gate_accumulates_multiple_failures() {
    let result = evaluate_rollback_gate(5, 100_000, 900_000, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
    assert_eq!(result.disable_reasons.len(), 3);
}

// ===========================================================================
// 16. Serde roundtrip for tokens and output
// ===========================================================================

#[test]
fn token_kind_serde_roundtrip() {
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
fn lexer_output_serde_roundtrip() {
    let output = lex("var x = 42;", &scalar_config()).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: LexerOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, back);
}

#[test]
fn lexer_config_serde_roundtrip() {
    let config = LexerConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let back: LexerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, back);
}

#[test]
fn differential_result_serde_roundtrip() {
    let result = DifferentialLexer::lex(b"a + b", &diff_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    let back: DifferentialResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn lexer_artifact_serde_roundtrip() {
    let output = lex("x + y", &scalar_config()).unwrap();
    let artifact = LexerArtifact {
        artifact_id: derive_id(
            ObjectDomain::EvidenceRecord,
            "simd-lexer-test",
            &SchemaId::from_definition(b"test-artifact"),
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
fn rollback_gate_result_serde_roundtrip() {
    let result = evaluate_rollback_gate(0, 2_000_000, 0, &RollbackGateConfig::default());
    let json = serde_json::to_string(&result).unwrap();
    let back: RollbackGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, back);
}

#[test]
fn throughput_sample_serde_roundtrip() {
    let sample = ThroughputSample::compute(LexerMode::Swar, 1000, 50, 1_000_000);
    let json = serde_json::to_string(&sample).unwrap();
    let back: ThroughputSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, back);
}

// ===========================================================================
// 17. Large input stress testing
// ===========================================================================

#[test]
fn stress_large_mixed_input_differential_parity() {
    let cfg = LexerConfig {
        mode: LexerMode::Differential,
        swar_min_input_bytes: 0,
        max_tokens: 200_000,
        ..LexerConfig::default()
    };
    let mut input = String::new();
    for i in 0u64..500 {
        input.push_str(&format!("var x{} = {}; ", i, i));
        if i.is_multiple_of(5) {
            input.push_str(&format!("\"string{}\" ", i));
        }
        if i.is_multiple_of(7) {
            input.push_str("== != && || ");
        }
    }
    let result = DifferentialLexer::lex(input.as_bytes(), &cfg).unwrap();
    assert!(result.parity_ok, "parity mismatch: {:?}", result.mismatch);
}

#[test]
fn stress_dense_punctuation_parity() {
    let cfg = LexerConfig {
        swar_min_input_bytes: 0,
        max_tokens: 100_000,
        ..LexerConfig::default()
    };
    let input = "+-*/(){}[];,.:<>!@#%^~".repeat(50);
    let result = DifferentialLexer::lex(input.as_bytes(), &cfg).unwrap();
    assert!(result.parity_ok);
}

#[test]
fn stress_all_whitespace_swar() {
    let cfg = swar_config_no_threshold();
    let input = " ".repeat(4096);
    let out = lex(&input, &cfg).unwrap();
    assert_eq!(out.token_count, 0);
    assert_eq!(out.bytes_scanned, 4096);
}

#[test]
fn stress_long_string_content_parity() {
    let inner = "abcdefghij".repeat(100); // 1000 chars inside quotes
    let input = format!("\"{}\"", inner);
    let result = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert!(result.parity_ok);
    assert_eq!(result.swar_output.token_count, 1);
    assert_eq!(result.swar_output.tokens[0].kind, TokenKind::StringLiteral);
}

// ===========================================================================
// 18. Lexer determinism (same input = same output)
// ===========================================================================

#[test]
fn scalar_determinism() {
    let input = "var x = foo(1, 2, 3); if (a == b) { return 'hello'; }";
    let out1 = lex(input, &scalar_config()).unwrap();
    let out2 = lex(input, &scalar_config()).unwrap();
    assert_eq!(out1, out2);
}

#[test]
fn swar_determinism() {
    let input = "var x = foo(1, 2, 3); if (a == b) { return 'hello'; }";
    let out1 = lex(input, &swar_config_no_threshold()).unwrap();
    let out2 = lex(input, &swar_config_no_threshold()).unwrap();
    assert_eq!(out1, out2);
}

#[test]
fn count_tokens_determinism() {
    let input = "a + b * c / d";
    let c1 = count_tokens(input, &scalar_config()).unwrap();
    let c2 = count_tokens(input, &scalar_config()).unwrap();
    assert_eq!(c1, c2);
}

// ===========================================================================
// 19. Token kind categorization
// ===========================================================================

#[test]
fn token_kind_display_all() {
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
fn token_kind_ordering() {
    // Derived Ord follows declaration order.
    assert!(TokenKind::Identifier < TokenKind::NumericLiteral);
    assert!(TokenKind::NumericLiteral < TokenKind::StringLiteral);
    assert!(TokenKind::StringLiteral < TokenKind::UnterminatedString);
    assert!(TokenKind::UnterminatedString < TokenKind::TwoCharOperator);
    assert!(TokenKind::TwoCharOperator < TokenKind::Punctuation);
}

#[test]
fn dollar_and_underscore_are_ident_start() {
    let out = lex("$foo _bar", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
    assert_eq!(out.tokens[0].kind, TokenKind::Identifier);
    assert_eq!(out.tokens[1].kind, TokenKind::Identifier);
}

// ===========================================================================
// 20. Diagnostic generation for malformed tokens / error paths
// ===========================================================================

#[test]
fn source_too_large_error() {
    let cfg = LexerConfig {
        max_source_bytes: 5,
        ..scalar_config()
    };
    let err = lex("hello world", &cfg).unwrap_err();
    match err {
        LexerError::SourceTooLarge { size, max } => {
            assert_eq!(size, 11);
            assert_eq!(max, 5);
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn source_too_large_error_display() {
    let err = LexerError::SourceTooLarge {
        size: 200,
        max: 100,
    };
    assert_eq!(err.to_string(), "source too large: 200 bytes (max 100)");
}

#[test]
fn token_budget_exceeded_error_display() {
    let err = LexerError::TokenBudgetExceeded {
        count: 500,
        max: 100,
    };
    assert_eq!(
        err.to_string(),
        "token budget exceeded: 500 tokens (max 100)"
    );
}

#[test]
fn internal_error_display() {
    let err = LexerError::InternalError("something broke".to_string());
    assert_eq!(err.to_string(), "internal lexer error: something broke");
}

#[test]
fn budget_exceeded_stops_scanning() {
    let cfg = LexerConfig {
        max_tokens: 3,
        ..scalar_config()
    };
    let out = lex("a b c d e f", &cfg).unwrap();
    assert!(out.budget_exceeded);
    assert_eq!(out.token_count, 3);
    // bytes_scanned should be less than total since scanning stopped early.
    assert!(out.bytes_scanned <= 11);
}

#[test]
fn emit_tokens_false_returns_empty_vec() {
    let cfg = LexerConfig {
        emit_tokens: false,
        ..scalar_config()
    };
    let out = lex("a b c", &cfg).unwrap();
    assert_eq!(out.token_count, 3);
    assert!(out.tokens.is_empty());
}

// ===========================================================================
// Additional: Architecture profile
// ===========================================================================

#[test]
fn arch_capability_profile_detect() {
    let profile = ArchCapabilityProfile::detect();
    assert_eq!(profile.swar_width, 8);
    assert!(profile.swar_available);
    assert_eq!(
        profile.supports_feature_gate(SwarFeatureGate::Portable),
        profile.supports_swar()
    );
    // On typical CI/dev machines: 64-bit, little-endian.
    if cfg!(target_pointer_width = "64") {
        assert_eq!(profile.pointer_width, 64);
    }
    if cfg!(target_endian = "little") {
        assert!(profile.little_endian);
        assert!(profile.supports_swar());
    }
}

#[test]
fn arch_profile_serde_roundtrip() {
    let profile = ArchCapabilityProfile::detect();
    let json = serde_json::to_string(&profile).unwrap();
    let back: ArchCapabilityProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, back);
}

#[test]
fn fallback_matrix_rejects_missing_avx2_gate() {
    let profile = profile_for_tests(ArchFamily::X86_64, true, false, false, false);
    let cfg = LexerConfig {
        feature_gate: SwarFeatureGate::RequireAvx2,
        ..LexerConfig::default()
    };
    let reason = evaluate_swar_fallback_matrix(4096, &cfg, &profile).unwrap();
    assert_eq!(
        reason,
        SwarDisableReason::FeatureGateUnavailable {
            required: SwarFeatureGate::RequireAvx2,
            arch_family: ArchFamily::X86_64
        }
    );
}

#[test]
fn fallback_matrix_rejects_big_endian_profile() {
    let profile = profile_for_tests(ArchFamily::Other, false, false, false, false);
    let cfg = LexerConfig::default();
    let reason = evaluate_swar_fallback_matrix(4096, &cfg, &profile).unwrap();
    assert_eq!(
        reason,
        SwarDisableReason::ArchitectureUnsupported {
            pointer_width: 64,
            little_endian: false
        }
    );
}

// ===========================================================================
// Additional: Throughput measurement
// ===========================================================================

#[test]
fn throughput_sample_zero_time_gives_zero_rates() {
    let sample = ThroughputSample::compute(LexerMode::Scalar, 1000, 50, 0);
    assert_eq!(sample.bytes_per_second_millionths, 0);
    assert_eq!(sample.tokens_per_second_millionths, 0);
}

#[test]
fn throughput_comparison_speedup_ratio() {
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
    // 10B / 3.33B ~= 3x => speedup_millionths > 2_000_000
    assert!(comparison.speedup_millionths > 2_000_000);
}

// ===========================================================================
// Additional: ParityMismatch display
// ===========================================================================

#[test]
fn parity_mismatch_display_format() {
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

// ===========================================================================
// Additional: count_tokens matches full lex
// ===========================================================================

#[test]
fn count_tokens_matches_full_lex() {
    let input = "var x = foo(1, 2, 3); if (a == b) { return; }";
    let count = count_tokens(input, &scalar_config()).unwrap();
    let output = lex(input, &scalar_config()).unwrap();
    assert_eq!(count, output.token_count);
}

// ===========================================================================
// Additional: Schema version
// ===========================================================================

#[test]
fn schema_version_v1_display() {
    assert_eq!(LexerSchemaVersion::V1.to_string(), "v1");
}

#[test]
fn schema_version_serde_roundtrip() {
    let v = LexerSchemaVersion::V1;
    let json = serde_json::to_string(&v).unwrap();
    let back: LexerSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

#[test]
fn output_schema_version_is_v1() {
    let out = lex("a", &scalar_config()).unwrap();
    assert_eq!(out.schema_version, LexerSchemaVersion::V1);
}

#[test]
fn token_witness_log_contains_replay_command() {
    let input = "let result = alpha + beta;";
    let cfg = swar_config_no_threshold();
    let out = lex(input, &cfg).unwrap();
    let replay = "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact token_witness_log_contains_replay_command";
    let log = build_token_witness_log(
        input,
        &cfg,
        &out,
        "trace-simd-lexer-feature-gate",
        "decision-simd-lexer-feature-gate",
        "policy-simd-lexer-feature-gate-v1",
        replay,
    );
    assert_eq!(log.replay_command, replay);
    assert_eq!(log.actual_mode, out.actual_mode);
    assert_eq!(log.token_count, out.token_count);
    assert!(log.input_hash.starts_with("sha256:"));
    assert!(log.token_witness_hash.starts_with("sha256:"));
}

#[test]
fn token_witness_log_serde_roundtrip() {
    let input = "const z = 99;";
    let cfg = swar_config_no_threshold();
    let out = lex(input, &cfg).unwrap();
    let log = build_token_witness_log(
        input,
        &cfg,
        &out,
        "trace-simd-lexer-feature-gate",
        "decision-simd-lexer-feature-gate",
        "policy-simd-lexer-feature-gate-v1",
        "cargo test -p frankenengine-engine --test simd_lexer_integration -- --exact token_witness_log_serde_roundtrip",
    );
    let json = serde_json::to_string(&log).unwrap();
    let back: LexerTokenWitnessLog = serde_json::from_str(&json).unwrap();
    assert_eq!(log, back);
}

// ===========================================================================
// Enrichment tests — PearlTower 2026-03-12
// ===========================================================================

use frankenengine_engine::simd_lexer::TokenSpanStorage;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// TokenSpanStorage tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_token_span_storage_default_is_empty() {
    let storage = TokenSpanStorage::default();
    assert!(storage.is_empty());
    assert_eq!(storage.len(), 0);
    assert!(storage.token_kinds().is_empty());
    assert!(storage.starts().is_empty());
    assert!(storage.ends().is_empty());
}

#[test]
fn enrichment_token_span_storage_with_capacity_starts_empty() {
    let storage = TokenSpanStorage::with_capacity(100);
    assert!(storage.is_empty());
    assert_eq!(storage.len(), 0);
}

#[test]
fn enrichment_token_span_storage_push_increments_len() {
    let mut storage = TokenSpanStorage::default();
    storage.push(TokenKind::Identifier, 0, 3);
    assert_eq!(storage.len(), 1);
    assert!(!storage.is_empty());
    storage.push(TokenKind::Punctuation, 4, 5);
    assert_eq!(storage.len(), 2);
}

#[test]
fn enrichment_token_span_storage_accessors_match_pushed_data() {
    let mut storage = TokenSpanStorage::default();
    storage.push(TokenKind::Identifier, 0, 5);
    storage.push(TokenKind::NumericLiteral, 6, 8);
    storage.push(TokenKind::StringLiteral, 9, 20);
    assert_eq!(
        storage.token_kinds(),
        &[
            TokenKind::Identifier,
            TokenKind::NumericLiteral,
            TokenKind::StringLiteral
        ]
    );
    assert_eq!(storage.starts(), &[0, 6, 9]);
    assert_eq!(storage.ends(), &[5, 8, 20]);
}

#[test]
fn enrichment_token_span_storage_from_tokens_roundtrip() {
    let tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        },
        Token {
            kind: TokenKind::Punctuation,
            start: 4,
            end: 5,
        },
        Token {
            kind: TokenKind::NumericLiteral,
            start: 6,
            end: 9,
        },
    ];
    let storage = TokenSpanStorage::from_tokens(&tokens);
    assert_eq!(storage.len(), 3);
    let back = storage.to_tokens();
    assert_eq!(back, tokens);
}

#[test]
fn enrichment_token_span_storage_into_tokens_consumes() {
    let tokens = vec![
        Token {
            kind: TokenKind::StringLiteral,
            start: 0,
            end: 10,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 11,
            end: 14,
        },
    ];
    let storage = TokenSpanStorage::from_tokens(&tokens);
    let back = storage.into_tokens();
    assert_eq!(back, tokens);
}

#[test]
fn enrichment_token_span_storage_clone_eq() {
    let mut storage = TokenSpanStorage::default();
    storage.push(TokenKind::Identifier, 0, 3);
    storage.push(TokenKind::Punctuation, 4, 5);
    let cloned = storage.clone();
    assert_eq!(storage, cloned);
}

#[test]
fn enrichment_token_span_storage_debug_not_empty() {
    let storage = TokenSpanStorage::default();
    let debug = format!("{:?}", storage);
    assert!(debug.contains("TokenSpanStorage"));
}

#[test]
fn enrichment_token_span_storage_serde_roundtrip() {
    let mut storage = TokenSpanStorage::default();
    storage.push(TokenKind::Identifier, 0, 5);
    storage.push(TokenKind::TwoCharOperator, 6, 8);
    let json = serde_json::to_string(&storage).unwrap();
    let back: TokenSpanStorage = serde_json::from_str(&json).unwrap();
    assert_eq!(storage, back);
}

#[test]
fn enrichment_token_span_storage_empty_serde_roundtrip() {
    let storage = TokenSpanStorage::default();
    let json = serde_json::to_string(&storage).unwrap();
    let back: TokenSpanStorage = serde_json::from_str(&json).unwrap();
    assert_eq!(storage, back);
}

#[test]
fn enrichment_token_span_storage_from_empty_tokens() {
    let storage = TokenSpanStorage::from_tokens(&[]);
    assert!(storage.is_empty());
    assert_eq!(storage.to_tokens(), Vec::<Token>::new());
}

// ---------------------------------------------------------------------------
// Token edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_token_span_len_zero_width() {
    let token = Token {
        kind: TokenKind::Punctuation,
        start: 5,
        end: 5,
    };
    assert_eq!(token.span_len(), 0);
}

#[test]
fn enrichment_token_span_len_saturating_sub() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 10,
        end: 5,
    };
    // saturating_sub protects against underflow
    assert_eq!(token.span_len(), 0);
}

#[test]
fn enrichment_token_source_span_zero_offset() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 3,
    };
    let span = token.source_span(0, 0);
    assert_eq!(span.start_offset, 0);
    assert_eq!(span.end_offset, 3);
    assert_eq!(span.start_line, 0);
    assert_eq!(span.end_line, 0);
    assert_eq!(span.start_column, 0);
    assert_eq!(span.end_column, 3);
}

#[test]
fn enrichment_token_source_span_large_line() {
    let token = Token {
        kind: TokenKind::NumericLiteral,
        start: 1000,
        end: 1005,
    };
    let span = token.source_span(999, 50);
    assert_eq!(span.start_line, 999);
    assert_eq!(span.end_line, 999);
    assert_eq!(span.start_column, 50);
    assert_eq!(span.end_column, 55);
}

#[test]
fn enrichment_token_clone_eq() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 5,
    };
    let cloned = token.clone();
    assert_eq!(token, cloned);
}

#[test]
fn enrichment_token_debug_format() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 5,
    };
    let debug = format!("{:?}", token);
    assert!(debug.contains("Identifier"));
    assert!(debug.contains("start"));
    assert!(debug.contains("end"));
}

// ---------------------------------------------------------------------------
// TokenKind tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_token_kind_clone_copy() {
    let kind = TokenKind::Identifier;
    let cloned = kind.clone();
    let copied = kind;
    assert_eq!(kind, cloned);
    assert_eq!(kind, copied);
}

#[test]
fn enrichment_token_kind_hash_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(TokenKind::Identifier);
    set.insert(TokenKind::NumericLiteral);
    set.insert(TokenKind::Identifier); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_token_kind_all_variants_distinct_display() {
    let all = [
        TokenKind::Identifier,
        TokenKind::NumericLiteral,
        TokenKind::StringLiteral,
        TokenKind::UnterminatedString,
        TokenKind::TwoCharOperator,
        TokenKind::Punctuation,
    ];
    let mut displays = BTreeSet::new();
    for kind in &all {
        assert!(
            displays.insert(kind.to_string()),
            "duplicate display for {:?}",
            kind
        );
    }
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_token_kind_debug_contains_variant_name() {
    assert!(format!("{:?}", TokenKind::Identifier).contains("Identifier"));
    assert!(format!("{:?}", TokenKind::UnterminatedString).contains("UnterminatedString"));
}

// ---------------------------------------------------------------------------
// LexerMode tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lexer_mode_clone_copy() {
    let mode = LexerMode::Swar;
    let cloned = mode.clone();
    let copied = mode;
    assert_eq!(mode, cloned);
    assert_eq!(mode, copied);
}

#[test]
fn enrichment_lexer_mode_hash_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(LexerMode::Swar);
    set.insert(LexerMode::Scalar);
    set.insert(LexerMode::Differential);
    set.insert(LexerMode::Swar); // dup
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_lexer_mode_all_variants_distinct_display() {
    let all = [LexerMode::Swar, LexerMode::Scalar, LexerMode::Differential];
    let mut displays = BTreeSet::new();
    for m in &all {
        assert!(displays.insert(m.to_string()));
    }
    assert_eq!(displays.len(), 3);
}

// ---------------------------------------------------------------------------
// SwarFeatureGate tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_swar_feature_gate_clone_copy() {
    let gate = SwarFeatureGate::RequireAvx2;
    let cloned = gate.clone();
    assert_eq!(gate, cloned);
}

#[test]
fn enrichment_swar_feature_gate_ordering() {
    assert!(SwarFeatureGate::Portable < SwarFeatureGate::RequireAvx2);
    assert!(SwarFeatureGate::RequireAvx2 < SwarFeatureGate::RequireAvx512F);
    assert!(SwarFeatureGate::RequireAvx512F < SwarFeatureGate::RequireNeon);
}

#[test]
fn enrichment_swar_feature_gate_all_display_values() {
    assert_eq!(SwarFeatureGate::Portable.to_string(), "portable");
    assert_eq!(SwarFeatureGate::RequireAvx2.to_string(), "require_avx2");
    assert_eq!(
        SwarFeatureGate::RequireAvx512F.to_string(),
        "require_avx512f"
    );
    assert_eq!(SwarFeatureGate::RequireNeon.to_string(), "require_neon");
}

#[test]
fn enrichment_swar_feature_gate_hash_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(SwarFeatureGate::Portable);
    set.insert(SwarFeatureGate::RequireAvx2);
    set.insert(SwarFeatureGate::RequireAvx512F);
    set.insert(SwarFeatureGate::RequireNeon);
    set.insert(SwarFeatureGate::Portable); // dup
    assert_eq!(set.len(), 4);
}

// ---------------------------------------------------------------------------
// ArchFamily tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_arch_family_clone_copy() {
    let family = ArchFamily::X86_64;
    let cloned = family.clone();
    assert_eq!(family, cloned);
}

#[test]
fn enrichment_arch_family_ordering() {
    assert!(ArchFamily::X86_64 < ArchFamily::Aarch64);
    assert!(ArchFamily::Aarch64 < ArchFamily::Arm);
    assert!(ArchFamily::Arm < ArchFamily::Other);
}

#[test]
fn enrichment_arch_family_display_values() {
    assert_eq!(ArchFamily::X86_64.to_string(), "x86_64");
    assert_eq!(ArchFamily::Aarch64.to_string(), "aarch64");
    assert_eq!(ArchFamily::Arm.to_string(), "arm");
    assert_eq!(ArchFamily::Other.to_string(), "other");
}

// ---------------------------------------------------------------------------
// LexerSchemaVersion tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lexer_schema_version_clone_copy() {
    let v = LexerSchemaVersion::V1;
    let cloned = v.clone();
    assert_eq!(v, cloned);
}

#[test]
fn enrichment_lexer_schema_version_ordering() {
    assert_eq!(LexerSchemaVersion::V1, LexerSchemaVersion::V1);
}

#[test]
fn enrichment_lexer_schema_version_hash_in_btreeset() {
    let mut set = BTreeSet::new();
    set.insert(LexerSchemaVersion::V1);
    set.insert(LexerSchemaVersion::V1);
    assert_eq!(set.len(), 1);
}

#[test]
fn enrichment_lexer_schema_version_debug() {
    let debug = format!("{:?}", LexerSchemaVersion::V1);
    assert!(debug.contains("V1"));
}

// ---------------------------------------------------------------------------
// SwarDisableReason tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_swar_disable_reason_clone() {
    let reason = SwarDisableReason::ParityMismatch { mismatch_index: 42 };
    let cloned = reason.clone();
    assert_eq!(reason, cloned);
}

#[test]
fn enrichment_swar_disable_reason_debug_all_variants() {
    let variants: Vec<SwarDisableReason> = vec![
        SwarDisableReason::OperatorOverride,
        SwarDisableReason::ParityMismatch { mismatch_index: 0 },
        SwarDisableReason::InputBelowThreshold {
            input_len: 1,
            threshold: 64,
        },
        SwarDisableReason::ArchitectureUnsupported {
            pointer_width: 32,
            little_endian: false,
        },
        SwarDisableReason::FeatureGateUnavailable {
            required: SwarFeatureGate::RequireNeon,
            arch_family: ArchFamily::Arm,
        },
        SwarDisableReason::TokenBudgetExceeded,
    ];
    for v in &variants {
        let debug = format!("{:?}", v);
        assert!(!debug.is_empty());
    }
}

#[test]
fn enrichment_swar_disable_reason_display_parity_mismatch_zero_index() {
    assert_eq!(
        SwarDisableReason::ParityMismatch { mismatch_index: 0 }.to_string(),
        "parity_mismatch(index=0)"
    );
}

#[test]
fn enrichment_swar_disable_reason_display_architecture_big_endian() {
    assert_eq!(
        SwarDisableReason::ArchitectureUnsupported {
            pointer_width: 32,
            little_endian: false,
        }
        .to_string(),
        "architecture_unsupported(pointer_width=32, little_endian=false)"
    );
}

#[test]
fn enrichment_swar_disable_reason_display_feature_gate_neon_arm() {
    assert_eq!(
        SwarDisableReason::FeatureGateUnavailable {
            required: SwarFeatureGate::RequireNeon,
            arch_family: ArchFamily::Arm,
        }
        .to_string(),
        "feature_gate_unavailable(required=require_neon, arch=arm)"
    );
}

#[test]
fn enrichment_swar_disable_reason_display_feature_gate_avx512_x86() {
    assert_eq!(
        SwarDisableReason::FeatureGateUnavailable {
            required: SwarFeatureGate::RequireAvx512F,
            arch_family: ArchFamily::X86_64,
        }
        .to_string(),
        "feature_gate_unavailable(required=require_avx512f, arch=x86_64)"
    );
}

// ---------------------------------------------------------------------------
// LexerError tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lexer_error_clone() {
    let err = LexerError::InternalError("test".to_string());
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn enrichment_lexer_error_debug_all_variants() {
    let variants: Vec<LexerError> = vec![
        LexerError::SourceTooLarge { size: 1, max: 0 },
        LexerError::TokenBudgetExceeded { count: 1, max: 0 },
        LexerError::InternalError("msg".to_string()),
    ];
    for v in &variants {
        let debug = format!("{:?}", v);
        assert!(!debug.is_empty());
    }
}

#[test]
fn enrichment_lexer_error_internal_empty_message() {
    let err = LexerError::InternalError(String::new());
    assert_eq!(err.to_string(), "internal lexer error: ");
}

#[test]
fn enrichment_lexer_error_source_too_large_zero_max() {
    let err = LexerError::SourceTooLarge { size: 0, max: 0 };
    assert_eq!(err.to_string(), "source too large: 0 bytes (max 0)");
}

#[test]
fn enrichment_lexer_error_serde_internal_error() {
    let err = LexerError::InternalError("complex \"message\" with quotes".to_string());
    let json = serde_json::to_string(&err).unwrap();
    let back: LexerError = serde_json::from_str(&json).unwrap();
    assert_eq!(err, back);
}

// ---------------------------------------------------------------------------
// LexerConfig tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lexer_config_clone() {
    let cfg = LexerConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
}

#[test]
fn enrichment_lexer_config_debug() {
    let cfg = LexerConfig::default();
    let debug = format!("{:?}", cfg);
    assert!(debug.contains("mode"));
    assert!(debug.contains("max_tokens"));
    assert!(debug.contains("emit_tokens"));
}

#[test]
fn enrichment_lexer_config_default_json_field_names() {
    let cfg = LexerConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("\"mode\""));
    assert!(json.contains("\"max_tokens\""));
    assert!(json.contains("\"max_source_bytes\""));
    assert!(json.contains("\"swar_min_input_bytes\""));
    assert!(json.contains("\"feature_gate\""));
    assert!(json.contains("\"emit_tokens\""));
}

#[test]
fn enrichment_lexer_config_all_modes_serde() {
    for mode in [LexerMode::Swar, LexerMode::Scalar, LexerMode::Differential] {
        let cfg = LexerConfig {
            mode,
            ..LexerConfig::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: LexerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }
}

// ---------------------------------------------------------------------------
// LexerOutput tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lexer_output_clone() {
    let out = lex("a + b", &scalar_config()).unwrap();
    let cloned = out.clone();
    assert_eq!(out, cloned);
}

#[test]
fn enrichment_lexer_output_debug() {
    let out = lex("x", &scalar_config()).unwrap();
    let debug = format!("{:?}", out);
    assert!(debug.contains("actual_mode"));
    assert!(debug.contains("token_count"));
}

#[test]
fn enrichment_lexer_output_json_field_names() {
    let out = lex("x", &scalar_config()).unwrap();
    let json = serde_json::to_string(&out).unwrap();
    assert!(json.contains("\"actual_mode\""));
    assert!(json.contains("\"swar_disable_reason\""));
    assert!(json.contains("\"token_count\""));
    assert!(json.contains("\"tokens\""));
    assert!(json.contains("\"bytes_scanned\""));
    assert!(json.contains("\"budget_exceeded\""));
    assert!(json.contains("\"schema_version\""));
}

// ---------------------------------------------------------------------------
// ParityMismatch tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_parity_mismatch_with_tokens() {
    let m = ParityMismatch {
        token_index: 5,
        swar_token: Some(Token {
            kind: TokenKind::Identifier,
            start: 10,
            end: 15,
        }),
        scalar_token: Some(Token {
            kind: TokenKind::NumericLiteral,
            start: 10,
            end: 15,
        }),
        swar_count: 20,
        scalar_count: 20,
    };
    assert_eq!(
        m.to_string(),
        "parity mismatch at token 5: swar_count=20, scalar_count=20"
    );
    assert!(m.swar_token.is_some());
    assert!(m.scalar_token.is_some());
}

#[test]
fn enrichment_parity_mismatch_clone() {
    let m = ParityMismatch {
        token_index: 0,
        swar_token: None,
        scalar_token: None,
        swar_count: 0,
        scalar_count: 0,
    };
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn enrichment_parity_mismatch_serde_roundtrip() {
    let m = ParityMismatch {
        token_index: 3,
        swar_token: Some(Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 5,
        }),
        scalar_token: None,
        swar_count: 10,
        scalar_count: 9,
    };
    let json = serde_json::to_string(&m).unwrap();
    let back: ParityMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(m, back);
}

#[test]
fn enrichment_parity_mismatch_json_field_names() {
    let m = ParityMismatch {
        token_index: 0,
        swar_token: None,
        scalar_token: None,
        swar_count: 1,
        scalar_count: 2,
    };
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"token_index\""));
    assert!(json.contains("\"swar_token\""));
    assert!(json.contains("\"scalar_token\""));
    assert!(json.contains("\"swar_count\""));
    assert!(json.contains("\"scalar_count\""));
}

#[test]
fn enrichment_parity_mismatch_display_zero_counts() {
    let m = ParityMismatch {
        token_index: 0,
        swar_token: None,
        scalar_token: None,
        swar_count: 0,
        scalar_count: 0,
    };
    assert_eq!(
        m.to_string(),
        "parity mismatch at token 0: swar_count=0, scalar_count=0"
    );
}

// ---------------------------------------------------------------------------
// DifferentialResult tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_differential_result_clone() {
    let result = DifferentialLexer::lex(b"x + 1", &diff_config()).unwrap();
    let cloned = result.clone();
    assert_eq!(result, cloned);
}

#[test]
fn enrichment_differential_result_debug() {
    let result = DifferentialLexer::lex(b"x", &diff_config()).unwrap();
    let debug = format!("{:?}", result);
    assert!(debug.contains("parity_ok"));
}

#[test]
fn enrichment_differential_result_json_field_names() {
    let result = DifferentialLexer::lex(b"x", &diff_config()).unwrap();
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"swar_output\""));
    assert!(json.contains("\"scalar_output\""));
    assert!(json.contains("\"parity_ok\""));
    assert!(json.contains("\"mismatch\""));
}

// ---------------------------------------------------------------------------
// RollbackGateConfig tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_gate_config_default_values() {
    let cfg = RollbackGateConfig::default();
    assert_eq!(cfg.max_parity_mismatches, 0);
    assert_eq!(cfg.min_speedup_millionths, 1_000_000);
    assert_eq!(cfg.max_p99_regression_millionths, 500_000);
}

#[test]
fn enrichment_rollback_gate_config_clone() {
    let cfg = RollbackGateConfig::default();
    let cloned = cfg.clone();
    assert_eq!(cfg, cloned);
}

#[test]
fn enrichment_rollback_gate_config_serde_roundtrip() {
    let cfg = RollbackGateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    let back: RollbackGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_rollback_gate_config_custom_serde() {
    let cfg = RollbackGateConfig {
        max_parity_mismatches: 5,
        min_speedup_millionths: 500_000,
        max_p99_regression_millionths: 1_000_000,
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: RollbackGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(cfg, back);
}

#[test]
fn enrichment_rollback_gate_config_json_field_names() {
    let cfg = RollbackGateConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    assert!(json.contains("\"max_parity_mismatches\""));
    assert!(json.contains("\"min_speedup_millionths\""));
    assert!(json.contains("\"max_p99_regression_millionths\""));
}

// ---------------------------------------------------------------------------
// RollbackGateResult tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_rollback_gate_result_boundary_speedup_exactly_1x() {
    // exactly at min_speedup should approve
    let result = evaluate_rollback_gate(0, 1_000_000, 0, &RollbackGateConfig::default());
    assert!(result.swar_approved);
}

#[test]
fn enrichment_rollback_gate_result_boundary_speedup_just_below_1x() {
    let result = evaluate_rollback_gate(0, 999_999, 0, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
}

#[test]
fn enrichment_rollback_gate_result_boundary_p99_exactly_at_max() {
    // exactly at max_p99 should approve
    let result = evaluate_rollback_gate(0, 2_000_000, 500_000, &RollbackGateConfig::default());
    assert!(result.swar_approved);
}

#[test]
fn enrichment_rollback_gate_result_boundary_p99_just_above_max() {
    let result = evaluate_rollback_gate(0, 2_000_000, 500_001, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
}

#[test]
fn enrichment_rollback_gate_result_json_field_names() {
    let result = evaluate_rollback_gate(0, 2_000_000, 0, &RollbackGateConfig::default());
    let json = serde_json::to_string(&result).unwrap();
    assert!(json.contains("\"swar_approved\""));
    assert!(json.contains("\"parity_mismatches\""));
    assert!(json.contains("\"observed_speedup_millionths\""));
    assert!(json.contains("\"disable_reasons\""));
}

#[test]
fn enrichment_rollback_gate_result_custom_config_lenient() {
    let cfg = RollbackGateConfig {
        max_parity_mismatches: 10,
        min_speedup_millionths: 100_000,
        max_p99_regression_millionths: 2_000_000,
    };
    let result = evaluate_rollback_gate(5, 200_000, 1_500_000, &cfg);
    assert!(result.swar_approved);
    assert!(result.disable_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// ThroughputSample tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_throughput_sample_clone() {
    let sample = ThroughputSample::compute(LexerMode::Swar, 100, 10, 1000);
    let cloned = sample.clone();
    assert_eq!(sample, cloned);
}

#[test]
fn enrichment_throughput_sample_debug() {
    let sample = ThroughputSample::compute(LexerMode::Scalar, 100, 10, 1000);
    let debug = format!("{:?}", sample);
    assert!(debug.contains("ThroughputSample"));
}

#[test]
fn enrichment_throughput_sample_zero_bytes() {
    let sample = ThroughputSample::compute(LexerMode::Scalar, 0, 0, 1000);
    assert_eq!(sample.bytes_per_second_millionths, 0);
    assert_eq!(sample.tokens_per_second_millionths, 0);
}

#[test]
fn enrichment_throughput_sample_json_field_names() {
    let sample = ThroughputSample::compute(LexerMode::Swar, 100, 10, 1000);
    let json = serde_json::to_string(&sample).unwrap();
    assert!(json.contains("\"mode\""));
    assert!(json.contains("\"input_bytes\""));
    assert!(json.contains("\"token_count\""));
    assert!(json.contains("\"wall_time_ns\""));
    assert!(json.contains("\"bytes_per_second_millionths\""));
    assert!(json.contains("\"tokens_per_second_millionths\""));
}

// ---------------------------------------------------------------------------
// ThroughputComparison tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_throughput_comparison_serde_roundtrip() {
    let swar = ThroughputSample::compute(LexerMode::Swar, 1000, 50, 100_000);
    let scalar = ThroughputSample::compute(LexerMode::Scalar, 1000, 50, 300_000);
    let comparison = ThroughputComparison::compute(swar, scalar);
    let json = serde_json::to_string(&comparison).unwrap();
    let back: ThroughputComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(comparison, back);
}

#[test]
fn enrichment_throughput_comparison_clone() {
    let swar = ThroughputSample::compute(LexerMode::Swar, 100, 10, 1000);
    let scalar = ThroughputSample::compute(LexerMode::Scalar, 100, 10, 3000);
    let comparison = ThroughputComparison::compute(swar, scalar);
    let cloned = comparison.clone();
    assert_eq!(comparison, cloned);
}

#[test]
fn enrichment_throughput_comparison_zero_scalar_throughput() {
    let swar = ThroughputSample::compute(LexerMode::Swar, 100, 10, 1000);
    let scalar = ThroughputSample::compute(LexerMode::Scalar, 0, 0, 0);
    let comparison = ThroughputComparison::compute(swar, scalar);
    assert_eq!(comparison.speedup_millionths, 0);
}

#[test]
fn enrichment_throughput_comparison_json_field_names() {
    let swar = ThroughputSample::compute(LexerMode::Swar, 100, 10, 1000);
    let scalar = ThroughputSample::compute(LexerMode::Scalar, 100, 10, 3000);
    let comparison = ThroughputComparison::compute(swar, scalar);
    let json = serde_json::to_string(&comparison).unwrap();
    assert!(json.contains("\"swar\""));
    assert!(json.contains("\"scalar\""));
    assert!(json.contains("\"speedup_millionths\""));
}

// ---------------------------------------------------------------------------
// ArchCapabilityProfile tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_arch_profile_supports_swar_requires_little_endian() {
    let mut profile = profile_for_tests(ArchFamily::X86_64, true, false, false, false);
    assert!(profile.supports_swar());
    profile.little_endian = false;
    assert!(!profile.supports_swar());
}

#[test]
fn enrichment_arch_profile_supports_feature_gate_portable_when_swar_ok() {
    let profile = profile_for_tests(ArchFamily::X86_64, true, false, false, false);
    assert!(profile.supports_feature_gate(SwarFeatureGate::Portable));
}

#[test]
fn enrichment_arch_profile_portable_fails_when_big_endian() {
    let profile = profile_for_tests(ArchFamily::Other, false, false, false, false);
    assert!(!profile.supports_feature_gate(SwarFeatureGate::Portable));
}

#[test]
fn enrichment_arch_profile_avx2_requires_x86_64() {
    let profile = profile_for_tests(ArchFamily::Aarch64, true, true, false, false);
    assert!(!profile.supports_feature_gate(SwarFeatureGate::RequireAvx2));
}

#[test]
fn enrichment_arch_profile_avx512_requires_x86_64() {
    let profile = profile_for_tests(ArchFamily::Aarch64, true, false, true, false);
    assert!(!profile.supports_feature_gate(SwarFeatureGate::RequireAvx512F));
}

#[test]
fn enrichment_arch_profile_neon_requires_arm_family() {
    let profile = profile_for_tests(ArchFamily::X86_64, true, false, false, true);
    assert!(!profile.supports_feature_gate(SwarFeatureGate::RequireNeon));
}

#[test]
fn enrichment_arch_profile_neon_on_arm() {
    let profile = profile_for_tests(ArchFamily::Arm, true, false, false, true);
    assert!(profile.supports_feature_gate(SwarFeatureGate::RequireNeon));
}

#[test]
fn enrichment_arch_profile_neon_on_aarch64() {
    let profile = profile_for_tests(ArchFamily::Aarch64, true, false, false, true);
    assert!(profile.supports_feature_gate(SwarFeatureGate::RequireNeon));
}

#[test]
fn enrichment_arch_profile_avx2_when_available() {
    let profile = profile_for_tests(ArchFamily::X86_64, true, true, false, false);
    assert!(profile.supports_feature_gate(SwarFeatureGate::RequireAvx2));
}

#[test]
fn enrichment_arch_profile_avx512_when_available() {
    let profile = profile_for_tests(ArchFamily::X86_64, true, false, true, false);
    assert!(profile.supports_feature_gate(SwarFeatureGate::RequireAvx512F));
}

#[test]
fn enrichment_arch_profile_clone() {
    let profile = ArchCapabilityProfile::detect();
    let cloned = profile.clone();
    assert_eq!(profile, cloned);
}

#[test]
fn enrichment_arch_profile_json_field_names() {
    let profile = ArchCapabilityProfile::detect();
    let json = serde_json::to_string(&profile).unwrap();
    assert!(json.contains("\"arch_family\""));
    assert!(json.contains("\"swar_width\""));
    assert!(json.contains("\"pointer_width\""));
    assert!(json.contains("\"little_endian\""));
    assert!(json.contains("\"swar_available\""));
    assert!(json.contains("\"avx2_available\""));
    assert!(json.contains("\"avx512f_available\""));
    assert!(json.contains("\"neon_available\""));
}

// ---------------------------------------------------------------------------
// Fallback matrix tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_fallback_matrix_accepts_portable_on_good_profile() {
    let profile = profile_for_tests(ArchFamily::X86_64, true, false, false, false);
    let cfg = LexerConfig {
        feature_gate: SwarFeatureGate::Portable,
        swar_min_input_bytes: 64,
        ..LexerConfig::default()
    };
    let reason = evaluate_swar_fallback_matrix(4096, &cfg, &profile);
    assert!(reason.is_none());
}

#[test]
fn enrichment_fallback_matrix_rejects_below_threshold() {
    let profile = profile_for_tests(ArchFamily::X86_64, true, false, false, false);
    let cfg = LexerConfig {
        feature_gate: SwarFeatureGate::Portable,
        swar_min_input_bytes: 128,
        ..LexerConfig::default()
    };
    let reason = evaluate_swar_fallback_matrix(100, &cfg, &profile).unwrap();
    assert_eq!(
        reason,
        SwarDisableReason::InputBelowThreshold {
            input_len: 100,
            threshold: 128,
        }
    );
}

#[test]
fn enrichment_fallback_matrix_rejects_avx512_on_arm() {
    let profile = profile_for_tests(ArchFamily::Arm, true, false, false, true);
    let cfg = LexerConfig {
        feature_gate: SwarFeatureGate::RequireAvx512F,
        ..LexerConfig::default()
    };
    let reason = evaluate_swar_fallback_matrix(4096, &cfg, &profile).unwrap();
    assert_eq!(
        reason,
        SwarDisableReason::FeatureGateUnavailable {
            required: SwarFeatureGate::RequireAvx512F,
            arch_family: ArchFamily::Arm,
        }
    );
}

#[test]
fn enrichment_fallback_matrix_priority_arch_over_threshold() {
    // Architecture failure should be checked before threshold
    let profile = profile_for_tests(ArchFamily::Other, false, false, false, false);
    let cfg = LexerConfig {
        swar_min_input_bytes: 1000,
        ..LexerConfig::default()
    };
    let reason = evaluate_swar_fallback_matrix(5, &cfg, &profile).unwrap();
    // Should get ArchitectureUnsupported, not InputBelowThreshold
    assert!(matches!(
        reason,
        SwarDisableReason::ArchitectureUnsupported { .. }
    ));
}

// ---------------------------------------------------------------------------
// Lexing edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lex_single_char_identifier() {
    let out = lex("x", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::Identifier);
    assert_eq!(out.tokens[0].span_len(), 1);
}

#[test]
fn enrichment_lex_single_digit() {
    let out = lex("7", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::NumericLiteral);
}

#[test]
fn enrichment_lex_single_punctuation() {
    let out = lex("+", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::Punctuation);
}

#[test]
fn enrichment_lex_consecutive_strings() {
    let out = lex(r#""a""b""c""#, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 3);
    for tok in &out.tokens {
        assert_eq!(tok.kind, TokenKind::StringLiteral);
    }
}

#[test]
fn enrichment_lex_mixed_quote_strings() {
    let out = lex(r#""hello"'world'"#, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
    assert_eq!(out.tokens[0].kind, TokenKind::StringLiteral);
    assert_eq!(out.tokens[1].kind, TokenKind::StringLiteral);
}

#[test]
fn enrichment_lex_escape_at_end_of_string() {
    // backslash at very end of input in a string
    let out = lex("\"hello\\", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::UnterminatedString);
}

#[test]
fn enrichment_lex_backslash_newline_in_string() {
    // escaped newline: \n inside string should not terminate
    let out = lex("\"hello\\nworld\"", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::StringLiteral);
}

#[test]
fn enrichment_lex_arrow_function() {
    let out = lex("(x) => x + 1", &scalar_config()).unwrap();
    // ( x ) => x + 1  = 7 tokens
    assert_eq!(out.token_count, 7);
    assert_eq!(out.tokens[3].kind, TokenKind::TwoCharOperator); // =>
}

#[test]
fn enrichment_lex_nullish_coalescing() {
    let out = lex("a ?? b", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 3);
    assert_eq!(out.tokens[1].kind, TokenKind::TwoCharOperator);
}

#[test]
fn enrichment_lex_adjacent_two_char_operators() {
    // ==!= should be == and !=
    let out = lex("==!=", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
    assert_eq!(out.tokens[0].kind, TokenKind::TwoCharOperator);
    assert_eq!(out.tokens[1].kind, TokenKind::TwoCharOperator);
}

#[test]
fn enrichment_lex_identifier_with_digits_and_dollar() {
    let out = lex("$_abc123$", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 1);
    assert_eq!(out.tokens[0].kind, TokenKind::Identifier);
    assert_eq!(out.tokens[0].span_len(), 9);
}

#[test]
fn enrichment_lex_crlf_between_tokens() {
    let out = lex("a\r\nb\r\nc", &scalar_config()).unwrap();
    assert_eq!(out.token_count, 3);
}

#[test]
fn enrichment_lex_form_feed_is_whitespace() {
    // 0x0C (form feed) is treated as whitespace
    let input = "a\x0Cb";
    let out = lex(input, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
}

#[test]
fn enrichment_lex_vertical_tab_is_whitespace() {
    // 0x0B (vertical tab) is treated as whitespace
    let input = "a\x0Bb";
    let out = lex(input, &scalar_config()).unwrap();
    assert_eq!(out.token_count, 2);
}

// ---------------------------------------------------------------------------
// count_tokens edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_count_tokens_empty() {
    let count = count_tokens("", &scalar_config()).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn enrichment_count_tokens_whitespace_only() {
    let count = count_tokens("   \t\n  ", &scalar_config()).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn enrichment_count_tokens_source_too_large() {
    let cfg = LexerConfig {
        max_source_bytes: 3,
        ..scalar_config()
    };
    let err = count_tokens("hello", &cfg).unwrap_err();
    assert!(matches!(err, LexerError::SourceTooLarge { .. }));
}

#[test]
fn enrichment_count_tokens_matches_lex_swar() {
    let input = "let x = foo(1, 2); if (a && b) { return 'hi'; }";
    let cfg = swar_config_no_threshold();
    let count = count_tokens(input, &cfg).unwrap();
    let out = lex(input, &cfg).unwrap();
    assert_eq!(count, out.token_count);
}

// ---------------------------------------------------------------------------
// emit_tokens false
// ---------------------------------------------------------------------------

#[test]
fn enrichment_emit_tokens_false_swar_mode() {
    let cfg = LexerConfig {
        mode: LexerMode::Swar,
        swar_min_input_bytes: 0,
        emit_tokens: false,
        ..LexerConfig::default()
    };
    let out = lex("a b c d e", &cfg).unwrap();
    assert_eq!(out.token_count, 5);
    assert!(out.tokens.is_empty());
}

#[test]
fn enrichment_emit_tokens_false_still_counts() {
    let cfg = LexerConfig {
        emit_tokens: false,
        ..scalar_config()
    };
    let out = lex("x + 1", &cfg).unwrap();
    assert_eq!(out.token_count, 3);
    assert!(out.tokens.is_empty());
}

// ---------------------------------------------------------------------------
// Differential mode edge cases
// ---------------------------------------------------------------------------

#[test]
fn enrichment_differential_parity_single_token() {
    let result = DifferentialLexer::lex(b"x", &diff_config()).unwrap();
    assert!(result.parity_ok);
    assert_eq!(result.swar_output.token_count, 1);
    assert_eq!(result.scalar_output.token_count, 1);
}

#[test]
fn enrichment_differential_parity_only_operators() {
    let input = b"== != <= >= && || ?? =>";
    let result = DifferentialLexer::lex(input, &diff_config()).unwrap();
    assert!(result.parity_ok);
    assert_eq!(result.swar_output.token_count, 8);
}

#[test]
fn enrichment_differential_parity_long_string_with_escapes() {
    let inner = r#"hello \"world\" foo \'bar\' baz"#;
    let input = format!("\"{}\"", inner);
    let result = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert!(result.parity_ok);
}

#[test]
fn enrichment_differential_parity_mixed_whitespace_types() {
    let input = "a \t b \n c \r d \x0B e \x0C f";
    let result = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert!(result.parity_ok);
    assert_eq!(result.swar_output.token_count, 6);
}

// ---------------------------------------------------------------------------
// LexerArtifact tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lexer_artifact_clone() {
    let output = lex("a", &scalar_config()).unwrap();
    let artifact = LexerArtifact {
        artifact_id: derive_id(
            ObjectDomain::EvidenceRecord,
            "simd-lexer-test",
            &SchemaId::from_definition(b"test-clone"),
            b"test-clone",
        )
        .unwrap(),
        config: scalar_config(),
        output,
        input_hash: "hash".to_string(),
        input_len: 1,
        schema_version: LexerSchemaVersion::V1,
    };
    let cloned = artifact.clone();
    assert_eq!(artifact, cloned);
}

#[test]
fn enrichment_lexer_artifact_json_field_names() {
    let output = lex("x", &scalar_config()).unwrap();
    let artifact = LexerArtifact {
        artifact_id: derive_id(
            ObjectDomain::EvidenceRecord,
            "simd-lexer-test",
            &SchemaId::from_definition(b"test-fields"),
            b"test-fields",
        )
        .unwrap(),
        config: scalar_config(),
        output,
        input_hash: "sha256:abc".to_string(),
        input_len: 1,
        schema_version: LexerSchemaVersion::V1,
    };
    let json = serde_json::to_string(&artifact).unwrap();
    assert!(json.contains("\"artifact_id\""));
    assert!(json.contains("\"config\""));
    assert!(json.contains("\"output\""));
    assert!(json.contains("\"input_hash\""));
    assert!(json.contains("\"input_len\""));
    assert!(json.contains("\"schema_version\""));
}

// ---------------------------------------------------------------------------
// LexerTokenWitnessLog tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_token_witness_log_fields_populated() {
    let input = "var x = 42;";
    let cfg = swar_config_no_threshold();
    let out = lex(input, &cfg).unwrap();
    let log = build_token_witness_log(
        input,
        &cfg,
        &out,
        "trace-001",
        "decision-001",
        "policy-v1",
        "cargo test --test foo",
    );
    assert_eq!(log.schema_version, LexerSchemaVersion::V1);
    assert_eq!(log.trace_id, "trace-001");
    assert_eq!(log.decision_id, "decision-001");
    assert_eq!(log.policy_id, "policy-v1");
    assert_eq!(log.requested_mode, LexerMode::Swar);
    assert_eq!(log.feature_gate, SwarFeatureGate::Portable);
    assert_eq!(log.token_count, out.token_count);
    assert_eq!(log.replay_command, "cargo test --test foo");
}

#[test]
fn enrichment_token_witness_log_different_inputs_different_hashes() {
    let cfg = swar_config_no_threshold();
    let out1 = lex("var x = 1;", &cfg).unwrap();
    let out2 = lex("var y = 2;", &cfg).unwrap();
    let log1 = build_token_witness_log("var x = 1;", &cfg, &out1, "t", "d", "p", "r");
    let log2 = build_token_witness_log("var y = 2;", &cfg, &out2, "t", "d", "p", "r");
    assert_ne!(log1.input_hash, log2.input_hash);
    assert_ne!(log1.token_witness_hash, log2.token_witness_hash);
}

#[test]
fn enrichment_token_witness_log_json_field_names() {
    let cfg = swar_config_no_threshold();
    let out = lex("x", &cfg).unwrap();
    let log = build_token_witness_log("x", &cfg, &out, "t", "d", "p", "r");
    let json = serde_json::to_string(&log).unwrap();
    assert!(json.contains("\"schema_version\""));
    assert!(json.contains("\"trace_id\""));
    assert!(json.contains("\"decision_id\""));
    assert!(json.contains("\"policy_id\""));
    assert!(json.contains("\"requested_mode\""));
    assert!(json.contains("\"actual_mode\""));
    assert!(json.contains("\"feature_gate\""));
    assert!(json.contains("\"swar_disable_reason\""));
    assert!(json.contains("\"arch_profile\""));
    assert!(json.contains("\"input_hash\""));
    assert!(json.contains("\"token_count\""));
    assert!(json.contains("\"token_witness_hash\""));
    assert!(json.contains("\"replay_command\""));
}

// ---------------------------------------------------------------------------
// Determinism across modes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_determinism_differential_mode() {
    let input = "let a = 1 + 2 * 3;";
    let result1 = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    let result2 = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert_eq!(result1, result2);
}

#[test]
fn enrichment_determinism_count_tokens_across_runs() {
    let input = "function f(a, b, c) { return a + b + c; }";
    let c1 = count_tokens(input, &scalar_config()).unwrap();
    let c2 = count_tokens(input, &scalar_config()).unwrap();
    let c3 = count_tokens(input, &swar_config_no_threshold()).unwrap();
    assert_eq!(c1, c2);
    assert_eq!(c1, c3);
}

// ---------------------------------------------------------------------------
// Budget exceeded across modes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scalar_budget_exceeded_boundary() {
    let cfg = LexerConfig {
        max_tokens: 5,
        ..scalar_config()
    };
    let out = lex("a b c d e", &cfg).unwrap();
    assert!(!out.budget_exceeded);
    assert_eq!(out.token_count, 5);
}

#[test]
fn enrichment_scalar_budget_exceeded_one_over() {
    let cfg = LexerConfig {
        max_tokens: 4,
        ..scalar_config()
    };
    let out = lex("a b c d e", &cfg).unwrap();
    assert!(out.budget_exceeded);
    assert_eq!(out.token_count, 4);
}

#[test]
fn enrichment_swar_budget_exceeded_stops_early() {
    let cfg = LexerConfig {
        mode: LexerMode::Swar,
        swar_min_input_bytes: 0,
        max_tokens: 3,
        ..LexerConfig::default()
    };
    let out = lex("a b c d e f g h", &cfg).unwrap();
    assert!(out.budget_exceeded);
    assert_eq!(out.token_count, 3);
    assert!(out.bytes_scanned < 15);
}

// ---------------------------------------------------------------------------
// Source too large across modes
// ---------------------------------------------------------------------------

#[test]
fn enrichment_source_too_large_swar_mode() {
    let cfg = LexerConfig {
        mode: LexerMode::Swar,
        swar_min_input_bytes: 0,
        max_source_bytes: 3,
        ..LexerConfig::default()
    };
    let err = lex("hello world", &cfg).unwrap_err();
    assert!(matches!(
        err,
        LexerError::SourceTooLarge { size: 11, max: 3 }
    ));
}

#[test]
fn enrichment_source_too_large_differential_mode() {
    let cfg = LexerConfig {
        mode: LexerMode::Differential,
        max_source_bytes: 2,
        ..LexerConfig::default()
    };
    let err = lex("hello", &cfg).unwrap_err();
    assert!(matches!(err, LexerError::SourceTooLarge { .. }));
}

// ---------------------------------------------------------------------------
// Token JSON field names
// ---------------------------------------------------------------------------

#[test]
fn enrichment_token_json_field_names() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 5,
    };
    let json = serde_json::to_string(&token).unwrap();
    assert!(json.contains("\"kind\""));
    assert!(json.contains("\"start\""));
    assert!(json.contains("\"end\""));
}

#[test]
fn enrichment_token_serde_roundtrip() {
    let token = Token {
        kind: TokenKind::TwoCharOperator,
        start: 10,
        end: 12,
    };
    let json = serde_json::to_string(&token).unwrap();
    let back: Token = serde_json::from_str(&json).unwrap();
    assert_eq!(token, back);
}

// ---------------------------------------------------------------------------
// Scalar mode sets OperatorOverride
// ---------------------------------------------------------------------------

#[test]
fn enrichment_scalar_mode_sets_operator_override() {
    let out = lex("hello", &scalar_config()).unwrap();
    assert_eq!(
        out.swar_disable_reason,
        Some(SwarDisableReason::OperatorOverride)
    );
    assert_eq!(out.actual_mode, LexerMode::Scalar);
}

// ---------------------------------------------------------------------------
// SWAR mode with no disable reason on adequate input
// ---------------------------------------------------------------------------

#[test]
fn enrichment_swar_mode_no_disable_on_large_input() {
    let input = "a".repeat(200);
    let cfg = swar_config_no_threshold();
    let out = lex(&input, &cfg).unwrap();
    assert_eq!(out.actual_mode, LexerMode::Swar);
    assert!(out.swar_disable_reason.is_none());
}

// ---------------------------------------------------------------------------
// Stress: parity on dense numeric input
// ---------------------------------------------------------------------------

#[test]
fn enrichment_differential_parity_dense_numbers() {
    let mut input = String::new();
    for i in 0..100 {
        input.push_str(&format!("{} ", i));
    }
    let result = DifferentialLexer::lex(input.as_bytes(), &diff_config()).unwrap();
    assert!(result.parity_ok);
    assert_eq!(result.swar_output.token_count, 100);
}
