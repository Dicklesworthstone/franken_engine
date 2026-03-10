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
