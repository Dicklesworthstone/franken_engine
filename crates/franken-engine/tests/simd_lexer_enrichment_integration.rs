//! Enrichment integration tests for the `simd_lexer` module.
//!
//! Covers Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Display
//! coverage, Debug nonempty, Default, lexer lifecycle (scalar/SWAR/differential),
//! token classification, error paths, architecture capability, rollback gate,
//! throughput measurement, JSON field-name stability, and determinism.

use std::collections::BTreeSet;

use frankenengine_engine::simd_lexer::{
    ArchCapabilityProfile, ArchFamily, DifferentialLexer, LexerConfig, LexerError, LexerMode,
    LexerOutput, LexerSchemaVersion, ParityMismatch, RollbackGateConfig, RollbackGateResult,
    ScalarLexer, SwarDisableReason, SwarFeatureGate, SwarLexer, ThroughputComparison,
    ThroughputSample, Token, TokenKind, TokenSpanStorage, build_token_witness_log, count_tokens,
    evaluate_rollback_gate, evaluate_swar_fallback_matrix,
};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn default_config() -> LexerConfig {
    LexerConfig::default()
}

fn scalar_config() -> LexerConfig {
    LexerConfig {
        mode: LexerMode::Scalar,
        ..Default::default()
    }
}

// -----------------------------------------------------------------------
// Copy semantics
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_kind_copy() {
    let original = TokenKind::Identifier;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_token_kind_copy_all_variants() {
    for kind in [
        TokenKind::Identifier,
        TokenKind::NumericLiteral,
        TokenKind::StringLiteral,
        TokenKind::UnterminatedString,
        TokenKind::TwoCharOperator,
        TokenKind::Punctuation,
    ] {
        let copied = kind;
        assert_eq!(kind, copied);
    }
}

#[test]
fn enrichment_lexer_mode_copy() {
    let original = LexerMode::Swar;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_swar_feature_gate_copy() {
    let original = SwarFeatureGate::Portable;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_arch_family_copy() {
    let original = ArchFamily::X86_64;
    let copied = original;
    assert_eq!(original, copied);
}

#[test]
fn enrichment_lexer_schema_version_copy() {
    let original = LexerSchemaVersion::V1;
    let copied = original;
    assert_eq!(original, copied);
}

// -----------------------------------------------------------------------
// Clone independence
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_clone_independence() {
    let original = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 5,
    };
    let cloned = original.clone();
    assert_eq!(cloned.kind, TokenKind::Identifier);
    assert_eq!(cloned.end, 5);
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_lexer_config_clone_independence() {
    let original = default_config();
    let cloned = original.clone();
    assert_eq!(cloned.max_tokens, 65_536);
    assert_eq!(cloned.mode, LexerMode::Swar);
    assert_eq!(original, cloned);
}

#[test]
fn enrichment_lexer_output_clone_independence() {
    let output = ScalarLexer::lex(b"let x = 1", &default_config()).unwrap();
    let mut cloned = output.clone();
    cloned.token_count = 999;
    assert_ne!(output.token_count, 999);
}

#[test]
fn enrichment_token_span_storage_clone_independence() {
    let mut original = TokenSpanStorage::with_capacity(4);
    original.push(TokenKind::Identifier, 0, 3);
    let mut cloned = original.clone();
    cloned.push(TokenKind::Punctuation, 3, 4);
    assert_eq!(original.len(), 1);
    assert_eq!(cloned.len(), 2);
}

// -----------------------------------------------------------------------
// BTreeSet ordering and dedup
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_kind_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(TokenKind::Punctuation);
    set.insert(TokenKind::Identifier);
    set.insert(TokenKind::NumericLiteral);
    let items: Vec<_> = set.iter().collect();
    assert!(items[0] <= items[1]);
    assert!(items[1] <= items[2]);
}

#[test]
fn enrichment_token_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(TokenKind::Identifier);
    set.insert(TokenKind::Identifier);
    set.insert(TokenKind::Punctuation);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_lexer_mode_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(LexerMode::Differential);
    set.insert(LexerMode::Swar);
    set.insert(LexerMode::Scalar);
    assert_eq!(set.len(), 3);
}

// -----------------------------------------------------------------------
// Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_kind_serde_all() {
    for kind in [
        TokenKind::Identifier,
        TokenKind::NumericLiteral,
        TokenKind::StringLiteral,
        TokenKind::UnterminatedString,
        TokenKind::TwoCharOperator,
        TokenKind::Punctuation,
    ] {
        let json = serde_json::to_string(&kind).unwrap();
        let restored: TokenKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, restored);
    }
}

#[test]
fn enrichment_lexer_mode_serde_all() {
    for mode in [LexerMode::Swar, LexerMode::Scalar, LexerMode::Differential] {
        let json = serde_json::to_string(&mode).unwrap();
        let restored: LexerMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, restored);
    }
}

#[test]
fn enrichment_swar_feature_gate_serde_all() {
    for gate in [
        SwarFeatureGate::Portable,
        SwarFeatureGate::RequireAvx2,
        SwarFeatureGate::RequireAvx512F,
        SwarFeatureGate::RequireNeon,
    ] {
        let json = serde_json::to_string(&gate).unwrap();
        let restored: SwarFeatureGate = serde_json::from_str(&json).unwrap();
        assert_eq!(gate, restored);
    }
}

#[test]
fn enrichment_arch_family_serde_all() {
    for af in [
        ArchFamily::X86_64,
        ArchFamily::Aarch64,
        ArchFamily::Arm,
        ArchFamily::Other,
    ] {
        let json = serde_json::to_string(&af).unwrap();
        let restored: ArchFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(af, restored);
    }
}

#[test]
fn enrichment_schema_version_serde() {
    let v = LexerSchemaVersion::V1;
    let json = serde_json::to_string(&v).unwrap();
    let restored: LexerSchemaVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(v, restored);
}

#[test]
fn enrichment_token_serde_roundtrip() {
    let token = Token {
        kind: TokenKind::StringLiteral,
        start: 10,
        end: 25,
    };
    let json = serde_json::to_string(&token).unwrap();
    let restored: Token = serde_json::from_str(&json).unwrap();
    assert_eq!(token, restored);
}

#[test]
fn enrichment_lexer_config_serde_roundtrip() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    let restored: LexerConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn enrichment_lexer_output_serde_roundtrip() {
    let output = ScalarLexer::lex(b"x + 1", &default_config()).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let restored: LexerOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output, restored);
}

#[test]
fn enrichment_lexer_error_serde_all() {
    let errors = vec![
        LexerError::SourceTooLarge { size: 100, max: 50 },
        LexerError::TokenBudgetExceeded {
            count: 100,
            max: 50,
        },
        LexerError::InternalError("test".to_string()),
    ];
    for e in &errors {
        let json = serde_json::to_string(e).unwrap();
        let restored: LexerError = serde_json::from_str(&json).unwrap();
        assert_eq!(*e, restored);
    }
}

#[test]
fn enrichment_swar_disable_reason_serde_all() {
    let reasons = [
        SwarDisableReason::OperatorOverride,
        SwarDisableReason::ParityMismatch { mismatch_index: 5 },
        SwarDisableReason::InputBelowThreshold {
            input_len: 10,
            threshold: 64,
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
    for r in &reasons {
        let json = serde_json::to_string(r).unwrap();
        let restored: SwarDisableReason = serde_json::from_str(&json).unwrap();
        assert_eq!(*r, restored);
    }
}

#[test]
fn enrichment_token_span_storage_serde_roundtrip() {
    let mut storage = TokenSpanStorage::with_capacity(2);
    storage.push(TokenKind::Identifier, 0, 3);
    storage.push(TokenKind::Punctuation, 3, 4);
    let json = serde_json::to_string(&storage).unwrap();
    let restored: TokenSpanStorage = serde_json::from_str(&json).unwrap();
    assert_eq!(storage, restored);
}

#[test]
fn enrichment_parity_mismatch_serde_roundtrip() {
    let pm = ParityMismatch {
        token_index: 5,
        swar_token: Some(Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        }),
        scalar_token: Some(Token {
            kind: TokenKind::Punctuation,
            start: 0,
            end: 1,
        }),
        swar_count: 10,
        scalar_count: 11,
    };
    let json = serde_json::to_string(&pm).unwrap();
    let restored: ParityMismatch = serde_json::from_str(&json).unwrap();
    assert_eq!(pm, restored);
}

#[test]
fn enrichment_throughput_sample_serde_roundtrip() {
    let sample = ThroughputSample::compute(LexerMode::Swar, 1000, 50, 100_000);
    let json = serde_json::to_string(&sample).unwrap();
    let restored: ThroughputSample = serde_json::from_str(&json).unwrap();
    assert_eq!(sample, restored);
}

#[test]
fn enrichment_rollback_gate_config_serde_roundtrip() {
    let config = RollbackGateConfig::default();
    let json = serde_json::to_string(&config).unwrap();
    let restored: RollbackGateConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config, restored);
}

#[test]
fn enrichment_rollback_gate_result_serde_roundtrip() {
    let result = evaluate_rollback_gate(0, 2_000_000, 0, &RollbackGateConfig::default());
    let json = serde_json::to_string(&result).unwrap();
    let restored: RollbackGateResult = serde_json::from_str(&json).unwrap();
    assert_eq!(result, restored);
}

#[test]
fn enrichment_arch_capability_profile_serde_roundtrip() {
    let profile = ArchCapabilityProfile::detect();
    let json = serde_json::to_string(&profile).unwrap();
    let restored: ArchCapabilityProfile = serde_json::from_str(&json).unwrap();
    assert_eq!(profile, restored);
}

// -----------------------------------------------------------------------
// Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_kind_display_all_unique() {
    let displays: BTreeSet<String> = [
        TokenKind::Identifier,
        TokenKind::NumericLiteral,
        TokenKind::StringLiteral,
        TokenKind::UnterminatedString,
        TokenKind::TwoCharOperator,
        TokenKind::Punctuation,
    ]
    .iter()
    .map(|k| k.to_string())
    .collect();
    assert_eq!(displays.len(), 6);
}

#[test]
fn enrichment_token_kind_display_specific() {
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
fn enrichment_lexer_mode_display_all() {
    assert_eq!(LexerMode::Swar.to_string(), "SWAR");
    assert_eq!(LexerMode::Scalar.to_string(), "Scalar");
    assert_eq!(LexerMode::Differential.to_string(), "Differential");
}

#[test]
fn enrichment_swar_feature_gate_display_all() {
    assert_eq!(SwarFeatureGate::Portable.to_string(), "portable");
    assert_eq!(SwarFeatureGate::RequireAvx2.to_string(), "require_avx2");
    assert_eq!(
        SwarFeatureGate::RequireAvx512F.to_string(),
        "require_avx512f"
    );
    assert_eq!(SwarFeatureGate::RequireNeon.to_string(), "require_neon");
}

#[test]
fn enrichment_arch_family_display_all() {
    assert_eq!(ArchFamily::X86_64.to_string(), "x86_64");
    assert_eq!(ArchFamily::Aarch64.to_string(), "aarch64");
    assert_eq!(ArchFamily::Arm.to_string(), "arm");
    assert_eq!(ArchFamily::Other.to_string(), "other");
}

#[test]
fn enrichment_schema_version_display() {
    assert_eq!(LexerSchemaVersion::V1.to_string(), "v1");
}

#[test]
fn enrichment_swar_disable_reason_display_all() {
    let reasons = [
        SwarDisableReason::OperatorOverride,
        SwarDisableReason::ParityMismatch { mismatch_index: 5 },
        SwarDisableReason::InputBelowThreshold {
            input_len: 10,
            threshold: 64,
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
    let displays: BTreeSet<String> = reasons.iter().map(|r| r.to_string()).collect();
    assert_eq!(displays.len(), reasons.len());
}

#[test]
fn enrichment_lexer_error_display_all() {
    assert!(
        LexerError::SourceTooLarge { size: 100, max: 50 }
            .to_string()
            .contains("100")
    );
    assert!(
        LexerError::TokenBudgetExceeded {
            count: 100,
            max: 50
        }
        .to_string()
        .contains("100")
    );
    assert!(
        LexerError::InternalError("oops".to_string())
            .to_string()
            .contains("oops")
    );
}

#[test]
fn enrichment_parity_mismatch_display() {
    let pm = ParityMismatch {
        token_index: 5,
        swar_token: None,
        scalar_token: None,
        swar_count: 10,
        scalar_count: 11,
    };
    let display = pm.to_string();
    assert!(display.contains("token 5"));
    assert!(display.contains("swar_count=10"));
    assert!(display.contains("scalar_count=11"));
}

// -----------------------------------------------------------------------
// Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_debug() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 3,
    };
    let dbg = format!("{token:?}");
    assert!(dbg.contains("Token"));
}

#[test]
fn enrichment_lexer_config_debug() {
    let config = default_config();
    let dbg = format!("{config:?}");
    assert!(dbg.contains("LexerConfig"));
}

#[test]
fn enrichment_lexer_output_debug() {
    let output = ScalarLexer::lex(b"x", &default_config()).unwrap();
    let dbg = format!("{output:?}");
    assert!(dbg.contains("LexerOutput"));
}

#[test]
fn enrichment_arch_profile_debug() {
    let profile = ArchCapabilityProfile::detect();
    let dbg = format!("{profile:?}");
    assert!(dbg.contains("ArchCapabilityProfile"));
}

// -----------------------------------------------------------------------
// Default
// -----------------------------------------------------------------------

#[test]
fn enrichment_lexer_config_default() {
    let config = LexerConfig::default();
    assert_eq!(config.mode, LexerMode::Swar);
    assert_eq!(config.max_tokens, 65_536);
    assert_eq!(config.max_source_bytes, 1_048_576);
    assert_eq!(config.swar_min_input_bytes, 64);
    assert_eq!(config.feature_gate, SwarFeatureGate::Portable);
    assert!(config.emit_tokens);
}

#[test]
fn enrichment_rollback_gate_config_default() {
    let config = RollbackGateConfig::default();
    assert_eq!(config.max_parity_mismatches, 0);
    assert_eq!(config.min_speedup_millionths, 1_000_000);
    assert_eq!(config.max_p99_regression_millionths, 500_000);
}

#[test]
fn enrichment_token_span_storage_default() {
    let storage = TokenSpanStorage::default();
    assert!(storage.is_empty());
    assert_eq!(storage.len(), 0);
}

// -----------------------------------------------------------------------
// Token methods
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_span_len() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 5,
        end: 10,
    };
    assert_eq!(token.span_len(), 5);
}

#[test]
fn enrichment_token_span_len_zero() {
    let token = Token {
        kind: TokenKind::Punctuation,
        start: 3,
        end: 3,
    };
    assert_eq!(token.span_len(), 0);
}

#[test]
fn enrichment_token_source_span() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 5,
    };
    let span = token.source_span(1, 0);
    assert_eq!(span.start_offset, 0);
    assert_eq!(span.end_offset, 5);
}

// -----------------------------------------------------------------------
// TokenSpanStorage
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_span_storage_push_and_access() {
    let mut storage = TokenSpanStorage::with_capacity(4);
    storage.push(TokenKind::Identifier, 0, 3);
    storage.push(TokenKind::Punctuation, 3, 4);
    storage.push(TokenKind::NumericLiteral, 5, 8);
    assert_eq!(storage.len(), 3);
    assert!(!storage.is_empty());
    assert_eq!(
        storage.token_kinds(),
        &[
            TokenKind::Identifier,
            TokenKind::Punctuation,
            TokenKind::NumericLiteral
        ]
    );
    assert_eq!(storage.starts(), &[0, 3, 5]);
    assert_eq!(storage.ends(), &[3, 4, 8]);
}

#[test]
fn enrichment_token_span_storage_to_tokens() {
    let mut storage = TokenSpanStorage::with_capacity(2);
    storage.push(TokenKind::Identifier, 0, 3);
    storage.push(TokenKind::Punctuation, 3, 4);
    let tokens = storage.to_tokens();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].kind, TokenKind::Identifier);
    assert_eq!(tokens[1].kind, TokenKind::Punctuation);
}

#[test]
fn enrichment_token_span_storage_from_tokens() {
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
    ];
    let storage = TokenSpanStorage::from_tokens(&tokens);
    assert_eq!(storage.len(), 2);
    assert_eq!(storage.to_tokens(), tokens);
}

#[test]
fn enrichment_token_span_storage_into_tokens() {
    let mut storage = TokenSpanStorage::with_capacity(1);
    storage.push(TokenKind::StringLiteral, 0, 10);
    let tokens = storage.into_tokens();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].kind, TokenKind::StringLiteral);
}

// -----------------------------------------------------------------------
// Scalar lexer
// -----------------------------------------------------------------------

#[test]
fn enrichment_scalar_lex_identifier() {
    let output = ScalarLexer::lex(b"hello", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::Identifier);
    assert_eq!(output.actual_mode, LexerMode::Scalar);
}

#[test]
fn enrichment_scalar_lex_numeric() {
    let output = ScalarLexer::lex(b"12345", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::NumericLiteral);
}

#[test]
fn enrichment_scalar_lex_string_double() {
    let output = ScalarLexer::lex(b"\"hello\"", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::StringLiteral);
}

#[test]
fn enrichment_scalar_lex_string_single() {
    let output = ScalarLexer::lex(b"'hello'", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::StringLiteral);
}

#[test]
fn enrichment_scalar_lex_unterminated_string() {
    let output = ScalarLexer::lex(b"\"hello\n", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::UnterminatedString);
}

#[test]
fn enrichment_scalar_lex_two_char_operators() {
    let output = ScalarLexer::lex(b"== != <= >= && || => ??", &default_config()).unwrap();
    for token in &output.tokens {
        assert_eq!(token.kind, TokenKind::TwoCharOperator);
    }
    assert_eq!(output.token_count, 8);
}

#[test]
fn enrichment_scalar_lex_punctuation() {
    let output = ScalarLexer::lex(b"+ - *", &default_config()).unwrap();
    for token in &output.tokens {
        assert_eq!(token.kind, TokenKind::Punctuation);
    }
}

#[test]
fn enrichment_scalar_lex_mixed() {
    let output = ScalarLexer::lex(b"let x = 42;", &default_config()).unwrap();
    assert_eq!(output.token_count, 5); // let, x, =, 42, ;
    assert_eq!(output.tokens[0].kind, TokenKind::Identifier); // let
    assert_eq!(output.tokens[1].kind, TokenKind::Identifier); // x
    assert_eq!(output.tokens[2].kind, TokenKind::Punctuation); // =
    assert_eq!(output.tokens[3].kind, TokenKind::NumericLiteral); // 42
    assert_eq!(output.tokens[4].kind, TokenKind::Punctuation); // ;
}

#[test]
fn enrichment_scalar_lex_empty() {
    let output = ScalarLexer::lex(b"", &default_config()).unwrap();
    assert_eq!(output.token_count, 0);
    assert!(output.tokens.is_empty());
    assert!(!output.budget_exceeded);
}

#[test]
fn enrichment_scalar_lex_whitespace_only() {
    let output = ScalarLexer::lex(b"   \t\n  ", &default_config()).unwrap();
    assert_eq!(output.token_count, 0);
}

#[test]
fn enrichment_scalar_lex_source_too_large() {
    let config = LexerConfig {
        max_source_bytes: 5,
        ..Default::default()
    };
    let result = ScalarLexer::lex(b"hello world", &config);
    assert!(matches!(result, Err(LexerError::SourceTooLarge { .. })));
}

#[test]
fn enrichment_scalar_lex_token_budget() {
    let config = LexerConfig {
        max_tokens: 2,
        ..Default::default()
    };
    let output = ScalarLexer::lex(b"a b c d e", &config).unwrap();
    assert!(output.budget_exceeded);
    assert_eq!(output.token_count, 2);
}

// -----------------------------------------------------------------------
// SWAR lexer
// -----------------------------------------------------------------------

#[test]
fn enrichment_swar_lex_simple() {
    let output = SwarLexer::lex(b"let x = 42;", &default_config()).unwrap();
    assert_eq!(output.token_count, 5);
    assert_eq!(output.schema_version, LexerSchemaVersion::V1);
}

#[test]
fn enrichment_swar_lex_empty() {
    let output = SwarLexer::lex(b"", &default_config()).unwrap();
    assert_eq!(output.token_count, 0);
}

// -----------------------------------------------------------------------
// Differential lexer
// -----------------------------------------------------------------------

#[test]
fn enrichment_differential_parity_on_simple() {
    let diff = DifferentialLexer::lex(b"let x = 1;", &default_config()).unwrap();
    assert!(diff.parity_ok);
    assert!(diff.mismatch.is_none());
    assert_eq!(diff.swar_output.token_count, diff.scalar_output.token_count);
}

#[test]
fn enrichment_differential_parity_on_string() {
    let diff = DifferentialLexer::lex(b"\"hello world\"", &default_config()).unwrap();
    assert!(diff.parity_ok);
}

#[test]
fn enrichment_differential_parity_on_operators() {
    let diff = DifferentialLexer::lex(b"a == b && c || d", &default_config()).unwrap();
    assert!(diff.parity_ok);
}

// -----------------------------------------------------------------------
// Top-level lex function
// -----------------------------------------------------------------------

#[test]
fn enrichment_lex_scalar_mode() {
    let output = frankenengine_engine::simd_lexer::lex("let x = 1;", &scalar_config()).unwrap();
    assert!(output.swar_disable_reason.is_some());
    assert_eq!(output.token_count, 5);
}

#[test]
fn enrichment_lex_swar_mode() {
    let output = frankenengine_engine::simd_lexer::lex("let x = 1;", &default_config()).unwrap();
    assert_eq!(output.token_count, 5);
}

#[test]
fn enrichment_lex_differential_mode() {
    let config = LexerConfig {
        mode: LexerMode::Differential,
        ..Default::default()
    };
    let output = frankenengine_engine::simd_lexer::lex("let x = 1;", &config).unwrap();
    assert_eq!(output.token_count, 5);
}

// -----------------------------------------------------------------------
// count_tokens
// -----------------------------------------------------------------------

#[test]
fn enrichment_count_tokens_basic() {
    let count = count_tokens("let x = 1;", &default_config()).unwrap();
    assert_eq!(count, 5);
}

#[test]
fn enrichment_count_tokens_empty() {
    let count = count_tokens("", &default_config()).unwrap();
    assert_eq!(count, 0);
}

// -----------------------------------------------------------------------
// Architecture capability profile
// -----------------------------------------------------------------------

#[test]
fn enrichment_arch_profile_detect() {
    let profile = ArchCapabilityProfile::detect();
    assert_eq!(profile.swar_width, 8);
    assert!(profile.swar_available);
}

#[test]
fn enrichment_arch_profile_supports_swar() {
    let profile = ArchCapabilityProfile::detect();
    // On little-endian 64-bit, SWAR should be available
    if profile.little_endian {
        assert!(profile.supports_swar());
    }
}

#[test]
fn enrichment_arch_profile_supports_portable_gate() {
    let profile = ArchCapabilityProfile::detect();
    if profile.supports_swar() {
        assert!(profile.supports_feature_gate(SwarFeatureGate::Portable));
    }
}

// -----------------------------------------------------------------------
// Fallback matrix
// -----------------------------------------------------------------------

#[test]
fn enrichment_fallback_matrix_input_below_threshold() {
    let config = LexerConfig {
        swar_min_input_bytes: 100,
        ..Default::default()
    };
    let profile = ArchCapabilityProfile::detect();
    let reason = evaluate_swar_fallback_matrix(50, &config, &profile);
    if profile.supports_swar() {
        assert!(matches!(
            reason,
            Some(SwarDisableReason::InputBelowThreshold { .. })
        ));
    }
}

#[test]
fn enrichment_fallback_matrix_no_fallback() {
    let config = default_config();
    let profile = ArchCapabilityProfile::detect();
    let reason = evaluate_swar_fallback_matrix(1000, &config, &profile);
    if profile.supports_swar() {
        assert!(reason.is_none());
    }
}

// -----------------------------------------------------------------------
// Rollback gate
// -----------------------------------------------------------------------

#[test]
fn enrichment_rollback_gate_approved() {
    let result = evaluate_rollback_gate(0, 2_000_000, 0, &RollbackGateConfig::default());
    assert!(result.swar_approved);
    assert!(result.disable_reasons.is_empty());
}

#[test]
fn enrichment_rollback_gate_parity_mismatch_fails() {
    let result = evaluate_rollback_gate(1, 2_000_000, 0, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
    assert!(!result.disable_reasons.is_empty());
    assert!(result.disable_reasons[0].contains("parity"));
}

#[test]
fn enrichment_rollback_gate_low_speedup_fails() {
    let result = evaluate_rollback_gate(0, 500_000, 0, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
    assert!(result.disable_reasons.iter().any(|r| r.contains("speedup")));
}

#[test]
fn enrichment_rollback_gate_p99_regression_fails() {
    let result = evaluate_rollback_gate(0, 2_000_000, 600_000, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
    assert!(result.disable_reasons.iter().any(|r| r.contains("p99")));
}

#[test]
fn enrichment_rollback_gate_multiple_failures() {
    let result = evaluate_rollback_gate(5, 100_000, 999_999, &RollbackGateConfig::default());
    assert!(!result.swar_approved);
    assert!(result.disable_reasons.len() >= 2);
}

// -----------------------------------------------------------------------
// Throughput measurement
// -----------------------------------------------------------------------

#[test]
fn enrichment_throughput_sample_compute() {
    let sample = ThroughputSample::compute(LexerMode::Swar, 1000, 50, 100_000);
    assert_eq!(sample.mode, LexerMode::Swar);
    assert_eq!(sample.input_bytes, 1000);
    assert_eq!(sample.token_count, 50);
    assert!(sample.bytes_per_second_millionths > 0);
    assert!(sample.tokens_per_second_millionths > 0);
}

#[test]
fn enrichment_throughput_sample_zero_time() {
    let sample = ThroughputSample::compute(LexerMode::Scalar, 1000, 50, 0);
    assert_eq!(sample.bytes_per_second_millionths, 0);
    assert_eq!(sample.tokens_per_second_millionths, 0);
}

#[test]
fn enrichment_throughput_comparison_compute() {
    let swar = ThroughputSample::compute(LexerMode::Swar, 1000, 50, 50_000);
    let scalar = ThroughputSample::compute(LexerMode::Scalar, 1000, 50, 100_000);
    let comp = ThroughputComparison::compute(swar, scalar);
    // SWAR took half the time → should be ~2x speedup
    assert!(comp.speedup_millionths > 1_000_000);
}

// -----------------------------------------------------------------------
// Witness log
// -----------------------------------------------------------------------

#[test]
fn enrichment_build_token_witness_log() {
    let config = default_config();
    let output = frankenengine_engine::simd_lexer::lex("let x = 1;", &config).unwrap();
    let log = build_token_witness_log(
        "let x = 1;",
        &config,
        &output,
        "trace-1",
        "decision-1",
        "policy-1",
        "cargo test",
    );
    assert_eq!(log.schema_version, LexerSchemaVersion::V1);
    assert_eq!(log.trace_id, "trace-1");
    assert_eq!(log.decision_id, "decision-1");
    assert_eq!(log.policy_id, "policy-1");
    assert_eq!(log.token_count, 5);
    assert!(log.input_hash.starts_with("sha256:"));
    assert!(log.token_witness_hash.starts_with("sha256:"));
}

// -----------------------------------------------------------------------
// JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_token_json_field_names() {
    let token = Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 3,
    };
    let json = serde_json::to_string(&token).unwrap();
    for field in ["kind", "start", "end"] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_lexer_config_json_field_names() {
    let config = default_config();
    let json = serde_json::to_string(&config).unwrap();
    for field in [
        "mode",
        "max_tokens",
        "max_source_bytes",
        "swar_min_input_bytes",
        "feature_gate",
        "emit_tokens",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

#[test]
fn enrichment_lexer_output_json_field_names() {
    let output = ScalarLexer::lex(b"x", &default_config()).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    for field in [
        "actual_mode",
        "token_count",
        "tokens",
        "bytes_scanned",
        "budget_exceeded",
        "schema_version",
    ] {
        assert!(json.contains(field), "JSON missing field: {field}");
    }
}

// -----------------------------------------------------------------------
// Determinism
// -----------------------------------------------------------------------

#[test]
fn enrichment_scalar_lex_deterministic() {
    let input = b"function foo(x, y) { return x + y; }";
    let config = default_config();
    let o1 = ScalarLexer::lex(input, &config).unwrap();
    let o2 = ScalarLexer::lex(input, &config).unwrap();
    assert_eq!(o1, o2);
}

#[test]
fn enrichment_swar_lex_deterministic() {
    let input = b"function foo(x, y) { return x + y; }";
    let config = default_config();
    let o1 = SwarLexer::lex(input, &config).unwrap();
    let o2 = SwarLexer::lex(input, &config).unwrap();
    assert_eq!(o1, o2);
}

#[test]
fn enrichment_count_tokens_deterministic() {
    let config = default_config();
    let c1 = count_tokens("let x = 42;", &config).unwrap();
    let c2 = count_tokens("let x = 42;", &config).unwrap();
    assert_eq!(c1, c2);
}

#[test]
fn enrichment_scalar_swar_parity() {
    let input = b"let x = 42; if (x == 0) { return 'hello'; }";
    let config = default_config();
    let scalar = ScalarLexer::lex(input, &config).unwrap();
    let swar = SwarLexer::lex(input, &config).unwrap();
    assert_eq!(scalar.token_count, swar.token_count);
    assert_eq!(scalar.tokens.len(), swar.tokens.len());
    for (s, w) in scalar.tokens.iter().zip(swar.tokens.iter()) {
        assert_eq!(s.kind, w.kind);
        assert_eq!(s.start, w.start);
        assert_eq!(s.end, w.end);
    }
}

// -----------------------------------------------------------------------
// String with escape sequences
// -----------------------------------------------------------------------

#[test]
fn enrichment_scalar_lex_string_with_escape() {
    let output = ScalarLexer::lex(b"\"he\\\"llo\"", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::StringLiteral);
}

// -----------------------------------------------------------------------
// Identifiers with special start chars
// -----------------------------------------------------------------------

#[test]
fn enrichment_scalar_lex_dollar_identifier() {
    let output = ScalarLexer::lex(b"$foo", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::Identifier);
}

#[test]
fn enrichment_scalar_lex_underscore_identifier() {
    let output = ScalarLexer::lex(b"_bar", &default_config()).unwrap();
    assert_eq!(output.token_count, 1);
    assert_eq!(output.tokens[0].kind, TokenKind::Identifier);
}
