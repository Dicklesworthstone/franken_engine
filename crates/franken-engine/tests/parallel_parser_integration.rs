#![forbid(unsafe_code)]

//! Integration tests for the `parallel_parser` module.
//!
//! Tests exercise the public API from outside the crate, covering:
//! - Every public enum variant (construction, Display, serde round-trip)
//! - Every public struct (construction, field access, Default, serde round-trip)
//! - Every public method (happy path, error paths, edge cases)
//! - Parallel parsing strategy and chunking behaviour
//! - Error variant coverage and Display formatting
//! - Determinism: same inputs produce same outputs
//! - Cross-concern integration scenarios

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::parallel_parser::{
    self, BackpressureLevel, BackpressureSnapshot, COMPONENT, CancellationRecord,
    CancellationState, ChunkResult, ChunkTiming, DEFAULT_CHUNK_BUDGET_US, DEFAULT_MAX_WORKERS,
    DEFAULT_MERGE_BUFFER_BYTES, DEFAULT_MIN_PARALLEL_BYTES, DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS,
    FailoverDecision, FailoverState, FailoverTrigger, FailoverTriggerClass, FallbackCause,
    MergeWitness, ParallelConfig, ParityResult, ParseError, ParseInput, ParseLogEntry, ParserMode,
    PerformanceReport, RollbackControl, SCHEMA_VERSION, ScheduleDispatch, ScheduleTranscript,
    SerialReason, ThroughputSample, TimeoutPolicy,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::simd_lexer::{LexerConfig, Token, TokenKind};

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn default_config() -> ParallelConfig {
    ParallelConfig::default()
}

fn small_config() -> ParallelConfig {
    ParallelConfig {
        min_parallel_bytes: 10,
        max_workers: 4,
        always_check_parity: true,
        ..default_config()
    }
}

fn make_input<'a>(source: &'a str, config: &'a ParallelConfig) -> ParseInput<'a> {
    ParseInput {
        source,
        trace_id: "integ-trace",
        run_id: "integ-run",
        epoch: SecurityEpoch::from_raw(1),
        config,
    }
}

/// Generate a multi-line JS-like source of roughly `lines` lines.
fn generate_source(lines: usize) -> String {
    let mut s = String::new();
    for i in 0..lines {
        s.push_str(&format!("var x{i} = {i};\n"));
    }
    s
}

fn serde_roundtrip<
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
>(
    value: &T,
) {
    let json = serde_json::to_string(value).expect("serialize");
    let back: T = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(*value, back);
}

// =======================================================================
// 1. Constants
// =======================================================================

#[test]
fn constants_have_expected_values() {
    assert_eq!(COMPONENT, "parallel_parser");
    assert_eq!(SCHEMA_VERSION, "franken-engine.parallel-parser.v1");
    assert_eq!(DEFAULT_MIN_PARALLEL_BYTES, 4096);
    assert_eq!(DEFAULT_MAX_WORKERS, 8);
    assert_eq!(DEFAULT_CHUNK_BUDGET_US, 50_000);
    assert_eq!(DEFAULT_MERGE_BUFFER_BYTES, 1_048_576);
    assert_eq!(DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS, 100_000);
}

// =======================================================================
// 2. ParallelConfig
// =======================================================================

#[test]
fn parallel_config_default_fields() {
    let c = default_config();
    assert_eq!(c.min_parallel_bytes, DEFAULT_MIN_PARALLEL_BYTES);
    assert_eq!(c.max_workers, DEFAULT_MAX_WORKERS);
    assert_eq!(c.chunk_budget_us, DEFAULT_CHUNK_BUDGET_US);
    assert_eq!(c.merge_buffer_bytes, DEFAULT_MERGE_BUFFER_BYTES);
    assert_eq!(
        c.overhead_threshold_millionths,
        DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS
    );
    assert_eq!(c.schedule_seed, 0);
    assert!(c.always_check_parity);
}

#[test]
fn parallel_config_serde_roundtrip() {
    serde_roundtrip(&default_config());
}

#[test]
fn parallel_config_custom_serde_roundtrip() {
    let c = ParallelConfig {
        min_parallel_bytes: 128,
        max_workers: 16,
        chunk_budget_us: 10_000,
        merge_buffer_bytes: 512,
        overhead_threshold_millionths: 50_000,
        schedule_seed: 42,
        lexer_config: LexerConfig::default(),
        always_check_parity: false,
    };
    serde_roundtrip(&c);
}

#[test]
fn parallel_config_equality() {
    let a = default_config();
    let b = default_config();
    assert_eq!(a, b);
}

// =======================================================================
// 3. ParserMode enum
// =======================================================================

#[test]
fn parser_mode_variants_exist() {
    let _ = ParserMode::Serial;
    let _ = ParserMode::Parallel;
}

#[test]
fn parser_mode_display() {
    assert_eq!(ParserMode::Serial.to_string(), "serial");
    assert_eq!(ParserMode::Parallel.to_string(), "parallel");
}

#[test]
fn parser_mode_serde_roundtrip() {
    serde_roundtrip(&ParserMode::Serial);
    serde_roundtrip(&ParserMode::Parallel);
}

#[test]
fn parser_mode_ord() {
    // Derives Ord -- verify both variants are comparable.
    let mut modes = [ParserMode::Parallel, ParserMode::Serial];
    modes.sort();
    assert_eq!(modes[0], ParserMode::Serial);
    assert_eq!(modes[1], ParserMode::Parallel);
}

#[test]
fn parser_mode_clone_copy() {
    let m = ParserMode::Serial;
    let m2 = m;
    assert_eq!(m, m2);
}

// =======================================================================
// 4. SerialReason enum -- all variants, Display, serde
// =======================================================================

#[test]
fn serial_reason_input_below_threshold() {
    let r = SerialReason::InputBelowThreshold {
        input_bytes: 100,
        threshold: 4096,
    };
    let s = r.to_string();
    assert!(s.contains("100B"));
    assert!(s.contains("4096B"));
    serde_roundtrip(&r);
}

#[test]
fn serial_reason_single_worker() {
    let r = SerialReason::SingleWorker;
    assert_eq!(r.to_string(), "single worker configured");
    serde_roundtrip(&r);
}

#[test]
fn serial_reason_no_deterministic_split_points() {
    let r = SerialReason::NoDeterministicSplitPoints;
    assert_eq!(r.to_string(), "no deterministic split points");
    serde_roundtrip(&r);
}

#[test]
fn serial_reason_budget_exhausted() {
    let r = SerialReason::BudgetExhausted { budget_us: 50_000 };
    assert!(r.to_string().contains("50000us"));
    serde_roundtrip(&r);
}

#[test]
fn serial_reason_parity_mismatch() {
    let r = SerialReason::ParityMismatch { mismatch_index: 7 };
    assert!(r.to_string().contains("token 7"));
    serde_roundtrip(&r);
}

#[test]
fn serial_reason_merge_buffer_exceeded() {
    let r = SerialReason::MergeBufferExceeded {
        buffer_bytes: 2_000_000,
        limit: 1_048_576,
    };
    assert!(r.to_string().contains("2000000B"));
    assert!(r.to_string().contains("1048576B"));
    serde_roundtrip(&r);
}

// =======================================================================
// 5. ChunkPlan struct
// =======================================================================

#[test]
fn chunk_plan_serde_roundtrip() {
    let plan = parallel_parser::compute_chunk_plan(b"abc\ndef\n", 2);
    serde_roundtrip(&plan);
}

#[test]
fn chunk_plan_empty_input() {
    let plan = parallel_parser::compute_chunk_plan(b"", 4);
    assert!(plan.chunks.is_empty());
    assert_eq!(plan.worker_count, 1);
}

#[test]
fn chunk_plan_single_worker() {
    let plan = parallel_parser::compute_chunk_plan(b"hello world", 1);
    assert_eq!(plan.chunks.len(), 1);
    assert_eq!(plan.chunks[0], (0, 11));
    assert_eq!(plan.worker_count, 1);
}

#[test]
fn chunk_plan_two_workers_newline_alignment() {
    let input = b"line one\nline two\nline three\n";
    let plan = parallel_parser::compute_chunk_plan(input, 2);
    assert_eq!(plan.chunks.len(), 2);
    // First chunk must end at a newline.
    let (_, end) = plan.chunks[0];
    assert!(end > 0);
    assert_eq!(input[end as usize - 1], b'\n');
    // Second chunk starts where first ended and goes to the end.
    assert_eq!(plan.chunks[1].0, end);
    assert_eq!(plan.chunks[1].1, input.len() as u64);
}

#[test]
fn chunk_plan_covers_entire_input() {
    let input = b"line1\nline2\nline3\nline4\nline5\n";
    let plan = parallel_parser::compute_chunk_plan(input, 3);
    assert_eq!(plan.chunks.first().unwrap().0, 0);
    assert_eq!(plan.chunks.last().unwrap().1, input.len() as u64);
    // Chunks are contiguous.
    for w in plan.chunks.windows(2) {
        assert_eq!(w[0].1, w[1].0);
    }
}

#[test]
fn chunk_plan_deterministic_same_input() {
    let input = b"a\nb\nc\nd\ne\n";
    let p1 = parallel_parser::compute_chunk_plan(input, 3);
    let p2 = parallel_parser::compute_chunk_plan(input, 3);
    assert_eq!(p1.chunks, p2.chunks);
    assert_eq!(p1.plan_hash, p2.plan_hash);
}

#[test]
fn chunk_plan_no_newlines() {
    let input = b"abcdefghij";
    let plan = parallel_parser::compute_chunk_plan(input, 2);
    assert_eq!(plan.chunks.len(), 1);
    assert_eq!(plan.chunks.last().unwrap().1, 10);
}

#[test]
fn chunk_plan_prefers_low_depth_boundaries() {
    let source =
        b"function outer() {\n  if (x) {\n    return y;\n  }\n}\nconst z = 1;\nconst q = 2;\n";
    let plan = parallel_parser::compute_chunk_plan(source, 2);
    assert_eq!(plan.chunks.len(), 2);

    let split = plan.chunks[0].1 as usize;
    let first_chunk = std::str::from_utf8(&source[..split]).unwrap();
    assert!(
        first_chunk.contains("}\n"),
        "expected split on or after a low-depth block boundary, got: {first_chunk:?}"
    );
}

#[test]
fn chunk_plan_worker_count_capped_by_input_length() {
    let input = b"a\nb\nc\n";
    let plan = parallel_parser::compute_chunk_plan(input, 100);
    assert!(plan.worker_count <= input.len() as u32);
}

#[test]
fn chunk_plan_hash_differs_for_different_inputs() {
    let p1 = parallel_parser::compute_chunk_plan(b"a\nbcdefghijk\n", 2);
    let p2 = parallel_parser::compute_chunk_plan(b"abcdefghij\nk\n", 2);
    assert_ne!(p1.plan_hash, p2.plan_hash);
}

#[test]
fn chunk_plan_boundaries_aligned_to_newlines() {
    let input = b"first line\nsecond line\nthird line\nfourth line\n";
    let plan = parallel_parser::compute_chunk_plan(input, 2);
    for &(_, end) in plan.chunks.iter().take(plan.chunks.len().saturating_sub(1)) {
        assert_eq!(input[end as usize - 1], b'\n');
    }
}

#[test]
fn chunk_plan_sparse_utf8_boundary_falls_back_to_single_chunk() {
    let source = format!("{}\n", "é".repeat(6));
    let plan = parallel_parser::compute_chunk_plan(source.as_bytes(), 3);
    assert_eq!(plan.worker_count, 1);
    assert_eq!(plan.chunks, vec![(0, source.len() as u64)]);
}

#[test]
fn chunk_plan_one_byte_input() {
    let plan = parallel_parser::compute_chunk_plan(b"x", 4);
    assert!(!plan.chunks.is_empty());
    assert_eq!(plan.chunks[0], (0, 1));
}

#[test]
fn chunk_plan_more_workers_than_bytes() {
    let plan = parallel_parser::compute_chunk_plan(b"ab", 10);
    assert!(!plan.chunks.is_empty());
    assert!(plan.worker_count <= 2);
}

// =======================================================================
// 6. ChunkResult struct
// =======================================================================

#[test]
fn chunk_result_construction_and_serde() {
    let cr = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 10,
        tokens: vec![Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        }],
        token_count: 1,
    };
    assert_eq!(cr.chunk_index, 0);
    assert_eq!(cr.token_count, 1);
    serde_roundtrip(&cr);
}

#[test]
fn chunk_result_empty_tokens() {
    let cr = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 5,
        tokens: vec![],
        token_count: 0,
    };
    serde_roundtrip(&cr);
}

// =======================================================================
// 7. merge_chunks
// =======================================================================

#[test]
fn merge_chunks_empty() {
    let merged = parallel_parser::merge_chunks(&[]);
    assert!(merged.is_empty());
}

#[test]
fn merge_chunks_single() {
    let chunk = ChunkResult {
        chunk_index: 0,
        chunk_start: 10,
        chunk_end: 20,
        tokens: vec![Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        }],
        token_count: 1,
    };
    let merged = parallel_parser::merge_chunks(&[chunk]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].start, 10); // offset adjusted
    assert_eq!(merged[0].end, 13);
}

#[test]
fn merge_chunks_preserves_order_by_start() {
    let c1 = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 10,
        tokens: vec![Token {
            kind: TokenKind::Identifier,
            start: 5,
            end: 8,
        }],
        token_count: 1,
    };
    let c2 = ChunkResult {
        chunk_index: 1,
        chunk_start: 10,
        chunk_end: 20,
        tokens: vec![Token {
            kind: TokenKind::NumericLiteral,
            start: 0,
            end: 3,
        }],
        token_count: 1,
    };
    let merged = parallel_parser::merge_chunks(&[c1, c2]);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0].start, 5);
    assert_eq!(merged[1].start, 10);
}

#[test]
fn merge_chunks_multiple_tokens_per_chunk() {
    let c1 = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 10,
        tokens: vec![
            Token {
                kind: TokenKind::Identifier,
                start: 0,
                end: 2,
            },
            Token {
                kind: TokenKind::Punctuation,
                start: 3,
                end: 4,
            },
        ],
        token_count: 2,
    };
    let c2 = ChunkResult {
        chunk_index: 1,
        chunk_start: 10,
        chunk_end: 20,
        tokens: vec![Token {
            kind: TokenKind::NumericLiteral,
            start: 0,
            end: 1,
        }],
        token_count: 1,
    };
    let merged = parallel_parser::merge_chunks(&[c1, c2]);
    assert_eq!(merged.len(), 3);
    // Sorted by start offset.
    assert!(merged[0].start <= merged[1].start);
    assert!(merged[1].start <= merged[2].start);
}

#[test]
fn merge_chunks_independent_of_chunk_iteration_order() {
    let c0 = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 10,
        tokens: vec![
            Token {
                kind: TokenKind::Identifier,
                start: 0,
                end: 1,
            },
            Token {
                kind: TokenKind::Punctuation,
                start: 1,
                end: 2,
            },
        ],
        token_count: 2,
    };
    let c1 = ChunkResult {
        chunk_index: 1,
        chunk_start: 10,
        chunk_end: 20,
        tokens: vec![
            Token {
                kind: TokenKind::Identifier,
                start: 0,
                end: 1,
            },
            Token {
                kind: TokenKind::Punctuation,
                start: 1,
                end: 2,
            },
        ],
        token_count: 2,
    };

    let ordered = parallel_parser::merge_chunks(&[c0.clone(), c1.clone()]);
    let reversed = parallel_parser::merge_chunks(&[c1, c0]);
    assert_eq!(ordered, reversed);
}

#[test]
fn merge_chunks_empty_token_lists() {
    let c1 = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 5,
        tokens: vec![],
        token_count: 0,
    };
    let c2 = ChunkResult {
        chunk_index: 1,
        chunk_start: 5,
        chunk_end: 10,
        tokens: vec![],
        token_count: 0,
    };
    let merged = parallel_parser::merge_chunks(&[c1, c2]);
    assert!(merged.is_empty());
}

// =======================================================================
// 8. repair_boundary_tokens
// =======================================================================

#[test]
fn repair_empty() {
    let mut tokens: Vec<Token> = vec![];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert!(tokens.is_empty());
}

#[test]
fn repair_single_token() {
    let mut tokens = vec![Token {
        kind: TokenKind::Identifier,
        start: 0,
        end: 5,
    }];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 1);
}

#[test]
fn repair_no_overlap() {
    let mut tokens = vec![
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
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 2);
}

#[test]
fn repair_overlapping_same_kind_merges() {
    let mut tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 5,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 3,
            end: 8,
        },
    ];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].start, 0);
    assert_eq!(tokens[0].end, 8);
}

#[test]
fn repair_contiguous_same_kind_merges() {
    let mut tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 5,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 5,
            end: 10,
        },
    ];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].end, 10);
}

#[test]
fn repair_overlapping_different_kind_not_merged() {
    let mut tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 5,
        },
        Token {
            kind: TokenKind::Punctuation,
            start: 3,
            end: 8,
        },
    ];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 2);
}

#[test]
fn repair_multiple_consecutive_merges() {
    let mut tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 5,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 4,
            end: 10,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 9,
            end: 15,
        },
        Token {
            kind: TokenKind::Punctuation,
            start: 16,
            end: 17,
        },
    ];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].kind, TokenKind::Identifier);
    assert_eq!(tokens[0].start, 0);
    assert_eq!(tokens[0].end, 15);
    assert_eq!(tokens[1].kind, TokenKind::Punctuation);
}

#[test]
fn repair_alternating_kinds_no_merge() {
    let mut tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        },
        Token {
            kind: TokenKind::Punctuation,
            start: 3,
            end: 4,
        },
        Token {
            kind: TokenKind::NumericLiteral,
            start: 4,
            end: 7,
        },
    ];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 3);
}

// =======================================================================
// 9. MergeWitness struct
// =======================================================================

#[test]
fn merge_witness_serde_roundtrip() {
    let w = MergeWitness {
        merged_hash: ContentHash::compute(b"tokens"),
        witness_hash: ContentHash::compute(b"merge-witness"),
        chunk_count: 3,
        boundary_repairs: 1,
        total_tokens: 42,
    };
    serde_roundtrip(&w);
}

#[test]
fn merge_witness_from_parallel_parse() {
    let source = generate_source(100);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    if output.mode == ParserMode::Parallel {
        let mw = output.merge_witness.as_ref().unwrap();
        assert!(mw.chunk_count > 1);
        assert!(mw.total_tokens > 0);
    }
}

// =======================================================================
// 10. ScheduleTranscript struct
// =======================================================================

#[test]
fn schedule_transcript_serde_roundtrip() {
    let t = ScheduleTranscript {
        seed: 42,
        worker_count: 4,
        plan_hash: ContentHash::compute(b"plan"),
        execution_order: vec![0, 1, 2, 3],
        dispatches: vec![
            ScheduleDispatch {
                step_index: 0,
                chunk_index: 0,
                worker_slot: 0,
            },
            ScheduleDispatch {
                step_index: 1,
                chunk_index: 1,
                worker_slot: 1,
            },
            ScheduleDispatch {
                step_index: 2,
                chunk_index: 2,
                worker_slot: 2,
            },
            ScheduleDispatch {
                step_index: 3,
                chunk_index: 3,
                worker_slot: 3,
            },
        ],
        transcript_hash: ContentHash::compute(b"transcript"),
    };
    serde_roundtrip(&t);
}

#[test]
fn schedule_transcript_empty_order() {
    let t = ScheduleTranscript {
        seed: 0,
        worker_count: 0,
        plan_hash: ContentHash::compute(b""),
        execution_order: vec![],
        dispatches: vec![],
        transcript_hash: ContentHash::compute(b""),
    };
    serde_roundtrip(&t);
}

#[test]
fn schedule_transcript_plan_hash_matches_chunk_plan() {
    let source = generate_source(100);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    if let (Some(plan), Some(transcript)) = (&output.chunk_plan, &output.schedule_transcript) {
        assert_eq!(plan.plan_hash, transcript.plan_hash);
    }
}

#[test]
fn schedule_transcript_seed_matches_config() {
    let source = generate_source(100);
    let config = ParallelConfig {
        schedule_seed: 12345,
        ..small_config()
    };
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let transcript = output
        .schedule_transcript
        .as_ref()
        .expect("schedule_transcript should be present for parallel parse");
    assert_eq!(transcript.seed, 12345);
}

#[test]
fn schedule_transcript_replay_matches_execution_order() {
    let source = generate_source(120);
    let config = small_config();
    let output = parallel_parser::parse(&make_input(&source, &config)).unwrap();
    if let (Some(plan), Some(transcript)) = (&output.chunk_plan, &output.schedule_transcript) {
        let replay_order = parallel_parser::replay_schedule_transcript(transcript, plan).unwrap();
        assert_eq!(replay_order, transcript.execution_order);
    }
}

#[test]
fn schedule_transcript_dispatches_align_with_execution_order() {
    let source = generate_source(120);
    let config = small_config();
    let output = parallel_parser::parse(&make_input(&source, &config)).unwrap();
    if let Some(transcript) = &output.schedule_transcript {
        assert_eq!(
            transcript.dispatches.len(),
            transcript.execution_order.len()
        );
        for (step_index, chunk_index) in transcript.execution_order.iter().enumerate() {
            let dispatch = &transcript.dispatches[step_index];
            assert_eq!(dispatch.step_index, step_index as u32);
            assert_eq!(dispatch.chunk_index, *chunk_index);
            assert!(dispatch.worker_slot < transcript.worker_count);
        }
    }
}

#[test]
fn schedule_transcript_hash_deterministic_across_repeated_runs() {
    let source = generate_source(150);
    let config = ParallelConfig {
        schedule_seed: 77,
        ..small_config()
    };
    let o1 = parallel_parser::parse(&make_input(&source, &config)).unwrap();
    let o2 = parallel_parser::parse(&make_input(&source, &config)).unwrap();
    if let (Some(t1), Some(t2)) = (&o1.schedule_transcript, &o2.schedule_transcript) {
        assert_eq!(t1.transcript_hash, t2.transcript_hash);
        assert_eq!(t1.execution_order, t2.execution_order);
    }
}

#[test]
fn schedule_transcript_hash_changes_with_seed() {
    let source = generate_source(150);
    let c1 = ParallelConfig {
        schedule_seed: 11,
        ..small_config()
    };
    let c2 = ParallelConfig {
        schedule_seed: 29,
        ..small_config()
    };
    let o1 = parallel_parser::parse(&make_input(&source, &c1)).unwrap();
    let o2 = parallel_parser::parse(&make_input(&source, &c2)).unwrap();
    if let (Some(t1), Some(t2)) = (&o1.schedule_transcript, &o2.schedule_transcript) {
        assert_ne!(t1.transcript_hash, t2.transcript_hash);
    }
}

// =======================================================================
// 11. ParityResult struct
// =======================================================================

#[test]
fn parity_result_ok_serde() {
    let p = ParityResult {
        parity_ok: true,
        mismatch_index: None,
        parallel_count: 100,
        serial_count: 100,
    };
    serde_roundtrip(&p);
}

#[test]
fn parity_result_mismatch_serde() {
    let p = ParityResult {
        parity_ok: false,
        mismatch_index: Some(42),
        parallel_count: 100,
        serial_count: 99,
    };
    serde_roundtrip(&p);
    assert!(!p.parity_ok);
    assert_eq!(p.mismatch_index, Some(42));
}

#[test]
fn parity_check_passes_on_parallel_parse() {
    let source = generate_source(100);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    // Parity result may not be populated for small serial parses
    if let Some(ref pr) = output.parity_result {
        assert!(pr.parity_ok, "parity check should pass");
        assert_eq!(pr.mismatch_index, None, "no mismatch expected");
    }
}

#[test]
fn parse_utf8_sparse_boundary_matches_serial_without_forced_parity() {
    let source = format!("{}\n", "é".repeat(6));
    let serial_config = ParallelConfig {
        min_parallel_bytes: 1,
        max_workers: 1,
        always_check_parity: false,
        ..default_config()
    };
    let parallel_config = ParallelConfig {
        min_parallel_bytes: 1,
        max_workers: 3,
        always_check_parity: false,
        ..default_config()
    };

    let serial_output = parallel_parser::parse(&make_input(&source, &serial_config)).unwrap();
    let parallel_output = parallel_parser::parse(&make_input(&source, &parallel_config)).unwrap();

    assert_eq!(parallel_output.output_hash, serial_output.output_hash);
    assert_eq!(parallel_output.tokens, serial_output.tokens);
}

// =======================================================================
// 12. FallbackCause enum -- all variants, Display, serde
// =======================================================================

#[test]
fn fallback_cause_routing() {
    let c = FallbackCause::Routing(SerialReason::SingleWorker);
    assert!(c.to_string().contains("routing"));
    serde_roundtrip(&c);
}

#[test]
fn fallback_cause_parity_failure() {
    let c = FallbackCause::ParityFailure { mismatch_index: 7 };
    let s = c.to_string();
    assert!(s.contains("parity failure"));
    assert!(s.contains("7"));
    serde_roundtrip(&c);
}

#[test]
fn fallback_cause_resource_limit() {
    let c = FallbackCause::ResourceLimit(SerialReason::BudgetExhausted { budget_us: 10_000 });
    assert!(c.to_string().contains("resource limit"));
    serde_roundtrip(&c);
}

#[test]
fn fallback_cause_routing_with_input_below_threshold() {
    let c = FallbackCause::Routing(SerialReason::InputBelowThreshold {
        input_bytes: 50,
        threshold: 4096,
    });
    let s = c.to_string();
    assert!(s.contains("routing"));
    assert!(s.contains("50B"));
    serde_roundtrip(&c);
}

#[test]
fn fallback_cause_resource_limit_merge_buffer() {
    let c = FallbackCause::ResourceLimit(SerialReason::MergeBufferExceeded {
        buffer_bytes: 2_000_000,
        limit: 1_000_000,
    });
    assert!(c.to_string().contains("resource limit"));
    serde_roundtrip(&c);
}

#[test]
fn fallback_cause_transcript_divergence() {
    let c = FallbackCause::TranscriptDivergence {
        detail: "plan hash mismatch".to_string(),
    };
    assert!(c.to_string().contains("transcript divergence"));
    serde_roundtrip(&c);
}

#[test]
fn failover_trigger_class_display() {
    assert_eq!(FailoverTriggerClass::Timeout.to_string(), "timeout");
    assert_eq!(
        FailoverTriggerClass::TranscriptDivergence.to_string(),
        "transcript-divergence"
    );
    assert_eq!(
        FailoverTriggerClass::SafetyPolicyViolation.to_string(),
        "safety-policy-violation"
    );
}

#[test]
fn failover_decision_serde_roundtrip() {
    let decision = FailoverDecision {
        trigger: FailoverTrigger {
            class: FailoverTriggerClass::ResourceLimit,
            detail: "merge buffer exceeded".to_string(),
        },
        transition_path: vec![
            FailoverState::ParallelAttempted,
            FailoverState::TriggerClassified,
            FailoverState::SerialFallbackRequested,
            FailoverState::SerialFallbackCompleted,
        ],
        witness_ids: vec![
            "schedule_transcript:abc".to_string(),
            "merge_witness:def".to_string(),
            "output_hash:ghi".to_string(),
        ],
        replay_command:
            "franken-engine parallel-parse --trace-id t --run-id r --seed 1 --workers 4".to_string(),
    };
    serde_roundtrip(&decision);
}

// =======================================================================
// 13. TimeoutPolicy
// =======================================================================

#[test]
fn timeout_policy_default() {
    let tp = TimeoutPolicy::default();
    assert_eq!(tp.max_total_us, 500_000);
    assert_eq!(tp.max_chunk_us, 100_000);
    assert!(tp.allow_drain);
}

#[test]
fn timeout_policy_serde_roundtrip() {
    serde_roundtrip(&TimeoutPolicy::default());
    let custom = TimeoutPolicy {
        max_total_us: 1_000_000,
        max_chunk_us: 200_000,
        allow_drain: false,
    };
    serde_roundtrip(&custom);
}

// =======================================================================
// 14. CancellationState enum
// =======================================================================

#[test]
fn cancellation_state_all_variants_display() {
    assert_eq!(CancellationState::None.to_string(), "none");
    assert_eq!(CancellationState::Requested.to_string(), "requested");
    assert_eq!(CancellationState::Draining.to_string(), "draining");
    assert_eq!(CancellationState::Finalized.to_string(), "finalized");
}

#[test]
fn cancellation_state_ordering() {
    assert!(CancellationState::None < CancellationState::Requested);
    assert!(CancellationState::Requested < CancellationState::Draining);
    assert!(CancellationState::Draining < CancellationState::Finalized);
}

#[test]
fn cancellation_state_serde_roundtrip() {
    serde_roundtrip(&CancellationState::None);
    serde_roundtrip(&CancellationState::Requested);
    serde_roundtrip(&CancellationState::Draining);
    serde_roundtrip(&CancellationState::Finalized);
}

// =======================================================================
// 15. CancellationRecord struct
// =======================================================================

#[test]
fn cancellation_record_with_trigger_chunk() {
    let cr = CancellationRecord {
        state: CancellationState::Finalized,
        elapsed_us: 42_000,
        trigger_chunk: Some(2),
        drain_completed: true,
    };
    serde_roundtrip(&cr);
}

#[test]
fn cancellation_record_without_trigger_chunk() {
    let cr = CancellationRecord {
        state: CancellationState::Requested,
        elapsed_us: 500_000,
        trigger_chunk: None,
        drain_completed: false,
    };
    let json = serde_json::to_string(&cr).unwrap();
    assert!(json.contains("\"trigger_chunk\":null"));
    serde_roundtrip(&cr);
}

// =======================================================================
// 16. BackpressureLevel enum
// =======================================================================

#[test]
fn backpressure_level_all_variants_display() {
    assert_eq!(BackpressureLevel::Normal.to_string(), "normal");
    assert_eq!(BackpressureLevel::Elevated.to_string(), "elevated");
    assert_eq!(BackpressureLevel::Critical.to_string(), "critical");
}

#[test]
fn backpressure_level_ordering() {
    assert!(BackpressureLevel::Normal < BackpressureLevel::Elevated);
    assert!(BackpressureLevel::Elevated < BackpressureLevel::Critical);
}

#[test]
fn backpressure_level_serde_roundtrip() {
    serde_roundtrip(&BackpressureLevel::Normal);
    serde_roundtrip(&BackpressureLevel::Elevated);
    serde_roundtrip(&BackpressureLevel::Critical);
}

// =======================================================================
// 17. BackpressureSnapshot struct
// =======================================================================

#[test]
fn backpressure_snapshot_serde_roundtrip() {
    let bp = BackpressureSnapshot {
        queue_depth: 3,
        peak_queue_depth: 5,
        level: BackpressureLevel::Elevated,
        delayed_chunks: 2,
        total_delay_us: 15_000,
    };
    serde_roundtrip(&bp);
}

#[test]
fn backpressure_snapshot_zero_state() {
    let bp = BackpressureSnapshot {
        queue_depth: 0,
        peak_queue_depth: 0,
        level: BackpressureLevel::Normal,
        delayed_chunks: 0,
        total_delay_us: 0,
    };
    assert_eq!(bp.total_delay_us, 0);
    assert_eq!(bp.level, BackpressureLevel::Normal);
    serde_roundtrip(&bp);
}

#[test]
fn backpressure_snapshot_critical_level() {
    let bp = BackpressureSnapshot {
        queue_depth: 10,
        peak_queue_depth: 15,
        level: BackpressureLevel::Critical,
        delayed_chunks: 8,
        total_delay_us: 100_000,
    };
    assert_eq!(bp.level, BackpressureLevel::Critical);
    serde_roundtrip(&bp);
}

// =======================================================================
// 18. RoutingDigest struct
// =======================================================================

#[test]
fn routing_digest_serial_small_input() {
    let config = default_config();
    let d = parallel_parser::compute_routing_digest("x = 1", &config);
    assert_eq!(d.decision, ParserMode::Serial);
    assert_eq!(d.effective_workers, 1);
    assert!(d.rationale.contains("below threshold"));
    serde_roundtrip(&d);
}

#[test]
fn routing_digest_serial_single_worker() {
    let config = ParallelConfig {
        max_workers: 1,
        ..default_config()
    };
    let d = parallel_parser::compute_routing_digest("x\ny\n", &config);
    assert_eq!(d.decision, ParserMode::Serial);
    assert!(d.rationale.contains("single worker"));
}

#[test]
fn routing_digest_serial_no_newlines() {
    let config = ParallelConfig {
        min_parallel_bytes: 5,
        max_workers: 4,
        ..default_config()
    };
    let d = parallel_parser::compute_routing_digest("abcdefghijklmnop", &config);
    assert_eq!(d.decision, ParserMode::Serial);
    assert!(!d.has_partition_points);
    assert!(d.rationale.contains("no deterministic split points"));
}

#[test]
fn routing_digest_parallel_large_input() {
    let config = small_config();
    let source = generate_source(50);
    let d = parallel_parser::compute_routing_digest(&source, &config);
    assert_eq!(d.decision, ParserMode::Parallel);
    assert!(d.effective_workers > 1);
    assert!(d.has_partition_points);
}

#[test]
fn routing_digest_overhead_decreases_with_size() {
    let config = ParallelConfig {
        min_parallel_bytes: 10,
        max_workers: 4,
        ..default_config()
    };
    let small_src = "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\nk\n";
    let d_small = parallel_parser::compute_routing_digest(small_src, &config);
    let large_src = generate_source(200);
    let d_large = parallel_parser::compute_routing_digest(&large_src, &config);
    assert!(d_small.estimated_overhead_millionths >= d_large.estimated_overhead_millionths);
}

#[test]
fn routing_digest_empty_input() {
    let config = default_config();
    let d = parallel_parser::compute_routing_digest("", &config);
    assert_eq!(d.input_bytes, 0);
    assert_eq!(d.decision, ParserMode::Serial);
    assert_eq!(d.effective_workers, 1);
}

// =======================================================================
// 19. ThroughputSample
// =======================================================================

#[test]
fn throughput_sample_zero_elapsed() {
    let s = ThroughputSample::compute(1000, 50, 0);
    assert_eq!(s.bytes_per_sec_millionths, 0);
    assert_eq!(s.tokens_per_sec_millionths, 0);
    assert_eq!(s.bytes, 1000);
    assert_eq!(s.tokens, 50);
    assert_eq!(s.elapsed_us, 0);
}

#[test]
fn throughput_sample_normal() {
    let s = ThroughputSample::compute(1000, 50, 1000);
    assert!(s.bytes_per_sec_millionths > 0);
    assert!(s.tokens_per_sec_millionths > 0);
}

#[test]
fn throughput_sample_proportional() {
    let s1 = ThroughputSample::compute(1000, 50, 1000);
    let s2 = ThroughputSample::compute(2000, 100, 1000);
    assert!(s2.bytes_per_sec_millionths > s1.bytes_per_sec_millionths);
    assert!(s2.tokens_per_sec_millionths > s1.tokens_per_sec_millionths);
}

#[test]
fn throughput_sample_serde_roundtrip() {
    serde_roundtrip(&ThroughputSample::compute(500, 25, 2000));
}

#[test]
fn throughput_sample_large_values_no_overflow() {
    // Very large input with very short time to stress checked arithmetic.
    let s = ThroughputSample::compute(u64::MAX / 2, u64::MAX / 2, 1);
    // Should not panic; overflow handled gracefully via checked_mul/checked_div.
    let _ = s.bytes_per_sec_millionths;
}

#[test]
fn throughput_sample_all_zero() {
    let s = ThroughputSample::compute(0, 0, 0);
    assert_eq!(s.bytes_per_sec_millionths, 0);
    assert_eq!(s.tokens_per_sec_millionths, 0);
}

// =======================================================================
// 20. ChunkTiming struct
// =======================================================================

#[test]
fn chunk_timing_serde_roundtrip() {
    let ct = ChunkTiming {
        chunk_index: 2,
        chunk_bytes: 1024,
        token_count: 50,
        elapsed_us: 3500,
    };
    serde_roundtrip(&ct);
}

// =======================================================================
// 21. PerformanceReport struct
// =======================================================================

#[test]
fn performance_report_serde_roundtrip() {
    let report = PerformanceReport {
        throughput: ThroughputSample::compute(1000, 50, 2000),
        chunk_timings: vec![
            ChunkTiming {
                chunk_index: 0,
                chunk_bytes: 500,
                token_count: 25,
                elapsed_us: 1000,
            },
            ChunkTiming {
                chunk_index: 1,
                chunk_bytes: 500,
                token_count: 25,
                elapsed_us: 1000,
            },
        ],
        merge_elapsed_us: 200,
        parity_check_elapsed_us: 300,
    };
    serde_roundtrip(&report);
}

#[test]
fn performance_report_empty_timings() {
    let report = PerformanceReport {
        throughput: ThroughputSample::compute(0, 0, 0),
        chunk_timings: vec![],
        merge_elapsed_us: 0,
        parity_check_elapsed_us: 0,
    };
    serde_roundtrip(&report);
}

// =======================================================================
// 22. ParseError enum -- all variants, Display, serde
// =======================================================================

#[test]
fn parse_error_lexer_error() {
    let e = ParseError::LexerError {
        chunk_index: 2,
        detail: "unexpected char".to_string(),
    };
    let s = e.to_string();
    assert!(s.contains("chunk 2"));
    assert!(s.contains("unexpected char"));
    serde_roundtrip(&e);
}

#[test]
fn parse_error_input_too_large() {
    let e = ParseError::InputTooLarge {
        size: 2_000_000,
        max: 1_048_576,
    };
    let s = e.to_string();
    assert!(s.contains("2000000B"));
    assert!(s.contains("1048576B"));
    serde_roundtrip(&e);
}

#[test]
fn parse_error_invalid_config() {
    let e = ParseError::InvalidConfig {
        detail: "max_workers must be >= 1".to_string(),
    };
    assert!(e.to_string().contains("invalid config"));
    serde_roundtrip(&e);
}

// =======================================================================
// 23. ParseLogEntry struct
// =======================================================================

#[test]
fn parse_log_entry_serde_roundtrip() {
    let entry = ParseLogEntry {
        trace_id: "trace-1".to_string(),
        component: COMPONENT.to_string(),
        event: "parse_complete".to_string(),
        outcome: "ok".to_string(),
        parser_mode: Some("serial".to_string()),
        worker_count: Some(1),
        input_bytes: Some(100),
        token_count: Some(10),
        fallback_reason: None,
        failover_trigger: None,
        failover_transition_path: None,
        failover_witness_ids: None,
        replay_command: None,
        parity_result: None,
        cancellation_state: None,
        cancellation_elapsed_us: None,
        backpressure_level: None,
        backpressure_peak_queue_depth: None,
        error_code: None,
    };
    serde_roundtrip(&entry);
}

#[test]
fn parse_log_entry_all_none_fields() {
    let entry = ParseLogEntry {
        trace_id: "t".to_string(),
        component: "c".to_string(),
        event: "e".to_string(),
        outcome: "o".to_string(),
        parser_mode: None,
        worker_count: None,
        input_bytes: None,
        token_count: None,
        fallback_reason: None,
        failover_trigger: None,
        failover_transition_path: None,
        failover_witness_ids: None,
        replay_command: None,
        parity_result: None,
        cancellation_state: None,
        cancellation_elapsed_us: None,
        backpressure_level: None,
        backpressure_peak_queue_depth: None,
        error_code: None,
    };
    serde_roundtrip(&entry);
}

// =======================================================================
// 24. RollbackControl
// =======================================================================

#[test]
fn rollback_default() {
    let rc = RollbackControl::default();
    assert!(!rc.parallel_disabled);
    assert!(rc.disable_reason.is_none());
    assert_eq!(rc.consecutive_failures, 0);
    assert_eq!(rc.auto_rollback_threshold, 3);
    assert!(rc.failure_trace_ids.is_empty());
}

#[test]
fn rollback_record_failure_below_threshold() {
    let mut rc = RollbackControl::default();
    assert!(!rc.record_failure("t1"));
    assert_eq!(rc.consecutive_failures, 1);
    assert!(!rc.parallel_disabled);
    assert!(rc.failure_trace_ids.contains("t1"));
}

#[test]
fn rollback_auto_trigger_at_threshold() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t2");
    assert!(rc.record_failure("t3"));
    assert!(rc.parallel_disabled);
    assert!(
        rc.disable_reason
            .as_ref()
            .unwrap()
            .contains("3 consecutive")
    );
    assert_eq!(rc.failure_trace_ids.len(), 3);
}

#[test]
fn rollback_success_resets_counter() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t2");
    rc.record_success();
    assert_eq!(rc.consecutive_failures, 0);
    assert!(!rc.parallel_disabled);
}

#[test]
fn rollback_success_does_not_clear_trace_ids() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_success();
    // Trace IDs are NOT cleared on success, only on re_enable.
    assert!(rc.failure_trace_ids.contains("t1"));
}

#[test]
fn rollback_force_disable() {
    let mut rc = RollbackControl::default();
    rc.force_disable("manual stop");
    assert!(rc.parallel_disabled);
    assert_eq!(rc.disable_reason.as_deref(), Some("manual stop"));
}

#[test]
fn rollback_re_enable_clears_all() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t2");
    rc.record_failure("t3");
    assert!(rc.parallel_disabled);
    rc.re_enable();
    assert!(!rc.parallel_disabled);
    assert!(rc.disable_reason.is_none());
    assert_eq!(rc.consecutive_failures, 0);
    assert!(rc.failure_trace_ids.is_empty());
}

#[test]
fn rollback_custom_threshold() {
    let mut rc = RollbackControl {
        auto_rollback_threshold: 5,
        ..Default::default()
    };
    for i in 0..4 {
        assert!(!rc.record_failure(&format!("t{i}")));
    }
    assert!(rc.record_failure("t4"));
    assert!(rc.parallel_disabled);
}

#[test]
fn rollback_duplicate_trace_ids() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t1");
    assert_eq!(rc.consecutive_failures, 2);
    // BTreeSet deduplicates.
    assert_eq!(rc.failure_trace_ids.len(), 1);
}

#[test]
fn rollback_serde_roundtrip() {
    let mut rc = RollbackControl::default();
    rc.record_failure("trace-1");
    serde_roundtrip(&rc);
}

#[test]
fn rollback_threshold_one() {
    let mut rc = RollbackControl {
        auto_rollback_threshold: 1,
        ..Default::default()
    };
    assert!(rc.record_failure("t1"));
    assert!(rc.parallel_disabled);
}

#[test]
fn rollback_force_disable_then_re_enable() {
    let mut rc = RollbackControl::default();
    rc.force_disable("reason");
    assert!(rc.parallel_disabled);
    rc.re_enable();
    assert!(!rc.parallel_disabled);
    assert!(rc.disable_reason.is_none());
}

// =======================================================================
// 25. ParseOutput struct
// =======================================================================

#[test]
fn parse_output_serial_serde_roundtrip() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    serde_roundtrip(&output);
}

#[test]
fn parse_output_parallel_serde_roundtrip() {
    let config = small_config();
    let source = generate_source(100);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    serde_roundtrip(&output);
}

#[test]
fn parse_output_schema_version() {
    let config = default_config();
    let input = make_input("x", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.schema_version, SCHEMA_VERSION);
}

// =======================================================================
// 26. Core parse() -- routing and error paths
// =======================================================================

#[test]
fn parse_small_input_routes_serial() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert!(output.serial_reason.is_some());
    assert!(output.chunk_plan.is_none());
    assert!(output.merge_witness.is_none());
    assert!(output.schedule_transcript.is_none());
    assert!(output.parity_result.is_none());
}

#[test]
fn parse_single_worker_routes_serial() {
    let config = ParallelConfig {
        max_workers: 1,
        min_parallel_bytes: 0,
        ..default_config()
    };
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert!(matches!(
        output.serial_reason,
        Some(SerialReason::SingleWorker)
    ));
}

#[test]
fn parse_no_split_points_routes_serial() {
    let config = ParallelConfig {
        min_parallel_bytes: 1,
        max_workers: 8,
        ..default_config()
    };
    let input = make_input("identifier_without_any_delimiters", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert!(matches!(
        output.serial_reason,
        Some(SerialReason::NoDeterministicSplitPoints)
    ));
}

#[test]
fn parse_zero_workers_is_invalid_config() {
    let config = ParallelConfig {
        max_workers: 0,
        ..default_config()
    };
    let input = make_input("x", &config);
    let err = parallel_parser::parse(&input).unwrap_err();
    assert!(matches!(err, ParseError::InvalidConfig { .. }));
    assert!(err.to_string().contains("max_workers"));
}

#[test]
fn parse_zero_chunk_budget_is_invalid_config() {
    let config = ParallelConfig {
        chunk_budget_us: 0,
        ..default_config()
    };
    let input = make_input("x", &config);
    let err = parallel_parser::parse(&input).unwrap_err();
    assert!(matches!(err, ParseError::InvalidConfig { .. }));
    assert!(err.to_string().contains("chunk_budget_us"));
}

#[test]
fn parse_input_too_large() {
    let config = ParallelConfig {
        lexer_config: LexerConfig {
            max_source_bytes: 10,
            ..LexerConfig::default()
        },
        ..default_config()
    };
    let input = make_input("this is more than ten bytes", &config);
    let err = parallel_parser::parse(&input).unwrap_err();
    assert!(matches!(err, ParseError::InputTooLarge { .. }));
}

#[test]
fn parse_empty_input_serial() {
    let config = default_config();
    let input = make_input("", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert_eq!(output.token_count, 0);
    assert_eq!(output.bytes_scanned, 0);
}

#[test]
fn parse_parallel_large_input_with_newlines() {
    let config = small_config();
    let source = generate_source(100);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);
    assert!(output.chunk_plan.is_some());
}

#[test]
fn parse_parallel_exposes_timeout_policy_and_backpressure() {
    let config = small_config();
    let source = generate_source(120);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Parallel);
    let timeout_policy = output
        .timeout_policy
        .as_ref()
        .expect("parallel output should include timeout policy");
    assert_eq!(timeout_policy.max_chunk_us, config.chunk_budget_us);
    let backpressure = output
        .backpressure
        .as_ref()
        .expect("parallel output should include backpressure snapshot");
    assert_eq!(backpressure.level, BackpressureLevel::Normal);
    assert!(output.cancellation.is_none());
}

#[test]
fn parse_parallel_produces_output_hash() {
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_ne!(output.output_hash, ContentHash::compute(b""));
}

#[test]
fn parse_parallel_tokens_match_serial() {
    let source = generate_source(100);
    let parallel_cfg = small_config();
    let serial_cfg = ParallelConfig {
        max_workers: 1,
        min_parallel_bytes: 0,
        ..small_config()
    };

    let p_out = parallel_parser::parse(&make_input(&source, &parallel_cfg)).unwrap();
    let s_out = parallel_parser::parse(&make_input(&source, &serial_cfg)).unwrap();

    assert_eq!(p_out.token_count, s_out.token_count);
}

#[test]
fn parse_parallel_with_operators() {
    let mut source = String::new();
    for i in 0..50 {
        source.push_str(&format!("x{i} == y{i} && z{i} != w{i}\n"));
    }
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);
}

#[test]
fn parse_parallel_with_strings() {
    let mut source = String::new();
    for i in 0..50 {
        source.push_str(&format!("var s{i} = \"hello{i}\";\n"));
    }
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);
}

#[test]
fn parse_parallel_only_newlines() {
    let source = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
    let config = ParallelConfig {
        min_parallel_bytes: 5,
        max_workers: 4,
        always_check_parity: true,
        ..default_config()
    };
    let input = make_input(source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.token_count, 0);
}

#[test]
fn parse_parallel_eight_workers() {
    let source = generate_source(200);
    let config = ParallelConfig {
        max_workers: 8,
        min_parallel_bytes: 10,
        always_check_parity: true,
        ..default_config()
    };
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);
    // chunk_plan may not be present if input is routed to serial path
    if let Some(ref plan) = output.chunk_plan {
        assert!(plan.worker_count <= 8, "worker_count should respect config");
    }
}

#[test]
fn parse_parallel_parity_check_included() {
    let config = ParallelConfig {
        always_check_parity: true,
        ..small_config()
    };
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let pr = output
        .parity_result
        .as_ref()
        .expect("parity_result should be present");
    assert!(pr.parity_ok, "parity check should pass");
}

#[test]
fn parse_parallel_no_parity_check() {
    let config = ParallelConfig {
        always_check_parity: false,
        ..small_config()
    };
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.parity_result.is_none());
}

#[test]
fn parse_parallel_merge_witness_present() {
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    if output.mode == ParserMode::Parallel {
        let mw = output.merge_witness.as_ref().unwrap();
        assert!(mw.chunk_count > 0);
        assert!(mw.total_tokens > 0);
        assert_ne!(mw.witness_hash, ContentHash::compute(b""));
    }
}

#[test]
fn parse_parallel_schedule_transcript_present() {
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    if output.mode == ParserMode::Parallel {
        let st = output.schedule_transcript.as_ref().unwrap();
        assert!(st.worker_count > 0);
        assert!(!st.execution_order.is_empty());
        assert_eq!(st.dispatches.len(), st.execution_order.len());
        assert_ne!(st.transcript_hash, ContentHash::compute(b""));
    }
}

#[test]
fn parse_bytes_scanned_matches_input_length_serial() {
    let config = default_config();
    let source = "var x = 1;";
    let input = make_input(source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.bytes_scanned, source.len() as u64);
}

#[test]
fn parse_bytes_scanned_matches_input_length_parallel() {
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.bytes_scanned, source.len() as u64);
}

// =======================================================================
// 27. Determinism
// =======================================================================

#[test]
fn parse_deterministic_same_input() {
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let o1 = parallel_parser::parse(&input).unwrap();
    let o2 = parallel_parser::parse(&input).unwrap();
    assert_eq!(o1.output_hash, o2.output_hash);
    assert_eq!(o1.token_count, o2.token_count);
    assert_eq!(o1.tokens, o2.tokens);
}

#[test]
fn parse_deterministic_across_seeds() {
    let source = generate_source(100);
    let c1 = ParallelConfig {
        schedule_seed: 42,
        ..small_config()
    };
    let c2 = ParallelConfig {
        schedule_seed: 99,
        ..small_config()
    };
    let o1 = parallel_parser::parse(&make_input(&source, &c1)).unwrap();
    let o2 = parallel_parser::parse(&make_input(&source, &c2)).unwrap();
    assert_eq!(o1.token_count, o2.token_count);
}

#[test]
fn different_worker_counts_produce_same_token_count() {
    let source = generate_source(50);
    let c2 = ParallelConfig {
        max_workers: 2,
        ..small_config()
    };
    let c4 = ParallelConfig {
        max_workers: 4,
        ..small_config()
    };
    let c8 = ParallelConfig {
        max_workers: 8,
        ..small_config()
    };
    let o2 = parallel_parser::parse(&make_input(&source, &c2)).unwrap();
    let o4 = parallel_parser::parse(&make_input(&source, &c4)).unwrap();
    let o8 = parallel_parser::parse(&make_input(&source, &c8)).unwrap();
    assert_eq!(o2.token_count, o4.token_count);
    assert_eq!(o4.token_count, o8.token_count);
}

#[test]
fn chunk_plan_deterministic_repeated() {
    let input = b"line1\nline2\nline3\nline4\nline5\n";
    for _ in 0..10 {
        let p = parallel_parser::compute_chunk_plan(input, 3);
        let p2 = parallel_parser::compute_chunk_plan(input, 3);
        assert_eq!(p, p2);
    }
}

// =======================================================================
// 28. build_replay_envelope
// =======================================================================

#[test]
fn replay_envelope_serial() {
    let config = default_config();
    let input = make_input("x + y", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert_eq!(envelope.schema_version, SCHEMA_VERSION);
    assert_eq!(envelope.input_bytes, 5);
    assert!(envelope.replay_command.contains("--trace-id"));
    assert!(envelope.replay_command.contains("--workers"));
    assert!(envelope.replay_command.contains("--run-id"));
    assert!(envelope.replay_command.contains("--seed"));
    serde_roundtrip(&envelope);
}

#[test]
fn replay_envelope_parallel() {
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert!(envelope.input_bytes > 100);
    assert_eq!(envelope.output_hash, output.output_hash);
    assert!(envelope.replay_command.contains("--workers 4"));
}

#[test]
fn replay_envelope_deterministic() {
    let config = default_config();
    let input = make_input("var a = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let e1 = parallel_parser::build_replay_envelope(&input, &output, &digest);
    let e2 = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert_eq!(e1.input_hash, e2.input_hash);
    assert_eq!(e1.output_hash, e2.output_hash);
}

#[test]
fn replay_envelope_contains_epoch() {
    let config = default_config();
    let input = ParseInput {
        source: "x",
        trace_id: "t",
        run_id: "r",
        epoch: SecurityEpoch::from_raw(42),
        config: &config,
    };
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert_eq!(envelope.epoch_raw, 42);
}

#[test]
fn replay_envelope_cancellation_is_none() {
    let config = default_config();
    let input = make_input("x", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert!(envelope.cancellation.is_none());
}

#[test]
fn replay_envelope_projects_timeout_cancellation() {
    let config = ParallelConfig {
        min_parallel_bytes: 10,
        max_workers: 2,
        chunk_budget_us: 1_500,
        always_check_parity: true,
        ..default_config()
    };
    let source = generate_source(120);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.fallback_cause.is_some());
    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    let cancellation = envelope
        .cancellation
        .as_ref()
        .expect("timeout fallback should project cancellation into replay envelope");
    assert!(cancellation.trigger_chunk.is_some());
    let failover = envelope
        .failover_decision
        .as_ref()
        .expect("timeout fallback should include failover decision");
    assert_eq!(failover.trigger.class, FailoverTriggerClass::Timeout);
}

#[test]
fn replay_envelope_fields_populated() {
    let config = small_config();
    let source = generate_source(50);
    let input = ParseInput {
        source: &source,
        trace_id: "my-trace",
        run_id: "my-run",
        epoch: SecurityEpoch::from_raw(7),
        config: &config,
    };
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(&source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);

    assert_eq!(envelope.trace_id, "my-trace");
    assert_eq!(envelope.run_id, "my-run");
    assert_eq!(envelope.epoch_raw, 7);
    assert_eq!(envelope.config, config);
    assert!(envelope.replay_command.contains("my-trace"));
    assert!(envelope.replay_command.contains("my-run"));
}

#[test]
fn replay_envelope_includes_failover_decision() {
    let config = ParallelConfig {
        min_parallel_bytes: 10,
        max_workers: 2,
        merge_buffer_bytes: 1,
        always_check_parity: true,
        ..default_config()
    };
    let source = generate_source(40);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.fallback_cause.is_some());

    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    let decision = envelope
        .failover_decision
        .as_ref()
        .expect("failover decision should be projected into replay envelope");
    assert_eq!(decision.trigger.class, FailoverTriggerClass::ResourceLimit);
    assert!(!decision.witness_ids.is_empty());
    assert!(decision.replay_command.contains("--trace-id"));
}

// =======================================================================
// 29. generate_log_entries
// =======================================================================

#[test]
fn log_entries_serial_parse() {
    let config = default_config();
    let input = make_input("x + y", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("trace-1", &output);
    assert!(!entries.is_empty());
    let first = &entries[0];
    assert_eq!(first.trace_id, "trace-1");
    assert_eq!(first.component, COMPONENT);
    assert_eq!(first.event, "parse_complete");
    assert_eq!(first.outcome, "ok");
    assert_eq!(first.parser_mode.as_deref(), Some("serial"));
}

#[test]
fn log_entries_parallel_parse() {
    let config = small_config();
    let source = generate_source(100);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("trace-2", &output);
    assert!(!entries.is_empty());
    assert!(entries[0].worker_count.is_some());
}

#[test]
fn log_entries_trace_id_consistent() {
    let config = default_config();
    let input = make_input("x", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("trace-42", &output);
    for e in &entries {
        assert_eq!(e.trace_id, "trace-42");
    }
}

#[test]
fn log_entries_no_fallback_single_entry() {
    let config = default_config();
    let input = make_input("x", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.fallback_cause.is_none());
    let entries = parallel_parser::generate_log_entries("t", &output);
    // Only parse_complete, no fallback_triggered.
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event, "parse_complete");
}

#[test]
fn log_entries_failover_include_trigger_transition_and_replay() {
    let config = ParallelConfig {
        min_parallel_bytes: 10,
        max_workers: 2,
        merge_buffer_bytes: 1,
        always_check_parity: true,
        ..default_config()
    };
    let source = generate_source(40);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("trace-fallback", &output);
    assert!(entries.iter().any(|e| e.event == "fallback_triggered"));
    let fallback = entries
        .iter()
        .find(|e| e.event == "fallback_triggered")
        .expect("fallback entry should exist");
    assert!(fallback.failover_trigger.is_some());
    assert!(fallback.failover_transition_path.is_some());
    assert!(fallback.failover_witness_ids.is_some());
    assert!(fallback.replay_command.is_some());
}

#[test]
fn log_entries_include_cancellation_and_backpressure_fields() {
    let config = ParallelConfig {
        min_parallel_bytes: 10,
        max_workers: 2,
        chunk_budget_us: 1_500,
        always_check_parity: true,
        ..default_config()
    };
    let source = generate_source(120);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("trace-timeout", &output);
    assert_eq!(entries[0].cancellation_state.as_deref(), Some("finalized"));
    assert!(entries[0].cancellation_elapsed_us.is_some());
    assert_eq!(entries[0].backpressure_level.as_deref(), Some("elevated"));
    assert!(entries[0].backpressure_peak_queue_depth.is_some());
}

#[test]
fn log_entries_component_consistent() {
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("t", &output);
    for e in &entries {
        assert_eq!(e.component, COMPONENT);
    }
}

// =======================================================================
// 30. Cross-concern integration scenarios
// =======================================================================

#[test]
fn full_pipeline_serial_small() {
    let config = default_config();
    let source = "x = 1;";
    let digest = parallel_parser::compute_routing_digest(source, &config);
    assert_eq!(digest.decision, ParserMode::Serial);

    let input = make_input(source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);

    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert_eq!(envelope.input_bytes, source.len() as u64);

    let entries = parallel_parser::generate_log_entries("pipeline", &output);
    assert!(entries.iter().all(|e| e.trace_id == "pipeline"));
}

#[test]
fn full_pipeline_parallel_large() {
    let config = small_config();
    let source = generate_source(100);
    let digest = parallel_parser::compute_routing_digest(&source, &config);
    assert_eq!(digest.decision, ParserMode::Parallel);

    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);

    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert_eq!(envelope.output_hash, output.output_hash);
    assert!(envelope.replay_command.contains("--workers 4"));

    let entries = parallel_parser::generate_log_entries("pipeline", &output);
    assert!(!entries.is_empty());
}

#[test]
fn rollback_integration_with_parse() {
    let mut rc = RollbackControl::default();
    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);

    rc.record_success();
    assert!(!rc.parallel_disabled);

    for i in 0..3 {
        rc.record_failure(&format!("fail-{i}"));
    }
    assert!(rc.parallel_disabled);
}

#[test]
fn routing_then_parse_consistency() {
    let config = small_config();
    let source = generate_source(50);

    let digest = parallel_parser::compute_routing_digest(&source, &config);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();

    if digest.decision == ParserMode::Parallel
        && let Some(pr) = &output.parity_result
        && pr.parity_ok
    {
        assert_eq!(output.mode, ParserMode::Parallel);
    }
}

#[test]
fn mixed_content_types_parallel() {
    let mut source = String::new();
    for i in 0..50 {
        source.push_str(&format!(
            "var s{i} = \"hello\"; x{i} == {i} && y{i} != z{i};\n"
        ));
    }
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);
}

#[test]
fn rollback_re_enable_allows_parallel_again() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t2");
    rc.record_failure("t3");
    assert!(rc.parallel_disabled);

    rc.re_enable();
    assert!(!rc.parallel_disabled);

    let config = small_config();
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);
}

// =======================================================================
// 31. Edge cases
// =======================================================================

#[test]
fn parse_single_char() {
    let config = default_config();
    let input = make_input("x", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert!(output.token_count > 0);
}

#[test]
fn parse_single_newline() {
    let config = default_config();
    let input = make_input("\n", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert_eq!(output.token_count, 0);
}

#[test]
fn parse_whitespace_only() {
    let config = default_config();
    let input = make_input("   ", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert_eq!(output.token_count, 0);
}

#[test]
fn parse_input_at_exact_threshold() {
    let config = ParallelConfig {
        min_parallel_bytes: 20,
        max_workers: 2,
        always_check_parity: true,
        ..default_config()
    };
    // Build source exactly 20 bytes with newlines.
    let source = "abcdefghi\nabcdefghi\n"; // 20 bytes
    assert_eq!(source.len(), 20);
    let input = make_input(source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    // At exactly the threshold, should be parallel.
    assert!(output.chunk_plan.is_some());
}

#[test]
fn parse_input_one_byte_below_threshold() {
    let config = ParallelConfig {
        min_parallel_bytes: 20,
        max_workers: 2,
        always_check_parity: true,
        ..default_config()
    };
    let source = "abcdefghi\nabcdefgh\n"; // 19 bytes
    assert_eq!(source.len(), 19);
    let input = make_input(source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
}

// =======================================================================
// 32. Merge buffer exceeded fallback
// =======================================================================

#[test]
fn parse_merge_buffer_exceeded_falls_back_serial() {
    // Set merge buffer to 1 byte to trigger fallback.
    let config = ParallelConfig {
        min_parallel_bytes: 10,
        max_workers: 2,
        merge_buffer_bytes: 1,
        always_check_parity: true,
        ..default_config()
    };
    let source = generate_source(50);
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    assert!(matches!(
        output.serial_reason,
        Some(SerialReason::MergeBufferExceeded { .. })
    ));
    assert!(matches!(
        output.fallback_cause,
        Some(FallbackCause::ResourceLimit(_))
    ));
    let decision = output
        .failover_decision
        .as_ref()
        .expect("failover decision should be present for serial failover");
    assert_eq!(decision.trigger.class, FailoverTriggerClass::ResourceLimit);
    assert_eq!(decision.transition_path.len(), 4);
    assert!(!decision.witness_ids.is_empty());
    assert!(decision.replay_command.contains("--trace-id"));
}

// =======================================================================
// 33. ParseInput construction edge cases
// =======================================================================

#[test]
fn parse_input_unicode_source() {
    let config = default_config();
    let input = make_input("var emoji = '\u{1F600}';\n", &config);
    assert!(input.source.contains('\u{1F600}'));
    // Should still parse (serial mode for small input).
    let output = parallel_parser::parse(&input).unwrap();
    assert!(output.token_count > 0);
}

#[test]
fn parse_input_preserves_trace_and_run_ids() {
    let config = default_config();
    let input = ParseInput {
        source: "x",
        trace_id: "custom-trace-42",
        run_id: "custom-run-99",
        epoch: SecurityEpoch::from_raw(7),
        config: &config,
    };
    assert_eq!(input.trace_id, "custom-trace-42");
    assert_eq!(input.run_id, "custom-run-99");
    assert_eq!(input.epoch.as_u64(), 7);
}

// =======================================================================
// 34. ReplayEnvelope serde roundtrip
// =======================================================================

#[test]
fn replay_envelope_serde_roundtrip() {
    let config = default_config();
    let input = make_input("var a = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(input.source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    serde_roundtrip(&envelope);
}

// =======================================================================
// 35. Additional Display coverage
// =======================================================================

#[test]
fn serial_reason_display_all_variants_covered() {
    // InputBelowThreshold
    let r1 = SerialReason::InputBelowThreshold {
        input_bytes: 50,
        threshold: 4096,
    };
    assert!(r1.to_string().contains("input 50B below threshold 4096B"));

    // SingleWorker
    assert_eq!(
        SerialReason::SingleWorker.to_string(),
        "single worker configured"
    );

    // BudgetExhausted
    let r3 = SerialReason::BudgetExhausted { budget_us: 99_999 };
    assert!(r3.to_string().contains("budget exhausted (99999us)"));

    // ParityMismatch
    let r4 = SerialReason::ParityMismatch { mismatch_index: 0 };
    assert!(r4.to_string().contains("parity mismatch at token 0"));

    // MergeBufferExceeded
    let r5 = SerialReason::MergeBufferExceeded {
        buffer_bytes: 100,
        limit: 50,
    };
    assert!(r5.to_string().contains("merge buffer 100B exceeds 50B"));
}

#[test]
fn fallback_cause_display_parity_failure_at_zero() {
    let c = FallbackCause::ParityFailure { mismatch_index: 0 };
    assert_eq!(c.to_string(), "parity failure at token 0");
}

#[test]
fn parse_error_display_lexer_error_details() {
    let e = ParseError::LexerError {
        chunk_index: 0,
        detail: "EOF in string".to_string(),
    };
    assert_eq!(e.to_string(), "lexer error in chunk 0: EOF in string");
}

#[test]
fn parse_error_display_input_too_large_details() {
    let e = ParseError::InputTooLarge { size: 100, max: 50 };
    assert_eq!(e.to_string(), "input too large: 100B exceeds 50B");
}

#[test]
fn parse_error_display_invalid_config_details() {
    let e = ParseError::InvalidConfig {
        detail: "bad".to_string(),
    };
    assert_eq!(e.to_string(), "invalid config: bad");
}
