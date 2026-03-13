//! Enrichment integration tests for `parallel_parser`.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips, Debug
//! nonempty, Default coverage, Display coverage, JSON field-name stability,
//! higher-level API surface (RollbackControl, ThroughputSample, routing digest,
//! schedule transcripts, replay envelope, log generation, backpressure, etc.).

use std::collections::BTreeSet;

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::parallel_parser::{
    self, BackpressureLevel, BackpressureSnapshot, COMPONENT, CancellationRecord,
    CancellationState, ChunkPlan, ChunkResult, ChunkTiming, DEFAULT_CHUNK_BUDGET_US,
    DEFAULT_MAX_WORKERS, DEFAULT_MERGE_BUFFER_BYTES, DEFAULT_MIN_PARALLEL_BYTES,
    DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS, FailoverDecision, FailoverState, FailoverTrigger,
    FailoverTriggerClass, FallbackCause, MergeWitness, ParallelConfig, ParityResult, ParseError,
    ParseInput, ParseOutput, ParserMode, PerformanceReport, ReplayEnvelope, RollbackControl,
    SCHEMA_VERSION, ScheduleDispatch, SerialReason, ThroughputSample, TimeoutPolicy,
    TranscriptReplayError,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::simd_lexer::{Token, TokenKind};

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
        trace_id: "enrichment-trace",
        run_id: "enrichment-run",
        epoch: SecurityEpoch::from_raw(1),
        config,
    }
}

fn make_large_source(lines: usize) -> String {
    let mut s = String::new();
    for i in 0..lines {
        s.push_str(&format!("var x{i} = {i};\n"));
    }
    s
}

// -----------------------------------------------------------------------
// 1. Copy/Clone semantics for Copy types
// -----------------------------------------------------------------------

#[test]
fn enrichment_parser_mode_copy_semantics() {
    let a = ParserMode::Serial;
    let b = a;
    assert_eq!(a, b);
    let c = ParserMode::Parallel;
    let d = c;
    assert_eq!(c, d);
}

#[test]
fn enrichment_failover_trigger_class_copy_semantics() {
    let a = FailoverTriggerClass::Timeout;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_failover_state_copy_semantics() {
    let a = FailoverState::ParallelAttempted;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_cancellation_state_copy_semantics() {
    let a = CancellationState::None;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_backpressure_level_copy_semantics() {
    let a = BackpressureLevel::Critical;
    let b = a;
    assert_eq!(a, b);
}

// -----------------------------------------------------------------------
// 2. Clone independence for non-Copy types
// -----------------------------------------------------------------------

#[test]
fn enrichment_parallel_config_clone_independence() {
    let a = ParallelConfig {
        min_parallel_bytes: 100,
        ..default_config()
    };
    let mut b = a.clone();
    b.min_parallel_bytes = 999;
    assert_eq!(a.min_parallel_bytes, 100);
    assert_eq!(b.min_parallel_bytes, 999);
}

#[test]
fn enrichment_serial_reason_clone_independence() {
    let a = SerialReason::InputBelowThreshold {
        input_bytes: 50,
        threshold: 100,
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_chunk_plan_clone_independence() {
    let hash = ContentHash::compute(b"test");
    let a = ChunkPlan {
        chunks: vec![(0, 10), (10, 20)],
        plan_hash: hash,
        worker_count: 2,
    };
    let mut b = a.clone();
    b.chunks.push((20, 30));
    assert_eq!(a.chunks.len(), 2);
    assert_eq!(b.chunks.len(), 3);
}

#[test]
fn enrichment_chunk_result_clone_independence() {
    let a = ChunkResult {
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
    let mut b = a.clone();
    b.tokens.clear();
    assert_eq!(a.tokens.len(), 1);
    assert!(b.tokens.is_empty());
}

#[test]
fn enrichment_rollback_control_clone_independence() {
    let mut a = RollbackControl::default();
    a.record_failure("trace-1");
    let mut b = a.clone();
    b.record_failure("trace-2");
    assert_eq!(a.consecutive_failures, 1);
    assert_eq!(b.consecutive_failures, 2);
}

#[test]
fn enrichment_failover_decision_clone_independence() {
    let a = FailoverDecision {
        trigger: FailoverTrigger {
            class: FailoverTriggerClass::Timeout,
            detail: "test".to_string(),
        },
        transition_path: vec![FailoverState::ParallelAttempted],
        witness_ids: vec!["w1".to_string()],
        replay_command: "cmd".to_string(),
    };
    let mut b = a.clone();
    b.witness_ids.push("w2".to_string());
    assert_eq!(a.witness_ids.len(), 1);
    assert_eq!(b.witness_ids.len(), 2);
}

// -----------------------------------------------------------------------
// 3. BTreeSet ordering for Ord types
// -----------------------------------------------------------------------

#[test]
fn enrichment_parser_mode_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(ParserMode::Parallel);
    set.insert(ParserMode::Serial);
    set.insert(ParserMode::Serial); // dedup
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_failover_trigger_class_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(FailoverTriggerClass::Timeout);
    set.insert(FailoverTriggerClass::TranscriptDivergence);
    set.insert(FailoverTriggerClass::WitnessMismatch);
    set.insert(FailoverTriggerClass::SafetyPolicyViolation);
    set.insert(FailoverTriggerClass::ParityMismatch);
    set.insert(FailoverTriggerClass::ResourceLimit);
    set.insert(FailoverTriggerClass::Timeout); // dedup
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_failover_state_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(FailoverState::ParallelAttempted);
    set.insert(FailoverState::TriggerClassified);
    set.insert(FailoverState::SerialFallbackRequested);
    set.insert(FailoverState::SerialFallbackCompleted);
    set.insert(FailoverState::ParallelAttempted); // dedup
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_cancellation_state_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(CancellationState::None);
    set.insert(CancellationState::Requested);
    set.insert(CancellationState::Draining);
    set.insert(CancellationState::Finalized);
    set.insert(CancellationState::None); // dedup
    assert_eq!(set.len(), 4);
}

#[test]
fn enrichment_backpressure_level_btreeset_ordering() {
    let mut set = BTreeSet::new();
    set.insert(BackpressureLevel::Normal);
    set.insert(BackpressureLevel::Elevated);
    set.insert(BackpressureLevel::Critical);
    set.insert(BackpressureLevel::Normal); // dedup
    assert_eq!(set.len(), 3);
}

// -----------------------------------------------------------------------
// 4. Serde roundtrips
// -----------------------------------------------------------------------

#[test]
fn enrichment_parser_mode_serde_roundtrip() {
    for mode in [ParserMode::Serial, ParserMode::Parallel] {
        let json = serde_json::to_string(&mode).unwrap();
        let back: ParserMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, back);
    }
}

#[test]
fn enrichment_serial_reason_serde_roundtrip_all_variants() {
    let variants = vec![
        SerialReason::InputBelowThreshold {
            input_bytes: 50,
            threshold: 4096,
        },
        SerialReason::SingleWorker,
        SerialReason::NoDeterministicSplitPoints,
        SerialReason::BudgetExhausted { budget_us: 50_000 },
        SerialReason::ParityMismatch { mismatch_index: 42 },
        SerialReason::MergeBufferExceeded {
            buffer_bytes: 2_000_000,
            limit: 1_000_000,
        },
        SerialReason::TranscriptDivergence {
            detail: "diverged".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: SerialReason = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &back);
    }
}

#[test]
fn enrichment_fallback_cause_serde_roundtrip() {
    let variants = vec![
        FallbackCause::Routing(SerialReason::SingleWorker),
        FallbackCause::ParityFailure { mismatch_index: 5 },
        FallbackCause::ResourceLimit(SerialReason::BudgetExhausted { budget_us: 100 }),
        FallbackCause::TranscriptDivergence {
            detail: "oops".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: FallbackCause = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &back);
    }
}

#[test]
fn enrichment_failover_trigger_class_serde_roundtrip() {
    for v in [
        FailoverTriggerClass::Timeout,
        FailoverTriggerClass::TranscriptDivergence,
        FailoverTriggerClass::WitnessMismatch,
        FailoverTriggerClass::SafetyPolicyViolation,
        FailoverTriggerClass::ParityMismatch,
        FailoverTriggerClass::ResourceLimit,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: FailoverTriggerClass = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_failover_state_serde_roundtrip() {
    for v in [
        FailoverState::ParallelAttempted,
        FailoverState::TriggerClassified,
        FailoverState::SerialFallbackRequested,
        FailoverState::SerialFallbackCompleted,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: FailoverState = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_cancellation_state_serde_roundtrip() {
    for v in [
        CancellationState::None,
        CancellationState::Requested,
        CancellationState::Draining,
        CancellationState::Finalized,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: CancellationState = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_backpressure_level_serde_roundtrip() {
    for v in [
        BackpressureLevel::Normal,
        BackpressureLevel::Elevated,
        BackpressureLevel::Critical,
    ] {
        let json = serde_json::to_string(&v).unwrap();
        let back: BackpressureLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

#[test]
fn enrichment_chunk_plan_serde_roundtrip() {
    let hash = ContentHash::compute(b"plan");
    let plan = ChunkPlan {
        chunks: vec![(0, 100), (100, 200)],
        plan_hash: hash,
        worker_count: 2,
    };
    let json = serde_json::to_string(&plan).unwrap();
    let back: ChunkPlan = serde_json::from_str(&json).unwrap();
    assert_eq!(plan, back);
}

#[test]
fn enrichment_chunk_result_serde_roundtrip() {
    let cr = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 50,
        tokens: vec![Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        }],
        token_count: 1,
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: ChunkResult = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, back);
}

#[test]
fn enrichment_merge_witness_serde_roundtrip() {
    let mw = MergeWitness {
        merged_hash: ContentHash::compute(b"merged"),
        witness_hash: ContentHash::compute(b"witness"),
        chunk_count: 3,
        boundary_repairs: 1,
        total_tokens: 42,
    };
    let json = serde_json::to_string(&mw).unwrap();
    let back: MergeWitness = serde_json::from_str(&json).unwrap();
    assert_eq!(mw, back);
}

#[test]
fn enrichment_schedule_dispatch_serde_roundtrip() {
    let sd = ScheduleDispatch {
        step_index: 0,
        chunk_index: 2,
        worker_slot: 1,
    };
    let json = serde_json::to_string(&sd).unwrap();
    let back: ScheduleDispatch = serde_json::from_str(&json).unwrap();
    assert_eq!(sd, back);
}

#[test]
fn enrichment_timeout_policy_serde_roundtrip() {
    let tp = TimeoutPolicy::default();
    let json = serde_json::to_string(&tp).unwrap();
    let back: TimeoutPolicy = serde_json::from_str(&json).unwrap();
    assert_eq!(tp, back);
}

#[test]
fn enrichment_cancellation_record_serde_roundtrip() {
    let cr = CancellationRecord {
        state: CancellationState::Finalized,
        elapsed_us: 12345,
        trigger_chunk: Some(2),
        drain_completed: true,
    };
    let json = serde_json::to_string(&cr).unwrap();
    let back: CancellationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(cr, back);
}

#[test]
fn enrichment_backpressure_snapshot_serde_roundtrip() {
    let bp = BackpressureSnapshot {
        queue_depth: 3,
        peak_queue_depth: 5,
        level: BackpressureLevel::Elevated,
        delayed_chunks: 2,
        total_delay_us: 500,
    };
    let json = serde_json::to_string(&bp).unwrap();
    let back: BackpressureSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(bp, back);
}

#[test]
fn enrichment_parity_result_serde_roundtrip() {
    let pr = ParityResult {
        parity_ok: true,
        mismatch_index: None,
        parallel_count: 100,
        serial_count: 100,
    };
    let json = serde_json::to_string(&pr).unwrap();
    let back: ParityResult = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, back);
}

#[test]
fn enrichment_parse_error_serde_roundtrip() {
    let variants = vec![
        ParseError::LexerError {
            chunk_index: 0,
            detail: "bad".to_string(),
        },
        ParseError::InputTooLarge {
            size: 1_000_000,
            max: 500_000,
        },
        ParseError::InvalidConfig {
            detail: "nope".to_string(),
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: ParseError = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &back);
    }
}

#[test]
fn enrichment_throughput_sample_serde_roundtrip() {
    let ts = ThroughputSample::compute(1000, 200, 5000);
    let json = serde_json::to_string(&ts).unwrap();
    let back: ThroughputSample = serde_json::from_str(&json).unwrap();
    assert_eq!(ts, back);
}

#[test]
fn enrichment_rollback_control_serde_roundtrip() {
    let rc = RollbackControl::default();
    let json = serde_json::to_string(&rc).unwrap();
    let back: RollbackControl = serde_json::from_str(&json).unwrap();
    assert_eq!(rc.parallel_disabled, back.parallel_disabled);
    assert_eq!(rc.consecutive_failures, back.consecutive_failures);
}

#[test]
fn enrichment_performance_report_serde_roundtrip() {
    let pr = PerformanceReport {
        throughput: ThroughputSample::compute(500, 100, 1000),
        chunk_timings: vec![ChunkTiming {
            chunk_index: 0,
            chunk_bytes: 500,
            token_count: 100,
            elapsed_us: 1000,
        }],
        merge_elapsed_us: 50,
        parity_check_elapsed_us: 30,
    };
    let json = serde_json::to_string(&pr).unwrap();
    let back: PerformanceReport = serde_json::from_str(&json).unwrap();
    assert_eq!(pr, back);
}

#[test]
fn enrichment_transcript_replay_error_serde_roundtrip() {
    let hash = ContentHash::compute(b"h");
    let variants: Vec<TranscriptReplayError> = vec![
        TranscriptReplayError::PlanHashMismatch {
            expected: hash,
            actual: hash,
        },
        TranscriptReplayError::WorkerCountMismatch {
            expected: 4,
            actual: 2,
        },
        TranscriptReplayError::InvalidExecutionOrderLength {
            expected_chunks: 3,
            actual_entries: 5,
        },
        TranscriptReplayError::InvalidDispatchCount {
            expected_steps: 3,
            actual_steps: 2,
        },
        TranscriptReplayError::InvalidChunkReference {
            step_index: 0,
            chunk_index: 10,
            chunk_count: 3,
        },
        TranscriptReplayError::DuplicateChunkReference { chunk_index: 1 },
        TranscriptReplayError::MissingChunkReference { chunk_index: 2 },
        TranscriptReplayError::DispatchStepMismatch {
            expected_step: 0,
            actual_step: 1,
        },
        TranscriptReplayError::DispatchChunkMismatch {
            step_index: 0,
            expected_chunk: 1,
            actual_chunk: 2,
        },
        TranscriptReplayError::WorkerSlotOutOfRange {
            step_index: 0,
            worker_slot: 5,
            worker_count: 4,
        },
        TranscriptReplayError::TranscriptHashMismatch {
            expected: hash,
            actual: hash,
        },
    ];
    for v in &variants {
        let json = serde_json::to_string(v).unwrap();
        let back: TranscriptReplayError = serde_json::from_str(&json).unwrap();
        assert_eq!(v, &back);
    }
}

// -----------------------------------------------------------------------
// 5. Display coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_parser_mode_display() {
    assert_eq!(format!("{}", ParserMode::Serial), "serial");
    assert_eq!(format!("{}", ParserMode::Parallel), "parallel");
}

#[test]
fn enrichment_serial_reason_display_all_variants() {
    let variants = vec![
        SerialReason::InputBelowThreshold {
            input_bytes: 50,
            threshold: 4096,
        },
        SerialReason::SingleWorker,
        SerialReason::NoDeterministicSplitPoints,
        SerialReason::BudgetExhausted { budget_us: 50_000 },
        SerialReason::ParityMismatch { mismatch_index: 42 },
        SerialReason::MergeBufferExceeded {
            buffer_bytes: 2_000_000,
            limit: 1_000_000,
        },
        SerialReason::TranscriptDivergence {
            detail: "diverged".to_string(),
        },
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(
            !s.is_empty(),
            "Display for SerialReason variant should be nonempty"
        );
    }
}

#[test]
fn enrichment_serial_reason_display_input_below_threshold_contains_values() {
    let r = SerialReason::InputBelowThreshold {
        input_bytes: 50,
        threshold: 4096,
    };
    let s = format!("{r}");
    assert!(s.contains("50"), "should contain input bytes");
    assert!(s.contains("4096"), "should contain threshold");
}

#[test]
fn enrichment_fallback_cause_display_all_variants() {
    let variants = vec![
        FallbackCause::Routing(SerialReason::SingleWorker),
        FallbackCause::ParityFailure { mismatch_index: 5 },
        FallbackCause::ResourceLimit(SerialReason::BudgetExhausted { budget_us: 100 }),
        FallbackCause::TranscriptDivergence {
            detail: "oops".to_string(),
        },
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty());
    }
}

#[test]
fn enrichment_failover_trigger_class_display_all_variants() {
    let variants = [
        (FailoverTriggerClass::Timeout, "timeout"),
        (
            FailoverTriggerClass::TranscriptDivergence,
            "transcript-divergence",
        ),
        (FailoverTriggerClass::WitnessMismatch, "witness-mismatch"),
        (
            FailoverTriggerClass::SafetyPolicyViolation,
            "safety-policy-violation",
        ),
        (FailoverTriggerClass::ParityMismatch, "parity-mismatch"),
        (FailoverTriggerClass::ResourceLimit, "resource-limit"),
    ];
    for (v, expected) in &variants {
        assert_eq!(&format!("{v}"), expected);
    }
}

#[test]
fn enrichment_failover_state_display_all_variants() {
    let variants = [
        (FailoverState::ParallelAttempted, "parallel-attempted"),
        (FailoverState::TriggerClassified, "trigger-classified"),
        (
            FailoverState::SerialFallbackRequested,
            "serial-fallback-requested",
        ),
        (
            FailoverState::SerialFallbackCompleted,
            "serial-fallback-completed",
        ),
    ];
    for (v, expected) in &variants {
        assert_eq!(&format!("{v}"), expected);
    }
}

#[test]
fn enrichment_cancellation_state_display_all_variants() {
    let variants = [
        (CancellationState::None, "none"),
        (CancellationState::Requested, "requested"),
        (CancellationState::Draining, "draining"),
        (CancellationState::Finalized, "finalized"),
    ];
    for (v, expected) in &variants {
        assert_eq!(&format!("{v}"), expected);
    }
}

#[test]
fn enrichment_backpressure_level_display_all_variants() {
    let variants = [
        (BackpressureLevel::Normal, "normal"),
        (BackpressureLevel::Elevated, "elevated"),
        (BackpressureLevel::Critical, "critical"),
    ];
    for (v, expected) in &variants {
        assert_eq!(&format!("{v}"), expected);
    }
}

#[test]
fn enrichment_parse_error_display_all_variants() {
    let variants = vec![
        ParseError::LexerError {
            chunk_index: 3,
            detail: "bad token".to_string(),
        },
        ParseError::InputTooLarge {
            size: 999,
            max: 500,
        },
        ParseError::InvalidConfig {
            detail: "bad config".to_string(),
        },
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty());
    }
}

#[test]
fn enrichment_parse_error_display_preserves_values() {
    let e = ParseError::LexerError {
        chunk_index: 7,
        detail: "unexpected EOF".to_string(),
    };
    let s = format!("{e}");
    assert!(s.contains("7"));
    assert!(s.contains("unexpected EOF"));
}

#[test]
fn enrichment_transcript_replay_error_display_all_variants() {
    let hash = ContentHash::compute(b"h");
    let variants: Vec<TranscriptReplayError> = vec![
        TranscriptReplayError::PlanHashMismatch {
            expected: hash,
            actual: hash,
        },
        TranscriptReplayError::WorkerCountMismatch {
            expected: 4,
            actual: 2,
        },
        TranscriptReplayError::InvalidExecutionOrderLength {
            expected_chunks: 3,
            actual_entries: 5,
        },
        TranscriptReplayError::InvalidDispatchCount {
            expected_steps: 3,
            actual_steps: 2,
        },
        TranscriptReplayError::InvalidChunkReference {
            step_index: 0,
            chunk_index: 10,
            chunk_count: 3,
        },
        TranscriptReplayError::DuplicateChunkReference { chunk_index: 1 },
        TranscriptReplayError::MissingChunkReference { chunk_index: 2 },
        TranscriptReplayError::DispatchStepMismatch {
            expected_step: 0,
            actual_step: 1,
        },
        TranscriptReplayError::DispatchChunkMismatch {
            step_index: 0,
            expected_chunk: 1,
            actual_chunk: 2,
        },
        TranscriptReplayError::WorkerSlotOutOfRange {
            step_index: 0,
            worker_slot: 5,
            worker_count: 4,
        },
        TranscriptReplayError::TranscriptHashMismatch {
            expected: hash,
            actual: hash,
        },
    ];
    for v in &variants {
        let s = format!("{v}");
        assert!(!s.is_empty());
    }
}

// -----------------------------------------------------------------------
// 6. Debug nonempty
// -----------------------------------------------------------------------

#[test]
fn enrichment_parallel_config_debug_nonempty() {
    assert!(!format!("{:?}", default_config()).is_empty());
}

#[test]
fn enrichment_parser_mode_debug_nonempty() {
    assert!(!format!("{:?}", ParserMode::Serial).is_empty());
}

#[test]
fn enrichment_serial_reason_debug_nonempty() {
    assert!(!format!("{:?}", SerialReason::SingleWorker).is_empty());
}

#[test]
fn enrichment_chunk_plan_debug_nonempty() {
    let plan = parallel_parser::compute_chunk_plan(b"a\nb\n", 2);
    assert!(!format!("{plan:?}").is_empty());
}

#[test]
fn enrichment_chunk_result_debug_nonempty() {
    let cr = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 5,
        tokens: vec![],
        token_count: 0,
    };
    assert!(!format!("{cr:?}").is_empty());
}

#[test]
fn enrichment_merge_witness_debug_nonempty() {
    let mw = MergeWitness {
        merged_hash: ContentHash::compute(b"m"),
        witness_hash: ContentHash::compute(b"w"),
        chunk_count: 1,
        boundary_repairs: 0,
        total_tokens: 5,
    };
    assert!(!format!("{mw:?}").is_empty());
}

#[test]
fn enrichment_schedule_dispatch_debug_nonempty() {
    let sd = ScheduleDispatch {
        step_index: 0,
        chunk_index: 0,
        worker_slot: 0,
    };
    assert!(!format!("{sd:?}").is_empty());
}

#[test]
fn enrichment_timeout_policy_debug_nonempty() {
    assert!(!format!("{:?}", TimeoutPolicy::default()).is_empty());
}

#[test]
fn enrichment_rollback_control_debug_nonempty() {
    assert!(!format!("{:?}", RollbackControl::default()).is_empty());
}

#[test]
fn enrichment_parity_result_debug_nonempty() {
    let pr = ParityResult {
        parity_ok: true,
        mismatch_index: None,
        parallel_count: 0,
        serial_count: 0,
    };
    assert!(!format!("{pr:?}").is_empty());
}

#[test]
fn enrichment_failover_trigger_debug_nonempty() {
    let ft = FailoverTrigger {
        class: FailoverTriggerClass::Timeout,
        detail: "t".to_string(),
    };
    assert!(!format!("{ft:?}").is_empty());
}

#[test]
fn enrichment_cancellation_record_debug_nonempty() {
    let cr = CancellationRecord {
        state: CancellationState::None,
        elapsed_us: 0,
        trigger_chunk: None,
        drain_completed: false,
    };
    assert!(!format!("{cr:?}").is_empty());
}

#[test]
fn enrichment_backpressure_snapshot_debug_nonempty() {
    let bp = BackpressureSnapshot {
        queue_depth: 0,
        peak_queue_depth: 0,
        level: BackpressureLevel::Normal,
        delayed_chunks: 0,
        total_delay_us: 0,
    };
    assert!(!format!("{bp:?}").is_empty());
}

#[test]
fn enrichment_parse_log_entry_debug_nonempty() {
    let source = make_large_source(50);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("test", &output);
    for e in &entries {
        assert!(!format!("{e:?}").is_empty());
    }
}

// -----------------------------------------------------------------------
// 7. Default coverage
// -----------------------------------------------------------------------

#[test]
fn enrichment_parallel_config_default() {
    let config = ParallelConfig::default();
    assert_eq!(config.min_parallel_bytes, DEFAULT_MIN_PARALLEL_BYTES);
    assert_eq!(config.max_workers, DEFAULT_MAX_WORKERS);
    assert_eq!(config.chunk_budget_us, DEFAULT_CHUNK_BUDGET_US);
    assert_eq!(config.merge_buffer_bytes, DEFAULT_MERGE_BUFFER_BYTES);
    assert_eq!(
        config.overhead_threshold_millionths,
        DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS
    );
    assert!(config.always_check_parity);
    assert_eq!(config.schedule_seed, 0);
}

#[test]
fn enrichment_timeout_policy_default() {
    let tp = TimeoutPolicy::default();
    assert_eq!(tp.max_total_us, 500_000);
    assert_eq!(tp.max_chunk_us, 100_000);
    assert!(tp.allow_drain);
}

#[test]
fn enrichment_rollback_control_default() {
    let rc = RollbackControl::default();
    assert!(!rc.parallel_disabled);
    assert!(rc.disable_reason.is_none());
    assert_eq!(rc.consecutive_failures, 0);
    assert_eq!(rc.auto_rollback_threshold, 3);
    assert!(rc.failure_trace_ids.is_empty());
}

// -----------------------------------------------------------------------
// 8. Constants
// -----------------------------------------------------------------------

#[test]
fn enrichment_component_constant() {
    assert_eq!(COMPONENT, "parallel_parser");
}

#[test]
fn enrichment_schema_version_constant() {
    assert!(SCHEMA_VERSION.starts_with("franken-engine."));
}

#[test]
fn enrichment_default_constants_reasonable() {
    const { assert!(DEFAULT_MIN_PARALLEL_BYTES > 0) };
    const { assert!(DEFAULT_MAX_WORKERS > 0) };
    const { assert!(DEFAULT_CHUNK_BUDGET_US > 0) };
    const { assert!(DEFAULT_MERGE_BUFFER_BYTES > 0) };
    const { assert!(DEFAULT_OVERHEAD_THRESHOLD_MILLIONTHS > 0) };
}

// -----------------------------------------------------------------------
// 9. RollbackControl API
// -----------------------------------------------------------------------

#[test]
fn enrichment_rollback_record_failure_below_threshold() {
    let mut rc = RollbackControl::default();
    let triggered = rc.record_failure("t1");
    assert!(!triggered);
    assert_eq!(rc.consecutive_failures, 1);
    assert!(!rc.parallel_disabled);
    assert!(rc.failure_trace_ids.contains("t1"));
}

#[test]
fn enrichment_rollback_record_failure_reaches_threshold() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t2");
    let triggered = rc.record_failure("t3");
    assert!(triggered);
    assert!(rc.parallel_disabled);
    assert!(rc.disable_reason.is_some());
    assert_eq!(rc.consecutive_failures, 3);
}

#[test]
fn enrichment_rollback_record_success_resets_counter() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t2");
    rc.record_success();
    assert_eq!(rc.consecutive_failures, 0);
    assert!(!rc.parallel_disabled); // not triggered, so still enabled
}

#[test]
fn enrichment_rollback_force_disable() {
    let mut rc = RollbackControl::default();
    rc.force_disable("maintenance");
    assert!(rc.parallel_disabled);
    assert_eq!(rc.disable_reason.as_deref(), Some("maintenance"));
}

#[test]
fn enrichment_rollback_re_enable() {
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
fn enrichment_rollback_failure_trace_ids_deduplicate() {
    let mut rc = RollbackControl::default();
    rc.record_failure("t1");
    rc.record_failure("t1"); // same trace id
    assert_eq!(rc.failure_trace_ids.len(), 1);
    assert_eq!(rc.consecutive_failures, 2);
}

// -----------------------------------------------------------------------
// 10. ThroughputSample
// -----------------------------------------------------------------------

#[test]
fn enrichment_throughput_sample_zero_elapsed() {
    let ts = ThroughputSample::compute(1000, 200, 0);
    assert_eq!(ts.bytes_per_sec_millionths, 0);
    assert_eq!(ts.tokens_per_sec_millionths, 0);
}

#[test]
fn enrichment_throughput_sample_nonzero_elapsed() {
    let ts = ThroughputSample::compute(1000, 200, 1_000_000);
    assert!(ts.bytes_per_sec_millionths > 0);
    assert!(ts.tokens_per_sec_millionths > 0);
}

#[test]
fn enrichment_throughput_sample_stores_raw_values() {
    let ts = ThroughputSample::compute(42, 7, 100);
    assert_eq!(ts.bytes, 42);
    assert_eq!(ts.tokens, 7);
    assert_eq!(ts.elapsed_us, 100);
}

// -----------------------------------------------------------------------
// 11. compute_chunk_plan edge cases
// -----------------------------------------------------------------------

#[test]
fn enrichment_chunk_plan_very_short_input_with_newlines() {
    let plan = parallel_parser::compute_chunk_plan(b"a\n", 8);
    assert!(!plan.chunks.is_empty());
    assert!(plan.chunks.last().unwrap().1 == 2);
}

#[test]
fn enrichment_chunk_plan_many_workers_few_lines() {
    let plan = parallel_parser::compute_chunk_plan(b"a\nb\n", 100);
    // Worker count capped to boundaries + 1
    for window in plan.chunks.windows(2) {
        assert_eq!(window[0].1, window[1].0, "chunks must be contiguous");
    }
    assert_eq!(plan.chunks.first().unwrap().0, 0);
    assert_eq!(plan.chunks.last().unwrap().1, 4);
}

#[test]
fn enrichment_chunk_plan_hash_deterministic() {
    let input = b"line1;\nline2;\nline3;\n";
    let p1 = parallel_parser::compute_chunk_plan(input, 3);
    let p2 = parallel_parser::compute_chunk_plan(input, 3);
    assert_eq!(p1.plan_hash, p2.plan_hash);
}

#[test]
fn enrichment_chunk_plan_single_newline() {
    let plan = parallel_parser::compute_chunk_plan(b"\n", 4);
    assert!(!plan.chunks.is_empty());
}

// -----------------------------------------------------------------------
// 12. build_schedule_transcript and replay
// -----------------------------------------------------------------------

#[test]
fn enrichment_schedule_transcript_deterministic() {
    let plan = parallel_parser::compute_chunk_plan(b"a\nb\nc\nd\n", 3);
    let t1 = parallel_parser::build_schedule_transcript(&plan, 42);
    let t2 = parallel_parser::build_schedule_transcript(&plan, 42);
    assert_eq!(t1.transcript_hash, t2.transcript_hash);
    assert_eq!(t1.execution_order, t2.execution_order);
    assert_eq!(t1.dispatches.len(), t2.dispatches.len());
}

#[test]
fn enrichment_schedule_transcript_different_seeds_differ() {
    let plan = parallel_parser::compute_chunk_plan(b"a\nb\nc\nd\ne\nf\ng\nh\n", 4);
    let t1 = parallel_parser::build_schedule_transcript(&plan, 0);
    let t2 = parallel_parser::build_schedule_transcript(&plan, 999);
    // Transcript hashes differ because seed is part of the hash
    assert_ne!(t1.transcript_hash, t2.transcript_hash);
}

#[test]
fn enrichment_schedule_transcript_replay_roundtrip() {
    let plan = parallel_parser::compute_chunk_plan(b"a\nb\nc\nd\n", 2);
    let transcript = parallel_parser::build_schedule_transcript(&plan, 7);
    let order = parallel_parser::replay_schedule_transcript(&transcript, &plan).unwrap();
    assert_eq!(order, transcript.execution_order);
}

#[test]
fn enrichment_schedule_transcript_replay_detects_tampered_hash() {
    let plan = parallel_parser::compute_chunk_plan(b"a\nb\nc\n", 2);
    let mut transcript = parallel_parser::build_schedule_transcript(&plan, 0);
    transcript.transcript_hash = ContentHash::compute(b"tampered");
    let result = parallel_parser::replay_schedule_transcript(&transcript, &plan);
    assert!(result.is_err());
}

#[test]
fn enrichment_schedule_transcript_replay_detects_wrong_plan() {
    let plan1 = parallel_parser::compute_chunk_plan(b"a\nb\nc\n", 2);
    let plan2 = parallel_parser::compute_chunk_plan(b"x\ny\nz\nw\n", 3);
    let transcript = parallel_parser::build_schedule_transcript(&plan1, 0);
    let result = parallel_parser::replay_schedule_transcript(&transcript, &plan2);
    assert!(result.is_err());
}

// -----------------------------------------------------------------------
// 13. merge_chunks edge cases
// -----------------------------------------------------------------------

#[test]
fn enrichment_merge_chunks_reverse_order() {
    let chunk1 = ChunkResult {
        chunk_index: 1,
        chunk_start: 10,
        chunk_end: 20,
        tokens: vec![Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        }],
        token_count: 1,
    };
    let chunk0 = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 10,
        tokens: vec![Token {
            kind: TokenKind::NumericLiteral,
            start: 2,
            end: 5,
        }],
        token_count: 1,
    };
    // Pass in reverse order — merge should still sort by absolute position
    let merged = parallel_parser::merge_chunks(&[chunk1, chunk0]);
    assert_eq!(merged.len(), 2);
    assert!(
        merged[0].start < merged[1].start,
        "should be sorted by absolute offset"
    );
}

#[test]
fn enrichment_merge_chunks_multiple_tokens_per_chunk() {
    let chunk = ChunkResult {
        chunk_index: 0,
        chunk_start: 0,
        chunk_end: 20,
        tokens: vec![
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
                start: 5,
                end: 8,
            },
        ],
        token_count: 3,
    };
    let merged = parallel_parser::merge_chunks(&[chunk]);
    assert_eq!(merged.len(), 3);
    assert_eq!(merged[0].start, 0);
    assert_eq!(merged[1].start, 3);
    assert_eq!(merged[2].start, 5);
}

// -----------------------------------------------------------------------
// 14. repair_boundary_tokens edge cases
// -----------------------------------------------------------------------

#[test]
fn enrichment_repair_boundary_tokens_contiguous_same_kind() {
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
    assert_eq!(tokens[0].start, 0);
    assert_eq!(tokens[0].end, 10);
}

#[test]
fn enrichment_repair_boundary_tokens_chain_of_three() {
    let mut tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 3,
            end: 6,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 6,
            end: 9,
        },
    ];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].end, 9);
}

#[test]
fn enrichment_repair_boundary_tokens_gap_between_same_kind() {
    let mut tokens = vec![
        Token {
            kind: TokenKind::Identifier,
            start: 0,
            end: 3,
        },
        Token {
            kind: TokenKind::Identifier,
            start: 5,
            end: 8,
        },
    ];
    parallel_parser::repair_boundary_tokens(&mut tokens);
    // Gap: start(5) > end(3), so no merge
    assert_eq!(tokens.len(), 2);
}

// -----------------------------------------------------------------------
// 15. compute_routing_digest
// -----------------------------------------------------------------------

#[test]
fn enrichment_routing_digest_small_input_serial() {
    let config = default_config();
    let digest = parallel_parser::compute_routing_digest("x", &config);
    assert_eq!(digest.decision, ParserMode::Serial);
    assert_eq!(digest.effective_workers, 1);
    assert!(!digest.rationale.is_empty());
}

#[test]
fn enrichment_routing_digest_large_input_parallel() {
    let source = make_large_source(500);
    let config = default_config();
    let digest = parallel_parser::compute_routing_digest(&source, &config);
    assert_eq!(digest.decision, ParserMode::Parallel);
    assert!(digest.effective_workers > 1);
    assert!(digest.has_partition_points);
}

#[test]
fn enrichment_routing_digest_single_worker() {
    let config = ParallelConfig {
        max_workers: 1,
        ..default_config()
    };
    let source = make_large_source(500);
    let digest = parallel_parser::compute_routing_digest(&source, &config);
    assert_eq!(digest.decision, ParserMode::Serial);
    assert!(digest.rationale.contains("single worker"));
}

#[test]
fn enrichment_routing_digest_overhead_estimates() {
    let config = ParallelConfig {
        min_parallel_bytes: 100,
        ..default_config()
    };
    // Just above threshold: 20% overhead
    let source_small = "a".repeat(150) + "\n";
    let d1 = parallel_parser::compute_routing_digest(&source_small, &config);
    assert_eq!(d1.estimated_overhead_millionths, 200_000);

    // Well above threshold: 5%
    let source_large = make_large_source(500);
    let d2 = parallel_parser::compute_routing_digest(&source_large, &config);
    assert_eq!(d2.estimated_overhead_millionths, 50_000);
}

// -----------------------------------------------------------------------
// 16. Full parse integration
// -----------------------------------------------------------------------

#[test]
fn enrichment_parse_serial_has_output_hash() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.mode, ParserMode::Serial);
    // Output hash should be deterministic
    let output2 = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.output_hash, output2.output_hash);
}

#[test]
fn enrichment_parse_zero_budget_is_error() {
    let config = ParallelConfig {
        chunk_budget_us: 0,
        ..default_config()
    };
    let input = make_input("x", &config);
    assert!(matches!(
        parallel_parser::parse(&input),
        Err(ParseError::InvalidConfig { .. })
    ));
}

#[test]
fn enrichment_parse_input_too_large() {
    let mut config = default_config();
    config.lexer_config.max_source_bytes = 10;
    let input = make_input("this is more than ten bytes long input", &config);
    assert!(matches!(
        parallel_parser::parse(&input),
        Err(ParseError::InputTooLarge { .. })
    ));
}

#[test]
fn enrichment_parse_parallel_output_has_artifacts() {
    let source = make_large_source(200);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    // Either parallel or serial fallback, but should have chunk_plan
    assert!(output.chunk_plan.is_some() || output.mode == ParserMode::Serial);
    assert!(output.token_count > 0);
    assert!(output.bytes_scanned > 0);
}

#[test]
fn enrichment_parse_parallel_with_parity_check() {
    let source = make_large_source(100);
    let config = ParallelConfig {
        always_check_parity: true,
        ..small_config()
    };
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    // Parity result should exist since always_check_parity is true
    if output.mode == ParserMode::Parallel {
        assert!(output.parity_result.is_some());
        let pr = output.parity_result.as_ref().unwrap();
        assert!(pr.parity_ok);
    }
}

#[test]
fn enrichment_parse_schema_version_in_output() {
    let config = default_config();
    let input = make_input("x", &config);
    let output = parallel_parser::parse(&input).unwrap();
    assert_eq!(output.schema_version, SCHEMA_VERSION);
}

// -----------------------------------------------------------------------
// 17. generate_log_entries
// -----------------------------------------------------------------------

#[test]
fn enrichment_log_entries_serial_parse() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("trace-1", &output);
    assert!(!entries.is_empty());
    assert_eq!(entries[0].trace_id, "trace-1");
    assert_eq!(entries[0].component, COMPONENT);
    assert_eq!(entries[0].event, "parse_complete");
    assert_eq!(entries[0].outcome, "ok");
}

#[test]
fn enrichment_log_entries_contain_mode() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("t", &output);
    assert_eq!(entries[0].parser_mode, Some("serial".to_string()));
}

#[test]
fn enrichment_log_entries_parallel_parse() {
    let source = make_large_source(100);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let entries = parallel_parser::generate_log_entries("t2", &output);
    assert!(!entries.is_empty());
    assert!(entries[0].input_bytes.is_some());
    assert!(entries[0].token_count.is_some());
}

// -----------------------------------------------------------------------
// 18. build_replay_envelope
// -----------------------------------------------------------------------

#[test]
fn enrichment_replay_envelope_serial() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest("var x = 1;", &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert_eq!(envelope.schema_version, SCHEMA_VERSION);
    assert_eq!(envelope.input_bytes, 10);
    assert!(!envelope.replay_command.is_empty());
    assert!(envelope.chunk_plan.is_none());
}

#[test]
fn enrichment_replay_envelope_parallel() {
    let source = make_large_source(200);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest(&source, &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    assert_eq!(envelope.input_bytes, source.len() as u64);
    assert!(envelope.replay_command.contains("parallel-parse"));
    assert!(envelope.replay_command.contains("--trace-id"));
}

#[test]
fn enrichment_replay_envelope_serde_roundtrip() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let digest = parallel_parser::compute_routing_digest("var x = 1;", &config);
    let envelope = parallel_parser::build_replay_envelope(&input, &output, &digest);
    let json = serde_json::to_string(&envelope).unwrap();
    let back: ReplayEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(envelope.schema_version, back.schema_version);
    assert_eq!(envelope.input_bytes, back.input_bytes);
    assert_eq!(envelope.output_hash, back.output_hash);
}

// -----------------------------------------------------------------------
// 19. JSON field-name stability
// -----------------------------------------------------------------------

#[test]
fn enrichment_parallel_config_json_fields() {
    let json = serde_json::to_string(&default_config()).unwrap();
    for field in [
        "min_parallel_bytes",
        "max_workers",
        "chunk_budget_us",
        "merge_buffer_bytes",
        "overhead_threshold_millionths",
        "schedule_seed",
        "always_check_parity",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_chunk_plan_json_fields() {
    let plan = parallel_parser::compute_chunk_plan(b"a\nb\n", 2);
    let json = serde_json::to_string(&plan).unwrap();
    for field in ["chunks", "plan_hash", "worker_count"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_parity_result_json_fields() {
    let pr = ParityResult {
        parity_ok: true,
        mismatch_index: None,
        parallel_count: 0,
        serial_count: 0,
    };
    let json = serde_json::to_string(&pr).unwrap();
    for field in [
        "parity_ok",
        "mismatch_index",
        "parallel_count",
        "serial_count",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_rollback_control_json_fields() {
    let rc = RollbackControl::default();
    let json = serde_json::to_string(&rc).unwrap();
    for field in [
        "parallel_disabled",
        "disable_reason",
        "consecutive_failures",
        "auto_rollback_threshold",
        "failure_trace_ids",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_timeout_policy_json_fields() {
    let tp = TimeoutPolicy::default();
    let json = serde_json::to_string(&tp).unwrap();
    for field in ["max_total_us", "max_chunk_us", "allow_drain"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_backpressure_snapshot_json_fields() {
    let bp = BackpressureSnapshot {
        queue_depth: 1,
        peak_queue_depth: 2,
        level: BackpressureLevel::Normal,
        delayed_chunks: 0,
        total_delay_us: 0,
    };
    let json = serde_json::to_string(&bp).unwrap();
    for field in [
        "queue_depth",
        "peak_queue_depth",
        "level",
        "delayed_chunks",
        "total_delay_us",
    ] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

#[test]
fn enrichment_cancellation_record_json_fields() {
    let cr = CancellationRecord {
        state: CancellationState::Finalized,
        elapsed_us: 100,
        trigger_chunk: Some(0),
        drain_completed: true,
    };
    let json = serde_json::to_string(&cr).unwrap();
    for field in ["state", "elapsed_us", "trigger_chunk", "drain_completed"] {
        assert!(json.contains(field), "missing field: {field}");
    }
}

// -----------------------------------------------------------------------
// 20. ParseOutput serde roundtrip (full struct)
// -----------------------------------------------------------------------

#[test]
fn enrichment_parse_output_serde_roundtrip_serial() {
    let config = default_config();
    let input = make_input("var x = 1;", &config);
    let output = parallel_parser::parse(&input).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: ParseOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output.mode, back.mode);
    assert_eq!(output.token_count, back.token_count);
    assert_eq!(output.output_hash, back.output_hash);
}

#[test]
fn enrichment_parse_output_serde_roundtrip_parallel() {
    let source = make_large_source(100);
    let config = small_config();
    let input = make_input(&source, &config);
    let output = parallel_parser::parse(&input).unwrap();
    let json = serde_json::to_string(&output).unwrap();
    let back: ParseOutput = serde_json::from_str(&json).unwrap();
    assert_eq!(output.mode, back.mode);
    assert_eq!(output.token_count, back.token_count);
    assert_eq!(output.output_hash, back.output_hash);
}
